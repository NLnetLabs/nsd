/* Copyright (c) 2019, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#include "pzl/zonefile_processor.h"
#include <pthread.h>
#include <assert.h>

typedef struct zonefile_worker zonefile_worker;
typedef struct zonefile_processor {
	pthread_mutex_t     mutex;
	zonefile_iter       zi;
	int                 finished;
	process_rrs_func    process;
	void               *userarg;
	size_t            n_workers;
	zonefile_worker    *workers;
} zonefile_processor;

#ifndef ZONEFILE_WORKER_N_RRS
#define ZONEFILE_WORKER_N_RRS 1024
#endif

struct zonefile_worker {
	pthread_t           thread;
	zonefile_processor *mzp;

	presentation_rr     rrs[ZONEFILE_WORKER_N_RRS];
	parse_piece         pieces[ZONEFILE_WORKER_N_RRS * 4];
	return_status       st;
	parse_ref           ref;
	char               *origin_to_free;
	char               *owner_to_free;
	int                 have_lock;
};

static inline void *werr(zonefile_worker *w)
{
	size_t n = w - w->mzp->workers;
	size_t i;

	for (i = 0; i < w->mzp->n_workers; i++) {
		if (i == n)
			continue;
		(void) pthread_cancel(w->mzp->workers[i].thread);
	}
	if (w->have_lock)
		pthread_mutex_unlock(&w->mzp->mutex);
	free(w->origin_to_free);
	free(w->owner_to_free);
	return &w->st;
}

void *zonefile_worker_start(void *worker)
{
	char               origin_spc[1024] = "", *origin = origin_spc;
	size_t             origin_len = sizeof(origin_spc);
	char               owner_spc[1024] = "", *owner = owner_spc;
	size_t             owner_len = sizeof(owner_spc);
	zonefile_worker    *w       = (zonefile_worker *)worker;
	zonefile_processor *mzp     = w->mzp;

	pthread_mutex_t    *mutex   = &mzp->mutex;
	zonefile_iter      *zi      = &mzp->zi;
	process_rrs_func    process =  mzp->process;
	size_t            n_worker  =  w - w->mzp->workers;
	void               *userarg =  mzp->userarg;

	presentation_rr    *rrs = w->rrs, *cur_rr;
	presentation_rr    *end_of_rrs = rrs + sizeof( w->rrs)
	                                     / sizeof(*w->rrs);
	parse_piece        *pieces = w->pieces;
	parse_piece        *end_of_piece = pieces + sizeof( w->pieces)
	                                          / sizeof(*w->pieces);
	int                 pc;
	status_code         sc, prc;
	return_status      *st = &w->st, prst;
	parse_ref          *ref = &w->ref;

	float               text_sz = zi->p.end - zi->p.text;

	(void) pthread_setcanceltype(PTHREAD_CANCEL_ASYNCHRONOUS, NULL);

	for (;;) {
		if ((pc = pthread_mutex_lock(mutex)))
			return RETURN_PTHREAD_ERR(st,
			    "locking zonefile processor lock", pc), werr(w);
		w->have_lock = 1;

		if (ref->prev)
			(void) parse_dereference(ref, NULL);

		if (mzp->finished) {
			/* zonefile iterator finished already */
			(void) pthread_mutex_unlock(mutex);
			w->have_lock = 0;
			break;
		}
		if (zi->owner.r.text) {
			size_t zi_owner_len
			    = zi->owner.end - zi->owner.r.text;

			if (zi_owner_len > owner_len) {
				owner_len = (zi_owner_len / 1024 + 1) * 1024;
				if (!(owner = malloc(owner_len)))
					return RETURN_MEM_ERR(st,
					    "allocating owner space"), werr(w);
				free(w->owner_to_free);
				w->owner_to_free = owner;
			}
			(void) memcpy(
			    owner, zi->owner.r.text, zi_owner_len);
			owner[zi_owner_len] = 0;
			if (zi->owner.r.prev)
				(void) parse_dereference(&zi->owner.r, NULL);
		} else
			*owner = 0;
		zi->owner.r.text = owner;
		zi->owner.end = strchr(owner, 0);

		if (zi->origin.r.text) {
			size_t zi_origin_len
			    = zi->origin.end - zi->origin.r.text;

			if (zi_origin_len > origin_len) {
				origin_len = (zi_origin_len / 1024 + 1) * 1024;
				if (!(origin = malloc(origin_len)))
					return RETURN_MEM_ERR(st,
					    "allocating origin space"), werr(w);
				free(w->origin_to_free);
				w->origin_to_free = origin;
			}
			(void) memcpy(
			    origin, zi->origin.r.text, zi_origin_len);
			origin[zi_origin_len] = 0;
			if (zi->origin.r.prev)
				(void) parse_dereference(&zi->origin.r, NULL);
		} else
			*origin = 0;
		zi->origin.r.text = origin;
		zi->origin.end = strchr(origin, 0);

		ref->text = zi->p.cur;
		if ((sc = mmap_parser_up_ref(&zi->p, ref, st)))
			return werr(w);

		zi->p.pieces        = pieces;
		zi->p.end_of_pieces = end_of_piece;

		cur_rr = rrs;
		while (cur_rr < end_of_rrs
		    && zi->p.pieces < zi->p.end_of_pieces - 10) {
			if ((sc = zonefile_iter_next_(zi, st)))
				break;

			cur_rr->origin     = zi->origin.r.text;
			cur_rr->origin_end = zi->origin.end;
			cur_rr->owner      = zi->owner.r.text;
			cur_rr->owner_end  = zi->owner.end;
			cur_rr->ttl        = zi->ttl;
			cur_rr->rr_class   = zi->rr_class;
			cur_rr->rr_type    = zi->rr_type;
			cur_rr->end        = zi->p.cur_piece;

			cur_rr += 1;
			zi->p.pieces = zi->p.cur_piece;
		}
		if (sc == STATUS_OVERFLOW_ERR) {
			zi->p.cur = zi->p.start;/* Reset parser */
			if (strncmp(st->msg, "pieces", 6) == 0 
			    && zi->p.pieces > pieces)
				sc = STATUS_OK;
		}
		if (sc == STATUS_STOP_ITERATION)
			mzp->finished = 1;

		if ((pc = pthread_mutex_unlock(mutex)))
			return RETURN_PTHREAD_ERR(st,
			   "unlocking zonefile processor lock", pc), werr(w);
		w->have_lock = 0;
		prc = process(rrs, cur_rr, n_worker, userarg, !zi->p.cur ? 1
		    : (float)(zi->p.cur - zi->p.text) / text_sz, &prst);
		if (prc) {
			*st = prst;
			return werr(w);
		}
		if (sc == STATUS_STOP_ITERATION)
			break;
		else if (sc)
			return werr(w);
	}
	free(w->origin_to_free);
	free(w->owner_to_free);
	return NULL;
}

status_code zonefile_process_rrs_fn_(
    dns_config *cfg, const char *fn, size_t n_workers,
    process_rrs_func process_func, void *userarg, return_status *st)
{
	zonefile_processor mzp;
	status_code sc;
	size_t i;
	int pc;

	(void) pthread_mutex_init(&mzp.mutex, NULL);
	if ((sc = zonefile_iter_init_fn_(cfg, &mzp.zi, fn, st)))
		return sc;
	mzp.finished = 0;

	assert(!mzp.zi.p.pieces_malloced);

	if (mzp.zi.owner.malloced) {
		free(mzp.zi.owner.spc);
		(void) memset(&mzp.zi.owner, 0, sizeof(mzp.zi.owner));
	}
	if (mzp.zi.origin.malloced) {
		free(mzp.zi.origin.spc);
		(void) memset(&mzp.zi.origin, 0, sizeof(mzp.zi.origin));
		if (cfg && cfg->default_origin) {
			mzp.zi.origin.r.text = cfg->default_origin;
			mzp.zi.origin.end = strchr(cfg->default_origin, 0);
		}
	}
	mzp.process = process_func;
	mzp.userarg = userarg;
	mzp.n_workers = n_workers;
	if (!(mzp.workers = calloc(
	    mzp.n_workers, sizeof(zonefile_worker))))
		return RETURN_MEM_ERR(
		    st, "allocating space for zonefile_workers");

	if ((pc = pthread_mutex_lock(&mzp.mutex)))
		return RETURN_PTHREAD_ERR(
		    st, "initially locking zonefile processor lock", pc);

	for (i = 0; i < mzp.n_workers; i++) {
		mzp.workers[i].mzp = &mzp;

		if ((pc = pthread_create(&mzp.workers[i].thread, NULL,
		    zonefile_worker_start, &mzp.workers[i])))
			return RETURN_PTHREAD_ERR(st,
			    "starting a worker ", pc);
	}
	if ((pc = pthread_mutex_unlock(&mzp.mutex)))
		return RETURN_PTHREAD_ERR(st,
		    "unlocking zonefile processor lock "
		    "after workers initialization", pc);

	for (i = 0; i < mzp.n_workers; i++) {
		void *retval = NULL;

		if ((pc = pthread_join(mzp.workers[i].thread, &retval)))
			return RETURN_PTHREAD_ERR(st,
			    "joining a worker ", pc);

		if (retval && retval != PTHREAD_CANCELED) {
			if (st)
				*st = *(return_status *)retval;
			sc = ((return_status *)retval)->code;
		}
	}
	free(mzp.workers);
	return sc;
}

