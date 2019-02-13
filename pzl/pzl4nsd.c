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
#include "config.h"
#include "options.h"
#include "pzl/pzl4nsd.h"
#include "pzl/dnsextlang.h"
#include <pthread.h>

static dname_type *dname_init(uint8_t *dname,
    const char *start, const char *end, dname_type *origin)
{
	const uint8_t *s = (const uint8_t *) start;
	const uint8_t *e = (const uint8_t *) end;
	uint8_t *h;
	uint8_t *p;
	uint8_t *d = dname;
	size_t label_length;
	uint8_t *l = dname - 1;

	if (start + 1 == end) {
		if (*start == '.') {
			/* Root domain. */
			dname[-3] = 1; /* name_size = 1;        */
			dname[-2] = 1; /* label_count = 1;      */
			dname[-1] = 0; /* label_offsets[0] = 0; */
			dname[ 0] = 0; /* name[0] = 0;          */
			return (void *)&dname[-3];
		}
		if (origin && *start == '@') {
			(void) memcpy(dname - 2 - origin->label_count,
			    (void *)origin,
			    2 + origin->name_size + origin->label_count);
			return (void *)(dname - 2 - origin->label_count);
		}
	}
	if (*start == '.' && start + 1 == end) {
		/* Root domain.  */
		dname[-3] = 1; /* name_size = 1;        */
		dname[-2] = 1; /* label_count = 1;      */
		dname[-1] = 0; /* label_offsets[0] = 0; */
		dname[ 0] = 0; /* name[0] = 0;          */
		return (void *)&dname[-3];
	}
	for (h = d, p = h + 1; s < e; ++s, ++p) {
		if (p - dname >= MAXDOMAINLEN) {
			return 0;
		}
		switch (*s) {
		case '.':
			if (p == h + 1) {
				/* Empty label.  */
				return NULL;
			} else {
				label_length = p - h - 1;
				if (label_length > MAXLABELLEN) {
					return NULL;
				}
				*h = label_length;
				*l-- = h - dname;
				h = p;
			}
			break;
		case '\\':
			/* Handle escaped characters (RFC1035 5.1) */
			if (e - s > 3 && isdigit((unsigned char)s[1])
			              && isdigit((unsigned char)s[2])
			              && isdigit((unsigned char)s[3])) {
				int val = ((s[1] - '0') * 100 +
					   (s[2] - '0') * 10 +
					   (s[3] - '0'));
				if (0 <= val && val <= 255) {
					s += 3;
					*p = DNAME_NORMALIZE(
					    (unsigned char)val);
				} else {
					*p = DNAME_NORMALIZE(
					    (unsigned char)*++s);
				}
			} else  {
				*p = DNAME_NORMALIZE((unsigned char)*++s);
			}
			break;
		default:
			*p = DNAME_NORMALIZE((unsigned char)*s);
			break;
		}
	}
	if (p != h + 1) {
		/* Terminate last label.  */
		label_length = p - h - 1;
		if (label_length > MAXLABELLEN) {
			return NULL;
		}
		*h = label_length;
		*l-- = h - dname;
		h = p;
	}
	/* Add root label.  */
	if (h - dname >= MAXDOMAINLEN) {
		return NULL;
	}
	if (h == p && origin) {
		const uint8_t *o_l = dname_label_offsets(origin);
		const uint8_t *o_n = o_l + origin->label_count;

		/* non fqdn */
		(void) memcpy(p, o_n--, origin->name_size);
		while (o_n > dname_label_offsets(origin))
			*l-- = *o_n-- + (p - dname);
		l[-1] = dname - l;
		l[-2] = p - dname + origin->name_size;
		return (void *)&l[-2];
	}
	/* fqdn or no origin*/
	*h = 0;
	l[-1] = dname - l;
	l[-2] = h - dname + 1;
	return (void *)&l[-2];
}


#define WORKER_BUF 0x80000

typedef struct fst_parse_rr {
	rr_type rr;
	uint8_t dname[];
} fst_parse_rr;

typedef struct worker_data {
	size_t n_rrs;
} worker_data;

typedef struct process_data {
	size_t        n_workers;
	pthread_mutex_t mutex;
	const char     *name;
	time_t          start_time;
	worker_data *wd;
} process_data;


static status_code process_rrs(
    presentation_rr *rr, presentation_rr *end_of_rrs,
    size_t n_worker, void *userarg, float progress, return_status *st)
{
	process_data *pd = (process_data *)userarg;
	worker_data  *wd = &pd->wd[n_worker];
	const char   *origin_str = NULL;
	uint8_t       origin_spc[MAXDOMAINLEN * 2];
	dname_type   *origin = NULL;
	const char   *owner_str = NULL;
	uint8_t       owner_spc[MAXDOMAINLEN * 2];
	dname_type   *owner = NULL;
	domain_type  *domain = NULL;
	(void)st;

	wd->n_rrs += end_of_rrs - rr;
	while (rr < end_of_rrs) {
		rr_type rr2add;

		if (rr->origin != origin_str) {
			origin = dname_init(origin_spc + MAXDOMAINLEN,
			    rr->origin, rr->origin_end, NULL);
			origin_str = rr->origin;
		}
		if (rr->owner != owner_str && (!owner_str ||
		    strncmp(owner_str, rr->owner, rr->owner_end - rr->owner))) {
			owner = dname_init(owner_spc + MAXDOMAINLEN,
			    rr->owner, rr->owner_end, origin);
			(void) pthread_mutex_lock(&pd->mutex);
			rr2add.owner
			    = domain_table_insert(parser->db->domains, owner);
			(void) pthread_mutex_unlock(&pd->mutex);
			owner_str = rr->owner;
		}
		rr2add.owner = domain;
		rr2add.ttl = rr->ttl;
		rr2add.klass = rr->rr_class;
		rr2add.type = dnsextlang_get_type_(rr->rr_type->start,
                    rr->rr_type->end - rr->rr_type->start, NULL);

		(void) rr2add;
		rr += 1;
	}
	(void) pthread_mutex_lock(&pd->mutex);
	if (time(NULL) > pd->start_time + ZONEC_PCT_TIME) {
		pd->start_time = time(NULL);
		VERBOSITY(1, (LOG_INFO, "parse %s %6.2f %%",
		    pd->name, progress * 100));
	}
	(void) pthread_mutex_unlock(&pd->mutex);
	return STATUS_OK;
}

status_code pzl_load(const char *name, const char *filename, return_status *st)
{
	status_code  sc;
	process_data pd;
	dns_config   cfg;

	cfg.default_ttl = parser->default_ttl;
	cfg.default_class = parser->default_class;
	fprintf(stderr, "NAME: %s\n", name);
	cfg.default_origin = name;

	pd.name = name;
	pd.n_workers = sysconf(_SC_NPROCESSORS_ONLN);
	(void) pthread_mutex_init(&pd.mutex, NULL);
	pd.start_time = time(NULL);
	if (!(pd.wd = region_alloc_array(
	    parser->region, pd.n_workers, sizeof(worker_data))))
		return RETURN_MEM_ERR(st, "allocating worker data");

	VERBOSITY(1, (LOG_INFO, "parse %s   0.00 %%", name));
	sc = zonefile_process_rrs_fn_(
	    &cfg, filename, pd.n_workers, process_rrs, &pd, st);
	if (!sc)
		VERBOSITY(1, (LOG_INFO, "parse %s 100.00 %%", name));

	region_recycle(
	    parser->region, pd.wd, pd.n_workers * sizeof(worker_data));
	return sc;
}

