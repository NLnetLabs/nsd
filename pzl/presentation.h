/* Copyright (c) 2018, NLnet Labs. All rights reserved.
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

#ifndef PRESENTATION_H_
#define PRESENTATION_H_
#include "pzl/mmap_parser.h"
#include "pzl/dns_config.h"

typedef struct presentation_dname {
	parse_ref   r;
	const char *end;
	char       *spc;
	size_t      spc_sz;
	int         malloced;
} presentation_dname;

typedef struct presentation_rr {
	const char  *origin;
	const char  *origin_end;
	const char  *owner;
	const char  *owner_end;
	uint32_t     ttl;
	uint16_t     rr_class;
	parse_piece *rr_type;
	parse_piece *end;
} presentation_rr;

typedef struct zonefile_iter {
	mmap_parser        p;

	uint32_t           TTL; /* from $TTL directives (or the default) */
	presentation_dname origin;
	presentation_dname owner;

	uint32_t           ttl;
	uint16_t           rr_class;
	parse_piece       *rr_type;
} zonefile_iter;

status_code zonefile_iter_init_text_(dns_config *cfg,zonefile_iter *i,
    const char *text, size_t text_len, return_status *st);

status_code zonefile_iter_init_fn_(dns_config *cfg, zonefile_iter *i,
    const char *fn, return_status *st);

static inline status_code zonefile_iter_init_text(
    zonefile_iter *i, const char *text, size_t text_len)
{ return zonefile_iter_init_text_(NULL, i, text, text_len, NULL); }

static inline status_code zonefile_iter_init_fn(
   zonefile_iter *i, const char *fn)
{ return zonefile_iter_init_fn_(NULL, i, fn, NULL); }

status_code zonefile_iter_next_(zonefile_iter *i, return_status *st);

static inline status_code zonefile_iter_next(zonefile_iter *i)
{ return zonefile_iter_next_(i, NULL); }

void zonefile_iter_free_in_use(zonefile_iter *i);

#endif /* #ifndef PRESENTATION_H_ */
