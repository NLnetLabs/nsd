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
#include "pzl/presentation.h"
#include <assert.h>
#include <ctype.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

void zonefile_iter_free_in_use(zonefile_iter *i)
{
	(void) parse_dereference(&i->origin.r, NULL);
	(void) parse_dereference(&i->owner.r, NULL);

	if (i->origin.malloced) {
		free(i->origin.spc);
		i->origin.spc = NULL;
	}
	if (i->owner.malloced) {
		free(i->owner.spc);
		i->owner.spc = NULL;
	}
	mmap_parser_free_in_use(&i->p);
}

static inline status_code p_zfi_at_end(zonefile_iter *i)
{
	if (i->p.cur) {
		assert(i->p.cur == i->p.end);
		i->p.cur = NULL;
		i->p.cur_piece->start = NULL;
		return STATUS_OK;
	}
	zonefile_iter_free_in_use(i);
	return STATUS_STOP_ITERATION;
}

static status_code p_zfi_get_piece(zonefile_iter *i, return_status *st);
static inline status_code p_zfi_return(zonefile_iter *i, return_status *st)
{
	status_code sc;

	if (*i->p.cur++ == '\n') {
		i->p.line_nr += 1;
		i->p.sol = i->p.cur;
	}
	if ((sc = mmap_parser_progressive_munmap(&i->p, st)))
		return sc;

	if (i->p.cur_piece == i->p.pieces) {
		/* Nothing, so process next line*/
		i->p.start = i->p.cur;
		return i->p.start ? p_zfi_get_piece(i, st)
		                  : p_zfi_at_end(i);
	}
	i->p.cur_piece->start = NULL;
	return STATUS_OK;
}

static inline status_code p_zfi_get_closing_piece(
    zonefile_iter *i, return_status *st)
{
	status_code sc;

	switch (*i->p.cur) {
	case ';':
		/* A comment is NO PART, but skip till end-of-line */
		while (++i->p.cur < i->p.end)
			if (*i->p.cur == '\n') 
				/* p_zfi_get_closing_piece()
				 * does cur and line_nr incr. */
				return p_zfi_get_closing_piece(i, st);
		return p_zfi_at_end(i);

	case '\n':
		i->p.line_nr += 1;
		i->p.sol = i->p.cur + 1;
		/* fallthrough */
	case ' ': case '\t': case '\f':
		while (++i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
				i->p.line_nr += 1;
				i->p.sol = i->p.cur + 1;
				/* fallthrough */
			case ' ': case '\t': case '\f':
				/* Skip whitespace */
				continue;
			default:
				/* Non whitespace get this piece */
				return p_zfi_get_closing_piece(i, st);
			}
		return p_zfi_at_end(i);

	case ')':
		i->p.cur += 1;
		return p_zfi_get_piece(i, st);

	case '"': /* quoted piece (may contain whitespace) */
		if ((sc = equip_cur_piece(&i->p, st)))
			return sc;
		i->p.cur += 1;
		while (i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
				/* Newline is end of quoted piece too */
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				/* p_zfi_get_closing_piece()
				 * does cur and line_nr incr. */
				return p_zfi_get_closing_piece(i, st);
			case '"':
				/* Closing quote found, get next piece */
				i->p.cur += 1;
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				return p_zfi_get_closing_piece(i, st);

			case '\\':
				i->p.cur += 1;
				if (i->p.cur < i->p.end &&
				    (*i->p.cur == '"' || *i->p.cur == '\\'))
					i->p.cur += 1;
				continue;
			default:
				/* Skip non closing quote */
				i->p.cur += 1;
				continue;
			}

		if ((sc = increment_cur_piece(&i->p, st)))
			return sc;
		return p_zfi_at_end(i);

	default:
		if ((sc = equip_cur_piece(&i->p, st)))
			return sc;
		while (i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
			case ' ': case '\t': case '\f':
				/* Whitespace piece, get (but actually skip) */
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				/* p_zfi_get_closing_piece()
				 * does cur and line_nr incr. */
				return p_zfi_get_closing_piece(i, st);

			case ')':
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				i->p.cur += 1;
				return p_zfi_get_piece(i, st);

			default:
				/* Skip non whitespace */
				i->p.cur += 1;
				continue;
			}
		if ((sc = increment_cur_piece(&i->p, st)))
			return sc;
		return p_zfi_at_end(i);
	}
}

static status_code p_zfi_get_piece(zonefile_iter *i, return_status *st)
{
	status_code sc;

	switch (*i->p.cur) {
	case ';':
		/* A comment is NO PART, but skip till end-of-line */
		while (++i->p.cur < i->p.end)
			if (*i->p.cur == '\n')
				/* p_zfi_return()
				 * does cur and line_nr incr. */
				return p_zfi_return(i, st);
		return p_zfi_at_end(i);

	case '\n':
		/* Remaining space is no piece */
		/* p_zfi_return() does cur and line_nr incr. */
		return p_zfi_return(i, st);

	case ' ': case '\t': case '\f':
		while (++i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
				/* Remaining space is no piece */
				/* p_zfi_return()
				 * does cur and line_nr incr. */
				return p_zfi_return(i, st);

			case ' ': case '\t': case '\f':
				/* Skip whitespace */
				continue;
			default:
				/* Non whitespace get this piece */
				return p_zfi_get_piece(i, st);
			}
		return p_zfi_at_end(i);

	case '(':
		i->p.cur += 1;
		return p_zfi_get_closing_piece(i, st);

	case '"': /* quoted piece (may contain whitespace) */
		if ((sc = equip_cur_piece(&i->p, st)))
			return sc;
		i->p.cur += 1;
		while (i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
				/* Remaining space is no piece */
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				/* p_zfi_return()
				 * does cur and line_nr incr. */
				return p_zfi_return(i, st);

			case '"':
				/* Closing quote found, get next piece */
				i->p.cur += 1;
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				return p_zfi_get_piece(i, st);

			case '\\':
				i->p.cur += 1;
				if (i->p.cur < i->p.end &&
				    (*i->p.cur == '"' || *i->p.cur == '\\'))
					i->p.cur += 1;
				continue;
			default:
				/* Skip non closing quote */
				i->p.cur += 1;
				continue;
			}
		if ((sc = increment_cur_piece(&i->p, st)))
			return sc;
		return p_zfi_at_end(i);

	default: /* unquoted piece (bounded by whitespace) */
		if ((sc = equip_cur_piece(&i->p, st)))
			return sc;
		while (i->p.cur < i->p.end)
			switch (*i->p.cur) {
			case '\n':
				/* Remaining space is no piece */
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				/* p_zfi_return()
				 * does cur and line_nr incr. */
				return p_zfi_return(i, st);

			case ' ': case '\t': case '\f':
				/* Whitespace piece, get (but actually skip) */
				if ((sc = increment_cur_piece(&i->p, st)))
					return sc;
				return p_zfi_get_piece(i, st);

			case '\\':
				i->p.cur += 1;
				if (i->p.cur < i->p.end && isspace(*i->p.cur))
					i->p.cur += 1;
				continue;
			default:
				/* Skip non whitespace */
				i->p.cur += 1;
				continue;
			}
		if ((sc = increment_cur_piece(&i->p, st)))
			return sc;
		return p_zfi_at_end(i);
	}
}

static inline status_code pf_ttl2u32(zonefile_iter *i,
    const char *pf_ttl, const char *pf_ttl_end,
    uint32_t *rttl, return_status *st)
{
	char buf[11], *endptr;
	size_t  pf_ttl_len = pf_ttl_end - pf_ttl;

	if (pf_ttl_len >= sizeof(buf))
		return RETURN_PARSE_ERR(st, "in ttl value",
		    i->p.fn, i->p.line_nr, pf_ttl - i->p.sol);

	(void) memcpy(buf, pf_ttl, pf_ttl_len);
	buf[pf_ttl_len] = '\0';
	*rttl = strtoul(buf, &endptr, 10);
	if (*endptr != 0)
		return RETURN_PARSE_ERR(st, "in ttl value",
		    i->p.fn, i->p.line_nr, pf_ttl - i->p.sol);

	return STATUS_OK;
}

static inline status_code p_zfi_set_dname(
    zonefile_iter *i, presentation_dname *dname,
    const char *text, const char *end, return_status *st)
{
	status_code sc;
	size_t len;

	(void) parse_dereference(&dname->r, NULL);

	assert(end > text);
	if (!dname->spc_sz) {
		dname->r.text = text;
		dname->end = end;
		if (text >= i->p.text && text < i->p.end
		&& (sc = mmap_parser_up_ref(&i->p, &dname->r, st)))
			return sc;
		return STATUS_OK;
	}
	if ((len = end - text) > dname->spc_sz || !dname->spc) {
		if (dname->spc) {
			if (!dname->malloced)
				return RETURN_OVERFLOW_ERR(st,
				   "dname from zone does not "
				   "fit the fixed sized buffer");
			else {
				free(dname->spc);
				dname->spc = NULL;
			}
		}
		if (!dname->spc_sz)
			dname->spc_sz = ((len / 1024) + 1) * 1024;

		else while (len > dname->spc_sz)
			dname->spc_sz *= 2;

		if (!(dname->spc = calloc(1, dname->spc_sz)))
			return RETURN_MEM_ERR(st,
			    "could not allocate more "
			    "space to fit dname from zone");

		dname->malloced = 1;
	}
	(void) memcpy(dname->spc, text, len);
	dname->r.text = dname->spc;
	dname->end = dname->spc + len;
	return STATUS_OK;
}

static inline status_code
p_zfi_process_rr(zonefile_iter *i, return_status *st)
{
	status_code sc;
	parse_piece *piece = i->p.pieces;
	ssize_t piece_sz;

	piece_sz = (piece->end - piece->start);
	if (piece->start > i->p.start)
		; /* pass: Owner is previous owner */

	else if (piece_sz <= 0)
		return zonefile_iter_next_(i, st); /* Empty line? */

	else if ((piece->start[0] == '@' && piece_sz == 1)
	       || piece->start[0] != '$') {
		/* Owner */

		if ((sc = p_zfi_set_dname(
		    i, &i->owner, piece->start, piece->end, st)))
			return sc;
		piece++;
		piece_sz = (piece->end - piece->start);

	} else if (piece_sz == 7
	       && strncasecmp(piece->start, "$ORIGIN", 7) == 0) {
		/* $ORIGIN */
		piece++;
		if ((sc = p_zfi_set_dname(
		    i, &i->origin, piece->start, piece->end, st)))
			return sc;
		return zonefile_iter_next_(i, st);

	} else if (piece_sz == 4 && strncasecmp(piece->start, "$TTL", 4) == 0) {
		/* $TTL */
		piece++;
		if ((sc = pf_ttl2u32(
		    i, piece->start, piece->end, &i->TTL, st)))
			return sc;
		return zonefile_iter_next_(i, st);
	} else {
		/* Other $ directive */
		return zonefile_iter_next_(i, st);
	}
	/* Skip class */
	if (piece->start && piece->start[0] >= '0' && piece->start[0] <= '9') {
		/* TTL */
		if ((sc = pf_ttl2u32(
		    i, piece->start, piece->end, &i->ttl, st)))
			return sc;
		piece++;
		piece_sz = (piece->end - piece->start);
	} else {
		i->ttl = i->TTL;
	}
	/* Is last piece class? */
	if (piece_sz == 2) {
		if ((piece->start[0] == 'I' || piece->start[0] == 'i')
		&&  (piece->start[1] == 'N' || piece->start[1] == 'n')) {
			i->rr_class = 1;
			piece++;

		} else if ((piece->start[0] == 'C' || piece->start[0] == 'c')
		       &&  (piece->start[1] == 'H' || piece->start[1] == 'h')) {
			i->rr_class = 3;
			piece++;

		} else if ((piece->start[0] == 'H' || piece->start[0] == 'h')
		       &&  (piece->start[1] == 'S' || piece->start[1] == 's')) {
			i->rr_class = 4;
			piece++;
		}
	} else if (piece_sz > 5 && piece_sz < 11
	       && (piece->start[0] == 'C' || piece->start[0] == 'c')
	       && (piece->start[1] == 'L' || piece->start[1] == 'l')
	       && (piece->start[2] == 'A' || piece->start[2] == 'a')
	       && (piece->start[3] == 'S' || piece->start[3] == 's')
	       && (piece->start[4] == 'S' || piece->start[4] == 's')) {
		char nptr[7], *endptr;
		unsigned long int c;
		
		(void) memcpy(nptr, piece->start + 5, piece_sz - 5);
		nptr[piece_sz - 5] = 0;
		c = strtoul(nptr, &endptr, 10);
		if (*endptr == 0) {
			if (c > 65535)
				return RETURN_PARSE_ERR(st,
				    "DNS classes range from [0 ... 65535]",
				    i->p.fn, i->p.line_nr,
				    (piece->start - i->p.sol));
			i->rr_class = c;
			piece++;
		} /* Else warning about suspicous RR type name */
	}
	i->rr_type = piece;
	return STATUS_OK;
}

status_code zonefile_iter_next_(zonefile_iter *i, return_status *st)
{
	status_code sc;

	if (!i)
		return RETURN_USAGE_ERR(st,
		    "missing reference to zonefile_iter to next");

       	if ((sc = reset_cur_piece(&i->p, st)))
		return sc;

	i->p.start = i->p.cur;
	if (!i->p.start)
		return p_zfi_at_end(i);

	if ((sc = p_zfi_get_piece(i, st)))
		return sc;

	return p_zfi_process_rr(i, st);
}

static status_code p_zfi_init(
    dns_config *cfg, zonefile_iter *i, return_status *st)
{
	status_code sc;

	if (!i)
		return RETURN_INTERNAL_ERR(st,
		    "missing reference to zonefile_iter to initialize");

	i->TTL      = cfg ? cfg->default_ttl   : DNS_DEFAULT_TTL;
	i->rr_class = cfg ? cfg->default_class : DNS_DEFAULT_CLASS;

	i->origin.spc_sz = 1024;
	i->origin.spc = NULL;
	i->origin.malloced = 1;

	if (cfg && cfg->default_origin
	&& (sc = p_zfi_set_dname( i, &i->origin, cfg->default_origin
	                        , strchr(cfg->default_origin, 0), st)))
		return sc;

	i->owner.spc_sz = 1024;
	i->owner.spc = NULL;
	i->owner.malloced = 1;

	return STATUS_OK;
}

status_code zonefile_iter_init_text_(dns_config *cfg, zonefile_iter *i,
    const char *text, size_t text_len, return_status *st)
{
	status_code sc;

	if (!i)
		return RETURN_USAGE_ERR(st,
		    "missing reference to zonefile_iter to initialize");

	(void) memset(i, 0, sizeof(*i));
	if ((sc = mmap_parser_init(&i->p, text, text_len, st)))
		return sc;
	
	return p_zfi_init(cfg, i, st);
}

status_code zonefile_iter_init_fn_(dns_config *cfg,
    zonefile_iter *i, const char *fn, return_status *st)
{
	status_code sc;
	
	if (!i)
		return RETURN_USAGE_ERR(st,
		    "missing reference to zonefile_iter to initialize");

	(void) memset(i, 0, sizeof(*i));
	if ((sc = mmap_parser_init_fn(&i->p, fn, st)))
		return sc;
	
	return p_zfi_init(cfg, i, st);
}


