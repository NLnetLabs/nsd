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
#include "pzl/dnsextlang.h"
#include "pzl/mmap_parser.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

void uint_table_free(size_t d, uint64_t n, const void *ptr, void *u)
{
	(void) d; (void) n; (void) u;
	free((void *)ptr);
}

status_code uint8_table_add(
    uint8_table **tabler, uint8_t value, const void *ptr, return_status *st)
{
	if (!tabler)
		return RETURN_USAGE_ERR(st,
		    "missing reference to uint8_table to register value");

	if (!*tabler && !(*tabler = calloc(256, sizeof(uint8_table))))
		return RETURN_MEM_ERR(st, "allocating uint8_table");

	if ((*tabler)[value])
		return RETURN_DATA_ERR(st, "data already exists at value");

	(*tabler)[value] = ptr;
	return STATUS_OK;
}

static inline void uint8_table_walk_(
    size_t depth, uint64_t n, uint8_table *table,
    uint_table_walk_func leaf, uint_table_walk_func branch, void *userarg)
{
	if (!table) return;
	if (leaf) {
		size_t i;
		for (i = 0; i < 255; i++)
			if (table[i])
				leaf( depth + 1, (n << 8) | i
				    , table[i], userarg);
	}
	if (branch)
		branch(depth, n, table, userarg);
}

void uint8_table_walk(uint8_table *table,
    uint_table_walk_func leaf, uint_table_walk_func branch, void *userarg)
{ uint8_table_walk_(0, 0, table, leaf, branch, userarg); }

#define DEF_UINT_TABLE_IMPL(HI,LO,UINT_T,MASK) \
	status_code uint ## HI ## _table_add( \
	    uint ## HI ## _table **table_r, UINT_T value, \
	    const void *ptr, return_status *st) \
	{ \
		if (!table_r) \
			return RETURN_USAGE_ERR(st, "missing reference to " \
			    "uint" #HI "_table to register value"); \
		if (!*table_r \
		&& !(*table_r = calloc(256, sizeof(uint ## HI ## _table)))) \
			return RETURN_MEM_ERR(st, \
			    "allocating uint_" #HI "table"); \
		return uint ## LO ## _table_add( \
		    &(*table_r)[(value >> LO) & 0xFF], value & MASK, ptr, st); \
	} \
	static inline void uint ## HI ## _table_walk_( \
	    size_t depth, uint64_t n,  uint ## HI ## _table *table, \
	    uint_table_walk_func leaf, uint_table_walk_func branch, \
	    void *userarg) \
	{ \
		size_t i; \
		if (!table) return; \
		for (i = 0; i < 255; i++) \
			if (table[i]) \
				uint ## LO ## _table_walk_( \
				    depth + 1, (n << 8) | i, \
				    table[i], leaf, branch, \
				    userarg); \
		if (branch) \
			branch(depth, n, table, userarg); \
	} \
	void uint ## HI ## _table_walk( \
	    uint ## HI ## _table *table, uint_table_walk_func leaf, \
	   uint_table_walk_func branch, void *userarg) \
	{ uint ## HI ## _table_walk_(0, 0, table, leaf, branch, userarg); }

DEF_UINT_TABLE_IMPL(16,  8, uint16_t, 0xFF)
DEF_UINT_TABLE_IMPL(24, 16, uint32_t, 0xFFFFUL)
DEF_UINT_TABLE_IMPL(32, 24, uint32_t, 0xFFFFFFUL)

/* Not needed, but...
 * DEF_UINT_TABLE_IMPL(40, 32, uint64_t, 0xFFFFFFFFULL)
 * DEF_UINT_TABLE_IMPL(48, 40, uint64_t, 0xFFFFFFFFFFULL)
 * DEF_UINT_TABLE_IMPL(56, 48, uint64_t, 0xFFFFFFFFFFFFULL)
 * DEF_UINT_TABLE_IMPL(64, 56, uint64_t, 0xFFFFFFFFFFFFFFULL)
 */

static inline void ldh_radix_strncasecpy(char *dst, const char *src, size_t n)
{ while (n--) *dst++ = toupper(*src++); }

status_code ldh_radix_insert(ldh_radix **r,
    const char *str, size_t len, const void *value, return_status *st)
{
	char *n_label;
	const char *r_label;
	size_t r_len, n_len;
	ldh_radix *n;

	if (!r)
		return RETURN_USAGE_ERR(st,
		    "missing reference to ldh_radix to register value");

	if (!*r) {
		if (!(*r = calloc(1, sizeof(ldh_radix) + len + 1)))
			return RETURN_MEM_ERR(st, "allocating ldh_radix");
		n_label = (void *)&(*r)->edges[LDH_N_EDGES];
		(*r)->label = n_label;
		(*r)->len = len;
		ldh_radix_strncasecpy(n_label, str, len);
		n_label[len] = 0;
		(*r)->value = value;
		return STATUS_OK;
	}
	for (r_label = (*r)->label, r_len = (*r)->len
	    ; len; str++, len--, r_label++, r_len--) {
		if (!r_len)
			return ldh_radix_insert(
			    &(*r)->edges[(toupper(*str) - '-')
			                % LDH_N_EDGES],
			    str, len, value, st);

		if (toupper(*str) != *r_label)
			break;
	};
	if (!len && !r_len) {
		(*r)->value = value;
		return STATUS_OK;
	}

	n_len = (*r)->len - r_len;
	if (!(n = calloc(1, sizeof(ldh_radix) + n_len + 1)))
		return RETURN_MEM_ERR(st, "allocating ldh_radix");
	n_label = (void *)&n->edges[LDH_N_EDGES];
	n->label = n_label;
	n->len = n_len;
	ldh_radix_strncasecpy(n_label, (*r)->label, n_len);
	n_label[n_len] = 0;
	
	(*r)->label = r_label;
	(*r)->len = r_len;
	n->edges[(toupper(*r_label) - '-') % LDH_N_EDGES] = *r;
	*r = n;

	if (len)
		return ldh_radix_insert(
		    &(*r)->edges[(toupper(*str) - '-') % LDH_N_EDGES],
		    str, len, value, st);

	n->value = value;
	return STATUS_OK;
}

status_code ldh_radix_walk(char *buf, size_t bufsz, ldh_radix *r,
    ldh_radix_walk_func func, void *userarg, return_status *st)
{
	size_t i, l = 0;
	char *mybuf;
	status_code c;

	if (!r)
		return RETURN_USAGE_ERR(st, "no ldh_radix to walk");

	if (buf && !bufsz)
		return RETURN_USAGE_ERR(st, "buffer without size");

	if ((mybuf = buf)) {
		l = strlen(buf);
		if (l + r->len >= bufsz) {
			while (l + r->len >= bufsz)
				bufsz *= 2;
			if (mybuf != buf)
				free(mybuf);
			if (!(mybuf = calloc(1, bufsz)))
				RETURN_MEM_ERR(st, "could not grow buffer");
			(void) memcpy(mybuf, buf, l);
			mybuf[l] = 0;
		}
		(void) memcpy(mybuf + l, r->label, r->len);
		mybuf[l + r->len] = 0;
	}
	for (i = 0; i < LDH_N_EDGES; i++) {
		if (!r->edges[i])
			continue;
		c = ldh_radix_walk(
		    mybuf, bufsz, r->edges[i], func, userarg, st);
		if (mybuf)
			mybuf[l + r->len] = 0;
		if (c) {
			if (mybuf != buf)
				free(mybuf);
			return c;
		}
	}
	c = func(mybuf, r, userarg, st);
	if (mybuf) {
		if (mybuf != buf)
			free(mybuf);
		buf[l] = 0;
	}
	return c;
}

status_code ldh_trie_insert(ldh_trie **rr,
    const char *str, size_t len, const void *value, return_status *st)
{
       if (!rr)
               return RETURN_USAGE_ERR(st,
                   "missing reference to ldh_trie to register value");

       for (;;) {
               if (!*rr && !(*rr = calloc(1, sizeof(ldh_trie))))
                       return RETURN_MEM_ERR(st, "allocating ldh_trie");
               if (!len)
                       break;

               rr = &(*rr)->edges[(toupper(*str) - '-') % LDH_N_EDGES];
               str++;
               len--;
       }
       (*rr)->value = value;
       return STATUS_OK;
}

status_code ldh_trie_walk(char *buf, size_t bufsz, ldh_trie *r,
    ldh_trie_walk_func func, void *userarg, return_status *st)
{
	size_t i, l = 0;
	char *mybuf;
	status_code c;

	if (!r)
		return RETURN_USAGE_ERR(st, "no ldh_trie to walk");

	if (buf && !bufsz)
		return RETURN_USAGE_ERR(st, "buffer without size");

	if ((mybuf = buf)) {
		l = strlen(buf);
		if (l + 2 >= bufsz) {
			while (l + 2 >= bufsz)
				bufsz *= 2;
			if (mybuf != buf)
				free(mybuf);
			if (!(mybuf = calloc(1, bufsz)))
				RETURN_MEM_ERR(st, "could not grow buffer");
			(void) memcpy(mybuf, buf, l);
			mybuf[l] = 0;
		}
		mybuf[l + 1] = 0;
	}
	for (i = 0; i < LDH_N_EDGES; i++) {
		if (!r->edges[i])
			continue;
		if (mybuf)
			mybuf[l] = '-' + i;
		c = ldh_trie_walk(
		    mybuf, bufsz, r->edges[i], func, userarg, st);
		if (c) {
			if (mybuf != buf)
				free(mybuf);
			return c;
		}
	}
	if (mybuf)
		mybuf[l] = 0;
	c = func(mybuf, r, userarg, st);
	if (mybuf && mybuf != buf)
		free(mybuf);
	return c;
}

static status_code p_del_free_ldh_radix(
    char *str, ldh_radix *r, void *userarg, return_status *st)
{
	(void) str; (void) userarg; (void) st;
	free(r); return STATUS_OK;
}

static status_code p_del_free_ldh_cont(
    char *str, LDH_CONTAINER *r, void *userarg, return_status *st)
{
	(void) str; (void) userarg; (void) st;
	free(r); return STATUS_OK;
}

static inline void p_del_stanza_free(dnsextlang_stanza *s)
{
	size_t i;

	if (!s)
		return;
	if (s->name)
		free((char *)s->name);
	if (s->description)
		free((char *)s->description);
	for (i = 0; i < s->n_fields; i++) {
		dnsextlang_field *f = &s->fields[i];

		if (f->tag)
			free((char *)f->tag);
		if (f->description)
			free((char *)f->description);
		if (!f->symbols_by_ldh)
			continue;
		switch (f->ftype) {
		case del_ftype_I1:
			uint8_table_walk(f->symbols_by_int.I1,
			    uint_table_free, uint_table_free, NULL);
			break;
		case del_ftype_I2:
			uint16_table_walk(f->symbols_by_int.I2,
			    uint_table_free, uint_table_free, NULL);
			break;
		case del_ftype_I4:
			uint32_table_walk(f->symbols_by_int.I4,
			    uint_table_free, uint_table_free, NULL);
			break;
		default:
			assert(f->ftype == del_ftype_I1
			    || f->ftype == del_ftype_I2
			    || f->ftype == del_ftype_I4);
		}
		(void) ldh_radix_walk(NULL, 0, f->symbols_by_ldh,
		    p_del_free_ldh_radix, NULL, NULL);
	}
	free(s);
}

static inline status_code p_del_def_add_stanza(
    dnsextlang_def *d, dnsextlang_stanza *s, return_status *st)
{
	status_code c;

	if (!d)
		return RETURN_INTERNAL_ERR(st,
		    "reference to dnsextlang_def missing");
	if (!s)
		return RETURN_INTERNAL_ERR(st,
		    "reference to dnsextlang_stanza missing");
	if (!s->name)
		return RETURN_INTERNAL_ERR(st,
		    "dnsextlang_stanza had no name");

	if (dnsextlang_lookup__(d, s->name, strlen(s->name), NULL))
		return RETURN_DATA_ERR(st,
		    "stanza with name already exsist");

	if (dnsextlang_get_stanza_(d, s->number))
		return RETURN_DATA_ERR(st,
		    "stanza with number already exsist");

	if ((c = uint16_table_add(&d->stanzas_by_u16, s->number, s, st)))
		return c;

	return LDH_INSERT(
	    &d->stanzas_by_ldh, s->name, strlen(s->name), s, st);
}

/* Caller should produce MEM_ERR */
static inline char *p_del_strdup(const char *start, const char *end)
{
	char *str;

	if (!start || !end)
		return (char *)calloc(1, 1);

	assert(end > start);
	if (!(str = (char *)malloc(end - start + 1)))
		return NULL;
	(void) memcpy(str, start, end - start);
	str[end - start] = 0;
	return str;
}

static inline int p_scan_ftype(const char **p, const char *e)
{
	if (*p >= e) return -1;
	switch (toupper(*(*p)++)) {
	case 'I': if (*p >= e) return -1;
                  switch (*(*p)++) {
                  case '1': return del_ftype_I1;
                  case '2': return del_ftype_I2;
                  case '4': return del_ftype_I4;
	          default : return -1;
	          }
	case 'A': if (*p >= e || toupper(**p) != 'A')
	                  return del_ftype_A;
	          else if (++(*p) + 1 >= e || toupper(**p) != 'A'
	                                   || toupper((*p)[1]) != 'A')
	                  return del_ftype_AA;
		  else {
			  *p += 2;
	                  return del_ftype_AAAA;
		  }
	case 'X': if (*p >= e) return del_ftype_X;
                  switch (**p) {
                  case '6': *p += 1;
			    return del_ftype_X6;
                  case '8': *p += 1;
			    return del_ftype_X8;
	          default : return del_ftype_X;
	          }
	case 'T': if (*p >= e || **p != '6')
			  return del_ftype_T;
		  else {
			  *p += 1;
			  return del_ftype_T6;
		  }
	case 'E': if (*p + 4 >= e
	          ||  toupper((*p)[0]) != 'U'
		  ||  toupper((*p)[1]) != 'I') return -1;
		  if (toupper((*p)[2]) == '4'
	          &&  toupper((*p)[3]) == '8') {
			  *p += 4;
			  return del_ftype_EUI48;
		  }
		  if (toupper((*p)[2]) == '6'
	          &&  toupper((*p)[3]) == '4') {
			  *p += 4;
			  return del_ftype_EUI64;
		  }
		  return -1;
	case 'R': return del_ftype_R;
	case 'N': return del_ftype_N;
	case 'S': return del_ftype_S;
	case 'B': if (*p + 2 >= e) return -1;
	          if ((*p)[0] == '3' && (*p)[1] == '2') {
			  *p += 2;
			  return del_ftype_B32;
		  }
	          if ((*p)[0] == '6' && (*p)[1] == '4') {
			  *p += 2;
			  return del_ftype_B64;
		  }
		  return -1;
	case 'Z': return del_ftype_Z;
	default : return -1;
	}
}

static inline int p_lookup_qual(const char *s, const char *e)
{
	switch (e - s) {
	case 1: switch (*s) {
		case 'C': case 'c': return del_qual_C;
		case 'A': case 'a': return del_qual_A;
		case 'L': case 'l': return del_qual_L;
		case 'O': case 'o': return del_qual_O;
		case 'M': case 'm': return del_qual_M;
		case 'X': case 'x': return del_qual_X;
		case 'P': case 'p': return del_qual_P;
		default : return -1;
		}
	case 3: switch (*s) {
		case 'W': case 'w': return ( s[1] == 'K' || s[1] == 'k')
		                        && ( s[2] == 'S' || s[2] == 's')
		                         ? del_qual_WKS : -1;
		case 'N': case 'n': return ( s[1] == 'X' || s[1] == 'x')
		                        && ( s[2] == 'T' || s[2] == 't')
		                         ? del_qual_NXT : -1;
		case 'A':
		case 'a': switch (s[1]) {
		          case '6': return ( s[2] == 'P' || s[2] == 'p' )
		                         ? del_qual_A6P
		                         : ( s[2] == 'S' || s[2] == 's' )
		                         ? del_qual_A6S : -1;
		          case 'P':
		          case 'p': return ( s[2] == 'L' || s[2] == 'l' )
		                         ? del_qual_APL : -1;
		          default : return -1;
		          }
		default : return -1;
		}
	case 4: return strncasecmp(s, "NSAP"    , 4) ? -1 : del_qual_NSAP;
	case 8: return strncasecmp(s, "IPSECKEY", 8) ? -1 : del_qual_IPSECKEY;
	case 6: return strncasecmp(s, "HIPHIT"  , 6) ? -1 : del_qual_HIPHIT;
	case 5: return strncasecmp(s, "HIPPK"   , 5) ? -1 : del_qual_HIPPK;
	default: return -1;
	}
}

static inline status_code p_del_parse_quals(dnsextlang_field *f,
    parse_piece *p, return_status *st)
{
	const char *s;

	s = p->start;
	while (s < p->end) {
		const char *e, *eq = NULL;

		while ((s < p->end     && isspace(*s))
		   ||  (s < p->end - 1 && *s == '\\' && isspace(s[1])))
			s++;
		if (s >= p->end)
			return STATUS_OK;

		e = s;
		if (!isalpha(*e)) {
			return RETURN_PARSE_ERR(st,
			    "qualifiers must start with an alpha character",
			    p->fn, p->line_nr, p->col_nr + (e - p->start));
		}
		while (e < p->end && (isalnum(*e) || *e == '-'))
			e++;
		if (e < p->end && *e == '=') {
			char numbuf[30] = "", *endptr;
			long long int ll, *ll_ptr;
			status_code c;
			char *symbol;

			eq = e;
			if (++e >= p->end || !isdigit(*e))
				return RETURN_PARSE_ERR(st,
				    "missing number after equal sign",
				    p->fn, p->line_nr,
				    p->col_nr + (e - p->start));
			while (e < p->end && isdigit(*e))
				e++;
			assert(e > (eq + 1));
			if (e - (eq + 1) >= (int)sizeof(numbuf))
				return RETURN_PARSE_ERR(st,
				    "numeric field",
				    p->fn, p->line_nr,
				    p->col_nr + (eq + 1 - p->start));

			(void) memcpy(numbuf, eq + 1, e - (eq + 1));
			numbuf[e - (eq + 1)] = 0;
			ll = strtoll(numbuf, &endptr, 10);
			if (!*numbuf || *endptr)
				return RETURN_PARSE_ERR(st,
				    "numeric field",
				    p->fn, p->line_nr,
				    p->col_nr + (eq + 1 - p->start));

			if (!(symbol = p_del_strdup(s, eq)))
				return RETURN_MEM_ERR(st,
				    "could not duplicate symbolic field value");
			switch (f->ftype) {
			case del_ftype_I1:
				if (ll > 255) {
					free(symbol);
					return RETURN_PARSE_ERR(st,
					    "I1 field value must be < 256",
					    p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				}
				if ((c = uint8_table_add(
				    &f->symbols_by_int.I1, ll, symbol, st))) {
					free(symbol);
					return RETURN_PARSE_ERR(st,
					    "could not add value",
					    p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				}
				break;

			case del_ftype_I2:
				if (ll > 65535)
					return RETURN_PARSE_ERR(st,
					    "I2 field value must be < 65536",
					    p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				if ((c = uint16_table_add(
				    &f->symbols_by_int.I2, ll, symbol, st))) {
					free(symbol);
					return RETURN_PARSE_ERR(st,
					    "could not add value",
					    p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				}
				break;

			case del_ftype_I4:
				if (ll > 4294967295)
					return RETURN_PARSE_ERR(st,
					    "I4 field value must be "
					    "< 4294967296", p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				if ((c = uint32_table_add(
				    &f->symbols_by_int.I4, ll, symbol, st))) {
					free(symbol);
					return RETURN_PARSE_ERR(st,
					    "could not add value",
					    p->fn, p->line_nr,
					    p->col_nr + (eq + 1 - p->start));
				}
				break;
			default:
				free(symbol);
				return RETURN_PARSE_ERR(st,
				    "symbolic values allowed with "
				    "integer fields only",
				    p->fn, p->line_nr,
				    p->col_nr + (s - p->start));
			}
			if (!(ll_ptr = calloc(1, sizeof(ll)))) {
				free(symbol);
				return RETURN_MEM_ERR(st,
				    "could not duplicate numeric field value");
			}
			*ll_ptr = ll;
			if ((c = ldh_radix_insert(
			    &f->symbols_by_ldh, s, eq - s, ll_ptr, st))) {
				free(ll_ptr);
				free(symbol);
				return RETURN_PARSE_ERR(st,
				    "could not add symbol",
				    p->fn, p->line_nr,
				    p->col_nr + (s - p->start));
			}
		} else {
			int q = p_lookup_qual(s, e);

			if (q < 0)
				return RETURN_PARSE_ERR(st,
				    "unknown qualifier",
				    p->fn, p->line_nr,
				    p->col_nr + (s - p->start));
			f->quals |= q;
		}

		/* skip white space */
		s = e;
		while ((s < p->end     && isspace(*s))
		   ||  (s < p->end - 1 && *s == '\\' && isspace(s[1])))
			s++;

		/* skip comma */
		if (s < p->end && *s == ',')
			s++;

		else if (s < p->end)
			return RETURN_PARSE_ERR(st, "comma expected",
			    p->fn, p->line_nr, p->col_nr + (s - p->start));
	}
	return STATUS_OK;
}

static inline dnsextlang_stanza *p_err(dnsextlang_stanza *r, status_code code)
{
	(void) code;
	p_del_stanza_free(r);
	return NULL;
}

dnsextlang_stanza *dnsextlang_stanza_new_from_pieces(
   parse_piece *piece, size_t n_pieces, return_status *st)
{
	dnsextlang_stanza *r = NULL;
	const char *s, *e;
	char numbuf[6], *endptr;
	unsigned long int n;
	dnsextlang_field *f;
       
	if (!piece)
		return p_err(r, RETURN_INTERNAL_ERR(st,
		    "missing reference to pieces"));

	if (!n_pieces)
		return p_err(r, RETURN_DATA_ERR(st,
		    "at least one piece needed to construct stanza"));

	if (piece->end == piece->start)
		return p_err(r, RETURN_DATA_ERR(st, "empty first piece"));

	if (piece->end < piece->start)
		return p_err(r, RETURN_INTERNAL_ERR(st,
		    "malformed first piece"));

	if (!isalpha(*piece->start))
		return p_err(r, RETURN_PARSE_ERR(st,
		    "stanza name must start with alpha character",
		    piece->fn, piece->line_nr, piece->col_nr));

	for (s = e = piece->start; e < piece->end; e++)
		if (!isalnum(*e) && *e != '-')
			break;

	if (e >= piece->end || *e != ':')
		return p_err(r, RETURN_PARSE_ERR(st, "colon expected",
		    piece->fn, piece->line_nr, piece->col_nr + (e - s)));

	if (!(r = calloc(1, sizeof(dnsextlang_stanza)
	                  + sizeof(dnsextlang_field) * (n_pieces - 1))))
		return p_err(r, RETURN_MEM_ERR(st,
		    "allocating dnsextlang_stanza"));
	r->fields = (void *)((uint8_t *)r + sizeof(dnsextlang_stanza));

	if (!(r->name = p_del_strdup(s, e)))
		return p_err(r, RETURN_MEM_ERR(st, "duplicating name"));

	for (s = ++e; e < piece->end; e++)
		if (!isdigit(*e) && *e != '-')
			break;
	if (e == s)
		return p_err(r, RETURN_PARSE_ERR(st,
		    "stanza number missing", piece->fn, piece->line_nr,
		    piece->col_nr + (s - piece->start)));

	if (e - s > (int)sizeof(numbuf) - 1)
		return p_err(r, RETURN_PARSE_ERR(st,
		    "stanza number too large", piece->fn, piece->line_nr,
		    piece->col_nr + (s - piece->start)));

	(void) memcpy(numbuf, s, e - s);
	numbuf[e - s] = 0;
	n = strtoul(numbuf, &endptr, 10);
	if (*endptr || n > 65535)
		return p_err(r, RETURN_PARSE_ERR(st,
		    "stanza number overflow", piece->fn, piece->line_nr,
		    piece->col_nr + (s - piece->start)));
	r->number = n;

	if (e < piece->end && *e == ':') {
		for (s = ++e; e < piece->end; e++)
			if (isalpha(*e))
				r->options |= (1 << (toupper(*e) - 'A'));
			else
				break;
	}
	if (e < piece->end) {
		if (!isspace(*e)) 
			return p_err(r, RETURN_PARSE_ERR(st,
			    "colon + options or white space expected",
			    piece->fn, piece->line_nr,       
	                    piece->col_nr + (e - piece->start)));
		/* trim whitespace */
		for (s = ++e; s < piece->end && isspace(*s); s++)
			; /* pass */
		for (e = piece->end - 1; e + 1 > s && isspace(*e); e--)
			; /* pass */
		if (e + 1 > s && !(r->description = p_del_strdup(s, e + 1)))
			return p_err(r, RETURN_MEM_ERR(st,
			    "duplicating description"));
	}
	r->n_fields = --n_pieces;
	piece++;
	for (f = r->fields; n_pieces > 0; n_pieces--, f++, piece++) {
		int ft;

		s = e = piece->start;
		ft = p_scan_ftype(&e, piece->end);
		if (ft < 0)
			return p_err(r, RETURN_PARSE_ERR(st,                            
	                    "unknown field type",
			    piece->fn, piece->line_nr,       
	                    piece->col_nr));
		f->ftype = ft;
		if (e >= piece->end)
			continue;
		if (*e == '[') {
			parse_piece tmp_p;

			/* Just skip for now */
			s = ++e;
			while (e < piece->end && *e != ']')
				e++;
			tmp_p.start = s; tmp_p.end = e;
			tmp_p.fn = piece->fn;
			tmp_p.line_nr = piece->line_nr;
			tmp_p.col_nr = piece->col_nr + (s - piece->start);
			if (p_del_parse_quals(f, &tmp_p, st)) {
				p_del_stanza_free(r);
				return NULL;
			}
			if (e >= piece->end || ++e >= piece->end)
				continue;
		}
		if (*e == ':') {
			s = ++e;
			while (e < piece->end && !isspace(*e))
				e++;
			if (e > s && !(f->tag = p_del_strdup(s, e)))
				return p_err(r, RETURN_MEM_ERR(st,
				    "duplicating field tag"));
			if (e >= piece->end)
				continue;
		}
		/* trim whitespace */
		for (s = ++e; s < piece->end && isspace(*s); s++)
			; /* pass */
		for (e = piece->end - 1; e + 1 > s && isspace(*e); e--)
			; /* pass */
		if (e + 1 > s && !(f->description = p_del_strdup(s, e + 1)))
			return p_err(r, RETURN_MEM_ERR(st,
			    "duplicating field description"));
	}
	return r;
}

static inline mmap_parser *p_dfi_return(mmap_parser *p, return_status *st)
{
	if (p->cur_piece == p->pieces && !p->cur_piece->start) {
		assert(p->cur == p->end);
		mmap_parser_free_in_use(p);
		return NULL; /* End of text to parse */
	}
	if (p->cur_piece->start && !p->cur_piece->end) {
		p->cur_piece->end = p->cur;
		p->cur_piece += 1;
		p->cur_piece->start = NULL;
	}
	assert(p->pieces->start);
	p->start = p->pieces->start;
	return mmap_parser_progressive_munmap(p, st) ? NULL : p;
}

static inline mmap_parser *p_dfi_get_fields(mmap_parser *p, return_status *st)
{
	while (p->cur < p->end) {
		p->sol = p->cur;

		if (isalpha(*p->cur)) /* Start of stanza */
			return p_dfi_return(p, st);

		while (*p->cur != '\n' && isspace(*p->cur)) {
			if (++p->cur >= p->end)
				return p_dfi_return(p, st);
		}
		switch (*p->cur) {
		case '#' :
			if (++p->cur >= p->end)
				return p_dfi_return(p, st);
			while (*p->cur != '\n') {
				if (++p->cur >= p->end)
					return p_dfi_return(p, st);
			}
			p->cur += 1;
			p->line_nr += 1;
			break;
		case '\n':
			p->cur += 1;
			p->line_nr += 1;
			break;
		default:
			/* Start of field */
			if (equip_cur_piece(p, st))
				return NULL;
			while (*p->cur != '\n' && *p->cur != '#') {
				if (p->cur[0] == '\\' && p->cur + 1 < p->end
				&&  p->cur[1] == '\n') {
					p->line_nr += 1;
					p->cur += 1;
				}
				if (++p->cur >= p->end)
					return p_dfi_return(p, st);
			}
			if (increment_cur_piece(p, st))
				return NULL;

			if (*p->cur == '#') {
				p->cur += 1;
				while (*p->cur != '\n') {
					if (++p->cur >= p->end)
						return p_dfi_return(p, st);
				}
			}
			p->cur += 1;
			p->line_nr += 1;
			break;
		}
	}
	return p_dfi_return(p, st);
}

static inline mmap_parser *p_dfi_next(mmap_parser *p, return_status *st)
{
	if (reset_cur_piece(p, st))
		return NULL;
	while (p->cur < p->end) {
		p->sol = p->cur;

		if (isalpha(*p->cur)) {
			if (equip_cur_piece(p, st))
				return NULL;
			if (++p->cur >= p->end)
				return p_dfi_return(p, st);
			while (*p->cur != '\n' && *p->cur != '#') {
				if (p->cur[0] == '\\' && p->cur + 1 < p->end
				&&  p->cur[1] == '\n') {
					p->line_nr += 1;
					p->cur += 1;
				}
				if (++p->cur >= p->end)
					return p_dfi_return(p, st);
			}
			if (increment_cur_piece(p, st))
				return NULL;
			if (*p->cur == '#') {
				p->cur += 1;
				while (*p->cur != '\n') {
					if (++p->cur >= p->end)
						return p_dfi_return(p, st);
				}
			}
			p->cur += 1;
			p->line_nr += 1;
			return p_dfi_get_fields(p, st);
		}
		while (*p->cur != '\n' && isspace(*p->cur)) {
			if (++p->cur >= p->end)
				return p_dfi_return(p, st);
		}
		switch (*p->cur) {
		case '#' :
			if (++p->cur >= p->end)
				return p_dfi_return(p, st);
			while (*p->cur != '\n') {
				if (++p->cur >= p->end)
					return p_dfi_return(p, st);
			}
			p->cur += 1;
			p->line_nr += 1;
			break;
		case '\n':
			p->cur += 1;
			p->line_nr += 1;
			break;
		default:
			(void) RETURN_PARSE_ERR(st,
			    "dnsextlang stanza's start at beginning of a line",
			    p->fn, p->line_nr, p->cur - p->sol);
			return NULL;
		}
	}
	return p_dfi_return(p, st);
}

static
dnsextlang_def *p_dfi2def(dns_config *cfg, mmap_parser *i, return_status *st)
{
	dnsextlang_def *d = calloc(1, sizeof(dnsextlang_def));
	mmap_parser *j = i;
	return_status my_st;

	return_status_reset(&my_st);
	if (!st)
		st = &my_st;

	if (!d) {
		(void) RETURN_MEM_ERR(st,
		    "cannot allocate space for dnsextlang definitions");
		mmap_parser_free_in_use(j);
		return NULL;
	}

	while ((i = p_dfi_next(i, st))) {
		dnsextlang_stanza *s;

		if (!(s = dnsextlang_stanza_new_from_pieces(
		    i->pieces, (i->cur_piece - i->pieces), st)))
			break;

		if (p_del_def_add_stanza(d, s, st))
			break;
	}
	if (i || st->code)
		mmap_parser_free_in_use(j);

	if (st->code) {
		dnsextlang_def_free(d);
		return NULL;
	}
	d->fallback = cfg->rrtypes;
	return d;
}

dnsextlang_def *dnsextlang_def_new_from_text_(
    dns_config *cfg, const char *text, size_t text_len, return_status *st)
{
	mmap_parser p;
	return mmap_parser_init(&p, text, text_len, st)
	     ? NULL : p_dfi2def(cfg, &p, st);
}

dnsextlang_def *dnsextlang_def_new_from_fn_(
    dns_config *cfg, const char *fn, return_status *st)
{
	mmap_parser p;
	return mmap_parser_init_fn(&p, fn, st) ? NULL : p_dfi2def(cfg, &p, st);
}

static void p_del_free_stanza(
    size_t depth, uint64_t number, const void *ptr, void *userarg)
{
	(void) depth; (void) number; (void) userarg;
	p_del_stanza_free((dnsextlang_stanza *)ptr);
}

void dnsextlang_def_free(dnsextlang_def *d)
{
	if (!d)
		return;
	uint16_table_walk(d->stanzas_by_u16,
	    p_del_free_stanza, uint_table_free, NULL);
	(void) LDH_WALK(
	    NULL, 0, d->stanzas_by_ldh, p_del_free_ldh_cont, NULL, NULL);
	free(d);
}

// dnsextlang_def *dns_default_rrtypes = NULL;
