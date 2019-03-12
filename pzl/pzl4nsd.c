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
#include "zonec.h"
#include "rdata.h"
#include <pthread.h>

/* #define PRINT_DOMAIN_TABLES */
#ifndef NDEBUG
int print_rrs(FILE* out, struct zone* zone);
#endif
/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */
static int
pzl_zrdatacmp(uint16_t type, const rr_type *a, const rr_type *b)
{
	int i = 0;

	assert(a);
	assert(b);

	/* One is shorter than another */
	if (a->rdata_count != b->rdata_count)
		return 1;

	/* Compare element by element */
	for (i = 0; i < a->rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(a->rdatas[i])
			    != rdata_atom_domain(b->rdatas[i]))
			{
				return 1;
			}
		} else if(rdata_atom_is_literal_domain(type, i)) {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
				return 1;
			if (!dname_equal_nocase(rdata_atom_data(a->rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])))
				return 1;
		} else {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
			{
				return 1;
			}
			if (memcmp(rdata_atom_data(a->rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])) != 0)
			{
				return 1;
			}
		}
	}

	/* Otherwise they are equal */
	return 0;
}

static int
pzl_has_soa(const domain_type* domain)
{
        rrset_type* p = NULL;
        if(!domain) return 0;
        for(p = domain->rrsets; p; p = p->next)
                if(rrset_rrtype(p) == TYPE_SOA)
                        return 1;
        return 0;
}

/* TODO: Should return status_code and set return_status to make thread safe */
static int pzl_process_rr(region_type *region, zone_type *zone, rr_type *rr)
{
	rrset_type *rrset;
	size_t max_rdlength;
	int i;
	rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(rr->type);

	/* We only support IN class */
	if (rr->klass != CLASS_IN) {
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("only class IN is supported");
		else
			zc_error_prev_line("only class IN is supported");
		return 0;
	}

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.	*/
	max_rdlength = rdata_maximum_wireformat_size(
		descriptor, rr->rdata_count, rr->rdatas);

	if (max_rdlength > MAX_RDLENGTH) {
		zc_error_prev_line("maximum rdata length exceeds %d octets", MAX_RDLENGTH);
		return 0;
	}
	/* we have the zone already */
	assert(zone);
	if (rr->type == TYPE_SOA) {
		if (rr->owner != zone->apex) {
			zc_error_prev_line(
				"SOA record with invalid domain name");
			return 0;
		}
		if(pzl_has_soa(rr->owner)) {
			if(zone_is_slave(zone->opts))
				zc_warning_prev_line("this SOA record was already encountered");
			else
				zc_error_prev_line("this SOA record was already encountered");
			return 0;
		}
		rr->owner->is_apex = 1;
	}

	if (!domain_is_subdomain(rr->owner, zone->apex))
	{
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("out of zone data");
		else
			zc_error_prev_line("out of zone data");
		return 0;
	}

	/* Do we have this type of rrset already? */
	rrset = domain_find_rrset(rr->owner, zone, rr->type);
	if (!rrset) {
		rrset = (rrset_type *) region_alloc(region, sizeof(rrset_type));
		rrset->zone = zone;
		rrset->rr_count = 1;
		rrset->rrs = (rr_type *) region_alloc(region, sizeof(rr_type));
		rrset->rrs[0] = *rr;

		/* Add it */
		/* TODO: Replace with fast add_rrset and deal with is_existing
		 * parent and wildcard_child_closest_match later
		 */
		domain_add_rrset(rr->owner, rrset);
	} else {
		rr_type* o;
		if (rr->type != TYPE_RRSIG && rrset->rrs[0].ttl != rr->ttl) {
			zc_warning_prev_line(
				"%s TTL %u does not match the TTL %u of the %s RRset",
				domain_to_string(rr->owner), (unsigned)rr->ttl,
				(unsigned)rrset->rrs[0].ttl,
				rrtype_to_string(rr->type));
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rr_count; i++) {
			if (!pzl_zrdatacmp(rr->type, rr, &rrset->rrs[i])) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rr_count) {
			return 1;
		}
		if(rrset->rr_count == 65535) {
			zc_error_prev_line("too many RRs for domain RRset");
			return 0;
		}

		/* Add it... */
		o = rrset->rrs;
		rrset->rrs = (rr_type *) region_alloc_array(region,
			(rrset->rr_count + 1), sizeof(rr_type));
		memcpy(rrset->rrs, o, (rrset->rr_count) * sizeof(rr_type));
		region_recycle(region, o, (rrset->rr_count) * sizeof(rr_type));
		rrset->rrs[rrset->rr_count] = *rr;
		++rrset->rr_count;
	}

	if(rr->type == TYPE_DNAME && rrset->rr_count > 1) {
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("multiple DNAMEs at the same name");
		else
			zc_error_prev_line("multiple DNAMEs at the same name");
	}
	if(rr->type == TYPE_CNAME && rrset->rr_count > 1) {
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("multiple CNAMEs at the same name");
		else
			zc_error_prev_line("multiple CNAMEs at the same name");
	}
	if((rr->type == TYPE_DNAME && domain_find_rrset(rr->owner, zone, TYPE_CNAME))
	 ||(rr->type == TYPE_CNAME && domain_find_rrset(rr->owner, zone, TYPE_DNAME))) {
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("DNAME and CNAME at the same name");
		else
			zc_error_prev_line("DNAME and CNAME at the same name");
	}
	if(domain_find_rrset(rr->owner, zone, TYPE_CNAME) &&
		domain_find_non_cname_rrset(rr->owner, zone)) {
		if(zone_is_slave(zone->opts))
			zc_warning_prev_line("CNAME and other data at the same name");
		else
			zc_error_prev_line("CNAME and other data at the same name");
	}
	return 1;
}

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
			return NULL;
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

static unsigned int piece2uint(parse_piece *p, const char **endptr)
{
	unsigned int i = 0;

	for (*endptr = p->start;  *endptr < p->end ; (*endptr)++) {
		if (!isdigit(**endptr))
			return i;
		if ((i * 10) / 10 != i)
			/* number too large, return i
			 * with *endptr != 0 as a failure*/
			return i;
		i *= 10;
		i += (**endptr - '0');
	}
	return i;
}

typedef struct pieces_iter {
	parse_piece *cur;
	parse_piece *end;
} pieces_iter;

#define pieces_iter_stopped_parse_error(PI, ST, MSG) \
    RETURN_PARSE_ERR((ST), (MSG), \
        ((PI)->end - 1)->fn, ((PI)->end - 1)->line_nr, \
	((PI)->end - 1)->col_nr \
	    + (((PI)->end - 1)->end - ((PI)->end - 1)->start))

#define pieces_iter_parse_error(PI, ST, MSG) ((PI)->cur >= (PI)->end \
    ? pieces_iter_stopped_parse_error((PI), (ST), (MSG)) \
    : RETURN_PARSE_ERR((ST), (MSG), \
          (PI)->cur->fn, (PI)->cur->line_nr, (PI)->cur->col_nr))

static inline status_code pieces_iter_next(pieces_iter *i)
{
	return ++i->cur < i->end ? STATUS_OK : STATUS_STOP_ITERATION;
}

static inline status_code pieces_iter_init(
    pieces_iter *i, parse_piece *start, parse_piece *end)
{
	i->cur = start;
	i->end = end;
	return start < end ? STATUS_OK : STATUS_STOP_ITERATION;
}

static inline int pieces_iter_last(pieces_iter *i)
{ return i->cur == i->end - 1; }

static inline size_t pieces_iter_len(pieces_iter *i)
{ return i->cur->end - i->cur->start; }

typedef struct piece_char_iter {
	pieces_iter *pi;
	const char  *ch;
} pieces_char_iter;

static inline status_code pieces_char_iter_parse_error(
    pieces_char_iter *i, return_status *st, const char *msg)
{
	return RETURN_PARSE_ERR(
	    st, msg, i->pi->cur->fn, i->pi->cur->line_nr,
	    i->pi->cur->col_nr + (i->ch - i->pi->cur->start));
}

static inline status_code pieces_char_iter_init_ch(pieces_char_iter *i)
{
	do if ((i->ch = i->pi->cur->start) < i->pi->cur->end)
		return STATUS_OK;
	while (!pieces_iter_next(i->pi));
	return STATUS_STOP_ITERATION;
}

static inline status_code pieces_char_iter_next(pieces_char_iter *i)
{
	return ++i->ch < i->pi->cur->end ? STATUS_OK
	     : pieces_iter_next(i->pi)   ? STATUS_STOP_ITERATION
	     : pieces_char_iter_init_ch(i);
}

static inline status_code pieces_char_iter_init(
    pieces_char_iter *i, pieces_iter *pi)
{
	i->pi = pi;
	return pi->cur < pi->end ? pieces_char_iter_init_ch(i)
	                         : STATUS_STOP_ITERATION;
}

static inline status_code pzl_conv_hex_rdata(
    pieces_iter *pi, uint8_t *t, size_t *olen, return_status *st)
{
	status_code sc;
	pieces_char_iter pci;
	uint8_t *t_start = t;
	uint8_t *t_end = t + *olen;

	for ( sc = pieces_char_iter_init(&pci, pi)
	    ; sc == STATUS_OK && t < t_end
	    ; sc = pieces_char_iter_next(&pci), t++) {
		if (!isxdigit(*pci.ch))
			return pieces_char_iter_parse_error(
			    &pci, st, "hex digit expected");
		*t = hexdigit_to_int(*pci.ch) * 16;
		if ((sc = pieces_char_iter_next(&pci)))
			break;
		if (!isxdigit(*pci.ch))
			return pieces_char_iter_parse_error(
			    &pci, st, "hex digit expected");
		*t |= hexdigit_to_int(*pci.ch);
	}
	*olen = t - t_start;
	return STATUS_OK;
}

static inline status_code pzl_add_remaining_hex_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	size_t      len = 0;
	pieces_iter tmp_pi = *pi;
	uint16_t   *rdata;
	uint8_t    *target;
	status_code sc;

	do len += pieces_iter_len(&tmp_pi);
	while (pieces_iter_next(&tmp_pi) == STATUS_OK);
	len = (len + 1) / 2;
	if (len > 65535)
		return pieces_iter_parse_error(pi, st, "too much hex rdata");

	 rdata = region_alloc(region, sizeof(uint16_t) + len);
	*rdata = len;
	target = (uint8_t *)(rdata + 1);
	if ((sc = pzl_conv_hex_rdata(pi, target, &len, st))) {
		region_recycle(region, rdata, sizeof(uint16_t) + len);
		return sc;
	}
	rr->rdatas[rr->rdata_count++].data = rdata;
	return STATUS_OK;
}

static inline status_code pzl_add_small_hex_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	pieces_iter single_piece;
	size_t      len;
	uint16_t   *rdata;
	uint8_t    *target;
	status_code sc;

	if (pieces_iter_len(pi) == 1 && *pi->cur->start == '-') {
		 rdata = region_alloc(region, sizeof(uint16_t) + 1);
		*rdata = 1;
		((uint8_t *)(rdata + 1))[0] = 0;
		rr->rdatas[rr->rdata_count++].data = rdata;
		return STATUS_OK;
	}
	single_piece.cur = pi->cur;
	single_piece.end = single_piece.cur + 1;
	len = (pieces_iter_len(&single_piece) + 1) / 2;
	 rdata = region_alloc(region, sizeof(uint16_t) + len + 1);
	*rdata = len + 1;
	target = (uint8_t *)(rdata + 1);
	if ((sc = pzl_conv_hex_rdata(&single_piece, target + 1, &len, st))) {
		region_recycle(region, rdata, sizeof(uint16_t) + len + 1);
		return sc;
	}
	target[0] = len;
	rr->rdatas[rr->rdata_count++].data = rdata;
	return STATUS_OK;
}

static inline status_code pzl_add_small_b32_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	char        str[410];
	uint8_t     target[256];

	if (pi->cur->end - pi->cur->start > (int)(sizeof(str) - 1))
		return pieces_iter_parse_error(
		    pi, st, "Too much Base32 data");
	memcpy(str, pi->cur->start, pi->cur->end - pi->cur->start);
	str[pi->cur->end - pi->cur->start] = 0;
	target[0] = b32_pton(str, target + 1, sizeof(target) - 1);
	rr->rdatas[rr->rdata_count++].data =
	    alloc_rdata_init(region, target, target[0] + 1);
	return STATUS_OK;
}

static inline status_code pzl_add_n_remaining_b64_rdata(region_type *region,
    rr_type *rr, size_t targsize, pieces_iter *pi, return_status *st)
{
	uint16_t *rdata_elem;
	status_code sc;
	pieces_char_iter pci;
	const uint8_t pad64 = 64; /* is 64th in the b64 array */
	uint8_t in[4];
	size_t o = 0, incount = 0;
	uint8_t target[B64BUFSIZE];

	for ( sc = pieces_char_iter_init(&pci, pi)
	    ; sc == STATUS_OK
	    ; sc = pieces_char_iter_next(&pci)) {
		/* conceptually we do:
		const char* b64 =      pad'=' is appended to array
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		const char* d = strchr(b64, *s++);
		and use d-b64;
		*/
		char d = *pci.ch;
		
		if(d <= 'Z' && d >= 'A')
			d -= 'A';
		else if(d <= 'z' && d >= 'a')
			d = d - 'a' + 26;
		else if(d <= '9' && d >= '0')
			d = d - '0' + 52;
		else if(d == '+')
			d = 62;
		else if(d == '/')
			d = 63;
		else if(d == '=')
			d = 64;
		else
			return pieces_char_iter_parse_error(
			    &pci, st, "base64 character expected");

		in[incount++] = (uint8_t)d;
		if(incount != 4)
			continue;

		/* process whole block of 4 characters into 3 output bytes */
		if(in[3] == pad64 && in[2] == pad64) { /* A B = = */
			if(o+1 > targsize) {
				o += 1;
				break;
			}
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			o += 1;
			break; /* we are done */
		} else if(in[3] == pad64) { /* A B C = */
			if(o+2 > targsize) {
				o += 2;
				break;
			}
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			o += 2;
			break; /* we are done */
		} else {
			if(o+3 > targsize) {
				o += 3;
				break;
			}
			/* write xxxxxxyy yyyyzzzz zzwwwwww */
			target[o] = (in[0]<<2) | ((in[1]&0x30)>>4);
			target[o+1]= ((in[1]&0x0f)<<4) | ((in[2]&0x3c)>>2);
			target[o+2]= ((in[2]&0x03)<<6) | in[3];
			o += 3;
		}
		incount = 0;
	}
	if (o > targsize)
		return pieces_iter_parse_error(pi, st, "superfluous b64 rdata");
	 rdata_elem = region_alloc(region, sizeof(uint16_t) + o);
	*rdata_elem = o;
	(void) memcpy((uint8_t *)(rdata_elem + 1), target, o);
	assert(rr->rdata_count < MAXRDATALEN);
	rr->rdatas[rr->rdata_count++].data = rdata_elem;
	return STATUS_OK;
}

static inline status_code pzl_add_remaining_b64_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	size_t b64_size = 0;
	pieces_iter tmp_pi = *pi;

	if (pieces_iter_last(pi)
	    && pieces_iter_len(pi) == 1 && *pi->cur->start == '0') {
		uint16_t *rdata_elem;

		assert(rr->rdata_count < MAXRDATALEN);
		 rdata_elem = region_alloc(region, sizeof(uint16_t));
		*rdata_elem = 0;
		rr->rdatas[rr->rdata_count++].data = rdata_elem;
		return STATUS_OK;
	}
	do b64_size += pieces_iter_len(&tmp_pi);
	while (pieces_iter_next(&tmp_pi) == STATUS_OK);
	b64_size = (((((b64_size + 3) / 4) * 3)) + 1);
	if (b64_size > 65535)
		return pieces_iter_parse_error(pi, st, "too much base64 rdata");

	return pzl_add_n_remaining_b64_rdata(region, rr, b64_size, pi, st);
}

static inline status_code pzl_add_str_rdata_(pieces_iter *pi,
    uint8_t *t, size_t *olen, return_status *st)
{
	const char *ch = pi->cur->start;
	const char *end = pi->cur->end;
	uint8_t *t_start = t;
	uint8_t *t_end = t + *olen;

	if (ch < end && *ch == '"') {
		ch += 1;
		if (ch < end && end[-1] == '"')
			end -= 1;
	}
	while (ch < end) {
		if (t >= t_end)
			return pieces_iter_parse_error(pi, st,
			    "string item too long");
		if (*ch != '\\') {
			*t++ = *ch;
			ch++;

		} else if (ch < end - 3 && isdigit((unsigned char)ch[1])
		                        && isdigit((unsigned char)ch[2])
		                        && isdigit((unsigned char)ch[3])) {
			uint16_t val;

			val = (uint16_t)((ch[0] - '0') * 100 +
			                 (ch[1] - '0') *  10 +
			                 (ch[2] - '0'));
			if (val > 255)
				return RETURN_PARSE_ERR(st,
				    "escaped decimal value too large",
				    pi->cur->fn, pi->cur->line_nr,
				    pi->cur->col_nr + (ch - pi->cur->start));
			*t++ = val;
			ch += 4;

		} else if (ch < end - 1 && !isdigit((unsigned char)ch[1])) {
			*t++ = ch[1];
			ch += 2;

		} else
			return RETURN_PARSE_ERR(st,
			    "badly escaped character",
			    pi->cur->fn, pi->cur->line_nr,
			    pi->cur->col_nr + (ch - pi->cur->start));
	}
	*olen = t - t_start;
	return STATUS_OK;
}

static inline status_code pzl_add_raw_str_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	uint8_t     target[B64BUFSIZE];
	size_t      len = sizeof(target);
	status_code sc;
	uint16_t   *rdata_elem;

	if ((sc = pzl_add_str_rdata_(pi, target, &len, st)))
		return sc;

	 rdata_elem = region_alloc(region, sizeof(uint16_t) + len);
	*rdata_elem = len;
	(void)memcpy((uint8_t *)(rdata_elem + 1), target, len);
	rr->rdatas[rr->rdata_count++].data = rdata_elem;
	return STATUS_OK;
}

static inline status_code pzl_add_str_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	uint8_t     target[255];
	size_t      len = sizeof(target);
	status_code sc;
	uint16_t   *rdata_elem;

	if ((sc = pzl_add_str_rdata_(pi, target, &len, st)))
		return sc;

	 rdata_elem = region_alloc(region, sizeof(uint16_t) + len + 1);
	*rdata_elem = len + 1;
	*(uint8_t *)(rdata_elem + 1) = len;
	(void)memcpy((uint8_t *)(rdata_elem + 1) + 1, target, len);
	rr->rdatas[rr->rdata_count++].data = rdata_elem;
	return STATUS_OK;
}

static status_code pzl_add_rrtype_bitmap_rdata(
    region_type *region, rr_type *rr, pieces_iter *pi, return_status *st)
{
	status_code sc = STATUS_OK;
	int         rr_type;
	uint8_t     nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

	(void) memset(nsecbits, 0, sizeof(nsecbits));
	while (sc == STATUS_OK) {
		if ((rr_type = dnsextlang_get_type_(
		    pi->cur->start, pieces_iter_len(pi), NULL)) < 0)
			return pieces_iter_parse_error(
			    pi, st, "rrtype not found");
		set_bitnsec(nsecbits, rr_type);
		sc = pieces_iter_next(pi);
	}
	rr->rdatas[rr->rdata_count++].data =
	    zparser_conv_nsec(region, nsecbits);
	return STATUS_OK;
}

static void pzl_add_empty_rrtype_bitmap_rdata(region_type *region, rr_type *rr)
{
	uint8_t     nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

	(void) memset(nsecbits, 0, sizeof(nsecbits));
	rr->rdatas[rr->rdata_count++].data = zparser_conv_nsec(region, nsecbits);
}

static void pzl_recycle_rdata_elements(region_type *region, rr_type *rr)
{
	const dnsextlang_stanza *s = dnsextlang_get_stanza(rr->type);
	dnsextlang_field *field;
	size_t n_fields, i;

	if (!s) {
		for (i = 0; i < rr->rdata_count; i++)
			region_recycle(region, rr->rdatas[i].data,
			    *rr->rdatas[i].data + sizeof(uint16_t));
	} else {
		for ( n_fields = s->n_fields, field = s->fields, i = 0
		    ; n_fields && i < rr->rdata_count
		    ; n_fields--, field++, i++ ) 
			if (field->ftype != del_ftype_N
			|| (field->quals & del_qual_L))
				region_recycle(region, rr->rdatas[i].data,
				    *rr->rdatas[i].data + sizeof(uint16_t));
	}
	rr->rdata_count = 0;
}

typedef struct merge_sorter merge_sorter;
typedef struct worker_data worker_data;
typedef struct process_data {
	size_t        n_workers;
	pthread_mutex_t mutex;
	const char     *name;
	time_t          start_time;
	worker_data    *wd;
	worker_data   **domain_tables;
	size_t        n_mergers;
	merge_sorter  **mergers;
} process_data;

struct worker_data {
	process_data      *pd;
	size_t             i;
	size_t           n_rrs;
	size_t           n_names;
	dname_type        *origin;
	region_type       *region;
	region_type       *tmpregion; /* For pzl_domain_refs */
	domain_table_type *domains;
	zone_type         *zone;
	zone_type          wd_zone;
};

#define SORTBATCHSIZE 16374
#define MAXNBATCHES 32

typedef struct wd_domain {
	worker_data *wd;
	domain_type *domain;
} wd_domain;

typedef struct pzl_domain_ref pzl_domain_ref;
struct pzl_domain_ref {
	domain_type   **ref;
	pzl_domain_ref *next;
	region_type    *tmpregion;
};

static inline void pzl_merge_rrsets(
    region_type *dst_region, rrset_type *dst_rrset,
    region_type *src_region, rrset_type *src_rrset)
{
	rr_type *o;

	/* TODO: Search and discard possible duplicates... */
	/* TODO: Check total count of dst_rrset will be <= 65535 */
	assert(dst_rrset->rr_count + src_rrset->rr_count <= 65535);

	/* Add it... */
	o = dst_rrset->rrs;
	dst_rrset->rrs = (rr_type *)region_alloc_array(dst_region,
	    dst_rrset->rr_count + src_rrset->rr_count , sizeof(rr_type));
	memcpy(dst_rrset->rrs, o, dst_rrset->rr_count * sizeof(rr_type));
	region_recycle(dst_region, o, dst_rrset->rr_count * sizeof(rr_type));
	memcpy(dst_rrset->rrs + dst_rrset->rr_count, src_rrset->rrs,
	    src_rrset->rr_count * sizeof(rr_type));
	dst_rrset->rr_count += src_rrset->rr_count;
	region_recycle(src_region, src_rrset->rrs,
	    src_rrset->rr_count * sizeof(rr_type));
	region_recycle(src_region, src_rrset, sizeof(rrset_type));
}


static void pzl_merge(
    wd_domain dst, wd_domain src, int can_recycle, int final_merge)
{
	/* Merge src->domain (all RRs and refs to), into dst->domain.
	 * Afterwards recycle parts of src->domain which are redundant,
	 * but not the src->domain struct itself because it is stil
	 * needed for iterating.  The caller needs to free it after
	 * the complete tree was traversed.
	 */
	rrset_type *rrset, *next_rrset;
	pzl_domain_ref **src_ref;

	if (src.domain->is_existing && !dst.domain->is_existing)
		dst.domain->is_existing = 1;

	if ((src_ref = (void *)&src.domain->nsec3) && *src_ref) {
		while (*src_ref) {
			assert(*(*src_ref)->ref == src.domain);
			*(*src_ref)->ref = dst.domain;
			src_ref = &(*src_ref)->next;
		}
		dst.domain->usage += src.domain->usage;
		src.domain->usage = 0;
		if (!final_merge && dst.wd->i) {
			*src_ref = (void *)dst.domain->nsec3;
			dst.domain->nsec3 = src.domain->nsec3;

		} else if (can_recycle) { /* Not strictly necessary */
			pzl_domain_ref *ref, *next_ref;

			for ( ref = (void *)src.domain->nsec3
			    , next_ref = ref->next
			    ; ref ; ref = next_ref
			          , next_ref = ref ? ref->next : NULL) {
				region_recycle(ref->tmpregion, ref,
				    sizeof(pzl_domain_ref));
			}
		}
		src.domain->nsec3 = NULL;
	}
	for (rrset = src.domain->rrsets; rrset; rrset = rrset->next) {
		size_t i;

		rrset->zone = dst.wd->zone; /* needed for domain_find_rrset */
		for (i = 0; i < rrset->rr_count; i++)
			rrset->rrs[i].owner = dst.domain;
	}
	if (!src.domain->rrsets)
		; /* pass */

	else if (!dst.domain->rrsets)
		dst.domain->rrsets = src.domain->rrsets;

	else for ( rrset = src.domain->rrsets, next_rrset = rrset->next
	         ; rrset
	         ; next_rrset = (rrset = next_rrset) ? rrset->next : NULL) {
		rrset_type *dst_rrset;

		rrset->zone = dst.wd->zone;
		dst_rrset = domain_find_rrset(
		    dst.domain, dst.wd->zone, rrset_rrtype(rrset));
		if (!dst_rrset) {
			domain_add_rrset(dst.domain, rrset);
			continue;
		} else if (can_recycle) {
			pzl_merge_rrsets( dst.wd->region, dst_rrset
			                , src.wd->region, rrset);
		} else {
			/* We cannot merge the rrset, because we cannot use
			 * the region without the risk of interfering with
			 * another thead.  Merging rrsets must wait until
			 * the very end, but we can make sure they can be
			 * merged relatively quickly by making sure that the
			 * same types follow each other.
			 * Also, we can mark the domain with rrsets to merge,
			 * so the ones that are done already can be skipped
			 * quickly.
			 */
			rrset->next = dst_rrset->next;
			dst_rrset->next = rrset;
			dst.domain->rrsets2merge = 1;
		}
	}
	src.domain->rrsets = NULL;
}

typedef struct merge_batch merge_batch;
struct merge_batch {
	wd_domain   *cur;
	wd_domain   *end;
	merge_batch *next;
	wd_domain    domains[SORTBATCHSIZE];
};

struct merge_sorter {
	process_data   *pd;
	size_t          i;
	pthread_t       thread;
	pthread_mutex_t started_mut;
	pthread_cond_t  started;
	pthread_mutex_t has_sorted_mut;
	pthread_cond_t  has_sorted;
	merge_batch    *sorted;
	merge_batch    *last;
	pthread_mutex_t free_mut;
	pthread_cond_t  has_free;
	merge_batch    *free;
	size_t          n_mallocs;
	domain_type    *domains2free;
	domain_type    *domains2free_last;
};

static void batch_provide(merge_sorter *me, merge_batch *ready)
{
	(void) pthread_mutex_lock(&me->has_sorted_mut);
	if (ready) {
		ready->end = ready->cur;
		ready->cur = ready->domains;
		ready->next = NULL;
		if (me->last) {
			assert(me->sorted);
			me->last->next = ready;
			me->last = ready;
		} else {
			assert(me->sorted == NULL);
			me->last = me->sorted = ready;
			(void) pthread_cond_signal(&me->has_sorted);
		}
	} else {
		/* everything is processed and everything is freed */
		assert(me->sorted == NULL);
		(void) pthread_cond_signal(&me->has_sorted);
	}
	(void) pthread_mutex_unlock(&me->has_sorted_mut);
}

static merge_batch *batch_new(merge_sorter *me, merge_batch *ready)
{
	merge_batch *batch;

	if (ready) batch_provide(me, ready);
	(void) pthread_mutex_lock(&me->free_mut);
	if (me->free) {
		batch = me->free;
		me->free = me->free->next;
	} else if (me->n_mallocs >= MAXNBATCHES) {
		(void) pthread_cond_wait(&me->has_free, &me->free_mut);
		assert(me->free);
		batch = me->free;
		me->free = me->free->next;
	} else {
		batch = xalloc(sizeof(merge_batch));
		me->n_mallocs++;
	}
	batch->next = NULL;
	batch->cur = batch->domains;
	batch->end = batch->domains + SORTBATCHSIZE;
	(void) pthread_mutex_unlock(&me->free_mut);
	return batch;
}

static void batch_free(merge_sorter *me, merge_batch *to_free)
{
	(void) pthread_mutex_lock(&me->free_mut);
	to_free->next = me->free;
	me->free = to_free;
	(void) pthread_cond_signal(&me->has_free);
	(void) pthread_mutex_unlock(&me->free_mut);
}

static inline void merge_provide(
    merge_sorter *me, merge_batch **batch_ptr, wd_domain wdd)
{
	if (!*batch_ptr)
		*batch_ptr = batch_new(me, NULL);
	if ((*batch_ptr)->cur >= (*batch_ptr)->end)
		*batch_ptr = batch_new(me, *batch_ptr);
	*(*batch_ptr)->cur++ = wdd;
}

typedef struct wd_domain_iter {
	wd_domain     cur;
	merge_sorter *ms;
	merge_batch  *batch;
} wd_domain_iter;

static status_code wd_domain_iter_next(wd_domain_iter *wdi)
{
	if (!wdi->ms) {
		assert(wdi->cur.wd);

		wdi->cur.domain = wdi->cur.domain
		    ? domain_next(wdi->cur.domain)
		    : wdi->cur.wd->domains->root;
		return wdi->cur.domain ? STATUS_OK : STATUS_STOP_ITERATION;
	}
	if (wdi->batch) {
		if (wdi->batch->cur < wdi->batch->end) {
			wdi->cur = *wdi->batch->cur++;
			return STATUS_OK;
		}
		batch_free(wdi->ms, wdi->batch);
		wdi->batch = NULL;
	}
	while (!wdi->batch) {
		(void) pthread_mutex_lock(&wdi->ms->has_sorted_mut);
		if (!wdi->ms->sorted)
			(void) pthread_cond_wait( &wdi->ms->has_sorted
			                        , &wdi->ms->has_sorted_mut);
		if ((wdi->batch = wdi->ms->sorted)) {
			if (!(wdi->ms->sorted = wdi->ms->sorted->next))
				wdi->ms->last = NULL;
		}
		(void) pthread_mutex_unlock(&wdi->ms->has_sorted_mut);
		if (!wdi->batch)
			return STATUS_STOP_ITERATION;
		if (wdi->batch->cur < wdi->batch->end) {
			wdi->cur = *wdi->batch->cur++;
			return STATUS_OK;
		}
		batch_free(wdi->ms, wdi->batch);
		wdi->batch = NULL;
	}
	return STATUS_STOP_ITERATION;
}

static status_code wd_domain_iter_init(wd_domain_iter *wdi, process_data *pd)
{
	size_t i;

	wdi->cur.domain = NULL;
	for (i = 0; i < pd->n_workers; i++) {
		if (pd->domain_tables[i]) {
			wdi->ms = NULL;
			wdi->cur.wd = pd->domain_tables[i];
			wdi->cur.domain = NULL;
			pd->domain_tables[i] = NULL;
			return STATUS_OK;
		}
	}
	for (i = 0; i < pd->n_mergers; i++) {
		if (pd->mergers[i]) {
			wdi->cur.wd = NULL;
			wdi->ms = pd->mergers[i];
			pd->mergers[i] = NULL;
			wdi->batch = NULL;
			return STATUS_OK;
		}
	}
	return STATUS_NOT_FOUND_ERR;
}

static void *start_merger(void *arg)
{
	merge_sorter  *me = (merge_sorter *)arg;
	process_data  *pd = me->pd;
	wd_domain_iter i1, i2;
	status_code    sc1, sc2;
	size_t         i;
	merge_batch   *batch = NULL;
	int            can_recycle;
	int            final_merge = me->i == pd->n_workers - 1;

	(void) pthread_mutex_lock(&me->started_mut);
	sc1 = wd_domain_iter_init(&i1, pd);
	sc2 = wd_domain_iter_init(&i2, pd);
	if (sc1 != STATUS_OK || sc2 != STATUS_OK) {
		fprintf(stderr, "Cannot initialize merge sorter %zu\n", me->i);
		exit(EXIT_FAILURE);
	}
	can_recycle = !i1.ms && !i2.ms;
	for (i = 0; i < pd->n_mergers; i++) {
		if (pd->mergers[i] == NULL) {
			pd->mergers[i] = me;
			break;
		}
	}
	assert(i < pd->n_mergers);
	(void) pthread_cond_signal(&me->started);
	(void) pthread_mutex_unlock(&me->started_mut);

	sc1 = wd_domain_iter_next(&i1);
	sc2 = wd_domain_iter_next(&i2);

	while (sc1 == STATUS_OK && sc2 == STATUS_OK) {
		int dc = dname_compare( domain_dname(i1.cur.domain)
				      , domain_dname(i2.cur.domain));
		if (dc < 0) {
			merge_provide(me, &batch, i1.cur);
			if ((sc1 = wd_domain_iter_next(&i1)))
				break;
		} else if (dc > 0) {
			merge_provide(me, &batch, i2.cur);
			if ((sc2 = wd_domain_iter_next(&i2)))
				break;
		} else {
			wd_domain i2wd = i2.cur;

			pzl_merge(i1.cur, i2.cur, can_recycle, final_merge);
			merge_provide(me, &batch, i1.cur);
			sc1 = wd_domain_iter_next(&i1);
			sc2 = wd_domain_iter_next(&i2);

			if (!(i2wd.domain->numlist_next = me->domains2free))
				me->domains2free_last = i2wd.domain;
			me->domains2free = i2wd.domain;
			i2wd.domain->numlist_prev =
				(domain_type *)(void *)i2wd.wd;
		}
	}
	while (sc1 == STATUS_OK) {
		merge_provide(me, &batch, i1.cur);
		sc1 = wd_domain_iter_next(&i1);
	}
	while (sc2 == STATUS_OK) {
		merge_provide(me, &batch, i2.cur);
		sc2 = wd_domain_iter_next(&i2);
	}
	if (batch)
		batch_provide(me, batch);

	/* Wait until consumers are done
	 * this is when all batches are freed
	 */
	while (me->n_mallocs) {
		merge_batch *to_free;

		(void) pthread_mutex_lock(&me->free_mut);
		if (!me->free)
			pthread_cond_wait(&me->has_free, &me->free_mut);
		assert(me->free);
		to_free = me->free;
		me->free = to_free->next;
		free(to_free);
		me->n_mallocs--;
		(void) pthread_mutex_unlock(&me->free_mut);
	}
	if (!can_recycle) {
		if (i1.ms && i1.ms->domains2free) {
			if (!me->domains2free)
				me->domains2free = i1.ms->domains2free;
			else
				me->domains2free_last->numlist_next = 
					i1.ms->domains2free;
			me->domains2free_last = i1.ms->domains2free_last;
		}
		if (i2.ms && i2.ms->domains2free) {
			if (!me->domains2free)
				me->domains2free = i2.ms->domains2free;
			else
				me->domains2free_last->numlist_next = 
					i2.ms->domains2free;
			me->domains2free_last = i2.ms->domains2free_last;
		}
	} else while (me->domains2free) {
		domain_type *to_recycle = me->domains2free;

		me->domains2free = to_recycle->numlist_next;
		if (to_recycle->is_apex || !to_recycle->parent)
			continue;

		assert(to_recycle->rrsets == NULL);
		assert(to_recycle->nsec3 == NULL);

		region_recycle(
		    ((worker_data *)to_recycle->numlist_prev)->region,
		    domain_dname(to_recycle),
		    dname_total_size(domain_dname(to_recycle)));
		region_recycle(
		    ((worker_data *)to_recycle->numlist_prev)->region,
		    to_recycle, sizeof(domain_type));
	};
	batch_provide(me, NULL);
	return NULL;
}

/* These are protected by the started semaphore */
static size_t n_domain_tables(process_data *pd)
{
	size_t n = 0, i;

	for (i = 0; i < pd->n_workers; i++)
		if (pd->domain_tables[i])
			n++;
	return n;
}

static size_t n_mergers(process_data *pd)
{
	size_t n = 0, i;

	for (i = 0; i < pd->n_mergers; i++)
		if (pd->mergers[i])
			n++;
	return n;
}

/* pzl_add_rdata_field should return STATUS_STOP_ITERATION when all
 * pieces (from pi) consumed
 */
static inline status_code pzl_add_rdata_field(
    worker_data *wd, rr_type *rr2add,
    const dnsextlang_field *field, pieces_iter *pi, return_status *st)
{
	region_type *region = wd->region;
	status_code  sc;

	uint8_t      dname_spc[MAXDOMAINLEN * 2];
	dname_type  *dname;
	domain_type *domain;
	const char  *endptr;
	uint16_t    *rdata_elem;
	uint32_t     n;
	int          rr_type;
	char         tmp_buf[80]; /* for A, time etc */

	if (rr2add->rdata_count >= MAXRDATALEN)
		return pieces_iter_parse_error(
		    pi, st, "too many rdata elements");

	switch (field->ftype) {
	case del_ftype_I1:
	case del_ftype_I2:
	case del_ftype_I4:
		n = piece2uint(pi->cur, &endptr);
		if (endptr != pi->cur->end) 
			return pieces_iter_parse_error(pi, st, "integer value");

		switch (field->ftype) {
		case del_ftype_I1:
			if (n > 255)
				return pieces_iter_parse_error(pi, st,
				    "value out of range [0-255]");

			 rdata_elem = region_alloc(region, sizeof(uint16_t)
			            + sizeof(uint8_t));
			*rdata_elem = sizeof(uint8_t);
			*(uint8_t *)(rdata_elem + 1) = n;
			break;
		case del_ftype_I2:
			if (n > 65535)
				return pieces_iter_parse_error(pi, st,
				    "value out of range [0-65535]");

			 rdata_elem = region_alloc(region, sizeof(uint16_t)
			            + sizeof(uint16_t));
			*rdata_elem = sizeof(uint16_t);
			*(uint16_t *)(rdata_elem + 1) = htons(n);
			break;
		case del_ftype_I4:
			 rdata_elem = region_alloc(region, sizeof(uint16_t)
			            + sizeof(uint32_t));
			*rdata_elem = sizeof(uint32_t);
			*(uint32_t *)(rdata_elem + 1) = htonl(n);
			break;
		default:
			assert(0); /* impossible */
			rdata_elem = NULL;
		}
		rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
		break;

	case del_ftype_A:
		if (pieces_iter_len(pi) > sizeof(tmp_buf) - 1)
			return pieces_iter_parse_error(
			    pi, st, "IPv4 address expected");
		(void)memcpy(tmp_buf, pi->cur->start, pieces_iter_len(pi));
		tmp_buf[pieces_iter_len(pi)] = 0;
		if (!(rdata_elem = zparser_conv_a(region, tmp_buf)))
			return pieces_iter_parse_error(
			    pi, st, "IPv4 address expected");
		rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
		break;

	case del_ftype_AAAA:
		if (pieces_iter_len(pi) > sizeof(tmp_buf) - 1)
			return pieces_iter_parse_error(
			    pi, st, "IPv6 address expected");
		(void)memcpy(tmp_buf, pi->cur->start, pieces_iter_len(pi));
		tmp_buf[pieces_iter_len(pi)] = 0;
		if (!(rdata_elem = zparser_conv_aaaa(region, tmp_buf)))
			return pieces_iter_parse_error(
			    pi, st, "IPv6 address expected");
		rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
		break;

	case del_ftype_T:
		if (pieces_iter_len(pi) == 14) {
			(void)memcpy(tmp_buf, pi->cur->start, 14);
			tmp_buf[14] = 0;
			if ((rdata_elem = zparser_conv_time(region, tmp_buf))) {
				rr2add->rdatas[rr2add->rdata_count++].data =
				    rdata_elem;
				break;
			}
		}
		n = piece2uint(pi->cur, &endptr);
		if (endptr != pi->cur->end) 
			return pieces_iter_parse_error(
			    pi, st, "time or integer value");
		 rdata_elem = region_alloc(region, sizeof(uint16_t) + 4);
		*rdata_elem = 4;
		*(uint32_t *)(rdata_elem + 1) = htonl(n);
		rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
		break;

	case del_ftype_R:
		if (field->quals & del_qual_L) {
			if ((sc = pzl_add_rrtype_bitmap_rdata(
			    region, rr2add, pi, st)))
				return sc;
			return STATUS_STOP_ITERATION;
		}
		if ((rr_type = dnsextlang_get_type_(
		    pi->cur->start, pieces_iter_len(pi), NULL)) < 0)
			return pieces_iter_parse_error(
			    pi, st, "rrtype not found");
		 rdata_elem = region_alloc(region, sizeof(uint16_t) + 2);
		*rdata_elem = 2;
		*(uint16_t *)(rdata_elem + 1) = htons(rr_type);
		rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
		break;

	case del_ftype_N:
		dname = dname_init(dname_spc + MAXDOMAINLEN,
		    pi->cur->start, pi->cur->end, wd->origin);
		if (!dname)
			return pieces_iter_parse_error(
			    pi, st, "dname expected");

		if (field->quals & del_qual_L) {
			 rdata_elem = region_alloc(
			    region, sizeof(uint16_t) + dname->name_size);
			*rdata_elem = dname->name_size;
			(void) memcpy(rdata_elem + 1, dname_name(dname)
			                            , dname->name_size);
			rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
			break;
		}
		domain = domain_table_insert(wd->domains, dname);
		if (!domain)
			return pieces_iter_parse_error(
			    pi, st, "could not insert dname");

		rr2add->rdatas[rr2add->rdata_count].domain = domain;
		if (wd->i) {
			pzl_domain_ref *domain_ref = region_alloc(
                            wd->tmpregion, sizeof(pzl_domain_ref));

			domain_ref->tmpregion = wd->tmpregion;
			domain_ref->ref =
			    &rr2add->rdatas[rr2add->rdata_count].domain;
			domain_ref->next = (pzl_domain_ref *)domain->nsec3;
			domain->nsec3 = (void *)domain_ref;
		}
		domain->usage++;
		rr2add->rdata_count += 1;
		break;
	
	case del_ftype_S:
		do {
			sc = ( field->quals & del_qual_X )
			     ? pzl_add_raw_str_rdata(region, rr2add, pi, st)
			     : pzl_add_str_rdata(region, rr2add, pi, st);

			sc = sc ? sc : pieces_iter_next(pi);

		} while ((field->quals & del_qual_M) && sc == STATUS_OK);
		return sc;

	case del_ftype_B32:
		if ((sc = pzl_add_small_b32_rdata(region, rr2add, pi, st)))
			return sc;
		break;

	case del_ftype_B64:
		if ((sc = pzl_add_remaining_b64_rdata(region, rr2add, pi, st)))
			return sc;
		return STATUS_STOP_ITERATION;
	
	case del_ftype_X:
		if (!(field->quals && del_qual_C)) {
			if ((sc = pzl_add_remaining_hex_rdata(
			    region, rr2add, pi, st)))
				return sc;
			return STATUS_STOP_ITERATION;
		}
		if ((sc = pzl_add_small_hex_rdata(region, rr2add, pi, st)))
			return sc;
		break;
	default:
		fprintf(stderr, "Unimplemented rdata type %d\n", field->ftype);
		return pieces_iter_parse_error(pi, st,
		    "rdata type not yet implemented");
	}
	return pieces_iter_next(pi);
}

static status_code parse_rdata(
    worker_data *wd, const dnsextlang_stanza *s,
    presentation_rr *rr, rr_type *rr2add, return_status *st)
{
	region_type *region = wd->region;
	pieces_iter  pi;
	status_code  sc;
	size_t n_fields;
	const dnsextlang_field *field;

	if ((sc = pieces_iter_init(&pi, rr->rr_type + 1, rr->end)))
		return pieces_iter_parse_error(
		    &pi, st, "rdata element missing");

	if (pieces_iter_len(&pi) == 2 && !strncmp(pi.cur->start, "\\#", 2)) {
		/* rfc3597 unknown rdata type */
		unsigned int len;
		const char *endptr;

		if (pieces_iter_next(&pi))
			return pieces_iter_parse_error(&pi, st,
			    "missing rdata length element");

		len = piece2uint(pi.cur, &endptr);
		if (endptr != pi.cur->end)
			return pieces_iter_parse_error(&pi, st,
			    "rdata length should be a positive integer value");

		if (pieces_iter_next(&pi))
			return len == 0 ? STATUS_OK
			     : pieces_iter_parse_error(
			           &pi, st, "missing hex rdata");

		if ((sc = pzl_add_remaining_hex_rdata(
		    region, rr2add, &pi, st)))
			return sc;

		if (len != *rr2add->rdatas[rr2add->rdata_count - 1].data)
			return STATUS_OK;

		pzl_recycle_rdata_elements(region, rr2add);
		return len < *rr2add->rdatas[rr2add->rdata_count - 1].data
		    ? pieces_iter_parse_error(&pi, st, "too much hex rdata")
		    : pieces_iter_parse_error(&pi, st, "too little hex rdata");
	}
	if (!s)
		return pieces_iter_parse_error(&pi, st,
		    "unknown RR type requires rfc3597 formatted rdata");

	for ( n_fields = s->n_fields, field = s->fields
	    ; n_fields && sc == STATUS_OK
	    ; n_fields--, field++) {
		sc = pzl_add_rdata_field(wd, rr2add, field, &pi, st);
		if (sc && sc != STATUS_STOP_ITERATION) {
			pzl_recycle_rdata_elements(region, rr2add);
			return sc;
		}
	}
	if (sc == STATUS_OK) {
		assert(n_fields == 0);
		pzl_recycle_rdata_elements(region, rr2add);
		return pieces_iter_parse_error(&pi, st, "superfluous rdata");
	}
	if (n_fields == 1) {
		/* Handle empty or optional rdata */
		switch (field->ftype) {
		case del_ftype_R:
			if (!(field->quals & del_qual_L))
				break;
			pzl_add_empty_rrtype_bitmap_rdata(region, rr2add);
			field++;
			n_fields--;
			break;
		default:
			break;
		}
	}
	if (n_fields > 0) {
		assert(sc == STATUS_OK);
		pzl_recycle_rdata_elements(region, rr2add);
		return pieces_iter_parse_error(&pi, st, "more rdata expected");
	}
	return STATUS_OK;
}

static status_code process_rrs(
    presentation_rr *rr, presentation_rr *end_of_rrs,
    size_t n_worker, void *userarg, float progress, return_status *st)
{
	process_data *pd = (process_data *)userarg;
	worker_data  *wd = &pd->wd[n_worker];
	region_type  *region = wd->region;
	const char   *origin_str = NULL;
	uint8_t       origin_spc[MAXDOMAINLEN * 2];
	dname_type   *origin = NULL;
	const char   *owner_str = NULL;
	uint8_t       owner_spc[MAXDOMAINLEN * 2];
	dname_type   *owner_dname = NULL;
	domain_type  *owner  = NULL;
	status_code   sc     = STATUS_OK;

	if (time(NULL) > pd->start_time + ZONEC_PCT_TIME) {
		(void) pthread_mutex_lock(&pd->mutex);
		pd->start_time = time(NULL);
		VERBOSITY(1, (LOG_INFO, "parse %s %6.2f %%",
		    pd->name, progress * 100));
		(void) pthread_mutex_unlock(&pd->mutex);
	}
	wd->n_rrs += end_of_rrs - rr;
	while (rr < end_of_rrs) {
		rr_type rr2add;
		rdata_atom_type rdatas[MAXRDATALEN];
		const dnsextlang_stanza *s;

		if (rr->origin != origin_str || !origin) {
			origin = dname_init(origin_spc + MAXDOMAINLEN,
			    rr->origin, rr->origin_end, NULL);
			origin_str = rr->origin;
			wd->origin = origin;
			owner_dname = dname_init(owner_spc + MAXDOMAINLEN,
			    rr->owner, rr->owner_end, origin);
			owner = domain_table_insert(wd->domains, owner_dname);
			owner_str = rr->owner;
			if (!owner->rrsets)
				wd->n_names += 1;
		}
		else if (rr->owner != owner_str && (!owner_str ||
		    strncmp(owner_str,rr->owner,rr->owner_end-rr->owner))) {
			owner_dname = dname_init(owner_spc + MAXDOMAINLEN,
			    rr->owner, rr->owner_end, origin);
			owner = domain_table_insert(wd->domains, owner_dname);
			owner_str = rr->owner;
			if (!owner->rrsets)
				wd->n_names += 1;
		}
		if (!owner)
			return RETURN_PARSE_ERR(st, "missing owner",
			    rr->rr_type->fn, rr->rr_type->line_nr,      
                            rr->rr_type->col_nr);

		rr2add.owner = owner;
		rr2add.ttl = rr->ttl;
		rr2add.klass = rr->rr_class;
		s = dnsextlang_lookup_(rr->rr_type->start,
		     rr->rr_type->end - rr->rr_type->start, NULL);
		rr2add.rdata_count = 0;
		if (s) {
			rr2add.rdatas = (rdata_atom_type *)region_alloc_array(
			    region, s->n_fields, sizeof(rdata_atom_type));
			rr2add.type = s->number;
			if ((sc = parse_rdata(wd, s, rr, &rr2add, st)))
				return sc;
		} else {
			int t = dnsextlang_get_TYPE_rrtype(rr->rr_type->start,
			    rr->rr_type->end - rr->rr_type->start, NULL);

			if (t < 0) 
				return RETURN_PARSE_ERR(st, "unknown rrtype",
				    rr->rr_type->fn, rr->rr_type->line_nr,
				    rr->rr_type->col_nr);
			rr2add.type = t;
			rr2add.rdatas = rdatas;
			if ((sc = parse_rdata(wd, NULL, rr, &rr2add, st)))
				return sc;
			rr2add.rdatas = (rdata_atom_type *)
			    region_alloc_array_init(
			    region, rr2add.rdatas, rr2add.rdata_count,
			    sizeof(rdata_atom_type));
		}
		if (s)
			assert(rr2add.rdata_count == s->n_fields);

		if ((!pzl_process_rr(region, wd->zone, &rr2add))) {
			return RETURN_PARSE_ERR(st, "error processing rr type",
			    rr->rr_type->fn, rr->rr_type->line_nr,
			    rr->rr_type->col_nr);
		}
		rr += 1;
	}
	return sc;
}

static inline void pzl_scan_rrsets2merge(rrset_type *rrset)
{
	rrset_type *next;

	for ( next = rrset ? rrset->next : NULL
	    ; rrset && next
	    ; rrset = next, next = rrset ? rrset->next : NULL) {
		while (next && rrset_rrtype(rrset) == rrset_rrtype(next)
		            && rrset->zone->apex == next->zone->apex) {
			rrset->next = next->next;
			pzl_merge_rrsets( parser->db->region, rrset
			                , parser->db->region, next);
			next = rrset->next;
		}
	}
}

#define BLACK   0
#define RED     1

static rbnode_type *pzl_list2tree(
    domain_type **head_ref, int n, size_t depth)
{
	rbnode_type *left, *root;

	if (n <= 0)
		return RBTREE_NULL;

	left = pzl_list2tree(head_ref, n / 2, depth + 1);
	root = &(*head_ref)->node;
	root->color = ((depth % 2) == 0) ? BLACK : RED;
	root->left = left;
	if (left != RBTREE_NULL)
		left->parent = root;
	*head_ref = (*head_ref)->numlist_next;
	root->right = pzl_list2tree(head_ref, n - (n / 2) - 1, depth + 1);
	if (root->right != RBTREE_NULL)
		root->right->parent = root;
	return root;
}

typedef struct list2tree_args {
	domain_type *head;
	size_t       size;
	size_t       depth;
} list2tree_args;

typedef struct rbnode_infos rbnode_infos;
typedef struct rbnode_info rbnode_info;
struct rbnode_info {
	domain_type  *domain;
	size_t        depth;
	size_t        offset;
	size_t        count;
	rbnode_info  *prev;
	rbnode_info  *next;
	rbnode_infos *infos;
	pthread_t     thread;
};

struct rbnode_infos {
	size_t       depth;
	domain_type *root;
	rbnode_info  infos[];
};

static inline size_t ln2(size_t x) { return x / 2 ? ln2(x / 2) + 1 : 0; }
static inline size_t n_infos(size_t depth) { return (2 << depth) - 1; }
static inline size_t rbnode_info_n(rbnode_info *i)
{ return i->count / 2 + i->offset; }
static inline rbnode_info *rbnode_info_next(rbnode_info *i)
{ if (i) do i = i->next; while(i && i->depth == i->infos->depth);  return i; }

#ifndef NDEBUG
static void rbnode_infos_debug(rbnode_infos *rbis)
{
	rbnode_info *cur;

	fprintf(stderr, "-----\n");
	for (cur = rbis->infos; cur; cur = cur->next) {
		domain_type *left, *right, *parent;
		size_t l, r, n, p;

		fprintf(stderr, "d: %2zu, o: %9zu, n: %9zu, ",
		    cur->depth, cur->offset, rbnode_info_n(cur));
		if (!cur->domain) {
			fprintf(stderr, "-\n");
			continue;
		}
		left  = (domain_type *)(cur->domain->node.left);
		l     = left && &left->node != RBTREE_NULL ? left->number  : 0;
		right = (domain_type *)(cur->domain->node.right);
		r     = right && &right->node != RBTREE_NULL ? right->number : 0;
		parent = (domain_type *)(cur->domain->node.parent);
		p     = parent && &parent->node != RBTREE_NULL ? parent->number : 0;
		n     = cur->domain->number;
		fprintf(stderr, "l: %9zu, n: %9zu, r: %9zu, p: %9zu\n", l, n, r, p);
	}
	fprintf(stderr, "-----\n");
}
#else
#define rbnode_infos_debug(X)
#endif

static void *rbnode_info_worker(void *args)
{
	rbnode_info *rbi = args;
	domain_type *head;

	head = rbi->prev ? rbi->prev->domain->numlist_next : rbi->infos->root;
	assert(rbi->offset == head->number);
	rbi->domain = (domain_type *)pzl_list2tree(
	    &head, rbi->count, rbi->depth);
	assert(rbi->domain->number == rbnode_info_n(rbi));
	return rbi->domain;
}

static void *rbnode_info_mover(void *args)
{
	rbnode_info *rbi = args;
	size_t n = rbnode_info_n(rbi);

	while (rbi->domain->number > n)
		rbi->domain = rbi->domain->numlist_prev;
	while (rbi->domain->number < n)
		rbi->domain = rbi->domain->numlist_next;
	return NULL;
}

static void rbnode_info_equip_numbers(size_t depth, rbnode_info **head,
    size_t cur_depth, size_t offset, size_t count)
{
	size_t n;

	if (cur_depth < depth)
		rbnode_info_equip_numbers(depth, head,
		    cur_depth + 1, offset , count / 2);

	(*head)->depth  = cur_depth;
	(*head)->offset = offset;
	(*head)->count  = count;
	n = rbnode_info_n(*head);
	*head = (*head)->next;

	if (cur_depth < depth)
		rbnode_info_equip_numbers(depth, head,
		    cur_depth + 1, n + 1, count - count / 2 - 1);
}

static rbnode_info *rbnode_infos_connect_top(
    size_t depth, rbnode_info **head, size_t cur_depth)
{
	rbnode_info *me, *left = NULL, *right = NULL;

	if (cur_depth < depth)
		left = rbnode_infos_connect_top(depth, head, cur_depth + 1);

	me = *head;
	*head = (*head)->next;

	if (cur_depth < depth) {
		right = rbnode_infos_connect_top(depth, head, cur_depth + 1);

		me->domain->node.left = &left->domain->node;
		me->domain->node.right = &right->domain->node;
		me->domain->node.color = ((me->depth % 2) == 0) ? BLACK : RED;
		left->domain->node.parent = &me->domain->node;
		right->domain->node.parent = &me->domain->node;
	}
	return me;
}

static status_code rbnode_infos_fixup(
    rbnode_infos *rbis, domain_type *root, size_t count, return_status *st)
{
	rbnode_info *cur;
	int pc;

	rbis->root = root;
	cur = rbis->infos;
	rbnode_info_equip_numbers(rbis->depth, &cur, 0, 1, count);
	for (cur = rbis->infos; cur ; cur = cur->next) {
		if (!cur->domain)
			continue;

		if ((pc = pthread_create(
		    &cur->thread, NULL, rbnode_info_mover, cur)))
			return RETURN_PTHREAD_ERR(
			    st, "creating rbnode_info_mover", pc);
	}
	for (cur = rbis->infos; cur ; cur = cur->next) {
		if (!cur->domain)
			continue;
		if ((pc = pthread_join(cur->thread, NULL)))
			return RETURN_PTHREAD_ERR(
			    st, "creating rbnode_info_mover", pc);
	}
	VERBOSITY(3,
	    (LOG_INFO, "Make red/black tree for %d names", (int)count));
	for (cur = rbis->infos; cur ; cur = cur->next) {
		if (cur->domain)
			continue;

		assert(cur->depth == rbis->depth);
		if ((pc = pthread_create(
		    &cur->thread, NULL, rbnode_info_worker, cur)))
			return RETURN_PTHREAD_ERR(
			    st, "creating rbnode_info_worker", pc);
	}
	return STATUS_OK;
}

static status_code rbnode_infos_wait(
    rbnode_infos *rbis, domain_table_type *domains, return_status *st)
{
	rbnode_info *cur, *rb_root;

	for (cur = rbis->infos; cur ; cur = cur->next) {
		int pc;
		void *retval;

		if (cur->depth != rbis->depth)
			continue;

		if ((pc = pthread_join(cur->thread, &retval)))
			return RETURN_PTHREAD_ERR(
			    st, "joining rbnode_info_worker", pc);
		assert(retval == cur->domain);
	}
	cur = rbis->infos;
	rb_root = rbnode_infos_connect_top(rbis->depth, &cur, 0);
	rb_root->domain->node.parent = RBTREE_NULL;
	domains->names_to_domains->root = &rb_root->domain->node;
	domains->names_to_domains->count = rb_root->count;
	rbnode_infos_debug(rbis);
	VERBOSITY(3, (LOG_INFO, "Finished making red/black tree"));
	return STATUS_OK;
}

static rbnode_infos *rbnode_infos_new(
    region_type *region, size_t n_workers, size_t count)
{
	size_t depth = ln2(n_workers);
	rbnode_infos *rbis = (rbnode_infos *)region_alloc_zero(region,
	    sizeof(rbnode_infos) + n_infos(depth) * sizeof(rbnode_info));
	rbnode_info  *prev, *cur;
	size_t        i;
	
	rbis->depth = depth;
	for ( i = 0, cur = rbis->infos, prev = NULL
	    ; i < n_infos(depth); i++, prev = cur++) {
		cur->prev = prev;
		cur->infos = rbis;
		if (prev) prev->next = cur;
	}
	cur = rbis->infos;
	rbnode_info_equip_numbers(depth, &cur, 0, 1, count);
	rbnode_infos_debug(rbis);
	return rbis;
}

status_code pzl_load(
    region_type *region, domain_table_type *domains, zone_type *zone,
    uint32_t default_ttl, uint16_t default_class,
    const char *name, const char *fn, return_status *st)
{
	status_code  sc;
	process_data pd;
	dns_config   cfg;
	size_t       i;
	uint8_t      origin_spc[MAXDOMAINLEN * 2];
	dname_type  *origin;
	region_type *tmpregion = region_create(xalloc, free);

	/* variables used in red/black tree reconstruction */
	size_t        total_names;
	rbnode_infos *rbis;
	rbnode_info  *rbi;

	/* variables used in merging */
	merge_sorter *mergers, *started;
	int pc;
	void *retval = NULL;
	wd_domain_iter wdi;
	size_t n = 0;
	domain_type *prev;

	/* apex_rrset_checks */
	rrset_type  *rrset;
	size_t     n_rrsets2merge;
	domain_type *rrsets2merge;

	if (!tmpregion)
		return RETURN_MEM_ERR(st, "allocating PZL temporary region");

	origin = dname_init(origin_spc + MAXDOMAINLEN,
	    name, name + strlen(name), NULL);

	cfg.default_ttl = default_ttl;
	cfg.default_class = default_class;
	cfg.default_origin = name;

	pd.name = name;
	pd.n_workers = sysconf(_SC_NPROCESSORS_ONLN);
	assert(pd.n_workers > 0);
	VERBOSITY(3,
	    (LOG_INFO, "Parallel parse with %d workers", (int)pd.n_workers));

	(void) pthread_mutex_init(&pd.mutex, NULL);
	pd.start_time = time(NULL);
	pd.wd = region_alloc_array(
	    tmpregion, pd.n_workers, sizeof(worker_data));
	pd.domain_tables = region_alloc_array(
	    tmpregion, pd.n_workers, sizeof(worker_data *));
	
	for (i = 0; i < pd.n_workers; i++) {
		pd.domain_tables[i] = &pd.wd[i];
		pd.wd[i].pd = &pd;
		pd.wd[i].i = i;
		pd.wd[i].n_rrs = 0;
		pd.wd[i].n_names = 0;
		pd.wd[i].origin = NULL;
		pd.wd[i].tmpregion = region_create(xalloc, free);
		if (!pd.wd[i].tmpregion)
			return RETURN_MEM_ERR(
                            st, "creating worker temporary region");
		if (!i) {
			pd.wd[0].region = region;
			pd.wd[0].domains = domains;
			pd.wd[0].zone = zone;
			continue;
		}
# ifdef USE_MMAP_ALLOC
		pd.wd[i].region = region_create_custom(mmap_alloc, mmap_free,
		    MMAP_ALLOC_CHUNK_SIZE, MMAP_ALLOC_LARGE_OBJECT_SIZE,
		    MMAP_ALLOC_INITIAL_CLEANUP_SIZE, 1);
# else  /* ifdef USE_MMAP_ALLOC */
		pd.wd[i].region = region_create_custom(xalloc, free,
		    DEFAULT_CHUNK_SIZE, DEFAULT_LARGE_OBJECT_SIZE,
		    DEFAULT_INITIAL_CLEANUP_SIZE, 1);
# endif /* ifdef USE_MMAP_ALLOC */
		if (!pd.wd[i].region)
			return RETURN_MEM_ERR(st, "creating worker regions");
		pd.wd[i].domains = domain_table_create(pd.wd[i].region);
		if (!pd.wd[i].domains)
			return RETURN_MEM_ERR(
			    st, "creating worker domain table");

		pd.wd[i].wd_zone    = *zone;
		pd.wd[i].zone       = &pd.wd[i].wd_zone;
		pd.wd[i].zone->apex = domain_table_insert(
					  pd.wd[i].domains, origin);
		pd.wd[i].zone->apex->usage++;
		pd.wd[i].zone->apex->is_apex = 1;
	}
	sc = zonefile_process_rrs_fn_(
	    &cfg, fn, pd.n_workers, process_rrs, &pd, st);

	if (sc) {
		for (i = 0; i < pd.n_workers; i++) {
			region_destroy(pd.wd[i].region);
			region_destroy(pd.wd[i].tmpregion);
		}
		region_destroy(tmpregion);
		return sc;
	}
	if (verbosity >= 3) {
		for (i = 0; i < pd.n_workers; i++) {
			VERBOSITY(3, (LOG_INFO,
			    "Worker %d: %d RRs, %d names",
			    (int)i, (int)pd.wd[i].n_rrs,
			    (int)pd.wd[i].n_names));
		}
#ifdef PRINT_DOMAIN_TABLES
		if (1) for (i = 0; i < pd.n_workers; i++) {
			char fn[1024];
			FILE *f;

			snprintf(fn, sizeof(fn), "%s.worker_%zu", name, i);
			if ((f = fopen(fn, "w"))) {
				print_rrs(f, pd.wd[i].zone);
				fclose(f);
			}
		}
#endif
		VERBOSITY(3, (LOG_INFO, "Parallel merge of %d domain tables"
				      , (int)pd.n_workers));
	}
	total_names = 0;
	for (i = 0; i < pd.n_workers; i++)
		total_names += pd.wd[i].domains->names_to_domains->count;
	VERBOSITY(3, (LOG_INFO, "%d estimated total names"
			      , (int)total_names));

	rbis = rbnode_infos_new(tmpregion, pd.n_workers, total_names);
	rbi = rbnode_info_next(rbis->infos);

	pd.n_mergers = pd.n_workers - 1;
	mergers = region_alloc_array(
	    tmpregion, pd.n_mergers, sizeof(merge_sorter));
	pd.mergers = region_alloc_array(
	    tmpregion, pd.n_mergers, sizeof(merge_sorter *));
	for (i = 0; i < pd.n_mergers; i++) {
		merge_sorter *merger = &mergers[i];

		(void) memset(merger, 0, sizeof(merge_sorter));
		merger->pd = &pd;
		merger->i = i;
		(void) pthread_mutex_init(&merger->started_mut, NULL);
		(void) pthread_cond_init(&merger->started, NULL);
		(void) pthread_mutex_init(&merger->has_sorted_mut, NULL);
		(void) pthread_cond_init(&merger->has_sorted, NULL);
		(void) pthread_mutex_init(&merger->free_mut, NULL);
		(void) pthread_cond_init(&merger->has_free, NULL);

		pd.mergers[i] = NULL;
	}
	started = mergers;
	while (n_domain_tables(&pd) || n_mergers(&pd) != 1) {
		merge_sorter *merger = started++;

		(void) pthread_mutex_lock(&merger->started_mut);
		if ((pc = pthread_create(&merger->thread, NULL,
		    start_merger, merger))) {
			sc = RETURN_PTHREAD_ERR(
			    st, "starting merger", pc);
			break;
		}
		(void) pthread_cond_wait( &merger->started
					, &merger->started_mut);
		(void) pthread_mutex_unlock(&merger->started_mut);
	}
	n_rrsets2merge = 0;
	rrsets2merge = NULL;
	n = 1;
	prev = NULL;
	if ((sc = wd_domain_iter_init(&wdi, &pd)))
		; /* pass */
	else if ((sc = wd_domain_iter_next(&wdi)))
		; /* pass */
	else for (;;) {
		wdi.cur.domain->number = n;
		if (rbi && n == rbnode_info_n(rbi)) {
			rbi->domain = wdi.cur.domain;
			rbi = rbnode_info_next(rbi);
		}
		wdi.cur.domain->numlist_prev = prev;
		prev = wdi.cur.domain;
		if ((sc = wd_domain_iter_next(&wdi)))
			break;
		wdi.cur.domain->nsec3 = NULL; /* remaining pzl_domain_refs */
		if (wdi.cur.domain->rrsets2merge) {
			n_rrsets2merge += 1;
			wdi.cur.domain->nsec3 = (void *)rrsets2merge;
			rrsets2merge = wdi.cur.domain;
		}
		if ( domain_dname(wdi.cur.domain)->label_count >
		     domain_dname(prev)->label_count ) {
			assert(domain_dname(wdi.cur.domain)->label_count ==
			       domain_dname(prev)->label_count + 1);
			wdi.cur.domain->parent = prev;
		} else {
			domain_type *parent = prev->parent;
			size_t p_lc =
			    domain_dname(wdi.cur.domain)->label_count - 1;
			
			while (p_lc < domain_dname(parent)->label_count)
				parent = parent->parent;
			wdi.cur.domain->parent = parent;
		}
		/* TODO: Now wdi.cur.domain has a parent, we can do the
		 *       check_dname() (from zonec.c) check.
		 */
		/* wdi.cur.domain is merged, so safe to touch rrsets */
		if (wdi.cur.domain->rrsets) {
			if (wdi.cur.wd->zone != zone) {
				for ( rrset = wdi.cur.domain->rrsets
				    ; rrset ; rrset = rrset->next )
					rrset->zone = zone;
			}
			assert(wdi.cur.domain->is_existing);
			if (label_compare(
			    dname_name(domain_dname(wdi.cur.domain)),
			    (const uint8_t *) "\001*") <= 0
			&&  dname_compare(domain_dname(wdi.cur.domain),
			    domain_dname(wdi.cur.domain->parent->wildcard_child_closest_match)) > 0) {
				wdi.cur.domain->parent->wildcard_child_closest_match = wdi.cur.domain;
			}
		}
		assert(!wdi.cur.domain->is_existing ||
			wdi.cur.domain->parent->is_existing);
		n++;
		prev->numlist_next = wdi.cur.domain;
	};
	if (sc == STATUS_STOP_ITERATION) {
		assert(prev);
		prev->numlist_next = NULL;
		domains->numlist_last = prev;
		sc = STATUS_OK;
	}
	if (wdi.ms && (pc = pthread_join(wdi.ms->thread, &retval)))
		return RETURN_PTHREAD_ERR(st, "joining merger", pc);

	while (rbi) {
		rbi->domain = prev;
		rbi = rbnode_info_next(rbi);
	}
	if (!sc)
		sc = rbnode_infos_fixup(rbis, domains->root, n, st);

	if (sc) {
		for (i = 0; i < pd.n_workers; i++) {
			region_destroy(pd.wd[i].region);
			region_destroy(pd.wd[i].tmpregion);
		}
		region_destroy(tmpregion);
		return sc;
	}
	if (!wdi.ms)
		; /* pass */
	else while (wdi.ms->domains2free) {
		domain_type *to_recycle = wdi.ms->domains2free;

		wdi.ms->domains2free = to_recycle->numlist_next;
		if (to_recycle->is_apex || !to_recycle->parent)
			continue;

		assert(to_recycle->rrsets == NULL);
		assert(to_recycle->nsec3 == NULL);

		region_recycle(
		    ((worker_data *)to_recycle->numlist_prev)->region,
		    domain_dname(to_recycle),
		    dname_total_size(domain_dname(to_recycle)));
		region_recycle(
		    ((worker_data *)to_recycle->numlist_prev)->region,
		    to_recycle, sizeof(domain_type));
	};

	VERBOSITY(3,
	    (LOG_INFO, "%d names with rrsets to merge", (int)n_rrsets2merge));

	/* Change apex for worker zones to real apex so the
	 * zone can be recognised when we have to merge rrsets
	 * later on.
	 */
	for (i = 1; i < pd.n_workers; i++) {
		region_destroy(pd.wd[i].tmpregion); /* For domain_refs */

		region_recycle(pd.wd[i].region,
		                     domain_dname(pd.wd[i].domains->root),
		    dname_total_size(domain_dname(pd.wd[i].domains->root)));
		region_recycle(pd.wd[i].region,
		    pd.wd[i].domains->root, sizeof(domain_type));
		region_recycle(pd.wd[i].region,
		    pd.wd[i].domains , sizeof(domain_table_type));
		pd.wd[i].zone->apex = zone->apex;
	}
	while (rrsets2merge) {
		domain_type *next = (void *)rrsets2merge->nsec3;

		rrsets2merge->nsec3 = NULL;
		rrsets2merge->rrsets2merge = 0;
		pzl_scan_rrsets2merge(rrsets2merge->rrsets);
		rrsets2merge = next;
	}
	VERBOSITY(3,
	    (LOG_INFO, "%d names with rrsets merged", (int)n_rrsets2merge));

	VERBOSITY(3,
	    (LOG_INFO, "Merging %d regions", (int)pd.n_workers));
	for (i = 1; i < pd.n_workers; i++)
		region_merge(region, pd.wd[i].region, sizeof(domain_type));
	VERBOSITY(3,
	    (LOG_INFO, "%d regions merged", (int)pd.n_workers));

	if ((sc = rbnode_infos_wait(rbis, domains, st))) {
		region_destroy(tmpregion);
		return sc;
	}
	for ( rrset = zone->apex->rrsets; rrset ; rrset = rrset->next )
		apex_rrset_checks(parser->db, rrset, zone->apex);


	region_destroy(tmpregion);
	
#ifdef PRINT_DOMAIN_TABLES
	if (1) {
		char fn[1024];
		FILE *f;

		snprintf(fn, sizeof(fn), "%s.merged.zone", name);
		if ((f = fopen(fn, "w"))) {
			print_rrs(f, zone);
			fclose(f);
		}
	}
#endif
	return sc;
}

