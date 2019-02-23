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

	/* Check we have SOA */
	/* TODO: Do this last when merging the domain tables

	if(rr->owner == zone->apex)
		apex_rrset_checks(parser->db, rrset, rr->owner);
	*/
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

static inline status_code pzl_conv_b32_rdata(
    pieces_iter *pi, uint8_t *t, size_t *olen, return_status *st)
{
	status_code sc;
	pieces_char_iter pci;
	size_t p = 0;

	(void) memset(t, 0, *olen);
	for ( sc = pieces_char_iter_init(&pci, pi)
	    ; sc == STATUS_OK
	    ; sc = pieces_char_iter_next(&pci), t++) {
		uint8_t d;
		size_t b;
		size_t n;
		char   ch = *pci.ch;

		if(p+5 >= *olen * 8)
			break;

		if(ch >= '0' && ch <= '9')
			d=ch-'0';
		else if(ch >= 'A' && ch <= 'V')
			d=ch-'A'+10;
		else if(ch >= 'a' && ch <= 'v')
			d=ch-'a'+10;
		else
			return pieces_char_iter_parse_error(
			    &pci, st, "base32 character expected");

		b=7-p%8;
		n=p/8;

		if(b >= 4)
			t[n]|=d << (b-4);
		else {
			t[n]|=d >> (4-b);
			t[n+1]|=d << (b+4);
		}
		p+=5;

	}
	*olen = (p + 7) / 8;
	return STATUS_OK;
}

static inline status_code pzl_add_small_b32_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	pieces_iter single_piece;
	uint8_t     target[256];
	size_t      len = sizeof(target) - 1;
	status_code sc;

	single_piece.cur = pi->cur;
	single_piece.end = single_piece.cur + 1;
	if ((sc = pzl_conv_b32_rdata(&single_piece, target + 1, &len, st)))
		return sc;
	target[0] = len;
	rr->rdatas[rr->rdata_count++].data =
	    alloc_rdata_init(region, target, len + 1);
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
	assert(rr->rdata_count < MAXDATALEN);
	rr->rdatas[rr->rdata_count++].data = rdata_elem;
	return STATUS_OK;
}

static inline status_code pzl_add_remaining_b64_rdata(region_type *region,
    rr_type *rr, pieces_iter *pi, return_status *st)
{
	size_t b64_size = 0;
	pieces_iter tmp_pi = *pi;

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
			if (field->ftype != del_ftype_N)
				region_recycle(region, rr->rdatas[i].data,
				    *rr->rdatas[i].data + sizeof(uint16_t));
	}
	rr->rdata_count = 0;
}

typedef struct worker_data worker_data;
typedef struct process_data {
	size_t        n_workers;
	pthread_mutex_t mutex;
	const char     *name;
	time_t          start_time;
	worker_data    *wd;
} process_data;

struct worker_data {
	process_data      *pd;
	size_t           n_rrs;
	dname_type        *origin;
	region_type       *region;
	domain_table_type *domains;
	zone_type         *zone;
	zone_type          wd_zone;
};


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
			(void) memcpy(rdata_elem + 1,
			    dname_name(dname), dname->name_size);
			rr2add->rdatas[rr2add->rdata_count++].data = rdata_elem;
			break;
		}
		domain = domain_table_insert(wd->domains, dname);
		if (!domain)
			return pieces_iter_parse_error(
			    pi, st, "could not insert dname");

		rr2add->rdatas[rr2add->rdata_count++].domain = domain;
		domain->usage++;
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
		}
		if (rr->owner != owner_str && (!owner_str ||
		    strncmp(owner_str,rr->owner,rr->owner_end-rr->owner))) {
			owner_dname = dname_init(owner_spc + MAXDOMAINLEN,
			    rr->owner, rr->owner_end, origin);
			owner = domain_table_insert(wd->domains, owner_dname);
			owner_str = rr->owner;
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
		rr2add.rdatas = rdatas;
		rr2add.rdata_count = 0;
		if (s) {
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
			if ((sc = parse_rdata(wd, NULL, rr, &rr2add, st)))
				return sc;
		}
		rr2add.rdatas = (rdata_atom_type *)region_alloc_array_init(
		    region, rr2add.rdatas, rr2add.rdata_count,
		    sizeof(rdata_atom_type));
		if ((!pzl_process_rr(region, wd->zone, &rr2add))) {
			return RETURN_PARSE_ERR(st, "error processing rr type",
			    rr->rr_type->fn, rr->rr_type->line_nr,
			    rr->rr_type->col_nr);
		}
		rr += 1;
	}
	(void) pthread_mutex_lock(&pd->mutex);
	if (time(NULL) > pd->start_time + ZONEC_PCT_TIME) {
		pd->start_time = time(NULL);
		VERBOSITY(1, (LOG_INFO, "parse %s %6.2f %%",
		    pd->name, progress * 100));
	}
	(void) pthread_mutex_unlock(&pd->mutex);
	return sc;
}

status_code pzl_load(const char *name, const char *fn, return_status *st)
{
	status_code  sc;
	process_data pd;
	dns_config   cfg;
	size_t       i;
	uint8_t      origin_spc[MAXDOMAINLEN * 2];
	dname_type  *origin;

	origin = dname_init(origin_spc + MAXDOMAINLEN,
	    name, name + strlen(name), NULL);

	cfg.default_ttl = parser->default_ttl;
	cfg.default_class = parser->default_class;
	cfg.default_origin = name;

	pd.name = name;
	pd.n_workers = sysconf(_SC_NPROCESSORS_ONLN);
	assert(pd.n_workers > 0);

	(void) pthread_mutex_init(&pd.mutex, NULL);
	pd.start_time = time(NULL);
	if (!(pd.wd = region_alloc_array(
	    parser->region, pd.n_workers, sizeof(worker_data))))
		return RETURN_MEM_ERR(st, "allocating worker data");

	for (i = 0; i < pd.n_workers; i++) {
		pd.wd[i].pd = &pd;
		pd.wd[i].n_rrs = 0;
		pd.wd[i].origin = NULL;
		if (!i) {
			pd.wd[0].region = parser->db->region;
			pd.wd[0].domains = parser->db->domains;
			pd.wd[0].zone = parser->current_zone;
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

		pd.wd[i].wd_zone    = *parser->current_zone;
		pd.wd[i].zone       = &pd.wd[i].wd_zone;
		pd.wd[i].zone->apex = domain_table_insert(
					  pd.wd[i].domains, origin);
		pd.wd[i].zone->apex->usage++;
		pd.wd[i].zone->apex->is_apex = 1;
	}
	sc = zonefile_process_rrs_fn_(
	    &cfg, fn, pd.n_workers, process_rrs, &pd, st);

	region_recycle(
	    parser->region, pd.wd, pd.n_workers * sizeof(worker_data));
	return sc;
}

