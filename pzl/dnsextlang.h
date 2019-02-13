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

#ifndef DNSEXTLANG_H_
#define DNSEXTLANG_H_
#include "pzl/dns_config.h"
#include "pzl/return_status.h"
#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#ifndef NO_DNS_DEFAULT_RRTYPES
#ifdef  DNS_DEFAULT_RRTYPES
#undef  DNS_DEFAULT_RRTYPES
#endif
#define DNS_DEFAULT_RRTYPES dns_default_rrtypes

#ifdef  DNS_CONFIG_DEFAULTS
#undef  DNS_CONFIG_DEFAULTS
#define DNS_CONFIG_DEFAULTS { DNS_DEFAULT_TTL   , DNS_DEFAULT_CLASS   \
                            , DNS_DEFAULT_ORIGIN, DNS_DEFAULT_RRTYPES }
#endif
#endif

void uint_table_free(
    size_t depth, uint64_t number, const void *ptr, void *userarg);

typedef const void * uint8_table;

static inline const void **uint8_table_lookup_(uint8_table *table, uint8_t value)
{ return !table ? NULL : &table[value]; }

static inline const void *uint8_table_lookup(uint8_table *table, uint8_t value)
{ return !table ? NULL : table[value]; }

status_code uint8_table_add(
    uint8_table **tabler, uint8_t value, const void *ptr, return_status *st);

typedef void (*uint_table_walk_func)(
    size_t depth, uint64_t number, const void *ptr, void *userarg);

void uint8_table_walk(uint8_table *table,
    uint_table_walk_func leaf, uint_table_walk_func branch, void *userarg);

static inline void uint8_table_free_(
    uint8_table *table, uint_table_walk_func leaf, void *userarg)
{ uint8_table_walk(table, leaf, uint_table_free, userarg); }

static inline void uint8_table_free(uint8_table *table)
{ uint8_table_walk(table, NULL, uint_table_free, NULL); }

#define DEF_UINT_TABLE_DECL(HI,LO,UINT_T,MASK) \
	typedef uint ## LO ## _table *uint ## HI ##_table; \
	\
	static inline const void *uint ## HI ## _table_lookup( \
	    uint ## HI ## _table *table, UINT_T value) \
	{ return !table ? NULL : uint ## LO ## _table_lookup(\
	    table[(value >> LO) & 0xFF], value & MASK); } \
	\
	static inline const void **uint ## HI ## _table_lookup_( \
	    uint ## HI ## _table *table, UINT_T value) \
	{ return !table ? NULL : uint ## LO ## _table_lookup_(\
	    table[(value >> LO) & 0xFF], value & MASK); } \
	\
	status_code uint ## HI ## _table_add( \
	    uint ## HI ## _table **table_r, UINT_T value, \
	    const void *ptr, return_status *st); \
	\
	void uint ## HI ## _table_walk(uint ## HI ## _table *table, \
	    uint_table_walk_func leaf, uint_table_walk_func branch, \
	    void *userarg); \
	\
	static inline void uint ## HI ## _table_free_( \
	    uint ## HI ## _table *t, uint_table_walk_func l, void *u) \
	{ uint ## HI ## _table_walk(t, l, uint_table_free, u); } \
	\
	static inline void uint ## HI ## _table_free( \
	    uint ## HI ## _table *table) \
	{ uint ## HI ## _table_walk(table, NULL, uint_table_free, NULL); }

DEF_UINT_TABLE_DECL(16,  8, uint16_t, 0xFF)
DEF_UINT_TABLE_DECL(24, 16, uint32_t, 0xFFFFUL)
DEF_UINT_TABLE_DECL(32, 24, uint32_t, 0xFFFFFFUL)

/* Not needed, but...
 * DEF_UINT_TABLE_DECL(40, 32, uint64_t, 0xFFFFFFFFULL)
 * DEF_UINT_TABLE_DECL(48, 40, uint64_t, 0xFFFFFFFFFFULL)
 * DEF_UINT_TABLE_DECL(56, 48, uint64_t, 0xFFFFFFFFFFFFULL)
 * DEF_UINT_TABLE_DECL(64, 56, uint64_t, 0xFFFFFFFFFFFFFFULL)
 */

typedef union uint_table {
	uint8_table  *I1;
	uint16_table *I2;
	uint32_table *I4;
} uint_table;

#define LDH_N_EDGES 46

typedef struct ldh_radix ldh_radix;
struct ldh_radix {
	const char *label;
	uint16_t    len;
	const void *value;
	ldh_radix  *edges[LDH_N_EDGES];
};

static inline const void *ldh_radix_lookup(
    ldh_radix *r, const char *str, size_t len)
{
	for (;;) {
		if (!r || len < r->len
		||  (r->len && strncasecmp(r->label, str, r->len)))
			return NULL;
		len -= r->len;
		if (!len)
			return r->value;
		str += r->len;
		r = r->edges[(toupper(*str) - '-') % LDH_N_EDGES];
	}
}

status_code ldh_radix_insert(ldh_radix **r,
    const char *str, size_t len, const void *value, return_status *st);

typedef status_code (*ldh_radix_walk_func)(char *str, ldh_radix *r,
    void *userarg, return_status *st);

status_code ldh_radix_walk(char *buf, size_t bufsz, ldh_radix *r,
    ldh_radix_walk_func func, void *userarg, return_status *st);

/* ldh_trie is 4% faster than ldh_radix (but wastful with memory) */
typedef struct ldh_trie ldh_trie;
struct ldh_trie {
	ldh_trie   *edges[LDH_N_EDGES];
	const void *value;
};

static inline const void *ldh_trie_lookup(
    ldh_trie *r, const char *str, size_t len)
{ 
	if (!r)
		return NULL;

	else while (len) {
		if (!(r = r->edges[(toupper(*str)-'-')%LDH_N_EDGES]))
			return NULL;
		str++;
		len--;
	};
	return r->value;
}

status_code ldh_trie_insert(ldh_trie **r,
    const char *str, size_t len, const void *value, return_status *st);

typedef status_code (*ldh_trie_walk_func)(char *str, ldh_trie *r,
    void *userarg, return_status *st);

status_code ldh_trie_walk(char *buf, size_t bufsz, ldh_trie *r,
    ldh_trie_walk_func func, void *userarg, return_status *st);

#ifdef  USE_LDH_TRIE
#define LDH_CONTAINER ldh_trie
#define LDH_LOOKUP    ldh_trie_lookup
#define LDH_INSERT    ldh_trie_insert
#define LDH_WALK_FUNC ldh_trie_walk_func
#define LDH_WALK      ldh_trie_walk
#else
#define LDH_CONTAINER ldh_radix
#define LDH_LOOKUP    ldh_radix_lookup
#define LDH_INSERT    ldh_radix_insert
#define LDH_WALK_FUNC ldh_radix_walk_func
#define LDH_WALK      ldh_radix_walk
#endif

struct dnsextlang_def;
extern struct dnsextlang_def *dns_default_rrtypes;

typedef enum dnsextlang_qual {
	del_qual_C         = 1 <<  0, /* With N: Compressed dname
	                               *         ( NS, MD, MF, CNAME, SOA,
	                               *           MB, MG, MR, PTR, MINFO & MX )
	                               * With X: Hex data with 1 byte length
	                               *         ( NSEC3 & NSEC3PARAM )
	                               */
	del_qual_A         = 1 <<  1, /* With N: Mailbox dname 
	                               *         ( SOA, MG, MR, MINFO & RP )
	                               */
	del_qual_L         = 1 <<  2, /* With N: Lowercased dname
	                               * With R: Type bitmap
	                               */
	del_qual_O         = 1 <<  3, /* Optional rdata field  (must be last) */
	del_qual_M         = 1 <<  4, /* Multiple rdata fields (must be last) */
	del_qual_X         = 1 <<  5, /* Remaining data field  (must be last)
	                               * Only applies to variable length types:
	                               * S, B32, B64 (default) & X (default)
	                               */
	del_qual_P         = 1 <<  6, /* Defined but not described in draft   */
	del_qual_WKS       = 1 <<  7,
	del_qual_NSAP      = 1 <<  8,
	del_qual_NXT       = 1 <<  9, /* Should this not be R[L] ?            */
	del_qual_A6P       = 1 << 10,
	del_qual_A6S       = 1 << 11,
	del_qual_APL       = 1 << 12,
	del_qual_IPSECKEY  = 1 << 13,
	del_qual_HIPHIT    = 1 << 14,
	del_qual_HIPPK     = 1 << 15
} dnsextlang_qual;

typedef enum dnsextlang_ftype {
	del_ftype_I1 = 0, del_ftype_I2 = 1, del_ftype_I4    =  2,
	del_ftype_A  = 3, del_ftype_AA = 4, del_ftype_AAAA  =  5,
	                  del_ftype_X6 = 6, del_ftype_EUI48 =  6,
	                  del_ftype_X8 = 7, del_ftype_EUI64 =  7,
	del_ftype_T  = 8, del_ftype_T6 = 9, del_ftype_R     = 10,

	del_ftype_N , del_ftype_S , del_ftype_B32, del_ftype_B64,
	del_ftype_X , del_ftype_Z
} dnsextlang_ftype;

static inline uint8_t dnsextlang_wf_field_len(
    dnsextlang_ftype ftype, dnsextlang_qual quals) {
	if (ftype < del_ftype_R)
		return "\x01\x02\x04\x04\x08\x10\x06\x08\x04\x06"[ftype];
	switch (ftype) {
	case del_ftype_S  :
	case del_ftype_B32: return quals & del_qual_X ?
                            0x80 : quals & del_qual_L ? 0x82 : 0x81;
	case del_ftype_X  :
	case del_ftype_B64: return quals & del_qual_C ?
	                    0x81 : quals & del_qual_L ? 0x82 : 0x80;
	case del_ftype_R  : return quals & del_qual_L ? 0xFF : 0x02;
	case del_ftype_N  : return 0x40;
	default           : return 0xFF;
	}
}

typedef enum dnsextlang_option {
	del_option_A = 1 <<  0, del_option_B = 1 <<  1, del_option_C = 1 <<  2,
	del_option_D = 1 <<  3, del_option_E = 1 <<  4, del_option_F = 1 <<  5,
	del_option_G = 1 <<  6, del_option_H = 1 <<  7, del_option_I = 1 <<  8,
	del_option_J = 1 <<  9, del_option_K = 1 << 10, del_option_L = 1 << 11,
	del_option_M = 1 << 12, del_option_N = 1 << 13, del_option_O = 1 << 14,
	del_option_P = 1 << 15, del_option_Q = 1 << 16, del_option_R = 1 << 17,
	del_option_S = 1 << 18, del_option_T = 1 << 19, del_option_U = 1 << 20,
	del_option_V = 1 << 21, del_option_W = 1 << 22, del_option_X = 1 << 23,
	del_option_Y = 1 << 24, del_option_Z = 1 << 25
} dnsextlang_option;

typedef struct dnsextlang_field {
	dnsextlang_ftype   ftype;
	dnsextlang_qual    quals;
	uint_table         symbols_by_int;
	ldh_radix         *symbols_by_ldh;
	const char        *tag;
	const char        *description;
} dnsextlang_field;

typedef struct dnsextlang_stanza {
	const char        *name;
	uint16_t           number;
	dnsextlang_option  options;
	const char        *description;
	size_t           n_fields;
	dnsextlang_field  *fields;
} dnsextlang_stanza;

typedef struct dnsextlang_def dnsextlang_def;
struct dnsextlang_def {
	uint16_table   *stanzas_by_u16;
	LDH_CONTAINER  *stanzas_by_ldh;
	dnsextlang_def *fallback;
};

static inline const dnsextlang_stanza *dnsextlang_get_stanza_(
    dnsextlang_def *def, uint16_t rrtype)
{
	if (!def)
		return NULL;
	return (dnsextlang_stanza *)
	    uint16_table_lookup(def->stanzas_by_u16, rrtype);
}

static inline const dnsextlang_stanza *dnsextlang_get_stanza(uint16_t rrtype)
{ return dnsextlang_get_stanza_(DNS_DEFAULT_RRTYPES, rrtype); }


static inline int dnsextlang_get_TYPE_rrtype(
    const char *rrtype, size_t rrtype_strlen, return_status *st)
{
	if (rrtype_strlen > 4
	&& (rrtype[0] == 'T' || rrtype[0] == 't')
	&& (rrtype[1] == 'Y' || rrtype[1] == 'y')
	&& (rrtype[2] == 'P' || rrtype[2] == 'p')
	&& (rrtype[3] == 'E' || rrtype[3] == 'e')) {

		char numbuf[6], *endptr;
		unsigned long int n;

		if (rrtype_strlen - 4 > sizeof(numbuf) - 1)
			return -RETURN_PARSE_ERR(st,
			    "rrtype TYPE number too large", NULL, 0, 0);

		(void) memcpy(numbuf, rrtype + 4, rrtype_strlen - 4);
		numbuf[rrtype_strlen - 4] = 0;
		n = strtoul(numbuf, &endptr, 10);

		if (*endptr)
			return -RETURN_PARSE_ERR(st,
			    "syntax error in rrtype TYPE number", NULL, 0, 0);

		if (n > 65535)
			return -RETURN_PARSE_ERR(st,
			    "rrtype TYPE number must be < 65536", NULL, 0, 0);
		return n;
	}
	return -RETURN_NOT_FOUND_ERR(st, "rrtype not found");
}

int dnsextlang_get_type_(
    const char *rrtype, size_t rrtype_strlen, return_status *st);

static inline int dnsextlang_get_type__(dnsextlang_def *def,
    const char *rrtype, size_t rrtype_strlen, return_status *st)
{
	const dnsextlang_stanza *r;
       
	if (!def)
		return -RETURN_USAGE_ERR(st, "missing rrtypes definition");

	if (def) {
		if ((r = LDH_LOOKUP(
		    def->stanzas_by_ldh, rrtype, rrtype_strlen)))
			return r->number;
#if 0
		if (def->fallback == dns_default_rrtypes)
			return dnsextlang_get_type_(
			    rrtype, rrtype_strlen, st);
#endif
		if (def->fallback)
			return dnsextlang_get_type__(
			    def->fallback, rrtype, rrtype_strlen, st);
	}
	return dnsextlang_get_TYPE_rrtype(rrtype, rrtype_strlen, st);
}

static inline int dnsextlang_get_type(const char *rrtype)
{ return dnsextlang_get_type_(rrtype, (rrtype ? strlen(rrtype) : 0), NULL); }

const dnsextlang_stanza *dnsextlang_lookup_(
    const char *s, size_t len, return_status *st);

static inline const dnsextlang_stanza *dnsextlang_lookup__(dnsextlang_def *def,
    const char *rrtype, size_t rrtype_strlen, return_status *st)
{
	const dnsextlang_stanza *r;
	int ri;
       
	if (!def) {
		(void) RETURN_USAGE_ERR(st, "missing rrtypes definition");
		return NULL;
	}
	if (def) {
		if ((r = LDH_LOOKUP(
		    def->stanzas_by_ldh, rrtype, rrtype_strlen)))
			return r;
#if 0
		if (def->fallback == dns_default_rrtypes)
			return dnsextlang_lookup_(rrtype, rrtype_strlen, st);
#endif
		if (def->fallback)
			return dnsextlang_lookup__(
			    def->fallback, rrtype, rrtype_strlen, st);
	}
	ri = dnsextlang_get_TYPE_rrtype(rrtype, rrtype_strlen, st);
	if (ri < 0)
		return NULL;
	return dnsextlang_get_stanza_(def, ri);
}

const dnsextlang_stanza *dnsextlang_lookup_(
    const char *s, size_t len, return_status *st);

static inline const dnsextlang_stanza *dnsextlang_lookup(const char *rrtype)
{ return dnsextlang_lookup_(rrtype, ( rrtype ? strlen(rrtype) : 0 ), NULL); }

dnsextlang_def *dnsextlang_def_new_from_text_(
    dns_config *cfg, const char *text, size_t text_len, return_status *st);

inline static dnsextlang_def *dnsextlang_def_new_from_text(
    const char *text, size_t text_len)
{ return dnsextlang_def_new_from_text_(NULL, text, text_len, NULL); }


dnsextlang_def *dnsextlang_def_new_from_fn_(
    dns_config *cfg, const char *fn, return_status *st);

inline static dnsextlang_def *dnsextlang_def_new_from_fn(const char *fn)
{ return dnsextlang_def_new_from_fn_(NULL, fn, NULL); }

void dnsextlang_def_free(dnsextlang_def *def);

#endif /* #ifndef DNSEXTLANG_H_ */
