/*
 * $Id: namedb.h,v 1.36 2003/07/01 13:18:35 erik Exp $
 *
 * namedb.h -- nsd(8) internal namespace database definitions
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _NAMEDB_H_
#define	_NAMEDB_H_

#define DEFAULT_ALIGNMENT       (sizeof (void *))
#define ALIGN_UP(x)                (((x) + DEFAULT_ALIGNMENT - 1) & (~(DEFAULT_ALIGNMENT - 1)))

#define	NAMEDB_MAXDSIZE		32768	/* Maximum size of a domain */

#define	NAMEDB_DELEGATION	0x0001
#define	NAMEDB_STEALTH		0x0002

#define	NAMEDB_AUTHMASK		0
#define	NAMEDB_STARMASK		1
#define	NAMEDB_DATAMASK		2

#define	NAMEDB_BITMASKLEN	16

#define	NAMEDB_TSTBITMASK(db, mask, depth) (db->masks[mask][(depth) >> 3] & (1 << ((depth) & 0x7)))
#define	NAMEDB_SETBITMASK(db, mask, depth) db->masks[mask][(depth) >> 3] |= (1 << ((depth) & 0x7))


#define	ANSWER_SIZE(a)		a->size
#define	ANSWER_SIZE_PTR(a)	(&a->size)
#define	ANSWER_TYPE(a)		a->type
#define	ANSWER_TYPE_PTR(a)	(&a->type)
#define	ANSWER_ANCOUNT(a)	a->ancount
#define	ANSWER_ANCOUNT_PTR(a)	(&a->ancount)
#define	ANSWER_NSCOUNT(a)	a->nscount
#define	ANSWER_NSCOUNT_PTR(a)	(&a->nscount)
#define	ANSWER_ARCOUNT(a)	a->arcount
#define	ANSWER_ARCOUNT_PTR(a)	(&a->arcount)
#define	ANSWER_PTRSLEN(a)	a->ptrslen
#define	ANSWER_PTRSLEN_PTR(a)	(&a->ptrslen)
#define	ANSWER_RRSLEN(a)	a->rrslen
#define	ANSWER_RRSLEN_PTR(a)	(&a->rrslen)
#define	ANSWER_DATALEN(a)	a->datalen
#define	ANSWER_DATALEN_PTR(a)	(&a->datalen)
#define	ANSWER_END_PTR(a)	((struct answer *)a+1)
#define	ANSWER_PTRS_PTR(a)	((u_int16_t *)ANSWER_END_PTR(a))
#define	ANSWER_PTRS(a, i)	*((u_int16_t *)ANSWER_END_PTR(a) + (i))
#define	ANSWER_RRS_PTR(a)	((u_int16_t *)ANSWER_END_PTR(a))+ANSWER_PTRSLEN(a)
#define	ANSWER_RRS(a, i)	(*(((u_int16_t *)ANSWER_END_PTR(a))+ANSWER_PTRSLEN(a)+(i)) & ~NAMEDB_RRSET_COLOR)
#define	ANSWER_RRS_COLOR(a, i)	(*(((u_int16_t *)ANSWER_END_PTR(a))+ANSWER_PTRSLEN(a)+(i)) & NAMEDB_RRSET_COLOR)
#define	ANSWER_DATA_PTR(a)	(u_char *)(((u_int16_t *)ANSWER_END_PTR(a))+ANSWER_PTRSLEN(a)+ANSWER_RRSLEN(a))


struct answer {
	u_int32_t size;
	u_int16_t type;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
	u_int16_t ptrslen;
	u_int16_t rrslen;
	u_int32_t datalen;
	/* u_int16_t ptrs[0]; */
	/* u_int16_t rrs[0]; */
	/* char *data; */
};

struct domain {
	u_int32_t size;
	u_int16_t flags;
	void     *runtime_data; /* Additional run-time data (used for plugins) */
};

#define	NAMEDB_MAGIC		"NSDdbV02"
#define	NAMEDB_MAGIC_SIZE	8

#define	NAMEDB_RRSET_WHITE	0x8000U
#define	NAMEDB_RRSET_BLACK	0x0000U
#define	NAMEDB_RRSET_COLOR	0x8000U

#define	DOMAIN_WALK(d, a)	for(a = (struct answer *)(d + 1); \
					ANSWER_SIZE(a) != 0; \
					a = (struct answer *)((char *)a + ANSWER_SIZE(a)))
#define	DOMAIN_SIZE(d)		d->size
#define	DOMAIN_FLAGS(d)		d->flags

#if defined(NAMEDB_UPPERCASE) || defined(USE_NAMEDB_UPPERCASE)
#define	NAMEDB_NORMALIZE	toupper
#else
#define	NAMEDB_NORMALIZE	tolower
#endif


#include "heap.h"

struct namedb {
	heap_t *heap;
	u_char masks[3][NAMEDB_BITMASKLEN];
	char *mpool;
	size_t	mpoolsz;
	char *filename;
	int fd;
};

/* dbcreate.c */
struct namedb *namedb_new(const char *filename);
int namedb_put(struct namedb *db, const u_char *dname, struct domain *d);
int namedb_save(struct namedb *db);
void namedb_discard(struct namedb *db);


/* dbaccess.c */
int domaincmp(const void *a, const void *b);
unsigned long domainhash(const u_char *dname);
struct domain *namedb_lookup(struct namedb *db, const u_char *dname);
struct answer *namedb_answer(const struct domain *d, int type);
struct namedb *namedb_open(const char *filename);
void namedb_close(struct namedb *db);

/* Routines that the calling program must provide... */
extern void *xalloc (size_t size);
extern void *xrealloc(void *p, size_t size);

#endif
