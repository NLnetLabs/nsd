/*
 * $Id: namedb.h,v 1.4 2002/01/30 14:40:58 alexis Exp $
 *
 * namedb.h -- nsd(8) internal namespace database definitions
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
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

#define	NAMEDB_MAXDSIZE		32768	/* Maximum size of a domain */

#define	NAMEDB_DELEGATION	0x0001
#define	NAMEDB_WILDCARD		0x0002

#define	NAMEDB_TSTBITMASK(mask, depth) (mask[(depth) >> 3] & (1 << ((depth) & 0x7)))
#define	NAMEDB_SETBITMASK(mask, depth) mask[(depth) >> 3] |= (1 << ((depth) & 0x7))

#define	NAMEDB_BITMASKLEN	16

#define	ANSWER_SIZE(a)		(size_t *)(&a->size)
#define	ANSWER_TYPE(a)		(u_int16_t *)(&a->type)
#define	ANSWER_ANCOUNT(a)	(u_int16_t *)(&a->ancount)
#define	ANSWER_NSCOUNT(a)	(u_int16_t *)(&a->nscount)
#define	ANSWER_ARCOUNT(a)	(u_int16_t *)(&a->arcount)
#define	ANSWER_PTRLEN(a)	(u_int16_t *)(&a->ptrlen)
#define	ANSWER_RRSLEN(a)	(u_int16_t *)(&a->rrslen)
#define	ANSWER_DATALEN(a)	(size_t *)(&a->datalen)
#define	ANSWER_END(a)		((struct answer *)a+1)
#define	ANSWER_PTRS(a)		((u_int16_t *)ANSWER_END(a))
#define	ANSWER_RRS(a)		((u_int16_t *)ANSWER_END(a))+*ANSWER_PTRLEN(a)
#define	ANSWER_DATA(a)		(u_char *)(((u_int16_t *)ANSWER_END(a))+*ANSWER_PTRLEN(a)+*ANSWER_RRSLEN(a))


struct answer {
	size_t size;
	u_int16_t type;
	u_int16_t	ancount;
	u_int16_t nscount;
	u_int16_t arcount;
	u_int16_t ptrlen;
	u_int16_t rrslen;
	size_t datalen;
	/* u_int16_t ptrs[0]; */
	/* u_int16_t rrs[0]; */
	/* char *data; */
};

struct domain {
	size_t size;
	u_int16_t	flags;
};

#define	DOMAIN_WALK(d, a)	for(a = (struct answer *)(d + 1); *ANSWER_SIZE(a) != 0; ((char *)a) += *ANSWER_SIZE(a))
#define	DOMAIN_SIZE(d)		(size_t *)(&((struct domain *)d)->size)
#define	DOMAIN_FLAGS(d)		(u_int16_t *)(&((struct domain *)d)->flags)

#endif
