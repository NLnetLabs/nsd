/*
 * $Id: namedb.h,v 1.1 2002/01/28 16:02:59 alexis Exp $
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

#define	ANSWER_SIZE(answer)	(size_t *)(&answer->size)
#define	ANSWER_TYPE(answer)	(u_short *)(&answer->type)
#define	ANSWER_ANCOUNT(answer)	(u_short *)(&answer->ancount)
#define	ANSWER_NSCOUNT(answer)	(u_short *)(&answer->nscount)
#define	ANSWER_ARCOUNT(answer)	(u_short *)(&answer->arcount)
#define	ANSWER_PTRLEN(answer)	(u_short *)(&answer->ptrlen)
#define	ANSWER_RRSLEN(answer)	(u_short *)(&answer->rrslen)
#define	ANSWER_DATALEN(answer)	(size_t *)(&answer->datalen)
#define	ANSWER_END(answer)	(ANSWER_DATALEN(answer)+1)
#define	ANSWER_PTRS(answer)	((u_short *)ANSWER_END(answer))
#define	ANSWER_RRS(answer)	((u_short *)ANSWER_END(answer))+*ANSWER_PTRLEN(answer)
#define	ANSWER_DATA(answer)	(u_char *)(((u_short *)ANSWER_END(answer))+*ANSWER_PTRLEN(answer)+*ANSWER_RRSLEN(answer))


struct answer {
	size_t size;
	u_short type;
	u_short	ancount;
	u_short nscount;
	u_short arcount;
	u_short ptrlen;
	u_short rrslen;
	size_t datalen;
	/* u_short ptrs[0]; */
	/* u_short rrs[0]; */
	/* char *data; */
};

struct domain {
	size_t size;
	u_short	flags;
};

#define	DOMAIN_WALK(domain, answer)	for(answer = (struct answer *)(domain + 1); \
						*ANSWER_SIZE(answer) != 0; \
						((char *)answer) += *ANSWER_SIZE(answer))

#define	DOMAIN_SIZE(domain)	(size_t *)(&((struct domain *)domain)->size)
#define	DOMAIN_FLAGS(domain)	(u_short *)(&((struct domain *)domain)->flags)

#endif
