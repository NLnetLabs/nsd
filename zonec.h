/*
 * $Id: zonec.h,v 1.23 2003/06/16 15:13:16 erik Exp $
 *
 * zone.h -- internal zone representation
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

#ifndef _ZONEC_H_
#define _ZONEC_H_

struct rrset {
	struct rrset *next;
	u_int16_t type;
	u_int16_t class;
	int32_t ttl;
	int glue;
	int color;
	u_int16_t rrslen;
	u_int16_t ***rrs;
};

struct zone {
	u_char *dname;
	heap_t	*cuts;
	heap_t	*data;
	struct rrset *soa;
	struct rrset *ns;
};

#define MAXRRSPP	1024
#define	IOBUFSZ		MAXRRSPP * 64
#define	LINEBUFSZ	1024

struct message {
	u_char *bufptr;
	u_int16_t ancount;
	u_int16_t nscount;
	u_int16_t arcount;
	int dnameslen;
	int rrsetslen;
	int comprlen;
	u_int16_t pointerslen;
	u_int16_t pointers[MAXRRSPP];
	u_int16_t rrsetsoffslen;
	u_int16_t rrsetsoffs[MAXRRSPP];
	struct rrset *rrsets[MAXRRSPP];
	u_char *dnames[MAXRRSPP];
	struct {
		u_char *dname;
		u_int16_t dnameoff;
		u_char dnamelen;
	} compr[MAXRRSPP];
	u_char buf[IOBUFSZ];
};

/* zonec.c */
void *xalloc(register size_t size);
void *xrealloc(register void *p, register size_t size);
void zone_initmsg(struct message *m);
void zone_print(struct zone *z);
u_int16_t zone_addname(struct message *msg, u_char *dname);
u_int16_t zone_addrrset(struct message *msg, u_char *dname, struct rrset *rrset);
struct domain *zone_addanswer(struct domain *d, struct message *msg, int type);
void zone_free(struct zone *z);
struct zone *zone_read(char *name, char *zonefile);
int zone_dump(struct zone *z, struct namedb *db);
void usage(void);

#endif /* _ZONEC_H_ */
