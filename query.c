/*
 * $Id: query.c,v 1.6 2002/01/11 13:21:05 alexis Exp $
 *
 * query.c -- nsd(8) the resolver.
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "nsd.h"
#include "dns.h"
#include "db.h"
#include "query.h"

void
query_init(q)
	struct query *q;
{
	q->addrlen = sizeof(struct sockaddr);
	q->iobufsz = QIOBUFSZ;
	q->iobufptr = q->iobuf;
}

struct query *
query_new()
{
	struct query *q;

	if((q = xalloc(sizeof(struct query))) == NULL) {
		return NULL;
	}

	query_init(q);
	return q;
}

void
query_destroy(q)
	struct query *q;
{
	if(q)
		free(q);
}

void
query_addanswer(q, dname, a)
	struct query *q;
	u_char *dname;
	struct answer *a;
{
	int j;
	u_char *qptr;
	u_short pointer;
	u_short *ptrs;

	/* The size of the data */
	size_t datasize = a->size - ((a->ptrlen + 5) * sizeof(u_short) + sizeof(size_t));

	/* Copy the counters */
	bcopy(&a->ancount, q->iobuf + 6, 6);

	/* Then copy the data */
	bcopy(&a->ptrlen + a->ptrlen + 1, q->iobufptr, datasize);
	ptrs = &a->ptrlen + 1;

	/* Walk the pointers */
	for(j = 0; j < a->ptrlen; j++) {
		qptr = q->iobufptr + ptrs[j];
		bcopy(qptr, &pointer, 2);
		if(pointer & 0xc000) {
			/* XXX Check if dname is within packet */
			pointer = htons(0xc000 | (dname - q->iobuf + (pointer & 0x0fff)));/* dname - q->iobuf */
		} else {
			pointer = htons(0xc000 | (u_short)(pointer + q->iobufptr - q->iobuf));
		}
		bcopy(&pointer, qptr, 2);
	}
	q->iobufptr += datasize;
}


int
query_process(q, db)
	struct query *q;
	struct db *db;
{
	/* Just for safety, we dont need + 2 here... */
	u_char qnamestar[MAXDOMAINLEN + 2] = "\001*";

	/* The query... */
	u_char	*qname;
	u_char qnamelen;
	u_short qtype;
	u_short qclass;
	u_char *qptr;
	int qdepth;

	struct domain *d;
	struct answer *a;

	/* Sanity checks */
	if(QR(q)) return -1;	/* Not a query? Drop it on the floor. */

	*(u_short *)(q->iobuf + 2) = 0;
	QR_SET(q);				/* This is an answer */

	/* Do we serve this type of query */
	if(OPCODE(q) != OPCODE_QUERY) {
		RCODE_SET(q, RCODE_IMPL);
		return 0;
	}

	/* Dont bother to answer more than one question at once, but this will change for EDNS(0) */
	if(ntohs(QDCOUNT(q)) != 1) {
		RCODE_SET(q, RCODE_IMPL);
		return 0;
	}

	/* Lets parse the qname */
	for(qdepth = 0, qname = qptr = q->iobuf + QHEADERSZ; *qptr; qptr += *qptr + 1, qdepth++) {
		/*  If we are out of buffer limits or we have a pointer in question dname... */
		if((qptr > q->iobufptr) || (*qptr & 0xc0)) {
			RCODE_SET(q, RCODE_FORMAT);
			return 0;
		}
	}

	qptr++;

	/* Make sure name is not too long... */
	if((qnamelen = qptr - (q->iobuf + QHEADERSZ)) > MAXDOMAINLEN) {
		RCODE_SET(q, RCODE_FORMAT);
		return 0;
	}


	bcopy(qptr, &qtype, 2); qptr += 2;
	bcopy(qptr, &qclass, 2); qptr += 2;

	/* Unsupported class */
	if(ntohs(qclass) != CLASS_IN) {
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	/* Do we have the complete name? */
	if(TSTMASK(db->mask.data, qdepth) && ((d = db_lookup(db, qname, qnamelen)) != NULL)) {
		/* Is this a delegation point? */
		if(d->flags & DB_DELEGATION) {
			if((a = db_answer(d, htons(TYPE_NS))) == NULL) {
				RCODE_SET(q, RCODE_SERVFAIL);
				return 0;
			}
			AA_CLR(q);
			query_addanswer(q, qname, a);
			return 0;
		} else {
			if((a = db_answer(d, qtype)) != NULL) {
				AA_SET(q);
				query_addanswer(q, qname, a);
				return 0;
			} else {
				/* Do we have SOA record in this domain? */
				if((a = db_answer(d, htons(TYPE_SOA))) != NULL) {
					AA_SET(q);
					query_addanswer(q, qname, a);
					return 0;
				}
			}
		}
	} else {
		/* Set this if we find SOA later */
		RCODE_SET(q, RCODE_NXDOMAIN);
	}

	/* Start matching down label by label */
	do {
		/* Strip leftmost label */
		qnamelen -= (*qname + 1);
		qname += (*qname + 1);
		qdepth--;

		/* Do we have a SOA or zone cut? */
		if(TSTMASK(db->mask.auth, qdepth) && ((d = db_lookup(db, qname, qnamelen)) != NULL)) {
			if(d->flags & DB_DELEGATION) {
				if((a = db_answer(d, htons(TYPE_NS))) == NULL) {
					RCODE_SET(q, RCODE_SERVFAIL);
					return 0;
				}
				RCODE_SET(q, RCODE_OK);
				AA_CLR(q);
				query_addanswer(q, qname, a);
				return 0;
			} else {
				if((a = db_answer(d, htons(TYPE_SOA)))) {
					AA_SET(q);
					query_addanswer(q, qname, a);
					return 0;
				}
			}
		} else {
			/* Only look for wildcards if we did not match a domain before */
			if(TSTMASK(db->mask.stars, qdepth + 1) && (RCODE(q) == RCODE_NXDOMAIN)) {
				/* Prepend star */
				bcopy(qname, qnamestar + 2, qnamelen);

				/* Lookup star */
				if((d = db_lookup(db, qnamestar, qnamelen + 2)) != NULL) {
					/* We found a domain... */
					RCODE_SET(q, RCODE_OK);

					if((a = db_answer(d, qtype)) != NULL) {
						AA_SET(q);
						query_addanswer(q, qname, a);
						return 0;
					}
				}
			}
			/* Neither name nor wildcard exists */
			continue;
		}
	} while(*qname);

	RCODE_SET(q, RCODE_SERVFAIL);
	return 0;
}
