/*
 * $Id: query.c,v 1.1 2002/01/08 16:06:20 alexis Exp $
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
#include "query.h"
#include "db.h"

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

int
query_process(q, db)
	struct query *q;
	DB *db;
{
	u_short class;
	u_short type;
	u_short *pointers;
	u_short pointerslen;
	u_short pointer;

	u_char *qptr;
	DBT key, data;
	int i, j;

	/* qname parsing stack */
	u_char *stack[STACKSZ];
	int stacklen;

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
	stacklen = 0;
	qptr = q->iobuf + QHEADERSZ;

	while(*qptr) {
		/* If we are out of array limits... */
		if(stacklen >= STACKSZ - 1) {
			RCODE_SET(q, RCODE_SERVFAIL);
			return 0;
		}

		/*  If we are out of buffer limits or we have a pointer in question dname... */
		if((qptr > q->iobufptr) || (*qptr & 0xc0)) {
			RCODE_SET(q, RCODE_FORMAT);
			return 0;
		}

		stack[stacklen++] = qptr;
		qptr += ((int)*qptr) + 1;
	}
	stack[stacklen++] = qptr;

	/* Advance beyond the trailing \000 */
	stack[stacklen++] = ++qptr;

	bcopy(qptr, &type, 2); qptr += 2;
	bcopy(qptr, &class, 2); qptr += 2;

	/* Unsupported class */
	if(ntohs(class) != CLASS_IN) {
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	/* Any other answer is authorative */
	AA_SET(q);


/*	for(i = 0; i < stacklen - 1; i++) { */
	i = 0;
		key.size = (stack[stacklen - 1] - stack[i]) + sizeof(u_short);
		key.data = stack[i];

		switch(db->get(db, &key, &data, 0)) {
		case -1:
			syslog(LOG_ERR, "database lookup failed: %m");
			return -1;
		case 1:
			RCODE_SET(q, RCODE_NXDOMAIN);
			return 0;
		case 0:
			/* First the pointers */
			bcopy(data.data, q->iobuf + 6, 6);
			pointerslen = *(u_short *)(data.data + 6);
			pointers = data.data + 8;
			qptr = data.data + 8 + pointerslen * sizeof(u_short);
			bcopy(qptr, q->iobufptr, data.size - 8 - pointerslen * sizeof(u_short));
			
			for(j = 0; j < pointerslen; j++) {
				qptr = q->iobufptr + pointers[j];
				bcopy(qptr, &pointer, 2);
				if(pointer == 0) {
					/* XXX Check if dname is within packet */
					pointer = htons(0xc000 | (u_short)(12));/* dname - q->iobuf */
				} else {
					pointer = htons(0xc000 | (u_short)(pointer + q->iobufptr - q->iobuf));
				}
				bcopy(&pointer, qptr, 2);
			}
			q->iobufptr += data.size - 8 - pointerslen * sizeof(u_short);
	
			return 0;
		}
/*	} */

	return 0;
}
