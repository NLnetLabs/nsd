/*
 * $Id: query.c,v 1.19 2002/02/02 22:55:04 alexis Exp $
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
#include "nsd.h"

struct domain *
lookup(db, dname, dnamelen)
	DB *db;
	u_char *dname;
	int dnamelen;
{
	DBT key, data;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	key.size = (size_t)dnamelen;
	key.data = dname;

	switch(db->get(db, NULL, &key, &data, 0)) {
	case -1:
		syslog(LOG_ERR, "database lookup failed: %m");
		return NULL;
	case DB_NOTFOUND:
		return NULL;
	case 0:
		return data.data;
	}

	return NULL;
}


struct answer *
answer(d, type)
	struct domain *d;
	u_int16_t type;
{
	struct answer *a;

	DOMAIN_WALK(d, a) {
		if(a->type == type) {
			return a;
		}
	}
	return NULL;
}

void
query_init(q)
	struct query *q;
{
	q->addrlen = sizeof(struct sockaddr);
	q->iobufsz = QIOBUFSZ;
	q->iobufptr = q->iobuf;
	q->maxlen = 512;	/* XXX Should not be here */
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
	u_char *qptr;
	u_int16_t pointer;
	int  i, j;

	/* Copy the counters */
	ANCOUNT(q) = ANSWER_ANCOUNT(a);
	NSCOUNT(q) = ANSWER_NSCOUNT(a);
	ARCOUNT(q) = ANSWER_ARCOUNT(a);

	/* Then copy the data */
	bcopy(ANSWER_DATA_PTR(a), q->iobufptr, ANSWER_DATALEN(a));

	/* Walk the pointers */
	for(j = 0; j < ANSWER_PTRSLEN(a); j++) {
		qptr = q->iobufptr + *(ANSWER_PTRS_PTR(a)+j);
		bcopy(qptr, &pointer, 2);
		if(pointer & 0xc000) {
			/* XXX Check if dname is within packet */
			pointer = htons(0xc000 | (dname - q->iobuf + (pointer & 0x0fff)));/* dname - q->iobuf */
		} else {
			pointer = htons(0xc000 | (u_int16_t)(pointer + q->iobufptr - q->iobuf));
		}
		bcopy(&pointer, qptr, 2);
	}

	/* Truncate if necessary */
	if(q->maxlen < (q->iobufptr - q->iobuf + ANSWER_DATALEN(a))) {

		/* Start with the additional section, record by record... */
		for(i = ntohs(ANSWER_ARCOUNT(a)) - 1, j = ANSWER_RRSLEN(a) - 1; i > 0 && j > 0; j--, i--) {
			if(q->maxlen >= (q->iobufptr - q->iobuf + *(ANSWER_RRS_PTR(a) + j - 1))) {
				ARCOUNT(q) = htons(i-1);
				q->iobufptr += *(ANSWER_RRS_PTR(a) + j - 1);
				return;
			}
		}

		ARCOUNT(q) = htons(0);
		TC_SET(q);

		if(q->maxlen >= (q->iobufptr - q->iobuf + *(ANSWER_RRS_PTR(a) + j - ntohs(a->nscount) - 1))) {
			/* Truncate the athority section */
			NSCOUNT(q) = htons(0);
			q->iobufptr += *(ANSWER_RRS_PTR(a) + j - ntohs(a->nscount));
			return;
		}

		/* Send empty message */
		NSCOUNT(q) = 0;
		ANCOUNT(q) = 0;
		return;
	} else {
		q->iobufptr += ANSWER_DATALEN(a);
	}
}


int
query_process(q, db)
	struct query *q;
	DB *db;
{
	u_char qstar[2] = "\001*";
	u_char qnamebuf[MAXDOMAINLEN + 2];

	/* The query... */
	u_char	*qname, *qnamelow;
	u_char qnamelen;
	u_int16_t qtype;
	u_int16_t qclass;
	u_char *qptr;
	int qdepth, i;

	struct domain *d;
	struct answer *a;

	/* Sanity checks */
	if(QR(q)) return -1;	/* Not a query? Drop it on the floor. */

	*(u_int16_t *)(q->iobuf + 2) = 0;
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

	/* Dont allow any records in the query */
	if(ANCOUNT(q) != 0 || NSCOUNT(q) != 0 || ARCOUNT(q) != 0) {
		RCODE_SET(q, RCODE_FORMAT);
		return 0;
	}

	/* Lets parse the qname and convert it to lower case */
	qdepth = 0;
	qnamelow = qnamebuf + 2;
	qname = qptr = q->iobuf + QHEADERSZ;
	while(*qptr) {
		/*  If we are out of buffer limits or we have a pointer in question dname or the domain name is longer than MAXDOMAINLEN ... */
		if((qptr + qptr > q->iobufptr) || (*qptr & 0xc0) ||
			((qptr - q->iobuf + *qptr) > MAXDOMAINLEN)) {
			RCODE_SET(q, RCODE_FORMAT);
			return 0;
		}
		qdepth++;
		*qnamelow++ = *qptr;
		for(i = *qptr++; i; i--) {
			*qnamelow++ = NAMEDB_NORMALIZE(*qptr++);
		}
	}
	*qnamelow++ = *qptr++;
	qnamelow = qnamebuf + 2;

	/* Make sure name is not too long... */
	if((qnamelen = qptr - (q->iobuf + QHEADERSZ)) > MAXDOMAINLEN || TC(q)) {
		RCODE_SET(q, RCODE_FORMAT);
		return 0;
	}

	bcopy(qptr, &qtype, 2); qptr += 2;
	bcopy(qptr, &qclass, 2); qptr += 2;

	/* Unsupported class */
	if((ntohs(qclass) != CLASS_IN) && (ntohs(qclass) != CLASS_ANY)) {
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	switch(ntohs(qtype)) {
	case TYPE_AXFR:
	case TYPE_IXFR:
			RCODE_SET(q, RCODE_REFUSE);
			return 0;
			break;
	case TYPE_MAILA:
	case TYPE_MAILB:
			RCODE_SET(q, RCODE_IMPL);
			return 0;
			break;
	}

	/* Do we have the complete name? */
	if(NAMEDB_TSTBITMASK(datamask, qdepth) && ((d = lookup(db, qnamelow, qnamelen)) != NULL)) {
		/* Is this a delegation point? */
		if(DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
			if((a = answer(d, htons(TYPE_NS))) == NULL) {
				RCODE_SET(q, RCODE_SERVFAIL);
				return 0;
			}
			AA_CLR(q);
			query_addanswer(q, qname, a);
			return 0;
		} else {
			if((a = answer(d, qtype)) != NULL) {
				if(ntohs(qclass) != CLASS_ANY) {
					AA_SET(q);
				} else {
					AA_CLR(q);
				}
				query_addanswer(q, qname, a);
				return 0;
			} else {
				/* Do we have SOA record in this domain? */
				if((a = answer(d, htons(TYPE_SOA))) != NULL) {
					/* Setup truncation */
					qptr = q->iobufptr;

					if(ntohs(qclass) != CLASS_ANY) {
						AA_SET(q);
					} else {
						AA_CLR(q);
					}
					query_addanswer(q, qname, a);

					/* Truncate */
					ANCOUNT(q) = 0;
					NSCOUNT(q) = htons(1);
					ARCOUNT(q) = 0;
					q->iobufptr = qptr + *(ANSWER_RRS_PTR(a) + 1);

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
		qnamelow += (*qnamelow + 1);
		qdepth--;

		/* Do we have a SOA or zone cut? */
		if(NAMEDB_TSTBITMASK(authmask, qdepth) && ((d = lookup(db, qnamelow, qnamelen)) != NULL)) {
			if(DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
				if((a = answer(d, htons(TYPE_NS))) == NULL) {
					RCODE_SET(q, RCODE_SERVFAIL);
					return 0;
				}
				RCODE_SET(q, RCODE_OK);
				AA_CLR(q);
				query_addanswer(q, qname, a);
				return 0;
			} else {
				if((a = answer(d, htons(TYPE_SOA)))) {
					/* Setup truncation */
					qptr = q->iobufptr;

					if(ntohs(qclass) != CLASS_ANY) {
						AA_SET(q);
					} else {
						AA_CLR(q);
					}
					query_addanswer(q, qname, a);

					/* Truncate */
					ANCOUNT(q) = 0;
					NSCOUNT(q) = htons(1);
					ARCOUNT(q) = 0;
					q->iobufptr = qptr + *(ANSWER_RRS_PTR(a) + 1);

					return 0;
				}
			}
		} else {
			/* Only look for wildcards if we did not match a domain before */
			if(NAMEDB_TSTBITMASK(starmask, qdepth + 1) && (RCODE(q) == RCODE_NXDOMAIN)) {
				/* Prepend star */
				bcopy(qstar, qnamelow - 2, 2);

				/* Lookup star */
				if((d = lookup(db, qnamelow - 2, qnamelen + 2)) != NULL) {
					/* We found a domain... */
					RCODE_SET(q, RCODE_OK);

					if((a = answer(d, qtype)) != NULL) {
						if(ntohs(qclass) != CLASS_ANY) {
							AA_SET(q);
						} else {
							AA_CLR(q);
						}
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
