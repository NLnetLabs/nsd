/*
 * $Id: client.c,v 1.6 2003/07/04 07:55:09 erik Exp $
 *
 * client.c -- set of DNS client routines
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
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <dns.h>
#include <namedb.h>
#include <dname.h>
#include <nsd.h>
#include <zparser.h>
#include <query.h>
#include <zonec.h>
#include <client.h>

/*
 *
 * Uncompresses a dname at the iobufptr, advances the iobufptr.
 *
 * Returns
 *
 *	dname if successfull
 *	NULL if the dname was invalid
 *
 */
const uint8_t *
uncompress (struct query *q)
{
	static uint8_t dname[MAXDOMAINLEN + 1];

	int i;

	uint8_t *qptr = q->iobufptr;
	uint8_t *t = dname + 1;
	uint16_t pointer;
	int pointers = 0;

	/* While not end of dname... */
	while(*qptr) {
		/* qptr out of bounds? */
		if(qptr < q->iobuf || qptr > (q->iobuf + q->iobufsz)) {
			error("domain name compression outside of packet boundaries");
			return NULL;
		}

		/* Do we have a pointer? */
		if(*qptr & 0xc0) {
			pointers++;

			/* Is this the first pointer we encountered? */
			if(pointers == 1) {
				q->iobufptr = qptr + 2;
			}

			/* Set qptr to the pointer value and continue */
			memcpy(&pointer, qptr, 2);
			pointer = ntohs(pointer);
			pointer &= 0x3fff;
			qptr = q->iobuf + pointer;

			continue;
		}

		/* MAXDOMAINLEN-1 exceeded? We always need trailing zero... */
		if(t - (dname + 1) + *qptr > MAXDOMAINLEN - 1) {
			error("domain name is too long");
			return NULL;
		}

		/* Copy this label.... */

		*t++ = *qptr;

		for(i = *qptr++; i; i--) {
			*t++ = NAMEDB_NORMALIZE(*qptr++);
		}
	}

	/* We have to copy the trailing zero now... */
	*t++ = *qptr++;
	*dname = t - (dname + 1);

	/* Did we encounter any pointers? */
	if(pointers == 0) {
		q->iobufptr = qptr;
	}
	return dname;
}

static uint16_t *
rdatafromq(struct query *q, int n)
{
	uint16_t *r;

	if(q->iobufptr + n > q->iobuf + q->iobufsz) {
		error("truncated packed in rdata");
		return NULL;
	}

	r = xalloc(n + 2);
	*r = n;
	memcpy(r + 1, q->iobufptr, n);
	q->iobufptr += n;
	return r;
}

static uint16_t *
dnamefromq(struct query *q)
{
	uint16_t *r;
	const uint8_t *dname;

	if((dname = uncompress(q)) == NULL) {
		return NULL;
	}

	r = xalloc(*dname + 2);
	*r = 0xffff;
	memcpy(r + 1, dname, *dname);
	return r;
}


static uint16_t **
newrdata(int n)
{
	uint16_t **r;

	r = xalloc(sizeof(uint16_t *)  * (n + 1));
	memset(r, 0, sizeof(uint16_t *) * (n + 1));
	return r;
}


/*
 *
 * Unpacks the resource record rdata.
 *
 * Returns
 *
 *	-1 on failure.
 *	0 on success.
 *
 */
int
unpack(struct query *q, struct RR *rr, uint16_t rdlength)
{
	int i;

	uint8_t *qptr = q->iobufptr;

	switch(rr->type) {
	case TYPE_A:
		rr->rdata = newrdata(1);
		if((rr->rdata[0] = rdatafromq(q, 4)) == NULL) return -1;
		break;
	case TYPE_NS:
	case TYPE_MD:
	case TYPE_MF:
	case TYPE_CNAME:
	case TYPE_MB:
	case TYPE_MG:
	case TYPE_MR:
	case TYPE_PTR:
		rr->rdata = newrdata(1);
		if((rr->rdata[0] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_MINFO:
	case TYPE_RP:
		rr->rdata = newrdata(2);
		if((rr->rdata[0] = dnamefromq(q)) == NULL) return -1;
		if((rr->rdata[1] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_TXT:
		rr->rdata = newrdata(16);
		i = 0;
		do {
			if((rr->rdata[i++] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
			rr->rdata = xrealloc(rr->rdata, sizeof(uint16_t *) * (i + 1));
			rr->rdata[i] = NULL;
		} while((q->iobufptr - qptr) < rdlength);
		break;
	case TYPE_SOA:
		rr->rdata = newrdata(7);
		if((rr->rdata[0] = dnamefromq(q)) == NULL) return -1;
		if((rr->rdata[1] = dnamefromq(q)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[3] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[4] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[5] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[6] = rdatafromq(q, 4)) == NULL) return -1;
		break;
	case TYPE_LOC:
		rr->rdata = newrdata(1);
		if((rr->rdata[0] = rdatafromq(q, 16)) == NULL) return -1;
		break;
	case TYPE_HINFO:
		rr->rdata = newrdata(2);
		if((rr->rdata[0] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
		break;
	case TYPE_MX:
		rr->rdata = newrdata(2);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_AAAA:
		rr->rdata = newrdata(1);
		if((rr->rdata[0] = rdatafromq(q, 16)) == NULL) return -1;
		break;
	case TYPE_SRV:
		rr->rdata = newrdata(4);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[3] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_NAPTR:
		rr->rdata = newrdata(6);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
		if((rr->rdata[3] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
		if((rr->rdata[4] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
		if((rr->rdata[5] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_AFSDB:
		rr->rdata = newrdata(2);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = dnamefromq(q)) == NULL) return -1;
		break;
	case TYPE_SIG:
		rr->rdata = newrdata(9);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 1)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, 1)) == NULL) return -1;
		if((rr->rdata[3] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[4] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[5] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[6] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[7] = dnamefromq(q)) == NULL) return -1;

		if((rr->rdata[8] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;
		break;
	case TYPE_NULL:
		break;
	case TYPE_KEY:
		rr->rdata = newrdata(4);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 1)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, 1)) == NULL) return -1;

		/* No key situation */
		if((rr->rdata[0][1] & 0x1100) == 0x1100) {
			break;
		}

		if((rr->rdata[3] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;
		break;
	case TYPE_NXT:
		rr->rdata = newrdata(2);

		if((rr->rdata[0] = dnamefromq(q)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;

		break;
	case TYPE_DS:
		rr->rdata = newrdata(4);
		if((rr->rdata[0] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 1)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, 1)) == NULL) return -1;
		if((rr->rdata[3] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;
		break;
	case TYPE_WKS:
		rr->rdata = newrdata(3);
		if((rr->rdata[0] = rdatafromq(q, 4)) == NULL) return -1;
		if((rr->rdata[1] = rdatafromq(q, 2)) == NULL) return -1;
		if((rr->rdata[2] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;
		break;
	default:
		rr->rdata = newrdata(1);
		if((rr->rdata[0] = rdatafromq(q, rdlength - (q->iobufptr - qptr))) == NULL) return -1;
		break;
	}

	if(qptr + rdlength != q->iobufptr) {
		error("incorrect rdlength");
		return -1;
	}

	return 0;
}

/*
 *
 * Receives a response from the wire and parses it into resource records.
 *
 * Returns
 *
 *	NULL on failure.
 *
 */
struct RR **
response(int s, struct query *q)
{
	int len, r;
	uint16_t tcplen, rdlength;
	int n, rrsp;
	struct RR **rrs;

	/* Reinitialize the buffer */
	q->iobufsz = q->maxlen = QIOBUFSZ;
	q->iobufptr = q->iobuf;


	if(q->tcp) {
		/* Get the size... */
		for(len = 0; len < 2; len += r) {
			r = read(s, &tcplen + len, 2 - len);
			if(r == -1) {
				error("error reading message length");
				return NULL;
			}
		}

		/* Do we have enough space? */
		if((tcplen = ntohs(tcplen)) > q->iobufsz) {
			error("insufficient buffer space");
			return NULL;
		}

		/* Read the message... */
		for(len = 0; len < tcplen; len += r) {
			r = read(s, q->iobuf + len, tcplen - len);
			if(r == -1) {
				error("error reading message");
				return NULL;
			}
		}
		if(len != tcplen) {
			error("could not read the entire message");
			return NULL;
		}
	} else {
		if((len = recvfrom(s, q->iobuf, q->iobufsz, 0,
				(struct sockaddr *)&q->addr, &q->addrlen)) == -1) {
                        error("recvfrom failed");
			return NULL;
                }
	}


	/* Get the first dname */
	q->iobufsz = len;
	q->iobufptr = q->iobuf + QHEADERSZ;

	/* Initialize the RRs list... */
	n = ntohs(QDCOUNT(q)) + ntohs(ANCOUNT(q)) + ntohs(NSCOUNT(q)) + ntohs(ARCOUNT(q));

	/* XXX We should just allocate structures here, not the pointers */
	rrs = xalloc(sizeof(struct RR *) * (n + 1));
	memset(rrs, 0, sizeof(struct RR *) * (n + 1));
	rrsp = 0;

	/* Process it all! */
	while(rrsp < n) {
		/* Create a new RR... */
		rrs[rrsp] = xalloc(sizeof(struct RR));
		memset(rrs[rrsp], 0, sizeof(struct RR));

		/* Get the dname! */
		if((rrs[rrsp]->dname = dnamedup(uncompress(q))) == NULL) {
			return NULL;
		}

		/* Do we have enough data? */
		if(((rrsp == 0) && (q->iobufptr + 4 > q->iobuf + q->iobufsz))
			|| ((rrsp != 0) && (q->iobufptr + 10 > q->iobuf + q->iobufsz))) {
				error("truncated packet");
				return NULL;
		}

		/* Get type & class */
		memcpy(&rrs[rrsp]->type, q->iobufptr, 2); q->iobufptr += 2;
		rrs[rrsp]->type = ntohs(rrs[rrsp]->type);
		memcpy(&rrs[rrsp]->class, q->iobufptr, 2); q->iobufptr += 2;
		rrs[rrsp]->class = ntohs(rrs[rrsp]->class);

		/* Is this not the question section? */
		if(rrsp >= ntohs(QDCOUNT(q))) {
			/* Get TTL & rdlength */
			memcpy(&rrs[rrsp]->ttl, q->iobufptr, 4); q->iobufptr += 4;
			rrs[rrsp]->ttl = ntohl(rrs[rrsp]->ttl);
			memcpy(&rdlength, q->iobufptr, 2); q->iobufptr += 2;
			rdlength = ntohs(rdlength);

			/* Truncated package? */
			if(q->iobufptr + rdlength > q->iobuf + q->iobufsz) {
				error("truncated package");
				return NULL;
			}

			/* Unpack the rdata */
			if(rdlength > 0) {
				if(unpack(q, rrs[rrsp], rdlength) == -1) {
					return NULL;
				}
			}
		}

		/* Up to next resource record */
		rrsp++;
	}

	rrs[rrsp] = NULL;
	return rrs;
}

/*
 *
 * Send a query for the specified type and class.
 *
 * Returns
 *
 * 	0 if successfull
 *	-1 and errno in case of error.
 *
 */
int
query(int s, struct query *q, const uint8_t *dname, uint16_t qtype, uint16_t qclass, uint32_t qid, int op, int aa, int rd, int tcp)
{
	int len;
	uint16_t tcplen;

	/* Initialize the query */
	q->iobufsz = q->maxlen = QIOBUFSZ;
	q->iobufptr = q->iobuf;
	q->edns = 0;
	q->tcp = tcp;

	/* Set up the header */
	memset(q->iobuf, 0, QHEADERSZ);
	OPCODE_SET(q, op);
	ID(q) = htons(qid);

	if(aa)
		AA_SET(q);
	if(rd)
		RD_SET(q);

	q->iobufptr = q->iobuf + QHEADERSZ;

	/* Add the domain name */
	if(*dname > MAXDOMAINLEN) {
		error("domain name is too long");
		return -1;
	}

	memcpy(q->iobufptr, dname + 1, *dname);
	q->iobufptr += *dname;

	/* Add type & class */
	qtype = htons(qtype);
	memcpy(q->iobufptr, &qtype, 2);
	q->iobufptr += 2;
	qclass = htons(qclass);
	memcpy(q->iobufptr, &qclass, 2);
	q->iobufptr += 2;

	/* Set QDCOUNT=1 */
	QDCOUNT(q) = htons(1);

	/* Send it out... */
	if(q->tcp) {
		tcplen = htons(q->iobufptr - q->iobuf);
		if(write(s, &tcplen, 2) == -1
			|| write(s, q->iobuf, q->iobufptr - q->iobuf) == -1) {
			error("error sending query");
			close(s);
			return -1;
		}
	} else {
		if((len = sendto(s, q->iobuf, q->iobufptr - q->iobuf, 0,
				(struct sockaddr *)&q->addr, q->addrlen)) == -1) {
			error("sendto failed");
			return -1;
		} else if(len != q->iobufptr - q->iobuf) {
			error("sent less bytes than expected");
			return -1;
		}
	}

	return 0;
}
