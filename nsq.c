/*
 * $Id: nsq.c,v 1.5 2003/04/28 09:46:37 alexis Exp $
 *
 * nsq.c -- sends a DNS query and prints a response
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

static char *progname;

static struct ztab opcodes[] = 	{\
	{OPCODE_QUERY, "QUERY"},	\
	{OPCODE_IQUERY, "IQUERY"},	\
	{OPCODE_STATUS, "STATUS"},	\
	{OPCODE_NOTIFY, "NOTIFY"},	\
	{OPCODE_UPDATE, "UPDATE"},	\
	{0, NULL}};

/*
 *
 * Prints an error message and terminates.
 *
 */
void
error(char *msg)
{
	if(errno != 0) {
		fprintf(stderr, "%s: %s: %s\n", progname, msg, strerror(errno));
	} else {
		fprintf(stderr, "%s: %s\n", progname, msg);
	}
	exit(1);
}


/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * syslog().
 *
 */
void *
xalloc (register size_t size)
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "%s: failed allocating %u bytes: %s", progname, size,
			strerror(errno));
		exit(1);
	}
	return p;
}

void *
xrealloc (register void *p, register size_t size)
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "%s: failed reallocating %u bytes: %s", progname, size,
			strerror(errno));
		exit(1);
	}
	return p;
}

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
u_char *
uncompress (struct query *q)
{
	static u_char dname[MAXDOMAINLEN + 1];

	int i;

	u_char *qptr = q->iobufptr;
	u_char *t = dname + 1;
	u_int16_t pointer;
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

u_int16_t *
rdatafromq(struct query *q, int n)
{
	u_int16_t *r;

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

u_int16_t *
dnamefromq(struct query *q)
{
	u_int16_t *r;
	u_char *dname;

	if((dname = uncompress(q)) == NULL) {
		return NULL;
	}

	r = xalloc(*dname + 2);
	*r = 0xffff;
	memcpy(r + 1, dname, *dname);
	return r;
}


u_int16_t **
newrdata(int n)
{
	u_int16_t **r;

	r = xalloc(sizeof(u_int16_t *)  * (n + 1));
	memset(r, 0, sizeof(u_int16_t *) * (n + 1));
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
unpack(struct query *q, struct RR *rr, u_int16_t rdlength)
{
	int i;

	u_char *qptr = q->iobufptr;

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
		newrdata(16);
		i = 0;
		do {
			if((rr->rdata[i++] = rdatafromq(q, *q->iobufptr + 1)) == NULL) return -1;
			rr->rdata = xrealloc(rr->rdata, sizeof(u_int16_t *) * (i + 1));
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
	u_int16_t tcplen, rdlength;
	int n, rrsp;
	struct RR **rrs;

	/* Get the size... */
	if(read(s, &tcplen, 2) == -1) {
		error("error reading message length");
		return NULL;
	}

	/* Do we have enough space? */
	if((tcplen = ntohs(tcplen)) > q->iobufsz) {
		error("insufficient buffer space");
		return NULL;
	}

	/* Read the message... */
	if(read(s, q->iobuf, tcplen) == -1) {
		error("error reading message");
		return NULL;
	}

	/* Get the first dname */
	q->iobufsz = tcplen;
	q->iobufptr = q->iobuf + QHEADERSZ;

	/* Initialize the RRs list... */
	if((n = ntohs(QDCOUNT(q)) + ntohs(ANCOUNT(q)) + ntohs(NSCOUNT(q)) + ntohs(ARCOUNT(q))) == 0) {
		error("no resource records in the response");
		return NULL;
	}

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
		if(rrsp != 0) {
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
			if(unpack(q, rrs[rrsp], rdlength) != NULL) {
				return NULL;
			}
		}

		/* Up to next resource record */
		rrsp++;
	}

	rrs[rrsp] = NULL;
	return rrs;
}


/*
 * Prints a usage message and terminates.
 *
 */
void
usage(void)
{
	fprintf(stderr,
		"usage: %s [-p port] [-i id] [-a] [-r] [-o opcode] [-t type] [-c class] domain servers\n",
			progname);
	exit(1);
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
query(int s, struct query *q, u_char *dname, u_int16_t qtype, u_int16_t qclass, u_int32_t qid, int op, int aa, int rd)
{
	u_int16_t tcplen;

	/* Initialize the query */
	q->iobufsz = q->maxlen = QIOBUFSZ;
	q->iobufptr = q->iobuf;
	q->edns = 0;
	q->tcp = 1;

	/* Set up the header */
	OPCODE_SET(q, op);
	ID(q) = htonl(qid);

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
	tcplen = htons(q->iobufptr - q->iobuf);
	if(write(s, &tcplen, 2) == -1
		|| write(s, q->iobuf, q->iobufptr - q->iobuf) == -1) {
		error("error sending query");
		close(s);
		return -1;
	}

	return 0;
}

extern char *optarg;
extern int optind;

/*
 * The main function.
 *
 */
int 
main (int argc, char *argv[])
{
	int c, s, i;
	struct query q;
	struct in_addr pin;
	int port = 53;
	u_int32_t qid;
	int aflag = 0;
	int rflag = 0;
	u_int16_t qtype = TYPE_A;
	u_int16_t qclass = CLASS_IN;
	u_char *qdname;
	int qopcode = 0;
	struct RR **rrs;

	/* Randomize for query ID... */
	srand(time(NULL));
	qid = rand();

	/* Parse the command line... */
	progname = *argv;
	while((c = getopt(argc, argv, "p:i:aro:t:c:")) != -1) {
		switch (c) {
		case 'p':
			/* Port */
			if((port = atoi(optarg)) <= 0) {
				error("the port arguement must be a positive integer\n");
			}
			break;
		case 'i':
			/* Query ID */
			if((qid = atoi(optarg)) <= 0) {
				error("the query id arguement must be a positive integer\n");
			}
			break;
		case 'a':
			/* Authorative only answer? */
			aflag++;
			break;
		case 'r':
			/* Recursion desired? */
			rflag++;
			break;
		case 'o':
			if(isdigit(*optarg)) {
				if((qopcode = atoi(optarg)) < 0) {
					error("the query id arguement must be between 0 and 15\n");
				}
			} else {
				if((qopcode = intbyname(optarg, opcodes)) == 0) {
					error("uknown opcode");
				}
			}
			if(qopcode < 0 || qopcode > 15) {
				error("opcode must be between 0 and 15\n");
			}
			break;
		case 't':
			if(isdigit(*optarg)) {
				if((qtype  = atoi(optarg)) == 0) {
					error("the query type must be a positive integer\n");
				}
			} else {
				if((qtype = intbyname(optarg, ztypes)) == 0) {
					error("uknown type");
				}
			}
			break;
		case 'c':
			if(isdigit(*optarg)) {
				if((qclass  = atoi(optarg)) == 0) {
					error("the query class must be a positive integer\n");
				}
			} else {
				if((qclass = intbyname(optarg, zclasses)) == 0) {
					error("uknown class");
				}
			}
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* We need at least domain name and server... */
	if(argc < 2) {
		usage();
	}

	/* Now the the name */
	if((qdname = strdname(*argv, ROOT)) == NULL) {
		error("invalid domain name");
	}

	/* Try every server in turn.... */
	for(argv++, argc--; *argv; argv++, argc--) {
		/* Do we have a valid ip address here? */
		q.addrlen = sizeof(q.addr);
		memset(&q.addr, 0, q.addrlen);
		q.addr.sin_port = htons(port);
		q.addr.sin_family = AF_INET;

		if(inet_aton(*argv, &pin) == 1) {
			q.addr.sin_addr.s_addr = pin.s_addr;
		} else {
			fprintf(stderr, "skipping illegal ip address: %s", *argv);
			continue;
		}

		/* Make a tcp connection... */
		if((s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
			fprintf(stderr, "failed creating a socket: %s\n", strerror(errno));
			continue;
		}

		/* Connect to the server */
		if(connect(s, (struct sockaddr *)&q.addr, q.addrlen) == -1) {
			fprintf(stderr, "unable to connect to %s: %s\n", *argv, strerror(errno));
			close(s);
			continue;
		}

		/* Send the query */
		if(query(s, &q, qdname, qtype, qclass, qid, qopcode, aflag, rflag) != 0) {
			close(s);
			continue;
		}

		/* Receive & unpack it... */
		if((rrs = response(s, &q)) == NULL) {
			close(s);
			continue;
		}

		/* Print the header.... */
		printf(";; received %d bytes from %s, %lu questions, %lu answers, %lu authority, %lu additional\n",
			q.iobufsz, *argv, ntohs(QDCOUNT((&q))), ntohs(ANCOUNT((&q))),
					ntohs(NSCOUNT((&q))), ntohs(ARCOUNT((&q))));
		printf(";; query id: %lu, qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, z: %d, rcode: %d\n",
				ntohl(ID((&q))), QR((&q)) ? 1 : 0, OPCODE((&q)), AA((&q)) ? 1 : 0 , TC((&q)) ? 1 : 0,
					RD((&q)) ? 1 : 0, RA((&q)) ? 1 : 0, Z((&q)), RCODE((&q)));

		/* Print it */
		printf("; Question section\n");
		for(i = 0; rrs[i] != NULL && i < ntohs(QDCOUNT((&q))); i++) {
			printf("; ");
			zprintrr(stdout, rrs[i]);
		}
		printf("; Answer section\n");
		for(; rrs[i] != NULL && i < ntohs(QDCOUNT((&q))) + ntohs(ANCOUNT((&q))); i++) {
			zprintrr(stdout, rrs[i]);
		}
		printf("; Authority section\n");
		for(; rrs[i] != NULL && i < ntohs(QDCOUNT((&q))) + ntohs(ANCOUNT((&q))) + + ntohs(NSCOUNT((&q))); i++) {
			zprintrr(stdout, rrs[i]);
		}
		printf("; Additional section\n");
		for(; rrs[i] != NULL && i < ntohs(QDCOUNT((&q))) + ntohs(ANCOUNT((&q))) + ntohs(NSCOUNT((&q))) + ntohs(ARCOUNT((&q))); i++) {
			zprintrr(stdout, rrs[i]);
		}
		break;
	}

	exit(0);
}

