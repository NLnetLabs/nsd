/*
 * $Id: nsq.c,v 1.10 2003/06/17 14:50:28 erik Exp $
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
#include <network.h>
#include <nsd.h>
#include <zparser.h>
#include <query.h>
#include <zonec.h>
#include <client.h>

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
error(const char *msg)
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
 * Prints a usage message and terminates.
 *
 */
void
usage(void)
{
	fprintf(stderr,
		"usage: %s [-4] [-6] [-p port] [-i id] [-a] [-r] [-o opcode] [-t type] [-c class] domain servers\n",
			progname);
	exit(1);
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
	const char *port = "53";
	u_int32_t qid;
	int aflag = 0;
	int rflag = 0;
	u_int16_t qtype = TYPE_A;
	u_int16_t qclass = CLASS_IN;
	const u_char *qdname;
	int qopcode = 0;
	struct RR **rrs;
	struct addrinfo *addrinfo;
	int family = DEFAULT_AI_FAMILY;
	
	/* Randomize for query ID... */
	srand(time(NULL));
	qid = rand();

	/* Parse the command line... */
	progname = *argv;
	while((c = getopt(argc, argv, "46p:i:aro:t:c:")) != -1) {
		switch (c) {
		case '4':
			family = PF_INET;
			break;
#ifdef INET6
		case '6':
			family = PF_INET6;
			break;
#endif
		case 'p':
			/* Port */
			port = optarg;
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

	addrinfo = NULL;
	/* Try every server in turn.... */
	for(argv++, argc--; *argv; argv++, argc--) {
		struct addrinfo *addr;
		int rc;
		
		if (addrinfo != NULL) {
			freeaddrinfo(addrinfo);
			addrinfo = NULL;
		}
		rc = nw_host_lookup(&addrinfo, *argv, port, SOCK_STREAM, family, 0);
		if (rc != 0) {
			fprintf(stderr, "nsq: %s:%s: %s\n", *argv, port, gai_strerror(rc));
			continue;
		}

		addr = addrinfo;
		
		/* Make a tcp connection... */
		do {
			s = socket(addr->ai_family, SOCK_STREAM, 0);
			if (s == -1) {
				fprintf(stderr, "socket: %s\n", strerror(errno));
				addr = addr->ai_next;
			}
		} while (s == -1 && addr != NULL);

		if (s == -1)
			continue;

		/* Connect to the server */
		if(connect(s, addr->ai_addr, addr->ai_addrlen) == -1) {
			fprintf(stderr, "unable to connect to %s: %s\n", *argv, strerror(errno));
			close(s);
			continue;
		}

		memcpy(&q.addr, addr->ai_addr, addr->ai_addrlen);
		q.addrlen = addr->ai_addrlen;
		
		/* Send the query */
		if(query(s, &q, qdname, qtype, qclass, qid, qopcode, aflag, rflag, 1) != 0) {
			close(s);
			continue;
		}

		/* Receive & unpack it... */
		if((rrs = response(s, &q)) == NULL) {
			close(s);
			continue;
		}

		/* Print the header.... */
		printf(";; received %d bytes from %s, %u questions, %u answers, %u authority, %u additional\n",
			q.iobufsz, *argv,
		       (unsigned) ntohs(QDCOUNT((&q))), (unsigned) ntohs(ANCOUNT((&q))),
		       (unsigned) ntohs(NSCOUNT((&q))), (unsigned) ntohs(ARCOUNT((&q))));
		printf(";; query id: %u, qr: %d, opcode: %d, aa: %d, tc: %d, rd: %d, ra: %d, z: %d, rcode: %d\n",
		       (unsigned) ntohs(ID((&q))), QR((&q)) ? 1 : 0, OPCODE((&q)), AA((&q)) ? 1 : 0 , TC((&q)) ? 1 : 0,
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

