/*
 * $Id: nsd-notify.c,v 1.10.2.1 2003/06/18 09:11:24 erik Exp $
 *
 * nsd-notify.c -- sends notify(rfc1996) message to a list of servers
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
#include <config.h>

#ifdef INET6
#undef	INET6
#endif


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include <dns.h>
#include <namedb.h>
#include <dname.h>
#include <nsd.h>
#include <query.h>

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * fprintf(stderr, ...);
 *
 */
void *
xalloc (register size_t size)
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "zonec: malloc failed: %m\n");
		exit(1);
	}
	return p;
}

void *
xrealloc (register void *p, register size_t size)
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "zonec: realloc failed: %m\n");
		exit(1);
	}
	return p;
}


void 
usage (void)
{
	fprintf(stderr, "usage: nsd-notify -z zone servers\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int 
main (int argc, char *argv[])
{
	int c, udp_s;
	struct	query q;
	u_char *zone = NULL;
	u_int16_t qtype = htons(TYPE_SOA);
	u_int16_t qclass = htons(CLASS_IN);
	struct addrinfo hints, *res0, *res;
	int error;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "z:")) != -1) {
		switch (c) {
		case 'z':
			if((zone = strdname(optarg, (u_char *)"\001")) == NULL)
				usage();
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0 || zone == NULL)
		usage();

	/* Initialize the query */
	memset(&q, 0, sizeof(struct query));
	q.addrlen = sizeof(q.addr);
	q.iobufsz = QIOBUFSZ;
	q.iobufptr = q.iobuf;
	q.maxlen = 512;

	/* Set up the header */
	OPCODE_SET((&q), OPCODE_NOTIFY);
	ID((&q)) = 42;          /* Does not need to be random. */
	AA_SET((&q));

	q.iobufptr = q.iobuf + QHEADERSZ;

	/* Add the domain name */
	if (*zone > MAXDOMAINLEN) {
		fprintf(stderr, "zone name length exceeds %d\n", MAXDOMAINLEN);
		exit(1);
	}
	memcpy(q.iobufptr, zone + 1, *zone);
	q.iobufptr += *zone;

	/* Add type & class */
	memcpy(q.iobufptr, &qtype, 2);
	q.iobufptr += 2;
	memcpy(q.iobufptr, &qclass, 2);
	q.iobufptr += 2;

	/* Set QDCOUNT=1 */
	QDCOUNT((&q)) = htons(1);

	for (/*empty*/; *argv; argv++) {
		/* Set up UDP */
		memset(&hints, 0, sizeof(hints));
#ifdef INET6
		hints.ai_family = PF_UNSPEC;
#else
		hints.ai_family = PF_INET;
#endif
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		error = getaddrinfo(*argv, "53", &hints, &res0);
		if (error) {
			fprintf(stderr, "skipping bad address %s: %s\n", *argv,
			    gai_strerror(error));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			if (res->ai_addrlen > sizeof(q.addr))
				continue;

			udp_s = socket(res->ai_family, res->ai_socktype,
			    res->ai_protocol);
			if (udp_s == -1)
				continue;

			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

			/* WE ARE READY SEND IT OUT */

			if (sendto(udp_s, q.iobuf,
			    (size_t)(q.iobufptr - q.iobuf), 0,
			    res->ai_addr, res->ai_addrlen) == -1) {
				fprintf(stderr,
				    "send to %s failed: %s\n", *argv,
				    strerror(errno));
			}

			close(udp_s);
		}

		freeaddrinfo(res0);
	}

	exit(1);
}
