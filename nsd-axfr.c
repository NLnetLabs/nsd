/*
 * $Id: nsd-axfr.c,v 1.4 2003/04/29 13:40:53 alexis Exp $
 *
 * nsd-axfr.c -- axfr utility for nsd(8)
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
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <dns.h>
#include <namedb.h>
#include <dname.h>
#include <nsd.h>
#include <query.h>
#include <zparser.h>
#include <client.h>

static char *progname;

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
 * Prints a usage message and terminates.
 *
 */
void
usage(void)
{
	fprintf(stderr,
		"usage: %s [-F] [-p port] [-f zonefile] zone servers\n", progname);
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
	struct RR **rrs;
	struct in_addr pin;
	u_char *zname;
	char *zonefile;
	int port = 53;
	int force = 0;
	u_int16_t id = 0;

	/* Randomize for query ID... */
	srand(time(NULL));

	/* Parse the command line... */
	progname = *argv;
	while((c = getopt(argc, argv, "p:f:F")) != -1) {
		switch (c) {
		case 'p':
			/* Port */
			if((port = atoi(optarg)) <= 0) {
				error("the port arguement must be a positive integer\n");
			}
			break;
		case 'F':
			force++;
			break;
		case 'f':
			zonefile = optarg;
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	/* We need at least zone name and server... */
	if(argc < 2) {
		usage();
	}

	/* Now the zone name */
	if((zname = strdname(*argv, ROOT)) == NULL) {
		error("invalid zone name");
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
		id = rand();
		if(query(s, &q, zname, TYPE_SOA, CLASS_IN, id, 0, 1, 0) != 0) {
			close(s);
			continue;
		}

		/* Receive & unpack it... */
		if((rrs = response(s, &q)) == NULL) {
			close(s);
			continue;
		}

		/* Print it */
		for(i = 0; rrs[i] != NULL; i++) {
			zprintrr(stdout, rrs[i]);
		}
		break;
	}

	exit(0);
}

