/*
 * $Id: nsd-axfr.c,v 1.11 2003/07/04 07:55:10 erik Exp $
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
#include <netdb.h>
#include <unistd.h>

#include <dns.h>
#include <namedb.h>
#include <dname.h>
#include <network.h>
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
		"usage: %s [-4] [-6] [-F] [-p port] [-f zonefile] zone servers\n", progname);
	exit(1);
}

extern char *optarg;
extern int optind;

static int
sane(struct query *q, uint16_t id) {
	/* Is it an answer? */
	if(!QR(q)) {
		fprintf(stderr, "server returned query instead of answer\n");
		return -1;
	}

	/* Truncated? */
	if(TC(q)) {
		fprintf(stderr, "truncated answer over tcp\n");
		return -1;
	}

	/* Not authorative? */
	/* if(!AA(q)) {
		fprintf(stderr, "received non-authorative data\n");
		return -1;
	} */

	/* Opcode? */
	if(OPCODE(q) != OPCODE_QUERY) {
		fprintf(stderr, "unexpected opcode in the answer\n");
		return -1;
	}

	/* Rcode? */
	if(RCODE(q) != RCODE_OK) {
		fprintf(stderr, "error code %d received\n", RCODE(q));
		return -1;
	}

	/* Wrong id? */
	if(id != ntohs(ID(q))) {
		fprintf(stderr, "query id mismatch\n");
		return -1;
	}
	return 0;
}

/*
 * The main function.
 *
 */
int 
main (int argc, char *argv[])
{
	int c, s, i;
	struct query q;
	struct zparser *parser;
	struct RR *rr;
	struct RR **rrs;
	uint8_t *zname;
	char *zonefile = NULL;
	int transfer;
	const char *port = "53";
	int force = 0;
	uint16_t id = 0;
	uint32_t serial = 0;
	struct addrinfo *addrinfo;
	int family = DEFAULT_AI_FAMILY;
	
	/* Randomize for query ID... */
	srand(time(NULL));

	/* Parse the command line... */
	progname = *argv;
	while((c = getopt(argc, argv, "46p:f:F")) != -1) {
		switch (c) {
		case '4':
			family = AF_INET;
			break;
#ifdef INET6
		case '6':
			family = AF_INET6;
			break;
#endif
		case 'p':
			/* Port */
			port = optarg;
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
	if((zname = strdup(strdname(*argv, ROOT))) == NULL) {
		error("invalid zone name");
	}

	/* Do we have the file? */
	if(zonefile != NULL) {
		if((parser = zopen(zonefile, 3600, CLASS_IN, *argv)) == NULL) {
			if(errno != ENOENT) {
				error("unable to open the master zone file");
			}
		} else {
			/* Do we have SOA? */
			if((rr = zread(parser)) == NULL || rr->type != TYPE_SOA) {
				error("missing SOA record on top of the master zone file");
			}
			serial = ntohl(*(uint32_t *)(&rr->rdata[2][1]));

			zrdatafree(rr->rdata);
			rr->rdata = NULL;
			zclose(parser);
		}
	}


	addrinfo = NULL;

	/* Try every server in turn.... */
	for(argv++, argc--; *argv; argv++, argc--) {
		struct addrinfo *addr;
		
		if (addrinfo != NULL) {
			freeaddrinfo(addrinfo);
			addrinfo = NULL;
		}
		if (nw_host_lookup(&addrinfo, *argv, port, SOCK_STREAM, family, 0) != 0) {
			fprintf(stderr, "skipping illegal ip address: %s port %s\n", *argv, port);
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
		id = rand();
		if(query(s, &q, zname, TYPE_SOA, CLASS_IN, id, 0, 1, 0, 1) != 0) {
			close(s);
			continue;
		}

		/* Receive & unpack it... */
		if((rrs = response(s, &q)) == NULL) {
			close(s);
			continue;
		}

		/* Sanity check */
		if(sane(&q, id) != 0) {
			close(s);
			continue;
		}

		/* Do we have a SOA? Compare! */
		if(rrs[ntohs(QDCOUNT((&q)))]->type != TYPE_SOA) {
			fprintf(stderr, "did not receive a SOA record\n");
			close(s);
			continue;
		}

		/* Compare serials... */
		if(ntohl(*(uint32_t *)(&rrs[ntohs(QDCOUNT((&q)))]->rdata[2][1]))
			<= serial) {
			fprintf(stderr, "we have the same or newer serial, no transfer\n");
			break;
		}

		/* XXX free response */
		fprintf(stdout, "; ");
		zprintrr(stdout, rrs[ntohs(QDCOUNT((&q)))]);


		/* Zero the serial... */
		serial = 0;

		/* Do the AXFR */
		id = rand();
		if(query(s, &q, zname, TYPE_AXFR, CLASS_IN, id, 0, 1, 0, 1) != 0) {
			close(s);
			continue;
		}

		transfer = 1;

		/* Read it... */
		while((transfer == 1) && ((rrs = response(s, &q)) != NULL)) {
			/* Is it good? */
			if(sane(&q, id) != 0) {
				rrs = NULL;
				break;
			}


			/* Print it... */
			for(i = ntohs(QDCOUNT((&q))); rrs[i] != NULL && i < ntohs(QDCOUNT((&q))) + ntohs(ANCOUNT((&q))); i++) {
				zprintrr(stdout, rrs[i]);

				/* End of zone transfer? */
				if(serial != 0 && rrs[i]->type == TYPE_SOA) {
					transfer = 0;
					if(ntohl(*(uint32_t *)(&rrs[i]->rdata[2][1])) != serial) {
						fprintf(stderr, "zone changed during the transfer, retry...\n");
						/* retrys++; */
						/*XXX: h->h_addr_list--; */
						rrs = NULL;
						break;
					}
				}
			}

			/* We're just beginning AXFR... */
			if(serial == 0) {
				if(rrs[ntohs(QDCOUNT((&q)))]->type != TYPE_SOA) {
					fprintf(stderr, "no SOA record at the beginning of axfr\n");
					rrs = NULL;
					break;
				}
				/* Save it... */
				serial = ntohl(*(uint32_t *)(&rrs[ntohs(QDCOUNT((&q)))]->rdata[2][1]));
				if(serial == 0) {
					fprintf(stderr, "received SOA with a null serial number\n");
					rrs = NULL;
					break;
				}
			}

			/* Free the resource records & its rdata... */
			for(i = 0; rrs[i] != NULL; i++) {
				zrdatafree(rrs[i]->rdata);
				free(rrs[i]->dname);
				free(rrs[i]);
			}
			free(rrs);
				
                }

		/* AXFR failed... */
		if(rrs == NULL)  {
			close(s);
			continue;
		}

		break;
	}

	exit(0);
}
