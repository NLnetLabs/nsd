/*
 * nsd-notify.c -- sends notify(rfc1996) message to a list of servers
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
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
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include "query.h"

static void 
usage (void)
{
	fprintf(stderr, "usage: nsd-notify [-4] [-6] [-p port] -z zone servers\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int 
main (int argc, char *argv[])
{
	int c, udp_s;
	struct query q;
	const dname_type *zone = NULL;
	struct addrinfo hints, *res0, *res;
	int error;
	int default_family = DEFAULT_AI_FAMILY;
	const char *port = UDP_PORT;
	region_type *region = region_create(xalloc, free);
	
	log_init("nsd-notify");
	
	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46p:z:")) != -1) {
		switch (c) {
		case '4':
			default_family = AF_INET;
			break;
		case '6':
#ifdef INET6
			default_family = AF_INET6;
			break;
#else /* !INET6 */
			log_msg(LOG_ERR, "IPv6 support not enabled\n");
			exit(1);
#endif /* !INET6 */
		case 'p':
			port = optarg;
			break;
		case 'z':
			zone = dname_parse(region, optarg);
			if (!zone) {
				log_msg(LOG_ERR,
					"incorrect domain name '%s'",
					optarg);
				exit(1);
			}
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
	q.maxlen = 512;
	q.packet = buffer_create(region, QIOBUFSZ);
	memset(buffer_begin(q.packet), 0, buffer_remaining(q.packet));

	/* Set up the header */
	OPCODE_SET(q.packet, OPCODE_NOTIFY);
	ID_SET(q.packet, 42);	/* Does not need to be random. */
	AA_SET(q.packet);
	QDCOUNT_SET(q.packet, 1);
	buffer_skip(q.packet, QHEADERSZ);
	buffer_write(q.packet, dname_name(zone), zone->name_size);
	buffer_write_u16(q.packet, TYPE_SOA);
	buffer_write_u16(q.packet, CLASS_IN);
	buffer_flip(q.packet);

	for (/*empty*/; *argv; argv++) {
		/* Set up UDP */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		error = getaddrinfo(*argv, port, &hints, &res0);
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
			if (sendto(udp_s,
				   buffer_current(q.packet),
				   buffer_remaining(q.packet), 0,
				   res->ai_addr, res->ai_addrlen) == -1)
			{
				fprintf(stderr,
					"send to %s failed: %s\n", *argv,
					strerror(errno));
			}

			close(udp_s);
		}

		freeaddrinfo(res0);
	}

	exit(0);
}
