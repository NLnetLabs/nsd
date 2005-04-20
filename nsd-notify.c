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

#include "client.h"
#include "options.h"
#include "packet.h"
#include "query.h"

static void
usage (void)
{
	fprintf(stderr, "usage: nsd-notify [-h] [-c config-file] -z zone\n");
	fprintf(stderr, "NSD notify utility\n\nSupported options:\n");
	fprintf(stderr, "  -c config-file  Specify the configuration file.\n");
	fprintf(stderr, "  -z zone         The zone.\n");
	fprintf(stderr, "  -h              Print this help information.\n");
	fprintf(stderr, "\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);

	exit(EXIT_FAILURE);
}

extern char *optarg;
extern int optind;

int
main(int argc, char *argv[])
{
	int c, udp_s;
	query_type q;
	const dname_type *zone_name = NULL;
	struct addrinfo hints, *res0, *res;
	int gai_error;
	region_type *region = region_create(xalloc, free);
	const char *options_file = CONFIGFILE;
	nsd_options_type *options;
	nsd_options_zone_type *zone_info;
	size_t i;

	log_init("nsd-notify");

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "c:hz:")) != -1) {
		switch (c) {
		case 'c':
			options_file = optarg;
			break;
		case 'z':
			zone_name = dname_parse(region, optarg);
			if (!zone_name) {
				log_msg(LOG_ERR,
					"incorrect domain name '%s'",
					optarg);
				exit(1);
			}
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0 || zone_name == NULL) {
		usage();
	}

	options = nsd_load_config(region, options_file);
	if (!options) {
		error(EXIT_FAILURE, "failed to load configuration file '%s'",
		      options_file);
	}

	zone_info = nsd_options_find_zone(options, zone_name);
	if (!zone_info) {
		error(EXIT_FAILURE,
		      "zone '%s' not found in the configuration file",
		      dname_to_string(zone_name, NULL));
	}

	/* Initialize the query */
	memset(&q, 0, sizeof(query_type));
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
	buffer_write(q.packet,
		     dname_name(zone_info->name),
		     dname_length(zone_info->name));
	buffer_write_u16(q.packet, TYPE_SOA);
	buffer_write_u16(q.packet, CLASS_IN);
	buffer_flip(q.packet);

	for (i = 0; i < zone_info->notify->count; ++i) {
		nsd_options_address_type *address
			= zone_info->notify->addresses[i];

		/* Set up UDP */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = address->family;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		gai_error = getaddrinfo(
			address->address,
			address->port ? address->port : DEFAULT_DNS_PORT,
			&hints,
			&res0);
		if (gai_error) {
			fprintf(stderr, "skipping bad address %s: %s\n",
				address->address, gai_strerror(gai_error));
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

			fprintf(stderr, "notifying %s (%s)\n",
				address->address,
				sockaddr_to_string(res->ai_addr));

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
