/*
 * nsdc.c - nsdc(8)
 *
 * Copyright (c) 2001-2005, NLnet Labs, All right reserved
 *
 * See LICENSE for the license
 *
 * nsdc - re-implementation of nsdc.sh in C
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "nsd.h"
#include "options.h"
#include "plugins.h"
#include "client.h"
#include "packet.h"
#include "query.h"

extern char *optarg;
extern int optind;

static nsd_type nsdc;

/* static? */
static lookup_table_type control_msgs[] = {
	{ CONTROL_STATUS, "status.nsd" },	/* status control msg */
	{ CONTROL_VERSION, "version.nsd" },	/* version control msg */
	{ CONTROL_UNKNOWN, NULL } 		/* not known */
};

/* string gotten from the cmd line */
static lookup_table_type arg_control_msgs[] = {
	{ CONTROL_STATUS, "status" },
	{ CONTROL_VERSION, "version" },
	{ CONTROL_UNKNOWN, NULL }
};

static void
usage(void)
{
	fprintf(stderr, "Usage: nsdc [OPTION]... {stop|reload|rebuild|restart|running|update|notify|version}\n");
	fprintf(stderr,
                "Supported options:\n"
                "  -c config-file  Specify the location of the configuration file.\n"
                "  -h              Print this help information.\n"
                );
	fprintf(stderr,
                "  -p port         Specify the port to listen to.\n"
                "  -v              Print version information.\n\n"
                );
	exit(1);
}

static void
version(void)
{
        fprintf(stderr, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
        fprintf(stderr, "Written by NLnet Labs.\n\n");
        fprintf(stderr,
                "Copyright (C) 2001-2005 NLnet Labs.  This is free software.\n"
                "There is NO warranty; not even for MERCHANTABILITY or FITNESS\n"
                "FOR A PARTICULAR PURPOSE.\n");
        exit(0);
}

int
main (int argc, char *argv[])
{
	int c;
	const char * port;
	lookup_table_type *control;
	query_type q;
	const dname_type *control_msg;
	int default_family;
	int rc;
	struct addrinfo hints, *res;
	int sockfd;

	control_msg = NULL;
	default_family = DEFAULT_AI_FAMILY;
	port = DEFAULT_CONTROL_PORT;

	log_init("nsdc");

        /* Initialize the handler... */
        memset(&nsdc, 0, sizeof(nsd_type));
        nsdc.region      = region_create(xalloc, free);
#if 0
	- copied not needed I think
        nsdc.server_kind = NSD_SERVER_MAIN;
#endif

	nsdc.options_file = CONFIGFILE;
        nsdc.options      = NULL;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "c:hp:v")) != -1) {
		switch (c) {
			case 'c':
				nsdc.options_file = optarg;
				break;
			case 'p':
				port = optarg;
				break;
			case 'v':
				version();
				break;
			case 'h':
				usage();
				break;
			case '?':
			default:
				usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* what kind of service does the user want? */
	control = lookup_by_name(arg_control_msgs, argv[0]);

	if (!control)
		error(EXIT_FAILURE, "unknown control message\n");

	control = lookup_by_id(control_msgs, control->id);

	printf("qname to use: %s\n", control->name);

        nsdc.options = load_configuration(nsdc.region, nsdc.options_file);
        if (!nsdc.options) {
		error(EXIT_FAILURE, "failed to load configuration file '%s'",
				nsdc.options_file);
        }

	control_msg = dname_parse(nsdc.region, control->name);
	if (!control_msg) {
		error(EXIT_FAILURE,
				"incorrect domain name '%s'",
				control->name);
	}

	/* Initialize the query */
        memset(&q, 0, sizeof(query_type));
        q.addrlen = sizeof(q.addr);
        q.maxlen = 512;
        q.packet = buffer_create(nsdc.region, QIOBUFSZ);
        memset(buffer_begin(q.packet), 0, buffer_remaining(q.packet));

        /* Set up the header */
        OPCODE_SET(q.packet, OPCODE_QUERY);
        ID_SET(q.packet, 42);   /* Does not need to be random. */
        /* AA_SET(q.packet); */
        QDCOUNT_SET(q.packet, 1);
        buffer_skip(q.packet, QHEADERSZ);
        buffer_write(q.packet, dname_name(control_msg), dname_length(control_msg));
        buffer_write_u16(q.packet, TYPE_TXT);
        buffer_write_u16(q.packet, CLASS_CH);
        buffer_flip(q.packet);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = default_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	rc = getaddrinfo(DEFAULT_CONTROL_HOST, port, &hints, &res);
	if (rc)
		error(EXIT_FAILURE, "bad address %s: %s\n", DEFAULT_CONTROL_HOST,
				gai_strerror(rc));

	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sockfd == -1)
		error(EXIT_FAILURE, "could not connect to server on %s:%d\n", DEFAULT_CONTROL_HOST,
				DEFAULT_CONTROL_PORT);

	if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
	{
		warning("cannot connect to %s: %s\n",
				DEFAULT_CONTROL_HOST,
				strerror(errno));
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

	if (send_query(sockfd, &q) != 1) {
		warning("sending of the query to %s failed\n", DEFAULT_CONTROL_HOST);
		close(sockfd);
		exit(EXIT_FAILURE);
	}

#if 0
	/* process the reply and print the RR in there */
	char buf[1024];
	read_socket(sockfd, buf, 1025);
#endif

	close(sockfd);
}

