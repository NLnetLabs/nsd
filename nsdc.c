bja
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
#include "client.h"
#include "options.h"
#include "plugins.h"

extern char *optarg;
extern int optind;

static struct nsd nsdc;

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
                "  -f config-file  Specify the location of the configuration file.\n"
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

static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(1);
}


int
main (int argc, char *argv[])
{
	int c;
	uint16_t port;
	uint8_t klass;
	lookup_table_type *control;
	struct query_type *q;

	port = DEFAULT_CONTROL_PORT;
	klass = CLASS_CH;

	log_init("nsdc");
		
        /* Initialize the server handler... */
        memset(&nsdc, 0, sizeof(struct nsd));
        nsdc.region      = region_create(xalloc, free);
#if 0  
	- copied not needed I think
        nsdc.server_kind = NSD_SERVER_MAIN;
#endif

	nsdc.options_file = CONFIGFILE;
        nsdc.options      = NULL;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "f:hp:v")) != -1) {
		switch (c) {
			case 'f':
				nsdc.options_file = optarg;
				break;
			case 'p':
				port = atoi(optarg);
				if (port == 0) 
					error("port must be a number > 0");
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
		error("unknown control message\n");

	control = lookup_by_id(control_msgs, control->id);

	printf("qname to use: %s\n", control->name);

        nsdc.options = load_configuration(nsdc.region, nsdc.options_file);
        if (!nsdc.options) {
		error("failed to load configuration file '%s'",
				nsdc.options_file);
        }
	
	q = query_create(nsdc.region, NULL);
	
	/* open a socket, make a packet, send it, receive reply, and print */

	/* add the control message as a txt rr */
	query_addtxt(q, (const uint8_t*) control->name,
			CLASS_CH,
			DEFAULT_CONTROL_TTL,
			"");
}
 
