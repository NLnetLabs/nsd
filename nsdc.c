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

extern char *optarg;
extern int optind;

static struct nsd nsd;

static void
usage(void)
{
	fprintf(stderr, "Usage: nsdc [OPTION]... {start|stop|reload|rebuild|restart|running|update|notify\n");
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
	const char *port;

	port = DEFAULT_PORT;

        /* Initialize the server handler... */
        memset(&nsd, 0, sizeof(struct nsd));
        nsd.region      = region_create(xalloc, free);
#if 0  
	- copied not needed I think
        nsd.server_kind = NSD_SERVER_MAIN;
#endif

	nsd.options_file = CONFIGFILE;
        nsd.options      = NULL;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "f:hp:v")) != -1) {
		switch (c) {
			case 'f':
				nsd.options_file = optarg;
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

        //nsd.options = load_configuration(nsd.region, nsd.options_file);
        if (!nsd.options) {
          //      error("failed to load configuration file '%s'",
            //          nsd.options_file);
        }
}
 
