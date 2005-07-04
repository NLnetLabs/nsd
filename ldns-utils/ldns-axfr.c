/* 
 * ldns-axfr.c - ldns-axfr(8)
 * 
 * Copyright (c) 2001-2005, NLnet Labs, All right reserved
 *
 * See LICENSE for the license
 *
 * requests an AXFR transfer from a master server
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

/* nsd includes */
#include <nsd.h>
#include <options.h>

/* ldns */
#include <ldns/dns.h>

/* ldns-util specific includes */
#include "ldns-nsd-glue.h"

static void
usage(void)
{
	fprintf(stderr, "usage: nsd-axfr [-f file] <zone> <server>\n");
	fprintf(stderr, "\t-f file\t\tstore zone in file (defaults to zone name)\n");
	fprintf(stderr, "Report bugs to <nsd-bugs@nlnetlabs.nl>\n");
	exit(EXIT_FAILURE);
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
        exit(EXIT_SUCCESS);
}

int
main(int argc, char **argv)
{
	int c;
	int i;
	int chk;
	int result;
	
	char *filename = NULL;
	FILE *fp;
	
	/* LDNS types */
	ldns_pkt *query = NULL;
	ldns_resolver *res = NULL;
	ldns_resolver *cmdline_res = NULL;
	ldns_rdf *ldns_zone_name = NULL;
	ldns_rdf *ns_addr = NULL;
	ldns_rdf *ns_name = NULL;
	ldns_rr_list *cmdline_rr_list = NULL;
	ldns_rr *axfr_rr = NULL;

        while ((c = getopt(argc, argv, "f:vh")) != -1) {
                switch (c) {
                case 'f':
                	filename = optarg;
                	break;
		case 'v':
			version();
                case 'h':
                case '?':
                default:
                        usage();
                }
        }
        argc -= optind;
        argv += optind;
        
        if (argc != 2) {  /* || zone_name == NULL) { */
                usage();
        }
        
        chk = ldns_str2rdf_dname(&ldns_zone_name, argv[0]);
        if (chk != LDNS_STATUS_OK) {
        	fprintf(stderr, "Bad zone name: %s (error %d)\n", argv[0], chk);
        	usage();
        }

        if (!filename) {
        	filename = argv[0];
        }

        /* server address can be an ipv4 address, an ipv6 address, or a hostname */
        ns_addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, argv[1]);
        if (!ns_addr) {
	        ns_addr = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, argv[1]);
        }
        if (!ns_addr) {
		chk = ldns_str2rdf_dname(&ns_name, argv[1]);
		if (chk != LDNS_STATUS_OK) {
			fprintf(stderr, "Bad server name: %s (error %d)\n", argv[1], chk);
			usage();
		}

		/* try to resolv the name if possible */
		cmdline_res = ldns_resolver_new_frm_file(NULL);
		
		if (!cmdline_res) {
			fprintf(stderr, "%s", "Unable to create resolver to resolve server name");
			result = EXIT_FAILURE;
			goto exit;
		}

		cmdline_rr_list = ldns_get_rr_list_addr_by_name(
					cmdline_res, 
					ns_name,
					LDNS_RR_CLASS_IN,
					0);

		ldns_resolver_deep_free(cmdline_res);

		if (!cmdline_rr_list) {
			fprintf(stderr, "%s", "could not find any address for the server name");
			result = EXIT_FAILURE;
			goto exit;
		} else {
			/* just grab the first address we got from the nameserver */
			ns_addr = ldns_rdf_clone(ldns_rr_rdf(ldns_rr_list_rr(cmdline_rr_list, 0), 0));
			ldns_rr_list_deep_free(cmdline_rr_list);
		}
        }

        printf("Doing AXFR for zone ");
        ldns_rdf_print(stdout, ldns_zone_name);
        printf(" at server ");
        ldns_rdf_print(stdout, ns_addr);
        printf("\n");
        
        /* Create the resolver that will handle the AXFR */
        res = ldns_resolver_new();
        if (!res) {
        	fprintf(stderr, "%s", "Unable to create resolver object for AXFR transfer\n");
        	goto exit;
	}
        
        /* always use tcp */
        ldns_resolver_set_usevc(res, true);
        
        ldns_resolver_push_nameserver(res, ns_addr);

        result = ldns_axfr_start(res, ldns_zone_name, LDNS_RR_CLASS_IN);
        if (result != LDNS_STATUS_OK) {
        	fprintf(stderr, "Unable to start AXFR session: %s\n", ldns_get_errorstr_by_id(result));
        	goto exit;
	}

	/* write it to the file */
	fp = fopen(filename, "w");
	if (!fp) {
		printf("Unable to open %s for writing\n", filename);
		goto exit;
	}

	while (axfr_rr = ldns_axfr_next(res)) {
		ldns_rr_print(fp, axfr_rr);
        	fprintf(fp, "\n");
        	ldns_rr_free(axfr_rr);
        }

        printf("Stored in %s\n", filename);

        result = EXIT_SUCCESS;

        exit:
        ldns_rdf_deep_free(ldns_zone_name);
        ldns_rdf_deep_free(ns_name);
        ldns_rdf_deep_free(ns_addr);
        ldns_pkt_free(query);
        ldns_resolver_deep_free(res);
        
        return result;

}
