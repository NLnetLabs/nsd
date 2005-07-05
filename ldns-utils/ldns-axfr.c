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
	fprintf(stderr, "usage: nsd-axfr [options] <zone> <server>\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "-4\t\tUse IPv4 only\n");
	fprintf(stderr, "-6\t\tUse IPv6 only\n");
	fprintf(stderr, "-f file\t\tstore zone in file (defaults to zone name, '-' for stdout)\n");
	fprintf(stderr, "-p port\t\tthe port to connect to\n");
	fprintf(stderr, "-s serial\tserial to check (only perform axfr if master serial is higher)\n");
	fprintf(stderr, "-v \t\tshow version information\n");
	fprintf(stderr, "-V \t\tverbose mode\n");
	fprintf(stderr, "-h \t\tshow this help\n");
	fprintf(stderr, "zone\t\tname of the zone to transfer\n");
	fprintf(stderr, "server\t\tname or address of the master server\n");
	fprintf(stderr, "\n");

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
	FILE *fp;
	size_t count = 0;

	/* options and arguments */
	bool verbose = false;
	char *filename = NULL;
	/* ipv4/ipv6? 0=doesn't matter, 1=ipv4, 2=ipv6, see ldns resolver */
	int ip6 = 0;
	bool have_serial = false;
	uint32_t serial = 0;
	uint32_t master_serial = 0;
	int port = 53;
	
	/* LDNS types */
	ldns_pkt *query = NULL;
	ldns_resolver *res = NULL;
	ldns_resolver *cmdline_res = NULL;
	ldns_rdf *ldns_zone_name = NULL;
	ldns_rdf *ns_addr = NULL;
	ldns_rdf *ns_name = NULL;
	ldns_rr_list *cmdline_rr_list = NULL;
	ldns_rr *axfr_rr = NULL;
	ldns_pkt *soa_pkt = NULL;
	ldns_rr_list *soa_rrs = NULL;

        while ((c = getopt(argc, argv, "f:p:s:vVh46")) != -1) {
                switch (c) {
                case 'f':
                	filename = optarg;
                	break;
		case 'p':
			port = atoi(optarg);
			break;
		case 's':
			have_serial = true;
			serial = atoi(optarg);
			break;
		case 'v':
			version();
			break;
		case 'V':
			verbose = true;
			break;
                case '4':
			ip6 = 1;
			break;
		case '6':
			ip6 = 2;
			break;
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
		
		ldns_resolver_set_ip6(cmdline_res, ip6);

		if (!cmdline_res) {
			fprintf(stderr, "%s", "Unable to create resolver to resolve server name\n");
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
			fprintf(stderr, "%s", "could not find any address for the server name\n");
			result = EXIT_FAILURE;
			goto exit;
		} else {
			/* just grab the first address we got from the nameserver */
			ns_addr = ldns_rdf_clone(ldns_rr_rdf(ldns_rr_list_rr(cmdline_rr_list, 0), 0));
			ldns_rr_list_deep_free(cmdline_rr_list);
		}
        }

	if (verbose) {
		printf("Doing AXFR for zone ");
		ldns_rdf_print(stdout, ldns_zone_name);
		printf(" at server ");
		ldns_rdf_print(stdout, ns_addr);
		printf("\n");
	}
        
        /* Create the resolver that will handle the AXFR */
        res = ldns_resolver_new();
        if (!res) {
        	fprintf(stderr, "%s", "Unable to create resolver object for AXFR transfer\n");
        	goto exit;
	}
        
	ldns_resolver_set_port(res, port);
	ldns_resolver_set_ip6(res, ip6);

        ldns_resolver_push_nameserver(res, ns_addr);

	/* if we have a serial, check it */
	if (have_serial) {
		soa_pkt = ldns_resolver_query(res, ldns_zone_name, LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, 0);
		if (!soa_pkt) {
			fprintf(stderr, "Unable to check serial, no SOA packet received\n");
			result = EXIT_FAILURE;
			goto exit;
		} else if (ldns_pkt_rcode(soa_pkt) != 0) {
			ldns_pkt_print(stderr, soa_pkt);
			result = ldns_pkt_rcode(soa_pkt);
			goto exit;
		} else {
			soa_rrs = ldns_pkt_rr_list_by_type(soa_pkt, LDNS_RR_TYPE_SOA, LDNS_SECTION_ANSWER);
			if (ldns_rr_list_rr_count(soa_rrs) > 1) {
				fprintf(stderr, "Error: received more than 1 SOA\n");
				result = EXIT_FAILURE;
				goto exit;
			} else if (ldns_rr_list_rr_count(soa_rrs) < 1) {
				fprintf(stderr, "Error: SOA packet contains no SOA record\n");
				result = EXIT_FAILURE;
				goto exit;
			} else {
				master_serial = ldns_rdf2native_int32(ldns_rr_rdf(ldns_rr_list_rr(soa_rrs, 0), 2));
				if (serial >= master_serial) {
					if (verbose) {
						fprintf(stdout, "Serial from master: %u, specified serial: %u, no axfr transfer needed.\n", master_serial, serial);
					}
					result = EXIT_SUCCESS;
					goto exit;
				}
			}
		}

	}

        /* always use tcp for axfr itself */
        ldns_resolver_set_usevc(res, true);
        
        result = ldns_axfr_start(res, ldns_zone_name, LDNS_RR_CLASS_IN);
        if (result != LDNS_STATUS_OK) {
        	fprintf(stderr, "Unable to start AXFR session: %s\n", ldns_get_errorstr_by_id(result));
        	goto exit;
	}

	/* write it to the file */
	if (strncmp(filename, "-", 2) == 0) {
		fp = stdout;
	} else {
		fp = fopen(filename, "w");
	}
	if (!fp) {
		printf("Unable to open %s for writing\n", filename);
		goto exit;
	}

	while (axfr_rr = ldns_axfr_next(res)) {
		count++;
		ldns_rr_print(fp, axfr_rr);
        	ldns_rr_free(axfr_rr);
        }

	if (fp != stdout) {
		fclose(fp);
	}

	/* if not completed, something has gone wrong, print (last) packet */
	if (!ldns_axfr_complete(res)) {
		ldns_pkt_print(stderr, ldns_axfr_last_pkt(res));
		result = ldns_pkt_rcode(ldns_axfr_last_pkt(res));
		goto exit;
	}

        if (verbose && strncmp(filename, "-", 2) != 0) {
		printf("%u resource records stored in %s\n", count, filename);
	}

        result = EXIT_SUCCESS;

        exit:
        ldns_rdf_deep_free(ldns_zone_name);
        ldns_rdf_deep_free(ns_name);
        ldns_rdf_deep_free(ns_addr);
        ldns_pkt_free(query);
        ldns_resolver_deep_free(res);
	ldns_pkt_free(soa_pkt);
        
        return result;

}
