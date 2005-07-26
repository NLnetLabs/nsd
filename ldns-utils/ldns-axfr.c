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
#include <netdb.h>
#include <errno.h>

/* nsd includes */
#include <nsd.h>
#include <options.h>

/* ldns */
#include <ldns/dns.h>

#define DEFAULT_CONFIG_FILE "/etc/nsd/nsd.conf"
#define MAX_LINE_LEN 4000
#define MAX_LINES 10

static void
usage(void)
{
	fprintf(stderr, "usage: nsd-axfr [options] [zones]\n");
	fprintf(stderr, "options:\n");
	fprintf(stderr, "-c file\t\tUse configfile file\n");
	fprintf(stderr, "-d\t\tDelete backup files upon successful completion of each transfer\n");
	fprintf(stderr, "-v \t\tshow version information\n");
	fprintf(stderr, "-V \t\tverbose mode\n");
	fprintf(stderr, "-h \t\tshow this help\n");
	fprintf(stderr, "zone\t\tname(s) of the zone(s) to transfer\n");
	fprintf(stderr, "(don't forget root zone dot)\n");
	fprintf(stderr, "\n");

	fprintf(stderr, "Report bugs to <nsd-bugs@nlnetlabs.nl>\n");
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
}

int
main(int argc, char **argv)
{
	int c;
	int result = EXIT_FAILURE;
	FILE *fp;
	FILE *orig_zone_fp;
	size_t count = 0;

	/* options and arguments */
	bool verbose = false;
	bool delete_backups = false;
	const char *filename = NULL;
	char *backup_filename = NULL;
	const char *config_file = NULL;
	
	/* used to read SOAs from existing zone files */
	char line[MAX_LINE_LEN];
	char soa_str[MAX_LINE_LEN * MAX_LINES];
	int lines;
	
	/* 'options' read from config file */
	bool have_serial = false;
	uint32_t serial = 0;
	uint32_t master_serial = 0;
	int port = 0;
	char **zone_names = NULL;
	size_t zone_count = 0;
	size_t x,y;
	const char *current_zone_name;
	bool current_zone_found;

	/* will be set to true if a zone in the list does not need axfr */
	bool skip_current_zone;
	bool current_zone_transfered;

	/* NSD types */
	nsd_options_type *options = NULL;
	region_type *region = region_create(xalloc, free);
	size_t axfr_zone_count = 0;
	size_t zone_i, master_i, addr_i;
	nsd_options_zone_type **axfr_zone_list = NULL;
	nsd_options_address_type *master_address;

	struct servent *serv;

	/* LDNS types */
	ldns_resolver *res = NULL;
	ldns_rdf *ldns_zone_name = NULL;
	ldns_rdf *ns_addr = NULL;
	ldns_rr *axfr_rr = NULL;
	ldns_pkt *soa_pkt = NULL;
	ldns_rr_list *soa_rrs = NULL;
	ldns_rr *soa_rr;

        while ((c = getopt(argc, argv, "c:dvVh")) != -1) {
                switch (c) {
		case 'c':
			config_file = optarg;
			break;
		case 'd':
			delete_backups = true;
			break;
		case 'v':
			version();
			goto exit;
			break;
		case 'V':
			verbose = true;
			break;
                case 'h':
                	result = EXIT_SUCCESS;
                case '?':
                default:
                        usage();
                        goto exit;
                }
        }
        argc -= optind;
        argv += optind;
        
	/* if there are arguments left, they should be the zone names
	   that are to be axfr'ed. If not, do all in config file */
	if (argc > 0) {
		zone_names = argv;
		zone_count = argc;
	}

	if (!filename) {
		filename = argv[0];
	}

	if (!config_file) {
		config_file = DEFAULT_CONFIG_FILE;
	}

	options = nsd_load_config(region, config_file);

	if (zone_count == 0) {
		for (y = 0; y < options->zone_count; y++) {
			current_zone_name = dname_to_string(options->zones[y]->name, NULL);
			axfr_zone_count++;
			axfr_zone_list = realloc(axfr_zone_list, axfr_zone_count*sizeof(nsd_options_zone_type));
			axfr_zone_list[axfr_zone_count-1] = options->zones[y];
			if (verbose) {
				printf("Scheduling %s for zone transfer\n", current_zone_name);
			}
		}
	} else {
		for (x = 0; x < zone_count; x++) {
			/*printf("CL zone: %s (%u)\n", zone_names[x], x);*/
			current_zone_found = false;
			
	                for (y = 0; y < options->zone_count && !current_zone_found; y++) {
	                        current_zone_name = dname_to_string(options->zones[y]->name, NULL);
	                        if (strlen(zone_names[x]) == strlen(current_zone_name) && 
	                            strncmp(current_zone_name, zone_names[x], strlen(current_zone_name)) == 0) {
	                                axfr_zone_count++;
	                                axfr_zone_list = realloc(axfr_zone_list, axfr_zone_count);
	                                axfr_zone_list[axfr_zone_count-1] = options->zones[y];
					if (verbose) {
						printf("Scheduling %s for zone transfer\n", current_zone_name);
					}
					current_zone_found = true;
	                        }
	                }

			if (!current_zone_found) {
				printf("No config settings for zone %s. Aborting all transfers.\n", zone_names[x]);
				result = EXIT_FAILURE;
				goto exit;
			}
                }
	}

	for (zone_i = 0; zone_i < axfr_zone_count; zone_i++) {
		
		current_zone_transfered = false;
		skip_current_zone = false;
		have_serial = false;
		
		current_zone_name = dname_to_string(axfr_zone_list[zone_i]->name, NULL);
		
		count = 0;
		
		if (verbose) {
			printf("zone: %s\n", current_zone_name);
			printf("\t%u master server(s) configured:\n", axfr_zone_list[zone_i]->master_count);
		}
		for (master_i = 0; master_i < axfr_zone_list[zone_i]->master_count && !current_zone_transfered; master_i++) {
			for (addr_i = 0; addr_i < axfr_zone_list[zone_i]->masters[master_i]->addresses->count && !current_zone_transfered; addr_i++) {
				master_address = axfr_zone_list[zone_i]->masters[master_i]->addresses->addresses[addr_i];

				if (master_address->family == AF_INET) {
					result = ldns_str2rdf_a(&ns_addr, master_address->address);
				} else if (master_address->family == AF_INET6) {
					result = ldns_str2rdf_aaaa(&ns_addr, master_address->address);
				} else {
					/* No inet type given, try aaaa then a */
					if (ldns_str2rdf_aaaa(&ns_addr, master_address->address) != LDNS_STATUS_OK &&
					    ldns_str2rdf_a(&ns_addr, master_address->address) != LDNS_STATUS_OK) {
						fprintf(stderr, "Error, unknown address family (%u) for %s, aborting\n", master_address->family, master_address->address);
						goto exit;
					}
				}
				
				if (verbose) {
					printf("\taddress:");
					ldns_rdf_print(stdout, ns_addr);
					printf("\n");
				}
				
				res = ldns_resolver_new();
				if (!res) {
					fprintf(stderr, "Unable to create resolver object");
					goto exit;
				}
				
				ldns_resolver_push_nameserver(res, ns_addr);
				ldns_rdf_deep_free(ns_addr);
				ns_addr = NULL;
				
				/* TODO: move service->port to ldns (?) */
				serv = getservbyname(master_address->port, NULL);
				if (serv) {
					port = serv->s_port;
				} else {
					port = atoi(master_address->port);
				}

				ldns_resolver_set_port(res, port);


				/* always use tcp for axfr itself */
				ldns_resolver_set_usevc(res, true);
				

				result = ldns_str2rdf_dname(&ldns_zone_name, current_zone_name);
				if (result != LDNS_STATUS_OK) {
					fprintf(stderr, "Unable to convert zone name %s\n", current_zone_name);
				}
				
				/* find the file in which it is stored */
				filename = axfr_zone_list[zone_i]->file;
				if (!filename) {
					fprintf(stderr, "Unable to find file for zone %s\n", dname_to_string(options->zones[y]->name, NULL));
					goto exit;
				}

				if (verbose) {
					fprintf(stdout, "\tZone file: %s\n", filename);
				}

				/* if the file exists, find soa serial */
				orig_zone_fp = fopen(filename, "r");
				if (orig_zone_fp) {

					if (verbose) {
					printf("\tchecking serial\n");
					}
					while (!have_serial) {
						fgets(line, MAX_LINE_LEN-1, orig_zone_fp);
						if (strstr(line, "SOA")) {
							strncpy(soa_str, line, MAX_LINE_LEN);
							/* if line contains (, keep adding until )  TODO */
							/* skip comments by hand for now */
							if (strchr(line, ';')) {
								*strchr(line, ';') = '\0';
							}
							if (strchr(line, '(')) {
								lines = 1;
								while (!strchr(line, ')') && lines < MAX_LINES) {
									fgets(line, MAX_LINE_LEN-1, orig_zone_fp);
									/* skip comments by hand for now */
									if (strchr(line, ';')) {
										*strchr(line, ';') = '\0';
									}
									strcat(soa_str, line);
									lines++;
								}
							}

							soa_rr = ldns_rr_new_frm_str(soa_str);
							
							if (!soa_rr) {
								fprintf(stderr, "Unable to extract SOA record from %s. Aborting.\n", filename);
								result = 1;
								goto exit;
							}

							serial = ldns_rdf2native_int32(ldns_rr_rdf(soa_rr, 2));
							have_serial = true;
							ldns_rr_free(soa_rr);
							soa_rr = NULL;
						}
					}
					fclose(orig_zone_fp);

					soa_pkt = ldns_resolver_query(res, ldns_zone_name, LDNS_RR_TYPE_SOA, LDNS_RR_CLASS_IN, 0);
					if (!soa_pkt) {
						fprintf(stderr, "\tUnable to check serial, no SOA packet received\n");
						result = EXIT_FAILURE;
						goto exit;
					} else if (ldns_pkt_rcode(soa_pkt) != 0) {
						ldns_pkt_print(stderr, soa_pkt);
						result = ldns_pkt_rcode(soa_pkt);
						ldns_pkt_free(soa_pkt);
						soa_pkt = NULL;
						goto exit;
					} else {
						soa_rrs = ldns_pkt_rr_list_by_type(soa_pkt, LDNS_RR_TYPE_SOA, LDNS_SECTION_ANSWER);
						if (ldns_rr_list_rr_count(soa_rrs) > 1) {
							fprintf(stderr, "\tError: received more than 1 SOA\n");
							result = EXIT_FAILURE;
							goto exit;
						} else if (ldns_rr_list_rr_count(soa_rrs) < 1) {
							fprintf(stderr, "\tError: SOA packet contains no SOA record\n");
							result = EXIT_FAILURE;
							goto exit;
						} else {
							master_serial = ldns_rdf2native_int32(ldns_rr_rdf(ldns_rr_list_rr(soa_rrs, 0), 2));
							if (verbose) {
								fprintf(stdout, "\tSerial from master: %u\n\tCurrent serial: %u\n", master_serial, serial);
							}
							if (serial >= master_serial) {
								if (verbose) {
									fprintf(stdout, "\tNo axfr transfer needed for %s.\n", current_zone_name);
								}
								skip_current_zone = true;
							}
						}
						ldns_pkt_free(soa_pkt);
						soa_pkt = NULL;
						ldns_rr_list_deep_free(soa_rrs);
						soa_rrs = NULL;
						
					}
				} else {
					if (verbose) {
						result = errno;
						printf("\tUnable to open %s for reading (%s)\n", filename, strerror(result));
					}
				}

				if (!skip_current_zone) {
					
					if (have_serial) {
						/* Create backup file */
						backup_filename = malloc(strlen(filename) + 15);
						if (!backup_filename) {
							fprintf(stderr, "Out of memory. Aborting");
							goto exit;
						}
						sprintf(backup_filename, "%s.%u", filename, serial);
						if (rename(filename, backup_filename) == -1) {
							result = errno;
							fprintf (stderr, "Unable to create backup file %s (%s). Aborting.\n", backup_filename, strerror(result));
							goto exit;
						}
					}

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

					current_zone_transfered = true;
					
					if (delete_backups) {
						remove(backup_filename);
					}

				}

				ldns_rdf_deep_free(ldns_zone_name);
				ldns_zone_name = NULL;
				
				ldns_resolver_deep_free(res);
				res = NULL;

				if (backup_filename) {
					free(backup_filename);
					backup_filename = NULL;
				}

			}
		}

		if (!skip_current_zone && !current_zone_transfered) {
			fprintf(stderr, "Zone %s not transferred.\n", current_zone_name);
		}
		
		if (verbose) {
			printf("\n");
		}
		
	}

        result = EXIT_SUCCESS;

        exit:
	free(axfr_zone_list);
        region_destroy(region);
        
        return result;

}
