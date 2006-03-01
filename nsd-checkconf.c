/*
 * printconf - Read and repeat configuration file to output.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include "options.h"
#include "util.h"

static void
usage(void)
{
	fprintf(stderr, "usage: checkconf [-v] <configfilename>\n");
	exit(1);
}

static void print_string_var(const char* varname, const char* value)
{
	if(!value) printf("\t#%s\n", varname);
	else printf("\t%s \"%s\"\n", varname, value);
}

static void print_acl(const char* varname, acl_options_t* acl)
{
	while(acl)
	{
		printf("\t%s %s %s\n", varname, acl->ip_address_spec,
			acl->nokey?"NOKEY":(acl->blocked?"BLOCKED":
			(acl->key_name?acl->key_name:"(null)")));
		if(1) {
			printf("\t# %s", acl->is_ipv6?"ip6":"ip4");
			if(acl->port == 0) printf(" noport");
			else printf(" port=%d", acl->port);
			if(acl->rangetype == acl_range_single) printf(" single");
			if(acl->rangetype == acl_range_mask)   printf(" masked");
			if(acl->rangetype == acl_range_subnet) printf(" subnet");
			if(acl->rangetype == acl_range_minmax) printf(" minmax");
			if(acl->is_ipv6) {
#ifdef INET6
				char dest[INET6_ADDRSTRLEN+100];
				inet_ntop(AF_INET6, &acl->addr.addr6, dest, sizeof(dest));
				printf(" addr=%s", dest);
				if(acl->rangetype != acl_range_single) {
					inet_ntop(AF_INET6, &acl->range_mask.addr6, dest, sizeof(dest));
					printf(" rangemask=%s", dest);
				}
#else
				printf(" ip6addr-noip6defined");
#endif
			} else {
				char dest[INET_ADDRSTRLEN+100];
				inet_ntop(AF_INET, &acl->addr.addr6, dest, sizeof(dest));
				printf(" addr=%s", dest);
				if(acl->rangetype != acl_range_single) {
					inet_ntop(AF_INET, &acl->range_mask.addr6, dest, sizeof(dest));
					printf(" rangemask=%s", dest);
				}
			}
			printf("\n");
		}
		acl=acl->next;
	}
}

void config_test_print_server(nsd_options_t* opt)
{
	ip_address_option_t* ip;
	key_options_t* key;
	zone_options_t* zone;

	printf("# Config settings.\n");
	printf("server:\n");
	printf("\tdebug-mode: %s\n", opt->debug_mode?"yes":"no");
	printf("\tip4-only: %s\n", opt->ip4_only?"yes":"no");
	printf("\tip6-only: %s\n", opt->ip6_only?"yes":"no");
	print_string_var("database:", opt->database);
	print_string_var("identity:", opt->identity);
	print_string_var("logfile:", opt->logfile);
	printf("\tserver_count: %d\n", opt->server_count);
	printf("\ttcp_count: %d\n", opt->tcp_count);
	print_string_var("pidfile:", opt->pidfile);
	print_string_var("port:", opt->port);
	printf("\tstatistics: %d\n", opt->statistics);
	print_string_var("chroot:", opt->chroot);
	print_string_var("username:", opt->username);
	print_string_var("zonesdir:", opt->zonesdir);

	for(ip = opt->ip_addresses; ip; ip=ip->next)
	{
		print_string_var("ip-address:", ip->address);
	}
	for(key = opt->keys; key; key=key->next)
	{
		printf("\nkey:\n");
		print_string_var("name:", key->name);
		print_string_var("algorithm:", key->algorithm);
		print_string_var("secret:", key->secret);
	}
	for(zone = opt->zone_options; zone; zone=zone->next)
	{
		printf("\nzone:\n");
		print_string_var("name:", zone->name);
		print_string_var("zonefile:", zone->zonefile);
		print_acl("allow-notify:", zone->allow_notify);
		print_acl("request-xfr:", zone->request_xfr);
		print_acl("notify:", zone->notify);
		print_acl("provide-xfr:", zone->provide_xfr);
	}
	
}

static int additional_checks(nsd_options_t* opt, const char* filename)
{
	ip_address_option_t* ip = opt->ip_addresses;
	int num = 0;
	int errors = 0;
	while(ip) {
		num++;
		ip = ip->next;
	}
	if(num >= MAX_INTERFACES) {
		fprintf(stderr, "%s: too many interfaces (ip-address:) specified.\n", filename);
		errors ++;
	}
#ifndef BIND8_STATS
	if(opt->statistics > 0)
	{
		fprintf(stderr, "%s: 'statistics: %d' but BIND 8 statistics feature not enabled.\n", 
			filename, opt->statistics);
		errors ++;
	}
#endif
#ifndef HAVE_CHROOT
	if(opt->chroot != 0)
	{
		fprintf(stderr, "%s: chroot %s given. chroot not supported on this platform.\n", 
			filename, opt->chroot);
		errors ++;
	}
#endif
#ifndef INET6
	if(opt->ipv6_only)
	{
		fprintf(stderr, "%s: ipv6_only given but IPv6 support not enabled.\n", filename);
		errors ++;
	}
#endif
	if (strlen(opt->identity) > UCHAR_MAX) {
                fprintf(stderr, "%s: server identity too long (%u characters)\n",
                      filename, (unsigned) strlen(opt->identity));
		errors ++;
        }

	/* not done here: parsing of ip-address. parsing of username. */

        if (opt->chroot) {
                int l = strlen(opt->chroot);

                if (strncmp(opt->chroot, opt->pidfile, l) != 0) {
			fprintf(stderr, "%s: pidfile %s is not relative to chroot %s.\n", 
				filename, opt->pidfile, opt->chroot);
			errors ++;
                } 
		if (strncmp(opt->chroot, opt->database, l) != 0) {
			fprintf(stderr, "%s: databasefile %s is not relative to chroot %s.\n", 
				filename, opt->database, opt->chroot);
			errors ++;
                }
        }
	if (atoi(opt->port) <= 0) {
		fprintf(stderr, "%s: port number '%s' is not a positive number.\n", 
			filename, opt->port);
		errors ++;
	}
	if(errors != 0) {
		fprintf(stderr, "%s: parse ok %d zones, %d keys, but %d semantic errors.\n",
			filename, opt->numzones, opt->numkeys, errors);
	}
	
	return (errors == 0);
}

int main(int argc, char* argv[])
{
	int c;
	int verbose = 0;
	const char* configfile;
        /* Parse the command line... */
        while ((c = getopt(argc, argv, "v")) != -1) {
		switch (c) {
		case 'v':
			verbose = 1;
			break;
		default:
			usage();
		};
	}
        argc -= optind;
        argv += optind;
        if (argc == 0 || argc>=2) usage();
	configfile = argv[0];

	/* read config file */
	nsd_options_create(region_create(xalloc, free));
	if(!parse_options_file(nsd_options, configfile) ||
	   !additional_checks(nsd_options, configfile))
		return 1;
	printf("# Read file %s: %d zones, %d keys.\n", configfile, 
		nsd_options->numzones, nsd_options->numkeys);
	if(verbose) {
		config_test_print_server(nsd_options);
	}
	return 0;
}
