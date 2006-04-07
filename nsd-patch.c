/*
 * nsd-patch - read database and ixfrs and patch up zone files.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "options.h"
#include "difffile.h"
#include "namedb.h"
#include "util.h"

static void
usage(void)
{
	/* TODO manpage */
        fprintf(stderr, "usage: nsd-patch [-c <configfilename>]\n");
        exit(1);
}

static int
exist_difffile(struct nsd_options* opt)
{
	/* see if diff file exists */
	const char* file = DIFFFILE;
	FILE *f;
	if(opt->difffile) file = opt->difffile;

	f = fopen(file, "r");
	if(!f) {
		if(errno == ENOENT)
			return 0;
		fprintf(stderr, "could not open file %s: %s",
			file, strerror(errno));
		return 0;
	}
	return 1;
}

static void
print_rrs(FILE* out, struct zone* zone)
{
	rrset_type *rrset;
	domain_type *domain = zone->apex;
	region_type* region = region_create(xalloc, free);
	struct state_pretty_rr* state = create_pretty_rr(region);
        /* go through entire tree below the zone apex (incl subzones) */
	while(domain && dname_is_subdomain(
		domain_dname(domain), domain_dname(zone->apex)))
	{
		for(rrset = domain->rrsets; rrset; rrset=rrset->next)
		{
			size_t i;
			if(rrset->zone != zone)
				continue;
			for(i=0; i<rrset->rr_count; i++) {
				if(!print_rr(out, state, &rrset->rrs[i])){
					fprintf(stderr, "There was an error "
					   "printing RR to zone %s\n",
					   zone->opts->name);
				}
			}
		}
		domain = domain_next(domain);
	}
	region_destroy(region);
}

static void
write_to_zonefile(struct zone* zone)
{
	const char* filename = zone->opts->zonefile;
	time_t now = time(0);
	FILE *out;

	printf("writing zone %s to file %s\n", zone->opts->name, filename);

	if(!zone->apex) {
		fprintf(stderr, "zone %s has no apex, no data.", filename);
		return;
	}

	out = fopen(filename, "w");
	if(!out) {
		fprintf(stderr, "cannot open or create file %s for writing: %s",
			filename, strerror(errno));
		return;
	}
	
	/* print zone header */
	fprintf(out, "; NSD version %s\n", PACKAGE_VERSION);
	fprintf(out, "; nsd-patch zone %s run at time %s", 
		zone->opts->name, ctime(&now));
	/* TODO ; as comments commit strings from diff file */

	print_rrs(out, zone);

	fclose(out);
}

int main(int argc, char* argv[])
{
	int c;
	const char* configfile = CONFIGFILE;
	nsd_options_t *options;
	struct namedb* db;
	struct zone* zone;

        /* Parse the command line... */
	while ((c = getopt(argc, argv, "c:")) != -1) {
	switch (c) {
		case 'c':
			configfile = optarg;
			break;
		default:
			usage();
		};
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) 
		usage();

	/* read config file */
	log_init("nsd-patch");
	options = nsd_options_create(region_create(xalloc, free));
	if(!parse_options_file(options, configfile)) {
		fprintf(stderr, "Could not read config: %s\n", configfile);
		exit(1);
	}

	/* see if necessary */
	if(!exist_difffile(options)) {
		printf("No diff file, nothing to do\n");
		exit(0);
	}

	/* read database and diff file */
	printf("reading database\n");
	db = namedb_open(options->database, options);
	if(!db) {
		fprintf(stderr, "Could not read database: %s\n", 
			options->database);
		exit(1);
	}

	/* set all updated to 0 so we know what has changed */
	for(zone = db->zones; zone; zone = zone->next)
	{
		zone->updated = 0;
	}

	/* read ixfr diff file */
	printf("reading updates to database\n");
	if(!diff_read_file(db, options)) {
		fprintf(stderr, "unable to load the diff file: %s", 
			strerror(errno));
		exit(1);
	}

	printf("writing changed zones\n");
	for(zone = db->zones; zone; zone = zone->next)
	{
		if(!zone->updated) {
			printf("zone %s had not changed.\n",
				zone->opts->name);
			continue;
		}
		/* write zone to its zone file */
		write_to_zonefile(zone);
	}
	printf("done\n");

	return 0;
}
