/*
 * $Id: zonec2.c,v 1.24 2003/10/23 18:41:39 miekg Exp $
 *
 * zone.c -- reads in a zone file and stores it in memory
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "heap.h"
#include "namedb.h"
#include "util.h"
#include "region-allocator.h"
#include "zonec2.h"
#include "zparser2.h"

region_type *zone_region;
region_type *rr_region;

/* The database file... */
static const char *dbfile = DBFILE;

/* Some global flags... */
static int vflag = 0;
static int pflag = 0;

/* Total errors counter */
static int totalerrors = 0;

static void 
zone_print (zone_type *zone)
{
	return;
}

static int
write_dname(struct namedb *db, domain_type *domain)
{
	const dname_type *dname = domain->dname;
	
	if (!write_data(db->fd, &dname->name_size, sizeof(dname->name_size)))
		return 0;

	if (!write_data(db->fd, dname_name(dname), dname->name_size))
		return 0;

	return 1;
}

static int
write_number(struct namedb *db, uint32_t number)
{
	number = htonl(number);
	return write_data(db->fd, &number, sizeof(number));
}

static int
write_rrset(struct namedb *db, domain_type *domain, rrset_type *rrset)
{
	uint32_t ttl;
	uint16_t class;
	uint16_t type;
	uint16_t rdcount;
	uint16_t rrslen;
	int i, j;

	assert(db);
	assert(domain);
	assert(rrset);
	
	class = htons(CLASS_IN);
	type = htons(rrset->type);
	ttl = htonl(rrset->ttl);
	rrslen = htons(rrset->rrslen);
	
	if (!write_number(db, domain->number))
		return 0;

	if (!write_number(db, rrset->zone->number))
		return 0;
	
	if (!write_data(db->fd, &type, sizeof(type)))
		return 0;
		
	if (!write_data(db->fd, &class, sizeof(class)))
		return 0;
		
	if (!write_data(db->fd, &ttl, sizeof(ttl)))
		return 0;

	if (!write_data(db->fd, &rrslen, sizeof(rrslen)))
		return 0;
		
	for (i = 0; i < rrset->rrslen; ++i) {
		rdcount = 0;
		for (rdcount = 0; !rdata_atom_is_terminator(rrset->rrs[i][rdcount]); ++rdcount)
			;
		
		rdcount = htons(rdcount);
		if (!write_data(db->fd, &rdcount, sizeof(rdcount)))
			return 0;
		
		for (j = 0; !rdata_atom_is_terminator(rrset->rrs[i][j]); ++j) {
			rdata_atom_type atom = rrset->rrs[i][j];
			if (rdata_atom_is_domain(rrset->type, j)) {
				if (!write_number(db, rdata_atom_domain(atom)->number))
					return 0;
			} else {
				uint16_t size = htons(rdata_atom_size(atom));
				if (!write_data(db->fd, &size, sizeof(size)))
					return 0;
				if (!write_data(db->fd,
						rdata_atom_data(atom),
						rdata_atom_size(atom)))
					return 0;
			}
		}
	}

	return 1;
}

static void
cleanup_rrset(void *r)
{
	struct rrset *rrset = r;
	if (rrset) {
		free(rrset->rrs);
	}
}

int
process_rr(zparser_type *parser, rr_type *rr)
{
	zone_type *zone = parser->current_zone;
	rrset_type *rrset;
	int i;
	
	/*
        if (pflag > 0) 
		zprintrr(stderr, rr);
		*/
		
	/* We only support IN class */
	if (rr->class != CLASS_IN) {
		zerror("Wrong class");
		return 0;
	}

	if (!dname_is_subdomain(rr->domain->dname, zone->domain->dname)) {
		zerror("Out of zone data");
		return 0;
	}

	/* Do we have this type of rrset already? */
	rrset = domain_find_rrset(rr->domain, zone, rr->type);

	/* Do we have this particular rrset? */
	if (rrset == NULL) {
		rrset = region_alloc(zone_region, sizeof(rrset_type));
		rrset->zone = rr->zone;
		rrset->type = rr->type;
		rrset->class = rr->class;
		rrset->ttl = rr->ttl;
		rrset->rrslen = 1;
		rrset->rrs = xalloc(sizeof(rdata_atom_type **));
		rrset->rrs[0] = rr->rdata;
			
		region_add_cleanup(zone_region, cleanup_rrset, rrset);

		/* Add it */
		domain_add_rrset(rr->domain, rrset);
	} else {
		if (rrset->ttl != rr->ttl) {
			zerror("ttl doesn't match the ttl of the rrset");
			return 0;
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rrslen; i++) {
			if (!zrdatacmp(rrset->type, rrset->rrs[i], rr->rdata)) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rrslen) {
			return 0;
		}

		/* Add it... */
		rrset->rrs = xrealloc(rrset->rrs, (rrset->rrslen + 1) * sizeof(rdata_atom_type **));
		rrset->rrs[rrset->rrslen++] = rr->rdata;
	}

	/* Check we have SOA */
	if (zone->soa_rrset == NULL) {
		if (rr->type != TYPE_SOA) {
			zerror("Missing SOA record on top of the zone");
		} else if (rr->domain != zone->domain) {
			zerror( "SOA record with invalid domain name");
		} else {
			zone->soa_rrset = rrset;
		}
	} else if (rr->type == TYPE_SOA) {
		zerror("Duplicate SOA record discarded");
		--rrset->rrslen;
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && rr->domain == zone->domain) {
		zone->ns_rrset = rrset;
	}

	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static zone_type *
zone_read (struct namedb *db, char *name, char *zonefile)
{
	zone_type *zone;
	const dname_type *dname;

	dname = dname_parse(zone_region, name, NULL);
	if (!dname) {
		return NULL;
	}
	
#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dname->label_count == 1) {
		fprintf(stderr, "zonec: Not configured as a root server. See the documentation.\n");
		return NULL;
	}
#endif

	/* Allocate new zone structure */
	zone = region_alloc(zone_region, sizeof(zone_type));
	zone->domain = domain_table_insert(db->domains, dname);
	zone->soa_rrset = NULL;
	zone->ns_rrset = NULL;

	zone->next = db->zones;
	db->zones = zone;
	
	/* Open the zone file */
	if (!nsd_zopen(zone, zonefile, 3600, CLASS_IN, name)) {
		fprintf(stderr, "zonec: unable to open %s: %s\n", zonefile, strerror(errno));
		return NULL;
	}

	/* Parse and process all RRs.  */
	yyparse();

	fflush(stdout);
	totalerrors += current_parser->errors;

	return zone;
}

static void
number_dnames_iterator(domain_type *node, void *user_data)
{
	size_t *current_number = user_data;

	node->number = *current_number;
	++*current_number;
}

static void
write_dname_iterator(domain_type *node, void *user_data)
{
	struct namedb *db = user_data;
	
	write_dname(db, node);
}

static void
write_domain_iterator(domain_type *node, void *user_data)
{
	struct namedb *db = user_data;
	struct rrset *rrset;

	for (rrset = node->rrsets; rrset; rrset = rrset->next) {
		write_rrset(db, node, rrset);
	}
}

/*
 * Writes databse data into open database *db
 *
 * Returns zero if success.
 */
static int 
db_dump (namedb_type *db)
{
	zone_type *zone;
	uint32_t terminator = 0;
	uint32_t dname_count = 1;
	uint32_t zone_count = 1;
	
	for (zone = db->zones; zone; zone = zone->next) {
		zone->number = zone_count;
		++zone_count;
		
		if (!zone->soa_rrset) {
			fprintf(stderr, "SOA record not present in %s\n",
				dname_to_string(zone->domain->dname));
			++totalerrors;
		}
	}

	if (totalerrors > 0)
		return -1;

	--zone_count;
	if (!write_number(db, zone_count))
		return -1;
	for (zone = db->zones; zone; zone = zone->next) {
		if (!write_dname(db, zone->domain))
			return -1;
	}
	
	domain_table_iterate(db->domains, number_dnames_iterator, &dname_count);
	--dname_count;
	if (!write_number(db, dname_count))
		return -1;

	DEBUG(DEBUG_ZONEC, 1,
	      (stderr, "Storing %lu domain names\n", (unsigned long) dname_count));
	
	domain_table_iterate(db->domains, write_dname_iterator, db);
		   
	domain_table_iterate(db->domains, write_domain_iterator, db);
	if (!write_data(db->fd, &terminator, sizeof(terminator)))
		return -1;

	return 0;
}

static void 
usage (void)
{
	fprintf(stderr, "usage: zonec [-v] [-p] [-f database] [-d directory] zone-list-file\n\n");
	fprintf(stderr, "\t-p\tprint rr after compilation\n");
	fprintf(stderr, "\t-v\tbe more verbose\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int 
main (int argc, char **argv)
{
	char *zonename, *zonefile, *s;
	char buf[LINEBUFSZ];
	struct namedb *db;
	const char *sep = " \t\n";
	int c;
	int line = 0;
	FILE *f;

	struct zone *z = NULL;

	log_init("zonec");
	zone_region = region_create(xalloc, free);
	rr_region = region_create(xalloc, free);
	
	totalerrors = 0;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "d:f:vpF:L:")) != -1) {
		switch (c) {
		case 'p':
			pflag = 1;
			break;
		case 'v':
			++vflag;
			break;
		case 'f':
			dbfile = optarg;
			break;
		case 'd':
			if (chdir(optarg)) {
				fprintf(stderr, "zonec: cannot chdir to %s: %s\n", optarg, strerror(errno));
				break;
			}
			break;
#ifndef NDEBUG
		case 'F':
			sscanf(optarg, "%x", &nsd_debug_facilities);
			break;
		case 'L':
			sscanf(optarg, "%d", &nsd_debug_level);
			break;
#endif /* NDEBUG */
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* Create the database */
	if ((db = namedb_new(dbfile)) == NULL) {
		fprintf(stderr, "zonec: error creating the database: %s\n", strerror(errno));
		exit(1);
	}

	current_parser = zparser_init(db);
	current_rr = region_alloc(zone_region, sizeof(rr_type));
	
	/* Open the master file... */
	if ((f = fopen(*argv, "r")) == NULL) {
		fprintf(stderr, "zonec: cannot open %s: %s\n", *argv, strerror(errno));
		exit(1);
	}

	/* Do the job */
	while (fgets(buf, LINEBUFSZ - 1, f) != NULL) {
		/* Count the lines... */
		line++;

		/* Skip empty lines and comments... */
		if ((s = strtok(buf, sep)) == NULL || *s == ';')
			continue;

		if (strcasecmp(s, "zone") != 0) {
			fprintf(stderr, "zonec: syntax error in %s line %d: expected token 'zone'\n", *argv, line);
			break;
		}

		/* Zone name... */
		if ((zonename = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d: expected zone name\n", *argv, line);
			break;
		}

		/* File name... */
		if ((zonefile = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d: expected file name\n", *argv, line);
			break;
		}

		/* Trailing garbage? Ignore masters keyword that is used by nsdc.sh update */
		if ((s = strtok(NULL, sep)) != NULL && *s != ';' && strcasecmp(s, "masters") != 0
		    && strcasecmp(s, "notify") != 0) {
			fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
		}

		/* If we did not have any errors... */
		if ((z = zone_read(db, zonename, zonefile)) != NULL) {
			if (pflag)
				zone_print(z);
		} else {
			totalerrors++;
		}

		fprintf(stderr, "zone_region: ");
		region_dump_stats(zone_region, stderr);
		fprintf(stderr, "\n");
	};

	if (db_dump(db) != 0) {
		fprintf(stderr, "zonec: error dumping the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}		
	
	/* Close the database */
	if (namedb_save(db) != 0) {
		fprintf(stderr, "zonec: error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	/* Print the total number of errors */
	fprintf(stderr, "zonec: done with total %d errors.\n", totalerrors);

	region_destroy(zone_region);
	
	return totalerrors ? 1 : 0;
}
