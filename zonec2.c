/*
 * $Id: zonec2.c,v 1.18 2003/10/17 13:51:31 erik Exp $
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
zone_print (struct zone *z)
{
#if 0
	rrset_type *rrset;
	rr_type rr;
	const uint8_t *dname;
	int i;
#endif

	printf("; zone %s\n", dname_to_string(z->dname));
	printf("; zone data\n");

#if 0
	HEAP_WALK(z->data, dname, rrset) {
		while (rrset) {
			rr.dname = (uint8_t *)dname;
			rr.ttl = rrset->ttl;
			rr.class = rrset->class;
			rr.type = rrset->type;
			for (i = 0; i < rrset->rrslen; i++) {
				rr.rdata = rrset->rrs[i];
				/*zprintrr(stdout, &rr);*/
			}
			rrset = rrset->next;
		}
	}
#endif
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
write_dname_number(struct namedb *db, domain_type *domain)
{
	return write_data(db->fd, &domain->number, sizeof(domain->number));
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
	
	if (!write_dname_number(db, domain))
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
				if (!write_dname_number(db, rdata_atom_domain(atom)))
					return 0;
			} else {
				uint16_t size = rdata_atom_size(atom);
				if (!write_data(db->fd, &size, sizeof(uint16_t)))
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
process_rr(struct zone *z, rr_type *rr)
{
	rrset_type *rrset, *r;
	int i;
	
        if ( pflag > 0 ) 
		zprintrr(stderr, rr);
		
	/* Report progress... 
	   if (vflag > 1) {
	   if ((parser->lines % 100000) == 0) {
	   printf("zonec: reading zone \"%s\": %lu\r", dnamestr(z->dname), (unsigned long) parser->lines);
	   fflush(stdout);
	   }
	   }
	   [XXX] done inside lex whatever
	*/

	/* We only support IN class */
	if (rr->class != CLASS_IN) {
		zerror("Wrong class");
		return 0;
	}

	/* Is this in-zone data? */
	/* 
	   printf("d name: [%s]\n", z->dname);
	   printf("rr name: [%s]\n", rr->dname);
	   printf("d name: [%d]\n", (int)z->dname[0]);
	   printf("rr name: [%d]\n", (int)rr->dname[0]);
	   printf("d name: [%d]\n", (int)z->dname[1]);
	   printf("rr name: [%d]\n", (int)rr->dname[1]);
	   printf("d name: [%s]\n", dnamestr(z->dname));
	   printf("rr name: [%s]\n", dnamestr(rr->dname));
	*/
	if (!dname_is_subdomain(rr->domain->dname, z->dname)) {
		zerror("Out of zone data");
		return 0;
	}

	/* Do we have this domain name in heap? */
	if ((rrset = rr->domain->rrsets) != NULL) {
		for (r = rrset; r; r = r->next) {
			if (r->type == rr->type) {
				break;
			}
		}
	} else {
		r = NULL;
	}

	/* Do we have this particular rrset? */
	if (r == NULL) {
		r = region_alloc(zone_region, sizeof(rrset_type));
		region_add_cleanup(zone_region, cleanup_rrset, r);
		r->type = 0;
	}
	if (r->type == 0) {
		r->type = rr->type;
		r->class = rr->class;
		r->ttl = rr->ttl;
		r->rrslen = 1;
		r->rrs = xalloc(sizeof(rdata_atom_type **));
		r->rrs[0] = rr->rdata;
			
		/* Add it */
		domain_add_rrset(rr->domain, r);
	} else {
		if (r->ttl != rr->ttl) {
			zerror("ttl doesn't match the ttl of the rrset");
			return 0;
		}

		/* Search for possible duplicates... */
		for (i = 0; i < r->rrslen; i++) {
			if (!zrdatacmp(r->type, r->rrs[i], rr->rdata)) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < r->rrslen) {
			return 0;
		}

		/* Add it... */
		r->rrs = xrealloc(r->rrs, (r->rrslen + 1) * sizeof(rdata_atom_type **));
		r->rrs[r->rrslen++] = rr->rdata;
	}

	/* Check we have SOA */
	if (z->soa == NULL) {
		if (rr->type != TYPE_SOA) {
			zerror("Missing SOA record on top of the zone");
		} else {
			if (dname_compare(rr->domain->dname, z->dname) != 0) {
				zerror( "SOA record with invalid domain name");
			} else {
				z->soa = r;
			}
		}
	} else {
		if (rr->type == TYPE_SOA) {
			zerror("Duplicate SOA record discarded");
			--r->rrslen;
		}
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && dname_compare(rr->domain->dname, z->dname) == 0) {
		z->ns = r;
	}

	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static struct zone *
zone_read (struct namedb *db, char *name, char *zonefile)
{
	struct zone *z;

	/* Allocate new zone structure */
	z = region_alloc(zone_region, sizeof(struct zone));
	z->db = db;
	
	/* Get the zone name */
	if ((z->dname = dname_parse(zone_region, name, NULL)) == NULL) {
		return NULL;
	}

#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (z->dname->label_count == 1) {
		fprintf(stderr, "zonec: Not configured as a root server. See the documentation.\n");
		return NULL;
	}
#endif

	z->db->domains = domain_table_create(zone_region);
	z->soa = z->ns = NULL;
	
	/* Open the zone file */
	if ( nsd_zopen(z, zonefile, 3600, CLASS_IN, name) == NULL) {
		fprintf(stderr, "zonec: unable to open %s: %s\n", zonefile, strerror(errno));
		return NULL;
	}

	/* Parse and process all RRs.  */
	yyparse();

	fflush(stdout);
	totalerrors += zdefault->errors;

	return z;
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
	struct rrset *rrset = node->rrsets;
	
	while (rrset) {
		write_rrset(db, node, rrset);
		rrset = rrset->next;
	}
}

/*
 * Writes zone data into open database *db
 *
 * Returns zero if success.
 */
static int 
zone_dump (struct zone *z, struct namedb *db)
{
	size_t terminator = 0;
	size_t dname_count = 1;	/* Start with 1 so 0 can be used as a terminator. */
	
	if (!z->soa) {
		fprintf(stderr, "SOA record not present in %s\n", dname_to_string(z->dname));
		++totalerrors;
		return -1;
	}

	domain_table_iterate(z->db->domains, number_dnames_iterator, &dname_count);
	--dname_count;
	write_data(db->fd, &dname_count, sizeof(dname_count));

	DEBUG(DEBUG_ZONEC, 1,
	      (stderr, "Storing %lu domain names\n", (unsigned long) dname_count));
	
	domain_table_iterate(z->db->domains, write_dname_iterator, db);
		   
	domain_table_iterate(z->db->domains, write_domain_iterator, db);
	write_data(db->fd, &terminator, sizeof(terminator));

	if (vflag > 0) {
		fprintf(stderr, "zonec: writing zone \"%s\": done.\n",
			dname_to_string(z->dname));
	}

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
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Zone name... */
		if ((zonename = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* File name... */
		if ((zonefile = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Trailing garbage? Ignore masters keyword that is used by nsdc.sh update */
		if ((s = strtok(NULL, sep)) != NULL && *s != ';' && strcasecmp(s, "masters") != 0
		    && strcasecmp(s, "notify") != 0) {
			fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
		}

		/* If we did not have any errors... */
		if ((z = zone_read(db, zonename, zonefile)) != NULL) {
			zone_dump(z, db);
			if (pflag)
				zone_print(z);
		} else {
			totalerrors++;
		}

		fprintf(stderr, "zone_region: ");
		region_dump_stats(zone_region, stderr);
		fprintf(stderr, "\n");
	    
		region_free_all(zone_region);
	};

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
