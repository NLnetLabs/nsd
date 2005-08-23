/*
 * dbaccess.c -- access methods for nsd(8) database
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>		/* DEBUG */

#include "dns.h"
#include "namedb.h"
#include "util.h"


static void initialize_zone_info(namedb_type *db);

static int
read_magic(namedb_type *db)
{
	char buf[NAMEDB_MAGIC_SIZE];

	if (fread(buf, sizeof(char), sizeof(buf), db->fd) != sizeof(buf))
		return 0;

	return memcmp(buf, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) == 0;
}

static const dname_type *
read_dname(FILE *fd, region_type *region)
{
	uint8_t size;
	uint8_t temp[MAXDOMAINLEN];

	if (fread(&size, sizeof(uint8_t), 1, fd) != 1)
		return NULL;
	if (fread(temp, sizeof(uint8_t), size, fd) != size)
		return NULL;

	return dname_make(region, temp);
}

static int
read_size(namedb_type *db, uint32_t *result)
{
	if (fread(result, sizeof(*result), 1, db->fd) == 1) {
		*result = ntohl(*result);
		return 1;
	} else {
		return 0;
	}
}

static domain_type *
read_domain(namedb_type *db, uint32_t domain_count, domain_type **domains)
{
	uint32_t domain_number;

	if (!read_size(db, &domain_number))
		return NULL;

	if (domain_number == 0 || domain_number > domain_count)
		return NULL;

	return domains[domain_number - 1];
}

static int
read_rdata_atom(namedb_type *db, uint16_t type, int index, uint32_t domain_count, domain_type **domains, rdata_atom_type *result)
{
	uint8_t data[65536];

	if (rdata_atom_is_domain(type, index)) {
		result->domain = read_domain(db, domain_count, domains);
		if (!result->domain)
			return 0;
	} else {
		uint16_t size;

		if (fread(&size, sizeof(size), 1, db->fd) != 1)
			return 0;
		size = ntohs(size);
		if (fread(data, sizeof(uint8_t), size, db->fd) != size)
			return 0;

		result->data = (uint16_t *) region_alloc(
			db->region, sizeof(uint16_t) + size);
		memcpy(result->data, &size, sizeof(uint16_t));
		memcpy((uint8_t *) result->data + sizeof(uint16_t), data, size);
	}

	return 1;
}

static rrset_type *
read_rrset(namedb_type *db, zone_type *zone,
	   uint32_t domain_count, domain_type **domains)
{
	rrset_type *rrset;
	int i, j;
	domain_type *owner;
	uint16_t type;
	uint16_t klass;

	owner = read_domain(db, domain_count, domains);
	if (!owner)
		return NULL;

	rrset = (rrset_type *) region_alloc(db->region, sizeof(rrset_type));

	if (fread(&type, sizeof(type), 1, db->fd) != 1)
		return NULL;
	type = ntohs(type);

	if (fread(&klass, sizeof(klass), 1, db->fd) != 1)
		return NULL;
	klass = ntohs(klass);

	if (fread(&rrset->rr_count, sizeof(rrset->rr_count), 1, db->fd) != 1)
		return NULL;
	rrset->rr_count = ntohs(rrset->rr_count);
	rrset->rrs = (rr_type *) region_alloc(
		db->region, rrset->rr_count * sizeof(rr_type));

	assert(rrset->rr_count > 0);

	for (i = 0; i < rrset->rr_count; ++i) {
		rr_type *rr = &rrset->rrs[i];

		rr->type = type;
		rr->klass = klass;

		if (fread(&rr->rdata_count, sizeof(rr->rdata_count), 1, db->fd) != 1)
			return NULL;
		rr->rdata_count = ntohs(rr->rdata_count);
		rr->rdatas = (rdata_atom_type *) region_alloc(
			db->region, rr->rdata_count * sizeof(rdata_atom_type));

		if (fread(&rr->ttl, sizeof(rr->ttl), 1, db->fd) != 1)
			return NULL;
		rr->ttl = ntohl(rr->ttl);

		for (j = 0; j < rr->rdata_count; ++j) {
			if (!read_rdata_atom(db, rr->type, j, domain_count, domains, &rr->rdatas[j]))
				return NULL;
		}
	}

	domain_add_rrset(owner, rrset);

	if (rrset_rrtype(rrset) == TYPE_SOA) {
		assert(owner == zone->apex);
		zone->soa_rrset = rrset;
	} else if (owner == zone->apex && rrset_rrtype(rrset) == TYPE_NS) {
		zone->ns_rrset = rrset;
	}

#ifdef DNSSEC
	if (owner == zone->apex && rrset_rrtype(rrset) == TYPE_RRSIG) {
		for (i = 0; i < rrset->rr_count; ++i) {
			if (rr_rrsig_type_covered(&rrset->rrs[i]) == TYPE_SOA) {
				zone->is_secure = 1;
				break;
			}
		}
	}
#endif

	return rrset;
}

namedb_type *
namedb_open(const char *filename)
{
	namedb_type *db;

	/*
	 * Region used to store the loaded database.  The region is
	 * freed in namedb_close.
	 */
	region_type *db_region;

	/*
	 * Temporary region used while loading domain names from the
	 * database.  The region is freed after each time a dname is
	 * read from the database.
	 */
	region_type *dname_region;

	/*
	 * Temporary region used to store array of domains and zones
	 * while loading the database.  The region is freed before
	 * returning.
	 */
	region_type *temp_region;

	uint32_t dname_count;
	domain_type **domains;	/* Indexed by domain number.  */

	uint32_t zone_count;

	uint32_t i;

	rrset_type *rrset;

	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(namedb_type) = %lu\n", (unsigned long) sizeof(namedb_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(zone_type) = %lu\n", (unsigned long) sizeof(zone_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(domain_type) = %lu\n", (unsigned long) sizeof(domain_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rrset_type) = %lu\n", (unsigned long) sizeof(rrset_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rr_type) = %lu\n", (unsigned long) sizeof(rr_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rdata_atom_type) = %lu\n", (unsigned long) sizeof(rdata_atom_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rbnode_t) = %lu\n", (unsigned long) sizeof(rbnode_t)));

	db_region = region_create(xalloc, free);
	db = (namedb_type *) region_alloc(db_region, sizeof(namedb_type));
	db->region = db_region;
	db->zones = heap_create(db->region, dname_compare_void);
	db->filename = region_strdup(db->region, filename);

	/* Open it... */
	db->fd = fopen(db->filename, "r");
	if (db->fd == NULL) {
		log_msg(LOG_ERR, "unable to load %s: %s",
			db->filename, strerror(errno));
		region_destroy(db_region);
		return NULL;
	}

	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database (bad magic): %s",
			db->filename);
		namedb_close(db);
		return NULL;
	}

	if (!read_size(db, &zone_count)) {
		log_msg(LOG_ERR, "corrupted database (no zones): %s",
			db->filename);
		namedb_close(db);
		return NULL;
	}

	DEBUG(DEBUG_DBACCESS, 1,
	      (stderr, "Retrieving %lu zones\n", (unsigned long) zone_count));

	temp_region = region_create(xalloc, free);
	dname_region = region_create(xalloc, free);
	for (i = 0; i < zone_count; ++i) {
		uint32_t j;
		uint32_t rrset_count;
		uint32_t rr_count;
		zone_type *zone;
		const dname_type *apex;

		apex = read_dname(db->fd, dname_region);
		if (!apex) {
			log_msg(LOG_ERR,
				"corrupted database (missing zone): %s",
				db->filename);
			region_destroy(dname_region);
			region_destroy(temp_region);
			namedb_close(db);
			return NULL;
		}
		zone = namedb_insert_zone(db, apex);
		region_free_all(dname_region);

		if (!read_size(db, &dname_count)) {
			log_msg(LOG_ERR,
				"corrupted database (missing domain table): %s",
				db->filename);
			region_destroy(dname_region);
			region_destroy(temp_region);
			namedb_close(db);
			return NULL;
		}

		DEBUG(DEBUG_DBACCESS, 1,
		      (stderr, "Retrieving %lu domain names for zone %s\n",
		       (unsigned long) dname_count,
		       dname_to_string(domain_dname(zone->apex), NULL)));

		domains = (domain_type **) region_alloc(
			temp_region, dname_count * sizeof(domain_type *));
		for (j = 0; j < dname_count; ++j) {
			const dname_type *dname
				= read_dname(db->fd, dname_region);
			if (!dname) {
				log_msg(LOG_ERR, "corrupted database (missing domain name): %s",
					db->filename);
				region_destroy(dname_region);
				region_destroy(temp_region);
				namedb_close(db);
				return NULL;
			}
			DEBUG(DEBUG_DBACCESS, 3,
			      (stderr, "Retreived domain name %s\n",
			       dname_to_string(dname, NULL)));
			domains[j] = domain_table_insert(zone->domains, dname);
			domains[j]->number = j + 1;
			region_free_all(dname_region);
		}

		rrset_count = 0;
		rr_count = 0;

		while ((rrset = read_rrset(db, zone, dname_count, domains))) {
			++rrset_count;
			rr_count += rrset->rr_count;
		}

		DEBUG(DEBUG_DBACCESS, 1,
		      (stderr, "Retrieved %lu RRs in %lu RRsets for zone %s\n",
		       (unsigned long) rr_count,
		       (unsigned long) rrset_count,
		       dname_to_string(domain_dname(zone->apex), NULL)));
	}

	region_destroy(dname_region);
	region_destroy(temp_region);

	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database (bad magic): %s",
			db->filename);
		namedb_close(db);
		return NULL;
	}

	fclose(db->fd);
	db->fd = NULL;

	initialize_zone_info(db);

#ifndef NDEBUG
	fprintf(stderr, "database region after loading database: ");
	region_dump_stats(db->region, stderr);
	fprintf(stderr, "\n");
#endif

	return db;
}

void
namedb_close (namedb_type *db)
{
	if (db) {
		if (db->fd) {
			fclose(db->fd);
		}
		region_destroy(db->region);
	}
}

static void
initialize_zone_info(namedb_type *db)
{
	const dname_type *apex;
	zone_type *zone;
	region_type *region = region_create(xalloc, free);

	/* Find closest enclosing auhoritative zones.  */
	HEAP_WALK(db->zones, apex, zone) {
		const dname_type *temp = apex;
		while (!dname_is_root(temp)) {
			zone_type *closest_ancestor;

			temp = dname_origin(region, temp);
			closest_ancestor = namedb_find_zone(db, temp);
			if (closest_ancestor) {
				DEBUG(DEBUG_DBACCESS, 2,
				      (stderr,
				       "%s is the closest enclosing zone of ",
				       dname_to_string(
					       domain_dname(
						       closest_ancestor->apex),
					       NULL)));
				DEBUG(DEBUG_DBACCESS, 2,
				      (stderr, "%s\n",
				       dname_to_string(apex, NULL)));
				zone->closest_ancestor = closest_ancestor;

				break;
			}
		}

		region_free_all(region);
	}

	/*
	 * Check if the closest authoritative enclosing zone is the
	 * parent zone.  The parent zone has a zone cut at the child
	 * zone's apex.
	 */
	HEAP_WALK(db->zones, apex, zone) {
		zone_type *parent = zone->closest_ancestor;
		domain_type *zone_cut;

		if (parent
		    && (zone_cut = domain_table_find(parent->domains, apex))
		    && domain_find_rrset(zone_cut, TYPE_NS))
		{
			DEBUG(DEBUG_DBACCESS, 2,
			      (stderr, "%s is the parent zone of ",
			       dname_to_string(domain_dname(parent->apex),
					       NULL)));
			DEBUG(DEBUG_DBACCESS, 2,
			      (stderr, "%s\n", dname_to_string(apex, NULL)));

			zone->parent = parent;
		} else {
			zone->parent = NULL;
		}
	}

	region_destroy(region);
}

void
namedb_set_zone_options(namedb_type *db,
			size_t zone_count,
			nsd_options_zone_type **zones)
{
	size_t i;
	const dname_type *apex;
	zone_type *zone;

	/*
	 * Link all the options for the zone to the database.
	 */
	for (i = 0; i < zone_count; ++i) {
		nsd_options_zone_type *options = zones[i];
		assert(options);

		zone = namedb_find_zone(db, options->name);
		if (!zone) {
			log_msg(LOG_WARNING,
				"zone '%s' specified in the configuration file is not present in the database",
				dname_to_string(options->name, NULL));
		} else {
			zone->options = options;
		}
	}

	/*
	 * Check that every zone in the database is configured with
	 * options.
	 */
	HEAP_WALK(db->zones, apex, zone) {
		if (!zone->options) {
			log_msg(LOG_WARNING,
				"zone '%s' in the database has no configuration information",
				dname_to_string(apex, NULL));
		}
	}
}
