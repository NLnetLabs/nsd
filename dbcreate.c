/*
 * dbcreate.c -- routines to create an nsd(8) name database 
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "namedb.h"

static int write_db (namedb_type *db);

struct namedb *
namedb_new (const char *filename)
{
	namedb_type *db;
	region_type *region = region_create(xalloc, free);
	
	/* Make a new structure... */
	db = (namedb_type *) region_alloc(region, sizeof(namedb_type));
	db->region = region;
	db->zones = heap_create(db->region, dname_compare_void);
	db->filename = region_strdup(region, filename);

	/*
	 * Unlink the old database, if it exists.  This is useful to
	 * ensure that NSD (when using mmap) doesn't see the changes
	 * until a reload is done.
	 */
	if (unlink(db->filename) == -1 && errno != ENOENT) {
		region_destroy(region);
		return NULL;
	}
	
	/* Create the database */
        if ((db->fd = fopen(db->filename, "w")) == NULL) {
		region_destroy(region);
		return NULL;
	}

	return db;
}


int 
namedb_save (struct namedb *db)
{
	if (!write_data(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE)) {
		fclose(db->fd);
		namedb_discard(db);
		return NULL;
	}

	if (write_db(db) != 0) {
		return -1;
	}		
	
	/* Write the magic... */
	if (!write_data(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE)) {
		fclose(db->fd);
		return -1;
	}

	/* Close the database */
	fclose(db->fd);

	region_destroy(db->region);
	return 0;
}


void 
namedb_discard (struct namedb *db)
{
	unlink(db->filename);
	region_destroy(db->region);
}


static int
write_dname(struct namedb *db, domain_type *domain)
{
	const dname_type *dname = domain_dname(domain);
	uint8_t length = dname_length(dname);
	
	if (!write_data(db->fd, &length, sizeof(length)))
		return 0;
	if (!write_data(db->fd, dname_name(dname), length))
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
	uint16_t rr_count;
	int i, j;
	uint16_t type;
	uint16_t klass;

	assert(db);
	assert(domain);
	assert(rrset);
	
	rr_count = htons(rrset->rr_count);
	
	if (!write_number(db, domain->number))
		return 0;

	type = htons(rrset_rrtype(rrset));
	if (!write_data(db->fd, &type, sizeof(type)))
		return 0;

	klass = htons(rrset_rrclass(rrset));
	if (!write_data(db->fd, &klass, sizeof(klass)))
		return 0;

	if (!write_data(db->fd, &rr_count, sizeof(rr_count)))
		return 0;
		
	for (i = 0; i < rrset->rr_count; ++i) {
		rr_type *rr = &rrset->rrs[i];
		uint32_t ttl;
		uint16_t rdata_count;
		
		rdata_count = htons(rr->rdata_count);
		if (!write_data(db->fd, &rdata_count, sizeof(rdata_count)))
			return 0;

		ttl = htonl(rr->ttl);
		if (!write_data(db->fd, &ttl, sizeof(ttl)))
			return 0;

		for (j = 0; j < rr->rdata_count; ++j) {
			rdata_atom_type atom = rr->rdatas[j];
			if (rdata_atom_is_domain(rr->type, j)) {
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
number_dnames_iterator(domain_type *node, void *user_data)
{
	uint32_t *current_number = (uint32_t *) user_data;

	node->number = *current_number;
	++*current_number;
}

static void
write_dname_iterator(domain_type *node, void *user_data)
{
	namedb_type *db = (namedb_type *) user_data;
	
	write_dname(db, node);
}

static void
write_domain_iterator(domain_type *node, void *user_data)
{
	namedb_type *db = (namedb_type *) user_data;
	rrset_type *rrset;

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
write_db(namedb_type *db)
{
	const uint32_t terminator = 0;
	const uint32_t zone_count = (uint32_t) db->zones->count;
	const dname_type *zone_apex;
	zone_type *zone;

	fprintf(stderr, "writing %lu zones\n", (unsigned long) zone_count);
	
	if (!write_number(db, zone_count))
		return -1;
	
	HEAP_WALK(db->zones, zone_apex, zone) {
		uint32_t dname_count;
		
		if (!zone->soa_rrset) {
			fprintf(stderr, "SOA record not present in %s\n",
				dname_to_string(domain_dname(zone->apex),
						NULL));
			return -1;
		}

		if (!write_dname(db, zone->apex))
			return -1;

		dname_count = 1;
		domain_table_iterate(zone->domains, number_dnames_iterator,
				     &dname_count);
		--dname_count;
		if (!write_number(db, dname_count))
			return -1;

		DEBUG(DEBUG_ZONEC, 1,
		      (stderr, "Storing %lu domain names for zone %s\n",
		       (unsigned long) dname_count,
		       dname_to_string(domain_dname(zone->apex), NULL)));
	
		domain_table_iterate(zone->domains, write_dname_iterator, db);
		   
		domain_table_iterate(zone->domains, write_domain_iterator, db);
		
		if (!write_data(db->fd, &terminator, sizeof(terminator)))
			return -1;
	}
	
	return 0;
}
