/*
 * namedb_create.c -- routines to create an nsd(8) name database 
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
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
#include "util.h"

static int write_db (namedb_type *db);

struct namedb *
namedb_new (const char *filename)
{
	namedb_type *db;
	region_type *region = region_create(xalloc, free);
	
	/* Make a new structure... */
	db = (namedb_type *) region_alloc(region, sizeof(namedb_type));
	db->region = region;
	db->domains = domain_table_create(region);
	db->zones = NULL;
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


	if (!write_data(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE)) {
		fclose(db->fd);
		namedb_discard(db);
		return NULL;
	}

	return db;
}


int 
namedb_save (struct namedb *db)
{
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
	uint16_t klass;
	uint16_t type;
	uint16_t rdcount;
	uint16_t rrslen;
	int i, j;

	assert(db);
	assert(domain);
	assert(rrset);
	
	klass = htons(rrset->klass);
	type = htons(rrset->type);
	rrslen = htons(rrset->rrslen);
	
	if (!write_number(db, domain->number))
		return 0;

	if (!write_number(db, rrset->zone->number))
		return 0;
	
	if (!write_data(db->fd, &type, sizeof(type)))
		return 0;
		
	if (!write_data(db->fd, &klass, sizeof(klass)))
		return 0;
		
	if (!write_data(db->fd, &rrslen, sizeof(rrslen)))
		return 0;
		
	for (i = 0; i < rrset->rrslen; ++i) {
		rdcount = htons(rrset->rrs[i]->rdata_count);
		if (!write_data(db->fd, &rdcount, sizeof(rdcount)))
			return 0;

		ttl = htonl(rrset->rrs[i]->ttl);
		if (!write_data(db->fd, &ttl, sizeof(ttl)))
			return 0;

		for (j = 0; j < rrset->rrs[i]->rdata_count; ++j) {
			rdata_atom_type atom = rrset->rrs[i]->rdata[j];
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
	zone_type *zone;
	uint32_t terminator = 0;
	uint32_t dname_count = 1;
	uint32_t zone_count = 1;
	int errors = 0;
	
	for (zone = db->zones; zone; zone = zone->next) {
		zone->number = zone_count;
		++zone_count;
		
		if (!zone->soa_rrset) {
			fprintf(stderr, "SOA record not present in %s\n",
				dname_to_string(domain_dname(zone->apex)));
			++errors;
		}
	}

	if (errors > 0)
		return -1;

	--zone_count;
	if (!write_number(db, zone_count))
		return -1;
	for (zone = db->zones; zone; zone = zone->next) {
		if (!write_dname(db, zone->apex))
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
