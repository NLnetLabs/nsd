/*
 * dbaccess.c -- access methods for nsd(8) database
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
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

int
namedb_lookup(struct namedb    *db,
	      const dname_type *dname,
	      domain_type     **closest_match,
	      domain_type     **closest_encloser)
{
	return domain_table_search(
		db->domains, dname, closest_match, closest_encloser);
}

static int
read_magic(namedb_type *db)
{
	static const char magic[NAMEDB_MAGIC_SIZE] = NAMEDB_MAGIC;
	char buf[NAMEDB_MAGIC_SIZE];

	if (fread(buf, sizeof(char), sizeof(buf), db->fd) != sizeof(buf))
		return 0;

	return memcmp(buf, magic, NAMEDB_MAGIC_SIZE) == 0;
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

static zone_type *
read_zone(namedb_type *db, uint32_t zone_count, zone_type **zones)
{
	uint32_t zone_number;

	if (!read_size(db, &zone_number))
		return NULL;

	if (zone_number == 0 || zone_number > zone_count)
		return NULL;

	return zones[zone_number - 1];
}

static int
read_rdata_atom(namedb_type *db, uint16_t type, int index, uint32_t domain_count, domain_type **domains, rdata_atom_type *result)
{
	uint8_t data[65536];

	if (rdata_atom_is_domain(type, index)) {
		result->data = read_domain(db, domain_count, domains);
		if (!result->data)
			return 0;
	} else {
		uint16_t size;

		if (fread(&size, sizeof(size), 1, db->fd) != 1)
			return 0;
		size = ntohs(size);
		if (fread(data, sizeof(uint8_t), size, db->fd) != size)
			return 0;

		result->data = region_alloc(db->region, sizeof(uint16_t) + size);
		memcpy(result->data, &size, sizeof(uint16_t));
		memcpy((uint8_t *) result->data + sizeof(uint16_t), data, size);
	}

	return 1;
}

static int
read_rrset(namedb_type *db,
	   uint32_t domain_count, domain_type **domains,
	   uint32_t zone_count, zone_type **zones)
{
	rrset_type *rrset;
	int i, j;
	uint16_t rdcount;
	uint32_t ttl;
	domain_type *owner;
	
	owner = read_domain(db, domain_count, domains);
	if (!owner)
		return 0;

	rrset = region_alloc(db->region, sizeof(rrset_type));
			     
	rrset->zone = read_zone(db, zone_count, zones);
	if (!rrset->zone)
		return 0;
	
	if (fread(&rrset->type, sizeof(rrset->type), 1, db->fd) != 1)
		return 0;

	if (fread(&rrset->class, sizeof(rrset->class), 1, db->fd) != 1)
		return 0;

	if (fread(&rrset->rrslen, sizeof(rrset->rrslen), 1, db->fd) != 1)
		return 0;

	rrset->type = ntohs(rrset->type);
	rrset->class = ntohs(rrset->class);
	rrset->rrslen = ntohs(rrset->rrslen);

	rrset->rrs = region_alloc(db->region, rrset->rrslen * sizeof(rrdata_type *));
	
	for (i = 0; i < rrset->rrslen; ++i) {
		if (fread(&rdcount, sizeof(rdcount), 1, db->fd) != 1)
			return 0;

		if (fread(&ttl, sizeof(ttl), 1, db->fd) != 1)
			return 0;

		rdcount = ntohs(rdcount);
		
		rrset->rrs[i] = region_alloc(db->region, rrdata_size(rdcount));
		rrset->rrs[i]->ttl = ntohl(ttl);
		
		for (j = 0; j < rdcount; ++j) {
			if (!read_rdata_atom(db, rrset->type, j, domain_count, domains, &rrset->rrs[i]->rdata[j]))
				return 0;
		}
		rrset->rrs[i]->rdata[rdcount].data = NULL;
	}

	domain_add_rrset(owner, rrset);

	if (rrset->type == TYPE_SOA) {
		assert(owner == rrset->zone->domain);
		rrset->zone->soa_rrset = rrset;
	} else if (owner == rrset->zone->domain && rrset->type == TYPE_NS) {
		rrset->zone->ns_rrset = rrset;
	}

	if (rrset->type == TYPE_RRSIG && owner == rrset->zone->domain) {
		for (i = 0; i < rrset->rrslen; ++i) {
			if (rrset_rrsig_type_covered(rrset, i) == TYPE_SOA) {
				rrset->zone->is_secure = 1;
				break;
			}
		}
	}
	return 1;
}

struct namedb *
namedb_open (const char *filename)
{
	namedb_type *db;
	
	region_type *region = region_create(xalloc, free);
	region_type *dname_region = region_create(xalloc, free);
	uint32_t dname_count;
	domain_type **domains;	/* Indexed by domain number.  */
	uint32_t zone_count;
	zone_type **zones;	/* Indexed by zone number.  */
	uint32_t i;
	
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(namedb_type) = %d\n", sizeof(namedb_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(zone_type) = %d\n", sizeof(zone_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(domain_type) = %d\n", sizeof(domain_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rrset_type) = %d\n", sizeof(rrset_type)));
	DEBUG(DEBUG_DBACCESS, 2,
	      (stderr, "sizeof(rbnode_t) = %d\n", sizeof(rbnode_t)));
	
	db = region_alloc(region, sizeof(struct namedb));
	db->region = region;
	db->domains = domain_table_create(db->region);
	db->zones = NULL;
	db->filename = region_strdup(region, filename);

	/* Open it... */
	if ((db->fd = fopen(db->filename, "r")) == NULL) {
		region_destroy(region);
		return NULL;
	}

	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	if (!read_size(db, &zone_count)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	DEBUG(DEBUG_DBACCESS, 1,
	      (stderr, "Retrieving %lu zones\n", (unsigned long) zone_count));
	
	zones = xalloc(zone_count * sizeof(zone_type *));
	for (i = 0; i < zone_count; ++i) {
		const dname_type *dname = read_dname(db->fd, dname_region);
		if (!dname) {
			log_msg(LOG_ERR, "corrupted database: %s", db->filename);
			free(zones);
			fclose(db->fd);
			namedb_close(db);
			return NULL;
		}
		zones[i] = region_alloc(db->region, sizeof(zone_type));
		zones[i]->next = db->zones;
		db->zones = zones[i];
		zones[i]->domain = domain_table_insert(db->domains, dname);
		zones[i]->soa_rrset = NULL;
		zones[i]->ns_rrset = NULL;
		zones[i]->number = i + 1;
		zones[i]->is_secure = 0;

		region_free_all(dname_region);
	}
	
	if (!read_size(db, &dname_count)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		free(zones);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	DEBUG(DEBUG_DBACCESS, 1,
	      (stderr, "Retrieving %lu domain names\n", (unsigned long) dname_count));
	
	domains = xalloc(dname_count * sizeof(domain_type *));
	for (i = 0; i < dname_count; ++i) {
		const dname_type *dname = read_dname(db->fd, dname_region);
		if (!dname) {
			log_msg(LOG_ERR, "corrupted database: %s", db->filename);
			free(zones);
			free(domains);
			fclose(db->fd);
			namedb_close(db);
			return NULL;
		}
		domains[i] = domain_table_insert(db->domains, dname);
		domains[i]->number = i + 1;
		region_free_all(dname_region);
	}
	
	region_destroy(dname_region);

#ifndef NDEBUG
	fprintf(stderr, "db_region (before RRsets): ");
	region_dump_stats(region, stderr);
	fprintf(stderr, "\n");
#endif
	    
	while (read_rrset(db, dname_count, domains, zone_count, zones))
		;

	free(domains);
	free(zones);
	
	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	fclose(db->fd);

#ifndef NDEBUG
	fprintf(stderr, "db_region (after RRsets): ");
	region_dump_stats(region, stderr);
	fprintf(stderr, "\n");
#endif
	
	return db;
}

void
namedb_close (struct namedb *db)
{
	/* If it is already closed... */
	if (db == NULL)
		return;
	region_destroy(db->region);
}
