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

#ifdef USE_MMAP
#include <sys/mman.h>
#endif

#include "dns.h"
#include "namedb.h"
#include "util.h"
#include "zparser2.h"

int
namedb_lookup (struct namedb    *db,
	       const dname_type *dname,
	       domain_type     **closest_match,
	       domain_type     **closest_encloser)
{
	return domain_table_search(
		db->domains, dname, closest_match, closest_encloser);
}

#ifdef USE_MMAP
static void
unmap_database(void *param)
{
	struct namedb *db = param;

	munmap(db->mpool, db->mpoolsz);
}
#endif /* USE_MMAP */

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
read_dname(namedb_type *db)
{
	uint8_t size;
	uint8_t temp[MAXDOMAINLEN];

	if (fread(&size, sizeof(uint8_t), 1, db->fd) != 1)
		return NULL;
	if (fread(temp, sizeof(uint8_t), size, db->fd) != size)
		return NULL;

	return dname_make(db->region, temp);
}

static int
read_size(namedb_type *db, size_t *result)
{
	return fread(result, sizeof(size_t), 1, db->fd) == 1;
}

static domain_type *
read_domain(namedb_type *db, size_t domain_count, domain_type **domains)
{
	size_t domain_number;

	if (!read_size(db, &domain_number))
		return NULL;

	if (domain_number == 0 || domain_number > domain_count)
		return NULL;

	return domains[domain_number - 1];
}

static int
read_rdata_atom(namedb_type *db, uint16_t type, int index, size_t domain_count, domain_type **domains, rdata_atom_type *result)
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
		if (fread(data, sizeof(uint8_t), size, db->fd) != size)
			return 0;

		result->data = region_alloc(db->region, sizeof(uint16_t) + size);
		memcpy(result->data, &size, sizeof(uint16_t));
		memcpy((uint8_t *) result->data + sizeof(uint16_t), data, size);
	}

	return 1;
}

static int
read_rrset(namedb_type *db, size_t domain_count, domain_type **domains)
{
	rrset_type *rrset;
	int i, j;
	uint16_t rdcount;
	
	rrset = region_alloc(db->region, sizeof(rrset_type));
			     
	rrset->owner = read_domain(db, domain_count, domains);
	if (!rrset->owner)
		return 0;
	
	if (fread(&rrset->type, sizeof(rrset->type), 1, db->fd) != 1)
		return 0;

	if (fread(&rrset->class, sizeof(rrset->class), 1, db->fd) != 1)
		return 0;

	if (fread(&rrset->ttl, sizeof(rrset->ttl), 1, db->fd) != 1)
		return 0;

	if (fread(&rrset->rrslen, sizeof(rrset->rrslen), 1, db->fd) != 1)
		return 0;

	rrset->type = ntohs(rrset->type);
	rrset->class = ntohs(rrset->class);
	rrset->ttl = ntohl(rrset->ttl);
	rrset->rrslen = ntohs(rrset->rrslen);

	rrset->rrs = xalloc(rrset->rrslen * sizeof(rdata_atom_type *));
/* 	region_add_cleanup(db->region, cleanup_rrset, rrset); */
	
	for (i = 0; i < rrset->rrslen; ++i) {
		if (fread(&rdcount, sizeof(rdcount), 1, db->fd) != 1)
			return 0;

		rdcount = ntohs(rdcount);

		rrset->rrs[i] = region_alloc(db->region, (rdcount + 1) * sizeof(rdata_atom_type));
		
		for (j = 0; j < rdcount; ++j) {
			if (!read_rdata_atom(db, rrset->type, j, domain_count, domains, &rrset->rrs[i][j]))
				return 0;
		}
		rrset->rrs[i][rdcount].data = NULL;
	}

	rrset->next = rrset->owner->rrsets;
	rrset->owner->rrsets = rrset;
	
	return 1;
}

struct namedb *
namedb_open (const char *filename)
{
	namedb_type *db;
	
	region_type *region = region_create(xalloc, free);
	size_t dname_count;
	domain_type **domains;	/* Indexed by domain number. */
	size_t i;
	
	db = region_alloc(region, sizeof(struct namedb));
	db->region = region;
	db->filename = region_strdup(region, filename);
	db->domains = domain_table_create(db->region);

	/* Open it... */
	if ((db->fd = fopen(db->filename, "r")) == NULL ) {
		region_destroy(region);
		return NULL;
	}

	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	if (fread(&dname_count, sizeof(dname_count), 1, db->fd) != 1) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

	DEBUG(DEBUG_DBACCESS, 1,
	      (stderr, "Retrieving %lu domain names\n", (unsigned long) dname_count));
	
	domains = xalloc(dname_count * sizeof(domain_type *));
	for (i = 0; i < dname_count; ++i) {
		const dname_type *dname = read_dname(db);
		if (!dname) {
			log_msg(LOG_ERR, "corrupted database: %s", db->filename);
			free(domains);
			fclose(db->fd);
			namedb_close(db);
			return NULL;
		}
		domains[i] = domain_table_insert(db->domains, dname);
		domains[i]->number = i;
	}

	while (read_rrset(db, dname_count, domains))
		;
	
	if (!read_magic(db)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		free(domains);
		fclose(db->fd);
		namedb_close(db);
		return NULL;
	}

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
