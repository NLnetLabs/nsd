/*
 * namedb.h -- nsd(8) internal namespace database definitions
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

#ifndef _NAMEDB_H_
#define	_NAMEDB_H_

#include <stdio.h>

#include "dname.h"
#include "heap.h"
#include "region-allocator.h"

#define	NAMEDB_MAGIC		"NSDdbV03"
#define	NAMEDB_MAGIC_SIZE	8

#if defined(NAMEDB_UPPERCASE) || defined(USE_NAMEDB_UPPERCASE)
#define	NAMEDB_NORMALIZE	toupper
#else
#define	NAMEDB_NORMALIZE	tolower
#endif


typedef struct rdata_atom rdata_atom_type;
typedef struct rrset rrset_type;

/*
 * A domain name table supporting fast insert and search operations.
 */
typedef struct domain_table domain_table_type;
typedef struct domain domain_type;
typedef struct zone zone_type;

struct domain_table
{
	region_type *region;
	heap_t      *names_to_domains;
	domain_type *root;
};

struct domain
{
	const dname_type  *dname;
	domain_type       *parent;
	domain_type       *wildcard_child;
	rrset_type        *rrsets;
	uint32_t           number; /* Unique domain name number.  */
	void             **plugin_data;
	
	/*
	 * This domain name exists (see wildcard clarification draft).
	 */
	unsigned           is_existing : 1;
};

struct zone
{
	zone_type         *next;
	domain_type       *domain;
	rrset_type        *soa_rrset;
	rrset_type        *ns_rrset;
	uint32_t           number;
};

struct rrset
{
	rrset_type       *next;
	zone_type        *zone;
	int32_t           ttl;
	uint16_t          type;
	uint16_t          class;
	uint16_t          rrslen;
	rdata_atom_type **rrs;
};

/*
 * Create a new domain_table containing only the root domain.
 */
domain_table_type *domain_table_create(region_type *region);

/*
 * Search the domain table for a match and the closest encloser.
 */
int domain_table_search(domain_table_type *table,
			const dname_type  *dname,
			domain_type      **closest_match,
			domain_type      **closest_encloser);

/*
 * The number of domains stored in the table (minimum is one for the
 * root domain).
 */
static inline uint32_t
domain_table_count(domain_table_type *table)
{
	return table->names_to_domains->count;
}

/*
 * Find the specified dname in the domain_table.  NULL is returned if
 * there is no exact match.
 */
domain_type *domain_table_find(domain_table_type *table,
			       const dname_type  *dname);

/*
 * Insert a domain name in the domain table.  If the domain name is not
 * yet present in the table it is copied and a new dname_info node is
 * created (as well as for the missing parent domain names, if any).
 * Otherwise the domain_info that is already in the domain_table is
 * returned.
 */
domain_type *domain_table_insert(domain_table_type *table,
				 const dname_type  *dname);


/*
 * Iterate over all the domain names in the domain tree.
 */
typedef void (*domain_table_iterator_type)(domain_type *node,
					   void *user_data);

void domain_table_iterate(domain_table_type *table,
			  domain_table_iterator_type iterator,
			  void *user_data);

/*
 * Add an RRset to the specified domain.  Updates the is_existing flag
 * as required.
 */
void domain_add_rrset(domain_type *domain, rrset_type *rrset);

rrset_type *domain_find_rrset(domain_type *domain, zone_type *zone, uint16_t type);
rrset_type *domain_find_any_rrset(domain_type *domain, zone_type *zone);

zone_type *domain_find_zone(domain_type *domain);

domain_type *domain_find_ns_rrsets(domain_type *domain, zone_type *zone, rrset_type **ns);

typedef struct namedb namedb_type;
struct namedb
{
	region_type       *region;
	domain_table_type *domains;
	zone_type         *zones;
	char              *filename;
	FILE              *fd;
};

struct rdata_atom
{
	void *data;
};

static inline int
rdata_atom_is_terminator(rdata_atom_type atom)
{
	return atom.data == NULL;
}

int rdata_atom_is_domain(uint16_t type, size_t index);

static inline int
rdata_atom_is_data(uint16_t type, size_t index)
{
	return !rdata_atom_is_domain(type, index);
}

static inline domain_type *
rdata_atom_domain(rdata_atom_type atom)
{
	return (domain_type *) atom.data;
}

static inline uint16_t
rdata_atom_size(rdata_atom_type atom)
{
	return * (uint16_t *) atom.data;
}

static inline void *
rdata_atom_data(rdata_atom_type atom)
{
	return (uint16_t *) atom.data + 1;
}


/* dbcreate.c */
struct namedb *namedb_new(const char *filename);
int namedb_save(struct namedb *db);
void namedb_discard(struct namedb *db);


/* dbaccess.c */
int namedb_lookup (struct namedb    *db,
		   const dname_type *dname,
		   domain_type **less_equal,
		   domain_type **closest_encloser);
struct namedb *namedb_open(const char *filename);
void namedb_close(struct namedb *db);

#endif
