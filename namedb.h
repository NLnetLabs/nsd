/*
 * namedb.h -- nsd(8) internal namespace database definitions
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _NAMEDB_H_
#define	_NAMEDB_H_

#include <stdio.h>

#include "dname.h"
#include "dns.h"
#include "heap.h"

#define	NAMEDB_MAGIC		"NSDdbV07"
#define	NAMEDB_MAGIC_SIZE	8

typedef union rdata_atom rdata_atom_type;
typedef struct rrset rrset_type;
typedef struct rr rr_type;

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
	rbnode_t     node;
	domain_type *parent;
	domain_type *wildcard_child_closest_match;
	rrset_type  *rrsets;
#ifdef PLUGINS
	void       **plugin_data;
#endif
	uint32_t     number; /* Unique domain name number.  */
	
	/*
	 * This domain name exists (see wildcard clarification draft).
	 */
	unsigned     is_existing : 1;
};

struct zone
{
	rbnode_t           node;
	domain_table_type *domains;
	domain_type       *apex;
	rrset_type        *soa_rrset;
	rrset_type        *ns_rrset;

	/*
	 * The closest ancestor zone stored in the database.
	 */
	zone_type         *closest_ancestor;
	
	/*
	 * The direct parent zone if stored in the database.
	 */
	zone_type         *parent;

	unsigned           is_secure : 1;
};

/* a RR in DNS */
struct rr {
	domain_type     *owner;
	rdata_atom_type *rdatas;
	uint32_t         ttl;
	uint16_t         type;
	uint16_t         klass;
	uint16_t         rdata_count;
};

/*
 * An RRset consists of at least one RR.
 */
struct rrset
{
	rrset_type *next;
	rr_type    *rrs;
	uint16_t    rr_count;
};

/*
 * The field used is based on the wireformat the atom is stored in.
 * The allowed wireformats are defined by the rdata_wireformat_type
 * enumeration.
 */
union rdata_atom
{
	/* RDATA_WF_COMPRESSED_DNAME, RDATA_WF_UNCOMPRESSED_DNAME.  */
	domain_type *domain;

	/* Default.  */
	uint16_t    *data;
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
static inline size_t
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
 * Insert a domain name in the domain table.  If the domain name is
 * not yet present in the table it is copied and a new dname_info node
 * is created (as well as for the missing parent domain names, if
 * any).  Otherwise the domain_type that is already in the
 * domain_table is returned.
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

/*
 * Find a specific RRset for DOMAIN with the indicated TYPE.
 */
rrset_type *domain_find_rrset(domain_type *domain, uint16_t type);

/*
 * Find the RRset of TYPE in DOMAIN or one of its ancestor domains.
 */
domain_type *domain_find_enclosing_rrset(domain_type *domain,
					 uint16_t type,
					 rrset_type **rrset);

/*
 * True if DOMAIN is at or below a zone cut.
 */
int domain_is_glue(domain_type *domain);

/*
 * Returns the wildcard child of DOMAIN or NULL if there is no such
 * domain.
 */
domain_type *domain_wildcard_child(domain_type *domain);

/*
 * Returns true if ZONE is secure (there is an RRSIG RR for the zone's
 * SOA RRset).
 */
int zone_is_secure(zone_type *zone);

static inline const dname_type *
domain_dname(domain_type *domain)
{
	return (const dname_type *) domain->node.key;
}

static inline domain_type *
domain_previous(domain_type *domain)
{
	rbnode_t *prev = heap_previous((rbnode_t *) domain);
	return prev == RBTREE_NULL ? NULL : (domain_type *) prev;
}

static inline domain_type *
domain_next(domain_type *domain)
{
	rbnode_t *prev = heap_next((rbnode_t *) domain);
	return prev == RBTREE_NULL ? NULL : (domain_type *) prev;
}

/*
 * The type covered by the signature in the specified RRSIG RR.
 */
uint16_t rr_rrsig_type_covered(rr_type *rr);

typedef struct namedb namedb_type;
struct namedb
{
	region_type       *region;
	heap_t            *zones;
	char              *filename;
	FILE              *fd;
};

static inline int rdata_atom_is_domain(uint16_t type, size_t index);

static inline domain_type *
rdata_atom_domain(rdata_atom_type atom)
{
	return atom.domain;
}

static inline uint16_t
rdata_atom_size(rdata_atom_type atom)
{
	return *atom.data;
}

static inline uint8_t *
rdata_atom_data(rdata_atom_type atom)
{
	return (uint8_t *) (atom.data + 1);
}


/*
 * Find the zone for the specified domain name in DB.
 */
zone_type *namedb_find_zone(namedb_type *db, const dname_type *apex);

/*
 * Find the zone authoritative for DNAME (not taking into account zone
 * cuts).
 */
zone_type *namedb_find_authoritative_zone(namedb_type *db,
					  const dname_type *dname);

/*
 * Find or insert a zone in DB.
 */
zone_type *namedb_insert_zone(namedb_type *db, const dname_type *apex);

int zone_lookup (zone_type        *zone,
		 const dname_type *dname,
		 domain_type     **closest_match,
		 domain_type     **closest_encloser);
/* dbcreate.c */
namedb_type *namedb_new(const char *filename);
int namedb_save(namedb_type *db);
void namedb_discard(namedb_type *db);


/* dbaccess.c */
namedb_type *namedb_open(const char *filename);
void namedb_close(namedb_type *db);

static inline int
rdata_atom_is_domain(uint16_t type, size_t index)
{
	const rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(type);
	return (index < descriptor->maximum
		&& descriptor->rdata_kinds[index] == RDATA_ZF_DNAME);
}

static inline rdata_kind_type
rdata_atom_kind(uint16_t type, size_t index)
{
	const rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(type);
	assert(index < descriptor->maximum);
	return (rdata_kind_type) descriptor->rdata_kinds[index];
}

static inline uint16_t
rrset_rrtype(rrset_type *rrset)
{
	assert(rrset);
	assert(rrset->rr_count > 0);
	return rrset->rrs[0].type;
}

static inline uint16_t
rrset_rrclass(rrset_type *rrset)
{
	assert(rrset);
	assert(rrset->rr_count > 0);
	return rrset->rrs[0].klass;
}


#endif
