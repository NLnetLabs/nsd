/*
 * namedb.c -- common namedb operations.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "namedb.h"


int
zone_lookup(zone_type        *zone,
	    const dname_type *dname,
	    domain_type     **closest_match,
	    domain_type     **closest_encloser)
{
	return domain_table_search(
		zone->domains, dname, closest_match, closest_encloser);
}

zone_type *
namedb_insert_zone(namedb_type *db, const dname_type *apex)
{
	zone_type *zone = namedb_find_zone(db, apex);
	if (!zone) {
		zone = (zone_type *) region_alloc(db->region,
						  sizeof(zone_type));
		memset(&zone->node, 0, sizeof(zone->node));
		zone->domains = domain_table_create(db->region);
		zone->apex = domain_table_insert(zone->domains, apex);
		zone->soa_rrset = NULL;
		zone->ns_rrset = NULL;
		zone->closest_ancestor = NULL;
		zone->parent = NULL;
		zone->is_secure = 0;
		zone->node.key = domain_dname(zone->apex);
		heap_insert(db->zones, (rbnode_t *) zone);
	}
	return zone;
}

static domain_type *
allocate_domain_info(domain_table_type *table,
		     const dname_type *dname,
		     domain_type *parent)
{
	domain_type *result;

	assert(table);
	assert(dname);
	assert(parent);

	result = (domain_type *) region_alloc(table->region,
					      sizeof(domain_type));
	result->node.key = dname_partial_copy(
		table->region,
		dname,
		dname_label_count(domain_dname(parent)) + 1);
	result->parent = parent;
	result->wildcard_child_closest_match = result;
	result->rrsets = NULL;
	result->number = 0;
#ifdef PLUGINS
	result->plugin_data = NULL;
#endif
	result->is_existing = 0;

	return result;
}

domain_table_type *
domain_table_create(region_type *region)
{
	const dname_type *origin;
	domain_table_type *result;
	domain_type *root;

	assert(region);

	origin = dname_make(region, (uint8_t *) "");

	root = (domain_type *) region_alloc(region, sizeof(domain_type));
	root->node.key = origin;
	root->parent = NULL;
	root->wildcard_child_closest_match = root;
	root->rrsets = NULL;
	root->number = 0;
#ifdef PLUGINS
	root->plugin_data = NULL;
#endif
	root->is_existing = 0;

	result = (domain_table_type *) region_alloc(region,
						    sizeof(domain_table_type));
	result->region = region;
	result->names_to_domains = heap_create(region, dname_compare_void);
	heap_insert(result->names_to_domains, (rbnode_t *) root);

	result->root = root;

	return result;
}

int
domain_table_search(domain_table_type *table,
		    const dname_type   *dname,
		    domain_type       **closest_match,
		    domain_type       **closest_encloser)
{
	int exact;
	uint8_t label_match_count;

	assert(table);
	assert(dname);
	assert(closest_match);
	assert(closest_encloser);

	exact = rbtree_find_less_equal(table->names_to_domains,
				       dname,
				       (rbnode_t **) closest_match);
	assert(*closest_match);

	*closest_encloser = *closest_match;

	if (!exact) {
		size_t label_count
			= dname_label_count(domain_dname(*closest_encloser));

		label_match_count = dname_label_match_count(
			domain_dname(*closest_encloser),
			dname);
		while (label_match_count < label_count) {
			--label_count;
			(*closest_encloser) = (*closest_encloser)->parent;
			assert(*closest_encloser);
			assert(label_count == dname_label_count(
				       domain_dname(*closest_encloser)));
		}
	}

	return exact;
}

domain_type *
domain_table_find(domain_table_type *table,
		  const dname_type *dname)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;

	exact = domain_table_search(
		table, dname, &closest_match, &closest_encloser);
	return exact ? closest_encloser : NULL;
}


domain_type *
domain_table_insert(domain_table_type *table,
		    const dname_type  *dname)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	domain_type *result;
	int exact;

	assert(table);
	assert(dname);

	exact = domain_table_search(
		table, dname, &closest_match, &closest_encloser);
	if (exact) {
		result = closest_encloser;
	} else {
		assert(dname_label_count(domain_dname(closest_encloser))
		       < dname_label_count(dname));

		/* Insert new node(s).  */
		do {
			result = allocate_domain_info(table,
						      dname,
						      closest_encloser);
			heap_insert(table->names_to_domains, (rbnode_t *) result);

			/*
			 * If the newly added domain name is larger
			 * than the parent's current
			 * wildcard_child_closest_match but smaller or
			 * equal to the wildcard domain name, update
			 * the parent's wildcard_child_closest_match
			 * field.
			 */
			if (label_compare(dname_name(domain_dname(result)),
					  (const uint8_t *) "\001*") <= 0
			    && dname_compare(domain_dname(result),
					     domain_dname(closest_encloser->wildcard_child_closest_match)) > 0)
			{
				closest_encloser->wildcard_child_closest_match
					= result;
			}
			closest_encloser = result;
		} while (dname_label_count(domain_dname(closest_encloser))
			 < dname_label_count(dname));
	}

	return result;
}

void
domain_table_iterate(domain_table_type *table,
		    domain_table_iterator_type iterator,
		    void *user_data)
{
	const void *dname;
	void *node;

	assert(table);

	HEAP_WALK(table->names_to_domains, dname, node) {
		iterator((domain_type *) node, user_data);
	}
}

void
domain_add_rrset(domain_type *domain, rrset_type *rrset)
{
	rrset->next = domain->rrsets;
	domain->rrsets = rrset;

	while (domain && !domain->is_existing) {
		domain->is_existing = 1;
		domain = domain->parent;
	}
}


rrset_type *
domain_find_rrset(domain_type *domain, uint16_t type)
{
	rrset_type *result = domain->rrsets;

	while (result) {
		if (rrset_rrtype(result) == type) {
			return result;
		}
		result = result->next;
	}
	return NULL;
}

domain_type *
domain_find_enclosing_rrset(domain_type *domain,
			    uint16_t type,
			    rrset_type **rrset)
{
	while (domain) {
		*rrset = domain_find_rrset(domain, type);
		if (*rrset)
			return domain;
		domain = domain->parent;
	}

	*rrset = NULL;
	return NULL;
}

int
domain_is_glue(domain_type *domain)
{
	rrset_type *unused;
	domain_type *ns_domain
		= domain_find_enclosing_rrset(domain, TYPE_NS, &unused);
	return ns_domain && !domain_find_rrset(ns_domain, TYPE_SOA);
}

domain_type *
domain_wildcard_child(domain_type *domain)
{
	domain_type *wildcard_child;

	assert(domain);
	assert(domain->wildcard_child_closest_match);

	wildcard_child = domain->wildcard_child_closest_match;
	if (wildcard_child != domain
	    && label_is_wildcard(dname_name(domain_dname(wildcard_child))))
	{
		return wildcard_child;
	} else {
		return NULL;
	}
}

int
zone_is_secure(zone_type *zone)
{
	return zone->is_secure;
}

uint16_t
rr_rrsig_type_covered(rr_type *rr)
{
	assert(rr->type == TYPE_RRSIG);
	assert(rr->rdata_count > 0);
	assert(rdata_atom_size(rr->rdatas[0]) == sizeof(uint16_t));

	return ntohs(* (uint16_t *) rdata_atom_data(rr->rdatas[0]));
}

zone_type *
namedb_find_zone(namedb_type *db, const dname_type *apex)
{
	return (zone_type *) heap_search(db->zones, apex);
}

zone_type *
namedb_find_authoritative_zone(namedb_type *db, const dname_type *dname)
{
	rbnode_t *node;

	rbtree_find_less_equal(db->zones, dname, &node);
	while (node && !dname_is_subdomain(dname, node->key)) {
		node = (rbnode_t * ) ((zone_type *) node)->closest_ancestor;
	}
	if (node) {
		return (zone_type *) node;
	} else {
		return NULL;
	}
}
