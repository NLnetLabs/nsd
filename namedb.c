/*
 * namedb.c -- common namedb operations.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights
 * reserved.
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

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "dname.h"
#include "namedb.h"
#include "util.h"


static domain_type *
allocate_domain_info(domain_table_type *table,
		     const dname_type *dname,
		     domain_type *parent)
{
	domain_type *result;

	assert(table);
	assert(dname);
	assert(parent);
	
	result = region_alloc(table->region, sizeof(domain_type));
	result->node.key = dname_partial_copy(
		table->region, dname, domain_dname(parent)->label_count + 1);
	result->parent = parent;
	result->wildcard_child_closest_match = NULL;
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

	root = region_alloc(region, sizeof(domain_type));
	root->node.key = origin;
	root->parent = NULL;
	root->rrsets = NULL;
	root->number = 0;
#ifdef PLUGINS
	root->plugin_data = NULL;
#endif
	root->is_existing = 0;
	
	result = region_alloc(region, sizeof(domain_table_type));
	result->region = region;
	result->names_to_domains = heap_create(
		region, (int (*)(const void *, const void *)) dname_compare);
	result->root = root;

	root->wildcard_child_closest_match
		= (domain_type *) heap_insert(result->names_to_domains, (rbnode_t *) root);
	assert(root->wildcard_child_closest_match);
	
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

	exact = rbtree_find_less_equal(table->names_to_domains, dname, (rbnode_t **) closest_match);
	assert(*closest_match);

	*closest_encloser = *closest_match;
	
	if (!exact) {
		label_match_count = dname_label_match_count(
			domain_dname(*closest_encloser),
			dname);
		assert(label_match_count < dname->label_count);
		while (label_match_count < domain_dname(*closest_encloser)->label_count) {
			(*closest_encloser) = (*closest_encloser)->parent;
			assert(*closest_encloser);
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
		assert(domain_dname(closest_encloser)->label_count < dname->label_count);
	
		/* Insert new node(s).  */
		do {
			rbnode_t *node;
			
			result = allocate_domain_info(table,
						      dname,
						      closest_encloser);
			node = heap_insert(table->names_to_domains, (rbnode_t *) result);
			assert(node);
			result->wildcard_child_closest_match = (domain_type *) node;

			/*
			 * If the newly added domain name is larger
			 * than the parent's current
			 * wildcard_child_closest_match but smaller or
			 * equal to the wildcard domain name, update
			 * the parent's wildcard_child_closest_match
			 * field.
			 */
			if (label_compare(dname_name(domain_dname(result)), (const uint8_t *) "\001*") <= 0
			    && dname_compare(domain_dname(result), domain_dname(closest_encloser)) > 0)
			{
				closest_encloser->wildcard_child_closest_match
					= (domain_type *) node;
			}
			closest_encloser = result;
		} while (domain_dname(closest_encloser)->label_count < dname->label_count);
	}

	return result;
}

void
domain_table_iterate(domain_table_type *table,
		    domain_table_iterator_type iterator,
		    void *user_data)
{
	const dname_type *dname;
	domain_type *node;

	assert(table);

	HEAP_WALK(table->names_to_domains, dname, node) {
		iterator(node, user_data);
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
domain_find_rrset(domain_type *domain, zone_type *zone, uint16_t type)
{
	rrset_type *result = domain->rrsets;

	while (result) {
		if (result->zone == zone && result->type == type) {
			return result;
		}
		result = result->next;
	}
	return NULL;
}

rrset_type *
domain_find_any_rrset(domain_type *domain, zone_type *zone)
{
	rrset_type *result = domain->rrsets;

	while (result) {
		if (result->zone == zone) {
			return result;
		}
		result = result->next;
	}
	return NULL;
}

zone_type *
domain_find_zone(domain_type *domain)
{
	rrset_type *rrset;
	while (domain) {
		for (rrset = domain->rrsets; rrset; rrset = rrset->next) {
			if (rrset->type == TYPE_SOA) {
				return rrset->zone;
			}
		}
		domain = domain->parent;
	}
	return NULL;
}

zone_type *
domain_find_parent_zone(zone_type *zone)
{
	rrset_type *rrset;

	assert(zone);

	for (rrset = zone->domain->rrsets; rrset; rrset = rrset->next) {
		if (rrset->zone != zone && rrset->type == TYPE_NS) {
			return rrset->zone;
		}
	}
	return NULL;
}

domain_type *
domain_find_ns_rrsets(domain_type *domain, zone_type *zone, rrset_type **ns)
{
	while (domain && domain != zone->domain) {
		*ns = domain_find_rrset(domain, zone, TYPE_NS);
		if (*ns)
			return domain;
		domain = domain->parent;
	}

	*ns = NULL;
	return NULL;
}

int
domain_is_glue(domain_type *domain, zone_type *zone)
{
	rrset_type *unused;
	domain_type *ns_domain = domain_find_ns_rrsets(domain, zone, &unused);
	return (ns_domain != NULL &&
		domain_find_rrset(ns_domain, zone, TYPE_SOA) == NULL);
}

domain_type *
domain_wildcard_child(domain_type *domain)
{
	domain_type *wildcard_child;
	
	assert(domain);
	assert(domain->wildcard_child_closest_match);

	wildcard_child = domain->wildcard_child_closest_match;
	return (label_is_wildcard(dname_name(domain_dname(wildcard_child)))
		? wildcard_child
		: NULL);
}

int
zone_is_secure(zone_type *zone)
{
	return zone->is_secure;
}

uint16_t
rrset_rrsig_type_covered(rrset_type *rrset, uint16_t rr)
{
	rdata_atom_type atom;
	
	assert(rrset->type == TYPE_RRSIG);
	assert(rr < rrset->rrslen);

	atom = rrset->rrs[rr]->rdata[0];
	assert(!rdata_atom_is_terminator(atom));
	assert(rdata_atom_size(atom) == sizeof(uint16_t));
	
	return ntohs(* (uint16_t *) rdata_atom_data(atom));
}

/*
 * The type of the rdatas for each known RR type.  The possible types
 * are:
 *
 *   2 - 2 octet field.
 *   4 - 4 octet field
 *   d - a compressable domain name.
 *   X - no rdata at this position.
 */
const char *rdata_types[] =
{
	"XX",
	"XX",			/*  1, A */
	"dX",			/*  2, NS */
	"dX",			/*  3, MD */
	"dX",			/*  4, MF */
	"dX",			/*  5, CNAME */
	"dd44444",		/*  6, SOA */
	"dX",			/*  7, MB */
	"dX",			/*  8, MG */
	"dX",			/*  9, MR */
	"XX",			/* 10, NULL */
	"XX",			/* 11, WKS */
	"dX",			/* 12, PTR */
	"XX",			/* 13, HINFO */
	"dd",			/* 14, MINFO */
	"2d",			/* 15, MX */
	"XX",			/* 16, TXT */
};

#ifdef TEST

#include <stdio.h>
#include <stdlib.h>

#define BUFSZ 1000

int
main(void)
{
	static const char *dnames[] = {
		"com",
		"aaa.com",
		"hhh.com",
		"zzz.com",
		"ns1.aaa.com",
		"ns2.aaa.com",
		"foo.bar.com",
		"a.b.c.d.e.bar.com",
		"*.aaa.com"
	};
	region_type *region = region_create(xalloc, free);
	dname_table_type *table = dname_table_create(region);
	size_t key = dname_info_create_key(table);
	const dname_type *dname;
	size_t i;
	dname_info_type *closest_match;
	dname_info_type *closest_encloser;
	int exact;
	
	for (i = 0; i < sizeof(dnames) / sizeof(char *); ++i) {
		dname_info_type *temp;
		dname = dname_parse(region, dnames[i], NULL);
		temp = dname_table_insert(table, dname);
		dname_info_put_ptr(temp, key, (void *) dnames[i]);
	}
	
	exact = dname_table_search(
		table,
		dname_parse(region, "foo.bar.com", NULL),
		&closest_match, &closest_encloser);
	assert(exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[6]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[6]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.b.hhh.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[2]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[2]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "ns3.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[5]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[1]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.ns1.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[4]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[4]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "x.y.z.d.e.bar.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
/* 	assert(dname_compare(closest_match->dname, */
/* 			     dname_parse(region, "c.d.e.bar.com", NULL)) == 0); */
/* 	assert(dname_compare(closest_encloser->dname, */
/* 			     dname_parse(region, "d.e.bar.com", NULL)) == 0); */
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[8]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[1]);
	assert(closest_encloser->wildcard_child);
	assert(dname_info_get_ptr(closest_encloser->wildcard_child, key)
	       == dnames[8]);

	dname = dname_parse(region, "a.b.c.d", NULL);
	assert(dname_compare(dname_parse(region, "d", NULL),
			     dname_partial_copy(region, dname, 2)) == 0);
	
	exit(0);
}

#endif /* TEST */
