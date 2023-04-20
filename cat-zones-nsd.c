/*
 * cat-zones-nsd.c -- catalog zone implementation for NSD
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include "cat-zones-nsd.h"
#include "difffile.h"
#include "nsd.h"
#include "radtree.h"

int
catz_dname_equal(const catz_dname *a, const catz_dname *b)
{
	return dname_compare(&a->dname, &b->dname);
}

catz_member_zone *
catz_member_by_dname(const catz_dname *member_zone_name,
		void *arg)
{
	nsd_type* nsd = (nsd_type*)arg;
	zone_type* zone = namedb_find_zone(nsd->db, &member_zone_name->dname);
	catz_member_zone* catz_zone = malloc(sizeof(catz_member_zone));
	catz_zone->member_id->dname = *zone->apex->dname;
	return catz_zone;
}

catz_catalog_zone *
catz_catalog_from_member(const catz_member_zone *member_zone,
		void *arg)
{
	nsd_type* nsd = (nsd_type*)arg;

	catz_catalog_zone* catz_zone = malloc(sizeof(catz_catalog_zone));
	const dname_type* dname = &member_zone->member_id->dname;
	catz_zone->zone = *namedb_find_zone(nsd->db, dname);
	return catz_zone;
}

int
catz_add_zone(const catz_dname *member_zone_name,
	const catz_dname *member_id,
	catz_catalog_zone *catalog_zone, void *arg)
{
	nsd_type* nsd = (nsd_type*)arg;
	const char* zname = dname_to_string(&member_zone_name->dname, NULL);
	const char* pname = PATTERN_IMPLICIT_MARKER;
	zone_type* t;
	DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Zone name: %s", zname));
	t = find_or_create_zone(
		nsd->db, 
		&member_zone_name->dname, 
		nsd->options, 
		zname, 
		pname
	);

	if (t) {
		t->is_from_catalog = 1;
		return CATZ_SUCCESS;
	} else {
		// This should never happen
		return -1;
	}
}

int
catz_remove_zone(const catz_dname *member_zone_name,
	void *arg)
{
	nsd_type* nsd = (nsd_type*) arg;
	zone_type* zone = namedb_find_zone(nsd->db, &member_zone_name->dname);

	if (zone->is_from_catalog) {
		namedb_zone_delete(nsd->db, zone);
		return CATZ_SUCCESS;
	} else {
		return -1;
	}
}

int nsd_catalog_consumer_process(struct nsd *nsd, struct zone *zone)
{
	struct zone_rr_iter rr_iter;
	struct rr *rr;

	uint8_t has_version_txt = 0;

	// Current MVP implementation: remove all zones coming from a catalog
	// Readd all zones coming from a catalog
	// Very inefficient

	for (struct radnode* n = radix_first(nsd->db->zonetree); n; n = radix_next(n)) {
		zone_type* z = (zone_type*)n->elem;
		if (z->is_from_catalog) {
			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Deleted zone %s", dname_to_string(z->apex->dname, NULL)));
			namedb_zone_delete(nsd->db, z);
		}
	}
	
	DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Catalog zone processing"));
	zone_rr_iter_init(&rr_iter, zone);
	for ( rr = zone_rr_iter_next(&rr_iter)
	    ; rr != NULL
	    ; rr = zone_rr_iter_next(&rr_iter)) {
		const dname_type *dname = rr->owner->dname;

		if (rr->klass != CLASS_IN) {
			continue;
		}
		// Maybe also check whether an NS record is present, although it is 
		// not really breaking anything when it fails.
		switch (rr->type) {
		case TYPE_TXT:
			if (dname->label_count == zone->apex->dname->label_count + 1
			&&  label_compare( dname_name(dname)
			                 , (const uint8_t *)"\x07version") == 0) {
				DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Catz version TXT"));
				if (has_version_txt) {
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, "Catz has more than one version TXT defined"));
				} else if (
					rr->rdata_count != 1 || 
					rdata_atom_size(rr->rdatas[0]) != 2 ||
					rdata_atom_data(rr->rdatas[0])[0] != 1 ||
					rdata_atom_data(rr->rdatas[0])[1] != '2'
				) {
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, "Catz has a version different than 2"));
				} else {
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, "Catz version is 2"));
					has_version_txt = 2;
				}
				break;
			}
			break;
		case TYPE_PTR:
			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "%s", dname_to_string(
				dname, 
				zone->apex->dname
			)));
			if (dname->label_count == zone->apex->dname->label_count + 2
			&& label_compare( dname_label(dname, dname->label_count - 2)
			                , (const uint8_t*)"\x05zones") == 0) {
				// For the time being we ignore all other PTR records
				const catz_dname* member_zone = dname2catz_dname(domain_dname(rdata_atom_domain(rr->rdatas[0])));

				const catz_dname* member_id = dname2catz_dname(rr->owner->dname);

				catz_catalog_zone* cat_zone = zone2catz_catalog_zone(zone);

				DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "PTR parsed"));

				catz_add_zone(member_zone, member_id, cat_zone, nsd);
				break;
			}
			break;
		}
		DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Process RR"));
	}

	return -1;
}
