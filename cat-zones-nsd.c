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
	const char* pname = zname;
	zone_type* t = find_or_create_zone(
		nsd->db, 
		&member_zone_name->dname, 
		nsd->options, 
		zname, 
		pname
	);

	if (t) {
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

	delete_zone_rrs(nsd->db, zone);
	return CATZ_SUCCESS;
}

void nsd_catalog_consumer_process(struct nsd *nsd, struct zone *zone)
{
	struct zone_rr_iter rr_iter;
	struct rr *rr;

	uint8_t has_version_txt = 0;
	
	dname_type* previous_ptrs = (dname_type*)malloc(0 * sizeof(dname_type));
	uint32_t previous_ptrs_no = 0;
	

	DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Catalog zone processing"));
	zone_rr_iter_init(&rr_iter, zone);
	for ( rr = zone_rr_iter_next(&rr_iter)
	    ; rr != NULL
	    ; rr = zone_rr_iter_next(&rr_iter)) {
			if (
				rr->type == TYPE_TXT && 
				rr->klass == CLASS_IN && 
				strcasecmp(
					dname_to_string(rr->owner->dname, zone->apex->dname),
					 "version"
				) == 0
			) {
				DEBUG(DEBUG_CATZ, 1, 
				(LOG_INFO, "Catz version TXT"));
				if (has_version_txt) {
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, "Catz has more than one version TXT defined"));
				} else if (
					rr->rdata_count != 1 || 
					strcmp((char*)rr->rdatas[0].data, "\"2\"") != 0
				) {
					// TODO: Fix check for 2
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, "Catz has a version different than 2"));
					DEBUG(DEBUG_CATZ, 1, (LOG_INFO, rr->rdatas[1].data));
				} else {
					has_version_txt = 2;
				}
			}
			// Maybe also check whether an NS record is present, although it is 
			// not really breaking anything when it fails.
			if (rr->type == TYPE_PTR && rr->klass == CLASS_IN) {
				char* label = dname_to_string(
					rr->owner->dname, 
					zone->apex->dname
				);
				DEBUG(DEBUG_CATZ, 1, 
				(LOG_INFO, label));

				dname_type* ptrs[previous_ptrs_no + 1];
				for (uint32_t i = 0; i < previous_ptrs_no; i++) {
					if (dname_compare(
						rr->owner->dname, 
						&previous_ptrs[i]
					) == 0) {
						DEBUG(DEBUG_CATZ, 1, 
						(LOG_INFO, "Catz more than one PTR record for this label"));
					}
					ptrs[i] = &previous_ptrs[i];
				}
				ptrs[previous_ptrs_no] = rr->owner->dname;
				free(previous_ptrs);
				previous_ptrs = 
					(dname_type*)malloc(previous_ptrs_no + 1 * sizeof(dname_type));

				previous_ptrs = &ptrs;
				previous_ptrs_no++;
			}
		DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Process RR"));
	}
}
