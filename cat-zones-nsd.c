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
catz_add_zone(const dname_type *member_zone_name,
	const dname_type *member_id,
	zone_type *catalog_zone, 
	const char* pname,
	void *arg,
	udb_base* udb,
	udb_ptr* last_task)
{
	nsd_type* nsd = (nsd_type*)arg;

	const char* zname = 
		region_strdup(nsd->region, dname_to_string(member_zone_name, NULL));
	const char* catname = 
		region_strdup(nsd->region, dname_to_string(catalog_zone->apex->dname, NULL));
	zone_type* t = namedb_find_zone(nsd->db, member_zone_name);

	struct pattern_options* patopt;

	if (!pname) {
		pname = catname;
	} 
	patopt = pattern_options_find(nsd->options, pname);

	if (t) {
		task_new_check_coo(
			udb, 
			last_task, 
			zname, 
			catname, 
			dname_to_string(member_id, NULL)
		);
	}

	if (!patopt || !patopt->pname) {
		patopt = pattern_options_create(nsd->region);
		patopt->pname = pname;
		pattern_options_add_modify(nsd->options, patopt);
	}

	DEBUG(DEBUG_CATZ, 1, 
	(LOG_INFO, "Task created for catalog %s: %s", catname, zname));
	task_new_add_catzone(udb, last_task, zname, pname, catname, dname_to_string(member_id, NULL), 0);
	return 1;
}

int nsd_catalog_consumer_process(
	struct nsd *nsd, 
	struct zone *zone,
	udb_base* udb,
	udb_ptr* last_task
)
{
	struct zone_rr_iter rr_iter;
	struct rr *rr;

	uint8_t has_version_txt = 0;

	// Remove all zones coming from a catalog
	// Re-add all zones coming from a catalog

	const char* catname = region_strdup(nsd->region, 
		dname_to_string(zone->apex->dname, NULL));

	for (struct radnode* n = radix_first(nsd->db->zonetree);
	n;
	n = radix_next(n)) {
		zone_type* z = (zone_type*)n->elem;
		if (z->from_catalog && strcmp(z->from_catalog, catname) == 0) {
			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Deleted zone %s", 
				dname_to_string(z->apex->dname, NULL)));
			task_new_del_zone(udb, last_task, z->apex->dname);
		}
	}
	
	zone_rr_iter_init(&rr_iter, zone);
	for ( rr = zone_rr_iter_next(&rr_iter)
	    ; rr != NULL
	    ; rr = zone_rr_iter_next(&rr_iter)) {
		const dname_type *dname = rr->owner->dname;

		if (rr->klass != CLASS_IN) {
			continue;
		}
		// Maybe also check whether an NS record is present, although it 
		// is not really breaking anything when it fails.
		switch (rr->type) {
		case TYPE_TXT:
			if (dname->label_count == zone->apex->dname->label_count + 1
			&&  label_compare( dname_name(dname)
			                 , (const uint8_t *)"\007version") == 0) {
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

			if (dname->label_count == 
			zone->apex->dname->label_count + 3 && 
			label_compare(
				dname_label(dname, dname->label_count - 3),
				(const uint8_t*)"\005zones") == 0 && 
			label_compare(
				dname_label(dname, dname->label_count - 1), 
				(const uint8_t*)"\005group") == 0) {
				
				DEBUG(DEBUG_CATZ, 1, 
				(LOG_INFO, "Group property discovered"));

				task_new_apply_pattern(udb, last_task, dname_to_string(dname, NULL), (const char*)(rdata_atom_data(rr->rdatas[0]) + 1));
			}
			break;
		case TYPE_PTR:
			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "%s", dname_to_string(
				dname, 
				zone->apex->dname
			)));
			if (dname->label_count == zone->apex->dname->label_count + 2
			&& label_compare( dname_label(dname, dname->label_count - 2)
			                , (const uint8_t*)"\005zones") == 0) {
				// For the time being we ignore all other PTR records
				const dname_type* member_zone = 
					domain_dname(rdata_atom_domain(rr->rdatas[0]));

				const dname_type* member_id = rr->owner->dname;

				catz_add_zone(
					member_zone, 
					member_id, 
					zone,
					NULL,
					nsd,
					udb,
					last_task
				);
				break;				
			} 
			break;
		}
	}

	return -1;
}
