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
	return (catz_member_zone*)zone;
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
	catz_catalog_zone *catalog_zone, 
	const char* pname,
	void *arg,
	udb_base* udb,
	udb_ptr* last_task)
{
	nsd_type* nsd = (nsd_type*)arg;

	const char* zname = 
		region_strdup(nsd->region, dname_to_string(&member_zone_name->dname, NULL));
	const char* catname = 
		region_strdup(nsd->region, dname_to_string(catalog_zone->zone.apex->dname, NULL));
	zone_type* t = namedb_find_zone(nsd->db, member_zone_name);

	struct zone_options* zopt;
	struct pattern_options* patopt;

	if (!pname) {
		pname = catname;
	} 
	patopt = pattern_options_find(nsd->options, pname);

	if (t) {
		if (!t->from_catalog) {
			return -1;
		}
		zone_type* cz = namedb_find_zone(
			nsd->db, 
			dname_parse(
				nsd->region, 
				t->from_catalog)
			);
		struct zone_rr_iter rr_iter;
		struct rr *rr;

		int coo_correct = 0;

		DEBUG(DEBUG_CATZ, 1, 
			(LOG_INFO, 
			"Found existing zone belong to a catalog zone %s", 
			dname_to_string(cz->apex->dname, NULL)));

		zone_rr_iter_init(&rr_iter, cz);
		for ( rr = zone_rr_iter_next(&rr_iter)
		; rr != NULL
		; rr = zone_rr_iter_next(&rr_iter)) {
			if (rr->klass != CLASS_IN) {
				continue;
			}
			if (rr->type != TYPE_PTR) {
				continue;
			}
			dname_type* dname = rr->owner->dname;

			DEBUG(DEBUG_CATZ, 1, 
			(LOG_INFO, 
			"Checking %s", 
			dname_to_string(dname, NULL)));

			if (dname->label_count == 
			cz->apex->dname->label_count + 3 && 
			label_compare(
				dname_label(dname, dname->label_count - 3),
				(const uint8_t*)"\005zones") == 0 && 
			label_compare(
				dname_label(dname, dname->label_count - 1), 
				(const uint8_t*)"\003coo") == 0) {
				// `dname` is now the RR for the coo property

				const dname_type* coo_property = 
					domain_dname(rdata_atom_domain(rr->rdatas[0]));

				if (dname_label_match_count(t->catalog_member_id, dname)
				 == t->catalog_member_id->label_count && 
				dname_compare(coo_property, catalog_zone->zone.apex->dname) == 0) {
					DEBUG(DEBUG_CATZ, 1, 
					(LOG_INFO, 
					"COO correct, transferring from %s to %s", 
					t->from_catalog, catname));
					coo_correct = 1;
					break;
				}
			} 
		}

		if (coo_correct) {
			t->from_catalog = catname;
			t->catalog_member_id = member_id;
			return CATZ_SUCCESS;
		} else {
			return -1;
		}
	}

	if (!patopt || !patopt->pname) {
		patopt = pattern_options_create(nsd->region);
		patopt->pname = pname;
		pattern_options_add_modify(nsd->options, patopt);
	}

	// pattern_options_add_modify(nsd->options, patopt);
	zopt = zone_list_zone_insert(nsd->options, zname, pname, 0, 0);
	DEBUG(DEBUG_CATZ, 1, 
	(LOG_INFO, "Task created for catalog %s: %s", catname, zname));
	// t = namedb_zone_create(nsd->db, dname_copy(nsd->region, &member_zone_name->dname), zopt);
	// namedb_read_zonefile(nsd, t, udb, last_task);
	// task_new_add_pattern(udb, last_task, patopt);
	task_new_add_catzone(udb, last_task, zname, pname, catname, dname_to_string(member_id, NULL), 0);
	t = namedb_find_zone(nsd->db, dname_parse(nsd->region, zname));

	if (t) {
		t->from_catalog = (char*)catname;
		t->catalog_member_id = (dname_type*)member_id;
		t->is_updated = 1;
		// namedb_read_zonefile(nsd, t, udb, last_task);
		// Generate dummy SOA, check xfrd
		task_new_soainfo(udb, last_task, t, soainfo_ok);
		DEBUG(DEBUG_CATZ, 1, 
		(LOG_INFO, "Zone added for catalog %s: %s", catname, zname));
		return CATZ_SUCCESS;
	} else {
		DEBUG(DEBUG_CATZ, 1, 
		(LOG_INFO, "Zone not found for catalog %s: %s", catname, zname));
		return -1;
	}
}

int
catz_remove_zone(const catz_dname *member_zone_name,
	void *arg,
	udb_base* udb,
	udb_ptr* last_task)
{
	nsd_type* nsd = (nsd_type*) arg;
	// zone_type* zone = namedb_find_zone(nsd->db, &member_zone_name->dname);
	// struct zone_options* zopt = zone->opts;

	task_new_del_zone(udb, last_task, member_zone_name);
	return CATZ_SUCCESS;
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

	// Current MVP implementation: remove all zones coming from a catalog
	// Re-add all zones coming from a catalog
	// Very inefficient

	const char* catname = strdup(dname_to_string(zone->apex->dname, NULL));

	for (struct radnode* n = radix_first(nsd->db->zonetree);
	n;
	n = radix_next(n)) {
		zone_type* z = (zone_type*)n->elem;
		struct zone_options* zopt = z->opts;
		DEBUG(DEBUG_CATZ, 1, 
		(LOG_INFO, "From catalog %s", z->from_catalog));
		if (z->from_catalog && strcmp(z->from_catalog, catname) == 0) {
			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Deleted zone %s", 
				dname_to_string(z->apex->dname, NULL)));
			// delete_zone_rrs(nsd->db, z);
			// namedb_zone_delete(nsd->db, z);
			// zone_options_delete(nsd->options, zopt);
			task_new_del_zone(udb, last_task, z->apex);
		}
	}
	
	// DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Catalog zone processing"));
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

				task_new_apply_pattern(udb, last_task, dname_to_string(dname, NULL), rdata_atom_data(rr->rdatas[0]) + 1);
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
				const catz_dname* member_zone = 
					dname2catz_dname(domain_dname(rdata_atom_domain(rr->rdatas[0])));

				const catz_dname* member_id = dname2catz_dname(rr->owner->dname);

				catz_catalog_zone* cat_zone = zone2catz_catalog_zone(zone);

				DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "PTR parsed"));

				int res = catz_add_zone(
					member_zone, 
					member_id, 
					cat_zone,
					NULL,
					nsd,
					udb,
					last_task
				);
				DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Task added"));
				break;				
			} 
			break;
		}
		// DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "TODO: Process RR"));
	}

	free((void*)catname);

	return -1;
}
