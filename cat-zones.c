/*
 * cat-zones.c -- catalog zone implementation for NSD
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include "cat-zones.h"
#include "difffile.h"
#include "nsd.h"
#include "radtree.h"
#include "util.h"


struct catzonezone
{
	dname_type* member_zone;
	dname_type* member_id;
	uint to_delete : 1;
	uint to_add : 1;
	uint updated_pattern : 1;
	const char* original_pname;
	char* pname;
	struct catzonezone* next;
};
typedef struct catzonezone catzonezone_type;


void
catz_add_zone(const dname_type *member_zone_name,
	const dname_type *member_id,
	zone_type *catalog_zone, 
	const char* pname,
	nsd_type* nsd,
	udb_base* udb,
	udb_ptr* last_task)
{
	region_type* cat_region = region_create(xalloc, free);

	const char* zname = 
		region_strdup(cat_region, dname_to_string(member_zone_name, NULL));
	const char* catname = 
		region_strdup(cat_region, dname_to_string(catalog_zone->apex->dname, NULL));
	zone_type* t = namedb_find_zone(nsd->db, member_zone_name);

	// struct pattern_options* patopt;
	if (!pname) {
		pname = catname;
	}
	// patopt = pattern_options_find(nsd->options, pname);

	if (t) {
		task_new_check_coo(
			udb, 
			last_task, 
			zname, 
			catname, 
			dname_to_string(member_id, NULL)
		);
	}

	// if (!patopt || !patopt->pname) {
	// 	patopt = pattern_options_create(nsd->region);
	// 	patopt->pname = pname;
	// 	pattern_options_add_modify(nsd->options, patopt);
	// }

	DEBUG(DEBUG_CATZ, 1, 
	(LOG_INFO, "Task created for catalog %s: %s", catname, zname));
	task_new_add_catzone(udb, last_task, zname, pname, catname, dname_to_string(member_id, NULL), 0);

	region_destroy(cat_region);
}

void catalog_consumer_process(
	struct nsd *nsd, 
	struct zone *zone,
	udb_base* udb,
	udb_ptr* last_task
)
{
	struct zone_rr_iter rr_iter;
	struct rr *rr;

	uint8_t has_version_txt = 0;

	const char* catname = region_strdup(nsd->region, 
		domain_to_string(zone->apex));
	
	catzonezone_type* catzonezones = NULL;
	region_type* catzonezones_region = region_create(xalloc, free);

	for (struct radnode* n = radix_first(nsd->db->zonetree);
	n;
	n = radix_next(n)) {
		zone_type* z = (zone_type*)n->elem;
		if (z->from_catalog && strcmp(z->from_catalog, catname) == 0) {
			catzonezone_type* c = region_alloc(catzonezones_region, sizeof(catzonezone_type));
			c->member_id = z->catalog_member_id;
			c->member_zone = (dname_type*)dname_parse(catzonezones_region, z->from_catalog);
			c->to_delete = 1;
			c->to_add = 0;
			c->updated_pattern = 0;
			c->original_pname = z->opts->pattern->pname;
			c->pname = (char*)z->opts->pattern->pname;
			c->next = catzonezones;
			catzonezones = c;

			DEBUG(DEBUG_CATZ, 1, (LOG_INFO, "Deleted zone %s", 
				dname_to_string(z->apex->dname, NULL)));
			// task_new_del_zone(udb, last_task, z->apex->dname);
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
				(const uint8_t*)"\005group") == 0 &&
			rdata_atom_size(rr->rdatas[0]) > 1) {
				catzonezone_type* c = catzonezones;
				const char* pname = (const char*)(rdata_atom_data(rr->rdatas[0]) + 1);

				DEBUG(DEBUG_CATZ, 1, 
				(LOG_INFO, "Group property discovered"));

				do {
					if (c->member_id && 
					dname_label_match_count(c->member_id, dname)
					 == c->member_id->label_count && strcmp(c->original_pname, pname) != 0) {
						c->pname = (char*)pname;
						c->updated_pattern = 1;
						break;
					}
				} while ((c = c->next));
			
				// task_new_apply_pattern(udb, last_task, dname_to_string(dname, NULL), (const char*)(rdata_atom_data(rr->rdatas[0]) + 1));
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

				catzonezone_type* c = catzonezones;

				int zone_exists = 0;

				do {
					if (!c) {
						break;
					}
					if (c->member_id && 
					dname_label_match_count(c->member_id, member_id)
					 == c->member_id->label_count) {
						if (dname_compare(c->member_zone, member_zone) != 0) {
							// This member_id got a new zone
							c->to_delete = 1;
							zone_exists = 0;
						} else {
							c->to_delete = 0;
							c->pname = region_strdup(
								catzonezones_region, 
								dname_to_string(zone->apex->dname, NULL)
							);
							zone_exists = 1;
						}
						break;
					}
				} while ((c = c->next));

				if (!zone_exists) {
					char* pname = region_strdup(
						catzonezones_region,
						dname_to_string(zone->apex->dname, NULL)
					);
					c = region_alloc(catzonezones_region, sizeof(catzonezone_type));
					c->member_id = (dname_type*)member_id;
					c->member_zone = (dname_type*)member_zone;
					c->to_delete = 0;
					c->to_add = 1;
					c->updated_pattern = 0;
					c->original_pname = pname;
					c->pname = pname;
					c->next = catzonezones;
					catzonezones = c;
				}
				break;				
			} 
			break;
		}
	}

	do {
		if (!catzonezones) {
			break;
		}
		if (catzonezones->to_delete) {
			task_new_del_zone(udb, last_task, 
			catzonezones->member_zone);
		} else if (catzonezones->to_add) {
			catz_add_zone(
				catzonezones->member_zone, 
				catzonezones->member_id, 
				zone, 
				catzonezones->pname, 
				nsd, 
				udb, 
				last_task
			);
		} else if (catzonezones->updated_pattern) {
			task_new_apply_pattern(
				udb, 
				last_task, 
				dname_to_string(catzonezones->member_id, NULL), 
				catzonezones->pname
			);
		}
	} while ((catzonezones = catzonezones->next));
	
	region_destroy(catzonezones_region); 
}
