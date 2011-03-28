/*
 * dbcreate.c -- routines to create an nsd(8) name database
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "namedb.h"
#include "udb.h"
#include "udbradtree.h"
#include "udbzone.h"

/** add an rdata (uncompressed) to the destination */
static size_t
add_rdata(rr_type* rr, unsigned i, uint8_t* buf, size_t buflen)
{
	switch(rdata_atom_wireformat_type(rr->type, i)) {
		case RDATA_WF_COMPRESSED_DNAME:
		case RDATA_WF_UNCOMPRESSED_DNAME:
		{
			const dname_type* dname = domain_dname(
				rdata_atom_domain(rr->rdatas[i]));
			if(dname->name_size > buflen)
				return 0;
			memmove(buf, dname_name(dname), dname->name_size);
			return dname->name_size;
		}
		default:
			break;
	}
	memmove(buf, rdata_atom_data(rr->rdatas[i]),
		rdata_atom_size(rr->rdatas[i]));
	return rdata_atom_size(rr->rdatas[i]);
}

/** write rr */
static int
write_rr(udb_base* udb, udb_ptr* z, rr_type* rr)
{
	/* marshal the rdata (uncompressed) into a buffer */
	uint8_t rdata[MAX_RDLENGTH];
	size_t rdatalen = 0;
	unsigned i;
	for(i=0; i<rr->rdata_count; i++) {
		rdatalen += add_rdata(rr, i, rdata+rdatalen,
			sizeof(rdata)-rdatalen);
	}
	return udb_zone_add_rr(udb, z, (uint8_t*)dname_name(domain_dname(
		rr->owner)), domain_dname(rr->owner)->name_size, rr->type,
		rr->klass, rr->ttl, rdata, rdatalen);
}

/** write rrset */
static int
write_rrset(udb_base* udb, udb_ptr* z, rrset_type* rrset)
{
	unsigned i;
	for(i=0; i<rrset->rr_count; i++) {
		if(!write_rr(udb, z, &rrset->rrs[i]))
			return 0;
	}
	return 1;
}

/** write a zone */
static int
write_zone(udb_base* udb, udb_ptr* z, zone_type* zone)
{
	/* write all domains in the zone */
	domain_type* walk;
	rrset_type* rrset;
	for(walk=zone->apex; walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex)); walk=domain_next(walk)) {
		/* write all rrsets (in the zone) for this domain */
		for(rrset=walk->rrsets; rrset; rrset=rrset->next) {
			if(rrset->zone == zone) {
				if(!write_rrset(udb, z, rrset))
					return 0;
			}
		}
	}
	return 1;
}

/** create and write a zone */
int
write_zone_to_udb(udb_base* udb, zone_type* zone, time_t mtime)
{
	udb_ptr z;
	/* find or create zone */
	if(udb_zone_search(udb, &z, (uint8_t*)dname_name(domain_dname(
		zone->apex)), domain_dname(zone->apex)->name_size)) {
		/* wipe existing contents */
		udb_zone_clear(udb, &z);
	} else {
		if(!udb_zone_create(udb, &z, (uint8_t*)dname_name(domain_dname(
			zone->apex)), domain_dname(zone->apex)->name_size))
			return 0;
	}
	/* set mtime */
	ZONE(&z)->mtime = (uint64_t)mtime;
	/* write zone */
	if(!write_zone(udb, &z, zone))
		return 0;
	udb_ptr_unlink(&z, udb);
	return 1;
}

/** write all the zones */
static int
write_all_zones(udb_base* udb, struct namedb* db)
{
	struct radnode* n;
	for(n=radix_first(db->zonetree); n; n=radix_next(n)) {
		if(!write_zone_to_udb(udb, (zone_type*)n->elem, time(NULL)))
			return 0;
	}
	return 1;
}

int
namedb_save (struct namedb *db)
{
	udb_base *udb = db->udb;
	/* create new udb for the storage */
	if(!udb_dns_init_file(udb)) {
		region_destroy(db->region);
		return -1;
	}
	/* we need to write all the RRs to the file and create zones */
	if(!write_all_zones(udb, db)) {
		region_destroy(db->region);
		return -1;
	}
	udb_base_free(udb);

	region_destroy(db->region);
	return 0;
}

