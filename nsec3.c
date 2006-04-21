/*
 * nsec3.c -- nsec3 handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#ifdef NSEC3
#include <stdio.h>

#include "nsec3.h"
#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"

static void detect_nsec3_params(rrset_type* nsec3_apex,
	const unsigned char** salt, int* salt_len, int* iter)
{
	/* always uses first NSEC3 record with SOA bit set */
	assert(salt && salt_len && iter);
	assert(nsec3_apex);
	*salt_len = rdata_atom_data(nsec3_apex->rrs[0].rdatas[2])[0];
	*salt = (unsigned char*)(rdata_atom_data(nsec3_apex->rrs[0].rdatas[2])+1);
	*iter = (rdata_atom_data(nsec3_apex->rrs[0].rdatas[1])[0]<<16) |
		(rdata_atom_data(nsec3_apex->rrs[0].rdatas[1])[1]<<8) |
		(rdata_atom_data(nsec3_apex->rrs[0].rdatas[1])[2]);
	*iter &= 0x7fffff;
}

const dname_type *
nsec3_hash_dname(region_type *region, zone_type *zone,
	const dname_type *dname)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	char b32[SHA_DIGEST_LENGTH*2+1];
	const unsigned char* nsec3_salt = NULL;
	int nsec3_saltlength = 0;
	int nsec3_iterations = 0;

	detect_nsec3_params(zone->nsec3_rrset, &nsec3_salt, 
		&nsec3_saltlength, &nsec3_iterations);
	iterated_hash(hash, nsec3_salt, nsec3_saltlength, dname_name(dname),
		dname->name_size, nsec3_iterations);
	b32_ntop(hash, sizeof(hash), b32, sizeof(b32));
	dname=dname_parse(region, b32);
	dname=dname_concatenate(region, dname, domain_dname(zone->apex));
	return dname;
}

static int nsec3_has_soa(rr_type* rr)
{
	if(rdata_atom_size(rr->rdatas[4]) > 0 && /* has types in bitmap */
		rdata_atom_data(rr->rdatas[4])[0] == 0 && /* first window = 0, */
						/* [1]: windowlen must be >= 1 */
		rdata_atom_data(rr->rdatas[4])[2]&0x02)  /* SOA bit set */
		return 1;
	return 0;
}

static rrset_type* find_zone_nsec3(zone_type *zone)
{
	domain_type *domain = zone->apex;
	while(domain && dname_is_subdomain(
		domain_dname(domain), domain_dname(zone->apex)))
	{
		rrset_type *rrset = domain_find_rrset(domain, zone, TYPE_NSEC3);
		if(rrset && nsec3_has_soa(rrset->rrs))
		{
			const unsigned char* salt;
			int slen, iter;
			detect_nsec3_params(rrset, &salt, &slen, &iter);
			log_msg(LOG_INFO, "detected NSEC3 for zone %s saltlen=%d iter=%d",
				dname_to_string(domain_dname(zone->apex),0), slen, iter);
			return rrset;
		}
		domain = domain_next(domain);
	}
	return 0;
}

static domain_type* nsec3_find_last(zone_type* zone)
{
	/* this is the longest possible walk to get to the end, but is precomputed */
	/* could also tree-find the <max_val>.domain name */
	domain_type* walk = zone->apex;
	domain_type* result = 0;
	while(walk && 
		dname_is_subdomain(domain_dname(walk), domain_dname(zone->apex)))
	{
		/* remember last domain with an NSEC3 rrset */
		if(domain_find_rrset(walk, zone, TYPE_NSEC3)) {
			result = walk;
		}
		walk = domain_next(walk);
	}
	return result;
}

int nsec3_find_cover(namedb_type* db, zone_type* zone, 
	const dname_type* hashname, domain_type** result)
{
	rrset_type *rrset;
	domain_type *walk;
	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;

	assert(result);
	assert(zone->nsec3_rrset);

	exact = domain_table_search(
		db->domains, hashname, &closest_match, &closest_encloser);
	/* exact match of hashed domain name + it has an NSEC3? */
	if(exact && (rrset = domain_find_rrset(closest_encloser, zone, TYPE_NSEC3))) {
		*result = closest_encloser;
		assert(*result != 0);
		return 1;
	}

	/* find covering NSEC3 record, lexicographically before the closest match */
	walk = closest_match;
	rrset = 0;
	while(walk && dname_is_subdomain(domain_dname(walk), domain_dname(zone->apex))
		&& !(rrset = domain_find_rrset(walk, zone, TYPE_NSEC3)))
	{
		walk = domain_previous(walk);
	}
	if(rrset)
		*result = walk;
	else 	{
		/* 
		 * There are no NSEC3s before the closest match.
		 * so the hash name is before the first NSEC3 record in the zone.
		 * use last NSEC3, which covers the wraparound in hash space 
		 *
		 * Since the zone has an NSEC3 with the SOA bit set for NSEC3 to turn on,
		 * there is also a last nsec3, so find_cover always assigns *result!=0.
		 */
		*result = zone->nsec3_last;
	}
	assert(*result != 0);
	return 0;
}

static void prehash_domain(namedb_type* db, zone_type* zone, 
	domain_type* domain, region_type* region)
{
	/* find it */
	domain_type* result = 0;
	const dname_type *wcard, *wcard_child, *hashname;
	int exact;

	if(!zone->nsec3_rrset)
	{
		/* set to 0 (in case NSEC3 removed after an update) */
		domain->nsec3_exact = 0;
		domain->nsec3_cover = 0;
		domain->nsec3_wcard_child_cover = 0;
		return;
	}

	hashname = nsec3_hash_dname(region, zone, domain_dname(domain));
	exact = nsec3_find_cover(db, zone, hashname, &result);
	domain->nsec3_cover = result;
	if(exact)
		domain->nsec3_exact = result;
	else	domain->nsec3_exact = 0;

	/* find cover for *.domain for wildcard denial */
	wcard = dname_parse(region, "*");
	wcard_child = dname_concatenate(region, wcard, domain_dname(domain));
	hashname = nsec3_hash_dname(region, zone, wcard_child);
	exact = nsec3_find_cover(db, zone, hashname, &result);
	if(exact)
		domain->nsec3_wcard_child_cover = result;
	else 	domain->nsec3_wcard_child_cover = 0;
}

static void prehash_ds(namedb_type* db, zone_type* zone, 
	domain_type* domain, region_type* region)
{
	domain_type* result = 0;
	const dname_type* hashname;
	int exact;

	if(!zone->nsec3_rrset) {
		domain->nsec3_ds_parent_exact = NULL;
		return;
	}

	/* hash again, other zone could have different hash parameters */
	hashname = nsec3_hash_dname(region, zone, domain_dname(domain));
	exact = nsec3_find_cover(db, zone, hashname, &result);
	if(exact)
		domain->nsec3_ds_parent_exact = result;
	else 	domain->nsec3_ds_parent_exact = 0;
}

static void prehash_zone(struct namedb* db, struct zone* zone)
{
	domain_type *walk;
	region_type *temp_region = region_create(xalloc, free);
	assert(db && zone);

	/* find zone settings */
	zone->nsec3_rrset = find_zone_nsec3(zone);
	zone->nsec3_last = nsec3_find_last(zone); 
	assert((zone->nsec3_rrset&&zone->nsec3_last) ||
		(!zone->nsec3_rrset&&!zone->nsec3_last));
	if(zone->nsec3_rrset) {
		/* check that hashed, the apex name equals the found nsec3 domain */
		const dname_type* checkname = nsec3_hash_dname(temp_region, 
			zone, domain_dname(zone->apex));
		assert(zone->nsec3_rrset->rr_count > 0);
		if(dname_compare(checkname, domain_dname(
			zone->nsec3_rrset->rrs[0].owner)) != 0) {
			log_msg(LOG_ERR, "NSEC3 record with SOA bit on %s is bad."
				" name!=hash(zone). disabling NSEC3 for zone",
				dname_to_string(domain_dname(
				zone->nsec3_rrset->rrs[0].owner),0));
			zone->nsec3_rrset = 0;
			zone->nsec3_last = 0;
		}
	}

	/* go through entire zone */
	walk = zone->apex;
	while(walk && dname_is_subdomain(
		domain_dname(walk), domain_dname(zone->apex)))
	{
		zone_type* z = namedb_find_zone(db, walk);
		if(z && z==zone)
		{
			prehash_domain(db, zone, walk, temp_region);
			region_free_all(temp_region);
		}
		/* prehash the DS (parent zone) */
		/* only if there is a DS (so z==parent side of zone cut) */
		if(domain_find_rrset(walk, zone, TYPE_DS))
		{
			assert(walk != zone->apex /* DS must be above zone cut */);
			prehash_ds(db, zone, walk, temp_region);	
			region_free_all(temp_region);
		}
		walk = domain_next(walk);
	}
	region_destroy(temp_region);
}

void prehash(struct namedb* db, struct zone* zone)
{
	if(zone) {
		prehash_zone(db, zone);
		return;
	} else {
		zone_type *z;
		for(z = db->zones; z; z = z->next)
		{
			prehash_zone(db, z);
		}
	}
}

#endif /* NSEC3 */
