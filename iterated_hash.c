/*
 * iterated_hash.c -- nsec3 hash calculation.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * With thanks to Ben Laurie.
 */
#include <config.h>
#ifdef NSEC3
#include <openssl/sha.h>
#include <stdio.h>

#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"

int 
iterated_hash(unsigned char out[SHA_DIGEST_LENGTH],
	const unsigned char *salt, int saltlength,
	const unsigned char *in, int inlength, int iterations)
{
	SHA_CTX ctx;
	int n;
	for(n=0 ; n <= iterations ; ++n)
	{
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, in, inlength);
		SHA1_Update(&ctx, salt, saltlength);
		SHA1_Final(out, &ctx);
		in=out;
		inlength=SHA_DIGEST_LENGTH;
	}
	return SHA_DIGEST_LENGTH;
}

static int nsec3_has_soa(rr_type* rr)
{
	if(rdata_atom_size(rr->rdatas[4]) > 0 && /* has types in bitmap */
		rdata_atom_data(rr->rdatas[4])[0] == 0 && /* first window = 0 */
		rdata_atom_data(rr->rdatas[4])[2]&0x02)  /* SOA bit set */
		return 1;
	return 0;
}

static void detect_nsec3_params(zone_type *zone,
	const unsigned char** salt, int* salt_len, int* iter)
{
	/* always uses first NSEC3 record with SOA set */
	assert(salt && salt_len && iter);
	assert(zone->nsec3_rrset);
	*salt_len = rdata_atom_data(zone->nsec3_rrset->rrs[0].rdatas[2])[0];
	*salt = (unsigned char*)(rdata_atom_data(zone->nsec3_rrset->rrs[0].rdatas[2])+1);
	*iter = (rdata_atom_data(zone->nsec3_rrset->rrs[0].rdatas[1])[0]<<16) |
		(rdata_atom_data(zone->nsec3_rrset->rrs[0].rdatas[1])[1]<<8) |
		(rdata_atom_data(zone->nsec3_rrset->rrs[0].rdatas[1])[2]);
	*iter &= 0x7fffff;
}

static void find_zone_nsec3(zone_type *zone)
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
			zone->nsec3_rrset = rrset;
			detect_nsec3_params(zone, &salt, &slen, &iter);
			log_msg(LOG_INFO, "detected NSEC3 for zone %s saltlen=%d iter=%d",
				dname_to_string(domain_dname(zone->apex),0), slen, iter);
			return;
		}
		domain = domain_next(domain);
	}
	return;
}

const dname_type *
nsec3_hash_dname(region_type *region, zone_type *zone,
	const dname_type *dname)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	char b32[HASHED_NAME_LENGTH+1];
	const unsigned char* nsec3_salt = NULL;
	int nsec3_saltlength = 0;
	int nsec3_iterations = 0;
	detect_nsec3_params(zone, &nsec3_salt, &nsec3_saltlength, &nsec3_iterations);
	iterated_hash(hash, nsec3_salt, nsec3_saltlength, dname_name(dname),
		dname->name_size, nsec3_iterations);
	b32_ntop(hash, sizeof(hash), b32, sizeof(b32));
	dname=dname_parse(region, b32);
	dname=dname_concatenate(region, dname, domain_dname(zone->apex));
	return dname;
}

int nsec3_find_cover(struct region *region, namedb_type* db, 
	zone_type* zone, const dname_type* dname, domain_type** result)
{
	assert(result);
	const dname_type* hashname = nsec3_hash_dname(region, zone, dname);
	rrset_type *rrset;
	domain_type *walk;

	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;
	exact = domain_table_search(
		db->domains, hashname, &closest_match, &closest_encloser);
	if(exact) {
		*result = closest_encloser;
		return 1;
	}

	/* find cover */
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
		*result = 0; 
		/* find last NSEC3, which covers the wraparound in hash space */
	}
	return 0;
}

static void prehash_domain(namedb_type* db, zone_type* zone, 
	domain_type* domain, region_type* region)
{
	/* find it */
	domain_type* result = 0;
	const dname_type *wcard, *wcard_child;
	int exact = nsec3_find_cover(region, db, zone, 
		domain_dname(domain), &result);
	domain->nsec3_cover = result;
	if(exact)
		domain->nsec3_exact = result;
	else	domain->nsec3_exact = 0;

	wcard = dname_parse(region, "*");
	wcard_child = dname_concatenate(region, wcard, domain_dname(domain));
	printf("For %s", dname_to_string(domain_dname(domain),0));
	printf(" wcard %s", dname_to_string(wcard,0));
	printf(" wcardch %s\n", dname_to_string(wcard_child,0));
	exact = nsec3_find_cover(region, db, zone, wcard_child, &result);
	if(exact)
		domain->nsec3_wcard_child_cover = result;
	else 	domain->nsec3_wcard_child_cover = 0;
}

static void prehash_ds(namedb_type* db, zone_type* zone, 
	domain_type* domain, region_type* region)
{
	/* hash again, other zone could have different hash parameters */
	domain_type* result = 0;
	int exact = nsec3_find_cover(region, db, zone, 
		domain_dname(domain), &result);
	if(exact)
		domain->nsec3_ds_parent_exact = result;
	else 	domain->nsec3_ds_parent_exact = 0;
}

void prehash(struct namedb* db, struct zone* zone)
{
	domain_type *domain, *top;
	region_type *region = region_create(xalloc, free);

	/* detect NSEC3 settings for zone(s) */
	if(zone) {
		find_zone_nsec3(zone);
	} else {
		zone_type *z;
		for(z = db->zones; z; z = z->next)
			find_zone_nsec3(z);
	}

	if(zone) top = zone->apex;
	else top = db->domains->root;
	domain = top;
	/* go through entire tree below the top */
	while(domain && dname_is_subdomain(
		domain_dname(domain), domain_dname(top)))
	{
		zone_type* z = namedb_find_zone(db, domain);
		if(z && z->nsec3_rrset &&
			((zone && z==zone) || (!zone)))
		{
			prehash_domain(db, z, domain, region);
		}
		/* prehash the DS (parent zone) */
		/* only if there is a DS */
		domain->nsec3_ds_parent_exact = NULL;
		if(z && (z = domain_find_parent_zone(z)) &&
			z->nsec3_rrset &&
			domain_find_rrset(domain, z, TYPE_DS)) 
		{
			prehash_ds(db, z, domain, region);	
		}
		region_free_all(region);
		domain = domain_next(domain);
	}
	region_destroy(region);
}

#endif /* NSEC3 */
