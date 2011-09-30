/*
 * nsec4.c -- nsec4 handling.
 *
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#ifdef NSEC4
#include <stdio.h>
#include <stdlib.h>

#include "nsec4.h"
#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"
#include "answer.h"

#define NSEC4_SHA1_HASH 1 /* same type code as DS hash */

/* detect is the latter rrset has the same hashalgo, iterations and salt
   as the base. Does not compare optout bit, or other rdata.
   base=NULL uses the zone soa_rr. */
static int nsec4_rrset_params_ok(rr_type* base, rrset_type* rrset);

static void
detect_nsec4_params(rr_type* nsec4_apex,
	const unsigned char** salt, int* salt_len, int* iter, int* algo)
{
	/* always uses first NSEC4 record with SOA bit set */
	assert(salt && salt_len && iter);
	assert(nsec4_apex);
	*salt_len = rdata_atom_data(nsec4_apex->rdatas[3])[0];
	*salt = (unsigned char*)(rdata_atom_data(nsec4_apex->rdatas[3])+1);
	*iter = read_uint16(rdata_atom_data(nsec4_apex->rdatas[2]));
	*algo = rdata_atom_data(nsec4_apex->rdatas[0])[0];
}

static const dname_type *
nsec4_hash_dname_param(region_type *region, zone_type *zone,
	const dname_type *dname, rr_type* param_rr)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	char b32[SHA_DIGEST_LENGTH*2+1];
	const unsigned char* nsec4_salt = NULL;
	int nsec4_saltlength = 0;
	int nsec4_iterations = 0;
	int nsec4_algorithm = 0;

	detect_nsec4_params(param_rr, &nsec4_salt,
		&nsec4_saltlength, &nsec4_iterations, &nsec4_algorithm);
	if (nsec4_algorithm) {
		iterated_hash(hash, nsec4_salt, nsec4_saltlength, dname_name(dname),
			dname->name_size, nsec4_iterations);
		b32_ntop(hash, sizeof(hash), b32, sizeof(b32));
		dname=dname_parse(region, b32);
		dname=dname_concatenate(region, dname, domain_dname(zone->apex));
	}
	return dname;
}

const dname_type *
nsec4_hash_dname(region_type *region, zone_type *zone,
	const dname_type *dname)
{
	return nsec4_hash_dname_param(region, zone,
		dname, zone->nsec4_soa_rr);
}

static int
nsec4_has_soa(rr_type* rr)
{
	if(rdata_atom_size(rr->rdatas[5]) >= 3 && /* has types in bitmap */
		rdata_atom_data(rr->rdatas[5])[0] == 0 && /* first window = 0, */
						/* [1]: windowlen must be >= 1 */
		rdata_atom_data(rr->rdatas[5])[2]&0x02)  /* SOA bit set */
		return 1;
	return 0;
}

static rr_type*
find_zone_nsec4(namedb_type* namedb, zone_type *zone)
{
	size_t i;
	domain_type* domain;
	region_type* tmpregion;
	/* Check settings in NSEC4PARAM.
	   Hash algorithm must be OK. And a NSEC4 with soa bit
	   must map to the zone apex.  */
	rrset_type* paramset = domain_find_rrset(zone->apex, zone, TYPE_NSEC4PARAM);
	if(!paramset || !paramset->rrs || !paramset->rr_count)
		return 0;
	tmpregion = region_create(xalloc, free);
	for(i=0; i < paramset->rr_count; i++)
	{
		rr_type* rr = &paramset->rrs[i];
		const dname_type* hashed_apex;
		rrset_type* nsec4_rrset;
		size_t j;

		if(rdata_atom_data(rr->rdatas[0])[0] != NSEC4_SHA1_HASH) {
			if (rdata_atom_data(rr->rdatas[0])[0] != 0) {
				log_msg(LOG_ERR, "%s NSEC4PARAM entry %d has unknown hash algo %d",
				dname_to_string(domain_dname(zone->apex), NULL), (int)i,
				rdata_atom_data(rr->rdatas[0])[0]);
				continue;
			}
		}
		if(rdata_atom_data(rr->rdatas[1])[0] != 0) {
			/* NSEC4PARAM records with flags
			   field value other than zero MUST be ignored. */
			continue;
		}
		/* check hash of apex -> NSEC4 with soa bit on */
		hashed_apex = nsec4_hash_dname_param(tmpregion,
			zone, domain_dname(zone->apex), &paramset->rrs[i]);
		domain = domain_table_find(namedb->domains, hashed_apex);
		if(!domain) {
			log_msg(LOG_ERR, "%s NSEC4PARAM entry %d has no hash(apex).",
				dname_to_string(domain_dname(zone->apex), NULL), (int)i);
			log_msg(LOG_ERR, "hash(apex)= %s",
				dname_to_string(hashed_apex, NULL));
			continue;
		}
		nsec4_rrset = domain_find_rrset(domain, zone, TYPE_NSEC4);
		if(!nsec4_rrset) {
			log_msg(LOG_ERR, "%s NSEC4PARAM entry %d: hash(apex) has no NSEC4 RRset",
				dname_to_string(domain_dname(zone->apex), NULL), (int)i);
			continue;
		}
		/* find SOA bit enabled nsec4, with the same settings */
		for(j=0; j < nsec4_rrset->rr_count; j++)
		{
			const unsigned char *salt1, *salt2;
			int saltlen1, saltlen2, iter1, iter2, algo1, algo2;
			if(!nsec4_has_soa(&nsec4_rrset->rrs[j]))
				continue;
			/* check params OK. Ignores the optout bit. */
			detect_nsec4_params(rr, &salt1, &saltlen1, &iter1, &algo1);
			detect_nsec4_params(&nsec4_rrset->rrs[j],
				&salt2, &saltlen2, &iter2, &algo2);
			if(saltlen1 == saltlen2 && iter1 == iter2 && algo1 == algo2
				&& memcmp(salt1, salt2, saltlen1) == 0) {
				/* found it */
				DEBUG(DEBUG_QUERY, 1, (LOG_INFO,
					"detected NSEC4 for zone %s saltlen=%d iter=%d",
					dname_to_string(domain_dname(
					zone->apex),0), saltlen2, iter2));
				region_destroy(tmpregion);
				return &nsec4_rrset->rrs[j];
			}
		}
		log_msg(LOG_ERR, "%s NSEC4PARAM entry %d: hash(apex) no NSEC4 with SOAbit",
			dname_to_string(domain_dname(zone->apex), NULL), (int)i);
	}
	region_destroy(tmpregion);
	return 0;
}

/* check that the rrset has an NSEC4 that uses the same parameters as the
   zone is using. Pass NSEC4 rrset, and zone must have nsec4_rrset set.
   if you pass NULL then 0 is returned. */
static int
nsec4_rrset_params_ok(rr_type* base, rrset_type* rrset)
{
	rdata_atom_type* prd;
	rdata_atom_type* rd;
	size_t i;
	if(!rrset)
		return 0; /* without rrset, no matching params either */
	assert(rrset && rrset->zone && (base || rrset->zone->nsec4_soa_rr));
	if(!base)
		base = rrset->zone->nsec4_soa_rr;
	prd = base->rdatas;
	for(i=0; i < rrset->rr_count; ++i)
	{
		rd = rrset->rrs[i].rdatas;
		assert(rrset->rrs[i].type == TYPE_NSEC4);
		if(rdata_atom_data(rd[0])[0] ==
			rdata_atom_data(prd[0])[0] && /* hash algo */
		   rdata_atom_data(rd[2])[0] ==
			rdata_atom_data(prd[2])[0] && /* iterations 0 */
		   rdata_atom_data(rd[2])[1] ==
			rdata_atom_data(prd[2])[1] && /* iterations 1 */
		   rdata_atom_data(rd[3])[0] ==
			rdata_atom_data(prd[3])[0] && /* salt length */
		   memcmp(rdata_atom_data(rd[3])+1,
			rdata_atom_data(prd[3])+1, rdata_atom_data(rd[3])[0])
			== 0 )
		{
			/* this NSEC4 matches nsec4 parameters from zone */
			return 1;
		}
	}
	return 0;
}

int
nsec4_find_cover(namedb_type* db, zone_type* zone,
	const dname_type* hashname, domain_type** result)
{
	rrset_type *rrset;
	domain_type *walk;
	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;

	assert(result);
	assert(zone->nsec4_soa_rr);

	exact = domain_table_search(
		db->domains, hashname, &closest_match, &closest_encloser);
	/* exact match of hashed domain name + it has an NSEC4? */
	if(exact &&
	   nsec4_rrset_params_ok(NULL,
	   	domain_find_rrset(closest_encloser, zone, TYPE_NSEC4))) {
		*result = closest_encloser;
		assert(*result != 0);
		return 1;
	}

	/* find covering NSEC4 record, lexicographically before the closest match */
	/* use nsec4_lookup to jumpstart the search */
	walk = closest_match->nsec4_lookup;
	rrset = 0;
	while(walk && dname_is_subdomain(domain_dname(walk), domain_dname(zone->apex)))
	{
		if(nsec4_rrset_params_ok(NULL,
			domain_find_rrset(walk, zone, TYPE_NSEC4))) {
			/* this rrset is OK NSEC4, exit while */
			rrset = domain_find_rrset(walk, zone, TYPE_NSEC4);
			break;
		}
		walk = domain_previous(walk);
	}
	if(rrset)
		*result = walk;
	else 	{
		/*
		 * There are no NSEC4s before the closest match.
		 * so the hash name is before the first NSEC4 record in the zone.
		 * use last NSEC4, which covers the wraparound in hash space
		 *
		 * Since the zone has an NSEC4 with the SOA bit set for NSEC4 to turn on,
		 * there is also a last nsec4, so find_cover always assigns *result!=0.
		 */
		*result = zone->nsec4_last;
	}
	assert(*result != 0);
	return 0;
}

static void
prehash_domain(namedb_type* db, zone_type* zone,
	domain_type* domain, region_type* region)
{
	/* find it */
	domain_type* result = 0;
	const dname_type *wcard, *wcard_child, *hashname;
	int exact;

	if(!zone->nsec4_soa_rr)
	{
		/* set to 0 (in case NSEC4 removed after an update) */
		domain->nsec4_is_exact = 0;
		domain->nsec4_cover = NULL;
		domain->nsec4_wcard_child_cover = NULL;
		return;
	}

	hashname = nsec4_hash_dname(region, zone, domain_dname(domain));
	exact = nsec4_find_cover(db, zone, hashname, &result);
	domain->nsec4_cover = result;
	if(exact)
		domain->nsec4_is_exact = 1;
	else	domain->nsec4_is_exact = 0;

	/* find cover for *.domain for wildcard denial */
	wcard = dname_parse(region, "*");
	wcard_child = dname_concatenate(region, wcard, domain_dname(domain));
	hashname = nsec4_hash_dname(region, zone, wcard_child);
	exact = nsec4_find_cover(db, zone, hashname, &result);
	domain->nsec4_wcard_child_cover = result;

	if(exact && !domain_wildcard_child(domain))
	{
		/* We found an exact match for the *.domain NSEC4 hash,
		 * but the domain wildcard child (*.domain) does not exist.
		 * Thus there is a hash collision. It will cause servfail
		 * for NXdomain queries below this domain.
		 */
		log_msg(LOG_WARNING, "prehash: collision of wildcard "
			"denial for %s. Sign zone with different salt "
			"to remove collision.",
			dname_to_string(domain_dname(domain),0));
	}
}

static void
prehash_ds(namedb_type* db, zone_type* zone,
	domain_type* domain, region_type* region)
{
	domain_type* result = 0;
	const dname_type* hashname;
	int exact;

	if(!zone->nsec4_soa_rr) {
		domain->nsec4_ds_parent_is_exact = 0;
		domain->nsec4_ds_parent_cover = NULL;
		return;
	}

	/* hash again, other zone could have different hash parameters */
	hashname = nsec4_hash_dname(region, zone, domain_dname(domain));
	exact = nsec4_find_cover(db, zone, hashname, &result);
	if(exact)
		domain->nsec4_ds_parent_is_exact = 1;
	else 	domain->nsec4_ds_parent_is_exact = 0;
	domain->nsec4_ds_parent_cover = result;
}

static void
prehash_zone(struct namedb* db, struct zone* zone)
{
	domain_type *walk;
	domain_type *last_nsec4_node;
	region_type *temp_region;
	assert(db && zone);

	/* find zone settings */
	zone->nsec4_soa_rr = find_zone_nsec4(db, zone);
	if(!zone->nsec4_soa_rr) {
		zone->nsec4_last = 0;
		return;
	}

	temp_region = region_create(xalloc, free);

	/* go through entire zone and setup nsec4_lookup speedup */
	walk = zone->apex;
	last_nsec4_node = NULL;
	/* since we walk in sorted order, we pass all NSEC4s in sorted
	   order and we can set the lookup ptrs */
	while(walk && dname_is_subdomain(
		domain_dname(walk), domain_dname(zone->apex)))
	{
		zone_type* z = domain_find_zone(walk);
		if(z && z==zone)
		{
			if(domain_find_rrset(walk, zone, TYPE_NSEC4))
				last_nsec4_node = walk;
			walk->nsec4_lookup = last_nsec4_node;
		}
		walk = domain_next(walk);
	}
	zone->nsec4_last = last_nsec4_node;

	/* go through entire zone */
	walk = zone->apex;
	while(walk && dname_is_subdomain(
		domain_dname(walk), domain_dname(zone->apex)))
	{
		zone_type* z;
		if(!walk->is_existing && domain_has_only_NSEC4(walk, zone)) {
			walk->nsec4_cover = NULL;
			walk->nsec4_wcard_child_cover = NULL;
			walk = domain_next(walk);
			continue;
		}
		z = domain_find_zone(walk);
		if(z && z==zone && !domain_is_glue(walk, zone))
		{
			prehash_domain(db, zone, walk, temp_region);
			region_free_all(temp_region);
		}
		/* prehash the DS (parent zone) */
		if(domain_find_rrset(walk, zone, TYPE_DS) ||
			(domain_find_rrset(walk, zone, TYPE_NS) &&
			 walk != zone->apex))
		{
			assert(walk != zone->apex /* DS must be above zone cut */);
			prehash_ds(db, zone, walk, temp_region);
			region_free_all(temp_region);
		}
		walk = domain_next(walk);
	}
	region_destroy(temp_region);
}

void
nsec4_prehash(struct namedb* db, int updated_only)
{
	zone_type *z;
	time_t end, start = time(NULL);
	int count = 0;
	for(z = db->zones; z; z = z->next)
	{
		if(!updated_only || z->updated) {
			prehash_zone(db, z);
			if(z->nsec4_soa_rr)
				count++;
		}
	}
	end = time(NULL);
	if(count > 0)
		VERBOSITY(1, (LOG_INFO, "nsec4-prepare took %d "
		"seconds for %d zones.", (int)(end-start), count));
}

/* add the NSEC4 rrset to the query answer at the given domain */
static void
nsec4_add_rrset(struct query *query, struct answer *answer,
	rr_section_type section, struct domain* domain)
{
	if(domain) {
		rrset_type* rrset = domain_find_rrset(domain, query->zone, TYPE_NSEC4);
		if(rrset)
			answer_add_rrset(answer, section, domain, rrset);
	}
}

/* this routine does hashing at query-time. slow. */
static void
nsec4_add_nonexist_proof(struct query *query, struct answer *answer,
        struct domain *encloser, struct namedb* db, const dname_type* qname)
{
	const dname_type *to_prove, *hashed;
	domain_type *cover=0;
	assert(encloser);
	/* if query=a.b.c.d encloser=c.d. then proof needed for b.c.d. */
	/* if query=a.b.c.d encloser=*.c.d. then proof needed for b.c.d. */
	to_prove = dname_partial_copy(query->region, qname,
		dname_label_match_count(qname, domain_dname(encloser))+1);
	/* generate proof that one label below closest encloser does not exist */
	hashed = nsec4_hash_dname(query->region, query->zone, to_prove);
	if(nsec4_find_cover(db, query->zone, hashed, &cover))
	{
		/* exact match, hash collision */
		/* the hashed name of the query corresponds to an existing name. */
		log_msg(LOG_ERR, "nsec4 hash collision for name=%s",
			dname_to_string(to_prove, NULL));
		RCODE_SET(query->packet, RCODE_SERVFAIL);
		return;
	}
	else
	{
		/* nsec4 covers next closer: proves the qname does not exist */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION, cover);
	}
}


static void
nsec4_add_closest_encloser_proof(
	struct query *query, struct answer *answer,
	struct domain *closest_encloser, struct namedb* db,
	const dname_type* qname)
{
	if(!closest_encloser)
		return;

	/* prove that next closer does not exist */
	nsec4_add_nonexist_proof(query, answer, closest_encloser, db, qname);
	/* proof that closest encloser exists */
	if(closest_encloser->nsec4_is_exact)
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			closest_encloser->nsec4_cover);
}

void
nsec4_answer_wildcard(struct query *query, struct answer *answer,
        struct domain *wildcard, struct namedb* db, const dname_type* qname)
{
	if(!wildcard)
		return;
	if(!query->zone->nsec4_soa_rr)
		return;
	/* proof that next closer does not exist */
	nsec4_add_nonexist_proof(query, answer, wildcard, db, qname);
}

static void
nsec4_add_ds_proof(struct query *query, struct answer *answer,
	struct domain *domain, int delegpt)
{
	/* assert we are above the zone cut */
	assert(domain != query->zone->apex);
	/* nsec4 matches qname */
	if(domain->nsec4_ds_parent_is_exact) {
		/* use NSEC4 record from above the zone cut. */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec4_ds_parent_cover);
	} else if (!delegpt && domain->nsec4_is_exact) {
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec4_cover);
	} else {
		/* there is no nsec4 that matches qname */
		domain_type* par = domain->parent;
		domain_type* prev_par = 0;

		while(par && !par->nsec4_is_exact)
		{
			prev_par = par;
			par = par->parent;
		}
		assert(par); /* parent zone apex must be provable, thus this ends */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			par->nsec4_cover);
		/* we took several steps to go to the provable parent, so
		   the one below it has no exact NSEC4, disprove it.
		   disprove is easy, it has a prehashed cover ptr. */
		if(prev_par) {
			assert(prev_par != domain && !prev_par->nsec4_is_exact);
			nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
				prev_par->nsec4_cover);
		}

		/* What's this? */

		/* add optout range from parent zone */
		/* note: no check of optout bit, resolver checks it */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec4_ds_parent_cover);
	}
}

void
nsec4_answer_nodata(struct query *query, struct answer *answer,
	struct domain *original)
{
	if(!query->zone->nsec4_soa_rr)
		return;
	/* nodata when asking for secure delegation */
	if(query->qtype == TYPE_DS)
	{
		if(original == query->zone->apex) {
			/* DS at zone apex, but server not authoritative for parent zone */
			/* so answer at the child zone level */

			/* add nsec4 matches qname */
			if(original->nsec4_is_exact)
				nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
					original->nsec4_cover);
			return;
		}
		/* query->zone must be the parent zone */
		nsec4_add_ds_proof(query, answer, original, 0);
	}
	/* the nodata is result from a wildcard match */
	else if (original==original->wildcard_child_closest_match
		&& label_is_wildcard(dname_name(domain_dname(original)))) {
		/* nsec4 covers next closer is already there */
		/* nsec4 matches source of synthesis */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
			original->nsec4_cover);
	}
	else {	/* add nsec4 matches qname */
		if(original->nsec4_is_exact)
			nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
				original->nsec4_cover);
	}
}

void
nsec4_answer_delegation(struct query *query, struct answer *answer)
{
	if(!query->zone->nsec4_soa_rr)
		return;
	nsec4_add_ds_proof(query, answer, query->delegation_domain, 1);
}

int
domain_has_only_NSEC4(struct domain* domain, struct zone* zone)
{
	/* check for only NSEC4/RRSIG */
	rrset_type* rrset = domain->rrsets;
	int nsec4_seen = 0, rrsig_seen = 0;
	while(rrset)
	{
		if(!zone || rrset->zone == zone)
		{
			if(rrset->rrs[0].type == TYPE_NSEC4)
				nsec4_seen = 1;
			else if(rrset->rrs[0].type == TYPE_RRSIG)
				rrsig_seen = 1;
			else
				return 0;
		}
		rrset = rrset->next;
	}
	return nsec4_seen;
}

void
nsec4_answer_authoritative(struct domain** match, struct query *query,
	struct answer *answer, struct domain* closest_encloser,
	struct namedb* db, const dname_type* qname)
{
	if(!query->zone->nsec4_soa_rr)
		return;
	assert(match);
	/* there is a match, this has 1 RRset, which is NSEC4, but qtype is not. */
	if(*match && !(*match)->is_existing &&
		domain_has_only_NSEC4(*match, query->zone))
	{
		/* act as if the NSEC4 domain did not exist, name error */
		*match = 0;

		/* all NSEC4s are directly below the apex, that is closest encloser */
		if(query->zone->apex->nsec4_is_exact)
			nsec4_add_rrset(query, answer, AUTHORITY_SECTION,
				query->zone->apex->nsec4_cover);
		/* disprove the NSEC4 record. */
		nsec4_add_rrset(query, answer, AUTHORITY_SECTION, closest_encloser->nsec4_cover);

		/* disprove a wildcard: covered by the wildcard bit set in the flags */
		return;
	} else if(*match && (*match)->is_existing &&
		domain_has_only_NSEC4(*match, query->zone))
	{
		/* empty non-terminal: nodata */
		nsec4_answer_nodata(query, answer, *match);
		return;
	}
	if (!*match) {
		/* name error, domain does not exist */
		nsec4_add_closest_encloser_proof(query, answer, closest_encloser,
			db, qname);
		/* disprove a wildcard: covered by the wildcard bit set
		 * in the flags of the NSEC4 record matching the closest
		 * encloser. We do not verify that the bit is unset, that's
		 * the job of the resolver. */
	}
}

#endif /* NSEC4 */
