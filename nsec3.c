/*
 * nsec3.c -- nsec3 handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#ifdef NSEC3
#include <stdio.h>
#include <stdlib.h>

#include "nsec3.h"
#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"
#include "answer.h"
#include "udbzone.h"

static void
detect_nsec3_params(rr_type* nsec3_apex,
	const unsigned char** salt, int* salt_len, int* iter)
{
	assert(salt && salt_len && iter);
	assert(nsec3_apex);
	*salt_len = rdata_atom_data(nsec3_apex->rdatas[3])[0];
	*salt = (unsigned char*)(rdata_atom_data(nsec3_apex->rdatas[3])+1);
	*iter = read_uint16(rdata_atom_data(nsec3_apex->rdatas[2]));
}

const dname_type *
nsec3_b32_create(region_type* region, zone_type* zone, unsigned char* hash)
{
	const dname_type* dname;
	char b32[SHA_DIGEST_LENGTH*2+1];
	b32_ntop(hash, SHA_DIGEST_LENGTH, b32, sizeof(b32));
	dname=dname_parse(region, b32);
	dname=dname_concatenate(region, dname, domain_dname(zone->apex));
	return dname;
}

void
nsec3_hash_and_store(zone_type *zone, const dname_type *dname, uint8_t* store)
{
	const unsigned char* nsec3_salt = NULL;
	int nsec3_saltlength = 0;
	int nsec3_iterations = 0;

	detect_nsec3_params(zone->nsec3_param, &nsec3_salt,
		&nsec3_saltlength, &nsec3_iterations);
	iterated_hash((unsigned char*)store, nsec3_salt, nsec3_saltlength,
		dname_name(dname), dname->name_size, nsec3_iterations);
}

#define STORE_HASH(x,y) memmove(domain->x,y,NSEC3_HASH_LEN); domain->have_##x =1;

/** find hash or create it and store it */
static void
nsec3_lookup_hash_and_wc(namedb_type* db, zone_type* zone, udb_ptr* z,
	const dname_type* dname, domain_type* domain)
{
	uint8_t h[NSEC3_HASH_LEN], h_wc[NSEC3_HASH_LEN];
	const dname_type* wcard;
	if(domain->have_nsec3_hash && domain->have_nsec3_wc_hash) {
		return;
	}
	if(udb_zone_lookup_hash_wc(db->udb, z, dname_name(dname),
		dname->name_size, h, h_wc)) {
		STORE_HASH(nsec3_hash, h);
		STORE_HASH(nsec3_wc_hash, h_wc);
		return;
	}
	/* lookup failed; disk failure or so */
	nsec3_hash_and_store(zone, dname, domain->nsec3_hash);
	domain->have_nsec3_hash = 1;
	if(1) {
		region_type* region = region_create(xalloc, free);
		wcard = dname_parse(region, "*");
		wcard = dname_concatenate(region, wcard, dname);
		nsec3_hash_and_store(zone, wcard, domain->nsec3_wc_hash);
		domain->have_nsec3_wc_hash = 1;
		region_destroy(region);
	}
}

static void
nsec3_lookup_hash_ds(namedb_type* db, zone_type* zone, udb_ptr* z,
	const dname_type* dname, domain_type* domain)
{
	uint8_t h[NSEC3_HASH_LEN];
	if(domain->have_nsec3_ds_parent_hash) {
		return;
	}
	if(udb_zone_lookup_hash(db->udb, z, dname_name(dname),
		dname->name_size, h)) {
		STORE_HASH(nsec3_ds_parent_hash, h);
		return;
	}
	/* lookup failed; disk failure or so */
	nsec3_hash_and_store(zone, dname, domain->nsec3_ds_parent_hash);
	domain->have_nsec3_ds_parent_hash = 1;
}

static int
nsec3_has_soa(rr_type* rr)
{
	if(rdata_atom_size(rr->rdatas[5]) >= 3 && /* has types in bitmap */
	  rdata_atom_data(rr->rdatas[5])[0] == 0 && /* first window = 0, */
	  /* [1]: windowlen must be >= 1 */
	  rdata_atom_data(rr->rdatas[5])[2]&0x02)  /* SOA bit set */
	  return 1;
	return 0;
}

static rr_type*
check_apex_soa(namedb_type* namedb, zone_type *zone, udb_ptr* z)
{
	uint8_t h[NSEC3_HASH_LEN];
	domain_type* domain;
	const dname_type* hashed_apex, *dname = domain_dname(zone->apex);
	unsigned j;
	rrset_type* nsec3_rrset;
	region_type* tmpregion;
	if(!udb_zone_lookup_hash(namedb->udb, z, dname_name(dname),
		dname->name_size, h)) {
		return NULL;
	}
	tmpregion = region_create(xalloc, free);
	hashed_apex = nsec3_b32_create(tmpregion, zone, h);
	domain = domain_table_find(namedb->domains, hashed_apex);
	if(!domain) {
		log_msg(LOG_ERR, "%s NSEC3PARAM entry has no hash(apex).",
			dname_to_string(domain_dname(zone->apex), NULL));
		log_msg(LOG_ERR, "hash(apex)= %s",
			dname_to_string(hashed_apex, NULL));
		region_destroy(tmpregion);
		return NULL;
	}
	nsec3_rrset = domain_find_rrset(domain, zone, TYPE_NSEC3);
	if(!nsec3_rrset) {
		log_msg(LOG_ERR, "%s NSEC3PARAM entry: hash(apex) has no NSEC3 RRset.",
			dname_to_string(domain_dname(zone->apex), NULL));
		log_msg(LOG_ERR, "hash(apex)= %s",
			dname_to_string(hashed_apex, NULL));
		region_destroy(tmpregion);
		return NULL;
	}
	for(j=0; j<nsec3_rrset->rr_count; j++) {
		if(nsec3_has_soa(&nsec3_rrset->rrs[j])) {
			region_destroy(tmpregion);
			return &nsec3_rrset->rrs[j];
		}
	}
	log_msg(LOG_ERR, "%s NSEC3PARAM entry: hash(apex) NSEC3 has no SOA flag.",
		dname_to_string(domain_dname(zone->apex), NULL));
	log_msg(LOG_ERR, "hash(apex)= %s",
		dname_to_string(hashed_apex, NULL));
	region_destroy(tmpregion);
	return NULL;
}

static struct rr* udb_zone_find_nsec3param(udb_base* udb, udb_ptr* uz,
        struct zone* z)
{
	udb_ptr urr;
	unsigned i;
	rrset_type* rrset = domain_find_rrset(z->apex, z, TYPE_NSEC3PARAM);
	if(!rrset) /* no NSEC3PARAM in mem */
		return NULL;
	udb_ptr_new(&urr, udb, &ZONE(uz)->nsec3param);
	if(!urr.data || RR(&urr)->len < 5) {
		/* no NSEC3PARAM in udb */
		udb_ptr_unlink(&urr, udb);
		return NULL;
	}
	/* find matching NSEC3PARAM RR in memory */
	for(i=0; i<rrset->rr_count; i++) {
		/* if this RR matches the udb RR then we are done */
		rdata_atom_type* rd = rrset->rrs[i].rdatas;
		if(RR(&urr)->wire[0] == rdata_atom_data(rd[0])[0] && /*alg*/
		   RR(&urr)->wire[1] == rdata_atom_data(rd[1])[0] && /*flg*/
		   RR(&urr)->wire[2] == rdata_atom_data(rd[2])[0] && /*iter*/
		   RR(&urr)->wire[3] == rdata_atom_data(rd[2])[1] &&
		   RR(&urr)->wire[4] == rdata_atom_data(rd[3])[0] && /*slen*/
		   RR(&urr)->len >= 5 + RR(&urr)->wire[4] &&
		   memcmp(RR(&urr)->wire+5, rdata_atom_data(rd[3])+1,
			rdata_atom_data(rd[3])[0]) == 0)
			return &rrset->rrs[i];
	}
	udb_ptr_unlink(&urr, udb);
	return NULL;
}

void nsec3_find_zone_param(struct namedb* db, struct zone* zone, udb_ptr* z)
{
	/* get nsec3param RR from udb */
	zone->nsec3_param = udb_zone_find_nsec3param(db->udb, z, zone);
	/* check if zone apex has SOA flag */
	if(zone->nsec3_param && !check_apex_soa(db, zone, z)) {
		zone->nsec3_param = NULL;
	}
}

/* check params ok for one RR */
static int
nsec3_rdata_params_ok(rdata_atom_type* prd, rdata_atom_type* rd)
{
	return (rdata_atom_data(rd[0])[0] ==
		rdata_atom_data(prd[0])[0] && /* hash algo */
	   rdata_atom_data(rd[2])[0] ==
		rdata_atom_data(prd[2])[0] && /* iterations 0 */
	   rdata_atom_data(rd[2])[1] ==
		rdata_atom_data(prd[2])[1] && /* iterations 1 */
	   rdata_atom_data(rd[3])[0] ==
		rdata_atom_data(prd[3])[0] && /* salt length */
	   memcmp(rdata_atom_data(rd[3])+1,
		rdata_atom_data(prd[3])+1, rdata_atom_data(rd[3])[0])
		== 0 );
}

int nsec3_rr_uses_params(rr_type* rr, zone_type* zone)
{
	if(!rr || rr->rdata_count < 4)
		return 0;
	return nsec3_rdata_params_ok(zone->nsec3_param->rdatas, rr->rdatas);
}

int nsec3_in_chain_count(domain_type* domain, zone_type* zone)
{
	rrset_type* rrset = domain_find_rrset(domain, zone, TYPE_NSEC3);
	unsigned i;
	int count = 0;
	if(!rrset || !zone->nsec3_param)
		return 0; /* no NSEC3s, none in the chain */
	for(i=0; i<rrset->rr_count; i++) {
		if(nsec3_rr_uses_params(&rrset->rrs[i], zone))
			count++;
	}
	return count;
}

struct domain* nsec3_chain_find_prev(struct zone* zone, struct domain* domain)
{
	if(domain->nsec3_node) {
		/* see if there is a prev */
		struct radnode* r = radix_prev(domain->nsec3_node);
		if(r && r->parent) {
			/* found a previous, which is not the root-node in
			 * the prehash tree (and thus points to the tree) */
			return (domain_type*)r->elem;
		}
	}
	if(zone->nsec3_last)
		return zone->nsec3_last;
	return NULL;
}

void nsec3_clear_precompile(struct namedb* db, zone_type* zone)
{
	domain_type *walk;
	/* clear prehash items (there must not be items for other zones) */
	prehash_clear(db->domains);
	/* clear trees */
	if(zone->nsec3tree)
		radix_tree_clear(zone->nsec3tree);
	if(zone->hashtree)
		radix_tree_clear(zone->hashtree);
	if(zone->wchashtree)
		radix_tree_clear(zone->wchashtree);
	if(zone->dshashtree)
		radix_tree_clear(zone->dshashtree);
	/* wipe hashes */
	/* wipe precompile */
	walk = zone->apex;
	while(walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex))) {
		if(domain_find_zone(walk) == zone) {
			if(domain_find_zone(walk) == zone)
				walk->nsec3_node = NULL;
			if(nsec3_condition_hash(walk, zone)) {
				walk->nsec3_cover = NULL;
				walk->nsec3_wcard_child_cover = NULL;
				walk->nsec3_is_exact = 0;
				walk->have_nsec3_hash = 0;
				walk->have_nsec3_wc_hash = 0;
				walk->hash_node = NULL;
				walk->wchash_node = NULL;
			}
			if(nsec3_condition_dshash(walk, zone)) {
				walk->nsec3_ds_parent_cover = NULL;
				walk->nsec3_ds_parent_is_exact = 0;
				walk->have_nsec3_ds_parent_hash = 0;
				walk->dshash_node = NULL;
			}
		}
		walk = domain_next(walk);
	}
}

/* condition when a domain is precompiled */
int
nsec3_condition_hash(domain_type* d, zone_type* z)
{
	return d->is_existing && !domain_has_only_NSEC3(d, z) &&
		z == domain_find_zone(d) && !domain_is_glue(d, z);
}

/* condition when a domain is ds precompiled */
int
nsec3_condition_dshash(domain_type* d, zone_type* z)
{
	return d->is_existing && !domain_has_only_NSEC3(d, z) &&
		(domain_find_rrset(d, z, TYPE_DS) ||
		domain_find_rrset(d, z, TYPE_NS)) && d != z->apex;
}

int
nsec3_find_cover(zone_type* zone, uint8_t* hash, size_t hashlen,
	domain_type** result)
{
	struct radnode* r = NULL;
	int exact;

	assert(result);
	assert(zone->nsec3_param && zone->nsec3tree);

	exact = radix_find_less_equal(zone->nsec3tree, hash, hashlen, &r);
	/* the r->parent check is to make sure we did not pick up the
	 * rootnode in the nsec3tree which points to the tree itself */
	if(r && r->parent) {
		*result = (domain_type*)r->elem;
	} else {
		*result = zone->nsec3_last;
	}
	return exact;
}

void nsec3_precompile_domain(struct namedb* db, struct domain* domain,
	struct zone* zone, struct udb_ptr* z)
{
	domain_type* result = 0;
	int exact;

	/* hash it */
	nsec3_lookup_hash_and_wc(db, zone, z, domain_dname(domain), domain);

	/* add into tree */
	zone_add_domain_in_hash_tree(&zone->hashtree, domain->nsec3_hash,
		sizeof(domain->nsec3_hash), domain, &domain->hash_node);
	zone_add_domain_in_hash_tree(&zone->wchashtree, domain->nsec3_wc_hash,
		sizeof(domain->nsec3_wc_hash), domain, &domain->wchash_node);

	/* lookup in tree cover ptr (or exact) */
	exact = nsec3_find_cover(zone, domain->nsec3_hash,
		sizeof(domain->nsec3_hash), &result);
	domain->nsec3_cover = result;
	if(exact)
		domain->nsec3_is_exact = 1;
	else	domain->nsec3_is_exact = 0;

	/* find cover for *.domain for wildcard denial */
	exact = nsec3_find_cover(zone, domain->nsec3_wc_hash,
		sizeof(domain->nsec3_wc_hash), &result);
	domain->nsec3_wcard_child_cover = result;
}

void nsec3_precompile_domain_ds(struct namedb* db, struct domain* domain,
	struct zone* zone, struct udb_ptr* z)
{
	domain_type* result = 0;
	int exact;

	/* hash it : it could have different hash parameters then the
	   other hash for this domain name */
	nsec3_lookup_hash_ds(db, zone, z, domain_dname(domain), domain);
	/* lookup in tree cover ptr (or exact) */
	exact = nsec3_find_cover(zone, domain->nsec3_ds_parent_hash,
		sizeof(domain->nsec3_ds_parent_hash), &result);
	if(exact)
		domain->nsec3_ds_parent_is_exact = 1;
	else 	domain->nsec3_ds_parent_is_exact = 0;
	domain->nsec3_ds_parent_cover = result;
	/* add into tree */
	zone_add_domain_in_hash_tree(&zone->dshashtree,
		domain->nsec3_ds_parent_hash,
		sizeof(domain->nsec3_ds_parent_hash),
		domain, &domain->dshash_node);
}

static void
parse_nsec3_name(const dname_type* dname, uint8_t* hash, size_t hashlen)
{
	/* first label must be the match, */
	size_t lablen = hashlen * 8 / 5;
	const uint8_t* wire = dname_name(dname);
	assert(lablen == 32); /* labels of length 32 for SHA1 */
	if(wire[0] != lablen) {
		/* not NSEC3 */
		memset(hash, 0, hashlen);
		return;
	}
	(void)b32_pton((char*)wire+1, hash, hashlen);
}

void nsec3_precompile_nsec3rr(struct domain* domain, struct zone* zone)
{
	uint8_t zehash[NSEC3_HASH_LEN];
	/* add into nsec3tree */
	parse_nsec3_name(domain_dname(domain), zehash, sizeof(zehash));
	zone_add_domain_in_hash_tree(&zone->nsec3tree, zehash, sizeof(zehash),
		domain, &domain->nsec3_node);
	/* fixup the last in the zone */
	if(radix_last(zone->nsec3tree)->elem == domain) {
		zone->nsec3_last = domain;
	}
}

void nsec3_precompile_newparam(namedb_type* db, zone_type* zone,
	udb_ptr* udbz)
{
	domain_type* walk;
	/* add nsec3s of chain to nsec3tree */
	for(walk=zone->apex; walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex)); walk = domain_next(walk)) {
		if(nsec3_in_chain_count(walk, zone) != 0) {
			nsec3_precompile_nsec3rr(walk, zone);
		}
	}
	/* hash and precompile zone */
	for(walk=zone->apex; walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex)); walk = domain_next(walk)) {
		if(nsec3_condition_hash(walk, zone))
			nsec3_precompile_domain(db, walk, zone, udbz);
		if(nsec3_condition_dshash(walk, zone))
			nsec3_precompile_domain_ds(db, walk, zone, udbz);
	}
}

void
prehash_zone_complete(struct namedb* db, struct zone* zone)
{
	udb_ptr udbz;

	/* robust clear it */
	nsec3_clear_precompile(db, zone);
	/* find zone settings */

	assert(db && zone);
	if(!udb_zone_search(db->udb, &udbz, dname_name(domain_dname(
		zone->apex)), domain_dname(zone->apex)->name_size)) {
		udb_ptr_init(&udbz, db->udb); /* zero the ptr */
	}
	nsec3_find_zone_param(db, zone, &udbz);
	if(!zone->nsec3_param) {
		zone->nsec3_last = 0;
		udb_ptr_unlink(&udbz, db->udb);
		return;
	}
	nsec3_precompile_newparam(db, zone, &udbz);
	udb_ptr_unlink(&udbz, db->udb);
}

/* find first in the tree and true if the first to process it */
static int
process_first(struct radtree* tree, uint8_t* hash, size_t hashlen,
	struct radnode** p)
{
	if(!tree) {
		*p = NULL;
		return 0;
	}
	if(radix_find_less_equal(tree, hash, hashlen, p)) {
		/* found an exact match */
		return 1;
	}
	if(!*p || !(*p)->parent) /* before first, go from first */
		*p = radix_next(radix_first(tree));
	return 0;
}

/* set end pointer if possible */
static void
process_end(struct radtree* tree, uint8_t* hash, size_t hashlen,
	struct radnode** p)
{
	if(!tree) {
		*p = NULL;
		return;
	}
	if(radix_find_less_equal(tree, hash, hashlen, p)) {
		/* an exact match, fine, because this one does not get
		 * processed */
		return;
	}
	/* inexact element, but if NULL, until first element in tree */
	if(!*p || !(*p)->parent) {
		*p = radix_next(radix_first(tree));
		return;
	}
	/* inexact match, use next element, if possible, the smaller
	 * element is part of the range */
	*p = radix_next(*p);
	/* if next returns null, we go until the end of the tree */
}

/* prehash domains in hash range start to end */
static void
process_range(zone_type* zone, domain_type* start, domain_type* end,
	domain_type* nsec3)
{
	/* start NULL means from first in tree */
	/* end NULL means to last in tree */
	struct radnode *p = NULL, *pwc = NULL, *pds = NULL;
	struct radnode *p_end = NULL, *pwc_end = NULL, *pds_end = NULL;
	/* set start */
	if(start) {
		uint8_t hash[NSEC3_HASH_LEN];
		parse_nsec3_name(domain_dname(start), hash, sizeof(hash));
		/* if exact match on first, set is_exact */
		if(process_first(zone->hashtree, hash, sizeof(hash), &p)) {
			((domain_type*)(p->elem))->nsec3_cover = nsec3;
			((domain_type*)(p->elem))->nsec3_is_exact = 1;
			p = radix_next(p);
		}
		(void)process_first(zone->wchashtree, hash,sizeof(hash),&pwc);
		if(process_first(zone->dshashtree, hash, sizeof(hash), &pds)) {
			((domain_type*)(pds->elem))->nsec3_ds_parent_cover
				= nsec3;
			((domain_type*)(pds->elem))->nsec3_ds_parent_is_exact
				= 1;
			pds = radix_next(pds);
		}
	} else {
		if(zone->hashtree)
			p = radix_next(radix_first(zone->hashtree));
		if(zone->wchashtree)
			pwc = radix_next(radix_first(zone->wchashtree));
		if(zone->dshashtree)
			pds = radix_next(radix_first(zone->dshashtree));
	}
	/* set end */
	if(end) {
		uint8_t hash[NSEC3_HASH_LEN];
		parse_nsec3_name(domain_dname(end), hash, sizeof(hash));
		process_end(zone->hashtree, hash, sizeof(hash), &p);
		process_end(zone->wchashtree, hash, sizeof(hash), &pwc);
		process_end(zone->dshashtree, hash, sizeof(hash), &pds);
	}

	/* precompile */
	while(p && p != p_end) {
		((domain_type*)(p->elem))->nsec3_cover = nsec3;
		((domain_type*)(p->elem))->nsec3_is_exact = 0;
		p = radix_next(p);
	}
	while(pwc && pwc != pwc_end) {
		((domain_type*)(pwc->elem))->nsec3_wcard_child_cover = nsec3;
		pwc = radix_next(pwc);
	}
	while(pds && pds != pds_end) {
		((domain_type*)(pds->elem))->nsec3_ds_parent_cover = nsec3;
		((domain_type*)(pds->elem))->nsec3_ds_parent_is_exact = 0;
		pds = radix_next(pds);
	}
}

/* prehash a domain from the prehash list */
static void
process_prehash_domain(domain_type* domain, zone_type* zone)
{
	/* in the hashtree, wchashtree, dshashtree walk through to next NSEC3
	 * and set precompile pointers to point to this domain (or is_exact),
	 * the first domain can be is_exact. If it is the last NSEC3, also
	 * process the initial part (before the first) */
	struct radnode* nx;

	assert(domain->nsec3_node);
	nx = radix_next(domain->nsec3_node);
	if(nx) {
		/* process until next nsec3 */
		domain_type* end = (domain_type*)nx->elem;
		process_range(zone, domain, end, domain);
	} else {
		/* first is root, but then comes the first nsec3 */
		domain_type* first = (domain_type*)(radix_next(radix_first(
			zone->nsec3tree))->elem);
		/* last in zone */
		process_range(zone, domain, NULL, domain);
		/* also process before first in zone */
		process_range(zone, NULL, first, domain);
	}
}

void prehash_zone(struct namedb* db, struct zone* zone)
{
	domain_type* d;
	/* process prehash list */
	for(d = db->domains->prehash_list; d; d = d->prehash_next) {
		process_prehash_domain(d, zone);
	}
	/* clear prehash list */
	prehash_clear(db->domains);
}

/* add the NSEC3 rrset to the query answer at the given domain */
static void
nsec3_add_rrset(struct query *query, struct answer *answer,
	rr_section_type section, struct domain* domain)
{
	if(domain) {
		rrset_type* rrset = domain_find_rrset(domain, query->zone, TYPE_NSEC3);
		if(rrset)
			answer_add_rrset(answer, section, domain, rrset);
	}
}

/* this routine does hashing at query-time. slow. */
static void
nsec3_add_nonexist_proof(struct query *query, struct answer *answer,
        struct domain *encloser, const dname_type* qname)
{
	uint8_t hash[NSEC3_HASH_LEN];
	const dname_type *to_prove;
	domain_type *cover=0;
	assert(encloser);
	/* if query=a.b.c.d encloser=c.d. then proof needed for b.c.d. */
	/* if query=a.b.c.d encloser=*.c.d. then proof needed for b.c.d. */
	to_prove = dname_partial_copy(query->region, qname,
		dname_label_match_count(qname, domain_dname(encloser))+1);
	/* generate proof that one label below closest encloser does not exist */
	nsec3_hash_and_store(query->zone, to_prove, hash);
	if(nsec3_find_cover(query->zone, hash, sizeof(hash), &cover))
	{
		/* exact match, hash collision */
		/* the hashed name of the query corresponds to an existing name. */
		log_msg(LOG_ERR, "nsec3 hash collision for name=%s",
			dname_to_string(to_prove, NULL));
		RCODE_SET(query->packet, RCODE_SERVFAIL);
		return;
	}
	else
	{
		/* cover proves the qname does not exist */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION, cover);
	}
}

static void
nsec3_add_closest_encloser_proof(
	struct query *query, struct answer *answer,
	struct domain *closest_encloser, const dname_type* qname)
{
	if(!closest_encloser)
		return;
	/* prove that below closest encloser nothing exists */
	nsec3_add_nonexist_proof(query, answer, closest_encloser, qname);
	/* proof that closest encloser exists */
	if(closest_encloser->nsec3_is_exact)
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			closest_encloser->nsec3_cover);
}

void
nsec3_answer_wildcard(struct query *query, struct answer *answer,
        struct domain *wildcard, const dname_type* qname)
{
	if(!wildcard)
		return;
	if(!query->zone->nsec3_param)
		return;
	nsec3_add_nonexist_proof(query, answer, wildcard, qname);
}

static void
nsec3_add_ds_proof(struct query *query, struct answer *answer,
	struct domain *domain, int delegpt)
{
	/* assert we are above the zone cut */
	assert(domain != query->zone->apex);
	if(domain->nsec3_ds_parent_is_exact) {
		/* use NSEC3 record from above the zone cut. */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec3_ds_parent_cover);
	} else if (!delegpt && domain->nsec3_is_exact) {
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec3_cover);
	} else {
		/* prove closest provable encloser */
		domain_type* par = domain->parent;
		domain_type* prev_par = 0;

		while(par && !par->nsec3_is_exact)
		{
			prev_par = par;
			par = par->parent;
		}
		assert(par); /* parent zone apex must be provable, thus this ends */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			par->nsec3_cover);
		/* we took several steps to go to the provable parent, so
		   the one below it has no exact nsec3, disprove it.
		   disprove is easy, it has a prehashed cover ptr. */
		if(prev_par) {
			assert(prev_par != domain && !prev_par->nsec3_is_exact);
			nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
				prev_par->nsec3_cover);
		}
		/* add optout range from parent zone */
		/* note: no check of optout bit, resolver checks it */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			domain->nsec3_ds_parent_cover);
	}
}

void
nsec3_answer_nodata(struct query *query, struct answer *answer,
	struct domain *original)
{
	if(!query->zone->nsec3_param)
		return;
	/* nodata when asking for secure delegation */
	if(query->qtype == TYPE_DS)
	{
		if(original == query->zone->apex) {
			/* DS at zone apex, but server not authoritative for parent zone */
			/* so answer at the child zone level */
			if(original->nsec3_is_exact)
				nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
					original->nsec3_cover);
			return;
		}
		/* query->zone must be the parent zone */
		nsec3_add_ds_proof(query, answer, original, 0);
	}
	/* the nodata is result from a wildcard match */
	else if (original==original->wildcard_child_closest_match
		&& label_is_wildcard(dname_name(domain_dname(original)))) {
		/* denial for wildcard is already there */
		/* add parent proof to have a closest encloser proof for wildcard parent */
		if(original->parent && original->parent->nsec3_is_exact)
			nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
				original->parent->nsec3_cover);
		/* proof for wildcard itself */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			original->nsec3_cover);
	}
	else {	/* add nsec3 to prove rrset does not exist */
		if(original->nsec3_is_exact)
			nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
				original->nsec3_cover);
	}
}

void
nsec3_answer_delegation(struct query *query, struct answer *answer)
{
	if(!query->zone->nsec3_param)
		return;
	nsec3_add_ds_proof(query, answer, query->delegation_domain, 1);
}

int
domain_has_only_NSEC3(struct domain* domain, struct zone* zone)
{
	/* check for only NSEC3/RRSIG */
	rrset_type* rrset = domain->rrsets;
	int nsec3_seen = 0, rrsig_seen = 0;
	while(rrset)
	{
		if(!zone || rrset->zone == zone)
		{
			if(rrset->rrs[0].type == TYPE_NSEC3)
				nsec3_seen = 1;
			else if(rrset->rrs[0].type == TYPE_RRSIG)
				rrsig_seen = 1;
			else
				return 0;
		}
		rrset = rrset->next;
	}
	return nsec3_seen;
}

void
nsec3_answer_authoritative(struct domain** match, struct query *query,
	struct answer *answer, struct domain* closest_encloser,
	const dname_type* qname)
{
	if(!query->zone->nsec3_param)
		return;
	assert(match);
	/* there is a match, this has 1 RRset, which is NSEC3, but qtype is not. */
	if(*match &&
#if 0
		query->qtype != TYPE_NSEC3 &&
#endif
		domain_has_only_NSEC3(*match, query->zone))
	{
		/* act as if the NSEC3 domain did not exist, name error */
		*match = 0;
		/* all nsec3s are directly below the apex, that is closest encloser */
		if(query->zone->apex->nsec3_is_exact)
			nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
				query->zone->apex->nsec3_cover);
		/* disprove the nsec3 record. */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION, closest_encloser->nsec3_cover);
		/* disprove a wildcard */
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION, query->zone->apex->
			nsec3_wcard_child_cover);
		if (domain_wildcard_child(query->zone->apex)) {
			/* wildcard exists below the domain */
			/* wildcard and nsec3 domain clash. server failure. */
			RCODE_SET(query->packet, RCODE_SERVFAIL);
		}
		return;
	}
	if(!*match) {
		/* name error, domain does not exist */
		nsec3_add_closest_encloser_proof(query, answer, closest_encloser,
			qname);
		nsec3_add_rrset(query, answer, AUTHORITY_SECTION,
			closest_encloser->nsec3_wcard_child_cover);
	}
}

#endif /* NSEC3 */
