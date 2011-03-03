/*
 * pktc.c -- packet compiler routines.
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#include "pktc.h"
#include "radtree.h"
#include "util.h"
#include "namedb.h"
#include "query.h"
#include "answer.h"

#define FLAGCODE_QR 0x8000U
#define FLAGCODE_AA 0x0400U

/** some uncompressed dname functionality */
/** length (+final0) of dname */
size_t dname_length(uint8_t* dname)
{
	size_t len = 0;
	size_t labellen;
	labellen = *dname++;
	while(labellen) {
		if(labellen&0xc0)
			return 0; /* no compression ptrs allowed */
		len += labellen + 1;
		if(len >= MAXDOMAINLEN)
			return 0; /* too long */
		dname += labellen;
		labellen = *dname++;
	}
	len += 1;
	return len;
}

/** strip one label from a dname in uncompressed wire format */
uint8_t* dname_strip_label(uint8_t* dname)
{
	/* root is not stripped further */
	if(*dname == 0) return dname;
	return dname+*dname+1;
}

/** like strdup but for memory regions */
uint8_t* memdup(void* data, size_t len)
{
	void* r = xalloc(len);
	memcpy(r, data, len);
	return r;
}

struct comptree* comptree_create(void)
{
	struct comptree* ct = (struct comptree*)xalloc(sizeof(*ct));
	ct->nametree = radix_tree_create();
	ct->zonetree = radix_tree_create();
	return ct;
}

void comptree_delete(struct comptree* ct)
{
	struct radnode* n;
	if(!ct) return;
	/* delete the elements in the trees (no tree operations) */
	for(n = radix_first(ct->nametree); n; n=radix_next(n))
		compname_delete((struct compname*)n->elem);
	for(n = radix_first(ct->zonetree); n; n=radix_next(n))
		compzone_delete((struct compzone*)n->elem);
	/* postorder delete of the trees themselves */
	radix_tree_delete(ct->nametree);
	radix_tree_delete(ct->zonetree);
	free(ct);
}

struct compzone* compzone_create(struct comptree* ct, uint8_t* zname)
{
	struct compzone* cz = (struct compzone*)xalloc(sizeof(*cz));
	size_t zlen = dname_length(zname);
	cz->name = memdup(zname, zlen);
	cz->nsec3tree = NULL; /* empty for now, may not be NSEC3-zone */
	/* todo nsec3parms empty */
	cz->serial = 0;
	
	/* add into tree */
	cz->rnode = radname_insert(ct->zonetree, zname, zlen, cz);

	return cz;
}

void compzone_delete(struct compzone* cz)
{
	if(!cz) return;
	free(cz->name);
	if(cz->nsec3tree) {
		struct radnode* n;
		for(n = radix_first(cz->nsec3tree); n; n = radix_next(n))
			compnsec3_delete((struct compnsec3*)n->elem);
		radix_tree_delete(cz->nsec3tree);
	}
	free(cz);
}

struct compzone* compzone_search(struct comptree* ct, uint8_t* name)
{
	struct radnode* n = radname_search(ct->zonetree, name,
		dname_length(name));
	if(n) return (struct compzone*)n->elem;
	return NULL;
}

struct compzone* compzone_find(struct comptree* ct, uint8_t* name, int* ce)
{
	/* simply walk the zones */
	struct radnode* n = radname_search(ct->zonetree, name,
		dname_length(name));
	if(n) {
		*ce = 0;
		return (struct compzone*)n->elem;
	}
	do {
		name = dname_strip_label(name);
		n = radname_search(ct->zonetree, name, dname_length(name));
		if(n) {
			*ce = 1;
			return (struct compzone*)n->elem;
		}
	} while(*name);
	return NULL;
}

struct compname* compname_create(struct comptree* ct, uint8_t* name)
{
	struct compname* cn = (struct compname*)xalloc(sizeof(*cn));
	memset(cn, 0, sizeof(*cn));
	cn->namelen = dname_length(name);

	/* add into tree */
	cn->rnode = radname_insert(ct->zonetree, name, cn->namelen, cn);

	return cn;
}

void compname_delete(struct compname* cn)
{
	size_t i;
	if(!cn) return;
	for(i=0; i<cn->typelen; i++)
		cpkt_delete(cn->types[i]);
	free(cn->types);
	cpkt_delete(cn->notype);
	cpkt_delete(cn->side);
	if(cn->belowtype == BELOW_NORMAL || cn->belowtype == BELOW_SYNTHC)
		cpkt_delete(cn->below);
	/* else, it is only a reference */
	free(cn);
}

struct compname* compname_search(struct comptree* ct, uint8_t* name)
{
	struct radnode* n = radname_search(ct->nametree, name,
		dname_length(name));
	if(n) return (struct compname*)n->elem;
	return NULL;
}

void compnsec3_delete(struct compnsec3* c3)
{
	if(!c3) return;
	cpkt_delete(c3->nx);
	free(c3);
}

struct cpkt* compile_packet(uint8_t* qname, int adjust, uint16_t flagcode,
	uint16_t num_an, uint16_t num_ns, uint16_t num_ar,
	uint8_t** rrname, uint16_t* rrtype, uint16_t* rrclass,
	uint32_t* rrttl, uint8_t* rrdata)
{
	struct cpkt c; /* temporary structure */
	struct cpkt* cp = NULL;
	memset(&c, 0, sizeof(c));

	/* compile */
	/* TODO */

	/* allocate */

	return cp;
}

/** compile answer info packet */
static struct cpkt* compile_answer_packet(struct answer_info* ai)
{
	/* TODO */
	return NULL;
}

/** init answer info */
static void answer_info_init(struct answer_info* ai, uint8_t* qname)
{
	ai->qname = qname;
	ai->adjust = 0;
	ai->flagcode = FLAGCODE_QR; /* set QR flag, NOERROR */
	answer_init(&ai->answer);
}

/** add additional rrsets to the result based on type and list */
static void ai_additional(struct answer_info* ai, rrset_type* master_rrset,
	size_t rdata_index, int allow_glue, struct additional_rr_types types[],
	struct zone* zone)
{
	size_t i;
	for (i = 0; i < master_rrset->rr_count; ++i) {
		int j;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i].rdatas[rdata_index]);
		domain_type *match = additional;
		assert(additional);
		if (!allow_glue && domain_is_glue(match, zone))
			continue;
		/*
		 * Check to see if we need to generate the dependent
		 * based on a wildcard domain.
		 */
		while (!match->is_existing) {
			match = match->parent;
		}
		if (additional != match && domain_wildcard_child(match)) {
			domain_type *wildcard_child =
				domain_wildcard_child(match);
			domain_type *temp = (domain_type *) region_alloc(
				ai->region, sizeof(domain_type));		
#ifdef USE_RADIX_TREE
			temp->rnode = NULL;
			temp->dname = additional->dname;
#else
			memcpy(&temp->node, &additional->node, sizeof(rbnode_t));
#endif
			temp->number = additional->number;
			temp->parent = match;
			temp->wildcard_child_closest_match = temp;
			temp->rrsets = wildcard_child->rrsets;
			temp->is_existing = wildcard_child->is_existing;
			additional = temp;
		}
		for (j = 0; types[j].rr_type != 0; ++j) {
			rrset_type *rrset = domain_find_rrset(
				additional, zone, types[j].rr_type);
			if(rrset)
				answer_add_rrset(&ai->answer,
					types[j].rr_section, additional, rrset);
		}
	}
}

/** answer info add rrset, possibly additionals */
static void ai_add_rrset(struct answer_info* ai, rr_section_type section,
	domain_type *owner, rrset_type *rrset, struct zone* zone)
{
	answer_add_rrset(&ai->answer, section, owner, rrset);
	switch(rrset_rrtype(rrset)) {
	case TYPE_NS:
		ai_additional(ai, rrset, 0, 1, default_additional_rr_types,
			zone);
		break;
	case TYPE_MB:
		ai_additional(ai, rrset, 0, 0, default_additional_rr_types,
			zone);
		break;
	case TYPE_MX:
	case TYPE_KX:
		ai_additional(ai, rrset, 1, 0, default_additional_rr_types,
			zone);
		break;
	case TYPE_RT:
		ai_additional(ai, rrset, 1, 0, rt_additional_rr_types,
			zone);
		break;
	default:
		break;
	}
}

/** compile delegation */
static struct cpkt* compile_delegation_answer(uint8_t* dname,
	struct domain* domain, struct zone* zone, struct compzone* cz)
{
	rrset_type* rrset;
	struct answer_info ai;
	answer_info_init(&ai, dname);
	ai.adjust = 1;
	rrset = domain_find_rrset(domain, zone, TYPE_NS);
	assert(rrset);
	ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	if((rrset = domain_find_rrset(domain, zone, TYPE_DS))) {
		ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	} else if(cz->nsec3tree) {
		/* TODO nsec3_add_ds_proof(&ai, domain, 1); */
	} else if((rrset = domain_find_rrset(domain, zone, TYPE_NSEC))) {
		ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	}
	return compile_answer_packet(&ai);
}

/** compile DS answer */
static struct cpkt* compile_DS_answer(uint8_t* dname,
	struct domain* domain, struct zone* zone, struct compzone* cz)
{
	rrset_type* rrset;
	struct answer_info ai;
	answer_info_init(&ai, dname);
	ai.adjust = 0;
	ai.flagcode |= FLAGCODE_AA;
	if((rrset = domain_find_rrset(domain, zone, TYPE_DS))) {
		ai_add_rrset(&ai, ANSWER_SECTION, domain, rrset, zone);
	} else if(cz->nsec3tree) {
		/* TODO nsec3_add_ds_proof(&ai, domain, 1); */
	} else if((rrset = domain_find_rrset(domain, zone, TYPE_NSEC))) {
		ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	}
	return compile_answer_packet(&ai);
}

void cpkt_delete(struct cpkt* cp)
{
	free(cp);
}

int cpkt_compare_qtype(const void* a, const void* b)
{
	struct cpkt* x = *(struct cpkt* const*)a;
	struct cpkt* y = *(struct cpkt* const*)b;
	return ((int)y->qtype) - ((int)x->qtype);
}

void compile_zones(struct comptree* ct, struct zone* zonelist,
	struct domain_table* table)
{
	struct zone* z;
	struct compzone* cz;
	time_t s, e;
	int n=0;
	s = time(NULL);
	/* fill the zonetree first */
	for(z = zonelist; z; z = z->next) {
		n++;
		cz = compzone_create(ct,
			(uint8_t*)dname_name(domain_dname(z->apex)));
	}
	/* so that compile_zone can access the zonetree */
	for(z = zonelist; z; z = z->next) {
		compile_zone(ct, cz, z, table);
	}
	e = time(NULL);
	VERBOSITY(1, (LOG_INFO, "compiled %d zones in %d seconds", n, (int)(e-s)));
}

void compile_zone(struct comptree* ct, struct compzone* cz, struct zone* zone,
	struct domain_table* table)
{
	domain_type* walk;
	/* setup NSEC3 */
	if(domain_find_rrset(zone->apex, zone, TYPE_NSEC3PARAM)) {
		/* fill NSEC3params in cz */
		/* TODO */
		cz->nsec3tree = radix_tree_create();
	}

	/* walk through the names */
	walk = zone->apex;
	while(walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex))) {
		zone_type* curz = domain_find_zone(walk);
		if(curz && curz == zone) {
			compile_name(ct, cz, zone, table, walk);
		}
		walk = domain_next(walk);
	}
}

enum domain_type_enum determine_domain_type(struct domain* domain,
	struct zone* zone, int* apex)
{
	if(!domain->is_existing)
		return dtype_notexist;
	if(domain->is_apex)
		*apex = 1;
	if(!domain->is_apex && domain_find_rrset(domain, zone, TYPE_NS))
		return dtype_delegation;
	if(domain_find_rrset(domain, zone, TYPE_CNAME))
		return dtype_cname;
	if(domain_find_rrset(domain, zone, TYPE_DNAME))
		return dtype_dname;
	return dtype_normal;
}

/** find wirename or add a compname(empty) for it */
static struct compname* find_or_create_name(struct comptree* ct, uint8_t* nm)
{
	struct compname* cn = compname_search(ct, nm);
	if(cn) return cn;
	return compname_create(ct, nm);
}

/** add a type to the typelist answers (during precompile it can grow */
static void cn_add_type(struct compname* cn, uint16_t t, struct cpkt* p)
{
	/* check if already present */
	size_t i;
	for(i=0; i<cn->typelen; i++)
		if(cn->types[i]->qtype == t) {
			log_msg(LOG_ERR, "internal error: double type in list");
			/* otherwise ignore it */
		}
	p->qtype = t;
	cn->types[i]=p;
	cn->typelen++;
}

static void compile_delegation(struct compname* cn, struct domain* domain,
	uint8_t* dname, struct zone* zone, struct compzone* cz)
{
	/* type DS */
	cn_add_type(cn, TYPE_DS, compile_DS_answer(dname, domain, zone, cz));
	/* notype is referral */
	cn->notype = compile_delegation_answer(dname, domain, zone, cz);
	/* below is referral */
	cn->below = compile_delegation_answer(dname, domain, zone, cz);
	cn->belowtype = BELOW_NORMAL;
}

static void compile_normal(struct compname* cn, struct domain_table* table,
        struct domain* domain, struct zone* zone)
{
	rrset_type* rrset;
	/* add all existing qtypes */
	for(rrset = domain->rrsets; rrset; rrset = rrset->next) {
		if(rrset->zone != zone)
			continue;

	}
	/* add qtype RRSIG (if necessary) */

	/* add qtype ANY */

	/* notype */
	//compile_nodata();
}

static void compile_dname(struct compname* cn, struct domain_table* table,
	struct domain* domain, struct zone* zone)
{
	/* fill for normal types, other types next to DNAME */
	compile_normal(cn, table, domain, zone);
	/* below is dname */
	cn->belowtype = BELOW_SYNTHC;
}

static void compile_cname(struct compname* cn, struct domain_table* table,
        struct domain* domain)
{
	/* todo: follow in-zone */
	/* notype is CNAME */
}

static void compile_side_nsec(struct compname* cn, struct domain_table* table,
        struct domain* domain)
{
	/* NXDOMAIN in side */
	cn->belowtype = BELOW_NORMAL;
}

static void compile_below_nsec3(struct compname* cn, struct domain_table* table,
        struct domain* domain, struct compzone* cz)
{
	/* create nxdomain in nsec3tree, belowptr */

	cn->below = (struct cpkt*)cz;
	cn->belowtype = BELOW_NSEC3NX;
}

static void compile_below_wcard(struct compname* cn, struct comptree* ct,
	uint8_t* dname)
{
	/* belowptr to wildcardname, create if not yet exists, but it gets
	 * filled on its own accord */
	uint8_t wname[MAXDOMAINLEN+2];
	struct compname* wcard;
	/* the wildcard must exist */
	assert(dname_length(dname) == cn->namelen);
	assert(dname_length(dname)+2 <= MAXDOMAINLEN);
	wname[0]=1;
	wname[1]='*';
	memmove(wname+2, dname, cn->namelen);
	wcard = find_or_create_name(ct, wname);
	cn->below = (struct cpkt*)wcard;
	cn->belowtype = BELOW_WILDCARD;
}

static void compile_apex_ds(struct compname* cn, struct domain_table* table,
        struct domain* domain, struct comptree* ct, uint8_t* dname)
{
	/* create a qtype DS for the zone apex, but only if we host a zone
	 * above this zone, can be posDS, NSEC-DS, NSEC3DS(nodata,optout).
	 * in case its nxdomain above, include that(assume optout). */
	int ce = 0;
	uint8_t* dsname = dname_strip_label(dname);
	struct compzone* above = compzone_find(ct, dsname, &ce);
	if(above) {
		/* add a DS-answer from the point of view of that zone */
		/* TODO */
	}
}

void compile_name(struct comptree* ct, struct compzone* cz, struct zone* zone,
        struct domain_table* table, struct domain* domain)
{
	/* determine the 'type' of this domain name */
	int apex = 0;
	enum domain_type_enum t = determine_domain_type(domain, zone, &apex);
	struct compname* cn;
	uint8_t* dname = (uint8_t*)dname_name(domain_dname(domain));
	struct cpkt* pktlist[65536+10]; /* all types and some spare */

	/* type: NSEC3domain: treat as occluded. */
	/* type: glue: treat as occluded. */
	/* type: occluded: do nothing, do not add the name. */
	if(t == dtype_notexist)
		return;
	/* if we host the subzone of referral too, add it as itself */
	else if(t == dtype_delegation && compzone_search(ct, dname))
		return;
	
	/* create cn(or find) and setup typelist for additions */
	cn = find_or_create_name(ct, dname);
	assert(cn->typelen < sizeof(pktlist));
	memcpy(pktlist, cn->types, cn->typelen*sizeof(struct cpkt*));
	free(cn->types);
	cn->types = pktlist;

	/* type: delegation: type-DS, notype=referral, below=referral */
	if(t == dtype_delegation)
		compile_delegation(cn, domain, dname, zone, cz);
	/* type: dname: fill for dname, type and below */
	else if(t == dtype_dname)
		compile_dname(cn, table, domain, zone);
	/* type: cname: fill for cname : if in-zone: for all types at dest,
	 * 				             and for notype-dest.
	 * 				not-in-zone: just the cname. */
	else if(t == dtype_cname)
		compile_cname(cn, table, domain);
	/* type: normal: all types, ANY, RRSIG, notype(NSEC/NSEC3). */
	else if(t == dtype_normal)
		compile_normal(cn, table, domain, zone);
	
	/* fill below and side */
	if(t == dtype_delegation)
		/* below is referral */;
	else if(t == dtype_dname)
		/* below is dname */;
	else if(domain_wildcard_child(domain) && cn->namelen+2<=MAXDOMAINLEN)
		compile_below_wcard(cn, ct, dname);
	/* else if zone is NSEC3: create nxdomain in nsec3tree, belowptr */
	else if(cz->nsec3tree)
		compile_below_nsec3(cn, table, domain, cz);
	/* else if zone is NSEC: create nxdomain in side */
	else 	compile_side_nsec(cn, table, domain);

	/* if apex: see if we need special type-DS compile (parent zone) */
	if(apex)
		compile_apex_ds(cn, table, domain, ct, dname);
	
	/* sort and allocate typelist */
	assert(cn->typelen < sizeof(pktlist));
	if(cn->typelen == 0) {
		cn->types = NULL;
	} else {
		qsort(pktlist, cn->typelen, sizeof(struct cpkt*),
			&cpkt_compare_qtype);
		cn->types = (struct cpkt**)memdup(pktlist,
			cn->typelen*sizeof(struct cpkt*));
	}
}

