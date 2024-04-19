/*
	test namedb.c
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "options.h"
#include "namedb.h"
#include "nsec3.h"
#include "udb.h"
#include "difffile.h"
#include "zonec.h"
#include "nsd.h"
#include "zone.h"

static void namedb_1(CuTest *tc);
static void namedb_2(CuTest *tc);
#ifdef NSEC3
static void namedb_3(CuTest *tc);
static void namedb_4(CuTest *tc);
#endif /* NSEC3 */
static int v = 0; /* verbosity */

/** get a temporary file name */
char* udbtest_get_temp_file(char* suffix);

CuSuite* reg_cutest_namedb(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, namedb_1);
	SUITE_ADD_TEST(suite, namedb_2);
#ifdef NSEC3
	SUITE_ADD_TEST(suite, namedb_3);
	SUITE_ADD_TEST(suite, namedb_4);
#endif /* NSEC3 */
	return suite;
}

/** read a particular zone into memory,
 * the zonename must be fully qualified.
 * the zone must be secure if apex has RRSIG.
 * the zone must have nsec3 if there are NSEC3PARAM.
 * the zone must have SOA record if valid.
 */
static struct namedb*
create_and_read_db(CuTest* tc, region_type* region, const char* zonename,
	const char* ztxt)
{
	struct nsd nsd;
	struct nsd_options* opt;
	struct zone_options* zone;
	namedb_type* db;
	char* zonefile = udbtest_get_temp_file("namedb.zone");
	FILE* out = fopen(zonefile, "w");
	if(!out) {
		printf("failed to write %s: %s\n", zonefile, strerror(errno));
		exit(1);
	}
	fprintf(out, "%s", ztxt);
	fclose(out);

	/* add our zone option */
	opt = nsd_options_create(region);
	zone = zone_options_create(region);
	memset(zone, 0, sizeof(*zone));
	zone->name = region_strdup(region, zonename);
	zone->pattern = pattern_options_create(region);
	zone->pattern->pname = zone->name;
	zone->pattern->zonefile = region_strdup(region, zonefile);
	zone->pattern->request_xfr = (void*)-1; /* dummy value to make zonec not error*/
	if(!nsd_options_insert_zone(opt, zone)) {
		CuAssertTrue(tc, 0);
	}

	/* read the db */
	memset(&nsd, 0, sizeof(nsd));
	nsd.db = db = namedb_open(opt);
	if(!db) {
		printf("failed to open namedb\n");
		exit(1);
	}
	namedb_check_zonefiles(&nsd, opt, NULL, NULL);
	unlink(zonefile);
	free(zonefile);
	return db;
}

#ifdef NSEC3
/* see if lastnsec3 is really the last, return false on trouble */
static int
nsec3last(zone_type* zone)
{
	domain_type* d = zone->nsec3_last;
	d = domain_next(d);
	while(d && dname_is_subdomain(domain_dname(d),
		domain_dname(zone->apex))) {
		if(domain_find_rrset(d, zone, TYPE_NSEC3)) {
			/* an NSEC3? After nsec3_last?, if it has the same
			 * paramset, then the nsec3_last is wrong */
			if(nsec3_in_chain_count(d, zone) != 0)
				return 0; /* this is later than the last */
		}
		d = domain_next(d);
	}
	return 1; /* OK : no NSEC3 later in zone */
}
#endif /* NSEC3 */

/* walk zones and check them */
static void
check_walkzones(CuTest* tc, namedb_type* db)
{
	struct radnode* n;
	for(n=radix_first(db->zonetree); n; n=radix_next(n)) {
		zone_type* zone = (zone_type*)n->elem;
		CuAssertTrue(tc, zone->apex != NULL);
		CuAssertTrue(tc, zone->opts != NULL);
		/* options are for this zone */
		CuAssertTrue(tc, strcmp(dname_to_string(domain_dname(
			zone->apex), NULL), zone->opts->name) == 0);
		/* either: the zone is servfail (nothing), and no SOA, ...
		 * or: it exists and has a SOA, NS, ... */
		if(zone->is_ok) {
			/* check soa_rrset */
			CuAssertTrue(tc, zone->soa_rrset != NULL);
			CuAssertTrue(tc, zone->soa_nx_rrset != NULL);
			CuAssertTrue(tc, zone->soa_rrset ==
				domain_find_rrset(zone->apex, zone, TYPE_SOA));
			CuAssertTrue(tc, zone->apex->is_existing);
			CuAssertTrue(tc, zone->apex->is_apex);
			/* if NS */
			CuAssertTrue(tc, zone->ns_rrset ==
				domain_find_rrset(zone->apex, zone, TYPE_NS));
			/* if RRSIG then secure */
			if(domain_find_rrset(zone->apex, zone, TYPE_RRSIG)) {
				CuAssertTrue(tc, zone->is_secure);
			} else {
				CuAssertTrue(tc, !zone->is_secure);
			}
			/* if NSEC3PARAM then nsec3 */
#ifdef NSEC3
			if(domain_find_rrset(zone->apex, zone,
				TYPE_NSEC3PARAM)) {
				CuAssertTrue(tc, zone->nsec3_param != NULL);
				CuAssertTrue(tc, zone->nsec3_param->type ==
					TYPE_NSEC3PARAM);
				CuAssertTrue(tc, zone->nsec3_param->owner ==
					zone->apex);
				if(zone->nsec3_last) {
					CuAssertTrue(tc, domain_find_rrset(
						zone->nsec3_last, zone,
						TYPE_NSEC3) != NULL);
					/* check that last nsec3, is last */
					CuAssertTrue(tc, nsec3last(zone));
				}
			} else {
				CuAssertTrue(tc, zone->nsec3_param == NULL);
				CuAssertTrue(tc, zone->nsec3_last == NULL);
			}
#endif /* NSEC3 */
		} else {
			CuAssertTrue(tc, zone->soa_rrset == NULL);
			/*CuAssertTrue(tc, zone->soa_nx_rrset == NULL);
			  alloc saved for later update */
			/*CuAssertTrue(tc, zone->ns_rrset == NULL);*/
#ifdef NSEC3
			/*CuAssertTrue(tc, zone->nsec3_param == NULL);
			CuAssertTrue(tc, zone->nsec3_last == NULL);*/
#endif /* NSEC3 */
			/*CuAssertTrue(tc, !zone->apex->is_existing);*/
		}
	}
}

/** set usage for zones */
static void
usage_for_zones(namedb_type* db, size_t* usage)
{
	struct radnode* n;
	for(n=radix_first(db->zonetree); n; n=radix_next(n)) {
		zone_type* zone = (zone_type*)n->elem;
		usage[zone->apex->number]++;
	}
}
	
/** find wildcard under a name or NULL */
static domain_type*
find_wc_under(namedb_type* db, domain_type* d)
{
	domain_type* wc_closest_match = NULL, *ce = NULL;
	const dname_type* wild, *wcname;
	region_type* region = region_create(xalloc, free);
	wild = dname_parse(region, "*");
	wcname = dname_concatenate(region, wild, domain_dname(d));
	(void)domain_table_search(db->domains, wcname, &wc_closest_match, &ce);
	region_destroy(region);
	return wc_closest_match;
}

/** check the type does not exist further on */
static void
NoTypeInRest(CuTest* tc, rrset_type* list, uint16_t t, zone_type* zone)
{
	rrset_type* rrset;
	for(rrset=list; rrset; rrset=rrset->next) {
		if(rrset->zone == zone && rrset_rrtype(rrset)==t) {
			CuAssertTrue(tc, 0);
		}
	}
}

/** check rrsets */
static void
check_rrsets(CuTest* tc, domain_type* domain)
{
	rrset_type* rrset;
	unsigned i;
	for(rrset=domain->rrsets; rrset; rrset=rrset->next) {
		CuAssertTrue(tc, rrset->rr_count != 0);
		CuAssertTrue(tc, rrset->rrs != NULL);
		CuAssertTrue(tc, rrset->zone != NULL);
		/* rrsets: type-once-per-zone. */
		NoTypeInRest(tc, rrset->next, rrset_rrtype(rrset), rrset->zone);
		/* rrsets: rr owner is d */
		for(i=0; i<rrset->rr_count; i++) {
			CuAssertTrue(tc, rrset->rrs[i].type ==
				rrset_rrtype(rrset));
			CuAssertTrue(tc, rrset->rrs[i].owner == domain);
		}
	}
}

#ifdef NSEC3
/* get NSEC3 for given nsec3-domain-name, b32.zone */
static domain_type*
get_nsec3_for(namedb_type* db, const dname_type* look, zone_type* zone)
{
	domain_type* closest=NULL, *ce=NULL;
	(void)domain_table_search(db->domains, look, &closest, &ce);
	/* walk back through zone until we find an NSEC3 record.
	 * this uses the normal db tree to check the NSEC3-trees */
	while(closest && nsec3_in_chain_count(closest, zone) == 0)
		closest = domain_previous(closest);
	if(!closest) {
		return zone->nsec3_last;
	}
	return closest;
}
#endif /* NSEC3 */

/* see if a domain has an rrset (without zone check) */
static rrset_type*
domain_has_rrset_plain(domain_type* domain, uint16_t t)
{
	rrset_type* rrset;
	for(rrset=domain->rrsets; rrset; rrset=rrset->next)
		if(rrset_rrtype(rrset) == t)
			return rrset;
	return NULL;
}

#ifdef NSEC3
/* see if a domain has a delegation NS rrset */
static rrset_type*
domain_has_deleg_rrset(domain_type* domain)
{
	rrset_type* rrset;
	for(rrset=domain->rrsets; rrset; rrset=rrset->next)
		if(rrset_rrtype(rrset) == TYPE_NS &&
			rrset->zone->apex != domain)
			return rrset;
	return NULL;
}

/* see if a domain is inside the nsec3-hashed space, look for parent zones */
static int
domain_in_nsec3_space(domain_type* domain, zone_type** zone)
{
	rrset_type* rrset;
	while(domain) {
		if((rrset=domain_has_rrset_plain(domain, TYPE_NSEC3PARAM))) {
			*zone = rrset->zone;
			return 1;
		}
		domain = domain->parent;
	}
	return 0;
}
#endif /* NSEC3 */

/* check nsec3 data for domain */
static void
check_nsec3(CuTest* tc, namedb_type* db, domain_type* domain)
{
#ifdef NSEC3
	region_type* region;
	zone_type* zone = NULL;
	rrset_type* rrset;
	/* check nsec3_lookup */
	if(!domain_in_nsec3_space(domain, &zone)) {
		return;
	}
	region = region_create(xalloc, free);

	/* see if this domain is processed */
	if(!zone || !zone->nsec3_param || 
		!nsec3_condition_hash(domain, zone)) {
		/*
		 * for domains that previously held normal data, but then
		 * became part of the NSEC3 chain, the hashes exist,
		 * so cannot assert !have_nsec3_hash and !have_nsec3_wc_hash */
		if(domain->nsec3) {
			CuAssertTrue(tc, !domain->nsec3->nsec3_is_exact);
			CuAssertTrue(tc, !domain->nsec3->nsec3_cover);
			CuAssertTrue(tc, !domain->nsec3->nsec3_wcard_child_cover);
		}
	} else {
		const dname_type* h, *wch, *wild;
		uint8_t hash[NSEC3_HASH_LEN], wchash[NSEC3_HASH_LEN];
		CuAssertTrue(tc, domain->nsec3->hash_wc
		              && domain->nsec3->hash_wc->hash.node.key);
		CuAssertTrue(tc, domain->nsec3->hash_wc
		              && domain->nsec3->hash_wc->wc.node.key);
		nsec3_hash_and_store(zone, domain_dname(domain), hash);
		h = nsec3_b32_create(region, zone, hash);
		wild = dname_parse(region, "*");
		wild = dname_concatenate(region, wild, domain_dname(domain));
		nsec3_hash_and_store(zone, wild, wchash);
		wch = nsec3_b32_create(region, zone, wchash);

		CuAssertTrue(tc, memcmp(domain->nsec3->hash_wc->hash.hash, hash,
			NSEC3_HASH_LEN) == 0);
		CuAssertTrue(tc, memcmp(domain->nsec3->hash_wc->wc.hash, wchash,
			NSEC3_HASH_LEN) == 0);

		/* check nsec3_cover, nsec3_is_exact */
		CuAssertTrue(tc, get_nsec3_for(db, h, zone) ==
			domain->nsec3->nsec3_cover);
		if(domain->nsec3->nsec3_cover && dname_compare(domain_dname(
			domain->nsec3->nsec3_cover), h) == 0) {
			CuAssertTrue(tc, domain->nsec3->nsec3_is_exact);
		} else {
			CuAssertTrue(tc, !domain->nsec3->nsec3_is_exact);
		}
		/* check nsec3_wcard_child_cover */
		CuAssertTrue(tc, get_nsec3_for(db, wch, zone) ==
			domain->nsec3->nsec3_wcard_child_cover);
	}
	if((rrset=domain_has_rrset_plain(domain, TYPE_DS)) ||
		(rrset=domain_has_deleg_rrset(domain))) {
	    zone_type* pz = rrset->zone;
	    if(pz->nsec3_param && domain->is_existing) {
		const dname_type* h;
		uint8_t hash[NSEC3_HASH_LEN];
		CuAssertTrue(tc, domain->nsec3 != NULL);
		CuAssertTrue(tc, domain->nsec3->ds_parent_hash
		              && domain->nsec3->ds_parent_hash->node.key);
		nsec3_hash_and_store(pz, domain_dname(domain), hash);
		h = nsec3_b32_create(region, pz, hash);
		CuAssertTrue(tc, memcmp(domain->nsec3->ds_parent_hash->hash,
			hash, NSEC3_HASH_LEN) == 0);

		/* check nsec3_ds_parent_cover, nsec3_ds_parent_is_exact */
		CuAssertTrue(tc, get_nsec3_for(db, h, pz) ==
			domain->nsec3->nsec3_ds_parent_cover);
		if(domain->nsec3->nsec3_ds_parent_cover && dname_compare(
			domain_dname(domain->nsec3->nsec3_ds_parent_cover), h) == 0) {
			CuAssertTrue(tc, domain->nsec3->nsec3_ds_parent_is_exact);
		} else {
			CuAssertTrue(tc, !domain->nsec3->nsec3_ds_parent_is_exact);
		}
	    } else {
		if(domain->nsec3) {
			CuAssertTrue(tc, !domain->nsec3->ds_parent_hash);
			CuAssertTrue(tc, !domain->nsec3->nsec3_ds_parent_cover);
			CuAssertTrue(tc, !domain->nsec3->nsec3_ds_parent_is_exact);
		}
	    }
	} else {
		/* if it previously was DS but not any more, it can remain
		CuAssertTrue(tc, !domain->have_nsec3_ds_parent_hash);
		*/
		if(domain->nsec3) {
			CuAssertTrue(tc, !domain->nsec3->nsec3_ds_parent_cover);
			CuAssertTrue(tc, !domain->nsec3->nsec3_ds_parent_is_exact);
		}
	}
	region_destroy(region);
#else
	(void)tc; (void)db; (void)domain;
#endif /* NSEC3 */
}

/* see if domain has data below it */
static int
has_data_below(domain_type* domain)
{
	domain_type* walk;
	for(walk=domain_next(domain); walk && dname_is_subdomain(
		domain_dname(walk), domain_dname(domain));
		walk=domain_next(walk)) {
		if(walk->rrsets)
			return 1;
	}
	return 0;
}

/* add usage for rr */
static void
usage_for_rr(rr_type* rr, size_t* usage)
{
	unsigned i;
	domain_type* d;
	for(i=0; i<rr->rdata_count; i++) {
		switch(rdata_atom_wireformat_type(rr->type, i)) {
		case RDATA_WF_COMPRESSED_DNAME:
		case RDATA_WF_UNCOMPRESSED_DNAME:
			d = rdata_atom_domain(rr->rdatas[i]);
			usage[d->number] ++;
			break;
		default:
			break;
		}
	}
}

/* add usage for rrsets */
static void
usage_for_rrsets(rrset_type* list, size_t* usage)
{
	unsigned i;
	for(; list; list=list->next) {
		for(i=0; i<list->rr_count; i++) {
			usage_for_rr(&list->rrs[i], usage);
		}
	}
}

/* check numlist for consistency */
static void
check_numlist(CuTest* tc, domain_table_type* table)
{
	domain_type* d = table->root, *prevd = NULL;
	size_t num = 1;
	/* first is root at number 1 */
	CuAssertTrue(tc, d != NULL);
	CuAssertTrue(tc, d->number == num);
	CuAssertTrue(tc, domain_dname(d)->label_count == 1);
	while(d) {
		/* check number */
		CuAssertTrue(tc, d->number == num);
		/* check list structure */
		CuAssertTrue(tc, d->numlist_prev == prevd);
		if(d->numlist_next) {
			CuAssertTrue(tc, d == d->numlist_next->numlist_prev);
		} else {
			CuAssertTrue(tc, d == table->numlist_last);
		}

		num++;
		prevd = d;
		d = d->numlist_next;
	}
	CuAssertTrue(tc, table->numlist_last->number == domain_table_count(table));
}

/* walk domains and check them */
static void
check_walkdomains(CuTest* tc, namedb_type* db)
{
	domain_type* d;
	uint8_t* numbers = xalloc_zero(domain_table_count(db->domains)+10);
	size_t* usage = xalloc_zero((domain_table_count(db->domains)+10)*
		sizeof(size_t));
	for(d=db->domains->root; d; d=domain_next(d)) {
		if(v) printf("at domain %s\n", dname_to_string(domain_dname(d),
			NULL));
		/* check parent: exists, NULL for root and one label less */
		if(domain_dname(d)->label_count == 1) {
			CuAssertTrue(tc, d->parent == NULL);
		} else {
			CuAssertTrue(tc, d->parent != NULL);
			CuAssertTrue(tc, domain_dname(d->parent)->label_count
				== domain_dname(d)->label_count-1);
			CuAssertTrue(tc, dname_is_subdomain(domain_dname(d),
				domain_dname(d->parent)));
		}
		/* check wildcard_child_closest_match */
		CuAssertTrue(tc, find_wc_under(db, d) ==
			d->wildcard_child_closest_match);
		/* check rrsets */
		check_rrsets(tc, d);
		/* check nsec3 */
		check_nsec3(tc, db, d);
		/* check number, and numberlist */
		CuAssertTrue(tc, d->number != 0);
		CuAssertTrue(tc, d->number <= domain_table_count(db->domains));
		CuAssertTrue(tc, numbers[d->number] == 0);
		numbers[d->number] = 1;
		/* check is_existing (has_data, DNAME, NS above) */
		if(d->rrsets) {
			CuAssertTrue(tc, d->is_existing);
		} else if(has_data_below(d)) {
			CuAssertTrue(tc, d->is_existing);
		} else {
			CuAssertTrue(tc, !d->is_existing);
		}
		/* check is_apex */
		if(d->is_apex) {
			rrset_type* soa = domain_has_rrset_plain(d, TYPE_SOA);
			if(soa) {
				CuAssertTrue(tc, soa->zone->apex == d);
			}
		}
	}
	check_numlist(tc, db->domains);
	/* add up domain usage */
	/* usage for root node (so it does not get deleted) */
	usage[db->domains->root->number]++;
	usage_for_zones(db, usage);
	for(d=db->domains->root; d; d=domain_next(d)) {
		if(d->rrsets)
			usage_for_rrsets(d->rrsets, usage);
	}
	for(d=db->domains->root; d; d=domain_next(d)) {
		/* check usage */
		if(d->usage != usage[d->number]) {
			printf("bad usage %s, have %d want %d\n",
				dname_to_string(domain_dname(d), NULL),
				(int)d->usage, (int)usage[d->number]);
		}
		CuAssertTrue(tc, d->usage == usage[d->number]);
	}
	free(numbers);
	free(usage);
}

/* check namedb invariants */
static void
check_namedb(CuTest *tc, namedb_type* db)
{
	/* check zone entries are correct for zones */
	check_walkzones(tc, db);
	/* check domaintree */
	check_walkdomains(tc, db);
}

struct parse_rr_state {
	size_t errors;
	struct region *region;
	const struct dname *owner;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength;
	uint8_t rdata[MAX_RDLENGTH];
};

/** parse a string into temporary storage */
static int32_t parse_rr_accept(
	zone_parser_t *parser,
	const zone_name_t *owner,
	uint16_t type,
	uint16_t class,
	uint32_t ttl,
	uint16_t rdlength,
	const uint8_t *rdata,
	void *user_data)
{
	struct parse_rr_state *state = (struct parse_rr_state *)user_data;

	assert(state);

	(void)parser;

	assert(state->owner == NULL);
	state->owner = dname_make(state->region, owner->octets, 1);
	assert(state->owner != NULL);
	state->type = type;
	state->class = class;
	state->ttl = ttl;
	state->rdlength = rdlength;
	memcpy(&state->rdata, rdata, rdlength);
	return 0;
}

static void parse_rr_log(
	zone_parser_t *parser,
	uint32_t category,
	const char *file,
	size_t line,
	const char *message,
	void *user_data)
{
	struct parse_rr_state *state = (struct parse_rr_state *)user_data;

	assert(state);

	(void)parser;
	(void)category;
	(void)file;
	(void)line;
	(void)message;

	assert(state->owner == NULL);
	state->errors++;
	return;
}

/* parse string into parts */
static int
parse_rr_str(struct zone *zone, char *input, struct parse_rr_state *state)
{
	int32_t code;
	size_t length;
	char *string;
	const struct dname *origin;
	zone_parser_t parser;
	zone_options_t options;
	zone_name_buffer_t name_buffer;
	zone_rdata_buffer_t rdata_buffer;
	zone_buffers_t buffers = { 1, &name_buffer, &rdata_buffer };

	/* the temp region is cleared after every RR */
	memset(&options, 0, sizeof(options));

	origin = domain_dname(zone->apex);
	options.origin.octets = dname_name(origin);
	options.origin.length = origin->name_size;
	options.no_includes = true;
	options.pretty_ttls = false;
	options.default_ttl = DEFAULT_TTL;
	options.default_class = CLASS_IN;
	options.log.callback = &parse_rr_log;
	options.accept.callback = &parse_rr_accept;

	length = strlen(input);
	string = malloc(length + 1 + ZONE_BLOCK_SIZE);
	memcpy(string, input, length);
	string[length] = 0;

	/* Parse and process all RRs.  */
	code = zone_parse_string(&parser, &options, &buffers, string, length, state);
	free(string);

	return state->errors == 0 && code == 0;
}

/** find zone in namebd from string */
static zone_type*
find_zone(namedb_type* db, char* z)
{
	region_type* t = region_create(xalloc, free);
	const dname_type* d = dname_parse(t, z);
	zone_type* zone;
	if(!d) {
		printf("cannot parse zone name %s\n", z);
		exit(1);
	}
	zone = namedb_find_zone(db, d);
	region_destroy(t);
	return zone;
}

/* add an RR from string */
static void
add_str(namedb_type* db, zone_type* zone, char* str)
{
	struct buffer buffer;
	struct parse_rr_state state;
	int softfail = 0;
	if(v) printf("add_str %s\n", str);
	memset(&state, 0, sizeof(state));
	state.region = region_create(xalloc, free);
	state.owner = NULL;
	if(!parse_rr_str(zone, str, &state)) {
		printf("cannot parse RR: %s\n", str);
		exit(1);
	}
	buffer_create_from(&buffer, state.rdata, state.rdlength);
	if(!add_RR(db, state.owner, state.type, state.class, state.ttl,
		&buffer, state.rdlength, zone, &softfail)) {
		printf("cannot add RR: %s\n", str);
		exit(1);
	}
	region_destroy(state.region);
}

/* del an RR from string */
static void
del_str(namedb_type* db, zone_type* zone, char* str)
{
	struct buffer buffer;
	struct parse_rr_state state;
	int softfail = 0;
	if(v) printf("del_str %s\n", str);
	memset(&state, 0, sizeof(state));
	state.region = region_create(xalloc, free);
	state.owner = NULL;
	if(!parse_rr_str(zone, str, &state)) {
		printf("cannot parse RR: %s\n", str);
		exit(1);
	}
	buffer_create_from(&buffer, state.rdata, state.rdlength);
	if(!delete_RR(db, state.owner, state.type, state.class,
		&buffer, state.rdlength, zone, state.region, &softfail)) {
		printf("cannot delete RR: %s\n", str);
		exit(1);
	}
	region_destroy(state.region);
}

/* test the namedb, and add, remove items from it */
static void
test_add_del(CuTest *tc, namedb_type* db)
{
	zone_type* zone = find_zone(db, "example.org");
	check_namedb(tc, db);

	/* plain record */
	add_str(db, zone, "added.example.org. IN A 1.2.3.4\n");
	check_namedb(tc, db);
	del_str(db, zone, "added.example.org. IN A 1.2.3.4\n");
	check_namedb(tc, db);

	/* rdata domain name */
	add_str(db, zone, "ns2.example.org. IN NS example.org.\n");
	check_namedb(tc, db);
	add_str(db, zone, "zoop.example.org. IN MX 5 server.example.org.\n");
	check_namedb(tc, db);
	del_str(db, zone, "zoop.example.org. IN MX 5 server.example.org.\n");
	check_namedb(tc, db);

	/* empty nonterminal */
	add_str(db, zone, "a.bb.c.d.example.org. IN A 1.2.3.4\n");
	check_namedb(tc, db);
	del_str(db, zone, "a.bb.c.d.example.org. IN A 1.2.3.4\n");
	check_namedb(tc, db);

	/* wildcard */
	add_str(db, zone, "*.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);
	del_str(db, zone, "*.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);
	/* wildcard child closest match */
	add_str(db, zone, "!.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);
	add_str(db, zone, "%.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);
	del_str(db, zone, "%.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);
	del_str(db, zone, "!.www.example.org. IN A 1.2.3.5\n");
	check_namedb(tc, db);

	/* zone apex : delete all records at apex */
	zone->is_ok = 0;
	del_str(db, zone,
		"example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
		); check_namedb(tc, db);
	del_str(db, zone,
		"example.org. IN NS ns.example.com.\n"
		); check_namedb(tc, db);
	del_str(db, zone,
		"example.org. IN NS ns2.example.com.\n"
		); check_namedb(tc, db);

	/* zone apex : add records at zone apex */
	zone->is_ok = 1;
	add_str(db, zone,
		"example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
		); check_namedb(tc, db);
	add_str(db, zone,
		"example.org. IN NS ns.example.com.\n"
		); check_namedb(tc, db);
	add_str(db, zone,
		"example.org. IN NS ns2.example.com.\n"
		); check_namedb(tc, db);

	/* zonecut: add one */
	add_str(db, zone,
		"bla.example.org. IN NS ns.bla.example.org.\n"
		); check_namedb(tc, db);
	/* zonecut: add DS and zone is signed */
	add_str(db, zone,
		"bla.example.org. IN DS 50602 8 2 FA8EE175C47325F4BD46D8A4083C3EBEB11C977D689069F2B41F1A29 B22446B1\n"
		); check_namedb(tc, db);
	/* zonecut: remove DS and zone is signed */
	del_str(db, zone,
		"bla.example.org. IN DS 50602 8 2 FA8EE175C47325F4BD46D8A4083C3EBEB11C977D689069F2B41F1A29 B22446B1\n"
		); check_namedb(tc, db);
	/* zonecut: add below */
	add_str(db, zone,
		"zoink.bla.example.org. IN A 1.2.3.7\n"
		); check_namedb(tc, db);
	add_str(db, zone,
		"ns.bla.example.org. IN A 1.2.3.8\n"
		); check_namedb(tc, db);
	/* zonecut: remove below */
	del_str(db, zone,
		"zoink.bla.example.org. IN A 1.2.3.7\n"
		); check_namedb(tc, db);
	del_str(db, zone,
		"ns.bla.example.org. IN A 1.2.3.8\n"
		); check_namedb(tc, db);
	/* zonecut: remove one */
	del_str(db, zone,
		"bla.example.org. IN NS ns.bla.example.org.\n"
		); check_namedb(tc, db);

	/* domain with multiple subdomains (count of subdomains) */
	add_str(db, zone, "lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	add_str(db, zone, "p1.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	add_str(db, zone, "p2.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	add_str(db, zone, "p3.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	del_str(db, zone, "p1.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	del_str(db, zone, "p2.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	del_str(db, zone, "p3.lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);
	del_str(db, zone, "lotso.example.org. IN TXT lotso\n");
	check_namedb(tc, db);

	zone->is_ok = 0;
	delete_zone_rrs(db, zone);
	check_namedb(tc, db);
}

static void namedb_1(CuTest *tc)
{
	region_type* region;
	namedb_type* db;
	if(v) verbosity = 3;
	else verbosity = 0;
	if(v) printf("test namedb start\n");
	region = region_create(xalloc, free);
	db = create_and_read_db(tc, region, "example.org.", 
		"example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
		"example.org. IN NS ns.example.com.\n"
		"example.org. IN NS ns2.example.com.\n"
		"wc.example.org. IN A 1.2.3.4\n"
		"*.wc.example.org. IN A 1.2.3.5\n"
		"in.*.wc.example.org. IN A 1.2.3.6\n"
		"ack.wc.example.org. IN A 1.2.3.7\n"
		"zoop.wc.example.org. IN A 1.2.3.7\n"
		"a.b.c.d.example.org. IN A 1.2.3.4\n"
		"www.example.org. IN A 1.2.3.4\n"
		"www.example.org. IN AAAA ::1\n"
		"deleg.example.org. IN NS ns.deleg.example.org.\n"
		"deleg.example.org. IN NS extns.example.org.\n"
		"ns.deleg.example.org. IN A 1.2.3.8\n"
		"dname.example.org. IN DNAME foo.com.\n"
		"obscured.dname.example.org. IN A 1.2.3.9\n"
		"server.example.org. IN A 1.2.3.10\n"
		"example.org. IN MX 50 server.example.org.\n"
		"extns.example.org. IN A 1.2.3.11\n"
		"nonmx.example.org. IN MX 100 blabla.nonmx.example.org.\n"
	);

	/* test it */
	test_add_del(tc, db);

	if(v) printf("test namedb end\n");
	namedb_close(db);
	region_destroy(region);
}

static void
test_add_del_2(CuTest *tc, namedb_type* db)
{
	zone_type* zone = find_zone(db, "example.org");
	check_namedb(tc, db);
	zone->is_ok = 0;

	del_str(db, zone, "example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n");
	check_namedb(tc, db);
	del_str(db, zone, "example.org. IN NS ns.example.com.\n");
	check_namedb(tc, db);
	del_str(db, zone, "example.org. IN NS ns2.example.com.\n");
	check_namedb(tc, db);
	/* the root has not been deleted */
	CuAssertTrue(tc, domain_table_count(db->domains) != 0);
	CuAssertTrue(tc, db->domains->root && db->domains->root->number);
}

/* test _2 : check that root is not deleted */
static void namedb_2(CuTest *tc)
{
	region_type* region;
	namedb_type* db;
	if(v) printf("test 2 namedb start\n");
	region = region_create(xalloc, free);
	db = create_and_read_db(tc, region, "example.org.", 
		"example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
		"example.org. IN NS ns.example.com.\n"
		"example.org. IN NS ns2.example.com.\n"
	);
	test_add_del_2(tc, db);
	if(v) printf("test 2 namedb end\n");
	namedb_close(db);
	region_destroy(region);
}

#ifdef NSEC3
/* test the namedb, and add, remove items from it */
static void
test_add_del_3(CuTest *tc, namedb_type* db)
{
	zone_type* zone = find_zone(db, "example.org");
	check_namedb(tc, db);

	/* plain record */
	add_str(db, zone, "added.example.org. IN A 1.2.3.4\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "added.example.org. IN A 1.2.3.4\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* rdata domain name */
	add_str(db, zone, "ns2.example.org. IN NS example.org.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "zoop.example.org. IN MX 5 server.example.org.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "zoop.example.org. IN MX 5 server.example.org.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* empty nonterminal */
	add_str(db, zone, "a.bb.c.d.example.org. IN A 1.2.3.4\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "a.bb.c.d.example.org. IN A 1.2.3.4\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* wildcard */
	add_str(db, zone, "*.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "*.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* wildcard child closest match */
	add_str(db, zone, "!.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "%.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "%.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "!.www.example.org. IN A 1.2.3.5\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* zone apex : delete all records at apex */
	zone->is_ok = 0;
	del_str(db, zone,
		"example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
		);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "example.org. IN NS ns.example.com.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "example.org. IN NS ns2.example.com.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* zone apex : add records at zone apex */
	zone->is_ok = 1;
	add_str(db, zone, "example.org. IN SOA ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "example.org. IN NS ns.example.com.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "example.org. IN NS ns2.example.com.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* zonecut: add one */
	add_str(db, zone, "bla.example.org. IN NS ns.bla.example.org.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* zonecut: add DS and zone is signed */
	add_str(db, zone, "bla.example.org. IN DS 50602 8 2 FA8EE175C47325F4BD46D8A4083C3EBEB11C977D689069F2B41F1A29 B22446B1\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* zonecut: remove DS and zone is signed */
	del_str(db, zone, "bla.example.org. IN DS 50602 8 2 FA8EE175C47325F4BD46D8A4083C3EBEB11C977D689069F2B41F1A29 B22446B1\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* zonecut: add below */
	add_str(db, zone, "zoink.bla.example.org. IN A 1.2.3.7\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "ns.bla.example.org. IN A 1.2.3.8\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* zonecut: remove below */
	del_str(db, zone, "zoink.bla.example.org. IN A 1.2.3.7\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "ns.bla.example.org. IN A 1.2.3.8\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* zonecut: remove one */
	del_str(db, zone, "bla.example.org. IN NS ns.bla.example.org.\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* domain with multiple subdomains (count of subdomains) */
	add_str(db, zone, "lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "p1.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "p2.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone, "p3.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "p1.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "p2.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "p3.lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone, "lotso.example.org. IN TXT lotso\n");
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* remove last NSEC3 in chain and then add it again */
	del_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* remove last NSEC3 and add it again, other order */
	del_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* remove a domain and its NSEC3, first in one order then the other */
	del_str(db, zone,
"server.example.org.	3600	IN	A	1.2.3.10\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"server.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. WW+TqIl0EO9lRvKl72iySFxn112KSzZfdYCKD3P34PEvExZ0MxAdgGhnpJH5Styv5i8c7uo2qIVQ/zVCcg9OwQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add domain and its nsec3 again */
	add_str(db, zone,
"server.example.org.	3600	IN	A	1.2.3.10\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"server.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. WW+TqIl0EO9lRvKl72iySFxn112KSzZfdYCKD3P34PEvExZ0MxAdgGhnpJH5Styv5i8c7uo2qIVQ/zVCcg9OwQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* and remove domain and its nsec3 in other order */
	del_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"server.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. WW+TqIl0EO9lRvKl72iySFxn112KSzZfdYCKD3P34PEvExZ0MxAdgGhnpJH5Styv5i8c7uo2qIVQ/zVCcg9OwQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"server.example.org.	3600	IN	A	1.2.3.10\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add domain and its nsec3 again, in other order */
	add_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"server.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. WW+TqIl0EO9lRvKl72iySFxn112KSzZfdYCKD3P34PEvExZ0MxAdgGhnpJH5Styv5i8c7uo2qIVQ/zVCcg9OwQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"server.example.org.	3600	IN	A	1.2.3.10\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* add and remove the wildcard and its NSEC3 record, first one order
	 * then another order */
	del_str(db, zone,
"*.wc.example.org.	3600	IN	A	1.2.3.5\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"*.wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. fuCdRkvOSUgFuItIsYB51hzuBBDGpWJk4ICZcPrHcEZaZvmiixUbTYDoECb+oGGrsU34Si3QkIAhmUgjNn3WQA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add wildcard and its NSEC3 */
	add_str(db, zone,
"*.wc.example.org.	3600	IN	A	1.2.3.5\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"*.wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. fuCdRkvOSUgFuItIsYB51hzuBBDGpWJk4ICZcPrHcEZaZvmiixUbTYDoECb+oGGrsU34Si3QkIAhmUgjNn3WQA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* and remove wildcard and nsec3 in another order */
	del_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"*.wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. fuCdRkvOSUgFuItIsYB51hzuBBDGpWJk4ICZcPrHcEZaZvmiixUbTYDoECb+oGGrsU34Si3QkIAhmUgjNn3WQA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"*.wc.example.org.	3600	IN	A	1.2.3.5\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add wildcard and its NSEC3 */
	add_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"*.wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. fuCdRkvOSUgFuItIsYB51hzuBBDGpWJk4ICZcPrHcEZaZvmiixUbTYDoECb+oGGrsU34Si3QkIAhmUgjNn3WQA== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"*.wc.example.org.	3600	IN	A	1.2.3.5\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* delete delegation and its NSEC3, then add again, and other order */
	del_str(db, zone,
"deleg.example.org.	3600	IN	NS	ns.deleg.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"deleg.example.org.	3600	IN	NS	extns.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add delegation and nsec3 again */
	add_str(db, zone,
"deleg.example.org.	3600	IN	NS	ns.deleg.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"deleg.example.org.	3600	IN	NS	extns.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* remove delegation and nsec3 other order */
	del_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"deleg.example.org.	3600	IN	NS	extns.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"deleg.example.org.	3600	IN	NS	ns.deleg.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add delegation and nsec3 again */
	add_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"deleg.example.org.	3600	IN	NS	extns.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"deleg.example.org.	3600	IN	NS	ns.deleg.example.org.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* remove and add DNAME and nsec3. and then in another order */
	del_str(db, zone,
"dname.example.org.	3600	IN	DNAME	foo.com.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"dname.example.org.	3600	IN	RRSIG	DNAME 5 3 3600 20110519131330 20110421131330 30899 example.org. EsNccft58pZ0Toi+nX5E/cedeFPxLi+wD1QqP94+jjJwLPl5D959sr21qB164D3pg/DzumNZWHr7y8T7n6xz/Q== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add DNAME and nsec3 */
	add_str(db, zone,
"dname.example.org.	3600	IN	DNAME	foo.com.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"dname.example.org.	3600	IN	RRSIG	DNAME 5 3 3600 20110519131330 20110421131330 30899 example.org. EsNccft58pZ0Toi+nX5E/cedeFPxLi+wD1QqP94+jjJwLPl5D959sr21qB164D3pg/DzumNZWHr7y8T7n6xz/Q== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* remove and add DNAME and nsec3 in another order */
	del_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"dname.example.org.	3600	IN	RRSIG	DNAME 5 3 3600 20110519131330 20110421131330 30899 example.org. EsNccft58pZ0Toi+nX5E/cedeFPxLi+wD1QqP94+jjJwLPl5D959sr21qB164D3pg/DzumNZWHr7y8T7n6xz/Q== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
"dname.example.org.	3600	IN	DNAME	foo.com.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	/* add DNAME and nsec3 */
	add_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"dname.example.org.	3600	IN	RRSIG	DNAME 5 3 3600 20110519131330 20110421131330 30899 example.org. EsNccft58pZ0Toi+nX5E/cedeFPxLi+wD1QqP94+jjJwLPl5D959sr21qB164D3pg/DzumNZWHr7y8T7n6xz/Q== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
"dname.example.org.	3600	IN	DNAME	foo.com.\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);


	zone->is_ok = 0;
	delete_zone_rrs(db, zone);
	nsec3_clear_precompile(db, zone);
	zone->nsec3_param = NULL;
	prehash_zone(db, zone);
	check_namedb(tc, db);
}

static const char* nsec3zone_txt =
"example.org.	3600	IN	SOA	ns.example.org. hostmaster.example.org. 2011041200 28800 7200 604800 3600\n"
"example.org.	3600	IN	RRSIG	SOA 5 2 3600 20110519131330 20110421131330 30899 example.org. Fg0LEhpORA2Fzu6oMIXq9lBXPX0ZeClmPTA3ZCbWmL+0stifiXI0ShmCnKtuTKUdeKDKPN/OWjjlu1O7eB5+Fg== ;{id = 30899}\n"

"example.org.	3600	IN	NS	ns.example.com.\n"
"example.org.	3600	IN	NS	ns2.example.com.\n"
"example.org.	3600	IN	RRSIG	NS 5 2 3600 20110519131330 20110421131330 30899 example.org. qsPN/jGXykOImnI0tI/HXYjm7K6kiZeYZut4mep5gbC2tugWewwdASwodF4Goi/uaNPXRLboM2wPLvafq93y0A== ;{id = 30899}\n"
"example.org.	3600	IN	MX	50 server.example.org.\n"
"example.org.	3600	IN	RRSIG	MX 5 2 3600 20110519131330 20110421131330 30899 example.org. qp/vKi2WEx9CWsT3LW62PAqA0UNjR/pn+frvdd2YinOQOlbumsY0jmYm8nrBUal1q50wGjLVQE2k6A6nXvxPJw== ;{id = 30899}\n"
"example.org.	3600	IN	DNSKEY	256 3 5 AQPQ41chR9DEHt/aIzIFAqanbDlRflJoRs5yz1jFsoRIT7dWf0r+PeDuewdxkszNH6wnU4QL8pfKFRh5PIYVBLK3 ;{id = 30899 (zsk), size = 512b}\n"
"example.org.	3600	IN	RRSIG	DNSKEY 5 2 3600 20110519131330 20110421131330 30899 example.org. CKMEbL7UyUB/qjPyFt74jZM41M0i/NAxw9w/lN0y/JkTKiD1LxTqbcWs3dhqIW/p9tBBksS4E5KSl87tHhNoMA== ;{id = 30899}\n"
"example.org.	3600	IN	NSEC3PARAM	1 0 1 1234 \n"
"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. THFhaMtVP25A31/aGJ7wU2GAMSuJrGCB5vkTZnmIelpQQ7j/uVDuFQRB73Zr87owwP8l02Aqf71iFA3LSdpEyQ== ;{id = 30899}\n"
"86er3qr3ol0n6a0drbbffrcdk1ops77n.example.org.	3600	IN	NSEC3	1 0 1 1234  9cq8bno9lfqsbbm51irbq5tb43fl0ls2 NS SOA MX RRSIG DNSKEY NSEC3PARAM \n"
"86er3qr3ol0n6a0drbbffrcdk1ops77n.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. s7D3UlAohE5hGs0ytWIqxND+ulpPwFfvdla874/qtDV+/hD57nShFgcP5pIc/J3e8lu0jPbdBnBdI1Tw1WKAqA== ;{id = 30899}\n"

/* ;; Empty nonterminal: d.example.org. */
"bll46u32m32oetik7pcgfcuss7n5pqql.example.org.	3600	IN	NSEC3	1 0 1 1234  eki8ig6abn9vbk8tk6m6vou9me8l1o7c\n"
"bll46u32m32oetik7pcgfcuss7n5pqql.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. bYuCl2N/AoyzBn9IaVBgg9JGjeeczWabxFeL0wGwSrtzbndnd+Ow/6R1Rwx10YtCqe84el3YljRdD2kArUynRA== ;{id = 30899}\n"

/* ;; Empty nonterminal: c.d.example.org. */
"eki8ig6abn9vbk8tk6m6vou9me8l1o7c.example.org.	3600	IN	NSEC3	1 0 1 1234  g1hcjueqjvfi7f48f5gbncll68nqj0it\n"
"eki8ig6abn9vbk8tk6m6vou9me8l1o7c.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. GyopIM3UdbBaVQbm81aiaxqXkR5RTdQ80Wo/PewmUEWFb2JKL0Qp16DT6yBcSckuzWZveFVUoGhiJir7Pyj9yQ== ;{id = 30899}\n"

/* ;; Empty nonterminal: b.c.d.example.org. */
"gtitidhf26une8fj2t3eaj47qf8tbuci.example.org.	3600	IN	NSEC3	1 0 1 1234  jdup4m0edbcmtb7g5utvc2hgnees76us\n"
"gtitidhf26une8fj2t3eaj47qf8tbuci.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. o+apZPI/6FaODE93OhtP6bf3E52OUzkwO4+oeU17MR300N5BRm+VFUyXNEGIFMy8RrSshnoozcZzkDOFx/Lk2g== ;{id = 30899}\n"

"a.b.c.d.example.org.	3600	IN	A	1.2.3.4\n"
"a.b.c.d.example.org.	3600	IN	RRSIG	A 5 6 3600 20110519131330 20110421131330 30899 example.org. F8RNDwe6JEn1QvfI0ZQgIvkDkomhWW2zwVZNNcT7XT1IjJ2V7g5kOoJpONRMPwXnNWrGVZ5O9cmT8SjcMdkmKA== ;{id = 30899}\n"
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n"
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n"

"deleg.example.org.	3600	IN	NS	ns.deleg.example.org.\n"
"deleg.example.org.	3600	IN	NS	extns.example.org.\n"
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n"
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n"

"ns.deleg.example.org.	3600	IN	A	1.2.3.8\n"

"dname.example.org.	3600	IN	DNAME	foo.com.\n"
"dname.example.org.	3600	IN	RRSIG	DNAME 5 3 3600 20110519131330 20110421131330 30899 example.org. EsNccft58pZ0Toi+nX5E/cedeFPxLi+wD1QqP94+jjJwLPl5D959sr21qB164D3pg/DzumNZWHr7y8T7n6xz/Q== ;{id = 30899}\n"
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n"
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n"

"obscured.dname.example.org.	3600	IN	A	1.2.3.9\n"
"obscured.dname.example.org.	3600	IN	RRSIG	A 5 4 3600 20110519131330 20110421131330 30899 example.org. SjDOiiDHHewmWobaj67+pVtinlq+Xe+N7ez5TXyBSG7hsa7IrbrDStpE/E09DSbM4sl6FVRRC+/XxEnB+Xaa3w== ;{id = 30899}\n"
"q5f9fvlq89hnof4sbp3uum6233pt6ofi.example.org.	3600	IN	NSEC3	1 0 1 1234  seag98uuge9jk9ejdnml5dqvc32aa1ec A RRSIG \n"
"q5f9fvlq89hnof4sbp3uum6233pt6ofi.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wa8hbTLIkt8uOIbDFwYra3xbInTbx4QcyOPC9fPVGa1zvhemy86V2XiJB1vcmaGYXr9832cwT3e/11HR+VVakg== ;{id = 30899}\n"

"extns.example.org.	3600	IN	A	1.2.3.11\n"
"extns.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. hzN9o8Um03XlobeFoWn9YsiKpUllLEZbINXYFvKi9GOBK5LY6V8HsvXA1Jx0rTqG/iAuutQnBOmab65XCnY4YA== ;{id = 30899}\n"
"seag98uuge9jk9ejdnml5dqvc32aa1ec.example.org.	3600	IN	NSEC3	1 0 1 1234  t46dlvjh87nm2smr9tshdappe8c6uolu A RRSIG \n"
"seag98uuge9jk9ejdnml5dqvc32aa1ec.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. fCdz7ttJcgc+Kxs+AVAxvBvMidYojTMQdl4n9/ixcLt68LhaF4MyActctDXL4+dKDUaJF/IlMluWdzys6J5RFg== ;{id = 30899}\n"

"nonmx.example.org.	3600	IN	MX	100 blabla.nonmx.example.org.\n"
"nonmx.example.org.	3600	IN	RRSIG	MX 5 3 3600 20110519131330 20110421131330 30899 example.org. Qqao4EPjDXbeBBToFOKZq4wSV0IerSA6FIDk4ZZP6yRradR9p9NgkeUga91tbwu7qBm6XXKOZFT/5eTyThyxnw== ;{id = 30899}\n"
"3o3tqldra9tgt2e01ikvc1f5r7qjct5q.example.org.	3600	IN	NSEC3	1 0 1 1234  86er3qr3ol0n6a0drbbffrcdk1ops77n MX RRSIG \n"
"3o3tqldra9tgt2e01ikvc1f5r7qjct5q.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q/KEK/BUxv8O9WG5i0FKDnvwc03GTp7Gq1jcHgr6lqvYEJLSTwtgDDGF1JXgvjaUqobLYEilZoCUYYMZh0SAPw== ;{id = 30899}\n"

"server.example.org.	3600	IN	A	1.2.3.10\n"
"server.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. WW+TqIl0EO9lRvKl72iySFxn112KSzZfdYCKD3P34PEvExZ0MxAdgGhnpJH5Styv5i8c7uo2qIVQ/zVCcg9OwQ== ;{id = 30899}\n"
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n"
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n"

"wc.example.org.	3600	IN	A	1.2.3.4\n"
"wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. GNC/gH++k4Huk8/vK9ftl7bP4JzHbELZdwiRrgHM4FbgGPocfKac3fY+5BqDXX7Qk4bGI1f7fVBCuxKzkAYH9w== ;{id = 30899}\n"
"jdup4m0edbcmtb7g5utvc2hgnees76us.example.org.	3600	IN	NSEC3	1 0 1 1234  lrckab0ombfgqe8944cpph33vvf1q3ss A RRSIG \n"
"jdup4m0edbcmtb7g5utvc2hgnees76us.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. ezk3rhdKfJ44Hw25Jh3J0Q4rRSt2PxnSzdgNoiapFW6dg9TWbAx4J3al0ioPRWveUHDCLkCEnldPATCSyu0Xrw== ;{id = 30899}\n"

"*.wc.example.org.	3600	IN	A	1.2.3.5\n"
"*.wc.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. fuCdRkvOSUgFuItIsYB51hzuBBDGpWJk4ICZcPrHcEZaZvmiixUbTYDoECb+oGGrsU34Si3QkIAhmUgjNn3WQA== ;{id = 30899}\n"
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n"
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n"

"in.*.wc.example.org.	3600	IN	A	1.2.3.6\n"
"in.*.wc.example.org.	3600	IN	RRSIG	A 5 5 3600 20110519131330 20110421131330 30899 example.org. WdZebq9ceA3jj9a19UQpy2mJfZjiTvZFf6ugPIrph/dF2KGSJn8IWjKisZLHS2eSQxjlsJjQbGRmiJAsLcCGbg== ;{id = 30899}\n"
"an5c8h70kkk482f35kojaluuvp2k4al7.example.org.	3600	IN	NSEC3	1 0 1 1234  atnd4lu4hk3nfigk82orjqu8qbdlu4gn A RRSIG \n"
"an5c8h70kkk482f35kojaluuvp2k4al7.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. uJB7yf+hWyM55S5bPBJNPFNsinu3//58VfbkJJESLgGiGTcFa68rjrBbCkVfueGeEy+/xk20avO8Ggzkqpx8rQ== ;{id = 30899}\n"

"ack.wc.example.org.	3600	IN	A	1.2.3.7\n"
"ack.wc.example.org.	3600	IN	RRSIG	A 5 4 3600 20110519131330 20110421131330 30899 example.org. SJchZpWSdZfMqR2PFK5vIfxnZNXGp0HPRllnIs5MFqAGOTcY7bNm8ktUA1QjN/up/m5Xq8Ns7Ggkk1kL9mQUjw== ;{id = 30899}\n"
"lrckab0ombfgqe8944cpph33vvf1q3ss.example.org.	3600	IN	NSEC3	1 0 1 1234  o334hngponsojfvecb16ef11pluqci6c A RRSIG \n"
"lrckab0ombfgqe8944cpph33vvf1q3ss.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. n9QXqq1+flcrkvCmsoEKEkMt24gEuhpQSFUms/oFFP2++ppll/ydWhUsbY35TfOsI8XAin4sxfOl0ImdQVNJeg== ;{id = 30899}\n"

"zoop.wc.example.org.	3600	IN	A	1.2.3.7\n"
"zoop.wc.example.org.	3600	IN	RRSIG	A 5 4 3600 20110519131330 20110421131330 30899 example.org. gdeAgDTDjClNZ1aO/2AIWHj3wzdOCX777sCHPs97NbR3VgOyAiLbDXCJBIF3eut6nqSG4vvLeyXkPkNFQONp2w== ;{id = 30899}\n"
"atnd4lu4hk3nfigk82orjqu8qbdlu4gn.example.org.	3600	IN	NSEC3	1 0 1 1234  bll46u32m32oetik7pcgfcuss7n5pqql A RRSIG \n"
"atnd4lu4hk3nfigk82orjqu8qbdlu4gn.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. J4VWXjkJBv4UXqze1uRyHRT98vqGn8WJ7jm08zdrhbNZ8McRZxqFSjcyqbM0exq6ZM6ceQeap69eJ50TRHqXtw== ;{id = 30899}\n"

"www.example.org.	3600	IN	A	1.2.3.4\n"
"www.example.org.	3600	IN	RRSIG	A 5 3 3600 20110519131330 20110421131330 30899 example.org. GpbkkEsKRDgX7ftDEC0SAvacA6ogYsx5BFBu3PUCty19KWgZCd5LzEF0ADRTQN3fVA5Fk8PECRN+do8xdSeSzQ== ;{id = 30899}\n"
"www.example.org.	3600	IN	AAAA	::1\n"
"www.example.org.	3600	IN	RRSIG	AAAA 5 3 3600 20110519131330 20110421131330 30899 example.org. MuQiC1ajdIRkYCsMxyH520Y/gtOxUdc8Gkson+q2KRarfEb6rQckVX3W+8uLyu0bTpxEUFJVSXTblkdH+yJZ7A== ;{id = 30899}\n"
"o334hngponsojfvecb16ef11pluqci6c.example.org.	3600	IN	NSEC3	1 0 1 1234  os1tu4plekke6t993674mq6j79d73fdo A AAAA RRSIG \n"
"o334hngponsojfvecb16ef11pluqci6c.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. T/8XSAGtKBcPh2FfsT9qQyen8S2InP+GM/JLULxmZbQTJyRVX4Zoy+pVlAPv2FyiTcYVgjXCv4XF6ewvwqNRtw== ;{id = 30899}\n"
;
	
static void namedb_3(CuTest *tc)
{
	/* test _3 : check NSEC3 precompile, same as _1 but nsec3signed */
	region_type* region;
	namedb_type* db;
	if(v) verbosity = 3;
	else verbosity = 0;
	if(v) printf("test namedb start\n");
	region = region_create(xalloc, free);
	db = create_and_read_db(tc, region, "example.org.", nsec3zone_txt);

	/* test it */
	test_add_del_3(tc, db);

	if(v) printf("test namedb end\n");
	namedb_close(db);
	region_destroy(region);
}

/* test the namedb, and add, remove items from it */
static void
test_add_del_4(CuTest *tc, namedb_type* db)
{
	zone_type* zone = find_zone(db, "example.org");
	int i;
	/* the new nsec3 chain */
	char* new_nsec3s[] = {
"f37m7fketcp72terievrl57uqvohm1g2.example.org.	3600	IN	NSEC3	1 0 2 5678  i4ifdmtv5t3tulghb2k8bvdspt66bbju NS SOA MX RRSIG DNSKEY NSEC3PARAM \n",
"f37m7fketcp72terievrl57uqvohm1g2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. D31eXABfTEFMQuHsTGKO6JgwmAm49QH/E66GpTIjfAJwxCl9oCKX4kKtgV9zeiUlFMKGIGkEZVW9sZ6pcbOoCw== ;{id = 30899}\n",
"i8ger853h8dunu9h2bun3k63ehgiigiq.example.org.	3600	IN	NSEC3	1 0 2 5678  nfbovj2t4827jeadfr7rchdta9lenibs\n",
"i8ger853h8dunu9h2bun3k63ehgiigiq.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. d5LnSScXd3oHUvsSa0ZNXDP8Ok83GniYUQbrk2edtDvC3Tb/ibB2DQ/c0MYTSUK69bzW2c+IQdbhl9nRTTihLQ== ;{id = 30899}\n",
"nfbovj2t4827jeadfr7rchdta9lenibs.example.org.	3600	IN	NSEC3	1 0 2 5678  p3mligj7o6v67g7r1at5i9pir89it2ko\n",
"nfbovj2t4827jeadfr7rchdta9lenibs.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. fwm9vTCrMNQ+CuVAb1eJX0lNrxzfMIGH+V/wGguKD9PCu5JWkZVEKL1j65+aDUe+B4F8VuQdDkaV1xHYuaOptA== ;{id = 30899}\n",
"5v48cpnjqh2p2593hgpk4ibr499fgd22.example.org.	3600	IN	NSEC3	1 0 2 5678  64j95h195ncae4hqt4i0gc52l4ps9h3c\n",
"5v48cpnjqh2p2593hgpk4ibr499fgd22.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. tvvxBACLqoL00AdBlaeCZJrGgZuA4LGjDn5yv3NXPPLzFiZmc+LpB5LZFu++k6NAK5gCoJ+rn+M0za7/fH2sHA== ;{id = 30899}\n",
"67kq04off3kphm2f4caes2cuo0lj7577.example.org.	3600	IN	NSEC3	1 0 2 5678  7ef49r8su1kopup7pjqfpdfo2pnb0aqe A RRSIG \n",
"67kq04off3kphm2f4caes2cuo0lj7577.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. xURGs6qZzWonvrIHrKX2pYbumgWE9SOHrCdaP2aRKv47US7EGakQvV9iq9/AhkCA9+SPBVuUMfg9lr9WkYgPOQ== ;{id = 30899}\n",
"dqsfade7eimicd6fb35t4ug23v16oo6n.example.org.	3600	IN	NSEC3	1 0 2 5678  f37m7fketcp72terievrl57uqvohm1g2 NS \n",
"dqsfade7eimicd6fb35t4ug23v16oo6n.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. S9TYpxd6i2N7GlsoSNMJ/paMFPOBxUptk90PMCAH1qb6bHe4HJDseL1aXC/LvLKwnm2wcYWkp3kW0FQeG2fyCQ== ;{id = 30899}\n",
"b5k1hrvanin9qddessltceea62uib27b.example.org.	3600	IN	NSEC3	1 0 2 5678  dqsfade7eimicd6fb35t4ug23v16oo6n DNAME RRSIG \n",
"b5k1hrvanin9qddessltceea62uib27b.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. LqjNTNhMCp6ZomnyQcuE60S3cz8wOacajb0ShXXmbLxSU7R5oxM+25waAR4TlKVX0fhT54M+Tz3agVasdqRUmg== ;{id = 30899}\n",
"qial0cb6uo37ajrfd47qphv57snfluar.example.org.	3600	IN	NSEC3	1 0 2 5678  ueovdcqshbnsbt6bg8prbdoo0je03l1m A RRSIG \n",
"qial0cb6uo37ajrfd47qphv57snfluar.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. VBXhsLX0L7dFDf9x7qppD/KKxQINSs4iN8dbxdH39oEof2NdAtwURdGJcQ6mlnXbCoIXtAM83A4zt4dxrTM7NA== ;{id = 30899}\n",
"5d1n99t0t8nj1nqgapiihqbc705v83ad.example.org.	3600	IN	NSEC3	1 0 2 5678  5v48cpnjqh2p2593hgpk4ibr499fgd22 A RRSIG \n",
"5d1n99t0t8nj1nqgapiihqbc705v83ad.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. RQy+T0o8SrXFqxMI3XP/1xlk7ESSUhIf7vo9tm4y25vp6O/7rOjhQhYdo3laiStwe/rI2EnUC6KTux/qR5wuBg== ;{id = 30899}\n",
"7ef49r8su1kopup7pjqfpdfo2pnb0aqe.example.org.	3600	IN	NSEC3	1 0 2 5678  9t70p1mvin2c4lj56i0bbjqrolcmpprn MX RRSIG \n",
"7ef49r8su1kopup7pjqfpdfo2pnb0aqe.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. vODMAJN9uKt4pxBjp+A9YdHipB4p09+q3Bj4iix/7z1/YREwYPz9rXUDKsIC32XTSrhOoKIXr4vDTBw4HA/Qxg== ;{id = 30899}\n",
"03pnll4hfvr5linnqeq0tfkhsjiuph1a.example.org.	3600	IN	NSEC3	1 0 2 5678  5d1n99t0t8nj1nqgapiihqbc705v83ad A RRSIG \n",
"03pnll4hfvr5linnqeq0tfkhsjiuph1a.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. CATNsZBAQAVYTpclghI7O3zYv08SwkwblCD2FaKTufUGgbGs75KUtHd8y63CtezqvVI8ehv4LiGDCaxpjnwgBw== ;{id = 30899}\n",
"p3mligj7o6v67g7r1at5i9pir89it2ko.example.org.	3600	IN	NSEC3	1 0 2 5678  q0ut57q04fj4csfov6obtgd09qca5hgv A RRSIG \n",
"p3mligj7o6v67g7r1at5i9pir89it2ko.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. mrcTNHxvv60yA4WzMODcqHoZp/9TEusroImXomIWmZSLZcfX8YvjHHXf1Kd4aujKVRFLu9LK0BUZxScyvekStA== ;{id = 30899}\n",
"i4ifdmtv5t3tulghb2k8bvdspt66bbju.example.org.	3600	IN	NSEC3	1 0 2 5678  i8ger853h8dunu9h2bun3k63ehgiigiq A RRSIG \n",
"i4ifdmtv5t3tulghb2k8bvdspt66bbju.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Brklo7nrnA6XVvTdyDQkiH6MeF+ubrY5pDLS6BiAqQZrYPACW2sQEByPMB0iatVQmes0XkP5umbdjDnjAp+nsg== ;{id = 30899}\n",
"64j95h195ncae4hqt4i0gc52l4ps9h3c.example.org.	3600	IN	NSEC3	1 0 2 5678  67kq04off3kphm2f4caes2cuo0lj7577 A RRSIG \n",
"64j95h195ncae4hqt4i0gc52l4ps9h3c.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. pwsO3dvzHTXJ/pX1LKZQ4VxrNFz39esET+6k+k6Z3mMfFj7Y9qqR5Jf65U1T23knlFFe51m1jakbAKUXK646uA== ;{id = 30899}\n",
"ueovdcqshbnsbt6bg8prbdoo0je03l1m.example.org.	3600	IN	NSEC3	1 0 2 5678  03pnll4hfvr5linnqeq0tfkhsjiuph1a A RRSIG \n",
"ueovdcqshbnsbt6bg8prbdoo0je03l1m.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. rkwo9R8L8YkG+VfMLA4UZdR4q/aenV9GP8Zn+JvbOoI8UVzFdVovwlA3rLzg3hVT9FgbEh61l/gBWWKY7/ZkJg== ;{id = 30899}\n",
"9t70p1mvin2c4lj56i0bbjqrolcmpprn.example.org.	3600	IN	NSEC3	1 0 2 5678  b5k1hrvanin9qddessltceea62uib27b A RRSIG \n",
"9t70p1mvin2c4lj56i0bbjqrolcmpprn.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. KnKK/xMOoSaKne1B/M9mZ7SerN4tfO5GB5Y+TnIkmSq7ouxdmRoa5sqEgRlievIC+LvI/aSWnW2kPlj5bzzC6Q== ;{id = 30899}\n",
"q0ut57q04fj4csfov6obtgd09qca5hgv.example.org.	3600	IN	NSEC3	1 0 2 5678  qial0cb6uo37ajrfd47qphv57snfluar A AAAA RRSIG \n",
"q0ut57q04fj4csfov6obtgd09qca5hgv.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. iJJm547x4fdbsDI3+R/0ZG9jnqmdtpVKHNjx6Fk+g5PZqPcqBDIdM1d/F1X7hB2hl4tnosPgZBQymPyErVa8Fw== ;{id = 30899}\n",
		NULL
	};
	/* the old nsec3 chain */
	char* old_nsec3s[] = {
"86er3qr3ol0n6a0drbbffrcdk1ops77n.example.org.	3600	IN	NSEC3	1 0 1 1234  9cq8bno9lfqsbbm51irbq5tb43fl0ls2 NS SOA MX RRSIG DNSKEY NSEC3PARAM \n",
"86er3qr3ol0n6a0drbbffrcdk1ops77n.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. s7D3UlAohE5hGs0ytWIqxND+ulpPwFfvdla874/qtDV+/hD57nShFgcP5pIc/J3e8lu0jPbdBnBdI1Tw1WKAqA== ;{id = 30899}\n",
"bll46u32m32oetik7pcgfcuss7n5pqql.example.org.	3600	IN	NSEC3	1 0 1 1234  eki8ig6abn9vbk8tk6m6vou9me8l1o7c\n",
"bll46u32m32oetik7pcgfcuss7n5pqql.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. bYuCl2N/AoyzBn9IaVBgg9JGjeeczWabxFeL0wGwSrtzbndnd+Ow/6R1Rwx10YtCqe84el3YljRdD2kArUynRA== ;{id = 30899}\n",
"eki8ig6abn9vbk8tk6m6vou9me8l1o7c.example.org.	3600	IN	NSEC3	1 0 1 1234  g1hcjueqjvfi7f48f5gbncll68nqj0it\n",
"eki8ig6abn9vbk8tk6m6vou9me8l1o7c.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. GyopIM3UdbBaVQbm81aiaxqXkR5RTdQ80Wo/PewmUEWFb2JKL0Qp16DT6yBcSckuzWZveFVUoGhiJir7Pyj9yQ== ;{id = 30899}\n",
"gtitidhf26une8fj2t3eaj47qf8tbuci.example.org.	3600	IN	NSEC3	1 0 1 1234  jdup4m0edbcmtb7g5utvc2hgnees76us\n",
"gtitidhf26une8fj2t3eaj47qf8tbuci.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. o+apZPI/6FaODE93OhtP6bf3E52OUzkwO4+oeU17MR300N5BRm+VFUyXNEGIFMy8RrSshnoozcZzkDOFx/Lk2g== ;{id = 30899}\n",
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	NSEC3	1 0 1 1234  1t1dk1m24102gngs9umpl1s4euti62js A RRSIG \n",
"t46dlvjh87nm2smr9tshdappe8c6uolu.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wzLORHkPVDVVi51HUInYoKgPdnc8+RtVLPcUv1L8EzD6rk7CtI9JEotWlc9az7p07/qAaOc+KpTlckB16KEsEw== ;{id = 30899}\n",
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	NSEC3	1 0 1 1234  q5f9fvlq89hnof4sbp3uum6233pt6ofi NS \n",
"os1tu4plekke6t993674mq6j79d73fdo.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. zBc4ePB0UmbDRt1NJElooHV5KPFxjZkKq641PonOJdtKp5OIV3bklK/DwXM2MTMa5vzUC+X8h/ePBkyg/7FBzw== ;{id = 30899}\n",
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	NSEC3	1 0 1 1234  an5c8h70kkk482f35kojaluuvp2k4al7 DNAME RRSIG \n",
"9cq8bno9lfqsbbm51irbq5tb43fl0ls2.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q6NNfU7UHLFG5ZPlbkPc53M4cAbZh3AxF6qDBKxah0cZd6kpGfRm9myZor0HUAW+XnQuHt96yfZe9M/adH7CXg== ;{id = 30899}\n",
"q5f9fvlq89hnof4sbp3uum6233pt6ofi.example.org.	3600	IN	NSEC3	1 0 1 1234  seag98uuge9jk9ejdnml5dqvc32aa1ec A RRSIG \n",
"q5f9fvlq89hnof4sbp3uum6233pt6ofi.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wa8hbTLIkt8uOIbDFwYra3xbInTbx4QcyOPC9fPVGa1zvhemy86V2XiJB1vcmaGYXr9832cwT3e/11HR+VVakg== ;{id = 30899}\n",
"seag98uuge9jk9ejdnml5dqvc32aa1ec.example.org.	3600	IN	NSEC3	1 0 1 1234  t46dlvjh87nm2smr9tshdappe8c6uolu A RRSIG \n",
"seag98uuge9jk9ejdnml5dqvc32aa1ec.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. fCdz7ttJcgc+Kxs+AVAxvBvMidYojTMQdl4n9/ixcLt68LhaF4MyActctDXL4+dKDUaJF/IlMluWdzys6J5RFg== ;{id = 30899}\n",
"3o3tqldra9tgt2e01ikvc1f5r7qjct5q.example.org.	3600	IN	NSEC3	1 0 1 1234  86er3qr3ol0n6a0drbbffrcdk1ops77n MX RRSIG \n",
"3o3tqldra9tgt2e01ikvc1f5r7qjct5q.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. Q/KEK/BUxv8O9WG5i0FKDnvwc03GTp7Gq1jcHgr6lqvYEJLSTwtgDDGF1JXgvjaUqobLYEilZoCUYYMZh0SAPw== ;{id = 30899}\n",
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	NSEC3	1 0 1 1234  3o3tqldra9tgt2e01ikvc1f5r7qjct5q A RRSIG \n",
"1t1dk1m24102gngs9umpl1s4euti62js.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. wvjHs9xj5M3c/SaGwrUGUVm9zgsNYG/4yxGdwQ5uS1X+mZsbYSYyxz7eoAebkuJTgmd98usoOD/QcxMyI+tUCA== ;{id = 30899}\n",
"jdup4m0edbcmtb7g5utvc2hgnees76us.example.org.	3600	IN	NSEC3	1 0 1 1234  lrckab0ombfgqe8944cpph33vvf1q3ss A RRSIG \n",
"jdup4m0edbcmtb7g5utvc2hgnees76us.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. ezk3rhdKfJ44Hw25Jh3J0Q4rRSt2PxnSzdgNoiapFW6dg9TWbAx4J3al0ioPRWveUHDCLkCEnldPATCSyu0Xrw== ;{id = 30899}\n",
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	NSEC3	1 0 1 1234  gtitidhf26une8fj2t3eaj47qf8tbuci A RRSIG \n",
"g1hcjueqjvfi7f48f5gbncll68nqj0it.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. qs1ck0jaO2JBiwJ1Gm+vDkDxrqLKq0ASgGSpRPdimCXSv/xje/v6sbuKv2hVkvPLnp2mKsTEuzwahw+Pm09PdQ== ;{id = 30899}\n",
"an5c8h70kkk482f35kojaluuvp2k4al7.example.org.	3600	IN	NSEC3	1 0 1 1234  atnd4lu4hk3nfigk82orjqu8qbdlu4gn A RRSIG \n",
"an5c8h70kkk482f35kojaluuvp2k4al7.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. uJB7yf+hWyM55S5bPBJNPFNsinu3//58VfbkJJESLgGiGTcFa68rjrBbCkVfueGeEy+/xk20avO8Ggzkqpx8rQ== ;{id = 30899}\n",
"lrckab0ombfgqe8944cpph33vvf1q3ss.example.org.	3600	IN	NSEC3	1 0 1 1234  o334hngponsojfvecb16ef11pluqci6c A RRSIG \n",
"lrckab0ombfgqe8944cpph33vvf1q3ss.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. n9QXqq1+flcrkvCmsoEKEkMt24gEuhpQSFUms/oFFP2++ppll/ydWhUsbY35TfOsI8XAin4sxfOl0ImdQVNJeg== ;{id = 30899}\n",
"atnd4lu4hk3nfigk82orjqu8qbdlu4gn.example.org.	3600	IN	NSEC3	1 0 1 1234  bll46u32m32oetik7pcgfcuss7n5pqql A RRSIG \n",
"atnd4lu4hk3nfigk82orjqu8qbdlu4gn.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. J4VWXjkJBv4UXqze1uRyHRT98vqGn8WJ7jm08zdrhbNZ8McRZxqFSjcyqbM0exq6ZM6ceQeap69eJ50TRHqXtw== ;{id = 30899}\n",
"o334hngponsojfvecb16ef11pluqci6c.example.org.	3600	IN	NSEC3	1 0 1 1234  os1tu4plekke6t993674mq6j79d73fdo A AAAA RRSIG \n",
"o334hngponsojfvecb16ef11pluqci6c.example.org.	3600	IN	RRSIG	NSEC3 5 3 3600 20110519131330 20110421131330 30899 example.org. T/8XSAGtKBcPh2FfsT9qQyen8S2InP+GM/JLULxmZbQTJyRVX4Zoy+pVlAPv2FyiTcYVgjXCv4XF6ewvwqNRtw== ;{id = 30899}\n",
		NULL
	};
	check_namedb(tc, db);

	/* change NSEC3 salt : first add new NSEC3s, then add NSEC3PARAM.
	 * remove old NSEC3PARAM. remove old NSEC3s */
	for(i=0; new_nsec3s[i]; i++) {
		add_str(db, zone, new_nsec3s[i]);
		prehash_zone(db, zone);
		check_namedb(tc, db);
	}
	add_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 2 5678\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. jDz61FLnJs0mOO61HOeB6SuGwWZWahmzMmyNtit/9Yk4+zYrPPs/wJvqNuuuIcyXU5gLih3H+SVUddKaZlskZg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	del_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. THFhaMtVP25A31/aGJ7wU2GAMSuJrGCB5vkTZnmIelpQQ7j/uVDuFQRB73Zr87owwP8l02Aqf71iFA3LSdpEyQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 1 1234 \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* now, try to get the param change in another way:
	 * remove the NSEC3PARAM (none left), then add it */
	del_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 2 5678\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	del_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. jDz61FLnJs0mOO61HOeB6SuGwWZWahmzMmyNtit/9Yk4+zYrPPs/wJvqNuuuIcyXU5gLih3H+SVUddKaZlskZg== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	add_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. THFhaMtVP25A31/aGJ7wU2GAMSuJrGCB5vkTZnmIelpQQ7j/uVDuFQRB73Zr87owwP8l02Aqf71iFA3LSdpEyQ== ;{id = 30899}\n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);
	add_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 1 1234 \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	/* remove two strings at once */
	del_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. THFhaMtVP25A31/aGJ7wU2GAMSuJrGCB5vkTZnmIelpQQ7j/uVDuFQRB73Zr87owwP8l02Aqf71iFA3LSdpEyQ== ;{id = 30899}\n"
	);
	del_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 1 1234 \n"
	);
	prehash_zone(db, zone);
	check_namedb(tc, db);

	for(i=0; old_nsec3s[i]; i++) {
		del_str(db, zone, old_nsec3s[i]);
		prehash_zone(db, zone);
		check_namedb(tc, db);
	}

	/* change NSEC3PARAM in different order: delete all NSEC3s, then
	 * NSEC3PARAM, then add the new PARAM, then the new NSEC3s */
	for(i=0; new_nsec3s[i]; i++) {
		del_str(db, zone, new_nsec3s[i]);
	}
	prehash_zone(db, zone); /* delete all nsec3 chain in one go */
	check_namedb(tc, db);

	add_str(db, zone,
		"example.org.	3600	IN	RRSIG	NSEC3PARAM 5 2 3600 20110519131330 20110421131330 30899 example.org. THFhaMtVP25A31/aGJ7wU2GAMSuJrGCB5vkTZnmIelpQQ7j/uVDuFQRB73Zr87owwP8l02Aqf71iFA3LSdpEyQ== ;{id = 30899}\n"
	);
	add_str(db, zone,
		"example.org.	3600	IN	NSEC3PARAM	1 0 1 1234 \n"
	);
	for(i=0; old_nsec3s[i]; i++) {
		add_str(db, zone, old_nsec3s[i]);
	}
	prehash_zone(db, zone);
	check_namedb(tc, db);

	zone->is_ok = 0;
	delete_zone_rrs(db, zone);
	nsec3_clear_precompile(db, zone);
	zone->nsec3_param = NULL;
	prehash_zone(db, zone);
	check_namedb(tc, db);
}

static void namedb_4(CuTest *tc)
{
	/* test _4 : check NSEC3 precompile, change of nsec3salt */
	region_type* region;
	namedb_type* db;
	if(v) verbosity = 3;
	else verbosity = 0;
	if(v) printf("test namedb-nsec3-saltchange start\n");
	region = region_create(xalloc, free);
	db = create_and_read_db(tc, region, "example.org.", nsec3zone_txt);

	/* test it */
	test_add_del_4(tc, db);

	if(v) printf("test namedb-nsec3-saltchange end\n");
	namedb_close(db);
	region_destroy(region);
}
#endif /* NSEC3 */
