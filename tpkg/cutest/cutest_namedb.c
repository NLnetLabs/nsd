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

static void namedb_1(CuTest *tc);
static int v = 1; /* verbosity */

/** get a temporary file name */
char* udbtest_get_temp_file(char* suffix);

CuSuite* reg_cutest_namedb(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, namedb_1);
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
	nsd_options_t* opt;
	zone_options_t* zone;
	int child_count = 1;
	namedb_type* db;
	char* dbfile = udbtest_get_temp_file("namedb.udb");
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
	zone->zonefile = region_strdup(region, zonefile);
	zone->request_xfr = (void*)-1; /* dummy value to make zonec not error*/
	if(!nsd_options_insert_zone(opt, zone)) {
		CuAssertTrue(tc, 0);
	}

	/* read the db */
	db = namedb_open(dbfile, opt, child_count);
	if(!db) {
		printf("failed to open %s: %s\n", dbfile, strerror(errno));
		exit(1);
	}
	namedb_check_zonefiles(db, opt, child_count);
#ifdef NSEC3
        prehash(db, 0);
#endif
	unlink(zonefile);
	free(dbfile);
	free(zonefile);
	return db;
}

/* walk zones and check them */
static void
check_walkzones(CuTest* tc, namedb_type* db)
{
	struct radnode* n;
	for(n=radix_first(db->zonetree); n; n=radix_next(n)) {
		zone_type* zone = (zone_type*)n->elem;
		CuAssertTrue(tc, zone->apex);
		CuAssertTrue(tc, zone->opts);
		/* options are for this zone */
		CuAssertTrue(tc, strcmp(dname_to_string(domain_dname(
			zone->apex), NULL), zone->opts->name) == 0);
		/* either: the zone is servfail (nothing), and no SOA, ...
		 * or: it exists and has a SOA, NS, ... */
		if(zone->is_ok) {
			/* check soa_rrset */
			CuAssertTrue(tc, zone->soa_rrset);
			CuAssertTrue(tc, zone->soa_nx_rrset);
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
				CuAssertTrue(tc, zone->nsec3_soa_rr);
				CuAssertTrue(tc, zone->nsec3_last);
				/* TODO: check soa_rr NSEC3 has soa flag,
				 * check that last nsec3, is last in zone */
			} else {
				CuAssertTrue(tc, zone->nsec3_soa_rr == NULL);
				CuAssertTrue(tc, zone->nsec3_last == NULL);
			}
#endif /* NSEC3 */
		} else {
			CuAssertTrue(tc, zone->soa_rrset == NULL);
			CuAssertTrue(tc, zone->soa_nx_rrset == NULL);
			CuAssertTrue(tc, zone->ns_rrset == NULL);
#ifdef NSEC3
			CuAssertTrue(tc, zone->nsec3_soa_rr == NULL);
			CuAssertTrue(tc, zone->nsec3_last == NULL);
#endif /* NSEC3 */
			CuAssertTrue(tc, !zone->apex->is_existing);
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
		CuAssertTrue(tc, rrset->rrs);
		CuAssertTrue(tc, rrset->zone);
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
static void
CheckNSEC3lookup(CuTest* tc, domain_type* domain, zone_type* zone)
{
	domain_type* d;
	if(domain->nsec3_lookup) {
		/* check no NSEC3s between the nsec3lookup and domain */
		for(d=domain_next(domain->nsec3_lookup); d && d!=domain;
			d = domain_next(d)) {
			CuAssertTrue(tc, !domain_find_rrset(d,zone,TYPE_NSEC3));
		}
	} else {
		/* first lookup, NULL, no NSEC3s before domain */
		for(d=domain; d; d=domain_previous(d)) {
			CuAssertTrue(tc, !domain_find_rrset(d,zone,TYPE_NSEC3));
		}
	}
}
#endif /* NSEC3 */

#ifdef NSEC3
/* get NSEC3 for given nsec3-domain-name, b32.zone */
static domain_type*
get_nsec3_for(namedb_type* db, const dname_type* look, zone_type* zone)
{
	domain_type* closest=NULL, *ce=NULL;
	if(domain_table_search(db->domains, look, &closest, &ce)) {
		return closest;
	}
	if(!closest->nsec3_lookup) {
		return zone->nsec3_last;
	}
	return closest->nsec3_lookup;
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

#ifdef NSEC3
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
	if(domain_in_nsec3_space(domain, &zone))
		CheckNSEC3lookup(tc, domain, zone);
	region = region_create(xalloc, free);

	/* see if this domain is processed */
	if(!zone || !zone->nsec3_soa_rr || !domain->is_existing ||
		domain_find_zone(domain) != zone ||
		domain_has_only_NSEC3(domain, zone) ||
		domain_is_glue(domain, zone)) {
		CuAssertTrue(tc, !domain->have_nsec3_hash);
		CuAssertTrue(tc, !domain->have_nsec3_wc_hash);
		CuAssertTrue(tc, !domain->nsec3_is_exact);
		CuAssertTrue(tc, !domain->nsec3_cover);
		CuAssertTrue(tc, !domain->nsec3_wcard_child_cover);
	} else {
		const dname_type* h, *wch, *wild;
		uint8_t hash[NSEC3_HASH_LEN], wchash[NSEC3_HASH_LEN];
		CuAssertTrue(tc, domain->have_nsec3_hash);
		CuAssertTrue(tc, domain->have_nsec3_wc_hash);
		h = nsec3_hash_and_store(region, zone, domain_dname(domain),
			hash);
		wild = dname_parse(region, "*");
		wild = dname_concatenate(region, wild, domain_dname(domain));
		wch = nsec3_hash_and_store(region, zone, wild, wchash);

		CuAssertTrue(tc, memcmp(domain->nsec3_hash, hash,
			NSEC3_HASH_LEN) == 0);
		CuAssertTrue(tc, memcmp(domain->nsec3_wc_hash, wchash,
			NSEC3_HASH_LEN) == 0);

		/* check nsec3_cover, nsec3_is_exact */
		CuAssertTrue(tc, get_nsec3_for(db, h, zone) ==
			domain->nsec3_cover);
		if(dname_compare(domain_dname(domain->nsec3_cover), h) == 0) {
			CuAssertTrue(tc, domain->nsec3_is_exact);
		} else {
			CuAssertTrue(tc, !domain->nsec3_is_exact);
		}
		/* check nsec3_wcard_child_cover */
		CuAssertTrue(tc, get_nsec3_for(db, wch, zone) ==
			domain->nsec3_wcard_child_cover);
	}
	if((rrset=domain_has_rrset_plain(domain, TYPE_DS)) ||
		(rrset=domain_has_deleg_rrset(domain))) {
	    zone_type* pz = rrset->zone;
	    if(pz->nsec3_soa_rr && domain->is_existing) {
		const dname_type* h;
		uint8_t hash[NSEC3_HASH_LEN];
		CuAssertTrue(tc, domain->have_nsec3_ds_parent_hash);
		h = nsec3_hash_and_store(region, pz, domain_dname(domain),
			hash);
		CuAssertTrue(tc, memcmp(domain->nsec3_ds_parent_hash, hash,
			NSEC3_HASH_LEN) == 0);

		/* check nsec3_ds_parent_cover, nsec3_ds_parent_is_exact */
		CuAssertTrue(tc, get_nsec3_for(db, h, pz) ==
			domain->nsec3_ds_parent_cover);
		if(dname_compare(domain_dname(domain->nsec3_ds_parent_cover),
			h) == 0) {
			CuAssertTrue(tc, domain->nsec3_is_exact);
		} else {
			CuAssertTrue(tc, !domain->nsec3_is_exact);
		}
	    } else {
		CuAssertTrue(tc, !domain->have_nsec3_ds_parent_hash);
		CuAssertTrue(tc, !domain->nsec3_ds_parent_cover);
		CuAssertTrue(tc, !domain->nsec3_ds_parent_is_exact);
	    }
	} else {
		CuAssertTrue(tc, !domain->have_nsec3_ds_parent_hash);
		CuAssertTrue(tc, !domain->nsec3_ds_parent_cover);
		CuAssertTrue(tc, !domain->nsec3_ds_parent_is_exact);
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

/* walk domains and check them */
static void
check_walkdomains(CuTest* tc, namedb_type* db)
{
	domain_type* d;
	uint8_t* numbers = xalloc_zero(db->domains->nametree->count+10);
	size_t* usage = xalloc_zero((db->domains->nametree->count+10)*
		sizeof(size_t));
	size_t* chnum = xalloc_zero((db->domains->nametree->count+10)*
		sizeof(size_t));
	for(d=db->domains->root; d; d=domain_next(d)) {
		if(v) printf("at domain %s\n", dname_to_string(domain_dname(d),
			NULL));
		/* check parent: exists, NULL for root and one label less */
		if(domain_dname(d)->label_count == 1) {
			CuAssertTrue(tc, d->parent == NULL);
		} else {
			CuAssertTrue(tc, d->parent);
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
		CuAssertTrue(tc, d->number <= db->domains->nametree->count);
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
		/* keep track of number of domains that have a parent */
		if(d->parent) {
			chnum[d->parent->number]++;
		}
	}
	/* add up domain usage */
	/* usage for root node (so it does not get deleted) */
	usage[db->domains->root->number]++;
	usage_for_zones(db, usage);
	for(d=db->domains->root; d; d=domain_next(d)) {
		if(d->rrsets)
			usage_for_rrsets(d->rrsets, usage);
	}
	for(d=db->domains->root; d; d=domain_next(d)) {
		/* check chnum */ 
		/* TODO CuAssertTrue(tc, d->chnum == chnum[d->number]); */
		/* check usage */
		/* TODO CuAssertTrue(tc, d->usage == usage[d->number]); */
	}
	free(numbers);
	free(chnum);
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

/* test the namedb, and add, remove items from it */
static void
test_add_del(CuTest *tc, namedb_type* db)
{
	check_namedb(tc, db);
	/* TODO : make some changes and check again */
	/* setup_string_parser (then desetup it and pop global parser back).
	 * string to db in tempregion, then marshal like udb_write.
	 * zonec_scan_string(zone):  setparser->current_zone,
	 * 	errors=0; totalrrs = 0;
	 *         setprotoent(1);  -- do once at createglobalparser 
	        setservent(1);  -- do once at createglobalparser
	 * 	zparser_init(filename="string", ttl=3600, IN, origin=root);
	 * 	yy_scan_string(str); */
	/*
	add_RR(namedb_type* db, const dname_type* dname,
	       uint16_t type, uint16_t klass, uint32_t ttl,
		buffer_type* packet, size_t rdatalen, zone_type *zone, udb_ptr* udbz)
	delete_RR(namedb_type* db, const dname_type* dname,
	        uint16_t type, uint16_t klass,
		buffer_type* packet, size_t rdatalen, zone_type *zone,
		region_type* temp_region, udb_ptr* udbz)
	*/
}

static void namedb_1(CuTest *tc)
{
	region_type* region;
	namedb_type* db;
	verbosity = 3;
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
	unlink(db->udb->fname);
	region_destroy(region);
	exit(0);
}
