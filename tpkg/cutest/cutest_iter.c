/*
	test zone_rr_iter
*/
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "nsd.h"
#include "options.h"
#include "namedb.h"

#include "tpkg/cutest/cutest.h"

static struct namedb *
create_namedb(void)
{
	struct namedb *db;

	if((db = namedb_open(NULL)) == NULL) {
		fprintf(stderr, "failed to create namedb\n");
		exit(1);
	}

	return db;
}

static void
destroy_namedb(struct namedb *db)
{
	namedb_close(db);
}

static void
create_zone(struct namedb *db, const char *name, const char *data)
{
	struct nsd nsd;
	struct nsd_options *options;
	struct region *region;
	char zonefile[512];
	struct zone_options *zone;
	FILE *zonefh;
	size_t datalen;

	assert(db != NULL);
	assert(name != NULL);
	assert(data != NULL);

	memset(&nsd, 0, sizeof(nsd));
	nsd.db = db;
	region = region_create(xalloc, free);
	options = nsd_options_create(region);
	snprintf(zonefile, sizeof(zonefile), "%szone", name);
	zone = zone_options_create(region);
	memset(zone, 0, sizeof(*zone));
	zone->name = region_strdup(region, name);
	zone->pattern = pattern_options_create(region);
	zone->pattern->pname = zone->name;
	zone->pattern->zonefile = region_strdup(region, zonefile);
	zone->pattern->request_xfr = (void*)-1; /* dummy value to make zonec not error */

	if(!nsd_options_insert_zone(options, zone)) {
		fprintf(stderr, "failed to create zone %s\n", name);
		exit(1);
	}
	if((zonefh = fopen(zonefile, "w")) == NULL) {
		fprintf(stderr, "failed to open %s: %s\n", zonefile, strerror(errno));
		exit(1);
	}
	datalen = strlen(data);
	if(fwrite(data, 1, datalen, zonefh) != datalen) {
		fprintf(stderr, "failed to write %s: %s\n", zonefile, strerror(errno));
	}
	fclose(zonefh);

	namedb_check_zonefiles(&nsd, options, NULL, NULL);
	unlink(zonefile);
	nsd_options_destroy(options);
}

static const char bar_foo[] = "bar.foo.";
static const char bar_foo_zone[] =
"$ORIGIN bar.foo.\n"
"@    IN  SOA        ns1.bar.foo. hostmaster.bar.foo. 2019103100 28800 7200 604800 3600\n"
"     IN  NS         ns1.bar.foo.\n"
"     IN  NS         ns2.bar.foo.\n"
"     IN  MX     10  mx1.bar.foo.\n"
"     IN  MX     10  mx2.bar.foo.\n"
"     IN  A          10.20.30.40\n"
"ns1  IN  A          11.12.13.14\n"
"ns2  IN  A          19.18.17.16\n"
"mx1  IN  A          11.12.13.14\n"
"mx2  IN  A          19.18.17.16\n"
"web  IN  A          10.20.30.40\n"
"www  IN  CNAME      web\n"
"baz  IN  NS         ns1.baz.bar.foo\n"
"baz  IN  NS         ns2.baz.bar.foo\n";

static const char baz_bar_foo[] = "baz.bar.foo.";
static const char baz_bar_foo_zone[] =
"$ORIGIN baz.bar.foo.\n"
"@    IN  SOA        ns1.baz.bar.foo. hostmaster.bar.foo. 2020120100 28800 7200 604800 3600\n"
"     IN  NS         ns1.baz.bar.foo.\n"
"     IN  NS         ns2.baz.bar.foo.\n"
"     IN  MX     10  mx1.baz.baz.foo.\n"
"     IN  MX     10  mx2.baz.baz.foo.\n"
"     IN  A          10.20.30.40\n"
"ns1  IN  NS         11.12.13.14\n"
"ns2  IN  NS         19.18.17.16\n"
"mx1  IN  A          11.12.13.14\n"
"mx2  IN  A          19.18.17.16\n"
"web  IN  A          10.20.30.40\n"
"www  IN  CNAME      web\n";

static const char baz_foo[] = "baz.foo.";
static const char baz_foo_zone[] =
"$ORIGIN baz.foo.\n"
"@    IN  SOA        ns1.bar.foo. hostmaster.bar.foo. 2019103100 28800 7200 604800 3600\n"
"     IN  NS         ns1.bar.foo.\n"
"     IN  NS         ns2.bar.foo.\n"
"     IN  MX     10  mx1.baz.foo.\n"
"     IN  MX     10  mx2.baz.foo.\n"
"     IN  A          20.30.40.50\n"
"mx1  IN  A          21.22.23.24\n"
"mx2  IN  A          29.28.27.26\n"
"web  IN  CNAME      web.bar.foo.\n"
"www  IN  CNAME      web\n";

static void iterate_zone(CuTest *tc)
{
	int eq;
	struct namedb *db;
	const struct dname *dname;
	struct zone *zone;
	struct zone_rr_iter iter;
	struct rr *rr;
	size_t a, ns, mx, cname;

	db = create_namedb();
	/* create two zones to ensure zone boundaries are respected */
	create_zone(db, bar_foo, bar_foo_zone);
	create_zone(db, baz_foo, baz_foo_zone);
	create_zone(db, baz_bar_foo, baz_bar_foo_zone);

	dname = dname_parse(db->region, bar_foo);
	zone = namedb_find_zone(db, dname);
	CuAssert(tc, "", zone != NULL);

	zone_rr_iter_init(&iter, zone);

	a = ns = mx = cname = 0;

	/* verify soa rr is returned first */
	rr = zone_rr_iter_next(&iter);
	CuAssert(tc, "", rr != NULL);
	eq = dname_compare(dname, domain_dname(rr->owner));
	CuAssert(tc, "", eq == 0);
	CuAssert(tc, "", rr->type == TYPE_SOA);

	while((rr = zone_rr_iter_next(&iter)) != NULL) {
		/* verify soa rr is not returned again */
		CuAssert(tc, "", rr->type != TYPE_SOA);
		if((eq = dname_compare(dname, domain_dname(rr->owner))) != 0) {
			eq = !dname_is_subdomain(domain_dname(rr->owner),
			                         dname);
		}
		CuAssert(tc, "", eq == 0);
		switch(rr->type) {
		case TYPE_A:
			a++;
			break;
		case TYPE_NS:
			ns++;
			break;
		case TYPE_MX:
			mx++;
			break;
		case TYPE_CNAME:
			cname++;
			break;
		default:
			break;
		}
	}

	/* verify all records were there */
	CuAssert(tc, "", a == 6);
	CuAssert(tc, "", ns == 4);
	CuAssert(tc, "", mx == 2);
	CuAssert(tc, "", cname == 1);

	destroy_namedb(db);
}

CuSuite *reg_cutest_iter(void)
{
	CuSuite *suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, iterate_zone);
	return suite;
}

