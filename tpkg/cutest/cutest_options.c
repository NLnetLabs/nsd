/*
	test options.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "options.h"
#include "util.h"
#include "dname.h"
#include "nsd.h"

static void acl_1(CuTest *tc);
static void acl_2(CuTest *tc);
static void acl_3(CuTest *tc);
static void acl_4(CuTest *tc);
static void acl_5(CuTest *tc);
static void acl_6(CuTest *tc);
static void replace_1(CuTest *tc);
static void replace_2(CuTest *tc);
static void zonelist_1(CuTest *tc);

CuSuite* reg_cutest_options(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, acl_1); /* acl_addr_match_range */
	SUITE_ADD_TEST(suite, acl_2); /* acl_addr_match_mask */
	SUITE_ADD_TEST(suite, acl_3); /* parse_acl_is_ipv6 */
	SUITE_ADD_TEST(suite, acl_4); /* parse_acl_range_type */
	SUITE_ADD_TEST(suite, acl_5); /* parse_acl_range_subnet */
	SUITE_ADD_TEST(suite, acl_6); /* acl_same_host */
	SUITE_ADD_TEST(suite, replace_1); /* replace_str */
	SUITE_ADD_TEST(suite, replace_2); /* make_zonefile */
	SUITE_ADD_TEST(suite, zonelist_1); /* zonelist */
	return suite;
}

static void acl_1(CuTest *tc)
{
	uint32_t min, x, max;
	int exp;
#ifdef INET6
	uint32_t a[4] = {0,0,0,0};
	uint32_t b[4] = {0,0,0,0};
	uint32_t c[4] = {0,0,0,0};
#endif
	/* check 32-bit performance */
#define CHK CuAssert(tc, "check acl_range", \
	exp==acl_addr_match_range_v4(&min, &x, &max, sizeof(uint32_t)));
	min=0x00000000; max=0xffffffff; x=0x00000001; exp=1; CHK;
	min=0x00000000; max=0xffffffff; x=0x00000000; exp=1; CHK;
	min=0x00000000; max=0xffffffff; x=0xffffffff; exp=1; CHK;
	min=0x00000010; max=0x00000020; x=0x00000000; exp=0; CHK;
	min=0x00000010; max=0x00000020; x=0x00000005; exp=0; CHK;
	min=0x00000010; max=0x00000020; x=0x00000009; exp=0; CHK;
	min=0x00000010; max=0x00000020; x=0x00000010; exp=1; CHK;
	min=0x00000010; max=0x00000020; x=0x00000015; exp=1; CHK;
	min=0x00000010; max=0x00000020; x=0x00000019; exp=1; CHK;
	min=0x00000010; max=0x00000020; x=0x00000020; exp=1; CHK;
	min=0x00000010; max=0x00000020; x=0x00000021; exp=0; CHK;
	min=0x00000010; max=0x00000020; x=0x000ff004; exp=0; CHK;
	min=0x1f000010; max=0x1a000020; x=0x1b000020; exp=0; CHK;
	min=0x1a000010; max=0x1f000020; x=0x1b000020; exp=1; CHK;
	min=0x1a000010; max=0x1f000020; x=0xf0000021; exp=0; CHK;
	min=0x54321654; max=0x54321654; x=0x54321654; exp=1; CHK;
#undef CHK

	/* check multi word performance */
#ifdef INET6
#define CHK CuAssert(tc, "check acl_range longcontents", \
	exp==acl_addr_match_range_v6(a, b, c, 4*sizeof(uint32_t)));
	exp=1; CHK;
	a[2]=10; b[2]=0; c[2]=20; exp=0; CHK;
	a[2]=10; b[2]=10; c[2]=20; exp=1; CHK;
	a[2]=10; b[2]=15; c[2]=20; exp=1; CHK;
	a[2]=10; b[2]=20; c[2]=20; exp=1; CHK;
	a[2]=10; b[2]=30; c[2]=20; exp=0; CHK;

	a[2]=10; b[2]=10; c[2]=20;
	a[3]=50; b[3]=40; c[3]=60; exp=0; CHK;
	a[3]=50; b[3]=50; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=55; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=60; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=80; c[3]=60; exp=1; CHK;

	a[2]=10; b[2]=20; c[2]=20;
	a[3]=50; b[3]=40; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=50; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=55; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=60; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=80; c[3]=60; exp=0; CHK;

	a[2]=10; b[2]=15; c[2]=20;
	a[3]=50; b[3]=40; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=50; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=55; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=60; c[3]=60; exp=1; CHK;
	a[3]=50; b[3]=80; c[3]=60; exp=1; CHK;
#undef CHK
#endif /* INET6 */
}

static void acl_2(CuTest *tc)
{
	uint32_t x, y, mask;
	int exp;
	uint32_t a[4] = {0, 0, 0, 0};
	uint32_t b[4] = {0, 0, 0, 0};
	uint32_t m[4] = {0, 0, 0, 0};
#define CHK CuAssert(tc, "check acl_mask", \
	exp==acl_addr_match_mask(&x, &y, &mask, sizeof(uint32_t)));
	x=0; y=0; mask=0; exp=1; CHK;
	x=81; y=234; mask=0; exp=1; CHK;
	x=0xffffffff; y=0xcccccccc; mask=0; exp=1; CHK;
	x=0x1234; y=0x1206; mask=0xffff; exp=0; CHK;
	x=0x1234; y=0x1284; mask=0xffff; exp=0; CHK;
	x=0x1234; y=0x1234; mask=0xffff; exp=1; CHK;
	x=0xfe1234; y=0x861234; mask=0xffff; exp=1; CHK;
	x=0xfe1284; y=0x861264; mask=0xff0f; exp=1; CHK;
	x=0xfe1284; y=0x861264; mask=0xff8f; exp=0; CHK;
#undef CHK
	/* check multiple words */
#define CHK CuAssert(tc, "check acl_mask", \
	exp==acl_addr_match_mask(a, b, m, 4*sizeof(uint32_t)));
	exp=1; CHK;
	a[2]=0x10; b[2]=0x20; m[2]=0xff; exp=0; CHK;
	a[2]=0x10; b[2]=0x10; m[2]=0xff; exp=1; CHK;

	a[2]=0x10; b[2]=0x10; m[2]=0xff;
	a[3]=0x100; b[3]=0x100; m[3]=0xfff; exp=1; CHK;
	a[3]=0x100; b[3]=0x200; m[3]=0xfff; exp=0; CHK;

	a[2]=0x10; b[2]=0x20; m[2]=0xff;
	a[3]=0x100; b[3]=0x100; m[3]=0xfff; exp=0; CHK;
	a[3]=0x100; b[3]=0x200; m[3]=0xfff; exp=0; CHK;
#undef CHK
}

static void acl_3(CuTest *tc)
{
	CuAssert(tc, "check parse_acl_is_ipv6",
		parse_acl_is_ipv6("0.0.0.0") == 0);
	CuAssert(tc, "check parse_acl_is_ipv6",
		parse_acl_is_ipv6("::1") == 1);
	CuAssert(tc, "check parse_acl_is_ipv6",
		parse_acl_is_ipv6("ff08:1234:1232:0000") == 1);
	CuAssert(tc, "check parse_acl_is_ipv6",
		parse_acl_is_ipv6("ffff::127.0.0.1") == 1);
}

static void acl_4(CuTest *tc)
{
	char *mask=0;
	region_type* region = region_create(xalloc, free);
	CuAssert(tc, "check parse_acl_range_type",
		parse_acl_range_type(
			region_strdup(region, "10.11.12.13"), &mask) 
			== acl_range_single);
	CuAssert(tc, "check parse_acl_range_type",
		parse_acl_range_type(
			region_strdup(region, "ff::1"), &mask) 
		== acl_range_single);
	CuAssert(tc, "check parse_acl_range_type",
		parse_acl_range_type(
			region_strdup(region, "10.20.30.40&255.255.255.0"), &mask) 
		== acl_range_mask);
	CuAssert(tc, "check parse_acl_range_type",
		parse_acl_range_type(
			region_strdup(region, "10.20.30.40/28"), &mask) 
		== acl_range_subnet);
	CuAssert(tc, "check parse_acl_range_type",
		parse_acl_range_type(
			region_strdup(region, "10.20.30.40-10.20.30.60"), &mask) 
		== acl_range_minmax);
	region_destroy(region);
}

static void acl_5(CuTest *tc)
{
	/* parse_acl_range_subnet */
	union acl_addr_storage addr;
	uint32_t res=0;

	memset(&addr, 0, sizeof(addr));
	parse_acl_range_subnet("28", &addr, 32); res=htonl(0xfffffff0);
	CuAssert(tc, "check parseacl_range_subnet", memcmp(&addr, &res, sizeof(res)) == 0);

	memset(&addr, 0, sizeof(addr));
	parse_acl_range_subnet("16", &addr, 32); res=htonl(0xffff0000);
	CuAssert(tc, "check parseacl_range_subnet", memcmp(&addr, &res, sizeof(res)) == 0);

	memset(&addr, 0, sizeof(addr));
	parse_acl_range_subnet("8", &addr, 32); res=htonl(0xff000000);
	CuAssert(tc, "check parseacl_range_subnet", memcmp(&addr, &res, sizeof(res)) == 0);
}

static void acl_6(CuTest *tc)
{
	/* acl_same_host */
	region_type* region = region_create(xalloc, free);
	acl_options_type *x=0, *y=0;

	x = parse_acl_info(region, "10.20.30.40", "NOKEY");
	y = parse_acl_info(region, "10.20.30.40", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 1);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 1);

#ifdef INET6
	x = parse_acl_info(region, "10.20.30.40", "NOKEY");
	y = parse_acl_info(region, "10ff:20ff:30ff:40ff::", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);

	x = parse_acl_info(region, "10ff:20ff:30ff:40ff::", "NOKEY");
	y = parse_acl_info(region, "10ff:20ff:30ff:40ff::", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 1);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 1);

	x = parse_acl_info(region, "10ff:20ff:30ff:40ff::", "NOKEY");
	y = parse_acl_info(region, "10ff:20ff:30ff:ff40::", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);

	x = parse_acl_info(region, region_strdup(region, "10ff:20ff:30ff:40ff::@5353"), 
		"NOKEY");
	y = parse_acl_info(region, "10ff:20ff:30ff:40ff::", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);
#endif /* INET6 */

	x = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.50.60"), "NOKEY");
	y = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.50.60"), "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 1);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 1);

	x = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.50.60"), "NOKEY");
	y = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.77.60"), "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);

	x = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40&30.40.50.60"), "NOKEY");
	y = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.50.60"), "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);

	x = parse_acl_info(region, "10.20.30.40", "NOKEY");
	y = parse_acl_info(region, 
		region_strdup(region, "10.20.30.40-30.40.50.60"), "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 0);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 0);

	region_destroy(region);
}

static void replace_1(CuTest *tc)
{
	char buf[32];
	strlcpy(buf, "aad", sizeof(buf));
	replace_str(buf, sizeof(buf), "a", "aad");
	CuAssertStrEquals(tc, "aadaadd", buf);

	strlcpy(buf, "aca", sizeof(buf));
	replace_str(buf, sizeof(buf), "a", "aba");
	CuAssertStrEquals(tc, "abacaba", buf);

	strlcpy(buf, "aca", sizeof(buf));
	replace_str(buf, 5, "a", "aba");
	CuAssertStrEquals(tc, "aca", buf);

	strlcpy(buf, "aca", sizeof(buf));
	replace_str(buf, 6, "a", "aba");
	CuAssertStrEquals(tc, "abaca", buf);

	strlcpy(buf, "aca", sizeof(buf));
	replace_str(buf, 7, "a", "aba");
	CuAssertStrEquals(tc, "abaca", buf);

	strlcpy(buf, "aca", sizeof(buf));
	replace_str(buf, 8, "a", "aba");
	CuAssertStrEquals(tc, "abacaba", buf);

	strlcpy(buf, "%1", sizeof(buf));
	replace_str(buf, 8, "%1", "a");
	CuAssertStrEquals(tc, "a", buf);

	strlcpy(buf, "xx%1", sizeof(buf));
	replace_str(buf, 8, "%1", "a");
	CuAssertStrEquals(tc, "xxa", buf);

	strlcpy(buf, "xx%1yz", sizeof(buf));
	replace_str(buf, 8, "%1", "a");
	CuAssertStrEquals(tc, "xxayz", buf);

	strlcpy(buf, "xx%syz", sizeof(buf));
	replace_str(buf, sizeof(buf), "%s", "foobar");
	CuAssertStrEquals(tc, "xxfoobaryz", buf);
}

static void replace_2(CuTest *tc)
{
	struct nsd nsd;
	region_type* region = region_create(xalloc, free);
	struct zone_options z;
	struct pattern_options p;
	memset(&nsd, 0, sizeof(nsd));
	memset(&z, 0, sizeof(z));
	memset(&p, 0, sizeof(p));
	z.name = "example.com";
	z.node.key = dname_parse(region, z.name);
	z.pattern = &p;
	p.zonefile = "%s";
	CuAssertStrEquals(tc, "example.com", config_make_zonefile(&z, &nsd));
	p.zonefile = "zones/%1/%2/%3/%s.zone";
	CuAssertStrEquals(tc, "zones/e/x/a/example.com.zone",
		config_make_zonefile(&z, &nsd));
	p.zonefile = "%z/%y/thezone";
	CuAssertStrEquals(tc, "com/example/thezone",
		config_make_zonefile(&z, &nsd));

	region_destroy(region);
}

static int
has_free_elem(struct zonelist_free* e, off_t off)
{
	while(e) {
		if(e->off == off)
			return 1;
		e = e->next;
	}
	return 0;
}

static size_t
count_free(CuTest* tc, struct nsd_options* opt)
{
	struct zonelist_free* e;
	struct zonelist_bucket* b;
	size_t c = 0;
	RBTREE_FOR(b, struct zonelist_bucket*, opt->zonefree) {
		CuAssertTrue(tc, b->list != NULL);
		for(e = b->list; e; e = e->next)
			c++;
	}
	return c;
}

static void
check_zonelist_file(CuTest *tc, struct nsd_options* opt, const char* s)
{
	char buf[1024];
	FILE* in;
	int line = 0;
	size_t delcount = 0;
	fflush(opt->zonelist);
	in = fopen(opt->zonelistfile, "r");
	if(in == NULL) {
		printf("Error opening zonelistfile \"%s\": %s\n",
			(opt->zonelistfile ? opt->zonelistfile : "<nil>"),
			strerror(errno));
		CuAssertTrue(tc, 0);
		return;
	}
	while(fgets(buf, sizeof(buf), in)) {
		line++;
		if(strncmp(buf, s, strlen(buf)) != 0) {
			printf("zonelist fail line %d\n", line);
			printf("got: %s\n", buf);
			printf("wanted: %s\n", s);
			CuAssertTrue(tc, 0);
		}
		if(strncmp(buf, "del ", 4) == 0) {
			int linesize = strlen(buf);
			struct zonelist_bucket* b = (struct zonelist_bucket*)
				rbtree_search(opt->zonefree, &linesize);
			CuAssertTrue(tc, b != NULL);
			CuAssertTrue(tc, b->linesize == linesize);
			CuAssertTrue(tc, b->list != NULL);
			CuAssertTrue(tc, has_free_elem(b->list, ftello(in)-linesize));
			delcount ++;
		}
		s += strlen(buf);
	}
	if(ferror(in)) {
		printf("Error reading zonelistfile \"%s\": %s\n",
			(opt->zonelistfile ? opt->zonelistfile : "<nil>"),
			strerror(errno));
		CuAssertTrue(tc, 0);
		return;
	}
	if(*s != 0) {
		printf("zonelist fail: expected more at EOF\n");
		printf("wanted: %s\n", s);
		CuAssertTrue(tc, 0);
	}
	CuAssertTrue(tc, count_free(tc, opt) == delcount);
	CuAssertTrue(tc, opt->zonelist_off == ftello(in));
	fclose(in);
}

static void zonelist_1(CuTest *tc)
{
	struct zone_options* z1, *z2, *z3;
	struct pattern_options* p1, *p2;
	char zname[1024];
	region_type* region = region_create_custom(xalloc, free,
		DEFAULT_CHUNK_SIZE, DEFAULT_LARGE_OBJECT_SIZE,
		DEFAULT_INITIAL_CLEANUP_SIZE, 1);
	struct nsd_options* opt = nsd_options_create(region);
	opt->region = region;
	snprintf(zname, sizeof(zname), "/tmp/unitzlist%u.cfg",
		(unsigned)getpid());
	opt->zonelistfile = zname;

	/* create master and slave patterns */
	p1 = pattern_options_create(opt->region);
	p1->pname = region_strdup(opt->region, "master");
	nsd_options_insert_pattern(opt, p1);
	p2 = pattern_options_create(opt->region);
	p2->pname = region_strdup(opt->region, "slave");
	nsd_options_insert_pattern(opt, p2);

	/* file does not exist, try to open it */
	CuAssertTrue(tc, parse_zone_list_file(opt));
	CuAssertTrue(tc, opt->zonefree->count == 0);
	CuAssertTrue(tc, opt->zonelist == NULL);
	CuAssertTrue(tc, opt->zonelist_off == (off_t)0);

	/* add some entries */
	z1 = zone_list_add(opt, "example.com", "master");
	CuAssertTrue(tc, z1 != NULL);
	CuAssertTrue(tc, opt->zonelist_off != (off_t)0);
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n");
	z2 = zone_list_add(opt, "example.net", "slave");
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "add example.net slave\n");
	z3 = zone_list_add(opt, "foo.nl", "slave");
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "add example.net slave\n"
		"add foo.nl slave\n");
	CuAssertTrue(tc, opt->zonefree->count == 0);

	/* delete some entries */
	zone_list_del(opt, z2); /* "example.net" */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "del example.net slave\n"
		"add foo.nl slave\n");
	zone_list_del(opt, z3); /* "foo.nl" */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n");
	z2 = zone_list_add(opt, "bar.nl", "slave");
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "add bar.nl slave\n");
	z3 = zone_list_add(opt, "zoink.com", "slave");
	(void)z3;
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "add bar.nl slave\n" 
		"add zoink.com slave\n");
	zone_list_del(opt, z2); /* "bar.nl" */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "del bar.nl slave\n" 
		"add zoink.com slave\n");
	zone_list_close(opt);
	region_destroy(region);

	region = region_create_custom(xalloc, free,
		DEFAULT_CHUNK_SIZE, DEFAULT_LARGE_OBJECT_SIZE,
		DEFAULT_INITIAL_CLEANUP_SIZE, 1);
	opt = nsd_options_create(region);
	opt->region = region;
	opt->zonelistfile = zname;

	/* create master and slave patterns */
	p1 = pattern_options_create(opt->region);
	p1->pname = region_strdup(opt->region, "master");
	nsd_options_insert_pattern(opt, p1);
	p2 = pattern_options_create(opt->region);
	p2->pname = region_strdup(opt->region, "slave");
	nsd_options_insert_pattern(opt, p2);

	/* read zonelist contents (file exists) and compact */
	CuAssertTrue(tc, parse_zone_list_file(opt));
	CuAssertTrue(tc, opt->zonelist != NULL);
	CuAssertTrue(tc, opt->zonefree->count != 0);
	CuAssertTrue(tc, opt->zonefree_number != 0);
	CuAssertTrue(tc, opt->zonelist_off != (off_t)0);
	/* check contents of freelist memory */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "del bar.nl slave\n"
		"add zoink.com slave\n");
	zone_list_compact(opt);
	/* check contents of zonelist file */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n"
		"add example.com master\n" "add zoink.com slave\n");

	/* delete more zones, compact and see that it has truncated */
	while(opt->zone_options->count)
		zone_list_del(opt, (zone_options_type*)opt->zone_options->root);
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n");
	zone_list_compact(opt);
	/* check contents of zonelist file */
	check_zonelist_file(tc, opt, "# NSD zone list\n# name pattern\n");

	zone_list_close(opt);
	region_destroy(region);
	unlink(zname);
}
