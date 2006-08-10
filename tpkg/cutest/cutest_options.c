/*
	test options.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "options.h"
#include "util.h"

static void acl_1(CuTest *tc);
static void acl_2(CuTest *tc);
static void acl_3(CuTest *tc);
static void acl_4(CuTest *tc);
static void acl_5(CuTest *tc);
static void acl_6(CuTest *tc);

CuSuite* reg_cutest_options(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, acl_1); /* acl_addr_match_range */
	SUITE_ADD_TEST(suite, acl_2); /* acl_addr_match_mask */
	SUITE_ADD_TEST(suite, acl_3); /* parse_acl_is_ipv6 */
	SUITE_ADD_TEST(suite, acl_4); /* parse_acl_range_type */
	SUITE_ADD_TEST(suite, acl_5); /* parse_acl_range_subnet */
	SUITE_ADD_TEST(suite, acl_6); /* acl_same_host */
	return suite;
}

static void acl_1(CuTest *tc)
{
	uint32_t min, x, max;
	int exp;
	uint32_t a[4] = {0,0,0,0};
	uint32_t b[4] = {0,0,0,0};
	uint32_t c[4] = {0,0,0,0};
	/* check 32-bit performance */
#define CHK CuAssert(tc, "check acl_range", \
	exp==acl_addr_match_range(&min, &x, &max, sizeof(uint32_t)));
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
#define CHK CuAssert(tc, "check acl_range longcontents", \
	exp==acl_addr_match_range(a, b, c, 4*sizeof(uint32_t)));
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
	acl_options_t *x=0, *y=0;

	x = parse_acl_info(region, "10.20.30.40", "NOKEY");
	y = parse_acl_info(region, "10.20.30.40", "NOKEY");
	CuAssert(tc, "check acl_same_host", acl_same_host(x, y) == 1);
	CuAssert(tc, "check acl_same_host", acl_same_host(y, x) == 1);

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
