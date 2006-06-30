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

static void acl_1(CuTest *tc);
static void acl_2(CuTest *tc);

CuSuite* reg_cutest_options(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, acl_1); /* acl_addr_match_range */
	SUITE_ADD_TEST(suite, acl_2); /* acl_addr_match_mask */
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
