/*
	test dname.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "dname.h"

static void dname_1(CuTest *tc);

CuSuite* reg_cutest_dname(void)
{
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, dname_1);
	return suite;
}

static void 
check_dname(CuTest *tc, const dname_type* name, const char* exp)
{
	region_type* region = region_create(xalloc, free);
	const dname_type* made = dname_make(region, dname_name(name), 0);
	CuAssert(tc, "test dname integrity (size)", 
		dname_total_size(made) == dname_total_size(name));
	CuAssert(tc, "test dname integrity (labelcount)", 
		made->label_count == name->label_count );
	CuAssert(tc, "test dname integrity (name_size)", 
		made->name_size == name->name_size );
	CuAssert(tc, "test dname integrity (labels)", 
		memcmp(name, made, dname_total_size(name)-name->name_size) == 0);
	CuAssert(tc, "test dname integrity (all)", 
		memcmp(name, made, dname_total_size(name)) == 0);

	made = dname_parse(region, exp);
	CuAssert(tc, "test dname integrity (expected result)", 
		memcmp(name, made, dname_total_size(name)) == 0);

	region_destroy(region);
}

static void 
dname_1(CuTest *tc)
{
	/* test dname_replace */
	region_type* region = region_create(xalloc, free);
	const dname_type* src = dname_parse(region, "x.");
	const dname_type* dest = dname_parse(region, "yy.");
	const dname_type* n1 = dname_parse(region, "aa.bla.x.");
	const dname_type* res;
	check_dname(tc, src, "x.");
	check_dname(tc, dest, "yy.");
	check_dname(tc, n1, "aa.bla.x.");

	res = dname_replace(region, n1, src, dest);
	check_dname(tc, res, "aa.bla.yy.");

	res = dname_replace(region, dname_parse(region, "."),
		dname_parse(region, "."), dname_parse(region, "."));
	check_dname(tc, res, ".");

	res = dname_replace(region, dname_parse(region, "xn-com."),
		dname_parse(region, "xn-com."), dname_parse(region, "xn-com."));
	check_dname(tc, res, "xn-com.");

	res = dname_replace(region, dname_parse(region, "xn-com."),
		dname_parse(region, "xn-com."), dname_parse(region, "xn-net."));
	check_dname(tc, res, "xn-net.");

	res = dname_replace(region, dname_parse(region, "ar.x.xn-com."),
		dname_parse(region, "x.xn-com."), dname_parse(region, "y.xn-com."));
	check_dname(tc, res, "ar.y.xn-com.");

	res = dname_replace(region, dname_parse(region, "xx.yy.zz."),
		dname_parse(region, "."), dname_parse(region, "."));
	check_dname(tc, res, "xx.yy.zz.");

	res = dname_replace(region, dname_parse(region, "xx.yy.zz."),
		dname_parse(region, "zz."), dname_parse(region, "zz.zz."));
	check_dname(tc, res, "xx.yy.zz.zz.");

	res = dname_replace(region, dname_parse(region, "xx.yy.zz."),
		dname_parse(region, "yy.zz."), dname_parse(region, "."));
	check_dname(tc, res, "xx.");

	res = dname_replace(region, dname_parse(region, "xx.yy.zz."),
		dname_parse(region, "."), dname_parse(region, "bla.bla."));
	check_dname(tc, res, "xx.yy.zz.bla.bla.");

	res = dname_replace(region, dname_parse(region, "xx.yy.zz.a.v.c.d.e.f.g."),
		dname_parse(region, "a.v.c.d.e.f.g."), dname_parse(region, "bla.bla."));
	check_dname(tc, res, "xx.yy.zz.bla.bla.");

	res = dname_replace(region, dname_parse(region, /* name is 10x16+a bit long */
		"abcdef1234567890.abcdef1234567890.abcdef1234567890.abcdef1234567890."
		"abcdef1234567890.abcdef1234567890.abcdef1234567890.abcdef1234567890."
		"abcdef1234567890.abcdef1234567890.e.f.g."),
		dname_parse(region, "e.f.g."), 
		dname_parse(region, /* name is 6x16 + a bit long */
		"abcdef1234567890.abcdef1234567890.abcdef1234567890."
		"abcdef1234567890.abcdef1234567890.abcdef1234567890.long."));
	CuAssert(tc, "test dname replace overflow", res == NULL);

	region_destroy(region);
}
