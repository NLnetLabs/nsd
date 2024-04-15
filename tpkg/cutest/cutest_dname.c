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

/* check is_dname_subdomain_of_case function */
static void
check_dname_subdomain(CuTest *tc)
{
	int r;
	r = is_dname_subdomain_of_case((uint8_t*)"\003abc\000", 5,
		(uint8_t*)"\004defg\000", 6);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case((uint8_t*)"\003abc\000", 5,
		(uint8_t*)"\004abcd\000", 6);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case((uint8_t*)"\003abc\000", 5,
		(uint8_t*)"\004aabc\000", 6);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case((uint8_t*)"\001a\002bb\003ccc\000", 10,
		(uint8_t*)"\004aabc\001c\003ddd\000", 12);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www\007example\003com\000", 17,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www\007example\003com\000", 17,
		(uint8_t*)"\003com\000", 5);
	CuAssert(tc, "test dname_subdomain_of function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www\007example\003com\000", 17,
		(uint8_t*)"\000", 1);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case((uint8_t*)"\007example\003com\000", 13,
		(uint8_t*)"\003www\007example\003com\000", 17);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case((uint8_t*)"\003com\000", 5,
		(uint8_t*)"\003www\007example\003com\000", 17);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case((uint8_t*)"\000", 1,
		(uint8_t*)"\003www\007example\003com\000", 17);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www\007example\003com\000", 17,
		(uint8_t*)"\007eyymple\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www\007example\003com\000", 17,
		(uint8_t*)"\007example\003cpm\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003www7example\003com\000", 17,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\013www\007example\003com\000", 17,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003foo\007example\003com\000", 17,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\003bla\007example\003com\000", 17,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\001b\007example\003com\000", 15,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\001a\001b\001c\007example\003com\000", 19,
		(uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
  (uint8_t*)"\007example\003com\001a\001b\001c\007example\003com\000", 31,
  (uint8_t*)"\007example\003com\000", 13);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\005abcde\000", 7,
		(uint8_t*)"\005abcde\000", 7);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 1);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\005abcde\000", 7,
		(uint8_t*)"\005exmpl\000", 7);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	/* The domain name is malformed. */
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\005abcde\000", 7,
		(uint8_t*)"bcde\000", 5);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
	r = is_dname_subdomain_of_case(
		(uint8_t*)"\005abcde\000", 7,
		(uint8_t*)"\004bcde\000", 6);
	CuAssert(tc, "test dname_subdomain_of_case function", r == 0);
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

	check_dname_subdomain(tc);

	region_destroy(region);
}
