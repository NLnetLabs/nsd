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
static void dname_2(CuTest *tc);

CuSuite* reg_cutest_dname(void)
{
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, dname_1);
	SUITE_ADD_TEST(suite, dname_2);
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

/** Test entries for the dname_2 test */
struct d_test_entry {
	/* The wireformat to parse. */
	char* wire;
	/* Length of wire data */
	size_t wirelen;
	/* If the parse should fail or succeed. */
	int parse_succeed;
};

static void
dname_2(CuTest *tc)
{
	/* Test from dname.h: buf_name_length, dname_make_buffered,
	 * dname_make_from_packet_buffered, dname_make,
	 * dname_make_wire_from_packet, and dname_make_from_packet
	 * with uncompressed names. */

	/* List of uncompressed wireformat for test. */
	struct d_test_entry test_entries_uncompressed[] = {
		/* Test success cases */
		{"", 1, 1},
		{"\003foo\004barq", 10, 1},
		{"\003www\003foo\004barq", 14, 1},
		{"\001*\003wld\003foo\004barq", 16, 1},

		/* This string is zero length, and fails. */
		{NULL, 0, 0},

		/* This has a label too long for the buffer. */
		{"\100foo\004barq", 10, 0},

		/* This has a compressed label. */
		{"\303foo\004barq", 10, 0},

		/* This has a compressed label. */
		{"\303\004barq", 7, 0},

		/* This has a label length that is wrong */
		{"\003fooblablablabla\004barq", 19, 0},

		/* This has a label too long, labellen=64 */
		{"\100x123456789x123456789x123456789x123456789x123456789x123456789xyzz\004barq", 71, 0},

		/* This has a label too long, labellen=72 */
		{"\110x123456789x123456789x123456789x123456789x123456789x123456789xyzz12345678\004barq", 79, 0},

		/* This has a label len 63. */
		{"\077x123456789x123456789x123456789x123456789x123456789x123456789xyz\004barq", 70, 1},

		/* This name is long, 11*23+1=254 */
		{"\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789"
		 "", 254, 1},

		/* This name is long, 11*22+12+1=255 */
		{"\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\013x123456789z"
		 "", 255, 1},

		/* This name is too long, 11*22+13+1=256 */
		{"\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\014x123456789zz"
		 "", 256, 0},

		/* This name is too long, 11*24+1=265 */
		{"\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "\012x123456789\012x123456789\012x123456789\012x123456789"
		 "", 265, 0},

	};
	size_t test_entries_uncompressed_num =
		sizeof(test_entries_uncompressed)/
		sizeof(*test_entries_uncompressed);
	size_t i;
	region_type* region;
	int verb=0; /* Enable to 1 for verbose output in this test. */
	if(verb)
		printf("num test entries %d\n",
			(int)test_entries_uncompressed_num);
	region = region_create(xalloc, free);

	for(i=0; i<test_entries_uncompressed_num; i++) {
		uint8_t* wire = (uint8_t*)test_entries_uncompressed[i].wire;
		size_t wirelen = test_entries_uncompressed[i].wirelen;
		struct dname_buffer buffer;
		buffer_type packet;
		size_t res;
		int r;
		if(verb)
			printf("entry %d, len %d\n", (int)i, (int)wirelen);

		res = buf_dname_length(wire, wirelen);
		if(verb)
			printf("entry %d: buf_dname_length=%d\n",
				(int)i, (int)res);
		if(test_entries_uncompressed[i].parse_succeed) {
			CuAssert(tc, "test buf_dname_length parse",
				res == wirelen);
		} else {
			CuAssert(tc, "test buf_dname_length parse failure",
				res == 0);
		}

		if(wire != NULL) {
			memset(&buffer, 0, sizeof(buffer));
			r = dname_make_buffered(&buffer, wire, 0);
			if(verb)
				printf("entry %d: dname_make_buffered=%d\n",
					(int)i, r);
			if(test_entries_uncompressed[i].parse_succeed) {
				CuAssert(tc, "test dname_make_buffered parse",
					r == 1);
				CuAssert(tc, "test dname_make_buffered string",
					strcmp(wiredname2str(wire),
					dname_to_string((void*)&buffer, NULL))
					== 0);
			} else {
				CuAssert(tc, "test dname_make_buffered parse failure",
					r == 0);
			}
		}

		if(wire == NULL)
			buffer_create_from(&packet, "", wirelen);
		else buffer_create_from(&packet, wire, wirelen);
		memset(&buffer, 0, sizeof(buffer));
		r = dname_make_from_packet_buffered(&buffer,
			&packet, 0, 0);
		if(verb)
			printf("entry %d: dname_make_from_packet_buffered=%d\n",
				(int)i, r);
		if(test_entries_uncompressed[i].parse_succeed) {
			CuAssert(tc, "test dname_make_from_packet_buffered parse",
				r == (int)wirelen);
			CuAssert(tc, "test dname_make_from_packet_buffered string",
				strcmp(wiredname2str(wire),
				dname_to_string((void*)&buffer, NULL)) == 0);
		} else {
			CuAssert(tc, "test dname_make_from_packet_buffered parse failure",
				r == 0);
		}

		/* dname_make */
		if(wire != NULL) {
			uint8_t wbuf[MAXDOMAINLEN+1];
			const dname_type* dn;
			dn = dname_make(region, wire, 0);
			if(verb)
				printf("entry %d: dname_make=%s\n",
					(int)i,
					(dn?dname_to_string(dn, NULL):"NULL"));
			if(test_entries_uncompressed[i].parse_succeed) {
				CuAssert(tc, "test dname_make parse",
					dn != NULL);
				CuAssert(tc, "test dname_make string",
					strcmp(wiredname2str(wire),
					dname_to_string(dn, NULL)) == 0);
			} else {
				CuAssert(tc, "test dname_make parse failure",
					dn == NULL);
			}

			buffer_set_position(&packet, 0);
			r = dname_make_wire_from_packet(wbuf, &packet, 0);
			if(verb)
				printf("entry %d: dname_make_wire_from_packet=%d %s\n",
					(int)i, r,
					(r?wiredname2str(wbuf):"none"));
			if(test_entries_uncompressed[i].parse_succeed) {
				CuAssert(tc, "test dname_make_wire_from_packet parse",
					r == (int)wirelen);
				CuAssert(tc, "test dname_make_wire_from_packet string",
					strcmp(wiredname2str(wire),
					wiredname2str(wbuf)) == 0);
			} else {
				CuAssert(tc, "test dname_make_wire_from_packet parse failure",
					r == 0);
			}

			buffer_set_position(&packet, 0);
			dn = dname_make_from_packet(region, &packet, 0, 0);
			if(verb)
				printf("entry %d: dname_make_from_packet=%s\n",
					(int)i,
					(dn?dname_to_string(dn, NULL):"NULL"));
			if(test_entries_uncompressed[i].parse_succeed) {
				CuAssert(tc, "test dname_make_from_packet parse",
					dn != NULL);
				CuAssert(tc, "test dname_make_from_packet string",
					strcmp(wiredname2str(wire),
					dname_to_string(dn, NULL)) == 0);
			} else {
				CuAssert(tc, "test dname_make_from_packet parse failure",
					dn == NULL);
			}

			region_free_all(region);
		}
	}
	region_destroy(region);
}
