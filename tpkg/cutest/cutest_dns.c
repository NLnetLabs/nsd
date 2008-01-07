/*
	test dns.c
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "dns.h"

static void dns_1(CuTest *tc);

CuSuite* reg_cutest_dns(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, dns_1);
	return suite;
}

static void dns_1(CuTest *tc)
{
	/* Check consistency of rrtype descriptor table. */
	int i;
	struct rrtype_descriptor* d;
	struct rrtype_descriptor* start = rrtype_descriptor_by_type(0);
	for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
		struct rrtype_descriptor* d = rrtype_descriptor_by_type(i);
		CuAssert(tc, "dns rrtype descriptor: type", i == d->type);
		CuAssert(tc, "dns rrtype descriptor: offset", i == d - start);
	}

	d = rrtype_descriptor_by_type(TYPE_NSEC3);
	CuAssert(tc, "dns rrtype descriptor: type nsec3", d->type == TYPE_NSEC3);
}
