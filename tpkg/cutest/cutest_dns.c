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
	const struct nsd_type_descriptor* d;
	const struct nsd_type_descriptor* start = nsd_type_descriptor(0);
	for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
		const struct nsd_type_descriptor* d = start+i;
		const struct nsd_type_descriptor* lookup = nsd_type_descriptor(
			d->type);

		if(i <= 264) {
			CuAssert(tc, "dns rrtype descriptor: index",
				i == d->type);
			CuAssert(tc, "dns rrtype descriptor: offset",
				i == d - start);
		}
		CuAssert(tc, "dns rrtype descriptor: type",
			lookup->type == d->type);
	}

	d = nsd_type_descriptor(TYPE_NSEC3);
	CuAssert(tc, "dns rrtype descriptor: type nsec3", d->type == TYPE_NSEC3);
}
