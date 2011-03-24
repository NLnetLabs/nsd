/*
	test iterated_hash.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "util.h"
#include "iterated_hash.h"
#include "dname.h"

static void hash_1(CuTest *tc);

CuSuite* reg_cutest_iterated_hash(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, hash_1);
	return suite;
}

static void hash_1(CuTest *tc)
{
#ifdef NSEC3
	/* test the iterated_hash function */
	unsigned char out[SHA_DIGEST_LENGTH];
	unsigned char salt[36];
	int saltlen = 0;
	char buf[1000];
	int iterations = 0;
	int i;
	int count = 10000;

	CuAssert(tc, "check hardcoded SHA-1 size", sizeof(out)==20);

	for(i=0; i<count; i++)
	{
		snprintf(buf, sizeof(buf), "example%d.com", i);
		CuAssert(tc, "iterated_hash test 1", 
			sizeof(out)== iterated_hash(out, salt, saltlen, 
			(unsigned char*)buf, strlen(buf), iterations));
	}
#else
	(void)tc;
#endif /* NSEC3 */
}
