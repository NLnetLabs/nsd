/*
	test xfrd-tcp.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "xfrd-tcp.h"

static void xfrd_tcp_1(CuTest *tc);

CuSuite* reg_cutest_xfrd_tcp(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, xfrd_tcp_1);
	return suite;
}

/* compare for sort of ID values */
static int
compare_value(const void* x, const void* y)
{
	const uint16_t* ax = (const uint16_t*)x;
	const uint16_t* ay = (const uint16_t*)y;
	if(*ax < *ay)
		return -1;
	if(*ax > *ay)
		return 1;
	return 0;
}

/* check if array contains no duplicates. */
static void check_nodupes(CuTest* tc, uint16_t* array, int num)
{
	int i;
	qsort(array, num, sizeof(array[0]), &compare_value);
	for(i=0; i<num-1; i++) {
		if(i+1 < num) {
			CuAssert(tc, "checknodupes",
				array[i] != array[i+1]);
		}
	}
}

static void testarray(CuTest* tc, int num, int max)
{
	uint16_t array[65536];
	memset(array, 0, sizeof(array[0])*65536);
	pick_id_values(array, num, max);
	check_nodupes(tc, array, num);
}

static void xfrd_tcp_1(CuTest *tc)
{
	/* test void pick_id_values(uint16_t* array, int num, int max); */
	testarray(tc, 1, 1);
	testarray(tc, 10, 10);
	testarray(tc, 1, 1);
	testarray(tc, 10, 10);
	testarray(tc, 100, 100);
	testarray(tc, 32768, 32768);
	testarray(tc, 5, 10);
	testarray(tc, 5, 10);
	testarray(tc, 5, 65536);
}
