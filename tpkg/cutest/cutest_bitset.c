/*
	test bitset.h
*/

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "bitset.h"
#include "tpkg/cutest/cutest.h"

static void bitset_set_unset_test(CuTest *tc, size_t bits, size_t mod)
{
	size_t bit;
	struct nsd_bitset *bset;

	assert(mod == 1 || mod == 2);

	bset = malloc(nsd_bitset_size(bits));
	assert(bset != NULL);
	nsd_bitset_init(bset, bits);

	for(bit = 0; bit < bits; bit++) {
		CuAssert(tc, "", nsd_bitset_isset(bset, bit) == 0);
		if((bit % mod) == 0) {
			nsd_bitset_set(bset, bit);
			CuAssert(tc, "", nsd_bitset_isset(bset, bit) == 1);
		}
	}

	for(bit = 0; bit < bits; bit++) {
		CuAssert(tc, "", nsd_bitset_isset(bset, bit) == ((bit % mod) == 0));
	}

	for(bit = 0; bit < bits; bit++) {
		nsd_bitset_unset(bset, bit);
	}

	for(bit = 0; bit < bits; bit++) {
		CuAssert(tc, "", nsd_bitset_isset(bset, bit) == 0);
	}

	free(bset);
}

static void bitset_set_unset(CuTest *tc)
{
	int *bits, arr[] = { 1, 2, 3, 100, 101, 0 };

	for(bits = arr; *bits; bits++) {
		bitset_set_unset_test(tc, *bits, 1);
	}

	for(bits = arr; *bits; bits++) {
		bitset_set_unset_test(tc, *bits, 2);
	}
}

static void bitset_or_even_odd(CuTest *tc)
{
	struct nsd_bitset *destset1, *destset2, *srcset1, *srcset2;
	size_t bit, bits = 32;

	destset1 = malloc(nsd_bitset_size(bits-2));
	destset2 = malloc(nsd_bitset_size(bits+2));
	srcset1 = malloc(nsd_bitset_size(bits));
	srcset2 = malloc(nsd_bitset_size(bits));

	assert(destset1 != NULL);
	assert(destset2 != NULL);
	assert(srcset1 != NULL);
	assert(srcset2 != NULL);

	nsd_bitset_init(destset1, bits-2);
	nsd_bitset_init(destset2, bits+2);
	nsd_bitset_init(srcset1, bits);
	nsd_bitset_init(srcset2, bits);

	for(bit = 0; bit < bits; bit++) {
		if((bit % 2) == 0) {
			nsd_bitset_set(srcset1, bit);
		}
		if((bit % 2) == 1) {
			nsd_bitset_set(srcset2, bit);
		}
	}

	for(bit = 0; bit < (bits+2); bit++) {
		CuAssert(tc, "", nsd_bitset_isset(destset1, bit) == 0);
		CuAssert(tc, "", nsd_bitset_isset(destset2, bit) == 0);
	}

	nsd_bitset_or(destset1, srcset1, srcset2);
	nsd_bitset_or(destset2, srcset1, srcset2);

	for(bit = 0; bit < (bits+2); bit++) {
		CuAssert(tc, "", nsd_bitset_isset(destset1, bit) == ((bit < bits - 2) ? 1 : 0));
		CuAssert(tc, "", nsd_bitset_isset(destset2, bit) == ((bit < bits)     ? 1 : 0));
	}

	free(destset1);
	free(destset2);
	free(srcset1);
	free(srcset2);
}

static void bitset_or_even_even(CuTest *tc)
{
	struct nsd_bitset *destset1, *destset2, *srcset1, *srcset2;
	size_t bit, bits = 32;

	destset1 = malloc(nsd_bitset_size(bits-2));
	destset2 = malloc(nsd_bitset_size(bits+2));
	srcset1 = malloc(nsd_bitset_size(bits));
	srcset2 = malloc(nsd_bitset_size(bits));

	assert(destset1 != NULL);
	assert(destset2 != NULL);
	assert(srcset1 != NULL);
	assert(srcset2 != NULL);

	nsd_bitset_init(destset1, bits-2);
	nsd_bitset_init(destset2, bits+2);
	nsd_bitset_init(srcset1, bits);
	nsd_bitset_init(srcset2, bits);

	for(bit = 0; bit < bits; bit++) {
		if((bit % 2) == 0) {
			nsd_bitset_set(srcset1, bit);
			nsd_bitset_set(srcset2, bit);
		}
	}

	for(bit = 0; bit < (bits+2); bit++) {
		CuAssert(tc, "", nsd_bitset_isset(destset1, bit) == 0);
		CuAssert(tc, "", nsd_bitset_isset(destset2, bit) == 0);
	}

	nsd_bitset_or(destset1, srcset1, srcset2);
	nsd_bitset_or(destset2, srcset1, srcset2);

	for(bit = 0; bit < (bits+2); bit++) {
		CuAssert(tc, "", nsd_bitset_isset(destset1, bit)
			== ((bit < (bits-2)) ? ((bit % 2) == 0) : 0));
		CuAssert(tc, "", nsd_bitset_isset(destset2, bit)
			== ((bit < (bits))   ? ((bit % 2) == 0) : 0));
	}

	free(destset1);
	free(destset2);
	free(srcset1);
	free(srcset2);
}

CuSuite* reg_cutest_bitset(void)
{
	CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, bitset_set_unset);
	SUITE_ADD_TEST(suite, bitset_or_even_odd);
	SUITE_ADD_TEST(suite, bitset_or_even_even);

	return suite;
}
