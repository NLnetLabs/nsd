/*
	test util.h
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

static void util_1(CuTest *tc);
static void util_2(CuTest *tc);
static void util_3(CuTest *tc);
static void util_4(CuTest *tc);
static void util_5(CuTest *tc);

CuSuite* reg_cutest_util(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, util_1);
	SUITE_ADD_TEST(suite, util_2);
	SUITE_ADD_TEST(suite, util_3);
	SUITE_ADD_TEST(suite, util_4);
	SUITE_ADD_TEST(suite, util_5);
	return suite;
}

/* 40 Octets filled with "0" */
/* CPCS-UU = 0, CPI = 0, Length = 40, CRC-32 = 864d7f99 */
char pkt_1[48]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x28,0x86,0x4d,0x7f,0x99};
uint32_t crc_1 = 0x864d7f99;

/* 40 Octets filled with "1" */
/* CPCS-UU = 0, CPI = 0, Length = 40, CRC-32 = c55e457a */
char pkt_2[48]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                   0x00,0x00,0x00,0x28,0xc5,0x5e,0x45,0x7a};
uint32_t crc_2 = 0xc55e457a;

/* 40 Octets counting: 1 to 40 */
/* CPCS-UU = 0, CPI = 0, Length = 40, CRC-32 = bf671ed0 */
char pkt_3[48]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
                   0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,
                   0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,
                   0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
                   0x00,0x00,0x00,0x28,0xbf,0x67,0x1e,0xd0};
uint32_t crc_3 = 0xbf671ed0;

/* 40 Octets counting: 1 to 40 */
/* CPCS-UU = 11, CPI = 22, CRC-32 = acba602a */
char pkt_4[48]={0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,
                   0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,
                   0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,
                   0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,
                   0x11,0x22,0x00,0x28,0xac,0xba,0x60,0x2a};
uint32_t crc_4 = 0xacba602a;

static void util_1(CuTest *tc)
{
	uint32_t crc;

	crc = compute_crc(~0, (uint8_t*)pkt_1, 44);
	crc = ~crc;
	CuAssert(tc, "crc test 1 correct", crc == crc_1);
	
	crc = compute_crc(~0, (uint8_t*)pkt_2, 44);
	crc = ~crc;
	CuAssert(tc, "crc test 2 correct", crc == crc_2);
	
	crc = compute_crc(~0, (uint8_t*)pkt_3, 44);
	crc = ~crc;
	CuAssert(tc, "crc test 3 correct", crc == crc_3);
	
	crc = compute_crc(~0, (uint8_t*)pkt_4, 44);
	crc = ~crc;
	CuAssert(tc, "crc test 4 correct", crc == crc_4);
}

static void util_2(CuTest *tc)
{
	uint32_t crc;
	int i;
	int len = 44;

	/* test that incremental calls work as well */
	crc = ~0;
	for(i=0; i<len; i++)
		crc = compute_crc(crc, (uint8_t*)&pkt_1[i], 1);
	crc = ~crc;
	CuAssert(tc, "crc test 1 correct", crc == crc_1);
	
	crc = ~0;
	for(i=0; i<len; i++)
		crc = compute_crc(crc, (uint8_t*)&pkt_2[i], 1);
	crc = ~crc;
	CuAssert(tc, "crc test 2 correct", crc == crc_2);
	
	crc = ~0;
	for(i=0; i<len; i++)
		crc = compute_crc(crc, (uint8_t*)&pkt_3[i], 1);
	crc = ~crc;
	CuAssert(tc, "crc test 3 correct", crc == crc_3);
	
	crc = ~0;
	for(i=0; i<len; i++)
		crc = compute_crc(crc, (uint8_t*)&pkt_4[i], 1);
	crc = ~crc;
	CuAssert(tc, "crc test 4 correct", crc == crc_4);
	
}

static void util_3(CuTest *tc)
{
	/* test base32 encoding */
	int i;
	uint8_t bin[32];
	uint8_t bin2[32];
	char str[32*5+1];
	
	for(i=0; i<10000; ++i)
	{
		int k;
		int len=20;
		for(k=0; k<len; k++)
			bin[k] = random();
		CuAssert(tc, "b32 test ntop",
			-1!=b32_ntop(bin, len, str, sizeof(str)));
		CuAssert(tc, "b32 test pton",
			len==b32_pton(str, bin2, sizeof(bin2)));
		CuAssert(tc, "b32 test cmp",
			memcmp(bin, bin2, len)==0);
	}
}

static void util_4(CuTest *tc)
{
	/* test hex_pton */
	uint8_t dest[100];
	char buf[200];
	const char* teststr = "0102034567890ABCDEFF";

	CuAssert(tc, "test uneven hex pton", hex_pton("123", dest, 10)==-1);
	CuAssert(tc, "test too long hex pton", hex_pton("12345678", dest, 2)==-1);

	CuAssert(tc, "test hex pton", hex_pton(teststr, dest, 20)==10);
	CuAssert(tc, "test if pton is correct with ntop", hex_ntop(dest, 10, buf, 100) == 20);
	/* strings differ only in case */
	CuAssert(tc, "test results of pton ntop", strcasecmp(buf, teststr)==0);
}

static void util_5(CuTest *tc)
{
	/* test ssize_t print_socket_servers(struct nsd_bitset *bitset, char *buf, size_t bufsz) */
	char *expect, result[100];
	struct nsd_bitset *bset = xalloc(nsd_bitset_size(5));
	nsd_bitset_init(bset, 5);

	expect = "(none)";
	nsd_bitset_zero(bset);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: (none)",
		expect, result);

	expect = "(all)";
	nsd_bitset_set(bset, 0);
	nsd_bitset_set(bset, 1);
	nsd_bitset_set(bset, 2);
	nsd_bitset_set(bset, 3);
	nsd_bitset_set(bset, 4);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: (all)",
		expect, result);

	expect = "1 2 4 5";
	nsd_bitset_zero(bset);
	nsd_bitset_set(bset, 0);
	nsd_bitset_set(bset, 1);
	nsd_bitset_set(bset, 3);
	nsd_bitset_set(bset, 4);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: 1 2 4 5",
		expect, result);

	expect = "2-5";
	nsd_bitset_zero(bset);
	nsd_bitset_set(bset, 1);
	nsd_bitset_set(bset, 2);
	nsd_bitset_set(bset, 3);
	nsd_bitset_set(bset, 4);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: 2-5",
		expect, result);

	expect = "1-3 5";
	nsd_bitset_zero(bset);
	nsd_bitset_set(bset, 0);
	nsd_bitset_set(bset, 1);
	nsd_bitset_set(bset, 2);
	nsd_bitset_set(bset, 4);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: 1-3 5",
		expect, result);

	expect = "1-4";
	nsd_bitset_zero(bset);
	nsd_bitset_set(bset, 0);
	nsd_bitset_set(bset, 1);
	nsd_bitset_set(bset, 2);
	nsd_bitset_set(bset, 3);
	(void)print_socket_servers(bset, result, sizeof(result));
	CuAssertStrEquals_Msg(tc, "test socket servers output: 1-4",
		expect, result);

	free(bset);
}
