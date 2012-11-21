/*
	test rrl.h
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "rrl.h"

#ifdef RATELIMIT
static void rrl_1(CuTest *tc);

CuSuite* reg_cutest_rrl(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, rrl_1);
	return suite;
}

static void rrl_1(CuTest *tc)
{
	query_type q;
	uint64_t source = 0x100;
	uint32_t now = 123;
	uint32_t hash = 0x743;
	uint16_t c = rrl_type_nxdomain;
	uint32_t i;
	uint32_t rate = 200;
	uint32_t m = 400; /* ratelimit */
	memset(&q, 0, sizeof(q));

	rrl_init(0);

	CuAssert(tc, "rrl 1st query", 1 == rrl_update(&q, hash, source, c, now, m));
	for(i=1; i<rate; i++) {
		CuAssert(tc, "rrl rate check", i+1 == rrl_update(&q, hash, source, c, now, m));
	}

	/* next second, again that many queries. */
	now++;
	for(i=0; i<rate-1; i++) {
		rrl_update(&q, hash, source, c, now, m);
	}
	CuAssert(tc, "rrl rate(t+1) check", rate+rate/2 == rrl_update(&q, hash, source, c, now, m));

	/* three seconds pass /8 rate */
	/* r(t) = rate, r(t+1)=rate, now three seconds pass */
	now += 3;
	CuAssert(tc, "rrl rate(t+4) check", rate/4+rate/8 == rrl_update(&q, hash, source, c, now, m));

	/* different source, recount */
	source++;
	for(i=0; i<rate; i++) {
		CuAssert(tc, "rrl source check", i+1 == rrl_update(&q, hash, source, c, now, m));
	}

	/* now at 'rate', but one second passes */
	now += 1;
	CuAssert(tc, "rrl time check", rate == rrl_update(&q, hash, source, c, now, m));
	/* the one extra query is rounded down in /2 */
	now += 1;
	CuAssert(tc, "rrl time check", rate/2+1 == rrl_update(&q, hash, source, c, now, m));
	now += 1;
	CuAssert(tc, "rrl time check", rate/4+1 == rrl_update(&q, hash, source, c, now, m));
}
#endif /* RATELIMIT */
