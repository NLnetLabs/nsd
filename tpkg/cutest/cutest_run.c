/*
	run the unit tests
	log
	31 jan 06 (WW): created file.
	21 feb 06 (MG): reworked for cutest
	28 oct 19 (JK): run tests based on pattern
*/
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "tpkg/cutest/cutest.h"
#include "tpkg/cutest/qtest.h"
#include "nsd.h"

CuSuite * reg_cutest_radtree(void);
CuSuite * reg_cutest_rbtree(void);
CuSuite * reg_cutest_util(void);
CuSuite * reg_cutest_options(void);
CuSuite * reg_cutest_dns(void);
CuSuite * reg_cutest_iterated_hash(void);
CuSuite * reg_cutest_dname(void);
CuSuite * reg_cutest_region(void);
CuSuite * reg_cutest_udb(void);
CuSuite * reg_cutest_namedb(void);
CuSuite * reg_cutest_bitset(void);
#ifdef RATELIMIT
CuSuite * reg_cutest_rrl(void);
#endif
CuSuite * reg_cutest_popen3(void);
CuSuite * reg_cutest_iter(void);
CuSuite * reg_cutest_event(void);

/* dummy functions to link */
struct nsd nsd;
int writepid(struct nsd * ATTR_UNUSED(nsd))
{
	return 0;
}
void unlinkpid(const char * ATTR_UNUSED(file), const char* ATTR_UNUSED(username))
{
}
void bind8_stats(struct nsd * ATTR_UNUSED(nsd))
{
}

void sig_handler(int ATTR_UNUSED(sig))
{
}

void disp_callback(CuTestResult result)
{
	if(result == CuFailed)
		fprintf(stderr, "F");
	else if(result == CuSkipped)
		fprintf(stderr, "S");
	else	fprintf(stderr, ".");
}

int runalltests(const char *regex)
{
	CuSuite *suite = CuSuiteNew();
	CuString *output = CuStringNew();
	int fail;

	CuSuiteAddSuite(suite, reg_cutest_region());
	CuSuiteAddSuite(suite, reg_cutest_dname());
	CuSuiteAddSuite(suite, reg_cutest_dns());
	CuSuiteAddSuite(suite, reg_cutest_options());
	CuSuiteAddSuite(suite, reg_cutest_radtree());
	CuSuiteAddSuite(suite, reg_cutest_rbtree());
	CuSuiteAddSuite(suite, reg_cutest_util());
	CuSuiteAddSuite(suite, reg_cutest_iterated_hash());
#ifdef HAVE_MMAP
	CuSuiteAddSuite(suite, reg_cutest_udb());
#endif
	CuSuiteAddSuite(suite, reg_cutest_namedb());
#ifdef RATELIMIT
	CuSuiteAddSuite(suite, reg_cutest_rrl());
#endif
	CuSuiteAddSuite(suite, reg_cutest_bitset());
	CuSuiteAddSuite(suite, reg_cutest_popen3());
	CuSuiteAddSuite(suite, reg_cutest_iter());
	CuSuiteAddSuite(suite, reg_cutest_event());

	if(CuSuiteRunRegexDisplay(suite, regex, disp_callback) == -1) {
		fprintf(stderr, "invalid regular expression");
	}
	fprintf(stderr, "\n");

 	/* CuSuiteSummary(suite, output); */
        CuSuiteDetails(suite, output);
        printf("%s\n", output->buffer);
	fail = suite->failCount;
	CuStringFree(output);
	CuSuiteFree(suite);
	return fail;
}

/** check if inet_ntop works as expected for string comparisons */
static int
check_inet_ntop(void)
{
#ifdef AF_INET6
	const char* s = "2001:610:240:0:53:cc:12:174";
	char r[1024];
	struct in6_addr a;
	if(inet_pton(AF_INET6, s, &a) != 1)
		return 1;
	if(inet_ntop(AF_INET6, &a, r, sizeof(r)) == NULL)
		return 1;
	printf("input %s becomes %s\n", s, r);
	if(strcmp(s, r) == 0)
		return 0;
	return 1;
#else
	return 1;
#endif
}

extern char *optarg;
extern int optind;

int main(int argc, char* argv[])
{
	int c;
	char* config = NULL, *qfile=NULL;
	int verb=0;
	unsigned seed;
	char *regex = ".*";
	log_init("cutest");
	while((c = getopt(argc, argv, "c:hq:r:tv")) != -1) {
		switch(c) {
		case 't':
			return check_inet_ntop();
		case 'c':
			config = optarg;
			break;
		case 'q':
			qfile = optarg;
			break;
		case 'v':
			verb++;
			break;
		case 'r':
			regex = optarg;
			break;
		case 'h':
		default:
			printf("usage: %s [opts]\n", argv[0]);
			printf("no options: run unit test\n");
			printf("-q file: run query answer test with file\n");
			printf("-c config: specify nsd.conf file\n");
			printf("-t test inet_ntop for string comparisons.\n");
			printf("-v verbose, -vv, -vvv\n");
			printf("-r regex: run only tests that match regex.\n");
			printf("-h show help\n");
			return 1;
		}
	}
	/* argc -= optind;
	   argv += optind; move along argc, argv, for positional args */
	if(qfile)
		return runqtest(config, qfile, verb);

	/* init random */
	seed = time(NULL) ^ getpid();
	fprintf(stderr, "srandom(%u)\n", seed);
	srandom(seed);

	if(runalltests(regex) > 0)
		return 1;
	else return 0;
}
