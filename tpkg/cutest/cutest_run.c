/*
	run the unit tests
	log
	31 jan 06 (WW): created file.
	21 feb 06 (MG): reworked for cutest
*/
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"

CuSuite * reg_cutest_rbtree(void);
CuSuite * reg_cutest_util(void);
CuSuite * reg_cutest_options(void);
CuSuite * reg_cutest_dns(void);
CuSuite * reg_cutest_iterated_hash(void);
CuSuite * reg_cutest_dname(void);
CuSuite * reg_cutest_region(void);

/* dummy functions to link */
struct nsd;
int writepid(struct nsd * ATTR_UNUSED(nsd))
{
	return 0;
}
void unlinkpid(const char * ATTR_UNUSED(file))
{
}
void bind8_stats(struct nsd * ATTR_UNUSED(nsd))
{
}

void disp_callback(int failed)
{
	if(failed)
		fprintf(stderr, "F");
	else	fprintf(stderr, ".");
}

int runalltests(void)
{
	CuSuite *suite = CuSuiteNew();
	CuString *output = CuStringNew();

	CuSuiteAddSuite(suite, reg_cutest_region());
	CuSuiteAddSuite(suite, reg_cutest_dname());
	CuSuiteAddSuite(suite, reg_cutest_dns());
	CuSuiteAddSuite(suite, reg_cutest_options());
	CuSuiteAddSuite(suite, reg_cutest_rbtree());
	CuSuiteAddSuite(suite, reg_cutest_util());
	CuSuiteAddSuite(suite, reg_cutest_iterated_hash());

	CuSuiteRunDisplay(suite, disp_callback);
	fprintf(stderr, "\n");

 	/* CuSuiteSummary(suite, output); */
        CuSuiteDetails(suite, output);
        printf("%s\n", output->buffer);
	return suite->failCount;
}

int main(void)
{
	if(runalltests() > 0)
		return 1;
	else return 0;
}
