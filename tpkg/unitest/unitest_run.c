/*
	run the unit tests
	log
	31 jan 06 (WW): created file.
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "CUnit/Basic.h"

void reg_unitest_rbtree(void);

/* dummy functions to link */
struct nsd;
int writepid(struct nsd * ATTR_UNUSED(nsd))
{
	return 0;
}
void bind8_stats(struct nsd * ATTR_UNUSED(nsd))
{
}


/* show summary of errors on stdout, in a clean (nagless) format. */
void ShowSummary(void)
{
	CU_pRunSummary pRunSummary = CU_get_run_summary();
	CU_pTestRegistry pRegistry = CU_get_registry();

	if(!pRunSummary || !pRegistry)
	{
		printf("Error in ShowSummary(), NULL ptr.\n");
		return;
	}
	
	printf("Unittest         Total            Ran         Passed         Failed\n"
               "suites %15u%15u%15u%15u\n"
               "tests  %15u%15u%15u%15u\n"
               "asserts%15u%15u%15u%15u\n",
		pRegistry->uiNumberOfSuites,
		pRunSummary->nSuitesRun,
		pRegistry->uiNumberOfSuites-pRunSummary->nSuitesFailed,
		pRunSummary->nSuitesFailed,
		pRegistry->uiNumberOfTests,
		pRunSummary->nTestsRun,
		pRunSummary->nTestsRun - pRunSummary->nTestsFailed,
		pRunSummary->nTestsFailed,
		pRunSummary->nAsserts,
		pRunSummary->nAsserts,
		pRunSummary->nAsserts - pRunSummary->nAssertsFailed,
		pRunSummary->nAssertsFailed);
}

void ShowErrors(void)
{
	CU_pFailureRecord p = CU_get_failure_list();
	int i=1;

	if(!p)
	{
		printf("No errors.\n");
		return;
	}
	
	printf("nr. suite test [file:line] condition\n");
	for(; p; p=p->pNext,++i)
	{
		printf("%d. %s %s [%s:%d] %s\n", i,
			p->pSuite->pName ? p->pSuite->pName : "",
			p->pTest->pName ? p->pTest->pName : "",
        		p->strFileName ? p->strFileName : "",
        		p->uiLineNumber, p->strCondition ? p->strCondition : "");
	}
}

/* The main() function for setting up and running the tests.
 * Returns a CUE_SUCCESS on successful running, another
 * CUnit error code on failure.
 */
int main(int argc, const char *argv[])
{
	/* initialize the CUnit test registry */
	if (CUE_SUCCESS != CU_initialize_registry())
	{
		printf("CUnit Error initializing test registry. %s\n", CU_get_error_msg());
		return 1;
	}

	/* register the tests */
	reg_unitest_rbtree();

	/* set to silent, so that CUnit does not show a big banner ad */
	/* set to VERBOSE for more detailed output */
	/* CU_BRM_VERBOSE or SILENT or NORMAL */
	if(argc>=2 && strcmp(argv[1], "-q")==0)
		CU_basic_set_mode(CU_BRM_SILENT);
	else CU_basic_set_mode(CU_BRM_VERBOSE);

	/* Run all tests using the CUnit Basic interface */
	if(CU_basic_run_tests() != CUE_SUCCESS)
	{
		printf("CUnit framework error running tests. %s\n", CU_get_error_msg());
		ShowSummary();
		CU_cleanup_registry();
		return 1;
	}

	if(CU_basic_get_mode() == CU_BRM_SILENT)
		ShowSummary();

	if(CU_get_number_of_failures() > 0)
	{
		ShowErrors();
		printf("There are %d errors in unit tests.\n", CU_get_number_of_failure_records());
		CU_cleanup_registry();
		/* exit failure */
		return 1;
	}
	printf("All unittests OK.\n");
	CU_cleanup_registry();
	/* exit success. */
	return 0;
}
