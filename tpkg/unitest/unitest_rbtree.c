/*
	test rbtree
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include "CUnit/CUnit.h"
#include "region-allocator.h"
#include "rbtree.h"

static int init_rbtree(void);
static int clean_rbtree(void);
static void rbtree_1(void);
static void rbtree_2(void);

void reg_unitest_rbtree(void)
{
        CU_pSuite pSuite = CU_add_suite("rbtree suite", init_rbtree, clean_rbtree);
        if (NULL == pSuite) {
                printf("CUnit Error adding test suite. %s\n", CU_get_error_msg());
                CU_cleanup_registry();
                exit(1);
        }

        if ((NULL == CU_add_test(pSuite, "rbtree 1", rbtree_1)) ||
        (NULL == CU_add_test(pSuite, "rbtree 2", rbtree_2)))
        {
                CU_cleanup_registry();
		exit(1);
        }
}

/* we will test an int tree */
struct testnode {
	rbnode_t	node;
	int		x;
};

static region_type* reg = 0;
static struct testnode* tree = 0;

static int testcompare(const void *lhs, const void *rhs)
{
	return 0;
}

static int init_rbtree(void)
{
	reg = region_create(malloc, free);
	if(reg == 0) return 1;
	tree = (struct testnode*)rbtree_create(reg, testcompare);
	if(tree == 0) return 1;
	return 0;
}

static int clean_rbtree(void)
{
	region_destroy(reg);
	return 0;
}

static void rbtree_1(void)
{
	/* tree should be empty on start. */
	CU_ASSERT(rbtree_first((rbtree_t*)tree) == &rbtree_null_node);
	CU_ASSERT(rbtree_last((rbtree_t*)tree) == &rbtree_null_node);
}

static void rbtree_2(void)
{
}

