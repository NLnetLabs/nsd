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
static void rbtree_3(void);
static void rbtree_4(void);
static void rbtree_5(void);
static void rbtree_6(void);
static void rbtree_7(void);
static void rbtree_8(void);
static void rbtree_9(void);
static void rbtree_10(void);
static int testcompare(const void *lhs, const void *rhs);
static void test_tree_integrity(rbtree_t* tree);

void reg_unitest_rbtree(void)
{
        CU_pSuite pSuite = CU_add_suite("rbtree suite", init_rbtree, clean_rbtree);
        if (NULL == pSuite) {
                printf("CUnit Error adding test suite. %s\n", CU_get_error_msg());
                CU_cleanup_registry();
                exit(1);
        }

        if ((NULL == CU_add_test(pSuite, "rbtree 1: check empty", rbtree_1))
          ||(NULL == CU_add_test(pSuite, "rbtree 2: check duplicate element", rbtree_2))
          ||(NULL == CU_add_test(pSuite, "rbtree 3: check null node", rbtree_3))
          ||(NULL == CU_add_test(pSuite, "rbtree 4: check tree invariant", rbtree_4))
          ||(NULL == CU_add_test(pSuite, "rbtree 5: extensive check", rbtree_5))
          ||(NULL == CU_add_test(pSuite, "rbtree 6: test find_less_equal", rbtree_6))
          ||(NULL == CU_add_test(pSuite, "rbtree 7: first, last", rbtree_7))
          ||(NULL == CU_add_test(pSuite, "rbtree 8: next, previous", rbtree_8))
          ||(NULL == CU_add_test(pSuite, "rbtree 9: delete element", rbtree_9))
          ||(NULL == CU_add_test(pSuite, "rbtree 10: delete more", rbtree_10)))
        {
                printf("CUnit Error adding test. %s\n", CU_get_error_msg());
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
static rbtree_t* tree = 0; /* tree of struct testnode */

/* init rbtree tests */
static int init_rbtree(void)
{
	reg = region_create(malloc, free);
	if(reg == 0) return 1;
	tree = rbtree_create(reg, testcompare);
	if(tree == 0) return 1;
	return 0;
}

/* cleanup rbtree tests */
static int clean_rbtree(void)
{
	region_destroy(reg);
	return 0;
}

/* NOTE! compare func can get two 0 ptrs. Return 0 then. */
static int testcompare(const void *lhs, const void *rhs)
{
	int *left = (int*) lhs;
	int *right = (int*) rhs;
	if(lhs == rhs) return 0;
	return *left - *right;
}

/* our test tree displayed for test comparison */
/* sink is assumed to be big enough to contain the tree */
/* int is the size of the added text */
static int tree_print_sub(struct testnode* tree, int depth, char* sink, char* prefix)
{
	char *oldsink = sink;
	int preflen = strlen(prefix);
	sink += sprintf(sink, "%s", prefix);
	if(depth > 0) sink += sprintf(sink, "-");
	if((rbnode_t*)tree == RBTREE_NULL) {
		sink += sprintf(sink, "**\n");
		return sink-oldsink;
	}
	/* print this node */
	sink += sprintf(sink, "%d", tree->x);
	if(tree->node.color) sink += sprintf(sink, "R\n");
	else sink += sprintf(sink, "B\n");

	if(tree->node.left != RBTREE_NULL || tree->node.right != RBTREE_NULL)
	{
		if(depth > 0) strcat(prefix, " ");
		strcat(prefix, "|");
		/* recurse. */
		sink += tree_print_sub((struct testnode*)tree->node.left, depth+1, sink, prefix);
		prefix[strlen(prefix)-1] = ' ';
		sink += tree_print_sub((struct testnode*)tree->node.right, depth+1, sink, prefix);
		prefix[preflen] = 0;
	}
	return sink - oldsink;
}

void tree_print(rbtree_t* tree)
{
	char buf[1024000];
	char prefixbuf[10240];
	char *sink = buf;
	sink += sprintf(sink, "Rbtree count=%d\n", tree->count);
	prefixbuf[0]=0;
	sink += tree_print_sub((struct testnode*)tree->root, 0, sink, prefixbuf);
	CU_ASSERT((size_t)(sink - buf) < sizeof(buf));
	printf("%s\n", buf);
}

static void tree_print_safe_sub(struct testnode* node)
{
	if((rbnode_t*)node == RBTREE_NULL) {
		return;
	}
	printf("Tree node (%x): ", (int)node);
	printf("parent=%x. left=%x. right=%x. key=%x. Color=%x. x=%d\n",
		(int)node->node.parent, (int)node->node.left, (int)node->node.right, 
		(int)node->node.key, node->node.color, node->x);
	tree_print_safe_sub((struct testnode*)node->node.left);
	tree_print_safe_sub((struct testnode*)node->node.right);
}

/* very very safe version of tree print */
void tree_print_safe(rbtree_t* tree)
{
	printf("Rbtree (at %x)", (int) tree);
	printf(" region=%x root=%x count=%d current=%x cmp=%x\n",
		(int)tree->region, (int)tree->root, (int)tree->count,
		(int)tree->_node, (int)tree->cmp);
	if(tree->root) 
		tree_print_safe_sub((struct testnode*)tree->root);
}

static void rbtree_1(void)
{
	/* tree should be empty on start. */
	CU_ASSERT(rbtree_first((rbtree_t*)tree) == &rbtree_null_node);
	CU_ASSERT(rbtree_last((rbtree_t*)tree) == &rbtree_null_node);
	test_tree_integrity(tree);
}

static void rbtree_2(void)
{
	// add same element twice.
	struct testnode *t;

	t = (struct testnode*) region_alloc(reg, sizeof(struct testnode));
	memset(t, 0x23, sizeof(struct testnode));
	t->x = 4;
	t->node.key = &t->x;
	CU_ASSERT(rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) != 0);
	CU_ASSERT(rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0);

	CU_ASSERT(tree->count == 1);
	CU_ASSERT(tree->root->parent == RBTREE_NULL);
	test_tree_integrity(tree);

	if(0) tree_print_safe(tree);

	if(0) tree_print(tree);
}

static int GetTestValue(double max)
{
	return (int)(max*rand() / (RAND_MAX+1.0));
}

static int AddRandomElement(rbtree_t* tree, int maxval)
{	
	struct testnode *t;

	t = (struct testnode*) region_alloc(reg, sizeof(struct testnode));
	t->node = *RBTREE_NULL;
	t->x = GetTestValue(maxval);
	t->node.key = &t->x;
	rbtree_insert((rbtree_t*)tree, (rbnode_t*)t);
	CU_ASSERT(rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0);
	return t->x;
}

static int AddElement(rbtree_t* tree, int val)
{	
	struct testnode *t;

	t = (struct testnode*) region_alloc(reg, sizeof(struct testnode));
	t->node = *RBTREE_NULL;
	t->x = val;
	t->node.key = &t->x;
	rbtree_insert((rbtree_t*)tree, (rbnode_t*)t);
	CU_ASSERT(rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0);
	return t->x;
}

static void rbtree_3(void)
{
	/* check RBTREE_NULL contents */
	CU_ASSERT(RBTREE_NULL != 0);
	CU_ASSERT((RBTREE_NULL)->parent == RBTREE_NULL);
	CU_ASSERT((RBTREE_NULL)->left == RBTREE_NULL);
	CU_ASSERT((RBTREE_NULL)->right == RBTREE_NULL);
	CU_ASSERT((RBTREE_NULL)->color == 0);
	CU_ASSERT((RBTREE_NULL)->key == 0);
}

/* make sure that pointers are OK. Also check that key != 0. */
static void test_tree_pointers_sub(rbnode_t *node)
{
	CU_ASSERT(node != 0);
	CU_ASSERT(node->key != 0);
	CU_ASSERT(node->key == &((struct testnode*)node)->x);

	if(node->left != RBTREE_NULL)
	{
		CU_ASSERT(node == node->left->parent);
		test_tree_pointers_sub(node->left);
	}
	if(node->right != RBTREE_NULL)
	{
		CU_ASSERT(node == node->right->parent);
		test_tree_pointers_sub(node->right);
	}
}

/* make sure pointers are consistent */
static void test_tree_pointers(rbtree_t* tree)
{
	CU_ASSERT(tree != 0);

	if(tree->count == 0)
	{
		CU_ASSERT(tree->region != 0);
		CU_ASSERT(tree->root == RBTREE_NULL);
		return;
	}

	CU_ASSERT(tree->root->parent == RBTREE_NULL);
	test_tree_pointers_sub(tree->root);
}

/* count non-null nodes in the tree */
static size_t test_tree_count_sub(rbnode_t* node)
{
	if(node == RBTREE_NULL) return 0;
	return test_tree_count_sub(node->left) + test_tree_count_sub(node->right) + 1;
}

static void test_tree_count(rbtree_t* tree)
{
	size_t mycount = test_tree_count_sub(tree->root);
	CU_ASSERT(mycount == tree->count);
}

/* see if the tree is properly sorted */
/* values are only allowed min < val < max */
static void test_tree_sorting_sub(rbnode_t* node, int* min, int* max)
{
	int value = ((struct testnode*)node)->x;
	if(min) CU_ASSERT(*min < value);
	if(max) CU_ASSERT(value < *max);

	/* left of this node all nodes must be smaller */
	if(node->left != RBTREE_NULL)
		test_tree_sorting_sub(node->left, min, &value);
	/* right of this node all nodes must be larger */
	if(node->right != RBTREE_NULL)
		test_tree_sorting_sub(node->right, &value, max);
}

static void test_tree_sorting(rbtree_t* tree)
{
	if(tree->count > 0)
		test_tree_sorting_sub(tree->root, 0, 0);
}

/* test that values are 0(Black) and 1(Red), and that all paths have 
   the rbtree invariant. */
static void test_tree_RBvalues_countB(rbnode_t *node, int Bcount, int *min, int *max)
{
	if(node == RBTREE_NULL)
	{
		/* check length of black-node-path */
		if(*min==-1 || Bcount<*min) *min=Bcount;
		if(*max==-1 || Bcount>*max) *max=Bcount;
		return;
	}
	if(node->color == 0) Bcount++;
	test_tree_RBvalues_countB(node->left, Bcount, min, max);
	test_tree_RBvalues_countB(node->right, Bcount, min, max);
}

static void test_tree_RBvalues_sub1(rbnode_t* node)
{
	int min, max;
	CU_ASSERT(node->color == 0 || node->color == 1);
	if(node == RBTREE_NULL) return;

	/* both left and right below a red node are black */
	if(node->color == 1) 
	{
		CU_ASSERT(node->left->color == 0);
		CU_ASSERT(node->right->color == 0);
	}

	/*All paths from any given node to its leaf nodes contain the same number of black nodes.*/
	/* so count the min number of black nodes to leaf nodes and max number */
	/* note this makes the test O(N^2) */
	min = -1; max = -1;
	test_tree_RBvalues_countB(node, 0, &min, &max);
	CU_ASSERT(min == max);

	test_tree_RBvalues_sub1(node->left);
	test_tree_RBvalues_sub1(node->right);
}

static void test_tree_RBvalues(rbtree_t* tree)
{
	/* the root must be black */
	CU_ASSERT(tree->root->color == 0);
	
	test_tree_RBvalues_sub1(tree->root);
}

static void test_tree_integrity(rbtree_t* tree)
{
	test_tree_pointers(tree);
	test_tree_count(tree);
	test_tree_sorting(tree);
	test_tree_RBvalues(tree);
}

static void rbtree_4(void)
{
	int i;
	int num_add = 15;
	srand(23);
	for(i=0; i<num_add; ++i)
	{
		AddRandomElement(tree, 100);
		test_tree_integrity(tree);
	}

	if(0) tree_print(tree);
	test_tree_integrity(tree);
}

/* like 4 but more extensive */
static void rbtree_5(void)
{
	int i;
	int num_add = 1000;
	srand(35);
	/*printf("rbtree_5: ");*/
	for(i=0; i<num_add; ++i)
	{
		/*if(i % (num_add/66) == 0) printf(".");*/
		AddRandomElement(tree, num_add);
		test_tree_integrity(tree);
	}
	/*printf("\n");*/

	/* and one really big tree */
	num_add = 100000;
	for(i=0; i<num_add; ++i)
		AddRandomElement(tree, num_add);
	test_tree_integrity(tree);
}
			
static int test6_in_tree(rbnode_t* node, int val)
{
	if(node == RBTREE_NULL) return 0;
	if(*(int*)node->key == val) return 1;
	if(test6_in_tree(node->left, val)) return 1;
	if(test6_in_tree(node->right, val)) return 1;
	return 0;
}

static rbnode_t* findsmallest(rbnode_t *node)
{
	if(node == RBTREE_NULL) return 0;
	if(node->left == RBTREE_NULL) return node;
	return findsmallest(node->left);
}

static rbnode_t* findlargest(rbnode_t *node)
{
	if(node == RBTREE_NULL) return 0;
	if(node->right == RBTREE_NULL) return node;
	return findlargest(node->right);
}

static void test6_check_le(rbtree_t *tree, int val)
{
	rbnode_t *node = 0;
	if(rbtree_find_less_equal(tree, &val, &node))
	{
		CU_ASSERT(test6_in_tree(tree->root, val));
		CU_ASSERT(node != 0);
		CU_ASSERT(val == *(int*)node->key);
	}
	else
	{
		CU_ASSERT(!test6_in_tree(tree->root, val));
		if(node != 0)
		{
			int smallval=*(int*)node->key;
			int k;
			CU_ASSERT(smallval < val);
			for(k=smallval+1; k < val; ++k)
				CU_ASSERT(!test6_in_tree(tree->root, k));
		}
		else
		{
			rbnode_t* smallest = findsmallest(tree->root);
			if(smallest) CU_ASSERT(val < *(int*)smallest->key);
		}
	}
}

static void rbtree_6(void)
{
	int num_try = 100;
	int i;
	srand(80);

	test6_check_le(tree, -10);
	test6_check_le(tree, 0);
	test6_check_le(tree, 1);
	test6_check_le(tree, 2);
	test6_check_le(tree, 998);
	test6_check_le(tree, 999);
	test6_check_le(tree, 1000);
	test6_check_le(tree, 100000);
	for(i=0; i<num_try; i++)
	{
		int val = GetTestValue(100);
		test6_check_le(tree, val);
	}
}

static void rbtree_7(void)
{
	CU_ASSERT(rbtree_first(tree) == findsmallest(tree->root));
	CU_ASSERT(rbtree_last(tree) == findlargest(tree->root));
}

static void rbtree_8(void)
{
	const void *key, *data;
	int lastkey = -1;
	rbnode_t* node;
	size_t count = 0;

	/* test next */
	RBTREE_WALK(tree, key, data)
	{
		count ++;
		if(lastkey!=-1)
			CU_ASSERT(lastkey < *(const int*)key);
		lastkey = *(const int*)key;
	}
	CU_ASSERT(count == tree->count);

	/* test previous */
	lastkey = -1;
	count = 0;
	for(node=rbtree_last(tree); node!=RBTREE_NULL; node=rbtree_previous(node))
	{
		count ++;
		if(lastkey!=-1) 
			CU_ASSERT(lastkey > *(int*)node->key);
		lastkey = *(int*)node->key;
	}
	CU_ASSERT(count == tree->count);
}

static void test_add_remove(rbtree_t* tree, const int* insert, const int* remove)
{
	size_t num_added = 0;
	const int* p = insert;
	size_t i;

	if(1)
	{
		const int *p;
		printf("AddRemoveTest in={");
		for(p=insert; *p!=-1; ++p) printf(" %d", *p);
		printf("} del={");
		for(p=remove; *p!=-1; ++p) printf(" %d", *p);
		printf("}\n");
	}

	while(*p != -1)
	{
		AddElement(tree, *p);
		test_tree_integrity(tree);
		num_added ++;
		p++;
	}

	CU_ASSERT(tree->count == num_added);
	if(0) {printf("Added "); tree_print(tree);}

	/* delete in order of (index) in remove array */
	for(i=0; i<num_added; i++)
	{
		CU_ASSERT(remove[i] != -1);
		if(1){ printf("i=%d/%d removing %d\n", i, num_added, insert[remove[i]]); tree_print(tree); }
		rbtree_delete(tree, &insert[remove[i]]);
		CU_ASSERT(tree->count == num_added - i - 1);
		test_tree_integrity(tree);
		CU_ASSERT(rbtree_search(tree, &insert[remove[i]]) == 0);
	}
}

static void fillperm(int d, int **perm, size_t* curx, int cury)
{
	int i;
	if(cury == d)
	{
		perm[*curx][cury] = -1;
		if(perm[1+(*curx)])
		{
		    for(i=0; i<cury; i++)
			perm[1+(*curx)][i] = perm[*curx][i];
		}
		++(*curx);
		return;
	}
	/* try all possibilities to fill the current item */
	for(i=0; i<d; i++)
	{
		int k;
		int found = 0;
		for(k=0; k<cury; k++)
			if(perm[*curx][k] == i) {
				found = 1; 
				break;
			}
		if(found) continue;
		perm[*curx][cury] = i;
		/* recurse */
		fillperm(d, perm, curx, cury+1);
	}
}

static size_t makepermutations(int d, int ***perm)
{
	size_t num = 1;
	size_t i=0;
	for(i=d; i>1; i--)
		num *= i;
	
	*perm = (int**)region_alloc(reg, sizeof(int*)*(num+10));
	for(i=0; i<num+1; i++)
	{
	      (*perm)[i] = (int*)region_alloc(reg, sizeof(int)*(d+1));
	      memset((*perm)[i], 23, sizeof(int)*(d+1));
	}
	perm[num+1] = 0;
	i=0;
	fillperm(d, *perm, &i, 0);
	CU_ASSERT(num == i);
	return num;
}

static void rbtree_9(void)
{
	rbtree_t* t;
	int val;

	srand(43);
	t = rbtree_create(reg, testcompare);
	CU_ASSERT(t->count == 0);
	
	/* add one element, remove one */
	val = AddRandomElement(t, 10);
	CU_ASSERT(t->count == 1);
	CU_ASSERT(rbtree_search(t, &val) != 0);

	rbtree_delete(t, &val);
	test_tree_integrity(t);
	CU_ASSERT(t->count == 0);
	CU_ASSERT(rbtree_search(t, &val) == 0);

	/* add more then remove in order given */
	{	/* end array with -1 */
		/* insert lists the elements to be inserted (in that order).
		 * delete gives the permutation to order the deletes */
		int two_insert1[] = {1, 2, -1};
		int two_delete1[] = {0, 1, -1};
		int two_insert2[] = {1, 2, -1};
		int two_delete2[] = {1, 0, -1};
		int two_insert3[] = {2, 1, -1};
		int two_delete3[] = {0, 1, -1};
		int two_insert4[] = {2, 1, -1};
		int two_delete4[] = {1, 0, -1};
		test_add_remove(t, two_insert1, two_delete1);
		test_add_remove(t, two_insert2, two_delete2);
		test_add_remove(t, two_insert3, two_delete3);
		test_add_remove(t, two_insert4, two_delete4);
	}

	{
		/* all permutations of 3 elements */
		int perm[][4] = { 
			{0, 1, 2, -1},
			{0, 2, 1, -1},
			{1, 0, 2, -1},
			{1, 2, 0, -1},
			{2, 0, 1, -1},
			{2, 1, 0, -1}};
		int i, j;
		/* add three elements in some order. Delete in another order. */
		for(i=0; i<6; i++)
			for(j=0; j<6; j++)
				test_add_remove(t, perm[i], perm[j]);
	}

	{
		int **perm;
		size_t num;
		size_t i, j;
		int d = 4;
		num = makepermutations(d, &perm);
		printf("Trying d=%d num=%d\n", d, (int)num);
		for(i=0; i<num; i++)
			for(j=0; j<num; j++)
				test_add_remove(t, perm[i], perm[j]);
	}
}

static void rbtree_10(void)
{
}
