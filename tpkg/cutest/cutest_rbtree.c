/*
	test rbtree
*/

#include "config.h"

#ifdef HAVE_STRING_H 
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "rbtree.h"


static int init_rbtree(void);
static void rbtree_1(CuTest *tc);
static void rbtree_2(CuTest *tc);
static void rbtree_3(CuTest *tc);
static void rbtree_4(CuTest *tc);
static void rbtree_5(CuTest *tc);
static void rbtree_6(CuTest *tc);
static void rbtree_7(CuTest *tc);
static void rbtree_8(CuTest *tc);
static void rbtree_9(CuTest *tc);
static void rbtree_10(CuTest *tc);
static int testcompare(const void *lhs, const void *rhs);

CuSuite* reg_cutest_rbtree(void)
{
	CuSuite* suite = CuSuiteNew();
	
	if (init_rbtree() != 0) {
		exit(1);
	}
	
	SUITE_ADD_TEST(suite, rbtree_1);
	SUITE_ADD_TEST(suite, rbtree_2);
	SUITE_ADD_TEST(suite, rbtree_3);
	SUITE_ADD_TEST(suite, rbtree_4);
	SUITE_ADD_TEST(suite, rbtree_5);
	SUITE_ADD_TEST(suite, rbtree_6);
	SUITE_ADD_TEST(suite, rbtree_7);
	SUITE_ADD_TEST(suite, rbtree_8);
	SUITE_ADD_TEST(suite, rbtree_9);
	SUITE_ADD_TEST(suite, rbtree_10);
        
	return suite;
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
	/* is leaked */
	reg = region_create(malloc, free);
	if(reg == 0) return 1;
	tree = rbtree_create(reg, testcompare);
	if(tree == 0) return 1;
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
	int len;
	sprintf(sink, "%s%n", prefix, &len);
	sink += len;
	if(depth > 0) {
		sprintf(sink, "-%n", &len);
		sink += len;
	}
	if((rbnode_t*)tree == RBTREE_NULL) {
		sprintf(sink, "**\n%n", &len);
		sink += len;
		return sink-oldsink;
	}
	/* print this node */
	sprintf(sink, "%d%n", tree->x, &len);
	sink += len;
	if(tree->node.color) {
		sprintf(sink, "R\n%n", &len);
		sink += len;
	} else {
		sprintf(sink, "B\n%n", &len);
		sink += len;
	}

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

void tree_print(CuTest *tc, rbtree_t* tree)
{
	char buf[1024000];
	char prefixbuf[10240];
	char *sink = buf;
	int len;
	sprintf(sink, "Rbtree count=%d\n%n", (int)tree->count, &len);
	sink += len;
	prefixbuf[0]=0;
	sink += tree_print_sub((struct testnode*)tree->root, 0, sink, prefixbuf);
	
	CuAssert(tc, "sink - buf  < sizeof(buf)", (size_t)(sink - buf) < sizeof(buf));
	printf("%s\n", buf);
}

static void tree_print_safe_sub(struct testnode* node)
{
	if((rbnode_t*)node == RBTREE_NULL) {
		return;
	}
	printf("Tree node (%p): ", node);
	printf("parent=%p. left=%p. right=%p. key=%p(%d). Color=%x. x=%d\n",
		node->node.parent, node->node.left, node->node.right, 
		node->node.key, node->node.key?*(int*)node->node.key:-1,
		node->node.color, node->x);
	tree_print_safe_sub((struct testnode*)node->node.left);
	tree_print_safe_sub((struct testnode*)node->node.right);
}

/* make sure that pointers are OK. Also check that key != 0. */
static void test_tree_pointers_sub(CuTest *tc, rbnode_t *node)
{
	CuAssert(tc, "node != 0", (node != 0));
	CuAssert(tc, "node->key != 0", (node->key != 0));
	CuAssert(tc, "node->key == &((struct testnode*)node)->x", (node->key == &((struct testnode*)node)->x));

	if(node->left != RBTREE_NULL)
	{
		CuAssert(tc, "node == node->left->parent", (node == node->left->parent));
		test_tree_pointers_sub(tc, node->left);
	}
	if(node->right != RBTREE_NULL)
	{
		CuAssert(tc, "node == node->right->parent", (node == node->right->parent));
		test_tree_pointers_sub(tc, node->right);
	}
}

/* make sure pointers are consistent */
static void test_tree_pointers(CuTest *tc, rbtree_t* tree)
{
	CuAssert(tc, "tree != 0", (tree != 0));

	if(tree->count == 0)
	{
		CuAssert(tc, "tree->region != 0", (tree->region != 0));
		CuAssert(tc, "tree->root == RBTREE_NULL", (tree->root == RBTREE_NULL));
		return;
	}

	CuAssert(tc, "tree->root->parent == RBTREE_NULL", (tree->root->parent == RBTREE_NULL));
	test_tree_pointers_sub(tc, tree->root); 
}

/* count non-null nodes in the tree */
static size_t test_tree_count_sub(rbnode_t* node)
{
	if(node == RBTREE_NULL) return 0;
	return test_tree_count_sub(node->left) + test_tree_count_sub(node->right) + 1;
}


static void test_tree_count(CuTest *tc, rbtree_t* tree)
{
	size_t mycount = test_tree_count_sub(tree->root);
	CuAssert(tc, "mycount == tree->count", (mycount == tree->count));
}

/* see if the tree is properly sorted */
/* values are only allowed min < val < max */
static void test_tree_sorting_sub(CuTest *tc, rbnode_t* node, int* min, int* max)
{
	int value = ((struct testnode*)node)->x;
	if(min) 
		CuAssert(tc, "*min < value", (*min < value));
	if(max) 
		CuAssert(tc, "value < *max", (value < *max));

	/* left of this node all nodes must be smaller */
	if(node->left != RBTREE_NULL)
		test_tree_sorting_sub(tc, node->left, min, &value);
	/* right of this node all nodes must be larger */
	if(node->right != RBTREE_NULL)
		test_tree_sorting_sub(tc, node->right, &value, max);
}


static void test_tree_sorting(CuTest *tc, rbtree_t* tree)
{
	if(tree->count > 0)
		test_tree_sorting_sub(tc, tree->root, 0, 0);
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

static void test_tree_RBvalues_sub1(CuTest *tc, rbnode_t* node)
{
	int min_black_nodes, max_black_nodes;
	CuAssert(tc, "node->color == 0 || node->color == 1)", (node->color == 0 || node->color == 1));
	if(node == RBTREE_NULL) return;

	/* both left and right below a red node are black */
	if(node->color == 1) 
	{
		CuAssert(tc, "node->left->color == 0", (node->left->color == 0));
		CuAssert(tc, "node->right->color == 0", (node->right->color == 0));
	}

	/*All paths from any given node to its leaf nodes contain the same number of black nodes.*/
	/* so count the min number of black nodes to leaf nodes and max number */
	/* note this makes the test O(N^2) */
	min_black_nodes = -1; max_black_nodes = -1;
	test_tree_RBvalues_countB(node, 0, &min_black_nodes, &max_black_nodes);
	CuAssert(tc, "min_black_nodes == max_black_nodes", (min_black_nodes == max_black_nodes));

	test_tree_RBvalues_sub1(tc, node->left);
	test_tree_RBvalues_sub1(tc, node->right);
}


static void test_tree_RBvalues(CuTest *tc, rbtree_t* tree)
{
	/* the root must be black */
	CuAssert(tc, "tree->root->color == BLACK?", (tree->root->color == 0));
	test_tree_RBvalues_sub1(tc, tree->root);
}


static void test_tree_integrity(CuTest *tc, rbtree_t* tree)
{
	test_tree_pointers(tc, tree);
	test_tree_count(tc, tree);
	test_tree_sorting(tc, tree);
	test_tree_RBvalues(tc, tree);
}

/* very very safe version of tree print */
void tree_print_safe(rbtree_t* tree)
{
	printf("Rbtree (at %p)", tree);
	printf(" region=%p root=%p count=%d current=%p cmp=%p\n",
		tree->region, tree->root, (int)tree->count,
		tree->_node, tree->cmp);
	if(tree->root) 
		tree_print_safe_sub((struct testnode*)tree->root);
}

#ifndef RAND_MAX
#define RAND_MAX INT_MAX
#endif
static int GetTestValue(double max)
{
	return (int)(max*rand() / (RAND_MAX+1.0));
}

static int AddRandomElement(CuTest *tc, rbtree_t* tree, int maxval)
{	
	struct testnode *t;

	t = (struct testnode*) region_alloc(reg, sizeof(struct testnode));
	t->node = *RBTREE_NULL;
	t->x = GetTestValue(maxval);
	t->node.key = &t->x;
	rbtree_insert((rbtree_t*)tree, (rbnode_t*)t);
	CuAssert(tc, "rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0", (rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0));
	return t->x;
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

static void test6_check_le(CuTest *tc, rbtree_t *tree, int val)
{
	rbnode_t *node = 0;
	if(rbtree_find_less_equal(tree, &val, &node))
	{
		CuAssert(tc, "test6_in_tree(tree->root, val)", test6_in_tree(tree->root, val));
		CuAssert(tc, "node != 0", (node != 0));
		CuAssert(tc, "val == *(int*)node->key", (val == *(int*)node->key));
	}
	else
	{
		CuAssert(tc, "!test6_in_tree(tree->root, val)", (!test6_in_tree(tree->root, val)));
		if(node != 0)
		{
			int smallval=*(int*)node->key;
			int k;
			CuAssert(tc, "smallval < val", (smallval < val));
			for(k=smallval+1; k < val; ++k)
				CuAssert(tc, "!test6_in_tree(tree->root, k)", (!test6_in_tree(tree->root, k)));
		}
		else
		{
			rbnode_t* smallest = findsmallest(tree->root);
			if(smallest) 
				CuAssert(tc, "val < *(int*)smallest->key", (val < *(int*)smallest->key));
		}
	}
}

/*
 *
 * THE TESTS
 *
 */

static void rbtree_1(CuTest *tc)
{
	/* tree should be empty on start. */
	CuAssert(tc, "empty tree?", (rbtree_first((rbtree_t*)tree) == &rbtree_null_node));
	CuAssert(tc, "empty tree?", (rbtree_last((rbtree_t*)tree) == &rbtree_null_node));
	test_tree_integrity(tc, tree);
}


static void rbtree_2(CuTest *tc)
{
	/* add same element twice. */
	struct testnode *t;

	t = (struct testnode*) region_alloc(reg, sizeof(struct testnode));
	memset(t, 0x23, sizeof(struct testnode));
	t->x = 4;
	t->node.key = &t->x;
	CuAssert(tc, "rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) != 0", (rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) != 0));
	CuAssert(tc, "rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0", (rbtree_insert((rbtree_t*)tree, (rbnode_t*)t) == 0));

	CuAssert(tc, "tree->count == 1", (tree->count == 1));
	CuAssert(tc, "tree->root->parent == RBTREE_NULL", (tree->root->parent == RBTREE_NULL));
	test_tree_integrity(tc, tree);

	if(0) tree_print_safe(tree);
	if(0) tree_print(tc, tree);
}

static void rbtree_3(CuTest *tc)
{
	/* check RBTREE_NULL contents */
	CuAssert(tc, "RBTREE_NULL != 0", (RBTREE_NULL != 0));
	CuAssert(tc, "RBTREE_NULL)->parent == RBTREE_NULL", ((RBTREE_NULL)->parent == RBTREE_NULL));
	CuAssert(tc, "RBTREE_NULL)->left == RBTREE_NULL", ((RBTREE_NULL)->left == RBTREE_NULL));
	CuAssert(tc, "RBTREE_NULL)->right == RBTREE_NULL", ((RBTREE_NULL)->right == RBTREE_NULL));
	CuAssert(tc, "RBTREE_NULL)->color == 0", ((RBTREE_NULL)->color == 0));
	CuAssert(tc, "RBTREE_NULL)->key == 0", ((RBTREE_NULL)->key == 0));
}

static void rbtree_4(CuTest *tc)
{
	int i;
	int num_add = 15;
	srand(23);
	for(i=0; i<num_add; ++i)
	{
		AddRandomElement(tc, tree, 100);
		test_tree_integrity(tc, tree);
	}

	if(0) tree_print(tc, tree);
	test_tree_integrity(tc, tree);
}

/* like 4 but more extensive */
static void rbtree_5(CuTest *tc)
{
	int i;
	int num_add = 1000;
	srand(35);
	/*printf("rbtree_5: ");*/
	for(i=0; i<num_add; ++i)
	{
		/*if(i % (num_add/66) == 0) printf(".");*/
		AddRandomElement(tc, tree, num_add);
		test_tree_integrity(tc, tree);
	}
	/*printf("\n");*/

	/* and one really big tree */
	num_add = 100000;
	for(i=0; i<num_add; ++i)
		AddRandomElement(tc, tree, num_add);
	test_tree_integrity(tc, tree);
}
			

static void rbtree_6(CuTest *tc)
{
	int num_try = 100;
	int i;
	srand(80);

	test6_check_le(tc, tree, -10);
	test6_check_le(tc, tree, 0);
	test6_check_le(tc, tree, 1);
	test6_check_le(tc, tree, 2);
	test6_check_le(tc, tree, 998);
	test6_check_le(tc, tree, 999);
	test6_check_le(tc, tree, 1000);
	test6_check_le(tc, tree, 100000);
	for(i=0; i<num_try; i++)
	{
		int val = GetTestValue(100);
		test6_check_le(tc, tree, val);
	}
}

static void rbtree_7(CuTest *tc)
{
	CuAssert(tc, "rbtree_first(tree) == findsmallest(tree->root)", rbtree_first(tree) == findsmallest(tree->root));
	CuAssert(tc, "rbtree_last(tree) == findlargest(tree->root)", rbtree_last(tree) == findlargest(tree->root));
}

static void rbtree_8(CuTest *tc)
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
			CuAssert(tc, "lastkey < *(const int*)key", (lastkey < *(const int*)key));

		lastkey = *(const int*)key;
	}
	CuAssert(tc, "count == tree->count", (count == tree->count));

	/* test previous */
	lastkey = -1;
	count = 0;
	for(node=rbtree_last(tree); node!=RBTREE_NULL; node=rbtree_previous(node))
	{
		count ++;
		if(lastkey!=-1) 
			CuAssert(tc, "lastkey > *(int*)node->key", (lastkey > *(int*)node->key));

		lastkey = *(int*)node->key;
	}
	CuAssert(tc, "count == tree->count", (count == tree->count));
}

static void test_add_remove(CuTest *tc, rbtree_t* tree, const int* insert, const int* remove)
{
	size_t num_added = 0;
	const int* p = insert;
	size_t i;
	int verbose = 0;
	struct testnode nodes[20];

	if(verbose)
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
		struct testnode* t=&nodes[num_added];
		t->node = *RBTREE_NULL;
		t->x = *p;
		t->node.key = &t->x;
		rbtree_insert((rbtree_t*)tree, (rbnode_t*)t);
		test_tree_integrity(tc, tree);
		num_added ++;
		CuAssert(tc, "num_added < 20", (num_added < 20));
		if(num_added>=20) return;
		p++;
	}

	CuAssert(tc, "tree->count == num_added", (tree->count == num_added));
	if(verbose) {printf("Added "); tree_print(tc, tree);}

	/* delete in order of (index) in remove array */
	for(i=0; i<num_added; i++)
	{
		CuAssert(tc, "remove[i] != -1", (remove[i] != -1));
		if(verbose){ printf("i=%d/%d removing %d\n", (int)i, (int)num_added, insert[remove[i]]); tree_print(tc, tree); }
		rbtree_delete(tree, &insert[remove[i]]);
		CuAssert(tc, "tree->count == num_added - i - 1", (tree->count == num_added - i - 1));
		test_tree_integrity(tc, tree);
		CuAssert(tc, "rbtree_search(tree, &insert[remove[i]]) == 0", (rbtree_search(tree, &insert[remove[i]]) == 0));

		/* stop on any errors */
		if(tc->failed > 0) {
			printf("Errors, stop \n");
			tree_print(tc, tree);
			return;
		}
	}
	/* all local elements must be gone now */
	CuAssert(tc, "tree->count == 0", (tree->count == 0));
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

static size_t makepermutations(CuTest *tc, int d, int ***perm)
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
	(*perm)[num+1] = 0;
	i=0;
	fillperm(d, *perm, &i, 0);
	CuAssert(tc, "num == i", (num == i));
	return num;
}

static void rbtree_9(CuTest *tc)
{
	rbtree_t* t;
	int val;

	srand(43);
	t = rbtree_create(reg, testcompare);
	CuAssert(tc, "t->count == 0", (t->count == 0));
	
	/* add one element, remove one */
	val = AddRandomElement(tc, t, 10);
	CuAssert(tc, "t->count == 1", (t->count == 1));
	CuAssert(tc, "rbtree_search(t, &val) != 0", (rbtree_search(t, &val) != 0));

	rbtree_delete(t, &val);
	test_tree_integrity(tc, t);
	CuAssert(tc, "t->count == 0", (t->count == 0));
	CuAssert(tc, "rbtree_search(t, &val) == 0", (rbtree_search(t, &val) == 0));
	CuAssert(tc, "rbtree_search(t, &val) == 0", (rbtree_search(t, &val) == 0));

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
		test_add_remove(tc, t, two_insert1, two_delete1);
		test_add_remove(tc, t, two_insert2, two_delete2);
		test_add_remove(tc, t, two_insert3, two_delete3);
		test_add_remove(tc, t, two_insert4, two_delete4);
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
				test_add_remove(tc, t, perm[i], perm[j]);
	}

	{
		int **perm;
		size_t num;
		size_t i, j;
		int d;

		for(d=4; d<6; d++)
		{
		    num = makepermutations(tc, d, &perm);
		    if(0) printf("Trying d=%d num=%d\n", d, (int)num);
		    for(i=0; i<num; i++)
			for(j=0; j<num; j++)
			{
				test_add_remove(tc, t, perm[i], perm[j]);
				/* stop on any errors */
				if (tc->failed > 0) {
					printf("Errors, stop \n");
					return;
				}
			}
		}
	}
}

static void rbtree_10(CuTest *tc)
{
	/* start a random add/delete sequence to simulate usage */
	size_t num_iter = 10000;
	int maxnum = 100;
	int p_add = 50;
	size_t i;

	/* empty old tree */
	while(tree->count > 0)
	{
	      /* select an element */
	      const void* key = tree->root->key;
	      rbtree_delete(tree, key);
	      if(tree->count%10000==0) 
	      {
		      test_tree_integrity(tc, tree);
	      }
	}

	for(i=0; i<num_iter; i++)
	{
	      if(GetTestValue(100) < p_add)
	      {
		      AddRandomElement(tc, tree, maxnum);
	      }
	      else
	      {
		      int key = GetTestValue(maxnum);
		      rbtree_delete(tree, &key);
	      }
	      test_tree_integrity(tc, tree);
	}
}
