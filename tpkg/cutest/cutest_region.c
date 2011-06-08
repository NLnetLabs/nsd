/*
	Test region-allocator.h
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
#include "rbtree.h"
#if SIZEOF_OFF_T > SIZEOF_VOIDP
#define ALIGNMENT (sizeof(off_t))
#else
#define ALIGNMENT (sizeof(void *))
#endif

static void region_1(CuTest *tc);

CuSuite* reg_cutest_region(void)
{
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, region_1); /* test recycle */
	return suite;
}

size_t
align_size(size_t x)
{
	if(x == 0) x = 1;
	x = ALIGN_UP(x, ALIGNMENT);
	return x;
}

/* test recycle by alloc and recycle blocks in a region.
	Keeps track of blocks by a redblacktree(with its own plain region).
	To make sure that alloced elements are recycled if possible, and
	not double used. */
/* bloclist of blocks of the same size with admin(alloced, recycle_bin) */
struct blocklist {
	void* block;
	int alloced; /* if false it is in recyclebin */
	size_t realsize;
	struct blocklist* next;
};
/* rbtree node for a size */
struct sizenode {
	rbnode_t node;
	size_t size;
	size_t numblocks;
	size_t numalloced;
	struct blocklist* list;
};
static int 
comparef(const void* x, const void* y)
{
	size_t* sx = (size_t*)x;
	size_t* sy = (size_t*)y;
	if(!sx || !sy) return 0;
	if(*sx < *sy) return -1;
	if(*sx > *sy) return 1;
	return 0;
}

/* random between min and max (inclusive) */
int GetRandom(int min, int max) {
	double val = drand48();
	int res;
	val *= (double)(max-min+1);
	val += min;
	res = (int)val;
	if(res < min) res=min;
	if(res > max) res=max;
	return res;
}

/* true if ptr exists in tree */
static int
CheckExist(rbtree_t* tree, void *block, struct blocklist** listitem,
	struct sizenode** treeitem)
{
	struct sizenode* p;
	struct blocklist* bl;
	RBTREE_FOR(p, struct sizenode*, tree) {
		bl = p->list;
		while(bl) {
			if(bl->block == block) {
				*treeitem = p;
				*listitem = bl;
				return 1;
			}
			if(bl->block < block && block < bl->block+p->size) {
				/* ptr in middle of other block */
				*treeitem = p;
				*listitem = bl;
				return 2;
			}
			bl = bl->next;
		}
	}
	*treeitem = 0;
	*listitem = 0;
	return 0;
}

static struct sizenode*
add_size_tree(rbtree_t* tree, size_t sz)
{
	struct sizenode *p=0;
	p = (struct sizenode*)rbtree_search(tree, (void*)&sz);
	if(!p) {
		p = region_alloc(tree->region, sizeof(*p));
		p->node = *RBTREE_NULL;
		p->node.key = (void*)&p->size;
		p->size = sz;
		p->numblocks = 0;
		p->numalloced = 0;
		p->list = NULL;
		rbtree_insert(tree, (rbnode_t*)p);
	}
	return p;
}

static void
test_alloc(CuTest *tc, rbtree_t* tree, region_type* region)
{
	size_t sz = 0;
	void *block = 0;
	int ret;
	struct sizenode *p=0;
	struct blocklist *bl=0;
	/*static int smallrand = 0;*/
	if(GetRandom(0, 10) < 5) {
		/*sz = GetRandom(0, 10);*/
		sz = GetRandom(0, DEFAULT_LARGE_OBJECT_SIZE-1);
		/*sz = smallrand++;*/
		/*if(smallrand == 8) smallrand = 0;*/
	} else
		sz = GetRandom(DEFAULT_LARGE_OBJECT_SIZE, 
			DEFAULT_LARGE_OBJECT_SIZE*10);
	if(0) printf("test alloc sz=%d(%d)\n", (int)sz, (int)align_size(sz));
	block = region_alloc(region, sz);
	CuAssert(tc, "region_alloc nonnull", block != NULL);

	/* see if it already exists */
	ret = CheckExist(tree, block, &bl, &p);
	CuAssert(tc, "region_alloc not inside another", ret != 2);
	if(ret == 1) {
		/* align up the sizes to compare them */
		size_t upgot = align_size(p->size), upask = align_size(sz);
		CuAssert(tc, "find block works", bl->block == block);
		CuAssert(tc, "region_alloc correct size", upgot == upask);
		CuAssert(tc, "region_alloc not double", bl->alloced == 0);
		bl->realsize = sz;
		bl->alloced = 1;
		p->numalloced ++;
	}
	if(ret == 0) {
		/* add an entry to tree */
		p = add_size_tree(tree, align_size(sz));
		CuAssert(tc, "add tree entry works", p != NULL);
		/* make sure none of the size are in recyclebin */
		bl = p->list;
		while(bl) {
			/* Test does not work anymore, because region-allocator
			   sometimes has wasted space that it keeps in recycle bin
			   And this test program cannot detect that it does so */
			/*
			CuAssert(tc, "region_alloc skips available blocks",
				bl->alloced != 0);
			*/
			bl = bl->next;
		}
		bl = region_alloc(tree->region, sizeof(*bl));
		bl->block = block;
		bl->alloced = 1;
		bl->realsize = sz;
		bl->next = p->list;
		p->list = bl;
		p->numalloced ++;
	}
}

static void
delete_item(rbtree_t* tree, struct sizenode* p, struct blocklist* bl)
{
	struct blocklist** prevp = &p->list;
	/* first delete from blocklist */
	while(*prevp && *prevp!=bl) {
		prevp=&((*prevp)->next);
	}
	/* must find prevp */
	*prevp = bl->next;
	/* memleak bl in tree_region */

	/* if blocklist empty, remove node from tree */
	if(p->list == NULL) {
		rbtree_delete(tree, &p->size);
		/* memleak p in tree_region */
	}
}

int
get_block_count(rbtree_t* tree)
{
	int total = 0;
	struct sizenode *p = 0;
	RBTREE_FOR(p, struct sizenode*, tree) {
		total += p->numalloced;
	}
	return total;
}

void
get_block_num(rbtree_t* tree, int num, 
	struct sizenode **p, struct blocklist** bl)
{
	int i = 0;
	RBTREE_FOR((*p), struct sizenode*, tree) {
		if(num < i + (int)(*p)->numalloced) {
			*bl = (*p)->list;
			while(*bl) {
				if((*bl)->alloced == 0) {
					/* only count alloced */
					*bl = (*bl)->next;
					continue;
				}
				if(i==num) {
					return;
				}
				i++;
				*bl = (*bl)->next;
			}
			printf("Error in get_block_num, bl\n");
			exit(1);
		}
		i += (*p)->numalloced;
	}
	printf("Error in get_block_num\n");
	exit(1);
}

static void
test_dealloc(CuTest *ATTR_UNUSED(tc), rbtree_t* tree, region_type* region)
{
	/* pick one to dealloc */
	int num, total;
	struct sizenode *p = 0;
	struct blocklist* bl = 0;
	total = get_block_count(tree);
	if(total == 0)
		return;
	num = GetRandom(0, total - 1);
	get_block_num(tree, num, &p, &bl);

	/* if not alloced, take next one */
	if(!bl->alloced) {
		printf("test error\n");
		exit(1);
	}
	/* delete block bl in treeitem p */
	if(0) printf("Delete of block size %d(%d)\n", (int)bl->realsize, 
		(int)p->size);
	region_recycle(region, bl->block, bl->realsize);
	bl->alloced = 0;
	p->numalloced --;
	if(p->size >= DEFAULT_LARGE_OBJECT_SIZE) {
		/* delete the entry, it is freed */
		delete_item(tree, p, bl);
	}
}

static void 
region_1(CuTest *tc)
{
	region_type* tree_region = region_create(xalloc, free);
	rbtree_t* tree = rbtree_create(tree_region, comparef);
	region_type* region = 0;
	int i;
	int max = 10000;
	int emptyup = 40;

	srand48(4096);
	region = region_create_custom(xalloc, free, DEFAULT_CHUNK_SIZE,
		DEFAULT_LARGE_OBJECT_SIZE, DEFAULT_INITIAL_CLEANUP_SIZE, 1);

	/* start adding and deleting random elements */
	for(i=0; i<max; i++) {
		if(drand48() < 0.5)
			test_alloc(tc, tree, region);
		else	test_dealloc(tc, tree, region);
		if(i == emptyup) {
			int j;
			/*printf("empty the bin\n");*/
			for(j=0; j<emptyup*2; ++j)
				test_dealloc(tc, tree, region);
		}
		if(0) {
			region_dump_stats(region, stdout);
			printf("\n");
		}
	}

	region_destroy(region);
	region_destroy(tree_region);
}
