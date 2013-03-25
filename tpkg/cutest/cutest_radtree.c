/*
 * test radtree -- generic radix tree for binary strings.
 *
 * Copyright (c) 2010, NLnet Labs.  See LICENSE for license.
 */
#include "config.h"
#include "tpkg/cutest/cutest.h"
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "radtree.h"
#include "region-allocator.h"
#include "util.h"

#include <stdio.h>
#include <ctype.h>

#ifndef RAND_MAX
#define RAND_MAX 2147483647
#endif
static void radtree_1(CuTest* tc);
static void radtree_2(CuTest* tc);
static void radtree_3(CuTest* tc);

CuSuite* reg_cutest_radtree(void)
{
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, radtree_1);
	SUITE_ADD_TEST(suite, radtree_2);
	SUITE_ADD_TEST(suite, radtree_3);
	return suite;
}

static CuTest* tc = NULL;
/* local verbosity */
static int verb = 0;

/*********** test code ************/
/** test data for radix tree tests */
struct teststr {
	struct radnode* mynode;
	uint8_t* mystr;
	radstrlen_t mylen;
	/* if a domain name, the domain name in original format */
	uint8_t* dname;
	size_t dname_len;
};

/** check invariants and count number of elems */
static size_t test_check_invariants(struct radnode* n)
{
	size_t num = 0;
	if(!n) return 0;
	if(n->elem) num++;
	CuAssert(tc, "invariant len<=cap", n->len <= n->capacity);
	CuAssert(tc, "invariant cap<=256", n->capacity <= 256);
	CuAssert(tc, "invariant offset", ((int)n->offset) + ((int)n->len) <= 256);
	if(n->array == NULL) {
		CuAssert(tc, "invariant empty cap", n->capacity == 0);
		CuAssert(tc, "invariant empty len", n->len == 0);
		CuAssert(tc, "invariant empty offset", n->offset == 0);
	} else {
		unsigned idx;
		CuAssert(tc, "invariant nonempty cap", n->capacity != 0);
		for(idx=0; idx<n->len; idx++) {
			struct radsel* r = &n->array[idx];
			if(r->node == NULL) {
				CuAssert(tc, "empty node", r->str == NULL);
				CuAssert(tc, "empty node", r->len == 0);
			} else {
				if(r->len == 0) {
					CuAssert(tc, "emptystr", r->str == NULL);
				} else {
					CuAssert(tc, "filledstr", r->str != NULL);
				}
				CuAssert(tc, "invariant parent", r->node->parent == n);
				CuAssert(tc, "invariant pidx", r->node->pidx == idx);
				num += test_check_invariants(r->node);
			}
		}
	}
	return num;
}

/** find all elems in the list and check that the name as indicated by the
 * lookup structure matches the one in the element */
static void
test_check_list_keys(struct radnode* n, struct teststr** all, size_t* all_idx,
	size_t all_num, uint8_t* fullkey, radstrlen_t fullkey_len,
	radstrlen_t fullkey_max)
{
	unsigned idx;
	if(!n) return;
	if(n->elem) {
		/* check this elements key */
		struct teststr* t = (struct teststr*)n->elem;
		CuAssert(tc, "testkey node", t->mynode == n);
		CuAssert(tc, "testkey len", t->mylen == fullkey_len);
		CuAssert(tc, "testkey val", memcmp(t->mystr, fullkey, fullkey_len) == 0);
		/* add to all list */
		CuAssert(tc, "testkey list",  (*all_idx) < all_num);
		all[ (*all_idx)++ ] = t;
	}
	for(idx=0; idx<n->len; idx++) {
		struct radsel* r = &n->array[idx];
		radstrlen_t newlen = fullkey_len;
		if(!r->node)
			continue;
		/* lengthen fullkey with the character and r->str */
		CuAssert(tc, "testkey len", newlen+1 < fullkey_max);
		fullkey[newlen++] = idx + n->offset;
		if(r->len != 0) {
			CuAssert(tc, "testkey len", newlen+r->len < fullkey_max);
			memmove(fullkey+newlen, r->str, r->len);
			newlen += r->len;
		}
		test_check_list_keys(r->node, all, all_idx, all_num, fullkey,
			newlen, fullkey_max);
	}
}

/** compare byte strings like the tree does */
static int bstr_cmp(uint8_t* x, radstrlen_t lenx, uint8_t* y, radstrlen_t leny)
{
	size_t m = (lenx<leny)?lenx:leny;
	if(m != 0 && memcmp(x, y, m) != 0)
		return memcmp(x, y, m);
	if(lenx < leny)
		return -1;
	else if(lenx > leny)
		return +1;
	return 0;
}

/** compare for qsort */
int test_sort_cmp(const void *a, const void *b)
{
	struct teststr* x = *(struct teststr**)a;
	struct teststr* y = *(struct teststr**)b;
	return bstr_cmp(x->mystr, x->mylen, y->mystr, y->mylen);
}

/** check walk functions */
static void test_check_walk(struct radtree* rt, struct teststr** all,
	size_t num)
{
	struct radnode* n;
	unsigned idx;

	/* check _first */
	n = radix_first(rt);
	if(num == 0) {
		CuAssert(tc, "walk first", n == NULL);
	} else {
		CuAssert(tc, "walk first", n == all[0]->mynode);
	}

	/* check _last */
	n = radix_last(rt);
	if(num == 0) {
		CuAssert(tc, "walk last", n == NULL);
	} else {
		CuAssert(tc, "walk last", n == all[num-1]->mynode);
	}

	/* check _next */
	for(idx = 0; idx < num; idx++) {
		n = radix_next(all[idx]->mynode);
		if(idx == num-1) {
			CuAssert(tc, "radix_next", n == NULL);
		} else {
			CuAssert(tc, "radix_next", n == all[idx+1]->mynode);
		}
	}

	/* check _prev */
	for(idx = 0; idx < num; idx++) {
		n = radix_prev(all[idx]->mynode);
		if(idx == 0) {
			CuAssert(tc, "radix_prev", n == NULL);
		} else {
			CuAssert(tc, "radix_prev", n == all[idx-1]->mynode);
		}
	}
}

/** check search function */
static void test_check_search(struct radtree* rt, struct teststr** all,
	size_t num)
{
	struct radnode* n;
	unsigned idx;
	for(idx = 0; idx < num; idx++) {
		n = radix_search(rt, all[idx]->mystr, all[idx]->mylen);
		CuAssert(tc, "radix_search", n == all[idx]->mynode);
	}
}

/** check closest match function for exact matches */
static void test_check_closest_match_exact(struct radtree* rt,
	struct teststr** all, size_t num)
{
	struct radnode* n;
	unsigned idx;
	for(idx = 0; idx < num; idx++) {
		n = NULL;
		if(radix_find_less_equal(rt, all[idx]->mystr,
			all[idx]->mylen, &n)) {
			/* check if exact match is correct */
			CuAssert(tc, "find_le", n == all[idx]->mynode);
		} else {
			/* should have returned true: exact match */
			CuAssert(tc, "find_le", 0);
		}
	}
}

/** get a random value */
static unsigned
get_ran_val(unsigned max)
{
	unsigned r = (random() & RAND_MAX);
	double ret = ((double)r * (double)max) / (1.0 + RAND_MAX);
	return (unsigned)ret;
}

/** generate random string and length */
static void
gen_ran_str_len(uint8_t* buf, radstrlen_t* len, radstrlen_t max)
{
	radstrlen_t i;
	*len = get_ran_val(5);
	CuAssert(tc, "ranstrlen", *len < max);
	buf[*len] = 0; /* zero terminate for easy debug */
	for(i=0; i< *len; i++) {
		/*buf[i] = get_ran_val(256); */
		buf[i] = 'a' + get_ran_val(26);
	}
}

/** generate random domain name and length */
static void
gen_ran_dname(uint8_t* buf, radstrlen_t* len, radstrlen_t max)
{
	int numlabs, labs;
	radstrlen_t i, lablen, pos;

	/* number nonzero labels */
	labs = get_ran_val(1000);
	if(labs < 10) numlabs = 0;
	else if(labs < 100) numlabs = 1;
	else if(labs < 1000) numlabs = 2;
	else numlabs = 3;

	pos = 0;
	for(labs=0; labs<numlabs; labs++) {
		/* add another nonzero label */
		lablen = get_ran_val(3)+1;
		CuAssert(tc, "nonzero label", pos + lablen + 1 < max);
		buf[pos++] = lablen;
		for(i=0; i<lablen; i++) {
			/*buf[i] = get_ran_val(256); */
			buf[pos++] = 'a' + get_ran_val(26);
		}
	}
	buf[pos++] = 0; /* zero terminate for easy debug */
	CuAssert(tc, "ranstr", pos < max);
	*len = pos;
	CuAssert(tc, "ranstr", strlen((char*)buf)+1 == *len);
}

/** check closest match function for inexact matches */
static void test_check_closest_match_inexact(struct radtree* rt)
{
	uint8_t buf[1024];
	radstrlen_t len;
	struct radnode* n;
	struct teststr* t;
	int i = 0, num=1000;
	/* what strings to try out? random */
	/* how to check result? use prev and next (they work checked before)*/
	for(i=0; i<num; i++) {
		/* generate random string */
		gen_ran_str_len(buf, &len, sizeof(buf));
		n = NULL;
		if(radix_find_less_equal(rt, buf, len, &n)) {
			CuAssert(tc, "find_le", n != NULL);
			CuAssert(tc, "find_le", n->elem != NULL);
			/* check exact match */
			t = (struct teststr*)n->elem;
			CuAssert(tc, "find_le", t->mylen == len);
			CuAssert(tc, "find_le", memcmp(t->mystr, buf, len) == 0);
		} else {
			/* check inexact match */
			if(n == NULL) {
				/* no elements in rt or before first item */
				if(rt->count != 0) {
					n = radix_first(rt);
					t = (struct teststr*)n->elem;
					CuAssert(tc, "find_le", bstr_cmp(buf, len,
					  t->mystr, t->mylen) < 0);
				}
			} else {
				struct radnode* nx;
				CuAssert(tc, "find_le", n->elem != NULL);
				/* n is before the item */
				t = (struct teststr*)n->elem;
				CuAssert(tc, "find_le", bstr_cmp(t->mystr, t->mylen,
					buf, len) < 0);
				/* the next item is NULL or after it */
				nx = radix_next(n);
				if(nx) {
					t = (struct teststr*)nx->elem;
					CuAssert(tc, "find_le", bstr_cmp(t->mystr, t->mylen,
						buf, len) > 0);
				}
			}
		}
	}
}

/** perform lots of checks on the test tree */
static void test_checks(struct radtree* rt)
{
	struct teststr* all[10240];
	size_t i=0;
	uint8_t fullkey_buf[1024];

	/* tree structure invariants */
	size_t num = test_check_invariants(rt->root);
	CuAssert(tc, "count", num == rt->count);

	/* otherwise does not fit in array */
	CuAssert(tc, "counts", num < sizeof(all)/sizeof(struct teststr*));

	/* check that keys appended match test-elem contents, and also
	 * produce a list of all elements */
	test_check_list_keys(rt->root, all, &i, num, fullkey_buf, 0, 
		sizeof(fullkey_buf));
	CuAssert(tc, "testlistkey count", i == num);

	/* qsort that list */
	qsort(all, num, sizeof(struct teststr*), &test_sort_cmp);

	test_check_walk(rt, all, num);

	/* check searches for every element */
	test_check_search(rt, all, num);

	/* check closest_match_searches for every exact element */
	test_check_closest_match_exact(rt, all, num);
	/* check closest_match_searches for every inexact element */
	test_check_closest_match_inexact(rt);
}

/** check radname_search */
static void test_check_dname_search(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n ; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		struct radnode* found;
		CuAssert(tc, "radname_search", n && s);
		found = radname_search(rt, s->dname, s->dname_len);
		CuAssert(tc, "radname_search", found != NULL);
		CuAssert(tc, "radname_search", found == n);
	}
}

/** check radname_less_or_equal for exact */
static void test_check_dname_closest_exact(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n ; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		struct radnode* found;
		CuAssert(tc, "radname_find_le", n && s);
		if(radname_find_less_equal(rt, s->dname, s->dname_len, &found)){
			/* exact match is expected */
			CuAssert(tc, "radname_find_le", found != NULL);
			CuAssert(tc, "radname_find_le", found == n);
		} else {
			CuAssert(tc, "radname_find_le", 0);
		}
	}
}

/** check radname_less_or_equal for inexact */
static void test_check_dname_closest_inexact(struct radtree* rt)
{
	uint8_t dname[1024];
	radstrlen_t dlen;
	uint8_t radname[1024];
	radstrlen_t rlen;
	struct radnode* n;
	struct teststr* t;
	int i = 0, num=1000;
	/* what strings to try out? random */
	/* how to check result? use prev and next (they work checked before)*/
	for(i=0; i<num; i++) {
		/* generate random string */
		gen_ran_dname(dname, &dlen, sizeof(dname));
		rlen = sizeof(radname);
		/* test the radname_lookup function internal conversion of
		 * the dname to radname against the d2r function */
		radname_d2r(radname, &rlen, dname, (size_t)dlen);
		n = NULL;
		if(radname_find_less_equal(rt, dname, (size_t)dlen, &n)) {
			CuAssert(tc, "radname_find", n != NULL);
			CuAssert(tc, "radname_find", n->elem != NULL);
			/* check exact match */
			t = (struct teststr*)n->elem;
			CuAssert(tc, "radname_find", t->mylen == rlen);
			CuAssert(tc, "radname_find", memcmp(t->mystr, radname, rlen) == 0);
		} else {
			/* check inexact match */
			if(n == NULL) {
				/* no elements in rt or before first item */
				if(rt->count != 0) {
					n = radix_first(rt);
					t = (struct teststr*)n->elem;
					CuAssert(tc, "radname_find", bstr_cmp(radname, rlen,
					  t->mystr, t->mylen) < 0);
				}
			} else {
				struct radnode* nx;
				CuAssert(tc, "radname_find", n->elem != NULL);
				/* n is before the item */
				t = (struct teststr*)n->elem;
				CuAssert(tc, "radname_find", bstr_cmp(t->mystr, t->mylen,
					radname, rlen) < 0);
				/* the next item is NULL or after it */
				nx = radix_next(n);
				if(nx) {
					t = (struct teststr*)nx->elem;
					CuAssert(tc, "radname_find", bstr_cmp(t->mystr, t->mylen,
						radname, rlen) > 0);
				}
			}
		}
	}
}

/** test checks for domain names */
static void test_checks_dname(struct radtree* rt)
{
	/* test_checks is already performed */
	/* check the exact match search for every exact element */
	test_check_dname_search(rt);
	test_check_dname_closest_exact(rt);
	test_check_dname_closest_inexact(rt);
}

static void test_print_str(uint8_t* str, radstrlen_t len)
{
	radstrlen_t x;
	for(x=0; x<len; x++) {
		char c = ((char*)str)[x];
		if(c == 0) fprintf(stderr, ".");
		else fprintf(stderr, "%c", c);
	}
}

static void test_node_print(struct radnode* n, int depth)
{
	int i;
	uint8_t idx;
	if(!n) return;
	for(i=0; i<depth; i++) fprintf(stderr, " ");
	if(n->parent)
		fprintf(stderr, "%c node=%p.", 
			n->pidx+n->parent->offset?n->pidx+n->parent->offset:'.',
			n);
	else
		fprintf(stderr, "rootnode=%p.", n);
	fprintf(stderr, " pidx=%d off=%d(%c) len=%d cap=%d parent=%p\n",
		n->pidx, n->offset, isprint(n->offset)?n->offset:'.',
		n->len, n->capacity, n->parent);
	for(i=0; i<depth; i++) fprintf(stderr, " ");
	if(n->elem) {
		/* for test setup */
		struct teststr* s = (struct teststr*)n->elem;
		fprintf(stderr, "  elem '");
		test_print_str(s->mystr, s->mylen);
		fprintf(stderr, "'\n");
		CuAssert(tc, "print", s->mynode == n);
	} else fprintf(stderr, "  elem NULL\n");
	for(idx=0; idx<n->len; idx++) {
		struct radsel* d = &n->array[idx];
		if(!d->node) {
			CuAssert(tc, "print", d->str == NULL);
			CuAssert(tc, "print", d->len == 0);
			continue;
		}
		for(i=0; i<depth; i++) fprintf(stderr, " ");
		if(n->offset+idx == 0) fprintf(stderr, "[.]");
		else fprintf(stderr, "[%c]", n->offset + idx);
		if(d->str) {
			fprintf(stderr, "+'");
			test_print_str(d->str, d->len);
			fprintf(stderr, "'");
			CuAssert(tc, "print", d->len != 0);
		} else {
			CuAssert(tc, "print", d->len == 0);
		}
		if(d->node) {
			fprintf(stderr, " node=%p\n", d->node);
			test_node_print(d->node, depth+2);
		} else 	fprintf(stderr, " node NULL\n");
	}
}

static void test_tree_print(struct radtree* rt)
{
	fprintf(stderr, "radtree %u elements\n", (unsigned)rt->count);
	test_node_print(rt->root, 0);
}

static void
test_insert_string(struct radtree* rt, char* str)
{
	size_t len = strlen(str);
	struct teststr* s = (struct teststr*)calloc(1, sizeof(*s));
	struct radnode* n;
	CuAssert(tc, "insert", s != NULL);
	s->mylen = len;
	s->mystr = (uint8_t*)strdup(str);
	CuAssert(tc, "insert", s->mystr != NULL);
	if(verb) fprintf(stderr, "radix insert: '%s'\n", str);
	n = radix_insert(rt, s->mystr, s->mylen, s);
	s->mynode = n;
	CuAssert(tc, "insert", n != NULL);
	/*test_tree_print(rt);*/
	test_checks(rt);
}

static void
test_insert_dname(struct radtree* rt, uint8_t* dname, size_t len)
{
	struct teststr* s;
	struct radnode* n;
	/* see if the dname is already in the tree */
	if(radname_search(rt, dname, len))
		return;
	s = (struct teststr*)calloc(1, sizeof(*s));
	CuAssert(tc, "insert", s != NULL);
	s->dname_len = len;
	s->dname = (uint8_t*)malloc(len);
	CuAssert(tc, "insert", s->dname != NULL);
	memcpy(s->dname, dname, len);
	/* convert it */
	s->mystr = (uint8_t*)malloc(len);
	s->mylen = len;
	CuAssert(tc, "insert", s->mystr != NULL);
	radname_d2r(s->mystr, &s->mylen, dname, len);
	/* check that its inverse conversion is the original */
	if(1) {
		uint8_t buf[1024];
		size_t len = sizeof(buf);
		radname_r2d(s->mystr, s->mylen, buf, &len);
		CuAssert(tc, "insert", s->dname_len == len);
		CuAssert(tc, "insert", memcmp(s->dname, buf, len) == 0);
	}

	if(verb) {
		fprintf(stderr, "radix insert: ");
		test_print_str(s->mystr, s->mylen);
		fprintf(stderr, "\n");
	}
	n = radix_insert(rt, s->mystr, s->mylen, s);
	s->mynode = n;
	CuAssert(tc, "insert", n != NULL);
	/*test_tree_print(rt);*/
	test_checks(rt);
	test_checks_dname(rt);
}

/** browse all elem's from tree with a for loop */
static void test_browse(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		if(verb) fprintf(stderr, "radix %p \telem ", n);
		if(verb) test_print_str(s->mystr, s->mylen);
		if(verb) fprintf(stderr, "\n");
		CuAssert(tc, "walk", s->mynode == n);
	}
}

/** delete all elem's from tree with a for loop */
static void test_del(struct radtree* rt)
{
	struct radnode* n;
	for(n = radix_first(rt); n; n = radix_next(n)) {
		struct teststr* s = (struct teststr*)n->elem;
		if(verb) fprintf(stderr, "del %p \telem ", n);
		if(verb) test_print_str(s->mystr, s->mylen);
		if(verb) fprintf(stderr, "\n");
		CuAssert(tc, "radix_del", s->mynode == n);
		free(s->mystr);
		free(s->dname);
		free(s);
	}
}

/** unit tests for radix functions */
void unit_radix(void)
{
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"", 0, (uint8_t*)"", 0));
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"foo", 3, (uint8_t*)"foobar", 6));
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"foobar", 6, (uint8_t*)"foo", 3)==0);
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"zoobar", 6, (uint8_t*)"foobar", 3)==0);
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"zoo", 3, (uint8_t*)"foo", 3)==0);
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"ozo", 3, (uint8_t*)"ofo", 3)==0);
	CuAssert(tc, "bstr_is_prefix", bstr_is_prefix_ext((uint8_t*)"ofo", 3, (uint8_t*)"ofo", 3));

	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"", 0, (uint8_t*)"", 0) == 0);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"foo", 3, (uint8_t*)"foobar", 6) == 3);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"foobar", 6, (uint8_t*)"foo", 3) == 3);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"zoobar", 6, (uint8_t*)"foobar", 3)==0);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"zoo", 3, (uint8_t*)"foo", 3)==0);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"ozo", 3, (uint8_t*)"ofo", 3)==1);
	CuAssert(tc, "bstr_common", bstr_common_ext((uint8_t*)"ofo", 3, (uint8_t*)"ofo", 3)==3);

	if(verb) fprintf(stderr, "unit_radix ok\n");
}

/* delete a random key */
static void
test_del_a_key(struct radtree* rt)
{
	unsigned x = get_ran_val(rt->count);
	unsigned i = 0;
	struct radnode* n = radix_first(rt);
	struct teststr* t;
	while(i++ < x) {
		n = radix_next(n);
	}
	if(!n) return;
	CuAssert(tc, "radix_delete", n->elem != NULL);
	t = (struct teststr*)n->elem;
	if(verb) fprintf(stderr, "delkey %p \telem ", n);
	if(verb) test_print_str(t->mystr, t->mylen);
	if(verb) fprintf(stderr, "\n");
	radix_delete(rt, n);
	test_checks(rt);

	/* and delete the test elem */
	free(t->mystr);
	free(t->dname);
	free(t);
}

/* random add and dell test */
static void
test_ran_add_del(struct radtree* rt)
{
	unsigned i, num = 1000;
	unsigned target = 10;
	for(i=0; i<num; i++) {
		/* add or del? */
		unsigned ran = random();
		if(  (rt->count < target && ran%4 != 0)
			|| (ran%2 == 0)) {
			uint8_t key[1024];
			radstrlen_t len;
			/* new string key */
			gen_ran_str_len(key, &len, sizeof(key));
			if(!radix_search(rt, key, len)) {
				test_insert_string(rt, (char*)key);
			}
		} else {
			test_del_a_key(rt);
		}

	}
	if(verb) test_tree_print(rt);
	while(rt->count != 0) {
		test_del_a_key(rt);
	}
}

/* random add and dell for dnames test */
static void
test_dname_add_del(struct radtree* rt)
{
	unsigned i, num = 1000;
	unsigned target = 10;
	test_checks(rt);
	test_checks_dname(rt);
	for(i=0; i<num; i++) {
		/* add or del? */
		unsigned ran = random();
		if(  (rt->count < target && ran%4 != 0)
			|| (ran%2 == 0)) {
			uint8_t key[1024];
			radstrlen_t len;
			/* new string key */
			gen_ran_dname(key, &len, sizeof(key));
			test_insert_dname(rt, key, len);
		} else {
			test_del_a_key(rt);
			test_checks_dname(rt);
		}

	}
	if(verb) test_tree_print(rt);
	test_checks(rt);
	test_checks_dname(rt);
	while(rt->count != 0) {
		test_del_a_key(rt);
		test_checks_dname(rt);
	}
}

/** test radname conversion */
static void test_radname(void)
{
	uint8_t d[1024];
	size_t dlen;
	uint8_t r[1024];
	radstrlen_t rlen;
	
	dlen = 1;
	rlen = sizeof(r);
	memcpy(d, "\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	CuAssert(tc, "radname_d2r", rlen == 0);

	dlen = 4;
	rlen = sizeof(r);
	memcpy(d, "\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	CuAssert(tc, "radname_d2r", rlen == 2);
	CuAssert(tc, "radname_d2r", memcmp(r, "nl", rlen) == 0);

	dlen = 9;
	rlen = sizeof(r);
	memcpy(d, "\004labs\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	CuAssert(tc, "radname_d2r", rlen == 7);
	CuAssert(tc, "radname_d2r", memcmp(r, "nl\000labs", rlen) == 0);

	dlen = 11;
	rlen = sizeof(r);
	memcpy(d, "\001x\004labs\002nl\000", dlen);
	radname_d2r(r, &rlen, d, dlen);
	CuAssert(tc, "radname_d2r", rlen == 9);
	CuAssert(tc, "radname_d2r", memcmp(r, "nl\000labs\000x", rlen) == 0);

	rlen = 0;
	dlen = sizeof(d);
	radname_r2d(r, rlen, d, &dlen);
	CuAssert(tc, "radname_r2d", dlen == 1);
	CuAssert(tc, "radname_r2d", d[0] == 0);

	rlen = 2;
	dlen = sizeof(d);
	memcpy(r, "nl", rlen);
	radname_r2d(r, rlen, d, &dlen);
	CuAssert(tc, "radname_r2d", dlen == 4);
	CuAssert(tc, "radname_r2d", memcmp(d, "\002nl\000", dlen) == 0);

	rlen = 7;
	dlen = sizeof(d);
	memcpy(r, "nl\000labs", rlen);
	radname_r2d(r, rlen, d, &dlen);
	CuAssert(tc, "radname_r2d", dlen == 9);
	CuAssert(tc, "radname_r2d", memcmp(d, "\004labs\002nl\000", dlen) == 0);

	rlen = 9;
	dlen = sizeof(d);
	memcpy(r, "nl\000labs\000x", rlen);
	radname_r2d(r, rlen, d, &dlen);
	CuAssert(tc, "radname_r2d", dlen == 11);
	CuAssert(tc, "radname_r2d", memcmp(d, "\001x\004labs\002nl\000", dlen) == 0);

	if(verb) fprintf(stderr, "radname: ok\n");
}

static void radtree_1(CuTest* t)
{
	tc = t;
	/* test radname conversion */
	test_radname();
}

static void radtree_2(CuTest* t)
{
	struct radtree* rt;
	struct region* region = region_create(xalloc, free);
	tc = t;

	rt = radix_tree_create(region);
	if(verb) test_tree_print(rt);
	test_checks(rt);

	test_ran_add_del(rt);
	test_dname_add_del(rt);
	if(verb) test_tree_print(rt);

	test_browse(rt);
	test_checks(rt);

	test_del(rt);
	radix_tree_delete(rt);
	region_destroy(region);
}

static void radtree_3(CuTest* t)
{
	tc = t;
	unit_radix();
}
