/* unitudb.c - unit test for udb
 * By W.C.A. Wijngaards
 * Copyright 2010, NLnet Labs.
 * BSD, see LICENSE.
 */

#include "config.h"
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "tpkg/cutest/cutest.h"
#include "udb.h"

static void udb_1(CuTest* tc);
static void udb_2(CuTest* tc);
static void udb_3(CuTest* tc);
static void udb_4(CuTest* tc);

CuSuite* reg_cutest_udb(void)
{
	CuSuite* suite = CuSuiteNew();
	SUITE_ADD_TEST(suite, udb_1);
	SUITE_ADD_TEST(suite, udb_2);
	SUITE_ADD_TEST(suite, udb_3);
	SUITE_ADD_TEST(suite, udb_4);
	return suite;
}

static CuTest* tc = NULL;

/*** test A for create and delete chunks ***/
/** global udb for test A */
static udb_base* udb_A = NULL;

/** get a temporary file name */
char* udbtest_get_temp_file(char* suffix)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), "/tmp/unitudb%u%s",
		(unsigned)getpid(), suffix);
	return strdup(buf);
}

/** walk through relptrs in types */
static void testAwalk(void* base, void* warg, uint8_t t, void* d, uint64_t s,
        udb_walk_relptr_cb* cb, void* arg)
{
	/* no relptrs */
	(void)base;
	(void)warg;
	(void)t;
	(void)d;
	(void)s;
	(void)cb;
	(void)arg;
}

/** info for A allocs */
struct info_A {
	/** pointer to alloc (original value) */
	udb_void a;
	/** relptr to the block */
	udb_ptr ptr;
	/** size of alloc */
	uint64_t sz;
	/** fill value */
	uint8_t fill;
};

/** max num of A allocs */
#define MAX_NUM_A 1024

/** get a random size for test A */
static uint64_t size_for_A(void) {
	uint64_t sz = random() % 1024;
	return sz;
}

/** assert udb invariants */
static void
assert_udb_invariant(udb_base* udb)
{
	CuAssertTrue(tc, udb->base != NULL);
	CuAssertTrue(tc, udb->base_size == udb->glob_data->fsize);
	CuAssertTrue(tc, udb->glob_data->hsize == UDB_HEADER_SIZE);
	CuAssertTrue(tc, udb->glob_data->dirty_alloc == 0);
	CuAssertTrue(tc, udb->glob_data->rb_old == 0);
	CuAssertTrue(tc, udb->glob_data->rb_new == 0);
	CuAssertTrue(tc, udb->glob_data->rb_size == 0);
	CuAssertTrue(tc, udb->glob_data->rb_seg == 0);
	CuAssertTrue(tc, udb->alloc->disk->stat_data <= udb->base_size);
	CuAssertTrue(tc, udb->alloc->disk->stat_alloc <= udb->base_size);
	CuAssertTrue(tc, udb->alloc->disk->stat_free <= udb->base_size);
	CuAssertTrue(tc, udb->alloc->disk->nextgrow <= udb->base_size);
}

/** assert that the alloc/free structure is OK */
static void
assert_free_structure(udb_base* udb)
{
	/* walk through all parts and note allocs */
	uint64_t num_free = 0;
	uint64_t num_free_bytes = 0;
	uint64_t num_alloc_bytes = 0;
	uint64_t exp_free[UDB_ALLOC_CHUNKS_MAX+1];

	void* base = udb->base;
	udb_void p = udb->glob_data->hsize;
	int e;
	uint64_t num_e;
	int verb = 0;
	(void)num_free; /* avoid unused warning */

	if(verb) printf("** current state ng=%llu\n",
		(long long unsigned)udb->alloc->disk->nextgrow);
	memset(exp_free, 0, sizeof(exp_free));
	while(p < udb->alloc->disk->nextgrow) {
		uint8_t exp = UDB_CHUNK(p)->exp;
		uint64_t sz;
		if(exp == UDB_EXP_XL)
			sz = UDB_XL_CHUNK(p)->size;
		else	sz = (uint64_t)1<<exp;
		if(UDB_CHUNK(p)->type == udb_chunk_type_free) {
			num_free ++;
			num_free_bytes += sz;
			exp_free[exp]++;
		} else num_alloc_bytes += sz;
		if(verb) printf("walk at %llu exp %d %s\n",
			(long long unsigned)p, exp,
			UDB_CHUNK(p)->type == udb_chunk_type_free?
			"free":"data");
		CuAssertTrue(tc, *(uint8_t*)UDB_REL(base, p+sz-1) == exp);
		p += sz;
	}
	CuAssertTrue(tc, num_free_bytes == udb->alloc->disk->stat_free);
	CuAssertTrue(tc, num_alloc_bytes == udb->alloc->disk->stat_alloc);
	if(verb) printf("num free chunks=%llu\n",
		(long long unsigned)num_free);

	/* check that the free lists are coherent */
	for(e = UDB_ALLOC_CHUNK_MINEXP; e <= UDB_ALLOC_CHUNKS_MAX; e++) {
		udb_void prev = 0;
		p = udb->alloc->disk->free[e - UDB_ALLOC_CHUNK_MINEXP];
		num_e = 0;
		while(p) {
			udb_free_chunk_d* fp;
			if(verb) printf("freelist exp %d at %llu\n", e, 
				(long long unsigned)p);
			fp = UDB_FREE_CHUNK(p);
			if(verb) printf("  ->exp=%d prev %llu next %llu\n",
				fp->exp, (long long unsigned)fp->prev,
				(long long unsigned)fp->next);
			CuAssertTrue(tc, fp->exp == (uint8_t)e);
			CuAssertTrue(tc, fp->type == udb_chunk_type_free);
			CuAssertTrue(tc, fp->prev == prev);
			num_e++;
			prev = p;
			p = fp->next;
		}
		CuAssertTrue(tc, num_e == exp_free[e]);
	}

}

/** find a pointer on a chunks pointerlist */
int
find_ptr_on_chunk(void* base, udb_void chdata, udb_void relptr, udb_base* udb)
{
	size_t count = 0;
	udb_void chunk = chunk_from_dataptr_ext(chdata);
	udb_void ptr = UDB_CHUNK(chunk)->ptrlist;
	/*printf("find ptr on chunk for relptr %llu, to ch %llu chdata %llu\n",
		relptr, chunk, chdata);*/
	while(ptr) {
		udb_rel_ptr* p = UDB_REL_PTR(ptr);
		if(ptr == relptr) {
			return 1;
		}
		ptr = p->next;
		if(count++ > udb->alloc->disk->nextgrow / 32)
			break; /* max number of chunks in file */
	}
	return 0;
}

/** callback to check relptrs */
void check_rptrs_cb(void* base, udb_rel_ptr* p, void* arg)
{
	udb_base* udb = (udb_base*)arg;
	/* check that this rptr is OK */
	if(p->data == 0)
		return;
	/* destination must be within the mmap */
	CuAssertTrue(tc, p->data > udb->glob_data->hsize);
	CuAssertTrue(tc, p->data < udb->alloc->disk->nextgrow);
	/* the pointer must be on the pointerlist of that chunk */
	if(!find_ptr_on_chunk(base, p->data, UDB_SYSTOREL(base, p), udb)) {
		printf("cannot find ptr %llu on its chunks list at %llu\n",
			(unsigned long long)UDB_SYSTOREL(base, p),
			(unsigned long long)p->data);
		abort();
	}
	CuAssertTrue(tc, find_ptr_on_chunk(base, p->data,
		UDB_SYSTOREL(base, p), udb) != 0);
}

/** assert that the relptr structure is OK */
static void
assert_relptr_structure(udb_base* udb)
{
	/* walk through all parts and check all relptrs */
	void* base = udb->base;
	udb_void p = udb->glob_data->hsize;
	int verb = 0;

	while(p < udb->alloc->disk->nextgrow) {
		uint8_t exp = UDB_CHUNK(p)->exp;
		uint64_t sz, dsz;
		udb_void dataptr;
		if(verb) printf("walk at %llu exp %d %s\n",
			(long long unsigned)p, exp,
			UDB_CHUNK(p)->type == udb_chunk_type_free?
			"free":"data");
		if(exp == UDB_EXP_XL) {
			sz = UDB_XL_CHUNK(p)->size;
			dataptr = p+sizeof(udb_xl_chunk_d);
			dsz = sz - sizeof(udb_xl_chunk_d)-16;
		} else {
			sz = (uint64_t)1<<exp;
			dataptr = p+sizeof(udb_chunk_d);
			dsz = sz - sizeof(udb_chunk_d)-1;
		}
		if(UDB_CHUNK(p)->type == udb_chunk_type_free) {
			/* nothing to do */
		} else if(UDB_CHUNK(p)->ptrlist) {
			/* go through the relptr list and assert begin/end */
			udb_rel_ptr* r = UDB_REL_PTR(UDB_CHUNK(p)->ptrlist);
			CuAssertTrue(tc, r->prev == 0);
			while(r->next != 0) {
				CuAssertTrue(tc, r->data == dataptr);
				CuAssertTrue(tc, UDB_REL_PTR(UDB_REL_PTR(
					r->next)->prev) == r);
				r = UDB_REL_PTR(r->next);
			}
			CuAssertTrue(tc, r->data == dataptr);
			CuAssertTrue(tc, r->next == 0);
		}
		/* perform udb-walk with our user arg to check relptrs inside*/
		(*udb->walkfunc)(base, udb->walkarg, UDB_CHUNK(p)->type,
			UDB_REL(base, dataptr), dsz, check_rptrs_cb, udb);
		CuAssertTrue(tc, *(uint8_t*)UDB_REL(base, p+sz-1) == exp);
		p += sz;
	}
}

udb_base* gdb = NULL;

/** check a UDB if it is OK */
void check_udb_structure(CuTest* t, udb_base* udb)
{
	if(t) tc = t;
	gdb = udb;
	assert_udb_invariant(udb);
	assert_free_structure(udb);
	assert_relptr_structure(udb);
}
void check_udb(void)
{
	if(!gdb) return;
	check_udb_structure(NULL, gdb);
}
	
/** assert the allocations are 'allright' */
static void
assert_info_A(udb_base* udb, struct info_A* inf, size_t num_a)
{
	size_t i;
	for(i=0; i<num_a; i++) {
		uint8_t* p = (uint8_t*)UDB_PTR(&inf[i].ptr);
		uint64_t j;
		udb_void d = (udb_void)((void*)p-udb->base);
		CuAssertTrue(tc, d+inf[i].sz < udb->alloc->disk->nextgrow);
		for(j=0; j<inf[i].sz; j++) {
			CuAssertTrue(tc, p[j] == inf[i].fill);
		}
	}
}

/** do the A tests */
static void
do_A_tests(udb_base* udb, int verb)
{
	struct info_A inf[MAX_NUM_A];
	size_t num_a = 0;
	int i, count = 10000;

	for(i=0; i<count; i++) {
		/* what do we do now? */
		int x = random();
		if( (x%2 == 0 && num_a < MAX_NUM_A) || num_a == 0) {
			/* alloc */
			uint64_t sz = size_for_A();
			int w = (int)(num_a++);
			inf[w].sz = sz;
			inf[w].fill = random()%255;
			if(verb) printf("alloc(%llu)", (long long unsigned)sz);
			inf[w].a = udb_alloc_space(udb->alloc, sz);
			memset(UDB_REL(udb->base, inf[w].a),
				(int)inf[w].fill, inf[w].sz);
			if(verb) printf(" = %llu\n",
				(long long unsigned)inf[w].a);
			udb_ptr_init(&inf[w].ptr, udb);
			udb_ptr_set(&inf[w].ptr, udb, inf[w].a);
			CuAssertTrue(tc, inf[w].a);
		} else if(x%2 == 1 && num_a > 0) {
			/* free */
			int w = random() % num_a;
			udb_void d;
			size_t sz;
			if(verb) printf("free(%llu, %llu)\n",
				(long long unsigned)inf[w].ptr.data,
				(long long unsigned)inf[w].sz);
			d = inf[w].ptr.data;
			sz = inf[w].sz;
			udb_ptr_set(&inf[w].ptr, udb, 0);
			CuAssertTrue(tc, udb_alloc_free(udb->alloc, d, sz));
			/* cleanup */
			if(num_a > 0 && (size_t)w != num_a-1) {
				inf[w] = inf[num_a-1];
				udb_ptr_init(&inf[w].ptr, udb);
				udb_ptr_set(&inf[w].ptr, udb,
					inf[num_a-1].ptr.data);
				udb_ptr_set(&inf[num_a-1].ptr, udb, 0);
			}
			num_a--;
		}
		assert_udb_invariant(udb);
		assert_info_A(udb, inf, num_a);
		assert_free_structure(udb);
		assert_relptr_structure(udb);
	}
}

static void test_A(void)
{
	char* fname = udbtest_get_temp_file(".udb");
	udb_base* udb;
	int verb = 0;
	if(verb) printf("Test A (%s)\n", fname);
	udb = udb_base_create_new(fname, testAwalk, NULL);
	udb_A = udb;

	/* perform tests on this udb file */
	do_A_tests(udb, verb);

	/* close and free it */
	udb_base_close(udb);
	udb_base_free(udb);
	if(verb) printf("End test A\n");
	if(unlink(fname) != 0)
		perror("unlink");
	free(fname);
}

/*** end test A for create and delete chunks ***/

/** test structure sizes for compiler padding */
static void
test_struct_sizes(void)
{
	size_t p = sizeof(udb_void);
	size_t rp = sizeof(udb_rel_ptr);
	CuAssertTrue(tc, rp == 3*p);
	CuAssertTrue(tc, sizeof(struct udb_glob_d) == 8*5+2*rp+2*p);
	CuAssertTrue(tc, sizeof(struct udb_chunk_d) == 8+p);
	CuAssertTrue(tc, sizeof(struct udb_chunk_d)%8 == 0); /* 64bit aligned */
	CuAssertTrue(tc, sizeof(struct udb_free_chunk_d) == 8+2*p);
	CuAssertTrue(tc, sizeof(struct udb_free_chunk_d)%8 == 0); /* 64bit aligned */
	CuAssertTrue(tc, sizeof(struct udb_xl_chunk_d) == 16+p);
	CuAssertTrue(tc, sizeof(struct udb_xl_chunk_d)%8 == 0); /* 64bit aligned */
	CuAssertTrue(tc, sizeof(struct udb_alloc_d) == 8*4+
		(UDB_ALLOC_CHUNKS_MAX-UDB_ALLOC_CHUNK_MINEXP+1)*p);
	/* need whole blocks of 32 to mark off as in-use/special */
	CuAssertTrue(tc, UDB_HEADER_SIZE%UDB_ALLOC_CHUNK_MINSIZE == 0);
	CuAssertTrue(tc, sizeof(udb_ptr*) % sizeof(uint32_t) == 0);
}

/** test exp size */
static void
test_ucb_exp_size(void)
{
	CuAssertTrue(tc, udb_exp_size(1) == 0);
	CuAssertTrue(tc, udb_exp_size(2) == 1);
	CuAssertTrue(tc, udb_exp_size(3) == 2);
	CuAssertTrue(tc, udb_exp_size(4) == 2);
	CuAssertTrue(tc, udb_exp_size(6) == 3);
	CuAssertTrue(tc, udb_exp_size(8) == 3);
	CuAssertTrue(tc, udb_exp_size(15) == 4);
	CuAssertTrue(tc, udb_exp_size(16) == 4);
	CuAssertTrue(tc, udb_exp_size(1023) == 10);
	CuAssertTrue(tc, udb_exp_size(1024) == 10);
	CuAssertTrue(tc, udb_exp_size(1025) == 11);
	CuAssertTrue(tc, udb_exp_size(1408) == 11);
	CuAssertTrue(tc, udb_exp_size(6758) == 13);
	CuAssertTrue(tc, udb_exp_size(1024*1024) == 20);
	CuAssertTrue(tc, udb_exp_size(0x0fffffff) == 28);
	CuAssertTrue(tc, udb_exp_size(0x0cf0f000) == 28);
	CuAssertTrue(tc, udb_exp_size(UDB_ALLOC_CHUNK_SIZE)==UDB_ALLOC_CHUNKS_MAX);
	CuAssertTrue(tc, UDB_ALLOC_CHUNKS_MAX < 255); /* to fit in uint8 */
	CuAssertTrue(tc, udb_exp_size(UDB_ALLOC_CHUNK_MINSIZE)
		== UDB_ALLOC_CHUNK_MINEXP);
}

/** test exp offset */
static void
test_ucb_exp_offset(void)
{
	CuAssertTrue(tc, udb_exp_offset(1) == 0);
	CuAssertTrue(tc, udb_exp_offset(2) == 1);
	CuAssertTrue(tc, udb_exp_offset(3) == 0);
	CuAssertTrue(tc, udb_exp_offset(4) == 2);
	CuAssertTrue(tc, udb_exp_offset(5) == 0);
	CuAssertTrue(tc, udb_exp_offset(6) == 1);
	CuAssertTrue(tc, udb_exp_offset(7) == 0);
	CuAssertTrue(tc, udb_exp_offset(8) == 3);
	CuAssertTrue(tc, udb_exp_offset(12) == 2);
	CuAssertTrue(tc, udb_exp_offset(16) == 4);
	CuAssertTrue(tc, udb_exp_offset(32) == 5);
	CuAssertTrue(tc, udb_exp_offset(256) == 8);
	CuAssertTrue(tc, udb_exp_offset(256+16) == 4);
	CuAssertTrue(tc, udb_exp_offset(1024+256+16) == 4);
	CuAssertTrue(tc, udb_exp_offset(1024+256) == 8);
	CuAssertTrue(tc, udb_exp_offset(1024) == 10);
	CuAssertTrue(tc, udb_exp_offset(288) == 5);
}

static void udb_1(CuTest* t)
{
	tc = t;
	test_struct_sizes();
}

static void udb_2(CuTest* t)
{
	tc = t;
	test_ucb_exp_size();
}

static void udb_3(CuTest* t)
{
	tc = t;
	test_ucb_exp_offset();
}

static void udb_4(CuTest* t)
{
	tc = t;
	test_A();
}
