/*
 * region-allocator.c -- region based memory allocator.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "region-allocator.h"
#ifdef MEMCHECK
#include "util.h"
#undef ALIGN_UP
#endif

#ifdef ALIGNMENT
#undef ALIGNMENT
#endif
#define ALIGN_UP(x, s)     (((x) + s - 1) & (~(s - 1)))
#define ALIGNMENT          (sizeof(void *))
#define CHECK_DOUBLE_FREE 0 /* set to 1 to perform expensive check for double recycle() */

#ifdef MEMCHECK
/* undefine the overrides, the originals are called by the overrides to
   provide the actual functionality */
#undef region_create
#undef region_create_custom
#undef region_destroy
#undef region_add_cleanup
#undef region_alloc
#undef region_alloc_init
#undef region_alloc_zero
#undef region_free_all
#undef region_strdup
#undef region_recycle
#undef region_recycle_str

struct region_mem {
	struct region_mem* prev, *next;
	const char* file;
	int32_t pad;  /* pad for 64-bit alignment of this struct */
	int32_t line;
	uint32_t size;
	uint32_t magic;
	uint8_t data[0];
};
/* file,line,magic before and magic after */
#define REGIONMEMCHECKPAD (sizeof(struct region_mem) + sizeof(uint32_t))
/* enable extra printout of existing allocs, to debug the debug code */
#define MEMCHECK_DEBUG 0
/* enable printout of every malloc and free */
#define MEMCHECK_TRACE 0

#endif /* MEMCHECK */

typedef struct cleanup cleanup_type;
struct cleanup
{
	void (*action)(void *);
	void *data;
};

struct recycle_elem {
	struct recycle_elem* next;
};

struct region
{
#ifdef MEMCHECK
	struct region_mem* reglist; /* list of allocated small-objects */
#endif /* MEMCHECK */
	size_t        total_allocated;
	size_t        small_objects;
	size_t        large_objects;
	size_t        chunk_count;
	size_t        unused_space; /* Unused space due to alignment, etc. */

	size_t        allocated;
	char         *initial_data;
	char         *data;

	void         *(*allocator)(size_t);
	void          (*deallocator)(void *);

	size_t        maximum_cleanup_count;
	size_t        cleanup_count;
	cleanup_type *cleanups;

	size_t        chunk_size;
	size_t        large_object_size;

	/* if not NULL recycling is enabled.
	 * It is an array of linked lists of parts held for recycle.
	 * The parts are all pointers to within the allocated chunks.
	 * Array [i] points to elements of size i. */
	struct recycle_elem** recycle_bin;
	/* amount of memory in recycle storage */
	size_t		recycle_size;
};


static region_type *
alloc_region_base(void *(*allocator)(size_t size),
		  void (*deallocator)(void *),
		  size_t initial_cleanup_count)
{
	region_type *result = (region_type *) allocator(sizeof(region_type));
	if (!result) return NULL;

	result->total_allocated = 0;
	result->small_objects = 0;
	result->large_objects = 0;
	result->chunk_count = 1;
	result->unused_space = 0;
	result->recycle_bin = NULL;
	result->recycle_size = 0;
#ifdef MEMCHECK
	result->reglist = NULL;
#endif

	result->allocated = 0;
	result->data = NULL;
	result->initial_data = NULL;

	result->allocator = allocator;
	result->deallocator = deallocator;

	assert(initial_cleanup_count > 0);
	result->maximum_cleanup_count = initial_cleanup_count;
	result->cleanup_count = 0;
	result->cleanups = (cleanup_type *) allocator(
		result->maximum_cleanup_count * sizeof(cleanup_type));
	if (!result->cleanups) {
		deallocator(result);
		return NULL;
	}

	result->chunk_size = DEFAULT_CHUNK_SIZE;
	result->large_object_size = DEFAULT_LARGE_OBJECT_SIZE;
	return result;
}

region_type *
region_create(void *(*allocator)(size_t size),
	      void (*deallocator)(void *))
{
	region_type* result = alloc_region_base(allocator, deallocator,
		DEFAULT_INITIAL_CLEANUP_SIZE);
	if(!result)
		return NULL;
	result->data = (char *) allocator(result->chunk_size);
	if (!result->data) {
		deallocator(result->cleanups);
		deallocator(result);
		return NULL;
	}
	result->initial_data = result->data;

	return result;
}


region_type *region_create_custom(void *(*allocator)(size_t),
				  void (*deallocator)(void *),
				  size_t chunk_size,
				  size_t large_object_size,
				  size_t initial_cleanup_size,
				  int recycle)
{
	region_type* result = alloc_region_base(allocator, deallocator,
		initial_cleanup_size);
	if(!result)
		return NULL;
	assert(large_object_size <= chunk_size);
	result->chunk_size = chunk_size;
	result->large_object_size = large_object_size;
	if(result->chunk_size > 0) {
		result->data = (char *) allocator(result->chunk_size);
		if (!result->data) {
			deallocator(result->cleanups);
			deallocator(result);
			return NULL;
		}
		result->initial_data = result->data;
	}
	if(recycle) {
		result->recycle_bin = allocator(sizeof(struct recycle_elem*)
			* result->large_object_size);
		if(!result->recycle_bin) {
			region_destroy(result);
			return NULL;
		}
		memset(result->recycle_bin, 0, sizeof(struct recycle_elem*)
			* result->large_object_size);
	}
	return result;
}


void
region_destroy(region_type *region)
{
	void (*deallocator)(void *);
	if (!region)
		return;
#ifdef MEMCHECK
	if(MEMCHECK_TRACE)
		memcheck_log_origin("regcheck region_destroy", region);
#endif

	deallocator = region->deallocator;

	region_free_all(region);
	deallocator(region->cleanups);
	deallocator(region->initial_data);
	if(region->recycle_bin)
		deallocator(region->recycle_bin);
	deallocator(region);
}


size_t
region_add_cleanup(region_type *region, void (*action)(void *), void *data)
{
	assert(action);

	if (region->cleanup_count >= region->maximum_cleanup_count) {
		cleanup_type *cleanups = (cleanup_type *) region->allocator(
			2 * region->maximum_cleanup_count * sizeof(cleanup_type));
		if (!cleanups)
			return 0;

		memcpy(cleanups, region->cleanups,
		       region->cleanup_count * sizeof(cleanup_type));
		region->deallocator(region->cleanups);

		region->cleanups = cleanups;
		region->maximum_cleanup_count *= 2;
	}

	region->cleanups[region->cleanup_count].action = action;
	region->cleanups[region->cleanup_count].data = data;

	++region->cleanup_count;
	return region->cleanup_count;
}

#ifdef MEMCHECK
void
region_remove_cleanup(region_type *region, void (*action)(void *), void *data)
{
	size_t i;
	for(i=0; i<region->cleanup_count; i++) {
		if(region->cleanups[i].action == action &&
		   region->cleanups[i].data == data) {
			region->cleanup_count--;
			region->cleanups[i] =
				region->cleanups[region->cleanup_count];
			return;
		}
	}
}
#endif /* MEMCHECK */

void *
region_alloc(region_type *region, size_t size)
{
	size_t aligned_size;
	void *result;

	if (size == 0) {
		size = 1;
	}
	aligned_size = ALIGN_UP(size, ALIGNMENT);

	if (aligned_size >= region->large_object_size) {
		result = region->allocator(size);
		if (!result)
			return NULL;

		if (!region_add_cleanup(region, region->deallocator, result)) {
			region->deallocator(result);
			return NULL;
		}

		region->total_allocated += size;
		++region->large_objects;

		return result;
	}

	if (region->recycle_bin && region->recycle_bin[aligned_size]) {
		result = (void*)region->recycle_bin[aligned_size];
		region->recycle_bin[aligned_size] = region->recycle_bin[aligned_size]->next;
		region->recycle_size -= aligned_size;
		region->unused_space += aligned_size - size;
		return result;
	}

	if (region->allocated + aligned_size > region->chunk_size) {
		void *chunk = region->allocator(region->chunk_size);
		size_t wasted;
		if (!chunk)
			return NULL;

		wasted = (region->chunk_size - region->allocated) & (~(ALIGNMENT-1));
		if(wasted >= ALIGNMENT) {
			/* put wasted part in recycle bin for later use */
			region->total_allocated += wasted;
			++region->small_objects;
			region_recycle(region, region->data+region->allocated, wasted);
			region->allocated += wasted;
		}
		++region->chunk_count;
		region->unused_space += region->chunk_size - region->allocated;

		if(!region_add_cleanup(region, region->deallocator, chunk)) {
			region->deallocator(chunk);
			region->chunk_count--;
			region->unused_space -=
                                region->chunk_size - region->allocated;
			return NULL;
		}
		region->allocated = 0;
		region->data = (char *) chunk;
	}

	result = region->data + region->allocated;
	region->allocated += aligned_size;

	region->total_allocated += aligned_size;
	region->unused_space += aligned_size - size;
	++region->small_objects;

	return result;
}

void *
region_alloc_init(region_type *region, const void *init, size_t size)
{
	void *result = region_alloc(region, size);
	if (!result) return NULL;
	memcpy(result, init, size);
	return result;
}

void *
region_alloc_zero(region_type *region, size_t size)
{
	void *result = region_alloc(region, size);
	if (!result) return NULL;
	memset(result, 0, size);
	return result;
}

void
region_free_all(region_type *region)
{
	size_t i;
	assert(region);
	assert(region->cleanups);

	i = region->cleanup_count;
	while (i > 0) {
		--i;
		assert(region->cleanups[i].action);
		region->cleanups[i].action(region->cleanups[i].data);
	}

	if(region->recycle_bin) {
		memset(region->recycle_bin, 0, sizeof(struct recycle_elem*)
			* region->large_object_size);
		region->recycle_size = 0;
	}

	region->data = region->initial_data;
	region->cleanup_count = 0;
	region->allocated = 0;

	region->total_allocated = 0;
	region->small_objects = 0;
	region->large_objects = 0;
	region->chunk_count = 1;
	region->unused_space = 0;
}


char *
region_strdup(region_type *region, const char *string)
{
	return (char *) region_alloc_init(region, string, strlen(string) + 1);
}

void
region_recycle(region_type *region, void *block, size_t size)
{
	size_t aligned_size;
	size_t i;

	if(!block || !region->recycle_bin)
		return;

	if (size == 0) {
		size = 1;
	}
	aligned_size = ALIGN_UP(size, ALIGNMENT);

	if(aligned_size < region->large_object_size) {
		struct recycle_elem* elem = (struct recycle_elem*)block;
		/* we rely on the fact that ALIGNMENT is void* so the next will fit */
		assert(aligned_size >= sizeof(struct recycle_elem));

		if(CHECK_DOUBLE_FREE) {
			/* make sure the same ptr is not freed twice. */
			struct recycle_elem *p = region->recycle_bin[aligned_size];
			while(p) {
				assert(p != elem);
				p = p->next;
			}
		}

		elem->next = region->recycle_bin[aligned_size];
		region->recycle_bin[aligned_size] = elem;
		region->recycle_size += aligned_size;
		region->unused_space -= aligned_size - size;
		return;
	}

	/* a large allocation */
	region->total_allocated -= size;
	--region->large_objects;
	for(i=0; i<region->cleanup_count; i++) {
		while(region->cleanups[i].data == block) {
			/* perform action (deallocator) on block */
			region->cleanups[i].action(block);
			region->cleanups[i].data = NULL;
			/* remove cleanup - move last entry here, check this one again */
			--region->cleanup_count;
			region->cleanups[i].action =
				region->cleanups[region->cleanup_count].action;
			region->cleanups[i].data =
				region->cleanups[region->cleanup_count].data;
		}
	}
}

void
region_dump_stats(region_type *region, FILE *out)
{
	fprintf(out, "%lu objects (%lu small/%lu large), %lu bytes allocated (%lu wasted) in %lu chunks, %lu cleanups, %lu in recyclebin",
		(unsigned long) (region->small_objects + region->large_objects),
		(unsigned long) region->small_objects,
		(unsigned long) region->large_objects,
		(unsigned long) region->total_allocated,
		(unsigned long) region->unused_space,
		(unsigned long) region->chunk_count,
		(unsigned long) region->cleanup_count,
		(unsigned long) region->recycle_size);
	if(1 && region->recycle_bin) {
		/* print details of the recycle bin */
		size_t i;
		for(i=0; i<region->large_object_size; i++) {
			size_t count = 0;
			struct recycle_elem* el = region->recycle_bin[i];
			while(el) {
				count++;
				el = el->next;
			}
			if(i%ALIGNMENT == 0 && i!=0)
				fprintf(out, " %lu", (unsigned long)count);
		}
	}
}

size_t region_get_recycle_size(region_type* region)
{
	return region->recycle_size;
}

/* debug routine, includes here to keep base region-allocator independent */
#undef ALIGN_UP
#include "util.h"
void
region_log_stats(region_type *region)
{
	char buf[10240], *str=buf;
	int strl = sizeof(buf);
	int len=0;
	snprintf(str, strl, "%lu objects (%lu small/%lu large), %lu bytes allocated (%lu wasted) in %lu chunks, %lu cleanups, %lu in recyclebin%n",
		(unsigned long) (region->small_objects + region->large_objects),
		(unsigned long) region->small_objects,
		(unsigned long) region->large_objects,
		(unsigned long) region->total_allocated,
		(unsigned long) region->unused_space,
		(unsigned long) region->chunk_count,
		(unsigned long) region->cleanup_count,
		(unsigned long) region->recycle_size,
		&len);
	str+=len;
	strl-=len;
	if(1 && region->recycle_bin) {
		/* print details of the recycle bin */
		size_t i;
		for(i=0; i<region->large_object_size; i++) {
			size_t count = 0;
			struct recycle_elem* el = region->recycle_bin[i];
			while(el) {
				count++;
				el = el->next;
			}
			if(i%ALIGNMENT == 0 && i!=0) {
				snprintf(str, strl, " %lu%n", (unsigned long)count,
					&len);
				str+=len;
				strl-=len;
			}
		}
	}
	log_msg(LOG_INFO, "memory: %s", buf);
}

/* debug routine for memory allocation checks */
#ifdef MEMCHECK
/* magic for buffer under/overflow checks */
#define MEMMAGIC 0x1234ffab
/* memory allocation prefix: prev,nextptr,size,magic */
struct mem {
	struct mem* prev;
	struct mem* next;
	const char* file;
	int line;
	const char* func;
	uint32_t size;
	uint32_t magic;
	uint8_t data[0];
};
/* memory allocation postfix: magic,size */
#define MEMPAD (sizeof(struct mem)+sizeof(uint32_t)+sizeof(uint32_t))

/* double linked list for memory allocations */
static struct mem* memlist = NULL;
/* total amount of memory allocated (without overhead) */
static unsigned total_alloc = 0;
#undef malloc
#undef free

/* get end pointer for mem struct */
static uint32_t*
get_end_ptr(struct mem* m)
{
	return (uint32_t*)(&m->data[m->size]);
}

/* log an allocation event */
static void
log_mem_event(char* event, int size, const char* file, int line,
	const char* func)
{
	log_msg(LOG_INFO, "mem_event %s %d %s:%d %s", event, size,
		file, line, func);
}

/* do the alloc work */
static struct mem*
do_alloc_work(size_t size, const char* file, int line, const char* func)
{
	struct mem* m = (struct mem*)malloc(size+MEMPAD);
	uint32_t x, *e;
	if(!m) {
		log_msg(LOG_ERR, "malloc failed in %s %d %s", file, line, func);
		exit(1);
	}
	m->prev = NULL;
	m->next = memlist;
	if(memlist) memlist->prev = m;
	memlist = m;
	m->size = size;
	m->magic = MEMMAGIC;
	e = get_end_ptr(m);
	x = MEMMAGIC;
	memmove(e, &x, sizeof(x));
	x = size;
	memmove(e+1, &x, sizeof(x));
	total_alloc += size;
	m->file = file;
	m->line = line;
	m->func = func;
	return m;
}

void *malloc_nsd(size_t size, const char* file, int line, const char* func)
{
	struct mem* m = do_alloc_work(size, file, line, func);
	memset(m->data, 0xCC, size); /* not zero, but certain of the value */
	if(MEMCHECK_TRACE)
		log_mem_event("malloc", size, file, line, func);
	return m->data;
}

void *calloc_nsd(size_t nmemb, size_t size, const char* file, int line,
	const char* func)
{
	struct mem* m = do_alloc_work(size*nmemb, file, line, func);
	memset(m->data, 0, m->size);
	if(MEMCHECK_TRACE)
		log_mem_event("calloc", m->size, file, line, func);
	return m->data;
}

/* do the free work */
static void
do_free_work(struct mem* m)
{
	uint32_t* e = get_end_ptr(m);

	/* remove from accounting */
	total_alloc -= m->size;
	if(m->prev) m->prev->next = m->next;
	else memlist = m->next;
	if(m->next) m->next->prev = m->prev;

	/* memset to 0xDD */
	memset(m->data, 0xDD, m->size);
	memset(e, 0xDD, sizeof(*e)*2);
	m->prev = NULL;
	m->next = NULL;
	m->size = 0;
	m->file = NULL;
	m->line = 0;
	m->func = NULL;
	m->magic = 0xDDDDDDDD;

	/* actual free */
	free(m);
}

/* check magic numbers for existing block */
static struct mem*
check_magic(void* ptr, char* ev, const char* file, int l, const char* func)
{
	struct mem* m = (struct mem*)(ptr - sizeof(struct mem));
	uint32_t x, *e;
	if(m->magic != MEMMAGIC) {
		log_msg(LOG_ERR, "%s: bad start %s %d %s", ev, file, l, func);
		exit(1);
	}
	e = get_end_ptr(m);
	memmove(&x, e, sizeof(x));
	if(x != MEMMAGIC) {
		log_msg(LOG_ERR, "%s: bad end %s %d %s", ev, file, l, func);
		exit(1);
	}
	memmove(&x, e+1, sizeof(x));
	if(m->size != x) {
		log_msg(LOG_ERR, "%s: sizesbad %s %d %s", ev, file, l, func);
		exit(1);
	}
	return m;
}

void free_nsd(void *ptr, const char* file, int line, const char* func)
{
	struct mem* m;

	if(!ptr) return; /* nothing */

	/* check magic strings */
	m = check_magic(ptr, "free", file, line, func);

	if(MEMCHECK_TRACE)
		log_mem_event("free", m->size, file, line, func);

	/* do the actual free */
	do_free_work(m);
}

void *realloc_nsd(void *ptr, size_t size, const char* file, int line,
	const char* func)
{
	struct mem* m;
	struct mem* m2;
	if(ptr == NULL && size == 0) {
		/* nothing to do */
		return NULL;
	} else if(size == 0) {
		/* free it */
		m = check_magic(ptr, "realloc-free", file, line, func);
		log_mem_event("realloc", -(int)m->size, file, line, func);
		do_free_work(m);
		return NULL;
	} else if(ptr == NULL) {
		/* malloc it */
		m = do_alloc_work(size, file, line, func);
		log_mem_event("realloc", m->size, file, line, func);
		return m->data;
	}
	/* check magic */
	m = check_magic(ptr, "realloc", file, line, func);
	if(size == m->size)
		return m->data; /* nothing to do */
	/* realloc it */
	m2 = do_alloc_work(size, file, line, func);
	if(m2->size > m->size)
		memcpy(m2->data, m->data, m->size);
	else	memcpy(m2->data, m->data, m2->size);
	if(MEMCHECK_TRACE)
		log_mem_event("realloc", (int)m2->size-(int)m->size,
			file, line, func);
	do_free_work(m);
	return m2->data;
}

char *strdup_nsd(const char *str, const char* file, int line, const char* func)
{
	struct mem* m;
	size_t s;
	if(!str) {
		log_msg(LOG_ERR, "strdup: NULLstr %s %d %s", file, line, func);
		exit(1);
	}
	s = strlen(str)+1;
	m = do_alloc_work(s, file, line, func);
	memmove(m->data, str, s);
	if(MEMCHECK_TRACE)
		log_mem_event("strdup", m->size, file, line, func);
	return (char*)m->data;
}

void memcheck_log_origin(char* desc, void* p)
{
	struct mem* m = check_magic(p, "memcheck_log_origin", __FILE__,
		__LINE__, __func__);
	log_msg(LOG_INFO, "%s %p %s:%d %s", desc, p, m->file, m->line, m->func);
}

/* set the malloced item to come from specified origin */
static void
set_alloc_report(void* p, const char* file, int line, const char* func)
{
	struct mem* m = check_magic(p, "set-alloc-report", file, line, func);
	m->file = file;
	m->line = line;
	m->func = func;
}

void *regalloc(size_t s)
{
	return malloc_nsd(s, "region", 1, "region-alloc-func");
}

void regfree(void* p)
{
	return free_nsd(p, "region", 1, "region-free-func");
}

#undef region_create
#undef region_create_custom
region_type* regcreate_nsd(const char* file, int line, const char* func)
{
	/* always make a recycle bin */
	region_type* r= region_create_custom(regalloc, regfree, 
		DEFAULT_CHUNK_SIZE, DEFAULT_LARGE_OBJECT_SIZE,
		DEFAULT_INITIAL_CLEANUP_SIZE, 1);
	if(MEMCHECK_TRACE)
		log_msg(LOG_INFO, "regcheck region_create %p at %s:%d %s",
			r, file, line, func);
	set_alloc_report(r, file, line, func);
	return r;
}

region_type* regcreate_custom_nsd(size_t chunk_size,
                                  size_t large_object_size,
                                  size_t initial_cleanup_size,
                                  int recycle,
				  const char* file, int line, const char* func)
{
	/* ignore recycle: always make and do */
	region_type* r = region_create_custom(regalloc, regfree, chunk_size,
		large_object_size, initial_cleanup_size, recycle?recycle:1);
	if(MEMCHECK_TRACE)
		log_msg(LOG_INFO, "regcheck region_create_custom %p at %s:%d %s",
			r, file, line, func);
	set_alloc_report(r, file, line, func);
	return r;
}

/* the allocated memory */
uint32_t memcheck_total(void)
{
	return total_alloc;
}

static int
codeline_cmp(const void *a, const void *b)
{
	struct mem* x = (struct mem*)a;
	struct mem* y = (struct mem*)b;
	if(strcmp(x->file, y->file) != 0)
		return strcmp(x->file, y->file);
	return x->line - y->line;
}

#include "rbtree.h"
/* check at end for bad pieces */
void memcheck_leak(void)
{
	struct mem* m;
	log_msg(LOG_INFO, "memcheck in-use at end %u", memcheck_total());
	for(m = memlist; m; m=m->next) {
		log_msg(LOG_INFO, "memcheck leak: %p %d %s:%d %s", m, m->size,
			m->file, m->line, m->func);
	}
	/* summarize per codeline */
	if(1) {
		rbtree_t x;
		rbnode_t* n;
		x.root = RBTREE_NULL;
		x.count = 0;
		x.region = NULL;
		x.cmp = codeline_cmp;
		for(m = memlist; m; m=m->next) {
			n = rbtree_search(&x, m);
			if(n) {
				struct mem* z = (struct mem*)n->key;
				z->magic += m->size; /* overwrite it */
				(&z->magic)[1] ++;
			} else {
				n = (rbnode_t*)malloc(sizeof(rbnode_t));
				if(!n) {
					log_msg(LOG_ERR, "mallocfail summary");
					return;
				}
				n->key = m;
				m->magic = m->size;
				(&m->magic)[1] = 1; /* use endmagic or abuse
					datacontents */
				rbtree_insert(&x, n);
			}
		}
		RBTREE_FOR(n, rbnode_t*, &x) {
			struct mem* z = (struct mem*)n->key;
			log_msg(LOG_INFO, "memcheck %u bytes leaked in %u "
				"blocks at %s:%d %s", z->magic, (&z->magic)[1],
				z->file, z->line, z->func);
		}
	}
}

/** get ptr to region endmagic */
static uint32_t*
regcheck_endmagic(struct region_mem* mem)
{
	return (uint32_t*)(&mem->data[mem->size]);
}

/** check magic numbers of a reg_mem */
static struct region_mem*
check_region_magic(region_type* r, void* p, size_t size,
	const char* f, int l, const char* ev)
{
	struct region_mem* m = (struct region_mem*)(p - sizeof(*m));
	/* first check the magic number */
	if(m->magic != MEMMAGIC) {
		log_msg(LOG_ERR, "%s: region %p bad start %s:%d", ev, r, f, l);
		log_msg(LOG_ERR, "for element %p, sz %d, mem %p", p, (int)size, m);
		log_msg(LOG_ERR, "from %s:%d", m->file, m->line);
		exit(1);
	}
	/* check size */
	if(m->size != size) {
		log_msg(LOG_ERR, "%s: region %p bad size %s:%d", ev, r, f, l);
		exit(1);
	}
	/* check end magic number */
	if(regcheck_endmagic(m)[0] != MEMMAGIC) {
		log_msg(LOG_ERR, "%s: region %p bad end %s:%d", ev, r, f, l);
		exit(1);
	}
	return m;
}

/** inside-region memcheck codes */
size_t
region_add_cleanup_check(region_type *region, void (*action)(void *),
	void *data, const char* file, int line)
{
	size_t ret = region_add_cleanup(region, action, data);
	/* just set that the allocated data origin is from here */
	/* but not that simple ... */
	/* set_alloc_report(data, file, line, "region_add_cleanup"); */
	if(MEMCHECK_TRACE)
		log_msg(LOG_INFO, "region_add_cleanup %p %p %s:%d",
			region, data, file, line);
	return ret;
}

#ifndef ALIGN_UP
#define ALIGN_UP(x, s)     (((x) + s - 1) & (~(s - 1)))
#endif
void *
region_alloc_check(region_type *region, size_t size, const char* file,
	int line)
{
	struct region_mem* mem;
	size_t lo = region->large_objects;
	mem = region_alloc(region, size + REGIONMEMCHECKPAD);
	if(MEMCHECK_TRACE)
		log_msg(LOG_INFO, "region %p alloc %p %d %s:%d",
			region, mem->data, (int)size, file, line);
	if(lo != region->large_objects) {
		/* large object, set the origin of the allocation */
		set_alloc_report(mem, file, line, "region_alloc");
	}
	/* memset the allocated to 0xCC, fixed but not 0 */
	memset(mem->data, 0xCC, size);
	mem->prev = NULL;
	mem->next = region->reglist;
	if(region->reglist) region->reglist->prev = mem;
	region->reglist = mem;
	mem->size = size;
	mem->pad = 0;
	mem->file = file;
	mem->line = line;
	mem->magic = MEMMAGIC;
	memmove(regcheck_endmagic(mem), &mem->magic, sizeof(mem->magic));

	if(MEMCHECK_DEBUG) {
		struct region_mem* mem, *pp = NULL;
		for(mem = region->reglist; mem; mem = mem->next) {
			log_msg(LOG_INFO, "memlist %p block %p %d prev %p next %p",
				mem, mem->data, (int)mem->size, mem->prev, mem->next);
			if(mem->prev != pp)
				log_msg(LOG_ERR, "bad prev!!");
			(void)check_region_magic(region, mem->data, mem->size,
				file, line, "alloc-listcheck");
			pp = mem;
		}
	}
	return mem->data;
}

void *
region_alloc_init_check(region_type *region, const void *init, size_t size,
	const char* file, int line)
{
	void* r = region_alloc_check(region, size, file, line);
	memcpy(r, init, size);
	return r;
}

void *
region_alloc_zero_check(region_type *region, size_t size, const char* file,
	int line)
{
	void* r = region_alloc_check(region, size, file, line);
	memset(r, 0, size);
	return r;
}

char *
region_strdup_check(region_type *region, const char *string,
	const char* file, int line)
{
	return region_alloc_init_check(region, string, strlen(string)+1,
		file, line);
}

void
region_recycle_check(region_type *region, void *block, size_t size,
	const char* file, int line)
{
	/* remove it from the object administration */
	struct region_mem* mem;
	if(!block) return;
	mem = check_region_magic(region, block, size, file, line, "recycle");
	if(MEMCHECK_TRACE)
		log_msg(LOG_INFO, "region %p recycle %p %d %s:%d mem %p",
			region, block, (int)size, file, line, mem);
	/* unlink from the object list */
	if(mem->next) mem->next->prev = mem->prev;
	if(mem->prev) mem->prev->next = mem->next;
	else region->reglist = mem->next;
	/* and wipe the contents */
	memset(mem->data, 0xEE, mem->size);
	memset(regcheck_endmagic(mem), 0xEE, sizeof(mem->magic));
	mem->prev = NULL;
	mem->next = NULL;
	mem->size = 0;
	mem->file = NULL;
	mem->line = 0;
	mem->magic = 0xEEEEEEEE;
	/* actual free */
	region_recycle(region, mem, size+REGIONMEMCHECKPAD);

	if(MEMCHECK_DEBUG) {
		struct region_mem* pp = NULL;
		for(mem = region->reglist; mem; mem = mem->next) {
			log_msg(LOG_INFO, "memlist %p block %p %d prev %p next %p",
				mem, mem->data, (int)mem->size, mem->prev, mem->next);
			if(pp != mem->prev) {
				log_msg(LOG_ERR, "bad prev!!");
				exit(1);
			}
			pp = mem;
			(void)check_region_magic(region, mem->data, mem->size,
				file, line, "recycle-listcheck");
		}
	}
}

void
region_free_all_check(region_type *region, const char* file, int line)
{
	/* check all magics for buffer trouble in the smallobject list */
	struct region_mem* mem;
	if(region->total_allocated - region->recycle_size != 0) {
		struct mem* m = check_magic(region, "region-free-all",
			file, line, "region-free-all");
		log_msg(LOG_INFO, "region-free-all of %d bytes for %p %s:%d %s at %s:%d",
			(int)(region->total_allocated- region->recycle_size),
			region, m->file, m->line, m->func, file, line);
	}
	for(mem = region->reglist; mem; mem = mem->next) {
		(void)check_region_magic(region, mem->data, mem->size,
			file, line, "free-all");
		if(!(mem->pad&0x1))
		    log_msg(LOG_INFO, "regcheck free-all-leak %d bytes %s:%d",
			mem->size, mem->file, mem->line);
	}
	region_free_all(region);
	region->reglist = NULL;
}

/* count the padded memory in the region */
static uint32_t
count_pad_ignore(region_type* region)
{
	uint32_t x = 0;
	struct region_mem* m;
	for(m=region->reglist; m; m=m->next) {
		if((m->pad&0x1)) {
			if(m->size + REGIONMEMCHECKPAD >=
				region->large_object_size)
				x+=m->size + REGIONMEMCHECKPAD;
			else 	x+=ALIGN_UP(m->size + REGIONMEMCHECKPAD, ALIGNMENT);
		}
	}
	return x;
}

void
regcheck_mark_ignore(region_type* region)
{
	struct region_mem* m;
	for(m=region->reglist; m; m=m->next) {
		m->pad |= 0x1;
		if(MEMCHECK_TRACE)
			log_msg(LOG_INFO, "regcheck ignore %d bytes %s:%d",
				m->size, m->file, m->line);
	}
}

void
region_destroy_check(region_type *region, const char* file, int line)
{
	/* all left are memory leaks */
	struct region_mem* mem;
	struct region_mem* pp = NULL;
	if(region->reglist && region->total_allocated - region->recycle_size
		- count_pad_ignore(region) != 0) {
		struct mem* m = check_magic(region, "region-destroy_check",
			file, line, "region-destroy-func");
		log_msg(LOG_INFO, "region leaks %d bytes for %p %s:%d %s at %s:%d (%d ignored)",
			(int)(region->total_allocated- region->recycle_size),
			region, m->file, m->line, m->func, file, line,
			count_pad_ignore(region));
	}
	for(mem = region->reglist; mem; mem = mem->next) {
		(void)check_region_magic(region, mem->data, mem->size,
			file, line, "destroy");
		if(pp != mem->prev) {
			log_msg(LOG_ERR, "bad prev!!");
			exit(1);
		}
		if(!(mem->pad&0x1))
			log_msg(LOG_INFO, "regcheck leak %d bytes %s:%d",
				mem->size, mem->file, mem->line);
		pp = mem;
	}
	region_destroy(region);
}

void region_recycle_str(region_type* region, const char* str)
{
	if(!str) return;
	region_recycle(region, (char*)str, strlen(str)+1);
}

void region_recycle_str_check(region_type* region, const char* str,
	const char* file, int line)
{
	if(!str) return;
	region_recycle_check(region, (char*)str, strlen(str)+1, file, line);
}

size_t regcheck_amount(region_type* region)
{
	/* do not account for recycle size, we want the churn */
	return region->total_allocated;
}

#endif /* MEMCHECK */
