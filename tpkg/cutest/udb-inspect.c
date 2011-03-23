/* udb-inspect - list the contents and inspect a udb file.
 * By W.C.A. Wijngaards
 * Copyright 2010, NLnet Labs.
 * BSD, see LICENSE.
 */

#include "config.h"
#include "udb.h"
#include "udbradtree.h"
#include "udbzone.h"
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

/* mmap and friends */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

/** verbosity for udb inspect */
static int v = 0;
/** shorthand for ease */
#ifdef ULL
#undef ULL
#endif
#define ULL (unsigned long long)

/** print usage text */
static void
usage(void)
{
	printf("usage:	udb-inspect [options] file\n");
	printf(" -h		this help\n");
	printf(" -v		increase verbosity\n");
}

/** inspect header enough to mmap it */
static uint64_t
inspect_initial(int fd)
{
	uint64_t m, sz, fsz;
	udb_glob_d g;
	ssize_t r;
	r = read(fd, &m, sizeof(m));
	if(r == -1 || r != (ssize_t)sizeof(m)) {
		printf("readfail magic: %s\n", strerror(errno));
		exit(1);
	}
	r = read(fd, &g, sizeof(g));
	if(r == -1 || r != (ssize_t)sizeof(g)) {
		printf("readfail globdata: %s\n", strerror(errno));
		exit(1);
	}
	if(m != UDB_MAGIC) {
		printf("bad magic number\n");
		exit(1);
	}
	sz = g.fsize;
	fsz = (uint64_t)lseek(fd, (off_t)0, SEEK_END);
	(void)lseek(fd, (off_t)0, SEEK_SET);
	printf("mmap size/file size:	%llu / %llu\n", ULL sz, ULL fsz);
	return sz;
}

/** printout relptr line */
static void
print_relptr(char* s, udb_rel_ptr* p)
{
	printf("%s	d=%llu p=%llu n=%llu\n",
		s, ULL p->data, ULL p->prev, ULL p->next);
}

/** inspect glob data part */
static udb_glob_d*
inspect_glob_data(void* base)
{
	udb_glob_d* g = (udb_glob_d*)(base+8);
	uint64_t magic = *(uint64_t*)base;
	printf("filetype:		0x%16.16llx (%s)\n", ULL magic,
		magic==UDB_MAGIC?"ok":"wrong");
	printf("header size:		%llu\n", ULL g->hsize);
	if(g->hsize != UDB_HEADER_SIZE)
		printf("  header size is wrong\n");
	printf("version:		%u\n", (unsigned)g->version);
	printf("clean_close:		%u\n", (unsigned)g->clean_close);
	if(g->clean_close != 0)
		printf("  file was not cleanly closed\n");
	printf("dirty_alloc:		%u\n", (unsigned)g->dirty_alloc);
	printf("padbytes:		0x%2.2x%2.2x%2.2x%2.2x%2.2x\n",
		g->pad1[0], g->pad1[1], g->pad1[2], g->pad1[3], g->pad1[4]);
	printf("file size:		%llu\n", ULL g->fsize);
	printf("rb_old:			%llu\n", ULL g->rb_old);
	printf("rb_new:			%llu\n", ULL g->rb_new);
	printf("rb_size:		%llu\n", ULL g->rb_size);
	printf("rb_seg:			%llu\n", ULL g->rb_seg);
	print_relptr("content_list:	", &g->content_list);
	print_relptr("user_global:	", &g->user_global);
	return g;
}

/** inspect alloc global part */
static udb_alloc_d*
inspect_alloc(udb_glob_d* g)
{
	int i;
	udb_alloc_d* a = (udb_alloc_d*)((void*)g + sizeof(*g));
	printf("bytes data allocated:	%llu\n", ULL a->stat_data);
	printf("bytes used for chunks:	%llu\n", ULL a->stat_alloc);
	printf("bytes free in chunks:	%llu\n", ULL a->stat_free);
	printf("  lost space:		%llu\n", ULL
		(a->stat_alloc-a->stat_data));
	printf("next chunk placement:	%llu\n", ULL a->nextgrow);
	printf("  unused space at EOF:	%llu\n", ULL g->fsize-a->nextgrow);

	if(v) {
		for(i=0; i<UDB_ALLOC_CHUNKS_MAX-UDB_ALLOC_CHUNK_MINEXP+1; i++) {
			printf("freelist[%d] (exp %d):	%llu\n",
				i, i+UDB_ALLOC_CHUNK_MINEXP, ULL a->free[i]);
		}
		printf("header size:		%llu\n",
			ULL *(uint64_t*)((void*)a+sizeof(*a)));
		printf("header endmarker exp:	%llu\n",
			ULL *(uint64_t*)((void*)a+sizeof(*a)+sizeof(uint64_t)));
	}
	return a;
}

/** inspection result total values */
struct inspect_totals {
	/** number of chunks */
	uint64_t num_chunks;
	/** count per size */
	uint64_t exp_num[UDB_ALLOC_CHUNKS_MAX];
	/** numfree per size */
	uint64_t exp_free[UDB_ALLOC_CHUNKS_MAX];
};

/** convert chunk type to string */
static const char*
chunk_type2str(enum udb_chunk_type tp)
{
	switch(tp) {
		case udb_chunk_type_free: return "free";
		case udb_chunk_type_data: return "data";
		case udb_chunk_type_index: return "index";
		case udb_chunk_type_internal: return "internal";
		case udb_chunk_type_radtree: return "radtree";
		case udb_chunk_type_radnode: return "radnode";
		case udb_chunk_type_radarray: return "radarray";
		case udb_chunk_type_zone: return "zone";
		case udb_chunk_type_domain: return "domain";
		case udb_chunk_type_rrset: return "rrset";
		case udb_chunk_type_rr: return "rr";
	}
	return "unknown";
}

/** print escaped string */
static void
print_escaped(uint8_t* s, size_t len)
{
	size_t i;
	for(i=0; i<len; i++) {
		if(isgraph((int)s[i]) && s[i] != '\\')
			printf("%c", (char)s[i]);
		else	printf("\\%03u", (unsigned int)s[i]);
	}
}

/** print domain name */
static void
print_dname(uint8_t* d, size_t len)
{
	uint8_t lablen;
	size_t i = 0;
	while(i < len) {
		lablen = d[i++];
		if(lablen == 0)
			continue;
		if(lablen+i > len) {
			printf(" malformed!");
			return;
		}
		print_escaped(&d[i], lablen);
		i += lablen;
		printf(".");
	}
}

/** print hex */
static void
print_hex(uint8_t* d, size_t len)
{
	size_t i;
	for(i=0; i<len; i++) {
		printf("%2.2x", (int)d[i]);
	}
}

/** inspect a chunk in the file */
static void*
inspect_chunk(void* base, void* cv, struct inspect_totals* t)
{
	udb_chunk_d* cp = (udb_chunk_d*)cv;
	udb_void c = (udb_void)(cv - base);
	udb_void data;
	uint8_t exp = cp->exp;
	uint8_t tp = cp->type;
	uint8_t flags = cp->flags;
	uint64_t sz = 0;
	if(exp == UDB_EXP_XL) {
		sz = ((udb_xl_chunk_d*)cp)->size;
		data = c + sizeof(udb_xl_chunk_d);
	} else {
		sz = (uint64_t)1<<exp;
		data = c + sizeof(udb_chunk_d);
	}
	if(v) {
		/* print chunk details */
		printf("chunk at %llu exp=%d type=%d (%s) flags=0x%x "
			"size=%llu\n", ULL c, exp, tp, chunk_type2str(tp),
			flags, ULL sz);
		if(tp == udb_chunk_type_free) {
			udb_free_chunk_d* fp = (udb_free_chunk_d*)cp;
			printf("prev:			%llu\n", ULL fp->prev);
			printf("next:			%llu\n", ULL fp->next);
		} else {
			printf("ptrlist:		%llu\n",
				ULL cp->ptrlist);
		}
	}
	if(v>=2 && tp != udb_chunk_type_free && cp->ptrlist) {
		/* follow the pointer list */
		udb_rel_ptr* pl = UDB_REL_PTR(cp->ptrlist);
		while(pl->next) {
			printf("relptr %llu\n", ULL UDB_SYSTOREL(base, pl));
			printf("    prev-ptrlist:	%llu\n", ULL pl->prev);
			printf("    data:		%llu\n", ULL pl->data);
			printf("    next-ptrlist:	%llu\n", ULL pl->next);
			pl = UDB_REL_PTR(pl->next);
		}
	}
	/* print data details */
	if(cp->type == udb_chunk_type_radtree) {
		struct udb_radtree_d* d = (struct udb_radtree_d*)UDB_REL(base,
			data);
		printf("	radtree count=%llu root=%llu\n",
			ULL d->count, ULL d->root.data);
	} else if(cp->type == udb_chunk_type_radnode) {
		struct udb_radnode_d* d = (struct udb_radnode_d*)UDB_REL(base,
			data);
		printf("	radnode pidx=%d offset=%d elem=%llu "
			"parent=%llu lookup=%llu\n",
			(int)d->pidx, (int)d->offset, ULL d->elem.data,
			ULL d->parent.data, ULL d->lookup.data);
	} else if(cp->type == udb_chunk_type_radarray) {
		struct udb_radarray_d* d = (struct udb_radarray_d*)UDB_REL(
			base, data);
		unsigned i;
		printf("	radarray len=%d capacity=%d str_cap=%d\n",
			(int)d->len, (int)d->capacity, (int)d->str_cap);
		for(i=0; i<d->len; i++)
			if(d->array[i].node.data) {
				printf("	[%u] node=%llu len=%d ",
					i, ULL d->array[i].node.data,
					(int)d->array[i].len);
				print_escaped(
					((uint8_t*)&d->array[d->capacity])+
					i*d->str_cap, (size_t)d->array[i].len);
				printf("\n");
			}
	} else if(cp->type == udb_chunk_type_zone) {
		struct zone_d* d = (struct zone_d*)UDB_REL(base, data);
		printf("	zone ");
		print_dname(d->name, d->namelen);
		printf(" rr_count=%llu rrset_count=%llu expired=%d "
			"node=%llu domains=%llu\n",
			ULL d->rr_count, ULL d->rrset_count, (int)d->expired,
			ULL d->node.data, ULL d->domains.data);
	} else if(cp->type == udb_chunk_type_domain) {
		struct domain_d* d = (struct domain_d*)UDB_REL(base, data);
		printf("	domain ");
		print_dname(d->name, d->namelen);
		printf(" node=%llu rrsets=%llu\n", ULL d->node.data,
			ULL d->rrsets.data);
	} else if(cp->type == udb_chunk_type_rrset) {
		struct rrset_d* d = (struct rrset_d*)UDB_REL(base, data);
		printf("	rrset type=%d next=%llu rrs=%llu\n",
			(int)d->type, ULL d->next.data, ULL d->rrs.data);
	} else if(cp->type == udb_chunk_type_rr) {
		struct rr_d* d = (struct rr_d*)UDB_REL(base, data);
		printf("	rr type=%d class=%d ttl=%u next=%llu len=%d ",
			(int)d->type, (int)d->klass, (unsigned)d->ttl,
			ULL d->next.data, (int)d->len);
		print_hex(d->wire, d->len);
		printf("\n");
	}

	/* update stats */
	t->exp_num[exp]++;
	if(tp == udb_chunk_type_free)
		t->exp_free[exp]++;
	/* check end marker */
	if(exp == UDB_EXP_XL) {
		if(sz != *(uint64_t*)(cv+sz-2*sizeof(uint64_t))) {
			printf("  end xl size is wrong:	%llu\n",
				ULL *(uint64_t*)(cv+sz-2*sizeof(uint64_t)));
		}
	}
	if(exp != *(uint8_t*)(cv+sz-1)) {
		printf("  end exp is wrong:	%d\n",  *(uint8_t*)(cv+sz-1));
	}
	return cv+sz;
}

/** walk through file and inspect contents */
static void
inspect_all_chunks(void* base, udb_glob_d* g, udb_alloc_d* a,
	struct inspect_totals* t)
{
	void* at = base + g->hsize;
	while(at < base+a->nextgrow) {
		t->num_chunks++;
		at = inspect_chunk(base, at, t);
	}
	printf("end of chunks at %llu\n", ULL (uint64_t)(at-base));
}

/** print totals */
static void
print_totals(struct inspect_totals* t)
{
	int i;
	printf("*** total num chunks:	%llu\n", ULL t->num_chunks);
	for(i=0; i<UDB_ALLOC_CHUNKS_MAX; i++) {
		if(t->exp_num[i] != 0 || t->exp_free[i] != 0)
			printf("exp %d chunks: free %llu alloc %llu "
				"total %llu\n", i, ULL t->exp_free[i],
				ULL (t->exp_num[i] - t->exp_free[i]),
				ULL t->exp_num[i]);
	}
}

/** inspect contents of mmap */
static void
inspect_contents(void* base)
{
	udb_glob_d* g;
	udb_alloc_d* a;
	struct inspect_totals t;
	memset(&t, 0, sizeof(t));
	g = inspect_glob_data(base);
	a = inspect_alloc(g);
	/* walk through file */
	inspect_all_chunks(base, g, a, &t);
	print_totals(&t);
}

/** inspect udb file */
static void
inspect_file(char* fname)
{
	int fd;
	uint64_t sz;
	void* base;
	printf("inspect file %s\n", fname);
	fd = open(fname, O_RDONLY);
	if(fd == -1) {
		printf("open %s: %s\n", fname, strerror(errno));
		exit(1);
	}
	sz = inspect_initial(fd);
	base = mmap(NULL, sz, PROT_READ, MAP_SHARED, fd, (off_t)0);
	if(base == MAP_FAILED) {
		printf("mmap %s %u: %s\n", fname, (unsigned)sz,
			strerror(errno));
		exit(1);
	}
	inspect_contents(base);
	close(fd);
}

/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/**
 * main program. Set options given commandline arguments.
 * @param argc: number of commandline arguments.
 * @param argv: array of commandline arguments.
 * @return: exit status of the program.
 */
int
main(int argc, char* argv[])
{
	int c;
	while( (c=getopt(argc, argv, "hv")) != -1) {
		switch(c) {
		case 'v':
			v++;
			break;
		default:
		case 'h':
			usage();
			return 1;
		}
	}
	argc -= optind;
	argv += optind;
	if(argc != 1) {
		usage();
		return 1;
	}
	inspect_file(argv[0]);

	return 0;
}
