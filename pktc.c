/*
 * pktc.c -- packet compiler routines.
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#include <ctype.h>
#include "pktc.h"
#include "radtree.h"
#include "util.h"
#include "namedb.h"
#include "query.h"
#include "answer.h"

#define FLAGCODE_QR 0x8000U
#define FLAGCODE_AA 0x0400U
#define FLAGCODE_TC 0x0200U
/** largest valid compression offset ; keep space for adjustment */
#define PTR_MAX_OFFSET  (0x3fff - MAXDOMAINLEN)

/** dname is a wildcard */
int dname_is_wildcard(uint8_t* dname)
{
	return dname[0] == 1 && dname[1] == '*';
}

/** some uncompressed dname functionality */
/** length (+final0) of dname */
size_t dname_length(uint8_t* dname)
{
	size_t len = 0;
	size_t labellen;
	labellen = *dname++;
	while(labellen) {
		if(labellen&0xc0)
			return 0; /* no compression ptrs allowed */
		len += labellen + 1;
		if(len >= MAXDOMAINLEN)
			return 0; /* too long */
		dname += labellen;
		labellen = *dname++;
	}
	len += 1;
	return len;
}

/** labelcount (+final0) of dname */
int dname_labs(uint8_t* dname)
{
	size_t labs = 0;
	size_t labellen;
	labellen = *dname++;
	while(labellen) {
		if(labellen&0xc0)
			return 0; /* no compression ptrs allowed */
		labs++;
		dname += labellen;
		labellen = *dname++;
	}
	labs += 1;
	return labs;
}

/** strip one label from a dname in uncompressed wire format */
uint8_t* dname_strip_label(uint8_t* dname)
{
	/* root is not stripped further */
	if(*dname == 0) return dname;
	return dname+*dname+1;
}

/** compare uncompressed, noncanonical, registers are hints for speed */
int 
dname_comp(register uint8_t* d1, register uint8_t* d2)
{
	register uint8_t lab1, lab2;
	assert(d1 && d2);
	lab1 = *d1++;
	lab2 = *d2++;
	while( lab1 != 0 || lab2 != 0 ) {
		/* compare label length */
		/* if one dname ends, it has labellength 0 */
		if(lab1 != lab2) {
			if(lab1 < lab2)
				return -1;
			return 1;
		}
		assert(lab1 == lab2 && lab1 != 0);
		/* compare lowercased labels. */
		while(lab1--) {
			/* compare bytes first for speed */
			if(*d1 != *d2 && 
				tolower((int)*d1) != tolower((int)*d2)) {
				if(tolower((int)*d1) < tolower((int)*d2))
					return -1;
				return 1;
			}
			d1++;
			d2++;
		}
		/* next pair of labels. */
		lab1 = *d1++;
		lab2 = *d2++;
	}
	return 0;
}

/** compare two wireformat names (given labelcounts) and return comparison
 * and number of matching labels in them. */
int 
dname_lab_cmp(uint8_t* d1, int labs1, uint8_t* d2, int labs2, int* mlabs)
{
	uint8_t len1, len2;
	int atlabel = labs1;
	int lastmlabs;
	int lastdiff = 0;
	/* first skip so that we compare same label. */
	if(labs1 > labs2) {
		while(atlabel > labs2) {
			len1 = *d1++;
			d1 += len1;
			atlabel--;
		}
		assert(atlabel == labs2);
	} else if(labs1 < labs2) {
		atlabel = labs2;
		while(atlabel > labs1) {
			len2 = *d2++;
			d2 += len2;
			atlabel--;
		}
		assert(atlabel == labs1);
	}
	lastmlabs = atlabel+1;
	/* now at same label in d1 and d2, atlabel */
	/* www.example.com.                  */
	/* 4   3       2  1   atlabel number */
	/* repeat until at root label (which is always the same) */
	while(atlabel > 1) {
		len1 = *d1++;
		len2 = *d2++;
		if(len1 != len2) {
			assert(len1 != 0 && len2 != 0);
			if(len1<len2)
				lastdiff = -1;
			else	lastdiff = 1;
			lastmlabs = atlabel;
			d1 += len1;
			d2 += len2;
		} else {
			/* memlowercmp is inlined here; or just like
			 * if((c=memlowercmp(d1, d2, len1)) != 0) { 
			 *	lastdiff = c;
			 *	lastmlabs = atlabel; } apart from d1++,d2++ */
			while(len1) {
				if(*d1 != *d2 && tolower((int)*d1) 
					!= tolower((int)*d2)) {
					if(tolower((int)*d1) < 
						tolower((int)*d2)) {
						lastdiff = -1;
						lastmlabs = atlabel;
						d1 += len1;
						d2 += len1;
						break;
					}
					lastdiff = 1;
					lastmlabs = atlabel;
					d1 += len1;
					d2 += len1;
					break; /* out of memlowercmp */
				}
				d1++;
				d2++;
				len1--;
			}
		}
		atlabel--;
	}
	/* last difference atlabel number, so number of labels matching,
	 * at the right side, is one less. */
	*mlabs = lastmlabs-1;
	if(lastdiff == 0) {
		/* all labels compared were equal, check if one has more
		 * labels, so that example.com. > com. */
		if(labs1 > labs2)
			return 1;
		else if(labs1 < labs2)
			return -1;
	}
	return lastdiff;
}

char* dname2str(uint8_t* dname)
{
	static char buf[MAXDOMAINLEN*5+3];
	char* p = buf;
	uint8_t lablen;
	if(*dname == 0) {
		strlcpy(buf, ".", sizeof(buf));
		return buf;
	}
	lablen = *dname++;
	while(lablen) {
		while(lablen--) {
			uint8_t ch = *dname++;
			if (isalnum(ch) || ch == '-' || ch == '_') {
				*p++ = ch;
			} else if (ch == '.' || ch == '\\') {
				*p++ = '\\';
				*p++ = ch;
			} else {
				snprintf(p, 5, "\\%03u", (unsigned int)ch);
				p += 4;
			}
		}
		lablen = *dname++;
		*p++ = '.';
	}
	*p++ = 0;
	return buf;
}

size_t pkt_dname_len_at(buffer_type* pkt, size_t pos)
{
	size_t len = 0;
	int ptrcount = 0;
	uint8_t labellen;

	/* read dname and determine length */
	/* check compression pointers, loops, out of bounds */
	while(1) {
		/* read next label */
		if(buffer_limit(pkt) < pos+1)
			return 0;
		labellen = buffer_read_u8_at(pkt, pos++);
		if(LABEL_IS_PTR(labellen)) {
			/* compression ptr */
			uint16_t ptr;
			if(buffer_limit(pkt) < pos+1)
				return 0;
			ptr = PTR_OFFSET(labellen, buffer_read_u8_at(pkt,
				pos++));
			if(ptrcount++ > MAX_COMPRESS_PTRS)
				return 0; /* loop! */
			if(buffer_limit(pkt) <= ptr)
				return 0; /* out of bounds! */
			pos = ptr;
		} else {
			/* label contents */
			if(labellen > 0x3f)
				return 0; /* label too long */
			len += 1 + labellen;
			if(len > MAXDOMAINLEN)
				return 0;
			if(labellen == 0) {
				/* end of dname */
				break;
			}
			if(buffer_limit(pkt) < pos+labellen)
				return 0;
			pos += labellen;
		}
	}
	return len;
}

static int
dname_buffer_write(buffer_type* pkt, uint8_t* dname)
{
	uint8_t lablen;

	if(buffer_remaining(pkt) < 1)
		return 0;
	lablen = *dname++;
	buffer_write_u8(pkt, lablen);
	while(lablen) {
		if(buffer_remaining(pkt) < (size_t)lablen+1)
			return 0;
		buffer_write(pkt, dname, lablen);
		dname += lablen;
		lablen = *dname++;
		buffer_write_u8(pkt, lablen);
	}
	return 1;
}

/** like strdup but for memory regions */
uint8_t* memdup(void* data, size_t len)
{
	void* r = xalloc(len);
	memcpy(r, data, len);
	return r;
}

struct comptree* comptree_create(void)
{
	struct comptree* ct = (struct comptree*)xalloc(sizeof(*ct));
	ct->nametree = radix_tree_create();
	ct->zonetree = radix_tree_create();
	return ct;
}

void comptree_delete(struct comptree* ct)
{
	struct radnode* n;
	if(!ct) return;
	/* delete the elements in the trees (no tree operations) */
	for(n = radix_first(ct->nametree); n; n=radix_next(n))
		compname_delete((struct compname*)n->elem);
	for(n = radix_first(ct->zonetree); n; n=radix_next(n))
		compzone_delete((struct compzone*)n->elem);
	/* postorder delete of the trees themselves */
	radix_tree_delete(ct->nametree);
	radix_tree_delete(ct->zonetree);
	free(ct);
}

struct compzone* compzone_create(struct comptree* ct, uint8_t* zname)
{
	struct compzone* cz = (struct compzone*)xalloc(sizeof(*cz));
	size_t zlen = dname_length(zname);
	cz->name = memdup(zname, zlen);
	cz->namelen = zlen;
	cz->nsec3tree = NULL; /* empty for now, may not be NSEC3-zone */
	/* todo nsec3parms empty */
	cz->serial = 0;
	
	/* add into tree */
	cz->rnode = radname_insert(ct->zonetree, zname, zlen, cz);
	assert(cz->rnode);

	return cz;
}

void compzone_delete(struct compzone* cz)
{
	if(!cz) return;
	free(cz->name);
	cpkt_delete(cz->nx);
	cpkt_delete(cz->nodata);
	if(cz->nsec3tree) {
		struct radnode* n;
		for(n = radix_first(cz->nsec3tree); n; n = radix_next(n))
			compnsec3_delete((struct compnsec3*)n->elem);
		radix_tree_delete(cz->nsec3tree);
	}
	free(cz);
}

struct compzone* compzone_search(struct comptree* ct, uint8_t* name)
{
	struct radnode* n = radname_search(ct->zonetree, name,
		dname_length(name));
	if(n) return (struct compzone*)n->elem;
	return NULL;
}

struct compzone* compzone_find(struct comptree* ct, uint8_t* name, int* ce)
{
	/* simply walk the zones */
	struct radnode* n = radname_search(ct->zonetree, name,
		dname_length(name));
	if(n) {
		*ce = 0;
		return (struct compzone*)n->elem;
	}
	do {
		name = dname_strip_label(name);
		n = radname_search(ct->zonetree, name, dname_length(name));
		if(n) {
			*ce = 1;
			return (struct compzone*)n->elem;
		}
	} while(*name);
	return NULL;
}

struct compname* compname_create(struct comptree* ct, uint8_t* name,
	struct compzone* cz)
{
	struct compname* cn = (struct compname*)xalloc(sizeof(*cn));
	memset(cn, 0, sizeof(*cn));
	cn->namelen = dname_length(name);
	cn->name = memdup(name, cn->namelen);
	cn->cz = cz;

	/* add into tree */
	cn->rnode = radname_insert(ct->nametree, name, cn->namelen, cn);
	assert(cn->rnode);

	return cn;
}

/** clear a compname */
void compname_clear_pkts(struct compname* cn)
{
	size_t i;
	if(!cn) return;
	for(i=0; i<cn->typelen; i++)
		cpkt_delete(cn->types[i]);
	free(cn->types);
	cn->types = NULL;
	cn->typelen = 0;
	for(i=0; i<cn->typelen_nondo; i++)
		cpkt_delete(cn->types_nondo[i]);
	free(cn->types_nondo);
	cn->types_nondo = NULL;
	cn->typelen_nondo = 0;
	cpkt_delete(cn->notype);
	cpkt_delete(cn->notype_nondo);
	cpkt_delete(cn->side);
	cn->notype = NULL;
	cn->notype_nondo = NULL;
	cn->side = NULL;
	if(cn->belowtype == BELOW_NORMAL || cn->belowtype == BELOW_SYNTHC)
		cpkt_delete(cn->below);
	if(cn->belowtype == BELOW_NORMAL || cn->belowtype == BELOW_SYNTHC)
		cpkt_delete(cn->below_nondo);
	/* else, it is only a reference */
	cn->below = NULL;
	cn->below_nondo = NULL;
}

void compname_delete(struct compname* cn)
{
	if(!cn) return;
	free(cn->name);
	compname_clear_pkts(cn);
	free(cn);
}

struct compname* compname_search(struct comptree* ct, uint8_t* name)
{
	struct radnode* n = radname_search(ct->nametree, name,
		dname_length(name));
	if(n) return (struct compname*)n->elem;
	return NULL;
}

void compnsec3_delete(struct compnsec3* c3)
{
	if(!c3) return;
	cpkt_delete(c3->nx);
	free(c3);
}

/**
 * Data structure to help domain name compression in outgoing messages.
 * A tree of dnames and their offsets in the packet is kept.
 * It is kept sorted, not canonical, but by label at least, so that after
 * a lookup of a name you know its closest match, and the parent from that
 * closest match. These are possible compression targets.
 *
 * It is a binary tree, not a rbtree or balanced tree, as the effort
 * of keeping it balanced probably outweighs usefulness (given typical
 * DNS packet size).
 */
struct compress_tree_node {
	/** left node in tree, all smaller to this */
	struct compress_tree_node* left;
	/** right node in tree, all larger than this */
	struct compress_tree_node* right;

	/** the parent node - not for tree, but zone parent. One less label */
	struct compress_tree_node* parent;
	/** the domain name for this node. Pointer to uncompressed memory. */
	uint8_t* dname;
	/** number of labels in domain name, kept to help compare func. */
	int labs;
	/** offset in packet that points to this dname */
	size_t offset;
};

/**
 * Find domain name in tree, returns exact and closest match.
 * @param tree: root of tree.
 * @param dname: pointer to uncompressed dname.
 * @param labs: number of labels in domain name.
 * @param match: closest or exact match.
 *	guaranteed to be smaller or equal to the sought dname.
 *	can be null if the tree is empty.
 * @param matchlabels: number of labels that match with closest match.
 *	can be zero is there is no match.
 * @param insertpt: insert location for dname, if not found.
 * @return: 0 if no exact match.
 */
static int
compress_tree_search(struct compress_tree_node** tree, uint8_t* dname,
	int labs, struct compress_tree_node** match, int* matchlabels,
	struct compress_tree_node*** insertpt)
{
	int c, n, closen=0;
	struct compress_tree_node* p = *tree;
	struct compress_tree_node* close = 0;
	struct compress_tree_node** prev = tree;
	while(p) {
		if((c = dname_lab_cmp(dname, labs, p->dname, p->labs, &n)) 
			== 0) {
			*matchlabels = n;
			*match = p;
			return 1;
		}
		if(c<0) {
			prev = &p->left;
			p = p->left;
		} else	{
			closen = n;
			close = p; /* p->dname is smaller than dname */
			prev = &p->right;
			p = p->right;
		}
	}
	*insertpt = prev;
	*matchlabels = closen;
	*match = close;
	return 0;
}

/**
 * Lookup a domain name in compression tree.
 * @param tree: root of tree (not the node with '.').
 * @param dname: pointer to uncompressed dname.
 * @param labs: number of labels in domain name.
 * @param insertpt: insert location for dname, if not found.
 * @return: 0 if not found or compress treenode with best compression.
 */
static struct compress_tree_node*
compress_tree_lookup(struct compress_tree_node** tree, uint8_t* dname,
	int labs, struct compress_tree_node*** insertpt)
{
	struct compress_tree_node* p;
	int m;
	if(labs <= 1)
		return 0; /* do not compress root node */
	if(compress_tree_search(tree, dname, labs, &p, &m, insertpt)) {
		/* exact match */
		return p;
	}
	/* return some ancestor of p that compresses well. */
	if(m>1) {
		/* www.example.com. (labs=4) matched foo.example.com.(labs=4)
		 * then matchcount = 3. need to go up. */
		while(p && p->labs > m)
			p = p->parent;
		return p;
	}
	return 0;
}

/**
 * Create node for domain name compression tree.
 * @param dname: pointer to uncompressed dname (stored in tree).
 * @param labs: number of labels in dname.
 * @param offset: offset into packet for dname.
 * @param region: how to allocate memory for new node.
 * @return new node or 0 on malloc failure.
 */
static struct compress_tree_node*
compress_tree_newnode(uint8_t* dname, int labs, size_t offset, 
	struct region* region)
{
	struct compress_tree_node* n = (struct compress_tree_node*)
		region_alloc(region, sizeof(struct compress_tree_node));
	if(!n) return 0;
	n->left = 0;
	n->right = 0;
	n->parent = 0;
	n->dname = dname;
	n->labs = labs;
	n->offset = offset;
	return n;
}

/**
 * Store domain name and ancestors into compression tree.
 * @param dname: pointer to uncompressed dname (stored in tree).
 * @param labs: number of labels in dname.
 * @param offset: offset into packet for dname.
 * @param region: how to allocate memory for new node.
 * @param closest: match from previous lookup, used to compress dname.
 *	may be NULL if no previous match.
 *	if the tree has an ancestor of dname already, this must be it.
 * @param insertpt: where to insert the dname in tree. 
 * @return: 0 on memory error.
 */
static int
compress_tree_store(uint8_t* dname, int labs, size_t offset, 
	struct region* region, struct compress_tree_node* closest, 
	struct compress_tree_node** insertpt)
{
	uint8_t lablen;
	struct compress_tree_node* newnode;
	struct compress_tree_node* prevnode = NULL;
	int uplabs = labs-1; /* does not store root in tree */
	if(closest) uplabs = labs - closest->labs;
	assert(uplabs >= 0);
	/* algorithms builds up a vine of dname-labels to hang into tree */
	while(uplabs--) {
		if(offset > PTR_MAX_OFFSET) {
			/* insertion failed, drop vine */
			return 1; /* compression pointer no longer useful */
		}
		if(!(newnode = compress_tree_newnode(dname, labs, offset, 
			region))) {
			/* insertion failed, drop vine */
			return 0;
		}

		if(prevnode) {
			/* chain nodes together, last one has one label more,
			 * so is larger than newnode, thus goes right. */
			newnode->right = prevnode;
			prevnode->parent = newnode;
		}

		/* next label */
		lablen = *dname++;
		dname += lablen;
		offset += lablen+1;
		prevnode = newnode;
		labs--;
	}
	/* if we have a vine, hang the vine into the tree */
	if(prevnode) {
		*insertpt = prevnode;
		prevnode->parent = closest;
	}
	return 1;
}

/** compress a domain name */
static int
write_compressed_dname(buffer_type* pkt, uint8_t* dname, int labs,
	struct compress_tree_node* p, uint16_t* ptrs, int* numptrs)
{
	/* compress it */
	int labcopy = labs - p->labs;
	uint8_t lablen;
	uint16_t ptr;

	if(labs == 1) {
		/* write root label */
		if(buffer_remaining(pkt) < 1)
			return 0;
		buffer_write_u8(pkt, 0);
		return 1;
	}

	/* copy the first couple of labels */
	while(labcopy--) {
		lablen = *dname++;
		if(buffer_remaining(pkt) < (size_t)lablen+1)
			return 0;
		buffer_write_u8(pkt, lablen);
		buffer_write(pkt, dname, lablen);
		dname += lablen;
	}
	/* insert compression ptr */
	if(buffer_remaining(pkt) < 2)
		return 0;
	if(*numptrs == -1) {
		/* no adjusting, write the pointer */
		ptr = PTR_CREATE(p->offset);
		buffer_write_u16(pkt, ptr);
	} else {
		/* for adjusting, write the offset */
		ptrs[*numptrs] = buffer_position(pkt);
		buffer_write_u16(pkt, p->offset);
		(*numptrs)++;
	}
	return 1;
}

/** compress any domain name to the packet, return false if TC */
static int
compress_any_dname(uint8_t* dname, buffer_type* pkt, int labs, 
	struct region* region, struct compress_tree_node** tree,
	uint16_t* ptrs, int* numptrs)
{
	struct compress_tree_node* p;
	struct compress_tree_node** insertpt = NULL;
	size_t pos = buffer_position(pkt);
	if((p = compress_tree_lookup(tree, dname, labs, &insertpt))) {
		if(!write_compressed_dname(pkt, dname, labs, p, ptrs, numptrs))
			return 0;
	} else {
		if(!dname_buffer_write(pkt, dname))
			return 0;
	}
	(void)compress_tree_store(dname, labs, pos, region, p, insertpt);
	return 1;
}

/** write and compress an RR, false on TC */
static int
write_and_compress_rdata(rr_type* rr, buffer_type* p, region_type* region,
	struct compress_tree_node** tree, uint16_t* ptrs, int* numptrs,
	uint16_t* soaserial)
{
	size_t lenpos = buffer_position(p);
	uint16_t j;
	uint8_t* dname;
	if(buffer_remaining(p) < 2)
		return 0;
	buffer_write_u16(p, 0);
	/* write the rdata elements or compress them */
	for (j = 0; j < rr->rdata_count; ++j) {
		switch (rdata_atom_wireformat_type(rr->type, j)) {
		case RDATA_WF_COMPRESSED_DNAME:
			dname = (uint8_t*)dname_name(domain_dname(
				rdata_atom_domain(rr->rdatas[j])));
			if(!compress_any_dname(dname, p, dname_labs(dname),
				region, tree, ptrs, numptrs))
				return 0;
			break;
		case RDATA_WF_UNCOMPRESSED_DNAME:
			dname = (uint8_t*)dname_name(domain_dname(
				rdata_atom_domain(rr->rdatas[j])));
			if(buffer_remaining(p) < dname_length(dname))
				return 0;
			buffer_write(p, dname, dname_length(dname));
			break;
		default:
			/* soa serial number, first fixedlen data after the
			 * domain names */
			if(rr->type == TYPE_SOA && *soaserial == 0)
				*soaserial = buffer_position(p);
			if(buffer_remaining(p) < rdata_atom_size(rr->rdatas[j]))
				return 0;
			buffer_write(p, rdata_atom_data(rr->rdatas[j]),
				rdata_atom_size(rr->rdatas[j]));
			break;
		}
	}

	/* overwrite the length with correct value */
	buffer_write_u16_at(p, lenpos, (uint16_t)(buffer_position(p)-lenpos-2));
	return 1;
}

/** write and compress an RR, false on TC */
static int
write_and_compress_rr(uint8_t* dname, rr_type* rr, buffer_type* p,
	region_type* region, struct compress_tree_node** tree,
	uint16_t* ptrs, int* numptrs, uint16_t* soaserial, int wildcard)
{
	/* add name and compress */
	if(wildcard && dname_is_wildcard(dname)) {
		/* write compression ptr to the final qname, not in the
		 * adjustment list so it will point to the expanded qname */
		if(buffer_remaining(p) < 2)
			return 0;
		buffer_write_u16(p, PTR_CREATE(QHEADERSZ));
	} else {
		if(!compress_any_dname(dname, p, dname_labs(dname), region,
			tree, ptrs, numptrs))
			return 0;
	}
	/* add type, class, ttl */
	if(buffer_remaining(p) < 8)
		return 0;
	buffer_write_u16(p, rr->type);
	buffer_write_u16(p, rr->klass);
	buffer_write_u32(p, rr->ttl);
	/* write and compress rdata */
	if(!write_and_compress_rdata(rr, p, region, tree, ptrs, numptrs,
		soaserial))
		return 0;
	return 1;
}

struct cpkt* compile_packet(uint8_t* qname, uint16_t qtype, int adjust,
	int wildcard, uint16_t flagcode, uint16_t num_an, uint16_t num_ns,
	uint16_t num_ar, uint8_t** rrname, struct rr** rrinfo,
	struct compzone* cz)
{
	struct cpkt c; /* temporary structure */
	struct cpkt* cp = NULL;
	region_type* region = region_create(xalloc, free);
	buffer_type* p = buffer_create(region, QIOBUFSZ);
	uint16_t truncpts[MAXRRSPP*2];
	size_t numtrunc = 0;
	uint16_t ptrs[MAXRRSPP];
	int numptrs = 0;
	int i;
	size_t j;
	uint16_t arcount = 0;
	struct compress_tree_node* tree = NULL;
	uint16_t soaserial = 0;

	if((size_t)num_an+(size_t)num_ns+(size_t)num_ar >= (size_t)MAXRRSPP) {
		/* too large */
		if((size_t)num_an + (size_t)num_ns >= (size_t)MAXRRSPP)
			return NULL;
		num_ar = 0; /* drop the additional section to make it work */
	}

	/* compile */
	if(wildcard && dname_is_wildcard(qname)) {
		/* adjust towards the wildcard without the '*' */
		qname = dname_strip_label(qname);
		adjust = 1;
	}
	if(adjust == 0)
		numptrs = -1;
	memset(&c, 0, sizeof(c));
	c.qtype = qtype;
	c.qnamelen = dname_length(qname);
	c.flagcode = flagcode;
	c.ancount = num_an;
	c.nscount = num_ns;

	/* insert qname at position. */
	buffer_clear(p);
	buffer_set_limit(p, MAX_PACKET_SIZE);
	if(buffer_remaining(p) < QHEADERSZ)
		goto tc_and_done;
	buffer_skip(p, QHEADERSZ);
	if(!compress_any_dname(qname, p, dname_labs(qname), region, &tree,
		ptrs, &numptrs))
		goto tc_and_done;
	/* skip virtual qname, and type and class of qname */
	if(buffer_remaining(p) < 4)
		goto tc_and_done;
	buffer_write_u16(p, qtype);
	buffer_write_u16(p, CLASS_IN);

	/* add answer and authority rrs. */
	for(i=0; i<num_an+num_ns; i++) {
		int dowc = (wildcard && i < num_an);
		if(!write_and_compress_rr(rrname[i], rrinfo[i], p, region,
			&tree, ptrs, &numptrs, &soaserial, dowc))
			goto tc_and_done;
	}

	/* add additional rrs and make truncation points between rrsets */
	/* keep track of the truncation point */
	for(i=num_an+num_ns; i<num_an+num_ns+num_ar; i++) {
		/* add a truncation point? this is the additional section,
		 * so startofadditional, typeRRSIG, different type or name */
		if(i == num_an+num_ns ||
			rrinfo[i]->type == TYPE_RRSIG ||
			rrinfo[i]->type != rrinfo[i-1]->type ||
			dname_comp(rrname[i], rrname[i-1]) != 0) {
			truncpts[numtrunc+1] = buffer_position(p);
			truncpts[numtrunc] = arcount;
			numtrunc+=2;
		}
		if(!write_and_compress_rr(rrname[i], rrinfo[i], p, region,
			&tree, ptrs, &numptrs, &soaserial, 0))
			goto normal_done;
		arcount++;
	}
	assert(arcount == num_ar);

	goto normal_done;
tc_and_done:
	c.flagcode |= FLAGCODE_TC;
normal_done:
	if(numtrunc == 0 || truncpts[numtrunc-1] != arcount) {
		truncpts[numtrunc+1] = buffer_position(p);
		truncpts[numtrunc] = arcount;
		numtrunc+=2;
	}
	if(soaserial) {
		c.serial = &cz->serial;
		c.serial_pos = soaserial;
	}
	/* reverse the truncation list */
	for(j=0; j<numtrunc/2; j++) {
		arcount = truncpts[j];
		truncpts[j] = truncpts[numtrunc-j-1];
		truncpts[numtrunc-j-1] = arcount;
	}

	/* allocate */
	if(numptrs == -1) {
		ptrs[0] = 0;
		numptrs = 1;
	} else	{
		ptrs[numptrs] = 0;
		numptrs += 1;
	}
	c.datalen = buffer_position(p)-QHEADERSZ-c.qnamelen-4;
	cp = (struct cpkt*)xalloc(sizeof(*cp) + c.datalen +
		sizeof(uint16_t)*numtrunc + sizeof(uint16_t)*numptrs);
	memmove(cp, &c, sizeof(*cp));
	cp->truncpts = (((void*)cp)+sizeof(*cp));
	cp->ptrs = (((void*)cp->truncpts)+sizeof(uint16_t)*numtrunc);
	cp->data = (((void*)cp->ptrs)+sizeof(uint16_t)*numptrs);

	cp->numtrunc = numtrunc;
	memmove(cp->truncpts, truncpts, sizeof(uint16_t)*numtrunc);
	memmove(cp->ptrs, ptrs, sizeof(uint16_t)*numptrs);
	memmove(cp->data, buffer_at(p, QHEADERSZ+c.qnamelen+4), c.datalen);

	/*
	printf("got packet:\n");
	FLAGS_SET(p, cp->flagcode);
	QDCOUNT_SET(p, 1);
	ANCOUNT_SET(p, num_an);
	NSCOUNT_SET(p, num_ns);
	ARCOUNT_SET(p, num_ar);
	buffer_flip(p);
	for(i=0; i<numptrs; i++)
		buffer_write_u16_at(p, ptrs[i], 
			PTR_CREATE(buffer_read_u16_at(p, ptrs[i])));
	debug_hex("packet", buffer_begin(p), buffer_remaining(p));
	print_buffer(p);
	*/

	region_destroy(region);
	return cp;
}

/** add rrset to arrays */
static void
enqueue_rr(domain_type* domain, rr_type* rr,
	uint8_t** rrname, struct rr** rrinfo, size_t* rrnum)
{
	rrname[*rrnum] = (uint8_t*)dname_name(domain_dname(domain));
	rrinfo[*rrnum] = rr;
	(*rrnum)++;
}

/** add rrset to arrays */
static uint16_t
enqueue_rrset(domain_type* domain, rrset_type* rrset,
	uint8_t** rrname, struct rr** rrinfo, size_t* rrnum,
	struct zone* zone, int withdo)
{
	size_t i;
	uint16_t added = 0;
	for (i = 0; i < rrset->rr_count; ++i) {
		enqueue_rr(domain, &rrset->rrs[i], rrname, rrinfo, rrnum);
		added++;
	}
	if(withdo && rrset_rrtype(rrset) != TYPE_RRSIG) {
		rrset_type* rrsig=domain_find_rrset(domain, zone, TYPE_RRSIG);
		if(rrsig) {
			for (i = 0; i < rrsig->rr_count; ++i) {
				if (rr_rrsig_type_covered(&rrsig->rrs[i])
				    == rrset_rrtype(rrset))
				{
					enqueue_rr(domain, &rrsig->rrs[i],
						rrname, rrinfo, rrnum);
					added++;
				}
			}
		}
	}
	return added;
}

/** compile answer info packet */
static struct cpkt* compile_answer_packet(struct answer_info* ai,
	struct zone* zone, struct compzone* cz)
{
	uint16_t counts[RR_SECTION_COUNT];
	rr_section_type section;
	size_t i;
	uint16_t ancount, nscount, arcount;
	uint8_t* rrname[MAXRRSPP];
	rr_type* rrinfo[MAXRRSPP];
	size_t rrnum = 0;

	for (section = ANSWER_SECTION; section < RR_SECTION_COUNT; ++section) {
		counts[section] = 0;
	}
	for (section = ANSWER_SECTION; section < RR_SECTION_COUNT; ++section) {
		for (i = 0; i < ai->answer.rrset_count; ++i) {
			if (ai->answer.section[i] == section) {
				counts[section] += enqueue_rrset(
					ai->answer.domains[i],
					ai->answer.rrsets[i], 
					rrname, rrinfo, &rrnum, zone,
					ai->withdo);
			}
		}
	}
	ancount = counts[ANSWER_SECTION];
	nscount = counts[AUTHORITY_SECTION];
	arcount = counts[ADDITIONAL_A_SECTION]
		+ counts[ADDITIONAL_AAAA_SECTION]
		+ counts[ADDITIONAL_OTHER_SECTION];
	return compile_packet(ai->qname, ai->qtype, ai->adjust, ai->wildcard,
		ai->flagcode, ancount, nscount, arcount, rrname, rrinfo, cz);
}

/** init answer info */
static void answer_info_init(struct answer_info* ai, uint8_t* qname)
{
	ai->qname = qname;
	ai->qtype = 0;
	ai->adjust = 0;
	ai->wildcard = 0;
	ai->flagcode = FLAGCODE_QR; /* set QR flag, NOERROR */
	answer_init(&ai->answer);
	region_free_all(ai->region);
}

/** add additional rrsets to the result based on type and list */
static void ai_additional(struct answer_info* ai, rrset_type* master_rrset,
	size_t rdata_index, int allow_glue, struct additional_rr_types types[],
	struct zone* zone)
{
	size_t i;
	for (i = 0; i < master_rrset->rr_count; ++i) {
		int j;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i].rdatas[rdata_index]);
		domain_type *match = additional;
		assert(additional);
		if (!allow_glue && domain_is_glue(match, zone))
			continue;
		/*
		 * Check to see if we need to generate the dependent
		 * based on a wildcard domain.
		 */
		while (!match->is_existing) {
			match = match->parent;
		}
		if (additional != match && domain_wildcard_child(match)) {
			domain_type *wildcard_child =
				domain_wildcard_child(match);
			domain_type *temp = (domain_type *) region_alloc(
				ai->region, sizeof(domain_type));		
#ifdef USE_RADIX_TREE
			temp->rnode = NULL;
			temp->dname = additional->dname;
#else
			memcpy(&temp->node, &additional->node, sizeof(rbnode_t));
#endif
			temp->number = additional->number;
			temp->parent = match;
			temp->wildcard_child_closest_match = temp;
			temp->rrsets = wildcard_child->rrsets;
			temp->is_existing = wildcard_child->is_existing;
			additional = temp;
		}
		for (j = 0; types[j].rr_type != 0; ++j) {
			rrset_type *rrset = domain_find_rrset(
				additional, zone, types[j].rr_type);
			if(rrset)
				answer_add_rrset(&ai->answer,
					types[j].rr_section, additional, rrset);
		}
	}
}

/** answer info add rrset, possibly additionals */
static void ai_add_rrset(struct answer_info* ai, rr_section_type section,
	domain_type *owner, rrset_type *rrset, struct zone* zone)
{
	if(!rrset)
		return;
	answer_add_rrset(&ai->answer, section, owner, rrset);
	switch(rrset_rrtype(rrset)) {
	case TYPE_NS:
		ai_additional(ai, rrset, 0, 1, default_additional_rr_types,
			zone);
		break;
	case TYPE_MB:
		ai_additional(ai, rrset, 0, 0, default_additional_rr_types,
			zone);
		break;
	case TYPE_MX:
	case TYPE_KX:
		ai_additional(ai, rrset, 1, 0, default_additional_rr_types,
			zone);
		break;
	case TYPE_RT:
		ai_additional(ai, rrset, 1, 0, rt_additional_rr_types,
			zone);
		break;
	default:
		break;
	}
}

/** perform type NS authority section processing */
static void process_type_NS(struct answer_info* ai, struct zone* zone)
{
	/* no NS-rrset and glue for type DNSKEY and DS */
	if(zone->ns_rrset && ai->qtype != TYPE_DNSKEY && ai->qtype != TYPE_DS)
		ai_add_rrset(ai, AUTHORITY_SECTION, zone->apex, zone->ns_rrset,
			zone);
}

/** compile delegation */
static struct cpkt* compile_delegation_answer(uint8_t* dname,
	struct domain* domain, struct zone* zone, struct compzone* cz,
	struct region* region, int adjust, int withdo)
{
	rrset_type* rrset;
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = adjust;
	ai.withdo = withdo;
	rrset = domain_find_rrset(domain, zone, TYPE_NS);
	assert(rrset);
	ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	if(!withdo) {
		/* do nothing */
	} else if((rrset = domain_find_rrset(domain, zone, TYPE_DS))) {
		ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	} else if(cz->nsec3tree) {
		/* TODO nsec3_add_ds_proof(&ai, domain, 1); */
	} else if((rrset = domain_find_rrset(domain, zone, TYPE_NSEC))) {
		ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset, zone);
	}
	printf("delegation:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile DS answer */
static struct cpkt* compile_DS_answer(uint8_t* dname, struct domain* domain,
	struct zone* zone, struct compzone* cz, struct region* region,
	int withdo)
{
	rrset_type* rrset;
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = 0;
	ai.withdo = withdo;
	ai.qtype = TYPE_DS;
	ai.flagcode |= FLAGCODE_AA;
	if((rrset = domain_find_rrset(domain, zone, TYPE_DS))) {
		ai_add_rrset(&ai, ANSWER_SECTION, domain, rrset, zone);
	} else {
		ai_add_rrset(&ai, AUTHORITY_SECTION, zone->apex,
			zone->soa_nx_rrset, zone);
		if(withdo) {
			if(cz->nsec3tree) {
				/* TODO nsec3_add_ds_proof(&ai, domain, 1); */
			} else if((rrset = domain_find_rrset(domain, zone, TYPE_NSEC))) {
				ai_add_rrset(&ai, AUTHORITY_SECTION, zone->apex,
					zone->soa_nx_rrset, zone);
				ai_add_rrset(&ai, AUTHORITY_SECTION, domain, rrset,
					zone);
			}
		}
	}
	process_type_NS(&ai, zone);
	printf("DSanswer:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile positive answer for an rrset */
static struct cpkt* compile_pos_answer(uint8_t* dname, struct domain* domain,
	struct zone* zone, struct compzone* cz, rrset_type* rrset,
	struct region* region, int withdo, int wildcard)
{
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = 0;
	ai.wildcard = wildcard;
	ai.withdo = withdo;
	ai.qtype = rrset_rrtype(rrset);
	ai.flagcode |= FLAGCODE_AA;
	ai_add_rrset(&ai, ANSWER_SECTION, domain, rrset, zone);
	process_type_NS(&ai, zone);
	printf("posanswer:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile answer for qtype ANY */
static struct cpkt* compile_any_answer(uint8_t* dname, struct domain* domain,
	struct zone* zone, struct compzone* cz, struct region* region,
	int withdo, int wildcard)
{
	rrset_type* rrset;
	struct answer_info ai;
	int added = 0;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = 0;
	ai.wildcard = wildcard;
	ai.withdo = withdo;
	ai.qtype = TYPE_ANY;
	ai.flagcode |= FLAGCODE_AA;
	for(rrset = domain_find_any_rrset(domain, zone); rrset; rrset = rrset->next) {
		if (rrset->zone == zone
#ifdef NSEC3
			&& rrset_rrtype(rrset) != TYPE_NSEC3
#endif
			/* RRSIGs added automatically if withdo,
			 * but if not, they are added as 'ANY' */
			&& (rrset_rrtype(rrset) != TYPE_RRSIG || !withdo))
		{
			ai_add_rrset(&ai, ANSWER_SECTION, domain, rrset, zone);
			++added;
		}
	}
	if(added == 0)
		return NULL;
	process_type_NS(&ai, zone);
	printf("anyanswer:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile answer for nodata for the qtype */
static struct cpkt* compile_nodata_answer(uint8_t* dname,
	struct domain* domain, struct zone* zone, struct compzone* cz,
	struct region* region, int adjust, int withdo)
{
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = adjust;
	ai.withdo = withdo;
	ai.flagcode |= FLAGCODE_AA;

	/* if no CNAMEs have been followed yet */
	/* TODO */
	ai_add_rrset(&ai, AUTHORITY_SECTION, zone->apex, zone->soa_nx_rrset,
		zone);

#ifdef NSEC3
	/* TODO: if(cz->nsec3tree) nsec3_answer_nodata 
	 * else*/
#endif
	if(withdo) { /* do NSECs (if present) (do work for tempdomain, ENTs) */
		domain_type *nsec_domain;
		rrset_type *nsec_rrset;
		nsec_domain = find_covering_nsec_ext(domain, zone, &nsec_rrset);
		if(nsec_domain) {
			ai_add_rrset(&ai, AUTHORITY_SECTION, nsec_domain,
				nsec_rrset, zone);
		}
	}
	printf("nodata:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile answer for nxdomain for the name */
static struct cpkt* compile_nxdomain_answer(struct domain* domain,
	struct zone* zone, struct compzone* cz, struct region* region,
	int withdo)
{
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, NULL);
	ai.adjust = 1;
	ai.withdo = withdo;
	ai.flagcode |= FLAGCODE_AA;
	ai.flagcode |= RCODE_NXDOMAIN;

	/* if CNAME followed, not NXDOMAIN, no SOA(soa added last).  TODO */

#ifdef NSEC3
	/* TODO: if(cz->nsec3tree) nsec3_answer_nxdomain 
	 * not really useful 
	 * else*/
#endif
	if(withdo) { /* do NSECs */
		domain_type *nsec_domain;
		rrset_type *nsec_rrset;
		/* denial NSEC */
		nsec_domain = find_covering_nsec_ext(domain, zone,
			&nsec_rrset);
		if(nsec_rrset) {
			ai_add_rrset(&ai, AUTHORITY_SECTION, nsec_domain,
				nsec_rrset, zone);
			/* we know that all query names are going to fall
			 * under this name */
			ai.qname = dname_strip_label((uint8_t*)dname_name(
				domain_dname(nsec_domain)));
			if(domain->parent)
				nsec_domain = domain->parent;
		} else {
			/* looks a lot like its likely to be unsigned */
			ai.qname = (uint8_t*)dname_name(domain_dname(
				zone->apex));
			nsec_domain = zone->apex;
		}
		/* wildcard denial */
		nsec_domain = find_covering_nsec_ext(nsec_domain->
			wildcard_child_closest_match, zone, &nsec_rrset);
		if(nsec_domain) {
			ai_add_rrset(&ai, AUTHORITY_SECTION, nsec_domain,
				nsec_rrset, zone);
		}
	} else {
		/* we only know the queries will be 'in the zone' */
		ai.qname = (uint8_t*)dname_name(domain_dname(zone->apex));
	}
	ai_add_rrset(&ai, AUTHORITY_SECTION, zone->apex, zone->soa_nx_rrset,
		zone);

	printf("nxdomain:\n");
	return compile_answer_packet(&ai, zone, cz);
}

/** compile positive answer for an rrset */
static struct cpkt* compile_dname_answer(uint8_t* dname, struct domain* domain,
	struct zone* zone, struct compzone* cz, rrset_type* rrset,
	struct region* region, int withdo)
{
	struct answer_info ai;
	ai.region = region;
	answer_info_init(&ai, dname);
	ai.adjust = 1;
	ai.withdo = withdo;
	ai.qtype = rrset_rrtype(rrset);
	ai.flagcode |= FLAGCODE_AA;
	ai_add_rrset(&ai, ANSWER_SECTION, domain, rrset, zone);
	printf("dnameanswer:\n");
	return compile_answer_packet(&ai, zone, cz);
}


void cpkt_delete(struct cpkt* cp)
{
	free(cp);
}

int cpkt_compare_qtype(const void* a, const void* b)
{
	struct cpkt* x = *(struct cpkt* const*)a;
	struct cpkt* y = *(struct cpkt* const*)b;
	return ((int)y->qtype) - ((int)x->qtype);
}

void compile_zones(struct comptree* ct, struct zone* zonelist,
	struct domain_table* table)
{
	struct zone* z;
	struct compzone* cz;
	time_t s, e;
	int n=0;
	s = time(NULL);
	/* fill the zonetree first */
	for(z = zonelist; z; z = z->next) {
		n++;
		cz = compzone_create(ct,
			(uint8_t*)dname_name(domain_dname(z->apex)));
	}
	/* so that compile_zone can access the zonetree */
	for(z = zonelist; z; z = z->next) {
		compile_zone(ct, cz, z, table);
	}
	e = time(NULL);
	VERBOSITY(1, (LOG_INFO, "compiled %d zones in %d seconds", n, (int)(e-s)));
}

/** see if zone is signed: if there is RRSIG(SOA) */
static int
zone_is_signed(struct zone* zone)
{
	rrset_type* rrsig = domain_find_rrset(zone->apex, zone, TYPE_RRSIG);
	size_t i;
	if(!rrsig)
		return 0;
	for(i=0; i<rrsig->rr_count; i++)
		if(rr_rrsig_type_covered(&rrsig->rrs[i]) == TYPE_SOA)
			return 1;
	return 0;
}

/** return zone serial number from SOA */
static uint32_t
zone_get_serial(struct zone* zone)
{
	if(!zone->soa_rrset || zone->soa_rrset->rr_count < 1)
		return 0; /* no SOA record? */
	if(zone->soa_rrset->rrs[0].rdata_count < 2)
		return 0; /* malformed SOA */
	if(rdata_atom_size(zone->soa_rrset->rrs[0].rdatas[2]) != 4)
		return 0; /* malformed SOA */
	return read_uint32(rdata_atom_data(zone->soa_rrset->rrs[0].rdatas[2]));
}

void compile_zone(struct comptree* ct, struct compzone* cz, struct zone* zone,
	struct domain_table* table)
{
	domain_type* walk;
	int is_signed;
	/* find serial number */
	cz->serial = zone_get_serial(zone);
	/* setup NSEC3 */
	if(domain_find_rrset(zone->apex, zone, TYPE_NSEC3PARAM)) {
		/* fill NSEC3params in cz */
		/* TODO */
		cz->nsec3tree = radix_tree_create();
	}
	/* see if the zone is signed */
	if(zone_is_signed(zone))
		is_signed = 1;
	else	is_signed = 0;

	/* walk through the names */
	walk = zone->apex;
	while(walk && dname_is_subdomain(domain_dname(walk),
		domain_dname(zone->apex))) {
		zone_type* curz = domain_find_zone(walk);
		if(curz && curz == zone) {
			compile_name(ct, cz, zone, table, walk, is_signed);
		}
		walk = domain_next(walk);
	}
}

enum domain_type_enum determine_domain_type(struct domain* domain,
	struct zone* zone, int* apex)
{
	rrset_type* rrset;
	if(!domain->is_existing)
		return dtype_notexist;
	/* there is a referral above it - rbtreeNSD */
	if(domain_find_ns_rrsets(domain->parent, zone, &rrset))
		return dtype_notexist;
	if(domain_find_rrset(domain, zone, TYPE_SOA))
		*apex = 1;
	else	*apex = 0;
	if(!*apex && domain_find_rrset(domain, zone, TYPE_NS))
		return dtype_delegation;
	/* test for DNAME first so DNAME+CNAME works as well as with NSD3 */
	if(domain_find_rrset(domain, zone, TYPE_DNAME))
		return dtype_dname;
	if(domain_find_rrset(domain, zone, TYPE_CNAME))
		return dtype_cname;
	return dtype_normal;
}

/** find wirename or add a compname(empty) for it */
static struct compname* find_or_create_name(struct comptree* ct, uint8_t* nm,
	struct compzone* cz)
{
	struct compname* cn = compname_search(ct, nm);
	if(cn) return cn;
	return compname_create(ct, nm, cz);
}

/** add a type to the typelist answers (during precompile it can grow */
static void cn_add_type(struct compname* cn, struct cpkt* p)
{
	/* check if already present */
	size_t i;
	if(!p) return;
	for(i=0; i<cn->typelen; i++)
		if(cn->types[i]->qtype == p->qtype) {
			log_msg(LOG_ERR, "internal error: double type in list");
			/* otherwise ignore it */
		}
	assert(cn->typelen <= 65536);
	cn->types[cn->typelen]=p;
	cn->typelen++;
}

/** add a type to the nonDO typelist answers (during precompile it can grow */
static void cn_add_type_nondo(struct compname* cn, struct cpkt* p)
{
	/* check if already present */
	size_t i;
	if(!p) return;
	for(i=0; i<cn->typelen_nondo; i++)
		if(cn->types_nondo[i]->qtype == p->qtype) {
			log_msg(LOG_ERR, "internal error: double type in list");
			/* otherwise ignore it */
		}
	assert(cn->typelen_nondo <= 65536);
	cn->types_nondo[cn->typelen_nondo]=p;
	cn->typelen_nondo++;
}

static void compile_delegation(struct compname* cn, struct domain* domain,
	uint8_t* dname, struct zone* zone, struct compzone* cz,
	struct region* region, int is_signed)
{
	/* type DS */
	cn_add_type(cn, compile_DS_answer(dname, domain, zone, cz, region, 1));
	cn_add_type_nondo(cn, compile_DS_answer(dname, domain, zone, cz,
		region, 0));
	/* notype is referral (fixed name) */
	cn->notype = compile_delegation_answer(dname, domain, zone, cz,
		region, 0, is_signed);
	cn->notype_nondo = compile_delegation_answer(dname, domain, zone, cz,
		region, 0, 0);
	/* below is referral (adjust name) */
	cn->below = compile_delegation_answer(dname, domain, zone, cz,
		region, 1, is_signed);
	cn->belowtype = BELOW_NORMAL;
	cn->below_nondo = compile_delegation_answer(dname, domain, zone, cz,
		region, 1, 0);
	cn->belowtype_nondo = BELOW_NORMAL;
}

static void compile_normal(struct compname* cn, struct domain* domain,
	uint8_t* dname, struct zone* zone, struct compzone* cz,
	struct region* region, int is_signed, int wildcard)
{
	rrset_type* rrset;
	/* add all existing qtypes */
	for(rrset = domain->rrsets; rrset; rrset = rrset->next) {
		if(rrset->zone != zone)
			continue;
#ifdef NSEC3
		if(rrset_rrtype(rrset) == TYPE_NSEC3)
			continue;
#endif
		cn_add_type(cn, compile_pos_answer(dname, domain, zone,
			cz, rrset, region, is_signed, wildcard));
		cn_add_type_nondo(cn, compile_pos_answer(dname, domain, zone,
			cz, rrset, region, 0, wildcard));
	}
	/* add qtype RRSIG (if necessary) */

	/* add qtype ANY */
	cn_add_type(cn, compile_any_answer(dname, domain, zone, cz, region,
		is_signed, wildcard));
	cn_add_type_nondo(cn, compile_any_answer(dname, domain, zone, cz,
		region, 0, wildcard));

	/* notype */
	if(is_signed)
		cn->notype = compile_nodata_answer(dname, domain, zone, cz,
			region, 0, is_signed);
	else	cn->notype = NULL; /* use zone ptr */
	cn->notype_nondo = NULL; /* use zone ptr */
}

static void compile_cname(struct compname* cn, struct domain* domain,
	uint8_t* dname, struct zone* zone, struct compzone* cz,
	struct region* region, int is_signed, int wildcard)
{
	rrset_type* rrset = NULL;
	/* TODO */
	/* todo: follow in-zone */
	/* notype is CNAME */
	rrset = domain_find_rrset(domain, zone, TYPE_CNAME);
	assert(rrset);
	cn->notype = compile_pos_answer(dname, domain, zone, cz, rrset,
		region, is_signed, wildcard);
	cn->notype_nondo = compile_pos_answer(dname, domain, zone, cz, rrset,
		region, 0, wildcard);
}

static void compile_dname(struct compname* cn, struct domain* domain,
	uint8_t* dname, struct zone* zone, struct compzone* cz,
	struct region* region, int is_signed, int wildcard)
{
	rrset_type* rrset = NULL;
	/* fill for normal types, other types next to DNAME */
	/* small support for CNAME+DNAME */
	if(domain_find_rrset(domain, zone, TYPE_CNAME))
		compile_cname(cn, domain, dname, zone, cz, region, is_signed,
			wildcard);
	else 	compile_normal(cn, domain, dname, zone, cz, region, is_signed,
			wildcard);
	/* below is dname */
	rrset = domain_find_rrset(domain, zone, TYPE_DNAME);
	assert(rrset);
	cn->below = compile_dname_answer(dname, domain, zone, cz, rrset,
		region, is_signed);
	cn->belowtype = BELOW_SYNTHC;
	cn->below_nondo = compile_dname_answer(dname, domain, zone, cz, rrset,
		region, 0);
	cn->belowtype_nondo = BELOW_SYNTHC;
}

static void compile_side_nsec(struct compname* cn, struct domain* domain,
	struct zone* zone, struct compzone* cz, struct region* region,
	int is_signed)
{
	/* NXDOMAIN in side */
	if(is_signed)
		cn->side = compile_nxdomain_answer(domain, zone, cz, region, 1);
	else	cn->side = NULL; /* use zone ptr */
}

static void compile_below_nsec3(struct compname* cn, struct domain_table* table,
        struct domain* domain, struct compzone* cz, int is_signed)
{
	/* create nxdomain in nsec3tree, belowptr */
	/* TODO */

	if(is_signed) {
		cn->below = (struct cpkt*)cz;
		cn->belowtype = BELOW_NSEC3NX;
	} else {
		cn->below = NULL;
		cn->belowtype = BELOW_NORMAL;
	}
	cn->below_nondo = NULL; /* get unsigned nxdomain from zone */
	cn->belowtype_nondo = BELOW_NORMAL;
}

static void compile_below_wcard(struct compname* cn, struct comptree* ct,
	uint8_t* dname, struct compzone* cz)
{
	/* belowptr to wildcardname, create if not yet exists, but it gets
	 * filled on its own accord */
	uint8_t wname[MAXDOMAINLEN+2];
	struct compname* wcard;
	/* the wildcard must exist */
	assert(dname_length(dname) == cn->namelen);
	assert(dname_length(dname)+2 <= MAXDOMAINLEN);
	wname[0]=1;
	wname[1]='*';
	memmove(wname+2, dname, cn->namelen);
	wcard = find_or_create_name(ct, wname, cz);
	cn->below = (struct cpkt*)wcard;
	cn->belowtype = BELOW_WILDCARD;
	cn->below_nondo = (struct cpkt*)wcard;
	cn->belowtype_nondo = BELOW_WILDCARD;
}

static void compile_apex_ds(struct compname* cn, struct domain_table* table,
        struct domain* domain, struct comptree* ct, uint8_t* dname,
	int is_signed)
{
	/* create a qtype DS for the zone apex, but only if we host a zone
	 * above this zone, can be posDS, NSEC-DS, NSEC3DS(nodata,optout).
	 * in case its nxdomain above, include that(assume optout). */
	int ce = 0;
	uint8_t* dsname = dname_strip_label(dname);
	struct compzone* above = compzone_find(ct, dsname, &ce);
	if(above) {
		/* add a DS-answer from the point of view of that zone */
		/* TODO */
	}
}

void compile_name(struct comptree* ct, struct compzone* cz, struct zone* zone,
        struct domain_table* table, struct domain* domain, int is_signed)
{
	/* determine the 'type' of this domain name */
	int apex = 0;
	int wildcard = 0;
	enum domain_type_enum t = determine_domain_type(domain, zone, &apex);
	struct compname* cn;
	uint8_t* dname = (uint8_t*)dname_name(domain_dname(domain));
	struct cpkt* pktlist[65536+10]; /* all types and some spare */
	struct cpkt* pktlist_nondo[65536+10]; /* all types and some spare */
	region_type* region;

	/* type: NSEC3domain: treat as occluded. */
	/* type: glue: treat as occluded. */
	/* type: occluded: do nothing, do not add the name. */
	if(t == dtype_notexist)
		return;
	/* if we host the subzone of referral too, add it as itself */
	else if(t == dtype_delegation && compzone_search(ct, dname))
		return;

	if(dname_is_wildcard(dname))
		wildcard = 1;

	log_msg(LOG_INFO, "compilename %s", dname_to_string(domain_dname(domain), NULL));
	/* create cn(or find) and setup typelist for additions */
	region = region_create(xalloc, free);
	cn = find_or_create_name(ct, dname, cz);
	/* avoid double allocations and memory leaks because of that */
	compname_clear_pkts(cn);
	assert(cn->typelen < sizeof(pktlist));
	assert(cn->typelen_nondo < sizeof(pktlist_nondo));
	memcpy(pktlist, cn->types, cn->typelen*sizeof(struct cpkt*));
	memcpy(pktlist_nondo, cn->types_nondo,
		cn->typelen_nondo*sizeof(struct cpkt*));
	free(cn->types);
	free(cn->types_nondo);
	cn->types = pktlist;
	cn->types_nondo = pktlist_nondo;

	/* type: delegation: type-DS, notype=referral, below=referral */
	if(t == dtype_delegation)
		compile_delegation(cn, domain, dname, zone, cz, region,
			is_signed);
	/* type: dname: fill for dname, type and below */
	else if(t == dtype_dname)
		compile_dname(cn, domain, dname, zone, cz, region, is_signed,
			wildcard);
	/* type: cname: fill for cname : if in-zone: for all types at dest,
	 * 				             and for notype-dest.
	 * 				not-in-zone: just the cname. */
	else if(t == dtype_cname)
		compile_cname(cn, domain, dname, zone, cz, region, is_signed,
			wildcard);
	/* type: normal: all types, ANY, RRSIG, notype(NSEC/NSEC3). */
	else if(t == dtype_normal)
		compile_normal(cn, domain, dname, zone, cz, region, is_signed,
			wildcard);
	
	/* fill below special */
	if(t == dtype_delegation)
		/* below is referral */;
	else if(t == dtype_dname)
		/* below is dname */;
	else if(domain_wildcard_child(domain) && cn->namelen+2<=MAXDOMAINLEN)
		compile_below_wcard(cn, ct, dname, cz);
	/* else if zone is NSEC3: create nxdomain in nsec3tree, belowptr */
	else if(cz->nsec3tree)
		compile_below_nsec3(cn, table, domain, cz, is_signed);
	else {
		cn->below = NULL;
		cn->belowtype = BELOW_NORMAL;
		cn->below_nondo = NULL; /* get unsigned nxdomain from zone */
		cn->belowtype_nondo = BELOW_NORMAL;
	}

	/* if zone is NSEC: create nxdomain in side (or do unsignedzone) */
	if(!cz->nsec3tree)
		compile_side_nsec(cn, domain, zone, cz, region, is_signed);
	else 	cn->side = NULL;

	if(apex) {
		/* see if we need special type-DS compile (parent zone) */
		compile_apex_ds(cn, table, domain, ct, dname, is_signed);
		/* compile unsigned nxdomain for zone */
		printf("compile unsigned nxdomain with dname %d\n",
			(int)dname_length(dname));
		cz->nx = compile_nxdomain_answer(domain, zone, cz, region, 0);
		/* compile unsigned nodata for zone; with adjust */
		cz->nodata = compile_nodata_answer(dname, domain, zone, cz,
			region, 1, 0);
	}
	
	/* sort and allocate typelist */
	assert(cn->typelen < sizeof(pktlist));
	assert(cn->typelen_nondo < sizeof(pktlist_nondo));
	if(cn->typelen == 0) {
		cn->types = NULL;
	} else {
		qsort(pktlist, cn->typelen, sizeof(struct cpkt*),
			&cpkt_compare_qtype);
		cn->types = (struct cpkt**)memdup(pktlist,
			cn->typelen*sizeof(struct cpkt*));
	}
	if(cn->typelen_nondo == 0) {
		cn->types_nondo = NULL;
	} else {
		qsort(pktlist_nondo, cn->typelen_nondo, sizeof(struct cpkt*),
			&cpkt_compare_qtype);
		cn->types_nondo = (struct cpkt**)memdup(pktlist_nondo,
			cn->typelen_nondo*sizeof(struct cpkt*));
	}
	region_destroy(region);
}

