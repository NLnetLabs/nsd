/*
 * dname.c -- dname operations
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <config.h>

#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include "dns.h"
#include "dname.h"
#include "namedb.h"
#include "util.h"


#if 0
static uint8_t
dname_common_label_count(dname_type *left, dname_type *right)
{
	uint8_t label_count;
	uint8_t i;
	
	assert(left);
	assert(right);

	if (left == right) {
		return left->label_count;
	}

	label_count = (left->label_count <= right->label_count
		       ? left->label_count
		       : right->label_count);
	for (i = 1; i < label_count; ++i) {
		int result = label_compare(dname_label(left, i),
					   dname_label(right, i));
		if (result)
			break;
	}
	return i;
}
#endif

const dname_type *
dname_make(region_type *region, const uint8_t *name)
{
	size_t name_size = 0;
	uint8_t label_offsets[MAXDOMAINLEN];
	uint8_t label_count = 0;
	const uint8_t *label = name;
	dname_type *result;
	ssize_t i;
	
	assert(name);
	
	while (1) {
		if (label_is_pointer(label))
			return NULL;
		
		label_offsets[label_count] = (uint8_t) (label - name);
		++label_count;
		name_size += label_length(label) + 1;

		if (label_is_root(label))
			break;
		
		label = label_next(label);
	}

	if (name_size > MAXDOMAINLEN)
		return NULL;

	assert(label_count <= MAXDOMAINLEN / 2 + 1);

	/* Reverse label offsets.  */
	for (i = 0; i < label_count / 2; ++i) {
		uint8_t tmp = label_offsets[i];
		label_offsets[i] = label_offsets[label_count - i - 1];
		label_offsets[label_count - i - 1] = tmp;
	}

	result = region_alloc(region, sizeof(dname_type) + (label_count + name_size) * sizeof(uint8_t));
	result->name_size = name_size;
	result->label_count = label_count;
	memcpy((uint8_t *) dname_label_offsets(result),
	       label_offsets,
	       label_count * sizeof(uint8_t));
	memcpy((uint8_t *) dname_name(result),
	       name,
	       name_size * sizeof(uint8_t));
	return result;
}


const dname_type *
dname_parse(region_type *region, const char *name, const dname_type *origin)
{
	uint8_t buf[MAXDOMAINLEN + 1];
	assert(origin);
	buf[0] = origin->name_size;
	memcpy(buf + 1, dname_name(origin), origin->name_size);
	return dname_make(region, strdname(name, buf) + 1);
}


const dname_type *
dname_copy(region_type *region, const dname_type *dname)
{
	dname_type *result;

	assert(dname);

	result = region_alloc(region, sizeof(dname_type) + (dname->label_count + dname->name_size) * sizeof(uint8_t));
	result->name_size = dname->name_size;
	result->label_count = dname->label_count;
	memcpy((uint8_t *) dname_label_offsets(result),
	       dname_label_offsets(dname),
	       result->label_count * sizeof(uint8_t));
	memcpy((uint8_t *) dname_name(result),
	       dname_name(dname),
	       result->name_size * sizeof(uint8_t));
	
	return result;
}


int
dname_compare(const dname_type *left, const dname_type *right)
{
	int result;
	uint8_t label_count;
	uint8_t i;
	
	assert(left);
	assert(right);

	if (left == right) {
		return 0;
	}

	label_count = (left->label_count <= right->label_count
		       ? left->label_count
		       : right->label_count);

	/* Skip the root label by starting at label 1.  */
	for (i = 1; i < label_count; ++i) {
		result = label_compare(dname_label(left, i),
				       dname_label(right, i));
		if (result) {
			return result;
		}
	}

	/* Dname with the fewest labels is "first".  */
	return (int) left->label_count - (int) right->label_count;
}


int
label_compare(const uint8_t *left, const uint8_t *right)
{
	int left_length;
	int right_length;
	size_t size;
	int result;
	
	assert(left);
	assert(right);

	assert(label_is_normal(left));
	assert(label_is_normal(right));
	
	left_length = label_length(left);
	right_length = label_length(right);
	size = left_length < right_length ? left_length : right_length;
	
	result = memcmp(label_data(left), label_data(right), size);
	if (result) {
		return result;
	} else {
		return (int) left_length - (int) right_length;
	}
#if 0
	int r;
	const uint8_t *a = left;
	const uint8_t *b = right;
	int alen = (int)*a;
	int blen = (int)*b;

	while(alen && blen) {
		a++; b++;
		if((r = *a - *b)) return r;
		alen--; blen--;
	}
	return alen - blen;
#endif
}


static dname_tree_type *
allocate_dname_tree(region_type *region, dname_tree_type *parent, uint8_t label_count, void *data)
{
	dname_tree_type *result;

	result = region_alloc(region, sizeof(dname_tree_type));
	result->region = region;
	result->parent = parent;
	result->children = NULL;
	result->wildcard_child = NULL;
 	result->label_count = label_count;
	result->data = data;
	result->plugin_data = NULL;
	
	return result;
}

dname_tree_type *
dname_tree_create(region_type *region)
{
	return allocate_dname_tree(region, NULL, 1, NULL);
}

int
dname_tree_search(dname_tree_type *dt,
		  const dname_type *dname,
		  dname_tree_type **less_equal,
		  dname_tree_type **closest_encloser)
{
	rbnode_t *child;
	uint8_t label = 1;
	
	assert(label <= dname->label_count);

	while (label < dname->label_count
	       && dt->children
	       && rbtree_find_less_equal(dt->children,
					 dname_label(dname, label),
					 &child))
	{
		/* Exact match.  */
		assert(dt->label_count == label);
		dt = child->data;
		++label;
	}

	if (label == dname->label_count) {
		/* Exact match.  */
		*less_equal = dt;
		*closest_encloser = dt;
		return 1;
	} else if (child == NULL) {
		/*
		 * No predecessor children, so the closest encloser is
		 * the predecessor.
		 */
		*less_equal = dt;
		*closest_encloser = dt;
		return 0;
	} else {
		*less_equal = child->data;
		*closest_encloser = dt;
		return 0;
	}
}

dname_tree_type *
dname_tree_find(dname_tree_type *tree,
		const dname_type *dname)
{
	dname_tree_type *less_equal;
	dname_tree_type *closest_encloser;
	int exact;

	exact = dname_tree_search(tree, dname, &less_equal, &closest_encloser);
	return exact ? closest_encloser : NULL;
}


dname_tree_type *
dname_tree_update(dname_tree_type *dt,
		  const dname_type *dname,
		  void *data)
{
	dname_tree_type *less_equal;
	dname_tree_type *closest_encloser;
	dname_tree_type *result;
	
	if (dname_tree_search(dt, dname, &less_equal, &closest_encloser)) {
		closest_encloser->data = data;
		return closest_encloser;
	}

	assert(closest_encloser->label_count < dname->label_count);
	
	/* Insert new node(s).  */
	do {
		/*
		 * Insert empty nodes between closest encloser and the
		 * new entry.
		 */
		result = allocate_dname_tree(dt->region,
					     closest_encloser,
					     closest_encloser->label_count + 1, NULL);
		if (!closest_encloser->children) {
			closest_encloser->children
				= heap_create(
					closest_encloser->region,
					(int (*)(const void *, const void *)) label_compare);
		}
		heap_insert(closest_encloser->children,
			    dname_label(dname, closest_encloser->label_count),
			    result, 0);
		if (label_is_wildcard(dname_label(dname, closest_encloser->label_count))) {
			closest_encloser->wildcard_child = result;
		}
		closest_encloser = result;
	} while (closest_encloser->label_count < dname->label_count);

	result->data = data;
	return result;
}

/*
 *
 * Compares two domain names.
 *
 */
int 
dnamecmp (const void *left, const void *right)
{
	int r;
	const uint8_t *a = left;
	const uint8_t *b = right;
	int alen = (int)*a;
	int blen = (int)*b;

	while(alen && blen) {
		a++; b++;
		if((r = DNAME_NORMALIZE(*a) - DNAME_NORMALIZE(*b))) return r;
		alen--; blen--;
	}
	return alen - blen;
}

const char *
dname_to_string(const dname_type *dname)
{
	return labels_to_string(dname_name(dname));
}

const char *
labels_to_string(const uint8_t *dname)
{
	static char buf[MAXDOMAINLEN + 1];
	char *p = buf;
	const uint8_t *label = dname;

	while (!label_is_root(label)) {
		const uint8_t *data = label_data(label);
		uint8_t i;
		for (i = 0; i < label_length(label); ++i) {
			*p++ = data[i];
		}
		*p++ = '.';
		label = label_next(label);
	}

	if (buf == p)
		*p++ = '.';
	*p++ = '\0';
	
	return buf;
}

/*
 *
 * Converts dname to text
 *
 * XXX Actually should not be here cause it is a debug routine.
 *
 */
const char *
dnamestr (const uint8_t *dname)
{
	static char s[MAXDOMAINLEN+1];
	char *p;
	int l;
	const uint8_t *n = dname;

	l = (int) *dname;
	n++;
	p = s;

	if(*n) {
		while(n < dname + l) {
			memcpy(p, n+1, (int) *n);
			p += (int) *n;
			*p++ = '.';
			n += (int) *n + 1;
		}
	} else {
		*p++ = '.';
	}
	*p = 0;
	return s;
}

/*
 * Parses the string and returns a dname with
 * the first byte indicating the size of the entire
 * dname.
 *
 * XXX Check if we dont run out of space (p < d + len)
 * XXX Verify that every label dont exceed MAXLABELLEN
 * XXX Complain about empty labels (.nlnetlabs..nl)
 */
const uint8_t *
strdname (const char *source, const uint8_t *o)
{
	static uint8_t dname[MAXDOMAINLEN+1];

	const uint8_t *s = (const uint8_t *) source;
	uint8_t *h;
	uint8_t *p;
	uint8_t *d = dname + 1;

	if(*s == '@' && *(s+1) == 0) {
		for(p = dname, s = o; s < o + *o + 1; p++, s++)
			*p = DNAME_NORMALIZE(*s);
	} else {
		for(h = d, p = h + 1; *s; s++, p++) {
			switch(*s) {
			case '.':
				if(p == (h + 1)) p--;	/* Suppress empty labels */
				*h = p - h - 1;
				h = p;
				break;
			case '\\':
				/* Handle escaped characters (RFC1035 5.1) */
				if ('0' <= s[1] && s[1] <= '9' &&
				    '0' <= s[2] && s[2] <= '9' &&
				    '0' <= s[3] && s[3] <= '9')
				{
					int val = ((s[1] - '0') * 100 +
						   (s[2] - '0') * 10 +
						   (s[3] - '0'));
					if (val >= 0 && val <= UCHAR_MAX) {
						s += 3;
						*p = NAMEDB_NORMALIZE(val);
					} else {
						*p = NAMEDB_NORMALIZE(*++s);
					}
				} else if (s[1] != '\0') {
					*p = NAMEDB_NORMALIZE(*++s);
				}
				break;
			default:
				*p = DNAME_NORMALIZE(*s);
			}
		}
		*h = p - h - 1;

		/* If not absolute, append origin... */
		if((*(p-1) != 0) && (o != NULL)) {
			for(s = o + 1; s < o + *o + 1; p++, s++)
				*p = DNAME_NORMALIZE(*s);
		}

		*dname = (uint8_t) (p - d);

	}

	return dname;
}

/*
 * Duplicates a domain name.
 *
 */
uint8_t *
dnamedup (const uint8_t *dname)
{
	uint8_t *p;

	if(dname == NULL)
		return NULL;

	p = xalloc((int)*dname + 1);
	memcpy(p, dname, (int)*dname + 1);
	return p;
}


#ifdef TEST

#include <stdio.h>
#include <stdlib.h>

#define BUFSZ 1000

int
main(void)
{
	static char *dnames[] = {
		"com",
		"aaa.com",
		"hhh.com",
		"zzz.com",
		"ns1.aaa.com",
		"ns2.aaa.com",
		"foo.bar.com",
		"a.b.c.d.e.bar.com",
		"*.aaa.com"
	};
	region_type *region = region_create(xalloc, free);
	const dname_type *origin = dname_make(region, (uint8_t *) "", 0);
	dname_tree_type *tree = dname_tree_create(region);
	const dname_type *dname;
	size_t i;
	dname_tree_type *less_equal;
	dname_tree_type *closest_encloser;
	int exact;
	
	for (i = 0; i < sizeof(dnames) / sizeof(char *); ++i) {
		dname = dname_parse(region, dnames[i], origin);
		dname_tree_update(tree, dname, dnames[i]);
	}

	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "foo.bar.com", origin),
		&less_equal, &closest_encloser);
	assert(exact);
	assert(less_equal->data == dnames[6]);
	assert(closest_encloser->data == dnames[6]);
	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "a.b.hhh.com", origin),
		&less_equal, &closest_encloser);
	assert(!exact);
	assert(less_equal->data == dnames[2]);
	assert(closest_encloser->data == dnames[2]);
	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "ns3.aaa.com", origin),
		&less_equal, &closest_encloser);
	assert(!exact);
	assert(less_equal->data == dnames[5]);
	assert(closest_encloser->data == dnames[1]);
	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "a.ns1.aaa.com", origin),
		&less_equal, &closest_encloser);
	assert(!exact);
	assert(less_equal->data == dnames[4]);
	assert(closest_encloser->data == dnames[4]);
	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "x.y.z.d.e.bar.com", origin),
		&less_equal, &closest_encloser);
	assert(!exact);
/* 	assert(dname_compare(less_equal->dname, */
/* 			     dname_parse(region, "c.d.e.bar.com", origin)) == 0); */
/* 	assert(dname_compare(closest_encloser->dname, */
/* 			     dname_parse(region, "d.e.bar.com", origin)) == 0); */
	
	exact = dname_tree_search(
		tree,
		dname_parse(region, "a.aaa.com", origin),
		&less_equal, &closest_encloser);
	assert(!exact);
 	assert(less_equal->data == dnames[8]);
	assert(closest_encloser->data == dnames[1]);
	assert(closest_encloser->wildcard_child);
	assert(closest_encloser->wildcard_child->data == dnames[8]);
	
	exit(0);
}

#endif /* TEST */
