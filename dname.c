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


static const uint8_t *strdname (const char *source, const uint8_t *o);

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
	if (origin) {
		buf[0] = origin->name_size;
		memcpy(buf + 1, dname_name(origin), origin->name_size);
	} else {
		buf[0] = 1;
		buf[1] = 0;
	}
	return dname_make(region, strdname(name, buf) + 1);
}


const dname_type *
dname_copy(region_type *region, const dname_type *dname)
{
	dname_type *result;

	assert(dname);

	result = region_alloc(region, dname_total_size(dname));
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

const dname_type *
dname_partial_copy(region_type *region, const dname_type *dname, uint8_t label_count)
{
	assert(label_count > 0);

	if (!dname)
		return NULL;
	
	assert(label_count <= dname->label_count);

	return dname_make(region, dname_label(dname, label_count - 1));
}


int
dname_is_subdomain(const dname_type *left, const dname_type *right)
{
	uint8_t i;
	
	if (left->label_count < right->label_count)
		return 0;

	for (i = 1; i < right->label_count; ++i) {
		if (label_compare(dname_label(left, i),
				  dname_label(right, i)) != 0)
			return 0;
	}

	return 1;
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

uint8_t
dname_label_match_count(const dname_type *left, const dname_type *right)
{
	uint8_t i;
	
	assert(left);
	assert(right);

	for (i = 1; i < left->label_count && i < right->label_count; ++i) {
		int result = label_compare(dname_label(left, i),
					   dname_label(right, i));
		if (result) {
			return i;
		}
	}

	return i;
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
 * Parses the string and returns a dname with
 * the first byte indicating the size of the entire
 * dname.
 *
 * XXX Check if we dont run out of space (p < d + len)
 * XXX Verify that every label dont exceed MAXLABELLEN
 * XXX Complain about empty labels (.nlnetlabs..nl)
 */
static const uint8_t *
strdname (const char *source, const uint8_t *o)
{
	static uint8_t dname[MAXDOMAINLEN+1];

	const uint8_t *s = (const uint8_t *) source;
	uint8_t *h;
	uint8_t *p;
	uint8_t *d = dname + 1;

	if (*s == '@' && *(s+1) == 0) {
		for (p = dname, s = o; s < o + *o + 1; p++, s++)
			*p = DNAME_NORMALIZE(*s);
	} else {
		for (h = d, p = h + 1; *s; s++, p++) {
			switch (*s) {
			case '.':
				if (p == (h + 1)) p--;	/* Suppress empty labels */
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
		if ((*(p-1) != 0) && (o != NULL)) {
			for (s = o + 1; s < o + *o + 1; p++, s++)
				*p = DNAME_NORMALIZE(*s);
		}

		*dname = (uint8_t) (p - d);

	}

	return dname;
}


const dname_type *
create_dname(region_type *region, const uint8_t *str, const size_t len)
{
	uint8_t temp[MAXDOMAINLEN + 1];
	size_t i;

	assert(len > 0 && len < 64);

	temp[0] = len;
	for (i = 0; i < len; ++i) {
		temp[i + 1] = DNAME_NORMALIZE(str[i]);
	}
	temp[len + 1] = '\000';

	return dname_make(region, temp);
}
         

const dname_type *
cat_dname(region_type *region,
	  const dname_type *left,
	  const dname_type *right)
{
	uint8_t temp[MAXDOMAINLEN];

	memcpy(temp, dname_name(left), left->name_size - 1);
	memcpy(temp + left->name_size - 1, dname_name(right), right->name_size);

	return dname_make(region, temp);
}

#ifdef TEST

#include <stdio.h>
#include <stdlib.h>

#define BUFSZ 1000

int
main(void)
{
	static const char *dnames[] = {
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
	dname_table_type *table = dname_table_create(region);
	size_t key = dname_info_create_key(table);
	const dname_type *dname;
	size_t i;
	dname_info_type *closest_match;
	dname_info_type *closest_encloser;
	int exact;
	
	for (i = 0; i < sizeof(dnames) / sizeof(char *); ++i) {
		dname_info_type *temp;
		dname = dname_parse(region, dnames[i], NULL);
		temp = dname_table_insert(table, dname);
		dname_info_put_ptr(temp, key, (void *) dnames[i]);
	}
	
	exact = dname_table_search(
		table,
		dname_parse(region, "foo.bar.com", NULL),
		&closest_match, &closest_encloser);
	assert(exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[6]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[6]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.b.hhh.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[2]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[2]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "ns3.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[5]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[1]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.ns1.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[4]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[4]);
	
	exact = dname_table_search(
		table,
		dname_parse(region, "x.y.z.d.e.bar.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
/* 	assert(dname_compare(closest_match->dname, */
/* 			     dname_parse(region, "c.d.e.bar.com", NULL)) == 0); */
/* 	assert(dname_compare(closest_encloser->dname, */
/* 			     dname_parse(region, "d.e.bar.com", NULL)) == 0); */
	
	exact = dname_table_search(
		table,
		dname_parse(region, "a.aaa.com", NULL),
		&closest_match, &closest_encloser);
	assert(!exact);
	assert(dname_info_get_ptr(closest_match, key) == dnames[8]);
	assert(dname_info_get_ptr(closest_encloser, key) == dnames[1]);
	assert(closest_encloser->wildcard_child);
	assert(dname_info_get_ptr(closest_encloser->wildcard_child, key)
	       == dnames[8]);

	dname = dname_parse(region, "a.b.c.d", NULL);
	assert(dname_compare(dname_parse(region, "d", NULL),
			     dname_partial_copy(region, dname, 2)) == 0);
	
	exit(0);
}

#endif /* TEST */
