/*
 * dname.c -- Domain name handling.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
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
#include "query.h"

static const uint8_t *strdname (const char *source, const uint8_t *o);

const dname_type *
dname_make(region_type *region, const uint8_t *name, int normalize)
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

	result = (dname_type *) region_alloc(
		region,
		(sizeof(dname_type)
		 + (label_count + name_size) * sizeof(uint8_t)));
	result->name_size = name_size;
	result->label_count = label_count;
	memcpy((uint8_t *) dname_label_offsets(result),
	       label_offsets,
	       label_count * sizeof(uint8_t));
	if (normalize) {
		uint8_t *dst = (uint8_t *) dname_name(result);
		const uint8_t *src = name;
		while (!label_is_root(src)) {
			ssize_t len = label_length(src);
			*dst++ = *src++;
			for (i = 0; i < len; ++i) {
				*dst++ = NAMEDB_NORMALIZE(*src++);
			}
		}
		*dst = *src;
	} else {
		memcpy((uint8_t *) dname_name(result),
		       name,
		       name_size * sizeof(uint8_t));
	}
	return result;
}


const dname_type *
dname_make_from_packet(region_type *region, buffer_type *packet,
		       int allow_pointers, int normalize)
{
	uint8_t buf[MAXDOMAINLEN + 1];
	int done = 0;
	uint8_t visited[(MAX_PACKET_SIZE+7)/8];
	size_t dname_length = 0;
	const uint8_t *label;
	ssize_t mark = -1;
	
	memset(visited, 0, (buffer_limit(packet)+7)/8);
	
	while (!done) {
		if (!buffer_available(packet, 1)) {
/* 			error("dname out of bounds"); */
			return NULL;
		}

		if (get_bit(visited, buffer_position(packet))) {
/* 			error("dname loops"); */
			return NULL;
		}
		set_bit(visited, buffer_position(packet));

		label = buffer_current(packet);
		if (label_is_pointer(label)) {
			size_t pointer;
			if (!allow_pointers) {
				return NULL;
			}
			if (!buffer_available(packet, 2)) {
/* 				error("dname pointer out of bounds"); */
				return NULL;
			}
			pointer = label_pointer_location(label);
			if (!buffer_available_at(packet, pointer, 0)) {
/* 				error("dname pointer points outside packet"); */
				return NULL;
			}
			buffer_skip(packet, 2);
			if (mark == -1) {
				mark = buffer_position(packet);
			}
			buffer_set_position(packet, pointer);
		} else if (label_is_normal(label)) {
			size_t length = label_length(label) + 1;
			done = label_is_root(label);
			if (!buffer_available(packet, length)) {
/* 				error("dname label out of bounds"); */
				return NULL;
			}
			if (dname_length + length >= sizeof(buf)) {
/* 				error("dname too large"); */
				return NULL;
			}
			buffer_read(packet, buf + dname_length, length);
			dname_length += length;
		} else {
/* 			error("bad label type"); */
			return NULL;
		}
	}

	if (mark != -1) {
		buffer_set_position(packet, mark);
	}

	return dname_make(region, buf, normalize);
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
	return dname_make(region, strdname(name, buf) + 1, 0);
}


const dname_type *
dname_copy(region_type *region, const dname_type *dname)
{
	dname_type *result;

	assert(dname);

	result = (dname_type *) region_alloc(region, dname_total_size(dname));
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

	return dname_make(region, dname_label(dname, label_count - 1), 0);
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


uint8_t
dname_label_match_count(const dname_type *left, const dname_type *right)
{
	uint8_t i;
	
	assert(left);
	assert(right);

	for (i = 1; i < left->label_count && i < right->label_count; ++i) {
		if (label_compare(dname_label(left, i),
				  dname_label(right, i)) != 0)
		{
			return i;
		}
	}

	return i;
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
dname_make_from_label(region_type *region,
		      const uint8_t *label, const size_t length)
{
	uint8_t temp[MAXLABELLEN + 2];

	assert(length > 0 && length <= MAXLABELLEN);

	temp[0] = length;
	memcpy(temp + 1, label, length * sizeof(uint8_t));
	temp[length + 1] = '\000';

	return dname_make(region, temp, 1);
}
         

const dname_type *
dname_concatenate(region_type *region,
		  const dname_type *left,
		  const dname_type *right)
{
	uint8_t temp[MAXDOMAINLEN];

	assert(left->name_size + right->name_size - 1 <= MAXDOMAINLEN);
	
	memcpy(temp, dname_name(left), left->name_size - 1);
	memcpy(temp + left->name_size - 1, dname_name(right), right->name_size);

	return dname_make(region, temp, 0);
}
