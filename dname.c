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

inline int
label_compare(const uint8_t *left, const uint8_t *right)
{
	int left_length;
	int right_length;
	int size;
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
		return left_length - right_length;
	}
}


const dname_type *
dname_make(region_type *region, const uint8_t *name)
{
	size_t name_length;
	uint8_t canonical_dname[MAXDOMAINLEN];
	const uint8_t *label;
	uint8_t *p;
	dname_type *result;
	size_t i;
	
	assert(name);

	/* Generate canonical representation.  */
	name_length = 1;	/* Always include root label. */
	canonical_dname[MAXDOMAINLEN - 1] = 0; /* Terminating root label.  */
	p = &canonical_dname[MAXDOMAINLEN - 1];
	label = name;
	for (label = name; !label_is_root(label); label = label_next(label)) {
		size_t length;
		
		if (label_is_pointer(label))
			return NULL;

		length = label_length(label);

		name_length += length + 1;
		if (name_length > MAXDOMAINLEN)
			return NULL;
		
		p -= length + 1;
		p[0] = length;
		for (i = 0; i < length; ++i) {
			p[i + 1] = DNAME_NORMALIZE(label[i + 1]);
		}
	}

	result = (dname_type *) region_alloc(
		region,	sizeof(dname_type) + 2 * name_length);
	result->_data[0] = name_length;
	memcpy(&result->_data[1], p, name_length);
	memcpy(&result->_data[1 + name_length], name, name_length);
	return result;
}


const dname_type *
dname_make_from_packet(region_type *region, buffer_type *packet,
		       int allow_pointers)
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
			if (pointer >= buffer_limit(packet)) {
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

	return dname_make(region, buf);
}

const dname_type *
dname_parse(region_type *region, const char *name)
{
	uint8_t dname[MAXDOMAINLEN];

	const uint8_t *s = (const uint8_t *) name;
	uint8_t *h;
	uint8_t *p;
	uint8_t *d = dname;
	size_t label_length;

	if (strcmp(name, ".") == 0) {
		/* Root domain.  */
		dname[0] = 0;
		return dname_make(region, dname);
	}
	
	for (h = d, p = h + 1; *s; ++s, ++p) {
		if (p - dname >= MAXDOMAINLEN) {
			return NULL;
		}
		
		switch (*s) {
		case '.':
			if (p == h + 1) {
				/* Empty label.  */
				return NULL;
			} else {
				label_length = p - h - 1;
				if (label_length > MAXLABELLEN) {
					return NULL;
				}
				*h = label_length;
				h = p;
			}
			break;
		case '\\':
			/* Handle escaped characters (RFC1035 5.1) */
			if (isdigit(s[1]) && isdigit(s[2]) && isdigit(s[3])) {
				int val = (hexdigit_to_int(s[1]) * 100 +
					   hexdigit_to_int(s[2]) * 10 +
					   hexdigit_to_int(s[3]));
				if (0 <= val && val <= 255) {
					s += 3;
					*p = val;
				} else {
					*p = *++s;
				}
			} else if (s[1] != '\0') {
				*p = *++s;
			}
			break;
		default:
			*p = *s;
			break;
		}
	}

	if (p != h + 1) {
		/* Terminate last label.  */
		label_length = p - h - 1;
		if (label_length > MAXLABELLEN) {
			return NULL;
		}
		*h = label_length;
		h = p;
	}

	/* Add root label.  */
	*h = 0;
	
	return dname_make(region, dname);
}


const dname_type *
dname_copy(region_type *region, const dname_type *dname)
{
	return (dname_type *) region_alloc_init(
		region, dname, dname_total_size(dname));
}


size_t
dname_label_count(const dname_type *dname)
{
	const uint8_t *label;
	size_t result;
	
	assert(dname);

	result = 1;
	for (label = dname_canonical_name(dname);
	     !label_is_root(label);
	     label = label_next(label))
	{
		++result;
	}

	return result;
}


const dname_type *
dname_partial_copy(region_type *region, const dname_type *dname, uint8_t count)
{
	if (!dname)
		return NULL;

	if (count == 0) {
		/* Always copy the root label.  */
		count = 1;
	}
	
	assert(count <= dname_label_count(dname));

	return dname_make(region, dname_label(dname, count - 1));
}


const dname_type *
dname_origin(region_type *region, const dname_type *dname)
{
	return dname_partial_copy(region, dname, dname_label_count(dname) - 1);
}


int
dname_is_subdomain(const dname_type *left, const dname_type *right)
{
	const uint8_t *left_label = dname_canonical_name(left);
	const uint8_t *right_label = dname_canonical_name(right);
	
	while (1) {
		if (label_is_root(right_label)) {
			return 1;
		}
		
		if (label_compare(left_label, right_label) != 0) {
			return 0;
		}

		left_label = label_next(left_label);
		right_label = label_next(right_label);
	}
}


const uint8_t *
dname_label(const dname_type *dname, size_t index)
{
	const uint8_t *result;
	size_t label_count = dname_label_count(dname);

	assert(index < label_count);
	
	result = dname_name(dname);
	while (label_count - 1 > index) {
		result = label_next(result);
		--label_count;
	}

	return result;
}


int
dname_compare(const dname_type *left, const dname_type *right)
{
	int result;
	const uint8_t *left_label;
	const uint8_t *right_label;
	
	assert(left);
	assert(right);

	if (left == right) {
		return 0;
	}

	left_label = dname_canonical_name(left);
	right_label = dname_canonical_name(right);
	while (1) {
		result = label_compare(left_label, right_label);
		if (result) {
			return result;
		} else if (label_is_root(left_label)) {
			assert(label_is_root(right_label));
			return 0;
		}

		left_label = label_next(left_label);
		right_label = label_next(right_label);
	}
}

int
dname_compare_void(const void *left, const void *right)
{
	return dname_compare((const dname_type *) left,
			     (const dname_type *) right);
}

uint8_t
dname_label_match_count(const dname_type *left, const dname_type *right)
{
	uint8_t i;
	const uint8_t *left_label;
	const uint8_t *right_label;
	
	assert(left);
	assert(right);

	left_label = dname_canonical_name(left);
	right_label = dname_canonical_name(right);

	i = 1;
	while (1) { 
		if (label_compare(left_label, right_label) != 0) {
			return i;
		}

		if (label_is_root(left_label)) {
			assert(label_is_root(right_label));
			return i;
		}

		++i;
		left_label = label_next(left_label);
		right_label = label_next(right_label);
	}
}

const char *
dname_to_string(const dname_type *dname, const dname_type *origin)
{
	static char buf[MAXDOMAINLEN * 5];
	size_t i;
	size_t labels_to_convert = dname_label_count(dname);
	int absolute;
	char *dst;
	const uint8_t *src;

	if (dname_is_root(dname) == 1) {
		strcpy(buf, ".");
		return buf;
	}
	
	if (origin && dname_is_subdomain(dname, origin)) {
		int common_labels = dname_label_match_count(dname, origin);
		labels_to_convert = labels_to_convert - common_labels;
		absolute = 0;
	} else {
		--labels_to_convert;
		absolute = 1;
	}

	dst = buf;
	src = dname_name(dname);
	for (i = 0; i < labels_to_convert; ++i) {
		size_t len = label_length(src);
		size_t j;
		++src;
		for (j = 0; j < len; ++j) {
			char ch = (char) *src++;
			if (isalnum(ch) || ch == '-' || ch == '_') {
				*dst++ = ch;
			} else if (isgraph(ch)) {
				*dst++ = '\\';
				*dst++ = ch;
			} else {
				snprintf(dst, 5, "\\%03u", (unsigned) ch);
				dst += 4;
			}
		}
		*dst++ = '.';
	}
	if (absolute) {
		*dst = '\0';
	} else {
		*--dst = '\0';
	}
	return buf;
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

	return dname_make(region, temp);
}
         

const dname_type *
dname_concatenate(region_type *region,
		  const dname_type *left,
		  const dname_type *right)
{
	uint8_t temp[MAXDOMAINLEN];

	assert(dname_length(left) + dname_length(right) - 1 <= MAXDOMAINLEN);
	
	memcpy(temp, dname_name(left), dname_length(left) - 1);
	memcpy(temp + dname_length(left) - 1, dname_name(right),
	       dname_length(right));

	return dname_make(region, temp);
}
