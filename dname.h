/*
 * dname.h -- domain name operations
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

#ifndef _DNAME_H_
#define _DNAME_H_

#include <assert.h>

#include "heap.h"
#include "region-allocator.h"

#define DNAME_NORMALIZE        tolower

/*
 * Domain names stored in memory add some additional information to be
 * able to quickly index and compare by label.
 */
typedef struct dname dname_type;
struct dname
{
	/*
	 * The actual name in wire format (a sequence of label, each
	 * prefixed by a length byte, terminated by a zero length
	 * label).
	 */
	const uint8_t *name;
	
	/*
	 * The size (in bytes) of the domain name in wire format.
	 */
	uint8_t name_size;
	
	/*
	 * The number of labels in this domain name (including the
	 * root label).
	 */
	uint8_t label_count;
};

/*
 * Construct a new domain name based on NAME in wire format.  NAME
 * cannot contain (compression) pointers.
 *
 * Pre: NAME != NULL.
 */
const dname_type *dname_make(region_type *region, const uint8_t *name, int copy);

/*
 * Construct a new domain name based on the ASCII representation NAME.
 * If ORIGIN is not NULL and NAME is not terminated by a "." the
 * ORIGIN is appended to the result.  NAME can contain escape
 * sequences.
 *
 * Returns NULL on failure.  Otherwise a newly allocated domain name
 * is returned.
 *
 * Pre: name != NULL.
 */
const dname_type *dname_parse(region_type *region,
			      const char *name,
			      const dname_type *origin);

/*
 * Return NULL if DNAME is NULL or a copy of DNAME otherwise.
 */
const dname_type *dname_copy(region_type *region, const dname_type *dname);

/*
 * Offsets into NAME for each label starting with the most
 * significant label (the root label, followed by the TLD,
 * etc).
 */
static inline const uint8_t *
dname_label_offsets(const dname_type *dname)
{
	return (const uint8_t *) ((const char *) dname + sizeof(dname_type));
}

/*
 * Return the label for DNAME specified by LABEL_INDEX.  The first
 * label (LABEL_INDEX == 0) is the root label, the next label is the
 * TLD, etc.
 *
 * Pre: dname != NULL && label_index < dname->label_count.
 */
static inline const uint8_t *
dname_label(const dname_type *dname, uint8_t label)
{
	uint8_t label_index;
	
	assert(dname != NULL);
	assert(label < dname->label_count);

	label_index = dname_label_offsets(dname)[label];
	assert(label_index < dname->name_size);
		
	return dname->name + label_index;
}

/*
 * Compare two domain names.  The comparison defines a lexographical
 * ordering based on the domain name's labels, starting with the most
 * significant label.
 *
 * Return < 0 if LEFT < RIGHT, 0 if LEFT == RIGHT, and > 0 if LEFT >
 * RIGHT.  The comparison is case insensitive.
 *
 * Pre: left != NULL && right != NULL
 */
int dname_compare(const dname_type *left, const dname_type *right);

static inline const uint8_t *
dname_labels(const dname_type *dname)
{
	return dname->name;
}

/*
 * Compare two labels.  The comparison defines a lexographical
 * ordering based on the characters in the labels.
 *
 * Return < 0 if LEFT < RIGHT, 0 if LEFT == RIGHT, and > 0 if LEFT >
 * RIGHT.  The comparison is case insensitive.
 *
 * Pre: left != NULL && right != NULL
 *      label_is_normal(left) && label_is_normal(right)
 */
int label_compare(const uint8_t *left, const uint8_t *right);

/*
 * Is LABEL a normal LABEL (not a pointer or reserved)?
 *
 * Pre: label != NULL;
 */
static inline int
label_is_normal(const uint8_t *label)
{
	assert(label);
	return (label[0] & 0xc0) == 0;
}

/*
 * Is LABEL a pointer?
 *
 * Pre: label != NULL;
 */
static inline int
label_is_pointer(const uint8_t *label)
{
	assert(label);
	return (label[0] & 0xc0) == 0xc0;
}

/*
 * LABEL's pointer location.
 *
 * Pre: label != NULL && label_is_pointer(label)
 */
static inline uint16_t
label_pointer_location(const uint8_t *label)
{
	assert(label);
	assert(label_is_pointer(label));
	return ((uint16_t) (label[0] & ~0xc0) << 8) | (uint16_t) label[1];
}

/*
 * Length of LABEL.
 *
 * Pre: label != NULL && label_is_normal(label)
 */
static inline uint8_t
label_length(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	return label[0];
}

/*
 * The data of LABEL.
 *
 * Pre: label != NULL && label_is_normal(label)
 */
static inline const uint8_t *
label_data(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	return label + 1;
}

/*
 * Is LABEL the root label?
 *
 * Pre: label != NULL
 */
static inline int
label_is_root(const uint8_t *label)
{
	assert(label);
	return label[0] == 0;
}

/*
 * Is LABEL the wildcard label?
 *
 * Pre: label != NULL
 */
static inline int
label_is_wildcard(const uint8_t *label)
{
	assert(label);
	return label[0] == 1 && label[1] == '*';
}

/*
 * The next label of LABEL.
 *
 * Pre: label != NULL
 *      label_is_normal(label)
 *      !label_is_root(label)
 */
static inline const uint8_t *
label_next(const uint8_t *label)
{
	assert(label);
	assert(label_is_normal(label));
	assert(!label_is_root(label));
	return label + label_length(label) + 1;
}


/*
 * A domain name tree supporting fast insert and search operations.
 */
typedef struct dname_tree dname_tree_type;
struct dname_tree
{
	region_type *region;
	dname_tree_type *parent;
	heap_t *children;
	dname_tree_type *wildcard_child;
	uint8_t label_count;
	void *data;
};

/*
 * Create a new dname_tree containing only the root domain.
 */
dname_tree_type *dname_tree_create(region_type *region);

/*
 * Search the dname tree a match and the closest encloser.
 */
int dname_tree_search(dname_tree_type *dt,
		      const dname_type *dname,
		      dname_tree_type **less_equal,
		      dname_tree_type **closest_encloser);

/*
 * Insert or update the data associated with a dname.  Empty data
 * nodes are inserted for parent dnames that are not yet in the tree.
 *
 * The dname's tree node is returned.
 */
dname_tree_type *dname_tree_update(dname_tree_type *dt,
				   const dname_type *dname,
				   void *data);

const char *dname_to_string(const uint8_t *dname);

int dnamecmp(const void *a, const void *b);
const char *dnamestr(const uint8_t *dname);
const uint8_t *strdname(const char *s, const uint8_t *o);
uint8_t *dnamedup(const uint8_t *dname);

#endif /* _DNAME_H_ */
