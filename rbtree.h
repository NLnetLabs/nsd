/*
 * rbtree.h -- generic red-black tree
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _RBTREE_H_
#define	_RBTREE_H_

#include "region-allocator.h"

/*
 * This structure must be the first member of the data structure in
 * the rbtree.  This allows easy casting between an rbnode_t and the
 * user data (poor man's inheritance).
 */
typedef struct rbnode_t rbnode_t;
struct rbnode_t {
	rbnode_t   *parent;
	rbnode_t   *left;
	rbnode_t   *right;
	int	    color;
	const void *key;
};

#define	RBTREE_NULL &rbtree_null_node
extern	rbnode_t	rbtree_null_node;

typedef struct rbtree_t rbtree_t;
struct rbtree_t {
	region_type     *region;
	
	/* The root of the red-black tree */
	rbnode_t	*root;

	/* The number of the nodes in the tree */
	unsigned long count;

	/* Current node for walks... */
	rbnode_t	*_node;

	/* Key compare function */
	int (*cmp) (const void *, const void *);
};

/* rbtree.c */
rbtree_t *rbtree_create(region_type *region, int (*cmpf)(const void *, const void *));
rbnode_t *rbtree_insert(rbtree_t *rbtree, rbnode_t *data);
rbnode_t *rbtree_search(rbtree_t *rbtree, const void *key);
int rbtree_find_less_equal(rbtree_t *rbtree, const void *key, rbnode_t **result);
rbnode_t *rbtree_first(rbtree_t *rbtree);
rbnode_t *rbtree_last(rbtree_t *rbtree);
rbnode_t *rbtree_next(rbnode_t *rbtree);
rbnode_t *rbtree_previous(rbnode_t *rbtree);

#define	RBTREE_WALK(rbtree, k, d) \
	for((rbtree)->_node = rbtree_first(rbtree);\
		(rbtree)->_node != RBTREE_NULL && ((k) = (rbtree)->_node->key) && \
		((d) = (void *) (rbtree)->_node); (rbtree)->_node = rbtree_next((rbtree)->_node))

#endif /* _RBTREE_H_ */
