/*
 * rbtree.c -- generic red black tree
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <stdlib.h>

#include "rbtree.h"

#define	BLACK	0
#define	RED	1

rbnode_t	rbtree_null_node = {
	RBTREE_NULL,		/* Parent.  */
	RBTREE_NULL,		/* Left.  */
	RBTREE_NULL,		/* Right.  */
	NULL,			/* Key.  */
	BLACK			/* Color.  */
};

static void rbtree_rotate_left(rbtree_t *rbtree, rbnode_t *node);
static void rbtree_rotate_right(rbtree_t *rbtree, rbnode_t *node);
static void rbtree_insert_fixup(rbtree_t *rbtree, rbnode_t *node);

/*
 * Creates a new red black tree, intializes and returns a pointer to it.
 *
 * Return NULL on failure.
 *
 */
rbtree_t *
rbtree_create (region_type *region, int (*cmpf)(const void *, const void *))
{
	rbtree_t *rbtree;

	/* Allocate memory for it */
	rbtree = (rbtree_t *) region_alloc(region, sizeof(rbtree_t));
	if (!rbtree) {
		return NULL;
	}

	/* Initialize it */
	rbtree->root = RBTREE_NULL;
	rbtree->count = 0;
	rbtree->region = region;
	rbtree->cmp = cmpf;

	return rbtree;
}

/*
 * Rotates the node to the left.
 *
 */
static void
rbtree_rotate_left(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t *right = node->right;
	node->right = right->left;
	if (right->left != RBTREE_NULL)
		right->left->parent = node;

	right->parent = node->parent;

	if (node->parent != RBTREE_NULL) {
		if (node == node->parent->left) {
			node->parent->left = right;
		} else  {
			node->parent->right = right;
		}
	} else {
		rbtree->root = right;
	}
	right->left = node;
	node->parent = right;
}

/*
 * Rotates the node to the right.
 *
 */
static void
rbtree_rotate_right(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t *left = node->left;
	node->left = left->right;
	if (left->right != RBTREE_NULL)
		left->right->parent = node;

	left->parent = node->parent;

	if (node->parent != RBTREE_NULL) {
		if (node == node->parent->right) {
			node->parent->right = left;
		} else  {
			node->parent->left = left;
		}
	} else {
		rbtree->root = left;
	}
	left->right = node;
	node->parent = left;
}

static void
rbtree_insert_fixup(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t	*uncle;

	/* While not at the root and need fixing... */
	while (node != rbtree->root && node->parent->color == RED) {
		/* If our parent is left child of our grandparent... */
		if (node->parent == node->parent->parent->left) {
			uncle = node->parent->parent->right;

			/* If our uncle is red... */
			if (uncle->color == RED) {
				/* Paint the parent and the uncle black... */
				node->parent->color = BLACK;
				uncle->color = BLACK;

				/* And the grandparent red... */
				node->parent->parent->color = RED;

				/* And continue fixing the grandparent */
				node = node->parent->parent;
			} else {				/* Our uncle is black... */
				/* Are we the right child? */
				if (node == node->parent->right) {
					node = node->parent;
					rbtree_rotate_left(rbtree, node);
				}
				/* Now we're the left child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				rbtree_rotate_right(rbtree, node->parent->parent);
			}
		} else {
			uncle = node->parent->parent->left;

			/* If our uncle is red... */
			if (uncle->color == RED) {
				/* Paint the parent and the uncle black... */
				node->parent->color = BLACK;
				uncle->color = BLACK;

				/* And the grandparent red... */
				node->parent->parent->color = RED;

				/* And continue fixing the grandparent */
				node = node->parent->parent;
			} else {				/* Our uncle is black... */
				/* Are we the right child? */
				if (node == node->parent->left) {
					node = node->parent;
					rbtree_rotate_right(rbtree, node);
				}
				/* Now we're the right child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				rbtree_rotate_left(rbtree, node->parent->parent);
			}
		}
	}
	rbtree->root->color = BLACK;
}


/*
 * Inserts a node into a red black tree.
 *
 * Returns NULL on failure or the pointer to the newly added node
 * otherwise.
 */
rbnode_t *
rbtree_insert (rbtree_t *rbtree, rbnode_t *data)
{
	/* XXX Not necessary, but keeps compiler quiet... */
	int r = 0;

	/* We start at the root of the tree */
	rbnode_t	*node = rbtree->root;
	rbnode_t	*parent = RBTREE_NULL;

	/* Lets find the new parent... */
	while (node != RBTREE_NULL) {
		/* Compare two keys, do we have a duplicate? */
		if ((r = rbtree->cmp(data->key, node->key)) == 0) {
			return NULL;
		}
		parent = node;

		if (r < 0) {
			node = node->left;
		} else {
			node = node->right;
		}
	}

	/* Initialize the new node */
	data->parent = parent;
	data->left = data->right = RBTREE_NULL;
	data->color = RED;
	rbtree->count++;

	/* Insert it into the tree... */
	if (parent != RBTREE_NULL) {
		if (r < 0) {
			parent->left = data;
		} else {
			parent->right = data;
		}
	} else {
		rbtree->root = data;
	}

	/* Fix up the red-black properties... */
	rbtree_insert_fixup(rbtree, data);

	return data;
}

/*
 * Searches the red black tree, returns the data if key is found or NULL otherwise.
 *
 */
rbnode_t *
rbtree_search (rbtree_t *rbtree, const void *key)
{
	rbnode_t *node;

	if (rbtree_find_less_equal(rbtree, key, &node)) {
		return node;
	} else {
		return NULL;
	}
}

int
rbtree_find_less_equal(rbtree_t *rbtree, const void *key, rbnode_t **result)
{
	int r;
	rbnode_t *node;

	assert(result);
	
	/* We start at root... */
	node = rbtree->root;

	*result = NULL;
	
	/* While there are children... */
	while (node != RBTREE_NULL) {
		r = rbtree->cmp(key, node->key);
		if (r == 0) {
			/* Exact match */
			*result = node;
			return 1;
		} 
		if (r < 0) {
			node = node->left;
		} else {
			/* Temporary match */
			*result = node;
			node = node->right;
		}
	}
	return 0;
}

/*
 * Finds the first element in the red black tree
 *
 */
rbnode_t *
rbtree_first (rbtree_t *rbtree)
{
	rbnode_t *node;

	for (node = rbtree->root; node->left != RBTREE_NULL; node = node->left);
	return node;
}

rbnode_t *
rbtree_last (rbtree_t *rbtree)
{
	rbnode_t *node;

	for (node = rbtree->root; node->right != RBTREE_NULL; node = node->right);
	return node;
}

/*
 * Returns the next node...
 *
 */
rbnode_t *
rbtree_next (rbnode_t *node)
{
	rbnode_t *parent;

	if (node->right != RBTREE_NULL) {
		/* One right, then keep on going left... */
		for (node = node->right; node->left != RBTREE_NULL; node = node->left);
	} else {
		parent = node->parent;
		while (parent != RBTREE_NULL && node == parent->right) {
			node = parent;
			parent = parent->parent;
		}
		node = parent;
	}
	return node;
}

rbnode_t *
rbtree_previous(rbnode_t *node)
{
	rbnode_t *parent;

	if (node->left != RBTREE_NULL) {
		/* One left, then keep on going right... */
		for (node = node->left; node->right != RBTREE_NULL; node = node->right);
	} else {
		parent = node->parent;
		while (parent != RBTREE_NULL && node == parent->left) {
			node = parent;
			parent = parent->parent;
		}
		node = parent;
	}
	return node;
}
