/*
 * $Id: rbtree.c,v 1.5 2002/02/13 11:14:48 alexis Exp $
 *
 * rbtree.c -- generic red black tree
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
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

#ifdef TEST
#include <stdio.h>
#include <string.h>
#endif

#include <stdlib.h>

#include "rbtree.h"

#define	BLACK	0
#define	RED	1

rbnode_t	rbtree_null_node = {RBTREE_NULL, RBTREE_NULL, RBTREE_NULL, BLACK, NULL, NULL};

/*
 * Creates a new red black tree, intializes and returns a pointer to it.
 *
 * Return NULL if mallocf() fails.
 *
 */
rbtree_t *
rbtree_create (void *(*mallocf)(size_t), int (*cmpf)(void *, void *))
{
	rbtree_t *rbtree;

	/* Allocate memory for it */
	if((rbtree = mallocf(sizeof(rbtree_t))) == NULL) {
		return NULL;
	}

	/* Initialize it */
	rbtree->root = RBTREE_NULL;
	rbtree->count = 0;
	rbtree->mallocf = mallocf;
	rbtree->cmp = cmpf;

	return rbtree;
};

/*
 * Rotates the node to the left.
 *
 */
void rbtree_rotate_left(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t *right = node->right;
	node->right = right->left;
	if(right->left != RBTREE_NULL)
		right->left->parent = node;

	right->parent = node->parent;

	if(node->parent != RBTREE_NULL) {
		if(node == node->parent->left) {
			node->parent->left = right;
		} else  {
			node->parent->right = right;
		}
	} else {
		rbtree->root = right;
	}
	right->left = node;
	node->parent = right;
};

/*
 * Rotates the node to the right.
 *
 */
void rbtree_rotate_right(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t *left = node->left;
	node->left = left->right;
	if(left->right != RBTREE_NULL)
		left->right->parent = node;

	left->parent = node->parent;

	if(node->parent != RBTREE_NULL) {
		if(node == node->parent->right) {
			node->parent->right = left;
		} else  {
			node->parent->left = left;
		}
	} else {
		rbtree->root = left;
	}
	left->right = node;
	node->parent = left;
};

void rbtree_insert_fixup(rbtree_t *rbtree, rbnode_t *node)
{
	rbnode_t	*uncle;

	/* While not at the root and need fixing... */
	while(node != rbtree->root && node->parent->color == RED) {
		/* If our parent is left child of our grandparent... */
		if(node->parent == node->parent->parent->left) {
			uncle = node->parent->parent->right;

			/* If our uncle is red... */
			if(uncle->color == RED) {
				/* Paint the parent and the uncle black... */
				node->parent->color = BLACK;
				uncle->color = BLACK;

				/* And the grandparent red... */
				node->parent->parent->color = RED;

				/* And continue fixing the grandparent */
				node = node->parent->parent;
			} else {				/* Our uncle is black... */
				/* Are we the right child? */
				if(node == node->parent->right) {
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
			if(uncle->color == RED) {
				/* Paint the parent and the uncle black... */
				node->parent->color = BLACK;
				uncle->color = BLACK;

				/* And the grandparent red... */
				node->parent->parent->color = RED;

				/* And continue fixing the grandparent */
				node = node->parent->parent;
			} else {				/* Our uncle is black... */
				/* Are we the right child? */
				if(node == node->parent->left) {
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
 * Returns if rbtree->mallocf() fails or the pointer to the newly added
 * data otherwise.
 *
 * If told to overwrite will replace the duplicate key and data with
 * the new values (thus will NOT destroy the existing node first),
 * otherwise will return the pointer to the data of already existing
 * data.
 *
 */
void *
rbtree_insert (rbtree_t *rbtree, void *key, void *data, int overwrite)
{
	/* XXX Not necessary, but keeps compiler quiet... */
	int r = 0;

	/* We start at the root of the tree */
	rbnode_t	*node = rbtree->root;
	rbnode_t	*parent = RBTREE_NULL;

	/* Lets find the new parent... */
	while(node != RBTREE_NULL) {
		/* Compare two keys, do we have a duplicate? */
		if((r = rbtree->cmp(key, node->key)) == 0) {
			if(overwrite) {
				node->key = key;
				node->data = data;
			}
			return node->data;
		}
		parent = node;

		if(r < 0) {
			node = node->left;
		} else {
			node = node->right;
		}
	}

	/* Create the new node */
	if((node = rbtree->mallocf(sizeof(rbnode_t))) == NULL) {
		return NULL;
	}

	node->parent = parent;
	node->left = node->right = RBTREE_NULL;
	node->color = RED;
	node->key = key;
	node->data = data;
	rbtree->count++;

	/* Insert it into the tree... */
	if(parent != RBTREE_NULL) {
		if(r < 0) {
			parent->left = node;
		} else {
			parent->right = node;
		}
	} else {
		rbtree->root = node;
	}

	/* Fix up the red-black properties... */
	rbtree_insert_fixup(rbtree, node);

	return node->data;
};

/*
 * Searches the red black tree, returns the data if key is found or NULL otherwise.
 *
 */
void *
rbtree_search (rbtree_t *rbtree, void *key)
{
	int r;
	rbnode_t *node;

	/* We start at root... */
	node = rbtree->root;

	/* While there are children... */
	while(node != RBTREE_NULL) {
		if((r = rbtree->cmp(key, node->key)) == 0) {
			return node->data;
		}
		if(r < 0) {
			node = node->left;
		} else {
			node = node->right;
		}
	}
	return NULL;
}

/*
 * Finds the first element in the red black tree
 *
 */
rbnode_t *
rbtree_first(rbtree)
	rbtree_t *rbtree;
{
	rbnode_t *node;

	for(node = rbtree->root; node->left != RBTREE_NULL; node = node->left);
	return node;
}

/*
 * Returns the next node...
 *
 */
rbnode_t *
rbtree_next(node)
	rbnode_t *node;
{
	rbnode_t *parent;

	if(node->right != RBTREE_NULL) {
		/* One right, then keep on going left... */
		for(node = node->right; node->left != RBTREE_NULL; node = node->left);
	} else {
		parent = node->parent;
		while(parent != RBTREE_NULL && node == parent->right) {
			node = parent;
			parent = parent->parent;
		}
		node = parent;
	}
	return node;
}

/* void rbtree_delete __P((rbtree_t *, void *, int, int)); */
void 
rbtree_destroy (rbtree_t *rbtree, int freekeys, int freedata)
{
	rbnode_t *parent;
	rbnode_t *node;

	if(rbtree == NULL) return;
	node = rbtree->root;

	while(node != RBTREE_NULL) {
		parent = node->parent;
		if(node->left != RBTREE_NULL) {
			/* Go all the way to the left... */
			node = node->left;
		} else if(node->right != RBTREE_NULL) {
			/* Then to the right... */
			node = node->right;
		} else {
			if(freekeys)
				free(node->key);
			if(freedata)
				free(node->data);
			free(node);

			if(parent != RBTREE_NULL) {
				if(parent->left == node) {
					parent->left = RBTREE_NULL;
				} else {
					parent->right = RBTREE_NULL;
				}
			}
			node = parent;
		}
	}
	free(rbtree);
}

#ifdef TEST

#define	BUFSZ	1000

int 
main (int argc, char **argv)
{
	rbtree_t *rbtree;
	char buf[BUFSZ];
	char *key, *data;

	if((rbtree = rbtree_create(malloc, strcmp)) == NULL) {
		perror("cannot create red black tree");
		exit(1);
	}

	while(fgets(buf, BUFSZ - 1, stdin)) {
		if(rbtree_insert(rbtree, strdup(buf), strdup(buf), 1) == NULL) {
			perror("cannot insert into a red black tree");
			exit(1);
		}
	}
	RBTREE_WALK(rbtree, key, data) {
		printf("%s", key);
	}
	rbtree_destroy(rbtree, 1, 1);
	return 0;
}
#endif
