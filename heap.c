/*
 * $Id: heap.c,v 1.3 2002/02/04 09:57:37 alexis Exp $
 *
 * heap.c -- generic heapionary based on red-black tree
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

#include "heap.h"

#define	BLACK	0
#define	RED	1

dnode_t	heap_null_node = {HEAP_NULL, HEAP_NULL, HEAP_NULL, BLACK, NULL, NULL};

/*
 * Creates a new heapionary, intializes and returns a pointer to it.
 *
 * Return NULL if mallocf() fails.
 *
 */
heap_t *
heap_create(mallocf, cmpf)
	void *(*mallocf)(size_t);
	int (*cmpf)(void *, void *);
{
	heap_t *heap;

	/* Allocate memory for it */
	if((heap = mallocf(sizeof(heap_t))) == NULL) {
		return NULL;
	}

	/* Initialize it */
	heap->root = HEAP_NULL;
	heap->count = 0;
	heap->mallocf = mallocf;
	heap->cmp = cmpf;

	return heap;
};

/*
 * Rotates the node to the left.
 *
 */
void
heap_rotate_left(heap, node)
	heap_t *heap;
	dnode_t *node;
{
	dnode_t *right = node->right;
	node->right = right->left;
	if(right->left != HEAP_NULL)
		right->left->parent = node;

	right->parent = node->parent;

	if(node->parent != HEAP_NULL) {
		if(node == node->parent->left) {
			node->parent->left = right;
		} else  {
			node->parent->right = right;
		}
	} else {
		heap->root = right;
	}
	right->left = node;
	node->parent = right;
};

/*
 * Rotates the node to the right.
 *
 */
void
heap_rotate_right(heap, node)
	heap_t *heap;
	dnode_t *node;
{
	dnode_t *left = node->left;
	node->left = left->right;
	if(left->right != HEAP_NULL)
		left->right->parent = node;

	left->parent = node->parent;

	if(node->parent != HEAP_NULL) {
		if(node == node->parent->right) {
			node->parent->right = left;
		} else  {
			node->parent->left = left;
		}
	} else {
		heap->root = left;
	}
	left->right = node;
	node->parent = left;
};

void
heap_insert_fixup(heap, node)
	heap_t *heap;
	dnode_t *node;
{
	dnode_t	*uncle;

	/* While not at the root and need fixing... */
	while(node != heap->root && node->parent->color == RED) {
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
					heap_rotate_left(heap, node);
				}
				/* Now we're the left child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				heap_rotate_right(heap, node->parent->parent);
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
					heap_rotate_right(heap, node);
				}
				/* Now we're the right child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				heap_rotate_left(heap, node->parent->parent);
			}
		}
	}
	heap->root->color = BLACK;
}


/*
 * Inserts a node into a heapionary.
 *
 * Returns if heap->mallocf() fails or the pointer to the newly added
 * data otherwise.
 *
 * If told to overwrite will replace the duplicate key and data with
 * the new values (thus will NOT destroy the existing node first),
 * otherwise will return the pointer to the data of already existing
 * data.
 *
 */
void *
heap_insert(heap, key, data, overwrite)
	heap_t *heap;
	void *key, *data;
	int overwrite;
{
	/* XXX Not necessary, but keeps compiler quiet... */
	int r = 0;

	/* We start at the root of the tree */
	dnode_t	*node = heap->root;
	dnode_t	*parent = HEAP_NULL;

	/* Lets find the new parent... */
	while(node != HEAP_NULL) {
		/* Compare two keys, do we have a duplicate? */
		if((r = heap->cmp(key, node->key)) == 0) {
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
	if((node = heap->mallocf(sizeof(dnode_t))) == NULL) {
		return NULL;
	}

	node->parent = parent;
	node->left = node->right = HEAP_NULL;
	node->color = RED;
	node->key = key;
	node->data = data;
	heap->count++;

	/* Insert it into the tree... */
	if(parent != HEAP_NULL) {
		if(r < 0) {
			parent->left = node;
		} else {
			parent->right = node;
		}
	} else {
		heap->root = node;
	}

	/* Fix up the red-black properties... */
	heap_insert_fixup(heap, node);

	return node->data;
};

/*
 * Searches the heapionary, returns the data if key is found or NULL otherwise.
 *
 */
void *
heap_search(heap, key)
	heap_t *heap;
	void *key;
{
	int r;
	dnode_t *node;

	/* We start at root... */
	node = heap->root;

	/* While there are children... */
	while(node != HEAP_NULL) {
		if((r = heap->cmp(key, node->key)) == 0) {
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
 * Finds the first element in the heapionary
 *
 */
dnode_t *
heap_first(heap)
	heap_t *heap;
{
	dnode_t *node;

	for(node = heap->root; node->left != HEAP_NULL; node = node->left);
	return node;
}

/*
 * Returns the next node...
 *
 */
dnode_t *
heap_next(node)
	dnode_t *node;
{
	dnode_t *parent;

	if(node->right != HEAP_NULL) {
		/* One right, then keep on going left... */
		for(node = node->right; node->left != HEAP_NULL; node = node->left);
	} else {
		parent = node->parent;
		while(parent != HEAP_NULL && node == parent->right) {
			node = parent;
			parent = parent->parent;
		}
		node = parent;
	}
	return node;
}

/* void heap_delete __P((heap_t *, void *, int, int)); */
void
heap_destroy(heap, freekeys, freedata)
	heap_t *heap;
	int freekeys;
	int freedata;
{
	dnode_t *parent;
	dnode_t *node;

	if(heap == NULL) return;
	node = heap->root;

	while(node != HEAP_NULL) {
		parent = node->parent;
		if(node->left != HEAP_NULL) {
			/* Go all the way to the left... */
			node = node->left;
		} else if(node->right != HEAP_NULL) {
			/* Then to the right... */
			node = node->right;
		} else {
			if(freekeys)
				free(node->key);
			if(freedata)
				free(node->data);
			free(node);

			if(parent != HEAP_NULL) {
				if(parent->left == node) {
					parent->left = HEAP_NULL;
				} else {
					parent->right = HEAP_NULL;
				}
			}
			node = parent;
		}
	}
	free(heap);
}

#ifdef TEST

#define	BUFSZ	1000

int
main(argc, argv)
	int argc;
	char **argv;
{
	heap_t *heap;
	char buf[BUFSZ];
	char *key, *data;

	if((heap = heap_create(malloc, strcmp)) == NULL) {
		perror("cannot create heapionary");
		exit(1);
	}

	while(fgets(buf, BUFSZ - 1, stdin)) {
		if(heap_insert(heap, strdup(buf), strdup(buf), 1) == NULL) {
			perror("cannot insert into a heapionary");
			exit(1);
		}
	}
	HEAP_WALK(heap, key, data) {
		printf("%s", key);
	}
	heap_destroy(heap, 1, 1);
	return 0;
}
#endif
