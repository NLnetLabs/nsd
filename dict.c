/*
 * $Id: dict.c,v 1.2 2002/01/28 16:02:59 alexis Exp $
 *
 * dict.c -- generic dictionary based on red-black tree
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

#include "dict.h"

#define	BLACK	0
#define	RED	1

dnode_t	dict_null_node = {DICT_NULL, DICT_NULL, DICT_NULL, BLACK, NULL, NULL};

/*
 * Creates a new dictionary, intializes and returns a pointer to it.
 *
 * Return NULL if mallocf() fails.
 *
 */
dict_t *
dict_create(mallocf, cmpf)
	void *(*mallocf)(size_t);
	int (*cmpf)(void *, void *);
{
	dict_t *dict;

	/* Allocate memory for it */
	if((dict = mallocf(sizeof(dict_t))) == NULL) {
		return NULL;
	}

	/* Initialize it */
	dict->root = DICT_NULL;
	dict->count = 0;
	dict->mallocf = mallocf;
	dict->cmp = cmpf;

	return dict;
};

/*
 * Rotates the node to the left.
 *
 */
void
dict_rotate_left(dict, node)
	dict_t *dict;
	dnode_t *node;
{
	dnode_t *right = node->right;
	node->right = right->left;
	if(right->left != DICT_NULL)
		right->left->parent = node;

	right->parent = node->parent;

	if(node->parent != DICT_NULL) {
		if(node == node->parent->left) {
			node->parent->left = right;
		} else  {
			node->parent->right = right;
		}
	} else {
		dict->root = right;
	}
	right->left = node;
	node->parent = right;
};

/*
 * Rotates the node to the right.
 *
 */
void
dict_rotate_right(dict, node)
	dict_t *dict;
	dnode_t *node;
{
	dnode_t *left = node->left;
	node->left = left->right;
	if(left->right != DICT_NULL)
		left->right->parent = node;

	left->parent = node->parent;

	if(node->parent != DICT_NULL) {
		if(node == node->parent->right) {
			node->parent->right = left;
		} else  {
			node->parent->left = left;
		}
	} else {
		dict->root = left;
	}
	left->right = node;
	node->parent = left;
};

void
dict_insert_fixup(dict, node)
	dict_t *dict;
	dnode_t *node;
{
	dnode_t	*uncle;

	/* While not at the root and need fixing... */
	while(node != dict->root && node->parent->color == RED) {
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
					dict_rotate_left(dict, node);
				}
				/* Now we're the left child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				dict_rotate_right(dict, node->parent->parent);
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
					dict_rotate_right(dict, node);
				}
				/* Now we're the right child, repaint and rotate... */
				node->parent->color = BLACK;
				node->parent->parent->color = RED;
				dict_rotate_left(dict, node->parent->parent);
			}
		}
	}
	dict->root->color = BLACK;
}


/*
 * Inserts a node into a dictionary.
 *
 * Returns if dict->mallocf() fails or the pointer to the newly added
 * data otherwise.
 *
 * If told to overwrite will replace the duplicate key and data with
 * the new values (thus will NOT destroy the existing node first),
 * otherwise will return the pointer to the data of already existing
 * data.
 *
 */
void *
dict_insert(dict, key, data, overwrite)
	dict_t *dict;
	void *key, *data;
	int overwrite;
{
	/* XXX Not necessary, but keeps compiler quiet... */
	int r = 0;

	/* We start at the root of the tree */
	dnode_t	*node = dict->root;
	dnode_t	*parent = DICT_NULL;

	/* Lets find the new parent... */
	while(node != DICT_NULL) {
		/* Compare two keys, do we have a duplicate? */
		if((r = dict->cmp(key, node->key)) == 0) {
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
	if((node = dict->mallocf(sizeof(dnode_t))) == NULL) {
		return NULL;
	}

	node->parent = parent;
	node->left = node->right = DICT_NULL;
	node->color = RED;
	node->key = key;
	node->data = data;
	dict->count++;

	/* Insert it into the tree... */
	if(parent != DICT_NULL) {
		if(r < 0) {
			parent->left = node;
		} else {
			parent->right = node;
		}
	} else {
		dict->root = node;
	}

	/* Fix up the red-black properties... */
	dict_insert_fixup(dict, node);

	return node->data;
};

/*
 * Searches the dictionary, returns the data if key is found or NULL otherwise.
 *
 */
void *
dict_search(dict, key)
	dict_t *dict;
	void *key;
{
	int r;
	dnode_t *node;

	/* We start at root... */
	node = dict->root;

	/* While there are children... */
	while(node != DICT_NULL) {
		if((r = dict->cmp(key, node->key)) == 0) {
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
 * Finds the first element in the dictionary
 *
 */
dnode_t *
dict_first(dict)
	dict_t *dict;
{
	dnode_t *node;

	for(node = dict->root; node->left != DICT_NULL; node = node->left);
	return node;
}

/*
 * Returns the next node...
 *
 */
dnode_t *
dict_next(node)
	dnode_t *node;
{
	dnode_t *parent;

	if(node->right != DICT_NULL) {
		/* One right, then keep on going left... */
		for(node = node->right; node->left != DICT_NULL; node = node->left);
	} else {
		parent = node->parent;
		while(parent != DICT_NULL && node == parent->right) {
			node = parent;
			parent = parent->parent;
		}
		node = parent;
	}
	return node;
}

/* void dict_delete __P((dict_t *, void *, int, int)); */
void
dict_destroy(dict, freekeys, freedata)
	dict_t *dict;
	int freekeys;
	int freedata;
{
	dnode_t *parent;
	dnode_t *node;

	if(dict == NULL) return;
	node = dict->root;

	while(node != DICT_NULL) {
		parent = node->parent;
		if(node->left != DICT_NULL) {
			/* Go all the way to the left... */
			node = node->left;
		} else if(node->right != DICT_NULL) {
			/* Then to the right... */
			node = node->right;
		} else {
			if(freekeys)
				free(node->key);
			if(freedata)
				free(node->data);
			free(node);

			if(parent != DICT_NULL) {
				if(parent->left == node) {
					parent->left = DICT_NULL;
				} else {
					parent->right = DICT_NULL;
				}
			}
			node = parent;
		}
	}
	free(dict);
}

#ifdef TEST

#define	BUFSZ	1000

int
main(argc, argv)
	int argc;
	char **argv;
{
	dict_t *dict;
	char buf[BUFSZ];
	char *key, *data;

	if((dict = dict_create(malloc, strcmp)) == NULL) {
		perror("cannot create dictionary");
		exit(1);
	}

	while(fgets(buf, BUFSZ - 1, stdin)) {
		if(dict_insert(dict, strdup(buf), strdup(buf), 1) == NULL) {
			perror("cannot insert into a dictionary");
			exit(1);
		}
	}
	DICT_WALK(dict, key, data) {
		printf("%s", key);
	}
	dict_destroy(dict, 1, 1);
}
#endif
