/*
 * $Id: rbtree.h,v 1.14 2003/07/01 13:18:37 erik Exp $
 *
 * rbtree.h -- generic red-black tree
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

#ifndef _RBTREE_H_
#define	_RBTREE_H_

typedef struct rbnode_t rbnode_t;
struct rbnode_t {
	rbnode_t *parent;
	rbnode_t *left;
	rbnode_t *right;
	int	color;
	void	*key;
	void	*data;
};

#define	RBTREE_NULL &rbtree_null_node
extern	rbnode_t	rbtree_null_node;

typedef struct rbtree_t rbtree_t;
struct rbtree_t {
	/* The root of the red-black tree */
	rbnode_t	*root;

	/* The number of the nodes in the tree */
	unsigned long count;

	/* Current node for walks... */
	rbnode_t	*_node;

	/* Free and compare functions */
	void *(*mallocf)(size_t);
	int (*cmp) (const void *, const void *);
};

#define	rbtree_last() RBTREE_NULL
/* rbtree.c */
rbtree_t *rbtree_create(void *(*mallocf)(size_t), int (*cmpf)(const void *, const void *));
void *rbtree_insert(rbtree_t *rbtree, void *key, void *data, int overwrite);
void *rbtree_search(rbtree_t *rbtree, const void *key);
void rbtree_destroy(rbtree_t *rbtree, int freekeys, int freedata);
rbnode_t *rbtree_first(rbtree_t *rbtree);
rbnode_t *rbtree_next(rbnode_t *rbtree);

#define	RBTREE_WALK(rbtree, k, d) \
	for((rbtree)->_node = rbtree_first(rbtree);\
		(rbtree)->_node != rbtree_last() && ((k) = (rbtree)->_node->key) && \
		((d) = (rbtree)->_node->data); (rbtree)->_node = rbtree_next((rbtree)->_node))

#endif /* _RBTREE_H_ */
