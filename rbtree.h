/*
 * $Id: rbtree.h,v 1.8 2002/04/02 10:00:16 alexis Exp $
 *
 * rbtree.h -- generic red-black tree
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

#ifndef _RBTREE_H_
#define	_RBTREE_H_

#if !defined(__P)
#	if defined(__STDC__)
#		define __P(protos)     protos          /* full-blown ANSI C */
# 	else
# 		define __P(protos)
# 	endif
#endif

#ifndef	NULL
#define	NULL	(void *)0
#endif

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
	void *(*mallocf)();
	int (*cmp) ();
};

rbtree_t *rbtree_create __P((void *(*)(), int (*)()));
void *rbtree_insert __P((rbtree_t *, void *, void *, int));
void *rbtree_search __P((rbtree_t *, void *));
void rbtree_delete __P((rbtree_t *, void *, int, int));
void rbtree_destroy __P((rbtree_t *, int, int));
rbnode_t *rbtree_first __P((rbtree_t *));
rbnode_t *rbtree_next __P((rbnode_t *));
#define	rbtree_last() RBTREE_NULL

#define	RBTREE_WALK(rbtree, k, d) \
	for((rbtree)->_node = rbtree_first(rbtree);\
		(rbtree)->_node != rbtree_last() && ((k) = (rbtree)->_node->key) && \
		((d) = (rbtree)->_node->data); (rbtree)->_node = rbtree_next((rbtree)->_node))

#endif /* _RBTREE_H_ */
