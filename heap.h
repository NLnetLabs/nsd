/*
 * $Id: heap.h,v 1.4 2002/02/04 09:57:37 alexis Exp $
 *
 * heap.h -- generic heapionary based on red-black tree
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

#ifndef _HEAP_H_
#define	_HEAP_H_

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

typedef struct dnode_t dnode_t;
struct dnode_t {
	dnode_t *parent;
	dnode_t *left;
	dnode_t *right;
	int	color;
	void	*key;
	void	*data;
};

#define	HEAP_NULL &heap_null_node
extern	dnode_t	heap_null_node;

typedef struct heap_t heap_t;
struct heap_t {
	/* The root of the red-black tree */
	dnode_t	*root;

	/* The number of the nodes in the tree */
	long long count;

	/* Current node for walks... */
	dnode_t	*_node;

	/* Free and compare functions */
	void *(*mallocf)();
	int (*cmp) ();
};

heap_t *heap_create __P((void *(*)(), int (*)()));
void *heap_insert __P((heap_t *, void *, void *, int));
void *heap_search __P((heap_t *, void *));
void heap_delete __P((heap_t *, void *, int, int));
void heap_destroy __P((heap_t *, int, int));
dnode_t *heap_first __P((heap_t *));
dnode_t *heap_next __P((dnode_t *));
#define	heap_last() HEAP_NULL

#define	HEAP_WALK(heap, k, d) \
	for((heap)->_node = heap_first(heap), (k) = (heap)->_node->key, (d) = (heap)->_node->data;\
		(heap)->_node != heap_last(); \
		(heap)->_node = heap_next((heap)->_node), (k) = (heap)->_node->key, (d) = (heap)->_node->data)

#endif /* _HEAP_H_ */
