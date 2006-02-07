/*
 * heap.h -- generic heap
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _HEAP_H_
#define	_HEAP_H_

#include "rbtree.h"

#define	heap_t	        rbtree_t
#define heapnode_t      rbnode_t
#define	heap_create	rbtree_create
#define	heap_insert	rbtree_insert
#define	heap_search	rbtree_search
#define	heap_delete	rbtree_delete
#define	heap_first	rbtree_first
#define	heap_last	rbtree_last
#define	heap_next	rbtree_next
#define	heap_previous	rbtree_previous
#define	HEAP_WALK	RBTREE_WALK
#define HEAP_NULL       RBTREE_NULL

#endif /* _HEAP_H_ */
