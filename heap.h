/*
 * $Id: heap.h,v 1.12 2002/05/23 13:20:57 alexis Exp $
 *
 * heap.h -- generic heap
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

#if !defined(USE_HEAP_RBTREE) && !defined(USE_HEAP_HASH)
#define	USE_HEAP_RBTREE
#endif

#if defined(USE_HEAP_RBTREE)

#include "rbtree.h"

#define	heap_t	rbtree_t
#define	heap_create	rbtree_create
#define	heap_insert	rbtree_insert
#define	heap_search	rbtree_search
#define	heap_delete	rbtree_delete
#define	heap_destroy	rbtree_destroy
#define	heap_first	rbtree_first
#define	heap_next	rbtree_next
#define	heap_last	rbtree_last
#define	HEAP_WALK	RBTREE_WALK

#else
# if defined(USE_HEAP_HASH)

#include "hash.h"

#define	heap_t	hash_t
#define	heap_create	hash_create
#define	heap_insert	hash_insert
#define	heap_search	hash_search
#define	heap_delete	hash_delete
#define	heap_destroy	hash_destroy
#define	heap_first	hash_first
#define	heap_next	hash_next
#define	heap_last	hash_last
#define	HEAP_WALK	HASH_WALK

# endif
#endif

#endif /* _HEAP_H_ */
