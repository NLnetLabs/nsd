/*
 * $Id: dict.h,v 1.1 2002/01/24 03:30:52 alexis Exp $
 *
 * dict.h -- generic dictionary based on red-black tree
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

#ifndef _DICT_H_
#define	_DICT_H_

#if !defined(__P)
#	if defined(__STDC__)
#		define __P(protos)     protos          /* full-blown ANSI C */
# 	else
# 		define __P(protos)
# 	endif
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

#define	DICT_NULL &dict_null_node
extern	dnode_t	dict_null_node;

typedef struct dict_t dict_t;
struct dict_t {
	/* The root of the red-black tree */
	dnode_t	*root;

	/* The number of the nodes in the tree */
	long long count;

	/* Current node for walks... */
	dnode_t	*node;

	/* Free and compare functions */
	void *(*mallocf)();
	int (*cmp) ();
};

dict_t *dict_create __P((void *(*)(), int (*)()));
void *dict_insert __P((dict_t *, void *, void *, int));
void *dict_search __P((dict_t *, void *));
void dict_delete __P((dict_t *, void *, int, int));
void dict_destroy __P((dict_t *, int, int));
dnode_t *dict_first __P((dict_t *));
dnode_t *dict_next __P((dnode_t *));
#define	dict_last() DICT_NULL

#define	DICT_WALK(dict, k, d) \
	for((dict)->node = dict_first(dict), (k) = (dict)->node->key, (d) = (dict)->node->data;\
		(dict)->node != dict_last(); \
		(dict)->node = dict_next((dict)->node), (k) = (dict)->node->key, (d) = (dict)->node->data)

#endif /* _DICT_H_ */
