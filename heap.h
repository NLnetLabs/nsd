/*
 * $Id: heap.h,v 1.1 2002/01/08 13:29:20 alexis Exp $
 *
 * heap.c -- generic heap operations
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
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <dict/dict.h>

#include "dns.h"
#include "nsd.h"
#include "zf.h"

typedef dict heap_t;
extern dict_itor *_heap_itor;

#define	HEAP_INIT(malloc_func)	dict_set_malloc(malloc_func)
#define	HEAP_NEW(cmp) rb_dict_new((dict_cmp_func)cmp, free, free)
#define	HEAP_INSERT(heap, key, data) dict_insert(heap, key, data, TRUE)
#define	HEAP_SEARCH(heap, key) dict_search(heap, key)
#define	HEAP_WALK(heap, key, data) for(_heap_itor = dict_itor_new(heap); \
				dict_itor_valid(_heap_itor) && (key = dict_itor_key(_heap_itor)) && \
				(data = dict_itor_data(_heap_itor)); dict_itor_next(_heap_itor))
#define	HEAP_STOP() dict_itor_destroy(_heap_itor);
