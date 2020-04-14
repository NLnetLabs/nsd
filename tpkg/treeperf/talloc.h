/*
 * talloc.h -- simple but slow allocator that keeps a tally
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _TALLOC_H_
#define _TALLOC_H_

#include <stddef.h>

void *talloc(size_t size);
void *talloczero(size_t size);
void *tallocarray(size_t nmemb, size_t size);
void tfree(void *ptr);

void print_talloc_stats(void);

#endif /* _ALLOC_H_ */
