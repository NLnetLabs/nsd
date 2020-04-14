/*
 * talloc.c -- simple but slow allocator that keeps a tally
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "talloc.h"
#include "util.h"

typedef struct alloc alloc_t;

struct alloc {
  alloc_t *next;
  alloc_t *prev;
  void *ptr;
  size_t size;
};

static alloc_t *alloc_log = NULL;
static size_t alloc_cnt = 0;

void *talloc(size_t size)
{
  alloc_t *alloc_rec;
  void *ptr;

  if ((alloc_rec = malloc(sizeof(*alloc_rec))) == NULL) {
    fprintf(stderr, "no memory\n");
    abort();
  }

  if ((ptr = malloc(size)) == NULL) {
    free(alloc_rec);
    return ptr;
  }

  alloc_rec->next = alloc_log;
  if (alloc_log != NULL) {
    alloc_log->prev = alloc_rec;
  }
  alloc_rec->prev = NULL;
  alloc_rec->ptr = ptr;
  alloc_rec->size = size;

  alloc_cnt += alloc_rec->size;

  return ptr;
}

void *talloczero(size_t size)
{
  void *ptr;

  if ((ptr = xalloc(size)) != NULL) {
    memset(ptr, 0, size);
  }

  return ptr;
}

void *tallocarray(size_t nmemb, size_t size)
{
  void *ptr;

  if ((ptr = xalloc(nmemb * size)) != NULL) {
    memset(ptr, 0, nmemb * size);
  }

  return ptr;
}

void tfree(void *ptr)
{
  if (ptr != NULL) {
    alloc_t *alloc_rec;
    for (alloc_rec = alloc_log;
         alloc_rec != NULL;
         alloc_rec = alloc_rec->next)
    {
      if (alloc_rec->ptr == ptr) {
        alloc_cnt -= alloc_rec->size;
        free(ptr);
        if (alloc_rec->prev != NULL) {
          alloc_rec->prev->next = alloc_rec->next;
        }
        if (alloc_rec->next != NULL) {
          alloc_rec->next->prev = alloc_rec->prev;
        }
        free(alloc_rec);
        return;
      }
    }
  }
}

void print_talloc_stats(void)
{
  printf("%zu bytes allocated\n", alloc_cnt);
}
