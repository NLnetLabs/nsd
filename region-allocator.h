/*
 * region-allocator.h -- region based memory allocator.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _REGION_ALLOCATOR_H_
#define _REGION_ALLOCATOR_H_

#include <stdio.h>

typedef struct region region_type;


/*
 * Create a new region.
 */
region_type *region_create(void *(*allocator)(size_t),
			   void (*deallocator)(void *));


/*
 * Destroy REGION.  All memory associated with REGION is freed as if
 * region_free_all was called.
 */
void region_destroy(region_type *region);


/*
 * Add a cleanup to REGION.  ACTION will be called with DATA as
 * parameter when the region is freed or destroyed.
 *
 * Returns 0 on failure.
 */
size_t region_add_cleanup(region_type *region,
			  void (*action)(void *),
			  void *data);


/*
 * Allocate SIZE bytes of memory inside REGION.  The memory is
 * deallocated when region_free_all is called for this region.
 */
void *region_alloc(region_type *region, size_t size);


/*
 * Allocate SIZE bytes of memory inside REGION and copy INIT into it.
 * The memory is deallocated when region_free_all is called for this
 * region.
 */
void *region_alloc_init(region_type *region, const void *init, size_t size);


/*
 * Allocate SIZE bytes of memory inside REGION that are initialized to
 * 0.  The memory is deallocated when region_free_all is called for
 * this region.
 */
void *region_alloc_zero(region_type *region, size_t size);


/*
 * Run the cleanup actions and free all memory associated with REGION.
 */
void region_free_all(region_type *region);


/*
 * Duplicate STRING and allocate the result in REGION.
 */
char *region_strdup(region_type *region, const char *string);


/*
 * Set the current active region to REGION.
 */
void region_set_current(region_type *region);


/*
 * Return the current active region.
 */
region_type *region_get_current(void);


/*
 * Allocate SIZE bytes of memory inside the currently active region.
 * The memory is deallocated when region_free_all is called for the
 * active region.  This is provided as an easy replacement of malloc.
 */
void *region_alloc_current(size_t size);

/*
 * Print some REGION statistics to OUT.
 */
void region_dump_stats(region_type *region, FILE *out);

#endif /* _REGION_ALLOCATOR_H_ */
