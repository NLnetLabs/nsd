/*
 * buffer.c -- generic memory buffer .
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include "buffer.h"

buffer_type *
buffer_create_new(region_type *region, size_t capacity)
{
	buffer_type *buffer = region_alloc(region, sizeof(buffer_type));
	if (!buffer)
		return NULL;
	
	buffer->data = region_alloc(region, capacity);
	if (!buffer->data)
		return NULL;
	
	buffer->position = 0;
	buffer->limit = buffer->capacity = capacity;

	buffer_invariant(buffer);
	
	return buffer;
}

buffer_type *
buffer_create_from(region_type *region, void *data, size_t size)
{
	buffer_type *buffer = region_alloc(region, sizeof(buffer_type));
	if (!buffer)
		return NULL;

	assert(data);

	buffer->position = 0;
	buffer->limit = buffer->capacity = size;
	buffer->data = data;

	buffer_invariant(buffer);
	
	return buffer;
}

void
buffer_clear(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->position = 0;
	buffer->limit = buffer->capacity;
}

void
buffer_flip(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->limit = buffer->position;
	buffer->position = 0;
}

void
buffer_rewind(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->position = 0;
}
