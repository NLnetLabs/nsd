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
buffer_create(region_type *region, size_t capacity)
{
	buffer_type *buffer = region_alloc(region, sizeof(buffer_type));
	if (!buffer)
		return NULL;
	
	buffer->_data = region_alloc(region, capacity);
	if (!buffer->_data)
		return NULL;
	
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = capacity;

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

	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = size;
	buffer->_data = data;

	buffer_invariant(buffer);
	
	return buffer;
}

void
buffer_clear(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity;
}

void
buffer_flip(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->_limit = buffer->_position;
	buffer->_position = 0;
}

void
buffer_rewind(buffer_type *buffer)
{
	buffer_invariant(buffer);
	
	buffer->_position = 0;
}
