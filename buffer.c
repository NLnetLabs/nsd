/*
 * buffer.c -- generic memory buffer .
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <stdio.h>

#include "buffer.h"

void
buffer_cleanup(void *arg)
{
	buffer_type *buffer = (buffer_type *) arg;
	free(buffer->_data);
}

buffer_type *
buffer_create(region_type *region, size_t capacity)
{
	buffer_type *buffer = region_alloc(region, sizeof(buffer_type));
	if (!buffer)
		return NULL;
	
	buffer->_data = xalloc(capacity);
	buffer->_position = 0;
	buffer->_limit = buffer->_capacity = capacity;
	buffer_invariant(buffer);
	
	region_add_cleanup(region, buffer_cleanup, buffer);

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

void
buffer_set_capacity(buffer_type *buffer, size_t capacity)
{
	buffer_invariant(buffer);
	assert(buffer->_position <= capacity);
	buffer->_data = xrealloc(buffer->_data, capacity);
	buffer->_limit = buffer->_capacity = capacity;
}

void
buffer_reserve(buffer_type *buffer, size_t amount)
{
	buffer_invariant(buffer);
	if (buffer->_capacity < buffer->_position + amount) {
		size_t new_capacity = buffer->_capacity * 3 / 2;
		if (new_capacity < buffer->_position + amount) {
			new_capacity = buffer->_position + amount;
		}
		buffer_set_capacity(buffer, new_capacity);
	}
	buffer->_limit = buffer->_capacity;
}

int
buffer_printf(buffer_type *buffer, const char *format, ...)
{
	int result;
	va_list args;
	va_start(args, format);
	result = buffer_vprintf(buffer, format, args);
	va_end(args);
	return result;
}

int
buffer_vprintf(buffer_type *buffer, const char *format, va_list args)
{
	int written;
	ssize_t remaining;
	
	buffer_invariant(buffer);
	assert(buffer->_limit == buffer->_capacity);

	remaining = buffer_remaining(buffer);
	written = vsnprintf((char *) buffer_current(buffer), remaining,
			    format, args);
	if (written >= remaining) {
		buffer_reserve(buffer, written + 1);
		written = vsnprintf((char *) buffer_current(buffer),
				    buffer_remaining(buffer),
				    format, args);
	}
	buffer->_position += written;
	return written;
}
