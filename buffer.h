/*
 * buffer.h -- generic memory buffer.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 *
 * The buffer module implements a generic buffer.  The API is based on the java.nio.Buffer interface.
 */
#ifndef _BUFFER_H_
#define _BUFFER_H_

#include <assert.h>
#include <string.h>

#include "region-allocator.h"
#include "util.h"

typedef struct buffer buffer_type;

struct buffer
{
	/*
	 * The current position used for reading/writing.
	 */ 
	size_t   position;

	/*
	 * The read/write limit.
	 */
	size_t   limit;

	/*
	 * The amount of data the buffer can contain.
	 */
	size_t   capacity;

	/*
	 * The data contained in the buffer.
	 */
	uint8_t *data;
};

static inline void
buffer_invariant(buffer_type *buffer)
{
	assert(buffer);
	assert(buffer->position <= buffer->limit);
	assert(buffer->limit <= buffer->capacity);
	assert(buffer->data);
}

/*
 * Create a new buffer with the specified capacity.
 */
buffer_type *buffer_create(region_type *region, size_t capacity);

/*
 * Create a buffer with the specified data.
 */
buffer_type *buffer_create_from(region_type *region, void *data, size_t size);


/*
 * Clear the buffer and make it ready for writing.
 */
void buffer_clear(buffer_type *buffer);

/*
 * Make the buffer ready for reading the data that has been written to
 * the buffer.
 */
void buffer_flip(buffer_type *buffer);

/*
 * Make the buffer ready for re-reading the data.
 */
void buffer_rewind(buffer_type *buffer);

static inline void
buffer_seek(buffer_type *buffer, size_t mark)
{
	buffer_invariant(buffer);

	assert(mark <= buffer->limit);
	buffer->position = mark;
}

static inline void
buffer_skip(buffer_type *buffer, size_t count)
{
	buffer->position += count;
}

static inline void
buffer_truncate(buffer_type *buffer, size_t limit)
{
	assert(limit <= buffer->capacity);
	buffer->limit = limit;
	if (buffer->limit < buffer->position)
		buffer->position = buffer->limit;
}

static inline uint8_t *
buffer_at(buffer_type *buffer, size_t at)
{
	assert(at <= buffer->limit);
	return buffer->data + at;
}

static inline uint8_t *
buffer_begin(buffer_type *buffer)
{
	return buffer_at(buffer, 0);
}

static inline uint8_t *
buffer_end(buffer_type *buffer)
{
	return buffer_at(buffer, buffer->limit);
}

static inline uint8_t *
buffer_current(buffer_type *buffer)
{
	return buffer_at(buffer, buffer->position);
}

/*
 * The number of bytes remaining between the current position and the
 * limit.
 */
static inline size_t
buffer_remaining_at(buffer_type *buffer, size_t at)
{
	buffer_invariant(buffer);
	
	return buffer->limit - at;
}

static inline size_t
buffer_remaining(buffer_type *buffer)
{
	return buffer_remaining_at(buffer, buffer->position);
}

/*
 * Check if the buffer has at least COUNT more bytes available.
 * Before reading or writing the caller needs to ensure enough space
 * is available!
 */
static inline int
buffer_available_at(buffer_type *buffer, size_t at, size_t count)
{
	buffer_invariant(buffer);
	
	return count <= buffer_remaining_at(buffer, at);
}

static inline int
buffer_available(buffer_type *buffer, size_t count)
{
	return buffer_available_at(buffer, buffer->position, count);
}

static inline void
buffer_write_at(buffer_type *buffer, size_t at, const void *data, size_t count)
{
	assert(buffer_available_at(buffer, at, count));
	memcpy(buffer->data + at, data, count);
}

static inline void
buffer_write(buffer_type *buffer, const void *data, size_t count)
{
	buffer_write_at(buffer, buffer->position, data, count);
	buffer->position += count;
}

static inline void
buffer_write_u8_at(buffer_type *buffer, size_t at, uint8_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	buffer->data[at] = data;
}

static inline void
buffer_write_u8(buffer_type *buffer, uint8_t data)
{
	buffer_write_u8_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_write_u16_at(buffer_type *buffer, size_t at, uint16_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	write_uint16(buffer->data + at, data);
}

static inline void
buffer_write_u16(buffer_type *buffer, uint16_t data)
{
	buffer_write_u16_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_write_u32_at(buffer_type *buffer, size_t at, uint32_t data)
{
	assert(buffer_available_at(buffer, at, sizeof(data)));
	write_uint32(buffer->data + at, data);
}

static inline void
buffer_write_u32(buffer_type *buffer, uint32_t data)
{
	buffer_write_u32_at(buffer, buffer->position, data);
	buffer->position += sizeof(data);
}

static inline void
buffer_read_at(buffer_type *buffer, size_t at, void *data, size_t count)
{
	assert(buffer_available_at(buffer, at, count));
	memcpy(data, buffer->data + at, count);
}

static inline void
buffer_read(buffer_type *buffer, void *data, size_t count)
{
	buffer_read_at(buffer, buffer->position, data, count);
	buffer->position += count;
}

static inline uint8_t
buffer_read_u8_at(buffer_type *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint8_t)));
	return buffer->data[at];
}

static inline uint8_t
buffer_read_u8(buffer_type *buffer)
{
	uint8_t result = buffer_read_u8_at(buffer, buffer->position);
	buffer->position += sizeof(uint8_t);
	return result;
}

static inline uint16_t
buffer_read_u16_at(buffer_type *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint16_t)));
	return read_uint16(buffer->data + at);
}

static inline uint16_t
buffer_read_u16(buffer_type *buffer)
{
	uint16_t result = buffer_read_u16_at(buffer, buffer->position);
	buffer->position += sizeof(uint16_t);
	return result;
}

static inline uint32_t
buffer_read_u32_at(buffer_type *buffer, size_t at)
{
	assert(buffer_available_at(buffer, at, sizeof(uint32_t)));
	return read_uint32(buffer->data + at);
}

static inline uint32_t
buffer_read_u32(buffer_type *buffer)
{
	uint32_t result = buffer_read_u32_at(buffer, buffer->position);
	buffer->position += sizeof(uint32_t);
	return result;
}

#endif /* _BUFFER_H_ */
