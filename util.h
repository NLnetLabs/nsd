/*
 * util.h -- set of various support routines.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2003-2004, NLnet Labs. All rights reserved.
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

#ifndef _UTIL_H_
#define _UTIL_H_

#include <config.h>

#include <sys/time.h>
#include <stdarg.h>
#include <syslog.h>
#include <time.h>

#define ALIGN_UP(n, alignment)  \
	(((n) + (alignment) - 1) & (~((alignment) - 1)))
#define PADDING(n, alignment)   \
	(ALIGN_UP((n), (alignment)) - (n))


/*
 * Initialize the logging system.  All messages are logged to stderr
 * until log_open and log_set_log_function are called.
 */
void log_init(const char *ident);

/*
 * Open the system log.  If FILENAME is not NULL, a log file is opened
 * as well.
 */
void log_open(int option, int facility, const char *filename);

/*
 * Finalize the logging system.
 */
void log_finalize(void);

/*
 * Type of function to use for the actual logging.
 */
typedef void log_function_type(int priority, const char *format, va_list args);

/*
 * The function used to log to the log file.
 */
log_function_type log_file;

/*
 * The function used to log to syslog.  The messages are also logged
 * using log_file.
 */
log_function_type log_syslog;

/*
 * Set the logging function to use (log_file or log_syslog).
 */
void log_set_log_function(log_function_type *log_function);

/*
 * Log a message using the current log function.
 */
void log_msg(int priority, const char *format, ...)
	ATTR_FORMAT(printf, 2, 3);

/*
 * Log a message using the current log function.
 */
void log_vmsg(int priority, const char *format, va_list args);

/*
 * (Re-)allocate SIZE bytes of memory.  Report an error if the memory
 * could not be allocated and exit the program.  These functions never
 * returns NULL.
 */
void *xalloc(size_t size);
void *xalloc_zero(size_t size);
void *xrealloc(void *ptr, size_t size);

/*
 * Write SIZE bytes of DATA to FILE.  Report an error on failure.
 *
 * Returns 0 on failure, 1 on success.
 */
int write_data(FILE * file, const void *data, size_t size);


/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
static inline void
copy_uint16(void *dst, uint16_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	* (uint16_t *) dst = htons(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 8) & 0xff);
	p[1] = (uint8_t) (data & 0xff);
#endif
}

static inline void
copy_uint32(void *dst, uint32_t data)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	* (uint32_t *) dst = htonl(data);
#else
	uint8_t *p = (uint8_t *) dst;
	p[0] = (uint8_t) ((data >> 24) & 0xff);
	p[1] = (uint8_t) ((data >> 16) & 0xff);
	p[2] = (uint8_t) ((data >> 8) & 0xff);
	p[3] = (uint8_t) (data & 0xff);
#endif
}

/*
 * Print debugging information using fprintf(3).
 */
#define DEBUG_PARSER           0x0001U
#define DEBUG_ZONEC            0x0002U
#define DEBUG_QUERY            0x0004U
#define DEBUG_DBACCESS         0x0008U
#define DEBUG_NAME_COMPRESSION 0x0010U

#ifdef NDEBUG
#define DEBUG(facility, level, args)  /* empty */
#else
extern unsigned nsd_debug_facilities;
extern int nsd_debug_level;
#define DEBUG(facility, level, args)				\
	do {							\
		if ((facility) & nsd_debug_facilities &&	\
		    (level) <= nsd_debug_level) {		\
			fprintf args ;				\
		}						\
	} while (0)
#endif


/*
 * Timespec functions.
 */
int timespec_compare(const struct timespec *left, const struct timespec *right);
void timespec_add(struct timespec *left, const struct timespec *right);
void timespec_subtract(struct timespec *left, const struct timespec *right);

static inline void
timeval_to_timespec(struct timespec *left,
		    const struct timeval *right)
{
	left->tv_sec = right->tv_sec;
	left->tv_nsec = 1000 * right->tv_usec;
}

#endif /* _UTIL_H_ */
