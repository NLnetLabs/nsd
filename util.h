/*
 * util.h -- set of various support routines.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _UTIL_H_
#define _UTIL_H_

#include <config.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdarg.h>
#include <stdio.h>
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
typedef void log_function_type(int priority, const char *message);

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
 * Set the INDEXth bit of BITS to 1.
 */
void set_bit(uint8_t bits[], size_t index);

/*
 * Set the INDEXth bit of BITS to 0.
 */
void clear_bit(uint8_t bits[], size_t index);

/*
 * Return the value of the INDEXth bit of BITS.
 */
int get_bit(uint8_t bits[], size_t index);

/* A general purpose lookup table */
typedef struct lookup_table lookup_table_type;
struct lookup_table {
	int id;
	const char *name;
};

/*
 * Looks up the table entry by name, returns NULL if not found.
 */
lookup_table_type *lookup_by_name(lookup_table_type table[], const char *name);

/*
 * Looks up the table entry by id, returns NULL if not found.
 */
lookup_table_type *lookup_by_id(lookup_table_type table[], int id);

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
int write_data(FILE *file, const void *data, size_t size);


/*
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
static inline void
write_uint16(void *dst, uint16_t data)
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
write_uint32(void *dst, uint32_t data)
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
 * Copy data allowing for unaligned accesses in network byte order
 * (big endian).
 */
static inline uint16_t
read_uint16(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	return ntohs(* (uint16_t *) src);
#else
	uint8_t *p = (uint8_t *) src;
	return (p[0] << 8) | p[1];
#endif
}

static inline uint32_t
read_uint32(const void *src)
{
#ifdef ALLOW_UNALIGNED_ACCESSES
	return ntohl(* (uint32_t *) src);
#else
	uint8_t *p = (uint8_t *) src;
	return (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
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


/*
 * Converts a string representation of a period of time into
 * a long integer of seconds.
 *
 * Set the endptr to the first illegal character.
 *
 * Interface is similar as strtol(3)
 *
 * Returns:
 *	LONG_MIN if underflow occurs
 *	LONG_MAX if overflow occurs.
 *	otherwise number of seconds
 *
 * XXX This functions does not check the range.
 *
 */
long strtottl(const char *nptr, const char **endptr);

/*
 * Convert binary data to a string of hexadecimal characters.
 */
ssize_t hex_ntop(uint8_t const *src, size_t srclength, char *target,
		 size_t targsize);

/*
 * Strip trailing and leading whitespace from str.
 */
void strip_string(char *str);

/*
 * Convert a single (hexidecimal) digit to its integer value.
 */
int hexdigit_to_int(char ch);

/*
 * Convert ADDRESS to string notation.  The result is a pointer to a
 * statically allocated string, or NULL if an error occurs.
 */
const char *sockaddr_to_string(const struct sockaddr *address,
			       socklen_t length);

/*
 * Report an internal error and abort the program.
 */
void internal_error(const char *filename, int lineno, const char *format, ...)
	ATTR_FORMAT(printf, 3, 4)
	ATTR_NORETURN;

#endif /* _UTIL_H_ */
