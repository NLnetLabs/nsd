/*
 * util.c -- set of various support routines.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#include <unistd.h>

#include "util.h"

#ifndef NDEBUG
unsigned nsd_debug_facilities = 0xffff;
int nsd_debug_level = 0;
#endif

static const char *global_ident = NULL;
static log_function_type *current_log_function = log_file;
static FILE *current_log_file = NULL;

void
log_init(const char *ident)
{
	global_ident = ident;
	current_log_file = stderr;
}

void
log_open(int option, int facility, const char *filename)
{
#ifdef HAVE_SYSLOG_H
	openlog(global_ident, option, facility);
#endif /* HAVE_SYSLOG_H */
	if (filename) {
		FILE *file = fopen(filename, "a");
		if (!file) {
			log_msg(LOG_ERR, "Cannot open %s for appending, logging to stderr",
				filename);
		} else {
			current_log_file = file;
		}
	}
}

void
log_finalize(void)
{
#ifdef HAVE_SYSLOG_H
	closelog();
#endif /* HAVE_SYSLOG_H */
	if (current_log_file != stderr) {
		fclose(current_log_file);
	}
	current_log_file = NULL;
}

static lookup_table_type log_priority_table[] = {
	{ LOG_CRIT, "critical" },
	{ LOG_ERR, "error" },
	{ LOG_WARNING, "warning" },
	{ LOG_NOTICE, "notice" },
	{ LOG_INFO, "info" },
	{ 0, NULL }
};

void
log_file(int priority, const char *message)
{
	size_t length;
	lookup_table_type *priority_info;
	const char *priority_text = "unknown";

	assert(global_ident);
	assert(current_log_file);

	priority_info = lookup_by_id(log_priority_table, priority);
	if (priority_info) {
		priority_text = priority_info->name;
	}

	fprintf(current_log_file, "%s: %s: %s",
		global_ident, priority_text, message);
	length = strlen(message);
	if (length == 0 || message[length - 1] != '\n') {
		fprintf(current_log_file, "\n");
	}
	fflush(current_log_file);
}

void
log_syslog(int priority, const char *message)
{
#ifdef HAVE_SYSLOG_H
	syslog(priority, "%s", message);
#endif /* !HAVE_SYSLOG_H */
	log_file(priority, message);
}

void
log_set_log_function(log_function_type *log_function)
{
	current_log_function = log_function;
}

void
log_msg(int priority, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(priority, format, args);
	va_end(args);
}

void
log_vmsg(int priority, const char *format, va_list args)
{
	char message[MAXSYSLOGMSGLEN];
	vsnprintf(message, sizeof(message), format, args);
	current_log_function(priority, message);
}

void
set_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
}

void
clear_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	bits[index / 8] &= ~(1 << (7 - index % 8));
}

int
get_bit(uint8_t bits[], size_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	return bits[index / 8] & (1 << (7 - index % 8));
}

lookup_table_type *
lookup_by_name(lookup_table_type *table, const char *name)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0)
			return table;
		table++;
	}
	return NULL;
}

lookup_table_type *
lookup_by_id(lookup_table_type *table, int id)
{
	while (table->name != NULL) {
		if (table->id == id)
			return table;
		table++;
	}
	return NULL;
}

void *
xalloc(size_t size)
{
	void *result = malloc(size);

	if (!result) {
		log_msg(LOG_ERR, "malloc failed: %s", strerror(errno));
		exit(1);
	}
	return result;
}

void *
xalloc_zero(size_t size)
{
	void *result = xalloc(size);
	memset(result, 0, size);
	return result;
}

void *
xrealloc(void *ptr, size_t size)
{
	ptr = realloc(ptr, size);
	if (!ptr) {
		log_msg(LOG_ERR, "realloc failed: %s", strerror(errno));
		exit(1);
	}
	return ptr;
}

int
write_data(FILE *file, const void *data, size_t size)
{
	size_t result;

	if (size == 0)
		return 1;

	result = fwrite(data, 1, size, file);

	if (result == 0) {
		log_msg(LOG_ERR, "write failed: %s", strerror(errno));
		return 0;
	} else if (result < size) {
		log_msg(LOG_ERR, "short write (disk full?)");
		return 0;
	} else {
		return 1;
	}
}

int
timespec_compare(const struct timespec *left,
		 const struct timespec *right)
{
	/* Compare seconds.  */
	if (left->tv_sec < right->tv_sec) {
		return -1;
	} else if (left->tv_sec > right->tv_sec) {
		return 1;
	} else {
		/* Seconds are equal, compare nanoseconds.  */
		if (left->tv_nsec < right->tv_nsec) {
			return -1;
		} else if (left->tv_nsec > right->tv_nsec) {
			return 1;
		} else {
			return 0;
		}
	}
}


/* One second is 1e9 nanoseconds.  */
#define NANOSECONDS_PER_SECOND   1000000000L

void
timespec_add(struct timespec *left,
	     const struct timespec *right)
{
	left->tv_sec += right->tv_sec;
	left->tv_nsec += right->tv_nsec;
	if (left->tv_nsec >= NANOSECONDS_PER_SECOND) {
		/* Carry.  */
		++left->tv_sec;
		left->tv_nsec -= NANOSECONDS_PER_SECOND;
	}
}

void
timespec_subtract(struct timespec *left,
		  const struct timespec *right)
{
	left->tv_sec -= right->tv_sec;
	left->tv_nsec -= right->tv_nsec;
	if (left->tv_nsec < 0L) {
		/* Borrow.  */
		--left->tv_sec;
		left->tv_nsec += NANOSECONDS_PER_SECOND;
	}
}


long
strtottl(const char *nptr, const char **endptr)
{
	int sign = 0;
	long i = 0;
	long seconds = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
		case ' ':
		case '\t':
			break;
		case '-':
			if(sign == 0) {
				sign = -1;
			} else {
				return (sign == -1) ? -seconds : seconds;
			}
			break;
		case '+':
			if(sign == 0) {
				sign = 1;
			} else {
				return (sign == -1) ? -seconds : seconds;
			}
			break;
		case 's':
		case 'S':
			seconds += i;
			i = 0;
			break;
		case 'm':
		case 'M':
			seconds += i * 60;
			i = 0;
			break;
		case 'h':
		case 'H':
			seconds += i * 60 * 60;
			i = 0;
			break;
		case 'd':
		case 'D':
			seconds += i * 60 * 60 * 24;
			i = 0;
			break;
		case 'w':
		case 'W':
			seconds += i * 60 * 60 * 24 * 7;
			i = 0;
			break;
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			i *= 10;
			i += (**endptr - '0');
			break;
		default:
			seconds += i;
			return (sign == -1) ? -seconds : seconds;
		}
	}
	seconds += i;
	return (sign == -1) ? -seconds : seconds;
}


ssize_t
hex_ntop(uint8_t const *src, size_t srclength, char *target, size_t targsize)
{
	static char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	size_t i;

	if (targsize < srclength * 2 + 1) {
		return -1;
	}

	for (i = 0; i < srclength; ++i) {
		*target++ = hexdigits[src[i] >> 4U];
		*target++ = hexdigits[src[i] & 0xfU];
	}
	*target = '\0';
	return 2 * srclength;
}


void
strip_string(char *str)
{
	char *start = str;
	char *end = str + strlen(str) - 1;

	while (isspace(*start))
		++start;
	if (start > end) {
		/* Completely blank. */
		str[0] = '\0';
	} else {
		while (isspace(*end))
			--end;
		*++end = '\0';

		if (str != start)
			memmove(str, start, end - start + 1);
	}
}

int
hexdigit_to_int(char ch)
{
	switch (ch) {
	case '0': return 0;
	case '1': return 1;
	case '2': return 2;
	case '3': return 3;
	case '4': return 4;
	case '5': return 5;
	case '6': return 6;
	case '7': return 7;
	case '8': return 8;
	case '9': return 9;
	case 'a': case 'A': return 10;
	case 'b': case 'B': return 11;
	case 'c': case 'C': return 12;
	case 'd': case 'D': return 13;
	case 'e': case 'E': return 14;
	case 'f': case 'F': return 15;
	default:
		internal_error(__FILE__, __LINE__,
			       "hexdigit_to_int: argument not a hexdigit");
	}
}

const char *
sockaddr_to_string(const struct sockaddr *address, socklen_t length)
{
	static char result[NI_MAXHOST + NI_MAXSERV + 3];
	char host[NI_MAXHOST];
	char serv[NI_MAXSERV];

	if (!address) {
		return NULL;
	}

	if (getnameinfo(address, length,
			host, sizeof(host),
			serv, sizeof(serv),
			NI_NUMERICHOST | NI_NUMERICSERV) != 0)
	{
		return NULL;
	} else {
		snprintf(result, sizeof(result), "[%s]:%s", host, serv);
		return result;
	}
}

void
internal_error(const char *filename, int lineno, const char *format, ...)
{
	char temp[MAXSYSLOGMSGLEN];
	va_list args;

	va_start(args, format);
	vsnprintf(temp, sizeof(temp), format, args);
	va_end(args);

	log_msg(LOG_CRIT, "internal error at %s:%d: %s, aborting",
		filename, lineno, temp);
	abort();
}
