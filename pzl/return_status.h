/* Copyright (c) 2019, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef RETURN_STATUS_H_ 
#define RETURN_STATUS_H_
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef enum status_code {
	STATUS_OK             =  0,
	STATUS_IO_ERR         =  1, /* Check errno for details            */
	STATUS_MEM_ERR        =  2, /* Failure to allocate memory         */
	STATUS_PARSE_ERR      =  3, /* Syntax error while parsing strings */
	STATUS_USAGE_ERR      =  4, /* Wrong usage by library user.       */
	STATUS_DATA_ERR       =  5, /* Incoherent data structs            */
	STATUS_INTERNAL_ERR   =  6, /* Internal deficiency!               */
	STATUS_OVERFLOW_ERR   =  7, /* Something didn't fit               */
	STATUS_NOT_FOUND_ERR  =  8, /* Could not find requested item      */
	STATUS_STOP_ITERATION =  9, /* Iterator reached last element */
	STATUS_PTHREAD_ERR    = 10, /* A pthread func erred */
	STATUS_NOT_IMPL_ERR   = 11, /* Requested feature not yet implemented */
} status_code;

static inline const char *status_code2str(status_code code)
{
	const char *error_strings[] = {
		"NO", "I/O", "memory", "parse", "library usage",
		"data integrity", "internal", "overflow", "not found",
		"stop iteration", "pthread", "not implemented"
	};
	if (code >= STATUS_OK
	&&  code <  sizeof(error_strings) / sizeof(*error_strings))
		return error_strings[code];
	else	return "Unknown error";
}

typedef struct parse_error_details {
	const char *fn;
	size_t      line_nr;
	size_t      col_nr;
} parse_error_details;

typedef struct pthread_error_details {
	int  err;
} pthread_error_details;

typedef struct return_status {
	status_code code;
	const char *msg;
	const char *func;
	const char *file;
	int         line;
	union {
		parse_error_details   parse;
		pthread_error_details pthread;
	} details;
} return_status;

#define RETURN_STATUS_CLEAR { STATUS_OK, NULL, NULL, NULL, -1 }

static inline void return_status_reset(return_status *status)
{
	if (status) {
		status->code = STATUS_OK;
		status->msg = NULL;
		status->func = NULL;
		status->file = NULL;
		status->line = -1;
	}
}

static inline int fprint_return_status(FILE *f, return_status *stat)
{
	int r, t = 0;

	assert(stat);
	if ((r = fprintf(f, "%s error: %s in "
			  , status_code2str(stat->code), stat->msg)) < 0)
		return r;
	else	t += r;

	if (stat->code == STATUS_PARSE_ERR) {
		if ((r = fprintf(f, "\"%s\" at line %zu col %zu\n\tin "
		                  , stat->details.parse.fn
		                  , stat->details.parse.line_nr + 1
		                  , stat->details.parse.col_nr + 1)) < 0)
			return r;
		else	t += r;
	}
	if ((r = fprintf(f, "function %s at %s:%d\n"
	                  , stat->func, stat->file, stat->line) < 0))
		return r;
	else	t += r;

	return_status_reset(stat);
	return t;
}


#define RETURN_ERR(NAME, STAT, MSG) ( \
      (intptr_t)(STAT ) != (uintptr_t)NULL \
    ? ( ((STAT)->func = __func__ ) \
      , ((STAT)->file = __FILE__ ) \
      , ((STAT)->line = __LINE__ ) \
      , ((STAT)->msg  = (MSG) ) \
      , ((STAT)->code = STATUS_ ## NAME ## _ERR) ) \
    : STATUS_ ## NAME ## _ERR \
    )
#define RETURN_PARSE_ERR(STAT, MSG, FN, LINE_NR, COL_NR) ( \
      (intptr_t)(STAT ) != (uintptr_t)NULL \
    ? ( ((STAT)->details.parse.fn      = (FN)) \
      , ((STAT)->details.parse.line_nr = (LINE_NR)) \
      , ((STAT)->details.parse.col_nr  = (COL_NR)) \
      , RETURN_ERR(PARSE, (STAT), (MSG))) \
    : STATUS_PARSE_ERR \
    )
#define RETURN_PTHREAD_ERR(STAT, MSG, ERRNO) ( \
      (intptr_t)(STAT ) != (uintptr_t)NULL \
    ? ( ((STAT)->details.pthread.err = (ERRNO)) \
      , RETURN_ERR(PARSE, (STAT), (MSG))) \
    : STATUS_PTHREAD_ERR \
    )

#define RETURN_IO_ERR(...)        RETURN_ERR(IO       , __VA_ARGS__)
#define RETURN_MEM_ERR(...)       RETURN_ERR(MEM      , __VA_ARGS__)
#define RETURN_USAGE_ERR(...)     RETURN_ERR(USAGE    , __VA_ARGS__)
#define RETURN_DATA_ERR(...)      RETURN_ERR(DATA     , __VA_ARGS__)
#define RETURN_INTERNAL_ERR(...)  RETURN_ERR(INTERNAL , __VA_ARGS__)
#define RETURN_OVERFLOW_ERR(...)  RETURN_ERR(OVERFLOW , __VA_ARGS__)
#define RETURN_NOT_FOUND_ERR(...) RETURN_ERR(NOT_FOUND, __VA_ARGS__)
#define RETURN_NOT_IMPL_ERR(...)  RETURN_ERR(NOT_IMPL , __VA_ARGS__)

#endif /* #ifndef RETURN_STATUS_H_ */
