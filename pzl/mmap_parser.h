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

#ifndef MMAP_PARSER_H_ 
#define MMAP_PARSER_H_
#include "pzl/return_status.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

#ifndef DEFAULT_N_PARSER_PIECES
#define DEFAULT_N_PARSER_PIECES 32
#endif

#ifndef DEFAULT_PARSER_PAGESIZE
#include <unistd.h>
#define DEFAULT_PARSER_PAGESIZE sysconf(_SC_PAGESIZE)
#endif

#ifndef DEFAULT_PARSER_MUNMAP_TRESHOLD
#define DEFAULT_PARSER_MUNMAP_TRESHOLD 32 /* in pages */
#endif

#ifndef DEFAULT_PARSER_MUNMAP_PRESERVE
#define DEFAULT_PARSER_MUNMAP_PRESERVE  1 /* in pages */
#endif

typedef struct parse_piece parse_piece;
typedef struct parse_ref   parse_reference;
typedef struct parse_ref   parse_ref;
typedef struct mmap_parser {
	const char  *text;
	const char  *end;
	const char  *cur;

	int          fd;
	const char  *fn;
	size_t       line_nr;
	const char  *sol;     /* Start of line (for col_nr calculation) */

	char        *to_munmap;
	size_t       munmap_treshold;
	size_t       munmap_preserve;
	const char  *start;   /* Start of item returned on parse iteration
	                       * start can be < pieces[0].start
			       * start may not be munmapped
			       */
	parse_ref   *refs;    /* Positions within text which are referenced
	                       * and thus may not be munmapped
			       */

	parse_piece *pieces;
	parse_piece *end_of_pieces;
	parse_piece *cur_piece;
	int          pieces_malloced;
} mmap_parser;

#define MMAP_PARSER_CLEAR          { NULL, NULL, NULL \
                                   ,   -1, NULL,    0, NULL \
                                   , NULL, 0, 0, NULL, NULL \
                                   , NULL, NULL, NULL, 0 }

#define MMAP_PARSER_INIT(TEXT,LEN) { (TEXT), ((TEXT)+(LEN)), (TEXT) \
                                   ,   -1, NULL,    0, (TEXT) \
                                   , NULL, 0, 0, NULL, NULL \
                                   , NULL, NULL, NULL, 0 }

struct parse_piece {
	const char *start;
	const char *end;
	size_t      line_nr;
	size_t      col_nr;
	const char *fn;
};

struct parse_ref {
	const char *text;
	parse_ref  *next;
	parse_ref **prev;
};

static inline status_code mmap_parser_init(mmap_parser *p,
    const char *text, size_t len, return_status *st)
{
	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser to initialize");
	if (len && !text)
		return RETURN_USAGE_ERR(st,
		    "missing text to initialize parser");
	*p = (mmap_parser)MMAP_PARSER_INIT(text, len);
	return STATUS_OK;
}

static inline status_code mmap_parser_init_fn(
    mmap_parser *p, const char *fn, return_status *st)
{
	int fd;
	struct stat statbuf;
	char *text;

	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser to initialize");
	if (!fn)
		return RETURN_USAGE_ERR(st,
		    "missing filename to initialize parser");

	if ((fd = open(fn, O_RDONLY)) < 0)
		return RETURN_IO_ERR(st, "opening file to initialize parser");

	if (fstat(fd, &statbuf) < 0) {
		close(fd);
		return RETURN_IO_ERR(st,
		    "determening file size with which to initialize parser");
	}
	if ((text = mmap( NULL, statbuf.st_size, PROT_READ
	                , MAP_SHARED, fd, 0)) == MAP_FAILED) {
		close(fd);
		return RETURN_IO_ERR(st,
		    "mmapping the file with which to initialize parser");
	}
	*p = (mmap_parser)MMAP_PARSER_INIT(text, statbuf.st_size);
	p->fd = fd; p->fn = fn; p->to_munmap = text;
	p->munmap_treshold = DEFAULT_PARSER_MUNMAP_TRESHOLD
	                   * DEFAULT_PARSER_PAGESIZE;
	p->munmap_preserve = DEFAULT_PARSER_MUNMAP_PRESERVE
	                   * DEFAULT_PARSER_PAGESIZE;
	return STATUS_OK;
}

static inline void mmap_parser_free_in_use(mmap_parser *p)
{
	if (!p)
		return;

      	if (p->pieces && p->pieces_malloced) {
		free(p->pieces);
		p->pieces = NULL;
		p->end_of_pieces = NULL;
		p->cur_piece = NULL;
		p->pieces_malloced = 0;
	}
	if (p->to_munmap && !p->refs && p->end) {
		munmap(p->to_munmap, p->end - p->to_munmap);
		p->to_munmap = NULL;
	}
	if (p->fd >= 0 && !p->to_munmap) {
		close(p->fd);
		p->fd = -1;
	}
}

/* Progressively munmap mmapped text that is not referenced (anymore) */
static inline status_code mmap_parser_progressive_munmap(
    mmap_parser *p, return_status *st)
{
	ssize_t n_to_munmap;

	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser "
		    "with which to progressively munmap text");

	if (!p->to_munmap)
		return STATUS_OK;

	if (p->refs)
		n_to_munmap = p->refs->text - p->to_munmap;
	else if (p->start)
		n_to_munmap = p->start - p->to_munmap;
	else
		return STATUS_OK; /* parsing has not yet started */

	if (n_to_munmap < 0)
		return RETURN_DATA_ERR(st,
		    "p->to_munmap progressed beyond referenced text");

	assert(n_to_munmap >= 0);
	if ((size_t)n_to_munmap < p->munmap_treshold)
		return STATUS_OK;

	n_to_munmap /= p->munmap_treshold;
	n_to_munmap *= p->munmap_treshold;
	n_to_munmap -= p->munmap_preserve;

	if (p->to_munmap + n_to_munmap > p->end)
		return RETURN_DATA_ERR(st, "text referenced beyond end");

	munmap(p->to_munmap, n_to_munmap);
	p->to_munmap += n_to_munmap;
	return STATUS_OK;
}

/* To do before parsing each set of pieces */
static inline status_code reset_cur_piece(mmap_parser *p, return_status *st)
{
	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser "
		    "for which to reset the current piece");
	if (!p->pieces) {
		if (!(p->pieces = calloc(
		    DEFAULT_N_PARSER_PIECES, sizeof(parse_piece))))
			return RETURN_MEM_ERR(st, "allocating parser pieces");
		p->end_of_pieces = p->pieces + DEFAULT_N_PARSER_PIECES;
		p->pieces_malloced = 1;
	}
	p->cur_piece = p->pieces;
	p->cur_piece->start = NULL;
	return STATUS_OK;
}

static inline status_code equip_cur_piece(mmap_parser *p, return_status *st)
{
	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser "
		    "for which to equip the current piece");
	if (!p->cur_piece)
		return RETURN_DATA_ERR(st,
		    "uninitialized current piece to equip");
	if (!p->cur)
		return RETURN_DATA_ERR(st,
		    "missing data at cursor "
		    "when equipping the current piece");
	p->cur_piece->start = p->cur;
	p->cur_piece->end = NULL;
	p->cur_piece->line_nr = p->line_nr;
	p->cur_piece->col_nr = p->cur - p->sol;
	p->cur_piece->fn = p->fn;
	return STATUS_OK;
}

static inline status_code increment_cur_piece(mmap_parser *p, return_status *st)
{
	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser "
		    "for which to increment the current piece");
	if (!p->cur_piece)
		return RETURN_DATA_ERR(st,
		    "uninitialized current piece to increment");
	if (!p->cur)
		return RETURN_DATA_ERR(st,
		    "missing data at cursor "
		    "when incrementing the current piece");
	p->cur_piece->end = p->cur;
	p->cur_piece += 1;
	if (!p->end_of_pieces)
		return RETURN_DATA_ERR(st,
		    "uninitialized end_of_pieces "
		    "when incrementing current piece");
	if (p->cur_piece >= p->end_of_pieces) {
		size_t cur_piece_off, n_pieces;
		parse_piece *pieces;

		if (!p->pieces_malloced)
			return RETURN_OVERFLOW_ERR(st,
			    "pieces overflow");
		if (!p->pieces)
			return RETURN_DATA_ERR(st,
			    "cannot grow uninitialized parser pieces");
		if (p->cur_piece > p->end_of_pieces)
			return RETURN_DATA_ERR(st,
			    "current parser piece beyond end of pieces");
		cur_piece_off = p->cur_piece - p->pieces;
		n_pieces = (p->end_of_pieces - p->pieces) * 2;
		pieces = realloc(p->pieces, sizeof(parse_piece) * n_pieces);
		if (!pieces)
			return RETURN_MEM_ERR(st,
			    "could not grow parser pieces");
		p->pieces = pieces;
		p->end_of_pieces = p->pieces + n_pieces;
		p->cur_piece = p->pieces + cur_piece_off;
	}
	p->cur_piece->start = NULL;
	return STATUS_OK;
}

static inline status_code parse_dereference(parse_ref *r, return_status *st)
{
	if (!r)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parse_ref to dereference");
	if (!r->prev)
		return RETURN_DATA_ERR(st,
		    "dereferencing already dereferenced reference");
	if (r->next)
		r->next->prev = r->prev;
	*r->prev = r->next;
	r->prev = NULL;
	return STATUS_OK;
}

static inline status_code mmap_parser_up_ref(
    mmap_parser *p, parse_ref *r, return_status *st)
{
	parse_ref **refs;

	if (!p)
		return RETURN_USAGE_ERR(st,
		    "missing reference to the parser "
		    "for which to up the reference");
	if (!r)
                return RETURN_USAGE_ERR(st, "missing reference to up");

	if (r->text < p->text || r->text >= p->end)
                return RETURN_DATA_ERR(st,
		    "cannot up a reference outside of the parser text");

	if (r->prev)
		return RETURN_DATA_ERR(st,
		    "cannot add an already added reference");

	refs = &p->refs;
	for (;;) {
		if (!*refs || r->text < (*refs)->text) {
			r->next = *refs;
			r->prev =  refs;
			*refs =  r;
			return STATUS_OK;
		}
		refs = &(*refs)->next;
	}
}

#endif /* #ifndef MMAP_PARSER_H_ */
