/*
 * $Id: zf.c,v 1.13 2002/02/15 19:42:51 erik Exp $
 *
 * zf.c -- RFC1035 master zone file parser, nsd(8)
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
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
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
#include "nsd.h"
#include "zf.h"

static struct zf_type_tab zf_types[] = ZONEFILE_TYPES;
static struct zf_class_tab zf_classes[] = ZONEFILE_CLASSES;

/*
 * Buffer to hold the text representation of the current token.	 Note
 * that by using escape sequences the text representation can be up to
 * 4 times longer than allowed by DNS.
 */
static char current_token[4 * MAXTOKENLEN + 1];

/*
 * Converts dname to text
 *
 * XXX Actually should not be here cause it is a debug routine.
 *
 */
const char *
dnamestr(const u_char *dname)
{
	static char s[MAXDOMAINLEN+1];
	char *p;
	int l;
	const u_char *n = dname;

	l = (int) *dname;
	n++;
	p = s;

	if(*n) {
		while(n < dname + l) {
			memcpy(p, n + 1, *n);
			p += *n;
			*p++ = '.';
			n += *n + 1;
		}
	} else {
		*p++ = '.';
	}
	*p = 0;
	return s;
}

/*
 * Parses an character string containing escape characters. The
 * parsing is done in-place.
 */
static void
parse_escaped_string(char *s)
{
	char *d;
	for (d = s; *s; s++, d++) {
		if (*s == '\\') {
			if ('0' <= s[1] && s[1] <= '3'
			    && '0' <= s[2] && s[2] <= '7'
			    && '0' <= s[3] && s[3] <= '7')
			{
				char ch = (char) ((s[1] - '0') * 64
						  + (s[2] - '0') * 8
						  + (s[3] - '0'));
				*d = ch;
				s += 3;
			} else if (s[1] != '\0') {
				*d = *++s;
			} else {
				*d = *s;
			}
		} else {
			*d = *s;
		}
	}
	*d = '\0';
}

/*
 * Returns a pointer to the first unescaped character 'ch'. Returns
 * NULL if no unescaped character 'ch' could be found.
 */
static char *
find_unescaped_char(char *s, char ch)
{
	int in_escape = 0;
	for (; *s && (in_escape || *s != ch); s++) {
		in_escape = (!in_escape && *s == '\\');
	}
	return *s ? s : NULL;
}

/*
 * Parses the 'input' text and returns a dname with the first byte
 * indicating the size of the entire dname.  If the 'input' text
 * consists of a single '@' character the returned dname is a copy of
 * 'origin'. The resulting dname is always allocated on the heap and
 * the caller MUST free this memory later.
 *
 * XXX Complain about empty labels (.nlnetlabs..nl)
 */
u_char *
text_to_dname(const char *input, const u_char *origin)
{
	/* Temporary buffer to hold the parsed dname.  */
	u_char dname[MAXDOMAINLEN+1];
	u_char *result;

	char *copy = strdup(input);
	char *end;
	char *start;
		
	/*
	 * Points to the start of the current label in
	 * 'dname'.
	 */
	u_char *current_label = dname + 1;
	
	/*
	 * Points to the current character position in
	 * 'dname'.
	 */
	u_char *p;
	
	size_t dname_length = 0;
	size_t label_length;
	int absolute = 0;
	
	if(strcmp(copy, "@") == 0) {
		copy[0] = '\0';
	}
	
	/* Parse the dname.  */
	start = copy;
	end = find_unescaped_char(start, '.');
	for(;;) {
		if(end) {
			*end = '\0';
			absolute = (end[1] == '\0');
		}
		
		parse_escaped_string(start);
		label_length = strlen(start);
		if(label_length > MAXLABELLEN) {
			free(copy);
			return NULL;
		}
		
		dname_length += label_length + 1;
		if(dname_length > MAXDOMAINLEN) {
			free(copy);
			return NULL;
		}
		
		*current_label = label_length;
		if(label_length > 0) {
			size_t i;
			for (i = 0; i < label_length; i++)
				current_label[i + 1] = NAMEDB_NORMALIZE(start[i]);
			current_label += label_length + 1;
		}
		
		if(end) {
			start = end + 1;
			end = find_unescaped_char(start, '.');
		} else {
			break;
		}
	}
	
	*current_label = 0;
	p = current_label;
	
	/* If not absolute, append origin...  */
	if(!absolute) {
		const u_char *src;
		const u_char *end = origin + *origin + 1;
		
		if (dname_length + *origin > MAXDOMAINLEN) {
			free(copy);
			return NULL;
		}
		
		for(src = origin + 1; src < end; p++, src++)
			*p = NAMEDB_NORMALIZE(*src);
		p--;
	}
	
	/* Store total length of dname.	 */
	*dname = p - dname;
	
	free(copy);
	
	result = xalloc((size_t) *dname + 1);
	memcpy(result, dname, (size_t) *dname + 1);
	return result;
}

/*
 * Compares two domain names.
 */
int
dnamecmp(const u_char *a, const u_char *b)
{
	int r;
	size_t alen = *a;
	size_t blen = *b;

	while(alen && blen) {
		a++; b++;
		if((r = NAMEDB_NORMALIZE(*a) - NAMEDB_NORMALIZE(*b))) return r;
		alen--; blen--;
	}
	return alen - blen;
}

/*
 * Converts numeric value of resource record type into
 * a string.
 */
const char *
typetoa(u_int16_t n)
{
	struct zf_type_tab *type;
	static char name[5];

	for(type = zf_types; type->type; type++)
		if(n == type->type) return type->name;

	snprintf(name, sizeof(name), "%u", n);
	return name;
}

/*
 * Converts numeric value of resource record class into
 * a string.
 */
const char *
classtoa(u_int16_t n)
{
	struct zf_class_tab *class;
	static char name[6];

	for(class = zf_classes; class->class; class++)
		if(n == class->class) return class->name;

	snprintf(name, sizeof(name), "%u", n);
	return name;
}

/*
 * Returns type_tab by type name.
 *
 */
static struct zf_type_tab *
typebyname(const char *a)
{
	struct zf_type_tab *type;

	for(type = zf_types; type->type; type++)
		if(strcasecmp(a, type->name) == 0) return type;
	return	NULL;
}

/*
 * Returns type_tab by type name.
 *
 */
static struct zf_class_tab *
classbyname(const char *a)
{
	struct zf_class_tab *class;

	for(class = zf_classes; class->class; class++)
		if(strcasecmp(a, class->name) == 0) return class;
	return	NULL;
}

/*
 * Converts a string representation of a period of time into
 * a long integer of seconds.
 *
 * Set the endptr to the first illegal character.
 *
 * Interface is the same as strtol(3)
 *
 * Returns LONG_MIN if underflow occurs, LONG_MAX if overflow occurs.
 *
 * XXX This functions does not check the range.
 *
 */
static long
strtottl(char *nptr, char **endptr)
{
	int sign = 0;
	long i = 0;
	long seconds = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch(**endptr) {
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

/*
 * inet6_aton() - ipv6 brother for inet_aton()
 *
 * Returns inet6 address.
 * 
 * XXX Does not handle zero ranges.
 *
 */
void *
inet6_aton(const char *str)
{
	char *addr;
	u_int16_t w;
	const char *p;
	char *t, *z;

	addr = xalloc(IP6ADDRLEN);

	if(!str || !addr) {
		errno = EINVAL;
		return NULL;
	}

	for(p = str, t = addr; t < (addr + 8 * sizeof(u_int16_t)); p++) {
		if((*p == ':') || (*p == '\000')) {
			w = htons((u_int16_t) strtol(str, &z, 16));
			if(z != p) return NULL;
			memcpy(t, &w, sizeof(u_int16_t));
			t += sizeof(u_int16_t);
			str = p + 1;
		}
		if(*p == '\000') {
			if(t == (addr + 8 * sizeof(u_int16_t))) {
				return addr;
			} else {
				break;
			}
		}
	}
	free(addr);
	return NULL;
}

/*
 * Prints an error message related to a particular zone file.
 */
void
zf_error(struct zf *zf, char *msg)
{
	if(zf->iptr > -1) {
		fflush(stderr);
		fprintf(stderr, "%s in %s, line %lu\n", msg,
			zf->i[zf->iptr].filename,
			zf->i[zf->iptr].lineno);
	} else {
		fflush(stderr);
		fprintf(stderr, "%s\n", msg);
	}
	zf->errors++;
}

/*
 * Prints syntax error related to a particular zone file.
 *
 */
void
zf_syntax(struct zf *zf)
{
	zf_error(zf, "syntax error");
}

/*
 * Closes current include file.
 */
static int
zf_close_include(struct zf *zf)
{
	if(zf->iptr > -1) {
		free(zf->i[zf->iptr].filename);
		free(zf->i[zf->iptr].origin);
		fclose(zf->i[zf->iptr].file);
		zf->iptr--;
	}
	return zf->iptr + 1;
}

/*
 * Gets a character from the current zone file, returning to the
 * higher level include file if necessary and 'start' is true.
 */
static int
zf_getchar(struct zf *zf, int start)
{
	int ch;
	if (zf->iptr < 0)
		return EOF;

	if (zf->ungetchar != EOF) {
		ch = zf->ungetchar;
		zf->ungetchar = EOF;
	} else {
		
		while((ch = fgetc(zf->i[zf->iptr].file)) == EOF) {
			/*
			 * Only close include file if we're at the
			 * start of a token.  This way tokens can
			 * never start in one file and continue into
			 * the next file.
			 */
			if(!start) {
				return EOF;
			}
			
			if(zf->i[zf->iptr].parentheses) {
				zf_error(zf, "end of file inside of parentheses");
			}
			
			if(zf_close_include(zf) == 0) {
				return EOF;
			}
		}
	}

	if (ch == '\n') {
		zf->i[zf->iptr].lineno++;
		zf->lines++;
	}
	
	return ch;
}

/*
 * Ungets the character c.  Only a single character can be stored.
 */
static void
zf_ungetchar(struct zf *zf, char ch)
{
	assert(zf->ungetchar == EOF);
	if (ch == '\n') {
		zf->i[zf->iptr].lineno--;
		zf->lines--;
	}
	zf->ungetchar = ch;
}

/*
 * Peeks one character ahead using zf_getchar and zf_ungetchar.
 */
static int
zf_peekchar(struct zf *zf, int start)
{
	int ch = zf_getchar(zf, start);
	zf_ungetchar(zf, ch);
	return ch;
}

/*
 * We're at the end of a record if we're at the end of a file
 * or at a newline and there are no outstanding parentheses.
 */
static int
is_end_of_record(struct zf *zf, int ch)
{
	return ch == EOF || (ch == '\n' && !zf->i[zf->iptr].parentheses);
}

static int
is_delimiter(int ch)
{
	return isspace(ch) || ch == '(' || ch == ')' || ch == ';';
}

/*
 * Returns the next token. The return value is NULL if the end of a
 * record is reached (or the end of the file). Otherwise the result
 * points to a static area containing the token. If 'escape' is true
 * character espaces are replaced with the escaped character.
 *
 * This function deals with parentheses and quotes.
 */
static char *
zf_token(struct zf *zf)
{
	int ch;
	int truncated;
	int in_escape;		/* True if previous character is backslash. */
	size_t pos;

start:
	/* Skip whitespace.  */
	do {
		ch = zf_getchar(zf, 1);
	} while (isspace(ch) && !is_end_of_record(zf, ch));

	/* Return NULL at the end of the file or at the end of a
           record. */
	if (is_end_of_record(zf, ch)) {
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token EORR/EOF\n");
#endif
		return NULL;
	}

	switch (ch) {
	case ';':
		/* Skip comments upto the EOF or EOL. */
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token ';'\n");
#endif
		do {
			ch = zf_getchar(zf, 0);
		} while (ch != EOF && ch != '\n');
		zf_ungetchar(zf, ch);
		
		goto start;
	case '(':
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token '('\n");
#endif
		if (zf->i[zf->iptr].parentheses) {
			zf_error(zf, "nested parentheses");
		} else {
			zf->i[zf->iptr].parentheses = 1;
		}
		goto start;
	case ')':
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token ')'\n");
#endif
		if (zf->i[zf->iptr].parentheses) {
			zf->i[zf->iptr].parentheses = 0;
		} else {
			zf_error(zf, "unmatched closing paren");
		}
		goto start;
	case '"':
		truncated = 0;
		pos = 0;
		in_escape = 0;
		while ((ch = zf_getchar(zf, 0)), ch != EOF && (in_escape || ch != '"')) {
			if (pos < sizeof(current_token) - 1) {
				current_token[pos++] = ch;
			} else if (!truncated
				   && pos == sizeof(current_token) - 1)
			{
				zf_error(zf, "text truncated");
				truncated = 1;
			}

			/* We're starting a character escape if we're
                           are not yet in an escape and the current
                           character is a backslash. */
			in_escape = (!in_escape && ch == '\\');
		}
		current_token[pos] = '\0';
		
		if (ch == EOF) {
			zf_error(zf, "unterminated character string");
		}
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token '%s'\n", current_token);
#endif
		return current_token;
	default:
		truncated = 0;
		pos = 0;
		in_escape = 0;
		do {
			if (pos < sizeof(current_token) - 1) {
				current_token[pos++] = ch;
			} else if (!truncated
				   && pos == sizeof(current_token) - 1)
			{
				zf_error(zf, "text truncated");
				truncated = 1;
			}
			
			/* We're starting a character escape if we're
                           are not yet in an escape and the current
                           character is a backslash. */
			in_escape = (!in_escape && ch == '\\');
			
			ch = zf_getchar(zf, 0);
		} while (ch != EOF && (in_escape || !is_delimiter(ch)));
		zf_ungetchar(zf, ch);
		current_token[pos] = '\0';
		
#if DEBUG > 3
		fflush(stdout);
		fprintf(stderr, "token '%s'\n", current_token);
#endif
		return current_token;
	}
}

/*
 * Opens a file.
 *
 */
static int
zf_open_include(struct zf *zf, const char *filename, char *origin, int32_t ttl)
{
	if(zf->iptr + 1 > MAXINCLUDES) {
		zf_error(zf, "too many nested include files");
		return -1;
	}

	zf->iptr++;

	if((zf->i[zf->iptr].file = fopen(filename, "r")) == NULL) {
		fflush(stdout);
		fprintf(stderr, "cannot open file %s: %s\n", filename, strerror(errno));
		zf->iptr--;
		return -1;
	}

	zf->i[zf->iptr].lineno = 1;
	zf->i[zf->iptr].filename = strdup(filename);
	zf->i[zf->iptr].origin = origin;
	zf->i[zf->iptr].ttl = ttl;
	zf->i[zf->iptr].parentheses = 0;
	return 0;
}


/*
 * Opens a zone file and sets us up for parsing.
 */
struct zf *
zf_open(char *filename, u_char *origin)
{
	struct zf *zf;

	/* Allocate new handling structure */
	zf = xalloc(sizeof(struct zf));

	/* Initialize it */
	zf->errors = 0;
	zf->iptr = -1;
	zf->lines = 0;
	zf->ungetchar = EOF;

	memset(&zf->line, 0, sizeof(struct zf_entry));

	/* Open the main file... */
	if(zf_open_include(zf, filename, text_to_dname(origin, ROOT_ORIGIN), DEFAULT_TTL) == -1) {
		free(zf);
		return NULL;
	}

	return zf;
}

/*
 * Frees a zone file entry
 *
 */
void
zf_free_rdata(union zf_rdatom *rdata, char *f)
{
	int i;

	if(rdata) {
		for(i = 0; *f; f++, i++) {
			switch(*f) {
			case 'n':
			case '6':
			case 't':
				free(rdata[i].p);
			}
		}
		free(rdata);
	}
}

/*
 * Compares two entries, returns 0 when they are equal, non-zero
 * otherwise.
 *
 */
int
zf_cmp_rdata(union zf_rdatom *a, union zf_rdatom *b, register char *f)
{
	register int i;
	for(i = 0; *f; f++, i++) {
		switch(*f) {
		case 'n':
		case 't':
			if(dnamecmp(a[i].p, b[i].p))
				return 1;
			break;
		case 's':
			if(a[i].s != b[i].s)
				return 1;
			break;
		case 'l':
		case '4':
			if(a[i].l != b[i].l)
				return 1;
			break;
		case '6':
			if(memcmp(a[i].p, b[i].p, IP6ADDRLEN))
				return 1;
			break;
		default:
			fflush(stdout);
			fprintf(stderr, "panic! unknown atom in format %c\n", *f);
			return 1;
		}
	}
	return 0;
}

/*
 * Prints a zone file entry to standard output.
 *
 */
void
zf_print_entry(struct zf_entry *rr)
{
	printf("%s\t%d\t%s\t%s\t", dnamestr(rr->dname), rr->ttl, classtoa(rr->class), typetoa(rr->type));

	zf_print_rdata(rr->rdata, rr->rdatafmt);

	printf("\n");
}

void
zf_print_rdata(union zf_rdatom *rdata, char *rdatafmt)
{
	int i, j;
	struct in_addr in;
	char *f;

	for(i = 0, f = rdatafmt; *f; f++, i++) {
		switch(*f) {
		case '4':
			in.s_addr = rdata[i].l;
			printf("%s\t", inet_ntoa(in));
			break;
		case '6':
			printf("%x:%x:%x:%x:%x:%x:%x:%x",
				((u_int16_t *)rdata[i].p)[0],
				((u_int16_t *)rdata[i].p)[1],
				((u_int16_t *)rdata[i].p)[2],
				((u_int16_t *)rdata[i].p)[3],
				((u_int16_t *)rdata[i].p)[4],
				((u_int16_t *)rdata[i].p)[5],
				((u_int16_t *)rdata[i].p)[6],
				((u_int16_t *)rdata[i].p)[7]);
			break;
		case 'n':
			printf("%s\t", dnamestr(rdata[i].p));
			break;
		case 'l':
			printf("%d\t", rdata[i].l);
			break;
		case 's':
			printf("%d\t", rdata[i].s);
			break;
		case 't':
			putc('"', stdout);
			for(j = 0; j < *(char *)rdata[i].p; j++) {
				putc(*(char *)(rdata[i].p+j+1), stdout);
			}
			putc('"', stdout);
			break;
		default:
			printf("???");
			break;
		}
	}
}

/*
 * Parse a directive.  The first character of token MUST be '$'.
 * Errors are reported.
 */
static void
parse_directive(struct zf *zf, char *token)
{
	char *t;
	
	if(strcasecmp(token, "$TTL") == 0) {
		int32_t ttl;
		
		if((token = zf_token(zf)) == NULL) {
			zf_error(zf, "missing TTL in directive");
			return;
		}

		ttl = strtottl(token, &t);
		
		if(*t) {
			zf_error(zf, "default ttl is not a number");
			return;
		}
		
		zf->i[zf->iptr].ttl = ttl;
	} else if(strcasecmp(token, "$ORIGIN") == 0) {
		if((token = zf_token(zf)) == NULL) {
			zf_error(zf, "missing domain name in directive");
			return;
		}
		if((t = text_to_dname(token, zf->i[zf->iptr].origin)) == NULL) {
			zf_error(zf, "invalid domain name");
			return;
		}
		free(zf->i[zf->iptr].origin);
		
		/* XXX Will fail on binary labels */
		zf->i[zf->iptr].origin = t;
	} else if(strcasecmp(token, "$INCLUDE") == 0) {
		if((token = zf_token(zf)) == NULL) {
			zf_syntax(zf);
			return;
		}
		if(zf_open_include(zf, token, zf->i[zf->iptr].origin, zf->i[zf->iptr].ttl)) {
			zf_error(zf, "cannot open include file");
		}
	} else {
		zf_error(zf, "unknown directive");
		return;
	}

	if(zf_token(zf) != NULL) {
		zf_error(zf, "trailing characters after directive");
		while (zf_token(zf) != NULL)
			;
	}
}

/*
 * Parses a RR.	 The syntax of an RR is:
 *
 *   RR ::= [<domain-name>] [<TTL>] [<class>] <type> <RDATA>
 *	  | [<domain-name>] [<class>] [<TTL>] <type> <RDATA>
 */
static int
parse_rr(struct zf *zf, char *token, int blank)
{
	int parse_error;
	char *t;
	size_t i;
	size_t text_length;
	size_t format_length;
	
	struct zf_type_tab *type;
	struct zf_class_tab *class;

	u_int16_t default_class = CLASS_IN;
	
	/* PROCESS DNAME */
	if(blank) {
		/* XXX: What if the last dname was set in the include
		 * file? Should this affect the file it was included
		 * by? It does so currently... */
		if(zf->line.dname == NULL) {
			zf_error(zf, "missing domain name");
			/* We return 0 at the end of this method. This
                           way we still fully parse this line. */
		}
	} else {
		if(zf->line.dname)
			free(zf->line.dname);
	
		/* Parse the dname */
		if((zf->line.dname = text_to_dname(token, zf->i[zf->iptr].origin)) == NULL) {
			return 0;
		}
		
		/* Get the next token */
		token = zf_token(zf);
	}
	
	/* PROCESS TTL, CLASS AND TYPE */
	zf->line.ttl = zf->i[zf->iptr].ttl;
	zf->line.class = default_class;
	
	for(type = NULL; token; token = zf_token(zf)) {
		/* Is this a TTL? */
		if(isdigit(*token)) {
			int32_t ttl = strtottl(token, &t);
			if(*t) {
				zf_error(zf, "ttl is not a number");
				token = NULL;
				break;
			}
			zf->line.ttl = ttl;
			continue;
		}
		/* Class? */
		if((class = classbyname(token)) == NULL) {
			zf->line.class = default_class;
		} else {
			zf->line.class = class->class;
			continue;
		}
		
		/* Then this must be a type */
		type = typebyname(token);
		break;
	}
	
	/* Couldn't parse ttl, class or type? */
	if(type == NULL) {
		zf_syntax(zf);
		return 0;
	}
	
	/* Do we support this type? */
	if(type->fmt == NULL) {
		zf_error(zf, "unsupported resource record type");
		return 0;
	}

	format_length = strlen(type->fmt);
	zf->line.type = type->type;
	zf->line.rdatafmt = type->fmt;
	zf->line.rdata = xalloc(format_length * sizeof(union zf_rdatom));
	memset(zf->line.rdata, 0, format_length * sizeof(union zf_rdatom));
	
	/* Parse it */
	parse_error = 0;
	for(i = 0; i < format_length && !parse_error; i++) {
		char *rdata = zf_token(zf);
		if(rdata == NULL) {
			zf_error(zf, "missing RDATA");
			parse_error++;
			break;
		}
#if DEBUG > 2
		printf("token %c - %s\n", zf->line.rdatafmt[i], rdata);
#endif
		
		switch(zf->line.rdatafmt[i]) {
		case '4':
			if((zf->line.rdata[i].l = inet_addr(rdata)) == (in_addr_t) -1) {
				zf_error(zf, "malformed ipv4 address");
				parse_error++;
			}
			break;
		case '6':
			if((zf->line.rdata[i].p = inet6_aton(rdata)) == NULL) {
				zf_error(zf, "malformed ipv6 address");
				parse_error++;
			}
			break;
		case 'n':
			if((zf->line.rdata[i].p = text_to_dname(rdata, zf->i[zf->iptr].origin)) == NULL) {
				zf_error(zf, "malformed domain name");
				parse_error++;
			}
			break;
		case 'l':
			zf->line.rdata[i].l = strtottl(rdata, &t);
			if(*t != 0) {
				zf_error(zf, "illegal long");
				parse_error++;
			}
			break;
		case 's':
			zf->line.rdata[i].s = (u_int16_t)strtol(rdata, &t, 10);
			if(*t != 0) {
				zf_error(zf, "illegal short");
				parse_error++;
			}
			break;
		case 't':
			parse_escaped_string(rdata);
			if((text_length = strlen(rdata)) > 255) {
				zf_error(zf, "character string is too long");
				parse_error++;
			} else {
				zf->line.rdata[i].p = xalloc(text_length + 1);
				memcpy(zf->line.rdata[i].p + 1,
				       rdata,
				       text_length);
				*(u_char *)zf->line.rdata[i].p = text_length;
			}
			break;
		default:
			fflush(stdout);
			fprintf(stderr, "panic! uknown atom in format %c\n",
				zf->line.rdatafmt[i]);
			abort();
		}
	}
	
	if(!parse_error && zf_token(zf) != NULL) {
		zf_error(zf, "trailing characters");
		parse_error++;
		while (zf_token(zf) != NULL)
			;
		return 0;
	}

	/* We couldnt parse it completely */
	if(parse_error) {
		zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
		return 0;
	}
	
	if(zf->line.dname == NULL) {
		/* Error is reported above at the start of this
                   function. */
		return 0;
	}
	
	return 1;
}


/*
 * Reads a line from the parser and parses it as a resource record.
 * RRs with errors are ignored (but the error is reported).
 *
 * Returns NULL on end of file.
 */
struct zf_entry *
zf_read(struct zf *zf)
{
	/* Keep reading till we could parse a line or reached end of file */
	while(zf_peekchar(zf, 1) != EOF) {
		int blank = isspace(zf_peekchar(zf, 0));
		char *token = zf_token(zf);
		if (token == NULL)
			continue;
		
		/* Process directives */
		if(token[0] == '$') {
			parse_directive(zf, token);
			continue;
		} else {
			if (!parse_rr(zf, token, blank)) {
				continue;
			}
		}

		/* Success! */
		return &zf->line;
	}

	return NULL;
}

/*
 * Closes the zone file, frees the parsing structures. Does not free
 * the current line.
 */
void
zf_close(struct zf *zf)
{
	while(zf_close_include(zf))
		;
	
	if(zf->line.dname)
		free(zf->line.dname);
	
	free(zf);
}

#ifdef TEST

void *
xalloc(size_t size)
{
	void *p;

	if((p = malloc(size)) == NULL) {
		fflush(stdout);
		fprintf(stderr, "malloc failed: %m\n");
		exit(1);
	}
	return p;
}

int
usage()
{
	fflush(stdout);
	fprintf(stderr, "usage: zf zone-file [origin]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{

	struct zf *zf;
	struct zf_entry *rr;
	u_char *origin;


	/* Check the command line */
	if(argc < 2 || argc > 3) {
		usage();
	}

	if(argc == 2) {
		origin = ".";
	} else {
		origin = argv[2];
	}

	/* Open the file */
	if((zf = zf_open(argv[1], origin)) == NULL) {
		exit(1);
	}

	/* Read the file */
	while((rr = zf_read(zf)) != NULL) {
		if(rr->class != CLASS_IN) {
			zf_error(zf, "wrong class");
			break;
		}
		if((zf->lines % 100000) == 0) {
			fflush(stdout);
			fprintf(stderr, "read %u lines...\n", zf->lines);
		}
		zf_print_entry(rr);
		zf_free_rdata(rr->rdata, rr->rdatafmt);
	}

	fflush(stdout);
	fprintf(stderr, "complete: %d errors\n", zf->errors);

	/* Close the file */
	zf_close(zf);

	return 0;
}

#endif
