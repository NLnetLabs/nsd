/*
 * $Id: zf.c,v 1.44 2003/02/11 14:51:54 alexis Exp $
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
#include "config.h"

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
 * Converts one digit to a hex number
 *
 */
int
chartoi (char c)
{
	c = tolower(c);

	switch(c) {
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
		return c - '0';
	case 'a':
	case 'b':
	case 'c':
	case 'd':
	case 'e':
	case 'f':
		return c - 'a' + 10;
	default:
		return -1;
	}
}

/*
 * Converts dname to text
 *
 * XXX Actually should not be here cause it is a debug routine.
 *
 */
char *
dnamestr (u_char *dname)
{
	static char s[MAXDOMAINLEN+1];
	char *p;
	int l;
	u_char *n = dname;

	l = (int) *dname;
	n++;
	p = s;

	if(*n) {
		while(n < dname + l) {
			bcopy(n+1, p, (int) *n);
			p += (int) *n;
			*p++ = '.';
			n += (int) *n + 1;
		}
	} else {
		*p++ = '.';
	}
	*p = 0;
	return s;
}

/*
 * Parses the string and returns a dname with
 * the first byte indicating the size of the entire
 * dname.
 *
 * XXX Check if we dont run out of space (p < d + len)
 * XXX Verify that every label dont exceed MAXLABELLEN
 * XXX Complain about empty labels (.nlnetlabs..nl)
 */
u_char *
strdname (char *s, u_char *o)
{
	static u_char dname[MAXDOMAINLEN+1];

	register u_char *h;
	register u_char *p;
	register u_char *d = dname + 1;

	if(*s == '@' && *(s+1) == 0) {
		for(p = dname, s = (char *)o; (u_char *)s < o + *o + 1; p++, s++)
			*p = NAMEDB_NORMALIZE(*s);
	} else {
		for(h = d, p = h + 1; *s; s++, p++) {
			switch(*s) {
			case '.':
				if(p == (h + 1)) p--;	/* Suppress empty labels */
				*h = p - h - 1;
				h = p;
				break;
			case '\\':			/* Do we have a \. ? */
				if(*(s + 1) == '.')
					s++;
			default:
				*p = NAMEDB_NORMALIZE(*s);
			}
		}
		*h = p - h - 1;

		/* If not absolute, append origin... */
		if((*(p-1) != 0) && (o != NULL)) {
			for(s = (char *)o + 1; (u_char *)s < o + *o + 1; p++, s++)
				*p = NAMEDB_NORMALIZE(*s);
		}

		*dname = (u_char) (p - d);

	}

	h = xalloc((int)*dname + 1);
	bcopy(dname, h, (int)*dname + 1);
	return h;
}

/*
 *
 * Compares two domain names.
 *
 */
int 
dnamecmp (register u_char *a, register u_char *b)
{
	register int r;
	register int alen = (int)*a;
	register int blen = (int)*b;

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
char *
typetoa (int n)
{
	struct zf_type_tab *type;
	static char name[9];

	for(type = zf_types; type->type; type++)
		if(n == type->type) return type->name;

	snprintf(name, sizeof(name), "TYPE%u", n);
	return name;
}

/*
 * Converts numeric value of resource record class into
 * a string.
 */
char *
classtoa (int n)
{
	struct zf_class_tab *class;
	static char name[5];

	for(class = zf_classes; class->class; class++)
		if(n == class->class) return class->name;

	snprintf(name, sizeof(name), "%u", n);
	return name;
}

/*
 * Returns type_tab by type name.
 *
 */
struct zf_type_tab *
typebyname (char *a)
{
	struct zf_type_tab *type;

	for(type = zf_types; type->type; type++)
		if(strcasecmp(a, type->name) == 0) return type;
	return  NULL;
}

/*
 * Returns type_tab by type name.
 *
 */
struct zf_class_tab *
classbyname (char *a)
{
	struct zf_class_tab *class;

	for(class = zf_classes; class->class; class++)
		if(strcasecmp(a, class->name) == 0) return class;
	return  NULL;
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
long 
strtottl (char *nptr, char **endptr)
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

/*
 * Handles quotes.
 *
 */
char *
zone_strtok (register char *s)
{
	/* Special tokens */
	register char *t;
	static char *p = "";
	static char saved = 0;

	/* Is this a new string? */
	if(s) {
		p = s;
		saved = 0;
	} else if(saved) {
		*p = saved;
		saved = 0;
	}

	/* Skip leading delimiters */
	for(s = p; *s == ' ' || *s == '\t' || *s == '\n'; s++);

	/* Quotes... */
	if(*s == '"') {
		for(t = ++s; *t && *t != '"'; t++);
		if(*t) {
			*t = '\000';
			p = t + 1;
			return s;
		} else {
			fprintf(stderr, "missing closing quote\n");
			return NULL;
		}

	}
	/* Find the next delimiter */
	for(t = s; *t && *t != ' ' && *t != '\t' && *t != '\n'; t++) {
		if(t > s) {
			switch(*t) {
			case '(':
			case ')':
			case ';':
				saved = *t;
				*t = '\000';
				p = t;
				return s;
			}
		}
	}

	if(t == s) return NULL;

	if(*t) {
		*t = '\000';
		p = t + 1;
	} else {
		p = t;
	}

	return s;
}

/*
 * Prints an error message related to a particular zone file.
 */
void 
zf_error (struct zf *zf, char *msg)
{
	if(zf->iptr > -1) {
		fprintf(stderr, "%s in %s, line %lu\n", msg,
			zf->i[zf->iptr].filename,
			zf->i[zf->iptr].lineno);
	} else {
		fprintf(stderr, "%s\n", msg);
	}
	zf->errors++;
}

/*
 * Prints syntax error related to a particular zone file.
 *
 */
void 
zf_syntax (struct zf *zf)
{
	zf_error(zf, "syntax error");
}

/*
 * Closes current include file.
 */
int 
zf_close_include (struct zf *zf)
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
 * Gets a line from the current zone file, returns to higher
 * level include file if end of file. XXX Check for truncated lines?
 */
char *
zf_getline (struct zf *zf)
{

	/* Already at the top level */
	if(zf->iptr < 0) {
		return NULL;
	}

	/* Return to upper level include file if any... */
	while(fgets(zf->linebuf, LINEBUFSZ - 1, zf->i[zf->iptr].file) == NULL) {
		if(zf->i[zf->iptr].parentheses) {
			zf_error(zf, "end of file inside of parentheses");
		}

		if(zf_close_include(zf) == 0) {
			return NULL;
		}
	}

	/* New line */
	zf->i[zf->iptr].lineno++;
	zf->lines++;

	return zf->linebuf;
}


/*
 * Returns next token, with regard to '(' and ')'
 *
 */
char *
zf_token (struct zf *zf, char *s)
{
	char *t, *line;

	t = zone_strtok(s);

	while((t == NULL) || (*t == ';')) {
		if(zf->i[zf->iptr].parentheses) {
			if((line = zf_getline(zf)) == NULL) {
				return NULL;
			}
			t = zone_strtok(line);
		} else {
			return NULL;
		}
	}

	switch(*t) {
	case '(':
		/* Disregard the bracket if it is quoted */
		if(*(t-1) == '"') break;

		if(zf->i[zf->iptr].parentheses) {
			zf_error(zf, "nested open parenthes");
		} else {
			zf->i[zf->iptr].parentheses = 1;
		}
		if(*++t == 0) {
			return zf_token(zf, NULL);
		}
		break;
	case ')':
		if(!zf->i[zf->iptr].parentheses) {
			zf_error(zf, "missing open parenthes");
		} else {
			zf->i[zf->iptr].parentheses = 0;
		}
		if(*++t == 0) {
			return zf_token(zf, NULL);
		}
		break;
	}
	return t;
}

/*
 * Opens a file.
 *
 */
int 
zf_open_include (struct zf *zf, char *filename, u_char *origin, int32_t ttl)
{
	if((zf->iptr + 1 > MAXINCLUDES)) {
		zf_error(zf, "too many nested include files");
		return -1;
	}

	zf->iptr++;

	if((zf->i[zf->iptr].file = fopen(filename, "r")) == NULL) {
		fprintf(stderr, "cannot open file %s: %s\n", filename, strerror(errno));
		zf->iptr--;
		return -1;
	}

	zf->i[zf->iptr].lineno = 0;
	zf->i[zf->iptr].filename = strdup(filename);
	zf->i[zf->iptr].origin = (u_char *)strdup((char *)origin);
					/* XXX strdup() should be replaced with dnamedup() */
	zf->i[zf->iptr].ttl = ttl;
	zf->i[zf->iptr].parentheses = 0;
	return 0;
}


/*
 * Opens a zone file and sets us up for parsing.
 */
struct zf *
zf_open (char *filename, char *strorigin)
{
	struct zf *zf;

	/* Allocate new handling structure */
	zf = xalloc(sizeof(struct zf));

	/* Initialize it */
	zf->errors = 0;
	zf->iptr = -1;
	zf->lines = 0;

	memset(&zf->line, 0, sizeof(struct zf_entry));

	/* Open the main file... */
	if(zf_open_include(zf, filename, strdname(strorigin, (u_char *)ROOT_ORIGIN), DEFAULT_TTL) == -1) {
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
zf_free_rdata (union zf_rdatom *rdata, char *f)
{
	int i;

	if(rdata) {
		for(i = 0; *f; f++, i++) {
			switch(*f) {
			case 'n':
			case '6':
			case 't':
			case 'U':
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
zf_cmp_rdata (union zf_rdatom *a, union zf_rdatom *b, register char *f)
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
		case 'c':
			if(a[i].c != b[i].c)
				return 1;
			break;
		case 'l':
		case '4':
			if(a[i].l != b[i].l)
				return 1;
			break;
		case '6':
			if(bcmp(a[i].p, b[i].p, IP6ADDRLEN))
				return 1;
			break;
		case 'U':
			if(*((u_int16_t *)a[i].p) != *((u_int16_t *)b[i].p))
				return 1;
			if(bcmp(((u_int16_t *)a[i].p) + 1, ((u_int16_t *)b[i].p) + 1,
					*((u_int16_t *)a[i].p)))
				return 1;
			break;
		default:
			fprintf(stderr, "panic! uknown atom in format %c\n", *f);
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
zf_print_entry (struct zf_entry *rr)
{
	printf("%s\t%d\t%s\t%s\t", dnamestr(rr->dname), rr->ttl, classtoa(rr->class), typetoa(rr->type));

	zf_print_rdata(rr->rdata, rr->rdatafmt);

	printf("\n");
}

void 
zf_print_rdata (union zf_rdatom *rdata, char *rdatafmt)
{
	int i, j, k;
	struct in_addr in;
	char *f, *t;

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
		case 'c':
			printf("%d\t", rdata[i].c);
			break;
		case 't':
			putc('"', stdout);
			for(j = 0; j < *(char *)rdata[i].p; j++) {
				putc(*(char *)(rdata[i].p+j+1), stdout);
			}
			putc('"', stdout);
			break;
		case 'U':
			k = *((u_int16_t *)rdata[i].p);
			for(t = (char *)(((u_int16_t *)rdata[i].p) + 1); k--; t++) {
				printf("%x", *t);
				if((k % 16) == 0) {
					if((k % 64)) {
						printf("\n\t\t\t");
					} else {
						printf(" ");
					}
				}
			}
			break;
		default:
			printf("???");
			break;
		}
	}
}

/*
 *
 * Parse rdata in uknown format according to draft-ietf-dnsext-unknown-rrs-04
 *
 */
int
zf_parse_unkn (struct zf *zf, char *token) {
	u_int16_t unkn_size;
	char *t;
	int c;
	int error = 0;

	/* Get the rdlength */
	if((token = zf_token(zf, NULL)) == NULL) {
		zf_syntax(zf);
		return -1;
	}

	unkn_size = (u_int16_t)strtol(token, &t, 10);
	if(*t) {
		zf_error(zf, "illegal number of octets with uknown rr");
		return -1;
	}

	free(zf->line.rdatafmt);
	zf->line.rdatafmt = strdup("U");

	zf->line.rdata[0].p = xalloc(unkn_size + sizeof(u_int16_t));
	*((u_int16_t *)zf->line.rdata[0].p) = unkn_size;

	t = (char *)zf->line.rdata[0].p + sizeof(u_int16_t); 

	while(unkn_size && !error) {
		if((token = zf_token(zf, NULL)) == NULL) {
			zf_error(zf, "insufficient bytes for unknown record");
			error++;
			break;
		}
		while(unkn_size && *token) {
			if((c = chartoi(*(token++))) == -1) {
				zf_syntax(zf);
				error++;
				break;
			}
			*t = c * 16;
			if(*token == 0) {
				zf_error(zf, "uneven number of octets for unknown record");
				error++;
				break;
			}
			if((c = chartoi(*(token++))) == -1) {
				zf_syntax(zf);
				error++;
				break;
			}
			*t++ += c;
			unkn_size--;
		}
	}
	if(error || unkn_size != 0) {
		if(error == 0) {
			zf_error(zf, "insufficient number of octets");
		}
		free(zf->line.rdatafmt);
		free(zf->line.rdata[0].p);
		return -1;
	}

	return 0;
}


/*
 * Special parser for LOC record.
 *
 */
int
zf_parse_loc (struct zf *zf, char *token)
{
	char *t;

	zf->line.rdata[0].p = xalloc(LOCRDLEN + 2);
	
	for(t = token; token; token = zf_token(zf, NULL))  {
		*(token + strlen(token)) = ' ';
	}

	*((u_int16_t *)zf->line.rdata[0].p) = LOCRDLEN;
	if(loc_aton(t, zf->line.rdata[0].p + sizeof(u_int16_t)) != LOCRDLEN) {
		return -1;
	}
	return 0;
}

/*
 *
 * Parse a line according to the format string.
 *
 */
int
zf_parse_format (struct zf *zf, char *token, int start, int stop)
{

#ifndef USE_INET_ADDR
	struct in_addr pin;
#endif /* !USE_INET_ADDR */

	int parse_error;
	int i, j;
	char *f, *t;

	/* Format starting with ``*'' is an error */
	assert(*zf->line.rdatafmt != '*');

	/* Parse it */
	for(parse_error = 0, i = start, f = zf->line.rdatafmt + start;
			*f && token != NULL && !parse_error; i++) {


		assert(i < MAXRDATALEN);

#if DEBUG > 2
		printf("token %c - %s\n", *f, token);
#endif

		switch(*f) {
		case '4':
#ifdef USE_INET_ADDR
			if((zf->line.rdata[i].l = inet_addr(token)) == -1) {
#else
				if(inet_aton(token, &pin) == 1) {
					zf->line.rdata[i].l = pin.s_addr;
				} else {
#endif /* USE_INET_ADDR */
				zf_error(zf, "malformed ipv4 address");
				parse_error++;
			}
			break;
		case '6':
			if((zf->line.rdata[i].p = inet6_aton(token)) == NULL) {
				parse_error++;
			}
			break;
		case 'n':
			if((zf->line.rdata[i].p = strdname(token, zf->i[zf->iptr].origin)) == NULL) {
				parse_error++;
			}
			break;
		case 'l':
			zf->line.rdata[i].l = strtottl(token, &t);
			if(*t != 0) {
				zf_error(zf, "decimal number or time interval is expected");
				parse_error++;
			}
			break;
		case 's':
			zf->line.rdata[i].s = (u_int16_t)strtol(token, &t, 10);
			if(*t != 0) {
				zf_error(zf, "decimal number is expected");
				parse_error++;
			}
			break;
		case 'c':
			j = (u_int16_t)strtol(token, &t, 10);
			if(*t != 0 || j < 0 || j > 255) {
				zf_error(zf, "decimal number is expected");
				parse_error++;
			} else {
				zf->line.rdata[i].c = (u_char) j;
			}
			break;
		case 't':
			if((j = strlen(token)) > 255) {
				zf_error(zf, "character string is too long");
				parse_error++;
				break;
			} else {
				zf->line.rdata[i].p = xalloc(j + 1);
				bcopy(token, zf->line.rdata[i].p + 1, j);
				*(char *)zf->line.rdata[i].p = (u_char) j;
			}
			break;
		default:
			fprintf(stderr, "panic! uknown atom in format %c\n", *f);
			assert(0);
			return NULL;
		}

		/* Dont do anything further if we have to stop... */
		if(i == stop)
			return 0;

		f++;

		/* Handle the star case... */
		if(*f == '*') {
			/* Make a private format for this RR initialy if not done already*/
			zf->line.rdatafmt = xrealloc(zf->line.rdatafmt, MAXRDATALEN + 1);

			/* Copy the previous atom */
			*f = *(f - 1);
			memcpy(f + 1, "*", 2);

			/* Make sure we dont overflow */
			if((f - zf->line.rdatafmt) >= MAXRDATALEN) {
				zf_error(zf, "maximum number of elements exceeded");
				parse_error++;
				break;
			}
		}

		/* Get the next token... */
		token = zf_token(zf, NULL);
	}

	/* Was there a star? */
	if(*f && *(f + 1) == '*') *f = 0;

	/* More atoms expected? */
	if(*f != 0) {
		zf_error(zf, "missing element");
		zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
		return -1;
	}

	/* We couldnt parse it completely */
	if(parse_error) {
		zf_syntax(zf);
		zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
		return -1;
	}

	/* Trailing garbage... */
	if(token != NULL) {
		zf_error(zf, "trailing garbage");
		zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
		return -1;
	}

	return 0;
}

/*
 * Parse the rest of the line as base64 encoded string.
 *
 */
int
zf_parse_b64 (struct zf *zf, char *token, int start)
{
	int n;
	u_char *t;
	int s = 65535;

	t = zf->line.rdata[start].p = xalloc(s + sizeof(u_int16_t));
	t += sizeof(u_int16_t);
	
	while(token) {
		if((n = __b64_pton(token, t, s)) == -1) {
			zf_error(zf, "base64 encoding failed");
			free(zf->line.rdata[start].p);
			return -1;
		}
		t += n;
		s -= n;
		/* We ran out of buffer space... */
		if(s <= 0) {
			zf_error(zf, "out of buffer space");
			free(zf->line.rdata[start].p);
			return -1;
		}
		token = zf_token(zf, NULL);
	}
	*((u_int16_t *)zf->line.rdata[start].p) = t - zf->line.rdata[start].p
		- sizeof(u_int16_t);
	zf->line.rdata[start].p = xrealloc(zf->line.rdata[start].p, *((u_int16_t *)zf->line.rdata[start].p));

	return 0;
}

/*
 * Special parser for NXT record.
 *
 */
int
zf_parse_nxt (struct zf *zf, char *token)
{
	struct zf_type_tab *type;
	int byte;

	/* Parse the domain name... */
	if(zf_parse_format(zf, token, 0, 0) != 0)
		return -1;

	/* Get the first name... */
	if((token = zf_token(zf, NULL)) == NULL) {
		zf_error(zf, "types covered expected for NXT record");
		return -1;
	}

	zf->line.rdata[1].p = xalloc(16 + sizeof(u_int16_t));

	/* Initial size is 0, however it will always be 4 because we always set NXT bit... */
	*((u_int16_t *)zf->line.rdata[1].p) = 0;

	do {
		/* Find out which type is covered */
		if((type = typebyname(token)) == NULL) {
			zf_error(zf, "unknown type in a NXT record");
			return -1;
		}
		/* We dont support anything higher than 127 */
		if(type->type > 127) {
			zf_error(zf, "types higher than TYPE127 are not supported at this time");
			return -1;
		}
		/* Now set the bit and adjust the length of the bit map if needed */
		byte = type->type >> 3;
		zf->line.rdata[1].p[byte + 2] |= (1 << (type->type & 0x7));
		if(*((u_int16_t *)zf->line.rdata[1].p) < byte)
			*((u_int16_t *)zf->line.rdata[1].p) = byte;
	} while((token = zf_token(zf, NULL)) != NULL);

	/* Complain if NXT bit is not set */
	if(!(zf->line.rdata[1].p[(TYPE_NXT >> 3) + 2] & (1 << (TYPE_NXT & 0x7)))) {
		zf_error(zf, "NXT record must always cover NXT type");
		return -1;
	}
	return 0;
}

/*
 * Special parser for SIG record
 *
 */
int
zf_parse_sig (struct zf *zf, char *token)
{
	int i;
	struct tm tm;
	struct zf_type_tab *type;

	if((type = typebyname(token)) == NULL) {
		zf_error(zf, "unknown type in a SIG record");
		return -1;
	}

	/* Here we assume that token is always large enough, i.e. A still fits 1 */
	snprintf(token, strlen(token), "%d", type->type);

	/* Parse the first part... */
	if(zf_parse_format(zf, token, 0, 3) != 0)
		return -1;

	/* Now scan the dates */
	for(i = 4; i <= 5; i++) {
		if((token = zf_token(zf, NULL)) == NULL) {
			zf_error(zf, "time field is expected");
			free(zf->line.rdatafmt);
			return -1;
		}
		if((token = strptime(token, "%Y%m%d%H%M%S", &tm)) == NULL || *token != 0) {
			zf_error(zf, "invalid time value specified");
			free(zf->line.rdatafmt);
			return -1;
		}
		zf->line.rdata[i].l = mktime(&tm);
	}


	/* A bit more format */
	if((token = zf_token(zf, NULL)) == NULL) {
		zf_syntax(zf);
		return -1;
	}

	if(zf_parse_format(zf, token, 6, 7) != 0)
		return -1;

	/* And the last bit */
	if((token = zf_token(zf, NULL)) == NULL) {
		zf_error(zf, "missing signature data");
		return -1;
	}

	return zf_parse_b64(zf, token, 8);
}

/*
 * Special parser for KEY record.
 *
 */
int
zf_parse_key (struct zf *zf, char *token)
{
	char *t;
	zf->line.rdatafmt[3] = 0;

	/* Parse the first part with a standard parser */
	if(zf_parse_format(zf, token, 0, 2) != 0) {
		free(zf->line.rdatafmt);
		return -1;
	}

	/* A no key situation... */
	if((zf->line.rdata[0].s & 0x1100) == 0x1100)
		return 1;

	/* Otherwise restart with base64 format parser... */
	zf->line.rdatafmt[3] = 'U';
	if((token = zf_token(zf, NULL)) == NULL) {
		zf_error(zf, "key value is expected");
		free(zf->line.rdatafmt);
		return -1;
	}
	return zf_parse_b64(zf, token, 3);
}

/*
 * Reads a line from the parser and parses it as a resource record.
 *
 * Returns NULL on end of file.
 *
 */
struct zf_entry *
zf_read (struct zf *zf)
{
	char *line, *token;
	char *t, *f;
	int i, j;

	struct zf_type_tab *type;
	struct zf_class_tab *class;
	struct zf_type_tab unkn_type;
	u_int16_t unkn_size;

	u_int16_t default_class = CLASS_IN;

	/* Keep reading till we could parse a line or reached end of file */
	while((line = zf_getline(zf))) {
		/* Skip empty lines... */
		if((token = zf_token(zf, line)) == NULL) continue;

		/* Process directives */
		if(*token == '$') {
			if(strcasecmp(token, "$TTL") == 0) {
				if((token = zf_token(zf, NULL)) == NULL) {
					zf_syntax(zf);
					continue;
				}

				zf->i[zf->iptr].ttl = strtottl(token, &t);

				if(*t) {
					zf_error(zf, "default ttl is not a number");
					break;
				}
			} else if(strcasecmp(token, "$ORIGIN") == 0) {
				if((token = zf_token(zf, NULL)) == NULL) {
					zf_syntax(zf);
					continue;
				}
				if((t = (char *)strdname(token, zf->i[zf->iptr].origin)) == NULL) {
					return NULL;
				}
				free(zf->i[zf->iptr].origin);
				zf->i[zf->iptr].origin = (u_char *)t;	/* XXX Will fail on binary labels */
			} else if(strcasecmp(token, "$INCLUDE") == 0) {
				if((token = zf_token(zf, NULL)) == NULL) {
					zf_syntax(zf);
					continue;
				}
				if(zf_open_include(zf, token, zf->i[zf->iptr].origin, zf->i[zf->iptr].ttl)) {
					zf_error(zf, "cannot open include file");
				}
			} else {
				zf_error(zf, "unknown directive");
			}
			continue;
		}

		/* PROCESS DNAME */
		if(*line == ' ' || *line == '\t') {
			if(zf->line.dname == NULL) {
				zf_error(zf, "missing domain name");
				continue;
			}
		} else {
			/* Free the old name */
			if(zf->line.dname)
				free(zf->line.dname);
			/* Parse the dname */
			if((zf->line.dname = strdname(token, zf->i[zf->iptr].origin)) == NULL) {
				return NULL;
			}

			/* Get the next token */
			token = zf_token(zf, NULL);
		}

		/* PROCESS TTL, CLASS AND TYPE */
		zf->line.ttl = zf->i[zf->iptr].ttl;
		zf->line.class = default_class;

		for(type = NULL; token; token = zf_token(zf, NULL)) {
			/* Is this a TTL? */
			if(isdigit(*token)) {
				zf->line.ttl = strtottl(token, &t);
				if(*t) {
					zf_error(zf, "ttl is not a number");
					token = NULL;
					break;
				}
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
			if(strncasecmp(token, "TYPE", 4) == 0) {
				if((unkn_type.type = atoi(token+4)) == 0) {
					type = NULL; /* Syntax error below */
				} else {
					unkn_type.fmt = NULL;
					unkn_type.name = token;
					type = &unkn_type;
				}
			} else {
				type = typebyname(token);
			}
			break;
		}

		/* Couldn't parse ttl, class or type? */
		if(type == NULL) {
			zf_syntax(zf);
			continue;
		}

		/* Get the next token to see what it is */
		if((token = zf_token(zf, NULL)) == NULL) {
			zf_syntax(zf);
			continue;
		}

		if(type->fmt == NULL) {
			if(strcmp(token, "\\#")) {
				zf_error(zf, "uknown type rdata does not begin with \\#");
				continue;
			} else {
				unkn_type.fmt = "U";
			}
		}

		zf->line.type = type->type;
		zf->line.rdatafmt = strdup(type->fmt);
		zf->line.rdata = xalloc(sizeof(union zf_rdatom) * MAXRDATALEN);
		memset(zf->line.rdata, 0, sizeof(union zf_rdatom) * MAXRDATALEN);

		/* Is this UNKN form? */
		if(strcmp(token, "\\#") == 0) {
			if(zf_parse_unkn(zf, token) != 0)
				continue;
		} else {
			switch(zf->line.type) {
			case TYPE_LOC:
				if(zf_parse_loc(zf, token) != 0)
					continue;
				break;
			case TYPE_KEY:
				if(zf_parse_key(zf, token) != 0)
					continue;
				break;
			case TYPE_SIG:
				if(zf_parse_sig(zf, token) != 0)
					continue;
				break;
			case TYPE_NXT:
				if(zf_parse_nxt(zf, token) != 0)
					continue;
				break;
			default:
				/* Do we support this type? */
				if(zf->line.rdatafmt == NULL) {
					zf_error(zf, "unsupported resource record type");
					return NULL;
				}
				if(zf_parse_format(zf, token, 0, -1) != 0)
					continue;
				break;
			}
		}

		/* Success! */
		return &zf->line;
	}

	return NULL;
}

/*
 * Closes the zone file, frees the parsing structures. Does not free the
 * current line.
 *
 */
void
zf_close (struct zf *zf)
{
	while(zf_close_include(zf));
	if(zf->line.dname) free(zf->line.dname);
	free(zf);
}

/*
 * inet6_aton() - ipv6 brother for inet_aton()
 *
 * Returns inet6 address.
 *
 *
 */
void *
inet6_aton (char *str)
{
	char *addr;

	addr = xalloc(IP6ADDRLEN);
	if(!str || !addr) {
		errno = EINVAL;
		return NULL;
	}
	if(inet_pton(AF_INET6, str, addr) == 1) {
		return addr;
	}
	free(addr);
	return NULL;
}


#ifdef TEST

void *
xalloc(size)
	register size_t	size;
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "malloc failed: %m\n");
		exit(1);
	}
	return p;
}

int
usage()
{
	fprintf(stderr, "usage: zf zone-file [origin]\n");
	exit(1);
}

int
main(argc, argv)
	int argc;
	char *argv[];
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
			fprintf(stderr, "read %u lines...\n", zf->lines);
		}
		zf_print_entry(rr);
		zf_free_rdata(rr->rdata, rr->rdatafmt);
	}

	fprintf(stderr, "complete: %d errors\n", zf->errors);

	/* Close the file */
	zf_close(zf);

	return 0;
}

#endif
