/*
 * $Id: zf.c,v 1.38 2003/01/21 12:01:26 alexis Exp $
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

	bzero(&zf->line, sizeof(struct zf_entry));

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
			case 'L':
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
		case 'l':
		case '4':
			if(a[i].l != b[i].l)
				return 1;
			break;
		case '6':
			if(bcmp(a[i].p, b[i].p, IP6ADDRLEN))
				return 1;
			break;
		case 'L':
			if(bcmp(a[i].p, b[i].p, LOCRDLEN))
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
		case 'L':
			printf("%s\t", loc_ntoa(rdata[i].p, NULL, 0));
			break;
		default:
			printf("???");
			break;
		}
	}
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

#ifndef USE_INET_ADDR
	struct in_addr pin;
#endif /* !USE_INET_ADDR */

	int parse_error;
	char *line, *token;
	char *t, *f;
	int i, j;

	struct zf_type_tab *type;
	struct zf_class_tab *class;

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
			type = typebyname(token);
			break;
		}

		/* Couldn't parse ttl, class or type? */
		if(type == NULL) {
			zf_syntax(zf);
			continue;
		}

		/* Do we support this type? */
		if(type->fmt == NULL) {
			zf_error(zf, "unsupported resource record type");
			continue;
		}

		zf->line.type = type->type;
		zf->line.rdatafmt = type->fmt;
		zf->line.rdata = xalloc(sizeof(union zf_rdatom) * MAXRDATALEN);
		bzero(zf->line.rdata, sizeof(union zf_rdatom) * MAXRDATALEN);

		/* Format starting with ``*'' is an error */
		assert(*zf->line.rdatafmt != '*');

		/* Parse it */
		for(parse_error = 0, i = 0, f = zf->line.rdatafmt; *f && !parse_error; f++, i++) {
			/* Handle the star case first... */
			if(*f == '*') {
				/* Make a private format for this RR initialy */
				if(zf->line.rdatafmt == type->fmt) {
					zf->line.rdatafmt = xalloc(MAXRDATALEN + 1);
					strncpy(zf->line.rdatafmt, type->fmt, MAXRDATALEN + 2);
					f = f - type->fmt + zf->line.rdatafmt;
				}

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

			assert(i < MAXRDATALEN);

			if((token = zf_token(zf, NULL)) == NULL) {
				break;
			}
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
			case 'L':
				zf->line.rdata[i].p = xalloc(LOCRDLEN);
				
				for(t = token; token; token = zf_token(zf, NULL)) 
					*(token + strlen(token)) = ' ';
				if(loc_aton(t, zf->line.rdata[i].p) != 16)
					parse_error++;
				break;
			default:
				fprintf(stderr, "panic! uknown atom in format %c\n", *f);
				assert(0);
				return NULL;
			}
		}

		/* Was there a star? */
		if(*(f + 1) == '*') *f = 0;

		/* More atoms expected? */
		if(*f != 0) {
			zf_error(zf, "missing element");
			zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
			continue;
		}

		/* We couldnt parse it completely */
		if(parse_error) {
			zf_syntax(zf);
			zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
			continue;
		}

		/* Trailing garbage */
		if((token = zf_token(zf, NULL)) != NULL) {
			zf_error(zf, "trailing garbage");
			zf_free_rdata(zf->line.rdata, zf->line.rdatafmt);
			continue;
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
