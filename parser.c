/*
 * $Id: parser.c,v 1.3 2001/12/12 13:52:52 alexis Exp $
 *
 * parser.c -- RFC1035 master zone file parser, nsd(8)
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
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
#include "nsd.h"
#include "parser.h"

struct parser_type_tab types[] = ZONEFILE_TYPES;
struct parser_class_tab classes[] = ZONEFILE_CLASSES;

/*
 * Converts dname to text
 *
 * XXX Actually should not be here cause it is a debug routine.
 *
 */
char *
dnamestr(dname)
	u_char *dname;
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
strdname(s, o)
	char	*s;
	u_char	*o;
{
	static char dname[MAXDOMAINLEN+1];

	register char *h;
	register char *p;
	register char *d = dname + 1;

	if(*s == '@' && *(s+1) == 0) {
		bcopy(o, dname, *o + 1);
	} else {
		for(h = d, p = h + 1; *s; s++, p++) {
			if(*s == '.') {
				if(p == (h + 1)) p--;	/* Suppress empty labels */
				*h = p - h - 1;
				h = p;
			} else {
				*p = *s;
			}
		}
		*h = p - h - 1;

		/* If not absolute, append origin... */
		if((*(p-1) != 0) && (o != NULL)) {
			bcopy(o+1, p, (int) *o);
			p += *o;
		}

		*dname = (u_char) (p - d);

	}

	if((h = xalloc((int)*dname + 1)) == NULL) {
		return NULL;
	}
	bcopy(dname, h, (int)*dname + 1);
	return h;
}

/*
 *
 * Compares two domain names.
 *
 */
int
dnamecmp(a, b)
	register u_char *a;
	register u_char *b;
{
	register int r;
	register int alen = (int)*a;
	register int blen = (int)*b;

	while(alen && blen) {
		a++; b++;
		if((r = tolower(*a) - tolower(*b))) return r;
		alen--; blen--;
	}
	return alen - blen;
}

/*
 * Converts numeric value of resource record type into
 * a string.
 */
char *
typetoa(n)
	u_short n;
{
	struct parser_type_tab *type;
	static char name[5];

	for(type = types; type->type; type++)
		if(n == type->type) return type->name;

	sprintf(name, "%u", n);
	return name;
}

/*
 * Converts numeric value of resource record class into
 * a string.
 */
char *
classtoa(n)
	u_short n;
{
	struct parser_class_tab *class;
	static char name[5];

	for(class = classes; class->class; class++)
		if(n == class->class) return class->name;

	sprintf(name, "%u", n);
	return name;
}

/*
 * Returns type_tab by type name.
 *
 */
struct parser_type_tab *
typebyname(a)
	char *a;
{
	struct parser_type_tab *type;

	for(type = types; type->type; type++)
		if(strcasecmp(a, type->name) == 0) return type;
	return  NULL;
}

/*
 * Returns type_tab by type name.
 *
 */
struct parser_class_tab *
classbyname(a)
	char *a;
{
	struct parser_class_tab *class;

	for(class = classes; class->class; class++)
		if(strcasecmp(a, class->name) == 0) return class;
	return  NULL;
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
inet6_aton(str)
	char *str;
{
	char *addr;
	u_short w;
	char *p, *t, *z;

	if((addr = xalloc(IP6ADDRLEN)) == NULL) {
		return NULL;
	}

	if(!str || !addr) {
		errno = EINVAL;
		return NULL;
	}

	for(p = str, t = addr; t < (addr + 8 * sizeof(u_short)); p++) {
		if((*p == ':') || (*p == '\000')) {
			w = htons((u_short) strtol(str, &z, 16));
			if(z != p) return NULL;
			bcopy(&w, t, sizeof(u_short));
			t += sizeof(u_short);
			str = p + 1;
		}
		if(*p == '\000') {
			if(t == (addr + 8 * sizeof(u_short))) {
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
 * Handles quotes.
 *
 */
char *
zone_strtok(s)
	register char *s;
{
	register char *t;
	static char *p = "";

	if(s) {
		p = s;
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
			syslog(LOG_ERR, "missing closing quote");
			return NULL;
		}

	}
	/* Find the next delimiter */
	for(t = s; *t && *t != ' ' && *t != '\t' && *t != '\n'; t++);
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
parser_error(zf, msg)
	struct parser *zf;
	char *msg;
{
	if(zf->iptr > -1) {
		syslog(LOG_ERR, "%s in %s, line %lu", msg,
			zf->i[zf->iptr].filename,
			zf->i[zf->iptr].lineno);
	} else {
		syslog(LOG_ERR, "%s", msg);
	}
	zf->errors++;
}

/*
 * Prints syntax error related to a particular zone file.
 *
 */
void
parser_syntax(zf)
	struct parser *zf;
{
	parser_error(zf, "syntax error");
}

/*
 * Closes current include file.
 */
int
parser_close_include(zf)
	struct parser *zf;
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
parser_getline(zf)
	struct parser *zf;
{

	/* Return to upper level include file if any... */
	while(fgets(zf->linebuf, LINEBUFSZ - 1, zf->i[zf->iptr].file) == NULL) {
		if(zf->i[zf->iptr].parentheses) {
			parser_error(zf, "end of file inside of parentheses");
		}

		if(parser_close_include(zf) == 0) {
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
parser_token(zf, s)
	struct parser *zf;
	char *s;
{
	char *t, *line;

	t = zone_strtok(s);

	while((t == NULL) || (*t == ';')) {
		if(zf->i[zf->iptr].parentheses) {
			if((line = parser_getline(zf)) == NULL) {
				return NULL;
			}
			t = zone_strtok(line);
		} else {
			return NULL;
		}
	}

	switch(*t) {
	case '(':
		if(zf->i[zf->iptr].parentheses) {
			parser_error(zf, "nested open parenthes");
		} else {
			zf->i[zf->iptr].parentheses = 1;
		}
		if(*++t == 0) {
			return parser_token(zf, NULL);
		}
		break;
	case ')':
		if(!zf->i[zf->iptr].parentheses) {
			parser_error(zf, "missing open parenthes");
		} else {
			zf->i[zf->iptr].parentheses = 0;
		}
		if(*++t == 0) {
			return parser_token(zf, NULL);
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
parser_open_include(zf, filename, origin, ttl)
	struct parser *zf;
	char *filename;
	char *origin;
	long ttl;
{
	if((zf->iptr + 1 > MAXINCLUDES)) {
		parser_error(zf, "too many nested include files");
		return -1;
	}

	zf->iptr++;

	if((zf->i[zf->iptr].file = fopen(filename, "r")) == NULL) {
		syslog(LOG_ERR, "cannot open file %s: %m", filename);
		zf->iptr--;
		return -1;
	}

	zf->i[zf->iptr].lineno = 0;
	zf->i[zf->iptr].filename = strdup(filename);
	zf->i[zf->iptr].origin = origin;
	zf->i[zf->iptr].ttl = ttl;
	zf->i[zf->iptr].parentheses = 0;
	return 0;
}


/*
 * Opens a zone file and sets us up for parsing.
 */
struct parser *
parser_open(zonename, filename)
	char *zonename;
	char *filename;
{
	struct parser *zf;

	/* Allocate new handling structure */
	if((zf = xalloc(sizeof(struct parser))) == NULL) {
		return NULL;
	}

	/* Initialize it */
	zf->errors = 0;
	zf->iptr = -1;
	zf->lines = 0;

	bzero(&zf->line, sizeof(struct parser_entry));

	/* Open the main file... */
	if(parser_open_include(zf, filename, strdname(zonename, ROOT_ORIGIN), DEFAULT_TTL) == -1) {
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
parser_free_rdata(rr)
	struct parser_entry *rr;
{
	int i;
	char *f;

	if(rr->rdatafmt) {
		for(i = 0, f = rr->rdatafmt; *f; f++, i++) {
			switch(*f) {
			case 'n':
			case 'p':
			case '6':
			case 't':
				free(rr->rdata[i].p);
			}
		}
	}
}

/*
 * Prints a zone file entry to standard output.
 *
 */
void
parser_print_entry(rr)
	struct parser_entry *rr;
{
	int i, j;
	struct in_addr in;
	char *f;

	printf("%s\t%ld\t%s\t%s\t", dnamestr(rr->dname), rr->ttl, classtoa(rr->class), typetoa(rr->type));

	for(i = 0, f = rr->rdatafmt; *f; f++, i++) {
		switch(*f) {
		case '4':
			in.s_addr = rr->rdata[i].l;
			printf("%s\t", inet_ntoa(in));
			break;
		case '6':
			printf("%x:%x:%x:%x:%x:%x:%x:%x",
				((u_short *)rr->rdata[i].p)[0],
				((u_short *)rr->rdata[i].p)[1],
				((u_short *)rr->rdata[i].p)[2],
				((u_short *)rr->rdata[i].p)[3],
				((u_short *)rr->rdata[i].p)[4],
				((u_short *)rr->rdata[i].p)[5],
				((u_short *)rr->rdata[i].p)[6],
				((u_short *)rr->rdata[i].p)[7]);
			break;
		case 'n':
			printf("%s\t", dnamestr(rr->rdata[i].p));
			break;
		case 'l':
			printf("%ld\t", rr->rdata[i].l);
			break;
		case 's':
			printf("%d\t", rr->rdata[i].s);
			break;
		case 't':
			putc('"', stdout);
			for(j = 0; j < *(char *)rr->rdata[i].p; j++) {
				putc(*(char *)(rr->rdata[i].p+j+1), stdout);
			}
			putc('"', stdout);
			break;
		default:
			printf("???");
			break;
		}
	}
	printf("\n");
}

/*
 * Reads a line from the parser and parses it as a resource record.
 *
 * Returns NULL on end of file.
 *
 */
struct parser_entry *
parser_get_entry(zf)
	struct parser *zf;
{
	int parse_error;
	char *line, *token;
	char *t, *f;
	int i, j;

	struct parser_type_tab *type;
	struct parser_class_tab *class;

	u_short default_class = CLASS_IN;

	/* Keep reading till we could parse a line or reached end of file */
	while((line = parser_getline(zf))) {
		/* Skip empty lines... */
		if((token = parser_token(zf, line)) == NULL) continue;

		/* Process directives */
		if(*token == '$') {
			if(strcasecmp(token, "$TTL") == 0) {
				if((token = parser_token(zf, NULL)) == NULL) {
					parser_syntax(zf);
					continue;
				}

				zf->i[zf->iptr].ttl = strtol(token, &t, 10);

				if(*t) {
					parser_error(zf, "default ttl is not a number");
					break;
				}
			} else if(strcasecmp(token, "$ORIGIN") == 0) {
				if((token = parser_token(zf, NULL)) == NULL) {
					parser_syntax(zf);
					continue;
				}
				if((t = strdname(token, zf->i[zf->iptr].origin)) == NULL) {
					return NULL;
				}
				free(zf->i[zf->iptr].origin);
				zf->i[zf->iptr].origin = t;	/* XXX Will fail on binary labels */
			} else if(strcasecmp(token, "$INCLUDE") == 0) {
				if((token = parser_token(zf, NULL)) == NULL) {
					parser_syntax(zf);
					continue;
				}
				if(parser_open_include(zf, token, zf->i[zf->iptr].origin, zf->i[zf->iptr].ttl)) {
					parser_error(zf, "cannot open include file");
				}
			} else {
				parser_error(zf, "unknown directive");
			}
			continue;
		}

		/* PROCESS DNAME */
		if(*line == ' ' || *line == '\t') {
			if(zf->line.dname == NULL) {
				parser_error(zf, "missing domain name");
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
			token = parser_token(zf, NULL);
		}

		/* PROCESS TTL, CLASS AND TYPE */
		zf->line.ttl = zf->i[zf->iptr].ttl;
		zf->line.class = default_class;

		for(type = NULL; token; token = parser_token(zf, NULL)) {
			/* Is this a TTL? */
			if(isdigit(*token)) {
				zf->line.ttl = htonl(strtol(token, &t, 10));
				if(*t) {
					parser_error(zf, "ttl is not a number");
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
			parser_syntax(zf);
			continue;
		}

		/* Do we support this type? */
		if(type->fmt == NULL) {
			parser_error(zf, "unsupported resource record type");
			continue;
		}

		zf->line.type = type->type;
		zf->line.rdatafmt = type->fmt;

		/* Parse it */
		for(parse_error = 0, i = 0, f = zf->line.rdatafmt; *f && !parse_error; f++, i++) {
			assert(i < MAXRDATALEN);
			if((token = parser_token(zf, NULL)) == NULL) {
				break;
			}
#if DEBUG > 2
			printf("token %c - %s\n", *f, token);
#endif

			switch(*f) {
			case '4':
				if((zf->line.rdata[i].l = inet_addr(token)) == -1) {
					parser_error(zf, "malformed ipv4 address");
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
				zf->line.rdata[i].l = strtol(token, &t, 10);
				if(*t != 0) {
					parser_error(zf, "illegal long");
					parse_error++;
				}
				break;
			case 's':
				zf->line.rdata[i].s = (u_short)strtol(token, &t, 10);
				if(*t != 0) {
					parser_error(zf, "illegal short");
					parse_error++;
				}
				break;
			case 't':
				if((j = strlen(token)) > 255) {
					parser_error(zf, "character string is too long");
					parse_error++;
					break;
				} else {
					if((zf->line.rdata[i].p = xalloc(j + 1)) == NULL) {
						return NULL;
					}
					bcopy(token, zf->line.rdata[i].p + 1, j);
					*(char *)zf->line.rdata[i].p = (u_char) j;
				}
				break;
			default:
				syslog(LOG_ERR, "panic! uknown atom in format %c", *f);
				assert(0);
				return NULL;
			}
		}

		/* We couldnt parse it completely */
		if(parse_error) {
			parser_syntax(zf);
			continue;
		}

		/* Trailing garbage */
		if((token = parser_token(zf, NULL)) != NULL) {
			parser_error(zf, "trailing garbage");
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
parser_close(zf)
	struct parser *zf;
{
	while(parser_close_include(zf));
	if(zf->line.dname) free(zf->line.dname);
	free(zf);
}

#ifdef TEST

int
usage()
{
	fprintf(stderr, "usage: parser zonename parser\n");
	exit(1);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{

	struct parser *zf;
	struct parser_entry *rr;


#ifndef LOG_PERROR
#define		LOG_PERROR 0
#endif
	/* Set up the logging... */
	openlog("parser", LOG_PERROR, LOG_LOCAL5);

	/* Check the command line */
	if(argc != 3) {
		usage();
	}

	/* Open the file */
	if((zf = parser_open(argv[1], argv[2])) == NULL) {
		exit(1);
	}

	/* Read the file */
	while((rr = parser_get_entry(zf)) != NULL) {
		if(rr->class != CLASS_IN) {
			parser_error(zf, "wrong class");
			break;
		}
		parser_print_entry(rr);
		parser_free_rdata(rr);
	}

	fprintf(stderr, "complete: %d errors\n", zf->errors);

	/* Close the file */
	parser_close(zf);

	return 0;
}

#endif
