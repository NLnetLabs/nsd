/*
 * $Id: zf.c,v 1.1 2002/01/08 13:29:21 alexis Exp $
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
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
#include "nsd.h"
#include "zf.h"

struct zf_type_tab types[] = ZONEFILE_TYPES;
struct zf_class_tab classes[] = ZONEFILE_CLASSES;

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
		for(p = dname, s = o; (u_char *)s < o + *o + 1; p++, s++)
			*p = tolower(*s);
	} else {
		for(h = d, p = h + 1; *s; s++, p++) {
			if(*s == '.') {
				if(p == (h + 1)) p--;	/* Suppress empty labels */
				*h = p - h - 1;
				h = p;
			} else {
				*p = tolower(*s);
			}
		}
		*h = p - h - 1;

		/* If not absolute, append origin... */
		if((*(p-1) != 0) && (o != NULL)) {
			for(s = o + 1; (u_char *)s < o + *o + 1; p++, s++)
				*p = tolower(*s);
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
	struct zf_type_tab *type;
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
	struct zf_class_tab *class;
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
struct zf_type_tab *
typebyname(a)
	char *a;
{
	struct zf_type_tab *type;

	for(type = types; type->type; type++)
		if(strcasecmp(a, type->name) == 0) return type;
	return  NULL;
}

/*
 * Returns type_tab by type name.
 *
 */
struct zf_class_tab *
classbyname(a)
	char *a;
{
	struct zf_class_tab *class;

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

	addr = xalloc(IP6ADDRLEN);

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
zf_error(zf, msg)
	struct zf *zf;
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
zf_syntax(zf)
	struct zf *zf;
{
	zf_error(zf, "syntax error");
}

/*
 * Closes current include file.
 */
int
zf_close_include(zf)
	struct zf *zf;
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
zf_getline(zf)
	struct zf *zf;
{

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
zf_token(zf, s)
	struct zf *zf;
	char *s;
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
zf_open_include(zf, filename, origin, ttl)
	struct zf *zf;
	char *filename;
	char *origin;
	long ttl;
{
	if((zf->iptr + 1 > MAXINCLUDES)) {
		zf_error(zf, "too many nested include files");
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
struct zf *
zf_open(filename, origin)
	char *filename;
	u_char *origin;
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
	if(zf_open_include(zf, filename, strdname(origin, ROOT_ORIGIN), DEFAULT_TTL) == -1) {
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
zf_free_rdata(rr)
	struct zf_entry *rr;
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
zf_print_entry(rr)
	struct zf_entry *rr;
{
	printf("%s\t%ld\t%s\t%s\t", dnamestr(rr->dname), rr->ttl, classtoa(rr->class), typetoa(rr->type));

	zf_print_rdata(rr->rdata, rr->rdatafmt);

	printf("\n");
}

void
zf_print_rdata(rdata, rdatafmt)
	union zf_rdatom *rdata;
	char *rdatafmt;
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
				((u_short *)rdata[i].p)[0],
				((u_short *)rdata[i].p)[1],
				((u_short *)rdata[i].p)[2],
				((u_short *)rdata[i].p)[3],
				((u_short *)rdata[i].p)[4],
				((u_short *)rdata[i].p)[5],
				((u_short *)rdata[i].p)[6],
				((u_short *)rdata[i].p)[7]);
			break;
		case 'n':
			printf("%s\t", dnamestr(rdata[i].p));
			break;
		case 'l':
			printf("%ld\t", rdata[i].l);
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
 * Reads a line from the parser and parses it as a resource record.
 *
 * Returns NULL on end of file.
 *
 */
struct zf_entry *
zf_read(zf)
	struct zf *zf;
{
	int parse_error;
	char *line, *token;
	char *t, *f;
	int i, j;

	struct zf_type_tab *type;
	struct zf_class_tab *class;

	u_short default_class = CLASS_IN;

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

				zf->i[zf->iptr].ttl = strtol(token, &t, 10);

				if(*t) {
					zf_error(zf, "default ttl is not a number");
					break;
				}
			} else if(strcasecmp(token, "$ORIGIN") == 0) {
				if((token = zf_token(zf, NULL)) == NULL) {
					zf_syntax(zf);
					continue;
				}
				if((t = strdname(token, zf->i[zf->iptr].origin)) == NULL) {
					return NULL;
				}
				free(zf->i[zf->iptr].origin);
				zf->i[zf->iptr].origin = t;	/* XXX Will fail on binary labels */
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
				zf->line.ttl = htonl(strtol(token, &t, 10));
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

		/* Parse it */
		for(parse_error = 0, i = 0, f = zf->line.rdatafmt; *f && !parse_error; f++, i++) {
			assert(i < MAXRDATALEN);
			if((token = zf_token(zf, NULL)) == NULL) {
				break;
			}
#if DEBUG > 2
			printf("token %c - %s\n", *f, token);
#endif

			switch(*f) {
			case '4':
				if((zf->line.rdata[i].l = inet_addr(token)) == -1) {
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
				zf->line.rdata[i].l = strtol(token, &t, 10);
				if(*t != 0) {
					zf_error(zf, "illegal long");
					parse_error++;
				}
				break;
			case 's':
				zf->line.rdata[i].s = (u_short)strtol(token, &t, 10);
				if(*t != 0) {
					zf_error(zf, "illegal short");
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
			default:
				syslog(LOG_ERR, "panic! uknown atom in format %c", *f);
				assert(0);
				return NULL;
			}
		}

		/* We couldnt parse it completely */
		if(parse_error) {
			zf_syntax(zf);
			zf_free_rdata(zf->line);
			continue;
		}

		/* Trailing garbage */
		if((token = zf_token(zf, NULL)) != NULL) {
			zf_error(zf, "trailing garbage");
			zf_free_rdata(zf->line);
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
zf_close(zf)
	struct zf *zf;
{
	while(zf_close_include(zf));
	if(zf->line.dname) free(zf->line.dname);
	free(zf);
}

#ifdef TEST

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


#ifndef LOG_PERROR
#define		LOG_PERROR 0
#endif
	/* Set up the logging... */
	openlog("zf", LOG_PERROR, LOG_LOCAL5);

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
			fprintf(stderr, "read %lu lines...\n", zf->lines);
		}
		zf_print_entry(rr);
		zf_free_rdata(rr);
	}

	fprintf(stderr, "complete: %d errors\n", zf->errors);

	/* Close the file */
	zf_close(zf);

	return 0;
}

#endif
