/*
 * $Id: dname.c,v 1.4 2003/02/12 21:43:35 alexis Exp $
 *
 * dname.c -- dname operations
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
#include <config.h>

#include <sys/types.h>

#include <ctype.h>
#include <stdio.h>


#include <dns.h>
#include <dname.h>


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
		if((r = DNAME_NORMALIZE(*a) - DNAME_NORMALIZE(*b))) return r;
		alen--; blen--;
	}
	return alen - blen;
}

/*
 *
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
			memcpy(p, n+1, (int) *n);
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
			*p = DNAME_NORMALIZE(*s);
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
				*p = DNAME_NORMALIZE(*s);
			}
		}
		*h = p - h - 1;

		/* If not absolute, append origin... */
		if((*(p-1) != 0) && (o != NULL)) {
			for(s = (char *)o + 1; (u_char *)s < o + *o + 1; p++, s++)
				*p = DNAME_NORMALIZE(*s);
		}

		*dname = (u_char) (p - d);

	}

	return h;
}

/*
 * Duplicates a domain name.
 *
 */
u_char *
dnamedup (u_char *dname)
{
	u_char *p = xalloc((int)*dname + 1);
	memcpy(p, dname, (int)*dname + 1);
	return p;
}
