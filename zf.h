/*
 * $Id: zf.h,v 1.8 2002/02/19 14:13:42 alexis Exp $
 *
 * zf.h -- RFC1035 master zone file parser, nsd(8)
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
 *
 * COMMENTS:
 *
 * This module implements an extended RFC1035 master zone file parser with
 * an interface similar to the historical getpwent(3) library call.
 *
 * zf_t *zf_open(char *filename, u_char *zonename)
 *
 *	Opens the specified zone file name and sets the system up for
 *	parsing it. Returns NULL if an error has occurred.
 *
 * void zf_close(zf_t *zf)
 *
 *	Closes the parser and frees up the buffers and parsing structures.
 *
 * struct zf_entry *zf_read(struct zf *zf)
 *
 *	Reads, parses and returns an entry from the open parser. Returns
 *	NULL on the end of zone file. The number of encountered syntax errors
 *	this far is reflected with zf->errors counter.
 *
 * void zf_free_rdata(struct zf_entry *)
 *
 *	Frees the parser rdata but not the dname.
 *
 * Some useful variables:
 *
 *	zf->errors	- number of syntax errors this far
 *	zf->lines		- total number of lines read this far including
 *				  empty lines and comments.
 *
 */

#ifndef _ZF_H_
#define	_ZF_H_

#define	MAXRDATALEN	7		/* SOA */
#define	MAXINCLUDES	16		/* Maximum number of include files */
#define	LINEBUFSZ	2048		/* Maximum master file line length */
#define	IP6ADDRLEN	128/8
#define	ROOT_ORIGIN	"\001"		/* \001\000 */
#define	DEFAULT_TTL	3600

/* Rdata atom */
union zf_rdatom {
	u_int16_t	s;
	u_int32_t	l;
	u_char	*p;
};


/* A line in a zone file */
struct zf_entry {
	u_char *dname;
	int32_t ttl;
	u_int16_t class;
	u_int16_t type;
	char *rdatafmt;
	union zf_rdatom *rdata;
};

/* An open parser */
struct zf {
	int errors;
	int iptr;
	u_int32_t lines;
	/* Include files.... */
	struct {
		FILE	*file;
		u_long	lineno;
		char	*filename;
		u_char	*origin;
		int32_t	ttl;
		int	parentheses;
	} i[MAXINCLUDES+1];
	struct zf_entry line;
	char linebuf[LINEBUFSZ];
};

/* Structure to parse classes */
struct zf_class_tab {
	u_int16_t	class;
	char	*name;
};

#define	ZONEFILE_CLASSES {		\
	{CLASS_IN, "IN"},		\
	{0, NULL}			\
}

/*
 * Resource records types and format definitions.
 *
 * The following atoms are understood now:
 *
 *	'4' The next atom is an IPv4 address
 *	'6' The next atom is an IPv6 address
 *	'n' The next atom is a domain name (dname)
 *	's' The next atom is a two octets number.
 *	'l' The next atom is a four octets number.
 *	't' The next atom is a text string.
 *
 */

/* Structure to parse types */
struct zf_type_tab {
	u_int16_t	type;
	char	*name;
	char	*fmt;
};

#define	ZONEFILE_TYPES {		\
	{TYPE_A, "A", "4"},		\
	{TYPE_NS, "NS", "n"},		\
	{TYPE_MD, "MD", "n"},		\
	{TYPE_MF, "MF", "n"},		\
	{TYPE_CNAME, "CNAME", "n"},	\
	{TYPE_SOA, "SOA", "nnlllll"},	\
	{TYPE_MB, "MB", "n"},		\
	{TYPE_MG, "MG", "n"},		\
	{TYPE_MR, "MR", "n"},		\
	{TYPE_NULL, "NULL", ""},	\
	{TYPE_WKS, "WKS", NULL},	\
	{TYPE_PTR, "PTR", "n"},		\
	{TYPE_HINFO, "HINFO", "tt"},	\
	{TYPE_MINFO, "MINFO", "nn"},	\
	{TYPE_MX, "MX", "sn"},		\
	{TYPE_TXT, "TXT", "t"},		\
        {TYPE_AAAA, "AAAA", "6"},	\
	{TYPE_ANY, "ANY", NULL},	\
	{0, NULL, NULL}			\
}

/* Prototypes */
struct zf *zf_open __P((char *, u_char *));
struct zf_entry *zf_read __P((struct zf *));
char *typetoa __P((u_int16_t));
char *classtoa __P((u_int16_t));
struct zf_type_tab *typebyname __P((char *));
struct zf_class_tab *classbyname __P((char *));
void *inet6_aton __P((char *));
char *zone_strtok __P((register char *));
void zf_error __P((struct zf *, char *));
void zf_syntax __P((struct zf *));
char *zf_getline __P((struct zf *));
char *zf_token __P((struct zf *, char *));
int zf_open_include __P((struct zf *, char *, char *, int32_t));
void zf_print_entry __P((struct zf_entry *));
void zf_print_rdata __P((union zf_rdatom *, char *));
int zf_close_include __P((struct zf *));
int zf_cmp_rdata __P((union zf_rdatom *, union zf_rdatom *, char *));
void zf_free_rdata __P((union zf_rdatom *, char *));
void zf_close __P((struct zf *));
char *dnamestr __P((u_char *));
u_char *strdname __P((char *s, u_char *));
int dnamecmp __P((register u_char *, register u_char *));

#endif
