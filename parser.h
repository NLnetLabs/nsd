/*
 * $Id: parser.h,v 1.3 2001/12/12 15:05:08 alexis Exp $
 *
 * parser.h -- RFC1035 master zone file parser, nsd(8)
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
 * parser_t *parser_open(char *filename, u_char *zonename)
 *
 *	Opens the specified zone file name and sets the system up for
 *	parsing it. Returns NULL if an error has occurred.
 *
 * void parser_close(parser_t *parser)
 *
 *	Closes the parser and frees up the buffers and parsing structures.
 *
 * struct parser_entry *parser_get_entry(struct parser *parser)
 *
 *	Reads, parses and returns an entry from the open parser. Returns
 *	NULL on the end of zone file. The number of encountered syntax errors
 *	this far is reflected with parser->errors counter.
 *
 * void parser_free_rdata(struct parser_entry *)
 *
 *	Frees the parser rdata but not the dname.
 *
 * Some useful variables:
 *
 *	parser->errors	- number of syntax errors this far
 *	parser->lines		- total number of lines read this far including
 *				  empty lines and comments.
 *
 */
#define	MAXRDATALEN	7		/* SOA */
#define	MAXINCLUDES	16		/* Maximum number of include files */
#define	LINEBUFSZ	2048		/* Maximum master file line length */
#define	IP6ADDRLEN	128/8
#define	ROOT_ORIGIN	"\001"		/* \001\000 */
#define	DEFAULT_TTL	3600

/* Rdata atom */
union parser_rdatom {
	u_short	s;
	u_long	l;
	u_char	*p;
};

/* A line in a zone file */
struct parser_entry {
	u_char *dname;
	long ttl;
	u_short class;
	u_short type;
	char *rdatafmt;
	union parser_rdatom rdata[MAXRDATALEN];
};

/* An open parser */
struct parser {
	int errors;
	int iptr;
	u_long lines;
	/* Include files.... */
	struct {
		FILE	*file;
		u_long	lineno;
		char	*filename;
		u_char	*origin;
		long	ttl;
		int	parentheses;
	} i[MAXINCLUDES+1];
	struct parser_entry line;
	char linebuf[LINEBUFSZ];
};

/* Structure to parse classes */
struct parser_class_tab {
	u_short	class;
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
struct parser_type_tab {
	u_short	type;
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
struct parser *parser_open __P((char *, u_char *));
struct parser_entry *parser_get_entry __P((struct parser *));
char *typetoa __P((u_short));
char *classtoa __P((u_short));
struct parser_type_tab *typebyname __P((char *));
struct parser_class_tab *classbyname __P((char *));
void *inet6_aton __P((char *));
char *zone_strtok __P((register char *));
void parser_error __P((struct parser *, char *));
void parser_syntax __P((struct parser *));
char *parser_getline __P((struct parser *));
char *parser_token __P((struct parser *, char *));
int parser_open_include __P((struct parser *, char *, char *, long));
void parser_print_entry __P((struct parser_entry *));
int parser_close_include __P((struct parser *));
void parser_free_entry __P((struct parser_entry *));
void parser_close __P((struct parser *));
char *dnamestr __P((u_char *));
u_char *strdname __P((char *s, u_char *));
int dnamecmp __P((register u_char *, register u_char *));
