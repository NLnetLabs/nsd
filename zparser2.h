/* header file for the new parser
 * zparser2.h
 *
 * See LICENSE for license
 */


#include "config.h"
#include "util.h"
#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>


struct YYSTYPE_T {
    size_t len;
    uint8_t * str;
};


#define YYSTYPE     struct YYSTYPE_T*
#define YYSTYPE_IS_DECLARED 1
#define DEFAULT_TTL 3600
#define RRTYPES     52
#define DNAME_MAGIC 0xffff  /* this is used to in the first byte
                               to signal the presence of a dname 
                               in the string */
/* [XXX] fix MAXDNAME */
#define MAXDNAME    255
/* strlen cannot be used, [XXX] we need our own calls */

/* a RR in DNS */
struct RR {
        uint8_t *dname;
        int32_t ttl;
        uint16_t class;
        uint16_t type;
        uint16_t **rdata;
};

/* our linked list of nodes */
struct node_t {
    struct RR * rr;
    struct node_t * next;
};

/* administration struct */
struct zdefault_t {
    int32_t ttl;
    uint32_t minimum;
    uint16_t class;
    uint8_t *origin;
    size_t origin_len;
    uint8_t *prev_dname;
    size_t prev_dname_len;
    int _rc;   /* current rdata */
    size_t _tlineno;
    char *filename;
};

/* defined in zonec.y */
extern unsigned int lineno;
extern unsigned int error;
extern struct zdefault_t *zdefault;
extern struct RR * current_rr;
extern const struct node_t * root;
extern struct node_t * rrlist;

/* stuff used in zonec.lex */
extern FILE * yyin;
extern int yylex();
void yyrestart(FILE *);

#ifndef _ZPARSER_H_
#define	_ZPARSER_H_

#define	ZBUFSIZE	16384		/* Maximum master file entry size */
#define	MAXRDATALEN	64		/* This is more than enough, think multiple TXT */
#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	16384		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"
#define	MAXINCLUDES	10

#define	IP6ADDRLEN	128/8

#ifndef AF_INET6
#define AF_INET6	28	/* IPv6 */
#endif

/* Type of rdata elements we might encounter */
#define RDATA_A		1
#define RDATA_A6	2
#define RDATA_B64	3
#define RDATA_BYTE	4
#define RDATA_DNAME	5
#define RDATA_LONG	6
#define RDATA_SHORT	7
#define RDATA_TEXT	8
#define RDATA_PERIOD	9
#define RDATA_TYPE	10
#define RDATA_TIME	11
#define RDATA_HEX	12
#define RDATA_PROTO	13
#define RDATA_SERVICE	14

/* A generic purpose lookup table */
struct ztab {
	uint16_t sym;
	const char *name;
};

#define	Z_CLASSES {		\
	{CLASS_IN, "IN"},	\
	{0, NULL}		\
}

#define	Z_TYPES {		\
	{TYPE_A, "A"},		\
	{TYPE_NS, "NS"},	\
	{TYPE_MD, "MD"},	\
	{TYPE_MF, "MF"},	\
	{TYPE_CNAME, "CNAME"},	\
	{TYPE_SOA, "SOA"},	\
	{TYPE_MB, "MB"},	\
	{TYPE_MG, "MG"},	\
	{TYPE_MR, "MR"},	\
	{TYPE_NULL, "NULL"},	\
	{TYPE_WKS, "WKS"},	\
	{TYPE_PTR, "PTR"},	\
	{TYPE_HINFO, "HINFO"},	\
	{TYPE_MINFO, "MINFO"},	\
	{TYPE_MX, "MX"},	\
	{TYPE_TXT, "TXT"},	\
        {TYPE_AAAA, "AAAA"},	\
	{TYPE_SRV, "SRV"},	\
	{TYPE_NAPTR, "NAPTR"},	\
	{TYPE_LOC, "LOC"},	\
	{TYPE_AFSDB, "AFSDB"},	\
	{TYPE_RP, "RP"},	\
	{TYPE_SIG, "SIG"},	\
	{TYPE_KEY, "KEY"},	\
	{TYPE_NXT, "NXT"},	\
	{TYPE_DS, "DS"},	\
	{TYPE_ANY, "ANY"},	\
	{0, NULL}		\
}

extern struct ztab ztypes[];
extern struct ztab zclasses[];

/* zparser.c */
uint16_t * zparser_conv_hex(const char *hex);
uint16_t * zparser_conv_time(const char *time);
uint16_t * zparser_conv_rdata_type(struct RR * current, const char *type);
uint16_t * zparser_conv_rdata_proto(const char *protostr);
uint16_t * zparser_conv_rdata_service(const char *servicestr, const int arg);
uint16_t * zparser_conv_rdata_period(const char *periodstr);
uint16_t * zparser_conv_short(const char *shortstr);
uint16_t * zparser_conv_long(const char *longstr);
uint16_t * zparser_conv_byte(const char *bytestr);
uint16_t * zparser_conv_A(const char *a);
uint16_t * zparser_conv_dname(const uint8_t *dname);
uint16_t * zparser_conv_text(const char *txt);
uint16_t * zparser_conv_a6(const char *a6);
uint16_t * zparser_conv_b64(const char *b64);
int32_t zparser_ttl2int(char *ttlstr);
struct node_t * list_add(struct node_t *list, struct RR * rr);
void zreset_current_rr(struct zdefault_t *zdefault);
void zadd_rdata2(struct zdefault_t *zdefault, uint16_t *r);
void zadd_rdata_finalize(struct zdefault_t *zdefault);
void zadd_rtype(uint8_t *type);
uint16_t intbyname (const char *a, struct ztab *tab);
const char * namebyint (uint16_t n, struct ztab *tab);
int zrdatacmp(uint16_t **a, uint16_t **b);
long strtottl(char *nptr, char **endptr);
void zerror (const char *msg);
void zsyntax (struct zdefault_t *z);
void zunexpected (struct zdefault_t *z);
struct zdefault_t * nsd_zopen (const char *filename, uint32_t ttl, uint16_t class, const char *origin);
struct RR * zread (struct node_t *list);
void zclose (struct zdefault_t *z);
void zrdatafree(uint16_t **p);
const char * precsize_ntoa (int prec);
uint8_t precsize_aton (register char *cp, char **endptr);
const char * typebyint(uint16_t type);
const char * classbyint(uint16_t class);
static void usage (void);

#endif /* _ZPARSER_H_ */
