/*
 * zonec.h -- zone compiler.
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include "dns.h"
#include "namedb.h"

#define	ZBUFSIZE	16384		/* Maximum master file entry size */
#define	MAXRDATALEN	64		/* This is more than enough, think multiple TXT */
#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	16384		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"
#define	MAXINCLUDES	10

#define	IP6ADDRLEN	(128/8)

#ifndef AF_INET6
#define AF_INET6	28	/* IPv6 */
#endif /* AF_INET6 */

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

#define LINEBUFSZ 1024
#define yyerror	error

struct lex_data {
    size_t   len;		/* holds the label length */
    void    *str;		/* holds the data */
};


#define DEFAULT_TTL 3600
#define RRTYPES     57
#define MAXINCLUDES 10

/* a RR in DNS */
typedef struct rr rr_type;
struct rr {
	domain_type *domain;
	zone_type   *zone;
	uint16_t     class;
	uint16_t     type;
	rrdata_type *rrdata;
};

/* administration struct */
typedef struct zparser zparser_type;
struct zparser {
	namedb_type *db;
	int32_t ttl;
	int32_t minimum;
	uint16_t class;
	zone_type *current_zone;
	domain_type *origin;
	domain_type *prev_dname;
	unsigned int _rc;   /* current rdata cnt */
	unsigned int errors;
	unsigned int line;
	const char *filename;
};

extern zparser_type *current_parser;
extern rr_type *current_rr;
extern rrdata_type *temporary_rrdata;

/* used in zonec.lex */
extern FILE *yyin;

int yyparse(void);
int yylex(void);
/*int yyerror(const char *s);*/
void yyrestart(FILE *);

enum rr_spot { outside, expecting_dname, after_dname, reading_type };

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
	{TYPE_RRSIG, "RRSIG"},	\
	{TYPE_NSEC, "NSEC"},	\
	{TYPE_DNSKEY, "DNSKEY"},\
	{TYPE_ANY, "ANY"},	\
	{0, NULL}		\
}

extern struct ztab ztypes[];
extern struct ztab zclasses[];

/* zonec.c */
/*
 * This region is deallocated after each zone is parsed and analyzed.
 */
extern region_type *zone_region;

/*
 * This region is deallocated after each RR is parsed and analyzed.
 */
extern region_type *rr_region;

int warning(const char *fmt, ...);
int error(const char *fmt, ...);

int process_rr(zparser_type *parser, rr_type *rr);
uint16_t *zparser_conv_hex(region_type *region, const char *hex);
uint16_t *zparser_conv_time(region_type *region, const char *time);
uint16_t *zparser_conv_rdata_proto(region_type *region, const char *protostr);
uint16_t *zparser_conv_rdata_service(region_type *region, const char *servicestr, const int arg);
uint16_t *zparser_conv_rdata_period(region_type *region, const char *periodstr);
uint16_t *zparser_conv_short(region_type *region, const char *shortstr);
uint16_t *zparser_conv_long(region_type *region, const char *longstr);
uint16_t *zparser_conv_byte(region_type *region, const char *bytestr);
uint16_t *zparser_conv_a(region_type *region, const char *a);
uint16_t *zparser_conv_text(region_type *region, const char *txt);
uint16_t *zparser_conv_a6(region_type *region, const char *a6);
uint16_t *zparser_conv_b64(region_type *region, const char *b64);
uint16_t *zparser_conv_rrtype(region_type *region, const char *rr);
uint16_t *zparser_conv_nxt(region_type *region, uint8_t nxtbits[]);
uint16_t *zparser_conv_domain(region_type *region, domain_type *domain);

int32_t zparser_ttl2int(char *ttlstr);
void zadd_rdata_wireformat(zparser_type *parser, uint16_t *data);
void zadd_rdata_domain(zparser_type *parser, domain_type *domain);
void zadd_rdata_finalize(zparser_type *parser);
uint16_t intbyname (const char *a, struct ztab *tab);
const char * namebyint (uint16_t n, struct ztab *tab);
void zprintrr(FILE *f, rr_type *rr);

void set_bit(uint8_t bits[], int index);

/* zlexer.lex */
int zoctet(char *word);
int zrrtype (char *word);
uint16_t intbyclassxx(void *str);
uint16_t intbytypexx(void *str);

#endif /* _ZONEC_H_ */
