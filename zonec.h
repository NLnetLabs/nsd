/*
 * zonec.h -- zone compiler.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include "dns.h"
#include "namedb.h"

#define	MAXTOKENSLEN	512		/* Maximum number of tokens per entry */
#define	B64BUFSIZE	16384		/* Buffer size for b64 conversion */
#define	ROOT		(const uint8_t *)"\001"
#define	MAXINCLUDES	10

#define	IP6ADDRLEN	(128/8)

#ifndef AF_INET6
#define AF_INET6	28	/* IPv6 */
#endif /* AF_INET6 */

#define NSEC_WINDOW_COUNT     256
#define NSEC_WINDOW_BITS_COUNT 256
#define NSEC_WINDOW_BITS_SIZE  (NSEC_WINDOW_BITS_COUNT / 8)

#define LINEBUFSZ 1024

struct lex_data {
    size_t   len;		/* holds the label length */
    char    *str;		/* holds the data */
};

#define DEFAULT_TTL 3600
#define MAXINCLUDES 10

/* a RR in DNS */
typedef struct rr rr_type;
struct rr {
	domain_type *owner;
	zone_type   *zone;
	uint16_t     klass;
	uint16_t     type;
	rrdata_type *rrdata;
};

/* administration struct */
typedef struct zparser zparser_type;
struct zparser {
	region_type *region;	/* Allocate for parser lifetime data.  */
	region_type *rr_region;	/* Allocate RR lifetime data.  */
	namedb_type *db;

	const char *filename;
	int32_t default_ttl;
	int32_t default_minimum;
	uint16_t default_class;
	zone_type *current_zone;
	domain_type *origin;
	domain_type *prev_dname;

	int error_occurred;
	unsigned int errors;
	unsigned int line;

	rr_type current_rr;
	rrdata_type *temporary_rrdata;
};

extern zparser_type *parser;

/* used in zonec.lex */
extern FILE *yyin;

/*
 * Used to mark bad domains and domain names.  Do not dereference
 * these pointers!
 */
extern const dname_type *error_dname;
extern domain_type *error_domain;

int yyparse(void);
int yylex(void);
/*int yyerror(const char *s);*/
void yyrestart(FILE *);

enum rr_spot { outside, expecting_dname, after_dname, reading_type };

/* A generic purpose lookup table */
typedef struct lookup_table lookup_table_type;
struct lookup_table {
	uint16_t symbol;
	const char *name;
	int token;		/* Lexical token ID.  */
};

extern const lookup_table_type ztypes[];
extern const lookup_table_type zclasses[];
extern const lookup_table_type zalgs[];

void warning(const char *fmt, ...);
void warning_prev_line(const char *fmt, ...);
void error(const char *fmt, ...);
void error_prev_line(const char *fmt, ...);
int yyerror(const char *message); /* Dummy function.  */

int process_rr(void);
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
uint16_t *zparser_conv_nsec(region_type *region, uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE]);
uint16_t *zparser_conv_loc(region_type *region, char *str);
uint16_t *zparser_conv_algorithm(region_type *region, const char *algstr);
uint16_t *zparser_conv_certificate_type(region_type *region,
					const char *typestr);
uint16_t *zparser_conv_apl_rdata(region_type *region, char *str);

void parse_unknown_rdata(uint16_t type, uint16_t *wireformat);

long strtottl(char *nptr, char **endptr);

int32_t zparser_ttl2int(char *ttlstr);
void zadd_rdata_wireformat(uint16_t *data);
void zadd_rdata_domain(domain_type *domain);
void zprintrr(FILE *f, rr_type *rr);

void set_bit(uint8_t bits[], uint16_t index);
void set_bitnsec(uint8_t  bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
		 uint16_t index);

uint16_t intbytypexx(const char *str);

const lookup_table_type *lookup_by_name(const char *a, const lookup_table_type tab[]);
const lookup_table_type *lookup_by_symbol(uint16_t n, const lookup_table_type tab[]);
const lookup_table_type *lookup_by_token(int token, const lookup_table_type tab[]);

uint16_t lookup_type_by_name(const char *name);

/* zparser.y */
zparser_type *zparser_create(region_type *region, region_type *rr_region,
			     namedb_type *db);
void zparser_init(const char *filename, uint32_t ttl, uint16_t klass,
		  const char *origin);

#endif /* _ZONEC_H_ */
