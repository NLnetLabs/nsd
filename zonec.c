/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

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
#include <time.h>

#include <netinet/in.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "zonec.h"

#include "dname.h"
#include "dns.h"
#include "namedb.h"
#include "util.h"
#include "region-allocator.h"
#include "zparser.h"

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

region_type *zone_region;
region_type *rr_region;

const dname_type *error_dname;
domain_type *error_domain;

/* The database file... */
static const char *dbfile = DBFILE;

/* Some global flags... */
static int vflag = 0;
/* if -v then print progress each 'progress' RRs */
static int progress = 10000;

/* Total errors counter */
static long int totalerrors = 0;
static long int totalrrs = 0;

int error_occurred = 0;

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

/*
 *
 * Resource records types, classes and algorithms that we know.
 *
 */
const lookup_table_type zclasses[] = {
	{ CLASS_IN, "IN", T_IN },
	{ 0, NULL, 0 }
};

const lookup_table_type ztypes[] = {
	{ TYPE_A, "A", T_A },
	{ TYPE_NS, "NS", T_NS },
	{ TYPE_MD, "MD", T_MD },
	{ TYPE_MF, "MF", T_MF },
	{ TYPE_CNAME, "CNAME", T_CNAME },
	{ TYPE_SOA, "SOA", T_SOA },
	{ TYPE_MB, "MB", T_MB },
	{ TYPE_MG, "MG", T_MG },
	{ TYPE_MR, "MR", T_MR },
	{ TYPE_NULL, "NULL", T_NULL },
	{ TYPE_WKS, "WKS", T_WKS },
	{ TYPE_PTR, "PTR", T_PTR },
	{ TYPE_HINFO, "HINFO", T_HINFO },
	{ TYPE_MINFO, "MINFO", T_MINFO },
	{ TYPE_MX, "MX", T_MX },
	{ TYPE_TXT, "TXT", T_TXT },
        { TYPE_AAAA, "AAAA", T_AAAA },
	{ TYPE_SRV, "SRV", T_SRV },
	{ TYPE_LOC, "LOC", T_LOC },
	{ TYPE_AFSDB, "AFSDB", T_AFSDB }, /* RFC 1183 */
	{ TYPE_RP, "RP", T_RP },	  /* RFC 1183 */
	{ TYPE_X25, "X25", T_X25 },	  /* RFC 1183 */
	{ TYPE_ISDN, "ISDN", T_ISDN },	  /* RFC 1183 */
	{ TYPE_RT, "RT", T_RT },	  /* RFC 1183 */
	{ TYPE_NSAP, "NSAP", T_NSAP },	  /* RFC 1706 */
	{ TYPE_PX, "PX", T_PX },	  /* RFC 2163 */
	{ TYPE_SIG, "SIG", T_SIG },
	{ TYPE_KEY, "KEY", T_KEY },
	{ TYPE_NXT, "NXT", T_NXT },
	{ TYPE_NAPTR, "NAPTR", T_NAPTR }, /* RFC 2915 */
	{ TYPE_CERT, "CERT", T_CERT },	  /* RFC 2538 */
	{ TYPE_DS, "DS", T_DS },
	{ TYPE_SSHFP, "SSHFP", T_SSHFP },
	{ TYPE_RRSIG, "RRSIG", T_RRSIG },
	{ TYPE_NSEC, "NSEC", T_NSEC },
	{ TYPE_DNSKEY, "DNSKEY", T_DNSKEY },
	{ TYPE_ANY, "ANY", 0 },
	{ 0, NULL, 0 }
};

const lookup_table_type zalgs[] = {
	{ 1, "RSAMD5", 0 },
	{ 2, "DS", 0 },
	{ 3, "DSA", 0 },
	{ 4, "ECC", 0 },
	{ 5, "RSASHA1", 0 },
	{ 252, "INDIRECT", 0 },
	{ 253, "PRIVATEDNS", 0 },
	{ 254, "PRIVATEOID", 0 },
	{ 0, NULL, 0 }
};

/* 
 * These are parser function for generic zone file stuff.
 */
uint16_t *
zparser_conv_hex(region_type *region, const char *hex)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	size_t len;
	int i;
	
	len = strlen(hex);
	if (len % 2 != 0) {
		error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		error_prev_line("hex data exceeds maximum rdata length (%d)",
				MAX_RDLENGTH);
	} else {
		/* the length part */
		r = region_alloc(region, sizeof(uint16_t) + len/2);
		*r = len/2;
		t = (uint8_t *)(r + 1);
    
		/* Now process octet by octet... */
		while (*hex) {
			*t = 0;
			for (i = 16; i >= 1; i -= 15) {
				switch (*hex) {
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
					*t += (*hex - '0') * i;
					break;
				case 'a':
				case 'b':
				case 'c':
				case 'd':
				case 'e':
				case 'f':
					*t += (*hex - 'a' + 10) * i;
					break;
				case 'A':
				case 'B':
				case 'C':
				case 'D':
				case 'E':
				case 'F':
					*t += (*hex - 'A' + 10) * i;
					break;
				default:
					error_prev_line("illegal hex character '%c'", (int)*hex);
					return NULL;
				}
				++hex;
			}
			++t;
		}
        }
	return r;
}

uint16_t *
zparser_conv_time(region_type *region, const char *time)
{
	/* convert a time YYHM to wireformat */
	uint16_t *r = NULL;
	struct tm tm;
	uint32_t l;

	/* Try to scan the time... */
	/* [XXX] the cast fixes compile time warning */
	if((char*)strptime(time, "%Y%m%d%H%M%S", &tm) == NULL) {
		error_prev_line("Date and time is expected");
	} else {

		r = region_alloc(region, sizeof(uint32_t) + sizeof(uint16_t));

		l = htonl(timegm(&tm));
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
	}
	return r;
}

uint16_t *
zparser_conv_rdata_proto(region_type *region, const char *protostr)
{
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;
	uint16_t *r = NULL;
 
	if((proto = getprotobyname(protostr)) == NULL) {
		error_prev_line("Unknown protocol");
	} else {

		r = region_alloc(region, sizeof(uint16_t) + sizeof(uint16_t));

		*(r + 1) = htons(proto->p_proto);
		*r = sizeof(uint16_t);
	} 
	return r;
}

uint16_t *
zparser_conv_rdata_service(region_type *region, const char *servicestr, const int arg)
{
	/* convert a service in the rdata to wireformat */

	struct protoent *proto;
	struct servent *service;
	uint16_t *r = NULL;

	/* [XXX] need extra arg here .... */
	if((proto = getprotobynumber(arg)) == NULL) {
		error_prev_line("Unknown protocol, internal error");
        } else {
		if((service = getservbyname(servicestr, proto->p_name)) == NULL) {
			error_prev_line("Unknown service");
		} else {
			/* Allocate required space... */
			r = region_alloc(region, sizeof(uint16_t) + sizeof(uint16_t));

			*(r + 1) = service->s_port;
			*r = sizeof(uint16_t);
		}
        }
	return r;
}

uint16_t *
zparser_conv_rdata_period(region_type *region, const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */

	uint16_t *r = NULL;
	uint32_t l;
	char *end; 

	/* Allocate required space... */
	r = region_alloc(region, sizeof(uint16_t) + sizeof(uint32_t));

	l = htonl((uint32_t)strtottl((char *)periodstr, &end));

        if(*end != 0) {
		error_prev_line("Time period is expected");
        } else {
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
        }
	return r;
}

uint16_t *
zparser_conv_short(region_type *region, const char *shortstr)
{
	/* convert a short INT to wire format */

	char *end;      /* Used to parse longs, ttls, etc.  */
	uint16_t *r = NULL;
   
	r = region_alloc(region, sizeof(uint16_t) + sizeof(uint16_t));
    
	*(r+1)  = htons((uint16_t)strtol(shortstr, &end, 0));
            
	if(*end != 0) {
		error_prev_line("Unsigned short value is expected");
	} else {
		*r = sizeof(uint16_t);
	}
	return r;
}

uint16_t *
zparser_conv_long(region_type *region, const char *longstr)
{
	char *end;      /* Used to parse longs, ttls, etc.  */
	uint16_t *r = NULL;
	uint32_t l;

	r = region_alloc(region, sizeof(uint16_t) + sizeof(uint32_t));

	l = htonl((uint32_t)strtol(longstr, &end, 0));

	if(*end != 0) {
		error_prev_line("Long decimal value is expected");
        } else {
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
	}
	return r;
}

uint16_t *
zparser_conv_byte(region_type *region, const char *bytestr)
{

	/* convert a byte value to wireformat */
	char *end;      /* Used to parse longs, ttls, etc.  */
	uint16_t *r = NULL;
 
        r = region_alloc(region, sizeof(uint16_t) + sizeof(uint8_t));

        *((uint8_t *)(r+1)) = (uint8_t)strtol(bytestr, &end, 0);

        if(*end != 0) {
		error_prev_line("Decimal value is expected");
        } else {
		*r = sizeof(uint8_t);
        }
	return r;
}

uint16_t *
zparser_conv_algorithm(region_type *region, const char *algstr)
{
	/* convert a algoritm string to integer */
	uint16_t *r = NULL;
	const lookup_table_type *alg;

	alg = lookup_by_name(algstr, zalgs);

	if (!alg) {
		/* not a memonic */
		return zparser_conv_byte(region, algstr);
	}

        r = region_alloc(region, sizeof(uint16_t) + sizeof(uint8_t));
	*((uint8_t *)(r+1)) = alg->symbol;
	*r = sizeof(uint8_t);
	return r;
}

uint16_t *
zparser_conv_a(region_type *region, const char *a)
{
   
	/* convert a A rdata to wire format */
	struct in_addr pin;
	uint16_t *r = NULL;

	r = region_alloc(region, sizeof(uint16_t) + sizeof(in_addr_t));

	if(inet_pton(AF_INET, a, &pin) > 0) {
		memcpy(r + 1, &pin.s_addr, sizeof(in_addr_t));
		*r = sizeof(uint32_t);
	} else {
		error_prev_line("Invalid ip address");
	}
	return r;
}

/*
 * XXX: add length parameter to handle null bytes, remove strlen
 * check.
 */
uint16_t *
zparser_conv_text(region_type *region, const char *txt)
{
	/* convert text to wireformat */
	int i;
	uint16_t *r = NULL;

	if((i = strlen(txt)) > 255) {
		error_prev_line("Text string is longer than 255 charaters, try splitting in two");
        } else {

		/* Allocate required space... */
		r = region_alloc(region, sizeof(uint16_t) + i + 1);

		*((char *)(r+1))  = i;
		memcpy(((char *)(r+1)) + 1, txt, i);

		*r = i + 1;
        }
	return r;
}

uint16_t *
zparser_conv_a6(region_type *region, const char *a6)
{
	/* convert ip v6 address to wireformat */

	uint16_t *r = NULL;

	r = region_alloc(region, sizeof(uint16_t) + IP6ADDRLEN);

        /* Try to convert it */
        if(inet_pton(AF_INET6, a6, r + 1) != 1) {
		error_prev_line("Invalid ipv6 address");
        } else {
		*r = IP6ADDRLEN;
        }
        return r;
}

uint16_t *
zparser_conv_b64(region_type *region, const char *b64)
{
	uint8_t buffer[B64BUFSIZE];
	/* convert b64 encoded stuff to wireformat */
	uint16_t *r = NULL;
	int i;

        /* Try to convert it */
        if((i = b64_pton(b64, buffer, B64BUFSIZE)) == -1) {
		error_prev_line("Base64 encoding failed");
        } else {
		r = region_alloc(region, i + sizeof(uint16_t));
		*r = i;
		memcpy(r + 1, buffer, i);
        }
        return r;
}

uint16_t *
zparser_conv_domain(region_type *region, domain_type *domain)
{
	uint16_t *r = NULL;
	const dname_type *dname = domain_dname(domain);

	r = region_alloc(region, sizeof(uint16_t) + dname->name_size);
	*r = dname->name_size;
	memcpy(r + 1, dname_name(dname), dname->name_size);
	return r;
}

uint16_t *
zparser_conv_rrtype(region_type *region, const char *rr)
{
	/*
	 * get the official number for the rr type and return
	 * that. This is used by SIG in the type-covered field
	 */

	/* [XXX] error handling */
	uint16_t *r = NULL;
	
	r = region_alloc(region, sizeof(uint16_t) + sizeof(uint16_t));

	*(r+1)  = htons((uint16_t) 
			lookup_by_name(rr, ztypes)->symbol
			);
            
	*r = sizeof(uint16_t);
	return r;
}

uint16_t *
zparser_conv_nxt(region_type *region, uint8_t nxtbits[])
{
	/* nxtbits[] consists of 16 bytes with some zero's in it
	 * copy every byte with zero to r and write the length in
	 * the first byte
	 */
	uint16_t *r = NULL;
	uint16_t i;
	uint16_t last = 0;

	for (i = 0; i < 16; i++) {
		if (nxtbits[i] != 0)
			last = i + 1;
	}

	r = region_alloc(region, sizeof(uint16_t) + (last * sizeof(uint8_t)) );
	*r = last;
	memcpy(r+1, nxtbits, last);

	return r;
}


/* we potentially have 256 windows, each one is numbered. empty ones
 * should be discarded
 */
uint16_t *
zparser_conv_nsec(region_type *region, uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE])
{
	/* nsecbits contains up to 64K of bits which represent the
	 * types available for a name. Walk the bits according to
	 * nsec++ draft from jakob
	 */
	uint16_t *r;
	uint8_t *ptr;
	size_t i,j;
	uint16_t window_count = 0;
	uint16_t total_size = 0;

	int used[NSEC_WINDOW_COUNT]; /* what windows are used. */
	int size[NSEC_WINDOW_COUNT]; /* what is the last byte used in the window, the
		index of 'size' is the window's number*/

	/* used[i] is the i-th window included in the nsec 
	 * size[used[0]] is the size of window 0
	 */

	/* walk through the 256 windows */
	for (i = 0; i < NSEC_WINDOW_COUNT; ++i) {
		int empty_window = 1;
		/* check each of the 32 bytes */
		for (j = 0; j < NSEC_WINDOW_BITS_SIZE; ++j) {
			if (nsecbits[i][j] != 0) {
				size[i] = j + 1;
				empty_window = 0;
			}
		}
		if (!empty_window) {
			used[window_count] = i;
			window_count++;
		}
	}

	for (i = 0; i < window_count; ++i) {
		total_size += sizeof(uint16_t) + size[used[i]];
	}
	
	r = region_alloc(region, sizeof(uint16_t) + total_size * sizeof(uint8_t));
	*r = total_size;
	ptr = (uint8_t *) (r + 1);

	/* now walk used and copy it */
	for (i = 0; i < window_count; ++i) {
		ptr[0] = used[i];
		ptr[1] = size[used[i]];
		memcpy(ptr + 2, &nsecbits[used[i]], size[used[i]]);
		ptr += size[used[i]] + 2;
	}

	return r;
}

/* Parse an int terminated in the specified range. */
static int
parse_int(const char *str, char **end, int *result, const char *name, int min, int max)
{
	*result = (int) strtol(str, end, 10);
	if (*result < min || *result > max) {
		error_prev_line("%s must be within the [%d .. %d] range", name, min, max);
		return 0;
	} else {
		return 1;
	}
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				1000000,10000000,100000000,1000000000};

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
static uint8_t 
precsize_aton (char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	int exponent;
	int mantissa;

	while (isdigit(*cp))
		mval = mval * 10 + (*cp++ - '0');

	if (*cp == '.') {	/* centimeters */
		cp++;
		if (isdigit(*cp)) {
			cmval = (*cp++ - '0') * 10;
			if (isdigit(*cp)) {
				cmval += (*cp++ - '0');
			}
		}
	}

	cmval = (mval * 100) + cmval;

	for (exponent = 0; exponent < 9; exponent++)
		if (cmval < poweroften[exponent+1])
			break;

	mantissa = cmval / poweroften[exponent];
	if (mantissa > 9)
		mantissa = 9;

	retval = (mantissa << 4) | exponent;

	if(*cp == 'm') cp++;

	*endptr = cp;

	return (retval);
}

/*
 * Parses a specific part of rdata.
 *
 * Returns:
 *
 *	number of elements parsed
 *	zero on error
 *
 */
uint16_t *
zparser_conv_loc(region_type *region, char *str)
{
	uint16_t *r;
	int i;
	int deg = 0, min = 0, secs = 0, secfraq = 0, altsign = 0, altmeters = 0, altfraq = 0;
	uint32_t lat = 0, lon = 0, alt = 0;
	uint8_t vszhpvp[4] = {0, 0, 0, 0};

	for(;;) {
		/* Degrees */
		if (*str == '\0') {
			error_prev_line("Unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace(*str)) {
			error_prev_line("Space expected after degrees");
			return NULL;
		}
		++str;
		
		/* Minutes? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace(*str)) {
				error_prev_line("Space expected after minutes");
				return NULL;
			}
		}
		++str;
		
		/* Seconds? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &secs, "seconds", 0, 60))
				return NULL;
			if (!isspace(*str) && *str != '.') {
				error_prev_line("Space expected after seconds");
				return NULL;
			}
		}

		if (*str == '.') {
			secfraq = (int) strtol(str + 1, &str, 10);
			if (!isspace(*str)) {
				error_prev_line("Space expected after seconds");
				return NULL;
			}
		}
		++str;
		
		switch(*str) {
		case 'N':
		case 'n':
			lat = ((unsigned)1<<31) + (((((deg * 60) + min) * 60) + secs)
				* 1000) + secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'E':
		case 'e':
			lon = ((unsigned)1<<31) + (((((deg * 60) + min) * 60) + secs) * 1000)
				+ secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'S':
		case 's':
			lat = ((unsigned)1<<31) - (((((deg * 60) + min) * 60) + secs) * 1000)
				- secfraq;
			deg = min = secs = secfraq = 0;
			break;
		case 'W':
		case 'w':
			lon = ((unsigned)1<<31) - (((((deg * 60) + min) * 60) + secs) * 1000)
				- secfraq;
			deg = min = secs = secfraq = 0;
			break;
		default:
			error_prev_line("Invalid latitude/longtitude");
			return NULL;
		}
		++str;
		
		if (lat != 0 && lon != 0)
			break;

		if (!isspace(*str)) {
			error_prev_line("Space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		error_prev_line("Unexpected end of LOC data");
		return NULL;
	}

	/* Sign */
	switch(*str) {
	case '-':
		altsign = -1;
	case '+':
		++str;
		break;
	}

	/* Meters of altitude... */
	altmeters = strtol(str, &str, 10);
	switch(*str) {
	case ' ':
	case '\0':
	case 'm':
		break;
	case '.':
		++str;
		altfraq = strtol(str + 1, &str, 10);
		if (!isspace(*str) && *str != 0 && *str != 'm') {
			error_prev_line("Altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		error_prev_line("Altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace(*str) && *str != '\0')
		++str;
	
	alt = (10000000 + (altsign * (altmeters * 100 + altfraq)));

	if (!isspace(*str) && *str != '\0') {
		error_prev_line("Unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace(*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace(*str) && *str != '\0') {
			error_prev_line("Invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = region_alloc(region, sizeof(uint16_t) + 16);
	*r = 16;

	memcpy(r + 1, vszhpvp, 4);

	copy_uint32(r + 3, lat);
	copy_uint32(r + 5, lon);
	copy_uint32(r + 7, alt);

	return r;
}

/* 
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

int32_t
zparser_ttl2int(char *ttlstr)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	int32_t ttl;
	char *t;

	ttl = strtottl(ttlstr, &t);
	if(*t != 0) {
		error_prev_line("Invalid ttl value: %s",ttlstr);
		ttl = -1;
	}
    
	return ttl;
}


/* struct * RR current_rr is global, no 
 * need to pass it along */
void
zadd_rdata_wireformat(zparser_type *parser, uint16_t *data)
{
	if (parser->_rc > MAXRDATALEN) {
		error_prev_line("too many rdata elements");
	} else {
		current_rr->rrdata->rdata[parser->_rc].data = data;
		++parser->_rc;
	}
}

void
zadd_rdata_domain(zparser_type *parser, domain_type *domain)
{
	if (parser->_rc > MAXRDATALEN) {
		error_prev_line("too many rdata elements");
	} else {
		current_rr->rrdata->rdata[parser->_rc].data = domain;
		++parser->_rc;
	}
}

void
zadd_rdata_finalize(zparser_type *parser)
{
	/* Append terminating NULL.  */
	current_rr->rrdata->rdata[parser->_rc].data = NULL;
}

/* 
 * Receive a TYPEXXXX string and return XXXX as
 * an integer
 */
uint16_t
intbytypexx(const char *str)
{
        char *end;
        long type;

	if (strlen(str) < 5)
		return 0;
	
	if (strncasecmp(str, "TYPE", 4) != 0)
		return 0;

	if (!isdigit(str[4]))
		return 0;
	
	/* The rest from the string must be a number.  */
	type = strtol(str + 4, &end, 10);

	if (*end != '\0')
		return 0;
	if (type < 0 || type > 65535L)
		return 0;
	
        return (uint16_t) type;
}

/*
 * Looks up the table entry by name, returns NULL if not found.
 */
const lookup_table_type *
lookup_by_name(const char *name, const lookup_table_type *table)
{
	while (table->name != NULL) {
		if (strcasecmp(name, table->name) == 0)
			return table;
		table++;
	}
	return NULL;
}

/*
 * Looks up the table entry by symbol, returns NULL if not found.
 */
const lookup_table_type *
lookup_by_symbol(uint16_t symbol, const lookup_table_type *table)
{
	while (table->name != NULL) {
		if (table->symbol == symbol)
			return table;
		table++;
	}
	return NULL;
}

/*
 * Lookup the type in the ztypes lookup table.  If not found, check if
 * the type uses the "TYPExxx" notation for unknown types.
 *
 * Return 0 if no type matches.
 */
uint16_t
lookup_type_by_name(const char *name)
{
	const lookup_table_type *entry = lookup_by_name(name, ztypes);
	return entry ? entry->symbol : intbytypexx(name);
}

/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */
static int
zrdatacmp(uint16_t type, rdata_atom_type *a, rdata_atom_type *b)
{
	int i = 0;
	
	assert(a);
	assert(b);
	
	/* Compare element by element */
	for (i = 0; !rdata_atom_is_terminator(a[i]) && !rdata_atom_is_terminator(b[i]); ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(a[i]) != rdata_atom_domain(b[i]))
				return 1;
		} else {
			if (rdata_atom_size(a[i]) != rdata_atom_size(b[i]))
				return 1;
			if (memcmp(rdata_atom_data(a[i]),
				   rdata_atom_data(b[i]),
				   rdata_atom_size(a[i])) != 0)
				return 1;
		}
	}

	/* One is shorter than another */
	if (rdata_atom_is_terminator(a[i]) != rdata_atom_is_terminator(b[i]))
		return 1;

	/* Otherwise they are equal */
	return 0;
}

/*
 * Converts a string representation of a period of time into
 * a long integer of seconds.
 *
 * Set the endptr to the first illegal character.
 *
 * Interface is similar as strtol(3)
 *
 * Returns:
 *	LONG_MIN if underflow occurs
 *	LONG_MAX if overflow occurs.
 *	otherwise number of seconds
 *
 * XXX This functions does not check the range.
 *
 */
long
strtottl(char *nptr, char **endptr)
{
	int sign = 0;
	long i = 0;
	long seconds = 0;

	for(*endptr = nptr; **endptr; (*endptr)++) {
		switch (**endptr) {
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
 * Initializes the parser.
 */
static zparser_type *
zparser_init(namedb_type *db)
{
	zparser_type *result;
	
	result = region_alloc(zone_region, sizeof(zparser_type));
	result->db = db;
	return result;
}

/*
 *
 * Opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
static int
zone_open(const char *filename, uint32_t ttl, uint16_t class, const char *origin)
{
	/* Open the zone file... */
	if ( strcmp(filename, "-" ) == 0 ) {
		/* check for stdin */
		yyin = stdin;
	} else {
		if((yyin  = fopen(filename, "r")) == NULL) {
			return 0;
		}
	}

	/* Open the network database */
	setprotoent(1);
	setservent(1);

	current_parser->ttl = ttl;
	current_parser->minimum = 0;
	current_parser->class = class;
	current_parser->current_zone = NULL;
	current_parser->origin = domain_table_insert(
		current_parser->db->domains,
		dname_parse(current_parser->db->region, origin, NULL)); 
	current_parser->prev_dname =
		current_parser->origin; 
					
					 
	current_parser->_rc = 0;
	current_parser->errors = 0;
	current_parser->line = 1;
	current_parser->filename = filename;

	error_occurred = 0;
	current_rr->rrdata = temporary_rrdata;

	return 1;
}


void 
set_bit(uint8_t bits[], uint16_t index)
{
	/* set bit #place in the byte */
	/* the bits are counted from right to left
	 * so bit #0 is the right most bit
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
}

void 
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	    uint16_t index)
{
	/* set bit #place in the byte */
	/* the bits are counted from right to left
	 * so bit #0 is the right most bit
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;
		
	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}


static void
cleanup_rrset(void *r)
{
	struct rrset *rrset = r;
	if (rrset) {
		free(rrset->rrs);
	}
}

int
process_rr(zparser_type *parser, rr_type *rr)
{
	zone_type *zone = parser->current_zone;
	rrset_type *rrset;
	size_t max_rdlength;
	int i;
	
	/* We only support IN class */
	if (rr->class != CLASS_IN) {
		error_prev_line("only class IN is supported");
		return 0;
	}

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.  */
	max_rdlength = 0;
	for (i = 0; !rdata_atom_is_terminator(rr->rrdata->rdata[i]); ++i) {
		if (rdata_atom_is_domain(rr->type, i)) {
			max_rdlength += domain_dname(rdata_atom_domain(rr->rrdata->rdata[i]))->name_size;
		} else {
			max_rdlength += rdata_atom_size(rr->rrdata->rdata[i]);
		}
	}

	if (max_rdlength > MAX_RDLENGTH) {
		error_prev_line("maximum rdata length exceeds %d octets", MAX_RDLENGTH);
		return 0;
	}
		     
	if ( rr->type == TYPE_SOA ) {
		/*
		 * This is a SOA record, start a new zone or continue
		 * an existing one.
		 */
		zone = namedb_find_zone(parser->db, rr->domain);
		if (!zone) {
			/* new zone part */
			zone = region_alloc(zone_region, sizeof(zone_type));
			zone->domain = rr->domain;
			zone->soa_rrset = NULL;
			zone->ns_rrset = NULL;
			zone->is_secure = 0;
			
			/* insert in front of zone list */
			zone->next = parser->db->zones;
			parser->db->zones = zone;
		}
		
		/* parser part */
		current_parser->current_zone = zone;
	}

	if (!dname_is_subdomain(domain_dname(rr->domain), domain_dname(zone->domain))) {
		error_prev_line("out of zone data");
		return 0;
	}

	/* Do we have this type of rrset already? */
	rrset = domain_find_rrset(rr->domain, zone, rr->type);

	/* Do we have this particular rrset? */
	if (rrset == NULL) {
		rrset = region_alloc(zone_region, sizeof(rrset_type));
		rrset->zone = zone;
		rrset->type = rr->type;
		rrset->class = rr->class;
		rrset->rrslen = 1;
		rrset->rrs = xalloc(sizeof(rrdata_type **));
		rrset->rrs[0] = rr->rrdata;
			
		region_add_cleanup(zone_region, cleanup_rrset, rrset);

		/* Add it */
		domain_add_rrset(rr->domain, rrset);
	} else {
		if (rrset->type != TYPE_RRSIG && rrset->rrs[0]->ttl != rr->rrdata->ttl) {
			warning_prev_line("TTL doesn't match the TTL of the RRset");
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rrslen; i++) {
			if (!zrdatacmp(rrset->type, rrset->rrs[i]->rdata, rr->rrdata->rdata)) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rrslen) {
			return 0;
		}

		/* Add it... */
		rrset->rrs = xrealloc(rrset->rrs, (rrset->rrslen + 1) * sizeof(rrdata_type **));
		rrset->rrs[rrset->rrslen++] = rr->rrdata;
	}

#ifdef DNSSEC
	if (rrset->type == TYPE_RRSIG && rrset_rrsig_type_covered(rrset, rrset->rrslen - 1) == TYPE_SOA) {
		rrset->zone->is_secure = 1;
	}
#endif
	
	/* Check we have SOA */
	/* [XXX] this is dead code */
	if (zone->soa_rrset == NULL) {
		if (rr->type != TYPE_SOA) {
			error_prev_line("Missing SOA record on top of the zone");
		} else if (rr->domain != zone->domain) {
			error_prev_line( "SOA record with invalid domain name");
		} else {
			zone->soa_rrset = rrset;
		}
	} else if (rr->type == TYPE_SOA) {
		error_prev_line("Duplicate SOA record discarded");
		--rrset->rrslen;
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && rr->domain == zone->domain) {
		zone->ns_rrset = rrset;
	}
	if ( ( totalrrs % progress == 0 ) && vflag > 1  && totalrrs > 0) {
		printf("%ld\n", totalrrs);
	}
	++totalrrs;
	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static void
zone_read (const char *name, const char *zonefile)
{
	const dname_type *dname;

	dname = dname_parse(zone_region, name, NULL);
	if (!dname) {
		error_prev_line("Cannot parse zone name '%s'", name);
		return;
	}
	
#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dname->label_count == 1) {
		error("Not configured as a root server.");
		return;
	}
#endif

	/* Open the zone file */
	if (!zone_open(zonefile, 3600, CLASS_IN, name)) {
		/* cannot happen with stdin - so no fix needed for zonefile */
		/* this display (null), need seperate call here */
		error("Cannot open '%s': %s", zonefile, strerror(errno));
		return;
	}

	/* Parse and process all RRs.  */
	/* reset the nsecbits to zero */
	memset(nsecbits, 0, 8192);
	yyparse();

	fclose(yyin);
	yyin = NULL;

	fflush(stdout);
	totalerrors += current_parser->errors;
}

static void 
usage (void)
{
#ifndef NDEBUG
	fprintf(stderr, "usage: zonec [-v|-h|-F|-L] [-o origin] [-d directory] -f database zone-list-file\n\n");
#else
	fprintf(stderr, "usage: zonec [-v|-h] [-o origin] [-d directory] -f database zone-list-file\n\n");
#endif
	fprintf(stderr, "\t-v\tBe more verbose.\n");
	fprintf(stderr, "\t-h\tPrint this help information.\n");
	fprintf(stderr, "\t-o\tSpecify a zone's origin (only used if zone-list-file equals \'-\').\n");
#ifndef NDEBUG
	fprintf(stderr, "\t-F\tSet debug facilities.\n");
	fprintf(stderr, "\t-L\tSet debug level.\n");
#endif
	exit(1);
}

int
yyerror(const char *message ATTR_UNUSED)
{
	/* don't do anything with this */
	return 0;
}

static void
error_va_list(const char *fmt, va_list args)
{
	fprintf(stderr," ERR: Line %u in %s: ", current_parser->line,
			current_parser->filename);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	current_parser->errors++;
	error_occurred = 1;
}

/* the line counting sux, to say the least 
 * with this grose hack we try do give sane
 * numbers back */
void
error_prev_line(const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);

	current_parser->line--;
	error_va_list(fmt, args);
	current_parser->line++;

	va_end(args);
}

void
error(const char *fmt, ...)
{
	/* send an error message to stderr */
	va_list args;
	va_start(args, fmt);

	error_va_list(fmt, args);

	va_end(args);
}

static void
warning_va_list(const char *fmt, va_list args)
{
	fprintf(stderr,"WARN: Line %u in %s: ", current_parser->line,
			current_parser->filename);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

void
warning_prev_line(const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);

	current_parser->line--;
	warning_va_list(fmt, args);
	current_parser->line++;

	va_end(args);
}

void 
warning(const char *fmt, ... )
{
	va_list args;

	va_start(args, fmt);
	
	warning_va_list(fmt, args);

	va_end(args);
}

extern char *optarg;
extern int optind;

int 
main (int argc, char **argv)
{
	char *zonename, *zonefile, *s;
	char buf[LINEBUFSZ];
	struct namedb *db;
	const char *sep = " \t\n";
	char *nsd_stdin_origin = NULL;
	int c;
	int line = 0;
	FILE *f;

	log_init("zonec");
	zone_region = region_create(xalloc, free);
	rr_region = region_create(xalloc, free);
	
	totalerrors = 0;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "d:f:vhF:L:o:")) != -1) {
		switch (c) {
		case 'v':
			++vflag;
			break;
		case 'f':
			dbfile = optarg;
			break;
		case 'd':
			if (chdir(optarg)) {
				fprintf(stderr, "zonec: cannot chdir to %s: %s\n", optarg, strerror(errno));
				break;
			}
			break;
#ifndef NDEBUG
		case 'F':
			sscanf(optarg, "%x", &nsd_debug_facilities);
			break;
		case 'L':
			sscanf(optarg, "%d", &nsd_debug_level);
			break;
#endif /* NDEBUG */
		case 'o':
			nsd_stdin_origin = optarg;
			break;
		case 'h':
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* Create the database */
	if ((db = namedb_new(dbfile)) == NULL) {
		fprintf(stderr, "zonec: error creating the database: %s\n", dbfile);
		exit(1);
	}

	current_parser = zparser_init(db);
	current_rr = region_alloc(zone_region, sizeof(rr_type));

	/* Unique pointers used to mark errors.  */
	error_dname = region_alloc(zone_region, 0);
	error_domain = region_alloc(zone_region, 0);

	temporary_rrdata = region_alloc(zone_region, rrdata_size(MAXRDATALEN));
	
	if ( strcmp(*argv,"-") == 0 ) {
		/* ah, somebody give - (stdin) as input file name */
		if ( nsd_stdin_origin == NULL ) {
			fprintf(stderr,"zonec: need origin (-o switch) when reading from stdin.\n");
			exit(1);
		}
		
		zone_read(nsd_stdin_origin, "-");

#ifndef NDEBUG
		fprintf(stderr, "zone_region: ");
		region_dump_stats(zone_region, stderr);
		fprintf(stderr, "\n");
#endif /* NDEBUG */
	} else {
		/* Open the master file... */
		if ((f = fopen(*argv, "r")) == NULL) {
			fprintf(stderr, "zonec: cannot open %s: %s\n", *argv, strerror(errno));
			exit(1);
		}

		/* Do the job */
		while (fgets(buf, LINEBUFSZ - 1, f) != NULL) {
			/* Count the lines... */
			line++;

			/* Skip empty lines and comments... */
			if ((s = strtok(buf, sep)) == NULL || *s == ';')
				continue;

			if (strcasecmp(s, "zone") != 0) {
				fprintf(stderr, "zonec: syntax error in %s line %d: expected token 'zone'\n", *argv, line);
				break;
			}

			/* Zone name... */
			if ((zonename = strtok(NULL, sep)) == NULL) {
				fprintf(stderr, "zonec: syntax error in %s line %d: expected zone name\n", *argv, line);
				break;
			}

			/* File name... */
			if ((zonefile = strtok(NULL, sep)) == NULL) {
				fprintf(stderr, "zonec: syntax error in %s line %d: expected file name\n", *argv, line);
				break;
			}

			/* Trailing garbage? Ignore masters keyword that is used by nsdc.sh update */
			if ((s = strtok(NULL, sep)) != NULL && *s != ';' && strcasecmp(s, "masters") != 0
		    		&& strcasecmp(s, "notify") != 0) {
				fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
			}

			if (vflag > 0) fprintf(stderr,"zonec: reading zone \"%s\".\n",zonename);
			zone_read(zonename, zonefile);
			if (vflag > 0) fprintf(stderr,"zonec: processed %ld RRs in \"%s\".\n", totalrrs, zonename);
			totalrrs = 0;

#ifndef NDEBUG
			fprintf(stderr, "zone_region: ");
			region_dump_stats(zone_region, stderr);
			fprintf(stderr, "\n");
#endif /* NDEBUG */
		}
	}

	/* Close the database */
	if (namedb_save(db) != 0) {
		fprintf(stderr, "zonec: error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	/* Print the total number of errors */
	if (vflag > 0) {
		fprintf(stderr, "\n");
		fprintf(stderr, "zonec: done with %ld errors.\n", totalerrors);
	} else {
		if (totalerrors > 0) {
			fprintf(stderr, "\n");
			fprintf(stderr, "zonec: done with %ld errors.\n", totalerrors);
		}
	}
	
	/* Disable this to save some time.  */
#if 0
	region_destroy(zone_region);
#endif
	
	return totalerrors ? 1 : 0;
}
