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
#include "rdata.h"
#include "region-allocator.h"
#include "util.h"
#include "zparser.h"

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

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

extern uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

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
		zc_error_prev_line("number of hex digits must be a multiple of 2");
	} else if (len > MAX_RDLENGTH * 2) {
		zc_error_prev_line("hex data exceeds maximum rdata length (%d)",
				   MAX_RDLENGTH);
	} else {
		/* the length part */
		r = (uint16_t *) region_alloc(region,
					      sizeof(uint16_t) + len/2);
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
					zc_error_prev_line("illegal hex character '%c'", (int)*hex);
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
		zc_error_prev_line("Date and time is expected");
	} else {

		r = (uint16_t *) region_alloc(
			region, sizeof(uint32_t) + sizeof(uint16_t));
		l = htonl(timegm(&tm));
		memcpy(r + 1, &l, sizeof(uint32_t));
		*r = sizeof(uint32_t);
	}
	return r;
}

uint16_t *
zparser_conv_services(region_type *region, const char *protostr,
		      char *servicestr)
{
	/*
	 * Convert a protocol and a list of service port numbers
	 * (separated by spaces) in the rdata to wireformat
	 */
	uint16_t *r = NULL;
	uint8_t *p;
	uint8_t bitmap[65536/8];
	char sep[] = " ";
	char *word;
	int max_port = -8;
	/* convert a protocol in the rdata to wireformat */
	struct protoent *proto;

	memset(bitmap, 0, sizeof(bitmap));

	proto = getprotobyname(protostr);
	if (!proto) {
		proto = getprotobynumber(atoi(protostr));
	}
	if (!proto) {
		zc_error_prev_line("Unknown protocol");
		return NULL;
	}

	for (word = strtok(servicestr, sep);
	     word;
	     word = strtok(NULL, sep))
	{
		struct servent *service;

		service = getservbyname(word, proto->p_name);
		if (!service) {
			service = getservbyport(atoi(word), proto->p_name);
		}
		if (!service) {
			zc_error_prev_line("Unknown service '%s'", word);
		} else if (service->s_port < 0 || service->s_port > 65535) {
			zc_error_prev_line("bad port number %d", service->s_port);
		} else {
			set_bit(bitmap, service->s_port);
			if (service->s_port > max_port)
				max_port = service->s_port;
		}
        }

	r = (uint16_t *) region_alloc(
		region,
		sizeof(uint16_t) + sizeof(uint8_t) + max_port / 8 + 1);
	*r =  sizeof(uint8_t) + max_port / 8 + 1;
	p = (uint8_t *) (r + 1);
	*p++ = proto->p_proto;
	memcpy(p, bitmap, *r);
	
	return r;
}

uint16_t *
zparser_conv_period(region_type *region, const char *periodstr)
{
	/* convert a time period (think TTL's) to wireformat) */

	uint16_t *r = NULL;
	uint32_t l;
	const char *end; 

	/* Allocate required space... */
	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + sizeof(uint32_t));
	l = htonl((uint32_t)strtottl(periodstr, &end));

        if(*end != 0) {
		zc_error_prev_line("Time period is expected");
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
   
	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + sizeof(uint16_t));
    	*(r+1)  = htons((uint16_t)strtol(shortstr, &end, 0));
            
	if(*end != 0) {
		zc_error_prev_line("Unsigned short value is expected");
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

	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint32_t));
	l = htonl((uint32_t)strtol(longstr, &end, 0));

	if(*end != 0) {
		zc_error_prev_line("Long decimal value is expected");
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
 
        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint8_t));

        *((uint8_t *)(r+1)) = (uint8_t)strtol(bytestr, &end, 0);

        if(*end != 0) {
		zc_error_prev_line("Decimal value is expected");
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

	alg = lookup_by_name(dns_algorithms, algstr);

	if (!alg) {
		/* not a memonic */
		return zparser_conv_byte(region, algstr);
	}

        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint8_t));
	*((uint8_t *)(r+1)) = alg->id;
	*r = sizeof(uint8_t);
	return r;
}

uint16_t *
zparser_conv_certificate_type(region_type *region, const char *typestr)
{
	/* convert a algoritm string to integer */
	uint16_t *r = NULL;
	const lookup_table_type *type;

	type = lookup_by_name(dns_certificate_types, typestr);

	if (!type) {
		/* not a memonic */
		return zparser_conv_short(region, typestr);
	}

        r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint16_t));
	*r = sizeof(uint16_t);
	write_uint16(r + 1, type->id);
	return r;
}

uint16_t *
zparser_conv_a(region_type *region, const char *a)
{
	/* convert a A rdata to wire format */
	in_addr_t pin;
	uint16_t *r = NULL;

	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(in_addr_t));
	if(inet_pton(AF_INET, a, &pin) > 0) {
		memcpy(r + 1, &pin, sizeof(in_addr_t));
		*r = sizeof(in_addr_t);
	} else {
		zc_error_prev_line("Invalid ip address");
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
		zc_error_prev_line("Text string is longer than 255 charaters, try splitting in two");
        } else {

		/* Allocate required space... */
		r = (uint16_t *) region_alloc(region,
					      sizeof(uint16_t) + i + 1);

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
	char pin[IP6ADDRLEN];
	uint16_t *r = NULL;

	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + IP6ADDRLEN);

        /* Try to convert it */
        if (inet_pton(AF_INET6, a6, pin) != 1) {
		zc_error_prev_line("invalid IPv6 address");
        } else {
		*r = IP6ADDRLEN;
		memcpy(r + 1, pin, IP6ADDRLEN);
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
		zc_error_prev_line("Base64 encoding failed");
        } else {
		r = (uint16_t *) region_alloc(region, i + sizeof(uint16_t));
		*r = i;
		memcpy(r + 1, buffer, i);
        }
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
	uint16_t type = lookup_type_by_name(rr);
	uint16_t *r;

	if (type == 0) {
		zc_error_prev_line("unrecognized type '%s'", rr);
		return NULL;
	}
	
	r = (uint16_t *) region_alloc(region,
				      sizeof(uint16_t) + sizeof(uint16_t));
	r[0] = sizeof(uint16_t);
	r[1] = htons(type);
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

	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + (last * sizeof(uint8_t)) );
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
	
	r = (uint16_t *) region_alloc(
		region, sizeof(uint16_t) + total_size * sizeof(uint8_t));
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
		zc_error_prev_line("%s must be within the [%d .. %d] range", name, min, max);
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
			zc_error_prev_line("Unexpected end of LOC data");
			return NULL;
		}

		if (!parse_int(str, &str, &deg, "degrees", 0, 180))
			return NULL;
		if (!isspace(*str)) {
			zc_error_prev_line("Space expected after degrees");
			return NULL;
		}
		++str;
		
		/* Minutes? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &min, "minutes", 0, 60))
				return NULL;
			if (!isspace(*str)) {
				zc_error_prev_line("Space expected after minutes");
				return NULL;
			}
		}
		++str;
		
		/* Seconds? */
		if (isdigit(*str)) {
			if (!parse_int(str, &str, &secs, "seconds", 0, 60))
				return NULL;
			if (!isspace(*str) && *str != '.') {
				zc_error_prev_line("Space expected after seconds");
				return NULL;
			}
		}

		if (*str == '.') {
			secfraq = (int) strtol(str + 1, &str, 10);
			if (!isspace(*str)) {
				zc_error_prev_line("Space expected after seconds");
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
			zc_error_prev_line("Invalid latitude/longtitude");
			return NULL;
		}
		++str;
		
		if (lat != 0 && lon != 0)
			break;

		if (!isspace(*str)) {
			zc_error_prev_line("Space expected after latitude/longitude");
			return NULL;
		}
		++str;
	}

	/* Altitude */
	if (*str == '\0') {
		zc_error_prev_line("Unexpected end of LOC data");
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
			zc_error_prev_line("Altitude fraction must be a number");
			return NULL;
		}
		break;
	default:
		zc_error_prev_line("Altitude must be expressed in meters");
		return NULL;
	}
	if (!isspace(*str) && *str != '\0')
		++str;
	
	alt = (10000000 + (altsign * (altmeters * 100 + altfraq)));

	if (!isspace(*str) && *str != '\0') {
		zc_error_prev_line("Unexpected character after altitude");
		return NULL;
	}

	/* Now parse size, horizontal precision and vertical precision if any */
	for(i = 1; isspace(*str) && i <= 3; i++) {
		vszhpvp[i] = precsize_aton(str + 1, &str);

		if (!isspace(*str) && *str != '\0') {
			zc_error_prev_line("Invalid size or precision");
			return NULL;
		}
	}

	/* Allocate required space... */
	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + 16);
	*r = 16;

	memcpy(r + 1, vszhpvp, 4);

	write_uint32(r + 3, lat);
	write_uint32(r + 5, lon);
	write_uint32(r + 7, alt);

	return r;
}

/*
 * Convert an APL RR RDATA element.
 */
uint16_t *
zparser_conv_apl_rdata(region_type *region, char *str)
{
	int negated = 0;
	uint16_t address_family;
	uint8_t prefix;
	uint8_t maximum_prefix;
	uint8_t length;
	uint8_t address[IP6ADDRLEN];
	char *colon = strchr(str, ':');
	char *slash = strchr(str, '/');
	int af;
	int rc;
	uint16_t rdlength;
	uint16_t *r;
	uint8_t *t;
	char *end;
	long p;
	
	if (!colon) {
		zc_error("address family separator is missing");
		return NULL;
	}
	if (!slash) {
		zc_error("prefix separator is missing");
		return NULL;
	}

	*colon = '\0';
	*slash = '\0';
	
	if (*str == '!') {
		negated = 1;
		++str;
	}

	if (strcmp(str, "1") == 0) {
		address_family = 1;
		af = AF_INET;
		length = sizeof(in_addr_t);
		maximum_prefix = length * 8;
	} else if (strcmp(str, "2") == 0) {
		address_family = 2;
		af = AF_INET6;
		length = IP6ADDRLEN;
		maximum_prefix = length * 8;
	} else {
		zc_error("invalid address family '%s'", str);
		return NULL;
	}

	rc = inet_pton(af, colon + 1, address);
	if (rc == 0) {
		zc_error("invalid address '%s'", colon + 1);
	} else if (rc == -1) {
		zc_error("inet_pton failed: %s", strerror(errno));
	}

	/* Strip trailing zero octets.  */
	while (length > 0 && address[length - 1] == 0)
		--length;

	
	p = strtol(slash + 1, &end, 10);
	if (p < 0 || p > maximum_prefix) {
		zc_error("prefix not in the range 0 .. %d", maximum_prefix);
	} else if (*end != '\0') {
		zc_error("invalid prefix '%s'", slash + 1);
	}
	prefix = (uint8_t) p;

	rdlength = (sizeof(address_family) + sizeof(prefix) + sizeof(length)
		    + length);
	r = (uint16_t *) region_alloc(region, sizeof(uint16_t) + rdlength);
	*r = rdlength;
	t = (uint8_t *) (r + 1);
	
	memcpy(t, &address_family, sizeof(address_family));
	t += sizeof(address_family);
	memcpy(t, &prefix, sizeof(prefix));
	t += sizeof(prefix);
	memcpy(t, &length, sizeof(length));
	if (negated)
		*t |= 0x80;
	t += sizeof(length);
	memcpy(t, address, length);

	return r;
}

/* 
 * Below some function that also convert but not to wireformat
 * but to "normal" (int,long,char) types
 */

int32_t
zparser_ttl2int(const char *ttlstr)
{
	/* convert a ttl value to a integer
	 * return the ttl in a int
	 * -1 on error
	 */

	int32_t ttl;
	const char *t;

	ttl = strtottl(ttlstr, &t);
	if(*t != 0) {
		zc_error_prev_line("Invalid ttl value: %s",ttlstr);
		ttl = -1;
	}
    
	return ttl;
}


void
zadd_rdata_wireformat(uint16_t *data)
{
	if (parser->current_rr.rdata_count > MAXRDATALEN) {
		zc_error_prev_line("too many rdata elements");
	} else {
		parser->current_rr.rdatas[parser->current_rr.rdata_count].data
			= data;
		++parser->current_rr.rdata_count;
	}
}

void
zadd_rdata_domain(domain_type *domain)
{
	if (parser->current_rr.rdata_count > MAXRDATALEN) {
		zc_error_prev_line("too many rdata elements");
	} else {
		parser->current_rr.rdatas[parser->current_rr.rdata_count].domain
			= domain;
		++parser->current_rr.rdata_count;
	}
}

void
parse_unknown_rdata(uint16_t type, uint16_t *wireformat)
{
	buffer_type packet;
	uint16_t size = *wireformat;
	ssize_t rdata_count;
	ssize_t i;
	rdata_atom_type *rdatas;

	buffer_create_from(&packet, wireformat + 1, *wireformat);
	rdata_count = rdata_wireformat_to_rdata_atoms(parser->region,
						      parser->db->domains,
						      type,
						      size,
						      &packet,
						      &rdatas);
	if (rdata_count == -1) {
		zc_error_prev_line("bad unknown RDATA");
		return;
	}
	
	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			zadd_rdata_domain(rdatas[i].domain);
		} else {
			zadd_rdata_wireformat(rdatas[i].data);
		}
	}
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
 * Lookup the type in the ztypes lookup table.  If not found, check if
 * the type uses the "TYPExxx" notation for unknown types.
 *
 * Return 0 if no type matches.
 */
uint16_t
lookup_type_by_name(const char *name)
{
	rrtype_descriptor_type *entry = rrtype_descriptor_by_name(name);
	return entry ? entry->type : intbytypexx(name);
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
zrdatacmp(uint16_t type, rr_type *a, rr_type *b)
{
	int i = 0;
	
	assert(a);
	assert(b);
	
	/* One is shorter than another */
	if (a->rdata_count != b->rdata_count)
		return 1;

	/* Compare element by element */
	for (i = 0; i < a->rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(a->rdatas[i])
			    != rdata_atom_domain(b->rdatas[i]))
			{
				return 1;
			}
		} else {
			if (rdata_atom_size(a->rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
			{
				return 1;
			}
			if (memcmp(rdata_atom_data(a->rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(a->rdatas[i])) != 0)
			{
				return 1;
			}
		}
	}

	/* Otherwise they are equal */
	return 0;
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
zone_open(const char *filename, uint32_t ttl, uint16_t klass,
	  const char *origin)
{
	/* Open the zone file... */
	if ( strcmp(filename, "-" ) == 0 ) {
		/* check for stdin */
		yyin = stdin;
		filename = "STDIN";
	} else {
		if((yyin  = fopen(filename, "r")) == NULL) {
			return 0;
		}
	}

	/* Open the network database */
	setprotoent(1);
	setservent(1);

	zparser_init(filename, ttl, klass, origin);

	return 1;
}


void 
set_bitnsec(uint8_t bits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE],
	    uint16_t index)
{
	/*
	 * The bits are counted from left to right, so bit #0 is the
	 * left most bit.
	 */
	uint8_t window = index / 256;
	uint8_t bit = index % 256;
		
	bits[window][bit / 8] |= (1 << (7 - bit % 8));
}


static void
cleanup_rrset(void *r)
{
	rrset_type *rrset = (rrset_type *) r;
	if (rrset) {
		free(rrset->rrs);
	}
}

int
process_rr()
{
	zone_type *zone = parser->current_zone;
	rr_type *rr = &parser->current_rr;
	rrset_type *rrset;
	size_t max_rdlength;
	int i;
	rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(rr->type);
	
	/* We only support IN class */
	if (rr->klass != CLASS_IN) {
		zc_error_prev_line("only class IN is supported");
		return 0;
	}

	/* Make sure the maximum RDLENGTH does not exceed 65535 bytes.  */
	max_rdlength = rdata_maximum_wireformat_size(
		descriptor, rr->rdata_count, rr->rdatas);

	if (max_rdlength > MAX_RDLENGTH) {
		zc_error_prev_line("maximum rdata length exceeds %d octets", MAX_RDLENGTH);
		return 0;
	}
		     
	if ( rr->type == TYPE_SOA ) {
		/*
		 * This is a SOA record, start a new zone or continue
		 * an existing one.
		 */
		zone = namedb_find_zone(parser->db, rr->owner);
		if (!zone) {
			/* new zone part */
			zone = (zone_type *) region_alloc(parser->region,
							  sizeof(zone_type));
			zone->apex = rr->owner;
			zone->soa_rrset = NULL;
			zone->ns_rrset = NULL;
			zone->is_secure = 0;
			
			/* insert in front of zone list */
			zone->next = parser->db->zones;
			parser->db->zones = zone;
		}
		
		/* parser part */
		parser->current_zone = zone;
	}

	if (!dname_is_subdomain(domain_dname(rr->owner),
				domain_dname(zone->apex)))
	{
		zc_error_prev_line("out of zone data");
		return 0;
	}

	/* Do we have this type of rrset already? */
	rrset = domain_find_rrset(rr->owner, zone, rr->type);

	/* Do we have this particular rrset? */
	if (rrset == NULL) {
		rrset = (rrset_type *) region_alloc(parser->region,
						    sizeof(rrset_type));
		rrset->zone = zone;
		rrset->rr_count = 1;
		rrset->rrs = (rr_type *) xalloc(sizeof(rr_type));
		memcpy(&rrset->rrs[0], rr, sizeof(rr_type));
			
		region_add_cleanup(parser->region, cleanup_rrset, rrset);

		/* Add it */
		domain_add_rrset(rr->owner, rrset);
	} else {
		if (rrset->rrs[0].type != TYPE_RRSIG
		    && rrset->rrs[0].ttl != rr->ttl)
		{
			zc_warning_prev_line("TTL doesn't match the TTL of the RRset");
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rr_count; i++) {
			if (!zrdatacmp(rr->type, rr, &rrset->rrs[i]))
			{
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rr_count) {
			return 0;
		}

		/* Add it... */
		rrset->rrs = (rr_type *) xrealloc(
			rrset->rrs,
			(rrset->rr_count + 1) * sizeof(rr_type));
		memcpy(&rrset->rrs[rrset->rr_count], rr, sizeof(rr_type));
		++rrset->rr_count;
	}

#ifdef DNSSEC
	if (rrset->rrs[0].type == TYPE_RRSIG
	    && rrset_rrsig_type_covered(rrset, rrset->rr_count - 1) == TYPE_SOA)
	{
		rrset->zone->is_secure = 1;
	}
#endif
	
	/* Check we have SOA */
	/* [XXX] this is dead code */
	if (zone->soa_rrset == NULL) {
		if (rr->type != TYPE_SOA) {
			zc_error_prev_line("Missing SOA record on top of the zone");
		} else if (rr->owner != zone->apex) {
			zc_error_prev_line( "SOA record with invalid domain name");
		} else {
			zone->soa_rrset = rrset;
		}
	} else if (rr->type == TYPE_SOA) {
		zc_error_prev_line("Duplicate SOA record discarded");
		--rrset->rr_count;
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && rr->owner == zone->apex) {
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

	dname = dname_parse(parser->region, name, NULL);
	if (!dname) {
		zc_error_prev_line("Cannot parse zone name '%s'", name);
		return;
	}
	
#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dname->label_count == 1) {
		zc_error("Not configured as a root server.");
		return;
	}
#endif

	/* Open the zone file */
	if (!zone_open(zonefile, 3600, CLASS_IN, name)) {
		/* cannot happen with stdin - so no fix needed for zonefile */
		fprintf(stderr, " ERR: Cannot open \'%s\': %s\n", zonefile, strerror(errno));
		return;
	}

	/* Parse and process all RRs.  */
	/* reset the nsecbits to zero */
	yyparse();

	fclose(yyin);
	yyin = NULL;

	fflush(stdout);
	totalerrors += parser->errors;
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
	region_type *global_region;
	region_type *rr_region;
	
	log_init("zonec");

#ifndef NDEBUG
	/* Check consistency of rrtype descriptor table.  */
	{
		int i;
		for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
			if (i != rrtype_descriptors[i].type) {
				fprintf(stderr, "error: type descriptor entry '%d' does not match type '%d', fix the definition in dns.c\n", i, rrtype_descriptors[i].type);
				abort();
			}
		}
	}
#endif
	
	global_region = region_create(xalloc, free);
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

	parser = zparser_create(global_region, rr_region, db);

	/* Unique pointers used to mark errors.  */
	error_dname = (dname_type *) region_alloc(global_region, 0);
	error_domain = (domain_type *) region_alloc(global_region, 0);

	if (strcmp(*argv,"-") == 0) {
		/* ah, somebody give - (stdin) as input file name */
		if ( nsd_stdin_origin == NULL ) {
			fprintf(stderr,"zonec: need origin (-o switch) when reading from stdin.\n");
			exit(1);
		}
		
		zone_read(nsd_stdin_origin, "-");

#ifndef NDEBUG
		fprintf(stderr, "global_region: ");
		region_dump_stats(global_region, stderr);
		fprintf(stderr, "\n");
		fprintf(stderr, "db->region: ");
		region_dump_stats(db->region, stderr);
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

			if (vflag > 0)
				fprintf(stderr, "zonec: reading zone \"%s\".\n",
					zonename);
			zone_read(zonename, zonefile);
			if (vflag > 0)
				fprintf(stderr,
					"zonec: processed %ld RRs in \"%s\".\n",
					totalrrs, zonename);
			totalrrs = 0;

#ifndef NDEBUG
			fprintf(stderr, "global_region: ");
			region_dump_stats(global_region, stderr);
			fprintf(stderr, "\n");
			fprintf(stderr, "db->region: ");
			region_dump_stats(db->region, stderr);
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
	if (vflag > 0 || totalerrors > 0) {
		fprintf(stderr, "\n");
		fprintf(stderr, "zonec: done with %ld errors.\n", totalerrors);
	}
	
	/* Disable this to save some time.  */
#if 0
	region_destroy(global_region);
#endif
	
	return totalerrors ? 1 : 0;
}
