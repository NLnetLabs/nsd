/*
 * $Id: zparser2.c,v 1.29 2003/10/29 09:56:12 miekg Exp $
 *
 * zparser2.c -- parser helper function
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license
 */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <time.h>

#include <netinet/in.h>

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "zparser2.h"
#include "dns.h"
#include "dname.h"
#include "namedb.h"
#include "util.h"
#include "zonec2.h"

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength, char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

/* 
 * These are parser function for generic zone file stuff.
 */
uint16_t *
zparser_conv_hex(region_type *region, const char *hex)
{
	/* convert a hex value to wireformat */
	uint16_t *r = NULL;
	uint8_t *t;
	int i;
    
	if ((i = strlen(hex)) % 2 != 0) {
		zerror("hex representation must be a whole number of octets");
	} else {
		/* the length part */
		r = region_alloc(region, sizeof(uint16_t) + i/2);
		*r = i/2;
		t = (uint8_t *)(r + 1);
    
		/* Now process octet by octet... */
		while(*hex) {
			*t = 0;
			for(i = 16; i >= 1; i -= 15) {
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
					*t += (*hex - '0') * i; /* first hex */
					break;
				case 'a':
				case 'A':
				case 'b':
				case 'B':
				case 'c':
				case 'C':
				case 'd':
				case 'D':
				case 'e':
				case 'E':
				case 'f':
				case 'F':
					*t += (*hex - 'a' + 10) * i;    /* second hex */
					break;
				default:
					zerror("illegal hex character");
					return NULL;
				}
				*hex++;
			}
			t++;
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
		zerror("date and time is expected");
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
		zerror("unknown protocol");
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
		zerror("unknown protocol, internal error");
        } else {
		if((service = getservbyname(servicestr, proto->p_name)) == NULL) {
			zerror("unknown service");
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
		zerror("time period is expected");
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
		zerror("unsigned short value is expected");
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
		zerror("long decimal value is expected");
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
		zerror("decimal value is expected");
        } else {
		*r = sizeof(uint8_t);
        }
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
		zerror("invalid ip address");
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
		zerror("text string is longer than 255 charaters, try splitting in two");
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
		zerror("invalid ipv6 address");
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
		zerror("base64 encoding failed");
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

	r = region_alloc(region, sizeof(uint16_t) + domain->dname->name_size);
	*r = domain->dname->name_size;
	memcpy(r + 1, dname_name(domain->dname), domain->dname->name_size);
	return r;
}

uint16_t *
zparser_conv_rrtype(region_type *region, const char *rr)
{
	/* get the official number for the rr type and return
	 * that. This is used by SIG in the type-covered field
	 */

	/* [XXX] error handling */
	uint16_t *r = NULL;
	
	r = region_alloc(region, sizeof(uint16_t) + sizeof(uint16_t));

	*(r+1)  = htons((uint16_t) 
			intbyname(rr, ztypes)
			);
            
	*r = sizeof(uint16_t);
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
		zerror("invalid ttl value");
		ttl = -1;
	}
    
	return ttl;
}


/* struct * RR current_rr is global, no 
 * need to pass it along */
void
zadd_rdata_wireformat(zparser_type *parser, uint16_t *data)
{
	if(parser->_rc >= MAXRDATALEN - 1) {
		fprintf(stderr,"too many rdata elements");
		abort();
	}
	current_rr->rdata[parser->_rc].data = data;
	++parser->_rc;
}

void
zadd_rdata_domain(zparser_type *parser, domain_type *domain)
{
	if(parser->_rc >= MAXRDATALEN - 1) {
		fprintf(stderr,"too many rdata elements");
		abort();
	}
	current_rr->rdata[parser->_rc].data = domain;
	++parser->_rc;
}

void
zadd_rdata_finalize(zparser_type *parser)
{
	/* RDATA_TERMINATOR signals the last rdata */

	/* _rc is already incremented in zadd_rdata2 */
	current_rr->rdata[parser->_rc].data = NULL;
}

/*
 *
 * Resource records types and classes that we know.
 *
 */
struct ztab ztypes[] = Z_TYPES;
struct ztab zclasses[] = Z_CLASSES;

/*
 * Looks up the numeric value of the symbol, returns 0 if not found.
 *
 */
uint16_t
intbyname (const char *a, struct ztab *tab)
{
	while(tab->name != NULL) {
		if(strcasecmp(a, tab->name) == 0) return tab->sym;
		tab++;
	}
	return 0;
}

/*
 * Looks up the string value of the symbol, returns NULL if not found.
 *
 */
const char *
namebyint (uint16_t n, struct ztab *tab)
{
	while(tab->sym != 0) {
		if(tab->sym == n) return tab->name;
		tab++;
	}
	return NULL;
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
int
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
			break;
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
 * Prints error message and the file name and line number of the file
 * where it happened. Also increments the number of errors for the
 * particular file.
 *
 * Returns:
 *
 *	nothing
 */
void 
zerror (const char *msg)
{   
	yyerror(msg);
}


/*
 * Initializes the parser.
 */
zparser_type *
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
int
nsd_zopen(zone_type *zone, const char *filename, uint32_t ttl, uint16_t class, const char *origin)
{
	/* Open the zone file... */
	/* [XXX] still need to handle recursion */
	if((yyin  = fopen(filename, "r")) == NULL) {
		return 0;
	}

	/* Open the network database */
	setprotoent(1);
	setservent(1);

	current_parser->ttl = ttl;
	current_parser->minimum = 0;
	current_parser->class = class;
	current_parser->current_zone = zone;
	current_parser->origin = domain_table_insert(
		current_parser->db->domains,
		dname_parse(zone_region, origin, NULL));  /* hmm [XXX] MG */
	current_parser->prev_dname =
		current_parser->origin; /* XXX Or NULL + error check
					 * in zonec when first RR does
					 * not mention a domain
					 * name? */
	current_parser->_rc = 0;
	current_parser->errors = 0;
	current_parser->line = 1;
	current_parser->filename = filename;

	current_rr->rdata = temporary_rdata;

	return 1;
}

/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				      1000000,10000000,100000000,1000000000};

/*
 *
 * Takes an XeY precision/size value, returns a string representation.
 *
 */
const char *
precsize_ntoa (int prec)
{
	static char retbuf[sizeof("90000000.00")];
	unsigned long val;
	int mantissa, exponent;

	mantissa = (int)((prec >> 4) & 0x0f) % 10;
	exponent = (int)((prec >> 0) & 0x0f) % 10;

	val = mantissa * poweroften[exponent];

	(void) snprintf(retbuf, sizeof(retbuf), "%lu.%.2lu", val/100, val%100);
	return (retbuf);
}

/*
 * Converts ascii size/precision X * 10**Y(cm) to 0xXY.
 * Sets the given pointer to the last used character.
 *
 */
uint8_t 
precsize_aton (register char *cp, char **endptr)
{
	unsigned int mval = 0, cmval = 0;
	uint8_t retval = 0;
	register int exponent;
	register int mantissa;

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

const char *
typebyint(uint16_t type)
{
	static char typebuf[] = "TYPEXXXXX";
	const char *t = namebyint(type, ztypes);
	if(t == NULL) {
		snprintf(typebuf + 4, sizeof(typebuf) - 4, "%u", type);
		t = typebuf;
	}
	return t;
}

const char *
classbyint(uint16_t class)
{
	static char classbuf[] = "CLASSXXXXX";
	const char *t = namebyint(class, zclasses);
	if(t == NULL) {
		snprintf(classbuf + 5, sizeof(classbuf) - 5, "%u", class);
		t = classbuf;
	}
	return t;
}

