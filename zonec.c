/*
 * zonec.c -- zone compiler.
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
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

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength, char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

static long strtottl(char *nptr, char **endptr);
	
region_type *zone_region;
region_type *rr_region;

/* The database file... */
static const char *dbfile = DBFILE;

/* Some global flags... */
static int vflag = 0;

/* Total errors counter */
static int totalerrors = 0;

/*
 *
 * Resource records types and classes that we know.
 *
 */

struct ztab ztypes[] = Z_TYPES;
struct ztab zclasses[] = Z_CLASSES;


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
		error("hex representation must be a whole number of octets");
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
					error("illegal hex character");
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
		error("date and time is expected");
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
		error("unknown protocol");
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
		error("unknown protocol, internal error");
        } else {
		if((service = getservbyname(servicestr, proto->p_name)) == NULL) {
			error("unknown service");
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
		error("time period is expected");
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
		error("unsigned short value is expected");
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
		error("long decimal value is expected");
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
		error("decimal value is expected");
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
		error("invalid ip address");
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
		error("text string is longer than 255 charaters, try splitting in two");
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
		error("invalid ipv6 address");
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
		error("base64 encoding failed");
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
		error("invalid ttl value");
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
 * Looks up the numeric value of the symbol, returns 0 if not found.
 */
uint16_t
intbyname(const char *a, struct ztab *tab)
{
	while (tab->name != NULL) {
		if (strcasecmp(a, tab->name) == 0)
			return tab->sym;
		tab++;
	}
	return 0;
}

/*
 * Looks up the string value of the symbol, returns NULL if not found.
 */
const char *
namebyint(uint16_t n, struct ztab *tab)
{
	while (tab->sym != 0) {
		if (tab->sym == n)
			return tab->name;
		tab++;
	}
	return NULL;
}

#if 0
static const char *
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

static const char *
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
#endif


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
static long
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

	current_rr->rdata = temporary_rdata;

	return 1;
}

#if 0
/* RFC1876 conversion routines */
static unsigned int poweroften[10] = {1, 10, 100, 1000, 10000, 100000,
				      1000000,10000000,100000000,1000000000};

/*
 *
 * Takes an XeY precision/size value, returns a string representation.
 *
 */
static const char *
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
static uint8_t 
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
#endif

void 
setbit(uint8_t bits[], int index)
{
	/* set bit #place in the byte */
	/* the bits are counted from right to left
	 * so bit #0 is the right most bit
	 */
	bits[index / 8] |= (1 << (7 - index % 8));
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
	int i;
	
	/* We only support IN class */
	if (rr->class != CLASS_IN) {
		error("Wrong class");
		return 0;
	}
	if ( rr->type == TYPE_SOA ) {
		/* This is a SOA record, start a new zone */

		/* new zone part */
		zone = region_alloc(zone_region, sizeof(zone_type));
		zone->domain = domain_table_insert(parser->db->domains, 
				rr->domain->dname);
		zone->soa_rrset = NULL;
		zone->ns_rrset = NULL;

		/* ervoor plaatsen */
		zone->next = parser->db->zones;
		parser->db->zones = zone;

		/* parser part */
		current_parser->current_zone = zone;
	}

        /* [XXX] still need to check if we have seen this SOA already */

	if (!dname_is_subdomain(rr->domain->dname, zone->domain->dname)) {
		error("Out of zone data");
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
		rrset->ttl = rr->ttl;
		rrset->rrslen = 1;
		rrset->rrs = xalloc(sizeof(rdata_atom_type **));
		rrset->rrs[0] = rr->rdata;
			
		region_add_cleanup(zone_region, cleanup_rrset, rrset);

		/* Add it */
		domain_add_rrset(rr->domain, rrset);
	} else {
		if (rrset->ttl != rr->ttl) {
			error("ttl doesn't match the ttl of the rrset");
			return 0;
		}

		/* Search for possible duplicates... */
		for (i = 0; i < rrset->rrslen; i++) {
			if (!zrdatacmp(rrset->type, rrset->rrs[i], rr->rdata)) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < rrset->rrslen) {
			return 0;
		}

		/* Add it... */
		rrset->rrs = xrealloc(rrset->rrs, (rrset->rrslen + 1) * sizeof(rdata_atom_type **));
		rrset->rrs[rrset->rrslen++] = rr->rdata;
	}

	/* Check we have SOA */
	if (zone->soa_rrset == NULL) {
		if (rr->type != TYPE_SOA) {
			error("Missing SOA record on top of the zone");
		} else if (rr->domain != zone->domain) {
			error( "SOA record with invalid domain name");
		} else {
			zone->soa_rrset = rrset;
		}
	} else if (rr->type == TYPE_SOA) {
		error("Duplicate SOA record discarded");
		--rrset->rrslen;
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && rr->domain == zone->domain) {
		zone->ns_rrset = rrset;
	}

	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static void
zone_read (char *name, char *zonefile)
{
	const dname_type *dname;

	dname = dname_parse(zone_region, name, NULL);
	if (!dname) {
		error("cannot parse zone name '%s'", name);
		return;
	}
	
#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dname->label_count == 1) {
		error("not configured as a root server.");
		return;
	}
#endif

	/* Open the zone file */
	if (!zone_open(zonefile, 3600, CLASS_IN, name)) {
		/* cannot happen with stdin - so no fix needed for zonefile */
		error("cannot open '%s': %s", zonefile, strerror(errno));
		return;
	}

	/* Parse and process all RRs.  */
	yyparse();

	fflush(stdout);
	totalerrors += current_parser->errors;
}

static void 
usage (void)
{
	fprintf(stderr, "usage: zonec [-v|-p|-o|-F|-L] [-f database] [-d directory] zone-list-file\n\n");
	fprintf(stderr, "\t-h\tPrint this help information.\n");
	fprintf(stderr, "\t-p\tPrint rr after compilation.\n");
	fprintf(stderr, "\t-o\tSpecify a zone's origin (used zone-list-file equals \'-\'.\n)");
	fprintf(stderr, "\t-v\tBe more verbose.\n");
	fprintf(stderr, "\t-F\tSet debug facilities.\n");
	fprintf(stderr, "\t-L\tSet debug level.\n");
	exit(1);
}


int
error(const char *fmt, ...)
{
	/* send an error message to stderr */
	va_list args;
	va_start(args, fmt);

	fprintf(stderr," ERR: Line %u: ", current_parser->line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	va_end(args);
	current_parser->errors++;
	return 0;
}

int 
warning(const char *fmt, ... )
{
	va_list args;

	va_start(args, fmt);

	fprintf(stderr,"WARN: Line %u: ", current_parser->line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");

	va_end(args);
	return 0;
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

			zone_read(zonename, zonefile);

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
	fprintf(stderr, "zonec: done with total %d errors.\n", totalerrors);

	/* Disable this to save some time.  */
#if 0
	region_destroy(zone_region);
#endif
	
	return totalerrors ? 1 : 0;
}
