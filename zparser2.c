/*
 * $Id: zparser2.c,v 1.10 2003/08/19 14:14:18 miekg Exp $
 *
 * zparser2.c -- parser helper function
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license
 */

#include <config.h>
#include <zparser2.h>

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

#include "dns.h"
#include "dname.h"
#include "util.h"


/* 
 * These are parser function for generic zone file stuff.
 */

uint16_t *
zparser_conv_hex(const char *hex)
{
    /* convert a hex value to wireformat */
    uint16_t *r = NULL;
    uint8_t *t;
    int i;
    
    if ((i = strlen(hex)) % 2 != 0) {
            zerror("hex representation must be a whole number of octets");
            error++;
    } else {
        /* the length part */
        r = xalloc(sizeof(uint16_t) + i/2);
        *r = i/2;
        t = (uint8_t *)(r + 1);
    
        /* Now process octet by octet... */
        while(*hex) {
                *t = 0;
                for(i = 16; i >= 1; i -= 15) {
                    switch(*hex) {
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
                        error++;
                        free(r);
                        return 0;
                    }
                    *hex++;
                }
                t++;
            }
        }
    return r;
}

uint16_t *
zparser_conv_time(const char *time)
{
    /* convert a time YYHM to wireformat */
    uint16_t *r = NULL;
    struct tm tm;
    uint32_t l;

    /* Try to scan the time... */
    /* [XXX] the cast fixes compile time warning */
    if((char*)strptime(time, "%Y%m%d%H%M%S", &tm) == NULL) {
            zerror("date and time is expected");
            error++;
    } else {

            r = xalloc(sizeof(uint32_t) + sizeof(uint16_t));

            l = htonl(timegm(&tm));
            memcpy(r + 1, &l, sizeof(uint32_t));
            *r = sizeof(uint32_t);
    }
    return r;
}

uint16_t *
zparser_conv_rdata_type(struct RR * current, const char *type)
{
    /* convert rdata_type to wireformat */

    uint16_t *r = NULL;

    r = xalloc(sizeof(uint16_t) + sizeof(uint16_t));

    *(r+1)  = htons((uint16_t)intbyname(type, ztypes));

    if(*(r + 1) == 0) {
            zerror("resource record type is expected");
            error++;
    } else {
            *r = sizeof(uint16_t);
    }
    return r;
}

uint16_t *
zparser_conv_rdata_proto(const char *protostr)
{
    /* convert a protocol in the rdata to wireformat */
    struct protoent *proto;
    uint16_t *r = NULL;
 
    if((proto = getprotobyname(protostr)) == NULL) {
            zerror("unknown protocol");
            error++;
    } else {

            r = xalloc(sizeof(uint16_t) + sizeof(uint16_t));

            *(r + 1) = htons(proto->p_proto);
            *r = sizeof(uint16_t);
    } 
    return r;
}

uint16_t *
zparser_conv_rdata_service(const char *servicestr, const int arg)
{
    /* convert a service in the rdata to wireformat */

    struct protoent *proto;
    struct servent *service;
    uint16_t *r = NULL;

    /* [XXX] need extra arg here .... */
    if((proto = getprotobynumber(arg)) == NULL) {
            zerror("unknown protocol, internal error");
            error++;
        } else {
            if((service = getservbyname(servicestr, proto->p_name)) == NULL) {
                zerror("unknown service");
                error++;
            } else {
                /* Allocate required space... */
                r = xalloc(sizeof(uint16_t) + sizeof(uint16_t));

                *(r + 1) = service->s_port;
                *r = sizeof(uint16_t);
            }
        }
    return r;
}

uint16_t *
zparser_conv_rdata_period(const char *periodstr)
{
    /* convert a time period (think TTL's) to wireformat) */

    uint16_t *r = NULL;
    uint32_t l;
    char *end; 

    /* Allocate required space... */
    r = xalloc(sizeof(uint16_t) + sizeof(uint32_t));

    l = htonl((uint32_t)strtottl((char *)periodstr, &end));

        if(*end != 0) {
            zerror("time period is expected");
            error++;
        } else {
            memcpy(r + 1, &l, sizeof(uint32_t));
            *r = sizeof(uint32_t);
        }
    return r;
}

uint16_t *
zparser_conv_short(const char *shortstr)
{
    /* convert a short INT to wire format */

    char *end;      /* Used to parse longs, ttls, etc.  */
    uint16_t *r = NULL;
   
    r = xalloc(sizeof(uint16_t) + sizeof(uint16_t));
    
    *(r+1)  = htons((uint16_t)strtol(shortstr, &end, 0));
            
    if(*end != 0) {
            zerror("unsigned short value is expected");
            error++;
    } else {
        *r = sizeof(uint16_t);
    }
    return r;
}

uint16_t *
zparser_conv_long(const char *longstr)
{
    char *end;      /* Used to parse longs, ttls, etc.  */
    uint16_t *r = NULL;
    uint32_t l;

    r = xalloc(sizeof(uint16_t) + sizeof(uint32_t));

    l = htonl((uint32_t)strtol(longstr, &end, 0));

    if(*end != 0) {
            zerror("long decimal value is expected");
            error++;
        } else {
            memcpy(r + 1, &l, sizeof(uint32_t));
            *r = sizeof(uint32_t);
    }
    return r;
}

uint16_t *
zparser_conv_byte(const char *bytestr)
{

    /* convert a byte value to wireformat */
   char *end;      /* Used to parse longs, ttls, etc.  */
   uint16_t *r = NULL;
 
        r = xalloc(sizeof(uint16_t) + sizeof(uint8_t));

        *((uint8_t *)(r+1)) = (uint8_t)strtol(bytestr, &end, 0);

        if(*end != 0) {
            zerror("decimal value is expected");
            error++;
        } else {
            *r = sizeof(uint8_t);
        }
    return r;
}

uint16_t *
zparser_conv_A(const char *a)
{
   
    /* convert a A rdata to wire format */
    struct in_addr pin;
    uint16_t *r = NULL;

    r = xalloc(sizeof(uint16_t) + sizeof(in_addr_t));

    if(inet_pton(AF_INET, a, &pin) > 0) {
        memcpy(r + 1, &pin.s_addr, sizeof(in_addr_t));
        *r = sizeof(uint32_t);
     } else {
            zerror("invalid ip address");
            fprintf(stderr, "IP: [%s]\n",a);
            error++;
     }
    return r;
}

uint16_t *
zparser_conv_dname(const uint8_t *dname)
{
    /* convert a domain name to wireformat */
    /* [XXX] dname, dnam were declared as the same thing
     * need to fix it */
    uint16_t *r = NULL;

    /* Allocate required space... */
    r = xalloc(sizeof(uint16_t) + *dname + 1);
    
    memcpy(r+1, dname, *dname + 1);
    
    *r = DNAME_MAGIC;
    return r;
}

uint16_t *
zparser_conv_text(const char *txt)
{
    /* convert text to wireformat */
    int i;
    uint16_t *r = NULL;

    if((i = strlen(txt)) > 255) {
            zerror("text string is longer than 255 charaters, try splitting in two");
            error++;
        } else {

            /* Allocate required space... */
            r = xalloc(sizeof(uint16_t) + i + 1);

            *((char *)(r+1))  = i;
            memcpy(((char *)(r+1)) + 1, txt, i);

            *r = i + 1;
        }
    return r;
}

uint16_t *
zparser_conv_a6(const char *a6)
{
    /* convert ip v6 address to wireformat */

    uint16_t *r = NULL;

    r = xalloc(sizeof(uint16_t) + IP6ADDRLEN);

        /* Try to convert it */
        if(inet_pton(AF_INET6, a6, r + 1) != 1) {
            zerror("invalid ipv6 address");
            error++;
        } else {
            *r = IP6ADDRLEN;
        }
        return r;
}

uint16_t *
zparser_conv_b64(const char *b64)
{
    /* convert b64 encoded stuff to wireformat */
    uint16_t *r = NULL;
    int i;

    r = xalloc(sizeof(uint16_t) + B64BUFSIZE);

        /* Try to convert it */
        if((i = b64_pton(b64, (uint8_t *) (r + 1), B64BUFSIZE)) == -1) {
            zerror("base64 encoding failed");
            error++;
        } else {
            *r = i;
            r = xrealloc(r, i + sizeof(uint16_t));
        }
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


/* 
 * Now some function that are used in zonec.y, but don't belong there 
 * 
 */

struct node_t * 
list_add(struct node_t *list, struct RR * rr)
{
    /* extend the current linked list with one new item */
    struct node_t *node;

    assert(list);
    assert(list->next == NULL);

    node = xalloc(sizeof(struct node_t));
    node->rr = NULL;
    node->next = NULL;

    /* fill it in */
    list->rr = xalloc(sizeof(struct RR));
    list->rr = rr;
    
    /* connect it */
    list->next = node;
    list = list->next;  /* jump one further */
    
    return list;
}

void
list_walk(struct node_t *list)
{
    /* walk the list from start, till end and 
     * print out some interesting stuff */

    struct node_t * cur = list;

    while (cur->next != NULL) {
        
        fprintf(stdout,"rr dname: %s\n",dnamestr(cur->rr->dname));
        fprintf(stdout,"rr ttl: %d\n",cur->rr->ttl);
        fprintf(stdout,"rr class: %d\n",cur->rr->class);
        fprintf(stdout,"rr type: %d\n",cur->rr->type);
        fprintf(stdout,"\trr rdata not printed\n");

        cur = cur->next;
    }
}

void
zreset_current_rr(struct zdefault_t *zdefault)
{
    /* generate a new, clean current_rr */

    current_rr = xalloc(sizeof(struct RR));
    current_rr->rdata = xalloc(sizeof(void *) * (MAXRDATALEN + 1));

    /* ok, to this here */
    zdefault->_rc = 0;
}

/* struct * RR current_rr is global, no 
 * need to pass it along */
void
zadd_rdata2(struct zdefault_t *zdefault, uint16_t *r)
{
    /* add this rdata to the current resource record */
    
    if(zdefault->_rc >= MAXRDATALEN - 1) {
        fprintf(stderr,"too many rdata elements");
        abort();
    }
    current_rr->rdata[zdefault->_rc++] = r;
}

void
zadd_rdata_finalize(struct zdefault_t *zdefault)
{
    /* finalize the RR, and move on the next */

    /* NULL signals the last rdata */

    /* _rc is already incremented in zadd_rdata2 */
    current_rr->rdata[zdefault->_rc] = NULL;
}

void
zadd_rtype(uint8_t *type)
{
    /* add the type to the current resource record */

    current_rr->type = intbyname(type, ztypes);
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
 * Compares two rdata arrrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */
int
zrdatacmp(uint16_t **a, uint16_t **b)
{
	/* Compare element by element */
	while(*a != NULL && *b != NULL) {
		/* Wrong size */
		if(**a != **b)
			return 1;
		/* Is it a domain name */
		if(**a == 0xffff) {
			if(memcmp(*a+1, *b+1, *((uint8_t *)(*a + 1))))
				return 1;
		} else {
			if(memcmp(*a+1, *b+1, **a))
				return 1;
		}
		a++; b++;
	}

	/* One is shorter than another */
	if((*a == NULL && *b != NULL) || (*b == NULL && *a != NULL)) {
		return 1;
	}

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
		switch(**endptr) {
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
/*void 
zerror (struct zdefault_t *z, const char *msg)
{
}
*/
void 
zerror (const char *msg)
{   
    fprintf(stderr, msg);
}

/*
 * Prints syntax error message and the file name and line number of the file
 * where it happened. Also increments the number of errors for the
 * particular file.
 *
 * Returns:
 *
 *	nothing
 */
void 
zsyntax (struct zdefault_t *z)
{
}

/*
 * Prints UEOL message and the file name and line number of the file
 * where it happened. Also increments the number of errors for the
 * particular file.
 *
 * Returns:
 *
 *	nothing
 */
void 
zunexpected (struct zdefault_t *z)
{
}

/*
 *
 * Initializes the parser and opens a zone file.
 *
 * Returns:
 *
 *	- pointer to the parser structure
 *	- NULL on error and errno set
 *
 */
struct zdefault_t *
nsd_zopen (const char *filename, uint32_t ttl, uint16_t class, const char *origin)
{

    char *end;

    /* Open the zone file... */
    /* [XXX] still need to handle recursion */
    if(( yyin  = fopen(filename, "r")) == NULL) {
        return NULL;
    }

    /* Open the network database */
    setprotoent(1);
    setservent(1);

    printf("getting the origin [%s]\n", origin);

    /* Initialize the rest of the structure */
    zdefault = xalloc( sizeof(struct zdefault_t));
    
    zdefault->prev_dname = xalloc(MAXDNAME);
    zdefault->ttl = DEFAULT_TTL;
    zdefault->class = 1;
    
    zdefault->origin = xalloc(MAXDNAME);
    zdefault->origin = (uint8_t *)strdname(origin, ROOT);  /* hmm [XXX] MG */
    zdefault->origin_len = 0;
    zdefault->prev_dname = '\0';
    zdefault->prev_dname_len = 0;

    zreset_current_rr(zdefault);
    printf("zp2.c: origin %s",dnamestr(zdefault->origin));

    rrlist = xalloc(sizeof(struct node_t));
    rrlist->next = NULL;
    root = rrlist;

    yyparse();

    error == 1 ? printf("\nparsing complete, with %d error\n",error) : \
            printf("\nparsing complete, with %d errors\n",error);

    return zdefault;
}

/*
 *
 * Closes a zone file and destroys  the parser.
 *
 * Returns:
 *
 *	Nothing
 *
 */
void
zclose (struct zdefault_t *z)
{
}

/*
 * Frees any allocated rdata.
 *
 * Returns
 *
 *	nothing
 *
 */
void
zrdatafree(uint16_t **p)
{
	int i;

	if(p) {
		for(i = 0; p[i] != NULL; i++) {
			free(p[i]);
		}
		free(p);
	}
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

/*
 * Standard usage function for testing puposes.
 *
 */
static void
usage (void)
{
	fprintf(stderr, "usage: zparser zone-file [origin]\n");
	exit(1);
}

/* create a dname, constructed like this
 * byte         byte        data       \000
 * total len    label len   label data  . (root)
 * total len = label(s) + label(s) len + \000
 */
const uint8_t *
creat_dname(const uint8_t *str, const size_t len)
{
    uint8_t *dname;

    dname = (uint8_t*)xalloc(len + 4);  /* 2 for length, 1 for root */

    dname[0] = (uint8_t) (len + 2); /* total length, label len + label data + root*/
    dname[1] = (uint8_t) len;       /* label length */

    memcpy( (dname+2), str, len);   /* insert label data */

    dname[len + 3] = '\0';

    return dname;
}

/* concatenate 2 dnames, both made with creat_dname
 * create a new dname, with on the first byte the
 * total length
 */
const uint8_t *
cat_dname(const uint8_t *left, const uint8_t *right)
{

    uint8_t *dname;
    size_t sleft, sright;

    /* extract the lengths from left and right */
    sleft = (size_t) left[0];
    sright= (size_t) right[0];

    dname = (uint8_t*)xalloc( sleft + sright + 1);
    dname[0] = (uint8_t) (sleft + sright - 1);  /* the new length */

    memcpy( dname+1, left + 1, sleft ); /* cp left, not the lenght byte */
    memcpy( dname + sleft , right + 1 , sright ); /* cp the whole of right, skip
                                                    length byte */

    dname[ sleft + sright] = '\0';
    
    return dname;
}


/* DEBUG function used to print out RRs */

/*
 * Prints a specific part of rdata.
 *
 * Returns:
 *
 *	nothing
 */
void
zprintrdata (FILE *f, int what, uint16_t *r)
{
	char buf[B64BUFSIZE];
	uint8_t *t;
	struct in_addr in;
	uint32_t l;


	/* Depending on what we have to scan... */
	switch(what) {
	case RDATA_HEX:
		if(*r == 0xffff) {
			for(t = (uint8_t *)(r + 1) + 1; t < (uint8_t *)(r + 1) + *((uint8_t *)(r + 1)) + 1; t++) {
				fprintf(f, "%.2x", *t);
			}
		} else {
			for(t = (uint8_t *)(r + 1); t < (uint8_t *)(r + 1) + *r; t++) {
				fprintf(f, "%.2x", *t);
			}
		}
		fprintf(f, " ");
		break;
	case RDATA_TIME:
		memcpy(&l, &r[1], sizeof(uint32_t));
		l = ntohl(l);
		strftime(buf, B64BUFSIZE, "%Y%m%d%H%M%S ", gmtime((time_t *)&l));
		fprintf(f, "%s", buf);
		break;
	case RDATA_TYPE:
		fprintf(f, "%s ", typebyint(ntohs(r[1])));
		break;
	case RDATA_PROTO:
	case RDATA_SERVICE:
	case RDATA_PERIOD:
	case RDATA_LONG:
		memcpy(&l, &r[1], sizeof(uint32_t));
		fprintf(f, "%lu ", (unsigned long) ntohl(l));
		break;
	case RDATA_SHORT:
		fprintf(f, "%u ", (unsigned) ntohs(r[1]));
		break;
	case RDATA_BYTE:
		fprintf(f, "%u ", (unsigned) *((char *)(&r[1])));
		break;
	case RDATA_A:
		
		memcpy(&in.s_addr, &r[1], sizeof(uint32_t));
		fprintf(f, "%s ", inet_ntoa(in));
		break;
	case RDATA_A6:
		fprintf(f, "%x:%x:%x:%x:%x:%x:%x:%x ", ntohs(r[1]), ntohs(r[2]), ntohs(r[3]),
			ntohs(r[4]), ntohs(r[5]), ntohs(r[6]), ntohs(r[7]), ntohs(r[8]));
		break;
	case RDATA_DNAME:
		fprintf(f, "%s ", dnamestr((uint8_t *)(&r[1])));
		break;
	case RDATA_TEXT:
		fprintf(f, "\"%s\"", ((char *)&r[1]) + 1);
		break;
	case RDATA_B64:
		b64_ntop((uint8_t *)(&r[1]), r[0], buf, B64BUFSIZE);
		fprintf(f, "%s ", buf);
		break;
	default:
		fprintf(f, "*** ERRROR *** ");
		abort();
	}
	return;
}

/*
 * Prints textual representation of the rdata into the file.
 *
 * Returns
 *
 *	nothing
 *
 */
void
zprintrrrdata(FILE *f, struct RR *rr)
{
	uint16_t **rdata;
	uint16_t size;

	switch(rr->type) {
	case TYPE_A:
		zprintrdata(f, RDATA_A, rr->rdata[0]);
		return;
	case TYPE_NS:
	case TYPE_MD:
	case TYPE_MF:
	case TYPE_CNAME:
	case TYPE_MB:
	case TYPE_MG:
	case TYPE_MR:
	case TYPE_PTR:
		zprintrdata(f, RDATA_DNAME, rr->rdata[0]);
		return;
	case TYPE_MINFO:
	case TYPE_RP:
		zprintrdata(f, RDATA_DNAME, rr->rdata[0]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[1]);
		return;
	case TYPE_TXT:
		for(rdata = rr->rdata; *rdata; rdata++) {
			zprintrdata(f, RDATA_TEXT, *rdata);
		}
		return;
	case TYPE_SOA:
		zprintrdata(f, RDATA_DNAME, rr->rdata[0]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[1]);
		zprintrdata(f, RDATA_PERIOD, rr->rdata[2]);
		zprintrdata(f, RDATA_PERIOD, rr->rdata[3]);
		zprintrdata(f, RDATA_PERIOD, rr->rdata[4]);
		zprintrdata(f, RDATA_PERIOD, rr->rdata[5]);
		zprintrdata(f, RDATA_PERIOD, rr->rdata[6]);
		return;
	case TYPE_HINFO:
		zprintrdata(f, RDATA_TEXT, rr->rdata[0]);
		zprintrdata(f, RDATA_TEXT, rr->rdata[1]);
		return;
	case TYPE_MX:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[1]);
		return;
	case TYPE_AAAA:
		zprintrdata(f, RDATA_A6, rr->rdata[0]);
		return;
	case TYPE_SRV:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_SHORT, rr->rdata[1]);
		zprintrdata(f, RDATA_SHORT, rr->rdata[2]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[3]);
		return;
	case TYPE_NAPTR:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_SHORT, rr->rdata[1]);
		zprintrdata(f, RDATA_TEXT, rr->rdata[2]);
		zprintrdata(f, RDATA_TEXT, rr->rdata[3]);
		zprintrdata(f, RDATA_TEXT, rr->rdata[4]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[5]);
		return;
	case TYPE_AFSDB:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[1]);
		return;
	case TYPE_SIG:
		zprintrdata(f, RDATA_TYPE, rr->rdata[0]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[1]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[2]);
		zprintrdata(f, RDATA_LONG, rr->rdata[3]);
		zprintrdata(f, RDATA_TIME, rr->rdata[4]);
		zprintrdata(f, RDATA_TIME, rr->rdata[5]);
		zprintrdata(f, RDATA_SHORT, rr->rdata[6]);
		zprintrdata(f, RDATA_DNAME, rr->rdata[7]);
		zprintrdata(f, RDATA_B64, rr->rdata[8]);
		return;
	case TYPE_NULL:
		return;
	case TYPE_KEY:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[1]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[2]);
		zprintrdata(f, RDATA_B64, rr->rdata[3]);
		return;
	case TYPE_DS:
		zprintrdata(f, RDATA_SHORT, rr->rdata[0]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[1]);
		zprintrdata(f, RDATA_BYTE, rr->rdata[2]);
		zprintrdata(f, RDATA_HEX, rr->rdata[3]);
		return;
	/* Unknown format */
	case TYPE_NXT:
	case TYPE_WKS:
	case TYPE_LOC:
	default:
		fprintf(f, "\\# ");
		for(size = 0, rdata = rr->rdata; *rdata; rdata++) {
			if(**rdata == 0xffff) {
				size += *((uint8_t *)(*rdata + 1));
			} else {
				size += **rdata;
			}
		}
		fprintf(f, "%u ", size);
		for(rdata = rr->rdata; *rdata; rdata++)
			zprintrdata(f, RDATA_HEX, *rdata);
		return;
	}
}

/*
 * Prints textual representation of the resource record to a file.
 *
 * Returns
 *
 *	nothing
 *
 */
void
zprintrr(FILE *f, struct RR *rr)
{
	fprintf(f, "%s\t%u\t%s\t%s\t", dnamestr(rr->dname), rr->ttl,
		classbyint(rr->class), typebyint(rr->type));
	if(rr->rdata != NULL) {
		zprintrrrdata(f, rr);
	} else {
		fprintf(f, "; *** NO RDATA ***");
	}
	fprintf(f, "\n");
}
