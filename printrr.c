/*
 * printrr.c -- print RRs
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

#include "printrr.h"


/* print a entire zone */
int 
print_zone(zone_type *zone)
{

	/* TODO DOESN't WORK */
	zone_type *z;
	for ( z = zone; z != NULL ; z=z->next )
		print_rrset(z->domain->rrsets ,z->domain);

}

/* print a RR set */
int
print_rrset(rrset_type *rrset, domain_type *dom)
{
	/* print a RRset by calling print_rrdata for all the members */

	uint16_t i;
	uint32_t ttl;
	uint8_t *owner, *type;

	owner = (uint8_t *) dname_to_string( domain_dname(dom ));
	type = (uint8_t *)namebyint(rrset->type,ztypes);

	if ( type == NULL ) {
		type = (uint8_t *) malloc(10);
		sprintf(type, "TYPE%d", rrset->type);
	}

	for ( i = 0; i < rrset->rrslen; ++i ) {

		if ( rrset->type == TYPE_SOA ) {
			printf("%s\t%ld IN %s\t", owner,
					rrset->rrs[i]->ttl, type);
			print_rrdata( rrset->rrs[i] ,rrset->type);
			printf("\n");
			continue;
		}
		
		/* print each rr data element */
		if ( i == 0 || rrset->type == TYPE_RRSIG || rrset->type == TYPE_NSEC)
			printf("%s\t%ld %s\t", owner,
					rrset->rrs[i]->ttl, type);
		else
			printf("\t\t%ld %s\t",
					rrset->rrs[i]->ttl, type);

		print_rrdata( rrset->rrs[i] ,rrset->type);
	}
	printf("\n");
	return 0;
}


/* print a RR */
int
print_rr(rr_type *rr)
{
	uint32_t ttl;
	uint8_t *owner, *type;
	uint16_t *r;

	int i;	/* counter */
	char *j; /* unknown rr */
	
	owner	= (uint8_t*)dname_to_string( domain_dname(rr->domain) );
	ttl	= rr->rrdata->ttl;
	type	= (uint8_t *)namebyint(rr->type,ztypes);

	if ( type == NULL ) {
		/* no type found, must be unknown */
		type = (uint8_t *) malloc(10);
		/* should not exceed 5 digits */
		sprintf(type, "TYPE%d", rr->type);
	}
	
	printf("%s\t%ld IN %s\t", owner, ttl, type);

	print_rrdata(rr->rrdata	, rr->type);
	return 0;
}

int
print_rrdata(rrdata_type *rrdata, uint16_t type)
{
	/* print the RR data */
	uint8_t *typecovered;

        switch (type) {
		case TYPE_A:
			printf("%s",wire_conv_a(rrdata->rdata[0]));
			break;
		case TYPE_AAAA:
			printf("%s",wire_conv_aaaa(rrdata->rdata[0]));
			break;
		case TYPE_CNAME:
                case TYPE_NS:
			printf("%s",wire_conv_domain(rrdata->rdata[0]));
                        break;
		case TYPE_MX:
			printf("%d %s",wire_conv_short(rrdata->rdata[0]),
					wire_conv_domain(rrdata->rdata[1]));
			break;
		case TYPE_SOA:
			printf("%s %s %d %d %d %d %d",
				 	wire_conv_domain(rrdata->rdata[0]),
					wire_conv_domain(rrdata->rdata[1]),
					wire_conv_long(rrdata->rdata[2]),
					wire_conv_long(rrdata->rdata[3]),
					wire_conv_long(rrdata->rdata[4]),
					wire_conv_long(rrdata->rdata[5]),
					wire_conv_long(rrdata->rdata[6]));
			break;
		case TYPE_DNSKEY:
			printf("%d %d %d %s",
					wire_conv_short(rrdata->rdata[0]),
					wire_conv_byte(rrdata->rdata[1]),
					wire_conv_byte(rrdata->rdata[2]),
					wire_conv_b64(rrdata->rdata[3]));
			break;
		case TYPE_NSEC:
			printf("%s",
					wire_conv_labels(rrdata->rdata[0]));
			break;
		case TYPE_RRSIG:
			typecovered = (uint8_t *)namebyint(
					wire_conv_rrtype(rrdata->rdata[0]),ztypes);
			if ( typecovered == NULL ) {
				typecovered = (uint8_t *) malloc(10);
				sprintf(typecovered, "TYPE%d", 
						wire_conv_rrtype(rrdata->rdata[0]));
			}
	
			printf("%s %d %d %ld %s %s %d %s %s",
					typecovered,
					wire_conv_byte(rrdata->rdata[1]),
					wire_conv_byte(rrdata->rdata[2]),
					wire_conv_long(rrdata->rdata[3]),
					wire_conv_time(rrdata->rdata[4]),
					wire_conv_time(rrdata->rdata[5]),
					wire_conv_short(rrdata->rdata[6]),
					wire_conv_labels(rrdata->rdata[7]),
					wire_conv_b64(rrdata->rdata[8]));
			break;	
		case TYPE_DS:
			printf("%d %d %d %s",
					wire_conv_short(rrdata->rdata[0]),
					wire_conv_byte(rrdata->rdata[1]),
					wire_conv_byte(rrdata->rdata[2]),
					wire_conv_hex(rrdata->rdata[3]));
			break;		
		case TYPE_TXT:
			/* [XXX] need to loop */
			printf("%s",
					wire_conv_string(rrdata->rdata[0]));
			break;
		case TYPE_HINFO:
			printf("\"%s\" \"%s\"",
					wire_conv_string(rrdata->rdata[0]),
					wire_conv_string(rrdata->rdata[1]));
			break;
		default:
			/* print as hex */
			/* todo, looping */
			printf("\\# %d ",rdata_atom_size(rrdata->rdata[0]));
			/* todo print hex */
			printf("%s",wire_conv_hex(rrdata->rdata[0]));
        }

	printf("\n");

        return 0;
}

uint8_t *
wire_conv_domain(rdata_atom_type a)
{
	/* convert from wireformat to a printable owner name
	 * only works if  rdata_atom_is_domain() is true */

	uint8_t *r = malloc(rdata_atom_size(a) + 1 );

	strcpy(r, (uint8_t*)dname_to_string(domain_dname(rdata_atom_domain(a))));

	return r;
}

uint8_t *
wire_conv_labels(rdata_atom_type a)
{
	/* convert from wireformat to a printable owner name
	 * only works if rdata_atom_is_domain() is false */
	
	uint8_t *r;
	uint8_t *s,*o;
	unsigned int l;

	/* with dots? TODO */
	s = (uint8_t*) malloc(MAXDOMAINLEN + 1);

	o = s; /* remember for later */

	/* start of the labels */
	r = (uint8_t*)rdata_atom_data(a);

	while ( *r != 0 ) {

		/* copy */
		memcpy(s, (r+1), *r);
		/* insert . */
		*(s + *r) = '.';
		*(s + *r + 1) = '\0';

		s = s + 1 + *r;
		r = r + 1 + *r; /* move to next */

	}

	s    = o; /* rewind */

	return s;
}


uint8_t *
wire_conv_string(rdata_atom_type a)
{
	/* convert strings (TXT, HINFO), to printable string */

	uint8_t *r;

	r = (uint8_t*)rdata_atom_data(a);

	return r;
}

int
wire_conv_short(rdata_atom_type a)
{
	/* convert from wireformat to a short int */
	uint16_t *r;

	r = (uint16_t *)rdata_atom_data(a);

	return ( ntohs(*r) );
}

long int 
wire_conv_long(rdata_atom_type a)
{
	/* convert from wireformat to a long int */
	/* [XXX] not endian safe! */
	uint32_t *r;
	
	r = (uint32_t *)rdata_atom_data(a);

	return ( ntohl(*r) );
}

uint8_t *
wire_conv_a(rdata_atom_type a)
{
	/* convert from wireformat to a ip address */

	uint16_t *r;
	uint8_t  *dst;

	dst = malloc(INET_ADDRSTRLEN);

	r = (uint16_t *)rdata_atom_data(a);

	inet_ntop(AF_INET, r, dst, INET_ADDRSTRLEN);
	
	return dst;
}

uint8_t *
wire_conv_aaaa(rdata_atom_type a)
{
	/* convert from wire to AAAA */
	uint8_t *dst;
	uint16_t *r = NULL;

	dst = malloc(INET6_ADDRSTRLEN);

	r = (uint16_t *)rdata_atom_data(a);
	
        inet_ntop(AF_INET6, r, dst, INET6_ADDRSTRLEN);

	return dst;
}

uint8_t *
wire_conv_b64(rdata_atom_type a)
{
	/* convert wire to b64 string */

	uint8_t *buffer;
	uint16_t *r;
	int i = rdata_atom_size(a);

	r = (uint16_t *) rdata_atom_data(a);
	buffer = (uint8_t*) malloc(B64BUFSIZE);
	
	/*b64_ntop((uint8_t *) r, (size_t) i, char *target, size_t targsize); */
	b64_ntop( (uint8_t *)r, i, buffer, B64BUFSIZE);

	return buffer;
}

short int
wire_conv_byte(rdata_atom_type a)
{
	/* convert wire to byte value */
	
	return ( (short int) *( (uint8_t*)rdata_atom_data(a)));
}

uint8_t *
wire_conv_hex(rdata_atom_type a)
{
	/* convert wire to hex data */
	int len; int i,j,pos;
	char h[] = {'0','1','2','3','4','5','6','7','8','9',
		'A','B','C','D','E','F'};
	uint8_t *hex;
	uint8_t *p;

	/* per byte 2 hex numbers */
	len = rdata_atom_size(a);

	hex = (uint8_t *) malloc( len * 2 + 1);
	
	p   = (uint8_t*)rdata_atom_data(a);

	j = 0;
	for (i=0; i < len; ++i) {

		hex[j]   = h[*p >> 4];
		hex[++j] = h[*p & 0x0f];

		p++; ++j;
	}
	hex[++j] = '\0';
	return hex;
}

uint8_t *
wire_conv_time(rdata_atom_type a)
{
	/* convert wire timeformat to long */

        uint32_t *r;
        uint32_t l;
	const time_t * timep;
        struct tm *tm; 
	uint8_t *s;

	tm = (struct tm*) malloc(sizeof(struct tm));

	r = rdata_atom_data(a);

	l = ntohl(*r);
	timep = (time_t*)&l;

	gmtime_r( timep, tm );

	s = (uint8_t*)malloc(16);

	strftime(s, 15, "%Y%m%d%H%M%S" , tm);

        return s;
}

/* uint? */
uint16_t
wire_conv_rrtype(rdata_atom_type a)
{
	/* convert wire rrtype to int */

	uint16_t *r;

	r = rdata_atom_data(a);
	
	return (ntohs(*r));

}
