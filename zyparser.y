%{
/*
 * $Id: zyparser.y,v 1.38 2003/10/17 13:51:31 erik Exp $
 *
 * zyparser.y -- yacc grammar for (DNS) zone files
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license
 */

#include <config.h>
	
#include <stdio.h>
#include <string.h>

#include "dname.h"
#include "namedb.h"
#include "zonec2.h"
#include "zparser2.h"

/* these need to be global, otherwise they cannot be used inside yacc */
struct zdefault_t * zdefault;
rr_type *current_rr;

/* [XXX] should be local? */
int progress = 10000;

int yywrap(void);

static rdata_atom_type temporary_rdata[MAXRDATALEN + 1];

%}
/* this list must be in exactly the same order as *RRtypes[] in zlparser.lex. 
 * The only changed are:
 * - NSAP-PRT is named NSAP_PTR
 * - NULL which is named YYNULL.
 */
/* RR types */

%union {
	domain_type      *domain;
	const dname_type *dname;
	struct lex_data   data;
	uint32_t          ttl;
	uint16_t          class;
	uint16_t          type;
}

%token <type> A NS MX TXT CNAME AAAA PTR NXT KEY SOA SIG SRV CERT LOC MD MF MB
%token <type> MG MR YYNULL WKS HINFO MINFO RP AFSDB X25 ISDN RT NSAP NSAP_PTR PX GPOS 
%token <type> EID NIMLOC ATMA NAPTR KX A6 DNAME SINK OPT APL UINFO UID GID 
%token <type> UNSPEC TKEY TSIG IXFR AXFR MAILB MAILA

/* other tokens */
%token         DIR_TTL DIR_ORIG NL ORIGIN SP
%token <data>  STR PREV
%token <class> IN CH HS

/* unknown RRs */
%token         UN_RR
%token <class> UN_CLASS
%token <type>  UN_TYPE

%type <domain> owner_dname nonowner_dname
%type <dname>  dname abs_dname rel_dname
%type <data>   hex

%%
lines:  /* empty line */
    |   lines line
    { if ( zdefault->line % progress == 0 )
        printf("\nzonec: reading zone \"%s\": %lu\n", zdefault->filename,
	       (unsigned long) zdefault->line);
    }
    |    error      { yyerrok; }
    ;

line:   NL
    |   DIR_TTL dir_ttl
    |   DIR_ORIG dir_orig
    |   rr
    {   /* rr should be fully parsed */
        /*zprintrr(stderr, current_rr); DEBUG */
	    current_rr->rdata = region_alloc_init(
		    zone_region,
		    current_rr->rdata,
		    sizeof(rdata_atom_type) * (zdefault->_rc + 1));

	    process_rr(zdefault->zone, current_rr);

	    region_free_all(rr_region);
	    
	    current_rr->rdata = temporary_rdata;
	    zdefault->_rc = 0;
    }
    ;

dir_ttl:    SP STR NL
    { 
        if ($2.len > MAXDOMAINLEN ) {
            yyerror("$TTL value is too large");
            return 1;
        } 
        /* perform TTL conversion */
        if ( ( zdefault->ttl = zparser_ttl2int($2.str)) == -1 )
            zdefault->ttl = DEFAULT_TTL;
    }
    ;

dir_orig:   SP nonowner_dname NL
    {
        /* [xxx] does $origin not effect previous */
        if ( $2->dname->name_size > MAXDOMAINLEN ) { 
            yyerror("$ORIGIN domain name is too large");
            return 1;
        }

	/* Copy from RR region to zone region.  */
        zdefault->origin = $2;
    }
    ;

rr:     ORIGIN SP rrrest NL
    {
        /* starts with @, use the origin */
        current_rr->domain = zdefault->origin;

        /* also set this as the prev_dname */
        zdefault->prev_dname = zdefault->origin;
    }
    |   PREV rrrest NL
    {
        /* a tab, use previously defined dname */
        /* [XXX] is null -> error, not checked (yet) MG */
        current_rr->domain = zdefault->prev_dname;
        
    }
    |   owner_dname SP rrrest NL
    {
	    /* Copy from RR region to zone region.  */
	    current_rr->domain = $1;

	    /* set this as previous */
	    zdefault->prev_dname = current_rr->domain;
    }
    ;

/* A domain name used as the owner of an RR.  */
owner_dname: dname
	{
		$$ = domain_table_insert(zdefault->zone->db->domains, $1);
	}
	;

/* A domain name used in rdata or in an origin directive.  */
nonowner_dname: dname
	{
		$$ = domain_table_insert(zdefault->zone->db->domains, $1);
	}
	;

ttl:    STR
    {
        /* set the ttl */
        if ( (current_rr->ttl = zparser_ttl2int($1.str) ) == -1 )
            current_rr->ttl = DEFAULT_TTL;
    }
    ;

in:     IN
    {
        /* set the class */
        current_rr->class =  zdefault->class;
    }
    |   UN_CLASS
    {
	    /* unknown RR seen */
	    current_rr->class = $1;
    }
    ;

rrrest: classttl rtype 
    {
        /* Terminate the rdata list.  */
        zadd_rdata_finalize(zdefault);
    }
    ;

classttl:   /* empty - fill in the default, def. ttl and IN class */
    {
        current_rr->ttl = zdefault->ttl;
        current_rr->class = zdefault->class;
    }
    |   in SP         /* no ttl */
    {
        current_rr->ttl = zdefault->ttl;
    }
    |   ttl SP in SP  /* the lot */
    |   in SP ttl SP  /* the lot - reversed */
    |   ttl SP        /* no class */
    {   
        current_rr->class = zdefault->class;
    }
    |   CH SP         { yyerror("CHAOS class not supported"); }
    |   HS SP         { yyerror("HESIOD Class not supported"); }
    |   ttl SP CH SP         { yyerror("CHAOS class not supported"); }
    |   ttl SP HS SP         { yyerror("HESIOD class not supported"); }
    |   CH SP ttl SP         { yyerror("CHAOS class not supported"); }
    |   HS SP ttl SP         { yyerror("HESIOD class not supported"); }
    ;

dname:  abs_dname
    |   rel_dname
    {
        /* append origin */
        $$ = cat_dname(rr_region, $1, zdefault->origin->dname);
    }
    ;

abs_dname:  '.'
    {
            $$ = dname_make(rr_region, (const uint8_t *) "");
    }
    |       rel_dname '.'
    {
            $$ = $1;
    }
    ;

rel_dname:  STR
    {
        $$ = create_dname(rr_region, $1.str, $1.len);
    }
    |       rel_dname '.' STR
    {  
        $$ = cat_dname(rr_region, $1,
		       create_dname(rr_region, $3.str, $3.len));
    }
    ;

hex:	STR
    {
	$$.str = $1.str;
	$$.len = $1.len;
    }
    |	SP			/* ??? what to return? */
    {   $$.str = NULL; $$.len = 0; }
    |	hex STR
    {
	char *hexstr = region_alloc(rr_region, $1.len + $2.len + 1);
    	memcpy(hexstr, $1.str, $1.len);
	memcpy(hexstr + $1.len + 1, $2.str, $2.len);

	$$.str = hexstr;
	$$.len = $1.len + $2.len;
    }
    |   hex SP
    {
	/* discard SP */
	$$.str = $1.str;
	$$.len = $1.len;
    }
    ;

/* define what we can parse */

rtype:  SOA SP rdata_soa
    {
	    current_rr->type = $1;
    }
    |	SOA SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   A SP rdata_a
    {
	    current_rr->type = $1;
    }
    |	A SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   NS SP rdata_dname
    {
	    current_rr->type = $1;
    }
    |	NS SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   CNAME SP rdata_dname
    {
	    current_rr->type = $1;
    }
    |   CNAME SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   PTR SP rdata_dname
    {   
	    current_rr->type = $1;
    }
    |	PTR SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   TXT SP rdata_txt
    {
	    current_rr->type = $1;
    }
    |	TXT SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   MX SP rdata_mx
    {
	    current_rr->type = $1;
    }
    |   MX SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   AAAA SP rdata_aaaa
    {
	    current_rr->type = $1;
    }
    |	AAAA SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |	HINFO SP rdata_hinfo
    {
	    current_rr->type = $1;
    }
    |	HINFO SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |   SRV SP rdata_srv
    {
	    current_rr->type = $1;
    }
    |	SRV SP UN_RR SP rdata_unknown
    {
	    current_rr->type = $1;
    }
    |	UN_TYPE SP UN_RR SP rdata_unknown
    {
	/* try to add the unknown type */
	current_rr->type = $1;
    }
    |	error NL
    {	
	    fprintf(stderr,"Unimplemented RR seen\n");
    }
    ;


/* 
 * below are all the definition for all the different rdata 
 */

rdata_unknown: STR SP hex
    {
	/* check_hexlen($1.str, $2.str); */
	zadd_rdata_wireformat( zdefault, zparser_conv_hex(zone_region, $3.str) );
    }
    ;

rdata_soa:  nonowner_dname SP nonowner_dname SP STR STR STR STR STR
    {
        /* convert the soa data */
        zadd_rdata_domain( zdefault, $1);                                     /* prim. ns */
        zadd_rdata_domain( zdefault, $3);                                     /* email */
        zadd_rdata_wireformat( zdefault, zparser_conv_rdata_period(zone_region, $5.str) ); /* serial */
        zadd_rdata_wireformat( zdefault, zparser_conv_rdata_period(zone_region, $6.str) ); /* refresh */
        zadd_rdata_wireformat( zdefault, zparser_conv_rdata_period(zone_region, $7.str) ); /* retry */
        zadd_rdata_wireformat( zdefault, zparser_conv_rdata_period(zone_region, $8.str) ); /* expire */
        zadd_rdata_wireformat( zdefault, zparser_conv_rdata_period(zone_region, $9.str) ); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (zdefault->minimum = zparser_ttl2int($9.str) ) == -1 )
            zdefault->minimum = DEFAULT_TTL;
    }
    ;

rdata_dname:   nonowner_dname
    {
        /* convert a single dname record */
        zadd_rdata_domain(zdefault, $1);
    }
    ;

rdata_a:    STR '.' STR '.' STR '.' STR
    {
        /* setup the string suitable for parsing */
	    char *ipv4 = region_alloc(rr_region, $1.len + $3.len + $5.len + $7.len + 4);
        memcpy(ipv4, $1.str, $1.len);
        memcpy(ipv4 + $1.len , ".", 1);

        memcpy(ipv4 + $1.len + 1 , $3.str, $3.len);
        memcpy(ipv4 + $1.len + $3.len + 1, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + 2 , $5.str, $5.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + 2, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + $5.len + 3 , $7.str, $7.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + $7.len + 3, "\0", 1);

        zadd_rdata_wireformat(zdefault, zparser_conv_a(zone_region, ipv4));
    }
    ;

rdata_txt:  STR 
    {
        zadd_rdata_wireformat( zdefault, zparser_conv_text(zone_region, $1.str));
    }
    |   rdata_txt SP STR
    {
        zadd_rdata_wireformat( zdefault, zparser_conv_text(zone_region, $3.str));
    }
    ;

rdata_mx:   STR SP nonowner_dname
    {
        zadd_rdata_wireformat( zdefault, zparser_conv_short(zone_region, $1.str) );  /* priority */
        zadd_rdata_domain( zdefault, $3);  /* MX host */
    }
    ;

rdata_aaaa: STR
    {
        zadd_rdata_wireformat( zdefault, zparser_conv_a6(zone_region, $1.str) );  /* IPv6 address */
    }
    ;

rdata_hinfo:	STR SP STR
	{
        	zadd_rdata_wireformat( zdefault, zparser_conv_text(zone_region, $1.str) ); /* CPU */
        	zadd_rdata_wireformat( zdefault, zparser_conv_text(zone_region, $3.str) );  /* OS*/
	}
	;

rdata_srv:	STR SP STR SP STR SP nonowner_dname
	{
		zadd_rdata_wireformat(zdefault, zparser_conv_short(zone_region, $1.str)); /* prio */
		zadd_rdata_wireformat(zdefault, zparser_conv_short(zone_region, $3.str)); /* weight */
		zadd_rdata_wireformat(zdefault, zparser_conv_short(zone_region, $5.str)); /* port */
		zadd_rdata_wireformat(zdefault, zparser_conv_domain(zone_region, $7)); /* target name */
	}
	;
%%

int
yywrap(void)
{
    return 1;
}

/* print an error. S has the message. zdefault is global so just access it */
int
yyerror(const char *s)
{
    fprintf(stderr,"error: %s in %s, line %lu\n",s, zdefault->filename,
    (unsigned long) zdefault->line);
    zdefault->errors++;
    /*if ( zdefault->errors++ > 50 ) {
        fprintf(stderr,"too many errors (50+)\n");
        exit(1);
    }*/
    return 0;
}
