%{
/*
 * $Id: zyparser.y,v 1.22 2003/08/20 13:31:40 erik Exp $
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
#include "zonec2.h"
#include "zparser2.h"

/* these need to be  global, otherwise they cannot be used inside yacc */
unsigned int lineno;
struct zdefault_t * zdefault;
struct RR * current_rr;

/* [XXX] should be local */
unsigned int error = 0;
int progress = 10000;
int yydebug = 1;

%}
/* this list must be in exactly the same order as *RRtypes[] in zlparser.lex. 
 * The only changed are:
 * - NSAP-PRT is named NSAP_PTR
 * - NULL which is named YYNULL.
 */
/* RR types */
%token A NS MX TXT CNAME AAAA PTR NXT KEY SOA SIG SRV CERT LOC MD MF MB
%token MG MR YYNULL WKS HINFO MINFO RP AFSDB X25 ISDN RT NSAP NSAP_PTR PX GPOS 
%token EID NIMLOC ATMA NAPTR KX A6 DNAME SINK OPT APL UINFO UID GID 
%token UNSPEC TKEY TSIG IXFR AXFR MAILB MAILA

/* other tokens */
%token ORIGIN NL SP STR DIR_TTL DIR_ORIG PREV IN CH HS 

/* unknown RRs */
%token UN_RR UN_CLASS UN_TYPE

%%
lines:  /* empty line */
    |   lines line
    { if ( lineno % progress == 0 )
        printf("\nzonec: reading zone \"%s\": %d\n", zdefault->filename,
        lineno);
    }
    |    error      { yyerrok; }
    ;

line:   NL
    |   DIR_TTL dir_ttl
    |   DIR_ORIG dir_orig
    |   rr
    {   /* rr should be fully parsed */
        /*zprintrr(stderr, current_rr); DEBUG */
	    process_rr(current_rr);
	    current_rr->rdata = xalloc(sizeof(void *) * (MAXRDATALEN + 1));
	    zdefault->_rc = 0;
    }
    ;

dir_ttl:    SP STR NL
    { 
        if ($2.len > MAXDNAME ) {
            yyerror("TTL thingy too large");
            return 1;
        } 
        printf("\nttl-directive parsed: %s\n",  (char *) $2.str);
        /* perform TTL conversion */
        if ( ( zdefault->ttl = zparser_ttl2int($2.str)) == -1 )
            zdefault->ttl = DEFAULT_TTL;
    }
    ;

dir_orig:   SP dname NL
    {
        /* [xxx] does $origin not effect previous */
        if ( $2.len > MAXDNAME ) { 
            yyerror("origin thingy too large");
            return 1;
        } 
        zdefault->origin = (uint8_t *)dnamedup($2.str);
        zdefault->origin_len = $2.len;
    }
    ;

rr:     ORIGIN SP rrrest NL
    /* need to add reverse in here too */
    {
        /* starts with @, use the origin */
        current_rr->dname = (uint8_t *) dnamedup(zdefault->origin);

        /* also set this as the prev_dname */
        zdefault->prev_dname = zdefault->origin;
        zdefault->prev_dname_len = zdefault->origin_len; /* what about this len? */
    }
    |   PREV rrrest NL
    {
        /* a tab, use previously defined dname */
        /* [XXX] is null -> error, not checked (yet) MG */
        current_rr->dname = (uint8_t *) dnamedup(zdefault->prev_dname);
    }
    |   dname SP rrrest NL
    {
        current_rr->dname = $1.str;

        /* set this as previous */
        zdefault->prev_dname = dnamedup($1.str);
        zdefault->prev_dname_len = $1.len;
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
    ;

rrrest: classttl rtype 
    {
        /* terminate the rdata list - NULL does not have rdata */
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
    |   CH SP         { yyerror("chaos class not supported"); }
    |   HS SP         { yyerror("hesiod class not supported"); }
    |   ttl CH SP         { yyerror("chaos class not supported"); }
    |   ttl HS SP         { yyerror("hesiod class not supported"); }
    |   CH ttl SP         { yyerror("chaos class not supported"); }
    |   HS ttl SP         { yyerror("hesiod class not supported"); }
    ;

dname:  abs_dname
    {
        $$.str = $1.str;
        $$.len = $1.len;  /* length really not important anymore */
    }
    |   rel_dname
    {
        /* append origin */
        $$.str = (uint8_t *)cat_dname($1.str, zdefault->origin);
        $$.len = $1.len;
    }
    ;

abs_dname:  '.'
    {
            $$.str = (uint8_t *)dnamedup(ROOT);
            $$.len = 1;
    }
    |       rel_dname '.'
    {
            $$.str = cat_dname($1.str, ROOT);
            $$.len = $1.len;
    }
    ;

rel_dname:  STR
    {
        $$.str = create_dname($1.str, $1.len);
        $$.len = $1.len + 2; /* total length, label + len byte */
    }
    |       rel_dname '.' STR
    {  
        $$.str = cat_dname($1.str, create_dname($3.str,
						  $3.len));
        $$.len = $1.len + $3.len + 1;
    }
    ;

/* define what we can parse 
 * 19-08-2003: soa, a, ns, txt
 */

rtype:  SOA SP rdata_soa
    {   
        zadd_rtype("soa");
    }
    |   A SP rdata_a
    {
        zadd_rtype("a");
    }
    |   NS SP rdata_dname
    {
        zadd_rtype("ns");
    }
    |   CNAME SP rdata_dname
    {
        zadd_rtype("cname");
    }
    |   PTR SP rdata_dname
    {   
        zadd_rtype("ptr");
    }
    |   TXT SP rdata_txt
    {
        zadd_rtype("txt");
    }
    |   MX SP rdata_mx
    {
        zadd_rtype("mx");
    }
    |   AAAA SP rdata_aaaa
    {
        zadd_rtype("aaaa");
    }
    ;


/* 
 * below are all the definition for all the different rdata 
 */

rdata_soa:  dname SP dname SP STR STR STR STR STR
    {
        /* convert the soa data */
        zadd_rdata2( zdefault, zparser_conv_dname($1.str) );   /* prim. ns */
        zadd_rdata2( zdefault, zparser_conv_dname($3.str) );   /* email */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($5.str) ); /* serial */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($6.str) ); /* obscure item */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($7.str) ); /* obscure item */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($8.str) ); /* obscure item */
        zadd_rdata2( zdefault, zparser_conv_rdata_period($9.str) ); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (zdefault->minimum = zparser_ttl2int($9.str) ) == -1 )
            zdefault->minimum = DEFAULT_TTL;
        free($1.str);free($3.str);free($5.str);free($6.str);
        free($7.str);free($8.str);free($9.str);
    }
    ;

rdata_dname:   dname
    {
        /* convert a single dname record */
        zadd_rdata2( zdefault, zparser_conv_dname($1.str) ); /* domain name */
        free($1.str);
    }
    ;

rdata_a:    STR '.' STR '.' STR '.' STR
    {
        /* setup the string suitable for parsing */
	    char *ipv4 = xalloc($1.len + $3.len + $5.len + $7.len + 4);
        memcpy(ipv4, $1.str, $1.len);
        memcpy(ipv4 + $1.len , ".", 1);

        memcpy(ipv4 + $1.len + 1 , $3.str, $3.len);
        memcpy(ipv4 + $1.len + $3.len + 1, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + 2 , $5.str, $5.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + 2, ".", 1);

        memcpy(ipv4 + $1.len + $3.len + $5.len + 3 , $7.str, $7.len);
        memcpy(ipv4 + $1.len + $3.len + $5.len + $7.len + 3, "\0", 1);

        zadd_rdata2(zdefault, zparser_conv_A(ipv4));
        free($1.str);free($3.str);free($5.str);free($7.str);
        free(ipv4);
    }
    ;

rdata_txt:  STR
    {
        zadd_rdata2( zdefault, zparser_conv_text($1.str));
	free($1.str);
    }
    ;

rdata_mx:   STR SP dname
    {
        zadd_rdata2( zdefault, zparser_conv_short($1.str) );  /* priority */
        zadd_rdata2( zdefault, zparser_conv_dname($3.str) );  /* MX host */
        free($1.str);free($3.str);
    }
    ;

rdata_aaaa: STR
    {
        zadd_rdata2( zdefault, zparser_conv_a6($1.str) );  /* IPv6 address */
        free($1.str);
    }
    ;

%%

int
yywrap()
{
    return 1;
}

int
yyerror(char *s)
{
    fprintf(stderr,"\n[%d]error: %s: %s\n", lineno, s, (char *) yylval.str);
    if ( error++ > 50 ) {
        fprintf(stderr,"too many errors (50+)\n");
        exit(1);
    }
    return 0;
}
