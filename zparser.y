%{
/*
 * zyparser.y -- yacc grammar for (DNS) zone files
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
	
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
	
#include "dname.h"
#include "namedb.h"
#include "zonec.h"

/* these need to be global, otherwise they cannot be used inside yacc */
zparser_type *parser;

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */
int yywrap(void);

/* this hold the nxt bits */
static uint8_t nxtbits[16];

/* 256 windows of 256 bits (32 bytes) */
/* still need to reset the bastard somewhere */
static uint8_t nsecbits[NSEC_WINDOW_COUNT][NSEC_WINDOW_BITS_SIZE];

int yyerror(const char *message);

%}
%union {
	domain_type      *domain;
	const dname_type *dname;
	struct lex_data   data;
	uint32_t          ttl;
	uint16_t          klass;
	uint16_t          type;
	uint16_t         *unknown;
}

/*
 * Tokens to represent the known RR types of DNS.
 */
%token <type> T_A T_NS T_MX T_TXT T_CNAME T_AAAA T_PTR T_NXT T_KEY T_SOA T_SIG
%token <type> T_SRV T_CERT T_LOC T_MD T_MF T_MB T_MG T_MR T_NULL T_WKS T_HINFO
%token <type> T_MINFO T_RP T_AFSDB T_X25 T_ISDN T_RT T_NSAP T_NSAP_PTR T_PX
%token <type> T_GPOS T_EID T_NIMLOC T_ATMA T_NAPTR T_KX T_A6 T_DNAME T_SINK
%token <type> T_OPT T_APL T_UINFO T_UID T_GID T_UNSPEC T_TKEY T_TSIG T_IXFR
%token <type> T_AXFR T_MAILB T_MAILA T_DS T_SSHFP T_RRSIG T_NSEC T_DNSKEY

/* other tokens */
%token         DIR_TTL DIR_ORIG NL ORIGIN SP RD_ORIGIN
%token <data>  STR PREV TTL BITLAB
%token <klass> T_IN T_CH T_HS

/* unknown RRs */
%token         URR
%token <type>  T_UTYPE

%type <type>    rtype
%type <domain>  dname abs_dname
%type <dname>   rel_dname label
%type <data>    str_seq concatenated_str_seq str_sp_seq str_dot_seq dotted_str
%type <data>    nxt_seq nsec_seq
%type <unknown> rdata_unknown

%%
lines:  /* empty file */
    |   lines line
    ;

line:   NL
    |   sp NL
    |   DIR_TTL dir_ttl
    |   DIR_ORIG dir_orig
    |   rr
    {   /* rr should be fully parsed */
	    if (!parser->error_occurred) {
		    if (!parser->current_zone
			&& parser->current_rr.type != TYPE_SOA)
		    {
			    zc_error("RR before SOA skipped");
		    } else {
			    parser->current_rr.rdatas
				    = (rdata_atom_type *) region_alloc_init(
					    parser->region,
					    parser->current_rr.rdatas,
					    parser->current_rr.rdata_count * sizeof(rdata_atom_type));

			    process_rr();
		    }
	    }

	    region_free_all(parser->rr_region);

	    parser->current_rr.type = 0;
	    parser->current_rr.rdata_count = 0;
	    parser->current_rr.rdatas = parser->temporary_rdatas;
	    parser->error_occurred = 0;
    }
    | error NL
    {
	    zc_error_prev_line("syntax error");
    }
    ;

/* needed to cope with ( and ) in arbitary places */
sp:		SP
  	|	sp SP
	;

trail:		NL
	|	sp NL
	;

dir_ttl:    SP STR trail
    { 
        if ($2.len > MAXDOMAINLEN ) {
            zc_error("$TTL value is too large");
            return 1;
        } 
        /* perform TTL conversion */
        if ( ( parser->default_ttl = zparser_ttl2int($2.str)) == -1 )
            parser->default_ttl = DEFAULT_TTL;
    }
    ;

dir_orig:   SP abs_dname trail
    {
        /* [xxx] does $origin not effect previous */
	/* [XXX] label length checks should be in dname functions */

	/* Copy from RR region to zone region.  */
        parser->origin = $2;
    }
    | SP rel_dname trail
    {
	    zc_error_prev_line("$ORIGIN directive requires absolute domain name");
    }
    ;

rr:     ORIGIN sp rrrest
    {
        parser->current_rr.owner = parser->origin;
        parser->prev_dname = parser->origin;
    }
    |   PREV rrrest
    {
        /* a tab, use previously defined dname */
        parser->current_rr.owner = parser->prev_dname;
        
    }
    |   dname sp rrrest
    {
	    /* Copy from RR region to zone region.  */
	    parser->current_rr.owner = $1;

	    /* set this as previous */
	    parser->prev_dname = parser->current_rr.owner;
    }
    ;

ttl:    TTL
    {
        /* set the ttl */
        if ( (parser->current_rr.ttl = 
	      zparser_ttl2int($1.str) ) == (uint32_t) -1) {
	            parser->current_rr.ttl = parser->default_ttl;
		    return 0;
	}
    }
    ;

in:     T_IN
    {
        /* set the class  (class unknown handled in lexer) */
        parser->current_rr.klass =  parser->default_class;
    }
    ;

rrrest: classttl rtype 
    {
	parser->current_rr.type = $2;
    }
    ;

class:  in
    |	T_CH  { zc_error("CHAOS class not supported"); }
    |	T_HS   { zc_error("HESIOD Class not supported"); }
    ;

classttl:   /* empty - fill in the default, def. ttl and IN class */
    {
        parser->current_rr.ttl = parser->default_ttl;
        parser->current_rr.klass = parser->default_class;
    }
    |   class sp         /* no ttl */
    {
        parser->current_rr.ttl = parser->default_ttl;
    }
    |	ttl sp		/* no class */
    {   
        parser->current_rr.klass = parser->default_class;
    }
    |   ttl sp class sp  /* the lot */
    |   class sp ttl sp  /* the lot - reversed */
    ;

dname:      abs_dname
    	|   rel_dname
    	{
		if ($1 == error_dname) {
			$$ = error_domain;
		} else if ($1->name_size + domain_dname(parser->origin)->name_size - 1 > MAXDOMAINLEN) {
			zc_error("domain name exceeds %d character limit", MAXDOMAINLEN);
			$$ = error_domain;
		} else {
			$$ = domain_table_insert(
				parser->db->domains, 
				dname_concatenate(
					parser->rr_region,
					$1,
					domain_dname(parser->origin)));
		}
    	}
    	;

abs_dname:  '.'
    {
	    $$ = parser->db->domains->root;
    }
    | 	    RD_ORIGIN
    {
	    $$ = parser->origin;
    }
    |       rel_dname '.'
    { 
	    if ($1 != error_dname) {
		    $$ = domain_table_insert(parser->db->domains, $1);
	    } else {
		    $$ = error_domain;
	    }
    }
    ;

label: STR
    {
	    if ($1.len > MAXLABELLEN) {
		    zc_error("label exceeds %d character limit", MAXLABELLEN);
		    $$ = error_dname;
	    } else {
		    $$ = dname_make_from_label(parser->rr_region,
					       (uint8_t *) $1.str,
					       $1.len);
	    }
    }
    | BITLAB 
    {
		zc_error("\\[%s]: bitlabels are unsupported. RFC2673 has status experimental.",
		$1.str);
		$$ = error_dname;
    }
    ;

rel_dname:  label
    |       rel_dname '.' label
    {
	    if ($1 == error_dname || $3 == error_dname) {
		    $$ = error_dname;
	    } else if ($1->name_size + $3->name_size - 1 > MAXDOMAINLEN) {
		    zc_error("domain name exceeds %d character limit",
			     MAXDOMAINLEN);
		    $$ = error_dname;
	    } else {
		    $$ = dname_concatenate(parser->rr_region, $1, $3);
	    }
    }
    ;

str_seq:	STR
    	{
        	zadd_rdata_wireformat(zparser_conv_text(parser->region, $1.str, $1.len));
    	}
    	|   	str_seq sp STR
    	{
        	zadd_rdata_wireformat(zparser_conv_text(parser->region, $3.str, $3.len));
    	}	
    	;

/* Generate a single string from multiple STR tokens, separated by spaces. */
concatenated_str_seq: STR
	| '.'
	{
		$$.len = 1;
		$$.str = region_strdup(parser->rr_region, ".");
	}
	| concatenated_str_seq sp STR
	{
		$$.len = $1.len + $3.len + 1;
		$$.str = (char *) region_alloc(parser->rr_region, $$.len + 1);
		memcpy($$.str, $1.str, $1.len);
		memcpy($$.str + $1.len, " ", 1);
		memcpy($$.str + $1.len + 1, $3.str, $3.len);
		$$.str[$$.len] = '\0';
	}
	| concatenated_str_seq '.' STR
	{
		$$.len = $1.len + $3.len + 1;
		$$.str = (char *) region_alloc(parser->rr_region, $$.len + 1);
		memcpy($$.str, $1.str, $1.len);
		memcpy($$.str + $1.len, ".", 1);
		memcpy($$.str + $1.len + 1, $3.str, $3.len);
		$$.str[$$.len] = '\0';
	}
	;

/* used to convert a nxt list of types */
nxt_seq:	STR
	{
		uint16_t type = lookup_type_by_name($1.str);
		if (type != 0 && type < 128) {
			set_bit(nxtbits, type);
		} else {
			zc_error("bad type %d in NXT record", (int) type);
		}
	}
	|	nxt_seq sp STR
	{
		uint16_t type = lookup_type_by_name($3.str);
		if (type != 0 && type < 128) {
			set_bit(nxtbits, type);
		} else {
			zc_error("bad type %d in NXT record", (int) type);
		}
	}
	;

nsec_seq:	STR
	{
		uint16_t type = lookup_type_by_name($1.str);
		if (type != 0) {
			set_bitnsec(nsecbits, type);
		} else {
			zc_error("bad type %d in NSEC record", (int) type);
		}
	}
	|	nsec_seq sp STR
	{
		uint16_t type = lookup_type_by_name($3.str);
		if (type != 0) {
			set_bitnsec(nsecbits, type);
		} else {
			zc_error("bad type %d in NSEC record", (int) type);
		}
	}
	;

/*
 * Sequence of STR tokens separated by spaces.  The spaces are not
 * preserved during concatenation.
 */
str_sp_seq:	STR
	|	str_sp_seq sp STR
	{
		char *result = (char *) region_alloc(parser->rr_region,
						     $1.len + $3.len + 1);
		memcpy(result, $1.str, $1.len);
		memcpy(result + $1.len, $3.str, $3.len);
		$$.str = result;
		$$.len = $1.len + $3.len;
		$$.str[$$.len] = '\0';
	}
	;

/*
 * Sequence of STR tokens separated by dots.  The dots are not
 * preserved during concatenation.
 */
str_dot_seq:	STR
	|	str_dot_seq '.' STR
        {
		char *result = (char *) region_alloc(parser->rr_region,
						     $1.len + $3.len + 1);
		memcpy(result, $1.str, $1.len);
		memcpy(result + $1.len, $3.str, $3.len);
		$$.str = result;
		$$.len = $1.len + $3.len;
		$$.str[$$.len] = '\0';
	}		
	;

/*
 * A string that can contain dots.
 */
dotted_str:	STR
	|	dotted_str '.' STR
        {
		char *result = (char *) region_alloc(parser->rr_region,
						     $1.len + $3.len + 2);
		memcpy(result, $1.str, $1.len);
		result[$1.len] = '.';
		memcpy(result + $1.len + 1, $3.str, $3.len);
		$$.str = result;
		$$.len = $1.len + $3.len + 1;
		$$.str[$$.len] = '\0';
	}		
	;

/* define what we can parse */
rtype:
    /*
     * All supported RR types.  We don't support NULL and types marked
     * obsolete.
     */
      T_A sp rdata_a 
    | T_A sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_NS sp rdata_domain_name 
    | T_NS sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_MD sp rdata_domain_name { zc_warning_prev_line("MD is obsolete"); }
    | T_MD sp rdata_unknown
    {
	    zc_warning_prev_line("MD is obsolete");
	    $$ = $1; parse_unknown_rdata($1, $3);
    }
    | T_MF sp rdata_domain_name { zc_warning_prev_line("MF is obsolete"); }
    | T_MF sp rdata_unknown
    {
	    zc_warning_prev_line("MF is obsolete");
	    $$ = $1;
	    parse_unknown_rdata($1, $3);
    }
    | T_CNAME sp rdata_domain_name 
    | T_CNAME sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_SOA sp rdata_soa 
    | T_SOA sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_MB sp rdata_domain_name { zc_warning_prev_line("MB is obsolete"); }
    | T_MB sp rdata_unknown
    {
	    zc_warning_prev_line("MB is obsolete");
	    $$ = $1;
	    parse_unknown_rdata($1, $3);
    }
    | T_MG sp rdata_domain_name
    | T_MG sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_MR sp rdata_domain_name
    | T_MR sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
      /* NULL */
    | T_WKS sp rdata_wks
    | T_WKS sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_PTR sp rdata_domain_name 
    | T_PTR sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_HINFO sp rdata_hinfo 
    | T_HINFO sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_MINFO sp rdata_minfo /* Experimental */
    | T_MINFO sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_MX sp rdata_mx 
    | T_MX sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_TXT sp rdata_txt
    | T_TXT sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_RP sp rdata_rp		/* RFC 1183 */
    | T_RP sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_AFSDB sp rdata_afsdb	/* RFC 1183 */
    | T_AFSDB sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_X25 sp rdata_x25 	/* RFC 1183 */
    | T_X25 sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_ISDN sp rdata_isdn 	/* RFC 1183 */
    | T_ISDN sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_RT sp rdata_rt		/* RFC 1183 */
    | T_RT sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_NSAP sp rdata_nsap	/* RFC 1706 */
    | T_NSAP sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_SIG sp rdata_rrsig	/* XXX: Compatible format? */
    | T_SIG sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_KEY sp rdata_dnskey	/* XXX: Compatible format? */
    | T_KEY sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_PX sp rdata_px		/* RFC 2163 */
    | T_PX sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_AAAA sp rdata_aaaa 
    | T_AAAA sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_LOC sp rdata_loc
    | T_LOC sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_NXT sp rdata_nxt
    | T_NXT sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_SRV sp rdata_srv
    | T_SRV sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_NAPTR sp rdata_naptr	/* RFC 2915 */
    | T_NAPTR sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_KX sp rdata_kx		/* RFC 2230 */
    | T_KX sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_CERT sp rdata_cert	/* RFC 2538 */
    | T_CERT sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_DNAME sp rdata_domain_name /* RFC 2672 */
    | T_DNAME sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_APL trail		/* RFC 3123 */
    | T_APL sp rdata_apl	/* RFC 3123 */
    | T_APL sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_DS sp rdata_ds
    | T_DS sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_SSHFP sp rdata_sshfp
    | T_SSHFP sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_RRSIG sp rdata_rrsig
    | T_RRSIG sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_NSEC sp rdata_nsec
    | T_NSEC sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_DNSKEY sp rdata_dnskey
    | T_DNSKEY sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | T_UTYPE sp rdata_unknown { $$ = $1; parse_unknown_rdata($1, $3); }
    | STR error NL
    {
	    zc_error_prev_line("Unrecognized RR type '%s'", $1.str);
    }
    ;

/* 
 *
 * below are all the definition for all the different rdata 
 *
 */

rdata_a:    dotted_str trail
	{
		zadd_rdata_wireformat(zparser_conv_a(parser->region, $1.str));
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in A record"); }
    ;

rdata_domain_name:   dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain($1);
    }
	|   error NL
	{ zc_error_prev_line("Syntax error in RDATA (domain name expected)"); }
    ;

rdata_soa:  dname sp dname sp STR sp STR sp STR sp STR sp STR trail
    {
        /* convert the soa data */
        zadd_rdata_domain($1);	/* prim. ns */
        zadd_rdata_domain($3);	/* email */
        zadd_rdata_wireformat(zparser_conv_period(parser->region, $5.str)); /* serial */
        zadd_rdata_wireformat(zparser_conv_period(parser->region, $7.str)); /* refresh */
        zadd_rdata_wireformat(zparser_conv_period(parser->region, $9.str)); /* retry */
        zadd_rdata_wireformat(zparser_conv_period(parser->region, $11.str)); /* expire */
        zadd_rdata_wireformat(zparser_conv_period(parser->region, $13.str)); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (parser->default_minimum = zparser_ttl2int($11.str) ) == -1 )
            parser->default_minimum = DEFAULT_TTL;
    }
	|   error NL
	{ zc_error_prev_line("Syntax error in SOA record"); }
    ;

rdata_wks:	dotted_str sp STR sp concatenated_str_seq trail
	{
        	zadd_rdata_wireformat(zparser_conv_a(parser->region, $1.str)); /* address */
		zadd_rdata_wireformat(zparser_conv_services(parser->region, $3.str, $5.str)); /* protocol and services */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in WKS record"); }
	;

rdata_hinfo:	STR sp STR trail
	{
        	zadd_rdata_wireformat(zparser_conv_text(parser->region, $1.str, $1.len)); /* CPU */
        	zadd_rdata_wireformat(zparser_conv_text(parser->region, $3.str, $3.len)); /* OS*/
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in HINFO record"); }
	;

rdata_minfo:   dname sp dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain($1);
        zadd_rdata_domain($3);
    }
    ;

rdata_mx:   STR sp dname trail
    	{
        	zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str));  /* priority */
        	zadd_rdata_domain($3);  /* MX host */
    	}
	|   error NL
	{ zc_error_prev_line("Syntax error in MX record"); }
    	;

rdata_txt: str_seq trail {}
	|   error NL
	{ zc_error_prev_line("Syntax error in TXT record"); }
	;

/* RFC 1183 */
rdata_rp:	dname sp dname trail
	{
		zadd_rdata_domain($1); /* mbox d-name */
		zadd_rdata_domain($3); /* txt d-name */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in RP record"); }
	;

/* RFC 1183 */
rdata_afsdb:   STR sp dname trail
       {
               zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* subtype */
               zadd_rdata_domain($3); /* domain name */
       }
	|   error NL
	{ zc_error_prev_line("Syntax error in AFSDB record"); }
       ;

/* RFC 1183 */
rdata_x25:	STR trail
	{
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $1.str, $1.len)); /* X.25 address. */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in X25 record"); }
	;

/* RFC 1183 */
rdata_isdn:	STR trail
	{
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $1.str, $1.len)); /* address */
	}
	| STR sp STR trail
	{
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $1.str, $1.len)); /* address */
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $3.str, $3.len)); /* sub-address */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in ISDN record"); }
	;

/* RFC 1183 */
rdata_rt:	STR sp dname trail
	{
               zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* preference */
               zadd_rdata_domain($3); /* intermediate host */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in RT record"); }
	;

/* RFC 1706 */
rdata_nsap:	str_dot_seq trail
	{
		/* String must start with "0x" or "0X".  */
		if (strncasecmp($1.str, "0x", 2) != 0) {
			zc_error_prev_line("NSAP rdata must start with '0x'");
		} else {
			zadd_rdata_wireformat(zparser_conv_hex(parser->region, $1.str + 2)); /* NSAP */
		}
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in DS record"); }
	;

/* RFC 2163 */
rdata_px:	STR sp dname sp dname trail
	{
               zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* preference */
	       zadd_rdata_domain($3); /* MAP822 */
	       zadd_rdata_domain($5); /* MAPX400 */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in PX record"); }
	;

rdata_aaaa: dotted_str trail
    	{
        	zadd_rdata_wireformat(zparser_conv_aaaa(parser->region, $1.str));  /* IPv6 address */
    	}
	|   error NL
	{ zc_error_prev_line("Syntax error in AAAA record"); }
    	;

rdata_loc: concatenated_str_seq trail
	{
		zadd_rdata_wireformat(zparser_conv_loc(parser->region, $1.str)); /* Location */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in LOC record"); }
	;

rdata_nxt:	dname sp nxt_seq trail
	{
		zadd_rdata_domain($1); /* nxt name */
		zadd_rdata_wireformat(zparser_conv_nxt(parser->region, nxtbits)); /* nxt bitlist */
		memset(nxtbits, 0, sizeof(nxtbits));
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in NXT record"); }
	;

rdata_srv:	STR sp STR sp STR sp dname trail
	{
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* prio */
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $3.str)); /* weight */
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $5.str)); /* port */
		zadd_rdata_domain($7); /* target name */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in SRV record"); }
	;

/* RFC 2915 */
rdata_naptr:	STR sp STR sp STR sp STR sp STR sp dname trail
	{
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* order */
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $3.str)); /* preference */
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $5.str, $5.len)); /* flags */
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $7.str, $7.len)); /* service */
		zadd_rdata_wireformat(zparser_conv_text(parser->region, $9.str, $9.len)); /* regexp */
		zadd_rdata_domain($11); /* target name */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in NAPTR record"); }
	;

/* RFC 2230 */
rdata_kx:	STR sp dname trail
	{
               zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* preference */
	       zadd_rdata_domain($3); /* exchanger */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in KX record"); }
	;

/* RFC 2538 */
rdata_cert:	STR sp STR sp STR sp str_sp_seq trail
	{
		zadd_rdata_wireformat(zparser_conv_certificate_type(parser->region, $1.str)); /* type */
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $3.str)); /* key tag */
		zadd_rdata_wireformat(zparser_conv_algorithm(parser->region, $5.str)); /* algorithm */
		zadd_rdata_wireformat(zparser_conv_b64(parser->region, $7.str)); /* certificate or CRL */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in CERT record"); }
	;

/* RFC 3123 */
rdata_apl: rdata_apl_seq trail
	| error NL
	{ zc_error_prev_line("Syntax error in APL record"); }
	;

rdata_apl_seq: dotted_str
	{
		zadd_rdata_wireformat(zparser_conv_apl_rdata(parser->region, $1.str));
	}
	| rdata_apl_seq sp dotted_str
	{
		zadd_rdata_wireformat(zparser_conv_apl_rdata(parser->region, $3.str));
	}
	;

rdata_ds:	STR sp STR sp STR sp str_sp_seq trail
	{
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* keytag */
		zadd_rdata_wireformat(zparser_conv_byte(parser->region, $3.str)); /* alg */
		zadd_rdata_wireformat(zparser_conv_byte(parser->region, $5.str)); /* type */
		zadd_rdata_wireformat(zparser_conv_hex(parser->region, $7.str)); /* hash */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in DS record"); }
	;

rdata_sshfp:   STR sp STR sp str_sp_seq trail
       {
               zadd_rdata_wireformat(zparser_conv_byte(parser->region, $1.str)); /* alg */
               zadd_rdata_wireformat(zparser_conv_byte(parser->region, $3.str)); /* fp type */
               zadd_rdata_wireformat(zparser_conv_hex(parser->region, $5.str)); /* hash */
       }
	|   error NL
	{ zc_error_prev_line("Syntax error in SSHFP record"); }
       ;

rdata_rrsig:	STR sp STR sp STR sp STR sp STR sp STR sp STR sp dname sp str_sp_seq trail
	{
		zadd_rdata_wireformat(zparser_conv_rrtype(parser->region, $1.str)); /* rr covered */
		zadd_rdata_wireformat(zparser_conv_byte(parser->region, $3.str)); /* alg */
		zadd_rdata_wireformat(zparser_conv_byte(parser->region, $5.str)); /* # labels */
		zadd_rdata_wireformat(zparser_conv_period(parser->region, $7.str)); /* # orig TTL */
		zadd_rdata_wireformat(zparser_conv_time(parser->region, $9.str)); /* sig exp */
		zadd_rdata_wireformat(zparser_conv_time(parser->region, $11.str)); /* sig inc */
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $13.str)); /* key id */
		zadd_rdata_domain($15); /* signer name */
		zadd_rdata_wireformat(zparser_conv_b64(parser->region, $17.str)); /* sig data */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in RRSIG record"); }
	;

rdata_nsec:	dname sp nsec_seq trail
	{
		zadd_rdata_domain($1); /* nsec name */
		zadd_rdata_wireformat(zparser_conv_nsec(parser->region, nsecbits)); /* nsec bitlist */
		memset(nsecbits, 0, sizeof(nsecbits));
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in NSEC record"); }
	;


rdata_dnskey:	STR sp STR sp STR sp str_sp_seq trail
	{
		zadd_rdata_wireformat(zparser_conv_short(parser->region, $1.str)); /* flags */
		zadd_rdata_wireformat(zparser_conv_byte(parser->region, $3.str)); /* proto */
		zadd_rdata_wireformat(zparser_conv_algorithm(parser->region, $5.str)); /* alg */
		zadd_rdata_wireformat(zparser_conv_b64(parser->region, $7.str)); /* hash */
	}
	|   error NL
	{ zc_error_prev_line("Syntax error in DNSKEY record"); }
	;

rdata_unknown:	URR sp STR sp str_sp_seq trail
	{
		/* $2 is the number of octects, currently ignored */
		$$ = zparser_conv_hex(parser->region, $5.str);

	}
	| URR sp STR trail
	{	
		$$ = zparser_conv_hex(parser->region, "");
	}
	| URR error NL
        {
		zc_error_prev_line("Syntax error in UNKNOWN RR rdata");
		$$ = zparser_conv_hex(parser->region, "");
	}
        ;
%%

int
yywrap(void)
{
    return 1;
}

/*
 * Create the parser.
 */
zparser_type *
zparser_create(region_type *region, region_type *rr_region, namedb_type *db)
{
	zparser_type *result;
	
	result = (zparser_type *) region_alloc(region, sizeof(zparser_type));
	result->region = region;
	result->rr_region = rr_region;
	result->db = db;
	
	result->temporary_rdatas = (rdata_atom_type *) region_alloc(
		result->region, MAXRDATALEN * sizeof(rdata_atom_type));
	
	return result;
}

/*
 * Initialize the parser for a new zone file.
 */
void
zparser_init(const char *filename, uint32_t ttl, uint16_t klass,
	     const dname_type *origin)
{
	memset(nxtbits, 0, sizeof(nxtbits));
	memset(nsecbits, 0, sizeof(nsecbits));

	parser->default_ttl = ttl;
	parser->default_minimum = 0;
	parser->default_class = klass;
	parser->current_zone = NULL;
	parser->origin = domain_table_insert(parser->db->domains, origin); 
	parser->prev_dname = parser->origin;
	parser->error_occurred = 0;
	parser->errors = 0;
	parser->line = 1;
	parser->filename = filename;
	parser->current_rr.rdata_count = 0;
	parser->current_rr.rdatas = parser->temporary_rdatas;
}

int
yyerror(const char *ATTR_UNUSED(message))
{
	/* don't do anything with this */
	return 0;
}

static void
error_va_list(unsigned line, const char *fmt, va_list args)
{
	fprintf(stderr, " ERR: Line %u in %s: ", line,
		parser->filename);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
	++parser->errors;
	parser->error_occurred = 1;
}

/* the line counting sux, to say the least 
 * with this grose hack we try do give sane
 * numbers back */
void
zc_error_prev_line(const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	error_va_list(parser->line - 1, fmt, args);
	va_end(args);
}

void
zc_error(const char *fmt, ...)
{
	/* send an error message to stderr */
	va_list args;
	va_start(args, fmt);
	error_va_list(parser->line, fmt, args);
	va_end(args);
}

static void
warning_va_list(unsigned line, const char *fmt, va_list args)
{
	fprintf(stderr, "WARN: Line %u in %s: ", line,
		parser->filename);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

void
zc_warning_prev_line(const char *fmt, ...) 
{
	va_list args;
	va_start(args, fmt);
	warning_va_list(parser->line - 1, fmt, args);
	va_end(args);
}

void 
zc_warning(const char *fmt, ... )
{
	va_list args;
	va_start(args, fmt);
	warning_va_list(parser->line, fmt, args);
	va_end(args);
}
