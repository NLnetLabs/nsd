%{
/*
 * zyparser.y -- yacc grammar for (DNS) zone files
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license
 */

#include <config.h>
	
#include <stdio.h>
#include <string.h>

#include "dname.h"
#include "namedb.h"
#include "zonec.h"

/* these need to be global, otherwise they cannot be used inside yacc */
zparser_type *current_parser;
rr_type *current_rr;

int yywrap(void);

rrdata_type *temporary_rrdata = NULL;

/* this hold the nxt bits */
uint8_t nxtbits[16] = { '\0','\0','\0','\0',
	 		'\0','\0','\0','\0',
			'\0','\0','\0','\0',
			'\0','\0','\0','\0' };
/* 256 windows of 256 bits (32 bytes) */
/* still need to reset the bastard somewhere */
uint8_t nsecbits[256][32];

%}
%union {
	domain_type      *domain;
	const dname_type *dname;
	struct lex_data   data;
	uint32_t          ttl;
	uint16_t          class;
	uint16_t          type;
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
%token         DIR_TTL DIR_ORIG NL ORIGIN SP
%token <data>  STR PREV TTL
%token <class> T_IN T_CH T_HS

/* unknown RRs */
%token         URR
%token <type>  T_UTYPE

%type <type>   rtype
%type <domain> dname abs_dname
%type <dname>  rel_dname label
%type <data>   str_seq concatenated_str_seq str_sp_seq str_dot_seq dotted_str
%type <data>   nxt_seq nsec_seq

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
	    if (!error_occurred) {
		    if (!current_parser->current_zone && current_rr->type != TYPE_SOA) {
			    error("RR before SOA skipped");
		    } else {
			    current_rr->zone = current_parser->current_zone;
			    current_rr->rrdata = region_alloc_init(
				    zone_region,
				    current_rr->rrdata,
				    rrdata_size(current_parser->_rc));
			    
			    process_rr(current_parser, current_rr);
		    }
	    }

	    region_free_all(rr_region);

	    current_rr->type = 0;
	    current_rr->rrdata = temporary_rrdata;
	    current_parser->_rc = 0;
	    error_occurred = 0;
    }
    | error NL
    {
	    error_prev_line("syntax error");
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
            error("$TTL value is too large");
            return 1;
        } 
        /* perform TTL conversion */
        if ( ( current_parser->ttl = zparser_ttl2int($2.str)) == -1 )
            current_parser->ttl = DEFAULT_TTL;
    }
    ;

dir_orig:   SP abs_dname trail
    {
        /* [xxx] does $origin not effect previous */
	/* [XXX] label length checks should be in dname functions */

	/* Copy from RR region to zone region.  */
        current_parser->origin = $2;
    }
    | SP rel_dname trail
    {
	    error_prev_line("$ORIGIN directive requires absolute domain name");
    }
    ;

rr:     ORIGIN sp rrrest
    {
        current_rr->domain = current_parser->origin;

        current_parser->prev_dname = current_parser->origin;
    }
    |   PREV rrrest
    {
        /* a tab, use previously defined dname */
        current_rr->domain = current_parser->prev_dname;
        
    }
    |   dname sp rrrest
    {
	    /* Copy from RR region to zone region.  */
	    current_rr->domain = $1;

	    /* set this as previous */
	    current_parser->prev_dname = current_rr->domain;
    }
    ;

ttl:    TTL
    {
        /* set the ttl */
        if ( (current_rr->rrdata->ttl = 
		zparser_ttl2int($1.str) ) == -1) {
	            current_rr->rrdata->ttl = current_parser->ttl;
		    return 0;
	}
    }
    ;

in:     T_IN
    {
        /* set the class  (class unknown handled in lexer) */
        current_rr->class =  current_parser->class;
    }
    ;

rrrest: classttl rtype 
    {
        zadd_rdata_finalize(current_parser);
	current_rr->type = $2;
    }
    ;

class:  in
    |	T_CH  { error("CHAOS class not supported"); }
    |	T_HS   { error("HESIOD Class not supported"); }
    ;

classttl:   /* empty - fill in the default, def. ttl and IN class */
    {
        current_rr->rrdata->ttl = current_parser->ttl;
        current_rr->class = current_parser->class;
    }
    |   class sp         /* no ttl */
    {
        current_rr->rrdata->ttl = current_parser->ttl;
    }
    |	ttl sp		/* no class */
    {   
        current_rr->class = current_parser->class;
    }
    |   ttl sp class sp  /* the lot */
    |   class sp ttl sp  /* the lot - reversed */
    ;

dname:      abs_dname
    	|   rel_dname
    	{
		if ($1 == error_dname) {
			$$ = error_domain;
		} else if ($1->name_size + domain_dname(current_parser->origin)->name_size - 1 > MAXDOMAINLEN) {
			error("domain name exceeds %d character limit", MAXDOMAINLEN);
			$$ = error_domain;
		} else {
			$$ = domain_table_insert(
				current_parser->db->domains, 
				cat_dname(rr_region, $1, domain_dname(current_parser->origin)));
		}
    	}
    	;

abs_dname:  '.'
    {
	    $$ = current_parser->db->domains->root;
    }
    |       rel_dname '.'
    { 
	    if ($1 != error_dname) {
		    $$ = domain_table_insert(current_parser->db->domains, $1);
	    } else {
		    $$ = error_domain;
	    }
    }
    ;

label: STR
    {
	    if ($1.len > MAXLABELLEN) {
		    error("label exceeds %d character limit", MAXLABELLEN);
		    $$ = error_dname;
	    } else {
		    $$ = create_dname(rr_region, (uint8_t *) $1.str, $1.len);
	    }
    }
    ;

rel_dname:  label
    |       rel_dname '.' label
    {
	    if ($1 == error_dname || $3 == error_dname) {
		    $$ = error_dname;
	    } else if ($1->name_size + $3->name_size - 1 > MAXDOMAINLEN) {
		    error("domain name exceeds %d character limit", MAXDOMAINLEN);
		    $$ = error_dname;
	    } else {
		    $$ = cat_dname(rr_region, $1, $3);
	    }
    }
    ;

str_seq:	STR
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $1.str));
    	}
    	|   	str_seq sp STR
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $3.str));
    	}	
    	;

/* Generate a single string from multiple STR tokens, separated by spaces. */
concatenated_str_seq: STR
	| '.'
	{
		$$.len = 1;
		$$.str = region_strdup(rr_region, ".");
	}
	| concatenated_str_seq sp STR
	{
		$$.len = $1.len + $3.len + 1;
		$$.str = region_alloc(rr_region, $$.len + 1);
		memcpy($$.str, $1.str, $1.len);
		memcpy($$.str + $1.len, " ", 1);
		memcpy($$.str + $1.len + 1, $3.str, $3.len);
		$$.str[$$.len] = '\0';
	}
	| concatenated_str_seq '.' STR
	{
		$$.len = $1.len + $3.len + 1;
		$$.str = region_alloc(rr_region, $$.len + 1);
		memcpy($$.str, $1.str, $1.len);
		memcpy($$.str + $1.len, ".", 1);
		memcpy($$.str + $1.len + 1, $3.str, $3.len);
		$$.str[$$.len] = '\0';
	}
	;

/* used to convert a nxt list of types */
/* XXX goes wrong now */
/* get the type and flip a bit */
nxt_seq:	STR
	{
		uint16_t type = lookup_type_by_name($1.str);
		if (type != 0 && type < 128) {
			set_bit(nxtbits, type);
		} else {
			error("bad type %d in NXT record", (int) type);
		}
	}
	|	nxt_seq sp STR
	{
		uint16_t type = lookup_type_by_name($3.str);
		if (type != 0 && type < 128) {
			set_bit(nxtbits, type);
		} else {
			error("bad type %d in NXT record", (int) type);
		}
	}
	;

nsec_seq:	STR
	{
		uint16_t type = lookup_type_by_name($1.str);
		if (type != 0) {
			set_bitnsec(nsecbits, type);
		} else {
			error("bad type %d in NSEC record", (int) type);
		}
	}
	|	nsec_seq sp STR
	{
		uint16_t type = lookup_type_by_name($3.str);
		if (type != 0) {
			set_bitnsec(nsecbits, type);
		} else {
			error("bad type %d in NSEC record", (int) type);
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
		char *result = region_alloc(rr_region, $1.len + $3.len + 1);
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
		char *result = region_alloc(rr_region, $1.len + $3.len + 1);
		memcpy(result, $1.str, $1.len);
		memcpy(result + $1.len, $3.str, $3.len);
		$$.str = result;
		$$.len = $1.len + $3.len;
		$$.str[$$.len] = '\0';
	}		

/*
 * A string that can contain dots.
 */
dotted_str:	STR
	|	dotted_str '.' STR
        {
		char *result = region_alloc(rr_region, $1.len + $3.len + 2);
		memcpy(result, $1.str, $1.len);
		result[$1.len] = '.';
		memcpy(result + $1.len + 1, $3.str, $3.len);
		$$.str = result;
		$$.len = $1.len + $3.len + 1;
		$$.str[$$.len] = '\0';
	}		

/* define what we can parse */

rtype:
    /*
     * RFC 1035 RR types.  We don't support NULL, WKS, and types
     * marked obsolete.
     */
      T_CNAME sp rdata_compress_domain_name 
    | T_CNAME sp rdata_unknown_err
    | T_HINFO sp rdata_hinfo 
    | T_HINFO sp rdata_unknown 
    | T_MB sp rdata_compress_domain_name		/* Experimental */
    { error("MD is obsolete"); }
    | T_MB sp rdata_unknown_err
    | T_MD sp rdata_compress_domain_name		/* Obsolete */
    { error("MF is obsolete"); }
    | T_MD sp rdata_unknown_err
    | T_MF sp rdata_compress_domain_name		/* Obsolete */
    | T_MF sp rdata_unknown_err
    | T_MG sp rdata_compress_domain_name		/* Experimental */
    | T_MG sp rdata_unknown_err
    | T_MINFO sp rdata_minfo /* Experimental */
    | T_MINFO sp rdata_unknown_err
    | T_MR sp rdata_compress_domain_name		/* Experimental */
    | T_MR sp rdata_unknown_err
    | T_MX sp rdata_mx 
    | T_MX sp rdata_unknown_err
    | T_NS sp rdata_compress_domain_name 
    | T_NS sp rdata_unknown_err
    | T_PTR sp rdata_compress_domain_name 
    | T_PTR sp rdata_unknown_err
    | T_SOA sp rdata_soa 
    | T_SOA sp rdata_unknown_err
    | T_TXT sp rdata_txt
    | T_TXT sp rdata_unknown
    | T_A sp rdata_a 
    | T_A sp rdata_unknown
    | T_AAAA sp rdata_aaaa 
    | T_AAAA sp rdata_unknown 
    | T_LOC sp rdata_loc
    | T_LOC sp rdata_unknown
    | T_SRV sp rdata_srv
    | T_SRV sp rdata_unknown
    | T_DS sp rdata_ds
    | T_DS sp rdata_unknown
    | T_KEY sp rdata_dnskey	/* XXX: Compatible format? */
    | T_KEY sp rdata_unknown 	
    | T_DNSKEY sp rdata_dnskey
    | T_DNSKEY sp rdata_unknown
    | T_NXT sp rdata_nxt
    | T_NXT sp rdata_unknown
    | T_NSEC sp rdata_nsec
    | T_NSEC sp rdata_unknown
    | T_SIG sp rdata_rrsig	/* XXX: Compatible format? */
    | T_SIG sp rdata_unknown
    | T_RRSIG sp rdata_rrsig
    | T_RRSIG sp rdata_unknown
    | T_AFSDB sp rdata_afsdb	/* RFC 1183 */
    | T_AFSDB sp rdata_unknown_err /* rfc 1183 */
    | T_RP sp rdata_rp		/* RFC 1183 */
    | T_RP sp rdata_unknown_err	/* RFC 1183 */
    | T_X25 sp rdata_x25 	/* RFC 1183 */
    | T_X25 sp rdata_unknown 	/* RFC 1183 */
    | T_ISDN sp rdata_isdn 	/* RFC 1183 */
    | T_ISDN sp rdata_unknown 	/* RFC 1183 */
    | T_RT sp rdata_rt		/* RFC 1183 */
    | T_RT sp rdata_unknown_err	/* RFC 1183 */
    | T_NSAP sp rdata_nsap	/* RFC 1706 */
    | T_NSAP sp rdata_unknown	/* RFC 1706 */
    | T_PX sp rdata_px		/* RFC 2163 */
    | T_PX sp rdata_unknown	/* RFC 2163 */
    | T_NAPTR sp rdata_naptr	/* RFC 2915 */
    | T_NAPTR sp rdata_unknown	/* RFC 2915 */
    | T_CERT sp rdata_cert	/* RFC 2538 */
    | T_CERT sp rdata_unknown	/* RFC 2538 */
    | T_DNAME sp rdata_dname	/* RFC 2672 */
    | T_DNAME sp rdata_unknown	/* RFC 2672 */
    | T_APL trail		/* RFC 3123 */
    | T_APL sp rdata_apl	/* RFC 3123 */
    | T_APL sp rdata_unknown	/* RFC 3123 */
    | T_SSHFP sp rdata_sshfp
    | T_SSHFP sp rdata_unknown
    | T_UTYPE sp rdata_unknown
    | STR error NL
    {
	    error_prev_line("Unrecognized RR type '%s'", $1.str);
    }
    ;

/* 
 *
 * below are all the definition for all the different rdata 
 *
 */

rdata_minfo:   dname sp dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain(current_parser, $1);
        zadd_rdata_domain(current_parser, $3);
    }
    ;

rdata_soa:  dname sp dname sp STR sp STR sp STR sp STR sp STR trail
    {
        /* convert the soa data */
        zadd_rdata_domain( current_parser, $1);                                     /* prim. ns */
        zadd_rdata_domain( current_parser, $3);                                     /* email */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $5.str) ); /* serial */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $7.str) ); /* refresh */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $9.str) ); /* retry */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $11.str) ); /* expire */
        zadd_rdata_wireformat( current_parser, zparser_conv_rdata_period(zone_region, $13.str) ); /* minimum */

        /* [XXX] also store the minium in case of no TTL? */
        if ( (current_parser->minimum = zparser_ttl2int($11.str) ) == -1 )
            current_parser->minimum = DEFAULT_TTL;
    }
	|   error NL
	{ error_prev_line("Syntax error in SOA record"); }
    ;

rdata_compress_domain_name:   dname trail
    {
        /* convert a single dname record */
        zadd_rdata_domain(current_parser, $1);
    }
	|   error NL
	{ error_prev_line("Syntax error in RDATA (domain name expected)"); }
    ;

rdata_a:    dotted_str trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_a(zone_region, $1.str));
	}
	|   error NL
	{ error_prev_line("Syntax error in A record"); }
    ;

rdata_txt: str_seq trail {}
	|   error NL
	{ error_prev_line("Syntax error in TXT record"); }
	;

rdata_mx:   STR sp dname trail
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_short(zone_region, $1.str) );  /* priority */
        	zadd_rdata_domain( current_parser, $3);  /* MX host */
    	}
	|   error NL
	{ error_prev_line("Syntax error in MX record"); }
    	;

rdata_aaaa: STR trail
    	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_a6(zone_region, $1.str) );  /* IPv6 address */
    	}
	|   error NL
	{ error_prev_line("Syntax error in AAAA record"); }
    	;

rdata_loc: concatenated_str_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_loc(zone_region, $1.str)); /* Location */
	}
	|   error NL
	{ error_prev_line("Syntax error in LOC record"); }
	;

rdata_hinfo:	STR sp STR trail
	{
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $1.str) ); /* CPU */
        	zadd_rdata_wireformat( current_parser, zparser_conv_text(zone_region, $3.str) ); /* OS*/
	}
	|   error NL
	{ error_prev_line("Syntax error in HINFO record"); }
	;

rdata_srv:	STR sp STR sp STR sp dname trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* prio */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* weight */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $5.str)); /* port */
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $7)); /* target name */
	}
	|   error NL
	{ error_prev_line("Syntax error in SRV record"); }
	;

rdata_ds:	STR sp STR sp STR sp str_sp_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* keytag */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $3.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $5.str)); /* type */
		zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, $7.str)); /* hash */
	}
	|   error NL
	{ error_prev_line("Syntax error in DS record"); }
	;

rdata_dnskey:	STR sp STR sp STR sp str_sp_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* flags */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $3.str)); /* proto */
		zadd_rdata_wireformat(current_parser, zparser_conv_algorithm(zone_region, $5.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_b64(zone_region, $7.str)); /* hash */
	}
	|   error NL
	{ error_prev_line("Syntax error in DNSKEY record"); }
	;

rdata_nxt:	dname sp nxt_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $1)); /* nxt name */
		zadd_rdata_wireformat(current_parser, zparser_conv_nxt(zone_region, nxtbits)); /* nxt bitlist */
		memset(nxtbits, 0 , 16);
	}
	|   error NL
	{ error_prev_line("Syntax error in NXT record"); }
	;

rdata_nsec:	dname sp nsec_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $1)); /* nsec name */
		zadd_rdata_wireformat(current_parser, zparser_conv_nsec(zone_region, nsecbits)); /* nsec bitlist */
		memset(nsecbits, 0, sizeof(nsecbits));
	}
	|   error NL
	{ error_prev_line("Syntax error in NSEC record"); }
	;


rdata_rrsig:	STR sp STR sp STR sp STR sp STR sp STR sp STR sp dname sp str_sp_seq trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_rrtype(zone_region, $1.str)); /* rr covered */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $3.str)); /* alg */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $5.str)); /* # labels */
		zadd_rdata_wireformat(current_parser, zparser_conv_rdata_period(zone_region, $7.str)); /* # orig TTL */
		zadd_rdata_wireformat(current_parser, zparser_conv_time(zone_region, $9.str)); /* sig exp */
		zadd_rdata_wireformat(current_parser, zparser_conv_time(zone_region, $11.str)); /* sig inc */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $13.str)); /* key id */
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $15)); /* signer name */
		zadd_rdata_wireformat(current_parser, zparser_conv_b64(zone_region, $17.str)); /* sig data */
	}
	|   error NL
	{ error_prev_line("Syntax error in RRSIG record"); }
	;

/* RFC 1183 */
rdata_afsdb:   STR sp dname trail
       {
               zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* subtype */
               zadd_rdata_domain(current_parser, $3); /* domain name */
       }
	|   error NL
	{ error_prev_line("Syntax error in AFSDB record"); }
       ;

/* RFC 1183 */
rdata_rp:	dname sp dname trail
	{
		zadd_rdata_domain(current_parser, $1); /* mbox d-name */
		zadd_rdata_domain(current_parser, $3); /* txt d-name */
	}
	|   error NL
	{ error_prev_line("Syntax error in RP record"); }
	;

/* RFC 1183 */
rdata_x25:	STR trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $1.str)); /* X.25 address. */
	}
	|   error NL
	{ error_prev_line("Syntax error in X25 record"); }
	;

/* RFC 1183 */
rdata_isdn:	STR trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $1.str)); /* address */
	}
	| STR sp STR trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $1.str)); /* address */
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $3.str)); /* sub-address */
	}
	|   error NL
	{ error_prev_line("Syntax error in ISDN record"); }
	;

/* RFC 1183 */
rdata_rt:	STR sp dname trail
	{
               zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* preference */
               zadd_rdata_domain(current_parser, $3); /* intermediate host */
	}
	|   error NL
	{ error_prev_line("Syntax error in RT record"); }
	;

/* RFC 1706 */
rdata_nsap:	str_dot_seq trail
	{
		/* String must start with "0x" or "0X".  */
		if (strncasecmp($1.str, "0x", 2) != 0) {
			error_prev_line("");
		} else {
			zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, $1.str + 2)); /* NSAP */
		}
	}
	|   error NL
	{ error_prev_line("Syntax error in DS record"); }
	;

/* RFC 2163 */
rdata_px:	STR sp dname sp dname trail
	{
               zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str)); /* preference */
	       zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $3)); /* MAP822 */
	       zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $5)); /* MAPX400 */
	}
	|   error NL
	{ error_prev_line("Syntax error in RT record"); }
	;

/* RFC 2915 */
rdata_naptr:	STR sp STR sp STR sp STR sp STR sp dname trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str));	/* order */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* preference */
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $5.str)); /* flags */
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $7.str)); /* service */
		zadd_rdata_wireformat(current_parser, zparser_conv_text(zone_region, $9.str)); /* regexp */
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $11)); /* target name */
	}
	|   error NL
	{ error_prev_line("Syntax error in NAPTR record"); }
	;

/* RFC 2538 */
rdata_cert:	STR sp STR sp STR sp str_sp_seq trail
	{
		/* XXX: Handle memnonics */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $1.str));	/* type */
		zadd_rdata_wireformat(current_parser, zparser_conv_short(zone_region, $3.str)); /* key tag */
		zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $5.str)); /* algorithm */
		zadd_rdata_wireformat(current_parser, zparser_conv_b64(zone_region, $7.str)); /* certificate or CRL */
	}
	|   error NL
	{ error_prev_line("Syntax error in CERT record"); }
	;

/* RFC 2672 */
rdata_dname:	dname trail
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_domain(zone_region, $1));
	}
	|   error NL
	{ error_prev_line("Syntax error in DNAME record"); }
	;

/* RFC 3123 */
rdata_apl: rdata_apl_seq trail
	| error NL
	{ error_prev_line("Syntax error in APL record"); }
	;

rdata_apl_seq: dotted_str
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_apl_rdata(zone_region, $1.str));
	}
	| rdata_apl_seq sp dotted_str
	{
		zadd_rdata_wireformat(current_parser, zparser_conv_apl_rdata(zone_region, $3.str));
	}
	;

rdata_sshfp:   STR sp STR sp str_sp_seq trail
       {
               zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $1.str)); /* alg */
               zadd_rdata_wireformat(current_parser, zparser_conv_byte(zone_region, $3.str)); /* fp type */
               zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, $5.str)); /* hash */
       }
	|   error NL
	{ error_prev_line("Syntax error in SSHFP record"); }
       ;

rdata_unknown:	URR sp STR sp str_sp_seq trail
	{
		/* $2 is the number of octects, currently ignored */
		zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, $5.str));
	}
	| URR sp STR trail
	{	
		zadd_rdata_wireformat(current_parser, zparser_conv_hex(zone_region, ""));
		/* error_prev_line("\\# 0 not handled (yet)"); */
	}
	| URR error NL
	{ error_prev_line("Syntax error in UNKNOWN RR rdata"); }
       ;

rdata_unknown_err:	URR error NL
	{ error_prev_line("UKNOWN RR rdata for this type not handled (yet)");}
	;
%%

int
yywrap(void)
{
    return 1;
}
