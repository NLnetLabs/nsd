%{
/*
 * $Id: zlexer.lex,v 1.10 2003/11/05 09:26:38 miekg Exp $
 *
 * zlparser.lex - lexical analyzer for (DNS) zone files
 * 
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved
 *
 * See LICENSE for the license
 */

#include <config.h>

#include <string.h>
#include <strings.h>

#include "zonec.h"
#include "dname.h"
#include "zparser.h"

/* #define LEXOUT(s)  printf s /* used ONLY when debugging */
#define LEXOUT(s) 

/* see  http://www.iana.org/assignments/dns-parameters */
const char *RRtypes[] = {"A", "NS", "MX", "TXT", "CNAME", "AAAA", "PTR",
    "NXT", "KEY", "SOA", "SIG", "SRV", "CERT", "LOC", "MD", "MF", "MB",
    "MG", "MR", "NULL", "WKS", "HINFO", "MINFO", "RP", "AFSDB", "X25",
    "ISDN", "RT", "NSAP", "NSAP-PTR", "PX", "GPOS", "EID", "NIMLOC", "ATMA",
    "NAPTR", "KX", "A6", "DNAME", "SINK", "OPT", "APL", "UINFO", "UID",
    "GID", "UNSPEC", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA",
    "DS","RRSIG","NSEC","DNSKEY"};

YY_BUFFER_STATE include_stack[MAXINCLUDES];
zparser_type zparser_stack[MAXINCLUDES];
int include_stack_ptr = 0;

%}

SPACE   [ \t]
LETTER  [a-zA-Z]
NEWLINE \n
ZONESTR [a-zA-Z0-9+/=:_\-\*]
DOLLAR  \$
COMMENT ;
DOT     \.
SLASH   \\
ANY     [^\"]|\\.
CLASS   IN|CH|HS
Q       \"

%START	incl

%%
    static int paren_open = 0;
    static enum rr_spot in_rr = outside;
    char *ztext;
    int i;
    int j;
{SPACE}*{COMMENT}.*     /* ignore */
{COMMENT}.*{NEWLINE}    { 
                            current_parser->line++;
                            if ( paren_open == 0 )
                                return NL;
                        }
^@                      {
                            in_rr = expecting_dname;
                            return ORIGIN;
                        }
^{DOLLAR}TTL            return DIR_TTL;
^{DOLLAR}ORIGIN         return DIR_ORIG;
^{DOLLAR}INCLUDE        BEGIN(incl);

			/* see
			* http://dinosaur.compilertools.net/flex/flex_12.html#SEC12
			*/
<incl>[^\n]+ 		{ 	
				/* Need to fix this so that $INCLUDE * file origin works */
    				/* got the include file name
			     	 * open the new filename and continue parsing 
			     	 */

				char *include_origin;
				
				/* eat leading white space */
				while ( isspace(*yytext) ) 
					yytext++;

				include_origin = strrchr(yytext, 32); /* search for a space */
				
				if ( include_origin != NULL ) {
					/* split the original yytext */
					*include_origin = '\0';
					include_origin++;
				}
				

				if ( include_stack_ptr >= MAXINCLUDES ) {
				    error("Includes nested too deeply (>10)");
            			    exit(1);
            			}

				/* push zdefault on the stack (only the
				 * important values
				 */
				zparser_stack[include_stack_ptr].filename = 
					current_parser->filename;
				zparser_stack[include_stack_ptr].line	   = 
					current_parser->line;

				/* PUT ON THE STACK
				if ( include_origin != NULL ) {
					zparser_stack[include_stack_ptr].origin = 
						include_origin;
					current_parser->origin = include_origin;
				} else {
					zparser_stack[include_stack_ptr].origin = 
						current_parser->origin;
				}
				*/

			        include_stack[include_stack_ptr++] = 
					YY_CURRENT_BUFFER;

		        	yyin = fopen( yytext, "r" );
        			if ( ! yyin ) {
					error("Cannot open $INCLUDE file: %s", yytext);
				    	exit(1);
				}

				/* reset for the current file */
				current_parser->filename = region_strdup(zone_region, yytext);
				current_parser->line = 1;
        			yy_switch_to_buffer( yy_create_buffer( yyin, YY_BUF_SIZE ) );

			        BEGIN(INITIAL);
        		}	
<<EOF>>			{	/* end of file is reached - check if we were including */
        			if ( --include_stack_ptr < 0 )
				            yyterminate();
        			else {
					/* pop (once you pop, you can not stop) */
					current_parser->filename =
						zparser_stack[include_stack_ptr].filename;
					current_parser->line = 
						zparser_stack[include_stack_ptr].line;
					/* pop the origin */
					
            				yy_delete_buffer( YY_CURRENT_BUFFER );
            				yy_switch_to_buffer( include_stack[include_stack_ptr] );
            			}
        		}
^{DOLLAR}{LETTER}+      { warning("Uknown $directive: %s", yytext); }
^{DOT}                  {
                            /* a ^. means the root zone... also set in_rr */
                            in_rr = expecting_dname;
                            return '.';
                        }
{DOT}                   return '.';
{SLASH}#                return UN_RR;
^{SPACE}+               {
                            if ( paren_open == 0 ) { 
                                in_rr = after_dname;
                                return PREV;
                            }
                        }
{NEWLINE}               {
                            current_parser->line++;
                            if ( paren_open == 0 ) { 
                                in_rr = outside;
				LEXOUT(("NL \n"));
                                return NL;
                            } else {
				    LEXOUT(("SP "));
				    return SP;
			    }
                        }
{SPACE}*\({SPACE}*      {
                            if ( paren_open == 1 ) {
				error("Nested parentheses");
                                yyterminate();
                            }
                            LEXOUT(("SP( "));
                            paren_open = 1;
                            return SP;
                        }
{SPACE}*\){SPACE}*      {
                            if ( paren_open == 0 ) {
				error("Unterminated parentheses");
                                yyterminate();
                            }
                            LEXOUT(("SP) "));
                            paren_open = 0;
                            return SP;
                        }
{SPACE}+                {
                            if ( paren_open == 0 ) {
                                if ( in_rr == expecting_dname )
                                    in_rr = after_dname;
                            }
                            LEXOUT(("SP "));
                            return SP;
                        }
^({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word. Needs to be located
                             * before CLASS and TYPEXXX and CLASSXXX
                             * to correctly see a dname here */
                            ztext = region_strdup(rr_region, yytext);
                            yylval.data.len = zoctet(ztext);
                            yylval.data.str = ztext;
                            in_rr = expecting_dname;
			    LEXOUT(("STR "));
                            return STR;
                        }
{CLASS}                 {

				/* \000 here will not cause problems */
                            if ( in_rr == after_dname) { 
  			        if (strcasecmp(yytext, "IN") == 0) {
  				    yylval.class = CLASS_IN;
                                    return IN;
                                } else if (strcasecmp(yytext, "CH") == 0) {
				    yylval.class = CLASS_CHAOS;
                                    return CH;
                                } else if (strcasecmp(yytext, "HS") == 0) {
				    yylval.class = CLASS_HS;
                                    return HS;
				}
                            } else {
                                ztext = region_strdup(rr_region, yytext); 
                                yylval.data.len = zoctet(ztext);
                                yylval.data.str = ztext;
				return STR;
			    }
                            
                        }
TYPE[0-9]+              {
                            if ( in_rr == after_dname ) {
				/* check the type */
				j = intbytypexx(yytext);
				if ( j != 0 )  {
					yylval.type = intbyname(yytext, ztypes);
					return j - 1 + A;
				}
				else {
					ztext = region_strdup(rr_region, yytext);
					yylval.data.len = zoctet(ztext);
					yylval.data.str = ztext;
                                	return UN_TYPE;
				}
			    } else {
				    ztext = region_strdup(rr_region, yytext); 
				    yylval.data.len = zoctet(ztext);
				    yylval.data.str = ztext;
				    return STR;
                            }
                        }
CLASS[0-9]+             {
                            if ( in_rr == after_dname ) {
				j = intbyclassxx(yytext);
				if ( j == 1 ) { /* XXX: What about CH and HS? */
					yylval.class = j;
					return IN;
				} else {
					ztext = region_strdup(rr_region, yytext);
					yylval.data.len = zoctet(ztext);
					yylval.data.str = ztext;
                                	return UN_CLASS;
				}
			    }

                            if ( in_rr != after_dname)  {
                                ztext = region_strdup(rr_region, yytext); 
                                yylval.data.len = zoctet(ztext);
                                yylval.data.str = ztext;
                                return STR;
                            }
                        }
{Q}({ANY})({ANY})*{Q}   {
                            /* this matches quoted strings */
                            ztext = region_strdup(rr_region, yytext);
                            yylval.data.len = zoctet(ztext);
                            yylval.data.str = ztext;

                            if ( in_rr == after_dname ) {
                                i = zrrtype(ztext);
                                if ( i ) {
                                    in_rr = reading_type; return i;
                                }
                            }
			    LEXOUT(("STR "));
                            return STR;
                        }
({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word */
                            if ( in_rr == after_dname ) {
                                i = zrrtype(yytext);
                                if (i) {
                                    in_rr = reading_type;
				    yylval.type = intbyname(yytext, ztypes);
				    return i;
                                } 
                            }

                            ztext = region_strdup(rr_region, yytext);
                            yylval.data.len = zoctet(ztext);
                            yylval.data.str = ztext;
			    LEXOUT(("STR "));
                            return STR;
                        }
.                       {
                            /* we should NEVER reach this
                             * bail out with an error */
			    error("Uknown character seen - is this a zonefile?");
                            /*exit(1); [XXX] we should exit... */
                        }
%%

int
zrrtype (char *word) 
{
	/*
	 * Check to see if word is in the list of reconized keywords.
	 * 'A' is first token defined in YACC. With this hack we
	 * return the correct token based on our list of RR types
	 */
	int i;
	for (i = 0; i < RRTYPES - 1; i++) {
		if (strcasecmp(word, RRtypes[i]) == 0) {
			LEXOUT(("%s ", word));
			return i + A;
		}
		
	}
	return 0;
}

/* do some preparsing of the stuff */
int
zoctet(char *word) 
{
    /* remove \DDD constructs from the input. See RFC 1035, section 5.1 */
    /* s follows the string, p lags behind and rebuilds the new string */
    char * s; char * p;
    unsigned int length = 0;

    for (s = p = word; *s != '\0'; s++,p++ ) {
        switch ( *s ) {
            /* [XXX] what is so special about dots anyway?
            case '.':
                printf("Seeing dots\n\n");
                if ( s[1] == '.' ) {
                    printf("zlparser.lex: Empty label!\n");
                    break;
                }
                *p = *s;
                length++; 
                break;
            */
            case '\\':
                if ( '0' <= s[1] && s[1] <= '9' &&
                    '0' <= s[2] && s[2] <= '9' &&
                    '0' <= s[2] && s[3] <= '9' ) {
                    /* \DDD seen */
                    int val = ((s[1] - '0') * 100 +
                           (s[2] - '0') * 10 +
                           (s[3] - '0'));

                    if ( 0 <= val && val <= 255 ) {
                        /* this also handles \0 */
                        s += 3;
                        *p = val;
                        length++;
                    } else {
                        printf("zlparser.lex: ASCII overflow\n");
                    }

                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    *p = *++s;
                    length++;
                }
                break;
            case '\"':
                /* non quoted " Is either first or the last character in
                 * the string */

                *p = *++s; /* skip it */
                length++; 
                if ( *s == '\0' ) {
                    /* ok, it was the last one */
                    *p  = '\0'; return length;
                }
                break;
            default:
                *p = *s;
                length++;
                break;
        }
    }
    *p = '\0';
    return length;
}

/* 
 * receive a CLASSXXXX string and return XXXX as
 * an integer
 */
uint16_t
intbyclassxx(void *str)
{
        char *where;
        uint16_t type;

        where = strstr((char*)str, "CLASS");
        if ( where == NULL )
                where = strstr((char*)str, "class");

        if ( where == NULL )
                /* nothing found */
                return 0;

        if ( where != (char*) str )
                /* not the first character */
                return 0;

        /* the rest from the string, from
         * where to the end must be a number */
        type = (uint16_t) strtol(where + 5, (char**) NULL, 10);

        /* zero if not ok */
        return type;
}

/* 
 * receive a TYPEXXXX string and return XXXX as
 * an integer
 */
uint16_t
intbytypexx(void *str)
{
        char *where;
        uint16_t type;

        where = strstr((char*)str, "TYPE");
        if ( where == NULL )
                where = strstr((char*)str, "type");

        if ( where == NULL )
                /* nothing found */
                return 0;

        if ( where != (char*) str )
                /* not the first character */
                return 0;

        /* the rest from the string, from
         * where to the end must be a number */
        type = (uint16_t) strtol(where + 4, (char**) NULL, 10);

        /* zero if not ok */
        return type;
}
