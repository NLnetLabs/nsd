%{
/*
 * $Id: zlparser.lex,v 1.16 2003/08/25 19:39:08 miekg Exp $
 *
 * zlparser.lex - lexical analyzer for (DNS) zone files
 * 
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved
 *
 * See LICENSE for the license
 */

#include <config.h>
	
#include "zparser2.h"
#include "dname.h"
#include "zyparser.h"

/* see  http://www.iana.org/assignments/dns-parameters */
char *RRtypes[] = {"A", "NS", "MX", "TXT", "CNAME", "AAAA", "PTR",
    "NXT", "KEY", "SOA", "SIG", "SRV", "CERT", "LOC", "MD", "MF", "MB",
    "MG", "MR", "NULL", "WKS", "HINFO", "MINFO", "RP", "AFSDB", "X25",
    "ISDN", "RT", "NSAP", "NSAP-PTR", "PX", "GPOS" "EID", "NIMLOC", "ATMA",
    "NAPTR", "KX", "A6", "DNAME", "SINK", "OPT", "APL", "UINFO", "UID",
    "GID", "UNSPEC", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA"};

YY_BUFFER_STATE include_stack[MAXINCLUDES];
/* need to do something simular for zdefault [XXX] miek */
int include_stack_ptr = 0;

/* in_rr:
 * 0 = not in an rr
 * 1 = reading ^dname
 * 2 = after ^dname read space -> in RR
 * 3 = read RRTYPE
 */

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
    static int in_rr = 0;
    char *ztext;
    int i;
{COMMENT}.*{NEWLINE}    { 
                            zdefault->line++;
                            if ( paren_open == 0 )
                                return NL;
                        }
^@                      {
                            ztext = strdup(yytext);
                            yylval.len = zoctet(ztext);
                            yylval.str = ztext;
                            in_rr = 1;
                            return ORIGIN;
                        }
^{DOLLAR}TTL            return DIR_TTL;
^{DOLLAR}ORIGIN         return DIR_ORIG;
^{DOLLAR}INCLUDE        BEGIN(incl);

<incl>[ \t]* 		/* eat the whitespace - ripped from 
			* http://dinosaur.compilertools.net/flex/flex_12.html#SEC12
			*/
<incl>[^ \t\n]+ 	{ 	
    				/* got the include file name
			     	 * open the new filename and continue parsing 
			     	 */
				if ( include_stack_ptr >= MAXINCLUDES ) {
			            yyerror( "Includes nested too deeply (>10)" );
            			    exit(1);
            			}

			        include_stack[include_stack_ptr++] = YY_CURRENT_BUFFER;

		        	yyin = fopen( yytext, "r" );
        			if ( ! yyin ) {
            				yyerror("Cannot open $INCLUDE file" );
				    	exit(1);
				}

        			yy_switch_to_buffer( yy_create_buffer( yyin, YY_BUF_SIZE ) );

			        BEGIN(INITIAL);
        		}	
<<EOF>>			{	/* end of file is reached - check if we were
				 * including
				 */
        			if ( --include_stack_ptr < 0 )
				            yyterminate();
        			else {
            				yy_delete_buffer( YY_CURRENT_BUFFER );
            				yy_switch_to_buffer( include_stack[include_stack_ptr] );
            			}
        		}
^{DOLLAR}{LETTER}+      { yyerror("Uknown $-directive"); }
^{DOT}                  {
                            /* a ^. means the root zone... also set in_rr */
                            in_rr = 1;
                            return '.';
                        }
{DOT}                   return '.';
{SLASH}#                return UN_RR;
^{SPACE}+               {
                            if ( paren_open == 0 ) { 
                                in_rr = 2;
                                return PREV;
                            }
                        }
{NEWLINE}               {
                            zdefault->line++;
                            if ( paren_open == 0 ) { 
                                in_rr = 0;
                                return NL;
                            }
                        }
{SPACE}+{NEWLINE}       {
                            zdefault->line++;
                            if ( paren_open == 0 ) { 
                                in_rr = 0;
                                return NL;
                            }
                        }
{SPACE}+                {
                            if ( paren_open == 0 ) {
                                if ( in_rr == 1 )
                                    in_rr = 2;

                                return SP;
                            }
                        }
\(                      {
                            if ( paren_open == 1 ) {
                                yyerror( "nested parentheses" );
                                yyterminate();
                            }
                            paren_open = 1;
                        }
\){SPACE}*              {
                            if ( paren_open == 0 ) {
                                yyerror( "unterminated parentheses" );
                                yyterminate();
                            }
                            paren_open = 0;
                        }
^({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word. Needs to be located
                             * before CLASS and TYPEXXX and CLASSXXX
                             * to correctly see a dname here */
                            ztext = strdup(yytext);
                            yylval.len = zoctet(ztext);
                            yylval.str = ztext;
                            in_rr = 1;
                            return STR;
                        }
{CLASS}                 {
                            if ( in_rr == 2) { 
                                if ( strncasecmp(yytext, "IN", 2) == 0 )
                                    return IN;
                                if ( strncasecmp(yytext, "CH", 2) == 0 )
                                    return CH;
                                if ( strncasecmp(yytext, "HS", 2) == 0 )
                                    return HS;
                            }
                            if ( in_rr != 2) { 
                                ztext = strdup(yytext); 
                                yylval.len = zoctet(ztext);
                                yylval.str = ztext;
                                return STR;
                            }
                        }
TYPE[0-9]+              {
                            if ( in_rr == 2)
                                return UN_TYPE;

                            if ( in_rr != 2)  {
                                ztext = strdup(yytext); 
                                yylval.len = zoctet(ztext);
                                yylval.str = ztext;
                                return STR;
                            }
                        }
CLASS[0-9]+             {
                            if ( in_rr == 2)
                                return UN_TYPE;

                            if ( in_rr != 2)  {
                                ztext = strdup(yytext); 
                                yylval.len = zoctet(ztext);
                                yylval.str = ztext;
                                return STR;
                            }
                        }
{Q}({ANY})({ANY})*{Q}   {
                            /* this matches quoted strings */
                            if ( in_rr == 2 ) {
                                i = zrrtype(yytext);
                                if ( i ) {
                                    in_rr = 3; return i;
                                }
                            }
                            ztext = strdup(yytext);
                            yylval.len = zoctet(ztext);
                            yylval.str = ztext;
                            return STR;
                        }
({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word */
                            if ( in_rr == 2 ) {
                                i = zrrtype(yytext);
                                if ( i ) {
                                    in_rr = 3; return i;
                                } 
                            }
                            ztext = strdup(yytext);
                            yylval.len = zoctet(ztext);
                            yylval.str = ztext;
                            return STR;
                        }
.                       {
                            /* we should NEVER reach this
                             * bail out with an error */
                            printf("Unknown character seen - This is not a zone file! ABORT\n");
                            exit(1);
                        }
%%

int
zrrtype (char *word) 
{
    /* check to see if word is in the list of reconized keywords
     * 'A' is first token defined in YACC. With this hack we
     * return the correct token based on our list of RR types
     */
    int i;
    for( i=0; i < ( RRTYPES - 1 ); i++ ) {
        if ( strcasecmp(word, RRtypes[i]) == 0 )
            return (i + A);
        
    }
    return 0;
}

/* do some preparsing of the stuff */
int
zoctet(char *word) 
{
    /* remove \DDD constructs from the input. See RFC 1035, section 5.1 */
    /* s follows the string, p lags behind and rebuilds the new string */
    /*
     * Don't normalize here */
    char * s; char * p;
    unsigned int length = 0;

    for (s = p = word; *s != '\0'; s++,p++ ) {
        /* backslash detected -- do your work */
        switch ( *s ) {
            case '.':
                if ( s[1] == '.' ) {
                    printf("Empty label!\n");
                    /* .. situation */
                }
                break;
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
                        /* *p = DNAME_NORMALIZE(val); */
                        *p = val;
                        length++;
                    } else {
                        printf("zlparser.lex: ASCII overflow\n");
                    }

                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    /* *p = DNAME_NORMALIZE(*++s); */
                    *p = *++s;
                    length++;
                }
                break;
            case '\"':
                /* non quoted " */
                /* *p = DNAME_NORMALIZE(*++s); */
                *p = *++s;
                length++;
                break;
            default:
                /* *p = DNAME_NORMALIZE(*s); */
                *p = *s;
                length++;
                break;
        }
    }
    *p = '\0';
    return length;
}
