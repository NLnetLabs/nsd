%{
/*
 * zlparser.lex - lexical analyzer for (DNS) zone files
 * 
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved
 *
 * See LICENSE for the license
 */

#include <config.h>

#include <ctype.h>
#include <string.h>
#include <strings.h>

#include "zonec.h"
#include "dname.h"
#include "zparser.h"

#if 0
#define LEXOUT(s)  printf s /* used ONLY when debugging */
#else
#define LEXOUT(s)
#endif

static int parsestr(char * yytext, enum rr_spot *in_rr);

YY_BUFFER_STATE include_stack[MAXINCLUDES];
zparser_type zparser_stack[MAXINCLUDES];
int include_stack_ptr = 0;

%}

SPACE   [ \t]
LETTER  [a-zA-Z]
NEWLINE \n
ZONESTR [a-zA-Z0-9+/=:_!\-\*]
DOLLAR  \$
COMMENT ;
DOT     \.
SLASH   \\
ANY     [^\"]|\\.
Q       \"

%START	incl

%%
    static int paren_open = 0;
    static enum rr_spot in_rr = outside;
{SPACE}*{COMMENT}.*     /* ignore */
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

				/* put the given origin on the stack
				 * if no origin was present push the current
				 * origin on it. This way the popping of the
				 * origin always works ok */

				if ( include_origin != NULL ) {
					zparser_stack[include_stack_ptr].origin = 
						domain_table_insert(
						current_parser->db->domains,
							dname_parse(zone_region,
							include_origin,
							NULL));
					/* start using this origin */
					current_parser->origin = 
						domain_table_insert(
						current_parser->db->domains,
							dname_parse(zone_region,
							include_origin,
							NULL));
				} else {
					zparser_stack[include_stack_ptr].origin = 
						current_parser->origin;
				}

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
				if (include_stack_ptr == 0) {
					yyterminate();
        			} else {
					--include_stack_ptr;
					
					/* pop (once you pop, you can not stop) */
					current_parser->filename =
						zparser_stack[include_stack_ptr].filename;
					current_parser->line = 
						zparser_stack[include_stack_ptr].line;
					/* pop the origin */
					current_parser->origin =
						zparser_stack[include_stack_ptr].origin;
					
            				yy_delete_buffer( YY_CURRENT_BUFFER );
            				yy_switch_to_buffer( include_stack[include_stack_ptr] );
            			}
        		}
^{DOLLAR}{LETTER}+      { warning("Unknown $directive: %s", yytext); }
^{DOT}                  {
                            /* a ^. means the root zone... also set in_rr */
                            in_rr = expecting_dname;
			    LEXOUT((". "));
                            return '.';
                        }
{DOT}                   { LEXOUT((". ")); return '.'; }
{SLASH}#                { LEXOUT(("\\# "));return URR; }
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
{Q}({ANY})*{Q}   {
                            /* this matches quoted strings */
			    /* Strip leading and ending quotes.  */
			    yytext[strlen(yytext) - 1] = '\0';
                            return parsestr(yytext + 1, &in_rr);
                        }
({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word */
			    return parsestr(yytext, &in_rr);
                        }
.                       {
                            /* we should NEVER reach this
                             * bail out with an error */
			    error("Unknown character seen - is this a zonefile?");
                            /*exit(1); [XXX] we should exit... */
                        }
%%

/*
 * Analyze "word" to see if it matches an RR type, possibly by using
 * the "TYPExxx" notation.  If it matches, the corresponding token is
 * returned and the TYPE parameter is set to the RR type value.
 */
static int
zrrtype (const char *word, uint16_t *type) 
{
	uint16_t t = lookup_type_by_name(word);
	if (t != 0) {
		const lookup_table_type *entry
			= lookup_by_symbol(t, ztypes);
		*type = t;
		if (entry) {
			return entry->token;
		} else {
			LEXOUT(("TYPEx%d ", (int) t));
			return T_UTYPE;
		}
	}

	return 0;
}

/* do some preparsing of the stuff */
static int
zoctet(char *word) 
{
    /* remove \DDD constructs from the input. See RFC 1035, section 5.1 */
    /* s follows the string, p lags behind and rebuilds the new string */
    char * s; char * p;
    unsigned int length = 0;

    for (s = p = word; *s != '\0'; s++,p++ ) {
        switch ( *s ) {
            case '.':
		/* [XXX] is empty label handled correctly? */
                if (s[1] == '.') {
                    warning("Empty label");
                    break;
                }
                *p = *s;
                length++; 
                break;
            case '\\':
                if ('0' <= s[1] && s[1] <= '9' &&
                    '0' <= s[2] && s[2] <= '9' &&
                    '0' <= s[2] && s[3] <= '9')
		{
                    /* \DDD seen */
                    int val = ((s[1] - '0') * 100 +
                           (s[2] - '0') * 10 +
                           (s[3] - '0'));

                    if (0 <= val && val <= 255) {
                        /* this also handles \0 */
                        s += 3;
                        *p = val;
                        length++;
                    } else {
                        warning("ASCII \\DDD overflow");
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

static int
parsestr(char *yytext, enum rr_spot *in_rr)
{
	int token;
	char *t; char *ztext;

	switch(*in_rr) {
	case after_dname:
		/* type */
		token = zrrtype(yytext, &yylval.type);
		if (token != 0) {
			*in_rr = reading_type;
			return token;
		}

		/* class */
		if (strcasecmp(yytext, "IN") == 0 ||
		    strcasecmp(yytext,"CLASS1") == 0 ) {
			yylval.class = CLASS_IN;
			LEXOUT(("IN "));
			return T_IN;
		} else if (strcasecmp(yytext, "CH") == 0) {
			yylval.class = CLASS_CHAOS;
			return T_CH;
		} else if (strcasecmp(yytext, "HS") == 0) {
			yylval.class = CLASS_HS;
			return T_HS;
		}

		/* ttl */
		strtottl(yytext, &t);
		if ( *t == 0 ) {
			/* was parseable */
			yylval.data.str = yytext;
			yylval.data.len = strlen(yytext); /*needed?*/
			LEXOUT(("TTL "));
			return TTL;
		}
		/* fall through, default first, order matters */
	default:
		ztext = region_strdup(rr_region, yytext);
		yylval.data.len = zoctet(ztext);
		yylval.data.str = ztext;
		LEXOUT(("STR "));
		return STR;
	case outside:
		/* should match ^ */
		ztext = region_strdup(rr_region, yytext);
		yylval.data.len = zoctet(ztext);
		yylval.data.str = ztext;
		*in_rr = expecting_dname;
		LEXOUT(("STR "));
		return STR;
	}
}
