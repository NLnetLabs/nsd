%{
#include "zparser2.h"
#include "dname.h"
#include "zyparser.h"

/* see  http://www.iana.org/assignments/dns-parameters */
static char *RRtypes[] = {"A", "NS", "MX", "TXT", "CNAME", "AAAA", "PTR",
    "NXT", "KEY", "SOA", "SIG", "SRV", "CERT", "LOC", "MD", "MF", "MB",
    "MG", "MR", "NULL", "WKS", "HINFO", "MINFO", "RP", "AFSDB", "X25",
    "ISDN", "RT", "NSAP", "NSAP-PTR", "PX", "GPOS" "EID", "NIMLOC", "ATMA",
    "NAPTR", "KX", "A6", "DNAME", "SINK", "OPT", "APL", "UINFO", "UID",
    "GID", "UNSPEC", "TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA"};


unsigned int lineno = 0;

/* in_rr:
 * 0 = not in an rr
 * 1 = reading ^dname
 * 2 = after ^dname read space -> in RR
 * 3 = read RRTYPE
 *
 * Changelog: 
 *  09-07-2003: miekg: added unknown rrs 
 *  28-07-2003: miekg: added wildcards 
 *  06-08-2003: miekg: all YYSET reference deleted
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
ANY     .|\\.
Q       \"

%%
    static int paren_open = 0;
    static int in_rr = 0;
    char *ztext;
    int i;
    yylval = xalloc(sizeof(YYSTYPE)); /* [XXX] really, really needed */

{COMMENT}.*{NEWLINE}    { 
                            lineno++;
                            if ( paren_open == 0 )
                                return NL;
                        }
^@                      {
                            ztext = strdup(yytext);
                            yylval->str = ztext;
                            yylval->len = strlen(ztext);
                            in_rr = 1;
                            return ORIGIN;
                        }
^{DOLLAR}TTL            return DIR_TTL;
^{DOLLAR}ORIGIN         return DIR_ORIG;
^{DOLLAR}INCLUDE.*      /* ignore for now */    /* INCLUDE FILE DOMAINNAME */
^{DOLLAR}{LETTER}+      { printf("UNKNOWN DIRECTIVE - ignored");}
{DOT}                   return '.';
{SLASH}#                return UN_RR;
^{SPACE}+               {
                            if ( paren_open == 0 ) { 
                                in_rr = 2;
                                return PREV;
                            }
                        }
{NEWLINE}               {
                            lineno++;
                            if ( paren_open == 0 ) { 
                                in_rr = 0;
                                return NL;
                            }
                        }
{SPACE}+{NEWLINE}       {
                            lineno++;
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
                                printf( "nested parentheses\n" );
                                yyterminate();
                            }
                            paren_open = 1;
                        }
\){SPACE}*              {
                            if ( paren_open == 0 ) {
                                printf( "unterminated parentheses\n" );
                                yyterminate();
                            }
                            paren_open = 0;
                        }
IN                      {
                            if ( in_rr == 2) { return IN; }
                            if ( in_rr != 2) { 
                                ztext = strdup(yytext); 
                                yylval->len = zoctet(ztext);
                                yylval->str = ztext;
                                return STR;
                            }
                        }
CH                      {
                            if ( in_rr == 2) return CH;
                            if ( in_rr != 2) { 
                                ztext = strdup(yytext); 
                                yylval->len = zoctet(ztext);
                                yylval->str = ztext;
                                return STR;
                            }
                        }
HS                      {
                            if ( in_rr == 2) return HS;
                            if ( in_rr != 2) { 
                                ztext = strdup(yytext); 
                                yylval->len = zoctet(ztext);
                                yylval->str = ztext;
                                return STR;
                            }
                        }
TYPE[0-9]+              {
                            ztext = strdup(yytext); 
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            return UN_TYPE;
                        }
CLASS[0-9]+             {
                            ztext = strdup(yytext); 
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            return UN_CLASS;
                        }
^{Q}({ANY})({ANY})*{Q}  {
                            /* this matches quoted strings when ^ */
                            ztext = strdup(yytext);
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            in_rr = 1;
                            return STR;
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
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            return STR;
                        }

^({ZONESTR}|\\.)({ZONESTR}|\\.)* {
                            /* any allowed word */
                            ztext = strdup(yytext);
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            in_rr = 1;
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
                            yylval->len = zoctet(ztext);
                            yylval->str = ztext;
                            return STR;
                        }
.                       {
                            /* we should NEVER reach this
                             * bail out with an error */
                            printf("Unknown character seen - This is not a zone file! ABORT\n");
                            exit(1);
                        }
%%

int zrrtype (char *word) {
    /* check to see if word is in the list of reconized keywords
     * if so return the token number ( i + 258 ), otherwise return 0;
     * yacc starts to count at 258 for the tokens
     */
    int i;
    for( i=0; i < ( RRTYPES - 1 ); i++ ) {
        if ( strcasecmp(word, RRtypes[i]) == 0 )
            return (i + A);
        
    }
    return 0;
}

/* do some preparsing of the stuff */
int zoctet(char *word) {
    /* remove \DDD constructs from the input. See RFC 1035, section 5.1 */
    /* s follows the string, p lags behind and rebuilds the new string */
    char * s; char * p ;
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
                        /* mega problem here: \0 */
                        printf("value found [%c]", val);
                        s += 3;
                        *p = DNAME_NORMALIZE(val);
                        length++;
                    } else {
                        printf("ASCII overflow\n");
                    }

                } else {
                    /* an espaced character, like \<space> ? 
                    * remove the '\' keep the rest */
                    *p = DNAME_NORMALIZE(*++s);
                    length++;
                }
                break;
            case '\"':
                /* non quoted " */
                *p = DNAME_NORMALIZE(*++s);
                length++;
                break;
            default:
                *p = DNAME_NORMALIZE(*s);
                length++;
                break;
        }
    }
    *p = '\0';
    return length;
}
