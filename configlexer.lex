%{
/*
 * configlexer.lex - lexical analyzer for NSD config file
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include "options.h"
#include "configyyrename.h"
#include "configparser.h"
void c_error(const char *message);

#define YY_NO_UNPUT

#if 0
#define LEXOUT(s)  printf s /* used ONLY when debugging */
#else
#define LEXOUT(s)
#endif

%}

SPACE   [ \t]
LETTER  [a-zA-Z]
UNQUOTEDLETTER [^\"\n\r \t\\]|\\.
NEWLINE [\r\n]
COMMENT \#
COLON 	\:
ANY     [^\"\n\r\\]|\\.

%x	quotedstring

%%
{SPACE}* 		{ LEXOUT(("SP ")); /* ignore */ }
{SPACE}*{COMMENT}.* 	{ LEXOUT(("comment(%s) ", yytext)); /* ignore */ }
server{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_SERVER;}
name{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_NAME;}
ip-address{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_IP_ADDRESS;}
debug-mode{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_DEBUG_MODE;}
ip4-only{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_IP4_ONLY;}
ip6-only{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_IP6_ONLY;}
database{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_DATABASE;}
identity{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_IDENTITY;}
logfile{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_LOGFILE;}
server-count{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_SERVER_COUNT;}
tcp-count{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_TCP_COUNT;}
pidfile{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_PIDFILE;}
port{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_PORT;}
statistics{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_STATISTICS;}
chroot{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_CHROOT;}
username{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_USERNAME;}
zonesdir{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_ZONESDIR;}
difffile{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_DIFFFILE;}
xfrdfile{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_XFRDFILE;}
zone{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_ZONE;}
zonefile{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_ZONEFILE;}
allow-notify{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_ALLOW_NOTIFY;}
request-xfr{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_REQUEST_XFR;}
notify{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_NOTIFY;}
provide-xfr{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_PROVIDE_XFR;}
key{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_KEY;}
algorithm{COLON}	{ LEXOUT(("v(%s) ", yytext)); return VAR_ALGORITHM;}
secret{COLON}		{ LEXOUT(("v(%s) ", yytext)); return VAR_SECRET;}
{NEWLINE}		{ LEXOUT(("NL\n")); cfg_parser->line++;}

	/* Quoted strings. Strip leading and ending quotes */
\"			{ BEGIN(quotedstring); LEXOUT(("QS ")); }
<quotedstring><<EOF>>   {
        yyerror("EOF inside quoted string");
        BEGIN(INITIAL);
}
<quotedstring>{ANY}*    { LEXOUT(("STR(%s) ", yytext)); yymore(); }
<quotedstring>\n        { cfg_parser->line++; yymore(); }
<quotedstring>\" {
        LEXOUT(("QE "));
        BEGIN(INITIAL);
        yytext[yyleng - 1] = '\0';
	yylval.str = strdup(yytext);
        return STRING;
}

{UNQUOTEDLETTER}*	{ LEXOUT(("unquotedstr(%s) ", yytext)); 
			yylval.str = strdup(yytext); return STRING; }

%%
