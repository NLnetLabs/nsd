/*
 * configyyrename.h -- renames for config file yy values to avoid conflicts.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef CONFIGYYRENAME_H
#define CONFIGYYRENAME_H

/* defines to change symbols so that no yacc/lex symbols clash */
#define yymaxdepth c_maxdepth
#define yyparse c_parse
#define yylex   c_lex
#define yyerror c_error
#define yylval  c_lval
#define yychar  c_char
#define yydebug c_debug
#define yypact  c_pact
#define yyr1    c_r1
#define yyr2    c_r2
#define yydef   c_def
#define yychk   c_chk
#define yypgo   c_pgo
#define yyact   c_act
#define yyexca  c_exca
#define yyerrflag c_errflag
#define yynerrs c_nerrs
#define yyps    c_ps
#define yypv    c_pv
#define yys     c_s
#define yy_yys  c_yys
#define yystate c_state
#define yytmp   c_tmp
#define yyv     c_v
#define yy_yyv  c_yyv
#define yyval   c_val
#define yylloc  c_lloc
#define yyreds  c_reds
#define yytoks  c_toks
#define yylhs   c_yylhs
#define yylen   c_yylen
#define yydefred c_yydefred
#define yydgoto c_yydgoto
#define yysindex c_yysindex
#define yyrindex c_yyrindex
#define yygindex c_yygindex
#define yytable  c_yytable
#define yycheck  c_yycheck
#define yyname   c_yyname
#define yyrule   c_yyrule
#define yyin    c_in
#define yyout   c_out
#define yywrap  c_wrap
#define yy_load_buffer_state c_load_buffer_state
#define yy_switch_to_buffer c_switch_to_buffer
#define yy_flush_buffer c_flush_buffer
#define yy_init_buffer c_init_buffer
#define yy_scan_buffer c_scan_buffer
#define yy_scan_bytes c_scan_bytes
#define yy_scan_string c_scan_string
#define yy_create_buffer c_create_buffer
#define yyrestart c_restart
#define yy_delete_buffer c_delete_buffer

#endif /* CONFIGYYRENAME_H */
