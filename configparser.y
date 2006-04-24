/*
 * configparser.y -- yacc grammar for NSD configuration files
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

%{
#include <config.h>

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "options.h"
#include "configyyrename.h"
int c_lex(void);
void c_error(const char *message);

#ifdef __cplusplus
extern "C"
#endif /* __cplusplus */

/* these need to be global, otherwise they cannot be used inside yacc */
extern config_parser_state_t* cfg_parser;
static int server_settings_seen = 0;
static acl_options_t* parse_acl_info(char* ip, const char* key);

#if 0
#define OUTYY(s)  printf s /* used ONLY when debugging */
#else
#define OUTYY(s)
#endif

%}
%union {
	char*	str;
}

%token SPACE LETTER NEWLINE COMMENT COLON ANY ZONESTR
%token <str> STRING
%token VAR_SERVER VAR_NAME VAR_IP_ADDRESS VAR_DEBUG_MODE
%token VAR_IP4_ONLY VAR_IP6_ONLY VAR_DATABASE VAR_IDENTITY VAR_LOGFILE
%token VAR_SERVER_COUNT VAR_TCP_COUNT VAR_PIDFILE VAR_PORT VAR_STATISTICS
%token VAR_CHROOT VAR_USERNAME VAR_ZONESDIR VAR_XFRDFILE VAR_DIFFFILE
%token VAR_XFRD_RELOAD_TIMEOUT
%token VAR_ZONEFILE 
%token VAR_ZONE
%token VAR_ALLOW_NOTIFY VAR_REQUEST_XFR VAR_NOTIFY VAR_PROVIDE_XFR
%token VAR_KEY
%token VAR_ALGORITHM VAR_SECRET

%%
toplevelvars: /* empty */ | toplevelvars toplevelvar ;
toplevelvar: serverstart contents_server | zonestart contents_zone | 
	keystart contents_key;

/* server: declaration */
serverstart: VAR_SERVER
	{ OUTYY(("\nP(server:)\n")); 
		if(server_settings_seen) {
			yyerror("duplicate server: element.");
		}
		server_settings_seen = 1;
	}
	;
contents_server: contents_server content_server | ;
content_server: server_ip_address | server_debug_mode | server_ip4_only | 
	server_ip6_only | server_database | server_identity | server_logfile | 
	server_server_count | server_tcp_count | server_pidfile | server_port | 
	server_statistics | server_chroot | server_username | server_zonesdir |
	server_difffile | server_xfrdfile | server_xfrd_reload_timeout;
server_ip_address: VAR_IP_ADDRESS STRING 
	{ 
		OUTYY(("P(server_ip_address:%s)\n", $2)); 
		if(cfg_parser->current_ip_address_option) {
			cfg_parser->current_ip_address_option->next = 
				(ip_address_option_t*)region_alloc(
				cfg_parser->opt->region, sizeof(ip_address_option_t));
			cfg_parser->current_ip_address_option = 
				cfg_parser->current_ip_address_option->next;
			cfg_parser->current_ip_address_option->next=0;
		} else {
			cfg_parser->current_ip_address_option = 
				(ip_address_option_t*)region_alloc(
				cfg_parser->opt->region, sizeof(ip_address_option_t));
			cfg_parser->current_ip_address_option->next=0;
			cfg_parser->opt->ip_addresses = cfg_parser->current_ip_address_option;
		}

		cfg_parser->current_ip_address_option->address = 
			region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_debug_mode: VAR_DEBUG_MODE STRING 
	{ 
		OUTYY(("P(server_debug_mode:%s)\n", $2)); 
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->opt->debug_mode = (strcmp($2, "yes")==0);
	}
	;
server_ip4_only: VAR_IP4_ONLY STRING 
	{ 
		OUTYY(("P(server_ip4_only:%s)\n", $2)); 
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->opt->ip4_only = (strcmp($2, "yes")==0);
	}
	;
server_ip6_only: VAR_IP6_ONLY STRING 
	{ 
		OUTYY(("P(server_ip6_only:%s)\n", $2)); 
		if(strcmp($2, "yes") != 0 && strcmp($2, "no") != 0)
			yyerror("expected yes or no.");
		else cfg_parser->opt->ip6_only = (strcmp($2, "yes")==0);
	}
	;
server_database: VAR_DATABASE STRING
	{ 
		OUTYY(("P(server_database:%s)\n", $2)); 
		cfg_parser->opt->database = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_identity: VAR_IDENTITY STRING
	{ 
		OUTYY(("P(server_identity:%s)\n", $2)); 
		cfg_parser->opt->identity = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_logfile: VAR_LOGFILE STRING
	{ 
		OUTYY(("P(server_logfile:%s)\n", $2)); 
		cfg_parser->opt->logfile = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_server_count: VAR_SERVER_COUNT STRING
	{ 
		OUTYY(("P(server_server_count:%s)\n", $2)); 
		if(atoi($2) <= 0)
			yyerror("number greater than zero expected");
		else cfg_parser->opt->server_count = atoi($2);
	}
	;
server_tcp_count: VAR_TCP_COUNT STRING
	{ 
		OUTYY(("P(server_tcp_count:%s)\n", $2)); 
		if(atoi($2) <= 0)
			yyerror("number greater than zero expected");
		else cfg_parser->opt->tcp_count = atoi($2);
	}
	;
server_pidfile: VAR_PIDFILE STRING
	{ 
		OUTYY(("P(server_pidfile:%s)\n", $2)); 
		cfg_parser->opt->pidfile = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_port: VAR_PORT STRING
	{ 
		OUTYY(("P(server_port:%s)\n", $2)); 
		cfg_parser->opt->port = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_statistics: VAR_STATISTICS STRING
	{ 
		OUTYY(("P(server_statistics:%s)\n", $2)); 
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		else cfg_parser->opt->statistics = atoi($2);
	}
	;
server_chroot: VAR_CHROOT STRING
	{ 
		OUTYY(("P(server_chroot:%s)\n", $2)); 
		cfg_parser->opt->chroot = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_username: VAR_USERNAME STRING
	{ 
		OUTYY(("P(server_username:%s)\n", $2)); 
		cfg_parser->opt->username = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_zonesdir: VAR_ZONESDIR STRING
	{ 
		OUTYY(("P(server_zonesdir:%s)\n", $2)); 
		cfg_parser->opt->zonesdir = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_difffile: VAR_DIFFFILE STRING
	{ 
		OUTYY(("P(server_difffile:%s)\n", $2)); 
		cfg_parser->opt->difffile = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_xfrdfile: VAR_XFRDFILE STRING
	{ 
		OUTYY(("P(server_xfrdfile:%s)\n", $2)); 
		cfg_parser->opt->xfrdfile = region_strdup(cfg_parser->opt->region, $2);
	}
	;
server_xfrd_reload_timeout: VAR_XFRD_RELOAD_TIMEOUT STRING
	{ 
		OUTYY(("P(server_xfrd_reload_timeout:%s)\n", $2)); 
		if(atoi($2) == 0 && strcmp($2, "0") != 0)
			yyerror("number expected");
		cfg_parser->opt->xfrd_reload_timeout = atoi($2);
	}
	;

/* zone: declaration */
zonestart: VAR_ZONE
	{ 
		OUTYY(("\nP(zone:)\n")); 
		if(cfg_parser->current_zone) {
			if(!cfg_parser->current_zone->name) 
				c_error("previous zone has no name");
			else {
				if(!nsd_options_insert_zone(cfg_parser->opt, 
					cfg_parser->current_zone))
					c_error("duplicate zone");
			}
			if(!cfg_parser->current_zone->zonefile) 
				c_error("previous zone has no zonefile");
		}
		cfg_parser->current_zone = zone_options_create(cfg_parser->opt->region);
		cfg_parser->current_allow_notify = 0;
		cfg_parser->current_request_xfr = 0;
		cfg_parser->current_notify = 0;
		cfg_parser->current_provide_xfr = 0;
	}
	;
contents_zone: contents_zone content_zone | content_zone;
content_zone: zone_name | zone_zonefile | zone_allow_notify | 
	zone_request_xfr | zone_notify | zone_provide_xfr;
zone_name: VAR_NAME STRING
	{ 
		OUTYY(("P(zone_name:%s)\n", $2)); 
#ifndef NDEBUG
		assert(cfg_parser->current_zone);
#endif
		cfg_parser->current_zone->name = region_strdup(cfg_parser->opt->region, $2);
	}
	;
zone_zonefile: VAR_ZONEFILE STRING
	{ 
		OUTYY(("P(zone_zonefile:%s)\n", $2)); 
#ifndef NDEBUG
		assert(cfg_parser->current_zone);
#endif
		cfg_parser->current_zone->zonefile = region_strdup(cfg_parser->opt->region, $2);
	}
	;
zone_allow_notify: VAR_ALLOW_NOTIFY STRING STRING
	{ 
		acl_options_t* acl = parse_acl_info($2, $3);
		OUTYY(("P(zone_allow_notify:%s %s)\n", $2, $3)); 
		if(cfg_parser->current_allow_notify)
			cfg_parser->current_allow_notify->next = acl;
		else
			cfg_parser->current_zone->allow_notify = acl;
		cfg_parser->current_allow_notify = acl;
	}
	;
zone_request_xfr: VAR_REQUEST_XFR STRING STRING
	{ 
		acl_options_t* acl = parse_acl_info($2, $3);
		OUTYY(("P(zone_request_xfr:%s %s)\n", $2, $3)); 
		if(acl->blocked) c_error("blocked address used for request-xfr");
		if(acl->rangetype!=acl_range_single) c_error("address range used for request-xfr");
		if(cfg_parser->current_request_xfr)
			cfg_parser->current_request_xfr->next = acl;
		else
			cfg_parser->current_zone->request_xfr = acl;
		cfg_parser->current_request_xfr = acl;
	}
	;
zone_notify: VAR_NOTIFY STRING STRING
	{ 
		acl_options_t* acl = parse_acl_info($2, $3);
		OUTYY(("P(zone_notify:%s %s)\n", $2, $3)); 
		if(acl->blocked) c_error("blocked address used for notify");
		if(acl->rangetype!=acl_range_single) c_error("address range used for notify");
		if(cfg_parser->current_notify)
			cfg_parser->current_notify->next = acl;
		else
			cfg_parser->current_zone->notify = acl;
		cfg_parser->current_notify = acl;
	}
	;
zone_provide_xfr: VAR_PROVIDE_XFR STRING STRING
	{ 
		acl_options_t* acl = parse_acl_info($2, $3);
		OUTYY(("P(zone_provide_xfr:%s %s)\n", $2, $3)); 
		if(cfg_parser->current_provide_xfr)
			cfg_parser->current_provide_xfr->next = acl;
		else
			cfg_parser->current_zone->provide_xfr = acl;
		cfg_parser->current_provide_xfr = acl;
	}
	;

/* key: declaration */
keystart: VAR_KEY
	{ 
		OUTYY(("\nP(key:)\n")); 
		if(cfg_parser->current_key) {
			if(!cfg_parser->current_key->name) c_error("previous key has no name");
			if(!cfg_parser->current_key->algorithm) c_error("previous key has no algorithm");
			if(!cfg_parser->current_key->secret) c_error("previous key has no secret blob");
			cfg_parser->current_key->next = key_options_create(cfg_parser->opt->region);
			cfg_parser->current_key = cfg_parser->current_key->next;
		} else {
			cfg_parser->current_key = key_options_create(cfg_parser->opt->region);
                	cfg_parser->opt->keys = cfg_parser->current_key;
		}
		cfg_parser->opt->numkeys++;
	}
	;
contents_key: contents_key content_key | content_key;
content_key: key_name | key_algorithm | key_secret;
key_name: VAR_NAME STRING
	{ 
		OUTYY(("P(key_name:%s)\n", $2)); 
#ifndef NDEBUG
		assert(cfg_parser->current_key);
#endif
		cfg_parser->current_key->name = region_strdup(cfg_parser->opt->region, $2);
	}
	;
key_algorithm: VAR_ALGORITHM STRING
	{ 
		OUTYY(("P(key_algorithm:%s)\n", $2)); 
#ifndef NDEBUG
		assert(cfg_parser->current_key);
#endif
		cfg_parser->current_key->algorithm = region_strdup(cfg_parser->opt->region, $2);
	}
	;
key_secret: VAR_SECRET STRING
	{ 
		OUTYY(("key_secret:%s)\n", $2)); 
#ifndef NDEBUG
		assert(cfg_parser->current_key);
#endif
		cfg_parser->current_key->secret = region_strdup(cfg_parser->opt->region, $2);
	}
	;

%%

/* true if ipv6 address, false if ipv4 */
static int parse_is_ipv6(const char* p)
{
	/* see if addr is ipv6 or ipv4 -- by : and . */
	while(*p) {
		if(*p == '.') return 0;
		if(*p == ':') return 1;
		++p;
	}
	return 0;
}

/* returns range type. mask is the 2nd part of the range */
static int parse_range_type(char* ip, char** mask)
{
	char *p;
	if((p=strchr(ip, '&'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_mask;
	}
	if((p=strchr(ip, '/'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_subnet;
	}
	if((p=strchr(ip, '-'))!=0) {
		*p = 0;
		*mask = p+1;
		return acl_range_minmax;
	}
	*mask = 0;
	return acl_range_single;
}

/* parses subnet mask, fills 0 mask as well */
static void parse_range_subnet(char* p, void* addr, int maxbits)
{
	int subnet_bits = atoi(p);
	uint8_t* addr_bytes = (uint8_t*)addr;
	if(subnet_bits == 0 && strcmp(p, "0")!=0) {
		c_error_msg("bad subnet range '%s'", p);
		return;
	}
	if(subnet_bits < 0 || subnet_bits > maxbits) {
		c_error_msg("subnet of %d bits out of range [0..%d]", subnet_bits, maxbits);
		return;
	}
	/* fill addr with n bits of 1s (struct has been zeroed) */
	while(subnet_bits >= 8) {
		*addr_bytes++ = 0xff;
		subnet_bits -= 8;
	}
	if(subnet_bits > 0) {
		uint8_t shifts[] = {0x0, 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc, 0xfe, 0xff};
		*addr_bytes = shifts[subnet_bits];
	}
}

static acl_options_t* parse_acl_info(char* ip, const char* key)
{
	char* p;
	acl_options_t* acl = (acl_options_t*)region_alloc(
		cfg_parser->opt->region, sizeof(acl_options_t));
	acl->next = 0;
	/* ip */
	acl->ip_address_spec = region_strdup(cfg_parser->opt->region, ip);
	acl->key_options = 0;
	acl->is_ipv6 = 0;
	acl->port = 0;
	memset(&acl->addr, 0, sizeof(union acl_addr_storage));
	memset(&acl->range_mask, 0, sizeof(union acl_addr_storage));
	if((p=strrchr(ip, '@'))!=0) {
		if(atoi(p+1) == 0) c_error("expected port number after '@'");
		else acl->port = atoi(p+1);
		*p=0;
	}
	acl->rangetype = parse_range_type(ip, &p);
	if(parse_is_ipv6(ip)) {
		acl->is_ipv6 = 1;
#ifdef INET6
		if(inet_pton(AF_INET6, ip, &acl->addr.addr6) != 1) 
			c_error_msg("Bad ip6 address '%s'", ip);
		if(acl->rangetype==acl_range_mask || acl->rangetype==acl_range_minmax) 
			if(inet_pton(AF_INET6, p, &acl->range_mask.addr6) != 1) 
				c_error_msg("Bad ip6 address mask '%s'", p);
		if(acl->rangetype==acl_range_subnet)
			parse_range_subnet(p, &acl->range_mask.addr6, 128);
#else
		c_error_msg("encountered IPv6 address '%s'.", ip);
#endif /* INET6 */
	} else {
		acl->is_ipv6 = 0;
		if(inet_pton(AF_INET, ip, &acl->addr.addr) != 1) 
			c_error_msg("Bad ip4 address '%s'", ip);
		if(acl->rangetype==acl_range_mask || acl->rangetype==acl_range_minmax) 
			if(inet_pton(AF_INET, p, &acl->range_mask.addr) != 1) 
				c_error_msg("Bad ip4 address mask '%s'", p);
		if(acl->rangetype==acl_range_subnet)
			parse_range_subnet(p, &acl->range_mask.addr, 32);
	}

	/* key */
	if(strcmp(key, "NOKEY")==0) {
		acl->nokey = 1;
		acl->blocked = 0;
		acl->key_name = 0;
	} else if(strcmp(key, "BLOCKED")==0) {
		acl->nokey = 0;
		acl->blocked = 1;
		acl->key_name = 0;
	} else {
		acl->nokey = 0;
		acl->blocked = 0;
		acl->key_name = region_strdup(cfg_parser->opt->region, key);
	}
	return acl;
}
