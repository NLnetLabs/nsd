/*
 * options.c -- options functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include <config.h>
#include <string.h>
#include <errno.h>
#include "options.h"

#include "configyyrename.h"
#include "configparser.h"
nsd_options_t* nsd_options = 0;
config_parser_state_t* cfg_parser = 0;
extern FILE* c_in, *c_out;
int c_parse(void);
int c_lex(void);
int c_wrap(void);
void c_error(const char *message);

nsd_options_t* nsd_options_create(region_type* region)
{
	nsd_options_t* opt;
	opt = (nsd_options_t*)region_alloc(region, sizeof(nsd_options_t));
	opt->region = region;
	opt->zone_options = NULL;
	opt->numzones = 0;
	opt->keys = NULL;
	opt->numkeys = 0;
	opt->ip_addresses = NULL;
	opt->debug_mode = 0;
	opt->ip4_only = 0;
	opt->ip6_only = 0;
	opt->database = DBFILE;
	opt->identity = IDENTITY;
	opt->logfile = 0;
	opt->server_count = 1;
	opt->tcp_count = 10;
	opt->pidfile = PIDFILE;
	opt->port = UDP_PORT;
	opt->port = TCP_PORT;
	opt->statistics = 0;
	opt->chroot = 0;
	opt->username = USER;
	opt->zonesdir = 0;
	nsd_options = opt;
	return opt;
}

int parse_options_file(nsd_options_t* opt, const char* file)
{
	FILE *in = 0;
	zone_options_t* zone;
	acl_options_t* acl;

	if(!cfg_parser) 
		cfg_parser = (config_parser_state_t*)region_alloc(
			opt->region, sizeof(config_parser_state_t));
	cfg_parser->filename = file;
	cfg_parser->line = 1;
	cfg_parser->errors = 0;
	cfg_parser->opt = opt;
	cfg_parser->current_zone = opt->zone_options;
	while(cfg_parser->current_zone && cfg_parser->current_zone->next)
		cfg_parser->current_zone = cfg_parser->current_zone->next;
	cfg_parser->current_key = opt->keys;
	while(cfg_parser->current_key && cfg_parser->current_key->next)
		cfg_parser->current_key = cfg_parser->current_key->next;
	cfg_parser->current_ip_address_option = opt->ip_addresses;
	while(cfg_parser->current_ip_address_option && cfg_parser->current_ip_address_option->next)
		cfg_parser->current_ip_address_option = cfg_parser->current_ip_address_option->next;
	cfg_parser->current_allow_notify = 0;
	cfg_parser->current_request_xfr = 0;
	cfg_parser->current_notify = 0;
	cfg_parser->current_provide_xfr = 0;

	in = fopen(cfg_parser->filename, "r");
	if(!in) {
		fprintf(stderr, "Could not open %s: %s\n", file, strerror(errno));
		return 0;
	}
	c_in = in;
        c_parse();
	fclose(in);

	if(opt->zone_options) {
		if(!opt->zone_options->name) c_error("last zone has no name");
		if(!opt->zone_options->zonefile) c_error("last zone has no zonefile");
	}
	if(opt->keys)
	{
		if(!opt->keys->name) c_error("last key has no name");
		if(!opt->keys->algorithm) c_error("last key has no algorithm");
		if(!opt->keys->secret) c_error("last key has no secret blob");
	}
	for(zone=opt->zone_options; zone; zone=zone->next)
	{
		if(!zone->name) continue;
		if(!zone->zonefile) continue;
		/* lookup keys for acls */
		for(acl=zone->allow_notify; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked) continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options) 
				c_error_msg("key %s in zone %s could not be found",
					acl->key_name, zone->name);
		}
		for(acl=zone->notify; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked) continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options) 
				c_error_msg("key %s in zone %s could not be found",
					acl->key_name, zone->name);
		}
		for(acl=zone->request_xfr; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked) continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options) 
				c_error_msg("key %s in zone %s could not be found",
					acl->key_name, zone->name);
		}
		for(acl=zone->provide_xfr; acl; acl=acl->next)
		{
			if(acl->nokey || acl->blocked) continue;
			acl->key_options = key_options_find(opt, acl->key_name);
			if(!acl->key_options) 
				c_error_msg("key %s in zone %s could not be found",
					acl->key_name, zone->name);
		}
	}
	
	if(cfg_parser->errors > 0)
	{
        	fprintf(stderr, "read %s failed: %d errors in configuration file\n", 
			cfg_parser->filename,
			cfg_parser->errors);
		return 0;
	}
	return 1;
}

void c_error_va_list(const char *fmt, va_list args)
{
	cfg_parser->errors++;
        fprintf(stderr, "%s:%d: error: ", cfg_parser->filename,
		cfg_parser->line);
	vfprintf(stderr, fmt, args);
	fprintf(stderr, "\n");
}

void c_error_msg(const char* fmt, ...)
{
        va_list args;
        va_start(args, fmt);
        c_error_va_list(fmt, args);
        va_end(args);
}

void c_error(const char *str)
{
	cfg_parser->errors++;
        fprintf(stderr, "%s:%d: error: %s\n", cfg_parser->filename,
		cfg_parser->line, str);
}

int c_wrap()
{
        return 1;
}

zone_options_t* zone_options_create(region_type* region)
{
	zone_options_t* zone;
	zone = (zone_options_t*)region_alloc(region, sizeof(zone_options_t));
	zone->next = 0;
	zone->name = 0;
	zone->zonefile = 0;
	zone->allow_notify = 0;
	zone->request_xfr = 0;
	zone->notify = 0;
	zone->provide_xfr = 0;
	return zone;
}

key_options_t* key_options_create(region_type* region)
{
	key_options_t* key;
	key = (key_options_t*)region_alloc(region, sizeof(key_options_t));
	key->name = 0;
	key->next = 0;
	key->algorithm = 0;
	key->secret = 0;
	return key;
}

key_options_t* key_options_find(nsd_options_t* opt, const char* name)
{
	key_options_t* key = opt->keys;
	while(key) {
		if(strcmp(key->name, name)==0) return key;
		key = key->next;
	}
	return 0;
}
