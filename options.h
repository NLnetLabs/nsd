/*
 * options.h -- maintain NSD configuration information.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _OPTIONS_H_
#define _OPTIONS_H_

#include "dname.h"
#include "region-allocator.h"

struct nsd_options_address {
	int family;
	const char *port;
	const char *address;
};
typedef struct nsd_options_address nsd_options_address_type;

struct nsd_options_address_list
{
	size_t count;
	nsd_options_address_type **addresses;
};
typedef struct nsd_options_address_list nsd_options_address_list_type;

struct nsd_options_key {
	const char *name;
	const char *algorithm;
	const char *secret;
};
typedef struct nsd_options_key nsd_options_key_type;

struct nsd_options_master {
	nsd_options_key_type *key;
	nsd_options_address_list_type *addresses;
};
typedef struct nsd_options_master nsd_options_master_type;

struct nsd_options_zone {
	const dname_type *name;
	const char *file;

	size_t master_count;
	nsd_options_master_type **masters;

	nsd_options_address_list_type *notify;
};
typedef struct nsd_options_zone nsd_options_zone_type;

struct nsd_options {
	region_type *region;

	const char *user_id;
	const char *database;
	const char *version;
	const char *identity;
	const char *directory;
	const char *chroot_directory;
	const char *log_file;
	const char *pid_file;

	unsigned statistics_period;
	size_t server_count;
	size_t maximum_tcp_connection_count;

	nsd_options_address_list_type *listen_on;
	nsd_options_address_list_type *controls;

	size_t key_count;
	nsd_options_key_type **keys;

	size_t zone_count;
	nsd_options_zone_type **zones;
};
typedef struct nsd_options nsd_options_type;

/*
 * Load the NSD configuration from FILENAME.
 */
nsd_options_type *nsd_load_config(region_type *region, const char *filename);

nsd_options_address_type *options_address_make(region_type *region,
					       int family,
					       const char *port,
					       const char *address);

nsd_options_zone_type *nsd_options_find_zone(nsd_options_type *options,
					     const dname_type *name);

#endif /* _OPTIONS_H_ */
