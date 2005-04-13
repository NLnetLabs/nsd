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

#include "region-allocator.h"

struct nsd_options_address {
	int family;
	const char *port;
	const char *address;
};
typedef struct nsd_options_address nsd_options_address_type;

struct nsd_options_key {
	const char *name;
	const char *algorithm;
	const char *secret;
};
typedef struct nsd_options_key nsd_options_key_type;

struct nsd_options_zone {
	const char *apex;
	const char *filename;
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

	size_t listen_on_count;
	nsd_options_address_type **listen_on;

	size_t controls_count;
	nsd_options_address_type **controls;

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

#endif /* _OPTIONS_H_ */
