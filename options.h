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

struct nsd_options {
	const char *user_id;
	const char *database;
	const char *version;
	const char *identity;
	const char *directory;
	const char *pid_file;

	size_t listen_on_count;
	nsd_options_address_type **listen_on;
};
typedef struct nsd_options nsd_options_type;

/*
 * Load the NSD configuration from FILENAME.
 */
nsd_options_type *load_configuration(region_type *region, const char *filename);

#endif /* _OPTIONS_H_ */
