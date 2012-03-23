/*
 * verify.c -- running verifiers and serving the zone to be verified.
 *
 * Copyright (c) 2012, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef NSD_VERIFY_H
#define NSD_VERIFY_H
#include "nsd.h"

void server_verify_zones( nsd_type* nsd
			, int cmdsocket
			, size_t* good_zones
			, size_t* bad_zones
			);

#endif /* NSD_VERIFY_H */

