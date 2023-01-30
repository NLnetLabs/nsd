/*
 * cat-zones-nsd.h -- catalog zone implementation for NSD
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#ifndef _CAT_ZONES_NSD_H_
#define _CAT_ZONES_NSD_H_
#include "cat-zones.h"
#include "config.h"
#include "dname.h"
#include "namedb.h"

/**
 * Implementation of struct catz_dname
 */
struct catz_dname {
	dname_type dname;
};

/**
 * Implementation of catz_catalog_zone
 */
struct catz_catalog_zone {
	struct zone zone;
};

#endif
