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
#include "udb.h"

/**
 * Implementation of struct catz_dname
 */
struct catz_dname {
	dname_type dname;
};
static inline const struct catz_dname *dname2catz_dname(const struct dname* d)
{ return (struct catz_dname*)d; }

/**
 * Implementation of catz_catalog_zone
 */
struct catz_catalog_zone {
	struct zone zone;
};
static inline struct catz_catalog_zone *zone2catz_catalog_zone(struct zone* z)
{ return (struct catz_catalog_zone*)z; }

int nsd_catalog_consumer_process(
	struct nsd *nsd, 
	struct zone *zone,
	udb_base* udb,
	udb_ptr* last_task
);

#endif
