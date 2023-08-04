/*
 * cat-zones-nsd.h -- catalog zone implementation for NSD
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#ifndef _CAT_ZONES_NSD_H_
#define _CAT_ZONES_NSD_H_
#include "config.h"
#include "dname.h"
#include "namedb.h"
#include "udb.h"

void nsd_catalog_consumer_process(
	struct nsd *nsd, 
	struct zone *zone,
	udb_base* udb,
	udb_ptr* last_task
);

#endif
