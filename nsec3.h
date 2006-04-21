/*
 * nsec3.h -- nsec3 handling.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef NSEC3_H
#define NSEC3_H

#include <config.h>
#ifdef NSEC3

struct domain;
struct dname;
struct region;
struct zone;
struct namedb;

/* 
 * Create the hashed name of the nsec3 record
 * for the given dname. 
 */
const struct dname *nsec3_hash_dname(struct region *region, 
	struct zone *zone, const struct dname *dname);

/* 
 * calculate prehash information for the given zone,
 * or all zones if zone == NULL 
 */
void prehash(struct namedb* db, struct zone* zone);

/* 
 * finds nsec3 that covers the given domain dname. 
 * returns true if the find is exact. 
 * hashname is the already hashed dname for the NSEC3.
 */
int nsec3_find_cover(struct namedb* db, struct zone* zone, 
	const struct dname* hashname, struct domain** result);

#endif /* NSEC3 */
#endif /* NSEC3_H*/
