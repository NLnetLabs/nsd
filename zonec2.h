/*
 * $Id: zonec2.h,v 1.4 2003/10/17 13:51:31 erik Exp $
 *
 * zonec2.h -- internal zone representation.
 *
 * Copyright (c) 2001- 2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include "dname.h"
#include "region-allocator.h"
#include "zparser2.h"

/*
 * This region is deallocated after each zone is parsed and analyzed.
 */
extern region_type *zone_region;

/*
 * This region is deallocated after each RR is parsed and analyzed.
 */
extern region_type *rr_region;

struct zone {
	struct namedb *db;
	const dname_type *dname;
	struct rrset *soa;
	struct rrset *ns;
};

extern struct zone *current_zone;

#define LINEBUFSZ 1024

int process_rr(struct zone *z, rr_type *rr);

#endif /* _ZONEC_H_ */
