/*
 * $Id: zonec2.h,v 1.5 2003/10/22 07:07:57 erik Exp $
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

#define LINEBUFSZ 1024

int process_rr(zparser_type *parser, rr_type *rr);

#endif /* _ZONEC_H_ */
