/*
 * axfr.h -- generating AXFR responses.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _AXFR_H_
#define _AXFR_H_

#include "nsd.h"
#include "query.h"

query_state_type answer_axfr_ixfr(struct nsd *nsd, struct query *q);
query_state_type query_axfr(struct nsd *nsd, struct query *query);

#endif /* _AXFR_H_ */
