/* rrl.h - Response Rate Limiting for NSD.
 * By W.C.A. Wijngaards
 * Copyright 2012, NLnet Labs.
 * BSD, see LICENSE.
 */
#ifndef RRL_H
#define RRL_H
#include "query.h"

/** Number of buckets */
#define RRL_BUCKETS 1000000

/**
 * Initialize rate limiting (for this child server process)
 */
void rrl_init(void);

/**
 * Process query that happens, the query structure contains the
 * information about the query and the answer.
 * returns true if the query is ratelimited.
 */
int rrl_process_query(query_type* query);

/**
 * Deny the query, with slip.
 * Returns DISCARD or PROCESSED(with TC flag).
 */
query_state_type rrl_slip(query_type* query);

/** for unit test, update rrl bucket; return rate */
uint32_t rrl_update(query_type* query, uint32_t hash, uint64_t source,
	int32_t now);

#endif /* RRL_H */
