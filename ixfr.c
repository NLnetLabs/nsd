/*
 * ixfr.c -- generating IXFR responses.
 *
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include "ixfr.h"
#include "packet.h"

/*
 * For optimal compression IXFR response packets are limited in size
 * to MAX_COMPRESSION_OFFSET.
 */
#define IXFR_MAX_MESSAGE_LEN MAX_COMPRESSION_OFFSET

query_state_type query_ixfr(struct nsd *nsd, struct query *query)
{
}
