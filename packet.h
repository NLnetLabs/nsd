/*
 * packet.h -- low-level DNS packet encoding and decoding functions.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _PACKET_H_
#define _PACKET_H_

#include <sys/types.h>

#include "dns.h"
#include "namedb.h"
#include "query.h"

/*
 * Encode RR with OWNER as owner name into QUERY.  Returns the number
 * of RRs successfully encoded.
 */
int packet_encode_rr(query_type *query, domain_type *owner, rr_type *rr);

/*
 * Encode RRSET with OWNER as the owner name into QUERY.  Returns the
 * number of RRs successfully encoded.  If TRUNCATE_RRSET the entire
 * RRset is truncated in case an RR (or the RRsets signature) does not
 * fit.
 */
int packet_encode_rrset(query_type *query,
			domain_type *owner,
			rrset_type *rrset,
			int truncate_rrset);

/*
 * Skip the RR at the current position in PACKET.
 */
int packet_skip_rr(buffer_type *packet, int question_section);

/*
 * Read the RR at the current position in PACKET.
 */
rr_type *packet_read_rr(region_type *region,
			domain_table_type *owners,
			buffer_type *packet,
			int question_section);

#endif /* _PACKET_H_ */
