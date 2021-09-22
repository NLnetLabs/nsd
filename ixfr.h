/*
 * ixfr.h -- generating IXFR responses.
 *
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _IXFR_H_
#define _IXFR_H_
struct nsd;
#include "query.h"
struct ixfr_data;

/* data structure that stores IXFR contents for a zone. */
struct zone_ixfr {
	/* the IXFR that is available for this zone */
	struct ixfr_data* data;
};

/* Data structure that stores one IXFR.
 * The RRs are stored in uncompressed wireformat, that means
 * an uncompressed domain name, type, class, TTL, rdatalen,
 * uncompressed rdata in wireformat. */
struct ixfr_data {
	/* from what serial the IXFR starts from, the 'old' serial */
	uint32_t oldserial;
	/* where to IXFR goes to, the 'new' serial */
	uint32_t newserial;
	/* the new SOA record, with newserial */
	uint8_t* newsoa;
	/* byte length of the uncompressed wireformat RR in newsoa */
	size_t newsoa_len;
	/* the old SOA record, with oldserial */
	uint8_t* oldsoa;
	/* byte length of the uncompressed wireformat RR in oldsoa*/
	size_t oldsoa_len;
	/* the deleted RRs, ends with the newserial SOA record.
	 * if the ixfr is collated out multiple versions, then
	 * this deleted RRs section contains several add and del sections
	 * for the older versions, and ends with the last del section,
	 * and the SOA record with the newserial.
	 * That is everything except the final add section for newserial. */
	uint8_t* del;
	/* byte length of the uncompressed wireformat RRs in del */
	size_t del_len;
	/* the added RRs, ends with the newserial SOA record. */
	uint8_t* add;
	/* byte length of the uncompressed wireformat RRs in add */
	size_t add_len;
};

/* process queries in IXFR state */
query_state_type query_ixfr(struct nsd *nsd, struct query *query);

#endif /* _IXFR_H_ */
