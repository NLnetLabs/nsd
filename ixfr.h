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
struct zone;
struct buffer;
struct region;

/* data structure that stores IXFR contents for a zone. */
struct zone_ixfr {
	/* the IXFR that is available for this zone */
	struct ixfr_data* data;
	/* total size stored at this time, in bytes,
	 * sum of sizes of the ixfr data elements */
	size_t total_size;
};

/* Data structure that stores one IXFR.
 * The RRs are stored in uncompressed wireformat, that means
 * an uncompressed domain name, type, class, TTL, rdatalen,
 * uncompressed rdata in wireformat.
 *
 * The data structure is formatted like this so that making an IXFR
 * that moves across several versions can be done by collating the
 * pieces precisely from the versions involved. In particular, for
 * an IXFR from olddata to newdata, for a combined output:
 * newdata.newsoa olddata.oldsoa olddata.del olddata.add
 * newdata.del newdata.add
 * in sequence should produce a valid, non-condensed, IXFR with multiple
 * versions inside.
 */
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

/*
 * While an IXFR is processed, in incoming IXFR that is downloaded by NSD,
 * this structure keeps track of how to store the data from it. That data
 * can then be used to answer IXFR queries.
 *
 * The structure keeps track of allocation data for the IXFR records.
 * If it is cancelled, that is flagged so storage stops.
 */
struct ixfr_store {
	/* the zone info, with options and zone ixfr reference */
	struct zone* zone;
	/* are we cancelled, it is not an IXFR, no need to store information
	 * any more. */
	int cancelled;
	/* the ixfr data that we are storing into */
	struct ixfr_data* data;
	/* capacity for the delrrs storage, size of ixfr del allocation */
	size_t del_capacity;
	/* capacity for the addrrs storage, size of ixfr add allocation */
	size_t add_capacity;
};

/*
 * Start the storage of the IXFR data from this IXFR.
 * If it returns NULL, the IXFR storage stops. On malloc failure, the
 * storage is returned NULL, or cancelled if failures happen later on.
 *
 * When done, the finish routine links the data into the memory for the zone.
 * If it turns out to not be used, use the cancel routine. Or the free
 * routine if the ixfr_store itself needs to be deleted too, like on error.
 *
 * zone: the zone structure
 * ixfr_store_mem: preallocated by caller, used to allocate the store struct.
 * old_serial: the start serial of the IXFR.
 * new_serial: the end serial of the IXFR.
 * return NULL or a fresh ixfr_store structure for adding records to the
 * 	IXFR with this serial number. The NULL is on error.
 */
struct ixfr_store* ixfr_store_start(struct zone* zone,
	struct ixfr_store* ixfr_store_mem, uint32_t old_serial,
	uint32_t new_serial);

/*
 * Cancel the ixfr store in progress. The pointer remains valid, no store done.
 * ixfr_store: this is set to cancel.
 */
void ixfr_store_cancel(struct ixfr_store* ixfr_store);

/*
 * Free ixfr store structure, it is no longer used.
 * ixfr_store: deleted
 */
void ixfr_store_free(struct ixfr_store* ixfr_store);

/*
 * Finish ixfr store processing. Links the data into the zone ixfr data.
 * ixfr_store: Data is linked into the zone struct. The ixfr_store is freed.
 * log_buf: log string for the update.
 * time_start_0: time when download initiated, sec.
 * time_start_1: time when download initiated, nsec.
 * time_end_0: time when download finished, sec.
 * time_end_1: time when download finished, nsec.
 */
void ixfr_store_finish(struct ixfr_store* ixfr_store, char* log_buf,
	uint64_t time_start_0, uint32_t time_start_1, uint64_t time_end_0,
	uint32_t time_end_1);

/*
 * Add the new SOA record to the ixfr store.
 * ixfr_store: stores ixfr data that is collected.
 * packet: DNS packet that contains the SOA. position restored on function
 * 	exit.
 * ttlpos: position, just before the ttl, rdatalen, rdata of the SOA record.
 * 	we do not need to pass the name, because that is the zone name, or
 * 	the type or class of the record, because we already know.
 */
void ixfr_store_add_newsoa(struct ixfr_store* ixfr_store,
	struct buffer* packet, size_t ttlpos);

/*
 * Add the old SOA record to the ixfr store.
 * ixfr_store: stores ixfr data that is collected.
 * ttl: the TTL of the SOA record
 * packet: DNS packet that contains the SOA. position restored on function
 * 	exit.
 * rrlen: wire rdata length of the SOA.
 */
void ixfr_store_add_oldsoa(struct ixfr_store* ixfr_store, uint32_t ttl,
	struct buffer* packet, size_t rrlen);

void ixfr_store_delrr(struct ixfr_store* ixfr_store, const struct dname* dname,
	uint16_t type, uint16_t klass, uint32_t ttl, struct buffer* packet,
	uint16_t rrlen, struct region* temp_region);
void ixfr_store_addrr(struct ixfr_store* ixfr_store, const struct dname* dname,
	uint16_t type, uint16_t klass, uint32_t ttl, struct buffer* packet,
	uint16_t rrlen, struct region* temp_region);

/* return if the zone has ixfr storage enabled for it */
int zone_is_ixfr_enabled(struct zone* zone);

/* create new zone_ixfr structure */
struct zone_ixfr* zone_ixfr_create(void);

/* free the zone_ixfr */
void zone_ixfr_free(struct zone_ixfr* ixfr);

/* remove ixfr data from the zone_ixfr */
void zone_ixfr_remove(struct zone_ixfr* ixfr);

/* add ixfr data to the zone_ixfr */
void zone_ixfr_add(struct zone_ixfr* ixfr, struct ixfr_data* data);

#endif /* _IXFR_H_ */
