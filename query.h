/*
 * query.h -- manipulation with the queries
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _QUERY_H_
#define _QUERY_H_

#include <assert.h>
#include <string.h>

#include "namedb.h"
#include "nsd.h"

/*
 * Set of macro's to deal with the dns message header as specified
 * in RFC1035 in portable way.
 *
 */

/*
 *
 *                                    1  1  1  1  1  1
 *      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                      ID                       |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |QR|   Opcode  |AA|TC|RD|RA| Z|AD|CD|   RCODE   |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    QDCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ANCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    NSCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *    |                    ARCOUNT                    |
 *    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 */

/* The length of the header */
#define	QHEADERSZ	12

/* First octet of flags */
#define	RD_MASK		0x01U
#define	RD_SHIFT	0
#define	RD(packet)      (*buffer_at((packet), 2) & RD_MASK)
#define	RD_SET(packet)	(*buffer_at((packet), 2) |= RD_MASK)
#define	RD_CLR(packet)	(*buffer_at((packet), 2) &= ~RD_MASK)

#define TC_MASK		0x02U
#define TC_SHIFT	1
#define	TC(packet)	(*buffer_at((packet), 2) & TC_MASK)
#define	TC_SET(packet)	(*buffer_at((packet), 2) |= TC_MASK)
#define	TC_CLR(packet)	(*buffer_at((packet), 2) &= ~TC_MASK)

#define	AA_MASK		0x04U
#define	AA_SHIFT	2
#define	AA(packet)	(*buffer_at((packet), 2) & AA_MASK)
#define	AA_SET(packet)	(*buffer_at((packet), 2) |= AA_MASK)
#define	AA_CLR(packet)	(*buffer_at((packet), 2) &= ~AA_MASK)

#define	OPCODE_MASK	0x78U
#define	OPCODE_SHIFT	3
#define	OPCODE(packet)	((*buffer_at((packet), 2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define	OPCODE_SET(packet, opcode) \
	(*buffer_at((packet), 2) = (*buffer_at((packet), 2) & ~OPCODE_MASK) | ((opcode) << OPCODE_SHIFT))

#define	QR_MASK		0x80U
#define	QR_SHIFT	7
#define	QR(packet)	(*buffer_at((packet), 2) & QR_MASK)
#define	QR_SET(packet)	(*buffer_at((packet), 2) |= QR_MASK)
#define	QR_CLR(packet)	(*buffer_at((packet), 2) &= ~QR_MASK)

/* Second octet of flags */
#define	RCODE_MASK	0x0fU
#define	RCODE_SHIFT	0
#define	RCODE(packet)	(*buffer_at((packet), 3) & RCODE_MASK)
#define	RCODE_SET(packet, rcode) \
	(*buffer_at((packet), 3) = (*buffer_at((packet), 3) & ~RCODE_MASK) | (rcode))

#define	CD_MASK		0x10U
#define	CD_SHIFT	4
#define	CD(packet)	(*buffer_at((packet), 3) & CD_MASK)
#define	CD_SET(packet)	(*buffer_at((packet), 3) |= CD_MASK)
#define	CD_CLR(packet)	(*buffer_at((packet), 3) &= ~CD_MASK)

#define	AD_MASK		0x20U
#define	AD_SHIFT	5
#define	AD(packet)	(*buffer_at((packet), 3) & AD_MASK)
#define	AD_SET(packet)	(*buffer_at((packet), 3) |= AD_MASK)
#define	AD_CLR(packet)	(*buffer_at((packet), 3) &= ~AD_MASK)

#define	Z_MASK		0x40U
#define	Z_SHIFT		6
#define	Z(packet)	(*buffer_at((packet), 3) & Z_MASK)
#define	Z_SET(packet)	(*buffer_at((packet), 3) |= Z_MASK)
#define	Z_CLR(packet)	(*buffer_at((packet), 3) &= ~Z_MASK)

#define	RA_MASK		0x80U
#define	RA_SHIFT	7
#define	RA(packet)	(*buffer_at((packet), 3) & RA_MASK)
#define	RA_SET(packet)	(*buffer_at((packet), 3) |= RA_MASK)
#define	RA_CLR(packet)	(*buffer_at((packet), 3) &= ~RA_MASK)

/* Query ID */
#define	ID(packet)		(buffer_read_u16_at((packet), 0))
#define	ID_SET(packet, id)	(buffer_write_u16_at((packet), 0, (id)))

/* Flags, RCODE, and OPCODE. */
#define FLAGS(packet)		(buffer_read_u16_at((packet), 2))
#define FLAGS_SET(packet, f)	(buffer_write_u16_at((packet), 2, (f)))

/* Counter of the question section */
#define	QDCOUNT(packet)		(buffer_read_u16_at((packet), 4))
#define QDCOUNT_SET(packet, c)	(buffer_write_u16_at((packet), 4, (c)))

/* Counter of the answer section */
#define	ANCOUNT(packet)		(buffer_read_u16_at((packet), 6))
#define ANCOUNT_SET(packet, c)	(buffer_write_u16_at((packet), 6, (c)))

/* Counter of the authority section */
#define	NSCOUNT(packet)		(buffer_read_u16_at((packet), 8))
#define NSCOUNT_SET(packet, c)	(buffer_write_u16_at((packet), 8, (c)))

/* Counter of the additional section */
#define	ARCOUNT(packet)		(buffer_read_u16_at((packet), 10))
#define ARCOUNT_SET(packet, c)	(buffer_write_u16_at((packet), 10, (c)))

/* Miscelaneous limits */
#define MAX_PACKET_SIZE         65535   /* Maximum supported size of DNS packets.  */

#define	QIOBUFSZ		(MAX_PACKET_SIZE + MAX_RR_SIZE)

#define	MAXRRSPP		10240    /* Maximum number of rr's per packet */
#define MAX_COMPRESSED_DNAMES	MAXRRSPP /* Maximum number of compressed domains. */


enum query_state {
	QUERY_PROCESSED,
	QUERY_DISCARDED,
	QUERY_IN_AXFR
};
typedef enum query_state query_state_type;

/* Query as we pass it around */
typedef struct query query_type;
struct query {
	/*
	 * Memory region freed whenever the query is reset.
	 */
	region_type *region;

	/*
	 * The address the query was received from.
	 */
#ifdef INET6
	struct sockaddr_storage addr;
#else
	struct sockaddr_in addr;
#endif
	socklen_t addrlen;

	/*
	 * Maximum supported query size.
	 */
	size_t maxlen;

	/*
	 * Space reserved for optional records like EDNS.
	 */
	size_t reserved_space;

	/* EDNS information provided by the client.  */
	edns_record_type edns;

	int tcp;
	uint16_t tcplen;

	buffer_type *packet;

	/* Normalized query domain name.  */
	const dname_type *name;

	/* The zone used to answer the query.  */
	zone_type *zone;
	
	/* The domain used to answer the query.  */
	domain_type *domain;

	/* The delegation domain, if any.  */
	domain_type *delegation_domain;

	/* The delegation NS rrset, if any.  */
	rrset_type *delegation_rrset;

	/* Original opcode.  */
	uint8_t opcode;
	
	/* Query class and type in host byte order.  */
	uint16_t klass;
	uint16_t type;

	/*
	 * The number of CNAMES followed.  After a CNAME is followed
	 * we no longer change the RCODE to NXDOMAIN and no longer add
	 * SOA records to the authority section in case of NXDOMAIN
	 * and NODATA.
	 */
	int cname_count;
	
	/* Used for dname compression.  */
	uint16_t     compressed_dname_count;
	domain_type *compressed_dnames[MAXRRSPP];

	 /*
	  * Indexed by domain->number, index 0 is reserved for the
	  * query name when generated from a wildcard record.
	  */
	uint16_t    *compressed_dname_offsets;

	/*
	 * Used for AXFR processing.
	 */
	int          axfr_is_done;
	zone_type   *axfr_zone;
	domain_type *axfr_current_domain;
	rrset_type  *axfr_current_rrset;
	uint16_t     axfr_current_rr;
};


/* Check if the last write resulted in an overflow.  */
static inline int query_overflow(struct query *q);

/*
 * Store the offset of the specified domain in the dname compression
 * table.
 */
void query_put_dname_offset(struct query *query,
			    domain_type  *domain,
			    uint16_t      offset);
/*
 * Lookup the offset of the specified domain in the dname compression
 * table.  Offset 0 is used to indicate the domain is not yet in the
 * compression table.
 */
static inline
uint16_t query_get_dname_offset(struct query *query, domain_type *domain)
{
	return query->compressed_dname_offsets[domain->number];
}

/*
 * Remove all compressed dnames that have an offset that points beyond
 * the end of the current answer.  This must be done after some RRs
 * are truncated and before adding new RRs.  Otherwise dnames may be
 * compressed using truncated data!
 */
void query_clear_dname_offsets(struct query *query, size_t max_offset);

/*
 * Clear the compression tables.
 */
void query_clear_compression_tables(struct query *query);
	
/*
 * Enter the specified domain into the compression table starting at
 * the specified offset.
 */
void query_add_compression_domain(struct query *query,
				  domain_type  *domain,
				  uint16_t      offset);


/*
 * Create a new query structure.
 */
query_type *query_create(region_type *region,
			 uint16_t *compressed_dname_offsets);

/*
 * Reset a query structure so it is ready for receiving and processing
 * a new query.
 */
void query_reset(query_type *query, size_t maxlen, int is_tcp);

/*
 * Process a query and write the response in the query I/O buffer.
 */
query_state_type query_process(query_type *q, nsd_type *nsd);

/*
 * Prepare the query structure for writing the response. The packet
 * data up-to the current packet limit is preserved. This usually
 * includes the packet header and question section. Space is reserved
 * for the optional EDNS record, if required.
 */
void query_prepare_response(query_type *q);

/*
 * Add EDNS0 information to the response if required.
 */
void query_add_optional(query_type *q, nsd_type *nsd);

/*
 * Write an error response into the query structure with the indicated
 * RCODE.
 */
query_state_type query_error(query_type *q, nsd_rc_type rcode);

static inline int
query_overflow(query_type *q)
{
	return buffer_position(q->packet) > (q->maxlen - q->reserved_space);
}

#endif /* _QUERY_H_ */
