/*
 * query.h -- manipulation with the queries
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _QUERY_H_
#define _QUERY_H_

#include <assert.h>
#include <string.h>

#include "dname.h"
#include "namedb.h"
#include "nsd.h"
#include "region-allocator.h"

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
 *    |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
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
#define	RD(query)	(*(query->iobuf+2) & RD_MASK)
#define	RD_SET(query)	*(query->iobuf+2) |= RD_MASK
#define	RD_CLR(query)	*(query->iobuf+2) &= ~RD_MASK

#define TC_MASK		0x02U
#define TC_SHIFT	1
#define	TC(query)	(*(query->iobuf+2) & TC_MASK)
#define	TC_SET(query)	*(query->iobuf+2) |= TC_MASK
#define	TC_CLR(query)	*(query->iobuf+2) &= ~TC_MASK

#define	AA_MASK		0x04U
#define	AA_SHIFT	2
#define	AA(query)	(*(query->iobuf+2) & AA_MASK)
#define	AA_SET(query)	*(query->iobuf+2) |= AA_MASK
#define	AA_CLR(query)	*(query->iobuf+2) &= ~AA_MASK

#define	OPCODE_MASK	0x78U
#define	OPCODE_SHIFT	3
#define	OPCODE(query)	((*(query->iobuf+2) & OPCODE_MASK) >> OPCODE_SHIFT)
#define	OPCODE_SET(query, opcode) \
	*(query->iobuf+2) = ((*(query->iobuf+2)) & ~OPCODE_MASK) | (opcode << OPCODE_SHIFT)

#define	QR_MASK		0x80U
#define	QR_SHIFT	7
#define	QR(query)	(*(query->iobuf+2) & QR_MASK)
#define	QR_SET(query)	*(query->iobuf+2) |= QR_MASK
#define	QR_CLR(query)	*(query->iobuf+2) &= ~QR_MASK

#define	RCODE_MASK	0x0fU
#define	RCODE_SHIFT	0
#define	RCODE(query)	(*(query->iobuf+3) & RCODE_MASK)
#define	RCODE_SET(query, rcode) \
	*(query->iobuf+3) = ((*(query->iobuf+3)) & ~RCODE_MASK) | rcode

#define	Z_MASK		0x70U
#define	Z_SHIFT		4
#define	Z(query)	(*(query->iobuf+3) & Z_MASK)
#define	Z_SET(query, z) \
	*(query->iobuf+3) = ((*(query->iobuf+3)) & ~Z_MASK) | z

/* Second octet of flags */
#define	RA_MASK		0x80U
#define	RA_SHIFT	7
#define	RA(query)	(*(query->iobuf+3) & RA_MASK)
#define	RA_SET(query)	*(query->iobuf+3) |= RA_MASK
#define	RA_CLR(query)	*(query->iobuf+3) &= ~RA_MASK

/* Query ID */
#define	ID(query)		(*(uint16_t *)(query->iobuf))

/* Counter of the question section */
#define QDCOUNT_OFF		4
#define	QDCOUNT(query)		(*(uint16_t *)(query->iobuf+QDCOUNT_OFF))

/* Counter of the answer section */
#define ANCOUNT_OFF		6
#define	ANCOUNT(query)		(*(uint16_t *)(query->iobuf+ANCOUNT_OFF))

/* Counter of the authority section */
#define NSCOUNT_OFF		8
#define	NSCOUNT(query)		(*(uint16_t *)(query->iobuf+NSCOUNT_OFF))

/* Counter of the additional section */
#define ARCOUNT_OFF		10
#define	ARCOUNT(query)		(*(uint16_t *)(query->iobuf+ARCOUNT_OFF))

/* Possible OPCODE values */
#define	OPCODE_QUERY		0 	/* a standard query (QUERY) */
#define OPCODE_IQUERY		1 	/* an inverse query (IQUERY) */
#define OPCODE_STATUS		2 	/* a server status request (STATUS) */
#define OPCODE_NOTIFY		4 	/* NOTIFY */
#define OPCODE_UPDATE		5 	/* Dynamic update */

/* Possible RCODE values */
#define	RCODE_OK		0 	/* No error condition */
#define RCODE_FORMAT		1 	/* Format error */
#define RCODE_SERVFAIL		2 	/* Server failure */
#define RCODE_NXDOMAIN		3 	/* Name Error */
#define RCODE_IMPL		4 	/* Not implemented */
#define RCODE_REFUSE		5 	/* Refused */

/* Miscelaneous limits */
#define	QIOBUFSZ		16384	 /* Maximum size of returned packet.  */
#define	MAXLABELLEN		63
#define	MAXDOMAINLEN		255
#define	MAXRRSPP		10240    /* Maximum number of rr's per packet */
#define MAX_COMPRESSED_DNAMES	MAXRRSPP /* Maximum number of compressed domains. */


enum query_state {
	QUERY_PROCESSED,
	QUERY_DISCARDED,
	QUERY_IN_AXFR
};
typedef enum query_state query_state_type;

/* Query as we pass it around */
struct query {
	/* Memory region freed after each query is processed. */
	region_type *region;
#ifdef INET6
	struct sockaddr_storage addr;
#else
	struct sockaddr_in addr;
#endif
	socklen_t addrlen;
	size_t maxlen;
	int edns;
	int dnssec_ok;
	int tcp;
	
	uint8_t *iobufptr;
	uint8_t iobuf[QIOBUFSZ];
	int overflow;		/* True if the I/O buffer overflowed.  */

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
	
	/* Query class and type in host byte order.  */
	uint16_t class;
	uint16_t type;

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


/* Current amount of data in the query IO buffer.  */
static inline size_t query_used_size(struct query *q);

/* Current available data size of the query IO buffer.  */
static inline size_t query_available_size(struct query *q);

/* Append data to the query IO buffer until an overflow occurs.  */
static inline void query_write(struct query *q, const void *data, size_t size);


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
uint16_t query_get_dname_offset(struct query *query, domain_type *domain);
{
	return query->compressed_dname_offsets[domain->number];
}

/*
 * Remove all compressed dnames that have an offset that points beyond
 * the end of the current answer.  This must be done after some RRs
 * are truncated and before adding new RRs.  Otherwise dnames may be
 * compressed using truncated data!
 */
void query_clear_dname_offsets(struct query *query);

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


/* query.c */
void query_init(struct query *q);
query_state_type query_process(struct query *q, struct nsd *nsd);
void query_addedns(struct query *q, struct nsd *nsd);
void query_error(struct query *q, int rcode);



static inline size_t
query_used_size(struct query *q)
{
	return q->iobufptr - q->iobuf;
}

static inline size_t
query_available_size(struct query *q)
{
	return q->maxlen - query_used_size(q);
}

static inline void
query_write(struct query *q, const void *data, size_t size)
{
	if (size <= query_available_size(q)) {
		memcpy(q->iobufptr, data, size); 
		q->iobufptr += size;
	} else {
		q->overflow = 1;
	}	
}

#endif /* _QUERY_H_ */
