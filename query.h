/*
 * $Id: query.h,v 1.3 2002/01/09 11:45:39 alexis Exp $
 *
 * zone.h -- internal zone representation
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
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
#define	RD_MASK		0x01
#define	RD_SHIFT	0
#define	RD(query)	(*(query->iobuf+2) & RD_MASK)
#define	RD_SET(query)	*(query->iobuf+2) |= RD_MASK
#define	RD_CLR(query)	*(query->iobuf+2) &= !RD_MASK

#define TC_MASK		0x02
#define TC_SHIFT	1
#define	TC(query)	(*(query->iobuf+2) & TC_MASK)
#define	TC_SET(query)	*(query->iobuf+2) |= TC_MASK
#define	TC_CLR(query)	*(query->iobuf+2) &= !TC_MASK

#define	AA_MASK		0x04
#define	AA_SHIFT	2
#define	AA(query)	(*(query->iobuf+2) & AA_MASK)
#define	AA_SET(query)	*(query->iobuf+2) |= AA_MASK
#define	AA_CLR(query)	*(query->iobuf+2) &= !AA_MASK

#define	OPCODE_MASK	0x78
#define	OPCODE_SHIFT	3
#define	OPCODE(query)	(*(query->iobuf+2) & OPCODE_MASK)
#define	OPCODE_SET(query, opcode) \
	*(query->iobuf+2) = ((*(query->iobuf+2)) & !OPCODE_MASK) | opcode

#define	QR_MASK		0x80
#define	QR_SHIFT	7
#define	QR(query)	(*(query->iobuf+2) & QR_MASK)
#define	QR_SET(query)	*(query->iobuf+2) |= QR_MASK
#define	QR_CLR(query)	*(query->iobuf+2) &= !QR_MASK

#define	RCODE_MASK	0x0f
#define	RCODE_SHIFT	0
#define	RCODE(query)	(*(query->iobuf+3) & RCODE_MASK)
#define	RCODE_SET(query, rcode) \
	*(query->iobuf+3) = ((*(query->iobuf+3)) & !RCODE_MASK) | rcode

#define	Z_MASK		0x70
#define	Z_SHIFT		4
#define	Z(query)	(*(query->iobuf+3) & Z_MASK)
#define	Z_SET(query, z) \
	*(query->iobuf+3) = ((*(query->iobuf+3)) & !Z_MASK) | z

/* Second octet of flags */
#define	RA_MASK		0x80
#define	RA_SHIFT	7
#define	RA(query)	(*(query->iobuf+3) & RA_MASK)
#define	RA_SET(query)	*(query->iobuf+3) |= RA_MASK
#define	RA_CLR(query)	*(query->iobuf+3) &= !RA_MASK

/* Query ID */
#define	ID(query)		(*(u_short *)(query->iobuf))

/* Counter of the question section */
#define QDCOUNT_OFF		4
#define	QDCOUNT(query)		(*(u_short *)(query->iobuf+QDCOUNT_OFF))

/* Counter of the answer section */
#define ANCOUNT_OFF		6
#define	ANCOUNT(query)		(*(u_short *)(query->iobuf+ANCOUNT_OFF))

/* Counter of the authority section */
#define NSCOUNT_OFF		8
#define	NSCOUNT(query)		(*(u_short *)(query->iobuf+NSCOUNT_OFF))

/* Counter of the additional section */
#define ARCOUNT_OFF		10
#define	ARCOUNT(query)		(*(u_short *)(query->iobuf+ARCOUNT_OFF))

/* Possible OPCODE values */
#define	OPCODE_QUERY		0 	/* a standard query (QUERY) */
#define OPCODE_IQUERY		1 	/* an inverse query (IQUERY) */
#define OPCODE_STATUS		2 	/* a server status request (STATUS) */

/* Possible RCODE values */
#define	RCODE_OK		0 	/* No error condition */
#define RCODE_FORMAT		1 	/* Format error */
#define RCODE_SERVFAIL		2 	/* Server failure */
#define RCODE_NXDOMAIN		3 	/* Name Error */
#define RCODE_IMPL		4 	/* Not implemented */
#define RCODE_REFUSE		5 	/* Refused */

/* Size of IPv6 address */
#define	IP6ADDRLEN		128/8

/* Miscelaneous limits */
#define	QIOBUFSZ	1024	/* Input output buffer for queries */
#define	WIREBUFSZ	1024
#define	LINEBUFSZ	1024
#define	MAXLABELLEN	63
#define	MAXDOMAINLEN	255
#define STACKSZ		256	/* Multi purpose stack we use for dname parsing and glue */
#define MAXINCLUDES	10	/* Maximum nested includes */
#define	MAXRRSPP	1024	/* Maximum number of rr's per packet */
#define	MINRDNAMECOMP	3	/* Minimum dname to be compressed */


/* Query as we pass it around */
struct query {
	struct sockaddr_in addr;
	size_t addrlen;
	u_char *iobufptr;
	int  iobufsz;
	u_char iobuf[QIOBUFSZ];
};

/* query.c */
struct query *query_new __P((void));
void query_destroy __P((struct query *));
int query_process __P((struct query *, struct db *));
void query_init __P((struct query *));
void query_addanswer __P((struct query *, u_char *, struct answer *));
