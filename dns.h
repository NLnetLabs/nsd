/*
 * dns.h -- DNS definitions.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _DNS_H_
#define _DNS_H_

#include "buffer.h"
#include "region-allocator.h"

/* RFC1035 */
#define	CLASS_IN	1	/* Class IN */
#define	CLASS_CHAOS	3	/* Class CHAOS */
#define CLASS_HS        4       /* Class HS */
#define	CLASS_ANY	255	/* Class IN */

#define TYPE_A		1	/* a host address */
#define TYPE_NS		2	/* an authoritative name server */
#define TYPE_MD		3	/* a mail destination (Obsolete - use MX) */
#define TYPE_MF		4	/* a mail forwarder (Obsolete - use MX) */
#define TYPE_CNAME	5	/* the canonical name for an alias */
#define TYPE_SOA	6	/* marks the start of a zone of authority */
#define TYPE_MB		7	/* a mailbox domain name (EXPERIMENTAL) */
#define TYPE_MG		8	/* a mail group member (EXPERIMENTAL) */
#define TYPE_MR		9	/* a mail rename domain name (EXPERIMENTAL) */
#define TYPE_NULL	10	/* a null RR (EXPERIMENTAL) */
#define TYPE_WKS	11	/* a well known service description */
#define TYPE_PTR	12	/* a domain name pointer */
#define TYPE_HINFO	13	/* host information */
#define TYPE_MINFO	14	/* mailbox or mail list information */
#define TYPE_MX		15	/* mail exchange */
#define TYPE_TXT	16	/* text strings */
#define	TYPE_RP		17	/* RFC1183 */
#define	TYPE_AFSDB	18	/* RFC1183 */
#define TYPE_X25        19	/* RFC1183 */
#define TYPE_ISDN       20	/* RFC1183 */
#define TYPE_RT         21	/* RFC1183 */
#define TYPE_NSAP       22	/* RFC1706 */

#define	TYPE_SIG	24	/* 2535typecode */
#define	TYPE_KEY	25	/* 2535typecode */
#define TYPE_PX         26	/* RFC2163 */

#define TYPE_AAAA	28	/* ipv6 address */
#define TYPE_LOC	29	/* LOC record  RFC1876 */
#define	TYPE_NXT	30 	/* 2535typecode */

#define	TYPE_SRV	33	/* SRV record RFC2782 */

#define TYPE_NAPTR      35	/* RFC2915 */
#define TYPE_KX         36	/* RFC2230 */
#define TYPE_CERT       37	/* RFC2538 */

#define TYPE_DNAME      39	/* RFC2672 */

#define	TYPE_OPT	41	/* Pseudo OPT record... */
#define TYPE_APL        42	/* RFC3123 */
#define	TYPE_DS		43	/* draft-ietf-dnsext-delegation */
#define TYPE_SSHFP	44	/* SSH Key Fingerprint */

#define TYPE_RRSIG	46	/* draft-ietf-dnsext-dnssec-25 */
#define TYPE_NSEC	47	
#define TYPE_DNSKEY	48

#define	TYPE_IXFR	251
#define	TYPE_AXFR	252
#define	TYPE_MAILB	253 	/* A request for mailbox-related records (MB, MG or MR) */
#define	TYPE_MAILA	254	/* A request for mail agent RRs (Obsolete - see MX) */
#define TYPE_ANY	255	/* any type (wildcard) */

#define	MAXLABELLEN	63
#define	MAXDOMAINLEN	255

#define	MAXRDATALEN	64		/* This is more than enough, think multiple TXT */
#define MAX_RDLENGTH            65535

/* Maximum size of a single RR.  */
#define MAX_RR_SIZE \
	(MAXDOMAINLEN + sizeof(uint32_t) + 4*sizeof(uint16_t) + MAX_RDLENGTH)

#define IP4ADDRLEN      (32/8)
#define	IP6ADDRLEN	(128/8)

/*
 * The different types of RDATA wireformat data.
 */
enum rdata_wireformat
{
	RDATA_WF_COMPRESSED_DNAME,   /* Possibly compressed domain name.  */
	RDATA_WF_UNCOMPRESSED_DNAME, /* Uncompressed domain name.  */
	RDATA_WF_BYTE,		     /* 8-bit integer.  */
	RDATA_WF_SHORT,		     /* 16-bit integer.  */
	RDATA_WF_LONG,		     /* 32-bit integer.  */
	RDATA_WF_TEXT,		     /* Text string.  */
	RDATA_WF_A,		     /* 32-bit IPv4 address.  */
	RDATA_WF_AAAA,		     /* 128-bit IPv6 address.  */
	RDATA_WF_BINARY, 	     /* Binary data (unknown length).  */
	RDATA_WF_APL		     /* APL data.  */
};
typedef enum rdata_wireformat rdata_wireformat_type;

/*
 * The different types of RDATA that can appear in the zone file.
 */
enum rdata_zoneformat
{
	RDATA_ZF_DNAME,		/* Domain name.  */
	RDATA_ZF_TEXT,		/* Text string.  */
	RDATA_ZF_BYTE,		/* 8-bit integer.  */
	RDATA_ZF_SHORT,		/* 16-bit integer.  */
	RDATA_ZF_LONG,		/* 32-bit integer.  */
	RDATA_ZF_A,		/* 32-bit IPv4 address.  */
	RDATA_ZF_AAAA,		/* 128-bit IPv6 address.  */
	RDATA_ZF_RRTYPE,	/* RR type.  */
	RDATA_ZF_ALGORITHM,	/* Cryptographic algorithm.  */
	RDATA_ZF_CERTIFICATE_TYPE,
	RDATA_ZF_PERIOD,	/* Time period.  */
	RDATA_ZF_TIME,
	RDATA_ZF_BASE64,	/* Base-64 binary data.  */
	RDATA_ZF_HEX,		/* Hexadecimal binary data.  */
	RDATA_ZF_NSAP,		/* NSAP.  */
	RDATA_ZF_APL,		/* APL.  */
	RDATA_ZF_SERVICES,	/* Protocol and port number bitmap.  */
	RDATA_ZF_NXT,		/* NXT type bitmap.  */
	RDATA_ZF_NSEC,		/* NSEC type bitmap.  */
	RDATA_ZF_LOC,		/* Location data.  */
	RDATA_ZF_UNKNOWN	/* Unknown data.  */
};
typedef enum rdata_zoneformat rdata_zoneformat_type;

struct rrtype_descriptor
{
	uint16_t    type;	/* RR type */
	const char *name;	/* Textual name.  */
	int         token;	/* Parser token.  */
	uint8_t     minimum;	/* Minimum number of RDATAs.  */
	uint8_t     maximum;	/* Maximum number of RDATAs.  */
	uint8_t     wireformat[MAXRDATALEN]; /* rdata_wireformat_type */
	uint8_t     zoneformat[MAXRDATALEN]; /* rdata_zoneformat_type  */
};
typedef struct rrtype_descriptor rrtype_descriptor_type;

/*
 * Indexed by type.  The special type "0" can be used to get a
 * descriptor for unknown types (with one binary rdata).
 */
#define RRTYPE_DESCRIPTORS_LENGTH  (TYPE_DNSKEY+1)
extern rrtype_descriptor_type rrtype_descriptors[RRTYPE_DESCRIPTORS_LENGTH];

extern lookup_table_type dns_certificate_types[];
extern lookup_table_type dns_algorithms[];

static inline rrtype_descriptor_type *
rrtype_descriptor_by_type(uint16_t type)
{
	return (type < RRTYPE_DESCRIPTORS_LENGTH
		? &rrtype_descriptors[type]
		: &rrtype_descriptors[0]);
}

rrtype_descriptor_type *rrtype_descriptor_by_name(const char *name);

const char *rrtype_to_string(uint16_t rrtype);
const char *rrclass_to_string(uint16_t rrclass);

int rdata_to_string(buffer_type *output, rdata_zoneformat_type type,
		    buffer_type *packet);
		
#endif /* _DNS_H_ */
