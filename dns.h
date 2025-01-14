/*
 * dns.h -- DNS definitions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef DNS_H
#define DNS_H

enum rr_section {
	QUESTION_SECTION,
	ANSWER_SECTION,
	AUTHORITY_SECTION,
	/*
	 * Use a split authority section to ensure that optional
	 * NS RRsets in the response can be omitted.
	 */
	OPTIONAL_AUTHORITY_SECTION,
	ADDITIONAL_SECTION,
	/*
	 * Use a split additional section to ensure A records appear
	 * before any AAAA records (this is recommended practice to
	 * avoid truncating the additional section for IPv4 clients
	 * that do not specify EDNS0), and AAAA records before other
	 * types of additional records (such as X25 and ISDN).
	 * Encode_answer sets the ARCOUNT field of the response packet
	 * correctly.
	 */
	ADDITIONAL_A_SECTION = ADDITIONAL_SECTION,
	ADDITIONAL_AAAA_SECTION,
	ADDITIONAL_OTHER_SECTION,

	RR_SECTION_COUNT
};
typedef enum rr_section rr_section_type;

/* Possible OPCODE values */
#define OPCODE_QUERY		0 	/* a standard query (QUERY) */
#define OPCODE_IQUERY		1 	/* an inverse query (IQUERY) */
#define OPCODE_STATUS		2 	/* a server status request (STATUS) */
#define OPCODE_NOTIFY		4 	/* NOTIFY */
#define OPCODE_UPDATE		5 	/* Dynamic update */

/* Possible RCODE values */
#define RCODE_OK		0 	/* No error condition */
#define RCODE_FORMAT		1 	/* Format error */
#define RCODE_SERVFAIL		2 	/* Server failure */
#define RCODE_NXDOMAIN		3 	/* Name Error */
#define RCODE_IMPL		4 	/* Not implemented */
#define RCODE_REFUSE		5 	/* Refused */
#define RCODE_YXDOMAIN		6	/* name should not exist */
#define RCODE_YXRRSET		7	/* rrset should not exist */
#define RCODE_NXRRSET		8	/* rrset does not exist */
#define RCODE_NOTAUTH		9	/* server not authoritative */
#define RCODE_NOTZONE		10	/* name not inside zone */

/* Standardized NSD return code.  Partially maps to DNS RCODE values.  */
enum nsd_rc
{
	/* Discard the client request.  */
	NSD_RC_DISCARD  = -1,
	/* OK, continue normal processing.  */
	NSD_RC_OK       = RCODE_OK,
	/* Return the appropriate error code to the client.  */
	NSD_RC_FORMAT   = RCODE_FORMAT,
	NSD_RC_SERVFAIL = RCODE_SERVFAIL,
	NSD_RC_NXDOMAIN = RCODE_NXDOMAIN,
	NSD_RC_IMPL     = RCODE_IMPL,
	NSD_RC_REFUSE   = RCODE_REFUSE,
	NSD_RC_NOTAUTH  = RCODE_NOTAUTH
};
typedef enum nsd_rc nsd_rc_type;

/* RFC1035 */
#define CLASS_IN	1	/* Class IN */
#define CLASS_CS	2	/* Class CS */
#define CLASS_CH	3	/* Class CHAOS */
#define CLASS_HS	4	/* Class HS */
#define CLASS_NONE	254	/* Class NONE rfc2136 */
#define CLASS_ANY	255	/* Class ANY */

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
#define TYPE_RP		17	/* RFC1183 */
#define TYPE_AFSDB	18	/* RFC1183 */
#define TYPE_X25	19	/* RFC1183 */
#define TYPE_ISDN	20	/* RFC1183 */
#define TYPE_RT		21	/* RFC1183 */
#define TYPE_NSAP	22	/* RFC1706 (deprecated by RFC9121) */
#define TYPE_NSAP_PTR	23	/* RFC1348  (deprecated by RFC9121)*/
#define TYPE_SIG	24	/* 2535typecode */
#define TYPE_KEY	25	/* 2535typecode */
#define TYPE_PX		26	/* RFC2163 */
#define TYPE_GPOS	27	/* RFC1712 */
#define TYPE_AAAA	28	/* ipv6 address */
#define TYPE_LOC	29	/* LOC record  RFC1876 */
#define TYPE_NXT	30	/* 2535typecode */

#define TYPE_SRV	33	/* SRV record RFC2782 */

#define TYPE_NAPTR	35	/* RFC2915 */
#define TYPE_KX		36	/* RFC2230 Key Exchange Delegation Record */
#define TYPE_CERT	37	/* RFC2538 */
#define TYPE_A6		38	/* RFC2874 */
#define TYPE_DNAME	39	/* RFC2672 */

#define TYPE_OPT	41	/* Pseudo OPT record... */
#define TYPE_APL	42	/* RFC3123 */
#define TYPE_DS		43	/* RFC 4033, 4034, and 4035 */
#define TYPE_SSHFP	44	/* SSH Key Fingerprint */
#define TYPE_IPSECKEY	45	/* public key for ipsec use. RFC 4025 */
#define TYPE_RRSIG	46	/* RFC 4033, 4034, and 4035 */
#define TYPE_NSEC	47	/* RFC 4033, 4034, and 4035 */
#define TYPE_DNSKEY	48	/* RFC 4033, 4034, and 4035 */
#define TYPE_DHCID	49	/* RFC4701 DHCP information */
#define TYPE_NSEC3	50	/* NSEC3, secure denial, prevents zonewalking */
#define TYPE_NSEC3PARAM 51	/* NSEC3PARAM at zone apex nsec3 parameters */
#define TYPE_TLSA	52	/* RFC 6698 */
#define TYPE_SMIMEA	53	/* RFC 8162 */
#define TYPE_HIP	55	/* RFC 8005 */
#define TYPE_NINFO	56	/* NINFO/ninfo-completed-template */
#define TYPE_RKEY	57	/* RKEY/rkey-completed-template */

#define TYPE_CDS	59	/* RFC 7344 */
#define TYPE_CDNSKEY	60	/* RFC 7344 */
#define TYPE_OPENPGPKEY 61	/* RFC 7929 */
#define TYPE_CSYNC	62	/* RFC 7477 */
#define TYPE_ZONEMD	63	/* RFC 8976 */
#define TYPE_SVCB	64	/* RFC 9460 */
#define TYPE_HTTPS	65	/* RFC 9460 */

#define TYPE_SPF        99      /* RFC 4408 */

#define TYPE_NID        104     /* RFC 6742 */
#define TYPE_L32        105     /* RFC 6742 */
#define TYPE_L64        106     /* RFC 6742 */
#define TYPE_LP         107     /* RFC 6742 */
#define TYPE_EUI48      108     /* RFC 7043 */
#define TYPE_EUI64      109     /* RFC 7043 */

#define TYPE_TSIG	250
#define TYPE_IXFR	251
#define TYPE_AXFR	252
#define TYPE_MAILB	253	/* A request for mailbox-related records (MB, MG or MR) */
#define TYPE_MAILA	254	/* A request for mail agent RRs (Obsolete - see MX) */
#define TYPE_ANY	255	/* any type (wildcard) */
#define TYPE_URI	256	/* RFC 7553 */
#define TYPE_CAA	257	/* RFC 6844 */
#define TYPE_AVC	258	/* AVC/avc-completed-template */

#define TYPE_RESINFO	261	/* RFC 9606 */
#define TYPE_WALLET	262	/* WALLET/wallet-completed-template */
#define TYPE_CLA	263	/* CLA/cla-completed-template */

#define TYPE_TA		32768	/* http://www.watson.org/~weiler/INI1999-19.pdf */
#define TYPE_DLV	32769	/* RFC 4431 */
#define PSEUDO_TYPE_TA	RRTYPE_DESCRIPTORS_LENGTH
#define PSEUDO_TYPE_DLV	(RRTYPE_DESCRIPTORS_LENGTH + 1)

#define SVCB_KEY_MANDATORY		0
#define SVCB_KEY_ALPN			1
#define SVCB_KEY_NO_DEFAULT_ALPN	2
#define SVCB_KEY_PORT			3
#define SVCB_KEY_IPV4HINT		4
#define SVCB_KEY_ECH			5
#define SVCB_KEY_IPV6HINT		6
#define SVCB_KEY_DOHPATH		7
#define SVCB_KEY_OHTTP			8
#define SVCB_KEY_TLS_SUPPORTED_GROUPS	9

#define MAXLABELLEN	63
#define MAXDOMAINLEN	255

#define MAX_RDLENGTH	65535

/* Maximum size of a single RR.  */
#define MAX_RR_SIZE \
	(MAXDOMAINLEN + sizeof(uint32_t) + 4*sizeof(uint16_t) + MAX_RDLENGTH)

#define IP4ADDRLEN	(32/8)
#define IP6ADDRLEN	(128/8)
#define EUI48ADDRLEN	(48/8)
#define EUI64ADDRLEN	(64/8)

#define NSEC3_HASH_LEN 20

//
// the maximum value of rdata is always 65535 (UINT16_MAX), so if
// we define the values below to be above that we really should never
// clash. describe here that we don't use the previous way of configuring
// field length... because well... we don't really need it. only with
// printing
//

// >> we could choose to use a single bit
//    and reuse that >> we'll at least require the values to be a positive
//    value! that way if we try insert it into rdata, we usually check if
//    the limit is not exceeded. if we use negative values that may lead to
//    unexpected results

#define RDATA_COMPRESSED_NAME (-1)
#define RDATA_UNCOMPRESSED_NAME (-2)
#define RDATA_LITERAL_DNAME (-3)
#define RDATA_STRING (-4)
//#define RDATA_IPSECGATEWAY (-5) // << this is really, REALLY, cancelled
                                  //    upon getting the type descriptor the dev
																	//    is required to pass a reference to the rdata!
#define RDATA_REMAINDER (1u<<16) // << we just use 0 to indicate we take the remainder!


// function signature to determine length will take
// uint8_t pointer + offset + length
typedef int32_t(*nsd_rdata_length_t)(
	uint16_t rdlength,
	const uint8_t *rdata,
	uint16_t offset);
// offset is required for the ipsecgateway where we need to read a couple
// bytes back

typedef struct nsd_rdata_descriptor nsd_rdata_descriptor_t;
// the descriptor table shouldn't be used for validation.
// the read function will take care of that. it's used for
// implementing copy functions that are very specific, but where
// the data has already been checked for validity..
struct nsd_rdata_descriptor {
	const char *name;
	bool is_optional; // << whether or not this field is optional...
	int32_t length; // << will be set to a specialized value if
								//    the length function should be used. i.e.
								//    for any type where the length depends on a value
								//    in the rdata itself.
	// this function isn't actually all that useful!
	// >> actually... it kinda is...
	//
	nsd_rdata_field_length_t calculate_length; // << determine size of rdata field (uncompressed)
	//															 //    for scenarios where rdata has a different
	//															 //    format (internal names/possibly compressed names)
	//															 //    implement your own!
	nsd_print_rdata_field_t print; // << not sure if I want to use this one
																			 //    >> we'll see!
};

/*
RDATA minimization is outlined in https://github.com/k0ekk0ek/database-case.

The basic premise is that RDATA is directly allocated with the RR structure
and that pointers to domains are directly stored (likely unaligned) in the
RDATA. We do this primarily to save memory, but as the RDATA is directly
stored with the RR, it is likely that data is cached with the RR which should
have a positive impact on performance. When paired with direct conversion
routines we are very likely to improve performance when importing zones and
writing RRs out to the wire.

The original idea was to implement conversion routines for type, but upon
propagating changes throughout the codebase it turns out we have to do
convert between more formats that just wire-to-internal, internal-to-wire,
and internal-to-text. The result is an explosion in code.
Consider the following matrix.


* compressed wire format
* uncompressed wire format
* internal format
* presentation format
* generic presentation format (though mostly important for loading)

For incremental zone transfers we convert from presentation format to
uncompressed wire format to internal format to uncompressed wire format on
loading. When writing out to the network we convert from uncompressed wire
format to compressed wire format.

The idea is that we can at least skip uncompressed wire format to internal
format on loading, though we do have to normalize the domain names in the
data (or assume that users won't update the on-disk data in which case we
may trust the data gets written in normalized fashion). However, the
uncompressed wire format to compressed wire format remains necessary.

For conversion from uncompressed/compressed wire format to internal we make
the interface such that a packet buffer is required and use
dname\_make\_from\_packet so that the same import routines can be used.
For internal to compressed wire format we implement a specialized routine so
that answering of queries is as optimal as can be.

For all other conversions, speed is not as important so the proposal is that
we keep the descriptor table more-or-less as-is.

For converting to (generic) presentation format, I propose we move that code
to simdzone. The benefit there being that support for everything presentation
format is in one place. The idea is that the interface is uncompressed wire
format, so writing data out, the internal representation must replace the
domain pointers by the uncompressed domain name in wire format.
 */


typedef struct nsd_type_descriptor nsd_type_descriptor_t;
struct nsd_type_descriptor;

typedef int32_t(*nsd_read_rdata_t)(
	struct domain_table *domains,
	uint16_t rdlength,
	struct buffer *packet,
	struct rr **rr);

typedef int32_t(*nsd_write_rdata_t)(
	struct query *query,
	const struct rr *rr);

typedef int32_t(*nsd_print_rdata_t)(
	struct buffer *buffer,
	const struct rr *rr);


struct nsd_type_descriptor {
	uint16_t type;
	/** Mnemonic. */
	const char *name;
	/** Whether internal RDATA contains direct pointers. */
	bool has_references;
	/** Whether RDATA contains compressible names. */
	bool is_compressible;
	nsd_read_rdata_t read_rdata;
	nsd_write_rdata_t write_data;
	nsd_print_rdata_t print_rdata;
	struct {
		uint32_t flags; // << e.g. COMPRESSED_NAME
		size_t length;
		nsd_rdata_descriptor_t *fields;
	} rdata;
};


/*
 * Indexed by type.  The special type "0" can be used to get a
 * descriptor for unknown types (with one binary rdata).
 *
 * CLA + 1
 */
#define RRTYPE_DESCRIPTORS_LENGTH  (TYPE_CLA + 1)
rrtype_descriptor_type *rrtype_descriptor_by_type(uint16_t type);

const char *rrtype_to_string(uint16_t rrtype);

/*
 * Lookup the type in the ztypes lookup table.  If not found, check if
 * the type uses the "TYPExxx" notation for unknown types.
 *
 * Return 0 if no type matches.
 */
uint16_t rrtype_from_string(const char *name);

const char *rrclass_to_string(uint16_t rrclass);
uint16_t rrclass_from_string(const char *name);

#endif /* DNS_H */
