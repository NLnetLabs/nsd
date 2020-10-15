// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

#ifndef _NSD_XDP_
#define _NSD_XDP_

typedef uint8_t byte;

typedef enum dissect_tag {
	DISSECT_ARP,
	DISSECT_ECTP,
	DISSECT_ETH,
	DISSECT_ICMPV4,
	DISSECT_ICMPV6,
	DISSECT_IPV4,
	DISSECT_IPV4F,
	DISSECT_IPV6,
	DISSECT_IPV6F,
	DISSECT_LLC,
	DISSECT_LLDP,
	DISSECT_MPLS,
	DISSECT_SCTP,
	DISSECT_TCP,
	DISSECT_UDP,
	DISSECT_VLAN8021Q,
	DISSECT_UNKNOWN,
} dissect_tag;

typedef struct dissect_trace_entry {
	dissect_tag _tag;
	byte const* _begin;
} dissect_trace_entry_type;

typedef struct dissect_trace {
// needs to be power of two
#define DISSECT_TRACE_ENTRIES_COUNT 64
#define DISSECT_TRACE_ENTRIES_MASK  ( DISSECT_TRACE_ENTRIES_COUNT - 1 )
	dissect_trace_entry_type _stack[DISSECT_TRACE_ENTRIES_COUNT];
	uint32_t _idx;
} dissect_trace_type;

uint32_t dissect_en10mb(
	dissect_trace_type* const trace, byte const* data, size_t const size );

static inline void dissect_trace_push( dissect_trace_type* const trace,
	dissect_tag const tag, byte const* const begin ) {
	trace->_stack[trace->_idx & DISSECT_TRACE_ENTRIES_MASK]._tag = tag;
	trace->_stack[trace->_idx & DISSECT_TRACE_ENTRIES_MASK]._begin = begin;
	trace->_idx++;
}

#ifndef DISSECT_CUSTOM_TRACE_ARP_FN
static inline void dissect_trace_arp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ARP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_ETH_FN
static inline void dissect_trace_eth( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ETH, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_IPV4_FN
static inline void dissect_trace_ipv4( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV4, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_IPV4F_FN
static inline void dissect_trace_ipv4f( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV4F, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_ICMPV4_FN
static inline void dissect_trace_icmpv4( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ICMPV4, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_IPV6_FN
static inline void dissect_trace_ipv6( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV6, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_IPV6F_FN
static inline void dissect_trace_ipv6f( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV6F, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_ICMPV6_FN
static inline void dissect_trace_icmpv6( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ICMPV6, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_UNKNOWN_FN
static inline void dissect_trace_unknown( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_UNKNOWN, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_SCTP_FN
static inline void dissect_trace_sctp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_SCTP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_TCP_FN
static inline void dissect_trace_tcp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_TCP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_UDP_FN
static inline void dissect_trace_udp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_UDP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_LLDP_FN
static inline void dissect_trace_lldp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_LLDP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_ECTP_FN
static inline void dissect_trace_ectp( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ECTP, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_MPLS_FN
static inline void dissect_trace_mpls( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_MPLS, begin );
}
#endif

#ifndef DISSECT_CUSTOM_TRACE_VLAN8021Q_FN
static inline void dissect_trace_vlan8021q( dissect_trace_type* const trace,
	byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_VLAN8021Q, begin );
}
#endif

#ifndef DISSECT_CUSTOM_HASH8_FN
static inline uint32_t dissect_hash8( byte const* const begin ) {
	(void)begin;
	return 0u;
}
#endif

#ifndef DISSECT_CUSTOM_HASH32_FN
static inline uint32_t dissect_hash32( byte const* const begin ) {
	(void)begin;
	return 0u;
}
#endif

#endif
