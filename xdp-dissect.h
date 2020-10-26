// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

// derived from:
//   - https://github.com/stackless-goto/ox/blob/trunk/modules/nygma/libnygma/libnygma/nygma_dissect.hxx

#ifndef _NSD_XDP_DISSECT_
#define _NSD_XDP_DISSECT_

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t byte;

typedef enum dissect_tag {
	DISSECT_ARP = ( 1 << 0 ),
	DISSECT_ECTP = ( 1 << 1 ),
	DISSECT_ETH = ( 1 << 2 ),
	DISSECT_ICMPV4 = ( 1 << 3 ),
	DISSECT_ICMPV6 = ( 1 << 4 ),
	DISSECT_IPV4 = ( 1 << 5 ),
	DISSECT_IPV4F = ( 1 << 6 ),
	DISSECT_IPV6 = ( 1 << 7 ),
	DISSECT_IPV6F = ( 1 << 8 ),
	DISSECT_LLC = ( 1 << 9 ),
	DISSECT_LLDP = ( 1 << 10 ),
	DISSECT_MPLS = ( 1 << 11 ),
	DISSECT_SCTP = ( 1 << 12 ),
	DISSECT_TCP = ( 1 << 13 ),
	DISSECT_UDP = ( 1 << 14 ),
	DISSECT_VLAN8021Q = ( 1 << 15 ),
	DISSECT_UNKNOWN = ( 1 << 16 ),
} dissect_tag;

typedef struct dissect_trace_entry {
	dissect_tag _tag;
	byte const* _begin;
} dissect_trace_entry_type;

typedef struct dissect_trace {
// needs to be power of two
#define DISSECT_TRACE_ENTRIES_COUNT 64
#define DISSECT_TRACE_ENTRIES_MASK ( DISSECT_TRACE_ENTRIES_COUNT - 1 )
	dissect_trace_entry_type _stack[DISSECT_TRACE_ENTRIES_COUNT];
	uint32_t _idx;
	void* _env;
} dissect_trace_type;

static inline uint16_t peek_be16( uint8_t const* const p ) {
	return ( uint16_t )( (uint16_t)p[0] << 8 ) | (uint16_t)p[1];
}

uint32_t dissect_en10mb( dissect_trace_type* const trace, byte const* data,
			 size_t const size );

static inline void dissect_trace_push( dissect_trace_type* const trace,
				       dissect_tag const tag, byte const* const begin ) {
	trace->_stack[trace->_idx & DISSECT_TRACE_ENTRIES_MASK]._tag = tag;
	trace->_stack[trace->_idx & DISSECT_TRACE_ENTRIES_MASK]._begin = begin;
	trace->_idx++;
}

static inline dissect_trace_entry_type const*
dissect_trace_at( dissect_trace_type* const trace, uint32_t idx ) {
	return &trace->_stack[idx & DISSECT_TRACE_ENTRIES_MASK];
}

static inline uint32_t dissect_trace_layers( dissect_trace_type* const trace ) {
	return trace->_idx & DISSECT_TRACE_ENTRIES_MASK;
}

static inline uint32_t dissect_trace_layer_offset( dissect_trace_type* const trace,
						   uint32_t idx ) {
	return ( uint32_t )( dissect_trace_at( trace, idx )->_begin -
			     trace->_stack[0]._begin );
}

static inline void dissect_trace_arp( dissect_trace_type* const trace,
				      byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ARP, begin );
#ifdef DISSECT_CUSTOM_TRACE_ARP_FN
	DISSECT_CUSTOM_TRACE_ARP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_eth( dissect_trace_type* const trace,
				      byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ETH, begin );
#ifdef DISSECT_CUSTOM_TRACE_ETH_FN
	DISSECT_CUSTOM_TRACE_ETH_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_ipv4( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV4, begin );
#ifdef DISSECT_CUSTOM_TRACE_IPV4_FN
	DISSECT_CUSTOM_TRACE_IPV4_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_ipv4f( dissect_trace_type* const trace,
					byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV4F, begin );
#ifdef DISSECT_CUSTOM_TRACE_IPV4F_FN
	DISSECT_CUSTOM_TRACE_IPV4F_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_icmpv4( dissect_trace_type* const trace,
					 byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ICMPV4, begin );
#ifdef DISSECT_CUSTOM_TRACE_ICMPV4_FN
	DISSECT_CUSTOM_TRACE_ICMPV4_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_ipv6( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV6, begin );
#ifdef DISSECT_CUSTOM_TRACE_IPV6_FN
	DISSECT_CUSTOM_TRACE_IPV6_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_ipv6f( dissect_trace_type* const trace,
					byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_IPV6F, begin );
#ifdef DISSECT_CUSTOM_TRACE_IPV6F_FN
	DISSECT_CUSTOM_TRACE_IPV6F_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_icmpv6( dissect_trace_type* const trace,
					 byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ICMPV6, begin );
#ifdef DISSECT_CUSTOM_TRACE_ICMPV6_FN
	DISSECT_CUSTOM_TRACE_ICMPV6_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_unknown( dissect_trace_type* const trace,
					  byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_UNKNOWN, begin );
#ifdef DISSECT_CUSTOM_TRACE_UNKNOWN_FN
	DISSECT_CUSTOM_TRACE_UNKNOWN_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_sctp( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_SCTP, begin );
#ifdef DISSECT_CUSTOM_TRACE_SCTP_FN
	DISSECT_CUSTOM_TRACE_SCTP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_tcp( dissect_trace_type* const trace,
				      byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_TCP, begin );
#ifdef DISSECT_CUSTOM_TRACE_TCP_FN
	DISSECT_CUSTOM_TRACE_TCP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_udp( dissect_trace_type* const trace,
				      byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_UDP, begin );
#ifdef DISSECT_CUSTOM_TRACE_UDP_FN
	DISSECT_CUSTOM_TRACE_UDP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_lldp( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_LLDP, begin );
#ifdef DISSECT_CUSTOM_TRACE_LLDP_FN
	DISSECT_CUSTOM_TRACE_LLDP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_ectp( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_ECTP, begin );
#ifdef DISSECT_CUSTOM_TRACE_ECTP_FN
	DISSECT_CUSTOM_TRACE_ECTP_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_mpls( dissect_trace_type* const trace,
				       byte const* const begin, byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_MPLS, begin );
#ifdef DISSECT_CUSTOM_TRACE_MPLS_FN
	DISSECT_CUSTOM_TRACE_MPLS_FN( trace, begin, end );
#endif
}

static inline void dissect_trace_vlan8021q( dissect_trace_type* const trace,
					    byte const* const begin,
					    byte const* const end ) {
	(void)end;
	dissect_trace_push( trace, DISSECT_VLAN8021Q, begin );
#ifdef DISSECT_CUSTOM_TRACE_VLAN8021Q_FN
	DISSECT_CUSTOM_TRACE_VLAN8021Q_FN( trace, begin, end );
#endif
}

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

#define DISSECT_NEXT_ALLOW_VLAN( x )                                                     \
	do {                                                                             \
		switch( x ) {                                                            \
		case 0x0800: goto parse_ipv4;                                            \
		case 0x0806: goto parse_arp;                                             \
		case 0x86dd: goto parse_ipv6;                                            \
		case 0x8100: goto parse_vlan_8021q;                                      \
		case 0x8a88: goto parse_vlan_8021q;                                      \
		case 0x9100: goto parse_vlan_8021q;                                      \
		case 0x8847: goto parse_vlan_mpls;                                       \
		case 0x88cc: goto parse_lldp;                                            \
		case 0x9000: goto parse_ectp;                                            \
		default: dissect_trace_unknown( trace, p, end ); return hash;            \
		}                                                                        \
	} while( 0 )

#define DISSECT_NEXT( x )                                                                \
	do {                                                                             \
		switch( x ) {                                                            \
		case 0x0800: goto parse_ipv4;                                            \
		case 0x0806: goto parse_arp;                                             \
		case 0x86dd: goto parse_ipv6;                                            \
		case 0x8847: goto parse_vlan_mpls;                                       \
		case 0x88cc: goto parse_lldp;                                            \
		case 0x9000: goto parse_ectp;                                            \
		default: dissect_trace_unknown( trace, p, end ); return hash;            \
		}                                                                        \
	} while( 0 )

u32 dissect_en10mb( dissect_trace_type* const trace, byte const* data, size_t const size ) {
	byte const* const begin = data;
	byte const* const end = data + size;
	byte const* p = begin;
	u16 ethertype;
	u16 vlan_ex;
	u16 vlan_et;
	u32 hash = 0u;

	if( end - begin < 22 ) { return 0u; }

	dissect_trace_eth( trace, data, end );
	ethertype = peek_be16( p + 12 );
	vlan_ex = peek_be16( p + 16 );
	vlan_et = peek_be16( p + 20 );
	p += 14;

	DISSECT_NEXT_ALLOW_VLAN( ethertype );

parse_vlan_8021q:
	dissect_trace_vlan8021q( trace, p, end );
	p += vlan_ex == 0x8100u ? 8 : 4;
	ethertype = vlan_ex == 0x8100u ? vlan_et : vlan_ex;
	DISSECT_NEXT( ethertype );

parse_ipv4 : {
	u32 x, len, part, transport;

	if( p >= end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	x = ( u32 )( *p );
	len = ( x & 0x0f ) << 2;
	if( p + len > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	part = peek_be16( p + 6 );
	// unsigned const flag = part & 0b0010'0000'0000'0000u;
	// unsigned const foffset = part & 0b0001'1111'1111'1111u;
	hash = dissect_hash8( p + 12 );
	if( part & 0x3fffu ) {
		dissect_trace_ipv4f( trace, p, end );
		if( part & 0x1fffu ) { return hash; }
	} else {
		dissect_trace_ipv4( trace, p, end );
	}

	transport = (u32)p[9];
	p += len;
	switch( transport ) {
	case 1: goto parse_icmpv4;
	case 6: goto parse_tcp;
	case 17: goto parse_udp;
	case 132: goto parse_sctp;
	default: return hash;
	}
}

parse_tcp : {
	u32 len;
	if( p + 20 > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	len = ( (u32)p[12] >> 2 ) & ~0x3u;
	if( p + len > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	dissect_trace_tcp( trace, p, end );
	return hash;
}

parse_udp:
	if( p + 8 > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	dissect_trace_udp( trace, p, end );
	return hash;

parse_icmpv4:
	dissect_trace_icmpv4( trace, p, end );
	return hash;

parse_icmpv6:
	dissect_trace_icmpv6( trace, p, end );
	return hash;

parse_sctp:
	dissect_trace_sctp( trace, p, end );
	return hash;

parse_lldp:
	dissect_trace_lldp( trace, p, end );
	return hash;

parse_ectp:
	dissect_trace_ectp( trace, p, end );
	return hash;

parse_arp:
	dissect_trace_arp( trace, p, end );
	return hash;

parse_ipv6 : {
	u32 len, transport;
	if( p + 40 > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	hash = dissect_hash32( p + 8 );
	len = peek_be16( p + 4 );
	if( p + len + 40 > end ) {
		dissect_trace_unknown( trace, p, end );
		return hash;
	}
	dissect_trace_ipv6( trace, p, end );
	transport = (u32)p[6];
	p += 40;
	switch( transport ) {
	case 6: goto parse_tcp;
	case 17: goto parse_udp;
	case 58: goto parse_icmpv6;
	default: return hash;
	}
}

parse_vlan_mpls:
	dissect_trace_mpls( trace, p, end );
	return hash;
}

#endif
