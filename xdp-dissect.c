// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

// derived from:
//   - https://github.com/stackless-goto/ox/blob/trunk/modules/nygma/libnygma/libnygma/nygma_dissect.hxx

#include "config.h"

#include "xdp-dissect.h"

#include <stdint.h>

typedef uint32_t u32;
typedef uint16_t u16;

static inline u16 peek_be16( byte const* const p ) {
	return ( u16 )( (u16)p[0] << 8 ) | (u16)p[1];
}

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
