// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

// derived from:
//   - https://github.com/DPDK/dpdk/blob/main/drivers/net/af_xdp/rte_eth_af_xdp.c

// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2019-2020 Intel Corporation.

/*
TODO:
  - options:
    - huge_tables
    - queue_index
    - promicious_mode
    - inhibit_bpf_prog_load
    - batch size
    - XDP_UMEM_UNALIGNED_CHUNK_FLAG
 */

#include "config.h"

#include "query.h"
#include "region-allocator.h"
#include "util.h"

#include <assert.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wlanguage-extension-token"
#pragma clang diagnostic ignored "-Wc11-extensions"
#endif

#include <bpf/xsk.h>
#include <bpf/bpf.h>

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include "xdp-server.h"

struct dissect_trace;
static inline void xdp_dissect_trace_udp( struct dissect_trace* const trace,
					  uint8_t const* const begin,
					  uint8_t const* const end );
#define DISSECT_CUSTOM_TRACE_UDP_FN xdp_dissect_trace_udp
#include "xdp-dissect.h"

typedef struct xdp_umem_handle {
	struct xsk_umem* _umem;
	void* _buffer;
	size_t _buffer_size;
} xdp_umem_handle_type;

typedef struct xdp_queue_stats {
	uint64_t _packets;
	uint64_t _bytes;
	uint64_t _dropped;
} xdp_queue_stats_type;

typedef struct xdp_queue_rx {
	struct xsk_ring_cons _rx;
	xdp_queue_stats_type _stats;
	xdp_umem_handle_type* _umem;
	struct xsk_socket* _sock;
} xdp_queue_rx_type;

typedef struct xdp_queue_tx {
	struct xsk_ring_prod _tx;
	xdp_queue_stats_type _stats;
	xdp_umem_handle_type* _umem;
	struct xsk_socket* _sock;
} xdp_queue_tx_type;

typedef struct xdp_trace_env {
	xdp_server_type* _xdp;
	uint32_t _count;
} xdp_trace_env_type;

static int eth_dev_change_flags( char const* if_name, uint32_t flags, uint32_t mask ) {
	struct ifreq ifr;
	int s;

	s = socket( PF_INET, SOCK_DGRAM, 0 );
	if( s < 0 ) return -errno;

	strlcpy( ifr.ifr_name, if_name, IFNAMSIZ );
	if( ioctl( s, SIOCGIFFLAGS, &ifr ) < 0 ) {
		close( s );
		return -errno;
	}

	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if( ioctl( s, SIOCSIFFLAGS, &ifr ) < 0 ) {
		close( s );
		return -errno;
	}

	return 0;
}

static int eth_dev_promiscuous_enable( xdp_server_type* xdp ) {
	return eth_dev_change_flags( xdp->_options._interface_name, IFF_PROMISC, ~0u );
}

static int eth_dev_promiscuous_disable( xdp_server_type* xdp ) {
	return eth_dev_change_flags( xdp->_options._interface_name, 0u, ~IFF_PROMISC );
}

static int eth_dev_info( xdp_server_type* xdp ) {
	struct ifreq ifr;
	int sock;

	sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
	if( sock < 0 ) { return -1; }

	strlcpy( ifr.ifr_name, xdp->_options._interface_name, IFNAMSIZ );
	if( ioctl( sock, SIOCGIFINDEX, &ifr ) ) { goto error; }
	xdp->_interface_index = ifr.ifr_ifindex;

	if( ioctl( sock, SIOCGIFHWADDR, &ifr ) ) { goto error; }
	memcpy( xdp->_interface_hardware_address, ifr.ifr_hwaddr.sa_data,
		XDP_ETHER_ADDR_LEN );

	close( sock );
	return 0;

error:
	close( sock );
	return -1;
}

static int ethtool_channels_get( char const* if_name, u32* max_queues,
				 u32* combined_queues ) {
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, rc;

	fd = socket( AF_INET, SOCK_DGRAM, 0 );
	if( fd < 0 ) { return -1; }

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void*)&channels;
	strlcpy( ifr.ifr_name, if_name, IFNAMSIZ );
	rc = ioctl( fd, SIOCETHTOOL, &ifr );
	if( rc != 0 ) {
		if( errno != EOPNOTSUPP ) {
			close( fd );
			return -errno;
		}
	}

	if( channels.max_combined == 0 || errno == EOPNOTSUPP ) {
		// If the device says it has no channels, then all traffic
		// is sent to a single stream, so max queues = 1.
		*max_queues = 1;
		*combined_queues = 1;
	} else {
		*max_queues = channels.max_combined;
		*combined_queues = channels.combined_count;
	}

	close( fd );
	return 0;
}

static int xdp_socket_stats( xdp_server_type* xdp ) {
	socklen_t optlen = sizeof( struct xdp_statistics );
	int rc;

	assert( xdp->_rx->_sock != NULL );
	rc = getsockopt( xsk_socket__fd( xdp->_rx->_sock ), SOL_XDP, XDP_STATISTICS,
			 &xdp->_stats, &optlen );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "getsockopt() failed\n" );
		return -1;
	}

	return 0;
}

static inline int xdp_fill_queue_reserve( struct xsk_ring_prod* fq, uint16_t n ) {
	uint16_t i;
	u32 idx;
	int rc;

	rc = xsk_ring_prod__reserve( fq, n, &idx );
	if( rc != n ) { return -1; }
	for( i = 0; i < n; i++ ) {
		__u64* descriptor_address = xsk_ring_prod__fill_addr( fq, idx );
		descriptor_address[0] = (__u64)i * XDP_FRAME_SIZE;
		idx++;
	}

	xsk_ring_prod__submit( fq, n );

	return 0;
}

static int xdp_socket_init( xdp_server_type* xdp ) {
	struct xsk_socket_config config = {
		.rx_size = XDP_DESCRIPTORS_CONS_COUNT,
		.tx_size = XDP_DESCRIPTORS_PROD_COUNT,
		//.libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
		.libbpf_flags = 0,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	};
	int rc;

	xdp->_rx->_umem = xdp->_umem;
	xdp->_tx->_umem = xdp->_umem;

	log_msg( LOG_NOTICE, "xdp.socket.config: rx_size=%u tx_size=%u queue=%d",
		 config.rx_size, config.tx_size, xdp->_queue_index );

	rc = xsk_socket__create( &xdp->_sock, xdp->_options._interface_name,
				 xdp->_queue_index, xdp->_umem->_umem, &xdp->_rx->_rx,
				 &xdp->_tx->_tx, &config );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "xsk_socket__create() failed: %s ( rc = %d )",
			 strerror( -rc ), rc );
		return rc;
	}

	log_msg( LOG_NOTICE, "xdp.socket: fd=%d", xsk_socket__fd( xdp->_sock ) );

	if( xdp_fill_queue_reserve( xdp->_fill_q, XDP_DESCRIPTORS_TOTAL_COUNT ) != 0 ) {
		xsk_socket__delete( xdp->_sock );
		return -1;
	}

	return 0;
}

static int xdp_umem_init( xdp_server_type* xdp ) {
	struct xsk_umem_config config = {
		.fill_size = XDP_DESCRIPTORS_TOTAL_COUNT,
		.comp_size = XDP_DESCRIPTORS_PROD_COUNT,
		.flags = 0,
		.frame_size = XDP_FRAME_SIZE,
		.frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
	};
	size_t const buffer_size = XDP_FRAME_SIZE * XDP_DESCRIPTORS_TOTAL_COUNT;
	void* buffer;
	int rc;

	log_msg( LOG_NOTICE, "xdp.umem.config: fill_size=%u comp_size=%u frame_size=%u",
		 config.fill_size, config.comp_size, config.frame_size );

	xdp->_umem->_umem = NULL;
	buffer = mmap( NULL, buffer_size, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS /*| MAP_HUGETLB*/, -1, 0 );
	log_msg( LOG_NOTICE, "xdp.umem: buffer_size=%zu buffer_allocate_success=%d",
		 buffer_size, buffer != MAP_FAILED );
	if( buffer == MAP_FAILED ) { return -1; }

	rc = xsk_umem__create( &xdp->_umem->_umem, buffer, buffer_size, xdp->_fill_q,
			       xdp->_comp_q, &config );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "xsk_umem__create() failed: %s ( %d )",
			 strerror( errno ), errno );
		munmap( buffer, buffer_size );
		return -1;
	}

	xdp->_umem->_buffer = buffer;
	xdp->_umem->_buffer_size = buffer_size;

	return 0;
}

int xdp_server_socket_fd( xdp_server_type* sock ) {
	assert( sock != NULL && sock->_sock != NULL );
	return xsk_socket__fd( sock->_sock );
}

static void xdp_pull_umem_completion_queue( xdp_server_type* xdp, int size,
					    struct xsk_ring_cons* cq ) {
	size_t i, n;
	uint32_t idx = 0;
	n = xsk_ring_cons__peek( xdp->_comp_q, size, &idx );
	xsk_ring_cons__release( xdp->_comp_q, n );
}

static void xdp_kick_tx( xdp_server_type* xdp, struct xsk_ring_cons* cq ) {
	xdp_pull_umem_completion_queue( xdp, XDP_DESCRIPTORS_CONS_COUNT, cq );
	if( !xsk_ring_prod__needs_wakeup( &xdp->_tx->_tx ) ) { return; }
	while( send( xdp_server_socket_fd( xdp ), NULL, 0, MSG_DONTWAIT ) < 0 ) {
		if( errno != EBUSY && errno != EAGAIN && errno != EINTR ) { break; }
		if( errno == EAGAIN ) {
			xdp_pull_umem_completion_queue( xdp, XDP_DESCRIPTORS_CONS_COUNT,
							cq );
		}
	}
}

static inline void xdp_dissect_trace_udp( struct dissect_trace* const trace,
					  uint8_t const* const begin,
					  uint8_t const* const end ) {
	xdp_trace_env_type* env = trace->_env;
	uint16_t const src_port = peek_be16( begin );
	uint16_t const dst_port = peek_be16( begin + 2 );
	uint16_t const udp_len = peek_be16( begin + 4 );
	struct query* q = env->_xdp->_queries[env->_count];
	ptrdiff_t const len = end - begin;
	assert( udp_len <= len );
	if( dst_port != 53 || udp_len > len || udp_len < 8 ) { return; }
	log_msg( LOG_NOTICE, "got udp sp=%d dp=%d", src_port, dst_port );
	// TODO: query addrlen
	buffer_write( q->packet, begin + 8, udp_len - 8 );
	buffer_flip( q->packet );
	if( query_process( q, env->_xdp->_nsd ) != QUERY_DISCARDED ) {
		struct nsd* nsd = env->_xdp->_nsd;
		log_msg( LOG_NOTICE, "have response" );
		if( RCODE( q->packet ) == RCODE_OK && !AA( q->packet ) ) {
			STATUP( nsd, nona );
			ZTATUP( nsd, q->zone, nona );
		}

		// TODO: update stats ( bind and zone )

		// add EDNS0 and TSIG info if necessary
		query_add_optional( q, nsd );
		buffer_flip( q->packet );

		env->_count++;
	} else {
		query_reset( q, UDP_MAX_MESSAGE_LEN, 0 );
		log_msg( LOG_NOTICE, "query discarded" );
	}
}

int xdp_server_process( xdp_server_type* xdp ) {
	struct xsk_ring_cons* rx = &xdp->_rx->_rx;
	uint32_t tx_idx = 0, rx_idx = 0, fill_idx = 0;
	dissect_trace_type trace = { 0 };
	xdp_trace_env_type env = { xdp, 0 };
	size_t i, n, fill_n;

	trace._env = &env;

	// --- drain receive queue --------------------------------------------

	n = xsk_ring_cons__peek( rx, XDP_RX_BATCH_SIZE, &rx_idx );

	// --- re-populate fill queue -----------------------------------------

	fill_idx = 0;
	fill_n = xsk_ring_prod__reserve( xdp->_fill_q, n, &fill_idx );
	if( fill_n != n ) { return -1; }
	xsk_ring_prod__submit( xdp->_fill_q, fill_n );

	for( i = 0; i < n; i++, rx_idx++ ) {
		struct xdp_desc const* desc = xsk_ring_cons__rx_desc( rx, rx_idx );
		uintptr_t addr = desc->addr;
		uint32_t len = desc->len;
		uint8_t const* p = xsk_umem__get_data( xdp->_umem->_buffer, addr );

		log_msg( LOG_NOTICE, "xdp.rx.desc: n=%zu idx=%u/%u addr=%zu len=%u", n,
			 rx_idx, fill_idx, addr, len );

		// --- process ------------------------------------------------

		trace._idx = 0;
		dissect_en10mb( &trace, p, len );
	}

	// --- rx done --------------------------------------------------------

	xsk_ring_cons__release( rx, n );

	// --- prepare tx -----------------------------------------------------

	for( i = 0; i < env._count; i++ ) {}

	return 0;
}

int xdp_server_init( xdp_server_type* xdp ) {
	u32 combined_queues = 0;
	u32 max_queues = 0;
	char mac[32];
	int rc;
	uint8_t const* p;

	rc = eth_dev_info( xdp );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "failed: eth_dev_info(): %s\n", strerror( errno ) );
		return rc;
	}

	p = xdp->_interface_hardware_address;
	snprintf( mac, 32, "%02x:%02x:%02x:%02x:%02x:%02x",    //
		  p[0], p[1], p[2], p[3], p[4], p[5] );
	log_msg( LOG_NOTICE, "xdp: interface_index=%d interface_hardware_address=%s",
		 xdp->_interface_index, mac );

	rc = eth_dev_promiscuous_enable( xdp );
	log_msg( LOG_NOTICE, "xdp: promiscous_enable_success=%d", rc == 0 );

	rc = ethtool_channels_get( xdp->_options._interface_name, &max_queues,
				   &combined_queues );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "failed: ethtool_channels_get(): %s\n",
			 strerror( errno ) );
		return rc;
	}

	log_msg( LOG_NOTICE, "xdp: max_queues=%u combined_queues=%u\n", max_queues,
		 combined_queues );

	xdp->_rx = region_alloc( xdp->_region, sizeof( xdp_queue_rx_type ) );
	xdp->_tx = region_alloc( xdp->_region, sizeof( xdp_queue_tx_type ) );
	xdp->_fill_q = region_alloc( xdp->_region, sizeof( struct xsk_ring_prod ) );
	xdp->_comp_q = region_alloc( xdp->_region, sizeof( struct xsk_ring_cons ) );
	xdp->_stats = region_alloc( xdp->_region, sizeof( struct xdp_statistics ) );
	xdp->_umem = region_alloc( xdp->_region, sizeof( xdp_umem_handle_type ) );

	if( xdp_umem_init( xdp ) != 0 ) {
		log_msg( LOG_ERR, "xdp_umem_init() failed" );
		return -1;
	}

	if( xdp_socket_init( xdp ) != 0 ) {
		log_msg( LOG_ERR, "xdp_socket_init() failed" );
		return -1;
	}

	return 0;
}

int xdp_server_deinit( xdp_server_type* xdp ) {
	if( xdp->_sock != NULL ) { xsk_socket__delete( xdp->_sock ); }
	if( xdp->_umem->_umem != NULL ) { xsk_umem__delete( xdp->_umem->_umem ); }
	if( xdp->_umem->_buffer != NULL ) {
		log_msg( LOG_NOTICE, "deallocating xdp umem buffer" );
		munmap( xdp->_umem->_buffer, xdp->_umem->_buffer_size );
	}
	return 0;
}
