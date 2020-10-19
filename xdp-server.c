// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

// derived from:
//   - https://github.com/DPDK/dpdk/blob/main/drivers/net/af_xdp/rte_eth_af_xdp.c
// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2019-2020 Intel Corporation.

#include "config.h"

#include "region-allocator.h"
#include "util.h"

#include "xdp-dissect.h"

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

typedef uint32_t u32;
typedef uint16_t u16;

static int eth_dev_change_flags( char const* if_name, uint32_t flags, uint32_t mask ) {
	int s = socket( PF_INET, SOCK_DGRAM, 0 );
	if( s < 0 ) return -errno;

	struct ifreq ifr;
	strlcpy( ifr.ifr_name, if_name, IFNAMSIZ );
	int ret = 0;
	if( ioctl( s, SIOCGIFFLAGS, &ifr ) < 0 ) {
		ret = -errno;
		goto out;
	}
	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if( ioctl( s, SIOCSIFFLAGS, &ifr ) < 0 ) {
		ret = -errno;
		goto out;
	}
out:
	close( s );
	return ret;
}

static int eth_dev_promiscuous_enable( xdp_server_type* xdp ) {

	return eth_dev_change_flags( xdp->_options._interface_name, IFF_PROMISC, ~0u );
}

static int eth_dev_promiscuous_disable( xdp_server_type* xdp ) {

	return eth_dev_change_flags( xdp->_options._interface_name, 0u, ~IFF_PROMISC );
}

static int eth_dev_info( xdp_server_type* xdp ) {
	int sock = socket( AF_INET, SOCK_DGRAM, IPPROTO_IP );
	if( sock < 0 ) return -1;

	struct ifreq ifr;
	strlcpy( ifr.ifr_name, xdp->_options._interface_name, IFNAMSIZ );
	if( ioctl( sock, SIOCGIFINDEX, &ifr ) ) goto error;

	xdp->_interface_index = ifr.ifr_ifindex;

	if( ioctl( sock, SIOCGIFHWADDR, &ifr ) ) goto error;

	memcpy( xdp->_interface_hardware_address, ifr.ifr_hwaddr.sa_data,
		XDP_ETHER_ADDR_LEN );

	close( sock );
	return 0;

error:
	close( sock );
	return -1;
}

static int ethtool_channels_get(
	char const* if_name, u32* max_queues, u32* combined_queues ) {
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, ret;

	fd = socket( AF_INET, SOCK_DGRAM, 0 );
	if( fd < 0 ) return -1;

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void*)&channels;
	strlcpy( ifr.ifr_name, if_name, IFNAMSIZ );
	ret = ioctl( fd, SIOCETHTOOL, &ifr );
	if( ret ) {
		if( errno == EOPNOTSUPP ) {
			ret = 0;
		} else {
			ret = -errno;
			goto out;
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

out:
	close( fd );
	return ret;
}

int xdp_socket_stats( xdp_server_type* xdp ) {
	socklen_t optlen = sizeof( struct xdp_statistics );
	assert( xdp->_rx->_sock != NULL );
	int rc = getsockopt( xsk_socket__fd( xdp->_rx->_sock ), SOL_XDP, XDP_STATISTICS,
		&xdp->_stats, &optlen );
	if( rc != 0 ) {
		log_msg( LOG_ERR, "getsockopt() failed\n" );
		return -1;
	}
}

int xdp_umem_init( xdp_server_type* xdp ) {
	struct xsk_umem_config config = {
		.fill_size = XDP_DESCRIPTORS_COUNT * 2,
		.comp_size = XDP_DESCRIPTORS_COUNT,
		.flags = XDP_UMEM_UNALIGNED_CHUNK_FLAG,
		.frame_size = XDP_FRAME_SIZE,
		.frame_headroom = 0,
	};

	size_t const buffer_size = XDP_FRAME_SIZE * XDP_BUFFER_COUNT;
	void* buffer = NULL;
	buffer = mmap( NULL, buffer_size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS /*| MAP_HUGETLB*/, -1, 0 );
	log_msg( LOG_NOTICE, "xdp.umem.buffer_size=%zu xdp.umem.buffer.allocate_success=%d",
		buffer_size, buffer != MAP_FAILED );
	if( buffer == MAP_FAILED ) { return -1; }

	int rc_umem = xsk_umem__create( &xdp->_umem._umem, buffer, buffer_size,
		xdp->_fill_q, xdp->_comp_q, NULL );
	if( rc_umem != 0 ) {
		log_msg( LOG_ERR, "xsk_umem__create() failed: %s ( %d )",
			strerror( errno ), errno );
		munmap( buffer, buffer_size );
		return -1;
	}

	xdp->_umem._buffer = buffer;
	xdp->_umem._buffer_size = buffer_size;

	return 0;
}

int xdp_server_init( xdp_server_type* xdp ) {
	(void)xdp;

	u32 max_queues = 0;
	u32 combined_queues = 0;

	int rc_info = eth_dev_info( xdp );
	if( rc_info != 0 ) {
		log_msg( LOG_ERR, "failed: eth_dev_info(): %s\n", strerror( -errno ) );
		return rc_info;
	}

	char mac[32];
	uint8_t const* p = xdp->_interface_hardware_address;
	snprintf( mac, 32, "%02x:%02x:%02x:%02x:%02x:%02x",    //
		p[0], p[1], p[2], p[3], p[4], p[5] );
	log_msg( LOG_NOTICE, "xdp.interface_index=%d xdp.interface_hardware_address=%s",
		xdp->_interface_index, mac );

	int rc_queues = ethtool_channels_get(
		xdp->_options._interface_name, &max_queues, &combined_queues );
	if( rc_queues != 0 ) {
		log_msg( LOG_ERR, "failed: ethtool_channels_get(): %s\n",
			strerror( errno ) );
		return rc_queues;
	}

	log_msg( LOG_NOTICE, "xdp.max_queues=%u xdp.combined_queues=%u\n", max_queues,
		combined_queues );

	xdp->_rx = region_alloc( xdp->_region, sizeof( xdp_queue_rx_type ) );
	xdp->_tx = region_alloc( xdp->_region, sizeof( xdp_queue_tx_type ) );
	xdp->_fill_q = region_alloc( xdp->_region, sizeof( struct xsk_ring_prod ) );
	xdp->_comp_q = region_alloc( xdp->_region, sizeof( struct xsk_ring_cons ) );
	xdp->_stats = region_alloc( xdp->_region, sizeof( struct xdp_statistics ) );
	xdp->_umem = ( xdp_umem_handle_type ){ 0 };

	xdp_umem_init( xdp );

	return 0;
}

int xdp_server_deinit( xdp_server_type* xdp ) {
	if( xdp->_umem._buffer != NULL ) {
		log_msg( LOG_NOTICE, "deallocating xdp umem buffer" );
		munmap( xdp->_umem._buffer, xdp->_umem._buffer_size );
	}
	return 0;
}
