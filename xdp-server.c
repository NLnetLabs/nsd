// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

// derived from:
//   - https://github.com/DPDK/dpdk/blob/main/drivers/net/af_xdp/rte_eth_af_xdp.c
// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2019-2020 Intel Corporation.

#include "config.h"

#include "region-allocator.h"

#include "xdp-dissect.h"
#include "xdp-server.h"

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

static int ethtool_channels_get(
	char const* if_name, u32* max_queues, u32* combined_queues ) {
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, ret;

	fd = socket( AF_INET, SOCK_DGRAM, 0 );
	if( fd < 0 ) return -1;

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void*)&channels;
	strncpy( ifr.ifr_name, if_name, IFNAMSIZ );
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
		/* If the device says it has no channels, then all traffic
		 * is sent to a single stream, so max queues = 1.
		 */
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

int xdp_server_init( xdp_server_type* xdp ) {
	(void)xdp;
	return 0;
}

int xdp_server_deinit( xdp_server_type* xdp ) {
	(void)xdp;
	return 0;
}
