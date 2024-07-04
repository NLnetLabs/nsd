/*
 * xdp-util.h -- set of xdp related helpers
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#ifdef USE_XDP

#include <errno.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/sockios.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "xdp-util.h"

int ethtool_channels_get(char const *ifname) {
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, rc;
	int queue_count = 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		return -1;
	}

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void *)&channels;
	strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	if (rc != 0) {
		if (errno != EOPNOTSUPP) {
			close(fd);
			return -errno;
		}
	}

	if (errno == EOPNOTSUPP) {
		queue_count = 1;
	} else {
		/* ethtool_channels offers
		 * max_{rx,tx,other,combined} and
		 * {rx,tx,other,combined}_count
		 *
		 * Maybe check for different variations of rx/tx and combined
         * queues in the future? */
		if (channels.combined_count > 0) {
			queue_count = channels.combined_count;
		} else if (channels.rx_count > 0) {
			queue_count = channels.rx_count;
		} else {
			queue_count = 1;
		}
	}

	close(fd);
	return queue_count;
}

#endif /* USE_XDP */
