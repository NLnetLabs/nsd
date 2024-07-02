/*
 * xdp-util.h -- set of xdp related helpers
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef XDP_UTIL_H
#define XDP_UTIL_H

int ethtool_channels_get(char const *ifname);

#endif /* XDP_UTIL_H */
