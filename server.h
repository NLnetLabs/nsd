/*
 * server.h -- nsd(8) network input/output
 *
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef NSD_SERVER_H
#define NSD_SERVER_H
#include "nsd.h"
#include "netio.h"

void close_all_sockets(struct nsd_socket sockets[], size_t n);

void netio_add_udp_handlers(netio_type* netio, struct nsd* nsd,
	region_type* region, struct nsd_socket* udp_socket, size_t n);

void netio_add_tcp_handlers(netio_type* netio, struct nsd* nsd,
	region_type* region, struct nsd_socket* tcp_socket, size_t n);


#endif /* NSD_SERVER_H */

