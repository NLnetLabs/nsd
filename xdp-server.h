// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

#ifndef _NSD_XDP_SERVER_
#define _NSD_XDP_SERVER_

#define XDP_ETHER_ADDR_LEN 6

typedef struct xdp_server_options {
	char const* _interface_name;
	int _queue_count;
	int _promiscious_mode;
} xdp_server_options_type;

typedef struct xdp_server {
	xdp_server_options_type _options;
	region_type* _region;
	int _interface_index;
	uint8_t _interface_hardware_address[XDP_ETHER_ADDR_LEN];
} xdp_server_type;

int xdp_server_init( xdp_server_type* xdp );
int xdp_server_deinit( xdp_server_type* xdp );

#endif
