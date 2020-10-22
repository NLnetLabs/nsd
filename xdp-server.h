// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

#ifndef _NSD_XDP_SERVER_
#define _NSD_XDP_SERVER_

#define XDP_ETHER_ADDR_LEN 6
#define XDP_FRAME_SIZE 2048
#define XDP_DESCRIPTORS_PROD_COUNT XSK_RING_PROD__DEFAULT_NUM_DESCS
#define XDP_DESCRIPTORS_CONS_COUNT XSK_RING_CONS__DEFAULT_NUM_DESCS
#define XDP_DESCRIPTORS_TOTAL_COUNT                                                      \
	( XDP_DESCRIPTORS_PROD_COUNT + XDP_DESCRIPTORS_CONS_COUNT )

#define XDP_RX_BATCH_SIZE 32
#define XDP_TX_BATCH_SIZE XDP_RX_BATCH_SIZE

struct xdp_umem_handle;
struct xdp_queue_stats;
struct xdp_queue_rx;
struct xdp_queue_tx;

typedef struct xdp_server_options {
	char const* _interface_name;
	int _queue_count;
	int _promiscious_mode;
} xdp_server_options_type;

typedef struct xdp_server {
	struct xdp_server_options _options;
	region_type* _region;
	struct xdp_statistics* _stats;
	int _interface_index;
	uint8_t _interface_hardware_address[XDP_ETHER_ADDR_LEN];
	uint32_t _queue_index;
	struct xdp_umem_handle* _umem;
	struct xsk_ring_prod* _fill_q;
	struct xsk_ring_cons* _comp_q;
	struct xsk_socket* _sock;
	struct xdp_queue_rx* _rx;
	struct xdp_queue_tx* _tx;
	struct query** _queries;
	void* _nsd;
} xdp_server_type;

int xdp_server_process( xdp_server_type* sock );
int xdp_server_socket_fd( xdp_server_type* sock);
int xdp_server_init( xdp_server_type* xdp );
int xdp_server_deinit( xdp_server_type* xdp );

#endif
