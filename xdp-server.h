// Copyright (c) 2020, NLnet Labs. All rights reserved.
// See LICENSE for the details

#ifndef _NSD_XDP_SERVER_
#define _NSD_XDP_SERVER_

#define XDP_ETHER_ADDR_LEN    6
#define XDP_FRAME_SIZE	      2048
#define XDP_BUFFER_COUNT      4096
#define XDP_DESCRIPTORS_COUNT XSK_RING_CONS__DEFAULT_NUM_DESCS

#define ETH_AF_XDP_RX_BATCH_SIZE 32
#define ETH_AF_XDP_TX_BATCH_SIZE 32

typedef struct xdp_umem_handle {
	struct xsk_umem* _umem;
	void* _buffer;
	size_t _buffer_size;
} xdp_umem_handle_type;

typedef struct xdp_server_options {
	char const* _interface_name;
	int _queue_count;
	int _promiscious_mode;
} xdp_server_options_type;

typedef struct xdp_queue_stats {
	uint64_t _packets;
	uint64_t _bytes;
	uint64_t _dropped;
} xdp_queue_stats_type;

typedef struct xdp_queue_rx {
	xdp_queue_stats_type _stats;
	xdp_umem_handle_type* _umem;
	struct xsk_socket* _sock;
} xdp_queue_rx_type;

typedef struct xdp_queue_tx {
	xdp_queue_stats_type _stats;
	xdp_umem_handle_type* _umem;
	struct xsk_socket* _sock;
} xdp_queue_tx_type;

typedef struct xdp_server {
	xdp_server_options_type _options;
	region_type* _region;
	struct xdp_statistics* _stats;
	int _interface_index;
	uint8_t _interface_hardware_address[XDP_ETHER_ADDR_LEN];
	uint32_t _queue_index;
	xdp_umem_handle_type _umem;
	struct xsk_ring_prod* _fill_q;
	struct xsk_ring_cons* _comp_q;
	xdp_queue_rx_type* _rx;
	xdp_queue_tx_type* _tx;

} xdp_server_type;

int xdp_server_init( xdp_server_type* xdp );
int xdp_server_deinit( xdp_server_type* xdp );

#endif
