/*
Copyright (c) 2020, NLnet Labs. All rights reserved.
See LICENSE for the details

derived from:
  - https://github.com/DPDK/dpdk/blob/main/drivers/net/af_xdp/rte_eth_af_xdp.c

SPDX-License-Identifier: BSD-3-Clause
Copyright(c) 2019-2020 Intel Corporation.
*/

/*
TODO:
  - options:
    - huge_tables
    - queue_index
    - promicious_mode
    - inhibit_bpf_prog_load
    - batch size
    - XDP_UMEM_UNALIGNED_CHUNK_FLAG
    - checksum offloading
    - statistics and counters rx/tx/dropped/...
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

/* --- override dissector visitor callbacks ------------------------------- */

struct dissect_trace;
static inline void xdp_dissect_trace_udp(struct dissect_trace* const trace,
					 uint8_t const* const begin,
					 uint8_t const* const end);
#define DISSECT_CUSTOM_TRACE_UDP_FN xdp_dissect_trace_udp
#include "xdp-dissect.h"

/* ------------------------------------------------------------------------ */

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
	uint32_t _packet_prefix_size[XDP_BATCH_SIZE];
	uint32_t _count;
} xdp_trace_env_type;

static int eth_dev_change_flags(char const* if_name, uint32_t flags, uint32_t mask)
{
	struct ifreq ifr;
	int s;

	s = socket(PF_INET, SOCK_DGRAM, 0);
	if(s < 0)
		return -errno;

	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	if(ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		close(s);
		return -errno;
	}

	ifr.ifr_flags &= mask;
	ifr.ifr_flags |= flags;
	if(ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		close(s);
		return -errno;
	}

	return 0;
}

static int eth_dev_promiscuous_enable(xdp_server_type* xdp)
{
	return eth_dev_change_flags(xdp->_options._interface_name, IFF_PROMISC, ~0u);
}

static int eth_dev_promiscuous_disable(xdp_server_type* xdp)
{
	return eth_dev_change_flags(xdp->_options._interface_name, 0u, ~IFF_PROMISC);
}

static int eth_dev_info(xdp_server_type* xdp)
{
	struct ifreq ifr;
	int sock;

	sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if(sock < 0) {
		return -1;
	}

	strlcpy(ifr.ifr_name, xdp->_options._interface_name, IFNAMSIZ);
	if(ioctl(sock, SIOCGIFINDEX, &ifr)) {
		goto error;
	}
	xdp->_interface_index = ifr.ifr_ifindex;

	if(ioctl(sock, SIOCGIFHWADDR, &ifr)) {
		goto error;
	}
	memcpy(xdp->_interface_hardware_address, ifr.ifr_hwaddr.sa_data,
	       XDP_ETHER_ADDR_LEN);

	close(sock);
	return 0;

error:
	close(sock);
	return -1;
}

static int ethtool_channels_get(char const* if_name, u32* max_queues, u32* combined_queues)
{
	struct ethtool_channels channels;
	struct ifreq ifr;
	int fd, rc;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0) {
		return -1;
	}

	channels.cmd = ETHTOOL_GCHANNELS;
	ifr.ifr_data = (void*)&channels;
	strlcpy(ifr.ifr_name, if_name, IFNAMSIZ);
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	if(rc != 0) {
		if(errno != EOPNOTSUPP) {
			close(fd);
			return -errno;
		}
	}

	if(channels.max_combined == 0 || errno == EOPNOTSUPP) {
		/* If the device says it has no channels, then all traffic
		   is sent to a single stream, so max queues = 1 */
		*max_queues = 1;
		*combined_queues = 1;
	} else {
		*max_queues = channels.max_combined;
		*combined_queues = channels.combined_count;
	}

	close(fd);
	return 0;
}

static int xdp_socket_stats(xdp_server_type* xdp)
{
	socklen_t optlen = sizeof(struct xdp_statistics);
	int rc;

	assert(xdp->_rx->_sock != NULL);
	rc = getsockopt(xsk_socket__fd(xdp->_rx->_sock), SOL_XDP, XDP_STATISTICS,
			&xdp->_stats, &optlen);
	if(rc != 0) {
		log_msg(LOG_ERR, "getsockopt() failed\n");
		return -1;
	}

	return 0;
}

static inline int xdp_fill_queue_reserve(struct xsk_ring_prod* fq, uint16_t n)
{
	uint16_t i;
	u32 idx;
	int rc;

	rc = xsk_ring_prod__reserve(fq, n, &idx);
	if(rc != n) {
		return -1;
	}
	for(i = 0; i < n; i++) {
		__u64* descriptor_address = xsk_ring_prod__fill_addr(fq, idx);
		descriptor_address[0] = (__u64)i * XDP_FRAME_SIZE;
		idx++;
	}

	xsk_ring_prod__submit(fq, n);

	return 0;
}

static int xdp_socket_init(xdp_server_type* xdp)
{
	struct xsk_socket_config config = {
		.rx_size = XDP_DESCRIPTORS_CONS_COUNT,
		.tx_size = XDP_DESCRIPTORS_PROD_COUNT,
		/* .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD, */
		.libbpf_flags = 0,
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST,
		.bind_flags = XDP_USE_NEED_WAKEUP,
	};
	int rc;

	xdp->_rx->_umem = xdp->_umem;
	xdp->_tx->_umem = xdp->_umem;

	log_msg(LOG_NOTICE, "xdp.socket.config: rx_size=%u tx_size=%u queue=%d",
		config.rx_size, config.tx_size, xdp->_queue_index);

	rc = xsk_socket__create(&xdp->_sock, xdp->_options._interface_name,
				xdp->_queue_index, xdp->_umem->_umem, &xdp->_rx->_rx,
				&xdp->_tx->_tx, &config);
	if(rc != 0) {
		log_msg(LOG_ERR, "xsk_socket__create() failed: %s ( rc = %d )",
			strerror(-rc), rc);
		return rc;
	}

	log_msg(LOG_NOTICE, "xdp.socket: fd=%d", xsk_socket__fd(xdp->_sock));

	if(xdp_fill_queue_reserve(xdp->_fill_q, XDP_DESCRIPTORS_TOTAL_COUNT) != 0) {
		xsk_socket__delete(xdp->_sock);
		return -1;
	}

	return 0;
}

static int xdp_umem_init(xdp_server_type* xdp)
{
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

	log_msg(LOG_NOTICE, "xdp.umem.config: fill_size=%u comp_size=%u frame_size=%u",
		config.fill_size, config.comp_size, config.frame_size);

	xdp->_umem->_umem = NULL;
	/* `MMAP_SHARED` is actually needed because of the forking nature of nsd */
	buffer = mmap(NULL, buffer_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED | MAP_ANONYMOUS /*| MAP_HUGETLB*/, -1, 0);
	log_msg(LOG_NOTICE, "xdp.umem: buffer_size=%zu buffer_allocate_success=%d",
		buffer_size, buffer != MAP_FAILED);
	if(buffer == MAP_FAILED) {
		return -1;
	}

	rc = xsk_umem__create(&xdp->_umem->_umem, buffer, buffer_size, xdp->_fill_q,
			      xdp->_comp_q, &config);
	if(rc != 0) {
		log_msg(LOG_ERR, "xsk_umem__create() failed: %s ( %d )", strerror(errno),
			errno);
		munmap(buffer, buffer_size);
		return -1;
	}

	xdp->_umem->_buffer = buffer;
	xdp->_umem->_buffer_size = buffer_size;

	return 0;
}

int xdp_server_socket_fd(xdp_server_type* sock)
{
	assert(sock != NULL && sock->_sock != NULL);
	return xsk_socket__fd(sock->_sock);
}

static void xdp_completion_queue_release(xdp_server_type* xdp, size_t size)
{
	size_t n;
	uint32_t idx = 0;
	n = xsk_ring_cons__peek(xdp->_comp_q, size, &idx);
	xsk_ring_cons__release(xdp->_comp_q, n);
}

static void xdp_kick_tx(xdp_server_type* xdp)
{
	xdp_completion_queue_release(xdp, XDP_DESCRIPTORS_CONS_COUNT);
	if(!xsk_ring_prod__needs_wakeup(&xdp->_tx->_tx)) {
		return;
	}
	while(send(xdp_server_socket_fd(xdp), NULL, 0, MSG_DONTWAIT) < 0) {
		if(errno != EBUSY && errno != EAGAIN && errno != EINTR) {
			break;
		}
		if(errno == EAGAIN) {
			xdp_completion_queue_release(xdp, XDP_DESCRIPTORS_CONS_COUNT);
		}
	}
}

static inline void buffer_groom_right(buffer_type* buffer, size_t n)
{
	assert(n < buffer->_capacity);
	buffer->_data += n;
	buffer->_capacity -= n;
}

static inline void buffer_groom_left(buffer_type* buffer, size_t n)
{
	buffer->_data -= n;
	buffer->_limit += n;
	buffer->_capacity += n;
}

static inline void xdp_rewrite_swap(uint8_t scratch[XDP_PACKET_PREFIX_SIZE_ALLOWED_MAX],
				    uint8_t* a, uint8_t* b, size_t size)
{
	memcpy(scratch, a, size);
	memcpy(a, b, size);
	memcpy(b, scratch, size);
}

static inline void xdp_rewrite_shuffle(uint8_t scratch[XDP_PACKET_PREFIX_SIZE_ALLOWED_MAX],
				       uint8_t* a, size_t size)
{
	uint8_t* b = a + size;
	xdp_rewrite_swap(scratch, a, b, size);
}

#define XDP_REWRITE_ETH_MAC_SIZE 6

#define XDP_REWRITE_IPV4_OFFSET 12
#define XDP_REWRITE_IPV4_SIZE 4
#define XDP_REWRITE_IPV4_CHECKSUM_OFFSET 10
#define XDP_REWRITE_IPV4_CHECKSUM_SIZE 2
#define XDP_REWRITE_IPV4_TTL_OFFSET 8
#define XDP_REWRITE_IPV4_TTL_SIZE 2

#define XDP_REWRITE_UDP_OFFSET 0
#define XDP_REWRITE_UDP_SIZE 2
#define XDP_REWRITE_UDP_CHECKSUM_OFFSET 6
#define XDP_REWRITE_UDP_CHECKSUM_SIZE 2
#define XDP_REWRITE_UDP_LENGTH_OFFSET 4

#define XDP_REWRITE_IPV4_TOTAL_LENGTH_OFFSET 2

static inline void xdp_dissect_rewrite_packet_prefix(struct dissect_trace* const trace,
						     uint8_t* packet_ptr,
						     size_t const packet_prefix_size,
						     size_t const payload_size)
{
	uint8_t scratch[XDP_PACKET_PREFIX_SIZE_ALLOWED_MAX];
	uint32_t i, visited_layers = 0, handled_layers = 0;
	uint8_t const* begin = dissect_trace_at(trace, 0)->_begin;

	/* copy everything into the outgoing buffer and then modify inplace there */
	memcpy(packet_ptr, begin, packet_prefix_size);

	for(i = 0; i < dissect_trace_layers(trace); i++) {
		dissect_trace_entry_type const* entry = dissect_trace_at(trace, i);
		uint32_t layer_offset = dissect_trace_layer_offset(trace, i);
		uint8_t* const output_ptr = packet_ptr + layer_offset;
		visited_layers |= entry->_tag;
		switch(entry->_tag) {
		case DISSECT_ETH: {
			xdp_rewrite_shuffle(scratch, output_ptr, XDP_REWRITE_ETH_MAC_SIZE);
			handled_layers |= entry->_tag;
			break;
		}
		case DISSECT_IPV4: {
			/* TODO: checksum, ttl */
			uint16_t checksum = 0;
			uint16_t length = (uint16_t)(
				dissect_trace_layer_offset(trace, i + 1) -
				dissect_trace_layer_offset(trace, i) + payload_size + 8);
			xdp_rewrite_shuffle(scratch, output_ptr + XDP_REWRITE_IPV4_OFFSET,
					    XDP_REWRITE_IPV4_SIZE);
			memcpy(output_ptr + XDP_REWRITE_IPV4_CHECKSUM_OFFSET, &checksum,
			       XDP_REWRITE_IPV4_CHECKSUM_SIZE);

			log_msg(LOG_NOTICE, "xdp: !!! length=%u", length);
			poke_be16(output_ptr + XDP_REWRITE_IPV4_TOTAL_LENGTH_OFFSET,
				  length);
			handled_layers |= entry->_tag;
			break;
		}
		case DISSECT_IPV6: {
			handled_layers |= entry->_tag;
			break;
		}
		case DISSECT_UDP: {
			/* TODO: checksum */
			uint16_t checksum = 0;
			xdp_rewrite_shuffle(scratch, output_ptr + XDP_REWRITE_UDP_OFFSET,
					    XDP_REWRITE_UDP_SIZE);
			memcpy(output_ptr + XDP_REWRITE_UDP_CHECKSUM_OFFSET, &checksum,
			       XDP_REWRITE_UDP_CHECKSUM_SIZE);
			poke_be16(output_ptr + XDP_REWRITE_UDP_LENGTH_OFFSET,
				  payload_size + 8);
			handled_layers |= entry->_tag;
			break;
		}
		default:
			handled_layers |= DISSECT_UNKNOWN;
			break;
		}
	}

	log_msg(LOG_NOTICE,
		"xdp: ~~~ dissect: payload_size=%zu, layers=%u, visited_layers=%04x handled_layers=%04x",
		payload_size, dissect_trace_layers(trace), visited_layers, handled_layers);
}

static inline void xdp_dissect_trace_udp(struct dissect_trace* const trace,
					 uint8_t const* const begin,
					 uint8_t const* const end)
{
	xdp_trace_env_type* env = trace->_env;
	size_t packet_prefix_size = 8u + (size_t)(begin - trace->_stack[0]._begin);
	uint16_t const src_port = peek_be16(begin);
	uint16_t const dst_port = peek_be16(begin + 2);
	uint16_t const udp_len = peek_be16(begin + 4);
	struct query* q = env->_xdp->_queries[env->_count];
	ptrdiff_t const len = end - begin;
	uint8_t* packet_prefix_ptr = NULL;
	assert(udp_len <= len);
	if(dst_port != 53 || udp_len > len || udp_len < 8 ||
	   packet_prefix_size > XDP_PACKET_PREFIX_SIZE_ALLOWED_MAX) {
		return;
	}

	log_msg(LOG_NOTICE, "xdp: ... got udp src_port=%d dst_port=%d prefix_size=%zu",
		src_port, dst_port, packet_prefix_size);

	/* TODO: query addrlen */
	assert(packet_prefix_size > 0);

	/* leave room in the front of the buffer such that we
	 * can rewrite the packet header for the response later on */
	packet_prefix_ptr = q->packet->_data;
	buffer_groom_right(q->packet, packet_prefix_size);

	/* prepare udp payload for processing */
	buffer_write(q->packet, begin + 8, udp_len - 8);
	buffer_flip(q->packet);
	if(query_process(q, env->_xdp->_nsd) != QUERY_DISCARDED) {
		struct nsd* nsd = env->_xdp->_nsd;
		size_t payload_size;
		if(RCODE(q->packet) == RCODE_OK && !AA(q->packet)) {
			STATUP(nsd, nona);
			ZTATUP(nsd, q->zone, nona);
		}

		/* TODO: update stats ( bind and zone ) */

		/* add EDNS0 and TSIG info if necessary */
		query_add_optional(q, nsd);
		buffer_flip(q->packet);
		payload_size = buffer_remaining(q->packet);
		buffer_groom_left(q->packet, packet_prefix_size);
		log_msg(LOG_NOTICE, "xdp: ... response: payload_size=%zu remaining=%zu",
			payload_size, buffer_remaining(q->packet));
		xdp_dissect_rewrite_packet_prefix(trace, packet_prefix_ptr,
						  packet_prefix_size, payload_size);
		env->_count++;
	} else {
		query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
		log_msg(LOG_NOTICE, "query discarded");
	}
}

int xdp_server_process(xdp_server_type* xdp)
{
	struct xsk_ring_cons* rx_q = &xdp->_rx->_rx;
	struct xsk_ring_prod* tx_q = &xdp->_tx->_tx;
	uint32_t tx_retries, tx_count = 0, tx_idx = 0, rx_idx = 0, fill_idx = 0;
	dissect_trace_type trace;
	xdp_trace_env_type env;
	size_t i, j, n, fill_n, rx_count;
	uintptr_t _umem_offsets[XDP_BATCH_SIZE];

	env._count = 0;
	env._xdp = xdp;
	trace._env = &env;
	trace._idx = 0;

	/* --- drain receive queue ---------------------------------------- */

	rx_count = n = xsk_ring_cons__peek(rx_q, XDP_BATCH_SIZE, &rx_idx);

	/* --- re-populate fill queue ------------------------------------- */

	fill_idx = 0;
	fill_n = xsk_ring_prod__reserve(xdp->_fill_q, n, &fill_idx);
	if(fill_n != n) {
		return -1;
	}
	xsk_ring_prod__submit(xdp->_fill_q, fill_n);

	for(i = 0; i < n; i++, rx_idx++) {
		struct xdp_desc const* desc = xsk_ring_cons__rx_desc(rx_q, rx_idx);
		uintptr_t addr = desc->addr;
		uint32_t len = desc->len;
		uint8_t const* p = xsk_umem__get_data(xdp->_umem->_buffer, addr);
		_umem_offsets[i] = addr;

		log_msg(LOG_NOTICE, "xdp: ==> [%zu/%zu]: addr=%zu len=%u rx_idx=%u/%u ",
			i, n, addr, len, rx_idx, fill_idx);

		/* --- process -------------------------------------------- */

		trace._idx = 0;
		trace._stack[0]._begin = NULL;
		dissect_en10mb(&trace, p, len);
	}

	/* --- rx done ---------------------------------------------------- */

	xsk_ring_cons__release(rx_q, n);

	/* --- reserve tx descriptors:prepare tx -------------------------- */

	for(tx_retries = 0, i = 0; tx_count < env._count;) {
		if(tx_retries > 42) {
			break;
		}
		n = xsk_ring_prod__reserve(tx_q, env._count, &tx_idx);
		if(n != env._count) {
			tx_retries++;
			xdp_kick_tx(xdp);
			continue;
		}
		tx_count = env._count;
	}

	if(tx_count != env._count) {
		log_msg(LOG_NOTICE, "xdp: *** tx failed");
	}

	/* --- fill tx descriptors ---------------------------------------- */

	for(j = 0, i = 0; i < rx_count; i++) {
		struct query* q = xdp->_queries[i];
		struct xdp_desc* desc;
		uint8_t* p;
		if(buffer_remaining(q->packet) == 0 ||
		   buffer_remaining(q->packet) > UDP_MAX_MESSAGE_LEN) {
			log_msg(LOG_NOTICE, "xdp: !!! skip=%zu", i);
			continue;
		} else if(buffer_remaining(q->packet) > XDP_FRAME_SIZE) {
			log_msg(LOG_ERR, "xdp: invalid udp payload size=%zu",
				buffer_remaining(q->packet));
			query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
			continue;
		}
		desc = xsk_ring_prod__tx_desc(tx_q, tx_idx + j);
		p = xsk_umem__get_data(xdp->_umem->_buffer, _umem_offsets[j]);
		memcpy(p, buffer_begin(q->packet), buffer_remaining(q->packet));
		desc->addr = _umem_offsets[j++];
		desc->len = (uint32_t)buffer_remaining(q->packet);
		log_msg(LOG_NOTICE, "xdp: <== [%zu/%u] desc.addr=%llu desc.len: %u", j,
			tx_idx + j, desc->addr, desc->len);
		query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
	}

	/* --- submit tx -------------------------------------------------- */

	xsk_ring_prod__submit(tx_q, j);

	xdp_kick_tx(xdp);

	return j != env._count;
}

int xdp_server_init(xdp_server_type* xdp)
{
	u32 combined_queues = 0;
	u32 max_queues = 0;
	char mac[32];
	int rc;
	uint8_t const* p;

	rc = eth_dev_info(xdp);
	if(rc != 0) {
		log_msg(LOG_ERR, "failed: eth_dev_info(): %s\n", strerror(errno));
		return rc;
	}

	p = xdp->_interface_hardware_address;
	snprintf(mac, 32, "%02x:%02x:%02x:%02x:%02x:%02x", /**/
		 p[0], p[1], p[2], p[3], p[4], p[5]);
	log_msg(LOG_NOTICE, "xdp: interface_index=%d interface_hardware_address=%s",
		xdp->_interface_index, mac);

	rc = eth_dev_promiscuous_enable(xdp);
	log_msg(LOG_NOTICE, "xdp: promiscous_enable_success=%d", rc == 0);

	rc = ethtool_channels_get(xdp->_options._interface_name, &max_queues,
				  &combined_queues);
	if(rc != 0) {
		log_msg(LOG_ERR, "failed: ethtool_channels_get(): %s\n", strerror(errno));
		return rc;
	}

	log_msg(LOG_NOTICE, "xdp: max_queues=%u combined_queues=%u\n", max_queues,
		combined_queues);

	xdp->_rx = region_alloc(xdp->_region, sizeof(xdp_queue_rx_type));
	xdp->_tx = region_alloc(xdp->_region, sizeof(xdp_queue_tx_type));
	xdp->_fill_q = region_alloc(xdp->_region, sizeof(struct xsk_ring_prod));
	xdp->_comp_q = region_alloc(xdp->_region, sizeof(struct xsk_ring_cons));
	xdp->_stats = region_alloc(xdp->_region, sizeof(struct xdp_statistics));
	xdp->_umem = region_alloc(xdp->_region, sizeof(xdp_umem_handle_type));

	if(xdp_umem_init(xdp) != 0) {
		log_msg(LOG_ERR, "xdp_umem_init() failed");
		return -1;
	}

	if(xdp_socket_init(xdp) != 0) {
		log_msg(LOG_ERR, "xdp_socket_init() failed");
		return -1;
	}

	return 0;
}

int xdp_server_deinit(xdp_server_type* xdp)
{
	if(xdp->_sock != NULL) {
		xsk_socket__delete(xdp->_sock);
	}
	if(xdp->_umem->_umem != NULL) {
		xsk_umem__delete(xdp->_umem->_umem);
	}
	if(xdp->_umem->_buffer != NULL) {
		log_msg(LOG_NOTICE, "xdp: deallocating umem");
		munmap(xdp->_umem->_buffer, xdp->_umem->_buffer_size);
	}
	return 0;
}
