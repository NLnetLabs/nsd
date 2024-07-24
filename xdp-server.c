/*
 * xdp-server.c -- integration of AF_XDP into nsd
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

/*
 * Parts inspired by https://github.com/xdp-project/xdp-tutorial
 */

#include "config.h"

#ifdef USE_XDP

#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/limits.h>

#include <sys/poll.h>
#include <sys/resource.h>

/* #include <bpf/bpf.h> */
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <net/if.h>

#include "query.h"
#include "dns.h"
#include "region-allocator.h"
#include "util.h"
#include "xdp-server.h"
#include "xdp-util.h"
#include "nsd.h"

#define DNS_PORT 53

struct xdp_config {
	__u32 xdp_flags;
	__u32 libxdp_flags;
	__u16 xsk_bind_flags;
};

/*
 * Allocate memory for UMEM and setup rings
 */
static int
xsk_configure_umem(struct xsk_umem_info *umem_info, void *buffer, uint64_t size);

/*
 * Allocate a frame in UMEM
 */
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk);

/*
 * Bind AF_XDP socket and setup rings
 */
static int
xsk_configure_socket(struct xdp_server *xdp, struct xsk_umem_info *umem);

/*
 * Get number of free frames in UMEM
 */
static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk);

/*
 * Free a frame in UMEM
 */
static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint16_t frame);

/*
 * Load eBPF program to forward traffic to our socket
 */
static int load_xdp_program(struct xdp_server *xdp);

static int unload_xdp_program(struct xdp_server *xdp);

/*
 * Send outstanding packets and recollect completed frame addresses
 */
static void handle_tx(struct xsk_socket_info *xsk);

/*
 * Process packet and indicate if it should be dropped
 * return 0 => drop
 * return non-zero => use for tx
 */
static int
process_packet(struct xdp_server *xdp,
               uint8_t *pkt,
               uint64_t addr,
               uint32_t *len,
               struct query *query);

static inline void swap_eth(struct ethhdr *eth);
static inline void swap_udp(struct udphdr *udp);
static inline void swap_ipv6(struct ipv6hdr *ipv6);
static inline void swap_ipv4(struct iphdr *ipv4);
static inline void *parse_udp(struct udphdr *udp);
static inline void *parse_ipv6(struct ipv6hdr *ipv6);
static inline void *parse_ipv4(struct iphdr *ipv4);

/*
 * Parse dns message and return new length of dns message
 */
static int parse_dns(struct nsd* nsd,
                     void *dnshdr,
                     uint32_t dnslen,
                     struct query *q);

/* *************** */
/* Implementations */
/* *************** */

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
	uint64_t frame;
	if (xsk->umem->umem_frame_free == 0) {
		return XDP_INVALID_UMEM_FRAME;
	}

	frame = xsk->umem->umem_frame_addr[--xsk->umem->umem_frame_free];
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free] = XDP_INVALID_UMEM_FRAME;
	return frame;
}

static uint64_t xsk_umem_free_frames(struct xsk_socket_info *xsk) {
	return xsk->umem->umem_frame_free;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint16_t frame) {
	assert(xsk->umem_frame_free < XDP_NUM_FRAMES);
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free++] = frame;
}

/* TODO: rename or split up functionality (cause of map assignment and attaching) */
static int load_xdp_program(struct xdp_server *xdp) {
	struct bpf_map *map;
	char errmsg[512];
	int err, ret;
	// TODO: put this into a config option as well?
	enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC; /* UNSPEC => let libxdp decide */

	DECLARE_LIBXDP_OPTS(bpf_object_open_opts, opts);
	if (xdp->bpf_bpffs_path)
		opts.pin_root_path = xdp->bpf_bpffs_path;

	/* for now our xdp program should contain just one program section */
	// TODO: look at xdp_program__create because it can take a pinned prog
	xdp->bpf_prog = xdp_program__open_file(xdp->bpf_prog_filename, NULL, &opts);
	err = libxdp_get_error(xdp->bpf_prog);
	if (err) {
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		log_msg(LOG_ERR, "xdp: could not open xdp program: %s\n", errmsg);
		return err;
	}

	if (xdp->bpf_prog_should_load) {
		err = xdp_program__attach(xdp->bpf_prog, xdp->interface_index, attach_mode, 0);
		if (err) {
			libxdp_strerror(err, errmsg, sizeof(errmsg));
			log_msg(LOG_ERR, "xdp: could not attach xdp program to interface '%s' : %s\n", 
					xdp->interface_name, errmsg);
			return err;
		}

		/* We also need to get the file descriptor to the xsks_map */
		map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp->bpf_prog), "xsks_map");
		ret = bpf_map__fd(map);
		if (ret < 0) {
			log_msg(LOG_ERR, "xdp: no xsks map found in xdp program: %s\n", strerror(ret));
			return err;
		}
		xdp->xsk_map_fd = ret;
		xdp->xsk_map = map;
	} else {
		char map_path[PATH_MAX];
		int fd;

		snprintf(map_path, PATH_MAX, "%s/%s", xdp->bpf_bpffs_path, "xsks_map");

		fd = bpf_obj_get(map_path);
		if (fd < 0) {
			log_msg(LOG_ERR, "xdp: could not retrieve xsks_map pin: %s\n", strerror(errno));
			return fd;
		}

		map = bpf_object__find_map_by_name(xdp_program__bpf_obj(xdp->bpf_prog), "xsks_map");
		if ((ret = bpf_map__reuse_fd(map, fd))) {
			log_msg(LOG_ERR, "xdp: could not re-use xsks_map: %s\n", strerror(errno));
			return ret;
		}

		xdp->xsk_map_fd = fd;
		xdp->xsk_map = map;
	}

	return 0;
}

static int
xsk_configure_umem(struct xsk_umem_info *umem_info, void *buffer, uint64_t size) {
	int ret;

	ret = xsk_umem__create(&umem_info->umem, buffer, size, &umem_info->fq, &umem_info->cq, NULL);
	if (ret) {
		errno = -ret;
		return -ret;
	}

	return 0;
}

static int
xsk_configure_socket(struct xdp_server *xdp, struct xsk_umem_info *umem) {
	struct xdp_config cfg = {
		.xdp_flags = 0,
		.xsk_bind_flags = XDP_USE_NEED_WAKEUP,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
	};

	struct xsk_socket_info *xsk_info = xdp->xsk;
	struct xsk_socket_config xsk_cfg;
	uint32_t idx;
	uint32_t prog_id;
	int i, ret;

	xsk_info->umem = umem;
	/* TODO: maybe move rx/tx sizes to xdp_config too? */
	xsk_cfg.rx_size = XSK_RING_CONS__NUM_DESCS;
	xsk_cfg.tx_size = XSK_RING_PROD__NUM_DESCS;
	xsk_cfg.xdp_flags = cfg.xdp_flags;
	xsk_cfg.bind_flags = cfg.xsk_bind_flags;
	xsk_cfg.libxdp_flags = cfg.libxdp_flags;

	ret = xsk_socket__create(&xsk_info->xsk,
							 xdp->interface_name,
							 xdp->queue_index,
							 umem->umem,
							 &xsk_info->rx,
							 &xsk_info->tx,
							 &xsk_cfg);
	if (ret) {
		log_msg(LOG_ERR, "xdp: failed to create xsk_socket");
		goto error_exit;
	}

	/* TODO: maybe don't update xsk_map here and do it later when the
	 * xdp_handler event thing is set up
	 */
	ret = xsk_socket__update_xskmap(xsk_info->xsk, xdp->xsk_map_fd);
	if (ret) {
		log_msg(LOG_ERR, "xdp: failed to update xskmap");
		goto error_exit;
	}

	/* Initialize umem frame allocation */
	for (i = 0; i < XDP_NUM_FRAMES; ++i) {
		xsk_info->umem->umem_frame_addr[i] = i * XDP_FRAME_SIZE;
	}

	xsk_info->umem->umem_frame_free = XDP_NUM_FRAMES;

	/* TODO: maybe move this ring size to xdp_config too? */
	ret = xsk_ring_prod__reserve(&xsk_info->umem->fq,
			XSK_RING_PROD__NUM_DESCS, &idx);

	/* TODO: maybe move this ring size to xdp_config too? */
	if (ret != XSK_RING_PROD__NUM_DESCS) {
		log_msg(LOG_ERR, "xdp: amount of reserved addr not as expected");
		goto error_exit;
	}

	/* TODO: maybe move this ring size to xdp_config too? */
	for (i = 0; i < XSK_RING_PROD__NUM_DESCS; ++i) {
		*xsk_ring_prod__fill_addr(&xsk_info->umem->fq, idx++) =
			xsk_alloc_umem_frame(xsk_info);
	}

	/* TODO: maybe move this ring size to xdp_config too? */
	xsk_ring_prod__submit(&xsk_info->umem->fq, XSK_RING_PROD__NUM_DESCS);

	return 0;

error_exit:
	errno = -ret;
	return -ret;
}

int xdp_server_init(struct xdp_server *xdp) {
	struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};

	/* check if interface name exists */
	xdp->interface_index = if_nametoindex(xdp->interface_name);
	if (xdp->interface_index == -1) {
		log_msg(LOG_ERR, "xdp: configured xdp-interface is unknown: %s", strerror(errno));
		return -1;
	}

	/* (optionally) load xdp program and (definitely) set xsks_map_fd */
	if (load_xdp_program(xdp)) {
		log_msg(LOG_ERR, "xdp: failed to load/pin xdp program/map");
		return -1;
	}

	/* if we don't do set rlimit, libbpf does it */
	/* this either has to be done before privilege drop or
	 * requires CAP_SYS_RESOURCE */
	if (setrlimit(RLIMIT_MEMLOCK, &rlim)) {
		log_msg(LOG_ERR, "xdp: cannot adjust rlimit (RLIMIT_MEMLOCK): \"%s\"\n",
			strerror(errno));
		return -1;
	}

	return 0;
}

int xdp_server_cleanup(struct xdp_server *xdp) {
	int ret = 0;

	/* only unpin if we loaded the program */
	if (xdp->bpf_prog_should_load) {
		if (xdp->xsk_map && bpf_map__is_pinned(xdp->xsk_map)) {
			if (bpf_map__unpin(xdp->xsk_map, NULL)) {
				log_msg(LOG_ERR, "xdp: failed to unpin bpf map during cleanup: \"%s\"\n",
						strerror(errno));
				ret = -1;
			}
		}

		log_msg(LOG_INFO, "xdp: unloading xdp program");
		unload_xdp_program(xdp);
	}

	return ret;
}

static int unload_xdp_program(struct xdp_server *xdp) {
	struct xdp_multiprog *mp = NULL;
	struct xdp_program *prog = NULL;
	int ret = 0;

	mp = xdp_multiprog__get_from_ifindex(xdp->interface_index);
	if (!mp || libxdp_get_error(mp)) {
		log_msg(LOG_ERR, "xdp: unable to get xdp bpf prog handle: %s\n",
		        strerror(errno));
		return -1;
	}

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
	} else {
		while ((prog = xdp_multiprog__next_prog(prog, mp))) {
			if (xdp_program__id(prog) == xdp_program__id(xdp->bpf_prog)) {
				break;
			}
		}
	}

	log_msg(LOG_INFO, "xdp: detaching xdp program %u from %s\n",
	        xdp_program__id(prog), xdp->interface_name);
	ret = xdp_program__detach(prog, xdp->interface_index, XDP_MODE_UNSPEC, 0);
	if (ret) {
		log_msg(LOG_ERR, "xdp: failed to detach xdp program: %s\n",
		        strerror(-ret));
	}

	xdp_multiprog__close(mp);
	return ret;
}

int xdp_socket_init(struct xdp_server *xdp) {
	xdp->umem = region_alloc_zero(xdp->region, sizeof(*xdp->umem));
	if (!xdp->umem) {
		log_msg(LOG_ERR, "xdp: cannot allocate memory for umem info");
		return -1;
	}

	xdp->xsk = region_alloc_zero(xdp->region, sizeof(*xdp->xsk));
	if (!xdp->xsk) {
		log_msg(LOG_ERR, "xdp: cannot allocate memory for xsk info");
		return -1;
	}

	/* not using region here, because we need page aligned memory */
	if (posix_memalign(&xdp->umem->buffer, getpagesize(), XDP_BUFFER_SIZE)) {
		log_msg(LOG_ERR, "xdp: cannot allocate aligned memory buffer: %s", strerror(errno));
		return -1;
	}

	if (xsk_configure_umem(xdp->umem, xdp->umem->buffer, XDP_BUFFER_SIZE)) {
		log_msg(LOG_ERR, "xdp: cannot create umem: %s", strerror(errno));
		goto cleanup_failed_umem;
	}

	if (xsk_configure_socket(xdp, xdp->umem)) {
		log_msg(LOG_ERR, "xdp: cannot create AF_XDP socket: %s", strerror(errno));
		goto cleanup_failed_xsk;
	}

	return 0;

cleanup_failed_xsk:
	xsk_umem__delete(xdp->umem->umem);

cleanup_failed_umem:
	free(xdp->umem->buffer);
	return -1;
}

int xdp_socket_cleanup(struct xdp_server *xdp) {
	/* xsk_*__delete also call free() on the passed pointer */
	xsk_socket__delete(xdp->xsk->xsk);
	xsk_umem__delete(xdp->umem->umem);

	/* packet buffer is managed by us */
	free(xdp->umem->buffer);
	return 0;
}

static inline void swap_eth(struct ethhdr *eth) {
	uint8_t tmp_mac[ETH_ALEN];
	memcpy(tmp_mac, eth->h_dest, ETH_ALEN);
	memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
	memcpy(eth->h_source, tmp_mac, ETH_ALEN);
}

static inline void swap_udp(struct udphdr *udp) {
	uint16_t tmp_port; /* not touching endianness */
	tmp_port = udp->source;
	udp->source = udp->dest;
	udp->dest = tmp_port;
}

static inline void swap_ipv6(struct ipv6hdr *ipv6) {
	struct in6_addr tmp_ip;
	memcpy(&tmp_ip, &ipv6->saddr, sizeof(tmp_ip));
	memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(tmp_ip));
	memcpy(&ipv6->daddr, &tmp_ip, sizeof(tmp_ip));
}

static inline void swap_ipv4(struct iphdr *ipv4) {
	struct in_addr tmp_ip;
	memcpy(&tmp_ip, &ipv4->saddr, sizeof(tmp_ip));
	memcpy(&ipv4->saddr, &ipv4->daddr, sizeof(tmp_ip));
	memcpy(&ipv4->daddr, &tmp_ip, sizeof(tmp_ip));
}

static inline void *parse_udp(struct udphdr *udp) {
	if (ntohs(udp->dest) != DNS_PORT)
		return NULL;

	return (void *)(udp + 1);
}

static inline void *parse_ipv6(struct ipv6hdr *ipv6) {
	if (ipv6->nexthdr != IPPROTO_UDP)
		return NULL;

	return (void *)(ipv6 + 1);
}

static inline void *parse_ipv4(struct iphdr *ipv4) {
	if (ipv4->protocol != IPPROTO_UDP)
		return NULL;

	return (void *)(ipv4 + 1);
}

static int parse_dns(struct nsd* nsd, void *dnshdr, uint32_t dnslen, struct query *q) {
	/* TODO: implement RATELIMIT, BIND8_STATS, DNSTAP, PROXY, ...? */
	uint32_t now = 0;
	uint32_t new_dnslen = 0;

	/* ignoring q->remote_addrlen = addr_len; because it only seems to be
	 * necessary with the msghdr/iovec mechanism */
	/* TODO: check whether we need to set client_addr */
	q->client_addrlen = (socklen_t)sizeof(q->client_addr);
	q->is_proxied = 0;

	/* set the size of the dns message and move position to start */
	buffer_skip(q->packet, dnslen);
	buffer_flip(q->packet);

	if (query_process(q, nsd, &now) != QUERY_DISCARDED) {
		if (RCODE(q->packet) == RCODE_OK && !AA(q->packet)) {
			STATUP(nsd, nona);
			ZTATUP(nsd, q->zone, nona);
		}

		query_add_optional(q, nsd, &now);

		buffer_flip(q->packet);
		/* return new dns message length */
		return buffer_remaining(q->packet);
	} else {
		/* TODO: we might need somewhere to track whether the current query's
		 * buffer is usable/allowed to be used? */
		query_reset(q, UDP_MAX_MESSAGE_LEN, 0);
		STATUP(nsd, dropped);
		ZTATUP(nsd, q->zone, dropped);
		return 0;
	}
}

static int
process_packet(struct xdp_server *xdp, uint8_t *pkt, uint64_t addr,
               uint32_t *len, struct query *query) {
	log_msg(LOG_INFO, "xdp: received packet with len %d", *len);

	uint32_t dnslen = *len;
	uint32_t data_before_dnshdr_len = 0;

	struct ethhdr *eth = (struct ethhdr *)pkt;
	struct ipv6hdr *ipv6 = NULL;
	struct iphdr *ipv4 = NULL;
	struct udphdr *udp = NULL;
	void *dnshdr = NULL;

	/* doing the check here, so that the packet/frame is large enough to contain
	 * at least an ethernet header, an ipv4 header (ipv6 header is larger), and
	 * a udp header.
	 */
	if (*len < (sizeof(*eth) + sizeof(struct iphdr) + sizeof(*udp)))
		return 0;

	data_before_dnshdr_len = sizeof(*eth) + sizeof(*udp);

	/* TODO: implement only accepting IP traffic to actual server ip? */
	switch (ntohs(eth->h_proto)) {
	case ETH_P_IPV6: {
		ipv6 = (struct ipv6hdr *)(eth + 1);

		if (*len < (sizeof(*eth) + sizeof(*ipv6) + sizeof(*udp)))
			return 0;
		if (!(udp = parse_ipv6(ipv6)))
			return 0;

		dnslen -= (sizeof(*eth) + sizeof(*ipv6) + sizeof(*udp));
		data_before_dnshdr_len += sizeof(*ipv6);

		break;
	} case ETH_P_IP: {
		ipv4 = (struct iphdr *)(eth + 1);

		if (!(udp = parse_ipv4(ipv4)))
			return 0;

		dnslen -= (sizeof(*eth) + sizeof(*ipv4) + sizeof(*udp));
		data_before_dnshdr_len += sizeof(*ipv4);

		break;
	}

	/* TODO: vlan? */
	/* case ETH_P_8021AD: case ETH_P_8021Q: */
	/*     if (*len < (sizeof(*eth) + sizeof(*vlan))) */
	/*         break; */
	default:
		return 0;
	}

	if (!(dnshdr = parse_udp(udp)))
		return 0;

	query_set_buffer_data(query, dnshdr, XDP_FRAME_SIZE - data_before_dnshdr_len);

	dnslen = parse_dns(xdp->nsd, dnshdr, dnslen, query);
	if (!dnslen) {
		return 0;
	}

	udp->len = htons(sizeof(*udp) + dnslen);

	swap_eth(eth);
	swap_udp(udp);

	if (ipv4) {
		swap_ipv4(ipv4);
		__be16 ipv4_old_len = ipv4->tot_len;
		ipv4->tot_len = htons(sizeof(*ipv4)) + udp->len;
		csum16_replace(&ipv4->check, ipv4_old_len, ipv4->tot_len);
		udp->check = calc_csum_udp4(udp, ipv4);
	} else if (ipv6) {
		swap_ipv6(ipv6);
		ipv6->payload_len = udp->len;
		udp->check = calc_csum_udp6(udp, ipv6);
	} else {
		log_msg(LOG_ERR, "xdp: we forgot to implement something... oops");
		return 0;
	}

	log_msg(LOG_INFO, "xdp: parsed done with processing the packet");

	*len = data_before_dnshdr_len + dnslen;
	return 1;
}

void xdp_handle_recv_and_send(struct xdp_server *xdp) {
	struct xsk_socket_info *xsk = xdp->xsk;
	unsigned int recvd, stock_frames, i;
	uint32_t idx_rx = 0, idx_fq = 0;
	int ret;

	recvd = xsk_ring_cons__peek(&xsk->rx, XDP_RX_BATCH_SIZE, &idx_rx);
	if (!recvd) {
		/* no data available */
		return;
	}

	/* TODO: maybe put in it's own function and call after tx too? */

	/* fill the fill ring with as many frames as are available */
	/* get number of spots available in fq */
	stock_frames = xsk_prod_nb_free(&xsk->umem->fq, xsk_umem_free_frames(xsk));
	if (stock_frames > 0) {
		/* ignoring prod__reserve return value, because we got stock_frames
		 * from xsk_prod_nb_free(), which are therefore available */
		xsk_ring_prod__reserve(&xsk->umem->fq, stock_frames, &idx_fq);

		for (i = 0; i < stock_frames; ++i) {
			*xsk_ring_prod__fill_addr(&xsk->umem->fq, idx_fq++) =
				xsk_alloc_umem_frame(xsk);
		}

		xsk_ring_prod__submit(&xsk->umem->fq, stock_frames);
	}

	/* Process received packets */
	for (i = 0; i < recvd; ++i) {
		uint64_t addr = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx)->addr;
		uint32_t len = xsk_ring_cons__rx_desc(&xsk->rx, idx_rx++)->len;

		uint8_t *pkt = xsk_umem__get_data(xsk->umem->buffer, addr);
		if (!process_packet(xdp, pkt, addr, &len, xdp->queries[i])) {
			/* drop packet */
			xsk_free_umem_frame(xsk, addr);
			// TODO: also move query in queries around and recvd--? Maybe, or track query indices?
		} else {
			// TODO: send packet
			/* "Here we sent the packet out of the receive port. Note that
			 * we allocate one entry and schedule it. Your design would be
			 * faster if you do batch processing/transmission" -- xdp-tutorial */

			uint32_t tx_idx = 0;
			ret = xsk_ring_prod__reserve(&xsk->tx, 1, &tx_idx);
			if (ret != 1) {
				// no more tx slots available, drop packet
				xsk_free_umem_frame(xsk, addr);
				query_reset(xdp->queries[i], UDP_MAX_MESSAGE_LEN, 0);
				continue;
			}

			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
			xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
			xsk_ring_prod__submit(&xsk->tx, 1);
			xsk->outstanding_tx++;
		}
		query_reset(xdp->queries[i], UDP_MAX_MESSAGE_LEN, 0);

		/* xsk->stats.rx_bytes += len; */
	}

	xsk_ring_cons__release(&xsk->rx, recvd);
	/* xsk->stats.rx_packets += rcvd; */

	/* wake up kernel for tx if needed and collect completed tx buffers */
	handle_tx(xsk);
}

static void handle_tx(struct xsk_socket_info *xsk) {
	uint32_t completed, idx_cq;

	if (!xsk->outstanding_tx)
		return;

	if (xsk_ring_prod__needs_wakeup(&xsk->tx))
		sendto(xsk_socket__fd(xsk->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
		/* maybe use while (sendto() < 0) and if ==EAGAIN clear completion queue */

	/* free completed TX buffers */
	completed = xsk_ring_cons__peek(&xsk->umem->cq,
	                                XSK_RING_CONS__NUM_DESCS,
	                                &idx_cq);

	if (completed > 0) {
		for (int i = 0; i < completed; i++) {
			xsk_free_umem_frame(xsk, *xsk_ring_cons__comp_addr(&xsk->umem->cq,
			                                                   idx_cq++));
		}

		xsk_ring_cons__release(&xsk->umem->cq, completed);
		xsk->outstanding_tx -= completed < xsk->outstanding_tx ?
		                       completed : xsk->outstanding_tx;
	}
}

#endif /* USE_XDP */
