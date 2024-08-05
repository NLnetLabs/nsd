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
#include <sys/mman.h>

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

struct umem_ptr {
	uint64_t addr;
	uint32_t len;
};

static struct umem_ptr umem_ptrs[XDP_RX_BATCH_SIZE];

/*
 * Allocate memory for UMEM and setup rings
 */
static int
xsk_configure_umem(struct xsk_umem_info *umem_info, uint64_t size);

/*
 * Allocate a frame in UMEM
 */
static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk);

/*
 * Bind AF_XDP socket and setup rings
 */
static int xsk_configure_socket(struct xdp_server *xdp,
                                struct xsk_socket_info *xsk_info,
                                struct xsk_umem_info *umem,
                                uint32_t queue_index);

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
static int load_xdp_program_and_map(struct xdp_server *xdp);

static int unload_xdp_program(struct xdp_server *xdp);

/*
 * Setup XDP sockets
 */
static int xdp_sockets_init(struct xdp_server *xdp);

/*
 * Cleanup XDP sockets and memory
 */
static int xdp_sockets_cleanup(struct xdp_server *xdp);

/*
 * Allocate a block of shared memory
 */
static void *alloc_shared_mem(size_t len);

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

static int load_xdp_program_and_map(struct xdp_server *xdp) {
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

		if (xdp->bpf_bpffs_path)
			snprintf(map_path, PATH_MAX, "%s/%s", xdp->bpf_bpffs_path, "xsks_map");
		else
			/* document this behaviour, as the current documentation states that bpffs path is chosen by libbpf */
			snprintf(map_path, PATH_MAX, "%s", "/sys/fs/bpf/xsks_map");

		fd = bpf_obj_get(map_path);
		if (fd < 0) {
			log_msg(LOG_ERR, "xdp: could not retrieve xsks_map pin from %s: %s", map_path, strerror(errno));
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
xsk_configure_umem(struct xsk_umem_info *umem_info, uint64_t size) {
	int ret;

	ret = xsk_umem__create(&umem_info->umem, umem_info->buffer, size, &umem_info->fq, &umem_info->cq, NULL);
	if (ret) {
		errno = -ret;
		return -ret;
	}

	return 0;
}

static int
xsk_configure_socket(struct xdp_server *xdp, struct xsk_socket_info *xsk_info,
                     struct xsk_umem_info *umem, uint32_t queue_index) {
	struct xdp_config cfg = {
		.xdp_flags = 0,
		.xsk_bind_flags = XDP_USE_NEED_WAKEUP,
		.libxdp_flags = XSK_LIBXDP_FLAGS__INHIBIT_PROG_LOAD,
	};

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
	                         queue_index,
	                         umem->umem,
	                         &xsk_info->rx,
	                         &xsk_info->tx,
	                         &xsk_cfg);
	if (ret) {
		log_msg(LOG_ERR, "xdp: failed to create xsk_socket");
		goto error_exit;
	}

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
	                             XSK_RING_PROD__NUM_DESCS,
	                             &idx);

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

static void *alloc_shared_mem(size_t len) {
	/* MAP_ANONYMOUS memory is initialized with zero */
	return mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
}

static int xdp_sockets_init(struct xdp_server *xdp) {
	size_t umems_len = sizeof(struct xsk_umem_info) * xdp->queue_count;
	size_t xsks_len = sizeof(struct xsk_socket_info) * xdp->queue_count;

	xdp->umems = (struct xsk_umem_info *) alloc_shared_mem(umems_len);
	if (xdp->umems == MAP_FAILED) {
		log_msg(LOG_ERR,
		        "xdp: failed to allocate shared memory for umem info: %s",
		        strerror(errno));
		return -1;
	}

	xdp->xsks = (struct xsk_socket_info *) alloc_shared_mem(xsks_len);
	if (xdp->xsks == MAP_FAILED) {
		log_msg(LOG_ERR,
		        "xdp: failed to allocate shared memory for xsk info: %s",
		        strerror(errno));
		return -1;
	}

	for (int q_idx = 0; q_idx < xdp->queue_count; ++q_idx) {
		/* mmap is supposedly page-aligned, so should be fine */
		xdp->umems[q_idx].buffer = alloc_shared_mem(XDP_BUFFER_SIZE);

		if (xsk_configure_umem(&xdp->umems[q_idx], XDP_BUFFER_SIZE)) {
			log_msg(LOG_ERR, "xdp: cannot create umem: %s", strerror(errno));
			goto out_err_umem;
		}

		if (xsk_configure_socket(xdp, &xdp->xsks[q_idx], &xdp->umems[q_idx],
		                         q_idx)) {
			log_msg(LOG_ERR,
			        "xdp: cannot create AF_XDP socket: %s",
			        strerror(errno));
			goto out_err_xsk;
		}
	}

	return 0;

out_err_xsk:
	for (int i = 0; i < xdp->queue_count; ++i)
		xsk_umem__delete(xdp->umems[i].umem);

out_err_umem:
	return -1;
}

static int xdp_sockets_cleanup(struct xdp_server *xdp) {
	for (int i = 0; i < xdp->queue_count; ++i) {
		xsk_socket__delete(xdp->xsks[i].xsk);
		xsk_umem__delete(xdp->umems[i].umem);
	}

	return 0;
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
	if (load_xdp_program_and_map(xdp)) {
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

	if (xdp_sockets_init(xdp))
		return -1;

	for (int i = 0; i < XDP_RX_BATCH_SIZE; ++i) {
		umem_ptrs[i].addr = XDP_INVALID_UMEM_FRAME;
		umem_ptrs[i].len = 0;
	}

	return 0;
}

int xdp_server_cleanup(struct xdp_server *xdp) {
	int ret = 0;

	xdp_sockets_cleanup(xdp);

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

	if(ipv6) {
#ifdef INET6
		struct sockaddr_in6* sock6 = (struct sockaddr_in6*)&query->remote_addr;
		sock6->sin6_family = AF_INET6;
		sock6->sin6_port = udp->dest;
		memcpy(&sock6->sin6_addr, &ipv6->saddr, sizeof(ipv6->saddr));
#else
		return 0; /* no inet6 no network */
#endif
	} else {
		struct sockaddr_in* sock4 = (struct sockaddr_in*)&query->remote_addr;
		sock4->sin_family = AF_INET;
		sock4->sin_port = udp->dest;
		sock4->sin_addr.s_addr = ipv4->saddr;
	}

	query->remote_addrlen = (socklen_t)sizeof(query->remote_addr);
	query->client_addr    = query->remote_addr;
	query->client_addrlen = query->remote_addrlen;
	query->is_proxied = 0;

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
	struct xsk_socket_info *xsk = &xdp->xsks[xdp->queue_index];
	unsigned int recvd, stock_frames, i, to_send = 0;
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
		} else {
			umem_ptrs[to_send].addr = addr;
			umem_ptrs[to_send].len = len;
			++to_send;
		}
		/* we can reset the query directly after each packet processing,
		 * because the reset does not delete the underlying buffer/data.
		 * However, if we, in future, need to access data from the query
		 * struct when sending the answer, this needs to change.
		 * This also means, that currently a single query instance (and
		 * not an array) would suffice for this implementation. */
		query_reset(xdp->queries[i], UDP_MAX_MESSAGE_LEN, 0);

		/* xsk->stats.rx_bytes += len; */
	}

	xsk_ring_cons__release(&xsk->rx, recvd);
	/* xsk->stats.rx_packets += rcvd; */

	/* Process sending packets */

	uint32_t tx_idx = 0;

	/* TODO: at least send as many packets as slots are available */
	ret = xsk_ring_prod__reserve(&xsk->tx, to_send, &tx_idx);
	if (ret != to_send) {
		// not enough tx slots available, drop packets
		for (i = 0; i < to_send; ++i) {
			xsk_free_umem_frame(xsk, umem_ptrs[to_send].addr);
		}
	}

	for (i = 0; i < to_send; ++i) {
		uint64_t addr = umem_ptrs[i].addr;
		uint32_t len = umem_ptrs[i].len;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->addr = addr;
		xsk_ring_prod__tx_desc(&xsk->tx, tx_idx)->len = len;
		tx_idx++;
		xsk->outstanding_tx++;
		umem_ptrs[i].addr = XDP_INVALID_UMEM_FRAME;
		umem_ptrs[i].len = 0;
	}

	xsk_ring_prod__submit(&xsk->tx, to_send);

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
