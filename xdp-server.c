/*
 * xdp-server.c -- integration of AF_XDP into nsd
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

/* TODO: make sure we have the necessary capabilities
 * CAP_BPF,
 * CAP_NET_RAW (maybe),
 * CAP_SYS_RESOURCES (maybe)
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

#include <sys/poll.h>
#include <sys/resource.h>

/* #include <bpf/bpf.h> */
#include <xdp/xsk.h>
#include <xdp/libxdp.h>

#include <arpa/inet.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <net/if.h>

#include "query.h"
#include "region-allocator.h"
#include "util.h"
#include "xdp-server.h"
#include "xdp-util.h"

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


/*
 * Send outstanding packets and recollect completed frame addresses
 */
// TODO: needed?
static void complete_tx(struct xsk_socket_info *xsk);

/*
 * Process packet
 */
// TODO: needed?
static bool
process_packet(struct xsk_socket_info *xsk, uint64_t addr, uint32_t len);

/*
 * Receive frames from rings and send results
 */
// TODO: needed?
static void handle_receive_packets(struct xsk_socket_info *xsk);

/*
 * Main loop, poll for new frames
 */
// TODO: needed?
static void rx_and_process(struct xsk_socket_info *xsk_socket);


/* *************** */
/* Implementations */
/* *************** */

/* TODO: rename or split up functionality (cause of map assignment and attaching) */
static int load_xdp_program(struct xdp_server *xdp) {
	/* Load custom program */
	/* TODO: possibly add a xdp->should_load_bpf_prog config option
	 * We definitely need a bpf_prog to get a file descriptor to the xsk_map,
	 * but it could be useful to some users that implement their own XDP
	 * program to not load it from here.
	 * There are multiple options here:
	 *   - The user load their own bpf program and tells us the path to the file
	 *     so that we can use it to retrieve a file descriptor to the xsks_map
	 *   - The user specifies a bpf program for us to load and use for the
	 *     xsks_map file descriptor
	 *   - The user unsets our (config default) bpf program, so that libbpf
	 *     loads its default bpf program that forwards ALL traffic to AF_XDP
	 *     (I don't like this variant, and will probably not implement this)
	 */
	struct bpf_map *map;
	char errmsg[512];
	int err, ret;
	// TODO: put this into a config option as well?
	enum xdp_attach_mode attach_mode = XDP_MODE_UNSPEC; /* UNSPEC => let libxdp decide */

	DECLARE_LIBXDP_OPTS(bpf_object_open_opts, opts);

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
		/* TODO: implement reuse map fd from pinned map obj */
		/*
		 * Pin map in struct definition in bpf program and then use here:
		 * fd = bpf_obj_get("/sys/fs/bpf/xsks_map");
		 * map = ...find_map_by_name...;
		 * bpf_map__reuse_fd(map, fd);
		 */
	}

	return 0;
}

static uint64_t xsk_alloc_umem_frame(struct xsk_socket_info *xsk) {
	uint64_t frame;
	if (xsk->umem->umem_frame_free == 0) {
		return XDP_INVALID_UMEM_FRAME;
	}

	frame = xsk->umem->umem_frame_addr[--xsk->umem->umem_frame_free];
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free] = XDP_INVALID_UMEM_FRAME;
	return frame;
}

static uint64_t xsk_umem_free_frame(struct xsk_socket_info *xsk) {
	return xsk->umem->umem_frame_free;
}

static void xsk_free_umem_frame(struct xsk_socket_info *xsk, uint16_t frame) {
	assert(xsk->umem_frame_free < XDP_NUM_FRAMES);
	xsk->umem->umem_frame_addr[xsk->umem->umem_frame_free++] = frame;
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

	/* xdp->queue_count = ethtool_channels_get(xdp->interface_name); */
	/* if (xdp->queue_count <= 0) { */
	/*     log_msg(LOG_ERR, "xdp: could not determine netdev queue count: %s. (attempting to continue with 1 queue)", strerror(errno)); */
	/*     xdp->queue_count = 1; */
	/* } */

	/* (optionally) load xdp program and (definitely) set xsks_map_fd */
	if (load_xdp_program(xdp)) {
		log_msg(LOG_ERR, "xdp: failed to load xdp program or re-use pinned map");
		return -1;
	}

	/* if we don't do set rlimit, libbpf does it */
	// TODO: either get CAP_SYS_RESOURCE or do this before privilege drop
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

		/* TODO: unload BPF prog */
		log_msg(LOG_ERR, "xdp: would unload here, but not implemented");
	}

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

#endif /* USE_XDP */
