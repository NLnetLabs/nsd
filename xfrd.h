/*
 * xfrd.h - XFR (transfer) Daemon header file. Coordinates SOA updates.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef XFRD_H
#define XFRD_H

#include <config.h>
#include "netio.h"

struct nsd;
struct region;
typedef struct xfrd_state xfrd_state_t;
/*
 * The global state for the xfrd daemon process.
 * The time_t times are epochs in secs since 1970, absolute times.
 */
struct xfrd_state {
	/* time when daemon was last started */
	time_t xfrd_start_time;
	struct region* region;
	netio_type* netio;
	struct nsd* nsd;

	/* timer for NSD reload */
	time_t reload_time;
	netio_handler_type reload_handler;

	/* communication channel with server_main */
	netio_handler_type ipc_handler;
	/* xfrd shutdown flag */
	uint8_t shutdown;

	/* tree of zones, by apex name */
	/* TODO */
	
	/* notify retry state (not saved on disk) */
	/* TODO */
};

/* start xfrd, new start. Pass socket to server_main. */
void xfrd_init(int socket, struct nsd* nsd);

#endif /* XFRD_H */
