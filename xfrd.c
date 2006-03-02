/*
 * xfrd.h - XFR (transfer) Daemon header file. Coordinates SOA updates.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "xfrd.h"
#include "options.h"
#include "util.h"
#include "netio.h"
#include "region-allocator.h"
#include "nsd.h"

/* the daemon state */
static xfrd_state_t* xfrd = 0;

/* manage interprocess communication with server_main process */
static void
xfrd_handle_ipc(netio_type *netio, netio_handler_type *handler, 
	netio_event_types_type event_types);
/* main xfrd loop */
static void xfrd_main();
/* shut down xfrd, close sockets. */
static void xfrd_shutdown();

void xfrd_init(int socket, struct nsd* nsd)
{
#ifndef NDEBUG
	assert(xfrd == 0);
#endif
	region_type* region = region_create(xalloc, free);
	xfrd = (xfrd_state_t*)region_alloc(region, sizeof(xfrd_state_t));
	memset(xfrd, 0, sizeof(xfrd_state_t));
	xfrd->region = region;
	xfrd->xfrd_start_time = time(0);
	xfrd->netio = netio_create(xfrd->region);
	xfrd->nsd = nsd;

	xfrd->reload_time = 0;

	xfrd->ipc_handler.fd = socket;
	xfrd->ipc_handler.timeout = NULL;
	xfrd->ipc_handler.user_data = xfrd;
	xfrd->ipc_handler.event_types = NETIO_EVENT_READ;
	xfrd->ipc_handler.event_handler = xfrd_handle_ipc;
	netio_add_handler(xfrd->netio, &xfrd->ipc_handler);

	log_msg(LOG_INFO, "xfrd startup");
	xfrd_main();
}

static void 
xfrd_main()
{
	xfrd->shutdown = 0;
	while(!xfrd->shutdown)
	{
		if(netio_dispatch(xfrd->netio, NULL, 0) == -1) {
			if (errno != EINTR) {
				log_msg(LOG_ERR, 
					"xfrd netio_dispatch failed: %s", 
					strerror(errno));
			}
		}
		if(xfrd->nsd->signal_hint_quit || xfrd->nsd->signal_hint_shutdown)
			xfrd->shutdown = 1;
	}
	xfrd_shutdown();
}

static void xfrd_shutdown()
{
	log_msg(LOG_INFO, "xfrd shutdown");
	close(xfrd->ipc_handler.fd);
	region_destroy(xfrd->region);
	region_destroy(xfrd->nsd->options->region);
	region_destroy(xfrd->nsd->region);
	exit(0);
}

static void
xfrd_handle_ipc(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, 
	netio_event_types_type event_types)
{
        sig_atomic_t cmd;
        int len;
        if (!(event_types & NETIO_EVENT_READ)) {
                return;
        }

        if ((len = read(handler->fd, &cmd, sizeof(cmd))) == -1) {
                log_msg(LOG_ERR, "xfrd_handle_ipc: read: %s",
                        strerror(errno));
                return;
        }
        if (len == 0)
        {
		/* parent closed the connection. Quit */
		xfrd->shutdown = 1;
		return;
        }

        switch (cmd) {
        case NSD_QUIT:
        case NSD_SHUTDOWN:
                xfrd->shutdown = 1;
                break;
        default:
                log_msg(LOG_ERR, "xfrd_handle_ipc: bad mode %d", (int)cmd);
                break;
        }

}
