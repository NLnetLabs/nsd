/*
 * xfrd-notify.h - notify sending routines.
 *
 * Copyright (c) 2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef XFRD_NOTIFY_H
#define XFRD_NOTIFY_H

#include <config.h>
#include "tsig.h"
#include "netio.h"

struct nsd;
struct region;
struct xfrd_zone;

/* handle zone notify send */
void xfrd_handle_notify_send(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);
/* send notifications to all in the notify list */
void xfrd_send_notify(struct xfrd_zone* zone);

#endif /* XFRD_NOTIFY_H */
