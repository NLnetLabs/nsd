/*
 * netio.h -- network I/O support.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _NETIO_H_
#define _NETIO_H_

#ifdef	HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include "region-allocator.h"

enum netio_event_types {
	NETIO_HANDLER_NONE    = 0,
	NETIO_HANDLER_READ    = 1,
	NETIO_HANDLER_WRITE   = 2,
	NETIO_HANDLER_EXCEPT  = 4,
	NETIO_HANDLER_TIMEOUT = 8
};
typedef enum netio_event_types netio_event_types_type;

typedef struct netio netio_type;
typedef struct netio_handler netio_handler_type;
typedef struct netio_handler_list netio_handler_list_type;

struct netio
{
	/*
	 * The current time, which is initialized just before the
	 * event handlers are called.
	 */
	struct timespec current_time;

	/* Private.  */
	region_type             *region;
	netio_handler_list_type *handlers;
	netio_handler_list_type *deallocated;
};

typedef void (*netio_event_handler_type)(netio_type *netio,
					 netio_handler_type *handler,
					 netio_event_types_type event_types);

struct netio_handler
{
	/*
	 * The file descriptor that should be checked for events.  If
	 * the file descriptor is negative only timeout events are
	 * checked for.
	 */
	int fd;

	/*
	 * The time when no events should be checked for and the
	 * handler should be called with the NETIO_HANDLER_TIMEOUT
	 * event type.  Unlike most timeout parameters the time should
	 * be absolute, not relative!
	 */
	struct timespec *timeout;

	/*
	 * Additional user data.
	 */
	void *user_data;

	/*
	 * The type of events that should be checked for.  These types
	 * can be OR'ed together to wait for multiple types of events.
	 */
	netio_event_types_type event_types;

	/*
	 * The event handler.  The event_types parameter contains the
	 * OR'ed set of event types that actually triggered.  The
	 * event handler is allowed to modify this handler object.
	 * The event handler SHOULD NOT block!
	 */
	netio_event_handler_type event_handler;
};


netio_type *netio_create(region_type *region);

void netio_add_handler(netio_type *netio, netio_handler_type *handler);
void netio_remove_handler(netio_type *netio, netio_handler_type *handler);

/*
 * Check for events and dispatch them to the handlers.  If TIMEOUT is
 * specified it specifies the maximum time to wait for an event to
 * arrive.  SIGMASK is passed to the underlying pselect call.  Returns
 * the number of non-timeout events dispatched, 0 on timeout, and -1
 * on error (with errno set appropriately).
 */
int netio_dispatch(netio_type *netio,
		   const struct timespec *timeout,
		   const sigset_t *sigmask);

#endif /* _NETIO_H_ */
