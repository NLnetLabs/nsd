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
#include "rbtree.h"
#include "namedb.h"
#include "options.h"
#include "dns.h"

struct nsd;
struct region;
struct buffer;
struct xfrd_tcp;
struct xfrd_tcp_set;
typedef struct xfrd_state xfrd_state_t;
typedef struct xfrd_zone xfrd_zone_t;
typedef struct xfrd_soa xfrd_soa_t;
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

	struct xfrd_tcp_set* tcp_set;
	/* packet buffer for udp packets */
	struct buffer* packet;

	/* current time is cached */
	uint8_t got_time;
	time_t current_time;

	/* timer for NSD reload */
	struct timespec reload_timeout;
	netio_handler_type reload_handler;

	/* communication channel with server_main */
	netio_handler_type ipc_handler;
	uint8_t ipc_is_soa;
	struct xfrd_tcp *ipc_conn;
	/* xfrd shutdown flag */
	uint8_t shutdown;

	/* tree of zones, by apex name, contains xfrd_zone_t* */
	rbtree_t *zones;
	
	/* notify retry state (not saved on disk) */
	/* TODO */
};

/*
 * XFR daemon SOA information kept in network format.
 * This is in packet order.
 */
struct xfrd_soa {
	/* name of RR is zone apex dname */
	uint16_t type; /* = TYPE_SOA */
	uint16_t klass; /* = CLASS_IN */
	uint32_t ttl;
	uint16_t rdata_count; /* = 7 */
	/* format is 1 octet length, + wireformat dname.
	   one more octet since parse_dname_wire_from_packet needs it.
	   maximum size is allocated to avoid memory alloc/free. */
	uint8_t prim_ns[MAXDOMAINLEN + 2];
	uint8_t email[MAXDOMAINLEN + 2];
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};


/*
 * XFRD state for a single zone
 */
struct xfrd_zone {
	rbnode_t node;

	/* name of the zone */
	const dname_type* apex;
	const char* apex_str;

	/* Three types of soas:
	 * NSD: in use by running server
	 * disk: stored on disk in db/diff file
	 * notified: from notification, could be available on a master.
	 * And the time the soa was acquired (start time for timeouts).
	 * If the time==0, no SOA is available.
	 */
	xfrd_soa_t soa_nsd;
	time_t soa_nsd_acquired;
	xfrd_soa_t soa_disk;
	time_t soa_disk_acquired;
	xfrd_soa_t soa_notified;
	time_t soa_notified_acquired;

	enum xfrd_zone_state {
		xfrd_zone_ok,
		xfrd_zone_refreshing,
		xfrd_zone_expired
	} zone_state;

	/* master to try to transfer from, number for persistence */
	acl_options_t* master;
	int master_num;
	zone_options_t* zone_options;

	/* handler for timeouts */
	struct timespec timeout;
	netio_handler_type zone_handler;

	/* tcp connection zone is using, or -1 */
	int tcp_conn;
	/* zone is waiting for a tcp connection */
	uint8_t tcp_waiting;
	/* next zone in waiting list */
	xfrd_zone_t* tcp_waiting_next;
	/* query id */
	uint16_t query_id;
};

#define XFRD_FILE_MAGIC "NSDXFRD1"

/* start xfrd, new start. Pass socket to server_main. */
void xfrd_init(int socket, struct nsd* nsd);
/* get the current time epoch. Cached for speed. */
time_t xfrd_time();
/* handle final received packet from network */
void xfrd_handle_received_xfr_packet(xfrd_zone_t* zone, buffer_type* packet);
/* set timer to specific value */
void xfrd_set_timer(xfrd_zone_t* zone, time_t t);

#endif /* XFRD_H */
