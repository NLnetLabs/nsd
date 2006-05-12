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
#include "tsig.h"

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
	uint8_t parent_soa_info_pass;
	struct xfrd_tcp *ipc_conn;
	struct buffer* ipc_pass;
	/* xfrd shutdown flag */
	uint8_t shutdown;

	/* tree of zones, by apex name, contains xfrd_zone_t* */
	rbtree_t *zones;
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
	} state;

	/* master to try to transfer from, number for persistence */
	acl_options_t* master;
	int master_num;
	int next_master; /* -1 or set by notify where to try next */
	/* round of xfrattempts, -1 is waiting for timeout */
	int round_num; 
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

	/* xfr message handling data */
	/* query id */
	uint16_t query_id;
	uint32_t msg_seq_nr; /* number of messages already handled */
	uint32_t msg_old_serial, msg_new_serial; /* host byte order */
	size_t msg_rr_count;
	uint8_t msg_is_ixfr; /* 1:IXFR detected. 2:middle IXFR SOA seen. */
	struct region* query_region;
	struct region* notify_query_region;
#ifdef TSIG
	tsig_record_type tsig; /* tsig state for IXFR/AXFR */
	tsig_record_type notify_tsig; /* tsig state for notify */
#endif

	/* notify sending handler */
	/* Not saved on disk (i.e. kill of daemon stops notifies) */
	netio_handler_type notify_send_handler;
	struct timespec notify_timeout;
	acl_options_t* notify_current; /* current slave to notify */
	uint8_t notify_retry; /* how manieth retry in sending to current */
	uint16_t notify_query_id;
};

#define XFRD_FILE_MAGIC "NSDXFRD1"

enum xfrd_packet_result {
	xfrd_packet_bad, /* drop the packet/connection */
	xfrd_packet_more, /* more packets to follow on tcp */
	xfrd_packet_tcp, /* try tcp connection */
	xfrd_packet_transfer, /* server responded with transfer*/
	xfrd_packet_newlease /* no changes, soa OK */
};

/* start xfrd, new start. Pass socket to server_main. */
void xfrd_init(int socket, struct nsd* nsd);

/* get the current time epoch. Cached for speed. */
time_t xfrd_time();

/*
 * Handle final received packet from network.
 * returns enum of packet discovery results 
 */
enum xfrd_packet_result xfrd_handle_received_xfr_packet(
	xfrd_zone_t* zone, buffer_type* packet);

/* set timer to specific value */
void xfrd_set_timer(xfrd_zone_t* zone, time_t t);

/* 
 * Make a new request to next master server. 
 * uses next_master if set (and a fresh set of rounds).
 * otherwised, starts new round of requests if none started already. 
 * starts next round of requests if at last master.
 * if too many rounds of requests, sets timer for next retry.
 */
void xfrd_make_request(xfrd_zone_t* zone);

/*
 * TSIG sign outgoing request. Call if acl has a key.
 * region is freed here and used during tsig.
 */
void xfrd_tsig_sign_request(buffer_type* packet, struct tsig_record* tsig,
        acl_options_t* acl, struct region* tsig_region);

#endif /* XFRD_H */
