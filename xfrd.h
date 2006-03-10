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

#define XFRD_MAX_TCP 10 /* max number of tcp connections */

struct nsd;
struct region;
struct buffer;
typedef struct xfrd_tcp xfrd_tcp_t;
typedef struct xfrd_state xfrd_state_t;
typedef struct xfrd_zone_t xfrd_zone_t;
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

	/* tcp connections, each has packet and read/wr state */
	xfrd_tcp_t *tcp_state[XFRD_MAX_TCP];
	/* number of TCP connections in use. */
	int tcp_count;
	/* linked list of zones waiting for a TCP connection */
	xfrd_zone_t *tcp_waiting_first, *tcp_waiting_last;
	/* packet buffer for udp packets */
	struct buffer* packet;

	/* current time is cached */
	uint8_t got_time;
	time_t current_time;

	/* timer for NSD reload */
	time_t reload_time;
	netio_handler_type reload_handler;

	/* communication channel with server_main */
	netio_handler_type ipc_handler;
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
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t rdata_count;
	const dname_type* prim_ns;
	const dname_type* email;
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
};


/*
 * XFRD state for a single zone
 */
struct xfrd_zone_t {
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

struct xfrd_tcp {
	/* tcp connection state */
	/* state: reading or writing */
	uint8_t is_reading;

	/* how many bytes have been read/written - total,
	   incl. tcp length bytes */
	uint32_t total_bytes;

	/* msg len bytes */
	uint16_t msglen;

	/* fd of connection. -1 means unconnected */
	int fd;

	/* packet buffer of connection */
	struct buffer* packet;
};

#define XFRD_FILE_MAGIC "NSDXFRD1"
#define DIFF_FILE_MAGIC "NSDdfV01"
#define DIFF_FILE_MAGIC_LEN 8

/* start xfrd, new start. Pass socket to server_main. */
void xfrd_init(int socket, struct nsd* nsd);

/* write an xfr packet data to the diff file, type=IXFR.
   The diff file is created if necessary. */
void diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt);

#endif /* XFRD_H */
