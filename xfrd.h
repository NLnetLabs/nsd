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

struct nsd;
struct region;
struct buffer;
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

	/* next master to try to transfer from, number for persistence */
	acl_options_t* next_master;
	int next_master_num;
	zone_options_t* zone_options;

	/* handler for timeouts */
	struct timespec timeout;
	netio_handler_type zone_handler;
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
