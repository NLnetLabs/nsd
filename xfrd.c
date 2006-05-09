/*
 * xfrd.c - XFR (transfer) Daemon source file. Coordinates SOA updates.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include "xfrd.h"
#include "xfrd-tcp.h"
#include "options.h"
#include "util.h"
#include "netio.h"
#include "region-allocator.h"
#include "nsd.h"
#include "packet.h"
#include "difffile.h"

#define XFRDFILE "xfrd.state"
#define XFRD_TRANSFER_TIMEOUT 10 /* empty zone timeout is between x and 2*x seconds */
#define XFRD_TCP_TIMEOUT TCP_TIMEOUT /* seconds, before a tcp connectin is stopped */
#define XFRD_UDP_TIMEOUT 10 /* seconds, before a udp request times out */
#define XFRD_LOWERBOUND_REFRESH 1 /* seconds, smallest refresh timeout */
#define XFRD_LOWERBOUND_RETRY 1 /* seconds, smallest retry timeout */
#define XFRD_MAX_ROUNDS 3 /* number of rounds along the masters */
#define XFRD_TSIG_MAX_UNSIGNED 103 /* max number of packets without tsig in a tcp stream. */
			/* rfc recommends 100, +3 for offbyone errors/interoperability. */

/* the daemon state */
static xfrd_state_t* xfrd = 0;

/* manage interprocess communication with server_main process */
static void xfrd_handle_ipc(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);

/* main xfrd loop */
static void xfrd_main();
/* shut down xfrd, close sockets. */
static void xfrd_shutdown();
/* create zone rbtree at start */
static void xfrd_init_zones();
/* free up memory used by main database */
static void xfrd_free_namedb();
/* send expiry notify for all zones to nsd */
static void xfrd_send_expy_all_zones();

/* handle zone timeout, event */
static void xfrd_handle_zone(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);
/* handle incoming soa information (NSD is running it, time acquired=guess) */
static void xfrd_handle_incoming_soa(xfrd_zone_t* zone, 
	xfrd_soa_t* soa, time_t acquired);
/* get SOA INFO out of IPC packet buffer */
static void xfrd_handle_ipc_SOAINFO(buffer_type* packet);
/* handle network packet passed to xfrd */
static void xfrd_handle_passed_packet(buffer_type* packet, int acl_num);
/* handle incoming notification message. soa can be NULL. true if transfer needed. */
static int xfrd_handle_incoming_notify(xfrd_zone_t* zone, xfrd_soa_t* soa);

/* call with buffer just after the soa dname. returns 0 on error. */
static int xfrd_parse_soa_info(buffer_type* packet, xfrd_soa_t* soa);
/* copy SOA info from rr to soa struct. */
static void xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr);
/* set the zone state to a new state (takes care of expiry messages) */
static void xfrd_set_zone_state(xfrd_zone_t* zone, enum xfrd_zone_state new_zone_state);
/* set refresh timer of zone to refresh at time now */
static void xfrd_set_refresh_now(xfrd_zone_t* zone);
/* set timer for retry amount (depends on zone_state) */
static void xfrd_set_timer_retry(xfrd_zone_t* zone);
/* set timer for refresh timeout (depends on zone_state) */
static void xfrd_set_timer_refresh(xfrd_zone_t* zone);

/* set reload timeout */
static void xfrd_set_reload_timeout();
/* handle reload timeout */
static void xfrd_handle_reload(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);

/* send notifications to all in the notify list */
static void xfrd_send_notify(xfrd_zone_t* zone);
/* send expiry notifications to nsd */
static void xfrd_send_expire_notification(xfrd_zone_t* zone);
/* send ixfr request, returns fd of connection to read on */
static int xfrd_send_ixfr_request_udp(xfrd_zone_t* zone);

/* read state from disk */
static void xfrd_read_state();
/* write state to disk */
static void xfrd_write_state();

/* send packet via udp (returns UDP fd source socket) to acl addr. 0 on failure. */
static int xfrd_send_udp(acl_options_t* acl, buffer_type* packet);
/* read data via udp */
static void xfrd_udp_read(xfrd_zone_t* zone);

/* find acl by number */
static acl_options_t* acl_find_num(acl_options_t* acl, int num);
/* find master by notify number */
static int find_same_master_notify(xfrd_zone_t* zone, int acl_num_nfy);

void 
xfrd_init(int socket, struct nsd* nsd)
{
	region_type* region;

	assert(xfrd == 0);
	/* to setup signalhandling */
	nsd->server_kind = NSD_SERVER_BOTH;

	region = region_create(xalloc, free);
	xfrd = (xfrd_state_t*)region_alloc(region, sizeof(xfrd_state_t));
	memset(xfrd, 0, sizeof(xfrd_state_t));
	xfrd->region = region;
	xfrd->xfrd_start_time = time(0);
	xfrd->netio = netio_create(xfrd->region);
	xfrd->nsd = nsd;
	xfrd->packet = buffer_create(xfrd->region, QIOBUFSZ);
	xfrd->ipc_pass = buffer_create(xfrd->region, QIOBUFSZ);

	/* add the handlers already, because this involves allocs */
	xfrd->reload_handler.fd = -1;
	xfrd->reload_handler.timeout = NULL;
	xfrd->reload_handler.user_data = xfrd;
	xfrd->reload_handler.event_types = NETIO_EVENT_TIMEOUT;
	xfrd->reload_handler.event_handler = xfrd_handle_reload;
	netio_add_handler(xfrd->netio, &xfrd->reload_handler);
	xfrd->reload_timeout.tv_sec = 0;

	xfrd->ipc_conn = xfrd_tcp_create(xfrd->region);
	xfrd->ipc_conn->is_reading = 0; /* not reading using ipc_conn yet */
	xfrd->ipc_handler.fd = socket;
	xfrd->ipc_handler.timeout = NULL;
	xfrd->ipc_handler.user_data = xfrd;
	xfrd->ipc_handler.event_types = NETIO_EVENT_READ;
	xfrd->ipc_handler.event_handler = xfrd_handle_ipc;
	netio_add_handler(xfrd->netio, &xfrd->ipc_handler);

	xfrd->tcp_set = xfrd_tcp_set_create(xfrd->region);

	log_msg(LOG_INFO, "xfrd pre-startup");
	diff_snip_garbage(nsd->db, nsd->options);
	xfrd_init_zones();
	xfrd_free_namedb();
	xfrd_read_state();
	xfrd_send_expy_all_zones();

	log_msg(LOG_INFO, "xfrd startup");
	xfrd_main();
}

static void 
xfrd_main()
{
	xfrd->shutdown = 0;
	while(!xfrd->shutdown)
	{
		/* dispatch may block for a longer period, so current is gone */
		xfrd->got_time = 0;
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

static void 
xfrd_shutdown()
{
	xfrd_zone_t* zone;
	int i;

	log_msg(LOG_INFO, "xfrd shutdown");
	xfrd_write_state();
	close(xfrd->ipc_handler.fd);
	/* close tcp sockets */
	for(i=0; i<XFRD_MAX_TCP; i++)
	{
		if(xfrd->tcp_set->tcp_state[i]->fd != -1) {
			close(xfrd->tcp_set->tcp_state[i]->fd);
			xfrd->tcp_set->tcp_state[i]->fd = -1;
		}
	}
	/* close udp sockets */
	RBTREE_FOR(zone, xfrd_zone_t*, xfrd->zones)
	{
		if(zone->tcp_conn==-1 && zone->zone_handler.fd != -1) {
			close(zone->zone_handler.fd);
			zone->zone_handler.fd = -1;
		}
	}
	exit(0);
}

static void
xfrd_handle_ipc(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, 
	netio_event_types_type event_types)
{
        sig_atomic_t cmd;
        int len;
        if (!(event_types & NETIO_EVENT_READ))
                return;
	
	if(xfrd->ipc_conn->is_reading==2) {
		buffer_type* tmp = xfrd->ipc_pass;
		uint32_t acl_num;
		/* read acl_num */
		int ret = conn_read(xfrd->ipc_conn);
		if(ret == -1) {
			log_msg(LOG_ERR, "xfrd: error in read ipc: %s", strerror(errno));
			xfrd->ipc_conn->is_reading = 0;
			return;
		}
		if(ret == 0)
			return;
		buffer_flip(xfrd->ipc_conn->packet);
		xfrd->ipc_pass = xfrd->ipc_conn->packet;
		xfrd->ipc_conn->packet = tmp;
		xfrd->ipc_conn->is_reading = 0;
		acl_num = buffer_read_u32(xfrd->ipc_pass);
		xfrd_handle_passed_packet(xfrd->ipc_conn->packet, acl_num);
		return;
	}
	if(xfrd->ipc_conn->is_reading) {
		/* reading an IPC message */
		int ret = conn_read(xfrd->ipc_conn);
		if(ret == -1) {
			log_msg(LOG_ERR, "xfrd: error in read ipc: %s", strerror(errno));
			xfrd->ipc_conn->is_reading = 0;
			return;
		}
		if(ret == 0)
			return;
		buffer_flip(xfrd->ipc_conn->packet);
		if(xfrd->ipc_is_soa) {
			xfrd->ipc_conn->is_reading = 0;
			xfrd_handle_ipc_SOAINFO(xfrd->ipc_conn->packet);
		} else 	{
			/* use ipc_conn to read remaining data as well */
			buffer_type* tmp = xfrd->ipc_pass;
			xfrd->ipc_conn->is_reading=2;
			xfrd->ipc_pass = xfrd->ipc_conn->packet;
			xfrd->ipc_conn->packet = tmp;
			xfrd->ipc_conn->total_bytes = sizeof(xfrd->ipc_conn->msglen);
			xfrd->ipc_conn->msglen = sizeof(uint32_t);
			buffer_clear(xfrd->ipc_conn->packet);
			buffer_set_limit(xfrd->ipc_conn->packet, xfrd->ipc_conn->msglen);
		}
		return;
	}
        
        if((len = read(handler->fd, &cmd, sizeof(cmd))) == -1) {
                log_msg(LOG_ERR, "xfrd_handle_ipc: read: %s",
                        strerror(errno));
                return;
        }
        if(len == 0)
        {
		/* parent closed the connection. Quit */
		xfrd->shutdown = 1;
		return;
        }

        switch(cmd) {
        case NSD_QUIT:
        case NSD_SHUTDOWN:
                xfrd->shutdown = 1;
                break;
	case NSD_SOA_INFO:
		xfrd->ipc_is_soa = 1;
		xfrd->ipc_conn->is_reading = 1;
                break;
	case NSD_SOA_END:
		/* reload has finished */
		xfrd_send_expy_all_zones();
		break;
	case NSD_PASS_TO_XFRD:
		xfrd->ipc_is_soa = 0;
		xfrd->ipc_conn->is_reading = 1;
		break;
        default:
                log_msg(LOG_ERR, "xfrd_handle_ipc: bad mode %d (%d)", (int)cmd,
			ntohl(cmd));
                break;
        }

	if(xfrd->ipc_conn->is_reading) {
		/* setup read of info */
		xfrd->ipc_conn->total_bytes = 0;
		xfrd->ipc_conn->msglen = 0;
		xfrd->ipc_conn->fd = handler->fd;
		buffer_clear(xfrd->ipc_conn->packet);
	}
}

static void xfrd_handle_ipc_SOAINFO(buffer_type* packet)
{
	xfrd_soa_t soa;
	xfrd_zone_t* zone;
	/* dname is sent in memory format */
	const dname_type* dname = (const dname_type*)buffer_begin(packet);

	/* find zone and decode SOA */
	zone = (xfrd_zone_t*)rbtree_search(xfrd->zones, dname);
	if(!zone) {
		log_msg(LOG_ERR, "xfrd: zone %s not configured, but ipc of SOA INFO",
			dname_to_string(dname,0));
		return;
	}
	buffer_skip(packet, dname_total_size(dname));
	if(!buffer_available(packet, sizeof(uint32_t)*6 + sizeof(uint8_t)*2)) {
		/* NSD has zone without any info */
		log_msg(LOG_INFO, "SOAINFO for %s lost zone", dname_to_string(dname,0));

		xfrd_handle_incoming_soa(zone, NULL, xfrd_time());
		return;
	}

	/* read soa info */
	memset(&soa, 0, sizeof(soa));
	/* left out type, klass, count for speed */
	soa.type = htons(TYPE_SOA);
	soa.klass = htons(CLASS_IN);
	soa.ttl = htonl(buffer_read_u32(packet));
	soa.rdata_count = htons(7);
	soa.prim_ns[0] = buffer_read_u8(packet);
	if(!buffer_available(packet, soa.prim_ns[0]))
		return;
	buffer_read(packet, soa.prim_ns+1, soa.prim_ns[0]);
	soa.email[0] = buffer_read_u8(packet);
	if(!buffer_available(packet, soa.email[0]))
		return;
	buffer_read(packet, soa.email+1, soa.email[0]);

	soa.serial = htonl(buffer_read_u32(packet));
	soa.refresh = htonl(buffer_read_u32(packet));
	soa.retry = htonl(buffer_read_u32(packet));
	soa.expire = htonl(buffer_read_u32(packet));
	soa.minimum = htonl(buffer_read_u32(packet));
	log_msg(LOG_INFO, "SOAINFO for %s %d", dname_to_string(dname,0),
		ntohl(soa.serial));
	xfrd_handle_incoming_soa(zone, &soa, xfrd_time());
}

static void 
xfrd_init_zones()
{
	zone_type *dbzone;
	zone_options_t *zone_opt;
	xfrd_zone_t *xzone;
	const dname_type* dname;

	assert(xfrd->zones == 0);
	assert(xfrd->nsd->db != 0);

	xfrd->zones = rbtree_create(xfrd->region, 
		(int (*)(const void *, const void *)) dname_compare);
	
	RBTREE_FOR(zone_opt, zone_options_t*, xfrd->nsd->options->zone_options)
	{
		log_msg(LOG_INFO, "Zone %s\n", zone_opt->name);
		if(!zone_is_slave(zone_opt)) {
			log_msg(LOG_INFO, "skipping master zone %s\n", zone_opt->name);
			continue;
		}

		dname = dname_parse(xfrd->region, zone_opt->name);
		if(!dname) {
			log_msg(LOG_ERR, "xfrd: Could not parse zone name %s.", zone_opt->name);
			continue;
		}

		dbzone = domain_find_zone(domain_table_find(xfrd->nsd->db->domains, dname));
		if(dbzone && dname_compare(dname, domain_dname(dbzone->apex)) != 0)
			dbzone = 0; /* we found a parent zone */
		if(!dbzone)
			log_msg(LOG_INFO, "xfrd: adding empty zone %s\n", zone_opt->name);
		else log_msg(LOG_INFO, "xfrd: adding filled zone %s\n", zone_opt->name);
		
		xzone = (xfrd_zone_t*)region_alloc(xfrd->region, sizeof(xfrd_zone_t));
		memset(xzone, 0, sizeof(xfrd_zone_t));
		xzone->apex = dname;
		xzone->apex_str = zone_opt->name;
		xzone->state = xfrd_zone_expired;
		xzone->zone_options = zone_opt;
		xzone->master = 0; /* first retry will use first master */
		xzone->master_num = 0;
		xzone->next_master = 0;

		xzone->soa_nsd_acquired = 0;
		xzone->soa_disk_acquired = 0;
		xzone->soa_notified_acquired = 0;
		xzone->soa_nsd.prim_ns[0] = 1; /* [0]=1, [1]=0; "." domain name */
		xzone->soa_nsd.email[0] = 1;
		xzone->soa_disk.prim_ns[0]=1;
		xzone->soa_disk.email[0]=1;
		xzone->soa_notified.prim_ns[0]=1;
		xzone->soa_notified.email[0]=1;

		xzone->zone_handler.fd = -1;
		xzone->zone_handler.timeout = 0;
		xzone->zone_handler.user_data = xzone;
		xzone->zone_handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
		xzone->zone_handler.event_handler = xfrd_handle_zone;
		netio_add_handler(xfrd->netio, &xzone->zone_handler);
		xzone->tcp_waiting = 0;
		xzone->tcp_conn = -1;
		xzone->query_region = region_create(xalloc, free);
		region_add_cleanup(xfrd->region, cleanup_region, xzone->query_region);
		
		if(dbzone && dbzone->soa_rrset && dbzone->soa_rrset->rrs) {
			xzone->soa_nsd_acquired = xfrd_time();
			xzone->soa_disk_acquired = xfrd_time();
			/* we only use the first SOA in the rrset */
			xfrd_copy_soa(&xzone->soa_nsd, dbzone->soa_rrset->rrs);
			xfrd_copy_soa(&xzone->soa_disk, dbzone->soa_rrset->rrs);
			/* set refreshing anyway, we have data but it may be old */
		}
		xfrd_set_refresh_now(xzone);

		xzone->node.key = dname;
		rbtree_insert(xfrd->zones, (rbnode_t*)xzone);
	}
	log_msg(LOG_INFO, "xfrd: started server %d secondary zones", (int)xfrd->zones->count);
}

static void
xfrd_send_expy_all_zones()
{
	xfrd_zone_t* zone;
	RBTREE_FOR(zone, xfrd_zone_t*, xfrd->zones)
	{
		xfrd_send_expire_notification(zone);
	}
}

static void 
xfrd_free_namedb()
{
	namedb_close(xfrd->nsd->db);
	xfrd->nsd->db = 0;
}

static void 
xfrd_set_timer_refresh(xfrd_zone_t* zone)
{
	time_t set_refresh;
	time_t set_expire;
	time_t set_min;
	time_t set;
	if(zone->soa_disk_acquired == 0 || zone->state != xfrd_zone_ok) {
		xfrd_set_timer_retry(zone);
		return;
	}
	/* refresh or expire timeout, whichever is earlier */
	set_refresh = zone->soa_disk_acquired + ntohl(zone->soa_disk.refresh);
	set_expire = zone->soa_disk_acquired + ntohl(zone->soa_disk.expire);
	if(set_refresh < set_expire)
		set = set_refresh;
	else set = set_expire;
	set_min = zone->soa_disk_acquired + XFRD_LOWERBOUND_REFRESH;
	if(set < set_min)
		set = set_min;
	xfrd_set_timer(zone, set);
}

static void 
xfrd_set_timer_retry(xfrd_zone_t* zone)
{
	/* set timer for next retry or expire timeout if earlier. */
	if(zone->soa_disk_acquired == 0) {
		/* if no information, use reasonable timeout */
		xfrd_set_timer(zone, xfrd_time() + XFRD_TRANSFER_TIMEOUT
			+ random()%XFRD_TRANSFER_TIMEOUT);
	} else if(zone->state == xfrd_zone_expired ||
		xfrd_time() + ntohl(zone->soa_disk.retry) <
		zone->soa_disk_acquired + ntohl(zone->soa_disk.expire)) 
	{
		if(ntohl(zone->soa_disk.retry) < XFRD_LOWERBOUND_RETRY)
			xfrd_set_timer(zone, xfrd_time() + XFRD_LOWERBOUND_RETRY);
		else 	
			xfrd_set_timer(zone, xfrd_time() + ntohl(zone->soa_disk.retry));
	} else {
		if(ntohl(zone->soa_disk.expire) < XFRD_LOWERBOUND_RETRY)
			xfrd_set_timer(zone, xfrd_time() + XFRD_LOWERBOUND_RETRY);
		else
			xfrd_set_timer(zone, zone->soa_disk_acquired + 
				ntohl(zone->soa_disk.expire));
	}
}

static void 
xfrd_handle_zone(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, netio_event_types_type event_types)
{
	xfrd_zone_t* zone = (xfrd_zone_t*)handler->user_data;

	if(zone->tcp_conn != -1) {
		/* busy in tcp transaction */
		if(xfrd_tcp_is_reading(xfrd->tcp_set, zone->tcp_conn) &&
			event_types & NETIO_EVENT_READ) { 
			xfrd_set_timer(zone, xfrd_time() + XFRD_TCP_TIMEOUT);
			xfrd_tcp_read(xfrd->tcp_set, zone); 
			return;
		} else if(!xfrd_tcp_is_reading(xfrd->tcp_set, zone->tcp_conn) &&
			event_types & NETIO_EVENT_WRITE) { 
			xfrd_set_timer(zone, xfrd_time() + XFRD_TCP_TIMEOUT);
			xfrd_tcp_write(xfrd->tcp_set, zone); 
			return;
		} else if(event_types & NETIO_EVENT_TIMEOUT) {
			/* tcp connection timed out. Stop it. */
			xfrd_tcp_release(xfrd->tcp_set, zone);
			/* continue to retry; as if a timeout happened */
			event_types = NETIO_EVENT_TIMEOUT;
		}
	}

	if(event_types & NETIO_EVENT_READ) {
		/* busy in udp transaction */
		log_msg(LOG_INFO, "xfrd: zone %s event udp read", zone->apex_str);
		xfrd_set_refresh_now(zone);
		xfrd_udp_read(zone);
		return;
	}

	/* timeout */
	log_msg(LOG_INFO, "xfrd: zone %s timeout", zone->apex_str);
	if(handler->fd != -1) {
		close(handler->fd);
		handler->fd = -1;
	}

	if(zone->tcp_waiting) {
		log_msg(LOG_ERR, "xfrd: zone %s skips retry, TCP connections full",
			zone->apex_str);
		xfrd_set_timer_retry(zone);
		return;
	}

	if(zone->soa_disk_acquired)
	{
		if(	zone->state != xfrd_zone_expired &&
			(uint32_t)xfrd_time() >=
			zone->soa_disk_acquired + ntohl(zone->soa_disk.expire))
		{
			/* zone expired */
			log_msg(LOG_ERR, "xfrd: zone %s has expired", zone->apex_str);
			xfrd_set_zone_state(zone, xfrd_zone_expired);
		}
		else if(zone->state == xfrd_zone_ok &&
			(uint32_t)xfrd_time() >=
			zone->soa_disk_acquired + ntohl(zone->soa_disk.refresh))
		{
			/* zone goes to refreshing state. */
			log_msg(LOG_INFO, "xfrd: zone %s is refreshing", zone->apex_str);
			xfrd_set_zone_state(zone, xfrd_zone_refreshing);
		}
	}
	/* make a new request */
	xfrd_make_request(zone);
}

void
xfrd_make_request(xfrd_zone_t* zone)
{
	/* cycle master */
	if(zone->next_master != -1) {
		zone->master_num = zone->next_master;
		zone->master = acl_find_num(
			zone->zone_options->request_xfr, zone->master_num);
		if(!zone->master) {
			zone->master = zone->zone_options->request_xfr;
			zone->master_num = 0;
		}
		zone->next_master = -1;
		zone->round_num = 0; /* fresh set of retries after notify */
	} else {
		if(zone->round_num != -1 && zone->master && 
			zone->master->next) {
			zone->master = zone->master->next;
			zone->master_num++;
		} else {
			zone->master = zone->zone_options->request_xfr;
			zone->master_num = 0;
			zone->round_num++;
		}
		if(zone->round_num >= XFRD_MAX_ROUNDS) {
			/* tried all servers that many times, wait */
			zone->round_num = -1;
			xfrd_set_timer_retry(zone);
			log_msg(LOG_INFO, "xfrd zone %s makereq wait_retry, rd %d mr %d nx %d", 
				zone->apex_str, zone->round_num, zone->master_num, zone->next_master);
			return;
		}
	}

	log_msg(LOG_INFO, "xfrd zone %s make request round %d mr %d nx %d", 
		zone->apex_str, zone->round_num, zone->master_num, zone->next_master);
	/* perform xfr request */
	if(zone->soa_disk_acquired == 0) {
		/* request axfr */
		xfrd_set_timer(zone, xfrd_time() + XFRD_TCP_TIMEOUT);
		xfrd_tcp_obtain(xfrd->tcp_set, zone);
	} else {
		/* request ixfr ; start by udp */
		xfrd_set_timer(zone, xfrd_time() + XFRD_UDP_TIMEOUT);
		zone->zone_handler.fd = xfrd_send_ixfr_request_udp(zone);
	}
}

time_t 
xfrd_time()
{
	if(!xfrd->got_time) {
		xfrd->current_time = time(0);
		xfrd->got_time = 1;
	}
	return xfrd->current_time;
}

static void 
xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr)
{
	const uint8_t* rr_ns_wire = dname_name(domain_dname(rdata_atom_domain(rr->rdatas[0])));
	uint8_t rr_ns_len = domain_dname(rdata_atom_domain(rr->rdatas[0]))->name_size;
	const uint8_t* rr_em_wire = dname_name(domain_dname(rdata_atom_domain(rr->rdatas[1])));
	uint8_t rr_em_len = domain_dname(rdata_atom_domain(rr->rdatas[1]))->name_size;

	if(rr->type != TYPE_SOA || rr->rdata_count != 7) {
		log_msg(LOG_ERR, "xfrd: copy_soa called with bad rr, type %d rrs %d.", 
			rr->type, rr->rdata_count);
		return;
	}
	log_msg(LOG_INFO, "xfrd: copy_soa rr, type %d rrs %d, ttl %d.", 
			rr->type, rr->rdata_count, rr->ttl);
	soa->type = htons(rr->type);
	soa->klass = htons(rr->klass);
	soa->ttl = htonl(rr->ttl);
	soa->rdata_count = htons(rr->rdata_count);
	
	/* copy dnames */
	soa->prim_ns[0] = rr_ns_len;
	memcpy(soa->prim_ns+1, rr_ns_wire, rr_ns_len);
	soa->email[0] = rr_em_len;
	memcpy(soa->email+1, rr_em_wire, rr_em_len);

	/* already in network format */
	memcpy(&soa->serial, rdata_atom_data(rr->rdatas[2]), sizeof(uint32_t));
	memcpy(&soa->refresh, rdata_atom_data(rr->rdatas[3]), sizeof(uint32_t));
	memcpy(&soa->retry, rdata_atom_data(rr->rdatas[4]), sizeof(uint32_t));
	memcpy(&soa->expire, rdata_atom_data(rr->rdatas[5]), sizeof(uint32_t));
	memcpy(&soa->minimum, rdata_atom_data(rr->rdatas[6]), sizeof(uint32_t));
	log_msg(LOG_INFO, "xfrd: copy_soa rr, serial %d refresh %d retry %d expire %d", 
			ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry),
			ntohl(soa->expire));
}

static void 
xfrd_set_zone_state(xfrd_zone_t* zone, enum xfrd_zone_state s)
{
	if(s != zone->state) {
		enum xfrd_zone_state old = zone->state;
		zone->state = s;
		if(s == xfrd_zone_expired || old == xfrd_zone_expired) {
			xfrd_send_expire_notification(zone);
		}
	}
}

static void 
xfrd_set_refresh_now(xfrd_zone_t* zone) 
{
	xfrd_set_timer(zone, xfrd_time());
	log_msg(LOG_INFO, "xfrd zone %s sets timeout right now, state %d",
		zone->apex_str, zone->state);
}

void 
xfrd_set_timer(xfrd_zone_t* zone, time_t t)
{
	/* randomize the time, within 90%-100% of original */
	/* not later so zones cannot expire too late */
	/* only for times far in the future */
	if(t > xfrd_time() + 10) {
		time_t extra = t - xfrd_time();
		time_t base = extra*9/10;
		t = xfrd_time() + base + random()%(extra-base);
	}

	zone->zone_handler.timeout = &zone->timeout;
	zone->timeout.tv_sec = t;
	zone->timeout.tv_nsec = 0;
}

/* quick tokenizer, reads words separated by whitespace.
   No quoted strings. Comments are skipped (#... eol). */
static char* 
xfrd_read_token(FILE* in)
{
	static char buf[4000];
	buf[sizeof(buf)-1]=0;
	while(1) {
		if(fscanf(in, " %3990s", buf) != 1) 
			return 0;

		if(buf[0] != '#') 
			return buf;
		
		if(!fgets(buf, sizeof(buf), in)) 
			return 0;
	}
}

static int 
xfrd_read_i16(FILE *in, uint16_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) 
		return 0;

	*v=atoi(p);
	return 1;
}

static int 
xfrd_read_i32(FILE *in, uint32_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) 
		return 0;

	*v=atoi(p);
	return 1;
}

static int 
xfrd_read_time_t(FILE *in, time_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) 
		return 0;
	
	*v=atol(p);
	return 1;
}

static int 
xfrd_read_check_str(FILE* in, const char* str)
{
	char *p = xfrd_read_token(in);
	if(!p)
		return 0;

	if(strcmp(p, str) != 0) 
		return 0;

	return 1;
}

static int 
xfrd_read_state_soa(FILE* in, const char* id_acquired,
	const char* id, xfrd_soa_t* soa, time_t* soatime)
{
	char *p;

	if(!xfrd_read_check_str(in, id_acquired) ||
	   !xfrd_read_time_t(in, soatime)) {
		return 0;
	}

	if(*soatime == 0) 
		return 1;
	
	if(!xfrd_read_check_str(in, id) ||
	   !xfrd_read_i16(in, &soa->type) ||
	   !xfrd_read_i16(in, &soa->klass) ||
	   !xfrd_read_i32(in, &soa->ttl) ||
	   !xfrd_read_i16(in, &soa->rdata_count)) 
	{
		return 0;
	}

	soa->type = htons(soa->type);
	soa->klass = htons(soa->klass);
	soa->ttl = htonl(soa->ttl);
	soa->rdata_count = htons(soa->rdata_count);

	if(!(p=xfrd_read_token(in)) ||
	   !(soa->prim_ns[0] = dname_parse_wire(soa->prim_ns+1, p)))
		return 0;

	if(!(p=xfrd_read_token(in)) ||
	   !(soa->email[0] = dname_parse_wire(soa->email+1, p)))
		return 0;

	if(!xfrd_read_i32(in, &soa->serial) ||
	   !xfrd_read_i32(in, &soa->refresh) ||
	   !xfrd_read_i32(in, &soa->retry) ||
	   !xfrd_read_i32(in, &soa->expire) ||
	   !xfrd_read_i32(in, &soa->minimum)) 
	{
		return 0;
	}

	soa->serial = htonl(soa->serial);
	soa->refresh = htonl(soa->refresh);
	soa->retry = htonl(soa->retry);
	soa->expire = htonl(soa->expire);
	soa->minimum = htonl(soa->minimum);
	return 1;
}

static void 
xfrd_read_state()
{
	const char* statefile = xfrd->nsd->options->xfrdfile;
	FILE *in;
	uint32_t filetime = 0;
	uint32_t numzones, i;
	region_type *tempregion;
	if(!statefile) 
		statefile = XFRDFILE;

	tempregion = region_create(xalloc, free);
	if(!tempregion) 
		return;

	in = fopen(statefile, "r");
	if(!in) {
		if(errno != ENOENT) {
			log_msg(LOG_ERR, "xfrd: Could not open file %s for reading: %s",
				statefile, strerror(errno));
		} else {
			log_msg(LOG_INFO, "xfrd: no file %s. refreshing all zones.",
				statefile);
		}
		region_destroy(tempregion);
		return;
	}
	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC) ||
	   !xfrd_read_check_str(in, "filetime:") ||
	   !xfrd_read_i32(in, &filetime) ||
	   (time_t)filetime > xfrd_time()+15 ||
	   !xfrd_read_check_str(in, "numzones:") ||
	   !xfrd_read_i32(in, &numzones)) 
	{
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		fclose(in);
		region_destroy(tempregion);
		return;
	}

	for(i=0; i<numzones; i++) {
		char *p;
		xfrd_zone_t* zone;
		const dname_type* dname;
		uint32_t state, masnum, nextmas, round_num, timeout;
		xfrd_soa_t soa_nsd_read, soa_disk_read, soa_notified_read;
		time_t soa_nsd_acquired_read, 
			soa_disk_acquired_read, soa_notified_acquired_read;
		xfrd_soa_t incoming_soa;
		time_t incoming_acquired;

		memset(&soa_nsd_read, 0, sizeof(soa_nsd_read));
		memset(&soa_disk_read, 0, sizeof(soa_disk_read));
		memset(&soa_notified_read, 0, sizeof(soa_notified_read));

		if(!xfrd_read_check_str(in, "zone:") ||
		   !xfrd_read_check_str(in, "name:")  ||
		   !(p=xfrd_read_token(in)) ||
		   !(dname = dname_parse(tempregion, p)) ||
		   !xfrd_read_check_str(in, "state:") ||
		   !xfrd_read_i32(in, &state) || (state>2) ||
		   !xfrd_read_check_str(in, "master:") ||
		   !xfrd_read_i32(in, &masnum) ||
		   !xfrd_read_check_str(in, "next_master:") ||
		   !xfrd_read_i32(in, &nextmas) ||
		   !xfrd_read_check_str(in, "round_num:") ||
		   !xfrd_read_i32(in, &round_num) ||
		   !xfrd_read_check_str(in, "next_timeout:") ||
		   !xfrd_read_i32(in, &timeout) ||
		   !xfrd_read_state_soa(in, "soa_nsd_acquired:", "soa_nsd:",
			&soa_nsd_read, &soa_nsd_acquired_read) ||
		   !xfrd_read_state_soa(in, "soa_disk_acquired:", "soa_disk:",
			&soa_disk_read, &soa_disk_acquired_read) ||
		   !xfrd_read_state_soa(in, "soa_notify_acquired:", "soa_notify:",
			&soa_notified_read, &soa_notified_acquired_read))
		{
			log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
				statefile, (int)filetime, (int)xfrd_time());
			fclose(in);
			region_destroy(tempregion);
			return;
		}

		zone = (xfrd_zone_t*)rbtree_search(xfrd->zones, dname);
		if(!zone) {
			log_msg(LOG_INFO, "xfrd: state file has info for not configured zone %s", p);
			continue;
		}

		if(soa_nsd_acquired_read>xfrd_time()+15 ||
			soa_disk_acquired_read>xfrd_time()+15 ||
			soa_notified_acquired_read>xfrd_time()+15)
		{
			log_msg(LOG_ERR, "xfrd: statefile %s contains"
				" times in the future for zone %s. Ignoring.",
				statefile, zone->apex_str);
			continue;
		}
		zone->state = state;
		zone->master_num = masnum;
		zone->next_master = nextmas;
		zone->round_num = round_num;
		zone->timeout.tv_sec = timeout;
		zone->timeout.tv_nsec = 0;

		/* read the zone OK, now set the master properly */
		zone->master = acl_find_num(
			zone->zone_options->request_xfr, zone->master_num);
		if(!zone->master) {
			log_msg(LOG_INFO, "xfrd: masters changed for zone %s", 
				zone->apex_str);
			zone->master = zone->zone_options->request_xfr;
			zone->master_num = 0;
			zone->round_num = 0;
		}

		/* 
		 * There is no timeout,
		 * or there is a notification,
		 * or there is a soa && current time is past refresh point
		 */
		if(timeout == 0 || soa_notified_acquired_read != 0 ||
			(soa_disk_acquired_read != 0 &&
			(uint32_t)xfrd_time() - soa_disk_acquired_read 
				> ntohl(soa_disk_read.refresh)))
		{
			zone->state = xfrd_zone_refreshing;
			xfrd_set_refresh_now(zone);
		}

		/* There is a soa && current time is past expiry point */
		if(soa_disk_acquired_read!=0 &&
			(uint32_t)xfrd_time() - soa_disk_acquired_read 
				> ntohl(soa_disk_read.expire))
		{
			zone->state = xfrd_zone_expired;
			xfrd_set_refresh_now(zone);
		}

		/* handle as an incoming SOA. */
		incoming_soa = zone->soa_nsd;
		incoming_acquired = zone->soa_nsd_acquired;
		zone->soa_nsd = soa_nsd_read;
		zone->soa_disk = soa_disk_read;
		zone->soa_notified = soa_notified_read;
		zone->soa_nsd_acquired = soa_nsd_acquired_read;
		zone->soa_disk_acquired = soa_disk_acquired_read;
		zone->soa_notified_acquired = soa_notified_acquired_read;
		xfrd_handle_incoming_soa(zone, &incoming_soa, incoming_acquired);
	}

	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC)) {
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		region_destroy(tempregion);
		fclose(in);
		return;
	}

	log_msg(LOG_INFO, "xfrd: read %d zones from state file", numzones);
	fclose(in);
	region_destroy(tempregion);
}

/* prints neato days hours and minutes. */
static void 
neato_timeout(FILE* out, const char* str, uint32_t secs)
{
	fprintf(out, "%s", str);
	if(secs <= 0) {
		fprintf(out, " %ds", secs);
		return;
	}
	if(secs >= 3600*24) {
		fprintf(out, " %dd", secs/(3600*24));
		secs = secs % (3600*24);
	}
	if(secs >= 3600) {
		fprintf(out, " %dh", secs/3600);
		secs = secs%3600;
	}
	if(secs >= 60) {
		fprintf(out, " %dm", secs/60);
		secs = secs%60;
	}
	if(secs > 0) {
		fprintf(out, " %ds", secs);
	}
}

static void xfrd_write_dname(FILE* out, uint8_t* dname)
{
	uint8_t* d= dname+1;
	uint8_t len = *d++;
	uint8_t i;

	if(dname[0]<=1) {
		fprintf(out, ".");
		return;
	}

	while(len)
	{
		assert(d - (dname+1) <= dname[0]);
		for(i=0; i<len; i++)
		{
			uint8_t ch = *d++;
			if (isalnum(ch) || ch == '-' || ch == '_') {
				fprintf(out, "%c", ch);
			} else if (ch == '.' || ch == '\\') {
				fprintf(out, "\\%c", ch);
			} else {
				fprintf(out, "\\%03u", (unsigned int)ch);
			}
		}
		fprintf(out, ".");
		len = *d++;
	}
}

static void 
xfrd_write_state_soa(FILE* out, const char* id,
	xfrd_soa_t* soa, time_t soatime, const dname_type* ATTR_UNUSED(apex))
{
	fprintf(out, "\t%s_acquired: %d", id, (int)soatime);
	if(!soatime) {
		fprintf(out, "\n");
		return;
	}
	neato_timeout(out, "\t# was", xfrd_time()-soatime);
	fprintf(out, " ago\n");

	fprintf(out, "\t%s: %d %d %d %d", id, 
		ntohs(soa->type), ntohs(soa->klass), 
		ntohl(soa->ttl), ntohs(soa->rdata_count));
	fprintf(out, " ");
	xfrd_write_dname(out, soa->prim_ns);
	fprintf(out, " ");
	xfrd_write_dname(out, soa->email);
	fprintf(out, " %d", ntohl(soa->serial));
	fprintf(out, " %d", ntohl(soa->refresh));
	fprintf(out, " %d", ntohl(soa->retry));
	fprintf(out, " %d", ntohl(soa->expire));
	fprintf(out, " %d\n", ntohl(soa->minimum));
	fprintf(out, "\t#");
	neato_timeout(out, " refresh =", ntohl(soa->refresh));
	neato_timeout(out, " retry =", ntohl(soa->retry));
	neato_timeout(out, " expire =", ntohl(soa->expire));
	neato_timeout(out, " minimum =", ntohl(soa->minimum));
	fprintf(out, "\n");
}

static void xfrd_write_state()
{
	rbnode_t* p;
	const char* statefile = xfrd->nsd->options->xfrdfile;
	FILE *out;
	time_t now = xfrd_time();
	if(!statefile) 
		statefile = XFRDFILE;

	log_msg(LOG_INFO, "xfrd: write file %s", statefile);
	out = fopen(statefile, "w");
	if(!out) {
		log_msg(LOG_ERR, "xfrd: Could not open file %s for writing: %s",
				statefile, strerror(errno));
		return;
	}
	
	fprintf(out, "%s\n", XFRD_FILE_MAGIC);
	fprintf(out, "filetime: %d\t# %s\n", (int)now, ctime(&now));
	fprintf(out, "numzones: %d\n", (int)xfrd->zones->count);
	fprintf(out, "\n");
	for(p = rbtree_first(xfrd->zones); p && p!=RBTREE_NULL; p=rbtree_next(p))
	{
		xfrd_zone_t* zone = (xfrd_zone_t*)p;
		fprintf(out, "zone: \tname: %s\n", zone->apex_str);
		fprintf(out, "\tstate: %d", (int)zone->state);
		fprintf(out, " # %s", zone->state==xfrd_zone_ok?"OK":(
			zone->state==xfrd_zone_refreshing?"refreshing":"expired"));
		fprintf(out, "\n");
		fprintf(out, "\tmaster: %d\n", zone->master_num);
		fprintf(out, "\tnext_master: %d\n", zone->next_master);
		fprintf(out, "\tround_num: %d\n", zone->round_num);
		fprintf(out, "\tnext_timeout: %d", 
			zone->zone_handler.timeout?(int)zone->timeout.tv_sec:0);
		if(zone->zone_handler.timeout) {
			neato_timeout(out, "\t# =", zone->timeout.tv_sec - xfrd_time()); 
		}
		fprintf(out, "\n");
		xfrd_write_state_soa(out, "soa_nsd", &zone->soa_nsd, 
			zone->soa_nsd_acquired, zone->apex);
		xfrd_write_state_soa(out, "soa_disk", &zone->soa_disk, 
			zone->soa_disk_acquired, zone->apex);
		xfrd_write_state_soa(out, "soa_notify", &zone->soa_notified, 
			zone->soa_notified_acquired, zone->apex);
		fprintf(out, "\n");
	}

	fprintf(out, "%s\n", XFRD_FILE_MAGIC);
	log_msg(LOG_INFO, "xfrd: written %d zones to state file", (int)xfrd->zones->count);
	fclose(out);
}

static void xfrd_handle_incoming_soa(xfrd_zone_t* zone, 
	xfrd_soa_t* soa, time_t acquired)
{
	if(soa == NULL) {
		/* nsd no longer has a zone in memory */
		zone->soa_nsd_acquired = 0;
		xfrd_set_zone_state(zone, xfrd_zone_refreshing);
		xfrd_set_refresh_now(zone);
		return;
	}
	if(zone->soa_nsd_acquired && soa->serial == zone->soa_nsd.serial)
		return;

	if(zone->soa_disk_acquired && soa->serial == zone->soa_disk.serial)
	{
		/* soa in disk has been loaded in memory */
		log_msg(LOG_INFO, "Zone %s serial %d is updated to %d.",
			zone->apex_str, ntohl(zone->soa_nsd.serial),
			ntohl(soa->serial));
		zone->soa_nsd = zone->soa_disk;
		zone->soa_nsd_acquired = zone->soa_disk_acquired;
		if((uint32_t)xfrd_time() - zone->soa_disk_acquired 
			< ntohl(zone->soa_disk.refresh))
		{
			/* zone ok, wait for refresh time */
			xfrd_set_zone_state(zone, xfrd_zone_ok);
			zone->round_num = -1;
			xfrd_set_timer_refresh(zone);
		} else if((uint32_t)xfrd_time() - zone->soa_disk_acquired 
			< ntohl(zone->soa_disk.expire))
		{
			/* zone refreshing */
			xfrd_set_zone_state(zone, xfrd_zone_refreshing);
			xfrd_set_refresh_now(zone);
		} 
		if((uint32_t)xfrd_time() - zone->soa_disk_acquired
			>= ntohl(zone->soa_disk.expire)) {
			/* zone expired */
			xfrd_set_zone_state(zone, xfrd_zone_expired);
			xfrd_set_refresh_now(zone);
		}

		if(zone->soa_notified_acquired != 0 &&
			(zone->soa_notified.serial == 0 ||
		   	compare_serial(ntohl(zone->soa_disk.serial),
				ntohl(zone->soa_notified.serial)) >= 0))
		{	/* read was in response to this notification */
			zone->soa_notified_acquired = 0;
		}
		if(zone->soa_notified_acquired && zone->state == xfrd_zone_ok)
		{
			/* refresh because of notification */
			xfrd_set_zone_state(zone, xfrd_zone_refreshing);
			xfrd_set_refresh_now(zone);
		}
		xfrd_send_notify(zone);
		return;
	}

	/* user must have manually provided zone data */
	log_msg(LOG_INFO, "xfrd: zone %s serial %d from unknown source. refreshing", 
		zone->apex_str, ntohl(soa->serial));
	zone->soa_nsd = *soa;
	zone->soa_disk = *soa;
	zone->soa_nsd_acquired = acquired;
	zone->soa_disk_acquired = acquired;
	if(zone->soa_notified_acquired != 0 &&
		(zone->soa_notified.serial == 0 ||
	   	compare_serial(ntohl(zone->soa_disk.serial),
			ntohl(zone->soa_notified.serial)) >= 0))
	{	/* user provided in response to this notification */
		zone->soa_notified_acquired = 0;
	}
	xfrd_set_zone_state(zone, xfrd_zone_refreshing);
	xfrd_set_refresh_now(zone);
	xfrd_send_notify(zone);
}

static void 
xfrd_send_notify(xfrd_zone_t* zone)
{
	log_msg(LOG_INFO, "TODO: xfrd sending notifications for zone %s.",
		zone->apex_str);
}

static void 
xfrd_send_expire_notification(xfrd_zone_t* zone)
{
	sig_atomic_t cmd = NSD_ZONE_STATE;
	uint8_t ok = 1;
	uint16_t sz = dname_total_size(zone->apex) + 1;
	int fd = xfrd->ipc_handler.fd;
	log_msg(LOG_INFO, "xfrd sending zone state to nsd for zone %s state %d.",
		zone->apex_str, (int)zone->state);
	sz = htons(sz);
	if(zone->state == xfrd_zone_expired)
		ok = 0;
	/* note blocking IO */
	xfrd->got_time = 0;
	if(!write_socket(fd, &cmd, sizeof(cmd)) ||
		!write_socket(fd, &sz, sizeof(sz)) ||
		!write_socket(fd, &ok, sizeof(ok)) ||
		!write_socket(fd, zone->apex, dname_total_size(zone->apex))) {
		log_msg(LOG_ERR, "problems sending zone state from xfrd to nsd: %s",
			strerror(errno));
	}
}

static void 
xfrd_udp_read(xfrd_zone_t* zone)
{
	ssize_t received;

	log_msg(LOG_INFO, "xfrd: zone %s read udp data", zone->apex_str);
	/* read and handle the data */
	buffer_clear(xfrd->packet);
	received = recvfrom(zone->zone_handler.fd, 
		buffer_begin(xfrd->packet), buffer_remaining(xfrd->packet),
		0, NULL, NULL);
	if(received == -1) {
		log_msg(LOG_ERR, "xfrd: recvfrom failed: %s",
			strerror(errno));
		close(zone->zone_handler.fd);
		zone->zone_handler.fd = -1;
		return;
	}
	buffer_set_limit(xfrd->packet, received);
	close(zone->zone_handler.fd);
	zone->zone_handler.fd = -1;
	switch(xfrd_handle_received_xfr_packet(zone, xfrd->packet)) {
		case xfrd_packet_tcp:
			xfrd_set_timer(zone, xfrd_time() + XFRD_TCP_TIMEOUT);
			xfrd_tcp_obtain(xfrd->tcp_set, zone);
			break;
		case xfrd_packet_transfer:
		case xfrd_packet_newlease:
			/* nothing more to do */
			assert(zone->round_num == -1);
			break;
		case xfrd_packet_more:
		case xfrd_packet_bad:
		default:
			/* drop packet */
			/* query next server */
			xfrd_make_request(zone);
			break;
	}
}

static int 
xfrd_send_udp(acl_options_t* acl, buffer_type* packet)
{
	struct sockaddr_storage to;
	int fd, family;
	socklen_t to_len = xfrd_acl_sockaddr(acl, &to);

	if(acl->is_ipv6) {
#ifdef INET6
		family = PF_INET6;
#else
		return -1;
#endif
	} else {
		family = PF_INET;
	}

	fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if(fd == -1) {
		log_msg(LOG_ERR, "xfrd: cannot create udp socket to %s: %s",
			acl->ip_address_spec, strerror(errno));
		return -1;
	}

	/* send it (udp) */
	if(sendto(fd,
		buffer_current(packet),
		buffer_remaining(packet), 0,
		(struct sockaddr*)&to, to_len) == -1)
	{
		log_msg(LOG_ERR, "xfrd: sendto %s failed %s",
			acl->ip_address_spec, strerror(errno));
		return -1;
	}
	return fd;
}

void
xfrd_tsig_sign_request(buffer_type* packet, xfrd_zone_t* zone, 
	acl_options_t* acl)
{
#ifdef TSIG
	tsig_algorithm_type* algo;
	assert(acl->key_options && acl->key_options->tsig_key);
	algo = tsig_get_algorithm_by_name(acl->key_options->algorithm);
	if(!algo) {
		log_msg(LOG_ERR, "tsig unknown algorithm %s", 
			acl->key_options->algorithm);
		return;
	}
	assert(algo);
	region_free_all(zone->query_region);
	tsig_init_record(&zone->tsig, zone->query_region, algo, acl->key_options->tsig_key);
	tsig_init_query(&zone->tsig, ID(packet));
	tsig_prepare(&zone->tsig);
	tsig_update(&zone->tsig, packet, buffer_position(packet));
	tsig_sign(&zone->tsig);
	tsig_append_rr(&zone->tsig, packet);
	ARCOUNT_SET(packet, ARCOUNT(packet) + 1);
	log_msg(LOG_INFO, "appending tsig to packet");
	/* prepare for validating tsigs */
	tsig_prepare(&zone->tsig);
#endif
}

static int 
xfrd_send_ixfr_request_udp(xfrd_zone_t* zone)
{
	int fd;
	assert(zone->master);
	if(zone->tcp_conn != -1) {
		/* tcp is using the zone_handler.fd */
		log_msg(LOG_ERR, "xfrd: %s tried to send udp whilst tcp engaged",
			zone->apex_str);
		return -1;
	}
	xfrd_setup_packet(xfrd->packet, TYPE_IXFR, CLASS_IN, zone->apex);
	zone->query_id = ID(xfrd->packet);
	zone->msg_seq_nr = 0;
	zone->msg_rr_count = 0;
	log_msg(LOG_INFO, "sent query with ID %d", zone->query_id);
        NSCOUNT_SET(xfrd->packet, 1);
	xfrd_write_soa_buffer(xfrd->packet, zone, &zone->soa_disk);
	if(zone->master->key_options) {
		xfrd_tsig_sign_request(xfrd->packet, zone, zone->master);
	}
	buffer_flip(xfrd->packet);

	if((fd = xfrd_send_udp(zone->master, xfrd->packet)) == -1) 
		return -1;

	log_msg(LOG_INFO, "xfrd sent udp request for ixfr=%d for zone %s to %s", 
		ntohl(zone->soa_disk.serial),
		zone->apex_str, zone->master->ip_address_spec);
	return fd;
}

static int xfrd_parse_soa_info(buffer_type* packet, xfrd_soa_t* soa)
{
	if(!buffer_available(packet, 10))
		return 0;
	soa->type = htons(buffer_read_u16(packet));
	soa->klass = htons(buffer_read_u16(packet));
	soa->ttl = htonl(buffer_read_u32(packet));
	if(ntohs(soa->type) != TYPE_SOA || ntohs(soa->klass) != CLASS_IN)
	{
		return 0;
	}

	if(!buffer_available(packet, buffer_read_u16(packet)) /* rdata length */ ||
		!(soa->prim_ns[0] = dname_make_wire_from_packet(soa->prim_ns+1, packet, 1)) ||
		!(soa->email[0] = dname_make_wire_from_packet(soa->email+1, packet, 1)))
	{
		return 0;
	}
	soa->serial = htonl(buffer_read_u32(packet));
	soa->refresh = htonl(buffer_read_u32(packet));
	soa->retry = htonl(buffer_read_u32(packet));
	soa->expire = htonl(buffer_read_u32(packet));
	soa->minimum = htonl(buffer_read_u32(packet));

	return 1;
}


/* 
 * Check the RRs in an IXFR/AXFR reply.
 * returns 0 on error, 1 on correct parseable packet.
 * done = 1 if the last SOA in an IXFR/AXFR has been seen.
 * soa then contains that soa info.
 * (soa contents is modified by the routine) 
 */
static int
xfrd_xfr_check_rrs(xfrd_zone_t* zone, buffer_type* packet, size_t count, 
	int *done, xfrd_soa_t* soa)
{
	/* first RR has already been checked */
	uint16_t type, klass, rrlen;
	uint32_t ttl;
	size_t i, soapos;
	for(i=0; i<count; ++i,++zone->msg_rr_count)
	{
		if(!packet_skip_dname(packet))
			return 0;
		if(!buffer_available(packet, 10))
			return 0;
		soapos = buffer_position(packet);
		type = buffer_read_u16(packet);
		klass = buffer_read_u16(packet);
		ttl = buffer_read_u32(packet);
		rrlen = buffer_read_u16(packet);
		if(!buffer_available(packet, rrlen))
			return 0;
		if(type == TYPE_SOA) {
			/* check the SOAs */
			size_t mempos = buffer_position(packet);
			buffer_set_position(packet, soapos);
			if(!xfrd_parse_soa_info(packet, soa))
				return 0;
			if(zone->msg_rr_count == 1 && 
				ntohl(soa->serial) != zone->msg_new_serial) {
				/* 2nd RR is SOA with lower serial, this is an IXFR */
				zone->msg_is_ixfr = 1;
				if(!zone->soa_disk_acquired)
					return 0; /* got IXFR but need AXFR */
				if(ntohl(soa->serial) != ntohl(zone->soa_disk.serial))
					return 0; /* bad start serial in IXFR */
				zone->msg_old_serial = ntohl(soa->serial);
			}
			else if(ntohl(soa->serial) == zone->msg_new_serial) {
				/* saw another SOA of new serial. */
				if(zone->msg_is_ixfr == 1) {
					zone->msg_is_ixfr = 2; /* seen middle SOA in ixfr */
				} else {
					/* 2nd SOA for AXFR or 3rd newSOA for IXFR */
					*done = 1;
				}
			}
			buffer_set_position(packet, mempos);
		}
		buffer_skip(packet, rrlen);
	}
	/* packet seems to have a valid DNS RR structure */
	return 1;
}

static int
xfrd_xfr_process_tsig(xfrd_zone_t* zone, buffer_type* packet)
{
#ifdef TSIG
	int have_tsig = 0;
	assert(zone && zone->master && zone->master->key_options 
		&& zone->master->key_options->tsig_key && packet);
	if(!tsig_find_rr(&zone->tsig, packet)) {
		log_msg(LOG_ERR, "xfrd: zone %s, from %s: malformed tsig RR",
			zone->apex_str, zone->master->ip_address_spec);
		return 0;
	} 
	if(zone->tsig.status == TSIG_OK) {
		have_tsig = 1;
	}
	if(have_tsig) {
		/* strip the TSIG resource record off... */
		buffer_set_limit(packet, zone->tsig.position);
		ARCOUNT_SET(packet, ARCOUNT(packet) - 1);
	}

	/* keep running the TSIG hash */
	tsig_update(&zone->tsig, packet, buffer_limit(packet));
	if(have_tsig) {
		if (!tsig_verify(&zone->tsig)) {
			log_msg(LOG_ERR, "xfrd: zone %s, from %s: bad tsig signature",
				zone->apex_str, zone->master->ip_address_spec);
			return 0;
		}
		log_msg(LOG_INFO, "xfrd: zone %s, from %s: good tsig signature",
			zone->apex_str, zone->master->ip_address_spec);
		/* prepare for next tsigs */
		tsig_prepare(&zone->tsig);
	}
	else if(zone->tsig.updates_since_last_prepare > XFRD_TSIG_MAX_UNSIGNED) {
		/* we allow a number of non-tsig signed packets */
		log_msg(LOG_INFO, "xfrd: zone %s, from %s: too many consecutive "
			"packets without TSIG", zone->apex_str, 
			zone->master->ip_address_spec);
		return 0;
	}

	if(!have_tsig && zone->msg_seq_nr == 0) {
		log_msg(LOG_ERR, "xfrd: zone %s, from %s: no tsig in first packet of reply",
			zone->apex_str, zone->master->ip_address_spec);
		return 0;
	}
#endif
	return 1;
}

/* parse the received packet. returns xfrd packet result code. */
static enum xfrd_packet_result 
xfrd_parse_received_xfr_packet(xfrd_zone_t* zone, buffer_type* packet, 
	xfrd_soa_t* soa)
{
	size_t rr_count;
	size_t qdcount = QDCOUNT(packet);
	size_t ancount = ANCOUNT(packet), ancount_todo;
	int done = 0;

	/* has to be axfr / ixfr reply */
	if(!buffer_available(packet, QHEADERSZ)) {
		log_msg(LOG_INFO, "packet too small");
		return xfrd_packet_bad;
	}

	/* only check ID in first response message. Could also check that
	 * AA bit and QR bit are set, but not needed.
	 */
	log_msg(LOG_INFO, "got query with ID %d and %d needed", ID(packet), zone->query_id);
	if(ID(packet) != zone->query_id) {
		log_msg(LOG_ERR, "xfrd: zone %s received bad query id from %s, dropped",
			zone->apex_str, zone->master->ip_address_spec);
		return xfrd_packet_bad;
	}
	/* check RCODE in all response messages */
	if(RCODE(packet) != RCODE_OK) {
		log_msg(LOG_ERR, "xfrd: zone %s received error code %s from %s",
			zone->apex_str, rcode2str(RCODE(packet)), 
			zone->master->ip_address_spec);
		return xfrd_packet_bad;
	}
#ifdef TSIG
	/* check TSIG */
	if(zone->master->key_options) {
		if(!xfrd_xfr_process_tsig(zone, packet)) {
			log_msg(LOG_ERR, "dropping xfr reply due to bad TSIG");
			return xfrd_packet_bad;
		}
	}
#endif
	buffer_skip(packet, QHEADERSZ);

	/* skip question section */
	for(rr_count = 0; rr_count < qdcount; ++rr_count) {
		if (!packet_skip_rr(packet, 1)) {
			log_msg(LOG_ERR, "xfrd: zone %s, from %s: bad RR in question section",
				zone->apex_str, zone->master->ip_address_spec);
			return xfrd_packet_bad;
		}
	}
	if(ancount == 0) {
		log_msg(LOG_INFO, "xfrd: too short xfr packet: no answer");
		return xfrd_packet_bad;
	}
	ancount_todo = ancount;

	if(zone->msg_rr_count == 0) {
		/* parse the first RR, see if it is a SOA */
		if(!packet_skip_dname(packet) ||
			!xfrd_parse_soa_info(packet, soa))
		{
			log_msg(LOG_ERR, "xfrd: zone %s, from %s: no SOA begins answer section",
				zone->apex_str, zone->master->ip_address_spec);
			return xfrd_packet_bad;
		}
		if(zone->soa_disk_acquired != 0 &&
			zone->state != xfrd_zone_expired /* if expired - accept anything */ &&
			compare_serial(ntohl(zone->soa_disk.serial), ntohl(soa->serial)) > 0) {
			log_msg(LOG_INFO, "xfrd: zone %s ignoring old serial from %s",
				zone->apex_str, zone->master->ip_address_spec);
			return xfrd_packet_bad;
		}
		if(zone->soa_disk_acquired != 0 && zone->soa_disk.serial == soa->serial) {
			log_msg(LOG_INFO, "xfrd: zone %s got update indicating current serial",
				zone->apex_str);
			if(zone->soa_notified_acquired == 0) {
				/* we got a new lease on the SOA */
				zone->soa_disk_acquired = xfrd_time();
				if(zone->soa_nsd.serial == soa->serial)
					zone->soa_nsd_acquired = xfrd_time();
				xfrd_set_zone_state(zone, xfrd_zone_ok);
				log_msg(LOG_INFO, "xfrd: zone %s is ok", zone->apex_str);
				zone->round_num = -1; /* next try start anew */
				xfrd_set_timer_refresh(zone);
				return xfrd_packet_newlease;
			}
			/* try next master */
			return xfrd_packet_bad;
		}
		log_msg(LOG_INFO, "IXFR reply has newer serial (have %d, reply %d)",
			ntohl(zone->soa_disk.serial), ntohl(soa->serial));
		/* serial is newer than soa_disk */
		if(ancount == 1) {
			/* single record means it is like a notify */
			(void)xfrd_handle_incoming_notify(zone, soa);
		}
		else if(zone->soa_notified_acquired && zone->soa_notified.serial &&
			compare_serial(ntohl(zone->soa_notified.serial), ntohl(soa->serial)) < 0) {
			/* this AXFR/IXFR notifies me that an even newer serial exists */
			zone->soa_notified.serial = soa->serial;
		}
		zone->msg_new_serial = ntohl(soa->serial);
		zone->msg_rr_count = 1;
		zone->msg_is_ixfr = 0;
		if(zone->soa_disk_acquired)
			zone->msg_old_serial = ntohl(zone->soa_disk.serial);
		else zone->msg_old_serial = 0;
		ancount_todo = ancount - 1;
	}

	if(zone->tcp_conn == -1 && TC(packet)) {
		log_msg(LOG_INFO, "xfrd: zone %s received TC from %s. retry tcp.",
			zone->apex_str, zone->master->ip_address_spec);
		return xfrd_packet_tcp;
	}

	if(zone->tcp_conn == -1 && ancount < 2) {
		/* too short to be a real ixfr/axfr data transfer */
		log_msg(LOG_INFO, "xfrd: udp reply is short. Try tcp anyway.");
		return xfrd_packet_tcp;
	}

	if(!xfrd_xfr_check_rrs(zone, packet, ancount_todo, &done, soa))
	{
		log_msg(LOG_INFO, "xfrd: zone %s sent bad xfr reply.",
			zone->apex_str);
		return xfrd_packet_bad;
	}
	if(zone->tcp_conn == -1 && done == 0) {
		log_msg(LOG_INFO, "xfrd: udp reply incomplete");
		return xfrd_packet_bad;
	}
	if(done == 0)
		return xfrd_packet_more;
#ifdef TSIG
	if(zone->master->key_options) {
		if(zone->tsig.updates_since_last_prepare != 0) {
			log_msg(LOG_INFO, "xfrd: last packet of reply has no TSIG");
			return xfrd_packet_bad;
		}
	}
#endif
	return xfrd_packet_transfer;
}

enum xfrd_packet_result 
xfrd_handle_received_xfr_packet(xfrd_zone_t* zone, buffer_type* packet)
{
	xfrd_soa_t soa;
	enum xfrd_packet_result res;

	/* parse and check the packet - see if it ends the xfr */
	switch((res=xfrd_parse_received_xfr_packet(zone, packet, &soa)))
	{
		case xfrd_packet_more:
		case xfrd_packet_transfer:
			/* continue with commit */
			break;
		case xfrd_packet_newlease:
			return xfrd_packet_newlease;
		case xfrd_packet_tcp:
			return xfrd_packet_tcp;
		case xfrd_packet_bad:
		default:
			/* rollback */
			if(zone->msg_seq_nr > 0) {
				/* do not process xfr - if only one part simply ignore it. */
				/* rollback previous parts of commit */
				buffer_clear(packet);
				buffer_printf(packet, "xfrd: zone %s xfr rollback serial %d at time %d "
					"from %s of %d parts",
					zone->apex_str, (int)zone->msg_new_serial, (int)xfrd_time(), 
					zone->master->ip_address_spec, zone->msg_seq_nr);
				buffer_flip(packet);
				diff_write_commit(zone->apex_str, zone->msg_old_serial, zone->msg_new_serial,
					zone->query_id, zone->msg_seq_nr, 0, (char*)buffer_begin(packet),
					xfrd->nsd->options);
				log_msg(LOG_INFO, "xfrd: zone %s xfr reverted \"%s\"", zone->apex_str,
					(char*)buffer_begin(packet));
			}
			return xfrd_packet_bad;
	}

	/* dump reply on disk to diff file */
	diff_write_packet(zone->apex_str, zone->msg_new_serial, zone->query_id, zone->msg_seq_nr,
		buffer_begin(packet), buffer_limit(packet), xfrd->nsd->options);
	log_msg(LOG_INFO, "xfrd: zone %s written %d received XFR to serial %d from %s to disk (part %d)",
		zone->apex_str, (int)buffer_limit(packet), (int)zone->msg_new_serial, 
		zone->master->ip_address_spec, zone->msg_seq_nr);
	zone->msg_seq_nr++;
	if(res == xfrd_packet_more) {
		/* wait for more */
		return xfrd_packet_more;
	}

	/* done. we are completely sure of this */
	buffer_clear(packet);
	buffer_printf(packet, "xfrd: zone %s received update to serial %d at time %d from %s in %d parts",
		zone->apex_str, (int)zone->msg_new_serial, (int)xfrd_time(), 
		zone->master->ip_address_spec, zone->msg_seq_nr);
	buffer_flip(packet);
	diff_write_commit(zone->apex_str, zone->msg_old_serial, zone->msg_new_serial,
		zone->query_id, zone->msg_seq_nr, 1, (char*)buffer_begin(packet),
		xfrd->nsd->options);
	log_msg(LOG_INFO, "xfrd: zone %s committed \"%s\"", zone->apex_str,
		(char*)buffer_begin(packet));
	/* update the disk serial no. */
	zone->soa_disk_acquired = xfrd_time();
	zone->soa_disk = soa;
	if(zone->soa_notified_acquired && (
		zone->soa_notified.serial == 0 ||
		compare_serial(htonl(zone->soa_disk.serial), 
		htonl(zone->soa_notified.serial)) >= 0))
	{
		zone->soa_notified_acquired = 0;
	}
	if(!zone->soa_notified_acquired) {
		/* do not set expired zone to ok:
		 * it would cause nsd to start answering
		 * bad data, since the zone is not loaded yet.
		 * if nsd does not reload < retry time, more 
		 * queries (for even newer versions) are made.
		 * For expired zone after reload it is set ok (SOAINFO ipc). */
		if(zone->state != xfrd_zone_expired)
			xfrd_set_zone_state(zone, xfrd_zone_ok);
		log_msg(LOG_INFO, "xfrd: zone %s is waiting for reload", zone->apex_str);
		zone->round_num = -1; /* next try start anew */
		xfrd_set_timer_refresh(zone);
		xfrd_set_reload_timeout();
		return xfrd_packet_transfer;
	} else {
		/* try to get an even newer serial */
		/* pretend it was bad to continue queries */
		xfrd_set_reload_timeout();
		return xfrd_packet_bad;
	}
}

static void
xfrd_send_reload_req()
{
	sig_atomic_t req = NSD_RELOAD;
	/* ask server_main for a reload */
	if(write(xfrd->ipc_handler.fd, &req, sizeof(req)) == -1) {
		log_msg(LOG_ERR, "xfrd: problems sending reload command: %s",
			strerror(errno));
		return;
	}
	log_msg(LOG_ERR, "xfrd: asked nsd to reload new updates");
}

static void 
xfrd_set_reload_timeout()
{
	if(xfrd->nsd->options->xfrd_reload_timeout == -1)
		return; /* automatic reload disabled. */
	if(xfrd->reload_timeout.tv_sec == 0 ||
		xfrd_time() >= xfrd->reload_timeout.tv_sec ) {
		/* no reload wait period (or it passed), do it right away */
		xfrd_send_reload_req();
		/* start reload wait period */
		xfrd->reload_timeout.tv_sec = xfrd_time() +
			xfrd->nsd->options->xfrd_reload_timeout;
		xfrd->reload_timeout.tv_nsec = 0;
		return;
	}
	/* cannot reload now, set that after the timeout a reload has to happen */
	xfrd->reload_handler.timeout = &xfrd->reload_timeout;
}

static void 
xfrd_handle_reload(netio_type *ATTR_UNUSED(netio), 
	netio_handler_type *handler, netio_event_types_type event_types)
{
	/* reload timeout */
	assert(event_types & NETIO_EVENT_TIMEOUT);
	/* timeout wait period after this request is sent */
	handler->timeout = NULL;
	xfrd->reload_timeout.tv_sec = xfrd_time() +
		xfrd->nsd->options->xfrd_reload_timeout;
	xfrd_send_reload_req();
}

static void 
xfrd_handle_passed_packet(buffer_type* packet, int acl_num)
{
	uint8_t qnamebuf[MAXDOMAINLEN];
	uint16_t qtype, qclass;
	const dname_type* dname;
	region_type* tempregion = region_create(xalloc, free);
	xfrd_zone_t* zone;
	buffer_skip(packet, QHEADERSZ);
	if(!packet_read_query_section(packet, qnamebuf, &qtype, &qclass))
		return; /* drop bad packet */

	dname = dname_make(tempregion, qnamebuf, 1);
	log_msg(LOG_INFO, "xfrd: got passed packet for %s, acl %d", 
		dname_to_string(dname,0), acl_num);

	/* find the zone */
	zone = (xfrd_zone_t*)rbtree_search(xfrd->zones, dname);
	if(!zone) {
		log_msg(LOG_INFO, "xfrd: incoming packet for unknown zone %s", 
			dname_to_string(dname,0));
		region_destroy(tempregion);
		return; /* drop packet for unknown zone */
	}
	region_destroy(tempregion);

	/* handle */
	if(OPCODE(packet) == OPCODE_NOTIFY) {
		xfrd_soa_t soa;
		int have_soa = 0;
		int next;
		/* get serial from a SOA */
		if(ANCOUNT(packet) == 1 && packet_skip_dname(packet) &&
			xfrd_parse_soa_info(packet, &soa))
			have_soa = 1;
		if(xfrd_handle_incoming_notify(zone, have_soa?&soa:NULL))
			xfrd_set_refresh_now(zone);
		next = find_same_master_notify(zone, acl_num);
		if(next != -1) {
			zone->next_master = next;
			log_msg(LOG_INFO, "xfrd: notify set next master to query %d", next);
		}
	}
	else {
		/* TODO handle incoming IXFR udp reply via port 53 */
	}
}

static int 
xfrd_handle_incoming_notify(xfrd_zone_t* zone, xfrd_soa_t* soa)
{
	if(soa && zone->soa_disk_acquired && zone->state != xfrd_zone_expired
		&& compare_serial(ntohl(soa->serial), ntohl(zone->soa_disk.serial)) <= 0)
		return 0; /* ignore notify with old serial, we have a valid zone */
	if(soa == 0) {
		zone->soa_notified.serial = 0;
	}
	else if(zone->soa_notified_acquired == 0 || 
		zone->soa_notified.serial == 0 ||
		compare_serial(ntohl(soa->serial), ntohl(zone->soa_notified.serial)) > 0)
	{
		zone->soa_notified = *soa;
	}
	zone->soa_notified_acquired = xfrd_time();
	if(zone->state == xfrd_zone_ok) {
		xfrd_set_zone_state(zone, xfrd_zone_refreshing);
	}
	/* transfer right away */
	return 1;
}

static acl_options_t* 
acl_find_num(acl_options_t* acl, int num)
{
	int count = num;
	if(num < 0) 
		return 0;
	while(acl && count > 0) {
		acl = acl->next;
		count--;
	}
	if(count == 0) 
		return acl;
	return 0;
}

static int
find_same_master_notify(xfrd_zone_t* zone, int acl_num_nfy)
{
	acl_options_t* nfy_acl = acl_find_num(
		zone->zone_options->allow_notify, acl_num_nfy);
	int num = 0;
	acl_options_t* master = zone->zone_options->request_xfr;
	if(!nfy_acl) 
		return -1;
	while(master)
	{
		if(acl_same_host(nfy_acl, master))
			return num;
		master = master->next;
		num++;
	}
	return -1;
}
