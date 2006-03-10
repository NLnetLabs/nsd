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
#include "packet.h"

#define XFRDFILE "nsd.xfst"
#define DIFFFILE "nsd.diff"
#define XFRD_TRANSFER_TIMEOUT 10

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

/* handle zone timeout, event */
static void xfrd_handle_zone(netio_type *netio, 
	netio_handler_type *handler, netio_event_types_type event_types);
/* handle incoming soa information (NSD is running it, time acquired=guess) */
static void xfrd_handle_incoming_soa(xfrd_zone_t* zone, 
	xfrd_soa_t* soa, time_t acquired);

/* copy SOA info from rr to soa struct. Memleak if prim.ns or email changes in soa. */
static void xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr);
/* set refresh timer of zone to refresh at time now */
static void xfrd_set_refresh_now(xfrd_zone_t* zone, int zone_state);
/* set timer to specific value */
static void xfrd_set_timer(xfrd_zone_t* zone, time_t t);
/* get the current time epoch. Cached for speed. */
static time_t xfrd_time();
/* write soa in network format to the packet buffer */
static void xfrd_write_soa_buffer(xfrd_zone_t* zone, xfrd_soa_t* soa);

/* send notifications to all in the notify list */
static void xfrd_send_notify(xfrd_zone_t* zone);
/* send expiry notifications to nsd */
static void xfrd_send_expiry_notification(xfrd_zone_t* zone);
/* send ixfr request, returns fd of connection to read on */
static int xfrd_send_ixfr_request(xfrd_zone_t* zone);
/* send axfr request, returns fd of connection to read on */
static int xfrd_send_axfr_request(xfrd_zone_t* zone);

/* read state from disk */
static void xfrd_read_state();
/* write state to disk */
static void xfrd_write_state();

/* setup DNS packet for a query of this type */
static void xfrd_setup_packet(uint16_t type, uint16_t klass, 
	const dname_type* dname);
/* send packet via udp (using fd source socket) to acl addr. 0 on failure. */
static int xfrd_send_udp(int fd, acl_options_t* acl);
/* send packet via tcp (using fd) to acl addr */
static int xfrd_send_tcp(int fd, acl_options_t* acl);


void xfrd_init(int socket, struct nsd* nsd)
{
#ifndef NDEBUG
	assert(xfrd == 0);
#endif
	/* to setup signalhandling */
	nsd->server_kind = NSD_SERVER_BOTH;

	region_type* region = region_create(xalloc, free);
	xfrd = (xfrd_state_t*)region_alloc(region, sizeof(xfrd_state_t));
	memset(xfrd, 0, sizeof(xfrd_state_t));
	xfrd->region = region;
	xfrd->xfrd_start_time = time(0);
	xfrd->netio = netio_create(xfrd->region);
	xfrd->nsd = nsd;
	xfrd->packet = buffer_create(xfrd->region, QIOBUFSZ);

	xfrd->reload_time = 0;

	xfrd->ipc_handler.fd = socket;
	xfrd->ipc_handler.timeout = NULL;
	xfrd->ipc_handler.user_data = xfrd;
	xfrd->ipc_handler.event_types = NETIO_EVENT_READ;
	xfrd->ipc_handler.event_handler = xfrd_handle_ipc;
	netio_add_handler(xfrd->netio, &xfrd->ipc_handler);

	log_msg(LOG_INFO, "xfrd pre-startup");
	xfrd_init_zones();
	xfrd_free_namedb();
	xfrd_read_state();

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

static void xfrd_shutdown()
{
	log_msg(LOG_INFO, "xfrd shutdown");
	xfrd_write_state();
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

static void xfrd_init_zones()
{
	zone_type *dbzone;
	zone_options_t *zone_opt;
	xfrd_zone_t *xzone;
	const dname_type* dname;
#ifndef NDEBUG
	assert(xfrd->zones == 0);
	assert(xfrd->nsd->db != 0);
#endif
	xfrd->zones = rbtree_create(xfrd->region, 
		(int (*)(const void *, const void *)) dname_compare);
	
	for(zone_opt = xfrd->nsd->options->zone_options; 
		zone_opt; zone_opt=zone_opt->next)
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
		if(!dbzone)
			log_msg(LOG_INFO, "xfrd: adding empty zone %s\n", zone_opt->name);
		else log_msg(LOG_INFO, "xfrd: adding filled zone %s\n", zone_opt->name);
		
		xzone = (xfrd_zone_t*)region_alloc(xfrd->region,
			sizeof(xfrd_zone_t));
		memset(xzone, 0, sizeof(xfrd_zone_t));
		xzone->apex = dname;
		xzone->apex_str = zone_opt->name;
		xzone->zone_state = xfrd_zone_refreshing;
		xzone->zone_options = zone_opt;
		xzone->next_master = xzone->zone_options->request_xfr;
		xzone->next_master_num = 0;

		xzone->soa_nsd_acquired = 0;
		xzone->soa_disk_acquired = 0;
		xzone->soa_notified_acquired = 0;

		xzone->zone_handler.fd = -1;
		xzone->zone_handler.timeout = 0;
		xzone->zone_handler.user_data = xzone;
		xzone->zone_handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
		xzone->zone_handler.event_handler = xfrd_handle_zone;
		netio_add_handler(xfrd->netio, &xzone->zone_handler);
		
		if(dbzone && dbzone->soa_rrset && dbzone->soa_rrset->rrs) {
			xzone->soa_nsd_acquired = xfrd_time();
			xzone->soa_disk_acquired = xfrd_time();
			/* we only use the first SOA in the rrset */
			xfrd_copy_soa(&xzone->soa_nsd, dbzone->soa_rrset->rrs);
			xfrd_copy_soa(&xzone->soa_disk, dbzone->soa_rrset->rrs);
			/* set refreshing anyway, we have data but it may be old */
		}
		xfrd_set_refresh_now(xzone, xfrd_zone_refreshing);

		xzone->node.key = dname;
		rbtree_insert(xfrd->zones, (rbnode_t*)xzone);
	}
	log_msg(LOG_INFO, "xfrd: started server %d secondary zones", (int)xfrd->zones->count);
}

static void xfrd_free_namedb()
{
	namedb_close(xfrd->nsd->db);
	xfrd->nsd->db = 0;
}

static void xfrd_handle_zone(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, netio_event_types_type event_types)
{
	xfrd_zone_t* zone = (xfrd_zone_t*)handler->user_data;
	if(event_types & NETIO_EVENT_READ) {
		ssize_t received;

		/* received data */
		log_msg(LOG_INFO, "Got zone %s handler - read data", zone->apex_str);
		xfrd_set_timer(zone, xfrd_time() + 
			XFRD_TRANSFER_TIMEOUT + random()%XFRD_TRANSFER_TIMEOUT);
		/* read and handle the data */
		buffer_clear(xfrd->packet);
		uint16_t size = 0;
		if(recv(handler->fd, &size, sizeof(size), 0) == -1) return;
		size = ntohs(size);
		received = size;
		if(recv(handler->fd, buffer_begin(xfrd->packet), size, 0) == -1) return;
		/* received = recvfrom(handler->fd, 
			buffer_begin(xfrd->packet), buffer_remaining(xfrd->packet),
			0, NULL, NULL); */
		if(received == -1) {
			log_msg(LOG_ERR, "xfrd: recvfrom failed: %s",
				strerror(errno));
			close(handler->fd);
			handler->fd = -1;
			return;
		}
		buffer_set_limit(xfrd->packet, received);
		if(RCODE(xfrd->packet) != RCODE_OK) {
			log_msg(LOG_INFO, "xfrd: received error code %d for zone %s.",
				RCODE(xfrd->packet), zone->apex_str);
			close(handler->fd);
			handler->fd = -1;
			return;
		}
		/* dump reply on disk to diff file */
		diff_write_packet(buffer_begin(xfrd->packet), received, 
			xfrd->nsd->options);
		log_msg(LOG_INFO, "xfrd: written %zd received XFR for zone %s to disk",
			received, zone->apex_str);
		return;
	}
	/* timeout */
	log_msg(LOG_INFO, "Got zone %s timeout", zone->apex_str);
	if(handler->fd != -1) {
		close(handler->fd);
		handler->fd = -1;
	}
	if(zone->soa_disk_acquired == 0) {
		/* request axfr */
		handler->fd = xfrd_send_axfr_request(zone);
		xfrd_set_timer(zone, xfrd_time() + 
			XFRD_TRANSFER_TIMEOUT + random()%XFRD_TRANSFER_TIMEOUT);
	} else {
		/* request ixfr */
		handler->fd = xfrd_send_ixfr_request(zone);

		if(zone->soa_disk_acquired + ntohl(zone->soa_disk.expire)
			> (uint32_t)xfrd_time()) {
			/* zone expired */
			zone->zone_state = xfrd_zone_expired;
			xfrd_send_expiry_notification(zone);
		}

		if(zone->zone_state == xfrd_zone_expired ||
		   xfrd_time() + ntohl(zone->soa_disk.retry) <
		   zone->soa_disk_acquired + ntohl(zone->soa_disk.expire))
			xfrd_set_timer(zone, xfrd_time() + ntohl(zone->soa_disk.retry));
		else xfrd_set_timer(zone, zone->soa_disk_acquired + ntohl(zone->soa_disk.expire));

	}

	/* use different master next time */
	if(zone->next_master && zone->next_master->next) {
		zone->next_master = zone->next_master->next;
		zone->next_master_num++;
	} else {
		zone->next_master = zone->zone_options->request_xfr;
		zone->next_master_num = 0;
	}
}

static time_t xfrd_time()
{
	if(!xfrd->got_time) {
		xfrd->current_time = time(0);
		xfrd->got_time = 1;
	}
	return xfrd->current_time;
}

static void xfrd_copy_soa(xfrd_soa_t* soa, rr_type* rr)
{
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
	if(soa->prim_ns==0 || dname_compare(soa->prim_ns, 
		domain_dname(rdata_atom_domain(rr->rdatas[0])))!=0) {
		soa->prim_ns = dname_copy(xfrd->region, 
			domain_dname(rdata_atom_domain(rr->rdatas[0])));
	}
	if(soa->email==0 || dname_compare(soa->email, 
		domain_dname(rdata_atom_domain(rr->rdatas[1])))!=0) {
		soa->email = dname_copy(xfrd->region, 
			domain_dname(rdata_atom_domain(rr->rdatas[1])));
	}
	/* already in network format */
	soa->serial = *(uint32_t*)rdata_atom_data(rr->rdatas[2]);
	soa->refresh = *(uint32_t*)rdata_atom_data(rr->rdatas[3]);
	soa->retry = *(uint32_t*)rdata_atom_data(rr->rdatas[4]);
	soa->expire = *(uint32_t*)rdata_atom_data(rr->rdatas[5]);
	soa->minimum = *(uint32_t*)rdata_atom_data(rr->rdatas[6]);
}

static void xfrd_set_refresh_now(xfrd_zone_t* zone, int zone_state) 
{
	zone->zone_state = zone_state;
	zone->zone_handler.fd = -1;
	zone->zone_handler.timeout = &zone->timeout;
	zone->timeout.tv_sec = xfrd_time();
	zone->timeout.tv_nsec = 0;
}

static void xfrd_set_timer(xfrd_zone_t* zone, time_t t)
{
	zone->zone_handler.timeout = &zone->timeout;
	zone->timeout.tv_sec = t;
	zone->timeout.tv_nsec = 0;
}

/* quick tokenizer, reads words separated by whitespace.
   No quoted strings. Comments are skipped (#... eol). */
static char* xfrd_read_token(FILE* in)
{
	static char buf[4000];
	while(1) {
		if(fscanf(in, " %3990s", buf) != 1) return 0;
		if(buf[0] != '#') return buf;
		if(!fgets(buf, sizeof(buf), in)) return 0;
	}
}

static int xfrd_read_i16(FILE *in, uint16_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atoi(p);
	return 1;
}

static int xfrd_read_i32(FILE *in, uint32_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atoi(p);
	return 1;
}

static int xfrd_read_time_t(FILE *in, time_t* v)
{
	char* p = xfrd_read_token(in);
	if(!p) return 0;
	*v=atol(p);
	return 1;
}

static int xfrd_read_check_str(FILE* in, const char* str)
{
	char *p = xfrd_read_token(in);
	if(!p) return 0;
	if(strcmp(p, str) != 0) return 0;
	return 1;
}

static int xfrd_read_state_soa(FILE* in, const char* id_acquired,
	const char* id, xfrd_soa_t* soa, time_t* soatime, 
	region_type* region)
{
	char *p;

	if(!xfrd_read_check_str(in, id_acquired) ||
	   !xfrd_read_time_t(in, soatime) 
	) return 0;
	if(*soatime == 0) return 1;
	if(!xfrd_read_check_str(in, id) ||
	   !xfrd_read_i16(in, &soa->type) ||
	   !xfrd_read_i16(in, &soa->klass) ||
	   !xfrd_read_i32(in, &soa->ttl) ||
	   !xfrd_read_i16(in, &soa->rdata_count)
	) return 0;
	soa->type = htons(soa->type);
	soa->klass = htons(soa->klass);
	soa->ttl = htonl(soa->ttl);
	soa->rdata_count = htons(soa->rdata_count);

	if(!(p=xfrd_read_token(in))) return 0;
	soa->prim_ns = dname_parse(region, p);
	if(!soa->prim_ns) return 0;

	if(!(p=xfrd_read_token(in))) return 0;
	soa->email = dname_parse(region, p);
	if(!soa->email) return 0;

	if(!xfrd_read_i32(in, &soa->serial) ||
	   !xfrd_read_i32(in, &soa->refresh) ||
	   !xfrd_read_i32(in, &soa->retry) ||
	   !xfrd_read_i32(in, &soa->expire) ||
	   !xfrd_read_i32(in, &soa->minimum)
	) return 0;
	soa->serial = htonl(soa->serial);
	soa->refresh = htonl(soa->refresh);
	soa->retry = htonl(soa->retry);
	soa->expire = htonl(soa->expire);
	soa->minimum = htonl(soa->minimum);
	return 1;
}

static void xfrd_read_state()
{
	const char* statefile = xfrd->nsd->options->xfrdfile;
	FILE *in;
	uint32_t filetime = 0;
	uint32_t numzones, i;
	region_type *tempregion;
	if(!statefile) statefile = XFRDFILE;

	tempregion = region_create(xalloc, free);
	if(!tempregion) return;

	in = fopen(statefile, "r");
	if(!in) {
		if(errno != ENOENT) {
			log_msg(LOG_ERR, "xfrd: Could not open file %s for reading: %s",
				statefile, strerror(errno));
		}
		else log_msg(LOG_INFO, "xfrd: no file %s. refreshing all zones.",
			statefile);
		return;
	}
	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC) ||
	   !xfrd_read_check_str(in, "filetime:") ||
	   !xfrd_read_i32(in, &filetime) ||
	   (time_t)filetime > xfrd_time()+15 ||
	   !xfrd_read_check_str(in, "numzones:") ||
	   !xfrd_read_i32(in, &numzones)
	  ) 
	{
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		fclose(in);
		return;
	}
	for(i=0; i<numzones; i++)
	{
		char *p;
		xfrd_zone_t* zone;
		const dname_type* dname;
		uint32_t state, nextmas, timeout;
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
		   !(dname = dname_parse(tempregion, p))
		)
		{
			log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
				statefile, (int)filetime, (int)xfrd_time());
			fclose(in);
			return;
		}
		zone = (xfrd_zone_t*)rbtree_search(xfrd->zones, dname);

		if(!xfrd_read_check_str(in, "state:") ||
		   !xfrd_read_i32(in, &state) || (state>2) ||
		   !xfrd_read_check_str(in, "next_master:") ||
		   !xfrd_read_i32(in, &nextmas) ||
		   !xfrd_read_check_str(in, "next_timeout:") ||
		   !xfrd_read_i32(in, &timeout) ||
		   !xfrd_read_state_soa(in, "soa_nsd_acquired:", "soa_nsd:",
			&soa_nsd_read, &soa_nsd_acquired_read, tempregion) ||
		   !xfrd_read_state_soa(in, "soa_disk_acquired:", "soa_disk:",
			&soa_disk_read, &soa_disk_acquired_read, tempregion) ||
		   !xfrd_read_state_soa(in, "soa_notify_acquired:", "soa_notify:",
			&soa_notified_read, &soa_notified_acquired_read, tempregion)
		)
		{
			log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
				statefile, (int)filetime, (int)xfrd_time());
			fclose(in);
			return;
		}

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
		zone->zone_state = state;
		zone->next_master_num = nextmas;
		zone->timeout.tv_sec = timeout;
		zone->timeout.tv_nsec = 0;

		/* read the zone OK, now set the master properly */
		zone->next_master = zone->zone_options->request_xfr;
		while(zone->next_master && nextmas>0) {
			nextmas --;
			zone->next_master = zone->next_master->next;
		}
		if(nextmas!=0 || !zone->next_master) {
			log_msg(LOG_INFO, "xfrd: masters changed for zone %s", p);
			zone->next_master = zone->zone_options->request_xfr;
		}

		if(timeout == 0 ||
			timeout - soa_disk_acquired_read > ntohl(soa_disk_read.refresh) 
			|| soa_notified_acquired_read != 0) 
			xfrd_set_refresh_now(zone, xfrd_zone_refreshing);

		if(soa_disk_acquired_read!=0 &&
			(uint32_t)xfrd_time() - soa_disk_acquired_read > ntohl(soa_disk_read.expire))
		{
			xfrd_set_refresh_now(zone, xfrd_zone_expired);
		}

		/* handle as an incoming SOA. */
		incoming_soa = zone->soa_nsd;
		incoming_acquired = zone->soa_nsd_acquired;
		zone->soa_nsd = soa_nsd_read;
		zone->soa_disk = soa_disk_read;
		zone->soa_notified = soa_notified_read;
		if(soa_nsd_read.prim_ns)
			zone->soa_nsd.prim_ns = dname_copy(xfrd->region, soa_nsd_read.prim_ns);
		if(soa_nsd_read.email)
			zone->soa_nsd.email = dname_copy(xfrd->region, soa_nsd_read.email);
		if(soa_disk_read.prim_ns)
			zone->soa_disk.prim_ns = dname_copy(xfrd->region, soa_disk_read.prim_ns);
		if(soa_disk_read.email)
			zone->soa_disk.email = dname_copy(xfrd->region, soa_disk_read.email);
		if(soa_notified_read.prim_ns)
			zone->soa_notified.prim_ns = dname_copy(xfrd->region, soa_notified_read.prim_ns);
		if(soa_notified_read.email)
			zone->soa_notified.email = dname_copy(xfrd->region, soa_notified_read.email);
		zone->soa_nsd_acquired = soa_nsd_acquired_read;
		zone->soa_disk_acquired = soa_disk_acquired_read;
		zone->soa_notified_acquired = soa_notified_acquired_read;
		if(incoming_acquired != 0)
			xfrd_handle_incoming_soa(zone, &incoming_soa, incoming_acquired);
		xfrd_send_expiry_notification(zone);
	}

	if(!xfrd_read_check_str(in, XFRD_FILE_MAGIC)) {
		log_msg(LOG_ERR, "xfrd: corrupt state file %s dated %d (now=%d)", 
			statefile, (int)filetime, (int)xfrd_time());
		fclose(in);
		return;
	}
	
	log_msg(LOG_INFO, "xfrd: read %d zones from state file", numzones);
	fclose(in);
	region_destroy(tempregion);
}

/* prints neato days hours and minutes. */
static void neato_timeout(FILE* out, const char* str, uint32_t secs)
{
	fprintf(out, "%s", str);
	if(secs <= 0) {
		fprintf(out, " %ds\n", secs);
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

static void xfrd_write_state_soa(FILE* out, const char* id,
	xfrd_soa_t* soa, time_t soatime, const dname_type* apex)
{
	fprintf(out, "\t%s_acquired: %d\n", id, (int)soatime);
	if(!soatime) return;
	fprintf(out, "\t%s: %d %d %d %d", id, 
		ntohs(soa->type), ntohs(soa->klass), 
		ntohl(soa->ttl), ntohs(soa->rdata_count));
	fprintf(out, " %s", dname_to_string(soa->prim_ns, apex));
	fprintf(out, " %s", dname_to_string(soa->email, apex));
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
	if(!statefile) statefile = XFRDFILE;

	log_msg(LOG_INFO, "xfrd: write file %s", statefile);
	out = fopen(statefile, "w");
	if(!out) {
		log_msg(LOG_ERR, "xfrd: Could not open file %s for writing: %s",
				statefile, strerror(errno));
		return;
	}
	
	fprintf(out, "%s\n", XFRD_FILE_MAGIC);
	fprintf(out, "filetime: %d\n", (int)xfrd_time());
	fprintf(out, "numzones: %zd\n", xfrd->zones->count);
	fprintf(out, "\n");
	for(p = rbtree_first(xfrd->zones); p && p!=RBTREE_NULL; p=rbtree_next(p))
	{
		xfrd_zone_t* zone = (xfrd_zone_t*)p;
		fprintf(out, "zone: \tname: %s\n", zone->apex_str);
		fprintf(out, "\tstate: %d", zone->zone_state);
		fprintf(out, " # %s", zone->zone_state==xfrd_zone_ok?"OK":(
			zone->zone_state==xfrd_zone_refreshing?"refreshing":"expired"));
		fprintf(out, "\n");
		fprintf(out, "\tnext_master: %d\n", zone->next_master_num);
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
	log_msg(LOG_INFO, "xfrd: written %zd zones from state file", xfrd->zones->count);
	fclose(out);
}

static void xfrd_handle_incoming_soa(xfrd_zone_t* zone, 
	xfrd_soa_t* soa, time_t acquired)
{
	if(soa->serial == zone->soa_nsd.serial)
	{
		return;
	}
	if(soa->serial == zone->soa_disk.serial)
	{
		/* soa in disk has been loaded in memory */
		log_msg(LOG_INFO, "Zone %s serial %d is updated to %d.",
			zone->apex_str, ntohl(zone->soa_nsd.serial),
			ntohl(soa->serial));
		zone->soa_nsd = zone->soa_disk;
		zone->soa_nsd_acquired = zone->soa_disk_acquired;
		xfrd_send_notify(zone);
		if((uint32_t)xfrd_time() - zone->soa_disk_acquired 
			< ntohl(zone->soa_disk.refresh))
		{
			/* zone ok, wait for refresh time */
			zone->zone_state = xfrd_zone_ok;
			xfrd_set_timer(zone, 
				zone->soa_disk_acquired + ntohl(zone->soa_disk.refresh));
		}
		else if((uint32_t)xfrd_time() - zone->soa_disk_acquired 
			< ntohl(zone->soa_disk.expire))
		{
			/* zone refreshing */
			xfrd_set_refresh_now(zone, xfrd_zone_refreshing);
		}
		else 
		{
			/* zone expired */
			xfrd_set_refresh_now(zone, xfrd_zone_expired);
		}
		xfrd_send_expiry_notification(zone);

		if(zone->soa_notified_acquired != 0 &&
		   compare_serial(ntohl(zone->soa_disk.serial),
			ntohl(zone->soa_notified.serial)) > 1 )
		{	/* read was in response to this notification */
			zone->soa_notified_acquired = 0;
		}
		return;
	}

	/* user must have manually provided zone data */
	log_msg(LOG_INFO, "xfrd: zone %s serial %d from unknown source. refreshing", 
		zone->apex_str, ntohl(soa->serial));
	zone->soa_nsd = *soa;
	zone->soa_disk = *soa;
	zone->soa_nsd_acquired = acquired;
	zone->soa_disk_acquired = acquired;
	zone->soa_notified_acquired = 0;
	xfrd_set_refresh_now(zone, xfrd_zone_refreshing);
}

static void xfrd_send_notify(xfrd_zone_t* zone)
{
	log_msg(LOG_INFO, "TODO: xfrd sending notifications for zone %s.",
		zone->apex_str);
}

static void xfrd_send_expiry_notification(xfrd_zone_t* zone)
{
	log_msg(LOG_INFO, "TODO: xfrd sending expiry to nsd for zone %s.",
		zone->apex_str);
}

static void xfrd_setup_packet(uint16_t type, uint16_t klass, 
	const dname_type* dname)
{	
	/* Set up the header */
	buffer_clear(xfrd->packet);
	ID_SET(xfrd->packet, (uint16_t) random());
        FLAGS_SET(xfrd->packet, 0);
        OPCODE_SET(xfrd->packet, OPCODE_QUERY);
        AA_SET(xfrd->packet);
        QDCOUNT_SET(xfrd->packet, 1);
        ANCOUNT_SET(xfrd->packet, 0);
        NSCOUNT_SET(xfrd->packet, 0);
        ARCOUNT_SET(xfrd->packet, 0);
        buffer_skip(xfrd->packet, QHEADERSZ);

	/* The question record. */
        buffer_write(xfrd->packet, dname_name(dname), dname->name_size);
        buffer_write_u16(xfrd->packet, type);
        buffer_write_u16(xfrd->packet, klass);
}

static int xfrd_send_udp(int fd, acl_options_t* acl)
{
	unsigned int port = acl->port?acl->port:(unsigned)atoi(UDP_PORT);
	struct sockaddr_storage to;

	/* setup address structure */
	memset(&to, 0, sizeof(struct sockaddr_storage));
	if(acl->is_ipv6)
	{
#ifdef INET6
		struct sockaddr_in6* sa = (struct sockaddr_in6*)&to;
		sa->sin6_family = AF_INET6;
		sa->sin6_port = htons(port);
		sa->sin6_addr = acl->addr.addr6;
#else
		return 0;
#endif
	} else
	{
		struct sockaddr_in* sa = (struct sockaddr_in*)&to;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(port);
		sa->sin_addr = acl->addr.addr;
	}

	/* send it (udp) */
	if(sendto(fd,
		buffer_current(xfrd->packet),
		buffer_remaining(xfrd->packet), 0,
		(struct sockaddr*)&to, sizeof(to)) == -1)
	{
		log_msg(LOG_ERR, "xfrd: sendto %s failed %s",
			acl->ip_address_spec, strerror(errno));
		return 0;
	}
	return 1;
}

static int xfrd_send_tcp(int fd, acl_options_t* acl)
{
	unsigned int port = acl->port?acl->port:(unsigned)atoi(TCP_PORT);
	struct sockaddr_storage to;

	/* setup address structure */
	memset(&to, 0, sizeof(struct sockaddr_storage));
	if(acl->is_ipv6)
	{
#ifdef INET6
		struct sockaddr_in6* sa = (struct sockaddr_in6*)&to;
		sa->sin6_family = AF_INET6;
		sa->sin6_port = htons(port);
		sa->sin6_addr = acl->addr.addr6;
#else
		return 0;
#endif
	} else
	{
		struct sockaddr_in* sa = (struct sockaddr_in*)&to;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(port);
		sa->sin_addr = acl->addr.addr;
	}
	log_msg(LOG_ERR, "xfrd: port %d", port);

	/* send it (tcp */
	if(connect(fd, (struct sockaddr*)&to, sizeof(struct sockaddr_storage)) == -1)
	{
		log_msg(LOG_ERR, "xfrd: connect %s failed %s",
			acl->ip_address_spec, strerror(errno));
		return 0;
	}
	
	/* TODO - write in pieces if needed */
	uint16_t size = htons(buffer_remaining(xfrd->packet));
	if(write(fd, &size, sizeof(size)) == -1 ||
		write(fd,
		buffer_current(xfrd->packet),
		buffer_remaining(xfrd->packet)) == -1)
	{
		log_msg(LOG_ERR, "xfrd: write %s failed %s",
			acl->ip_address_spec, strerror(errno));
		return 0;
	}
	return 1;
}

static void xfrd_write_soa_buffer(xfrd_zone_t* zone, xfrd_soa_t* soa)
{
	buffer_write(xfrd->packet, dname_name(zone->apex), zone->apex->name_size);

	/* already in network order */
	buffer_write(xfrd->packet, &soa->type, sizeof(soa->type));
	buffer_write(xfrd->packet, &soa->klass, sizeof(soa->klass));
	buffer_write(xfrd->packet, &soa->ttl, sizeof(soa->ttl));
	buffer_write(xfrd->packet, &soa->rdata_count, sizeof(soa->rdata_count));

	/* uncompressed dnames */
	if(soa->prim_ns)
		buffer_write(xfrd->packet, dname_name(soa->prim_ns), soa->prim_ns->name_size);
	else buffer_write_u8(xfrd->packet, 0);
	if(soa->email)
		buffer_write(xfrd->packet, dname_name(soa->email), soa->email->name_size);
	else buffer_write_u8(xfrd->packet, 0);

	buffer_write(xfrd->packet, &soa->serial, sizeof(uint32_t));
	buffer_write(xfrd->packet, &soa->refresh, sizeof(uint32_t));
	buffer_write(xfrd->packet, &soa->retry, sizeof(uint32_t));
	buffer_write(xfrd->packet, &soa->expire, sizeof(uint32_t));
	buffer_write(xfrd->packet, &soa->minimum, sizeof(uint32_t));
}

static int xfrd_send_ixfr_request(xfrd_zone_t* zone)
{
	int fd;
	int family;

	if(!zone->next_master) return -1;
	xfrd_setup_packet(TYPE_IXFR, CLASS_IN, zone->apex);
        NSCOUNT_SET(xfrd->packet, 1);
	xfrd_write_soa_buffer(zone, &zone->soa_disk);
	buffer_flip(xfrd->packet);

	if(zone->next_master->is_ipv6) {
#ifdef INET6
		family = PF_INET6;
#else
		return -1;
#endif
	} else family = PF_INET;
	fd = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if(fd == -1) return -1;
	if(!xfrd_send_udp(fd, zone->next_master)) return -1;
	log_msg(LOG_INFO, "xfrd sent udp request for ixfr=%d for zone %s to %s", 
		ntohl(zone->soa_disk.serial),
		zone->apex_str, zone->next_master->ip_address_spec);
	return fd;
}

static int xfrd_send_axfr_request(xfrd_zone_t* zone)
{	
	int fd;
	int family;

	if(!zone->next_master) return -1;
	xfrd_setup_packet(TYPE_AXFR, CLASS_IN, zone->apex);
	buffer_flip(xfrd->packet);

	if(zone->next_master->is_ipv6) {
#ifdef INET6
		family = PF_INET6;
#else
		return -1;
#endif
	} else family = PF_INET;
	fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1) {
		log_msg(LOG_ERR, "xfrd: socket failed %s", strerror(errno));
		return -1;
	}
	if(!xfrd_send_tcp(fd, zone->next_master)) return -1;
	log_msg(LOG_INFO, "xfrd sent tcp request for axfr for zone %s to %s", 
		zone->apex_str, zone->next_master->ip_address_spec);
	return fd;
}

void diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	uint32_t val;
	if(opt->difffile) filename = opt->difffile;

	df = fopen(filename, "a");
	if(!df) {
		log_msg(LOG_ERR, "could not open file %s for append: %s",
			filename, strerror(errno));
		return;
	}

	write_data(df, "IXFR", sizeof(uint32_t));
	val = htonl(len);
	write_data(df, &val, sizeof(val));
	write_data(df, data, len);
	write_data(df, &val, sizeof(val));
	
	fclose(df);
}
