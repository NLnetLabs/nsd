/*
 * xfrd-tcp.c - XFR (transfer) Daemon TCP system source file. Manages tcp conn.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include "xfrd-tcp.h"
#include "buffer.h"
#include "packet.h"
#include "dname.h"
#include "options.h"
#include "namedb.h"
#include "xfrd.h"
#include "util.h"

xfrd_tcp_set_t* xfrd_tcp_set_create(struct region* region)
{
	int i;
	xfrd_tcp_set_t* tcp_set = region_alloc(region, sizeof(xfrd_tcp_set_t));
	memset(tcp_set, 0, sizeof(xfrd_tcp_set_t));
	tcp_set->tcp_count = 0;
	tcp_set->tcp_waiting_first = 0;
	tcp_set->tcp_waiting_last = 0;
	for(i=0; i<XFRD_MAX_TCP; i++)
		tcp_set->tcp_state[i] = xfrd_tcp_create(region);
	return tcp_set;
}

void 
xfrd_setup_packet(buffer_type* packet,
	uint16_t type, uint16_t klass, const dname_type* dname)
{	
	/* Set up the header */
	buffer_clear(packet);
	ID_SET(packet, (uint16_t) random());
        FLAGS_SET(packet, 0);
        OPCODE_SET(packet, OPCODE_QUERY);
        QDCOUNT_SET(packet, 1);
        ANCOUNT_SET(packet, 0);
        NSCOUNT_SET(packet, 0);
        ARCOUNT_SET(packet, 0);
        buffer_skip(packet, QHEADERSZ);

	/* The question record. */
        buffer_write(packet, dname_name(dname), dname->name_size);
        buffer_write_u16(packet, type);
        buffer_write_u16(packet, klass);
}

void 
xfrd_acl_sockaddr(acl_options_t* acl, struct sockaddr_storage *to)
{
	unsigned int port = acl->port?acl->port:(unsigned)atoi(TCP_PORT);

	/* setup address structure */
	memset(to, 0, sizeof(struct sockaddr_storage));
	if(acl->is_ipv6) {
#ifdef INET6
		struct sockaddr_in6* sa = (struct sockaddr_in6*)to;
		sa->sin6_family = AF_INET6;
		sa->sin6_port = htons(port);
		sa->sin6_addr = acl->addr.addr6;
#else
		log_msg(LOG_ERR, "xfrd: IPv6 connection to %s attempted but no INET6.",
			acl->ip_address_spec);
		return;
#endif
	} else {
		struct sockaddr_in* sa = (struct sockaddr_in*)to;
		sa->sin_family = AF_INET;
		sa->sin_port = htons(port);
		sa->sin_addr = acl->addr.addr;
	}
}

void 
xfrd_write_soa_buffer(struct buffer* packet,
	struct xfrd_zone* zone, struct xfrd_soa* soa)
{
	size_t rdlength_pos;
	uint16_t rdlength;
	buffer_write(packet, dname_name(zone->apex), zone->apex->name_size);

	/* already in network order */
	buffer_write(packet, &soa->type, sizeof(soa->type));
	buffer_write(packet, &soa->klass, sizeof(soa->klass));
	buffer_write(packet, &soa->ttl, sizeof(soa->ttl));
	rdlength_pos = buffer_position(packet);
	buffer_skip(packet, sizeof(rdlength));

	/* uncompressed dnames */
	/* TODO: compress the dnames here */
	buffer_write(packet, soa->prim_ns+1, soa->prim_ns[0]);
	buffer_write(packet, soa->email+1, soa->email[0]);

	buffer_write(packet, &soa->serial, sizeof(uint32_t));
	buffer_write(packet, &soa->refresh, sizeof(uint32_t));
	buffer_write(packet, &soa->retry, sizeof(uint32_t));
	buffer_write(packet, &soa->expire, sizeof(uint32_t));
	buffer_write(packet, &soa->minimum, sizeof(uint32_t));

	/* write length of RR */
	rdlength = buffer_position(packet) - rdlength_pos - sizeof(rdlength);
	buffer_write_u16_at(packet, rdlength_pos, rdlength);
}

xfrd_tcp_t* 
xfrd_tcp_create(region_type* region)
{
	xfrd_tcp_t* tcp_state = (xfrd_tcp_t*)region_alloc(
		region, sizeof(xfrd_tcp_t));
	memset(tcp_state, 0, sizeof(xfrd_tcp_t));
	tcp_state->packet = buffer_create(region, QIOBUFSZ);
	tcp_state->fd = -1;

	return tcp_state;
}

void 
xfrd_tcp_obtain(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	assert(zone->tcp_conn == -1);
	assert(zone->tcp_waiting == 0);

	if(set->tcp_count < XFRD_MAX_TCP) {
		int i;
		assert(!set->tcp_waiting_first);
		set->tcp_count ++;
		/* find a free tcp_buffer */
		for(i=0; i<XFRD_MAX_TCP; i++) {
			if(set->tcp_state[i]->fd == -1) {
				zone->tcp_conn = i;
				break;
			}
		}

		assert(zone->tcp_conn != -1);

		zone->tcp_waiting = 0;

		if(!xfrd_tcp_open(set, zone)) 
			return;

		xfrd_tcp_xfr(set, zone);
		return;
	}
	/* wait, at end of line */
	zone->tcp_waiting_next = 0;
	zone->tcp_waiting = 1;
	if(!set->tcp_waiting_last) {
		set->tcp_waiting_first = zone;
		set->tcp_waiting_last = zone;
	} else {
		set->tcp_waiting_last->tcp_waiting_next = zone;
		set->tcp_waiting_last = zone;
	}
}

int 
xfrd_tcp_open(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	/* TODO use port 53 */
	int fd;
	int family;
	struct sockaddr_storage to;

	assert(zone->tcp_conn != -1);
	log_msg(LOG_INFO, "xfrd: zone %s open tcp conn to %s",
		zone->apex_str, zone->master->ip_address_spec);
	set->tcp_state[zone->tcp_conn]->is_reading = 0;
	set->tcp_state[zone->tcp_conn]->total_bytes = 0;
	set->tcp_state[zone->tcp_conn]->msglen = 0;

	if(zone->master->is_ipv6) {
#ifdef INET6
		family = PF_INET6;
#else
		xfrd_tcp_release(set, zone);
		return 0;
#endif
	} else { 
		family = PF_INET;
	}
	fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1) {
		log_msg(LOG_ERR, "xfrd: %s cannot create tcp socket: %s", 
			zone->master->ip_address_spec, strerror(errno));
		xfrd_tcp_release(set, zone);
		return 0;
	}

	xfrd_acl_sockaddr(zone->master, &to);
	if(connect(fd, (struct sockaddr*)&to, sizeof(struct sockaddr_storage)) == -1)
	{
		log_msg(LOG_ERR, "xfrd: connect %s failed %s",
			zone->master->ip_address_spec, strerror(errno));
		xfrd_tcp_release(set, zone);
		return 0;
	}
	if(fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		log_msg(LOG_ERR, "xfrd: fcntl failed: %s", strerror(errno));
		xfrd_tcp_release(set, zone);
		return 0;
	}

	zone->zone_handler.fd = fd;
	set->tcp_state[zone->tcp_conn]->fd = fd;
	zone->zone_handler.event_types = NETIO_EVENT_TIMEOUT|NETIO_EVENT_WRITE;
	xfrd_set_timer(zone, xfrd_time() + XFRD_TCP_TIMEOUT);
	return 1;
}

void 
xfrd_tcp_xfr(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	xfrd_tcp_t* tcp = set->tcp_state[zone->tcp_conn];
	assert(zone->tcp_conn != -1);
	assert(zone->tcp_waiting == 0);
	/* start AXFR or IXFR for the zone */
	if(zone->soa_disk_acquired == 0) {
		xfrd_setup_packet(tcp->packet, TYPE_AXFR, CLASS_IN, zone->apex);
		buffer_flip(tcp->packet);
	} else {
		xfrd_setup_packet(tcp->packet, TYPE_IXFR, CLASS_IN, zone->apex);
        	NSCOUNT_SET(tcp->packet, 1);
		xfrd_write_soa_buffer(tcp->packet, zone, &zone->soa_disk);
		buffer_flip(tcp->packet);
	}
	zone->query_id = ID(tcp->packet);
	log_msg(LOG_INFO, "sent tcp query with ID %d", zone->query_id);
	tcp->msglen = buffer_limit(tcp->packet);
	xfrd_tcp_write(set, zone);
}

void 
xfrd_tcp_write(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	xfrd_tcp_t* tcp = set->tcp_state[zone->tcp_conn];
	ssize_t sent;

	assert(zone->tcp_conn != -1);
	if(tcp->total_bytes < sizeof(tcp->msglen)) {
		uint16_t sendlen = htons(tcp->msglen);
		sent = write(tcp->fd, 
			(const char*)&sendlen + tcp->total_bytes,
			sizeof(tcp->msglen) - tcp->total_bytes);

		if(sent == -1) {
			if(errno == EAGAIN || errno == EINTR) {
				/* write would block, try later */
				return;
			} else {
				log_msg(LOG_ERR, "xfrd: failed writing tcp %s",
					strerror(errno));
				xfrd_tcp_release(set, zone);
				return;
			}
		}

		tcp->total_bytes += sent;
		if(tcp->total_bytes < sizeof(tcp->msglen)) {
			/* incomplete write, resume later */
			return;
		}
		assert(tcp->total_bytes == sizeof(tcp->msglen));
	}

	assert(tcp->total_bytes < tcp->msglen + sizeof(tcp->msglen));
	
	sent = write(tcp->fd,
		buffer_current(tcp->packet),
		buffer_remaining(tcp->packet));
	if(sent == -1) {
		if(errno == EAGAIN || errno == EINTR) {
			/* write would block, try later */
			return;
		} else {
			log_msg(LOG_ERR, "xfrd: failed writing tcp %s",
				strerror(errno));
			xfrd_tcp_release(set, zone);
			return;
		}
	}
	
	buffer_skip(tcp->packet, sent);
	tcp->total_bytes += sent;

	if(tcp->total_bytes < tcp->msglen + sizeof(tcp->msglen)) {
		/* more to write when socket becomes writable again */
		return; 
	}
	
	assert(tcp->total_bytes == tcp->msglen + sizeof(tcp->msglen));
	/* done writing, get ready for reading */
	tcp->is_reading = 1;
	tcp->total_bytes = 0;
	tcp->msglen = 0;
	buffer_clear(tcp->packet);
	zone->zone_handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;
	xfrd_tcp_read(set, zone);
}

int conn_read(xfrd_tcp_t* tcp)
{
	ssize_t received;
	/* receive leading packet length bytes */
	if(tcp->total_bytes < sizeof(tcp->msglen)) {
		received = read(tcp->fd,
			(char*) &tcp->msglen + tcp->total_bytes,
			sizeof(tcp->msglen) - tcp->total_bytes);
		if(received == -1) {
			if(errno == EAGAIN || errno == EINTR) {
				/* read would block, try later */
				return 0;
			} else {
				log_msg(LOG_ERR, "read %s", strerror(errno));
				return -1;
			}
		} else if(received == 0) {
			/* EOF */
			return -1;
		}
		tcp->total_bytes += received;
		if(tcp->total_bytes < sizeof(tcp->msglen)) {
			/* not complete yet, try later */
			return 0;
		}

		assert(tcp->total_bytes == sizeof(tcp->msglen));
		tcp->msglen = ntohs(tcp->msglen);

		if(tcp->msglen > buffer_capacity(tcp->packet)) {
			log_msg(LOG_ERR, "buffer too small, dropping connection");
			return 0;
		}
		buffer_set_limit(tcp->packet, tcp->msglen);
	}

	assert(buffer_remaining(tcp->packet) > 0);

	received = read(tcp->fd, buffer_current(tcp->packet), 
		buffer_remaining(tcp->packet));
	if(received == -1) {
		if(errno == EAGAIN || errno == EINTR) {
			/* read would block, try later */
			return 0;
		} else {
			log_msg(LOG_ERR, "read %s",
				strerror(errno));
			return -1;
		}
	} else if(received == 0) {
		/* EOF */
		return -1;
	}

	tcp->total_bytes += received;
	buffer_skip(tcp->packet, received);

	if(buffer_remaining(tcp->packet) > 0) {
		/* not complete yet, wait for more */
		return 0;
	}

	/* completed */
	assert(buffer_position(tcp->packet) == tcp->msglen);
	return 1;
}

void 
xfrd_tcp_read(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	xfrd_tcp_t* tcp = set->tcp_state[zone->tcp_conn];
	int ret;
	
	assert(zone->tcp_conn != -1);
	ret = conn_read(tcp);
	if(ret == -1) {
		xfrd_tcp_release(set, zone);
		return;
	}
	if(ret == 0) 
		return;

	/* completed msg */
	buffer_flip(tcp->packet);
	xfrd_handle_received_xfr_packet(zone, tcp->packet);
	/* TODO read multiple packet XFRs */
	/* and done */
	xfrd_tcp_release(set, zone);
}

void 
xfrd_tcp_release(xfrd_tcp_set_t* set, xfrd_zone_t* zone)
{
	int conn = zone->tcp_conn;
	log_msg(LOG_INFO, "xfrd: zone %s released tcp conn to %s",
		zone->apex_str, zone->master->ip_address_spec);
	assert(zone->tcp_conn != -1);
	assert(zone->tcp_waiting == 0);
	zone->tcp_conn = -1;
	zone->tcp_waiting = 0;
	zone->zone_handler.fd = -1;
	zone->zone_handler.event_types = NETIO_EVENT_READ|NETIO_EVENT_TIMEOUT;

	if(set->tcp_state[conn]->fd != -1)
		close(set->tcp_state[conn]->fd);

	set->tcp_state[conn]->fd = -1;

	if(set->tcp_count == XFRD_MAX_TCP && set->tcp_waiting_first) {
		/* pop first waiting process */
		zone = set->tcp_waiting_first;
		if(set->tcp_waiting_last == zone) 
			set->tcp_waiting_last = 0;

		set->tcp_waiting_first = zone->tcp_waiting_next;
		zone->tcp_waiting_next = 0;
		/* start it */
		zone->tcp_conn = conn;
		zone->tcp_waiting = 0;

		if(!xfrd_tcp_open(set, zone)) 
			return;

		xfrd_tcp_xfr(set, zone);
	}
	else {
		assert(!set->tcp_waiting_first);
		set->tcp_count --;
		assert(set->tcp_count >= 0);
	}
}
