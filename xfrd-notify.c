/*
 * xfrd-notify.c - notify sending routines
 *
 * Copyright (c) 2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "xfrd-notify.h"
#include "xfrd.h"
#include "xfrd-tcp.h"
#include "packet.h"

#define XFRD_NOTIFY_RETRY_TIMOUT 15 /* seconds between retries sending NOTIFY */
#define XFRD_NOTIFY_MAX_NUM 5 /* number of attempts to send NOTIFY */

/* stop sending notifies */
static void xfrd_notify_disable(xfrd_zone_t* zone);

/* returns if the notify send is done for the notify_current acl */
static int xfrd_handle_notify_reply(xfrd_zone_t* zone, buffer_type* packet);

static void xfrd_notify_next(xfrd_zone_t* zone);

static void xfrd_notify_send_udp(xfrd_zone_t* zone, buffer_type* packet);

static void 
xfrd_notify_disable(xfrd_zone_t* zone)
{
	if(zone->notify_send_handler.fd != -1) {
		close(zone->notify_send_handler.fd);
	}
	zone->notify_current = 0;
	zone->notify_send_handler.fd = -1;
	zone->notify_send_handler.timeout = 0;
}

static int 
xfrd_handle_notify_reply(xfrd_zone_t* zone, buffer_type* packet) 
{
	if((OPCODE(packet) != OPCODE_NOTIFY) ||
		(QR(packet) == 0)) {
		log_msg(LOG_ERR, "xfrd: zone %s: received bad notify reply opcode/flags",
			zone->apex_str);
		return 0;
	}
	/* we know it is OPCODE NOTIFY, QUERY_REPLY and for this zone */
	if(ID(packet) != zone->notify_query_id) {
		log_msg(LOG_ERR, "xfrd: zone %s: received notify-ack with bad ID",
			zone->apex_str);
		return 0;
	}
	/* could check tsig, but why. The reply does not cause processing. */
	if(RCODE(packet) != RCODE_OK) {
		log_msg(LOG_ERR, "xfrd: zone %s: received notify response error %s from %s",
			zone->apex_str, rcode2str(RCODE(packet)),
			zone->notify_current->ip_address_spec);
		if(RCODE(packet) == RCODE_IMPL)
			return 1; /* rfc1996: notimpl notify reply: consider retries done */
		return 0;
	}
	log_msg(LOG_INFO, "xfrd: zone %s: host %s acknowledges notify",
		zone->apex_str, zone->notify_current->ip_address_spec);
	return 1;
}

static void
xfrd_notify_next(xfrd_zone_t* zone)
{
	/* advance to next in acl */
	zone->notify_current = zone->notify_current->next;
	zone->notify_retry = 0;
	if(zone->notify_current == 0) {
		log_msg(LOG_INFO, "xfrd: zone %s: no more notify-send acls. stop notify.", 
			zone->apex_str);
		xfrd_notify_disable(zone);
		return;
	}
}

static void 
xfrd_notify_send_udp(xfrd_zone_t* zone, buffer_type* packet)
{
	if(zone->notify_send_handler.fd != -1)
		close(zone->notify_send_handler.fd);
	zone->notify_send_handler.fd = -1;
	/* Set timeout for next reply */
	zone->notify_timeout.tv_sec = xfrd_time() + XFRD_NOTIFY_RETRY_TIMOUT;
	/* send NOTIFY to secondary. */
	xfrd_setup_packet(packet, TYPE_SOA, CLASS_IN, zone->apex);
	zone->notify_query_id = ID(packet);
	OPCODE_SET(packet, OPCODE_NOTIFY);
	AA_SET(packet);
	if(zone->soa_nsd_acquired != 0) {
		/* add current SOA to answer section */
		ANCOUNT_SET(packet, 1);
		xfrd_write_soa_buffer(packet, zone, &zone->soa_nsd);
	}
#ifdef TSIG
	if(zone->notify_current->key_options) {
		xfrd_tsig_sign_request(packet, &zone->notify_tsig, zone->notify_current);
	}
#endif /* TSIG */
	buffer_flip(packet);
	zone->notify_send_handler.fd = xfrd_send_udp(zone->notify_current, packet);
	if(zone->notify_send_handler.fd == -1) {
		log_msg(LOG_ERR, "xfrd: zone %s: could not send notify #%d to %s",
			zone->apex_str, zone->notify_retry,
			zone->notify_current->ip_address_spec);
		return;
	}
	log_msg(LOG_INFO, "xfrd: zone %s: sent notify #%d to %s",
		zone->apex_str, zone->notify_retry,
		zone->notify_current->ip_address_spec);
}

void 
xfrd_handle_notify_send(netio_type* ATTR_UNUSED(netio), 
	netio_handler_type *handler, netio_event_types_type event_types)
{
	xfrd_zone_t* zone = (xfrd_zone_t*)handler->user_data;
	buffer_type* packet = xfrd_get_temp_buffer();
	assert(zone->notify_current);
	if(event_types & NETIO_EVENT_READ) {
		log_msg(LOG_INFO, "xfrd: zone %s: read notify ACK", zone->apex_str);
		assert(handler->fd != -1);
		if(xfrd_udp_read_packet(packet, zone->zone_handler.fd)) {
			if(xfrd_handle_notify_reply(zone, packet))
				xfrd_notify_next(zone);
		}
	} else if(event_types & NETIO_EVENT_TIMEOUT) {
		log_msg(LOG_INFO, "xfrd: zone %s: notify timeout", zone->apex_str);
		zone->notify_retry++; /* timeout, try again */
		if(zone->notify_retry > XFRD_NOTIFY_MAX_NUM) {
			log_msg(LOG_ERR, "xfrd: zone %s: max notify send count reached, %s unreachable", 
				zone->apex_str, zone->notify_current->ip_address_spec);
			xfrd_notify_next(zone);
		}
	}
	/* see if notify is still enabled */
	if(zone->notify_current) {
		/* try again */
		xfrd_notify_send_udp(zone, packet);
	}
}

void 
xfrd_send_notify(xfrd_zone_t* zone)
{
	if(!zone->zone_options->notify) {
		return; /* no notify acl, nothing to do */
	}
	zone->notify_retry = 0;
	zone->notify_current = zone->zone_options->notify;
	zone->notify_send_handler.timeout = &zone->notify_timeout;
	zone->notify_timeout.tv_sec = xfrd_time();
	zone->notify_timeout.tv_nsec = 0;
}
