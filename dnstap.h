/*
 * dnstap.h - dnstap for NSD.
 *
 * By Matthijs Mekking.
 * Copyright (c) 2014, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef DNSTAP_H
#define DNSTAP_H

#include "nsd.h"
#include "query.h"
#include "buffer.h"

#define AUTH_QUERY 1
#define AUTH_RESPONSE 2

struct dnstap_message {
	int type;
	int socket_family;
	int socket_protocol;
#ifdef INET6
	struct sockaddr_storage query_address;
	struct sockaddr_storage response_address;
#else
	struct sockaddr_in query_address;
	struct sockaddr_in response_address;
#endif
	socklen_t query_address_len;
	socklen_t response_address_len;
	uint32_t query_port;
	uint32_t response_port;
	time_t query_time_sec;
	uint32_t query_time_nsec;
	buffer_type query_message;
	time_t response_time_sec;
	uint32_t response_time_nsec;
	buffer_type response_message;
	zone_type zone;
};

struct dnstap_struct {
	const char* nsid;
	const char* version;
	const char* extra;
	struct dnstap_message* message;
};


/**
 * Process query.
 *
 */
void dnstap_process_query(query_type* query, struct nsd* nsd);

/**
 * Process response.
 *
 */
void dnstap_process_response(query_type* query, struct nsd* nsd);

#endif /* DNSTAP_H */
