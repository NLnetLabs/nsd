/*
 * axfr.c -- generating AXFR responses.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include "axfr.h"
#include "dns.h"
#include "packet.h"

#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* LIBWRAP */

query_state_type
query_axfr (struct nsd *nsd, struct query *query)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	int exact;
	int added;
	uint16_t total_added = 0;

	if (query->axfr_is_done)
		return QUERY_PROCESSED;

	assert(!query_overflow(query));
	
	if (query->axfr_zone == NULL) {
		/* Start AXFR.  */
		exact = namedb_lookup(nsd->db,
				      query->name,
				      &closest_match,
				      &closest_encloser);
		
		query->domain = closest_encloser;
		query->axfr_zone = domain_find_zone(closest_encloser);
		
		if (!exact
		    || query->axfr_zone == NULL
		    || query->axfr_zone->apex != query->domain)
		{
			/* No SOA no transfer */
			RCODE_SET(query, RCODE_REFUSE);
			return QUERY_PROCESSED;
		}

		query->axfr_current_domain
			= (domain_type *) heap_first(nsd->db->domains->names_to_domains);
		query->axfr_current_rrset = NULL;
		query->axfr_current_rr = 0;

		query_add_compression_domain(query, query->domain, QHEADERSZ);

		assert(query->axfr_zone->soa_rrset->rr_count == 1);
		added = packet_encode_rr(query,
					 query->axfr_zone->apex,
					 &query->axfr_zone->soa_rrset->rrs[0]);
		if (!added) {
			/* XXX: This should never happen... generate error code? */
			abort();
		}
		++total_added;
	} else {
		/*
		 * Query name and EDNS need not be repeated after the
		 * first response packet.
		 */
		query->edns.status = EDNS_NOT_PRESENT;
		buffer_set_limit(query->packet, QHEADERSZ);
		QDCOUNT_SET(query, 0);
		query_prepare_response(query);
	}

	/* Add zone RRs until answer is full.  */
	assert(query->axfr_current_domain);
	
	while ((rbnode_t *) query->axfr_current_domain != HEAP_NULL) {
		if (!query->axfr_current_rrset) {
			query->axfr_current_rrset = domain_find_any_rrset(
				query->axfr_current_domain,
				query->axfr_zone);
			query->axfr_current_rr = 0;
		}
		while (query->axfr_current_rrset) {
			if (query->axfr_current_rrset != query->axfr_zone->soa_rrset
			    && query->axfr_current_rrset->zone == query->axfr_zone)
			{
				while (query->axfr_current_rr < query->axfr_current_rrset->rr_count) {
					added = packet_encode_rr(
						query,
						query->axfr_current_domain,
						&query->axfr_current_rrset->rrs[query->axfr_current_rr]);
					if (!added)
						goto return_answer;
					++total_added;
					++query->axfr_current_rr;
				}
			}

			query->axfr_current_rrset = query->axfr_current_rrset->next;
			query->axfr_current_rr = 0;
		}
		assert(query->axfr_current_domain);
		query->axfr_current_domain
			= (domain_type *) heap_next((rbnode_t *) query->axfr_current_domain);
	}

	/* Add terminating SOA RR.  */
	assert(query->axfr_zone->soa_rrset->rr_count == 1);
	added = packet_encode_rr(query,
				 query->axfr_zone->apex,
				 &query->axfr_zone->soa_rrset->rrs[0]);
	if (added) {
		++total_added;
		query->axfr_is_done = 1;
	}

return_answer:
	ANCOUNT_SET(query, total_added);
	NSCOUNT_SET(query, 0);
	ARCOUNT_SET(query, 0);
	query_clear_compression_tables(query);
	return QUERY_IN_AXFR;
}

/*
 * Answer if this is an AXFR or IXFR query.
 */
query_state_type
answer_axfr_ixfr(struct nsd *nsd, struct query *q)
{
	/* Is it AXFR? */
	switch (q->type) {
	case TYPE_AXFR:
#ifndef DISABLE_AXFR		/* XXX Should be a run-time flag */
		if (q->tcp) {
#ifdef LIBWRAP
			struct request_info request;
#ifdef AXFR_DAEMON_PREFIX
			const uint8_t *qptr = dname_name(q->name);
			char axfr_daemon[MAXDOMAINLEN + sizeof(AXFR_DAEMON_PREFIX)];
			char *t = axfr_daemon + sizeof(AXFR_DAEMON_PREFIX) - 1;

			memcpy(axfr_daemon, AXFR_DAEMON_PREFIX, sizeof(AXFR_DAEMON_PREFIX));

			/* Copy the qname as a string */
			while (*qptr)
			{
				memcpy(t, qptr + 1, *qptr);
				t += *qptr;
				*t++ = '.';
				qptr += *qptr + 1;
			}
			*t = 0;
			
#endif /* AXFR_DAEMON_PREFIX */
			request_init(&request, RQ_DAEMON, AXFR_DAEMON, RQ_CLIENT_SIN, &q->addr, 0);
			sock_methods(&request);	/* This is to work around the bug in libwrap */
			if (!hosts_access(&request)) {
#ifdef AXFR_DAEMON_PREFIX
				request_init(&request, RQ_DAEMON, axfr_daemon, RQ_CLIENT_SIN, &q->addr, 0);
				sock_methods(&request);	/* This is to work around the bug in libwrap */
				log_msg(LOG_ERR, "checking %s", axfr_daemon);
				if (!hosts_access(&request)) {
#endif /* AXFR_DAEMON_PREFIX */
					RCODE_SET(q, RCODE_REFUSE);
					return QUERY_PROCESSED;
#ifdef AXFR_DAEMON_PREFIX
				}
#endif /* AXFR_DAEMON_PREFIX */
			}
#endif /* LIBWRAP */
			return query_axfr(nsd, q);
		}
#endif	/* DISABLE_AXFR */
	case TYPE_IXFR:
		RCODE_SET(q, RCODE_REFUSE);
		return QUERY_PROCESSED;
	default:
		return QUERY_DISCARDED;
	}
}
