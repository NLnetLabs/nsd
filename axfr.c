/*
 * axfr.c -- generating AXFR responses.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <config.h>

#include "answer.h"
#include "axfr.h"
#include "dns.h"
#include "query.h"

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
		    || query->axfr_zone->domain != query->domain)
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

		assert(query->axfr_zone->soa_rrset->rrslen == 1);
		added = encode_rr(query,
				  query->axfr_zone->domain,
				  query->axfr_zone->soa_rrset,
				  0);
		if (!added) {
			/* XXX: This should never happen... generate error code? */
			abort();
		}
		++total_added;
	} else {
		/* Query name only needs to be preserved in first answer packet.  */
		query->iobufptr = query->iobuf + QHEADERSZ;
		QDCOUNT(query) = 0;
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
				while (query->axfr_current_rr < query->axfr_current_rrset->rrslen) {
					added = encode_rr(query,
							  query->axfr_current_domain,
							  query->axfr_current_rrset,
							  query->axfr_current_rr);
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
	assert(query->axfr_zone->soa_rrset->rrslen == 1);
	added = encode_rr(query,
			  query->axfr_zone->domain,
			  query->axfr_zone->soa_rrset,
			  0);
	if (added) {
		++total_added;
		query->axfr_is_done = 1;
	}

return_answer:
	ANCOUNT(query) = htons(total_added);
	NSCOUNT(query) = 0;
	ARCOUNT(query) = 0;
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
