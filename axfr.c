/*
 * axfr.c -- generating AXFR responses.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
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
#include "query.h"

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

	query->overflow = 0;
	
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

		query->axfr_current_domain = heap_first(nsd->db->domains->names_to_domains);
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
	
	while (query->axfr_current_domain != heap_last()) {
		if (!query->axfr_current_rrset) {
			query->axfr_current_rrset = domain_find_any_rrset(
				query->axfr_current_domain->data,
				query->axfr_zone);
			query->axfr_current_rr = 0;
		}
		while (query->axfr_current_rrset) {
			if (query->axfr_current_rrset != query->axfr_zone->soa_rrset
			    && query->axfr_current_rrset->zone == query->axfr_zone)
			{
				while (query->axfr_current_rr < query->axfr_current_rrset->rrslen) {
					added = encode_rr(query,
							  query->axfr_current_domain->data,
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
		query->axfr_current_domain = heap_next(query->axfr_current_domain);
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
