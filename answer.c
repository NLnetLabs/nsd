/*
 * answer.c -- manipulating query answers and encoding them.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <string.h>

#include "answer.h"
#include "dns.h"

void
answer_init(answer_type *answer)
{
	answer->rrset_count = 0;
}

int
answer_add_rrset(answer_type *answer, rr_section_type section,
		 domain_type *domain, rrset_type *rrset)
{
	size_t i;
	
	assert(section >= ANSWER_SECTION && section < RR_SECTION_COUNT);
	assert(domain);
	assert(rrset);

	/* Don't add an RRset multiple times.  */
	for (i = 0; i < answer->rrset_count; ++i) {
		if (answer->rrsets[i] == rrset) {
			if (section < answer->section[i]) {
				answer->section[i] = section;
				return 1;
			} else {
				return 0;
			}
		}
	}
	
	if (answer->rrset_count >= MAXRRSPP) {
		/* XXX: Generate warning/error? */
		return 0;
	}
	
	answer->section[answer->rrset_count] = section;
	answer->domains[answer->rrset_count] = domain;
	answer->rrsets[answer->rrset_count] = rrset;
	++answer->rrset_count;
	
	return 1;
}

static void
encode_dname(query_type *q, domain_type *domain)
{
	while (domain->parent && query_get_dname_offset(q, domain) == 0) {
		query_put_dname_offset(q, domain, buffer_position(q->packet));
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "dname: %s, number: %lu, offset: %u\n",
		       dname_to_string(domain_dname(domain)),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		buffer_write(q->packet, dname_name(domain_dname(domain)),
			     label_length(dname_name(domain_dname(domain))) + 1U);
		domain = domain->parent;
	}
	if (domain->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "dname: %s, number: %lu, pointer: %u\n",
		       dname_to_string(domain_dname(domain)),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		buffer_write_u16(q->packet,
				 0xc000 | query_get_dname_offset(q, domain));
	} else {
		buffer_write_u8(q->packet, 0);
	}
}

int
encode_rr(query_type *q, domain_type *owner, rr_type *rr)
{
	size_t truncation_mark;
	uint16_t rdlength = 0;
	size_t rdlength_pos;
	uint16_t j;
	
	assert(q);
	assert(owner);
	assert(rr);
	
	/*
	 * If the record does not in fit in the packet the packet size
	 * will be restored to the mark.
	 */
	truncation_mark = buffer_position(q->packet);
	
	encode_dname(q, owner);
	buffer_write_u16(q->packet, rr->type);
	buffer_write_u16(q->packet, rr->klass);
	buffer_write_u32(q->packet, rr->ttl);

	/* Reserve space for rdlength. */
	rdlength_pos = buffer_position(q->packet);
	buffer_skip(q->packet, sizeof(rdlength));

	for (j = 0; j < rr->rdata_count; ++j) {
		switch (rdata_atom_wireformat_type(rr->type, j)) {
		case RDATA_WF_COMPRESSED_DNAME:
			encode_dname(q, rdata_atom_domain(rr->rdatas[j]));
			break;
		case RDATA_WF_UNCOMPRESSED_DNAME:
		{
			const dname_type *dname = domain_dname(
				rdata_atom_domain(rr->rdatas[j]));
			buffer_write(q->packet,
				     dname_name(dname), dname->name_size);
			break;
		}
		default:
			buffer_write(q->packet,
				     rdata_atom_data(rr->rdatas[j]),
				     rdata_atom_size(rr->rdatas[j]));
			break;
		}
	}

	if (!query_overflow(q)) {
		rdlength = (buffer_position(q->packet) - rdlength_pos
			    - sizeof(rdlength));
		buffer_write_u16_at(q->packet, rdlength_pos, rdlength);
		return 1;
	} else {
		buffer_set_position(q->packet, truncation_mark);
		query_clear_dname_offsets(q, truncation_mark);
		assert(!query_overflow(q));
		return 0;
	}
}

static int
encode_rrset(query_type *q, uint16_t *count, domain_type *owner,
	     rrset_type *rrset, int truncate)
{
	uint16_t i;
	size_t truncation_mark;
	uint16_t added = 0;
	int all_added = 1;
	rrset_type *rrsig;
	
	assert(rrset->rr_count > 0);

	truncation_mark = buffer_position(q->packet);
	
	for (i = 0; i < rrset->rr_count; ++i) {
		if (encode_rr(q, owner, &rrset->rrs[i])) {
			++added;
		} else {
			all_added = 0;
			if (truncate) {
				/* Truncate entire RRset and set truncate flag.  */
				buffer_set_position(q->packet, truncation_mark);
				query_clear_dname_offsets(q, truncation_mark);
				TC_SET(q);
				added = 0;
			}
			break;
		}
	}

	if (all_added &&
	    q->edns.dnssec_ok &&
	    zone_is_secure(rrset->zone) &&
	    rrset->rrs[0].type != TYPE_RRSIG &&
	    (rrsig = domain_find_rrset(owner, rrset->zone, TYPE_RRSIG)))
	{
		for (i = 0; i < rrsig->rr_count; ++i) {
			if (rrset_rrsig_type_covered(rrsig, i) == rrset->rrs[0].type) {
				if (encode_rr(q, owner, &rrsig->rrs[i])) {
					++added;
				} else {
					all_added = 0;
					if (truncate) {
						/* Truncate entire RRset and set truncate flag.  */
						buffer_set_position(q->packet, truncation_mark);
						query_clear_dname_offsets(q, truncation_mark);
						TC_SET(q);
						added = 0;
					}
					break;
				}
			}
		}
	}
	
	(*count) += added;

	return all_added;
}

void
encode_answer(query_type *q, const answer_type *answer)
{
	uint16_t counts[RR_SECTION_COUNT];
	rr_section_type section;
	size_t i;

	for (section = ANSWER_SECTION; section < RR_SECTION_COUNT; ++section) {
		counts[section] = 0;
		for (i = 0; !query_overflow(q) && i < answer->rrset_count; ++i) {
			if (answer->section[i] == section) {
				int truncate = (section == ANSWER_SECTION
						|| section == AUTHORITY_SECTION);
				encode_rrset(q, &counts[section],
					     answer->domains[i],
					     answer->rrsets[i],
					     truncate);
			}
		}
	}

	ANCOUNT_SET(q, counts[ANSWER_SECTION]);
	NSCOUNT_SET(q, counts[AUTHORITY_SECTION]);
	ARCOUNT_SET(q,
		    counts[ADDITIONAL_A_SECTION]
		    + counts[ADDITIONAL_AAAA_SECTION]
		    + counts[ADDITIONAL_OTHER_SECTION]);
}
