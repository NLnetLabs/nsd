/*
 * query.c -- nsd(8) the resolver.
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include "answer.h"
#include "axfr.h"
#include "dns.h"
#include "dname.h"
#include "nsd.h"
#include "namedb.h"
#include "plugins.h"
#include "query.h"
#include "util.h"

#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* LIBWRAP */

static void add_rrset(struct query       *query,
		      answer_type        *answer,
		      answer_section_type section,
		      domain_type        *owner,
		      rrset_type         *rrset);

void
query_put_dname_offset(struct query *q, domain_type *domain, uint16_t offset)
{
	if (q->compressed_dname_count >= MAX_COMPRESSED_DNAMES)
		return;
	
	q->compressed_dname_offsets[domain->number] = offset;
	q->compressed_dnames[q->compressed_dname_count] = domain;
	++q->compressed_dname_count;
}

uint16_t
query_get_dname_offset(struct query *q, domain_type *domain)
{
	return q->compressed_dname_offsets[domain->number];
}

void
query_clear_dname_offsets(struct query *q)
{
	uint16_t max_offset = q->iobufptr - q->iobuf;
	
	while (q->compressed_dname_count > 0
	       && (q->compressed_dname_offsets[q->compressed_dnames[q->compressed_dname_count - 1]->number]
		   >= max_offset))
	{
		q->compressed_dname_offsets[q->compressed_dnames[q->compressed_dname_count - 1]->number] = 0;
		--q->compressed_dname_count;
	}
}

void
query_clear_compression_tables(struct query *q)
{
	uint16_t i;
	
	for (i = 0; i < q->compressed_dname_count; ++i) {
		assert(q->compressed_dnames);
		q->compressed_dname_offsets[q->compressed_dnames[i]->number] = 0;
	}
	q->compressed_dname_count = 0;
}

void
query_add_compression_domain(struct query *q, domain_type *domain, uint16_t offset)
{
	while (domain->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "query dname: %s, number: %lu, offset: %u\n",
		       dname_to_string(domain->dname),
		       (unsigned long) domain->number,
		       offset));
		query_put_dname_offset(q, domain, offset);
		offset += label_length(dname_name(domain->dname)) + 1;
		domain = domain->parent;
	}
}

/*
 * Generate an error response with the specified RCODE.
 */
void
query_error (struct query *q, int rcode)
{
	QR_SET(q);		/* This is an answer.  */
	RCODE_SET(q, rcode);	/* Error code.  */
	
	/* Truncate the question as well... */
	QDCOUNT(q) = ANCOUNT(q) = NSCOUNT(q) = ARCOUNT(q) = 0;
	q->iobufptr = q->iobuf + QHEADERSZ;
}

static void 
query_formerr (struct query *query)
{
	query_error(query, RCODE_FORMAT);
}

void 
query_init (struct query *q)
{
	q->addrlen = sizeof(q->addr);
	q->iobufptr = q->iobuf;
	q->overflow = 0;
	q->maxlen = UDP_MAX_MESSAGE_LEN;
	q->edns = 0;
	q->tcp = 0;
	q->name = NULL;
	q->zone = NULL;
	q->domain = NULL;
	q->class = 0;
	q->type = 0;
	q->delegation_domain = NULL;
	q->delegation_rrset = NULL;
	q->compressed_dname_count = 0;

	q->axfr_is_done = 0;
	q->axfr_zone = NULL;
	q->axfr_current_domain = NULL;
	q->axfr_current_rrset = NULL;
	q->axfr_current_rr = 0;
}

static void 
query_addtxt(struct query  *q,
	     const uint8_t *dname,
	     uint16_t       class,
	     uint32_t       ttl,
	     const char    *txt)
{
	uint16_t pointer;
	size_t txt_length = strlen(txt);
	uint8_t len = (uint8_t) txt_length;
	uint16_t rdlength = htons(len + 1);
	uint16_t type = htons(TYPE_TXT);

	assert(txt_length <= UCHAR_MAX);
	
	ttl = htonl(ttl);
	class = htons(class);

	/* Add the dname */
	if (dname >= q->iobuf && dname <= q->iobufptr) {
		pointer = htons(0xc000 | (dname - q->iobuf));
		query_write(q, &pointer, sizeof(pointer));
	} else {
		query_write(q, dname + 1, *dname);
	}

	query_write(q, &type, sizeof(type));
	query_write(q, &class, sizeof(class));
	query_write(q, &ttl, sizeof(ttl));
	query_write(q, &rdlength, sizeof(rdlength));
	query_write(q, &len, sizeof(len));
	query_write(q, txt, len);
}

/*
 * Parse the question section.  The query name is normalized and
 * stored in DOMAIN_NAME.  The DOMAIN_NAME is prefixed by a total
 * length byte.  DOMAIN_NAME must have room for at least MAXDOMAINLEN
 * + 1 bytes.  The number of labels (excluding the "root" label) in
 * the domain name is stored in LABEL_COUNT.  The query class and
 * query type are stored in QUERY_CLASS and QUERY_TYPE, respectively,
 * using network byte order.
 *
 * Result code: NULL on failure, a pointer to the byte after the query
 * section otherwise.
 */
static uint8_t *
process_query_section(struct query *query)
{
	uint8_t qnamebuf[MAXDOMAINLEN];

	uint8_t *dst = qnamebuf;
	uint8_t *query_name = query->iobuf + QHEADERSZ;
	uint8_t *src = query_name;
	size_t i;
	size_t len;
	
	/* Lets parse the query name and convert it to lower case.  */
	while (*src) {
		/*
		 * If we are out of buffer limits or we have a pointer
		 * in question dname or the domain name is longer than
		 * MAXDOMAINLEN ...
		 */
		if ((*src & 0xc0) ||
		    (src + *src + 1 > query->iobufptr) || 
		    (src + *src + 1 > query_name + MAXDOMAINLEN))
		{
			query_formerr(query);
			return NULL;
		}
		*dst++ = *src;
		for (i = *src++; i; i--) {
			*dst++ = NAMEDB_NORMALIZE(*src++);
		}
	}
	*dst++ = *src++;

	/* Make sure name is not too long or we have stripped packet... */
	len = src - query_name;
	if (len > MAXDOMAINLEN || (src + 2*sizeof(uint16_t) > query->iobufptr)) {
		query_formerr(query);
		return NULL;
	}

	query->name = dname_make(query->region, qnamebuf);

	memcpy(&query->type, src, sizeof(uint16_t));
	memcpy(&query->class, src + sizeof(uint16_t), sizeof(uint16_t));
	query->type = ntohs(query->type);
	query->class = ntohs(query->class);
	
	return src + 2*sizeof(uint16_t);
}


/*
 * Process an optional EDNS OPT record.  Sets QUERY->EDNS to 0 if
 * there was no EDNS record, to -1 if there was an invalid or
 * unsupported EDNS record, and to 1 otherwise.  Updates QUERY->MAXLEN
 * if the EDNS record specifies a maximum supported response length.
 *
 * Return 0 on failure, 1 on success.
 */
static int
process_edns (struct query *q, uint8_t *qptr)
{
	/* OPT record type... */
	uint16_t opt_type, opt_class, opt_rdlen;

	/* Do we have an OPT record? */
	if (ARCOUNT(q) > 0) {
		/* Only one opt is allowed... */
		if (ntohs(ARCOUNT(q)) != 1) {
			query_formerr(q);
			return 0;
		}

		/* Must have root owner name... */
		if (*qptr != 0) {
			query_formerr(q);
			return 0;
		}

		/* Must be of the type OPT... */
		memcpy(&opt_type, qptr + 1, 2);
		if (ntohs(opt_type) != TYPE_OPT) {
			query_formerr(q);
			return 0;
		}

		/* Ok, this is EDNS(0) packet... */
		q->edns = 1;

		/* Get the UDP size... */
		memcpy(&opt_class, qptr + 3, 2);
		opt_class = ntohs(opt_class);

		/* Check the version... */
		if (*(qptr + 6) != 0) {
			q->edns = -1;
		} else {
			/* Make sure there are no other options... */
			memcpy(&opt_rdlen, qptr + 9, 2);
			if (opt_rdlen != 0) {
				q->edns = -1;
			} else {
				/* Only care about UDP size larger than normal... */
				if (!q->tcp && opt_class > UDP_MAX_MESSAGE_LEN) {
					/* XXX Configuration parameter to limit the size needs to be here... */
					if (opt_class < QIOBUFSZ) {
						q->maxlen = opt_class;
					} else {
						q->maxlen = QIOBUFSZ;
					}
				}

#ifdef STRICT_MESSAGE_PARSE
				/* Trailing garbage? */
				if ((qptr + OPT_LEN) != q->iobufptr) {
					q->edns = 0;
					query_formerr(q);
					return 0;
				}
#endif

				/* Strip the OPT resource record off... */
				q->iobufptr = qptr;
				ARCOUNT(q) = 0;

				DEBUG(DEBUG_QUERY, 2,
				      (stderr, "EDNS0 maxlen = %u\n", q->maxlen));
			}
		}
	}

	/* Leave enough room for the EDNS field.  */
	if (q->edns != 0) {
		q->maxlen -= OPT_LEN;
	}
	
	return 1;
}


/*
 * Log notifies and return an RCODE_IMPL error to the client.
 *
 * Return 1 if answered, 0 otherwise.
 *
 * XXX: erik: Is this the right way to handle notifies?
 */
static int
answer_notify (struct query *query)
{
	char namebuf[BUFSIZ];

	switch (OPCODE(query)) {
	case OPCODE_QUERY:
		/* Not handled by this function.  */
		return 0;
	case OPCODE_NOTIFY:
		if (getnameinfo((struct sockaddr *) &(query->addr),
				query->addrlen, namebuf, sizeof(namebuf), 
				NULL, 0, NI_NUMERICHOST)
		    != 0)
		{
			log_msg(LOG_INFO, "notify from unknown remote address");
		} else {
			log_msg(LOG_INFO, "notify from %s", namebuf);
		}
	default:
		query_error(query, RCODE_IMPL);
		return 1;
	}
}


static void
add_dependent_rrsets(struct query *query, answer_type *answer,
		     answer_section_type section,
		     rrset_type *master_rrset,
		     size_t rdata_index, uint16_t type_of_dependent,
		     int allow_glue)
{
	size_t i;
	
	assert(query);
	assert(answer);
	assert(master_rrset);
	assert(rdata_atom_is_domain(master_rrset->type, rdata_index));

	for (i = 0; i < master_rrset->rrslen; ++i) {
		rrset_type *rrset;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i]->rdata[rdata_index]);
		domain_type *match = additional;
		
		assert(additional);

		if (!allow_glue && domain_is_glue(match, query->zone))
			continue;
		
		/*
		 * Check to see if we need to generate the dependent
		 * based on a wildcard domain.
		 */
		while (!match->is_existing) {
			match = match->parent;
		}
		if (additional != match && match->wildcard_child) {
			domain_type *temp = region_alloc(query->region, sizeof(domain_type));
			temp->dname = additional->dname;
			temp->number = additional->number;
			temp->parent = match;
			temp->wildcard_child = NULL;
			temp->rrsets = match->wildcard_child->rrsets;
			temp->plugin_data = match->wildcard_child->plugin_data;
			temp->is_existing = match->wildcard_child->is_existing;
			additional = temp;
		}

		rrset = domain_find_rrset(additional, query->zone, type_of_dependent);
		if (rrset) {
			add_rrset(query, answer, section, additional, rrset);
		}
	}
}

static void
add_rrset(struct query       *query,
	  answer_type        *answer,
	  answer_section_type section,
	  domain_type        *owner,
	  rrset_type         *rrset)
{
	assert(query);
	assert(answer);
	assert(owner);
	assert(rrset);
	assert(rrset->class == CLASS_IN);
	
	answer_add_rrset(answer, section, owner, rrset);
	switch (rrset->type) {
	case TYPE_NS:
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 0, TYPE_A, 1);
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 0, TYPE_AAAA, 1);
		break;
	case TYPE_MB:
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 0, TYPE_A, 0);
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 0, TYPE_AAAA, 0);
		break;
	case TYPE_MX:
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 1, TYPE_A, 0);
		add_dependent_rrsets(query, answer, ADDITIONAL_SECTION,
				     rrset, 1, TYPE_AAAA, 0);
		break;
	default:
		break;
	}
}

/*
 * Answer delegation information.
 */
static void
answer_delegation(struct query *query, answer_type *answer)
{
	assert(answer);
	assert(query->delegation_domain);
	assert(query->delegation_rrset);
	
	AA_CLR(query);
	add_rrset(query,
		  answer,
		  AUTHORITY_SECTION,
		  query->delegation_domain,
		  query->delegation_rrset);
	query->domain = query->delegation_domain;
}


/*
 * Answer SOA information.
 */
static void
answer_soa(struct query *query, answer_type *answer)
{
	query->domain = query->zone->domain;
	
	if (query->class == CLASS_ANY) {
		AA_CLR(query);
	} else {
		AA_SET(query);
		add_rrset(query, answer,
			  AUTHORITY_SECTION,
			  query->zone->domain,
			  query->zone->soa_rrset);
	}
}

static void
answer_nxtype(struct query *query, answer_type *answer, domain_type *domain)
{
	answer_soa(query, answer);
}

static void
answer_nxdomain(struct query *query, answer_type *answer)
{
	RCODE_SET(query, RCODE_NXDOMAIN);
	answer_soa(query, answer);
}

/*
 * Answer domain information (or SOA if we do not have an RRset for
 * the type specified by the query).
 */
static void
answer_domain(struct query *q, answer_type *answer, domain_type *domain)
{
	rrset_type *rrset;
	
	if (q->type == TYPE_ANY && (rrset = domain_find_any_rrset(domain, q->zone))) {
		for (; rrset; rrset = rrset->next) {
			if (rrset->zone == q->zone) {
				add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
			}
		}
	} else if ((rrset = domain_find_rrset(domain, q->zone, q->type))) {
		add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
	} else if ((rrset = domain_find_rrset(domain, q->zone, TYPE_CNAME))) {
		add_rrset(q, answer, ANSWER_SECTION, domain, rrset);
		add_dependent_rrsets(
			q, answer, ANSWER_SECTION, rrset, 0, q->type, 0);
	} else {
		answer_nxtype(q, answer, domain);
		return;
	}

	q->domain = domain;
	
	if (q->class == CLASS_ANY) {
		AA_CLR(q);
	} else if (q->zone->ns_rrset) {
		AA_SET(q);
		add_rrset(q, answer, AUTHORITY_SECTION, q->zone->domain, q->zone->ns_rrset);
	}
}


/*
 * Answer if this is a query in the CHAOS class or in a class not
 * supported by NSD.
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_chaos(struct nsd *nsd, struct query *q)
{
	switch (q->class) {
	case CLASS_IN:
	case CLASS_ANY:
		/* Not handled by this function. */
		return 0;
	case CLASS_CHAOS:
		/* Handled below.  */
		break;
	default:
		RCODE_SET(q, RCODE_REFUSE);
		return 1;
	}

	AA_CLR(q);
	switch (q->type) {
	case TYPE_ANY:
	case TYPE_TXT:
		if ((q->name->name_size == 11
		     && memcmp(dname_name(q->name), "\002id\006server", 11) == 0) || 
		    (q->name->name_size ==  15
		     && memcmp(dname_name(q->name), "\010hostname\004bind", 15) == 0))
		{
			/* Add ID */
			query_addtxt(q,
				     q->iobuf + QHEADERSZ,
				     CLASS_CHAOS,
				     0,
				     nsd->identity);
			ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
			return 1;
		} else if ((q->name->name_size == 16
			    && memcmp(dname_name(q->name), "\007version\006server", 16) == 0) ||
			   (q->name->name_size == 14
			    && memcmp(dname_name(q->name), "\007version\004bind", 14) == 0))
		{
			/* Add version */
			query_addtxt(q,
				     q->iobuf + QHEADERSZ,
				     CLASS_CHAOS,
				     0,
				     nsd->version);
			ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
			return 1;
		}
	default:
		RCODE_SET(q, RCODE_REFUSE);
		return 1;
	}
}


/*
 * Answer if this is an AXFR or IXFR query.
 */
static query_state_type
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


static void
answer_query(struct nsd *nsd, struct query *q)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	domain_type *match;
	uint16_t offset;
	int exact;
	answer_type answer;

	exact = namedb_lookup(nsd->db, q->name, &closest_match, &closest_encloser);
	if (!closest_encloser->is_existing) {
		exact = 0;
		while (!closest_encloser->is_existing)
			closest_encloser = closest_encloser->parent;
	}

	q->domain = closest_encloser;
	
	q->zone = domain_find_zone(closest_encloser);
	if (!q->zone) {
		RCODE_SET(q, RCODE_SERVFAIL);
		return;
	}

	offset = dname_label_offsets(q->name)[closest_encloser->dname->label_count - 1] + QHEADERSZ;
	query_add_compression_domain(q, closest_encloser, offset);

	if (exact) {
		match = closest_encloser;
	} else if (closest_encloser->wildcard_child) {
		/* Generate the domain from the wildcard.  */
		match = region_alloc(q->region, sizeof(domain_type));
		match->dname = q->name;
		match->parent = closest_encloser;
		match->wildcard_child = NULL;
		match->number = 0; /* Number 0 is always available. */
		match->rrsets = closest_encloser->wildcard_child->rrsets;
		match->plugin_data = closest_encloser->wildcard_child->plugin_data;
		match->is_existing = closest_encloser->wildcard_child->is_existing;
		query_put_dname_offset(q, match, QHEADERSZ);
	} else {
		match = NULL;
	}

	/*
	 * See 3.1.4.1 Responding to Queries for DS RRs in DNSSEC
	 * protocol.
	 */
	if (q->type == TYPE_DS && match == q->zone->domain) {
		/*
		 * Type DS query at a zone cut, use the responsible
		 * parent zone to generate the answer if we are
		 * authoritative for the parent zone.
		 */
		zone_type *zone = domain_find_parent_zone(q->zone);
		if (zone)
			q->zone = zone;
	}
	
	answer_init(&answer);
	if (q->type == TYPE_DS && match == q->zone->domain) {
		answer_domain(q, &answer, match);
	} else {
		q->delegation_domain = domain_find_ns_rrsets(
			closest_encloser, q->zone, &q->delegation_rrset);

		if (q->delegation_domain) {
			/* Delegation.  */
			answer_delegation(q, &answer);
		} else {
			/* Authorative zone.  */
			if (match) {
				answer_domain(q, &answer, match);
			} else {
				answer_nxdomain(q, &answer);
			}
		}
	}

	encode_answer(q, &answer);

	query_clear_compression_tables(q);
}


/*
 * Processes the query.
 *
 */
query_state_type
query_process(struct query *q, struct nsd *nsd)
{
	/* The query... */
	uint8_t *qname;
	uint8_t *qptr;
	int recursion_desired;
	query_state_type query_state;
	
	/* Sanity checks */
	if (QR(q)) {
		/* Not a query? Drop it on the floor. */
		return QUERY_DISCARDED;
	}

	/* Account the OPCODE */
	STATUP2(nsd, opcode, OPCODE(q));

	if (answer_notify(q)) {
		return QUERY_PROCESSED;
	}

	/* Dont bother to answer more than one question at once... */
	if (ntohs(QDCOUNT(q)) != 1 || TC(q)) {
		*(uint16_t *)(q->iobuf + 2) = 0;

		query_formerr(q);
		return QUERY_PROCESSED;
	}

	/* Save the RD flag (RFC1034 4.1.1).  */
	recursion_desired = RD(q);

	/* Zero the flags... */
	*(uint16_t *)(q->iobuf + 2) = 0;
	
	QR_SET(q);		/* This is an answer */
	if (recursion_desired)
		RD_SET(q);   /* Restore the RD flag (RFC1034 4.1.1) */
	
	/*
	 * Lets parse the qname and convert it to lower case.  Leave
	 * some space in front of the qname for the wildcard label.
	 */
	qptr = process_query_section(q);
	if (!qptr) {
		return QUERY_PROCESSED;
	}

	qname = q->iobuf + QHEADERSZ;
	
	/* Update the type and class */
	STATUP2(nsd, qtype, q->type);
	STATUP2(nsd, qclass, q->class);

	/* Dont allow any records in the answer or authority section... */
	if (ANCOUNT(q) != 0 || NSCOUNT(q) != 0) {
		query_formerr(q);
		return QUERY_PROCESSED;
	}

	if (!process_edns(q, qptr)) {
		return QUERY_PROCESSED;
	}

	/* Do we have any trailing garbage? */
	if (qptr != q->iobufptr) {
#ifdef	STRICT_MESSAGE_PARSE
		/* If we're strict.... */
		query_formerr(q);
		return QUERY_PROCESSED;
#else
		/* Otherwise, strip it... */
		q->iobufptr = qptr;
#endif
	}

	if (answer_chaos(nsd, q)) {
		return QUERY_PROCESSED;
	}

	query_state = answer_axfr_ixfr(nsd, q);
	if (query_state == QUERY_PROCESSED || query_state == QUERY_IN_AXFR) {
		return query_state;
	}

	answer_query(nsd, q);

	return QUERY_PROCESSED;
}

void
query_addedns(struct query *q, struct nsd *nsd) {
	switch (q->edns) {
	case 1:	/* EDNS(0) packet... */
		q->maxlen += OPT_LEN;
		query_write(q, nsd->edns.opt_ok, OPT_LEN);
		ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);

		STATUP(nsd, edns);
		break;
	case -1: /* EDNS(0) error... */
		q->maxlen += OPT_LEN;
		query_write(q, nsd->edns.opt_err, OPT_LEN);
		ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);

		STATUP(nsd, ednserr);
		break;
	}
}

