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

#include "dns.h"
#include "dname.h"
#include "nsd.h"
#include "namedb.h"
#include "plugins.h"
#include "query.h"
#include "util.h"
#include "zonec2.h"

#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* LIBWRAP */

static void
answer_add_rrset(answer_type *answer, answer_section_type section, domain_type *domain, rrset_type *rrset)
{
	size_t i;
	
	assert(section >= ANSWER_SECTION && section <= ADDITIONAL_SECTION);
	assert(domain);
	assert(rrset);
	
	/* Don't add an RRset multiple times.  */
	for (i = 0; i < answer->rrset_count; ++i) {
		if (answer->rrsets[i] == rrset) {
			if (section < answer->section[i])
				answer->section[i] = section;
			return;
		}
	}
	
	if (answer->rrset_count == MAXRRSPP)
		return;

	answer->section[answer->rrset_count] = section;
	answer->domains[answer->rrset_count] = domain;
	answer->rrsets[answer->rrset_count] = rrset;
	++answer->rrset_count;
	return;
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

int 
query_axfr (struct nsd *nsd, struct query *q, const uint8_t *qname)
{
	return 0;
#if 0
	/* Per AXFR... */
	static const dname_type *zone;
	static const struct answer *soa;
	static const struct rrset *d = NULL;
	
	const struct answer *a;
	const uint8_t *p;
	const dname_type *dname = NULL;
	uint8_t *qptr;
	dname_info_type *closest_match;
	dname_info_type *closest_encloser;

	STATUP(nsd, raxfr);

	/* Is it new AXFR? */
	if (qname) {
		/* New AXFR... */
		zone = dname_copy(q->region, q->name);

		/* Do we have the SOA? */
		if (namedb_lookup(nsd->db, q->name, &closest_match, &closest_encloser)
		    && (soa = namedb_answer(closest_encloser->rrsets, TYPE_SOA)))
		{
			d = closest_encloser->rrsets;
			
			/* We'd rather have ANY than SOA to improve performance */
			if ((a = namedb_answer(d, TYPE_ANY)) == NULL) {
				a = soa;
			}

			qptr = q->iobufptr;
			query_addanswer(q, qname, a, 0);

			/* Truncate */
			NSCOUNT(q) = 0;
			ARCOUNT(q) = 0;
			q->iobufptr = qptr + ANSWER_RRS(a, ntohs(ANCOUNT(q)));

			/* More data... */
			return 1;

		}

		/* No SOA no transfer */
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	/* We've done everything already, let the server know... */
	if (d == NULL) {
		return 0;	/* Done. */
	}

	/* Let get next domain */
	do {
		p = (const uint8_t *) d + d->size;
		if (!*p) break;
		dname = (const dname_type *) p;
		d = (const struct domain *) (p + ALIGN_UP(dname_total_size(dname), NAMEDB_ALIGNMENT));
	} while (DOMAIN_FLAGS(d) & NAMEDB_STEALTH);

	/* End of the database or end of zone? */
	if (*p == 0 || namedb_answer(d, TYPE_SOA) != NULL) {
		/* Prepare to send the terminating SOA record */
		a = soa;
		dname = zone;
		d = NULL;
	} else {
		/* Prepare the answer */
		if (DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
			a = namedb_answer(d, TYPE_NS);
		} else {
			a = namedb_answer(d, TYPE_ANY);
		}
	}

	/* Existing AXFR, strip the question section off... */
	q->iobufptr = q->iobuf + QHEADERSZ;

	/*
	 * Is the first dname a pointer?  If so, make room to store
	 * the complete dname.
	 */
	if (ANSWER_PTRS(a, 0) == 0) {
		/*
		 * Two bytes are already available because of the
		 * pointer.
		 */
		q->iobufptr += dname->name_size - 2;
		QDCOUNT(q) = ANCOUNT(q) = NSCOUNT(q) = ARCOUNT(q) = 0;
	}

	qptr = q->iobufptr;

	query_addanswer(q, q->iobuf + QHEADERSZ, a, 0);

	if (ANSWER_PTRS(a, 0) == 0) {
		memcpy(q->iobuf + QHEADERSZ, dname_name(dname), dname->name_size);
	}

	/* Truncate */
	if (d && DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
		ANCOUNT(q) = htons(ntohs(NSCOUNT(q)) + ntohs(ARCOUNT(q)));
	} else {
		q->iobufptr = qptr + ANSWER_RRS(a, ntohs(ANCOUNT(q)));
	}

	ARCOUNT(q) = 0;
	NSCOUNT(q) = 0;

	/* More data... */
	return 1;
#endif
}

void 
query_init (struct query *q)
{
	q->addrlen = sizeof(q->addr);
	q->iobufsz = QIOBUFSZ;
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
	q->answer.rrset_count = 0;
	q->delegation_domain = NULL;
	q->delegation_rrset = NULL;
	q->dname_stored_count = 0;
}

void 
query_addtxt (struct query *q, uint8_t *dname, int16_t class, int32_t ttl, const char *txt)
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
	if (dname >= q->iobuf  && dname <= q->iobufptr) {
		pointer = htons(0xc000 | (dname - q->iobuf));
		QUERY_WRITE(q, &pointer, sizeof(pointer));
	} else {
		QUERY_WRITE(q, dname + 1, *dname);
	}

	QUERY_WRITE(q, &type, sizeof(type));
	QUERY_WRITE(q, &class, sizeof(class));
	QUERY_WRITE(q, &ttl, sizeof(ttl));
	QUERY_WRITE(q, &rdlength, sizeof(rdlength));
	QUERY_WRITE(q, &len, sizeof(len));
	QUERY_WRITE(q, txt, len);
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
				if (opt_class > UDP_MAX_MESSAGE_LEN) {
					/* XXX Configuration parameter to limit the size needs to be here... */
					if (opt_class < q->iobufsz) {
						q->maxlen = opt_class;
					} else {
						q->maxlen = q->iobufsz;
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
add_dependent_rrsets(struct query *query, rrset_type *master_rrset,
		     answer_section_type section,
		     size_t rdata_index, uint16_t type_of_dependent)
{
	size_t i;
	
	assert(query);
	assert(master_rrset);
	assert(rdata_atom_is_domain(master_rrset->type, rdata_index));

	for (i = 0; i < master_rrset->rrslen; ++i) {
		rrset_type *rrset;
		domain_type *additional = rdata_atom_domain(master_rrset->rrs[i][rdata_index]);
		domain_type *match = additional;
		
		assert(additional);

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

		if ((rrset = domain_find_rrset(additional, query->zone, type_of_dependent))) {
			answer_add_rrset(&query->answer, section,
					 additional, rrset);
		}
	}
}

static void
add_ns_rrset(struct query *query, domain_type *owner, rrset_type *ns_rrset)
{
	assert(query);
	assert(ns_rrset);
	assert(ns_rrset->type == TYPE_NS);
	assert(ns_rrset->class == CLASS_IN);
	
	answer_add_rrset(&query->answer, AUTHORITY_SECTION, owner, ns_rrset);
	add_dependent_rrsets(query, ns_rrset, ADDITIONAL_SECTION, 0, TYPE_A);
	add_dependent_rrsets(query, ns_rrset, ADDITIONAL_SECTION, 0, TYPE_AAAA);
}

/*
 * Answer if this is a delegation.
 *
 * Return 1 if answered, 0 otherwise.
 */
static void
answer_delegation(struct query *query)
{
	assert(query->delegation_domain);
	assert(query->delegation_rrset);
	
	AA_CLR(query);
	add_ns_rrset(query, query->delegation_domain, query->delegation_rrset);
}


/*
 * Answer if we have SOA data for this domain.
 *
 * Return 1 if answered, 0 otherwise.
 */
static void
answer_soa(struct query *q)
{
	if (q->class == CLASS_ANY) {
		AA_CLR(q);
	} else {
		AA_SET(q);
		answer_add_rrset(&q->answer, AUTHORITY_SECTION, q->zone->domain, q->zone->soa_rrset);
	}
}


/*
 * Answer if we have data for this domain and qtype (or TYPE_CNAME).
 *
 * Return 1 if answered, 0 otherwise.
 */
static void
answer_domain(struct query *q, domain_type *domain)
{
	rrset_type *rrset;
	
	if (q->type == TYPE_ANY && (rrset = domain_find_any_rrset(domain, q->zone))) {
		for (; rrset; rrset = rrset->next) {
			if (rrset->zone == q->zone) {
				answer_add_rrset(&q->answer, ANSWER_SECTION, domain, rrset);
			}
		}
	} else if ((rrset = domain_find_rrset(domain, q->zone, q->type))) {
		answer_add_rrset(&q->answer, ANSWER_SECTION, domain, rrset);
	} else if ((rrset = domain_find_rrset(domain, q->zone, TYPE_CNAME))) {
		answer_add_rrset(&q->answer, ANSWER_SECTION, domain, rrset);
		add_dependent_rrsets(q, rrset, ANSWER_SECTION, 0, q->type);
	} else {
		/*
		 * Domain exists with data but no matching type found,
		 * so answer with a SOA record.
		 */
		answer_soa(q);
		return;
	}

	if (q->class == CLASS_ANY) {
		AA_CLR(q);
	} else if (q->zone->ns_rrset) {
		AA_SET(q);
		add_ns_rrset(q, q->zone->domain, q->zone->ns_rrset);
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
		if (q->name->name_size == 11
		   && memcmp(dname_name(q->name), "\002id\006server", 11) == 0)
		{
			/* Add ID */
			query_addtxt(q, q->iobuf + 12, CLASS_CHAOS, 0, nsd->identity);
			ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
			return 1;
		} else if (q->name->name_size == 16
			   && memcmp(dname_name(q->name), "\007version\006server", 16) == 0)
		{
			/* Add version */
			query_addtxt(q, q->iobuf + 12, CLASS_CHAOS, 0, nsd->version);
			ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
			return 1;
		}
	default:
		RCODE_SET(q, RCODE_REFUSE);
		return 1;
	}
}


/*
 * Answer if this is an AXFR or IXFR query.  If the query is answered
 * the IS_AXFR variable indicates whether an AXFR has been initiated.
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_axfr_ixfr(struct nsd *nsd, struct query *q, const uint8_t *qname, int *is_axfr)
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
					return 1;
#ifdef AXFR_DAEMON_PREFIX
				}
#endif /* AXFR_DAEMON_PREFIX */
			}
#endif /* LIBWRAP */
			*is_axfr = query_axfr(nsd, q, qname);
			return 1;
		}
#endif	/* DISABLE_AXFR */
	case TYPE_IXFR:
		RCODE_SET(q, RCODE_REFUSE);
		return 1;
	default:
		return 0;
	}
}


static void
generate_dname(struct query *q, domain_type *domain)
{
	while (domain->parent && query_get_dname_offset(q, domain) == 0) {
		query_put_dname_offset(q, domain, q->iobufptr - q->iobuf);
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "dname: %s, number: %lu, offset: %u\n",
		       dname_to_string(domain->dname),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		QUERY_WRITE(q, dname_name(domain->dname), label_length(dname_name(domain->dname)) + 1U);
		domain = domain->parent;
	}
	if (domain->parent) {
		uint16_t offset = htons(0xc000 | query_get_dname_offset(q, domain));
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "dname: %s, number: %lu, pointer: %u\n",
		       dname_to_string(domain->dname),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		QUERY_WRITE(q, &offset, sizeof(offset));
	} else {
		uint8_t zero = 0;
		QUERY_WRITE(q, &zero, sizeof(zero));
	}
}

static void
generate_rrset(struct query *q, uint16_t *count, domain_type *owner, rrset_type *rrset,
	       int truncate)
{
	uint16_t i, j;
	uint16_t type;
	uint16_t class;
	uint32_t ttl;
	uint16_t rdlength = 0;
	uint8_t *rdlength_pos;
	uint8_t *truncation_point = q->iobufptr;
	uint16_t compressed_dname_count = q->dname_stored_count;
	uint16_t added = 0;
	
	for (i = 0; i < rrset->rrslen; ++i) {
		if (!truncate) {
			/* Truncate on RR level.  */
			truncation_point = q->iobufptr;
			compressed_dname_count = q->dname_stored_count;
		}

		generate_dname(q, owner);
		type = htons(rrset->type);
		QUERY_WRITE(q, &type, sizeof(type));
		class = htons(rrset->class);
		QUERY_WRITE(q, &class, sizeof(class));
		ttl = htonl(rrset->ttl);
		QUERY_WRITE(q, &ttl, sizeof(ttl));

		/* Reserve space for rdlength. */
		rdlength_pos = q->iobufptr;
		QUERY_WRITE(q, &rdlength, sizeof(rdlength));

		for (j = 0; !rdata_atom_is_terminator(rrset->rrs[i][j]); ++j) {
			if (rdata_atom_is_domain(rrset->type, j)) {
				generate_dname(q, rdata_atom_domain(rrset->rrs[i][j]));
			} else {
				QUERY_WRITE(q,
					    rdata_atom_data(rrset->rrs[i][j]),
					    rdata_atom_size(rrset->rrs[i][j]));
			}
		}

		if (!q->overflow) {
			++added;
			rdlength = htons(q->iobufptr - rdlength_pos - sizeof(rdlength));
			memcpy(rdlength_pos, &rdlength, sizeof(rdlength));
		} else {
			q->overflow = 0;
			q->iobufptr = truncation_point;
			query_clear_dname_offsets(q, compressed_dname_count);
			if (truncate) {
				/* Truncate entire RRset and set truncate flag.  */
				TC_SET(q);
				added = 0;
			}
			break;
		}
	}

	(*count) += added;
}

static void
generate_answer(struct query *q)
{
	uint16_t counts[ADDITIONAL_SECTION + 1];
	answer_section_type section;
	size_t i;

	for (section = ANSWER_SECTION; section <= ADDITIONAL_SECTION; ++section) {
		counts[section] = 0;
		for (i = 0; i < q->answer.rrset_count; ++i) {
			if (q->answer.section[i] == section) {
				int truncate = (section == ANSWER_SECTION
						|| section == AUTHORITY_SECTION);
				generate_rrset(q, &counts[section],
					       q->answer.domains[i],
					       q->answer.rrsets[i],
					       truncate);
			}
		}
	}

	ANCOUNT(q) = htons(counts[ANSWER_SECTION]);
	NSCOUNT(q) = htons(counts[AUTHORITY_SECTION]);
	ARCOUNT(q) = htons(counts[ADDITIONAL_SECTION]);
}


static void
answer_query(struct nsd *nsd, struct query *q)
{
	domain_type *closest_match;
	domain_type *closest_encloser;
	domain_type *match;
	domain_type *temp;
	uint16_t offset;
	int exact;
	size_t i;
	
	exact = namedb_lookup(nsd->db, q->name, &closest_match, &closest_encloser);

	q->zone = domain_find_zone(closest_encloser);
	if (!q->zone) {
		RCODE_SET(q, RCODE_SERVFAIL);
		return;
	}

	q->delegation_domain = domain_find_ns_rrsets(
		closest_encloser, q->zone, &q->delegation_rrset);

	offset = dname_label_offsets(q->name)[closest_encloser->dname->label_count - 1] + QHEADERSZ;
	for (temp = closest_encloser; temp->parent; temp = temp->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 1,
		      (stderr, "query dname: %s, number: %lu, offset: %u\n",
		       dname_to_string(temp->dname),
		       (unsigned long) temp->number,
		       offset));
		query_put_dname_offset(q, temp, offset);
		offset += label_length(dname_name(temp->dname)) + 1;
	}

	if (!closest_encloser->is_existing) {
		exact = 0;
		while (!closest_encloser->is_existing)
			closest_encloser = closest_encloser->parent;
	}

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

	if (q->delegation_domain) {
		/* Delegation.  */
		answer_delegation(q);
	} else {
		/* Authorative zone.  */
		if (match) {
			answer_domain(q, match);
		} else {
			RCODE_SET(q, RCODE_NXDOMAIN);
			answer_soa(q);
		}
	}

	generate_answer(q);

	for (i = 0; i < q->dname_stored_count; ++i) {
		q->dname_offsets[q->dname_stored[i]->number] = 0;
	}
	q->dname_stored_count = 0;
}


/*
 * Processes the query, returns 0 if successfull, 1 if AXFR has been initiated
 * -1 if the query has to be silently discarded.
 *
 */
int 
query_process (struct query *q, struct nsd *nsd)
{
	/* The query... */
	uint8_t *qname;
	uint8_t *qptr;
	int recursion_desired;
	int axfr;

	/* Sanity checks */
	if (QR(q))
		return -1;	/* Not a query? Drop it on the floor. */

	/* Account the OPCODE */
	STATUP2(nsd, opcode, OPCODE(q));

	if (answer_notify(q)) {
		return 0;
	}

	/* Dont bother to answer more than one question at once... */
	if (ntohs(QDCOUNT(q)) != 1 || TC(q)) {
		*(uint16_t *)(q->iobuf + 2) = 0;

		query_formerr(q);
		return 0;
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
		return 0;
	}

	qname = q->iobuf + QHEADERSZ;
	
	/* Update the type and class */
	STATUP2(nsd, qtype, q->type);
	STATUP2(nsd, qclass, q->class);

	/* Dont allow any records in the answer or authority section... */
	if (ANCOUNT(q) != 0 || NSCOUNT(q) != 0) {
		query_formerr(q);
		return 0;
	}

	if (!process_edns(q, qptr)) {
		return 0;
	}

	/* Do we have any trailing garbage? */
	if (qptr != q->iobufptr) {
#ifdef	STRICT_MESSAGE_PARSE
		/* If we're strict.... */
		query_formerr(q);
		return 0;
#else
		/* Otherwise, strip it... */
		q->iobufptr = qptr;
#endif
	}

	if (answer_chaos(nsd, q)) {
		return 0;
	}

	if (answer_axfr_ixfr(nsd, q, qname, &axfr)) {
		return axfr;
	}

	answer_query(nsd, q);

	return 0;
}

void
query_addedns(struct query *q, struct nsd *nsd) {
	switch (q->edns) {
	case 1:	/* EDNS(0) packet... */
		q->maxlen += OPT_LEN;
		QUERY_WRITE(q, nsd->edns.opt_ok, OPT_LEN);
		ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);

		STATUP(nsd, edns);
		break;
	case -1: /* EDNS(0) error... */
		q->maxlen += OPT_LEN;
		QUERY_WRITE(q, nsd->edns.opt_err, OPT_LEN);
		ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);

		STATUP(nsd, ednserr);
		break;
	}
}
