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

#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* LIBWRAP */

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
query_axfr (struct query *q, struct nsd *nsd, const uint8_t *qname, const uint8_t *zname, int depth)
{
	/* Per AXFR... */
	static uint8_t zone[MAXDOMAINLEN + 1];
	static const struct answer *soa;
	static const struct domain *d = NULL;

	const struct answer *a;
	const uint8_t *dname;
	uint8_t *qptr;

	STATUP(nsd, raxfr);

	/* Is it new AXFR? */
	if(qname) {
		/* New AXFR... */
		memcpy(zone, zname, *zname + 1);

		/* Do we have the SOA? */
		if(NAMEDB_TSTBITMASK(nsd->db, NAMEDB_AUTHMASK, depth)
			&& (d = namedb_lookup(nsd->db, zname)) != NULL
				&& (soa = namedb_answer(d, htons(TYPE_SOA))) != NULL) {

			/* We'd rather have ANY than SOA to improve performance */
			if((a = namedb_answer(d, htons(TYPE_ANY))) == NULL) {
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
	if(d == NULL) {
		return 0;	/* Done. */
	}

	/* Let get next domain */
	do {
		dname = (const uint8_t *)d + d->size;
		d = (const struct domain *)(dname + ALIGN_UP(*dname + 1, NAMEDB_ALIGNMENT));
	} while(*dname && (DOMAIN_FLAGS(d) & NAMEDB_STEALTH));

	/* End of the database or end of zone? */
	if(*dname == 0 || namedb_answer(d, htons(TYPE_SOA)) != NULL) {
		/* Prepare to send the terminating SOA record */
		a = soa;
		dname = zone;
		d = NULL;
	} else {
		/* Prepare the answer */
		if(DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
			a = namedb_answer(d, htons(TYPE_NS));
		} else {
			a = namedb_answer(d, htons(TYPE_ANY));
		}
	}

	/* Existing AXFR, strip the question section off... */
	q->iobufptr = q->iobuf + QHEADERSZ;

	/* Is the first dname a pointer? */
	if(ANSWER_PTRS(a, 0) == 0) {
		/* XXX Very interesting math... Can you figure it? I cant anymore... */
		q->iobufptr += *dname - 2;
		QDCOUNT(q) = ANCOUNT(q) = NSCOUNT(q) = ARCOUNT(q) = 0;
	}

	qptr = q->iobufptr;

	query_addanswer(q, q->iobuf + QHEADERSZ, a, 0);

	if(ANSWER_PTRS(a, 0) == 0) {
		memcpy(q->iobuf + QHEADERSZ, dname + 1, *dname);
	}

	/* Truncate */
	if(d && DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
		ANCOUNT(q) = htons(ntohs(NSCOUNT(q)) + ntohs(ARCOUNT(q)));
	} else {
		q->iobufptr = qptr + ANSWER_RRS(a, ntohs(ANCOUNT(q)));
	}

	ARCOUNT(q) = 0;
	NSCOUNT(q) = 0;

	/* More data... */
	return 1;
}

void 
query_init (struct query *q)
{
	q->addrlen = sizeof(q->addr);
	q->iobufsz = QIOBUFSZ;
	q->iobufptr = q->iobuf;
	q->maxlen = UDP_MAX_MESSAGE_LEN;
	q->edns = 0;
	q->tcp = 0;
#ifdef PLUGINS
	q->normalized_domain_name[0] = '\0';
	q->plugin_data = NULL;
#endif /* PLUGINS */
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
	if(dname >= q->iobuf  && dname <= q->iobufptr) {
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

void 
query_addanswer (struct query *q, const uint8_t *dname, const struct answer *a, int trunc)
{
	uint8_t *qptr;
	uint16_t pointer;
	int  i, j;

	/* Check that the answer fits into our query buffer... */
	if(ANSWER_DATALEN(a) > QUERY_AVAILABLE_SIZE(q)) {
		log_msg(LOG_ERR, "the answer in the database is larger then the query buffer");
		RCODE_SET(q, RCODE_SERVFAIL);
		return;
	}

	/* Copy the counters */
	ANCOUNT(q) = ANSWER_ANCOUNT(a);
	NSCOUNT(q) = ANSWER_NSCOUNT(a);
	ARCOUNT(q) = ANSWER_ARCOUNT(a);

	/* Then copy the data */
	memcpy(q->iobufptr, ANSWER_DATA_PTR(a), ANSWER_DATALEN(a));

	/* Walk the pointers */
	for(j = 0; j < ANSWER_PTRSLEN(a); j++) {
		qptr = q->iobufptr + ANSWER_PTRS(a, j);
		memcpy(&pointer, qptr, 2);
		switch((pointer & 0xf000)) {
		case 0xc000:			/* This pointer is relative to the name in the query.... */
			/* XXX Check if dname is within packet */
			pointer = htons(0xc000 | (dname - q->iobuf + (pointer & 0x0fff)));/* dname - q->iobuf */
			break;
		case 0xd000:			/* This is the wildcard */
			pointer = htons(0xc00c);
			break;
		default:
			/* This pointer is relative to the answer that we have in the database... */
			pointer = htons(0xc000 | (uint16_t)(pointer + q->iobufptr - q->iobuf));
		}
		memcpy(qptr, &pointer, 2);
	}

	/* If we dont need truncation, return... */
	if(!trunc) {
		q->iobufptr += ANSWER_DATALEN(a);
		return;
	}

	/* Truncate if necessary */
	if(q->maxlen < QUERY_USED_SIZE(q) + ANSWER_DATALEN(a)) {

		/* Start with the additional section, record by record... */
		for(i = ntohs(ANSWER_ARCOUNT(a)), j = ANSWER_RRSLEN(a) - 1; i > 0 && j > 0; j--, i--) {
			if(q->maxlen >= QUERY_USED_SIZE(q) + ANSWER_RRS(a, j - 1)) {
				/* Make sure we remove the entire RRsets... */
				while(ANSWER_RRS_COLOR(a, j - 1) == ANSWER_RRS_COLOR(a, j - 2)) {
					j--; i--;
				}
				ARCOUNT(q) = htons(i-1);
				q->iobufptr += ANSWER_RRS(a, j - 1);
				return;
			}
		}

		ARCOUNT(q) = htons(0);
		TC_SET(q);

		if(q->maxlen >= QUERY_USED_SIZE(q) + ANSWER_RRS(a, j - ntohs(a->nscount) - 1)) {
			/* Truncate the athority section */
			NSCOUNT(q) = htons(0);
			q->iobufptr += ANSWER_RRS(a, j - ntohs(a->nscount) - 1);
			return;
		}

		/* Send empty message */
		NSCOUNT(q) = 0;
		ANCOUNT(q) = 0;

		return;
	} else {
		q->iobufptr += ANSWER_DATALEN(a);
	}
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
process_query_section(struct query *query,
		      uint8_t *domain_name, int *label_count,
		      uint16_t *query_type, uint16_t *query_class)
{
	uint8_t *dst = domain_name + 1;
	uint8_t *query_name = query->iobuf + QHEADERSZ;
	uint8_t *src = query_name;
	size_t i;
	size_t len;
	
	/* Lets parse the query name and convert it to lower case.  */
	*label_count = 0;
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
		++(*label_count);
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

	*domain_name = len;

	memcpy(query_type, src, sizeof(uint16_t));
	memcpy(query_class, src + sizeof(uint16_t), sizeof(uint16_t));
	
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
	if(ARCOUNT(q) > 0) {
		/* Only one opt is allowed... */
		if(ntohs(ARCOUNT(q)) != 1) {
			query_formerr(q);
			return 0;
		}

		/* Must have root owner name... */
		if(*qptr != 0) {
			query_formerr(q);
			return 0;
		}

		/* Must be of the type OPT... */
		memcpy(&opt_type, qptr + 1, 2);
		if(ntohs(opt_type) != TYPE_OPT) {
			query_formerr(q);
			return 0;
		}

		/* Ok, this is EDNS(0) packet... */
		q->edns = 1;

		/* Get the UDP size... */
		memcpy(&opt_class, qptr + 3, 2);
		opt_class = ntohs(opt_class);

		/* Check the version... */
		if(*(qptr + 6) != 0) {
			q->edns = -1;
		} else {
			/* Make sure there are no other options... */
			memcpy(&opt_rdlen, qptr + 9, 2);
			if(opt_rdlen != 0) {
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

#ifdef	STRICT_MESSAGE_PARSE
				/* Trailing garbage? */
				if((qptr + OPT_LEN) != q->iobufptr) {
					q->edns = 0;
					query_formerr(q);
					return 0;
				}
#endif

				/* Strip the OPT resource record off... */
				q->iobufptr = qptr;
				ARCOUNT(q) = 0;
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


/*
 * Answer if this is a delegation.
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_delegation(struct query *query, struct domain *domain, const uint8_t *qname)
{
	if (DOMAIN_FLAGS(domain) & NAMEDB_DELEGATION) {
		const struct answer *answer = namedb_answer(domain, htons(TYPE_NS));
		
		if (answer) {
			RCODE_SET(query, RCODE_OK);
			AA_CLR(query);
			query_addanswer(query, qname, answer, 1);
		} else {
			RCODE_SET(query, RCODE_SERVFAIL);
		}
		return 1;
	}
	return 0;
}


/*
 * Answer if we have data for this domain and qtype (or TYPE_CNAME).
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_domain(struct query *q,
	      struct domain *d,
	      const uint8_t *qname,
	      uint16_t qclass,
	      uint16_t qtype)
{
	const struct answer *a;
	uint8_t *qptr;
	
	if(((a = namedb_answer(d, qtype)) != NULL) ||	/* The query type? */
	   ((a = namedb_answer(d, htons(TYPE_CNAME))) != NULL)) { /* Or CNAME? */
		if(ntohs(qclass) != CLASS_ANY) {
			query_addanswer(q, qname, a, 1);
			AA_SET(q);
			return 1;
		}
		/* Class ANY */
		AA_CLR(q);
		
		/* Setup truncation */
		qptr = q->iobufptr;
		
		query_addanswer(q, qname, a, 0);
		
		/* Truncate */
		NSCOUNT(q) = 0;
		ARCOUNT(q) = 0;
		q->iobufptr = qptr + ANSWER_RRS(a, ntohs(ANCOUNT(q)));
		
		return 1;
	}
	return 0;
}


/*
 * Answer if we have SOA data for this domain.
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_soa(struct query *q,
	   struct domain *d,
	   const uint8_t *qname,
	   uint16_t qclass)
{
	const struct answer *a;
	uint8_t *qptr;
	
	/* Do we have SOA record in this domain? */
	if((a = namedb_answer(d, htons(TYPE_SOA))) != NULL) {
				
		if(ntohs(qclass) != CLASS_ANY) {
			AA_SET(q);
					
			/* Setup truncation */
			qptr = q->iobufptr;
					
			query_addanswer(q, qname, a, 0);
					
			/* Truncate */
			ANCOUNT(q) = 0;
			NSCOUNT(q) = htons(1);
			ARCOUNT(q) = 0;
			if(ANSWER_RRSLEN(a) > 1)
				q->iobufptr = qptr + ANSWER_RRS(a, 1);
				
		} else {
			AA_CLR(q);
		}
				
		return 1;
	}
	return 0;
}


/*
 * Answer if this is a query in the CHAOS class or in a class not
 * supported by NSD.
 *
 * Return 1 if answered, 0 otherwise.
 */
static int
answer_chaos(struct nsd *nsd,
	     struct query *q,
	     const uint8_t *qnamelow, uint8_t qnamelen,
	     uint16_t qclass,
	     uint16_t qtype)
{
	switch(ntohs(qclass)) {
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
	switch(ntohs(qtype)) {
	case TYPE_ANY:
	case TYPE_TXT:
		if(qnamelen == 11 && memcmp(qnamelow, "\002id\006server", 11) == 0) {
			/* Add ID */
			query_addtxt(q, q->iobuf + 12, CLASS_CHAOS, 0, nsd->identity);
			ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
			return 1;
		} else if(qnamelen == 16 && memcmp(qnamelow, "\007version\006server", 16) == 0) {
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
answer_axfr_ixfr(struct nsd *nsd,
		 struct query *q,
		 const uint8_t *qnamelow,
		 const uint8_t *qname,
		 int qdepth,
		 uint16_t qtype,
		 int *is_axfr)
{
	/* Is it AXFR? */
	switch(ntohs(qtype)) {
	case TYPE_AXFR:
#ifndef DISABLE_AXFR		/* XXX Should be a run-time flag */
		if(q->tcp) {
#ifdef LIBWRAP
			struct request_info request;
#ifdef AXFR_DAEMON_PREFIX
			const uint8_t *qptr = qnamelow;
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
			if(!hosts_access(&request)) {
#ifdef AXFR_DAEMON_PREFIX
				request_init(&request, RQ_DAEMON, axfr_daemon, RQ_CLIENT_SIN, &q->addr, 0);
				sock_methods(&request);	/* This is to work around the bug in libwrap */
				log_msg(LOG_ERR, "checking %s", axfr_daemon);
				if(!hosts_access(&request)) {
#endif /* AXFR_DAEMON_PREFIX */
					RCODE_SET(q, RCODE_REFUSE);
					return 1;
#ifdef AXFR_DAEMON_PREFIX
				}
#endif /* AXFR_DAEMON_PREFIX */
			}
#endif /* LIBWRAP */
			*is_axfr = query_axfr(q, nsd, qname, qnamelow - 1, qdepth);
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


static int
answer_query(struct nsd *nsd,
	     struct query *q,
	     uint8_t *qnamelow,
	     const uint8_t *qname,
	     uint8_t qnamelen,
	     int qdepth,
	     uint16_t qclass,
	     uint16_t qtype)
{
	const uint8_t qstar[2] = "\001*";
	struct domain *d;
	int match;
	
	/* BEWARE: THE RESOLVING ALGORITHM STARTS HERE */

	/* Do we have complete name? */
	if (NAMEDB_TSTBITMASK(nsd->db, NAMEDB_DATAMASK, qdepth) &&
	    ((d = namedb_lookup(nsd->db, qnamelow - 1)) != NULL))
	{
		if (answer_delegation(q, d, qname) ||
		    answer_domain(q, d, qname, qclass, qtype) ||
		    answer_soa(q, d, qname, qclass))
		{
#ifdef PLUGINS
			q->plugin_data = d->runtime_data;
#endif /* PLUGINS */
			return 1;
		}

		/* We have a partial match */
		match = 1;
	} else {
		/* Set this if we find SOA later */
		RCODE_SET(q, RCODE_NXDOMAIN);
		match = 0;
	}

	/* Start matching down label by label */
	do {
		/* Strip leftmost label */
		qnamelen -= (*qname + 1);
		qname += (*qname + 1);
		qnamelow += (*qnamelow + 1);

		qdepth--;
		/* Only look for wildcards if we did not have any match before */
		if(match == 0 && NAMEDB_TSTBITMASK(nsd->db, NAMEDB_STARMASK, qdepth + 1)) {
			/* Prepend star */
			memcpy(qnamelow - 2, qstar, 2);

			/* Lookup star */
			*(qnamelow - 3) = qnamelen + 2;
			if((d = namedb_lookup(nsd->db, qnamelow - 3)) != NULL) {
				/* We found a domain... */
				RCODE_SET(q, RCODE_OK);

				if (answer_domain(q, d, qname - 2, qclass, qtype)) {
#ifdef PLUGINS
					q->plugin_data = d->runtime_data;
#endif /* PLUGINS */
					return 1;
				}
			}
		}

		/* Do we have a SOA or zone cut? */
		*(qnamelow - 1) = qnamelen;
		if(NAMEDB_TSTBITMASK(nsd->db, NAMEDB_AUTHMASK, qdepth) && ((d = namedb_lookup(nsd->db, qnamelow - 1)) != NULL)) {
			if (answer_delegation(q, d, qname) ||
			    answer_soa(q, d, qname, qclass))
			{
#ifdef PLUGINS
				q->plugin_data = d->runtime_data;
#endif /* PLUGINS */
				return 1;
			}

			/* We found some data, so dont try to match the wildcards anymore... */
			match = 1;
		}

	} while(*qname);

	return 0;
}


/*
 * Processes the query, returns 0 if successfull, 1 if AXFR has been initiated
 * -1 if the query has to be silently discarded.
 *
 */
int 
query_process (struct query *q, struct nsd *nsd)
{
	uint8_t qnamebuf[MAXDOMAINLEN + 3];

	/* The query... */
	uint8_t	*qname, *qnamelow;
	uint8_t qnamelen;
	uint16_t qtype;
	uint16_t qclass;
	uint8_t *qptr;
	int qdepth;
	int recursion_desired;
	int axfr;

	/* Sanity checks */
	if(QR(q))
		return -1;	/* Not a query? Drop it on the floor. */

	/* Account the OPCODE */
	STATUP2(nsd, opcode, OPCODE(q));

	if (answer_notify(q)) {
		return 0;
	}

	/* Dont bother to answer more than one question at once... */
	if(ntohs(QDCOUNT(q)) != 1 || TC(q)) {
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
	qptr = process_query_section(q, qnamebuf + 2, &qdepth, &qtype, &qclass);
	if (!qptr) {
		return 0;
	}
	qnamelow = qnamebuf + 3;
	qnamelen = qnamebuf[2];

#ifdef PLUGINS
	/* Save the normalized domain name for plugins.  */
	memcpy(q->normalized_domain_name, qnamelow - 1, qnamelen + 1);
#endif /* PLUGINS */

	qname = q->iobuf + QHEADERSZ;
	
	/* Update the type and class */
	STATUP2(nsd, qtype, ntohs(qtype));
	STATUP2(nsd, qclass, ntohs(qclass));

	/* Dont allow any records in the answer or authority section... */
	if(ANCOUNT(q) != 0 || NSCOUNT(q) != 0) {
		query_formerr(q);
		return 0;
	}

	if (!process_edns(q, qptr)) {
		return 0;
	}

	/* Do we have any trailing garbage? */
	if(qptr != q->iobufptr) {
#ifdef	STRICT_MESSAGE_PARSE
		/* If we're strict.... */
		query_formerr(q);
		return 0;
#else
		/* Otherwise, strip it... */
		q->iobufptr = qptr;
#endif
	}

	if (answer_chaos(nsd, q, qnamelow, qnamelen, qclass, qtype)) {
		return 0;
	}

	if (answer_axfr_ixfr(nsd, q, qnamelow, qname, qdepth, qtype, &axfr)) {
		return axfr;
	}

	if (answer_query(nsd, q, qnamelow, qname, qnamelen, qdepth, qclass, qtype)) {
		return 0;
	}

	RCODE_SET(q, RCODE_SERVFAIL);

	/* We got a query for the zone we dont have */
	STATUP(nsd, wrongzone);

	return 0;
}

void
query_addedns(struct query *q, struct nsd *nsd) {
	switch(q->edns) {
	case 1:	/* EDNS(0) packet... */
		if (OPT_LEN <= QUERY_AVAILABLE_SIZE(q)) {
			QUERY_WRITE(q, nsd->edns.opt_ok, OPT_LEN);
			ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);
		}

		STATUP(nsd, edns);
		break;
	case -1: /* EDNS(0) error... */
		if (OPT_LEN <= QUERY_AVAILABLE_SIZE(q)) {
			QUERY_WRITE(q, nsd->edns.opt_err, OPT_LEN);
			ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);
		}

		STATUP(nsd, ednserr);
		break;
	}
}
