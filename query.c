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
#include <netdb.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include <dns.h>
#include <dname.h>
#include <nsd.h>
#include <namedb.h>
#include <query.h>


#ifdef LIBWRAP
#include <tcpd.h>

int allow_severity = LOG_INFO;
int deny_severity = LOG_NOTICE;
#endif /* LIBWRAP */

int 
query_axfr (struct query *q, struct nsd *nsd, u_char *qname, u_char *zname, int depth)
{
	/* Per AXFR... */
	static u_char *zone;
	static struct answer *soa;
	static struct domain *d = NULL;

	struct answer *a;
	u_char *dname;
	u_char *qptr;

	STATUP(nsd, raxfr);

	/* Is it new AXFR? */
	if(qname) {
		/* New AXFR... */
		zone = zname;

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
		dname = (u_char *)d + *((u_int32_t *)d);
		d = (struct domain *)(dname + (((u_int32_t)*dname + 1 + 3) & 0xfffffffc));
	} while(*dname && (DOMAIN_FLAGS(d) & NAMEDB_STEALTH));

	/* End of the database or end of zone? */
	if(*dname == 0 || namedb_answer(d, htons(TYPE_SOA)) != NULL) {
		/* Prepare to send the terminating SOA record */
		a = soa;
		dname = zone;
		d = NULL;
		zone = NULL;
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

/*
 * Stript the packet and set format error code.
 *
 */
void 
query_formerr (struct query *q)
{
	/* Setup the header... */
	QR_SET(q);		/* This is an answer */

	RCODE_SET(q, RCODE_FORMAT);

	/* Truncate the question as well... */
	QDCOUNT(q) = ANCOUNT(q) = NSCOUNT(q) = ARCOUNT(q) = 0;
	q->iobufptr = q->iobuf + QHEADERSZ;
}

void 
query_init (struct query *q)
{
	q->addrlen = sizeof(q->addr);
	q->iobufsz = QIOBUFSZ;
	q->iobufptr = q->iobuf;
	q->maxlen = 512;	/* XXX Should not be here */
	q->edns = 0;
	q->tcp = 0;
}

void 
query_addtxt (struct query *q, u_char *dname, int class, int32_t ttl, const char *txt)
{
	u_int16_t pointer;
	u_int16_t len = strlen(txt);
	u_int16_t rdlength = htons(len + 1);
	u_int16_t type = htons(TYPE_TXT);

	ttl = htonl(ttl);
	class = htons(class);

	/* Add the dname */
	if(dname >= q->iobuf  && dname <= q->iobufptr) {
		pointer = htons(0xc000 | (dname - q->iobuf));
		memcpy(q->iobufptr, &pointer, 2);
		q->iobufptr += 2;
	} else {
		memcpy(q->iobufptr, dname + 1, *dname);
		q->iobufptr += *dname;
	}

	memcpy(q->iobufptr, &type, 2);
	q->iobufptr += 2;

	memcpy(q->iobufptr, &class, 2);
	q->iobufptr += 2;

	memcpy(q->iobufptr, &ttl, 4);
	q->iobufptr += 4;

	memcpy(q->iobufptr, &rdlength, 2);
	q->iobufptr += 2;

	*q->iobufptr++ = (u_char)len;

	memcpy(q->iobufptr, txt, len);
	q->iobufptr += len;
}

void 
query_addanswer (struct query *q, const u_char *dname, struct answer *a, int trunc)
{
	u_char *qptr;
	u_int16_t pointer;
	int  i, j;

	/* Check that the answer fits into our query buffer... */
	if(ANSWER_DATALEN(a) > (q->iobufptr - q->iobuf + q->iobufsz)) {
		syslog(LOG_ERR, "the answer in the database is larger then the query buffer");
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
			pointer = htons(0xc000 | (u_int16_t)(pointer + q->iobufptr - q->iobuf));
		}
		memcpy(qptr, &pointer, 2);
	}

	/* If we dont need truncation, return... */
	if(!trunc) {
		q->iobufptr += ANSWER_DATALEN(a);
		return;
	}

	/* Truncate if necessary */
	if(q->maxlen < (q->iobufptr - q->iobuf + ANSWER_DATALEN(a))) {

		/* Start with the additional section, record by record... */
		for(i = ntohs(ANSWER_ARCOUNT(a)), j = ANSWER_RRSLEN(a) - 1; i > 0 && j > 0; j--, i--) {
			if(q->maxlen >= (q->iobufptr - q->iobuf + ANSWER_RRS(a, j - 1))) {
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

		if(q->maxlen >= (q->iobufptr - q->iobuf + ANSWER_RRS(a, j - ntohs(a->nscount) - 1))) {
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
static u_char *
process_query_section(struct query *query,
		      u_char *domain_name, int *label_count,
		      u_int16_t *query_type, u_int16_t *query_class)
{
	u_char *dst = domain_name + 1;
	u_char *query_name = query->iobuf + QHEADERSZ;
	u_char *src = query_name;
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
		if ((*src & 0xc0) || (src + *src > query->iobufptr) || 
		    ((src - query->iobuf + *src) > MAXDOMAINLEN)) {
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
	if (len > MAXDOMAINLEN || (src + 2*sizeof(u_int16_t) > query->iobufptr)) {
		query_formerr(query);
		return NULL;
	}

	*domain_name = len;

	memcpy(query_type, src, sizeof(u_int16_t));
	memcpy(query_class, src + sizeof(u_int16_t), sizeof(u_int16_t));
	
	return src + 2*sizeof(u_int16_t);
}


/*
 *
 */
static void
process_delegation(struct query *query, const u_char *qname, struct domain *domain)
{
	struct answer *answer = namedb_answer(domain, htons(TYPE_NS));

	if (answer) {
		RCODE_SET(query, RCODE_OK);
		AA_CLR(query);
		query_addanswer(query, qname, answer, 1);
	} else {
		RCODE_SET(query, RCODE_SERVFAIL);
	}
}



static void
process_other (struct query *q)
{
	QR_SET(q);
	RCODE_SET(q, RCODE_IMPL);
	
	/* Truncate the question as well... */
	QDCOUNT(q) = ANCOUNT(q) = NSCOUNT(q) = ARCOUNT(q) = 0;
	q->iobufptr = q->iobuf + QHEADERSZ;
}

/*
 * Log notifies and return an RCODE_IMPL error to the client.
 *
 * XXX: erik: Is this the right way to handle notifies?
 */
static void
process_notify (struct query *query)
{
	char namebuf[BUFSIZ];

	assert(OPCODE(query) == OPCODE_NOTIFY);
	
	if (getnameinfo((struct sockaddr *) &(query->addr),
			query->addrlen, namebuf, sizeof(namebuf), 
			NULL, 0, NI_NUMERICHOST)
	    != 0)
	{
		syslog(LOG_INFO, "notify from unknown remote address");
	} else {
		syslog(LOG_INFO, "notify from %s", namebuf);
	}

	process_other (query);
}

/*
 * Processes the query, returns 0 if successfull, 1 if AXFR has been initiated
 * -1 if the query has to be silently discarded.
 *
 */
int 
query_process (struct query *q, struct nsd *nsd)
{
	u_char qstar[2] = "\001*";
	u_char qnamebuf[MAXDOMAINLEN + 3];

	/* The query... */
	u_char	*qname, *qnamelow;
	u_char qnamelen;
	u_int16_t qtype;
	u_int16_t qclass;
	u_char *qptr;
	int qdepth;
	int recursion_desired;

	/* OPT record type... */
	u_int16_t opt_type, opt_class, opt_rdlen;

	struct domain *d;
	struct answer *a;
	int match;

	/* Sanity checks */
	if(QR(q))
		return -1;	/* Not a query? Drop it on the floor. */

	/* Account the OPCODE */
	STATUP2(nsd, opcode, OPCODE(q));

	/* Do we serve this type of query */
	switch (OPCODE(q)) {
	case OPCODE_QUERY:
		break;		/* Handled below. */
	case OPCODE_NOTIFY:
		process_notify(q);
		return 0;
	default:
		process_other(q);
		return 0;
	}

	/* Dont bother to answer more than one question at once... */
	if(ntohs(QDCOUNT(q)) != 1 || TC(q)) {
		*(u_int16_t *)(q->iobuf + 2) = 0;

		query_formerr(q);
		return 0;
	}

	/* Save the RD flag (RFC1034 4.1.1).  */
	recursion_desired = RD(q);

	/* Zero the flags... */
	*(u_int16_t *)(q->iobuf + 2) = 0;
	
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

	qname = q->iobuf + QHEADERSZ;
	
	/* Update the type and class */
	STATUP2(nsd, qtype, ntohs(qtype));
	STATUP2(nsd, qclass, ntohs(qclass));

	/* Dont allow any records in the answer or authority section... */
	if(ANCOUNT(q) != 0 || NSCOUNT(q) != 0) {
		query_formerr(q);
		return 0;
	}

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
				if(opt_class > 512) {
					/* XXX Configuration parameter to limit the size needs to be here... */
					if(opt_class < q->iobufsz) {
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

	/* Unsupported class */
	switch(ntohs(qclass)) {
	case CLASS_IN:
	case CLASS_ANY:
		break;
	case CLASS_CHAOS:
		AA_CLR(q);
		switch(ntohs(qtype)) {
		case TYPE_ANY:
		case TYPE_TXT:
			if(qnamelen == 11 && memcmp(qnamelow, "\002id\006server", 11) == 0) {
				/* Add ID */
				query_addtxt(q, q->iobuf + 12, CLASS_CHAOS, 0, nsd->identity);
				ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
				return 0;
			} else if(qnamelen == 16 && memcmp(qnamelow, "\007version\006server", 16) == 0) {
				/* Add version */
				query_addtxt(q, q->iobuf + 12, CLASS_CHAOS, 0, nsd->version);
				ANCOUNT(q) = htons(ntohs(ANCOUNT(q)) + 1);
				return 0;
			}
			break;
		}
	default:
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	/* Is it AXFR? */
	switch(ntohs(qtype)) {
	case TYPE_AXFR:
#ifndef DISABLE_AXFR		/* XXX Should be a run-time flag */
		if(q->tcp) {
#ifdef LIBWRAP
			struct request_info request;
#ifdef AXFR_DAEMON_PREFIX
			char *t;
			char axfr_daemon[MAXDOMAINLEN + sizeof(AXFR_DAEMON_PREFIX)];

			memcpy(axfr_daemon, AXFR_DAEMON_PREFIX, sizeof(AXFR_DAEMON_PREFIX));

			/* Copy the qname as a string */
			for(t = axfr_daemon + sizeof(AXFR_DAEMON_PREFIX) - 1,
					qptr = qnamelow; *qptr; t += *qptr, *t++ = '.', qptr += *qptr + 1) {
				memcpy(t, qptr + 1, *qptr);
				
			}
			*t = 0;
			
#endif /* AXFR_DAEMON_PREFIX */
			request_init(&request, RQ_DAEMON, AXFR_DAEMON, RQ_CLIENT_SIN, &q->addr, 0);
			sock_methods(&request);	/* This is to work around the bug in libwrap */
			if(!hosts_access(&request)) {
#ifdef AXFR_DAEMON_PREFIX
				request_init(&request, RQ_DAEMON, axfr_daemon, RQ_CLIENT_SIN, &q->addr, 0);
				sock_methods(&request);	/* This is to work around the bug in libwrap */
				syslog(LOG_ERR, "checking %s", axfr_daemon);
				if(!hosts_access(&request)) {
#endif /* AXFR_DAEMON_PREFIX */
					RCODE_SET(q, RCODE_REFUSE);
					return 0;
#ifdef AXFR_DAEMON_PREFIX
				}
#endif /* AXFR_DAEMON_PREFIX */
			}
#endif /* LIBWRAP */
			return query_axfr(q, nsd, qname, qnamelow - 1, qdepth);
		}
#endif	/* DISABLE_AXFR */
	case TYPE_IXFR:
		RCODE_SET(q, RCODE_REFUSE);
		return 0;
	}

	/* BEWARE: THE RESOLVING ALGORITHM STARTS HERE */

	/* Do we have complete name? */
	if(NAMEDB_TSTBITMASK(nsd->db, NAMEDB_DATAMASK, qdepth) &&
		((d = namedb_lookup(nsd->db, qnamelow - 1)) != NULL)) {
		/* Is this a delegation point? */
		if(DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
			process_delegation(q, qname, d);
			return 0;
		} else {
			if(((a = namedb_answer(d, qtype)) != NULL) ||	/* The query type? */
				((a = namedb_answer(d, htons(TYPE_CNAME))) != NULL)) { /* Or CNAME? */
				if(ntohs(qclass) != CLASS_ANY) {
					query_addanswer(q, qname, a, 1);
					AA_SET(q);
					return 0;
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

				return 0;
			} else {
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

					return 0;
				}

				/* We have a partial match */
				match = 1;
			}
		}
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

				if(((a = namedb_answer(d, qtype)) != NULL) ||
				 ((a = namedb_answer(d, htons(TYPE_CNAME))) != NULL)) {
					if(ntohs(qclass) != CLASS_ANY) {
						AA_SET(q);
						query_addanswer(q, qname - 2, a, 1);
						return 0;
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

					return 0;
				}
			}
		}

		/* Do we have a SOA or zone cut? */
		*(qnamelow - 1) = qnamelen;
		if(NAMEDB_TSTBITMASK(nsd->db, NAMEDB_AUTHMASK, qdepth) && ((d = namedb_lookup(nsd->db, qnamelow - 1)) != NULL)) {
			if(DOMAIN_FLAGS(d) & NAMEDB_DELEGATION) {
				process_delegation(q, qname, d);
				return 0;
			} else {
				if((a = namedb_answer(d, htons(TYPE_SOA)))) {

					if(ntohs(qclass) != CLASS_ANY) {
						/* Setup truncation */
						qptr = q->iobufptr;

						AA_SET(q);

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

					return 0;
				}
			}
			/* We found some data, so dont try to match the wildcards anymore... */
			match = 1;
		}

	} while(*qname);

	RCODE_SET(q, RCODE_SERVFAIL);

	/* We got a query for the zone we dont have */
	STATUP(nsd, wrongzone);

	return 0;
}

void
query_addedns(struct query *q, struct nsd *nsd) {
	switch(q->edns) {
	case 1:	/* EDNS(0) packet... */
		if((q->iobufptr - q->iobuf + OPT_LEN) <= q->iobufsz) {
			memcpy(q->iobufptr, nsd->edns.opt_ok, OPT_LEN);
			q->iobufptr += OPT_LEN;
			ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);
		}

		STATUP(nsd, edns);
		break;
	case -1: /* EDNS(0) error... */
		if((q->iobufptr - q->iobuf + OPT_LEN) <= q->iobufsz) {
			memcpy(q->iobufptr, nsd->edns.opt_err, OPT_LEN);
			q->iobufptr += OPT_LEN;
			ARCOUNT((q)) = htons(ntohs(ARCOUNT((q))) + 1);
		}

		STATUP(nsd, ednserr);
		break;
	}
}
