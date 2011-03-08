/*
 * pktd.c -- packet decompiler implementation.
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#include <ctype.h>
#include "pktd.h"
#include "pktc.h"
#include "query.h"
#include "nsd.h"

#define DEBUGPKTD(x, y, z) /* DEBUG(x, y, z) */

/** create a servfail */
static void
do_servfail(struct query* q)
{
	FLAGS_SET(q->packet, 0x8000U | (FLAGS(q->packet)&(0x0110U)));
	RCODE_SET(q->packet, RCODE_SERVFAIL);
	ANCOUNT_SET(q->packet, 0);
	NSCOUNT_SET(q->packet, 0);
	ARCOUNT_SET(q->packet, 0);
	buffer_set_position(q->packet, QHEADERSZ+dname_length(buffer_at(
		q->packet, QHEADERSZ))+4);
}

/** lookup entry in nametree and return exact, smaller, ce element */
static int
lookup(struct comptree* ct, uint8_t* qname, struct compname** match,
	struct compname** ce)
{
	struct radnode* n, *c;
	int exact = radname_find_less_equal(ct->nametree, qname,
		dname_length(qname), &n, &c);
	if(!n) {
		*match = NULL;
		*ce = NULL;
		return 0;
	}
	*match = (struct compname*)n->elem;
	if(exact) {
		*ce = (struct compname*)n->elem;
	} else {
		/* TODO: RADIX_TEST to unit tests and test,invariants for ce */

		/* walk up radix tree until we find a parent name with
		 * an element */
		while(c) {
			if(c->elem) {
				*ce = (struct compname*)c->elem;
				return 0;
			}
			c = c->parent;
		}
		*ce = NULL;
	}
	return exact;
}

/** copy data and truncate message */
static void copy_and_truncate_adjust(struct query* q, struct cpkt* p,
	uint16_t qlen, uint16_t nlen, uint16_t adjust)
{
	unsigned t;
	uint16_t max = q->maxlen - q->reserved_space - adjust;
	/* TODO: could use bsearch here */
	for(t=0; t<p->numtrunc; t+=2) {
		if(p->truncpts[t] <= max) {
			ARCOUNT_SET(q->packet, p->truncpts[t+1]);
			memmove(buffer_at(q->packet, QHEADERSZ+qlen+4),
				p->data, p->truncpts[t]-QHEADERSZ-nlen-4);
			buffer_set_position(q->packet, p->truncpts[t]+adjust);
			return;
		}
	}
	/* does not fit, TC */
	ANCOUNT_SET(q->packet, 0);
	NSCOUNT_SET(q->packet, 0);
	ARCOUNT_SET(q->packet, 0);
	TC_SET(q->packet);
	buffer_set_position(q->packet, QHEADERSZ+qlen+4);
	/* memmove(buffer_at(q->packet, QHEADERSZ+qlen+4), p->data,
		q->maxlen-q->reserved_space-QHEADERSZ-qlen-4);
	buffer_set_position(q->packet, q->maxlen-q->reserved_space); */
	/* TODO: test TC replies, EDNS, cutoff points */
}

/** fill reply and adjust compression pointers */
static void fill_reply_adjust(struct query* q, struct cpkt* p)
{
	/* TODO better handle qlen */
	uint16_t qlen = dname_length(buffer_at(q->packet, QHEADERSZ));
	uint16_t adjust = qlen - p->qnamelen;
	uint16_t* ptr;
	if(!p) {
		do_servfail(q);
		return;
	}
	assert(qlen >= p->qnamelen);
	/* make sure the 'cutoff' is at a labelboundary, loose test,
	 * but 'A' and 'a' are bigger than 63 so catches most. */
	assert(buffer_read_u8_at(q->packet, QHEADERSZ+adjust) <= MAXLABELLEN);
	FLAGS_SET(q->packet, p->flagcode | (FLAGS(q->packet)&(0x0110U)));
	ANCOUNT_SET(q->packet, p->ancount);
	NSCOUNT_SET(q->packet, p->nscount);
	copy_and_truncate_adjust(q, p, qlen, p->qnamelen, adjust);
	/* if this packet has a serial number in a SOA RR, then copy the
	 * serial number from the zone into the packet.  So that after a
	 * zone change the nxdomains and nodata answers stay valid and only
	 * the serial number in the zone struct has to be changed.
	 * serial number is per-packet, because DS is from different zone */
	if(p->serial)
		buffer_write_u32_at(q->packet, p->serial_pos+adjust,
			*p->serial);
	/* this even adjusts outside of the truncation point, but we
	 * don't care.  Assume the buffer is large enough (64kb).  */
	for(ptr = p->ptrs; *ptr; ptr++) {
		buffer_write_u16_at(q->packet, (*ptr)+adjust, PTR_CREATE(
			buffer_read_u16_at(q->packet, (*ptr)+adjust)+adjust));
	}
}

/** find type or notype to return for dnssec_ok packet */
static void find_type_for_DO(struct query* q, struct compname* n)
{
	size_t i;
	DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "match DO"));
	/* find exact match for answer to query,qtype in answer section,
	 * or perhaps specific qtype DS different answer, also type ANY */
	for(i=0; i<n->typelen; i++) {
		/* TODO: could binary search here */
		if(n->types[i]->qtype == q->qtype) {
			/* since exact match, no adjustment necessary */
			fill_reply_adjust(q, n->types[i]);
			return;
		}
	}
	/* for referrals the referral.
	 * if NULL, use shared unsigned nodata answer */
	if(n->notype)
		fill_reply_adjust(q, n->notype);
	else	fill_reply_adjust(q, n->cz->nodata);
}

/** find type or notype to return for nonDO packet */
static void find_type_for_nonDO(struct query* q, struct compname* n)
{
	size_t i;
	DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "match nonDO"));
	/* answer specific type, ANY, or qtype DS */
	for(i=0; i<n->typelen_nondo; i++) {
		/* TODO: could binary search here */
		if(n->types_nondo[i]->qtype == q->qtype) {
			fill_reply_adjust(q, n->types_nondo[i]);
			return;
		}
	}
	/* the NSEC/NSEC3 nodata, or for referrals the referral.
	 * if NULL, unsigned zone, use shared unsigned nodata answer */
	if(n->notype_nondo)
		fill_reply_adjust(q, n->notype_nondo);
	else	fill_reply_adjust(q, n->cz->nodata);
}

/** synthesize CNAME. pkt is adjustable, contains DNAME (+RRSIGs) */
static void do_synth_cname(struct query* q, struct cpkt* p)
{
	uint16_t dstlen, reslen, srclen = p->qnamelen;
	uint16_t qlen = dname_length(buffer_at(q->packet, QHEADERSZ));
	size_t rpos, dstpos, srcpos = QHEADERSZ + qlen + 4;
	fill_reply_adjust(q, p);

	/* see how long the DNAME target is */
	/* the DNAME-src is compressed, so, name(2)+t(2)+c(2)+ttl(4)+2(rdata)*/
	dstpos = srcpos+2+2+2+4+2;
	/* handle (optional) compression pointer in the rdata of the DNAME */
	dstlen = pkt_dname_len_at(q->packet, dstpos);
	if(!dstlen) {
		do_servfail(q);
		return;
	}

	/* calculate result, now query bla.foo for    foo DNAME bar
	 * 'bla' to be replaced. */
	reslen = qlen - srclen + dstlen;
	if(reslen > MAXDOMAINLEN) {
		/* if result is too long, YXDOMAIN */
		/* send the DNAME along as proof */
		RCODE_SET(q->packet, RCODE_YXDOMAIN);
		return;
	}

	/* append CNAME, we can compress with qname and with DNAME rdata */
	buffer_set_position(q->packet, buffer_limit(q->packet));
	buffer_set_limit(q->packet, q->maxlen-q->reserved_space);
	if(buffer_remaining(q->packet) < 2+2+2+4+2+(size_t)(qlen-srclen)+2)
		/* n,t,c,ttl,rdatalen, prefix, ptr */
		goto errtc;
	buffer_write_u16(q->packet, PTR_CREATE(QHEADERSZ));
	buffer_write_u16(q->packet, TYPE_CNAME);
	buffer_write_u16(q->packet, CLASS_IN);
	buffer_write_u32(q->packet, 0); /* ttl */
	rpos = buffer_position(q->packet);
	buffer_write_u16(q->packet, 0); /* rdatalen of CNAME */
	buffer_write(q->packet, q->qname, qlen - srclen); /* copy front */
	/* copy compression pointer to DNAME rdata with destination */
	buffer_write_u16(q->packet, PTR_CREATE(dstpos));
	/* fixup rdata length */
	buffer_write_u16_at(q->packet, rpos, buffer_position(q->packet)-rpos);
	buffer_flip(q->packet);
	assert(p->nscount == 0 && ARCOUNT(q->packet) == 0);
	ANCOUNT_SET(q->packet, ANCOUNT(q->packet)+1);
	return;
errtc:
	TC_SET(q->packet);
	buffer_flip(q->packet);
}

/** based on the type of below, send packet, for DO query */
static void execute_below_DO(struct query* q, struct compname* n,
	struct compname* ce)
{
	DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "below_DO"));
	/* the below-closest-encloser is most specific (DNAME, wildcard,
	 * referral).  Also for NSEC3-denials.  If NULL, use side for NSEC. */
	if(ce->below) {
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "use ce->below"));
		if(ce->belowtype==BELOW_NORMAL) {
			fill_reply_adjust(q, ce->below);
		} else if(ce->belowtype==BELOW_NSEC3NX) {
			/* TODO */
		} else if(ce->belowtype==BELOW_WILDCARD) {
			find_type_for_DO(q, (struct compname*)ce->below);
		} else if(ce->belowtype==BELOW_SYNTHC) {
			do_synth_cname(q, ce->below);
		} else {
			log_msg(LOG_ERR, "internal error: bad btype");
			do_servfail(q);
		}
	} else if(n->side) {
		/* use (smallername)->side for NSEC denial */
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "use n->side"));
		fill_reply_adjust(q, n->side);
	} else {
		/* unsigned zone, use shared nxdomain packet */
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "use shared unsigned nx"));
		fill_reply_adjust(q, ce->cz->nx);
	}
}

/** based on the type of below, send packet, for nonDO query */
static void execute_below_nonDO(struct query* q, struct compname* ce)
{
	DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO, "below_nonDO"));
	/* the below pointer is filled for special processing, for
	 * referrals, wildcards, DNAME. otherwise, send shared nxdomain pkt */
	if(ce->below_nondo) {
		//log_msg(LOG_INFO, "use ce->below_nondo");
		if(ce->belowtype_nondo==BELOW_NORMAL) {
			fill_reply_adjust(q, ce->below_nondo);
		} else if(ce->belowtype_nondo==BELOW_WILDCARD) {
			find_type_for_nonDO(q,
				(struct compname*)ce->below_nondo);
		} else if(ce->belowtype_nondo==BELOW_SYNTHC) {
			do_synth_cname(q, ce->below_nondo);
		} else if(ce->belowtype_nondo==BELOW_NSEC3NX) {
			log_msg(LOG_ERR, "internal error: nsec3 in unsignedzn");
			do_servfail(q);
		} else {
			log_msg(LOG_ERR, "internal error: bad btype");
			do_servfail(q);
		}
	} else {
		/* use shared NXDOMAIN answer */
		fill_reply_adjust(q, ce->cz->nx);
	}
}

void pktd_answer_query(struct nsd* nsd, struct query* q)
{
	struct compname* n; /* the match, or the smaller */
	struct compname* ce; /* closest encloser */
	uint8_t* qname = buffer_at(q->packet, QHEADERSZ);
	if(lookup(nsd->db->tree, qname, &n, &ce)) {
		/* exact match, ce==n */
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"query %s exact", dname2str(qname)));
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"match=%s", n?dname2str(n->name):"NULL"));
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"ce=%s", ce?dname2str(ce->name):"NULL"));
		if(q->edns.dnssec_ok) {
			find_type_for_DO(q, n);
		} else {
			find_type_for_nonDO(q, n);
		}
		return;
	} else {
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"query %s nonexact", dname2str(qname)));
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"sme=%s", n?dname2str(n->name):"NULL"));
		DEBUGPKTD(DEBUG_QUERY, 2, (LOG_INFO,
			"ce=%s", ce?dname2str(ce->name):"NULL"));
		if(!n || !ce) {
			do_servfail(q); /* SERVFAIL (no zone, lame) */
			return;
		}
		/* inexact match, n is smaller, ce is above qname.
		 * The closest-encloser below is more important, only if
		 * its NULL, then the n->side has the NSEC */
		if(q->edns.dnssec_ok) {
			execute_below_DO(q, n, ce);
		} else {
			execute_below_nonDO(q, ce);
		}
	}
}
