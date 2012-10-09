
/* rrl.c - Response Rate Limiting for NSD.
 * By W.C.A. Wijngaards
 * Copyright 2012, NLnet Labs.
 * BSD, see LICENSE.
 */
#include "config.h"
#include <errno.h>
#include "rrl.h"
#include "util.h"
#include "lookup3.h"

#ifdef RATELIMIT

#ifdef HAVE_MMAP
#include <sys/mman.h>
#if defined(MAP_ANON) && !defined(MAP_ANONYMOUS)
#define MAP_ANONYMOUS   MAP_ANON
#endif
#endif /* HAVE_MMAP */


/**
 * The rate limiting data structure bucket, this represents one rate of
 * packets from a single source.
 * Smoothed average rates.
 */
struct rrl_bucket {
	/* the source netmask */
	uint64_t source;
	/* rate, in queries per second, which due to rate=r(t)+r(t-1)/2 is
	 * equal to double the queries per second */
	uint32_t rate;
	/* counter for queries arrived in this second */
	uint32_t counter;
	/* timestamp, which time is the time of the counter, the rate is from
	 * one timestep before that. */
	int32_t stamp;
};

/* the (global) array of RRL buckets */
static struct rrl_bucket* rrl_array = NULL;
static size_t rrl_array_size = RRL_BUCKETS;
static uint32_t rrl_ratelimit = 400; /* 2x qps, default is 200 qps */

/* the array of mmaps for the children (saved between reloads) */
static void** rrl_maps = NULL;
static size_t rrl_maps_num = 0;

void rrl_mmap_init(int numch, size_t numbuck)
{
#ifdef HAVE_MMAP
	size_t i;
#endif
	if(numbuck != 0)
		rrl_array_size = numbuck;
#ifdef HAVE_MMAP
	/* allocate the ratelimit hashtable in a memory map so it is
	 * preserved across reforks (every child its own table) */
	rrl_maps_num = (size_t)numch;
	rrl_maps = (void**)xalloc(sizeof(void*)*rrl_maps_num);
	for(i=0; i<rrl_maps_num; i++) {
		rrl_maps[i] = mmap(NULL,
			sizeof(struct rrl_bucket)*rrl_array_size, 
			PROT_READ|PROT_WRITE, MAP_SHARED|MAP_ANONYMOUS, -1, 0);
		if(rrl_maps[i] == MAP_FAILED) {
			log_msg(LOG_ERR, "rrl: mmap failed: %s",
				strerror(errno));
			exit(1);
		}
		memset(rrl_maps[i], 0,
			sizeof(struct rrl_bucket)*rrl_array_size);
	}
#else
	(void)numch;
	rrl_maps_num = 0;
	rrl_maps = NULL;
#endif
}

void rrl_init(size_t ch)
{
	if(!rrl_maps || ch >= rrl_maps_num)
	    rrl_array = xalloc_zero(sizeof(struct rrl_bucket)*rrl_array_size);
#ifdef HAVE_MMAP
	else rrl_array = (struct rrl_bucket*)rrl_maps[ch];
#endif
}

/** return the source netblock of the query, this is the genuine source
 * for genuine queries and the target for reflected packets */
static uint64_t rrl_get_source(query_type* query, uint8_t* c2)
{
	/* we take a /24 for IPv4 and /64 for IPv6 */
	/* note there is an IPv6 subnet, that maps
	 * to the same buckets as IPv4 space, but there is a flag in c2
	 * that makes the hash different */
#ifdef INET6
	if( ((struct sockaddr_in*)&query->addr)->sin_family == AF_INET) {
		*c2 = 0;
		return ((struct sockaddr_in*)&query->addr)->
			sin_addr.s_addr & htonl(0xffffff00);
	} else {
		uint64_t s;
		*c2 = 0x80;
		memmove(&s, &((struct sockaddr_in6*)&query->addr)->sin6_addr,
			sizeof(s));
		return s;
	}
#else
	*c2 = 0;
	return query->addr.sin_addr.s_addr & htonl(0xffffff00);
#endif
}

/** debug source to string */
static const char* rrlsource2str(uint64_t s, uint8_t c2)
{
	static char buf[64];
	struct in_addr a4;
#ifdef INET6
	if(c2) {
		/* IPv6 */
		struct in6_addr a6;
		memset(&a6, 0, sizeof(a6));
		memmove(&a6, &s, sizeof(s));
		if(!inet_ntop(AF_INET6, &a6, buf, sizeof(buf)))
			strlcpy(buf, "[ip6 ntop failed]", sizeof(buf));
		else	strlcat(buf, "/64", sizeof(buf));
		return buf;
	}
#endif
	/* ipv4 */
	a4.s_addr = (uint32_t)s;
	if(!inet_ntop(AF_INET, &a4, buf, sizeof(buf)))
		strlcpy(buf, "[ip4 ntop failed]", sizeof(buf));
	else	strlcat(buf, "/24", sizeof(buf));
	return buf;
}

/** debug type to string */
static const char* rrltype2str(int c)
{
	switch(c & 0x7f) {
		case 1: return "nxdomain";
		case 2: return "error_response";
		case 3: return "qtype_any";
		case 4: return "referral";
		case 5: return "wildcard";
		case 6: return "nodata";
		case 7: return "answer";
	}
	return "unknown";
}

/** classify the query in a number of different types, each has separate
 * ratelimiting, so that positive queries are not impeded by others */
static uint8_t rrl_classify(query_type* query, const uint8_t** d, size_t* d_len)
{
	/* Types:	nr	dname
	 * nxdomain:	1	zone
	 * error:	2	zone
	 * qtypeANY:	3	qname
	 * referral:	4	delegpt
	 * wildcard:	5	wildcard
	 * nodata:	6	zone
	 * positive:	7	qname
	 */
	if(RCODE(query->packet) == RCODE_NXDOMAIN) {
		if(query->zone && query->zone->apex) {
			*d = dname_name(domain_dname(query->zone->apex));
			*d_len = domain_dname(query->zone->apex)->name_size;
		}
		return 1;
	}
	if(RCODE(query->packet) != RCODE_OK) {
		if(query->zone && query->zone->apex) {
			*d = dname_name(domain_dname(query->zone->apex));
			*d_len = domain_dname(query->zone->apex)->name_size;
		}
		return 2;
	}
	if(query->qtype == TYPE_ANY) {
		if(query->qname) {
			*d = dname_name(query->qname);
			*d_len = query->qname->name_size;
		}
		return 3;
	}
	if(query->delegation_domain) {
		*d = dname_name(domain_dname(query->delegation_domain));
		*d_len = domain_dname(query->delegation_domain)->name_size;
		return 4;
	}
	if(query->wildcard_domain) {
		*d = dname_name(domain_dname(query->wildcard_domain));
		*d_len = domain_dname(query->wildcard_domain)->name_size;
		return 5;
	}
	if(ANCOUNT(query->packet) == 0) { /* nodata */
		if(query->zone && query->zone->apex) {
			*d = dname_name(domain_dname(query->zone->apex));
			*d_len = domain_dname(query->zone->apex)->name_size;
		}
		return 6;
	}
	/* positive */
	if(query->qname) {
		*d = dname_name(query->qname);
		*d_len = query->qname->name_size;
	}
	return 7;
}

/** Examine the query and return hash and source of netblock. */
static void examine_query(query_type* query, uint32_t* hash, uint64_t* source)
{
	/* compile a binary string representing the query */
	uint8_t c, c2;
	/* size with 16 bytes to spare */
	uint8_t buf[MAXDOMAINLEN + sizeof(*source) + sizeof(c) + 16];
	const uint8_t* dname = NULL; size_t dname_len;
	uint32_t r = 0x267fcd16;

	*source = rrl_get_source(query, &c2);
	c = rrl_classify(query, &dname, &dname_len) | c2;
	memmove(buf, source, sizeof(*source));
	memmove(buf+sizeof(*source), &c, sizeof(c));

	DEBUG(DEBUG_QUERY, 1, (LOG_INFO, "rrl_examine type %s name %s", rrltype2str(c), dname?wiredname2str(dname):"NULL"));

	/* and hash it */
	if(dname && dname_len <= MAXDOMAINLEN) {
		memmove(buf+sizeof(*source)+sizeof(c), dname, dname_len);
		*hash = hashlittle(buf, sizeof(*source)+sizeof(c)+dname_len, r);
	} else
		*hash = hashlittle(buf, sizeof(*source)+sizeof(c), r);
}

/* age the bucket because elapsed time steps have gone by */
static void rrl_attenuate_bucket(struct rrl_bucket* b, int32_t elapsed)
{
	if(elapsed > 16) {
		b->rate = 0;
	} else {
		/* divide rate /2 for every elapsed time step, because
		 * the counters in the inbetween steps were 0 */
		/* r(t) = 0 + 0/2 + 0/4 + .. + oldrate/2^dt */
		b->rate >>= elapsed;
		/* we know that elapsed >= 2 */
		b->rate += (b->counter>>(elapsed-1));
	}
}

/** update the rate in a ratelimit bucket, return actual rate */
uint32_t rrl_update(query_type* query, uint32_t hash, uint64_t source,
	int32_t now)
{
	struct rrl_bucket* b = &rrl_array[hash % rrl_array_size];

	DEBUG(DEBUG_QUERY, 1, (LOG_INFO, "source %llx hash %x oldrate %d oldcount %d stamp %d",
		(long long unsigned)source, hash, b->rate, b->counter, b->stamp));

	/* check if different source */
	if(b->source != source) {
		/* initialise */
		b->source = source;
		b->counter = 1;
		b->rate = 0;
		b->stamp = now;
		return 1;
	}
	/* this is the same source */

	/* check if old, zero or smooth it */
	/* circular arith for time */
	if(now - b->stamp == 1) {
		/* very busy bucket and time just stepped one step */
		b->rate = b->rate/2 + b->counter;
		b->counter = 1;
		b->stamp = now;
	} else if(now - b->stamp > 0) {
		/* older bucket */
		rrl_attenuate_bucket(b, now - b->stamp);
		b->counter = 1;
		b->stamp = now;
	} else if(now != b->stamp) {
		/* robust, timestamp from the future */
		b->rate = 0;
		b->counter = 1;
		b->stamp = now;
	} else {
		/* bucket is from the current timestep, update counter */
		b->counter ++;

		/* log what is blocked for operational debugging */
		if(verbosity >= 2 && b->counter + b->rate/2 == rrl_ratelimit
			&& b->rate < rrl_ratelimit) {
			uint8_t c, c2;
			const uint8_t* d = NULL;
			size_t d_len;
			uint64_t s = rrl_get_source(query, &c2);
			c = rrl_classify(query, &d, &d_len) | c2;
			log_msg(LOG_INFO, "ratelimit %s type %s target %s",
				d?wiredname2str(d):"", rrltype2str(c),
				rrlsource2str(s, c2));
		}
	}

	/* return max from current rate and projected next-value for rate */
	/* so that if the rate increases suddenly very high, it is
	 * stopped halfway into the time step */
	if(b->counter > b->rate/2)
		return b->counter + b->rate/2;
	return b->rate;
}

int rrl_process_query(query_type* query)
{
	uint64_t source;
	uint32_t hash;
	int32_t now = (int32_t)time(NULL);

	/* examine query */
	examine_query(query, &hash, &source);

	/* update rate */
	return (rrl_update(query, hash, source, now) >= rrl_ratelimit);
}

query_state_type rrl_slip(query_type* query)
{
	/* discard half the packets, randomly */
	if((random() & 0x1)) {
		/* set TC on the rest */
		TC_SET(query->packet);
		ANCOUNT_SET(query->packet, 0);
		NSCOUNT_SET(query->packet, 0);
		ARCOUNT_SET(query->packet, 0);
		if(query->qname)
			/* header, type, class, qname */
			buffer_set_limit(query->packet,
				QHEADERSZ+8+query->qname->name_size);
		else 	buffer_set_limit(query->packet, QHEADERSZ);
		return QUERY_PROCESSED;
	}
	return QUERY_DISCARDED;
}

#endif /* RATELIMIT */
