/*
 * $Id: zonec2.h,v 1.3 2003/08/25 16:57:37 miekg Exp $
 *
 * zonec2.h -- internal zone representation.
 *
 * Copyright (c) 2001- 2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ZONEC_H_
#define _ZONEC_H_

#include "heap.h"
#include "zparser2.h"

struct rrset {
	struct rrset *next;
	uint16_t type;
	uint16_t class;
	int32_t ttl;
	int glue;
	int color;
	uint16_t rrslen;
	uint16_t ***rrs;
};

struct zone {
	uint8_t *dname;
	heap_t	*cuts;
	heap_t	*data;
	struct rrset *soa;
	struct rrset *ns;
};

#define MAXRRSPP	1024
#define	IOBUFSZ		MAXRRSPP * 64
#define	LINEBUFSZ	1024

struct message {
	uint8_t *bufptr;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
	int dnameslen;
	int rrsetslen;
	int comprlen;
	uint16_t pointerslen;
	uint16_t pointers[MAXRRSPP];
	uint16_t rrsetsoffslen;
	uint16_t rrsetsoffs[MAXRRSPP];
	struct rrset *rrsets[MAXRRSPP];
	uint8_t *dnames[MAXRRSPP];
	struct {
		const uint8_t *dname;
		uint16_t dnameoff;
		uint8_t dnamelen;
	} compr[MAXRRSPP];
	uint8_t buf[IOBUFSZ];
};

extern struct zone *current_zone;

int process_rr(struct RR *rr);

#endif /* _ZONEC_H_ */
