/*
 * $Id: zone.c,v 1.1 2002/01/08 13:29:21 alexis Exp $
 *
 * zone.c -- reads in a zone file and stores it in memory
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, NLnet Labs. All rights reserved.
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
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "dns.h"
#include "nsd.h"
#include "zf.h"
#include "heap.h"
#include "zone.h"

void
zone_print(z)
	struct zone *z;
{
	struct rrset *rrset;
	u_char *dname;
	int i;

	printf("; zone %s\n", dnamestr(z->dname));
	printf("; zone data\n");

	HEAP_WALK(z->data, (char *)dname, rrset) {
		while(rrset) {
			for(i = 0; i < rrset->rrslen; i++) {
				printf("%s\t%ld\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
					 classtoa(rrset->class), typetoa(rrset->type));
				zf_print_rdata(rrset->rrs[i], rrset->fmt);
				printf("\n");
			}
			rrset = rrset->next;
		}
	}
	HEAP_STOP();

	printf("; zone cuts\n");
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		while(rrset) {
			for(i = 0; i < rrset->rrslen; i++) {
				printf("%s\t%ld\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
					 classtoa(rrset->class), typetoa(rrset->type));
				zf_print_rdata(rrset->rrs[i], rrset->fmt);
				printf("\n");
			}
			rrset = rrset->next;
		}
	}
	HEAP_STOP();
}


/*
 * Reads the specified zone into the memory
 *
 */
struct zone *
zone_read(name, zonefile)
	char *name;
	char *zonefile;
{
	heap_t *h;

	struct zone *z;
	struct zf *zf;
	struct zf_entry *rr;
	struct rrset *rrset, *r;

	HEAP_INIT(xalloc);

	/* Allocate new zone structure */
	z = xalloc(sizeof(struct zone));
	bzero(z, sizeof(struct zone));

	/* Get the zone name */
	if((z->dname = strdname(name, ROOT_ORIGIN)) == NULL) {
		zone_free(z);
		return NULL;
	}

	/* Open the zone file */
	if((zf = zf_open(zonefile, z->dname)) == NULL) {
		zone_free(z);
		return NULL;
	}

	/* Two heaps: zone cuts and other data */
	z->cuts = HEAP_NEW(dnamecmp);
	z->data = HEAP_NEW(dnamecmp);
	z->soa = z->ns = NULL;

	/* Read the file */
	while((rr = zf_read(zf)) != NULL) {

#ifdef DEBUG
		/* Report progress... */
		if((zf->lines % 100000) == 0) {
			fprintf(stderr, "read %lu lines...\n", zf->lines);
		}
#endif

		/* We only support IN class */
		if(rr->class != CLASS_IN) {
			zf_error(zf, "wrong class");
			continue;
		}

		/* Is this in-zone data? */
		if((*z->dname > *rr->dname) ||
			(bcmp(z->dname + 1, rr->dname + (*rr->dname - *z->dname) + 1, *z->dname) != 0)) {
			zf_error(zf, "out of zone data");
			continue;
		}

		/* Insert the record into a rrset */
		if(rr->type == TYPE_NS && dnamecmp(rr->dname, z->dname) != 0) {
			h = z->cuts;
		} else {
			h = z->data;
		}

		/* Do we have this domain name in heap? */
		if((rrset = HEAP_SEARCH(h, rr->dname)) != NULL) {
			for(r = rrset; r; r = r->next) {
				if(r->type == rr->type)
					break;
			}
		} else {
			r = NULL;
		}

		/* Do we have this particular rrset? */
		if(r == NULL) {
			r = xalloc(sizeof(struct rrset));
			bzero(r, sizeof(struct rrset));
			r->type = rr->type;
			r->class = rr->class;
			r->ttl = rr->ttl;
			r->fmt = rr->rdatafmt;
			r->rrslen = 1;
			r->rrs = xalloc(sizeof(union zf_rdatom *));
			r->rrs[0] = rr->rdata;

			/* Add it */
			if(rrset == NULL) {
				HEAP_INSERT(h, strdup(rr->dname), r);
			} else {
				r->next = rrset->next;
				rrset->next = r;
			}
		} else {
			if(r->ttl != rr->ttl) {
				zf_error(zf, "rr ttl doesnt match the ttl of the rdataset");
				continue;
			}
			r->rrs = xrealloc(r->rrs, ((r->rrslen + 1) * sizeof(union zf_rdatom *)));
			r->rrs[r->rrslen++] = rr->rdata;
		}

		/* Check we have SOA */
		if(z->soa == NULL) {
			if(rr->type != TYPE_SOA) {
				zf_error(zf, "missing SOA record on top of the zone");
			} else {
				if(dnamecmp(rr->dname, z->dname) != 0) {
					zf_error(zf, "SOA record with invalid domain name");
				} else {
					z->soa = r;
				}
			}
		} else {
			if(rr->type == TYPE_SOA) {
				zf_error(zf, "duplicate SOA record");
			}
		}

		/* Is this a zone NS? */
		if(rr->type == TYPE_NS && h == z->data) {
			z->ns = r;
		}

	}

	fprintf(stderr, "complete: %d errors\n", zf->errors);
	return z;
}

/*
 * Frees all the data structures associated with the zone
 *
 */
void
zone_free(z)
	struct zone *z;
{
	if(z) {
		if(z->dname) free(z->dname);
	}
}

void
zone_dump(z)
	struct zone *z;
{
	struct rrset *rrset, *glue;
	u_char *dname, *nsname;
	int i;

	/* First we walk through all the zone cuts and write them out together with the glue */
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		/* We only have one rrset at zone delegation */
		assert((rrset->next == NULL) && (rrset->type == TYPE_NS));

		for(i = 0; i < rrset->rrslen; i++) {
			/* Do we need glue? */
			nsname = (u_char *)rrset->rrs[i].p;
			if((*nsname > *z->dname) &&
				(bcmp(z->dname + 1, nsname + (*nsname - *z->dname) + 1, *z->dname) == 0)) {
				if((glue = HEAP_SEARCH(z->data, nsname)) != NULL) {
					while(glue) {
						if(glue->type == 

			printf("%s\t%ld\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
				 classtoa(rrset->class), typetoa(rrset->type));
			zf_print_rdata(rrset->rrs[i], rrset->fmt);
			printf("\n");
		}
	}
	HEAP_STOP();

	printf("; zone cuts\n");
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		while(rrset) {
			for(i = 0; i < rrset->rrslen; i++) {
				printf("%s\t%ld\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
					 classtoa(rrset->class), typetoa(rrset->type));
				zf_print_rdata(rrset->rrs[i], rrset->fmt);
				printf("\n");
			}
			rrset = rrset->next;
		}
	}
	HEAP_STOP();
}

#ifdef TEST

int
usage()
{
	fprintf(stderr, "usage: zone name zone-file\n");
	exit(1);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{

	struct zone *z;

#ifndef LOG_PERROR
#define		LOG_PERROR 0
#endif
	/* Set up the logging... */
	openlog("zf", LOG_PERROR, LOG_LOCAL5);

	/* Check the command line */
	if(argc  != 3) {
		usage();
	}

	/* Open the file */
	if((z = zone_read(argv[1], argv[2])) == NULL) {
		exit(1);
	}

	zone_print(z);

	return 0;
}

#endif
