/*
 * $Id: zone.c,v 1.7 2002/01/09 15:19:50 alexis Exp $
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
#include "db.h"
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

/*
 * Writes zone data into open database *db
 *
 * Returns zero if success.
 */
int
zone_dump(z, db)
	struct 	zone *z;
	struct	db *db;
{
	struct domain *d;
	struct message msg;
	struct rrset *rrset, *additional;
	u_char *dname, *nameptr;
	int i;

	/* AUTHORITY CUTS */
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		/* Make sure the data is intact */
		assert((rrset->next == NULL) && (rrset->type == TYPE_NS));

		/* Initialize message */
		bzero(&msg, sizeof(struct message));
		msg.bufptr = msg.buf;

		/* Create a new domain */
		d = db_newdomain(DB_DELEGATION);

		/* Put the dname into compression array */
		for(nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1) {
			if((dname + *dname + 1 - nameptr) > 1) {
				msg.compr[msg.comprlen].dname = nameptr;
				msg.compr[msg.comprlen].dnameoff = (nameptr - (dname + 1)) | 0xc000;
				msg.compr[msg.comprlen].dnamelen = dname + *dname + 1 - nameptr;
				msg.comprlen++;
			}
		}

		/* Authority section */
		msg.nscount = zone_addrrset(&msg, dname, rrset);

		/* Additional section */
		for(i = 0; i < msg.dnameslen; i++) {
			additional = HEAP_SEARCH(z->data, msg.dnames[i]);
			while(additional) {
				if(additional->type == TYPE_A || additional->type == TYPE_AAAA) {
					msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
				}
				additional = additional->next;
			}
		}

		/* Add this answer */
		d = db_addanswer(d, &msg, rrset->type);

		/* Store it */
		db_write(db, dname, d);
		free(d);
	}
	HEAP_STOP();

	/* OTHER DATA */
	HEAP_WALK(z->data, (char *)dname, rrset) {
		/* Create a new domain, not a delegation */
		d = db_newdomain(0);

		while(rrset) {
			/* Initialize message */
			bzero(&msg, sizeof(struct message));
			msg.bufptr = msg.buf;

			/* Put the dname into compression array */
			for(nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1) {
				if((dname + *dname + 1 - nameptr) > 1) {
					msg.compr[msg.comprlen].dname = nameptr;
					msg.compr[msg.comprlen].dnameoff = (nameptr - (dname + 1)) | 0xc000;
					msg.compr[msg.comprlen].dnamelen = dname + *dname + 1 - nameptr;
					msg.comprlen++;
				}
			}

			/* Answer section */
			msg.ancount = zone_addrrset(&msg, dname, rrset);

			/* Authority section */
			msg.nscount = zone_addrrset(&msg, z->dname, z->ns);

			/* Additional section */
			for(i = 0; i < msg.dnameslen; i++) {
				additional = HEAP_SEARCH(z->data, msg.dnames[i]);
				while(additional) {
					if(additional->type == TYPE_A || additional->type == TYPE_AAAA) {
						msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
					}
					additional = additional->next;
				}
			}

			/* Add this answer */
			d = db_addanswer(d, &msg, rrset->type);

			rrset = rrset->next;
		}

		/* Store it */
		db_write(db, dname, d);
		free(d);
	}
	HEAP_STOP();


	return 0;
}

/*
 * XXXX: Check msg->buf boundaries!!!!!
 */
u_short
zone_addrrset(msg, dname, rrset)
	struct message *msg;
	u_char *dname;
	struct rrset *rrset;
{
	u_short class = htons(CLASS_IN);
	long ttl;
	union zf_rdatom *rdata;
	char *rdlengthptr;
	char *f;
	u_char *p;
	size_t l;
	u_short rdlength;
	u_short type;
	int rrcount;
	int i, j;

	/* Did I see you before? */
	for(i = 0; i < msg->rrsetslen; i++) {
		/* Not again, please! */
		if(rrset == msg->rrsets[i]) {
			return 0;
		}
	}

	/* Please sign in here... */
	msg->rrsets[msg->rrsetslen++] = rrset;

	for(rrcount = 0, j = 0; j < rrset->rrslen; j++, rrcount++) {
		rdata = rrset->rrs[j];

		/* dname */
		zone_addname(msg, dname);

		/* type */
		type = htons(rrset->type);
		bcopy(&type, msg->bufptr, sizeof(u_short));
		msg->bufptr += sizeof(u_short);

		/* class */
		bcopy(&class, msg->bufptr, sizeof(u_short));
		msg->bufptr += sizeof(u_short);

		/* ttl */
		ttl = htonl(rrset->ttl);
		bcopy(&ttl, msg->bufptr, sizeof(long));
		msg->bufptr += sizeof(long);

		/* rdlength */
		rdlengthptr = msg->bufptr;
		rdlength = 0;
		msg->bufptr += sizeof(u_short);

		/* Pack the rdata */
		for(p = NULL, l = 0, i = 0, f = rrset->fmt; *f; f++, i++, p = NULL, l = 0) {
			switch(*f) {
			case '4':
			case 'l':
				p = (char *)&rdata[i].l;
				l = sizeof(u_long);
				break;
			case '6':
				p = rdata[i].p;
				l = IP6ADDRLEN;
				break;
			case 'n':
				p = NULL;
				l = 0;
				rdlength += zone_addname(msg, rdata[i].p);
				msg->dnames[msg->dnameslen++] = rdata[i].p;
				break;
			case 't':
				p = rdata[i].p;
				l = (u_short) *p + 1;
				break;
			case 's':
				p = (char *)&rdata[i].s;
				l = sizeof(u_short);
				break;
			case 'g':
			case 'a':
				p = NULL;
				l = 0;
				break;
			default:
				syslog(LOG_ERR, "panic! uknown atom in format %c", *f);
				return rrcount;
			}
			bcopy(p, msg->bufptr, l);
			msg->bufptr += l;
			rdlength += l;
		}
		rdlength = htons(rdlength);
		bcopy(&rdlength, rdlengthptr, sizeof(u_short));
	}
	return rrcount;
}


u_short
zone_addname(msg, dname)
	struct message *msg;
	u_char *dname;
{
	/* Lets try rdata dname compression */
	int rdlength = 0;
	int j;
	u_short rdname_pointer = 0;
	register u_char *t;

	/* Walk through the labels in the dname to be compressed */
	if(*dname > 1) {
		for(t = dname + 1; (t < (dname + 1 + *dname)); t += *t + 1) {
			/* Walk through the dnames that we have already in the packet */
			for(j = 0; j < msg->comprlen; j++) {
				if((msg->compr[j].dnamelen == (dname + 1 + *dname - t)) &&
					(strncasecmp(t, msg->compr[j].dname, msg->compr[j].dnamelen) == 0)) {
					/* Match, first write down unmatched part */
					bcopy(dname + 1, msg->bufptr,
						(t - (dname + 1)));
					msg->bufptr += (t - (dname + 1));
					rdlength += (t - (dname + 1));

					/* Then construct the pointer, and add it */
					rdname_pointer = (u_short)msg->compr[j].dnameoff;
					bcopy(&rdname_pointer, msg->bufptr, 2);

					msg->pointers[msg->pointerslen++] = msg->bufptr - msg->buf;

					msg->bufptr += 2;
					return rdlength + 2;
				}
			}
			/* Add this part of dname */
			if((dname + 1 + *dname - t) > 1) {
				msg->compr[msg->comprlen].dname = t;
				msg->compr[msg->comprlen].dnameoff = msg->bufptr - msg->buf + (t - (dname + 1));
				msg->compr[msg->comprlen].dnamelen = (dname + 1 + *dname - t);
				msg->comprlen++;
			}
		}
	}
	bcopy(dname +1, msg->bufptr, *dname);
	msg->bufptr += *dname;
	return *dname;
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
	struct db *db;

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

	if((db = db_create("nsd.db")) == NULL) {
		exit(1);
	}
	zone_dump(z, db);
	db_sync(db);
	db_close(db);
	zone_print(z);

	return 0;
}

#endif
