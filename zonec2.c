/*
 * $Id: zonec2.c,v 1.16 2003/08/28 17:58:12 miekg Exp $
 *
 * zone.c -- reads in a zone file and stores it in memory
 *
 * Copyright (c) 2001-2003, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "heap.h"
#include "namedb.h"
#include "util.h"
#include "region-allocator.h"
#include "zonec.h"
#include "zparser2.h"

struct zone *current_zone = NULL;

static void zone_addbuf (struct message *, const void *, size_t);
static void zone_addcompr (struct message *msg, const uint8_t *dname, int offset, int len);

/*
 * This region is free'd after each zone is compiled.
 */
static region_type *zone_region;

/* The database file... */
static const char *dbfile = DBFILE;

/* Some global flags... */
static int vflag = 0;
static int pflag = 0;

/* Total errors counter */
static int totalerrors = 0;

static void
zone_initmsg(struct message *m)
{
	m->ancount = m->nscount = m->arcount = m->dnameslen = m->rrsetslen
		= m->comprlen = m->pointerslen = m->rrsetsoffslen = 0;
	m->bufptr = m->buf;
}

static void 
zone_print (struct zone *z)
{
	struct rrset *rrset;
	struct RR rr;
	const uint8_t *dname;
	int i;

	printf("; zone %s\n", dnamestr(z->dname));
	printf("; zone data\n");

	HEAP_WALK(z->data, dname, rrset) {
		while (rrset) {
			rr.dname = (uint8_t *)dname;
			rr.ttl = rrset->ttl;
			rr.class = rrset->class;
			rr.type = rrset->type;
			for (i = 0; i < rrset->rrslen; i++) {
				rr.rdata = rrset->rrs[i];
				/*zprintrr(stdout, &rr);*/
			}
			rrset = rrset->next;
		}
	}

	printf("; referrals\n");
	HEAP_WALK(z->cuts, dname, rrset) {
		while (rrset) {
			rr.dname = (uint8_t *)dname;
			rr.ttl = rrset->ttl;
			rr.class = rrset->class;
			rr.type = rrset->type;
			for (i = 0; i < rrset->rrslen; i++) {
				rr.rdata = rrset->rrs[i];
				/* zprintrr(stdout, &rr);*/
			}
			rrset = rrset->next;
		}
	}
}

static void 
zone_addbuf (struct message *msg, const void *data, size_t size)
{
	if (msg->bufptr - msg->buf + size > IOBUFSZ) {
		fflush(stdout);
		fprintf(stderr, "zonec: insufficient buffer space\n"); /* RR set too large? */
		exit(1);	/* XXX: do something smart */
	}

	memcpy(msg->bufptr, data, size);
	msg->bufptr += size;
}

static void 
zone_addcompr (struct message *msg, const uint8_t *dname, int offset, int len)
{
	if (msg->comprlen >= MAXRRSPP) {
		fflush(stdout);
		fprintf(stderr, "zonec: out of space many compressed dnames\n");
		exit(1);
	}
	
	msg->compr[msg->comprlen].dname = dname;
	msg->compr[msg->comprlen].dnameoff = offset;
	msg->compr[msg->comprlen].dnamelen = len;
	msg->comprlen++;
}

static uint16_t 
zone_addname (struct message *msg, const uint8_t *dname)
{
	/* Lets try rdata dname compression */
	int rdlength = 0;
	int j;
	const uint8_t *t;

	/* Walk through the labels in the dname to be compressed */
	if (*dname > 1) {
		for (t = dname + 1; (t < (dname + 1 + *dname)); t += *t + 1) {
			/* Walk through the dnames that we have already in the packet */
			for (j = 0; j < msg->comprlen; j++) {
				if ((msg->compr[j].dnamelen == (dname + 1 + *dname - t)) &&
					(strncasecmp((char *)t, (char *)msg->compr[j].dname,
						msg->compr[j].dnamelen) == 0)) {
					/* Match, first write down unmatched part */
					zone_addbuf(msg, dname + 1, t - (dname + 1));
					rdlength += (t - (dname + 1));

					/* Then construct the pointer, and add it */
					if (msg->pointerslen == MAXRRSPP) {
						fflush(stdout);
						fprintf(stderr, "zonec: too many pointers\n");
						exit(1);
					}
					
					msg->pointers[msg->pointerslen++] = msg->bufptr - msg->buf;
					zone_addbuf(msg, &msg->compr[j].dnameoff, 2);
					return rdlength + 2;
				}
			}
			/* Add this part of dname */
			if ((dname + 1 + *dname - t) > 1) {
				zone_addcompr(msg, t,
					      msg->bufptr - msg->buf + (t - (dname + 1)),
					      dname + 1 + *dname - t);
			}
		}
	}
	zone_addbuf(msg, dname + 1, *dname);
	return *dname;
}



static uint16_t 
zone_addrrset (struct message *msg, const uint8_t *dname, struct rrset *rrset)
{
	uint16_t class = htons(CLASS_IN);
	int32_t ttl;
	uint16_t **rdata;
	uint8_t *rdlengthptr;
	uint16_t rdlength;
	uint16_t type;
	int rrcount;
	int i, j;

	uint16_t s;

	if (rrset == NULL) return 0;

	/* Did I see you before? */
	for (i = 0; i < msg->rrsetslen; i++) {
		/* Not again, please! */
		if (rrset == msg->rrsets[i]) {
			return 0;
		}
	}

	/* Paint me black... */
	if (msg->rrsetslen) {
		rrset->color = !msg->rrsets[msg->rrsetslen - 1]->color;
	} else {
		rrset->color = 0;
	}

	if (msg->rrsetslen == MAXRRSPP) {
		fflush(stdout);
		fprintf(stderr, "zonec: too many rrsets\n");
		exit(1);
	}
	
	/* Please sign in here... */
	msg->rrsets[msg->rrsetslen++] = rrset;

	for (rrcount = 0, j = 0; j < rrset->rrslen; j++, rrcount++) {
		/* Add the offset of this record */
		if (msg->rrsetsoffslen == MAXRRSPP) {
			fflush(stdout);
			fprintf(stderr, "zonec: too many rrsets offsets\n");
			exit(1);
		}
		
		msg->rrsetsoffs[msg->rrsetsoffslen++] = (msg->bufptr - msg->buf) | (rrset->color ? NAMEDB_RRSET_WHITE : 0);


		/* dname */
		if (*(dname + 1) == 1 && *(dname + 2) == '*') {
			if (msg->pointerslen == MAXRRSPP) {
				fflush(stdout);
				fprintf(stderr, "zonec: too many pointers for %s\n", dnamestr(dname));
				exit(1);
			}

			msg->pointers[msg->pointerslen++] = msg->bufptr - msg->buf;

			s = 0xd000;
			zone_addbuf(msg, &s, 2);
		} else {
			zone_addname(msg, dname);
		}

		/* type */
		type = htons(rrset->type);
		zone_addbuf(msg, &type, sizeof(uint16_t));

		/* class */
		zone_addbuf(msg, &class, sizeof(uint16_t));

		/* ttl */
		ttl = htonl(rrset->ttl);
		zone_addbuf(msg, &ttl, sizeof(int32_t));

		/* rdlength */
		rdlengthptr = msg->bufptr;
		rdlength = 0;

		/*
		 * Reserver space for rdata length.  The actual length
		 * is filled in below.
		 */
		zone_addbuf(msg, &rdlength, sizeof(uint16_t));

		/* Pack the rdata */
		
		for (rdata = rrset->rrs[j]; *rdata; rdata++) {
			/* Is it a domain name? */
			if (**rdata == 0xffff) {
				if (msg->dnameslen >= MAXRRSPP) {
					fflush(stdout);
					fprintf(stderr, "zonec: too many domain names\n");
					exit(1);
				}
				rdlength += zone_addname(msg, (uint8_t *)(*rdata + 1));
				msg->dnames[msg->dnameslen++] = (uint8_t *)(*rdata + 1);
			} else {
				zone_addbuf(msg, *rdata + 1, **rdata);
				rdlength += **rdata;
			}
		}
		rdlength = htons(rdlength);
		memcpy(rdlengthptr, &rdlength, sizeof(uint16_t));
	}
	return rrcount;
}

/*
 * Adds an answer to a domain
 *
 */
static struct domain *
zone_addanswer (struct domain *d, struct message *msg, int type)
{
	struct answer *a;
	size_t size, datasize;

	/* First add an extra rrset offset */
	msg->rrsetsoffs[msg->rrsetsoffslen++] = (msg->bufptr - msg->buf);

	datasize = msg->bufptr - msg->buf;
	size = sizeof(struct answer) + msg->pointerslen * sizeof(uint16_t) /* ptrs */
		+ (msg->rrsetsoffslen) * sizeof(uint16_t)	/* rrs */
		+ datasize;					/* data */

	/* Assure the alignment for the next answer... */
	size = ALIGN_UP(size, NAMEDB_ALIGNMENT);

	d = xrealloc(d, d->size + size);
	memset((char *)d + d->size, 0, size);
	
	a = (struct answer *)((char *)d + d->size);

	ANSWER_SIZE(a) = size;
	ANSWER_TYPE(a) = htons(type);
	ANSWER_ANCOUNT(a) = htons(msg->ancount);
	ANSWER_NSCOUNT(a) = htons(msg->nscount);
	ANSWER_ARCOUNT(a) = htons(msg->arcount);
	ANSWER_PTRSLEN(a) = msg->pointerslen;
	ANSWER_RRSLEN(a) = msg->rrsetsoffslen;
	ANSWER_DATALEN(a) = datasize;

	memcpy(ANSWER_PTRS_PTR(a), msg->pointers, sizeof(uint16_t) * msg->pointerslen);
	memcpy(ANSWER_RRS_PTR(a), msg->rrsetsoffs, sizeof(uint16_t) * msg->rrsetsoffslen);
	memcpy(ANSWER_DATA_PTR(a), msg->buf, datasize);

	d->size += size;

	return d;
}

static void
cleanup_rrset(void *r)
{
	struct rrset *rrset = r;
	size_t i;
	if (rrset && rrset->rrs) {
		for (i = 0; rrset->rrs[i]; ++i) {
			zrdatafree(rrset->rrs[i]);
		}
		free(rrset->rrs);
	}
}

int
process_rr(struct RR *rr)
{
	heap_t *h;
	struct rrset *rrset, *r;
	int i;
	uint8_t *dname, *t;
	struct zone *z = current_zone;
	
        if ( pflag > 0 ) 
            zprintrr(stderr, rr);
		
	/* Report progress... 
	   if (vflag > 1) {
	   if ((parser->lines % 100000) == 0) {
	   printf("zonec: reading zone \"%s\": %lu\r", dnamestr(z->dname), (unsigned long) parser->lines);
	   fflush(stdout);
	   }
	   }
	   [XXX] done inside lex whatever
	*/

	/* We only support IN class */
	if (rr->class != CLASS_IN) {
		zerror("Wrong class");
		return 0;
	}

	/* Is this in-zone data? */
      /* 
	   printf("d name: [%s]\n", z->dname);
	   printf("rr name: [%s]\n", rr->dname);
	   printf("d name: [%d]\n", (int)z->dname[0]);
	   printf("rr name: [%d]\n", (int)rr->dname[0]);
	   printf("d name: [%d]\n", (int)z->dname[1]);
	   printf("rr name: [%d]\n", (int)rr->dname[1]);
	   printf("d name: [%s]\n", dnamestr(z->dname));
	   printf("rr name: [%s]\n", dnamestr(rr->dname));
       */
	if ((*z->dname > *rr->dname) ||
	   (memcmp(z->dname + 1, rr->dname + (*rr->dname - *z->dname) + 1, *z->dname) != 0)) {
		zerror("Out of zone data");
		return 0;
	}

	/* Insert the record into a rrset */
	if (rr->type == TYPE_NS && ((dnamecmp(rr->dname, z->dname) != 0) || (z->soa == NULL))) {
		h = z->cuts;
	} else {
		h = z->data;
	}

	/* Do we have this domain name in heap? */
	if ((rrset = heap_search(h, rr->dname)) != NULL) {
		for (r = rrset; r; r = r->next) {
			if (r->type == rr->type) {
				break;
			}
		}
	} else {
		r = NULL;
	}

	/* Do we have this particular rrset? */
	if (r == NULL) {
		r = region_alloc(zone_region, sizeof(struct rrset));
		region_add_cleanup(zone_region, cleanup_rrset, r);
		r->type = 0;
	}
	if (r->type == 0) {
		r->next = NULL;
		r->type = rr->type;
		r->class = rr->class;
		r->ttl = rr->ttl;
		r->rrslen = 1;
		r->rrs = xalloc(sizeof(uint16_t *) * 2);
		r->glue = r->color = 0;
		r->rrs[0] = rr->rdata;
		r->rrs[1] = NULL;
			
		/* Add it */
		if (rrset == NULL) {
			/* XXX We can use this more smart... */
			uint8_t *key = dnamedup(rr->dname);
			region_add_cleanup(zone_region, free, key);
			heap_insert(h, key, r, 1);
		} else {
			r->next = rrset->next;
			rrset->next = r;
		}
	} else {
		if (r->ttl != rr->ttl) {
			zerror("ttl doesn't match the ttl of the rrset");
			return 0;
		}

		/* Search for possible duplicates... */
		for (i = 0; i < r->rrslen; i++) {
			if (!zrdatacmp(r->rrs[i], rr->rdata)) {
				break;
			}
		}

		/* Discard the duplicates... */
		if (i < r->rrslen) {
			zrdatafree(rr->rdata);
			return 0;
		}

		/* Add it... */
		r->rrs = xrealloc(r->rrs, ((r->rrslen + 2) * sizeof(uint16_t *)));
		r->rrs[r->rrslen++] = rr->rdata;
		r->rrs[r->rrslen] = NULL;
	}

	/* Now create necessary empty nodes... */
	dname = dnamedup(rr->dname);
	for (t = dname + 2 + *(dname + 1); (t < (dname + 1 + *dname - *z->dname)); t += *t + 1) {
		*(t - 1) = dname + *dname - t + 1;
		if ((rrset = heap_search(z->data, t - 1)) == NULL) {
			uint8_t *key = dnamedup(t - 1);
			region_add_cleanup(zone_region, free, key);
			r = region_alloc(zone_region, sizeof(struct rrset));
			memset(r, 0, sizeof(struct rrset));
			region_add_cleanup(zone_region, cleanup_rrset, r);

			/* Add it */
			heap_insert(z->data, key, r, 1);
		}
	}
	free(dname);

	/* Check we have SOA */
	if (z->soa == NULL) {
		if (rr->type != TYPE_SOA) {
			zerror("Missing SOA record on top of the zone");
		} else {
			if (dnamecmp(rr->dname, z->dname) != 0) {
				zerror( "SOA record with invalid domain name");
			} else {
				z->soa = r;
			}
		}
	} else {
		if (rr->type == TYPE_SOA) {
			zerror("Duplicate SOA record discarded");
			zrdatafree(r->rrs[--r->rrslen]);
		}
	}

	/* Is this a zone NS? */
	if (rr->type == TYPE_NS && h == z->data) {
		z->ns = r;
	}
        /* free the data */
        /*zrdatafree( rr->rdata );*/

	return 1;
}

/*
 * Reads the specified zone into the memory
 *
 */
static struct zone *
zone_read (char *name, char *zonefile)
{
	struct zone *z;

	/* Allocate new zone structure */
	z = region_alloc(zone_region, sizeof(struct zone));
	memset(z, 0, sizeof(struct zone));

	/* Get the zone name */
	if ((z->dname = dnamedup(strdname(name, ROOT))) == NULL) {
		return NULL;
	}
	region_add_cleanup(zone_region, free, z->dname);

#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if (dnamecmp(z->dname, ROOT) == 0) {
		fprintf(stderr, "zonec: Not configured as a root server. See the documentation.\n");
		return NULL;
	}
#endif

	/* Open the zone file */
	if ( nsd_zopen(zonefile, 3600, CLASS_IN, name) == NULL) {
		fprintf(stderr, "zonec: unable to open %s: %s\n", zonefile, strerror(errno));
		return NULL;
	}

	/* Two heaps: zone cuts and other data */
	z->cuts = heap_create(zone_region, dnamecmp);
	z->data = heap_create(zone_region, dnamecmp);
	z->soa = z->ns = NULL;
	current_zone = z;
	
	/* Parse and process all RRs.  */
	yyparse();

	fflush(stdout);
	/*
	  if (vflag > 0) {
	  fprintf(stderr, "zonec: reading zone \"%s\": %d errors\n",
	  dnamestr(z->dname), parser->errors);
	  }
	*/
	totalerrors += zdefault->errors;

	/*zclose(parser);*/
	
	return z;
}

static void
zone_addzonecut(const uint8_t *dkey, const uint8_t *dname, struct rrset *rrset, struct zone *z, struct namedb *db)
{
	struct domain *d;
	struct message msg;
	struct rrset *additional;
	const uint8_t *nameptr;
	int i, namedepth;

	/* Make sure it is not a wildcard */
	if (*dname >= 2 && *(dname + 1) == '\001' && *(dname + 2) == '*') {
		fprintf(stderr, "zonec: wildcard delegations are not allowed (ignored)\n");
		return;
	}

	/* Initialize message */
	zone_initmsg(&msg);

	/* Create a new domain */
	d = xalloc_zero(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = NAMEDB_DELEGATION;
	
	/* Is this a real record? */
	if (dkey != dname)
		d->flags |= NAMEDB_STEALTH;

	/* Put the dkey into compression array */
	for (namedepth = 0, nameptr = dkey + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
		if ((dkey + *dkey + 1 - nameptr) > 1) {
			zone_addcompr(&msg, nameptr,
				      (nameptr - (dkey + 1)) | 0xc000,
				      dkey + *dkey + 1 - nameptr);
		}
	}

	/* Authority section */
	msg.nscount = zone_addrrset(&msg, dname, rrset);

	/* Additional section */
	for (i = 0; i < msg.dnameslen; i++) {

		additional = heap_search(z->data, msg.dnames[i]);

		/* This is a glue record */
		if ((*dkey < *msg.dnames[i]) &&
		    (memcmp(dkey + 1, msg.dnames[i] + (*msg.dnames[i] - *dkey) + 1, *dkey) == 0)) {
			if (additional == NULL) {
				fprintf(stderr, "zonec: missing glue record for %s\n", dnamestr(msg.dnames[i]));
			} else {
				/* Add duplicate for this glue with better name compression... */
				zone_addzonecut(msg.dnames[i], dname, rrset, z, db);

				/* Mark it as out of zone data */
				additional->glue = 1;
			}
		}

		while (additional) {
			if (additional->type == TYPE_A || additional->type == TYPE_AAAA) {
				msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
			}
			additional = additional->next;
		}
	}

	/* Add this answer */
	d = zone_addanswer(d, &msg, rrset->type);

	/* Add a terminator... */
	d = xrealloc(d, d->size + sizeof(uint32_t));
	memset((char *)d + d->size, 0, sizeof(uint32_t));
	d->size += sizeof(uint32_t);

	/* Store it */
	if (namedb_put(db, dkey, d) != 0) {
		fprintf(stderr, "zonec: error writing the database: %s\n", strerror(errno));
	}

	free(d);
}

static void
zone_adddata(const uint8_t *dname, struct rrset *rrset, struct zone *z, struct namedb *db) {
	struct domain *d;
	struct message msg, msgany;
	struct rrset *cnamerrset, *additional;
	const uint8_t *cname, *nameptr;
	int i, star;

	int namedepth = 0;

	/* Create a new domain, not a delegation */
	d = xalloc_zero(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = 0;

	/* This is not a wildcard */
	star = 0;

	/* Node with data? */
	if (rrset->type != 0) {
		/* Is this a CNAME */
		if (rrset->type == TYPE_CNAME) {
			/* XXX Not necessarily with NXT, BUT OH OH * assert(rrset->next == NULL); */
			cnamerrset = rrset;
			cname = (uint8_t *)(*cnamerrset->rrs[0]+1);
			rrset = heap_search(z->data, cname);
		} else {
			cnamerrset = NULL;
			cname = NULL;
		}

		/* Initialize message for TYPE_ANY */
		zone_initmsg(&msgany);

		/* XXX This is a bit confusing, needs renaming:
		 *
		 * cname - name of the target set
		 * rrset - target rr set
		 * cnamerrset - cname own rrset 
		 * dname - cname's rrset owner name
		 */
		while (rrset || cnamerrset) {
			/*
			 * When a CNAME points to a SOA record, don't
			 * add it to the answer.  Otherwise bug #56
			 * gets triggered because AXFR terminates
			 * early (because it thinks the final SOA
			 * record was encountered).
			 */
			if (cnamerrset && rrset && rrset->type == TYPE_SOA) {
				rrset = rrset->next;
				continue;
			}
			
			/* Initialize message */
			zone_initmsg(&msg);

			/* If we're done with the target sets, add CNAME itself */
			if (rrset == NULL) {
				rrset = cnamerrset;
				cnamerrset = NULL;
			}

			/* Put the dname into compression array */
			for (namedepth = 0, nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
				/* Do we have a wildcard? */
				if ((namedepth == 0) && (*(nameptr+1) == '*')) {
					star = 1;
				} else {
					if ((dname + *dname + 1 - nameptr) > 1) {
						zone_addcompr(&msg, nameptr,
							      (nameptr - (dname + 1)) | 0xc000,
							      dname + *dname + 1 - nameptr);
						zone_addcompr(&msgany, nameptr,
							      (nameptr - (dname + 1)) | 0xc000,
							      dname + *dname + 1 - nameptr);
					}
				}
			}

			/* Are we doing CNAME? */
			if (cnamerrset) {
				/* Add CNAME itself */
				msg.ancount += zone_addrrset(&msg, dname, cnamerrset);

				/* Add answer */
				msg.ancount += zone_addrrset(&msg, cname, rrset);
			} else {
				/* Answer section */
				msg.ancount += zone_addrrset(&msg, dname, rrset);

				/* Answer section of message any */
				msgany.ancount += zone_addrrset(&msgany, dname, rrset);
			}

			/* Authority section */
			msg.nscount = zone_addrrset(&msg, z->dname, z->ns);

			/* Additional section */
			for (i = 0; i < msg.dnameslen; i++) {
				additional = heap_search(z->data, msg.dnames[i]);
				while (additional) {
					if (additional->type == TYPE_A || additional->type == TYPE_AAAA) {
						msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
					}
					additional = additional->next;
				}
			}

			/* Add this answer */
			d = zone_addanswer(d, &msg, rrset->type);

			rrset = rrset->next;
		}

		/* Authority section for TYPE_ANY */
		msgany.nscount = zone_addrrset(&msgany, z->dname, z->ns);

		/* Additional section for TYPE_ANY */
		for (i = 0; i < msgany.dnameslen; i++) {
			additional = heap_search(z->data, msgany.dnames[i]);
			while (additional) {
				if (additional->type == TYPE_A || additional->type == TYPE_AAAA) {
					msgany.arcount += zone_addrrset(&msgany, msgany.dnames[i], additional);
				}
				additional = additional->next;
			}
		}

		/* Add this answer */
		d = zone_addanswer(d, &msgany, TYPE_ANY);
	} else {
		/* This is an empty node...*/
		d->flags |= NAMEDB_STEALTH;
		for (namedepth = 0, nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1, namedepth++);
	}

	/* Add a terminator... */
	d = xrealloc(d, d->size + sizeof(uint32_t));
	memset((char *)d + d->size, 0, sizeof(uint32_t));
	d->size += sizeof(uint32_t);

	/* Store it */
	if (namedb_put(db, dname, d) != 0) {
		fprintf(stderr, "zonec: error writing the database: %s\n", strerror(errno));
	}

	free(d);
}

/*
 * Writes zone data into open database *db
 *
 * Returns zero if success.
 */
static int 
zone_dump (struct zone *z, struct namedb *db)
{
	uint8_t dnamebuf[MAXDOMAINLEN+1];
	struct rrset *rrset;
	const uint8_t *dname;
	uint8_t *nameptr;
	
	/* Progress reporting... */
	unsigned long progress = 0;
	unsigned long fraction = 0;
	int percentage = 0;

	/* Set up the counter... */
	if (vflag > 1) {
		fraction = (z->cuts->count + z->data->count) / 20;	/* Report every 5% */
		if (fraction == 0)
			fraction = ULONG_MAX;
	}

	/* SOA RECORD FIRST */
	if (z->soa != NULL) {
		zone_adddata(z->dname, z->soa, z, db);
	} else {
		fprintf(stderr, "SOA record not present in %s\n", dnamestr(z->dname));
		totalerrors++;
		/* return -1; */
	}

	/* AUTHORITY CUTS */
	HEAP_WALK(z->cuts, dname, rrset) {
		/* Report progress... */
		if (vflag > 1) {
			if ((++progress % fraction) == 0) {
				printf("zonec: writing zone \"%s\": %d%%\r", dnamestr(z->dname), percentage);
				percentage += 5;
				fflush(stdout);
			}
		}

		/* Make sure the data is intact */
		if (rrset->type != TYPE_NS || rrset->next != NULL) {
			fprintf(stderr, "NS record with other data for %s\n", dnamestr(z->dname));
			totalerrors++;
			continue;
		}
		zone_addzonecut(dname, dname, rrset, z, db);

	}

	/* OTHER DATA */
	HEAP_WALK(z->data, dname, rrset) {
		/* Report progress... */
		if (vflag > 1) {
			if ((++progress % fraction) == 0) {
				printf("zonec: writing zone \"%s\": %d%%\r", dnamestr(z->dname), percentage);
				percentage += 5;
				fflush(stdout);
			}
		}

		/* Skip out of zone data */
		if (rrset->glue == 1)
			continue;

		/* Skip SOA because we added it first */
		if (rrset == z->soa)
			continue;

		/* This is an ugly slow way to find out of zone data... */
		memcpy(dnamebuf, dname, *dname + 1);
		for (nameptr = dnamebuf + 1; *(nameptr - 1) > *z->dname; 
				nameptr += *nameptr + 1, *(nameptr - 1) = dnamebuf + *dnamebuf - nameptr + 1) {

			if (heap_search(z->cuts, nameptr - 1)) {
				rrset->glue = 1;
				break;
			}
		}

		/* Skip out of zone data */
		if (rrset->glue == 1)
			continue;

		/* CNAME & other data */
		if ((rrset->type == TYPE_CNAME && rrset->next != NULL) ||
			(rrset->next != NULL && rrset->next->type == TYPE_CNAME)) {
			if (rrset->type != TYPE_NXT && rrset->next->type != TYPE_NXT) {
				if (rrset->type != TYPE_SIG && rrset->next->type != TYPE_SIG) {
					fprintf(stderr, "CNAME and other data for %s\n", dnamestr(z->dname));
					totalerrors++;
					continue;
				}
			}
		}

		/* Add it to the database */
		zone_adddata(dname, rrset, z, db);
	}

	fflush(stdout);
	if (vflag > 0) {
		fprintf(stderr, "zonec: writing zone \"%s\": done.\n",
			dnamestr(z->dname));
	}

	return 0;
}

static void 
usage (void)
{
	fprintf(stderr, "usage: zonec [-v] [-p] [-f database] [-d directory] zone-list-file\n\n");
	fprintf(stderr, "\t-p\tprint rr after compilation\n");
	fprintf(stderr, "\t-v\tbe more verbose\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int 
main (int argc, char **argv)
{
	char *zonename, *zonefile, *s;
	char buf[LINEBUFSZ];
    struct namedb *db;
	const char *sep = " \t\n";
	int c;
	int line = 0;
	FILE *f;

	struct zone *z = NULL;

	log_init("zonec");
	zone_region = region_create(xalloc, free);
	
	totalerrors = 0;

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "d:f:vp")) != -1) {
		switch (c) {
		case 'p':
			pflag = 1;
			break;
		case 'v':
			++vflag;
			break;
		case 'f':
			dbfile = optarg;
			break;
		case 'd':
			if (chdir(optarg)) {
				fprintf(stderr, "zonec: cannot chdir to %s: %s\n", optarg, strerror(errno));
				break;
			}
			break;
		case '?':
		default:
			usage();
		}
	}

	argc -= optind;
	argv += optind;

	if (argc != 1)
		usage();

	/* Create the database */
	if ((db = namedb_new(dbfile)) == NULL) {
		fprintf(stderr, "zonec: error creating the database: %s\n", strerror(errno));
		exit(1);
	}

	/* Open the master file... */
	if ((f = fopen(*argv, "r")) == NULL) {
		fprintf(stderr, "zonec: cannot open %s: %s\n", *argv, strerror(errno));
		exit(1);
	}

	/* Do the job */
	while (fgets(buf, LINEBUFSZ - 1, f) != NULL) {
		/* Count the lines... */
		line++;

		/* Skip empty lines and comments... */
		if ((s = strtok(buf, sep)) == NULL || *s == ';')
			continue;

		if (strcasecmp(s, "zone") != 0) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Zone name... */
		if ((zonename = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* File name... */
		if ((zonefile = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Trailing garbage? Ignore masters keyword that is used by nsdc.sh update */
		if ((s = strtok(NULL, sep)) != NULL && *s != ';' && strcasecmp(s, "masters") != 0
			&& strcasecmp(s, "notify") != 0) {
			fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
		}

		/* If we did not have any errors... */
		if ((z = zone_read(zonename, zonefile)) != NULL) {
			zone_dump(z, db);
			if (pflag)
				zone_print(z);
		} else {
			totalerrors++;
		}

		region_free_all(zone_region);
	};

	/* Close the database */
	if (namedb_save(db) != 0) {
		fprintf(stderr, "zonec: error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	/* Print the total number of errors */
	fprintf(stderr, "zonec: done with total %d errors.\n", totalerrors);

	region_destroy(zone_region);
	
	return totalerrors ? 1 : 0;
}
