/*
 * $Id: zonec.c,v 1.82 2003/03/19 14:09:25 alexis Exp $
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
#include <config.h>

#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <fcntl.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <heap.h>
#include <dns.h>
#include <zparser.h>
#include <namedb.h>
#include <dname.h>
#include <zonec.h>

#include <netinet/in.h>		/* htons, htonl on Linux */

static void zone_addbuf (struct message *, const void *, size_t);
static void zone_addcompr (struct message *msg, u_char *dname, int offset, int len);

/* The database file... */
char *dbfile = DBFILE;

/* The database masks */
u_char bitmasks[NAMEDB_BITMASKLEN * 3];
u_char *authmask = bitmasks;
u_char *starmask = bitmasks + NAMEDB_BITMASKLEN;
u_char *datamask = bitmasks + NAMEDB_BITMASKLEN * 2;

/* Some global flags... */
int vflag = 0;
int pflag = 0;

/* Total errors counter */
int totalerrors = 0;

#ifdef	USE_HEAP_HASH

unsigned long 
dnamehash (register u_char *dname)
{
        register unsigned long hash = 0;
	register u_char *p = dname;

	dname += *dname + 1;

        while (p < dname)
                hash = hash * 31 + *p++;
        return hash;
}

#endif

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * fprintf(stderr, ...);
 *
 */
void *
xalloc (register size_t size)
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "zonec: malloc failed: %m\n");
		exit(1);
	}
	return p;
}

void *
xrealloc (register void *p, register size_t size)
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "zonec: realloc failed: %m\n");
		exit(1);
	}
	return p;
}

void
zone_initmsg(struct message *m)
{
	m->ancount = m->nscount = m->arcount = m->dnameslen = m->rrsetslen
		= m->comprlen = m->pointerslen = m->rrsetsoffslen = 0;
	m->bufptr = m->buf;
}

void 
zone_print (struct zone *z)
{
	struct rrset *rrset;
	struct RR rr;
	u_char *dname;
	int i;

	printf("; zone %s\n", dnamestr(z->dname));
	printf("; zone data\n");

	HEAP_WALK(z->data, dname, rrset) {
		while(rrset) {
			rr.dname = dname;
			rr.ttl = rrset->ttl;
			rr.class = rrset->class;
			rr.type = rrset->type;
			for(i = 0; i < rrset->rrslen; i++) {
				rr.rdata = rrset->rrs[i];
				zprintrr(stdout, &rr);
			}
			rrset = rrset->next;
		}
	}

	printf("; referrals\n");
	HEAP_WALK(z->cuts, dname, rrset) {
		while(rrset) {
			rr.dname = dname;
			rr.ttl = rrset->ttl;
			rr.class = rrset->class;
			rr.type = rrset->type;
			for(i = 0; i < rrset->rrslen; i++) {
				rr.rdata = rrset->rrs[i];
				zprintrr(stdout, &rr);
			}
			rrset = rrset->next;
		}
	}
}

static void 
zone_addbuf (struct message *msg, const void *data, size_t size)
{
	if(msg->bufptr - msg->buf + size > IOBUFSZ) {
		fflush(stdout);
		fprintf(stderr, "zonec: insufficient buffer space\n"); /* RR set too large? */
		exit(1);	/* XXX: do something smart */
	}

	memcpy(msg->bufptr, data, size);
	msg->bufptr += size;
}

static void 
zone_addcompr (struct message *msg, u_char *dname, int offset, int len)
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

u_int16_t 
zone_addname (struct message *msg, u_char *dname)
{
	/* Lets try rdata dname compression */
	int rdlength = 0;
	int j;
	register u_char *t;

	/* Walk through the labels in the dname to be compressed */
	if(*dname > 1) {
		for(t = dname + 1; (t < (dname + 1 + *dname)); t += *t + 1) {
			/* Walk through the dnames that we have already in the packet */
			for(j = 0; j < msg->comprlen; j++) {
				if((msg->compr[j].dnamelen == (dname + 1 + *dname - t)) &&
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
			if((dname + 1 + *dname - t) > 1) {
				zone_addcompr(msg, t,
					      msg->bufptr - msg->buf + (t - (dname + 1)),
					      dname + 1 + *dname - t);
			}
		}
	}
	zone_addbuf(msg, dname + 1, *dname);
	return *dname;
}



u_int16_t 
zone_addrrset (struct message *msg, u_char *dname, struct rrset *rrset)
{
	u_int16_t class = htons(CLASS_IN);
	int32_t ttl;
	u_int16_t **rdata;
	u_char *rdlengthptr;
	u_int16_t rdlength;
	u_int16_t type;
	int rrcount;
	int i, j;

	u_int16_t s;

	if(rrset == NULL) return 0;

	/* Did I see you before? */
	for(i = 0; i < msg->rrsetslen; i++) {
		/* Not again, please! */
		if(rrset == msg->rrsets[i]) {
			return 0;
		}
	}

	/* Paint me black... */
	if(msg->rrsetslen) {
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

	for(rrcount = 0, j = 0; j < rrset->rrslen; j++, rrcount++) {
		/* Add the offset of this record */
		if (msg->rrsetsoffslen == MAXRRSPP) {
			fflush(stdout);
			fprintf(stderr, "zonec: too many rrsets offsets\n");
			exit(1);
		}
		
		msg->rrsetsoffs[msg->rrsetsoffslen++] = (msg->bufptr - msg->buf) | (rrset->color ? NAMEDB_RRSET_WHITE : 0);


		/* dname */
		if(*(dname + 1) == 1 && *(dname + 2) == '*') {
			if(msg->pointerslen == MAXRRSPP) {
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
		zone_addbuf(msg, &type, sizeof(u_int16_t));

		/* class */
		zone_addbuf(msg, &class, sizeof(u_int16_t));

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
		zone_addbuf(msg, &rdlength, sizeof(u_int16_t));

		/* Pack the rdata */
		
		for(rdata = rrset->rrs[j]; *rdata; rdata++) {
			/* Is it a domain name? */
			if(**rdata == 0xffff) {
				if (msg->dnameslen >= MAXRRSPP) {
					fflush(stdout);
					fprintf(stderr, "zonec: too many domain names\n");
					exit(1);
				}
				rdlength += zone_addname(msg, (u_char *)(*rdata + 1));
				msg->dnames[msg->dnameslen++] = (u_char *)(*rdata + 1);
			} else {
				zone_addbuf(msg, *rdata + 1, **rdata);
				rdlength += **rdata;
			}
		}
		rdlength = htons(rdlength);
		memcpy(rdlengthptr, &rdlength, sizeof(u_int16_t));
	}
	return rrcount;
}

/*
 * Adds an answer to a domain
 *
 */
struct domain *
zone_addanswer (struct domain *d, struct message *msg, int type)
{
	struct answer *a;
	size_t size, datasize;

	/* First add an extra rrset offset */
	msg->rrsetsoffs[msg->rrsetsoffslen++] = (msg->bufptr - msg->buf);

	datasize = msg->bufptr - msg->buf;
	size = sizeof(struct answer) + msg->pointerslen * sizeof(u_int16_t) /* ptrs */
		+ (msg->rrsetsoffslen) * sizeof(u_int16_t)	/* rrs */
		+ datasize;					/* data */

	/* Assure the alignment for the next answer... */
	size = ((size + 3) & 0xfffffffc);

	d = xrealloc(d, d->size + size);

	a = (struct answer *)((char *)d + d->size);

	ANSWER_SIZE(a) = size;
	ANSWER_TYPE(a) = htons(type);
	ANSWER_ANCOUNT(a) = htons(msg->ancount);
	ANSWER_NSCOUNT(a) = htons(msg->nscount);
	ANSWER_ARCOUNT(a) = htons(msg->arcount);
	ANSWER_PTRSLEN(a) = msg->pointerslen;
	ANSWER_RRSLEN(a) = msg->rrsetsoffslen;
	ANSWER_DATALEN(a) = datasize;

	memcpy(ANSWER_PTRS_PTR(a), msg->pointers, sizeof(u_int16_t) * msg->pointerslen);
	memcpy(ANSWER_RRS_PTR(a), msg->rrsetsoffs, sizeof(u_int16_t) * msg->rrsetsoffslen);
	memcpy(ANSWER_DATA_PTR(a), msg->buf, datasize);

	d->size += size;

	return d;
}

/*
 * Frees all the data structures associated with the zone
 *
 */
void 
zone_free (struct zone *z)
{
	if(z) {
		if(z->dname) free(z->dname);
		if(z->cuts) heap_destroy(z->cuts, 1, 1);
		if(z->data) heap_destroy(z->data, 1, 1);
		free(z);
	}
}

/*
 * Reads the specified zone into the memory
 *
 */
struct zone *
zone_read (char *name, char *zonefile)
{
	heap_t *h;
	int i;

	struct zone *z;
	struct zparser *parser;
	struct RR *rr;
	struct rrset *rrset, *r;

	/* Allocate new zone structure */
	z = xalloc(sizeof(struct zone));
	memset(z, 0, sizeof(struct zone));

	/* Get the zone name */
	if((z->dname = dnamedup(strdname(name, ROOT))) == NULL) {
		zone_free(z);
		return NULL;
	}

#ifndef ROOT_SERVER
	/* Is it a root zone? Are we a root server then? Idiot proof. */
	if(dnamecmp(z->dname, (u_char *)"\001") == 0) {
		fprintf(stderr, "zonec: Not configured as a root server. See documentation\n");
		zone_free(z);
		return NULL;
	}
#endif

	/* Open the zone file */
	if((parser = zopen(zonefile, 3600, CLASS_IN, name)) == NULL) {
		fprintf(stderr, "zonec: unable to open %s: %s\n", zonefile, strerror(errno));
		zone_free(z);
		return NULL;
	}

	/* Two heaps: zone cuts and other data */
#ifdef USE_HEAP_RBTREE
	z->cuts = heap_create(xalloc, (int (*)(void *, void *))dnamecmp);
	z->data = heap_create(xalloc, (int (*)(void *, void *))dnamecmp);
#else
# ifdef USE_HEAP_HASH
	z->cuts = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
	z->data = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
# endif
#endif
	z->soa = z->ns = NULL;

	/* Read the file */
	while((rr = zread(parser)) != NULL) {

		/* Report progress... */
		if(vflag) {
			if((parser->lines % 100000) == 0) {
				printf("zonec: reading zone \"%s\": %lu\r", dnamestr(z->dname), parser->lines);
				fflush(stdout);
			}
		}

		/* We only support IN class */
		if(rr->class != CLASS_IN) {
			zerror(parser, "wrong class");
			continue;
		}

		/* Is this in-zone data? */
		if((*z->dname > *rr->dname) ||
			(memcmp(z->dname + 1, rr->dname + (*rr->dname - *z->dname) + 1, *z->dname) != 0)) {
			zerror(parser, "out of zone data");
			continue;
		}

		/* Insert the record into a rrset */
		if(rr->type == TYPE_NS && ((dnamecmp(rr->dname, z->dname) != 0) || (z->soa == NULL))) {
			h = z->cuts;
		} else {
			h = z->data;
		}

		/* Do we have this domain name in heap? */
		if((rrset = heap_search(h, rr->dname)) != NULL) {
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

			r->next = NULL;
			r->type = rr->type;
			r->class = rr->class;
			r->ttl = rr->ttl;
			r->rrslen = 1;
			r->rrs = xalloc(sizeof(u_int16_t *) * 2);
			r->glue = r->color = 0;
			r->rrs[0] = rr->rdata;

			/* Add it */
			if(rrset == NULL) {
				/* XXX We can use this more smart... */
				heap_insert(h, dnamedup(rr->dname), r, 1);
			} else {
				r->next = rrset->next;
				rrset->next = r;
			}
		} else {
			if(r->ttl != rr->ttl) {
				zerror(parser, "ttl doesnt match the ttl of the rrset");
				continue;
			}

			/* Search for possible duplicates... */
			for(i = 0; i < r->rrslen; i++) {
				if(!zrdatacmp(r->rrs[i], rr->rdata))
					break;
			}

			/* Discard the duplicates... */
			if(i < r->rrslen) {
				/* zerror(parser, "duplicate record"); */
				zrdatafree(rr->rdata);
				continue;
			}

			/* Add it... */
			r->rrs = xrealloc(r->rrs, ((r->rrslen + 2) * sizeof(u_int16_t *)));
			r->rrs[r->rrslen++] = rr->rdata;
			r->rrs[r->rrslen] = NULL;
		}

		/* Check we have SOA */
		if(z->soa == NULL) {
			if(rr->type != TYPE_SOA) {
				zerror(parser, "missing SOA record on top of the zone");
			} else {
				if(dnamecmp(rr->dname, z->dname) != 0) {
					zerror(parser, "SOA record with invalid domain name");
				} else {
					z->soa = r;
				}
			}
		} else {
			if(rr->type == TYPE_SOA) {
				zerror(parser, "duplicate SOA record discarded");
				zrdatafree(r->rrs[--r->rrslen]);
			}
		}

		/* Is this a zone NS? */
		if(rr->type == TYPE_NS && h == z->data) {
			z->ns = r;
		}

	}

	fflush(stdout);
	fprintf(stderr, "zonec: reading zone \"%s\": %d errors\n", dnamestr(z->dname), parser->errors);
	totalerrors += parser->errors;
	return z;
}

static void
zone_addzonecut(u_char *dkey, u_char *dname, struct rrset *rrset, struct zone *z, struct namedb *db)
{
	struct domain *d;
	struct message msg;
	struct rrset *additional;
	u_char *nameptr;
	int i, namedepth;

	/* Make sure it is not a wildcard */
	if(*dname >= 2 && *(dname + 1) == '\001' && *(dname + 2) == '*') {
		fprintf(stderr, "zonec: wildcard delegations are not allowed (ignored)\n");
		return;
	}

	/* Initialize message */
	zone_initmsg(&msg);

	/* Create a new domain */
	d = xalloc(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = NAMEDB_DELEGATION;

	/* Is this a real record? */
	if(dkey != dname)
		d->flags |= NAMEDB_STEALTH;

	/* Put the dkey into compression array */
	for(namedepth = 0, nameptr = dkey + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
		if((dkey + *dkey + 1 - nameptr) > 1) {
			zone_addcompr(&msg, nameptr,
				      (nameptr - (dkey + 1)) | 0xc000,
				      dkey + *dkey + 1 - nameptr);
		}
	}

	/* Authority section */
	msg.nscount = zone_addrrset(&msg, dname, rrset);

	/* Additional section */
	for(i = 0; i < msg.dnameslen; i++) {

		additional = heap_search(z->data, msg.dnames[i]);

		/* This is a glue record */
		if((*dkey < *msg.dnames[i]) &&
		    (memcmp(dkey + 1, msg.dnames[i] + (*msg.dnames[i] - *dkey) + 1, *dkey) == 0)) {
			if(additional == NULL) {
				fprintf(stderr, "zonec: missing glue record for %s\n", dnamestr(msg.dnames[i]));
			} else {
				/* Add duplicate for this glue with better name compression... */
				zone_addzonecut(msg.dnames[i], dname, rrset, z, db);

				/* Mark it as out of zone data */
				additional->glue = 1;
			}
		}

		while(additional) {
			if(additional->type == TYPE_A || additional->type == TYPE_AAAA) {
				msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
			}
			additional = additional->next;
		}
	}

	/* Add this answer */
	d = zone_addanswer(d, &msg, rrset->type);

	/* Set the database masks */
	NAMEDB_SETBITMASK(db, NAMEDB_DATAMASK, namedepth);
	NAMEDB_SETBITMASK(db, NAMEDB_AUTHMASK, namedepth);

	/* Add a terminator... */
	d = xrealloc(d, d->size + sizeof(u_int32_t));
	memset((char *)d + d->size, 0, sizeof(u_int32_t));
	d->size += sizeof(u_int32_t);

	/* Store it */
	if(namedb_put(db, dkey, d) != 0) {
		fprintf(stderr, "zonec: error writing the database: %s\n", strerror(errno));
	}

	free(d);
}

static void
zone_adddata(u_char *dname, struct rrset *rrset, struct zone *z, struct namedb *db) {
	struct domain *d;
	struct message msg, msgany;
	struct rrset *cnamerrset, *additional;
	u_char *cname, *nameptr;
	int i, star;

	int namedepth = 0;

	/* Create a new domain, not a delegation */
	d = xalloc(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = 0;

	/* This is not a wildcard */
	star = 0;

	/* Is this a CNAME */
	if(rrset->type == TYPE_CNAME) {
		/* XXX Not necessarily with NXT, BUT OH OH * assert(rrset->next == NULL); */
		cnamerrset = rrset;
		cname = (u_char *)(*cnamerrset->rrs[0]+1);
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
	while(rrset || cnamerrset) {
		/* Initialize message */
		zone_initmsg(&msg);

		/* If we're done with the target sets, add CNAME itself */
		if(rrset == NULL) {
			rrset = cnamerrset;
			cnamerrset = NULL;
		}

		/* Put the dname into compression array */
		for(namedepth = 0, nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
			/* Do we have a wildcard? */
			if((namedepth == 0) && (*(nameptr+1) == '*')) {
				star = 1;
			} else {
				if((dname + *dname + 1 - nameptr) > 1) {
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
		if(cnamerrset) {
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
		for(i = 0; i < msg.dnameslen; i++) {
			additional = heap_search(z->data, msg.dnames[i]);
			while(additional) {
				if(additional->type == TYPE_A || additional->type == TYPE_AAAA) {
					msg.arcount += zone_addrrset(&msg, msg.dnames[i], additional);
				}
				additional = additional->next;
			}
		}

		/* Add this answer */
		d = zone_addanswer(d, &msg, rrset->type);

		/* Set the masks */
		if(rrset->type == TYPE_SOA)
			NAMEDB_SETBITMASK(db, NAMEDB_AUTHMASK, namedepth);

		rrset = rrset->next;
	}

	/* Authority section for TYPE_ANY */
	msgany.nscount = zone_addrrset(&msgany, z->dname, z->ns);

	/* Additional section for TYPE_ANY */
	for(i = 0; i < msgany.dnameslen; i++) {
		additional = heap_search(z->data, msgany.dnames[i]);
		while(additional) {
			if(additional->type == TYPE_A || additional->type == TYPE_AAAA) {
				msgany.arcount += zone_addrrset(&msgany, msgany.dnames[i], additional);
			}
			additional = additional->next;
		}
	}

	/* Add this answer */
	d = zone_addanswer(d, &msgany, TYPE_ANY);

	/* Set the data mask */
	NAMEDB_SETBITMASK(db, NAMEDB_DATAMASK, namedepth);
	if(star) {
		NAMEDB_SETBITMASK(db, NAMEDB_STARMASK, namedepth);
	}

	/* Add a terminator... */
	d = xrealloc(d, d->size + sizeof(u_int32_t));
	memset((char *)d + d->size, 0, sizeof(u_int32_t));
	d->size += sizeof(u_int32_t);

	/* Store it */
	if(namedb_put(db, dname, d) != 0) {
		fprintf(stderr, "zonec: error writing the database: %s\n", strerror(errno));
	}

	free(d);
}

/*
 * Writes zone data into open database *db
 *
 * Returns zero if success.
 */
int 
zone_dump (struct zone *z, struct namedb *db)
{
	u_char dnamebuf[MAXDOMAINLEN+1];
	struct rrset *rrset;
	u_char *dname, *nameptr;
	
	/* Progress reporting... */
	unsigned long progress = 0;
	unsigned long fraction = 0;
	int percentage = 0;

	/* Set up the counter... */
	if(vflag) {
		fraction = (z->cuts->count + z->data->count) / 20;	/* Report every 5% */
		if(fraction == 0)
			fraction = ULONG_MAX;
	}

	/* SOA RECORD FIRST */
	if(z->soa != NULL) {
		zone_adddata(z->dname, z->soa, z, db);
	} else {
		fprintf(stderr, "SOA record not present in %s\n", dnamestr(z->dname));
		totalerrors++;
		/* return -1; */
	}

	/* AUTHORITY CUTS */
	HEAP_WALK(z->cuts, dname, rrset) {
		/* Report progress... */
		if(vflag) {
			if((++progress % fraction) == 0) {
				printf("zonec: writing zone \"%s\": %d%%\r", dnamestr(z->dname), percentage);
				percentage += 5;
				fflush(stdout);
			}
		}

		/* Make sure the data is intact */
		if(rrset->type != TYPE_NS || rrset->next != NULL) {
			fprintf(stderr, "NS record with other data for %s\n", dnamestr(z->dname));
			totalerrors++;
			continue;
		}
		zone_addzonecut(dname, dname, rrset, z, db);

	}

	/* OTHER DATA */
	HEAP_WALK(z->data, dname, rrset) {
		/* Report progress... */
		if(vflag) {
			if((++progress % fraction) == 0) {
				printf("zonec: writing zone \"%s\": %d%%\r", dnamestr(z->dname), percentage);
				percentage += 5;
				fflush(stdout);
			}
		}

		/* Skip out of zone data */
		if(rrset->glue == 1)
			continue;

		/* Skip SOA because we added it first */
		if(rrset == z->soa)
			continue;

		/* This is an ugly slow way to find out of zone data... */
		memcpy(dnamebuf, dname, *dname + 1);
		for(nameptr = dnamebuf + 1; *(nameptr - 1) > *z->dname; 
				nameptr += *nameptr + 1, *(nameptr - 1) = dnamebuf + *dnamebuf - nameptr + 1) {

			if(heap_search(z->cuts, nameptr - 1)) {
				rrset->glue = 1;
				break;
			}
		}

		/* Skip out of zone data */
		if(rrset->glue == 1)
			continue;

		/* CNAME & other data */
		if((rrset->type == TYPE_CNAME && rrset->next != NULL) ||
			(rrset->next != NULL && rrset->next->type == TYPE_CNAME)) {
			if(rrset->type != TYPE_NXT && rrset->next->type != TYPE_NXT) {
				fprintf(stderr, "CNAME and other data for %s\n", dnamestr(z->dname));
				totalerrors++;
				continue;
			}
		}

		/* Add it to the database */
		zone_adddata(dname, rrset, z, db);
	}

	fflush(stdout);
	fprintf(stderr, "zonec: writing zone \"%s\": done.\n", dnamestr(z->dname));

	return 0;
}

void 
usage (void)
{
	fprintf(stderr, "usage: zonec [-f database] [-d directory] zone-list-file\n");
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
	char *sep = " \t\n";
	int c;
	int line = 0;
	FILE *f;

	struct zone *z = NULL;

	totalerrors = 0;

	/* Parse the command line... */
	while((c = getopt(argc, argv, "d:f:vp")) != -1) {
		switch (c) {
		case 'p':
			pflag = 1;
			break;
		case 'v':
			vflag = 1;
			break;
		case 'f':
			dbfile = optarg;
			break;
		case 'd':
			if(chdir(optarg)) {
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

	if(argc != 1)
		usage();

	/* Create the database */
	if((db = namedb_new(dbfile)) == NULL) {
		fprintf(stderr, "zonec: error creating the database: %s\n", strerror(errno));
		exit(1);
	}

	/* Open the master file... */
	if((f = fopen(*argv, "r")) == NULL) {
		fprintf(stderr, "zonec: cannot open %s: %s\n", *argv, strerror(errno));
		exit(1);
	}

	/* Do the job */
	while(fgets(buf, LINEBUFSZ - 1, f) != NULL) {
		/* Count the lines... */
		line++;

		/* Skip empty lines and comments... */
		if((s = strtok(buf, sep)) == NULL || *s == ';')
			continue;

		if(strcasecmp(s, "zone") != 0) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Zone name... */
		if((zonename = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* File name... */
		if((zonefile = strtok(NULL, sep)) == NULL) {
			fprintf(stderr, "zonec: syntax error in %s line %d\n", *argv, line);
			break;
		}

		/* Trailing garbage? Ignore masters keyword that is used by nsdc.sh update */
		if((s = strtok(NULL, sep)) != NULL && *s != ';' && strcasecmp(s, "masters") != 0
			&& strcasecmp(s, "notify") != 0) {
			fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
		}

		/* Free a zone if any... */
		if(z != NULL) {
			zone_free(z);
			z = NULL;
		}

		/* If we did not have any errors... */
		if((z = zone_read(zonename, zonefile)) != NULL) {
			zone_dump(z, db);
			if(pflag)
				zone_print(z);
		} else {
			totalerrors++;
		}

	};

	/* Close the database */
	if(namedb_save(db) != 0) {
		fprintf(stderr, "zonec: error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	/* Print the total number of errors */
	fprintf(stderr, "zonec: done with total %d errors.\n", totalerrors);

	return totalerrors ? 1 : 0;
}
