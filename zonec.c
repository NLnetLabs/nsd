/*
 * $Id: zonec.c,v 1.21 2002/02/12 13:26:55 alexis Exp $
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

#include "zonec.h"


/* The database file... */
char *dbfile = DEFAULT_DBFILE;

/* The database masks */
u_char bitmasks[NAMEDB_BITMASKLEN * 3];
u_char *authmask = bitmasks;
u_char *starmask = bitmasks + NAMEDB_BITMASKLEN;
u_char *datamask = bitmasks + NAMEDB_BITMASKLEN * 2;

#ifdef	USE_HEAP_HASH

#ifdef __STDC__

unsigned long 
dnamehash (register u_char *dname)
#else

unsigned long
dnamehash(dname)
	register u_char *dname;
#endif
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
#ifdef __STDC__

void *
xalloc (register size_t size)
#else

void *
xalloc(size)
	register size_t	size;
#endif
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "malloc failed: %s\n", strerror(errno));
		exit(1);
	}
	return p;
}

#ifdef __STDC__

void *
xrealloc (register void *p, register size_t size)
#else

void *
xrealloc(p, size)
	register void *p;
	register size_t	size;
#endif
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "realloc failed: %s\n", strerror(errno));
		exit(1);
	}
	return p;
}

#ifdef __STDC__

void 
zone_print (struct zone *z)
#else

void
zone_print(z)
	struct zone *z;
#endif
{
	struct rrset *rrset;
	u_char *dname;
	int i;

	printf("; zone %s\n", dnamestr(z->dname));
	printf("; zone data\n");

	HEAP_WALK(z->data, (char *)dname, rrset) {
		while(rrset) {
			for(i = 0; i < rrset->rrslen; i++) {
				printf("%s\t%d\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
					 classtoa(rrset->class), typetoa(rrset->type));
				zf_print_rdata(rrset->rrs[i], rrset->fmt);
				printf("\n");
			}
			rrset = rrset->next;
		}
	}

	printf("; zone cuts\n");
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		while(rrset) {
			for(i = 0; i < rrset->rrslen; i++) {
				printf("%s\t%d\t%s\t%s\t", dnamestr(dname), rrset->ttl, \
					 classtoa(rrset->class), typetoa(rrset->type));
				zf_print_rdata(rrset->rrs[i], rrset->fmt);
				printf("\n");
			}
			rrset = rrset->next;
		}
	}
}

#ifdef __STDC__

u_int16_t 
zone_addname (struct message *msg, u_char *dname)
#else

u_int16_t
zone_addname(msg, dname)
	struct message *msg;
	u_char *dname;
#endif
{
	/* Lets try rdata dname compression */
	int rdlength = 0;
	int j;
	u_int16_t rdname_pointer = 0;
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
					rdname_pointer = (u_int16_t)msg->compr[j].dnameoff;
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



/*
 * XXXX: Check msg->buf boundaries!!!!!
 */
#ifdef __STDC__

u_int16_t 
zone_addrrset (struct message *msg, u_char *dname, struct rrset *rrset)
#else

u_int16_t
zone_addrrset(msg, dname, rrset)
	struct message *msg;
	u_char *dname;
	struct rrset *rrset;
#endif
{
	u_int16_t class = htons(CLASS_IN);
	int32_t ttl;
	union zf_rdatom *rdata;
	char *rdlengthptr;
	char *f;
	size_t size;
	u_int16_t rdlength;
	u_int16_t type;
	int rrcount;
	int i, j;

	u_int32_t l;
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

	/* Please sign in here... */
	msg->rrsets[msg->rrsetslen++] = rrset;

	for(rrcount = 0, j = 0; j < rrset->rrslen; j++, rrcount++) {
		/* Add the offset of this record */
		msg->rrsetsoffs[msg->rrsetsoffslen++] = (msg->bufptr - msg->buf) | (rrset->color ? NAMEDB_RRSET_WHITE : 0);

		rdata = rrset->rrs[j];

		/* dname */
		zone_addname(msg, dname);

		/* type */
		type = htons(rrset->type);
		bcopy(&type, msg->bufptr, sizeof(u_int16_t));
		msg->bufptr += sizeof(u_int16_t);

		/* class */
		bcopy(&class, msg->bufptr, sizeof(u_int16_t));
		msg->bufptr += sizeof(u_int16_t);

		/* ttl */
		ttl = htonl(rrset->ttl);
		bcopy(&ttl, msg->bufptr, sizeof(int32_t));
		msg->bufptr += sizeof(int32_t);

		/* rdlength */
		rdlengthptr = msg->bufptr;
		rdlength = 0;
		msg->bufptr += sizeof(u_int16_t);

		/* Pack the rdata */
		for(size = 0, i = 0, f = rrset->fmt; *f; f++, i++, size = 0) {
			switch(*f) {
			case '4':
				size = sizeof(u_int32_t);
				bcopy((char *)&rdata[i].l, msg->bufptr, size);
				break;
			case 'l':
				size = sizeof(int32_t);
				l = htonl(rdata[i].l);
				bcopy((char *)&l, msg->bufptr, size);
				break;
			case '6':
				size = IP6ADDRLEN;
				bcopy((char *)rdata[i].p, msg->bufptr, size);
				break;
			case 'n':
				size = 0;
				rdlength += zone_addname(msg, rdata[i].p);
				msg->dnames[msg->dnameslen++] = rdata[i].p;
				break;
			case 't':
				size = *((char *)rdata[i].p) + 1;
				bcopy((char *)rdata[i].p, msg->bufptr, size);
				break;
			case 's':
				size = sizeof(u_int16_t);
				s = htons(rdata[i].s);
				bcopy((char *)&s, msg->bufptr, size);
				break;
			default:
				fprintf(stderr, "panic! uknown atom in format %c\n", *f);
				return rrcount;
			}
			msg->bufptr += size;
			rdlength += size;
		}
		rdlength = htons(rdlength);
		bcopy(&rdlength, rdlengthptr, sizeof(u_int16_t));
	}
	return rrcount;
}

/*
 * Adds an answer to a domain
 *
 */
#ifdef __STDC__

struct domain *
zone_addanswer (struct domain *d, struct message *msg, int type)
#else

struct domain *
zone_addanswer(d, msg, type)
	struct domain *d;
	struct message *msg;
	u_int16_t type;
#endif
{
	struct answer *a;
	size_t datasize = msg->bufptr - msg->buf;
	size_t size = sizeof(struct answer) + msg->pointerslen * sizeof(u_int16_t) /* ptrs */
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

	bcopy(msg->pointers, ANSWER_PTRS_PTR(a), sizeof(u_int16_t) * msg->pointerslen);
	bcopy(msg->rrsetsoffs, ANSWER_RRS_PTR(a), sizeof(u_int16_t) * msg->rrsetsoffslen);
	bcopy(msg->buf, ANSWER_DATA_PTR(a), datasize);

	d->size += size;

	return d;
}

/*
 * Frees all the data structures associated with the zone
 *
 */
#ifdef __STDC__

void 
zone_free (struct zone *z)
#else

void
zone_free(z)
	struct zone *z;
#endif
{
	if(z) {
		if(z->dname) free(z->dname);
		heap_destroy(z->cuts, 1, 1);
		heap_destroy(z->data, 1, 1);
		free(z);
	}
}

/*
 * Reads the specified zone into the memory
 *
 */
#ifdef __STDC__

struct zone *
zone_read (char *name, char *zonefile, int cache)
#else

struct zone *
zone_read(name, zonefile, cache)
	char *name;
	char *zonefile;
	int cache;
#endif
{
	heap_t *h;
	int i;

	struct zone *z;
	struct zf *zf;
	struct zf_entry *rr;
	struct rrset *rrset, *r;

	/* Allocate new zone structure */
	z = xalloc(sizeof(struct zone));
	bzero(z, sizeof(struct zone));

	/* Get the zone name */
	if((z->dname = strdname(name, ROOT_ORIGIN)) == NULL) {
		zone_free(z);
		return NULL;
	}

	/* Open the zone file */
	if((zf = zf_open(zonefile, name)) == NULL) {
		zone_free(z);
		return NULL;
	}

	/* Two heaps: zone cuts and other data */
#ifdef USE_HEAP_RBTREE
	z->cuts = heap_create(xalloc, dnamecmp);
	z->data = heap_create(xalloc, dnamecmp);
#else ifdef USE_HEAP_HASH
	z->cuts = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
	z->data = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
#endif
	z->soa = z->ns = NULL;

	/* Read the file */
	while((rr = zf_read(zf)) != NULL) {

#ifdef DEBUG
		/* Report progress... */
		if((zf->lines % 100000) == 0) {
			fprintf(stderr, "read %u lines...\n", zf->lines);
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
				/* XXX We can use this more smart... */
				heap_insert(h, strdup(rr->dname), r, 1);
			} else {
				r->next = rrset->next;
				rrset->next = r;
			}
		} else {
			if(r->ttl != rr->ttl) {
				zf_error(zf, "rr ttl doesnt match the ttl of the rdataset");
				continue;
			}
			/* Search for possible duplicates... */
			for(i = 0; i < r->rrslen; i++) {
				if(!zf_cmp_rdata(r->rrs[i], rr->rdata, rr->rdatafmt))
					break;
			}

			/* Discard the duplicates... */
			if(i < r->rrslen) {
				/* zf_error(zf, "duplicate record"); */
				zf_free_rdata(rr->rdata, rr->rdatafmt);
				continue;
			}

			/* Add it... */
			r->rrs = xrealloc(r->rrs, ((r->rrslen + 1) * sizeof(union zf_rdatom *)));
			r->rrs[r->rrslen++] = rr->rdata;
		}

		/* Check we have SOA */
		if(z->soa == NULL) {
			if(rr->type != TYPE_SOA) {
				if(!cache) {
					zf_error(zf, "missing SOA record on top of the zone");
				}
			} else {
				if(dnamecmp(rr->dname, z->dname) != 0) {
					zf_error(zf, "SOA record with invalid domain name");
				} else {
					if(!cache) {
						z->soa = r;
					} else {
						zf_error(zf, "SOA record present in the cache");
					}
				}
			}
		} else {
			if(rr->type == TYPE_SOA) {
				zf_error(zf, "duplicate SOA record discarded");
				zf_free_rdata(r->rrs[--r->rrslen], r->fmt);
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
 * Writes zone data into open database *db
 *
 * Returns zero if success.
 */
#ifdef __STDC__

int 
zone_dump (struct zone *z, struct namedb *db)
#else

int
zone_dump(z, db)
	struct 	zone *z;
	struct namedb *db;
#endif
{
	struct domain *d;
	struct message msg, msgany;
	struct rrset *rrset, *cnamerrset, *additional;
	u_char *dname, *cname, *nameptr;
	u_char dnamebuf[MAXDOMAINLEN+1];
	int i, star, namedepth;

	/* AUTHORITY CUTS */
	HEAP_WALK(z->cuts, (char *)dname, rrset) {
		/* Make sure the data is intact */
		assert((rrset->next == NULL) && (rrset->type == TYPE_NS));

		/* Make sure it is not a wildcard */
		if(*dname >= 2 && *(dname + 1) == '\001' && *(dname + 2) == '*') {
			fprintf(stderr, "wildcard delegations are not allowed\n");
			continue;
		}

		/* Initialize message */
		bzero(&msg, sizeof(struct message));
		msg.bufptr = msg.buf;

		/* Create a new domain */
        	d = xalloc(sizeof(struct domain));
		d->size = sizeof(struct domain);
		d->flags = NAMEDB_DELEGATION;

		/* Put the dname into compression array */
		for(namedepth = 0, nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
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

			additional = heap_search(z->data, msg.dnames[i]);

			/* This is a glue record */
			if((*dname < *msg.dnames[i]) &&
			    (bcmp(dname + 1, msg.dnames[i] + (*msg.dnames[i] - *dname) + 1, *dname) == 0)) {
				if(additional == NULL) {
					fprintf(stderr, "missing glue record\n");
				} else {
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
		bzero((char *)d + d->size, sizeof(u_int32_t));
		d->size += sizeof(u_int32_t);

		/* Store it */
		if(namedb_put(db, dname, d) != 0) {
			fprintf(stderr, "error writing the database: %s\n", strerror(errno));
		}

		free(d);
	}

	/* OTHER DATA */
	HEAP_WALK(z->data, (char *)dname, rrset) {
		/* Skip out of zone data */
		if(rrset->glue == 1)
			continue;

		/* This is an ugly slow way to find out of zone data... */
		bcopy(dname, dnamebuf, *dname + 1);
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

		/* Create a new domain, not a delegation */
        	d = xalloc(sizeof(struct domain));
		d->size = sizeof(struct domain);
		d->flags = 0;

		/* This is not a wildcard */
		star = 0;

 		/* Is this a CNAME */
 		if(rrset->type == TYPE_CNAME) {
 			assert(rrset->next == NULL);
 			cnamerrset = rrset;
 			cname = (*cnamerrset->rrs)[0].p;	/* The name of the target set */
 			rrset = heap_search(z->data, cname);
 		} else {
 			cnamerrset = NULL;
 			cname = NULL;
 		}

		/* Initialize message for TYPE_ANY */
		bzero(&msgany, sizeof(struct message));
		msgany.bufptr = msgany.buf;

		/* XXX This is a bit confusing, needs renaming:
		 *
		 * cname - name of the target set
		 * rrset - target rr set
		 * cnamerrset - cname own rrset 
		 * dname - cname's rrset owner name
		 */
 		while(rrset || cnamerrset) {
			/* Initialize message */
			bzero(&msg, sizeof(struct message));
			msg.bufptr = msg.buf;

 			/* If we're done with the target sets, add CNAME itself */
 			if(rrset == NULL) {
 				rrset = cnamerrset;
 				cnamerrset = NULL;
 			}
 
			/* Put the dname into compression array */
			for(namedepth = 0, nameptr = dname + 1; *nameptr; nameptr += *nameptr + 1, namedepth++) {
				/* Do we have a wildcard? */
				if((namedepth == 0) && (*(nameptr+1) == '*')) {
					star = *nameptr + 1;
				} else {
					if((dname + *dname + 1 - nameptr) > 1) {
						msg.compr[msg.comprlen].dname = nameptr;
						msg.compr[msg.comprlen].dnameoff = (nameptr - (dname + 1 + star)) | 0xc000;
						msg.compr[msg.comprlen].dnamelen = dname + *dname + 1 - nameptr;
						msg.comprlen++;

						msgany.compr[msgany.comprlen].dname = nameptr;
						msgany.compr[msgany.comprlen].dnameoff = (nameptr - (dname + 1 + star)) | 0xc000;
						msgany.compr[msgany.comprlen].dnamelen = dname + *dname + 1 - nameptr;
						msgany.comprlen++;
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
		bzero((char *)d + d->size, sizeof(u_int32_t));
		d->size += sizeof(u_int32_t);

		/* Store it */
		if(namedb_put(db, dname, d) != 0) {
			fprintf(stderr, "error writing the database: %s\n", strerror(errno));
		}

		free(d);
	}

	return 0;
}

#ifdef __STDC__

int 
usage (void)
#else

int
usage()
#endif
{
	fprintf(stderr, "usage: zonec [-a] [-f database] [-c cache-file] -z zone-name [zone-file] [...]\n");
	exit(1);
}

#ifdef __STDC__

int 
main (int argc, char **argv)
#else

int
main(argc, argv)
	int argc;
	char **argv;
#endif
{
        struct namedb *db;
	int aflag = 0;
	int options = 1;
	int cache = 0;
	char *zonefile, *zonename;
	struct zone *z;

	/* No command line? */
	if(argc == 1)
		usage();

	/* Parse the command line */
	while(options) {
		argc--;
		argv++;

		if(argc == 0 || **argv != '-') usage();

		switch(*(*argv+1)) {
		case 'a':
			aflag++;
			break;
		case 'f':
			dbfile = *(++argv); argc--;
			break;
		case 'c':
		case 'z':
			options = 0;
			break;
		default:
			usage();
		}
	}

	/* Create the database */
	if((db = namedb_new(dbfile)) == NULL) {
		fprintf(stderr, "erorr creating the database: %s\n", strerror(errno));
		exit(1);
	}

	/* Do the job */	
	while(argc) {
		if(**argv == '-') {
			if(*(*argv + 1) == 'c') {
				cache = 1;
			} else if(*(*argv + 1) == 'z') {
				cache = 0;
			} else {
				fprintf(stderr, "either -z or -c expected\n");
				break;
			}
		} else {
			fprintf(stderr, "either -z or -c expected\n");
			break;
		}
		argc--; zonename = *(++argv);

		/* Look ahead... */
		if(--argc > 0 && **(++argv) != '-') {
			zonefile = *argv;
			argv++; argc--;
		} else {
			zonefile = zonename;
		}

		/* Read the zone... */
		if((z = zone_read(zonename, zonefile, cache)) != NULL) {
			zone_dump(z, db);
			zone_free(z);
		}
	};

	/* Close the database */
	if(namedb_save(db) != 0) {
		fprintf(stderr, "error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	return 0;
}
