/*
 * $Id: zonec.c,v 1.46 2002/02/22 11:37:12 alexis Exp $
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

#include <netinet/in.h>		/* htons, htonl on Linux */

static void zone_addbuf __P((struct message *, const void *, size_t));
static void zone_addcompr __P((struct message *, u_char *, u_int16_t, u_char));

/* The database file... */
char *dbfile = DEFAULT_DBFILE;

/* The database masks */
u_char bitmasks[NAMEDB_BITMASKLEN * 3];
u_char *authmask = bitmasks;
u_char *starmask = bitmasks + NAMEDB_BITMASKLEN;
u_char *datamask = bitmasks + NAMEDB_BITMASKLEN * 2;

/* Some global flags... */
int vflag = 0;

#ifdef	USE_HEAP_HASH

unsigned long
dnamehash(dname)
	register u_char *dname;
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
xalloc(size)
	register size_t	size;
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		fprintf(stderr, "zonec: malloc failed: %m\n");
		exit(1);
	}
	return p;
}

void *
xrealloc(p, size)
	register void *p;
	register size_t	size;
{

	if((p = realloc(p, size)) == NULL) {
		fprintf(stderr, "zonec: realloc failed: %m\n");
		exit(1);
	}
	return p;
}

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

static void
zone_addbuf(msg, data, size)
	struct message *msg;
	const void *data;
	size_t size;
{
	if(msg->bufptr - msg->buf + size > IOBUFSZ) {
		fflush(stdout);
		fprintf(stderr, "zonec: insufficient buffer space\n"); /* RR set too large? */
		exit(1);	/* XXX: do something smart */
	}

	bcopy(data, msg->bufptr, size);
	msg->bufptr += size;
}

static void
zone_addcompr(msg, dname, offset, len)
	struct message *msg;
	u_char *dname;
	u_int16_t offset;
	u_char len;
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
zone_addname(msg, dname)
	struct message *msg;
	u_char *dname;
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
					(strncasecmp(t, msg->compr[j].dname, msg->compr[j].dnamelen) == 0)) {
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
zone_addrrset(msg, dname, rrset)
	struct message *msg;
	u_char *dname;
	struct rrset *rrset;
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

		rdata = rrset->rrs[j];

		/* dname */
		zone_addname(msg, dname);

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
		for(size = 0, i = 0, f = rrset->fmt; *f; f++, i++, size = 0) {
			switch(*f) {
			case '4':
				size = sizeof(u_int32_t);
				zone_addbuf(msg, &rdata[i].l, size);
				break;
			case 'l':
				size = sizeof(int32_t);
				l = htonl(rdata[i].l);
				zone_addbuf(msg, &l, size);
				break;
			case '6':
				size = IP6ADDRLEN;
				zone_addbuf(msg, rdata[i].p, size);
				break;
			case 'n':
				if (msg->dnameslen >= MAXRRSPP) {
					fflush(stdout);
					fprintf(stderr, "zonec: too many domain names\n");
					exit(1);
				}
				
				size = 0;
				rdlength += zone_addname(msg, rdata[i].p);
				msg->dnames[msg->dnameslen++] = rdata[i].p;
				break;
			case 't':
				size = *((u_char *)rdata[i].p) + 1;
				zone_addbuf(msg, rdata[i].p, size);
				break;
			case 's':
				size = sizeof(u_int16_t);
				s = htons(rdata[i].s);
				zone_addbuf(msg, &s, size);
				break;
			default:
				fprintf(stderr, "zonec: panic! uknown atom in format %c\n", *f);
				return rrcount;
			}
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
struct domain *
zone_addanswer(d, msg, type)
	struct domain *d;
	struct message *msg;
	u_int16_t type;
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
void
zone_free(z)
	struct zone *z;
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
zone_read(name, zonefile, cache)
	char *name;
	char *zonefile;
	int cache;
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
#else
# ifdef USE_HEAP_HASH
	z->cuts = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
	z->data = heap_create(xalloc, dnamecmp, dnamehash, NAMEDB_HASH_SIZE);
# endif
#endif
	z->soa = z->ns = NULL;

	/* Read the file */
	while((rr = zf_read(zf)) != NULL) {

		/* Report progress... */
		if(vflag) {
			if((zf->lines % 100000) == 0) {
				printf("read %u lines...\r", zf->lines);
				fflush(stdout);
			}
		}

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

	fprintf(stderr, "zonec: zone \"%s\" completed: %d errors\n", dnamestr(z->dname), zf->errors);
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
	bzero(&msg, sizeof(struct message));
	msg.bufptr = msg.buf;

	/* Create a new domain */
	d = xalloc(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = NAMEDB_DELEGATION;

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
		    (bcmp(dkey + 1, msg.dnames[i] + (*msg.dnames[i] - *dkey) + 1, *dkey) == 0)) {
			if(additional == NULL) {
				fprintf(stderr, "zonec: missing glue record\n");
			} else {
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
	bzero((char *)d + d->size, sizeof(u_int32_t));
	d->size += sizeof(u_int32_t);

	/* Store it */
	if(namedb_put(db, dkey, d) != 0) {
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
zone_dump(z, db)
	struct 	zone *z;
	struct namedb *db;
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

		zone_addzonecut(dname, dname, rrset, z, db);

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
						zone_addcompr(&msg, nameptr,
							      (nameptr - (dname + 1 + star)) | 0xc000,
							      dname + *dname + 1 - nameptr);
						zone_addcompr(&msgany, nameptr,
							      (nameptr - (dname + 1 + star)) | 0xc000,
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
		bzero((char *)d + d->size, sizeof(u_int32_t));
		d->size += sizeof(u_int32_t);

		/* Store it */
		if(namedb_put(db, dname, d) != 0) {
			fprintf(stderr, "zonec: error writing the database: %s\n", strerror(errno));
		}

		free(d);
	}

	return 0;
}

int
usage()
{
	fprintf(stderr, "usage: zonec [-f database] [-d directory] zone-list-file\n");
	exit(1);
}

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char **argv;
{
	char *zonename, *zonefile, *s;
	char buf[LINEBUFSZ];
        struct namedb *db;
	char *sep = " \t\n";
	int c;
	int line = 0;
	int cache = 0;
	FILE *f;

	int error = 0;
	struct zone *z = NULL;

	/* Parse the command line... */
	while((c = getopt(argc, argv, "d:f:v")) != -1) {
		switch (c) {
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

		/* Either zone or a cache... */
		if(strcasecmp(s, "cache") == 0) {
			cache = 1;
		} else if(strcasecmp(s, "zone") == 0) {
			cache = 0;
		} else {
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

		/* Trailing garbage? */
		if((s = strtok(NULL, sep)) != NULL && *s != ';') {
			fprintf(stderr, "zonec: ignoring trailing garbage in %s line %d\n", *argv, line);
		}

		/* If we did not have any errors... */
		if((z = zone_read(zonename, zonefile, cache)) != NULL) {
			zone_dump(z, db);
			zone_free(z);
			z = NULL;
		}

	};

	/* Close the database */
	if(namedb_save(db) != 0) {
		fprintf(stderr, "zonec: error saving the database: %s\n", strerror(errno));
		namedb_discard(db);
		exit(1);
	}

	return error;
}
