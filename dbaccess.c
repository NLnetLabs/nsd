/*
 * $Id: dbaccess.c,v 1.12 2002/02/12 13:49:36 alexis Exp $
 *
 * dbaccess.c -- access methods for nsd(8) database
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
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "namedb.h"

#ifndef	USE_BERKELEY_DB

int
domaincmp(a, b)
	register u_char *a;
	register u_char *b;
{
	register int r;
	register int alen = (int)*a;
	register int blen = (int)*b;

	while(alen && blen) {
		a++; b++;
		if((r = *a - *b)) return r;
		alen--; blen--;
	}
	return alen - blen;
}

#ifdef	USE_HEAP_HASH

unsigned long
domainhash(dname)
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

#endif

struct domain *
namedb_lookup(db, dname)
	struct namedb *db;
	u_char *dname;
{
#ifdef USE_BERKELEY_DB
	DBT key, data;

	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	key.size = (size_t)*dname;
	key.data = dname + 1;

	switch(db->db->get(db->db, NULL, &key, &data, 0)) {
	case -1:
		syslog(LOG_ERR, "database lookup failed: %m");
		return NULL;
	case DB_NOTFOUND:
		return NULL;
	case 0:
		return data.data;
	}

	return NULL;

#else 
	return (struct domain *)heap_search(db->heap, dname);

#endif /* USE_BERKELEY_DB */
}

struct answer *
namedb_answer(d, type)
	struct domain *d;
	u_int16_t type;
{
	struct answer *a;

	DOMAIN_WALK(d, a) {
		if(a->type == type) {
			return a;
		}
	}
	return NULL;
}

struct namedb *
namedb_open(filename)
	char *filename;
{
	struct namedb *db;
	char magic[NAMEDB_MAGIC_SIZE] = NAMEDB_MAGIC;

#ifdef	USE_BERKELEY_DB
	DBT key, data;
#else
	struct stat st;
	char *p;
#endif

	/* Allocate memory for it... */
	if((db = xalloc(sizeof(struct namedb))) == NULL) {
		return NULL;
	}

	/* Copy the name... */
	if((db->filename = strdup(filename)) == NULL) {
		free(db);
		return NULL;
	}

#ifdef USE_BERKELEY_DB
	/* Setup the name database... */
	if(db_create(&db->db, NULL, 0) != 0) {
		free(db->filename);
		free(db);
		return NULL;
	}

	/* Open the database... */
	if(db->db->open(db->db, db->filename, NULL, DB_UNKNOWN, DB_RDONLY, 0664) != 0) {
		namedb_close(db);
		return NULL;
	}

	/* Read the bitmasks... */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.size = 0;
	key.data = NULL;
	if(db->db->get(db->db, NULL, &key, &data, 0) != 0) {
		namedb_close(db);
		return NULL;
	}

	if((data.size != (NAMEDB_BITMASKLEN * 3 + NAMEDB_MAGIC_SIZE)) ||
		bcmp(data.data, magic, NAMEDB_MAGIC_SIZE)) {
		syslog(LOG_ERR, "corrupted superblock in %s", db->filename);
		namedb_close(db);
		return NULL;
	}

	bcopy(data.data + NAMEDB_MAGIC_SIZE, db->masks[NAMEDB_AUTHMASK], NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_MAGIC_SIZE + NAMEDB_BITMASKLEN, db->masks[NAMEDB_STARMASK], NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_MAGIC_SIZE + NAMEDB_BITMASKLEN * 2, db->masks[NAMEDB_DATAMASK], NAMEDB_BITMASKLEN);

#else

	/* Open it... */
	if((db->fd = open(db->filename, O_RDONLY)) == -1) {
		free(db->filename);
		free(db);
		return NULL;
	}

	/* Is it there? */
	if(fstat(db->fd, &st) == -1) {
		free(db->filename);
		free(db);
		return NULL;
	}

	if((db->mpool = malloc(st.st_size)) == NULL) {
		free(db->filename);
		free(db);
		return NULL;
	}

	if(read(db->fd, db->mpool, st.st_size) == -1) {
		free(db->mpool);
		free(db->filename);
		free(db);
		return NULL;
	}

	(void)close(db->fd);

#ifdef USE_HEAP_RBTREE
	if((db->heap = heap_create(malloc, domaincmp)) == NULL) {
#else ifdef(USE_HEAP_HASH)
	if((db->heap = heap_create(malloc, domaincmp, domainhash, NAMEDB_HASH_SIZE)) == NULL) {
#endif
		free(db->mpool);
		free(db->filename);
		free(db);
		return NULL;
	}

	p = db->mpool;

	if(bcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		syslog(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	while(*p) {
		if(heap_insert(db->heap, p, p + ((*p + 1 +3) & 0xfffffffc), 1) == NULL) {
			syslog(LOG_ERR, "failed to insert a domain: %m");
			namedb_close(db);
			return NULL;
		}
		p += (((u_int32_t)*p + 1 + 3) & 0xfffffffc);
		p += *((u_int32_t *)p);
		if(p > (db->mpool + st.st_size)) {
			syslog(LOG_ERR, "corrupted database %s", db->filename);
			namedb_close(db);
			errno = EINVAL;
			return NULL;
		}
	}

	p++;

	if(bcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		syslog(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	/* Copy the bitmasks... */
	bcopy(p, db->masks[NAMEDB_AUTHMASK], NAMEDB_BITMASKLEN);
	bcopy(p + NAMEDB_BITMASKLEN, db->masks[NAMEDB_STARMASK], NAMEDB_BITMASKLEN);
	bcopy(p + NAMEDB_BITMASKLEN * 2, db->masks[NAMEDB_DATAMASK], NAMEDB_BITMASKLEN);

#endif
#if !defined(USE_BERKELEY_DB)
#if defined(USE_HEAP_HASH)
	syslog(LOG_WARNING, "loaded %s, %lu entries %lu hash collisions", db->filename,
		db->heap->count, db->heap->collisions);
#else 
	syslog(LOG_WARNING, "loaded %s, %lu entries", db->filename, db->heap->count);
#endif
#else
	syslog(LOG_WARNING, "loaded %s", db->filename);
#endif
	return db;
}

void
namedb_close(db)
	struct namedb *db;
{
#ifdef	USE_BERKELEY_DB
	db->db->close(db->db, 0);
#else
	heap_destroy(db->heap, 0, 0);
	free(db->mpool);
#endif
	if(db->filename)
		free(db->filename);
	free(db);
}
