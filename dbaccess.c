/*
 * $Id: dbaccess.c,v 1.35 2003/06/25 11:36:58 erik Exp $
 *
 * dbaccess.c -- access methods for nsd(8) database
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
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

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#ifdef	USE_MMAP
#include <sys/mman.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>

#include "namedb.h"

int 
domaincmp (const void *left, const void *right)
{
	int r;
	const u_char *a = left;
	const u_char *b = right;
	int alen = (int)*a;
	int blen = (int)*b;

	while(alen && blen) {
		a++; b++;
		if((r = *a - *b)) return r;
		alen--; blen--;
	}
	return alen - blen;
}

struct domain *
namedb_lookup (struct namedb *db, const u_char *dname)
{
	return (struct domain *)heap_search(db->heap, dname);
}

struct answer *
namedb_answer (const struct domain *d, int type)
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
namedb_open (const char *filename)
{
	struct namedb *db;
	char magic[NAMEDB_MAGIC_SIZE] = NAMEDB_MAGIC;

	char *p;
	struct stat st;

	/* Allocate memory for it... */
	if((db = xalloc(sizeof(struct namedb))) == NULL) {
		return NULL;
	}

	/* Copy the name... */
	if((db->filename = strdup(filename)) == NULL) {
		free(db);
		return NULL;
	}

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

	/* What its size? */
	db->mpoolsz = st.st_size;

#ifdef	USE_MMAP
	if((db->mpool = mmap(NULL, db->mpoolsz, PROT_READ, MAP_PRIVATE, db->fd, 0)) == MAP_FAILED) {
		free(db->filename);
		free(db);
		return NULL;
	}
#else

	if((db->mpool = malloc(db->mpoolsz)) == NULL) {
		free(db->filename);
		free(db);
		return NULL;
	}

	if(read(db->fd, db->mpool, db->mpoolsz) == -1) {
		free(db->mpool);
		free(db->filename);
		free(db);
		return NULL;
	}
#endif	/* USE_MMAP */

	(void)close(db->fd);

	if((db->heap = heap_create(malloc, domaincmp)) == NULL) {
		free(db->mpool);
		free(db->filename);
		free(db);
		return NULL;
	}

	p = db->mpool;

	if(memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		syslog(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	while(*p) {
		if(heap_insert(db->heap, p, p + ALIGN(*p + 1), 1) == NULL) {
			syslog(LOG_ERR, "failed to insert a domain: %m");
			namedb_close(db);
			return NULL;
		}
		p += ALIGN(*p + 1);
		p += *((u_int32_t *)p);
		if(p > (db->mpool + db->mpoolsz)) {
			syslog(LOG_ERR, "corrupted database %s", db->filename);
			namedb_close(db);
			errno = EINVAL;
			return NULL;
		}
	}

	p++;

	if(memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		syslog(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	/* Copy the bitmasks... */
	memcpy(db->masks[NAMEDB_AUTHMASK], p, NAMEDB_BITMASKLEN);
	memcpy(db->masks[NAMEDB_STARMASK], p + NAMEDB_BITMASKLEN, NAMEDB_BITMASKLEN);
	memcpy(db->masks[NAMEDB_DATAMASK], p + NAMEDB_BITMASKLEN * 2, NAMEDB_BITMASKLEN);

	syslog(LOG_WARNING, "loaded %s, %lu entries", db->filename, db->heap->count);

	return db;
}

void
namedb_close (struct namedb *db)
{
	/* If it is already closed... */
	if(db == NULL)
		return;
	heap_destroy(db->heap, 0, 0);
#ifdef	USE_MMAP
	munmap(db->mpool, db->mpoolsz);
#else
	free(db->mpool);
#endif	/* USE_MMAP */
	if(db->filename)
		free(db->filename);
	free(db);
}
