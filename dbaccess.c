/*
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

#include <config.h>

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "namedb.h"
#include "util.h"

int 
domaincmp (const void *left, const void *right)
{
	int r;
	const uint8_t *a = left;
	const uint8_t *b = right;
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
namedb_lookup (struct namedb *db, const uint8_t *dname)
{
	return (struct domain *)heap_search(db->heap, dname);
}

const struct answer *
namedb_answer (const struct domain *d, int type)
{
	const struct answer *a;

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
	region_type *region = region_create(xalloc, free);

	db = region_alloc(region, sizeof(struct namedb));
	db->region = region;
	
	/* Copy the name... */
	if((db->filename = strdup(filename)) == NULL) {
		region_destroy(region);
		return NULL;
	}
	region_add_cleanup(region, free, db->filename);

	/* Open it... */
	if((db->fd = open(db->filename, O_RDONLY)) == -1) {
		region_destroy(region);
		return NULL;
	}

	/* Is it there? */
	if(fstat(db->fd, &st) == -1) {
		close(db->fd);
		region_destroy(region);
		return NULL;
	}

	/* What its size? */
	db->mpoolsz = st.st_size;
	db->mpool = region_alloc(region, db->mpoolsz);

	if(read(db->fd, db->mpool, db->mpoolsz) == -1) {
		close(db->fd);
		region_destroy(region);
		return NULL;
	}

	close(db->fd);

	db->heap = heap_create(db->region, domaincmp);

	p = db->mpool;

	if(memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	while(*p) {
		if(heap_insert(db->heap, p, p + ALIGN_UP(*p + 1, NAMEDB_ALIGNMENT), 1) == NULL) {
			log_msg(LOG_ERR, "failed to insert a domain: %s", strerror(errno));
			namedb_close(db);
			return NULL;
		}
		p += ALIGN_UP(*p + 1, NAMEDB_ALIGNMENT);
		p += *((uint32_t *)p);
		if(p > (db->mpool + db->mpoolsz)) {
			log_msg(LOG_ERR, "corrupted database %s", db->filename);
			namedb_close(db);
			errno = EINVAL;
			return NULL;
		}
	}

	p++;

	if(memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	/* Copy the bitmasks... */
	memcpy(db->masks[NAMEDB_AUTHMASK], p, NAMEDB_BITMASKLEN);
	memcpy(db->masks[NAMEDB_STARMASK], p + NAMEDB_BITMASKLEN, NAMEDB_BITMASKLEN);
	memcpy(db->masks[NAMEDB_DATAMASK], p + NAMEDB_BITMASKLEN * 2, NAMEDB_BITMASKLEN);

	log_msg(LOG_WARNING, "loaded %s, %lu entries", db->filename, db->heap->count);

	return db;
}

void
namedb_close (struct namedb *db)
{
	/* If it is already closed... */
	if(db == NULL)
		return;
	region_destroy(db->region);
}
