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
#include <stdio.h>		/* DEBUG */

#ifdef USE_MMAP
#include <sys/mman.h>
#endif

#include "namedb.h"
#include "util.h"

int
namedb_lookup (struct namedb    *db,
	       const dname_type *dname,
	       dname_tree_type **less_equal,
	       dname_tree_type **closest_encloser)
{
	return dname_tree_search(db->dnames, dname, less_equal, closest_encloser);
}

const struct answer *
namedb_answer (const struct domain *d, uint16_t type)
{
	const struct answer *a;
	type = htons(type);
	
	DOMAIN_WALK(d, a) {
		if (a->type == type) {
			return a;
		}
	}
	return NULL;
}

#ifdef USE_MMAP
static void
unmap_database(void *param)
{
	struct namedb *db = param;

	munmap(db->mpool, db->mpoolsz);
}
#endif /* USE_MMAP */

struct namedb *
namedb_open (const char *filename)
{
	struct namedb *db;
	char magic[NAMEDB_MAGIC_SIZE] = NAMEDB_MAGIC;

	uint8_t *p;
	struct stat st;
	region_type *region = region_create(xalloc, free);
	size_t entries = 0;
	
	db = region_alloc(region, sizeof(struct namedb));
	db->region = region;
	
	/* Copy the name... */
	if ((db->filename = strdup(filename)) == NULL) {
		region_destroy(region);
		return NULL;
	}
	region_add_cleanup(region, free, db->filename);

	/* Open it... */
	if ((db->fd = fopen(db->filename, "r")) == NULL ) {
		region_destroy(region);
		return NULL;
	}

	/* Is it there? */
	if (fstat( fileno(db->fd), &st) == -1) {
		fclose(db->fd);
		region_destroy(region);
		return NULL;
	}

	/* What its size? */
	db->mpoolsz = st.st_size;

#ifdef USE_MMAP
#ifndef MAP_NORESERVE
# define MAP_NORESERVE 0
#endif
	db->mpool = mmap(NULL, db->mpoolsz, PROT_READ, MAP_SHARED | MAP_NORESERVE, fileno(db->fd), 0);
	if (db->mpool == MAP_FAILED) {
		log_msg(LOG_ERR, "mmap failed: %s", strerror(errno));
		fclose(db->fd);
		region_destroy(region);
		return NULL;
	}

	region_add_cleanup(region, unmap_database, db);
#else /* !USE_MMAP */
	db->mpool = region_alloc(region, db->mpoolsz);

	if (read( fileno(db->fd), db->mpool, db->mpoolsz) != (ssize_t) db->mpoolsz) {
		log_msg(LOG_ERR, "read failed: %s", strerror(errno));
		fclose(db->fd);
		region_destroy(region);
		return NULL;
	}
#endif /* !USE_MMAP */
	
	fclose(db->fd);

	db->heap = NULL;
	db->dnames = dname_tree_create(db->region);

	p = db->mpool;

	if (memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	while (*p) {
		const dname_type *dname = (const dname_type *) p;
		if (dname_tree_update(db->dnames, dname, p + ALIGN_UP(dname_total_size(dname), NAMEDB_ALIGNMENT)) == NULL) {
			log_msg(LOG_ERR, "failed to insert a domain: %s", strerror(errno));
			namedb_close(db);
			return NULL;
		}
		p += ALIGN_UP(dname_total_size(dname), NAMEDB_ALIGNMENT);
		p += *((uint32_t *)p);
		if (p > (db->mpool + db->mpoolsz)) {
			log_msg(LOG_ERR, "corrupted database %s", db->filename);
			namedb_close(db);
			errno = EINVAL;
			return NULL;
		}
		++entries;
	}

	p++;

	if (memcmp(p, magic, NAMEDB_MAGIC_SIZE)) {
		log_msg(LOG_ERR, "corrupted database: %s", db->filename);
		namedb_close(db);
		return NULL;
	}
	p += NAMEDB_MAGIC_SIZE;

	log_msg(LOG_WARNING, "loaded %s, %lu entries", db->filename,
		(unsigned long) entries);

	return db;
}

void
namedb_close (struct namedb *db)
{
	/* If it is already closed... */
	if (db == NULL)
		return;
	region_destroy(db->region);
}
