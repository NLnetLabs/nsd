/*
 * namedb_create.c -- routines to create an nsd(8) name database 
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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "namedb.h"
#include "util.h"

struct namedb *
namedb_new (const char *filename)
{
	struct namedb *db;
	region_type *region = region_create(xalloc, free);
	
	/* Make a new structure... */
	db = region_alloc(region, sizeof(namedb_type));
	db->region = region;
	db->domains = domain_table_create(region);
	db->zones = NULL;
	db->filename = region_strdup(region, filename);

	/*
	 * Unlink the old database, if it exists.  This is useful to
	 * ensure that NSD (when using mmap) doesn't see the changes
	 * until a reload is done.
	 */
	if (unlink(db->filename) == -1 && errno != ENOENT) {
		region_destroy(region);
		return NULL;
	}
	
	/* Create the database */
        if ((db->fd = fopen(db->filename, "w")) == NULL) {
		region_destroy(region);
		return NULL;
	}


	if (!write_data(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE)) {
		fclose(db->fd);
		namedb_discard(db);
		return NULL;
	}

	return db;
}


int 
namedb_save (struct namedb *db)
{
	/* Write the magic... */
	if (!write_data(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE)) {
		fclose(db->fd);
		return -1;
	}

	/* Close the database */
	fclose(db->fd);

	region_destroy(db->region);
	return 0;
}


void 
namedb_discard (struct namedb *db)
{
	unlink(db->filename);
	region_destroy(db->region);
}
