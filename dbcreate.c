/*
 * $Id: dbcreate.c,v 1.25 2003/08/05 12:21:43 erik Exp $
 *
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

#include "config.h"

#include <sys/types.h>

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
	db = region_alloc(region, sizeof(struct namedb));
	db->region = region;
	
	if((db->filename = strdup(filename)) == NULL) {
		region_destroy(region);
		return NULL;
	}
	region_add_cleanup(region, free, db->filename);

	/* Create the database */
        if((db->fd = open(db->filename, O_CREAT | O_TRUNC | O_WRONLY, 0664)) == -1) {
		region_destroy(region);
		return NULL;
        }

	if (write(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) == -1) {
		close(db->fd);
		namedb_discard(db);
		return NULL;
	}

	/* Initialize the masks... */
	memset(db->masks[NAMEDB_AUTHMASK], 0, NAMEDB_BITMASKLEN);
	memset(db->masks[NAMEDB_STARMASK], 0, NAMEDB_BITMASKLEN);
	memset(db->masks[NAMEDB_DATAMASK], 0, NAMEDB_BITMASKLEN);

	return db;
}


int 
namedb_put (struct namedb *db, const uint8_t *dname, struct domain *d)
{
	/* Store the key */
	static const char zeroes[NAMEDB_ALIGNMENT];
	size_t padding = PADDING(*dname + 1, NAMEDB_ALIGNMENT);

	if (write(db->fd, dname, *dname + 1) == -1) {
		return -1;
	}

	if (write(db->fd, zeroes, padding) == -1) {
		return -1;
	}
	
	/* Store the domain */
	if (write(db->fd, d, d->size) == -1) {
		return -1;
	}

	return 0;
}

int 
namedb_save (struct namedb *db)
{
	/* Write an empty key... */
	if (write(db->fd, "", 1) == -1) {
		close(db->fd);
		return -1;
	}

	/* Write the magic... */
	if (write(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) == -1) {
		close(db->fd);
		return -1;
	}

	/* Write the bitmasks... */
	if (write(db->fd, db->masks, NAMEDB_BITMASKLEN * 3) == -1) {
		close(db->fd);
		return -1;
	}

	/* Close the database */
	close(db->fd);

	region_destroy(db->region);
	return 0;
}


void 
namedb_discard (struct namedb *db)
{
	unlink(db->filename);
	region_destroy(db->region);
}
