/*
 * $Id: dbcreate.c,v 1.23 2003/07/28 12:28:39 erik Exp $
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

	/* Make a new structure... */
	if((db = xalloc(sizeof(struct namedb))) == NULL) {
		return NULL;
	}

	if((db->filename = strdup(filename)) == NULL) {
		free(db);
		return NULL;
	}

	/* Create the database */
        if((db->fd = open(db->filename, O_CREAT | O_TRUNC | O_WRONLY, 0664)) == -1) {
		free(db->filename);
		free(db);
		return NULL;
        }

	if(write(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) == -1) {
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
	if(write(db->fd, dname, ALIGN_UP(*dname + 1)) == -1) {
		return -1;
	}

	/* Store the domain */
	if(write(db->fd, d, d->size) == -1) {
		return -1;
	}

	return 0;
}

int 
namedb_save (struct namedb *db)
{
	/* Write an empty key... */
	if(write(db->fd, "", 1) == -1) {
		close(db->fd);
		return -1;
	}

	/* Write the magic... */
	if(write(db->fd, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) == -1) {
		close(db->fd);
		return -1;
	}

	/* Write the bitmasks... */
	if(write(db->fd, db->masks, NAMEDB_BITMASKLEN * 3) == -1) {
		close(db->fd);
		return -1;
	}

	/* Close the database */
	close(db->fd);

	free(db->filename);
	free(db);

	return 0;
}


void 
namedb_discard (struct namedb *db)
{
	unlink(db->filename);
	free(db->filename);
	free(db);
}
