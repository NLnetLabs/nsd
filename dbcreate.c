/*
 * $Id: dbcreate.c,v 1.1 2002/02/05 12:17:33 alexis Exp $
 *
 * namedb_create.c -- routines to create an nsd(8) name database 
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

#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include "namedb.h"

#ifdef	USE_BERKELEY_DB

struct namedb *
namedb_new(filename)
	char *filename;
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
	if(db_create(&db->db, NULL, 0) != 0) {
		free(db);
                return NULL;
        }

        if(db->db->open(db->db, db->filename, NULL, DB_BTREE, DB_CREATE | DB_TRUNCATE, 0664) != 0) {
		free(db);
		return NULL;
        }

	/* Initialize the masks... */
	bzero(db->masks[NAMEDB_AUTHMASK], NAMEDB_BITMASKLEN);
	bzero(db->masks[NAMEDB_STARMASK], NAMEDB_BITMASKLEN);
	bzero(db->masks[NAMEDB_DATAMASK], NAMEDB_BITMASKLEN);

	return db;
};


int
namedb_put(db, dname, d)
	struct namedb *db;
	u_char *dname;
	struct domain *d;
{
	DBT key, data;

	/* Store it */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.size = *dname;
	key.data = dname + 1;
	data.size = d->size;
	data.data = d;

	if(db->db->put(db->db, NULL, &key, &data, 0) != 0) {
		return -1;
	}

	return 0;
};

int
namedb_save(db)
	struct namedb *db;
{
	/* The buffer for the super block */
	u_char sbuf[NAMEDB_BITMASKLEN * 3 + sizeof(NAMEDB_MAGIC)];

	DBT key, data;

	/* Create the super block */
	bcopy(NAMEDB_MAGIC, sbuf, sizeof(NAMEDB_MAGIC));
	bcopy(db->masks[NAMEDB_AUTHMASK], sbuf + sizeof(NAMEDB_MAGIC), NAMEDB_BITMASKLEN);
	bcopy(db->masks[NAMEDB_STARMASK], sbuf + sizeof(NAMEDB_MAGIC) + NAMEDB_BITMASKLEN, NAMEDB_BITMASKLEN);
	bcopy(db->masks[NAMEDB_DATAMASK], sbuf + sizeof(NAMEDB_MAGIC) + NAMEDB_BITMASKLEN * 2, NAMEDB_BITMASKLEN);

	/* Write the bitmasks... */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));
	data.size = NAMEDB_BITMASKLEN * 3 + sizeof(NAMEDB_MAGIC);
	data.data = sbuf;

	if(db->db->put(db->db, NULL, &key, &data, 0) != 0) {
		return -1;
	}

	/* Close the database */
	if(db->db->close(db->db, 0) != 0) {
		return -1;
	}

	free(db->filename);
	free(db);

	return 0;
}


void
namedb_discard(db)
	struct namedb *db;
{
	unlink(db->filename);
	free(db->filename);
	free(db);
}
#endif
