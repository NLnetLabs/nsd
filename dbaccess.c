/*
 * $Id: dbaccess.c,v 1.1 2002/02/05 12:17:33 alexis Exp $
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

#include <stdlib.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include "namedb.h"

#ifdef USE_BERKELEY_DB

struct domain *
namedb_lookup(db, dname)
	struct namedb *db;
	u_char *dname;
{
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
	DBT key, data;
	char *magic = NAMEDB_MAGIC;

	/* Allocate memory for it... */
	if((db = xalloc(sizeof(struct namedb))) == NULL) {
		return NULL;
	}

	/* Copy the name... */
	if((db->filename = strdup(filename)) == NULL) {
		free(db);
		return NULL;
	}

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

	if((data.size != (NAMEDB_BITMASKLEN * 3 + sizeof(NAMEDB_MAGIC))) ||
		bcmp(data.data, magic, sizeof(NAMEDB_MAGIC))) {
		syslog(LOG_ERR, "corrupted superblock in %s", db->filename);
		namedb_close(db);
		return NULL;
	}

	bcopy(data.data + sizeof(NAMEDB_MAGIC), db->masks[NAMEDB_AUTHMASK], NAMEDB_BITMASKLEN);
	bcopy(data.data + sizeof(NAMEDB_MAGIC) + NAMEDB_BITMASKLEN, db->masks[NAMEDB_STARMASK], NAMEDB_BITMASKLEN);
	bcopy(data.data + sizeof(NAMEDB_MAGIC) + NAMEDB_BITMASKLEN * 2, db->masks[NAMEDB_DATAMASK], NAMEDB_BITMASKLEN);

	return db;
}

void
namedb_close(db)
	struct namedb *db;
{
	db->db->close(db->db, 0);
	if(db->filename)
		free(db->filename);
	free(db);
}


#endif /* USE_BERKELEY_DB */
