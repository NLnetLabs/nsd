/*
 * $Id: db.c,v 1.6 2002/01/09 11:45:39 alexis Exp $
 *
 * db.c -- namespace database, nsd(8)
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

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <db.h>
#include "dns.h"
#include "nsd.h"
#include "db.h"
#include "zf.h"


struct db *
db_create(filename)
	char *filename;
{
	static struct db db;

	/* Create the database */
	if((db.db = dbopen(filename, O_CREAT | O_RDWR | O_TRUNC, 0644, DB_HASH, NULL)) == NULL) {
		syslog(LOG_ERR, "dbcreate failed for %s: %m", filename);
		return NULL;
	}
	return &db;
}

void
db_close(db)
	struct db *db;
{
	db->db->close(db->db);
}

void
db_write(db, dname, answer)
	struct db *db;
	u_char *dname;
	struct answer *answer;
{
	DBT key, data;

	key.size = (size_t)(*dname);
	key.data = dname + 1;

	data.size = answer->size;
	data.data = answer;

	if(db->db->put(db->db, &key, &data, 0)) {
		syslog(LOG_ERR, "failed to write to database: %m");
		return;
	}
}

struct db *
db_open(filename)
	char *filename;
{
	static struct db db;

        if((db.db = dbopen(filename, O_RDONLY, 0, DB_HASH, NULL)) == NULL) {
                syslog(LOG_ERR, "cant open %s: %m", filename);
                return NULL;
        }

	return &db;
}

struct answer *
db_lookup(db, dname, dnamelen)
	struct db *db;
	u_char *dname;
	u_char dnamelen;
{
	DBT key, data;

	key.size = (size_t)dnamelen;
	key.data = dname;

	switch(db->db->get(db->db, &key, &data, 0)) {
	case -1:
		syslog(LOG_ERR, "database lookup failed: %m");
		return NULL;
	case 1:
		return NULL;
	case 0:
		return data.data;
	}

	return NULL;
}
