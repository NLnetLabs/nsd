/*
 * $Id: db.c,v 1.11 2002/01/11 13:21:05 alexis Exp $
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
#include "heap.h"
#include "dns.h"
#include "nsd.h"
#include "db.h"
#include "zone.h"


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

	/* Clean the masks */
	bzero(&db.mask, sizeof(struct db_mask));
	return &db;
}

void
db_close(db)
	struct db *db;
{
	db->db->close(db->db);
}

void
db_write(db, dname, d)
	struct db *db;
	u_char *dname;
	struct domain *d;
{
	DBT key, data;

	key.size = (size_t)(*dname);
	key.data = dname + 1;

	data.size = d->size;
	data.data = d;

	if(db->db->put(db->db, &key, &data, 0)) {
		syslog(LOG_ERR, "failed to write to database: %m");
		return;
	}
}

void
db_sync(db)
	struct db *db;
{
	DBT key, data;
	
	key.size = 0;
	key.data = NULL;

	data.size = sizeof(struct db_mask);
	data.data = &db->mask;

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
	DBT key, data;

        if((db.db = dbopen(filename, O_RDONLY, 0, DB_HASH, NULL)) == NULL) {
                syslog(LOG_ERR, "cant open %s: %m", filename);
                return NULL;
        }

	key.size = 0;
	key.data = NULL;

	/* Read the masks */	
	if(db.db->get(db.db, &key, &data, 0) != 0) {
		syslog(LOG_ERR, "cannot read masks from %s: %m", filename);
		return NULL;
	}

	if(data.size != sizeof(struct db_mask)) {
		syslog(LOG_ERR, "corrupted masks in %s", filename);
		return NULL;
	}
	bcopy(data.data, &db.mask, sizeof(struct db_mask));

	return &db;
}

struct domain *
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


struct domain *
db_addanswer(d, msg, type)
	struct domain *d;
	struct message *msg;
	u_short type;
{
	struct answer *a;
	size_t size;

	size = sizeof(size_t) + (sizeof(u_short) * (msg->pointerslen + 5)) + (msg->bufptr - msg->buf);

	d = xrealloc(d, d->size + size);

	a = (struct answer *)((char *)d + d->size);
	a->size = size;
	a->type = htons(type);
	a->ancount = htons(msg->ancount);
	a->nscount = htons(msg->nscount);
	a->arcount = htons(msg->arcount);
	a->ptrlen = msg->pointerslen;
	bcopy(msg->pointers, &a->ptrlen + 1, sizeof(u_short) * msg->pointerslen);
	bcopy(msg->buf, &a->ptrlen + msg->pointerslen + 1, msg->bufptr - msg->buf);

	d->size += size;

	return d;
}

struct domain *
db_newdomain(flags)
	u_short flags;
{
	struct domain *d = xalloc(sizeof(struct domain));
	d->size = sizeof(struct domain);
	d->flags = flags;
	return d;
}

struct answer *
db_answer(d, type)
	struct domain *d;
	u_short type;
{
	struct answer *a;
	for(a = (struct answer *)((char *)d + sizeof(struct domain)); (char *)a < ((char *)d + d->size); (char *)a += a->size) {
		if(a->type == type) {
			return a;
		}
	}
	return NULL;
}
