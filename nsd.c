/*
 * $Id: nsd.c,v 1.2 2002/01/28 16:02:59 alexis Exp $
 *
 * nsd.c -- nsd(8)
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
#include "nsd.h"

u_char authmask[NAMEDB_BITMASKLEN];
u_char starmask[NAMEDB_BITMASKLEN];
u_char datamask[NAMEDB_BITMASKLEN];

static u_short _nshorts[NSHORTSLEN];

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * syslog().
 *
 */
void *
xalloc(size)
	register size_t	size;
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		syslog(LOG_ERR, "malloc failed: %m");
		exit(1);
	}
	return p;
}

void *
xrealloc(p, size)
	register void *p;
	register size_t	size;
{

	if((p = realloc(p, size)) == NULL) {
		syslog(LOG_ERR, "realloc failed: %m");
		exit(1);
	}
	return p;
}

int
usage()
{
	fprintf(stderr, "usage: nsd database\n");
	exit(1);
}

void
sig_handler(sig)
	int sig;
{
	exit(0);
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	DB *db;
	DBT key, data;
	int r, i;
	char *dbfile;

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR, LOG_LOCAL5);

	/* Convert the network byte order translation table... */
	for(i = 0; i < NSHORTSLEN; i++) _nshorts[i] = htons((u_short)i);

	/* Parse the command line... */
	if(argc != 2) {
		dbfile = "nsd.db";
	} else {
		dbfile = argv[1];
	}

	/* Parser the configuration file...*/

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);

	/* Setup the name database... */
	if((r = db_create(&db, NULL, 0)) != 0) {
                syslog(LOG_ERR, "db_create failed: %s", db_strerror(r));
                exit(1);
        }

	/* Open the database... */
        if((r = db->open(db, dbfile, NULL, DB_UNKNOWN, DB_RDONLY, 0664)) != 0) {
		syslog(LOG_ERR, "cannot open the database %s: %s", dbfile, db_strerror(r));
                exit(1);
        }

	/* Read the bitmasks... */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.size = 0;
	key.data = NULL;
	if((r = db->get(db, NULL, &key, &data, 0)) != 0) {
		syslog(LOG_ERR, "cannot read the superblock from %s: %s", dbfile, db_strerror(r));
		exit(1);
	}

	if(data.size != NAMEDB_BITMASKLEN * 3) {
		syslog(LOG_ERR, "corrupted superblock in %s", dbfile);
		exit(1);
	}

	bcopy(data.data, authmask, NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_BITMASKLEN, starmask, NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_BITMASKLEN * 2, datamask, NAMEDB_BITMASKLEN);


	server(4096, db);

	db->close(db, 0);

	exit(0);
}
