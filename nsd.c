/*
 * $Id: nsd.c,v 1.8 2002/01/31 12:45:42 alexis Exp $
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

char *cf_dbfile = CF_DBFILE;
char *cf_pidfile = CF_PIDFILE;
int cf_tcp_max_connections = CF_TCP_MAX_CONNECTIONS;
u_short cf_tcp_port = CF_TCP_PORT;
int cf_tcp_max_message_size = CF_TCP_MAX_MESSAGE_SIZE;
u_short cf_udp_port = CF_UDP_PORT;
int cf_udp_max_message_size = CF_UPD_MAX_MESSAGE_SIZE;


/* The nsd database */
DB *database;

int tcp_open_connections = 0;

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * syslog().
 *
 */
void *
xalloc(size)
	register size_t size;
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
	register size_t size;
{

	if((p = realloc(p, size)) == NULL) {
		syslog(LOG_ERR, "realloc failed: %m");
		exit(1);
	}
	return p;
}

/*
 * Open the database db...
 *
 */
DB *
opendb(void)
{
	int r;
	DBT key, data;
	DB *db;

	/* Setup the name database... */
	if((r = db_create(&db, NULL, 0)) != 0) {
		syslog(LOG_ERR, "db_create failed: %s", db_strerror(r));
		return NULL;
	}

	/* Open the database... */
	if((r = db->open(db, cf_dbfile, NULL, DB_UNKNOWN, DB_RDONLY, 0664)) != 0) {
		syslog(LOG_ERR, "cannot open the database %s: %s", cf_dbfile, db_strerror(r));
		return NULL;
	}

	/* Read the bitmasks... */
	bzero(&key, sizeof(key));
	bzero(&data, sizeof(data));

	key.size = 0;
	key.data = NULL;
	if((r = db->get(db, NULL, &key, &data, 0)) != 0) {
		syslog(LOG_ERR, "cannot read the superblock from %s: %s", cf_dbfile, db_strerror(r));
		return NULL;
	}

	if(data.size != NAMEDB_BITMASKLEN * 3) {
		syslog(LOG_ERR, "corrupted superblock in %s", cf_dbfile);
		return NULL;
	}

	bcopy(data.data, authmask, NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_BITMASKLEN, starmask, NAMEDB_BITMASKLEN);
	bcopy(data.data + NAMEDB_BITMASKLEN * 2, datamask, NAMEDB_BITMASKLEN);

	return db;
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
	int status;
	switch(sig) {
	case SIGCHLD:
		/* Any tcp children willing to report? */
		if(waitpid(0, &status, WNOHANG) != 0) {
			if(tcp_open_connections)
				tcp_open_connections--;
		}
		break;
	case SIGHUP:
		(void)database->close(database, 0);
		if((database = opendb()) == NULL) {
			syslog(LOG_ERR, "unable to reload the database, shutting down...");
			exit(1);
		}
		syslog(LOG_WARNING, "database reloaded...");
		break;
	case SIGTERM:
	default:
		syslog(LOG_WARNING, "signal %d received, shutting down...", sig);
		(void)database->close(database, 0);
		exit(0);
	}
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
	int fd;
	pid_t pid;

#	ifndef	LOG_PERROR
#		define	LOG_PERROR 0
#	endif

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR, LOG_LOCAL5);

	/* Parse the command line... */
	if(argc == 2) {
		cf_dbfile = argv[1];
	}

	/* Parser the configuration file...*/

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);

	/* Open the database... */
	if((database = opendb()) == NULL) {
		exit(1);
	}

	/* Take off... */
	switch((pid = fork())) {
	case 0:
		break;
	case -1:
		syslog(LOG_ERR, "fork failed: %m");
		exit(1);
	default:
		syslog(LOG_NOTICE, "nsd started, pid %d", pid);
		exit(0);
	}

	/* Detach ourselves... */
	if(setsid() == -1) {
		syslog(LOG_ERR, "setsid() failed: %m");
		exit(1);
	}

	(void)chdir("/");

	if((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}

	/* Run the server... */
	server(database);

	/* Should we return... */
	database->close(database, 0);
	exit(0);
}
