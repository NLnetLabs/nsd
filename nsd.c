/*
 * $Id: nsd.c,v 1.27 2002/02/20 14:25:24 alexis Exp $
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

/* The server handler... */
struct nsd nsd;

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

int
usage()
{
	fprintf(stderr, "usage: nsd [-d] [-p port] database\n");
	exit(1);
}

pid_t
readpid(file)
	char *file;
{
	int fd;
	pid_t pid;
	char pidbuf[16];
	char *t;

	if((fd = open(file, O_RDONLY)) == -1) {
		return -1;
	}

	if((read(fd, pidbuf, sizeof(pidbuf))) == -1) {
		close(fd);
		return -1;
	}
	pid = strtol(pidbuf, &t, 10);

	if(*t && *t != '\n') {
		return -1;
	}
	return pid;
}

int
writepid(pid, file)
	pid_t pid;
	char *file;
{
	int fd;
	char pidbuf[16];

	sprintf(pidbuf, "%u\n", pid);

	if((fd = open(file, O_WRONLY | O_TRUNC | O_CREAT, 0644)) == -1) {
		return -1;
	}

	if((write(fd, pidbuf, strlen(pidbuf))) == -1) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
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
			if(nsd.tcp.open_conn)
				nsd.tcp.open_conn--;
		}
		break;
	case SIGHUP:
		syslog(LOG_WARNING, "signal %d received, reloading...", sig);
		nsd.mode = NSD_RELOAD;
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_SHUTDOWN;
		break;
	case SIGTERM:
	default:
		syslog(LOG_WARNING, "signal %d received, shutting down...", sig);
		nsd.mode = NSD_SHUTDOWN;
		break;
		
	}
}

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	/* Scratch variables... */
	int fd, c;
	pid_t	oldpid;

	/* Initialize the server handler... */
	bzero(&nsd, sizeof(struct nsd));
	nsd.dbfile	= CF_DBFILE;
	nsd.pidfile	= CF_PIDFILE;
	nsd.tcp.port	= CF_TCP_PORT;
	nsd.tcp.max_conn = CF_TCP_MAX_CONNECTIONS;
	nsd.tcp.max_msglen = CF_TCP_MAX_MESSAGE_LEN;
	nsd.udp.port	= CF_UDP_PORT;
	nsd.udp.max_msglen = CF_UDP_MAX_MESSAGE_LEN;;

/* XXX A hack to let us compile without a change on systems which dont have LOG_PERROR option... */

#	ifndef	LOG_PERROR
#		define	LOG_PERROR 0
#	endif

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR, LOG_LOCAL5);

	/* Parse the command line... */
	while((c = getopt(argc, argv, "df:p:")) != -1) {
		switch (c) {
		case 'd':
			nsd.debug = 1;
			break;
		case 'f':
			nsd.dbfile = optarg;
			break;
		case 'p':
			nsd.udp.port = atoi(optarg);
			nsd.tcp.port = atoi(optarg);
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(argc != 0)
		usage();

	/* Do we have a running nsd? */
	if((oldpid = readpid(nsd.pidfile)) == -1) {
		if(errno != ENOENT) {
			syslog(LOG_ERR, "cant read pidfile %s: %m", nsd.pidfile);
		}
	} else {
		if(kill(oldpid, 0) == 0 || errno == EPERM) {
			syslog(LOG_ERR, "nsd is already running as %u, stopping", oldpid);
			exit(0);
		} else {
			syslog(LOG_ERR, "...stale pid file from process %u", oldpid);
		}
	}

	/* Write a temporary pid... */
	if(writepid(getpid(), nsd.pidfile) == -1) {
		syslog(LOG_ERR, "cannot write %s: %m", nsd.pidfile);
	}

	/* Open the database... */
	if((nsd.db = namedb_open(nsd.dbfile)) == NULL) {
		syslog(LOG_ERR, "unable to load %s: %m", nsd.dbfile);
		unlink(nsd.pidfile);
		exit(1);
	}

	/* Unless we're debugging, fork... */
	if(!nsd.debug) {
		/* Take off... */
		switch((nsd.pid = fork())) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "fork failed: %m");
			unlink(nsd.pidfile);
			exit(1);
		default:
			syslog(LOG_NOTICE, "nsd started, pid %d", nsd.pid);
			exit(0);
		}

		/* Detach ourselves... */
		if(setsid() == -1) {
			syslog(LOG_ERR, "setsid() failed: %m");
			exit(1);
		}

		if((fd = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(fd, STDIN_FILENO);
			(void)dup2(fd, STDOUT_FILENO);
			(void)dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void)close(fd);
		}
	}

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);
	signal(SIGINT, &sig_handler);

	/* Get our process id */
	nsd.pid = getpid();

	/* Overwrite pid... */
	if(writepid(nsd.pid, nsd.pidfile) == -1) {
		syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd.pidfile);
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	server(&nsd);

	/* Not needed since we terminate anyway... */
	/* namedb_close(nsd.db); */
	unlink(nsd.pidfile);

	exit(0);
}
