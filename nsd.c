/*
 * $Id: nsd.c,v 1.57 2002/12/17 14:41:29 alexis Exp $
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
char hostname[MAXHOSTNAMELEN];

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
	fprintf(stderr, "usage: nsd [-d] [-p port] [-a address] [-i identity] [-n tcp_servers ] [-u user|uid] [-t chrootdir] -f database\n");
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
	int l;

	if((fd = open(file, O_RDONLY)) == -1) {
		return -1;
	}

	if(((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	/* Empty pidfile means no pidfile... */
	if(l == 0) {
		errno = ENOENT;
		return -1;
	}

	pid = strtol(pidbuf, &t, 10);

	if(*t && *t != '\n') {
		return -1;
	}
	return pid;
}

int
writepid(nsd)
	struct nsd *nsd;
{
	int fd;
	char pidbuf[16];

	snprintf(pidbuf, sizeof(pidbuf), "%u\n", nsd->pid[0]);

	if((fd = open(nsd->pidfile, O_WRONLY | O_TRUNC | O_CREAT, 0644)) == -1) {
		return -1;
	}

	if((write(fd, pidbuf, strlen(pidbuf))) == -1) {
		close(fd);
		return -1;
	}
	close(fd);

	if(chown(nsd->pidfile, nsd->uid, nsd->gid) == -1) {
		syslog(LOG_ERR, "cannot chown %u.%u %s: %m", nsd->uid, nsd->gid, nsd->pidfile);
		return -1;
	}

	return 0;
}
	

void
sig_handler(sig)
	int sig;
{
	int status, i;

	/* Reinstall the signals... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGILL, &sig_handler);
	signal(SIGALRM, &sig_handler);


	/* Are we a tcp child? */
	if(nsd.pid[0] == 0) {
		switch(sig) {
		case SIGALRM:
			return;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			nsd.mode = NSD_QUIT;
			return;
		case SIGILL:
			nsd.mode = NSD_STATS;
			return;
		}
		return;
	}

	switch(sig) {
	case SIGCHLD:
		/* Any tcp children willing to report? */
		if(waitpid(0, &status, WNOHANG) != 0) {
			if(nsd.tcp.open_conn)
				nsd.tcp.open_conn--;
		}
		return;
	case SIGHUP:
		syslog(LOG_WARNING, "signal %d received, reloading...", sig);
		nsd.mode = NSD_RELOAD;
		return;
	case SIGALRM:
#ifdef BIND8_STATS
		alarm(nsd.st.period);
#endif
		sig = SIGILL;
	case SIGILL:
		/* Dump statistics... */
		nsd.mode = NSD_STATS;
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_QUIT;
		break;
	case SIGTERM:
	default:
		nsd.mode = NSD_SHUTDOWN;
		syslog(LOG_WARNING, "signal %d received, shutting down...", sig);
		break;
	}

	/* Distribute the signal to the servers... */
	for(i = nsd.tcp.open_conn; i > 0; i--) {
		if(kill(nsd.pid[i], sig) == -1) {
			syslog(LOG_ERR, "problems killing %d: %m", nsd.pid[i]);
		}
	}
}

/*
 * Statistic output...
 *
 */
#ifdef BIND8_STATS
void
bind8_stats(nsd)
	struct nsd *nsd;
{
	char buf[MAXSYSLOGMSGLEN];
	char *msg, *t;
	int i, len;

	/* XXX A bit ugly but efficient. Should be somewhere else. */
	static
	char *types[] = {NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG",		/* 8 */
			"MR", "NULL", "WKS", "PTR", "HINFO", "MINFO", "MX", "TXT",		/* 16 */
			"RP", "AFSDB", "X25", "ISDN", "RT", "NSAP", "NSAP_PTR", "SIG",		/* 24 */
			"KEY", "PX", "GPOS", "AAAA", "LOC", "NXT", "EID", "NIMLOC",		/* 32 */
			"SRV", "ATMA", "NAPTR", "KX", "CERT", "A6", "DNAME", "SINK",		/* 40 */
			"OPT", NULL, NULL, NULL, NULL, NULL, NULL, NULL,			/* 48 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 56 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 64 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 72 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 80 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 88 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 96 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 104 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 112 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 120 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 128 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 136 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 144 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 152 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 160 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 168 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 176 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 184 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 192 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 200 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 208 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 216 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 224 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 232 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 240 */
			NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,				/* 248 */
			"TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY"};		/* 255 */


	/* Current time... */
	time_t now;
	time(&now);

	/* NSTATS */
	t = msg = buf + snprintf(buf, MAXSYSLOGMSGLEN, "NSTATS %lu %lu", now, nsd->st.boot);
	for(i = 0; i <= 255; i++) {
		/* How much space left? */
		if((len = buf + MAXSYSLOGMSGLEN - t) < 32) {
			syslog(LOG_INFO, "%s", buf);
			t = msg;
			len = buf + MAXSYSLOGMSGLEN - t;
		}

		if(nsd->st.qtype[i] != 0) {
			if(types[i] == NULL) {
				t += snprintf(t, len, " TYPE%d=%lu", i, nsd->st.qtype[i]);
			} else {
				t += snprintf(t, len, " %s=%lu", types[i], nsd->st.qtype[i]);
			}
		}
	}
	if(t > msg)
		syslog(LOG_INFO, "%s", buf);

	/* XSTATS */
	/* Only print it if we're in the main daemon or have anything to report... */
	if(nsd->pid[0] != 0 
		|| nsd->st.dropped || nsd->st.raxfr || (nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped)
		|| nsd->st.txerr || nsd->st.opcode[OPCODE_QUERY] || nsd->st.opcode[OPCODE_IQUERY]
		|| nsd->st.wrongzone || nsd->st.ctcp + nsd->st.ctcp6 || nsd->st.rcode[RCODE_SERVFAIL]
		|| nsd->st.rcode[RCODE_FORMAT] || nsd->st.nona || nsd->st.rcode[RCODE_NXDOMAIN]
		|| nsd->st.opcode[OPCODE_UPDATE]) {

	    syslog(LOG_INFO, "XSTATS %lu %lu"
		" RR=%lu RNXD=%lu RFwdR=%lu RDupR=%lu RFail=%lu RFErr=%lu RErr=%lu RAXFR=%lu"
		" RLame=%lu ROpts=%lu SSysQ=%lu SAns=%lu SFwdQ=%lu SDupQ=%lu SErr=%lu RQ=%lu"
		" RIQ=%lu RFwdQ=%lu RDupQ=%lu RTCP=%lu SFwdR=%lu SFail=%lu SFErr=%lu SNaAns=%lu"
		" SNXD=%lu RUQ=%lu RURQ=%lu RUXFR=%lu RUUpd=%lu",
		now, nsd->st.boot,
		nsd->st.dropped, (unsigned long)0, (unsigned long)0, (unsigned long)0, (unsigned long)0,
		(unsigned long)0, (unsigned long)0, nsd->st.raxfr, (unsigned long)0, (unsigned long)0,
		(unsigned long)0, nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped, (unsigned long)0,
			(unsigned long)0, nsd->st.txerr,
		nsd->st.opcode[OPCODE_QUERY], nsd->st.opcode[OPCODE_IQUERY], nsd->st.wrongzone,
			(unsigned long)0, nsd->st.ctcp + nsd->st.ctcp6,
		(unsigned long)0, nsd->st.rcode[RCODE_SERVFAIL], nsd->st.rcode[RCODE_FORMAT],
			nsd->st.nona, nsd->st.rcode[RCODE_NXDOMAIN],
		(signed long)0, (unsigned long)0, (unsigned long)0, nsd->st.opcode[OPCODE_UPDATE]);
	}

}
#endif /* BIND8_STATS */

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	/* Scratch variables... */
	int i, c;
	pid_t	oldpid;

	/* Initialize the server handler... */
	bzero(&nsd, sizeof(struct nsd));
	nsd.dbfile	= CF_DBFILE;
	nsd.pidfile	= CF_PIDFILE;
	nsd.tcp.open_conn = 1;

	for(i = 0; i < CF_MAX_INTERFACES; i++) {
		nsd.udp[i].addr.sin_addr.s_addr = INADDR_ANY;
		nsd.udp[i].addr.sin_port = htons(CF_UDP_PORT);
		nsd.udp[i].addr.sin_family = AF_INET;
	}

        nsd.tcp.addr.sin_addr.s_addr = INADDR_ANY;
        nsd.tcp.addr.sin_port = htons(CF_TCP_PORT);
        nsd.tcp.addr.sin_family = AF_INET;

#ifdef INET6
        nsd.udp6.addr.sin6_port = htons(CF_UDP_PORT);	/* XXX: SHOULD BE CF_UDP6_PORT? */
        nsd.udp6.addr.sin6_family = AF_INET6;

        nsd.tcp6.addr.sin6_port = htons(CF_TCP_PORT);	/* XXX: SHOULD BE CF_TCP6_PORT? */
        nsd.tcp6.addr.sin6_family = AF_INET6;
#endif /* INET6 */

	nsd.tcp.max_msglen = CF_TCP_MAX_MESSAGE_LEN;
	nsd.identity	= CF_IDENTITY;
	nsd.version	= CF_VERSION;
	nsd.username	= CF_USERNAME;
	nsd.chrootdir	= NULL;

	/* EDNS0 */
	nsd.edns.max_msglen = CF_EDNS_MAX_MESSAGE_LEN;
	nsd.edns.opt_ok[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_ok[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_ok[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_ok[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */

	nsd.edns.opt_err[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_err[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_err[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_err[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */
	nsd.edns.opt_err[5] = 1;			/* XXX Extended RCODE=BAD VERS */

/* XXX A hack to let us compile without a change on systems which dont have LOG_PERROR option... */

#	ifndef	LOG_PERROR
#		define	LOG_PERROR 0
#	endif

#	ifndef LOG_PID
#		define LOG_PID	0
#endif

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR | LOG_PID, CF_FACILITY);

	/* Set up our default identity to gethostname(2) */
	if(gethostname(hostname, MAXHOSTNAMELEN) == 0) {
		nsd.identity = hostname;
	} else {
                syslog(LOG_ERR, "failed to get the host name: %m - using default identity");
	}


	/* Parse the command line... */
	while((c = getopt(argc, argv, "a:df:p:i:u:t:s:n:")) != -1) {
		switch (c) {
		case 'a':
			if((nsd.tcp.addr.sin_addr.s_addr = nsd.udp[nsd.ifs++].addr.sin_addr.s_addr
					= inet_addr(optarg)) == -1)
				usage();
			
			break;
		case 'd':
			nsd.debug = 1;
			break;
		case 'f':
			nsd.dbfile = optarg;
			break;
		case 'p':
			for(i = 0; i < CF_MAX_INTERFACES; i++) {
				nsd.udp[i].addr.sin_port = htons(atoi(optarg));
			}
			nsd.tcp.addr.sin_port = htons(atoi(optarg));
#ifdef INET6
			nsd.udp6.addr.sin6_port = htons(atoi(optarg));
			nsd.tcp6.addr.sin6_port = htons(atoi(optarg));
#endif /* INET6 */
			break;
		case 'i':
			nsd.identity = optarg;
			break;
		case 'u':
			nsd.username = optarg;
			break;
		case 't':
			nsd.chrootdir = optarg;
			break;
		case 'n':
			i = atoi(optarg);
			if(i <= 0) {
				syslog(LOG_ERR, "max number of tcp connections must be greather than zero");
			} else if(i > CF_TCP_MAX_CONNECTIONS) {
				syslog(LOG_ERR, "max number of tcp connections must be less than %d",
					CF_TCP_MAX_CONNECTIONS);
			} else {
				nsd.tcp.open_conn = i;
			}
			break;
		case 's':
#ifdef BIND8_STATS
			nsd.st.period = atoi(optarg);
#else /* BIND8_STATS */
			syslog(LOG_ERR, "option unavailabe, recompile with -DBIND8_STATS");
#endif /* BIND8_STATS */
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(argc != 0)
		usage();

	/* If multiple -a let nsd bind tcp socket to every interface */
	if(nsd.ifs > 1)
		nsd.tcp.addr.sin_addr.s_addr = INADDR_ANY;
	if(nsd.ifs == 0)
		nsd.ifs++;

	/* Parse the username into uid and gid */
	nsd.gid = getgid();
	nsd.uid = getuid();
	if(*nsd.username) {
		struct passwd *pwd;
		if(isdigit(*nsd.username)) {
			char *t;
			nsd.uid = strtol(nsd.username, &t, 10);
			if(*t != 0) {
				if(*t != '.' || !isdigit(*++t)) {
					syslog(LOG_ERR, "usage: -u user or -u uid  or -u uid.gid");
					exit(1);
				}
				nsd.gid = strtol(t, &t, 10);
			} else {
				/* Lookup the group id in /etc/passwd */
				if((pwd = getpwuid(nsd.uid)) == NULL) {
					syslog(LOG_ERR, "user id %d doesnt exist, will not setgid", nsd.uid);
				} else {
					nsd.gid = pwd->pw_gid;
				}
				endpwent();
			}
		} else {
			/* Lookup the user id in /etc/passwd */
			if((pwd = getpwnam(nsd.username)) == NULL) {
				syslog(LOG_ERR, "user %s doesnt exist, will not setuid", nsd.username);
			} else {
				nsd.uid = pwd->pw_uid;
				nsd.gid = pwd->pw_gid;
			}
			endpwent();
		}
	}

	/* Relativize the pathnames for chroot... */
	if(nsd.chrootdir) {
		int l = strlen(nsd.chrootdir);

		if(strncmp(nsd.chrootdir, nsd.pidfile, l) != 0) {
			syslog(LOG_ERR, "%s isnt relative to %s: wont chroot",
				nsd.pidfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		} else if(strncmp(nsd.chrootdir, nsd.dbfile, l) != 0) {
			syslog(LOG_ERR, "%s isnt relative to %s: wont chroot",
				nsd.dbfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		}
	}

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

	/* Unless we're debugging, fork... */
	if(!nsd.debug) {
		/* Take off... */
		switch((nsd.pid[0] = fork())) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "fork failed: %m");
			unlink(nsd.pidfile);
			exit(1);
		default:
			exit(0);
		}

		/* Detach ourselves... */
		if(setsid() == -1) {
			syslog(LOG_ERR, "setsid() failed: %m");
			exit(1);
		}

		if((i = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(i, STDIN_FILENO);
			(void)dup2(i, STDOUT_FILENO);
			(void)dup2(i, STDERR_FILENO);
			if (i > 2)
				(void)close(i);
		}
	}

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGILL, &sig_handler);
	signal(SIGALRM, &sig_handler);

	/* Get our process id */
	nsd.pid[0] = getpid();

	/* Overwrite pid... */
	if(writepid(&nsd) == -1) {
		syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd.pidfile);
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	if(server_init(&nsd) != 0)
		exit(1);

	syslog(LOG_NOTICE, "nsd started, pid %d", nsd.pid[0]);

	if(server_start_tcp(&nsd) != 0) {
		kill(nsd.pid[0], SIGTERM);
		exit(1);
	}

	server_udp(&nsd);

	/* NOTREACH */
	exit(0);
}
