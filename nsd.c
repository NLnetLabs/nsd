/*
 * nsd.c -- nsd(8)
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

#include <config.h>

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "namedb.h"
#include "nsd.h"
#include "plugins.h"
#include "query.h"
#include "util.h"


/* The server handler... */
static struct nsd nsd;
static char hostname[MAXHOSTNAMELEN];

static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);

static void
usage (void)
{
	fprintf(stderr, "Usage: nsd [OPTION]...\n");
	fprintf(stderr, "Start the NSD name server daemon.\n\n");
	fprintf(stderr,
		"Supported options:\n"
		"  -4              Only listen to IPv4 connections.\n"
		"  -6              Only listen to IPv6 connections.\n"
		"  -a ip-address   Listen to the specified incoming IP address (may be\n"
		"                  specified multiple times).\n"
		"  -d              Enable debug mode (do not fork as a daemon process).\n"
		"  -f database     Specify the database to load.\n"
		"  -h              Print this help information.\n"
		"  -i identity     Specify the identity when queried for id.server CHAOS TXT.\n"
		);
	fprintf(stderr,
		"  -l filename     Specify the log file.\n"
		"  -N udp-servers  Specify the number of child UDP servers.\n"
		"  -n tcp-servers  Specify the number of child TCP servers.\n"
		"  -p port         Specify the port to listen to.\n"
		"  -s seconds      Dump statistics every SECONDS seconds.\n"
		"  -t chrootdir    Change root to specified directory on startup.\n"
		"  -u user         Change effective uid to the specified user.\n"
		"  -v              Print version information.\n"
		"  -X plugin       Load a plugin (may be specified multiple times).\n\n"
		);
	fprintf(stderr, "Report bugs to <%s>.\n", PACKAGE_BUGREPORT);
	exit(1);
}

static void
version(void)
{
	fprintf(stderr, "%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	fprintf(stderr, "Written by NLnet Labs.\n\n");
	fprintf(stderr,
		"Copyright (C) 2001-2003 NLnet Labs.  This is free software.\n"
		"There is NO warranty; not even for MERCHANTABILITY or FITNESS\n"
		"FOR A PARTICULAR PURPOSE.\n");
	exit(0);
}

static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(1);
}

pid_t 
readpid (const char *file)
{
	int fd;
	pid_t pid;
	char pidbuf[16];
	char *t;
	int l;

	if ((fd = open(file, O_RDONLY)) == -1) {
		return -1;
	}

	if (((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	/* Empty pidfile means no pidfile... */
	if (l == 0) {
		errno = ENOENT;
		return -1;
	}

	pid = strtol(pidbuf, &t, 10);

	if (*t && *t != '\n') {
		return -1;
	}
	return pid;
}

int 
writepid (struct nsd *nsd)
{
	FILE * fd;
	char pidbuf[16];

	snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) nsd->pid);

	if ((fd = fopen(nsd->pidfile, "w")) ==  NULL ) {
		return -1;
	}

	if (!write_data(fd, pidbuf, strlen(pidbuf))) {
		fclose(fd);
		return -1;
	}
	fclose(fd);

	if (chown(nsd->pidfile, nsd->uid, nsd->gid) == -1) {
		log_msg(LOG_ERR, "cannot chown %u.%u %s: %s",
			(unsigned) nsd->uid, (unsigned) nsd->gid,
			nsd->pidfile, strerror(errno));
		return -1;
	}

	return 0;
}
	

void 
sig_handler (int sig)
{
	size_t i;
	
	/* Are we a child server? */
	if (nsd.server_kind != NSD_SERVER_MAIN) {
		switch (sig) {
		case SIGCHLD:
			/* Plugins may fork, reap all terminated children.  */
			while (waitpid(0, NULL, WNOHANG) > 0)
				;
			break;
		case SIGALRM:
			break;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			nsd.mode = NSD_QUIT;
			break;
		case SIGILL:
			nsd.mode = NSD_STATS;
			break;
		default:
			break;
		}
		return;
	}

	switch (sig) {
	case SIGCHLD:
		return;
	case SIGHUP:
		log_msg(LOG_WARNING, "signal %d received, reloading...", sig);
		nsd.mode = NSD_RELOAD;
		return;
	case SIGALRM:
#ifdef BIND8_STATS
		alarm(nsd.st.period);
#endif
		sig = SIGILL;
	case SIGILL:
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_QUIT;
		break;
	case SIGTERM:
	default:
		nsd.mode = NSD_SHUTDOWN;
		log_msg(LOG_WARNING, "signal %d received, shutting down...", sig);
		break;
	}

	/* Distribute the signal to the servers... */
	for (i = 0; i < nsd.child_count; ++i) {
		if (nsd.children[i].pid > 0 && kill(nsd.children[i].pid, sig) == -1) {
			log_msg(LOG_ERR, "problems killing %d: %s",
				(int) nsd.children[i].pid, strerror(errno));
		}
	}
}

/*
 * Statistic output...
 *
 */
#ifdef BIND8_STATS
void 
bind8_stats (struct nsd *nsd)
{
	char buf[MAXSYSLOGMSGLEN];
	char *msg, *t;
	int i, len;

	/* XXX A bit ugly but efficient. Should be somewhere else. */
	static const char *types[] = {
		NULL, "A", "NS", "MD", "MF", "CNAME", "SOA", "MB", "MG",		/* 8 */
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
		"TKEY", "TSIG", "IXFR", "AXFR", "MAILB", "MAILA", "ANY"			/* 255 */
	};


	/* Current time... */
	time_t now;
	time(&now);

	/* NSTATS */
	t = msg = buf + snprintf(buf, MAXSYSLOGMSGLEN, "NSTATS %lu %lu",
				 (unsigned long) now, (unsigned long) nsd->st.boot);
	for (i = 0; i <= 255; i++) {
		/* How much space left? */
		if ((len = buf + MAXSYSLOGMSGLEN - t) < 32) {
			log_msg(LOG_INFO, "%s", buf);
			t = msg;
			len = buf + MAXSYSLOGMSGLEN - t;
		}

		if (nsd->st.qtype[i] != 0) {
			if (types[i] == NULL) {
				t += snprintf(t, len, " TYPE%d=%lu", i, nsd->st.qtype[i]);
			} else {
				t += snprintf(t, len, " %s=%lu", types[i], nsd->st.qtype[i]);
			}
		}
	}
	if (t > msg)
		log_msg(LOG_INFO, "%s", buf);

	/* XSTATS */
	/* Only print it if we're in the main daemon or have anything to report... */
	if (nsd->server_kind == NSD_SERVER_MAIN
	    || nsd->st.dropped || nsd->st.raxfr || (nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped)
	    || nsd->st.txerr || nsd->st.opcode[OPCODE_QUERY] || nsd->st.opcode[OPCODE_IQUERY]
	    || nsd->st.wrongzone || nsd->st.ctcp + nsd->st.ctcp6 || nsd->st.rcode[RCODE_SERVFAIL]
	    || nsd->st.rcode[RCODE_FORMAT] || nsd->st.nona || nsd->st.rcode[RCODE_NXDOMAIN]
	    || nsd->st.opcode[OPCODE_UPDATE]) {

		log_msg(LOG_INFO, "XSTATS %lu %lu"
			" RR=%lu RNXD=%lu RFwdR=%lu RDupR=%lu RFail=%lu RFErr=%lu RErr=%lu RAXFR=%lu"
			" RLame=%lu ROpts=%lu SSysQ=%lu SAns=%lu SFwdQ=%lu SDupQ=%lu SErr=%lu RQ=%lu"
			" RIQ=%lu RFwdQ=%lu RDupQ=%lu RTCP=%lu SFwdR=%lu SFail=%lu SFErr=%lu SNaAns=%lu"
			" SNXD=%lu RUQ=%lu RURQ=%lu RUXFR=%lu RUUpd=%lu",
			(unsigned long) now, (unsigned long) nsd->st.boot,
			nsd->st.dropped, (unsigned long)0, (unsigned long)0, (unsigned long)0, (unsigned long)0,
			(unsigned long)0, (unsigned long)0, nsd->st.raxfr, (unsigned long)0, (unsigned long)0,
			(unsigned long)0, nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped, (unsigned long)0,
			(unsigned long)0, nsd->st.txerr,
			nsd->st.opcode[OPCODE_QUERY], nsd->st.opcode[OPCODE_IQUERY], nsd->st.wrongzone,
			(unsigned long)0, nsd->st.ctcp + nsd->st.ctcp6,
			(unsigned long)0, nsd->st.rcode[RCODE_SERVFAIL], nsd->st.rcode[RCODE_FORMAT],
			nsd->st.nona, nsd->st.rcode[RCODE_NXDOMAIN],
			(unsigned long)0, (unsigned long)0, (unsigned long)0, nsd->st.opcode[OPCODE_UPDATE]);
	}

}
#endif /* BIND8_STATS */

extern char *optarg;
extern int optind;

int 
main (int argc, char *argv[])
{
	/* Scratch variables... */
	int c;
	pid_t	oldpid;
	size_t udp_children = 1;
	size_t tcp_children = 1;
	size_t i;
	struct sigaction action;
	
	/* For initialising the address info structures */
	struct addrinfo hints[MAX_INTERFACES];
	const char *nodes[MAX_INTERFACES];
	const char *udp_port;
	const char *tcp_port;

	const char *log_filename = NULL;
	
#ifdef PLUGINS
	nsd_plugin_id_type plugin_count = 0;
	char **plugins = xalloc(sizeof(char *));
	maximum_plugin_count = 1;
#endif /* PLUGINS */

	log_init("nsd");
	
	/* Initialize the server handler... */
	memset(&nsd, 0, sizeof(struct nsd));
	nsd.region      = region_create(xalloc, free);
	nsd.dbfile	= DBFILE;
	nsd.pidfile	= PIDFILE;
	nsd.server_kind = NSD_SERVER_MAIN;
	
	/* Initialise the ports */
	udp_port = UDP_PORT;
	tcp_port = TCP_PORT;

	for (i = 0; i < MAX_INTERFACES; i++) {
		memset(&hints[i], 0, sizeof(hints[i]));
		hints[i].ai_family = DEFAULT_AI_FAMILY;
		hints[i].ai_flags = AI_PASSIVE;
		nodes[i] = NULL;
	}

	nsd.tcp_max_msglen = TCP_MAX_MESSAGE_LEN;
	nsd.identity	= IDENTITY;
	nsd.version	= VERSION;
	nsd.username	= USER;
	nsd.chrootdir	= NULL;

	/* EDNS0 */
	nsd.edns.max_msglen = EDNS_MAX_MESSAGE_LEN;
	nsd.edns.opt_ok[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_ok[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_ok[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_ok[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */

	nsd.edns.opt_err[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_err[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_err[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_err[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */
	nsd.edns.opt_err[5] = 1;			/* XXX Extended RCODE=BAD VERS */

	/* Set up our default identity to gethostname(2) */
	if (gethostname(hostname, MAXHOSTNAMELEN) == 0) {
		nsd.identity = hostname;
	} else {
		log_msg(LOG_ERR,
			"failed to get the host name: %s - using default identity",
			strerror(errno));
	}


	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46a:df:hi:l:N:n:p:s:u:t:X:v")) != -1) {
		switch (c) {
		case '4':
			for (i = 0; i < MAX_INTERFACES; ++i) {
				hints[i].ai_family = AF_INET;
			}
			break;
		case '6':
#ifdef INET6
			for (i = 0; i < MAX_INTERFACES; ++i) {
				hints[i].ai_family = AF_INET6;
			}
#else /* !INET6 */
			error("IPv6 support not enabled.");
#endif /* !INET6 */
			break;
		case 'a':
			nodes[nsd.ifs] = optarg;
			++nsd.ifs;
			break;
		case 'd':
			nsd.debug = 1;
			break;
		case 'f':
			nsd.dbfile = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'i':
			nsd.identity = optarg;
			break;
		case 'l':
			log_filename = optarg;
			break;
		case 'N':
			i = atoi(optarg);
			if (i <= 0) {
				error("number of UDP servers must be greather than zero");
			} else {
				udp_children = i;
			}
			break;
		case 'n':
			i = atoi(optarg);
			if (i <= 0) {
				error("number of TCP servers must be greather than zero");
			} else {
				tcp_children = i;
			}
			break;
		case 'p':
			tcp_port = optarg;
			udp_port = optarg;
			break;
		case 's':
#ifdef BIND8_STATS
			nsd.st.period = atoi(optarg);
#else /* !BIND8_STATS */
			error("BIND 8 statistics not enabled.");
#endif /* !BIND8_STATS */
			break;
		case 't':
#ifdef HAVE_CHROOT
			nsd.chrootdir = optarg;
#else /* !HAVE_CHROOT */
			error("chroot not supported on this platform.");
#endif /* !HAVE_CHROOT */
			break;
		case 'u':
			nsd.username = optarg;
			break;
		case 'X':
#ifdef PLUGINS
			if (plugin_count == maximum_plugin_count) {
				maximum_plugin_count *= 2;
				plugins = xrealloc(plugins, maximum_plugin_count * sizeof(char *));
			}
			plugins[plugin_count] = optarg;
			++plugin_count;
#else /* !PLUGINS */
			error("plugin support not enabled.");
#endif /* !PLUGINS */
			break;
		case 'v':
			version();
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	if (strlen(nsd.identity) > UCHAR_MAX) {
		error("server identity too long (%u characters)",
		      (unsigned) strlen(nsd.identity));
	}
	
	/* Number of child servers to fork.  */
	nsd.child_count = udp_children + tcp_children;
	nsd.children = region_alloc(
		nsd.region, nsd.child_count * sizeof(struct nsd_child));
	for (i = 0; i < udp_children; ++i) {
		nsd.children[i].kind = NSD_SERVER_UDP;
	}
	for (; i < nsd.child_count; ++i) {
		nsd.children[i].kind = NSD_SERVER_TCP;
	}
	
	/* We need at least one active interface */
	if (nsd.ifs == 0) {
		nsd.ifs = 1;

		/*
		 * With IPv6 we'd like to open two separate sockets,
		 * one for IPv4 and one for IPv6, both listening to
		 * the wildcard address (unless the -4 or -6 flags are
		 * specified).
		 *
		 * However, this is only supported on platforms where
		 * we can turn the socket option IPV6_V6ONLY _on_.
		 * Otherwise we just listen to a single IPv6 socket
		 * and any incoming IPv4 connections will be
		 * automatically mapped to our IPv6 socket.
		 */
#ifdef INET6
		if (hints[i].ai_family == AF_UNSPEC) {
# ifdef IPV6_V6ONLY
			hints[0].ai_family = AF_INET6;
			hints[1].ai_family = AF_INET;
			nsd.ifs = 2;
# else /* !IPV6_V6ONLY */
			hints[0].ai_family = AF_INET6;
# endif	/* !IPV6_V6ONLY */
		}
#endif /* INET6 */
	}

	/* Set up the address info structures with real interface/port data */
	for (i = 0; i < nsd.ifs; ++i)
	{
		/* We don't perform name-lookups */
		if (nodes[i] != NULL)
			hints[i].ai_flags |= AI_NUMERICHOST;
		
		hints[i].ai_socktype = SOCK_DGRAM;
		if ( getaddrinfo(nodes[i], udp_port, &hints[i], &nsd.udp[i].addr) != 0)
			usage();
		
		hints[i].ai_socktype = SOCK_STREAM;
		if ( getaddrinfo(nodes[i], tcp_port, &hints[i], &nsd.tcp[i].addr) != 0)
			usage();

	}

	/* Parse the username into uid and gid */
	nsd.gid = getgid();
	nsd.uid = getuid();
	if (*nsd.username) {
		struct passwd *pwd;
		if (isdigit(*nsd.username)) {
			char *t;
			nsd.uid = strtol(nsd.username, &t, 10);
			if (*t != 0) {
				if (*t != '.' || !isdigit(*++t)) {
					error("-u user or -u uid or -u uid.gid");
				}
				nsd.gid = strtol(t, &t, 10);
			} else {
				/* Lookup the group id in /etc/passwd */
				if ((pwd = getpwuid(nsd.uid)) == NULL) {
					error("user id %u does not exist.", (unsigned) nsd.uid);
				} else {
					nsd.gid = pwd->pw_gid;
				}
				endpwent();
			}
		} else {
			/* Lookup the user id in /etc/passwd */
			if ((pwd = getpwnam(nsd.username)) == NULL) {
				error("user '%s' does not exist.", nsd.username);
			} else {
				nsd.uid = pwd->pw_uid;
				nsd.gid = pwd->pw_gid;
			}
			endpwent();
		}
	}

	/* Set up the logging... */
	log_open(LOG_PID, FACILITY, log_filename);
	if (!log_filename) {
		log_set_log_function(log_syslog);
	}
	
	/* Relativize the pathnames for chroot... */
	if (nsd.chrootdir) {
		int l = strlen(nsd.chrootdir);

		if (strncmp(nsd.chrootdir, nsd.pidfile, l) != 0) {
			log_msg(LOG_ERR, "%s is not relative to %s: will not chroot",
				nsd.pidfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		} else if (strncmp(nsd.chrootdir, nsd.dbfile, l) != 0) {
			log_msg(LOG_ERR, "%s is not relative to %s: will not chroot",
				nsd.dbfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		}
	}

	/* Do we have a running nsd? */
	if ((oldpid = readpid(nsd.pidfile)) == -1) {
		if (errno != ENOENT) {
			log_msg(LOG_ERR, "can't read pidfile %s: %s",
				nsd.pidfile, strerror(errno));
		}
	} else {
		if (kill(oldpid, 0) == 0 || errno == EPERM) {
			log_msg(LOG_ERR,
				"nsd is already running as %u, stopping",
				(unsigned) oldpid);
/* 			exit(0); */
		} else {
			log_msg(LOG_ERR,
				"...stale pid file from process %u",
				(unsigned) oldpid);
		}
	}

	/* Unless we're debugging, fork... */
	if (nsd.debug) {
		nsd.server_kind = NSD_SERVER_BOTH;
	} else {
		int fd;
		
		/* Take off... */
		switch ((nsd.pid = fork())) {
		case 0:
			break;
		case -1:
			log_msg(LOG_ERR, "fork failed: %s", strerror(errno));
			unlink(nsd.pidfile);
			exit(1);
		default:
			exit(0);
		}

		/* Detach ourselves... */
		if (setsid() == -1) {
			log_msg(LOG_ERR, "setsid() failed: %s", strerror(errno));
			exit(1);
		}

		if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(fd, STDIN_FILENO);
			(void)dup2(fd, STDOUT_FILENO);
			(void)dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void)close(fd);
		}
	}

	/* Setup the signal handling... */
	action.sa_handler = sig_handler;
	sigfillset(&action.sa_mask);
	action.sa_flags = 0;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGHUP, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGCHLD, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);


	/* Get our process id */
	nsd.pid = getpid();

	/* Overwrite pid... */
	if (writepid(&nsd) == -1) {
		log_msg(LOG_ERR, "cannot overwrite the pidfile %s: %s",
			nsd.pidfile, strerror(errno));
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	if (server_init(&nsd) != 0) {
		unlink(nsd.pidfile);
		exit(1);
	}

#ifdef PLUGINS
	maximum_plugin_count = plugin_count;
	plugin_init(&nsd);
	for (i = 0; i < plugin_count; ++i) {
		const char *arg = "";
		char *eq = strchr(plugins[i], '=');
		if (eq) {
			*eq = '\0';
			arg = eq + 1;
		}
		if (!plugin_load(&nsd, plugins[i], arg)) {
			plugin_finalize_all();
			unlink(nsd.pidfile);
			exit(1);
		}
	}
	free(plugins);
#endif /* PLUGINS */
	
	log_msg(LOG_NOTICE, "nsd started, pid %d", (int) nsd.pid);

	if (nsd.server_kind == NSD_SERVER_MAIN) {
		server_main(&nsd);
	} else {
		server_child(&nsd);
	}

	/* NOTREACH */
	exit(0);
}
