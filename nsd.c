/*
 * nsd.c -- nsd(8)
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
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

#include "nsd.h"
#include "options.h"
#include "plugins.h"
#ifdef TSIG
#include "tsig.h"
#endif /* TSIG */

/* The server handler... */
static nsd_type nsd;
static char hostname[MAXHOSTNAMELEN];

static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);

static void
usage (void)
{
	fprintf(stderr, "Usage: nsd [OPTION]...\n");
	fprintf(stderr, "Name Server Daemon.\n\n");
	fprintf(stderr,
		"Supported options:\n"
		"  -c config-file  Specify the location of the configuration file.\n"
		"  -d              Enable debug mode (do not fork as a daemon process).\n"
		"  -h              Print this help information.\n"
		);
	fprintf(stderr,
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
		"Copyright (C) 2001-2004 NLnet Labs.  This is free software.\n"
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
writepid (nsd_type *nsd)
{
	FILE * fd;
	char pidbuf[16];

	snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long) nsd->pid);

	if ((fd = fopen(nsd->options->pid_file, "w")) ==  NULL ) {
		return -1;
	}

	if (!write_data(fd, pidbuf, strlen(pidbuf))) {
		fclose(fd);
		return -1;
	}
	fclose(fd);

	if (chown(nsd->options->pid_file, nsd->uid, nsd->gid) == -1) {
		log_msg(LOG_ERR, "cannot chown %u.%u %s: %s",
			(unsigned) nsd->uid, (unsigned) nsd->gid,
			nsd->options->pid_file, strerror(errno));
		return -1;
	}

	return 0;
}


void
sig_handler (int sig)
{
	size_t i;

	/* Are we a child server? */
	if (nsd.server_kind != NSD_SERVER_KIND_MAIN) {
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
		case SIGUSR1:	/* Dump stats on SIGUSR1.  */
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
		alarm(nsd.options->statistics_period);
#endif
		sig = SIGUSR1;
		break;
	case SIGILL:
		/*
		 * For backwards compatibility with BIND 8 and older
		 * versions of NSD.
		 */
		sig = SIGUSR1;
		break;
	case SIGUSR1:
		/* Dump statistics.  */
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_QUIT;
		break;
	case SIGTERM:
	default:
		nsd.mode = NSD_SHUTDOWN;
		log_msg(LOG_WARNING, "signal %d received, shutting down...", sig);
		sig = SIGTERM;
		break;
	}

	/* Distribute the signal to the servers... */
	for (i = 0; i < nsd.options->server_count; ++i) {
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
bind8_stats (nsd_type *nsd)
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
		"OPT", NULL, "DS", NULL, NULL, "RRSIG", "NSEC", "DNSKEY",		/* 48 */
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
	if (nsd->server_kind == NSD_SERVER_KIND_MAIN
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
	size_t i;
	struct sigaction action;

	/* For initialising the address info structures */
	nsd_socket_type *current_socket;

#ifdef PLUGINS
	nsd_plugin_id_type plugin_count = 0;
	char **plugins = (char **) xalloc(sizeof(char *));
	maximum_plugin_count = 1;
#endif /* PLUGINS */

	log_init("nsd");

	/* Initialize the server handler... */
	memset(&nsd, 0, sizeof(nsd_type));
	nsd.region      = region_create(xalloc, free);
	nsd.server_kind = NSD_SERVER_KIND_MAIN;

	nsd.options_file = CONFIGFILE;
	nsd.options      = NULL;
	nsd.current_tcp_connection_count = 0;

	/* EDNS0 */
	edns_init_data(&nsd.edns_ipv4, EDNS_MAX_MESSAGE_LEN);
#if defined(INET6)
# if defined(IPV6_USE_MIN_MTU)
	edns_init_data(&nsd.edns_ipv6, EDNS_MAX_MESSAGE_LEN);
# else /* !defined(IPV6_USE_MIN_MTU) */
	edns_init_data(&nsd.edns_ipv6, IPV6_MIN_MTU);
# endif
#endif

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "c:dhX:vF:L:")) != -1) {
		switch (c) {
		case 'c':
			nsd.options_file = optarg;
			break;
		case 'd':
			nsd.debug = 1;
			break;
		case 'h':
			usage();
			break;
		case 'X':
#ifdef PLUGINS
			if (plugin_count == maximum_plugin_count) {
				maximum_plugin_count *= 2;
				plugins = (char **) xrealloc(
					plugins,
					maximum_plugin_count * sizeof(char *));
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
#ifndef NDEBUG
		case 'F':
			sscanf(optarg, "%x", &nsd_debug_facilities);
			break;
		case 'L':
			sscanf(optarg, "%d", &nsd_debug_level);
			break;
#endif /* NDEBUG */
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 0)
		usage();

	nsd.options = load_configuration(nsd.region, nsd.options_file);
	if (!nsd.options) {
		error("failed to load configuration file '%s'",
		      nsd.options_file);
	}

#ifndef BIND8_STATS
	if (nsd.options->statistics_period > 0) {
			error("BIND 8 statistics not enabled.");
	}
#endif /* !BIND8_STATS */

	if (nsd.options->directory) {
		if (chdir(nsd.options->directory) == -1) {
			error("cannot change directory to '%s': %s",
			      nsd.options->directory,
			      strerror(errno));
		}
	}

	if (!nsd.options->user_id) {
		nsd.options->user_id = USER;
	}
	if (!nsd.options->database) {
		nsd.options->database = DBFILE;
	}
	if (!nsd.options->version) {
		nsd.options->version = VERSION;
	}

	if (!nsd.options->identity) {
		/* Set up our default identity to gethostname(2) */
		if (gethostname(hostname, MAXHOSTNAMELEN) == 0) {
			nsd.options->identity = hostname;
		} else {
			log_msg(LOG_ERR,
				"gethostbyname: %s - using default identity",
				strerror(errno));
			nsd.options->identity = IDENTITY;
		}
	}

	if (strlen(nsd.options->identity) > UCHAR_MAX) {
		error("server identity too long (%u characters)",
		      (unsigned) strlen(nsd.options->identity));
	}

	if (nsd.options->server_count == 0) {
		error("number of child servers must be greather than zero");
	}
	if (nsd.options->maximum_tcp_connection_count == 0) {
		error("maximum number of TCP connections must greater than zero");
	}

	/* Number of child servers to fork.  */
	nsd.children = (struct nsd_child *) region_alloc(
		nsd.region,
		nsd.options->server_count * sizeof(struct nsd_child));
	for (i = 0; i < nsd.options->server_count; ++i) {
		nsd.children[i].kind = NSD_SERVER_KIND_CHILD;
	}

	/* We need at least one active interface */
	if (nsd.options->listen_on_count == 0) {

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
# ifdef IPV6_V6ONLY
		nsd.options->listen_on_count = 2;
		nsd.options->listen_on = region_alloc(
			nsd.region, 2 * sizeof(nsd_options_address_type *));
		nsd.options->listen_on[0] = options_address_make(
			nsd.region, AF_INET6, DEFAULT_DNS_PORT, NULL);
		nsd.options->listen_on[1] = options_address_make(
			nsd.region, AF_INET, DEFAULT_DNS_PORT, NULL);
# else /* !IPV6_V6ONLY */
		nsd.options->listen_on_count = 1;
		nsd.options->listen_on = region_alloc(
			nsd.region, 1 * sizeof(nsd_options_address_type *));
		nsd.options->listen_on[0] = options_address_make(
			AF_INET6, DEFAULT_DNS_PORT, NULL);
# endif	/* !IPV6_V6ONLY */
#else /* !INET6 */
		nsd.options->listen_on_count = 1;
		nsd.options->listen_on = region_alloc(
			nsd.region, 1 * sizeof(nsd_options_address_type *));
		nsd.options->listen_on[0] = options_address_make(
			AF_INET, DEFAULT_PORT, NULL);
#endif /* !INET6 */
	}

	/* TODO: defaults for controls port */
	nsd.socket_count = (2 * nsd.options->listen_on_count
			    + nsd.options->controls_count);
	nsd.sockets = region_alloc(nsd.region,
				   nsd.socket_count * sizeof(nsd_socket_type));
	current_socket = &nsd.sockets[0];

	/* Set up the address info structures with real interface/port data */
	for (i = 0; i < nsd.options->listen_on_count; ++i) {
		nsd_options_address_type *listen_on = nsd.options->listen_on[i];
		struct addrinfo hints;

		if (!listen_on->port) {
			listen_on->port = DEFAULT_DNS_PORT;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = listen_on->family;
		if (listen_on->address) {
			hints.ai_flags = AI_NUMERICHOST;
		} else {
			hints.ai_flags = AI_PASSIVE;
		}

		hints.ai_socktype = SOCK_DGRAM;
		current_socket->kind = NSD_SOCKET_KIND_UDP;
		if (getaddrinfo(listen_on->address,
				listen_on->port,
				&hints,
				&current_socket->addr) != 0)
		{
			error("cannot parse address '%s'", listen_on->address);
		}
		++current_socket;

		hints.ai_socktype = SOCK_STREAM;
		current_socket->kind = NSD_SOCKET_KIND_TCP;
		if (getaddrinfo(listen_on->address,
				listen_on->port,
				&hints,
				&current_socket->addr) != 0)
		{
			error("cannot parse address '%s'", listen_on->address);
		}
		++current_socket;
	}

	for (i = 0; i < nsd.options->controls_count; ++i) {
		nsd_options_address_type *controls = nsd.options->controls[i];
		struct addrinfo hints;

		if (!controls->port) {
			controls->port = DEFAULT_CONTROL_PORT;
		}

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = controls->family;
		if (controls->address) {
			hints.ai_flags = AI_NUMERICHOST;
		} else {
			hints.ai_flags = AI_PASSIVE;
		}

		hints.ai_socktype = SOCK_STREAM;
		current_socket->kind = NSD_SOCKET_KIND_NSDC;
		if (getaddrinfo(controls->address,
				controls->port,
				&hints,
				&current_socket->addr) != 0)
		{
			error("cannot parse address '%s'", controls->address);
		}
		++current_socket;
	}

	/* Parse the username into uid and gid */
	nsd.gid = getgid();
	nsd.uid = getuid();
	if (*nsd.options->user_id) {
		struct passwd *pwd;
		if (isdigit(*nsd.options->user_id)) {
			char *t;
			nsd.uid = strtol(nsd.options->user_id, &t, 10);
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
			if ((pwd = getpwnam(nsd.options->user_id)) == NULL) {
				error("user '%s' does not exist.",
				      nsd.options->user_id);
			} else {
				nsd.uid = pwd->pw_uid;
				nsd.gid = pwd->pw_gid;
			}
			endpwent();
		}
	}

#ifdef TSIG
	tsig_init(nsd.region);

	for (i = 0; i < nsd.options->key_count; ++i) {
		nsd_options_key_type *key_option;
		tsig_key_type *key;
		size_t secret_size;
		int size;
		uint8_t *data;

		key_option = nsd.options->keys[i];
		if (!key_option)
			continue;


		key = region_alloc(nsd.region, sizeof(tsig_key_type));
		key->name = dname_parse(nsd.region, key_option->name);
		if (!key->name) {
			error("bad key name '%s'", key_option->name);
		}

		secret_size = strlen(key_option->secret);
		data = region_alloc(nsd.region, secret_size);
		size = b64_pton(key_option->secret, data, secret_size);
		if (size == -1) {
			error("bad key secret '%s'", key_option->secret);
		}
		key->data = data;
		key->size = size;

		tsig_add_key(key);

		log_msg(LOG_INFO, "key '%s' added",
			dname_to_string(key->name, NULL));
	}
#endif /* TSIG */

	/* Set up the logging... */
	log_open(LOG_PID, FACILITY, nsd.options->log_file);
	if (!nsd.options->log_file) {
		log_set_log_function(log_syslog);
	}

	/* Relativize the pathnames for chroot... */
	if (nsd.options->chroot_directory) {
#ifndef HAVE_CHROOT
		error("chroot not supported on this platform.");
#else /* !HAVE_CHROOT */
		size_t length = strlen(nsd.options->chroot_directory);

		if (strncmp(nsd.options->chroot_directory,
			    nsd.options->pid_file,
			    length) != 0)
		{
			error("%s is not relative to chroot-directory %s",
			      nsd.options->pid_file,
			      nsd.options->chroot_directory);
		} else if (strncmp(nsd.options->chroot_directory,
				   nsd.options->database,
				   length) != 0)
		{
			error("%s is not relative to chroot-directory %s",
			      nsd.options->database,
			      nsd.options->chroot_directory);
		}
#endif /* !HAVE_CHROOT */
	}

	/* Do we have a running nsd? */
	if ((oldpid = readpid(nsd.options->pid_file)) == -1) {
		if (errno != ENOENT) {
			log_msg(LOG_ERR, "can't read pidfile %s: %s",
				nsd.options->pid_file, strerror(errno));
		}
	} else {
		if (kill(oldpid, 0) == 0 || errno == EPERM) {
			log_msg(LOG_ERR,
				"nsd is already running as %u, stopping",
				(unsigned) oldpid);
			/* XXX: Stop or continue to bind port anyway? */
/* 			exit(0); */
		} else {
			log_msg(LOG_ERR,
				"...stale pid file from process %u",
				(unsigned) oldpid);
		}
	}

	/* Unless we're debugging, fork... */
	if (nsd.debug) {
		nsd.server_kind = NSD_SERVER_KIND_CHILD;
	} else {
		int fd;

		/* Take off... */
		switch ((nsd.pid = fork())) {
		case 0:
			break;
		case -1:
			log_msg(LOG_ERR, "fork failed: %s", strerror(errno));
			unlink(nsd.options->pid_file);
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
	sigaction(SIGUSR1, &action, NULL);
	sigaction(SIGALRM, &action, NULL);
	sigaction(SIGCHLD, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);


	/* Get our process id */
	nsd.pid = getpid();

	/* Overwrite pid... */
	if (writepid(&nsd) == -1) {
		log_msg(LOG_ERR, "cannot overwrite the pidfile %s: %s",
			nsd.options->pid_file, strerror(errno));
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	if (server_init(&nsd) != 0) {
		unlink(nsd.options->pid_file);
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

	switch (nsd.server_kind) {
	case NSD_SERVER_KIND_MAIN:
		server_main(&nsd);
		break;
	case NSD_SERVER_KIND_CHILD:
		server_child(&nsd);
		break;
	}

	/* NOTREACH */
	exit(0);
}
