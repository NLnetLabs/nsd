/*
 * nsd-dnstap.c -- capture dnstap payloads from a nameserver
 *
 * By Matthijs Mekking.
 * Copyright (c) 2014, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <fcntl.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <tsig.h>
#include <unistd.h>
#include <netdb.h>
#include <pwd.h>

#include "query.h"

extern char *optarg;
extern int optind;

static void
usage(void)
{
	fprintf(stderr, "usage: nsd-dnstap [-h] [-f filename]\n\n");
	fprintf(stderr, "Capture dnstap payloads from a server.\n");
	fprintf(stderr, "Version %s. Report bugs to <%s>.\n\n",
		PACKAGE_VERSION, PACKAGE_BUGREPORT);
	fprintf(stderr, "  -f           Unlink socket file before creating a new.\n");
	fprintf(stderr, "  -h           Print this help.\n");
	fprintf(stderr, "  -s filename  The filename of dnstap socket.\n");
	fprintf(stderr, "  -u username  Drop privileges to user.\n");
	exit(1);
}

static void
dnstap_chown(const char* file, uid_t uid, gid_t gid)
{
	if (chown(file, uid, gid) != 0) {
		fprintf(stderr, "nsd-dnstap: chown %s failed: %s", file, strerror(errno));
        }
	return;
}

static void
dnstap_start(const char* filename, const char* username, int count)
{
#ifdef HAVE_GETPWNAM
        struct passwd *pwd = NULL;
#endif /* HAVE_GETPWNAM */
	struct sockaddr_un servaddr;
	struct sockaddr_un cliaddr;
	socklen_t clilen;
	fd_set rset;
	int flags, ret, clifd;
	ssize_t n = 0;
	char buf[MAX_PACKET_SIZE];
	uid_t uid = -1;
	gid_t gid = -1;
	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		fprintf(stderr, "nsd-dnstap: cannot create socket: %s\n", strerror(errno));
		exit(1);
	}
	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0) {
		fprintf(stderr, "nsd-dnstap: fcntl failed: %s\n", strerror(errno));
		close(fd);
		exit(1);
	}
	flags |= O_NONBLOCK;
	if (fcntl(fd, F_SETFL, flags) < 0) {
		fprintf(stderr, "nsd-dnstap: fcntl failed: %s\n", strerror(errno));
		close(fd);
		exit(1);
	}
	bzero(&servaddr, sizeof(servaddr));
	servaddr.sun_family = AF_UNIX;
	strlcpy(servaddr.sun_path, filename, sizeof(servaddr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SUN_LEN
	servaddr.sun_len = strlen(servaddr.sun_path);
#endif
	/* bind and listen... */
	ret = bind(fd, (const struct sockaddr*) &servaddr,
        SUN_LEN(&servaddr));
	if (ret != 0) {
		fprintf(stderr, "nsd-dnstap: cannot bind to socket: %s\n", strerror(errno));
		close(fd);
		exit(1);
	}
	ret = listen(fd, count);
	if (ret != 0) {
		fprintf(stderr, "nsd-dnstap: cannot listen to socket: %s\n", strerror(errno));
		close(fd);
		exit(1);
	}

        /* drop the permissions */
	gid = getgid();
	uid = getuid();
#ifdef HAVE_GETPWNAM
	if (username) {
		if (isdigit((int)*username)) {
			char *t;
			uid = strtol(username, &t, 10);
			if (*t != 0) {
				if (*t != '.' || !isdigit((int)*++t)) {
					fprintf(stderr, "nsd-dnstap: username format error\n");
				}
				gid = strtol(t, &t, 10);
			} else {
				if ((pwd = getpwuid(uid)) == NULL) {
					fprintf(stderr, "nsd-dnstap: uid %u does not exist\n", (unsigned) uid);
				} else {
					gid = pwd->pw_gid;
				}
			}
		} else {
			if ((pwd = getpwnam(username)) == NULL) {
				fprintf(stderr, "nsd-dnstap: user %s does not exist\n", username);
			} else {
				uid = pwd->pw_uid;
				gid = pwd->pw_gid;
			}
		}
	}
	/* endpwent(); */
#endif /* HAVE_GETPWNAM */

	dnstap_chown(filename, uid, gid);

#ifdef HAVE_GETPWNAM
	if (username) {
#ifdef HAVE_INITGROUPS
		if(initgroups(username, gid) != 0)
			fprintf(stderr, "nsd-dnstap: unable to initgroups %s: %s", username, strerror(errno));
#endif /* HAVE_INITGROUPS */
		endpwent();

#ifdef HAVE_SETRESGID
		if(setresgid(gid,gid,gid) != 0)
#elif defined(HAVE_SETREGID) && !defined(DARWIN_BROKEN_SETREUID)
			 if(setregid(gid,gid) != 0)
#else /* use setgid */
				if(setgid(gid) != 0)
#endif /* HAVE_SETRESGID */
					fprintf(stderr, "nsd-dnstap: unable to set group id of %s: %s", username, strerror(errno));
#ifdef HAVE_SETRESUID
		if(setresuid(uid,uid,uid) != 0)
#elif defined(HAVE_SETREUID) && !defined(DARWIN_BROKEN_SETREUID)
			if(setreuid(uid,uid) != 0)
#else /* use setuid */
				if(setuid(uid) != 0)
#endif /* HAVE_SETRESUID */
					fprintf(stderr, "nsd-dnstap: unable to set user id of %s: %s", username, strerror(errno));
	}
#endif /* HAVE_GETPWNAM */

	/* accepting */
	FD_ZERO(&rset);
	while (1) {
		clilen = sizeof(cliaddr);
		FD_SET(fd, &rset);
		ret = select(fd+1, &rset, NULL, NULL, NULL);
		if (ret < 0) {
			if (errno != EINTR && errno != EWOULDBLOCK) {
				fprintf(stderr, "nsd-dnstap: select() error: %s", strerror(errno));
			}
			continue;
		}
		if (FD_ISSET(fd, &rset)) {
			clifd = accept(fd, (struct sockaddr *) &cliaddr, &clilen);
			if (clifd < 0) {
				if (errno != EINTR && errno != EWOULDBLOCK) {
					fprintf(stderr, "nsd-dnstap: accept() error: %s", strerror(errno));
				}
				continue;
			}
			while ((n = read(clifd, buf, MAX_PACKET_SIZE)) > 0) {
				buf[--n] = '\0';
				fprintf(stdout, "nsd-dnstap: %s\n", buf);
			}

		        close(clifd);
                }
	}
	/* shutdown */
	fprintf(stdout, "shutting down...\n");
	return;
}


int
main(int argc, char *argv[])
{
	int c, force = 0;
	const char *filename = DNSTAP_SOCKET_PATH;
	const char *username = NULL;

	log_init("nsd-dnstap");
	/* Parse the command line... */
	while ((c = getopt(argc, argv, "fhs:u:")) != -1) {
		switch (c) {
		case 'f':
			force = 1;
			break;
		case 's':
			filename = optarg;
			break;
		case 'u':
			username = optarg;
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 0) {
		usage();
	}

	if (force) {
		(void) unlink(filename);
	}
	dnstap_start(filename, username, 5);

	exit(0);
}
