/*
 * dnstap.h - dnstap for NSD.
 *
 * By Matthijs Mekking.
 * Copyright (c) 2014, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <strings.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

#include "dnstap.h"
#include "options.h"
#include "util.h"

#ifdef DNSTAP

static int dnstap_sockfd;


/**
 * Write to file descriptor.
 *
 */
ssize_t
dnstap_writen(int fd, const void* vptr, size_t n)
{
	ssize_t nwritten = 0;
	size_t nleft = n;
	const char* ptr = vptr;
	while (nleft > 0) {
		if ((nwritten = write(fd, ptr, nleft)) <= 0) {
			if (nwritten < 0 && errno == EINTR) {
				nwritten = 0; /* and call write again */
			} else {
				log_msg(LOG_ERR, "dnstap: write failed: %s",
						strerror(errno));
				return -1; /* error */
			}
		}
		nleft -= nwritten;
		ptr += nwritten;
	}
	return n;
}


/**
 * Connect to dnstap socket.
 *
 */
static int
dnstap_connect(struct nsd* nsd)
{
	dnstap_sockfd = -1;

	if (nsd->options->dnstap_enable) {
		struct sockaddr_un servaddr;
		int ret, flags;
		dnstap_sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (dnstap_sockfd < 0) {
			return -1;
		}
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sun_family = AF_UNIX;
		strlcpy(servaddr.sun_path, nsd->options->dnstap_sockpath,
			sizeof(servaddr.sun_path) - 1);
#ifdef HAVE_SOCKADDR_SUN_LEN
		servaddr.sun_len = strlen(servaddr.sun_path);
#endif
		/* set socket to non-blocking */
		flags = fcntl(dnstap_sockfd, F_GETFL, 0);
		if (flags < 0) {
			close(dnstap_sockfd);
			return -1;
		}
		flags |= O_NONBLOCK;
		if (fcntl(dnstap_sockfd, F_SETFL, flags) < 0) {
			close(dnstap_sockfd);
			return -1;
		}
		/* connect */
		ret = connect(dnstap_sockfd,
			(const struct sockaddr*) &servaddr, sizeof(servaddr));
		if (ret != 0) {
			close(dnstap_sockfd);
			return -1;
		}
	}
	return 0;
}


/**
 * Process query.
 *
 */
void
dnstap_process_query(query_type* query, struct nsd* nsd)
{
	const char* cmd = "QUERY\n";
	if (nsd->options->dnstap_enable && nsd->options->dnstap_query) {
		if (dnstap_connect(nsd) == 0) {
			(void)dnstap_writen(dnstap_sockfd, cmd, strlen(cmd));
			close(dnstap_sockfd);
		} else {
			log_msg(LOG_ERR, "dnstap: connect failed: %s",
				strerror(errno));
		}
	}
	return;
}


/**
 * Process response.
 *
 */
void
dnstap_process_response(query_type* query, struct nsd* nsd)
{
	const char* cmd = "RESPONSE\n";
	if (nsd->options->dnstap_enable && nsd->options->dnstap_response) {
		if (dnstap_connect(nsd) == 0) {
			(void)dnstap_writen(dnstap_sockfd, cmd, strlen(cmd));
			close(dnstap_sockfd);
		} else {
			log_msg(LOG_ERR, "dnstap: connect failed: %s",
				strerror(errno));
		}
	}
	return;
}

#endif /* DNSTAP */
