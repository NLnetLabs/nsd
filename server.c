/*
 * server.c -- nsd(8) network input/output
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

#ifdef	HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include <dns.h>
#include <namedb.h>
#include <dname.h>
#include <nsd.h>
#include <query.h>


/*
 * Remove the specified pid from the list of TCP pids.	Returns 0 if
 * the pid is not in the list, 1 otherwise.  The field is set to 0.
 */
int
delete_tcp_child_pid(struct nsd *nsd, pid_t pid)
{
	int i;
	for (i = 1; i <= nsd->tcp_open_conn; ++i) {
		if (nsd->pid[i] == pid) {
			nsd->pid[i] = 0;
			return 1;
		}
	}
	return 0;
}

/*
 * Restart child TCP servers if necessary.
 */
int
restart_tcp_child_servers(struct nsd *nsd)
{
	int i;

	if (nsd->debug) {
		/*
		 * NSD doesn't handle TCP connecties yet in debug mode
		 * (forking interferes with profiling).
		 */
		return 0;
	}
	
	/* Pre-fork the tcp processes... */
	for (i = 1; i <= nsd->tcp_open_conn; ++i) {
		if (nsd->pid[i] == 0) {
			nsd->pid[i] = fork();
			switch (nsd->pid[i]) {
			case 0: /* CHILD */
				nsd->pid[0] = 0;
				server_tcp(nsd);
				/* NOTREACH */
				exit(0);
			case -1:
				syslog(LOG_ERR, "fork failed: %m");
				return -1;
			}
		}
	}
	return 0;
}

/*
 * Initialize the server, create and bind the sockets.
 * Drop the priviledges and chroot if requested.
 *
 */
int
server_init(struct nsd *nsd)
{
	int i;
#if defined(SO_REUSEADDR) || (defined(INET6) && defined(IPV6_V6ONLY))
	int on = 1;
#endif

	/* UDP */

	/* Make a socket... */
	for(i = 0; i < nsd->ifs; i++) {
		if((nsd->udp[i].s = socket(nsd->udp[i].addr->ai_family, nsd->udp[i].addr->ai_socktype, 0)) == -1) {
			syslog(LOG_ERR, "cant create a socket: %m");
			return -1;
		}

#if defined(INET6) && defined(IPV6_V6ONLY)
		if (nsd->udp[i].addr->ai_family == PF_INET6 &&
		    setsockopt(nsd->udp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
		{
			syslog(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %m");
			return -1;
		}
#endif

		/* Bind it... */
		if(bind(nsd->udp[i].s, (struct sockaddr *) nsd->udp[i].addr->ai_addr, nsd->udp[i].addr->ai_addrlen) != 0) {
			syslog(LOG_ERR, "cant bind the socket: %m");
			return -1;
		}
	}

	/* TCP */

	/* Make a socket... */
	for(i = 0; i < nsd->ifs; i++) {
		if((nsd->tcp[i].s = socket(nsd->tcp[i].addr->ai_family, nsd->tcp[i].addr->ai_socktype, 0)) == -1) {
			syslog(LOG_ERR, "cant create a socket: %m");
			return -1;
		}

#ifdef	SO_REUSEADDR
		if(setsockopt(nsd->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			syslog(LOG_ERR, "setsockopt(..., SO_REUSEADDR, ...) failed: %m");
			return -1;
		}
#endif /* SO_REUSEADDR */

#if defined(INET6) && defined(IPV6_V6ONLY)
		if (nsd->tcp[i].addr->ai_family == PF_INET6 &&
		    setsockopt(nsd->tcp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
		{
			syslog(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %m");
			return -1;
		}
#endif

		/* Bind it... */
		if(bind(nsd->tcp[i].s, (struct sockaddr *) nsd->tcp[i].addr->ai_addr, nsd->tcp[i].addr->ai_addrlen) != 0) {
			syslog(LOG_ERR, "cant bind the socket: %m");
			return -1;
		}

		/* Listen to it... */
		if(listen(nsd->tcp[i].s, TCP_BACKLOG) == -1) {
			syslog(LOG_ERR, "cant listen: %m");
			return -1;
		}
	}

	/* Chroot */
	if(nsd->chrootdir) {
		int l = strlen(nsd->chrootdir);

		nsd->dbfile += l;
		nsd->pidfile += l;

		if(chroot(nsd->chrootdir)) {
			syslog(LOG_ERR, "unable to chroot: %m");
			return -1;
		}
	}

	/* Drop the permissions */
	if(setgid(nsd->gid) != 0 || setuid(nsd->uid) !=0) {
		syslog(LOG_ERR, "unable to drop user priviledges: %m");
		return -1;
	}

	/* Open the database... */
	if((nsd->db = namedb_open(nsd->dbfile)) == NULL) {
		syslog(LOG_ERR, "unable to load %s: %m", nsd->dbfile);
		return -1;
	}

#ifdef	BIND8_STATS
	/* Initialize times... */
	time(&nsd->st.boot);
	alarm(nsd->st.period);
#endif /* BIND8_STATS */

	return 0;
}

/*
 * Fork the required number of servers.
 */
int
server_start_tcp(struct nsd *nsd)
{
	int i;

	/* Start all child servers initially.  */
	for (i = 1; i <= nsd->tcp_open_conn; ++i) {
		nsd->pid[i] = 0;
	}

	return restart_tcp_child_servers(nsd);
}

static void
close_all_sockets(struct nsd_socket sockets[], size_t n)
{
	size_t i;

	/* Close all the sockets... */
	for (i = 0; i < n; ++i) {
		if (sockets[i].s != -1) {
			close(sockets[i].s);
			sockets[i].s = -1;
		}
	}
}

/*
 * Close the sockets, shutdown the server and exit.
 * Does not return.
 *
 */
void
server_shutdown(struct nsd *nsd)
{
#ifdef	BIND8_STATS
	bind8_stats(nsd);
#endif /* BIND8_STATS */

	close_all_sockets(nsd->udp, nsd->ifs);
	close_all_sockets(nsd->tcp, nsd->ifs);

	exit(0);
}

/*
 *
 * Serve udp requests. Main server.
 *
 */
void
server_udp(struct nsd *nsd)
{
	fd_set peer;
	int received, sent, maxfd, s, i;
	struct query q;

	/* The main loop... */	
	while(nsd->mode != NSD_SHUTDOWN) {
		/* Do we need to reload the database? */
		switch(nsd->mode) {
		case NSD_QUIT:
			server_shutdown(nsd);
			/* NOTREACH */
			break;
		case NSD_STATS:
			nsd->mode = NSD_RUN;

#ifdef BIND8_STATS
			/* Dump the statistics */
			bind8_stats(nsd);

#else /* BIND8_STATS */
			syslog(LOG_NOTICE, "No statistics available, recompile with -DBIND8_STATS");
#endif /* BIND8_STATS */
			break;
		case NSD_RELOAD:
			nsd->mode = NSD_RUN;

			switch(fork()) {
			case -1:
				syslog(LOG_ERR, "fork failed: %m");
				break;
			case 0:
				/* CHILD */

				namedb_close(nsd->db);
				if((nsd->db = namedb_open(nsd->dbfile)) == NULL) {
					syslog(LOG_ERR, "unable to reload the database: %m");
					exit(1);
				}

				/* Send the child SIGINT to the parent to terminate quitely... */
				if(kill(nsd->pid[0], SIGINT) != 0) {
					syslog(LOG_ERR, "cannot kill %d: %m", nsd->pid[0]);
					exit(1);
				}

				nsd->pid[0]  = getpid();

				/* Refork the tcp servers... */
				server_start_tcp(nsd);

				/* Overwrite pid... */
				if(writepid(nsd) == -1) {
					syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd->pidfile);
				}

				break;
			default:
				/* PARENT */
				break;
			}
			break;
		default:
			break;
		}

		/* Restart any TCP child processes that may have died.  */
		restart_tcp_child_servers(nsd);
		
		/* Set it up */
		FD_ZERO(&peer);

		maxfd = nsd->udp[0].s;

		for(i = 0; i < nsd->ifs; i++) {
			FD_SET(nsd->udp[i].s, &peer);
			maxfd = nsd->udp[i].s;
		}

		/* Wait for a query... */
		if(select(maxfd + 1, &peer, NULL, NULL, NULL) == -1) {
			if(errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}

		/* Process it... */
		s = -1;
		for(i = 0; i < nsd->ifs; i++) {
			if(FD_ISSET(nsd->udp[i].s, &peer)) {
				s = nsd->udp[i].s;
				if (nsd->udp[i].addr->ai_family == AF_INET)
				{
					/* Account... */
					STATUP(nsd, qudp);
				} else if (nsd->udp[i].addr->ai_family == AF_INET6) {
					/* Account... */
					STATUP(nsd, qudp6);
				}
				break;
			}
		}

		if(s == -1) {
			syslog(LOG_ERR, "selected non-existant socket");
			continue;
		}

		/* Initialize the query... */
		query_init(&q);

		if((received = recvfrom(s, q.iobuf, q.iobufsz, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
			syslog(LOG_ERR, "recvfrom failed: %m");
			STATUP(nsd, rxerr);
			continue;
		}
		q.iobufptr = q.iobuf + received;
		q.tcp = 0;

		/* Process and answer the query... */
		if(query_process(&q, nsd) != -1) {
			if(RCODE((&q)) == RCODE_OK && !AA((&q)))
				STATUP(nsd, nona);
			/* Add edns(0) info if necessary.. */
			query_addedns(&q, nsd);

			if((sent = sendto(s, q.iobuf, q.iobufptr - q.iobuf, 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
				syslog(LOG_ERR, "sendto failed: %m");
				STATUP(nsd, txerr);
				continue;
			} else if(sent != q.iobufptr - q.iobuf) {
				syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr - q.iobuf);
				continue;
			}

#ifdef BIND8_STATS
			/* Account the rcode & TC... */
			STATUP2(nsd, rcode, RCODE((&q)));
			if(TC((&q)))
			STATUP(nsd, truncated);
#endif /* BIND8_STATS */
		} else {
			STATUP(nsd, dropped);
		}

	}

	/* Truncate the pid file... Reuse s... */
	if((s = open(nsd->pidfile, O_WRONLY | O_TRUNC, 0644)) == -1) {
		syslog(LOG_ERR, "can not truncate the pid file %s: %m", nsd->pidfile);
	}
	close(s);

	/* Unlink it if possible... */
	(void)unlink(nsd->pidfile);

	server_shutdown(nsd);

	exit(0);
}
/*
 *
 * Serve tcp requests. Simplified server.
 *
 */
void
server_tcp(struct nsd *nsd)
{
	fd_set peer;
	int received, sent, axfr, maxfd, s, i;
	u_int16_t tcplen;
	struct query q;

	close_all_sockets(nsd->udp, nsd->ifs);
	
	/* Allow sigalarm to get us out of the loop */
	siginterrupt(SIGALRM, 1);
	siginterrupt(SIGINT, 1);	/* These two are to avoid hanging tcp connections... */
	siginterrupt(SIGTERM, 1);	/* ...on server restart. */

	/* The main loop... */	
	while(nsd->mode != NSD_QUIT) {
		/* Dont time out now... */
		alarm(0);

		/* Do we need to do the statistics... */
		if(nsd->mode == NSD_STATS) {
			nsd->mode = NSD_RUN;

#ifdef BIND8_STATS
			/* Dump the statistics */
			bind8_stats(nsd);

#else /* BIND8_STATS */
			syslog(LOG_NOTICE, "No statistics available, recompile with -DBIND8_STATS");
#endif /* BIND8_STATS */
		}

		/* Set it up */
		FD_ZERO(&peer);

		maxfd = nsd->tcp[0].s;

		for(i = 0; i < nsd->ifs; i++) {
			FD_SET(nsd->tcp[i].s, &peer);
			maxfd = nsd->tcp[i].s;
		}

		/* Break from select() to dump statistics... */
		siginterrupt(SIGILL, 1);
		/* Wait for a query... */
		if(select(maxfd + 1, &peer, NULL, NULL, NULL) == -1) {
			if(errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}

		/* Wait for transaction completion before dumping stats... */
		siginterrupt(SIGILL, 0);

		s = -1;
		for(i = 0; i < nsd->ifs; i++) {
			if(FD_ISSET(nsd->tcp[i].s, &peer)) {
				s = nsd->tcp[i].s;
				break;
			}
		}

		if(s == -1) {
			syslog(LOG_ERR, "selected non-existant socket");
			continue;
		}

		/* Account... */
		STATUP(nsd, ctcp);

		/* Accept it... */
		q.addrlen = sizeof(q.addr);
		if((s = accept(s, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
			if(errno != EINTR) {
				syslog(LOG_ERR, "accept failed: %m");
			}
			continue;
		}

		/* Initialize the query... */
		query_init(&q);

		q.maxlen = (q.iobufsz > nsd->tcp_max_msglen) ? nsd->tcp_max_msglen : q.iobufsz;
		q.tcp = 1;

		/* Until we've got end of file */
		alarm(TCP_TIMEOUT);
		while((received = read(s, &tcplen, 2)) == 2) {
			/* XXX Why 17???? */
			if(ntohs(tcplen) < 17) {
				syslog(LOG_WARNING, "dropping bogus tcp connection");
				break;
			}

			if(ntohs(tcplen) > q.iobufsz) {
				syslog(LOG_ERR, "insufficient tcp buffer, dropping connection");
				break;
			}

			if((received = read(s, q.iobuf, ntohs(tcplen))) == -1) {
				if(errno == EINTR)
					syslog(LOG_ERR, "timed out/interrupted reading tcp connection");
				else
					syslog(LOG_ERR, "failed reading tcp connection: %m");
				break;
			}

			if(received == 0) {
				syslog(LOG_WARNING, "remote end closed connection");
				break;
			}

			if(received != ntohs(tcplen)) {
				syslog(LOG_WARNING, "couldnt read entire tcp message, dropping connection");
				break;
			}

			q.iobufptr = q.iobuf + received;

			alarm(0);

			if((axfr = query_process(&q, nsd)) != -1) {
				if(RCODE((&q)) == RCODE_OK && !AA((&q)))
					STATUP(nsd, nona);
				do {
					query_addedns(&q, nsd);

					alarm(TCP_TIMEOUT);
					tcplen = htons(q.iobufptr - q.iobuf);
					if(((sent = write(s, &tcplen, 2)) == -1) ||
						((sent = write(s, q.iobuf, q.iobufptr - q.iobuf)) == -1)) {
						if(errno == EINTR)
							syslog(LOG_ERR, "timed out/interrupted writing");
						else
							syslog(LOG_ERR, "write failed: %s", strerror(errno));
							break;
					}
					if(sent != q.iobufptr - q.iobuf) {
						syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr
							- q.iobuf);
						break;
					}

					/* Do we have AXFR in progress? */
					if(axfr) {
						axfr = query_axfr(&q, nsd, NULL, NULL, 0);
					}
				} while(axfr);
			} else {
				/* Drop the entire connection... */
				break;
			}
		}

		/* Connection closed */
		if(received == -1) {
			if(errno == EINTR)
				syslog(LOG_ERR, "timed out/interrupted reading tcp connection");
			else
				syslog(LOG_ERR, "failed reading tcp connection: %m");
		}

		close(s);
	} /* while(nsd->mode != ... */

	server_shutdown(nsd);	/* Shouldn't truncate pid */

	/* NOTREACH */
}
