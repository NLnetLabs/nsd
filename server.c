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
#include <sys/wait.h>

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
#include "plugins.h"
#include <query.h>


/*
 * Remove the specified pid from the list of child pids.  Returns 0 if
 * the pid is not in the list, 1 otherwise.  The field is set to 0.
 */
static int
delete_child_pid(struct nsd *nsd, pid_t pid)
{
	size_t i;
	for (i = 0; i < nsd->child_count; ++i) {
		if (nsd->children[i].pid == pid) {
			nsd->children[i].pid = 0;
			return 1;
		}
	}
	return 0;
}

/*
 * Restart child servers if necessary.
 */
static int
restart_child_servers(struct nsd *nsd)
{
	size_t i;

	/* Fork the child processes... */
	for (i = 0; i < nsd->child_count; ++i) {
		if (nsd->children[i].pid == 0) {
			nsd->children[i].pid = fork();
			switch (nsd->children[i].pid) {
			case 0: /* CHILD */
				nsd->pid = 0;
				nsd->child_count = 0;
				nsd->server_kind = nsd->children[i].kind;
				server_child(nsd);
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
	size_t i;
#if defined(SO_REUSEADDR) || (defined(INET6) && defined(IPV6_V6ONLY))
	int on = 1;
#endif

	/* UDP */

	/* Make a socket... */
	for(i = 0; i < nsd->ifs; i++) {
		if((nsd->udp[i].s = socket(nsd->udp[i].addr->ai_family, nsd->udp[i].addr->ai_socktype, 0)) == -1) {
			syslog(LOG_ERR, "can't create a socket: %m");
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
			syslog(LOG_ERR, "can't bind the socket: %m");
			return -1;
		}
	}

	/* TCP */

	/* Make a socket... */
	for(i = 0; i < nsd->ifs; i++) {
		if((nsd->tcp[i].s = socket(nsd->tcp[i].addr->ai_family, nsd->tcp[i].addr->ai_socktype, 0)) == -1) {
			syslog(LOG_ERR, "can't create a socket: %m");
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
			syslog(LOG_ERR, "can't bind the socket: %m");
			return -1;
		}

		/* Listen to it... */
		if(listen(nsd->tcp[i].s, TCP_BACKLOG) == -1) {
			syslog(LOG_ERR, "can't listen: %m");
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
static int
server_start_children(struct nsd *nsd)
{
	size_t i;

	/* Start all child servers initially.  */
	for (i = 0; i < nsd->child_count; ++i) {
		nsd->children[i].pid = 0;
	}

	return restart_child_servers(nsd);
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
static void
server_shutdown(struct nsd *nsd)
{
	close_all_sockets(nsd->udp, nsd->ifs);
	close_all_sockets(nsd->tcp, nsd->ifs);

	exit(0);
}

/*
 * The main server simply waits for signals and child processes to
 * terminate.  Child processes are restarted as necessary.
 */
void
server_main(struct nsd *nsd)
{
	int fd;
	int status;
	pid_t child;
	
	assert(nsd->server_kind == NSD_SERVER_MAIN);

	if (server_start_children(nsd) != 0) {
		kill(nsd->pid, SIGTERM);
		exit(1);
	}

	while (nsd->mode != NSD_SHUTDOWN) {
		switch (nsd->mode) {
		case NSD_RUN:
			child = waitpid(0, &status, 0);
		
			if (child == -1) {
				if (errno == EINTR) {
					continue;
				}
				syslog(LOG_WARNING, "wait failed: %m");
			} else {
				int is_child = delete_child_pid(nsd, child);
				if (is_child) {
					syslog(LOG_WARNING,
					       "server %d died unexpectedly with status %d, restarting",
					       (int) child, status);
					restart_child_servers(nsd);
				} else {
					syslog(LOG_WARNING,
					       "Reload process %d failed with status %d, continuing with old database",
					       (int) child, status);
				}
			}
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

#ifdef PLUGINS
				if (plugin_database_reloaded() != NSD_PLUGIN_CONTINUE) {
					syslog(LOG_ERR, "plugin reload failed");
					exit(1);
				}
#endif /* PLUGINS */

				/* Send the child SIGINT to the parent to terminate quitely... */
				if (kill(nsd->pid, SIGINT) != 0) {
					syslog(LOG_ERR, "cannot kill %d: %m", nsd->pid);
					exit(1);
				}

				nsd->pid = getpid();

				/* Refork the servers... */
				server_start_children(nsd);

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
		case NSD_QUIT:
			server_shutdown(nsd);
			break;
		case NSD_SHUTDOWN:
			break;
		default:
			syslog(LOG_WARNING, "NSD main server mode invalid: %d", nsd->mode);
			nsd->mode = NSD_RUN;
		}
	}

#ifdef PLUGINS
	plugin_finalize_all();
#endif /* PLUGINS */
	
	/* Truncate the pid file.  */
	if((fd = open(nsd->pidfile, O_WRONLY | O_TRUNC, 0644)) == -1) {
		syslog(LOG_ERR, "can not truncate the pid file %s: %m", nsd->pidfile);
	}
	close(fd);

	/* Unlink it if possible... */
	unlink(nsd->pidfile);

	server_shutdown(nsd);
}

static int
process_query(struct nsd *nsd, struct query *query)
{
#ifdef PLUGINS
	int rc;
	nsd_plugin_callback_args_type callback_args;
	nsd_plugin_callback_result_type callback_result;
	
	callback_args.query = query;
	callback_args.domain_name = NULL;
	callback_args.data = NULL;
	callback_args.result_code = RCODE_OK;

	callback_result = query_received_callbacks(&callback_args, NULL);
	if (callback_result != NSD_PLUGIN_CONTINUE) {
		return handle_callback_result(callback_result, &callback_args);
	}

	rc = query_process(query, nsd);
	if (rc == 0) {
		callback_args.domain_name = query->normalized_domain_name;
		callback_args.data = NULL;
		callback_args.result_code = RCODE_OK;

		callback_result = query_processed_callbacks(
			&callback_args, query->plugin_data);
		if (callback_result != NSD_PLUGIN_CONTINUE) {
			return handle_callback_result(callback_result, &callback_args);
		}
	}
	return rc;
#else /* !PLUGINS */
	return query_process(query, nsd);
#endif /* !PLUGINS */
}

static int
handle_udp(struct nsd *nsd, fd_set *peer)
{
	int received, sent, s;
	struct query q;
	size_t i;
	
	/* Process it... */
	s = -1;
	for (i = 0; i < nsd->ifs; i++) {
		if (FD_ISSET(nsd->udp[i].s, peer)) {
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

	if (s == -1) {
		return 0;
	}

	/* Initialize the query... */
	query_init(&q);

	if ((received = recvfrom(s, q.iobuf, q.iobufsz, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		syslog(LOG_ERR, "recvfrom failed: %m");
		STATUP(nsd, rxerr);
		return 1;
	}
	q.iobufptr = q.iobuf + received;
	q.tcp = 0;

	/* Process and answer the query... */
	if (process_query(nsd, &q) != -1) {
		if (RCODE((&q)) == RCODE_OK && !AA((&q)))
			STATUP(nsd, nona);
		/* Add edns(0) info if necessary.. */
		query_addedns(&q, nsd);

		if ((sent = sendto(s, q.iobuf, q.iobufptr - q.iobuf, 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
			syslog(LOG_ERR, "sendto failed: %m");
			STATUP(nsd, txerr);
			return 1;
		} else if (sent != q.iobufptr - q.iobuf) {
			syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr - q.iobuf);
			return 1;
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
	return 1;
}

static int
handle_tcp(struct nsd *nsd, fd_set *peer)
{
	int received, sent, axfr, s;
	u_int16_t tcplen;
	struct query q;
	size_t i;
	
	s = -1;
	for (i = 0; i < nsd->ifs; i++) {
		if(FD_ISSET(nsd->tcp[i].s, peer)) {
			s = nsd->tcp[i].s;
			break;
		}
	}

	if (s == -1) {
		syslog(LOG_ERR, "selected non-existant socket");
		return 0;
	}

	/* Account... */
	STATUP(nsd, ctcp);

	/* Accept it... */
	q.addrlen = sizeof(q.addr);
	if ((s = accept(s, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		if (errno != EINTR) {
			syslog(LOG_ERR, "accept failed: %m");
		}
		return 1;
	}

	/* Initialize the query... */
	query_init(&q);

	q.maxlen = (q.iobufsz > nsd->tcp_max_msglen) ? nsd->tcp_max_msglen : q.iobufsz;
	q.tcp = 1;

	/* Until we've got end of file */
	alarm(TCP_TIMEOUT);
	while ((received = read(s, &tcplen, 2)) == 2) {
		/* XXX Why 17???? */
		if (ntohs(tcplen) < 17) {
			syslog(LOG_WARNING, "dropping bogus tcp connection");
			break;
		}

		if (ntohs(tcplen) > q.iobufsz) {
			syslog(LOG_ERR, "insufficient tcp buffer, dropping connection");
			break;
		}

		if ((received = read(s, q.iobuf, ntohs(tcplen))) == -1) {
			if(errno == EINTR)
				syslog(LOG_ERR, "timed out/interrupted reading tcp connection");
			else
				syslog(LOG_ERR, "failed reading tcp connection: %m");
			break;
		}

		if (received == 0) {
			syslog(LOG_WARNING, "remote end closed connection");
			break;
		}

		if (received != ntohs(tcplen)) {
			syslog(LOG_WARNING, "couldnt read entire tcp message, dropping connection");
			break;
		}

		q.iobufptr = q.iobuf + received;

		alarm(0);

		if ((axfr = process_query(nsd, &q)) != -1) {
			if (RCODE((&q)) == RCODE_OK && !AA((&q)))
				STATUP(nsd, nona);
			do {
				query_addedns(&q, nsd);

				alarm(TCP_TIMEOUT);
				tcplen = htons(q.iobufptr - q.iobuf);
				if (((sent = write(s, &tcplen, 2)) == -1) ||
				    ((sent = write(s, q.iobuf, q.iobufptr - q.iobuf)) == -1)) {
					if (errno == EINTR)
						syslog(LOG_ERR, "timed out/interrupted writing");
					else
						syslog(LOG_ERR, "write failed: %s", strerror(errno));
					break;
				}
				if (sent != q.iobufptr - q.iobuf) {
					syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr
					       - q.iobuf);
					break;
				}

				/* Do we have AXFR in progress? */
				if (axfr) {
					axfr = query_axfr(&q, nsd, NULL, NULL, 0);
				}
			} while(axfr);
		} else {
			/* Drop the entire connection... */
			break;
		}
	}

	alarm(0);
	
	/* Connection closed */
	if (received == -1) {
		if(errno == EINTR)
			syslog(LOG_ERR, "timed out/interrupted reading tcp connection");
		else
			syslog(LOG_ERR, "failed reading tcp connection: %m");
	}

	close(s);
	return 1;
}


/*
 * Serve DNS requests.
 */
void
server_child(struct nsd *nsd)
{
	fd_set peer;
	int maxfd;
	size_t i;
	sigset_t block_sigill;

	assert(nsd->server_kind != NSD_SERVER_MAIN);
	
	sigemptyset(&block_sigill);
	sigaddset(&block_sigill, SIGILL);

	if (!(nsd->server_kind & NSD_SERVER_TCP)) {
		close_all_sockets(nsd->tcp, nsd->ifs);
	}
	if (!(nsd->server_kind & NSD_SERVER_UDP)) {
		close_all_sockets(nsd->udp, nsd->ifs);
	}
	
	/* Allow sigalarm to get us out of the loop */
	siginterrupt(SIGALRM, 1);
	siginterrupt(SIGINT, 1);	/* These two are to avoid hanging tcp connections... */
	siginterrupt(SIGTERM, 1);	/* ...on server restart. */

	/* The main loop... */	
	while (nsd->mode != NSD_QUIT) {

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

		maxfd = nsd->udp[0].s;

		if (nsd->server_kind & NSD_SERVER_UDP) {
			for (i = 0; i < nsd->ifs; i++) {
				FD_SET(nsd->udp[i].s, &peer);
				maxfd = nsd->udp[i].s;
			}
		}
		if (nsd->server_kind & NSD_SERVER_TCP) {
			for (i = 0; i < nsd->ifs; i++) {
				FD_SET(nsd->tcp[i].s, &peer);
				maxfd = nsd->tcp[i].s;
			}
		}
		
		/* Break from select() to dump statistics... */
		sigprocmask(SIG_UNBLOCK, &block_sigill, NULL);
		
		/* Wait for a query... */
		if (select(maxfd + 1, &peer, NULL, NULL, NULL) == -1) {
			if (errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}

		/* Wait for transaction completion before dumping stats... */
		sigprocmask(SIG_BLOCK, &block_sigill, NULL);

		if ((nsd->server_kind & NSD_SERVER_UDP) &&
		    handle_udp(nsd, &peer))
			continue;
		
		if ((nsd->server_kind & NSD_SERVER_TCP) &&
		    handle_tcp(nsd, &peer))
			continue;

		syslog(LOG_ERR, "selected non-existant socket");
	}

#ifdef	BIND8_STATS
	bind8_stats(nsd);
#endif /* BIND8_STATS */

	server_shutdown(nsd);
}
