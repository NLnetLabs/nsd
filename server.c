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
#include <time.h>
#include <unistd.h>
#include <netdb.h>

#include "axfr.h"
#include "dns.h"
#include "namedb.h"
#include "dname.h"
#include "nsd.h"
#include "plugins.h"
#include "query.h"
#include "region-allocator.h"
#include "util.h"

#ifndef HAVE_PSELECT
int pselect(int n, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
	    const struct timespec *timeout, const sigset_t *sigmask);
#endif


static uint16_t *compressed_dname_offsets;

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
		if (nsd->children[i].pid <= 0) {
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
				log_msg(LOG_ERR, "fork failed: %s",
					strerror(errno));
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
	for (i = 0; i < nsd->ifs; i++) {
		if ((nsd->udp[i].s = socket(nsd->udp[i].addr->ai_family, nsd->udp[i].addr->ai_socktype, 0)) == -1) {
			log_msg(LOG_ERR, "can't create a socket: %s", strerror(errno));
			return -1;
		}

#if defined(INET6) && defined(IPV6_V6ONLY)
		if (nsd->udp[i].addr->ai_family == AF_INET6 &&
		    setsockopt(nsd->udp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
		{
			log_msg(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %s",
				strerror(errno));
			return -1;
		}
#endif

		/* Bind it... */
		if (bind(nsd->udp[i].s, (struct sockaddr *) nsd->udp[i].addr->ai_addr, nsd->udp[i].addr->ai_addrlen) != 0) {
			log_msg(LOG_ERR, "can't bind the socket: %s", strerror(errno));
			return -1;
		}
	}

	/* TCP */

	/* Make a socket... */
	for (i = 0; i < nsd->ifs; i++) {
		if ((nsd->tcp[i].s = socket(nsd->tcp[i].addr->ai_family, nsd->tcp[i].addr->ai_socktype, 0)) == -1) {
			log_msg(LOG_ERR, "can't create a socket: %s", strerror(errno));
			return -1;
		}

#ifdef	SO_REUSEADDR
		if (setsockopt(nsd->tcp[i].s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			log_msg(LOG_ERR, "setsockopt(..., SO_REUSEADDR, ...) failed: %s", strerror(errno));
			return -1;
		}
#endif /* SO_REUSEADDR */

#if defined(INET6) && defined(IPV6_V6ONLY)
		if (nsd->tcp[i].addr->ai_family == AF_INET6 &&
		    setsockopt(nsd->tcp[i].s, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)) < 0)
		{
			log_msg(LOG_ERR, "setsockopt(..., IPV6_V6ONLY, ...) failed: %s", strerror(errno));
			return -1;
		}
#endif

		/* Bind it... */
		if (bind(nsd->tcp[i].s, (struct sockaddr *) nsd->tcp[i].addr->ai_addr, nsd->tcp[i].addr->ai_addrlen) != 0) {
			log_msg(LOG_ERR, "can't bind the socket: %s", strerror(errno));
			return -1;
		}

		/* Listen to it... */
		if (listen(nsd->tcp[i].s, TCP_BACKLOG) == -1) {
			log_msg(LOG_ERR, "can't listen: %s", strerror(errno));
			return -1;
		}
	}

#ifdef HAVE_CHROOT
	/* Chroot */
	if (nsd->chrootdir) {
		int l = strlen(nsd->chrootdir);

		nsd->dbfile += l;
		nsd->pidfile += l;

		if (chroot(nsd->chrootdir)) {
			log_msg(LOG_ERR, "unable to chroot: %s", strerror(errno));
			return -1;
		}
	}
#endif

	/* Drop the permissions */
	if (setgid(nsd->gid) != 0 || setuid(nsd->uid) !=0) {
		log_msg(LOG_ERR, "unable to drop user priviledges: %s", strerror(errno));
		return -1;
	}

	/* Open the database... */
	if ((nsd->db = namedb_open(nsd->dbfile)) == NULL) {
		log_msg(LOG_ERR, "unable to load %s: %s", nsd->dbfile, strerror(errno));
		return -1;
	}

	compressed_dname_offsets = xalloc(
		(domain_table_count(nsd->db->domains) + 1) * sizeof(uint16_t));
	memset(compressed_dname_offsets, 0,
	       (domain_table_count(nsd->db->domains) + 1) * sizeof(uint16_t));
	region_add_cleanup(nsd->db->region, free, compressed_dname_offsets);
	
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
	pid_t child_pid;
	pid_t reload_pid = -1;
	
	assert(nsd->server_kind == NSD_SERVER_MAIN);

	if (server_start_children(nsd) != 0) {
		kill(nsd->pid, SIGTERM);
		exit(1);
	}

	while (nsd->mode != NSD_SHUTDOWN) {
		switch (nsd->mode) {
		case NSD_RUN:
			child_pid = waitpid(0, &status, 0);
		
			if (child_pid == -1) {
				if (errno == EINTR) {
					continue;
				}
				log_msg(LOG_WARNING, "wait failed: %s", strerror(errno));
			} else {
				int is_child = delete_child_pid(nsd, child_pid);
				if (is_child) {
					log_msg(LOG_WARNING,
					       "server %d died unexpectedly with status %d, restarting",
					       (int) child_pid, status);
					restart_child_servers(nsd);
				} else if (child_pid == reload_pid) {
					log_msg(LOG_WARNING,
					       "Reload process %d failed with status %d, continuing with old database",
					       (int) child_pid, status);
					reload_pid = -1;
				} else {
					log_msg(LOG_WARNING,
					       "Unknown child %d terminated with status %d",
					       (int) child_pid, status);
				}
			}
			break;
		case NSD_RELOAD:
			nsd->mode = NSD_RUN;

			if (reload_pid != -1) {
				log_msg(LOG_WARNING, "Reload already in progress (pid = %d)",
				       (int) reload_pid);
				break;
			}

			reload_pid = fork();
			switch (reload_pid) {
			case -1:
				log_msg(LOG_ERR, "fork failed: %s", strerror(errno));
				break;
			case 0:
				/* CHILD */

				namedb_close(nsd->db);
				if ((nsd->db = namedb_open(nsd->dbfile)) == NULL) {
					log_msg(LOG_ERR, "unable to reload the database: %s", strerror(errno));
					exit(1);
				}

#ifdef PLUGINS
				if (plugin_database_reloaded() != NSD_PLUGIN_CONTINUE) {
					log_msg(LOG_ERR, "plugin reload failed");
					exit(1);
				}
#endif /* PLUGINS */

				/* Send SIGINT to terminate the parent quitely... */
				if (kill(nsd->pid, SIGINT) != 0) {
					log_msg(LOG_ERR, "cannot kill %d: %s",
						(int) nsd->pid, strerror(errno));
					exit(1);
				}

				nsd->pid = getpid();
				reload_pid = -1;

				/* Refork the servers... */
				server_start_children(nsd);

				/* Overwrite pid... */
				if (writepid(nsd) == -1) {
					log_msg(LOG_ERR, "cannot overwrite the pidfile %s: %s", nsd->pidfile, strerror(errno));
				}

#ifdef BIND8_STATS
				/* Restart dumping stats if required.  */
				alarm(nsd->st.period);
#endif
				
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
			log_msg(LOG_WARNING, "NSD main server mode invalid: %d", nsd->mode);
			nsd->mode = NSD_RUN;
			break;
		}
	}

#ifdef PLUGINS
	plugin_finalize_all();
#endif /* PLUGINS */
	
	/* Truncate the pid file.  */
	if ((fd = open(nsd->pidfile, O_WRONLY | O_TRUNC, 0644)) == -1) {
		log_msg(LOG_ERR, "can not truncate the pid file %s: %s", nsd->pidfile, strerror(errno));
	}
	close(fd);

	/* Unlink it if possible... */
	unlink(nsd->pidfile);

	server_shutdown(nsd);
}

static query_state_type
process_query(struct nsd *nsd, struct query *query)
{
#ifdef PLUGINS
	query_state_type rc;
	nsd_plugin_callback_args_type callback_args;
	nsd_plugin_callback_result_type callback_result;
	
	callback_args.query = query;
	callback_args.data = NULL;
	callback_args.result_code = RCODE_OK;

	callback_result = query_received_callbacks(&callback_args, NULL);
	if (callback_result != NSD_PLUGIN_CONTINUE) {
		return handle_callback_result(callback_result, &callback_args);
	}

	rc = query_process(query, nsd);
	if (rc == QUERY_PROCESSED) {
		callback_args.data = NULL;
		callback_args.result_code = RCODE_OK;

		callback_result = query_processed_callbacks(
			&callback_args,
			query->domain->plugin_data);
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
handle_udp(region_type *query_region, struct nsd *nsd, fd_set *peer)
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
	q.region = query_region;
	q.compressed_dname_offsets = compressed_dname_offsets;
	
	if ((received = recvfrom(s, q.iobuf, QIOBUFSZ, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		if (errno != EAGAIN) {
			log_msg(LOG_ERR, "recvfrom failed: %s", strerror(errno));
			STATUP(nsd, rxerr);
		}
		return 1;
	}
	q.iobufptr = q.iobuf + received;
	q.tcp = 0;

	/* Process and answer the query... */
	if (process_query(nsd, &q) != QUERY_DISCARDED) {
		if (RCODE((&q)) == RCODE_OK && !AA((&q)))
			STATUP(nsd, nona);
		/* Add edns(0) info if necessary.. */
		query_addedns(&q, nsd);

		if ((sent = sendto(s, q.iobuf, query_used_size(&q), 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
			log_msg(LOG_ERR, "sendto failed: %s", strerror(errno));
			STATUP(nsd, txerr);
			return 1;
		} else if (sent != q.iobufptr - q.iobuf) {
			log_msg(LOG_ERR, "sent %d in place of %d bytes", sent, (int) query_used_size(&q));
			return 1;
		}

#ifdef BIND8_STATS
		/* Account the rcode & TC... */
		STATUP2(nsd, rcode, RCODE((&q)));
		if (TC((&q)))
			STATUP(nsd, truncated);
#endif /* BIND8_STATS */
	} else {
		STATUP(nsd, dropped);
	}
	return 1;
}

/*
 * Read COUNT bytes from S and store in BUF.  If a single read(2)
 * returns fewer than COUNT bytes keep reading until COUNT bytes are
 * received or the socket is closed.
 *
 * Also returns early an error or signal occurs.  In this case -1 is
 * returned and it is impossible to determine how many bytes have
 * actually been read.
 */
static ssize_t
read_socket(int s, void *buf, size_t count)
{
	ssize_t actual = 0;
	
	while (actual < (ssize_t) count) {
		ssize_t result = read(s, (char *) buf + actual, count - actual);
		if (result == -1) {
			return -1;
		} else if (result == 0) {
			return actual;
		} else {
			actual += result;
		}
	}

	return (ssize_t) actual;
}

static int
handle_tcp(region_type *query_region, struct nsd *nsd, fd_set *peer)
{
	int received, sent, s;
	uint16_t tcplen;
	struct query q;
	size_t i;
	query_state_type query_state;
	
	s = -1;
	for (i = 0; i < nsd->ifs; i++) {
		if (FD_ISSET(nsd->tcp[i].s, peer)) {
			s = nsd->tcp[i].s;
			break;
		}
	}

	if (s == -1) {
		log_msg(LOG_ERR, "selected non-existant socket");
		return 0;
	}

	/* Account... */
	STATUP(nsd, ctcp);

	/* Accept it... */
	q.addrlen = sizeof(q.addr);
	if ((s = accept(s, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		if (errno != EINTR) {
			log_msg(LOG_ERR, "accept failed: %s", strerror(errno));
		}
		return 1;
	}

	/* Initialize the query... */
	query_init(&q);
	q.region = query_region;
	q.compressed_dname_offsets = compressed_dname_offsets;
	q.maxlen = QIOBUFSZ < nsd->tcp_max_msglen ? QIOBUFSZ : nsd->tcp_max_msglen;
	q.tcp = 1;

	/* Until we've got end of file */
	alarm(TCP_TIMEOUT);
	while ((received = read_socket(s, &tcplen, 2)) == 2) {
		/*
		 * Minimum query size is:
		 *
		 *     Size of the header (12)
		 *   + Root domain name   (1)
		 *   + Query class        (2)
		 *   + Query type         (2)
		 */
		if (ntohs(tcplen) < QHEADERSZ + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
			log_msg(LOG_WARNING, "dropping bogus tcp connection");
			break;
		}

		if (ntohs(tcplen) > QIOBUFSZ) {
			log_msg(LOG_ERR, "insufficient tcp buffer, dropping connection");
			break;
		}

		if ((received = read_socket(s, q.iobuf, ntohs(tcplen))) == -1) {
			if (errno == EINTR)
				log_msg(LOG_ERR, "timed out/interrupted reading tcp connection");
			else
				log_msg(LOG_ERR, "failed reading tcp connection: %s", strerror(errno));
			break;
		}

		if (received == 0) {
			log_msg(LOG_WARNING, "remote end closed connection");
			break;
		}

		if (received != ntohs(tcplen)) {
			log_msg(LOG_WARNING, "couldnt read entire tcp message, dropping connection");
			break;
		}

		q.iobufptr = q.iobuf + received;

		alarm(0);

		query_state = process_query(nsd, &q);
		if (query_state != QUERY_DISCARDED) {
			if (RCODE((&q)) == RCODE_OK && !AA((&q)))
				STATUP(nsd, nona);
			do {
				query_addedns(&q, nsd);

				alarm(TCP_TIMEOUT);
				tcplen = htons(q.iobufptr - q.iobuf);
				if (((sent = write(s, &tcplen, 2)) == -1) ||
				    ((sent = write(s, q.iobuf, query_used_size(&q))) == -1)) {
					if (errno == EINTR)
						log_msg(LOG_ERR, "timed out/interrupted writing");
					else
						log_msg(LOG_ERR, "write failed: %s", strerror(errno));
					break;
				}
				if (sent != q.iobufptr - q.iobuf) {
					log_msg(LOG_ERR, "sent %d in place of %d bytes",
					       sent, (int) query_used_size(&q));
					break;
				}

				/* Do we have AXFR in progress? */
				if (query_state == QUERY_IN_AXFR) {
					query_state = query_axfr(nsd, &q);
				}
			} while (query_state != QUERY_PROCESSED);
		} else {
			/* Drop the entire connection... */
			break;
		}
	}

	alarm(0);
	
	/* Connection closed */
	if (received == -1) {
		if (errno == EINTR)
			log_msg(LOG_ERR, "timed out/interrupted reading tcp connection");
		else
			log_msg(LOG_ERR, "failed reading tcp connection: %s", strerror(errno));
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
	sigset_t block_sigmask;
	sigset_t default_sigmask;
	region_type *query_region = region_create(xalloc, free);
	
	assert(nsd->server_kind != NSD_SERVER_MAIN);
	
	if (!(nsd->server_kind & NSD_SERVER_TCP)) {
		close_all_sockets(nsd->tcp, nsd->ifs);
	}
	if (!(nsd->server_kind & NSD_SERVER_UDP)) {
		close_all_sockets(nsd->udp, nsd->ifs);
	}
	
	/* Allow sigalarm to get us out of the loop */
	siginterrupt(SIGALRM, 1);

	/*
	 * Block signals that modify nsd->mode, which must be tested
	 * for atomically.  These signals are only unblocked while
	 * waiting in pselect below.
	 */
	sigemptyset(&block_sigmask);
	sigaddset(&block_sigmask, SIGHUP);
	sigaddset(&block_sigmask, SIGILL);
	sigaddset(&block_sigmask, SIGINT);
	sigaddset(&block_sigmask, SIGTERM);
	sigprocmask(SIG_BLOCK, &block_sigmask, &default_sigmask);
	
	/* The main loop... */	
	while (nsd->mode != NSD_QUIT) {

		/* Do we need to do the statistics... */
		if (nsd->mode == NSD_STATS) {
			nsd->mode = NSD_RUN;

#ifdef BIND8_STATS
			/* Dump the statistics */
			bind8_stats(nsd);
#else /* BIND8_STATS */
			log_msg(LOG_NOTICE, "Statistics support not enabled at compile time.");
#endif /* BIND8_STATS */
		}
		
		region_free_all(query_region);

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
		
		/* Wait for a query... */
		if (pselect(maxfd + 1, &peer, NULL, NULL, NULL, &default_sigmask) == -1) {
			if (errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				log_msg(LOG_ERR, "select failed: %s", strerror(errno));
				break;
			}
		}

		if ((nsd->server_kind & NSD_SERVER_UDP) &&
		    handle_udp(query_region, nsd, &peer))
			continue;
		
		if ((nsd->server_kind & NSD_SERVER_TCP) &&
		    handle_tcp(query_region, nsd, &peer))
			continue;

		log_msg(LOG_ERR, "selected non-existant socket");
	}

#ifdef	BIND8_STATS
	bind8_stats(nsd);
#endif /* BIND8_STATS */

	region_destroy(query_region);
	
	server_shutdown(nsd);
}
