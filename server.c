/*
 * server.c -- nsd(8) network input/output
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
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
#include <fcntl.h>
#include <netdb.h>

#include "axfr.h"
#include "dns.h"
#include "namedb.h"
#include "dname.h"
#include "netio.h"
#include "nsd.h"
#include "plugins.h"
#include "query.h"
#include "region-allocator.h"
#include "util.h"


static void handle_tcp_reading(netio_type *netio,
			       netio_handler_type *handler,
			       netio_event_types_type event_types);
static void handle_tcp_writing(netio_type *netio,
			       netio_handler_type *handler,
			       netio_event_types_type event_types);


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

static void
initialize_dname_compression_tables(struct nsd *nsd)
{
	compressed_dname_offsets = xalloc(
		(domain_table_count(nsd->db->domains) + 1) * sizeof(uint16_t));
	memset(compressed_dname_offsets, 0,
	       (domain_table_count(nsd->db->domains) + 1) * sizeof(uint16_t));
	compressed_dname_offsets[0] = QHEADERSZ; /* The original query name */
	region_add_cleanup(nsd->db->region, free, compressed_dname_offsets);
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

	initialize_dname_compression_tables(nsd);
	
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

				initialize_dname_compression_tables(nsd);
	
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
			query->domain ? query->domain->plugin_data : NULL);
		if (callback_result != NSD_PLUGIN_CONTINUE) {
			return handle_callback_result(callback_result, &callback_args);
		}
	}
	return rc;
#else /* !PLUGINS */
	return query_process(query, nsd);
#endif /* !PLUGINS */
}

struct handler_data
{
	region_type       *query_region;
	struct nsd        *nsd;
	struct nsd_socket *socket;
};

static void
handle_udp(netio_type *netio ATTR_UNUSED,
	   netio_handler_type *handler,
	   netio_event_types_type event_types)
{
	struct handler_data *data = handler->user_data;
	int received, sent;
	struct query q;

	if (!(event_types & NETIO_EVENT_READ)) {
		return;
	}
	
	/* Account... */
	if (data->socket->addr->ai_family == AF_INET) {
		STATUP(data->nsd, qudp);
	} else if (data->socket->addr->ai_family == AF_INET6) {
		STATUP(data->nsd, qudp6);
	}

	/* Initialize the query... */
	query_init(&q);
	q.region = data->query_region;
	q.compressed_dname_offsets = compressed_dname_offsets;
	
	if ((received = recvfrom(handler->fd, q.iobuf, QIOBUFSZ, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		if (errno != EAGAIN) {
			log_msg(LOG_ERR, "recvfrom failed: %s", strerror(errno));
			STATUP(data->nsd, rxerr);
		}
		return;
	}
	q.iobufptr = q.iobuf + received;
	q.tcp = 0;

	/* Process and answer the query... */
	if (process_query(data->nsd, &q) != QUERY_DISCARDED) {
		if (RCODE((&q)) == RCODE_OK && !AA((&q)))
			STATUP(data->nsd, nona);
		/* Add edns(0) info if necessary.. */
		query_addedns(&q, data->nsd);

		if ((sent = sendto(handler->fd, q.iobuf, query_used_size(&q), 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
			log_msg(LOG_ERR, "sendto failed: %s", strerror(errno));
			STATUP(data->nsd, txerr);
			return;
		} else if (sent != q.iobufptr - q.iobuf) {
			log_msg(LOG_ERR, "sent %d in place of %d bytes", sent, (int) query_used_size(&q));
			return;
		}

#ifdef BIND8_STATS
		/* Account the rcode & TC... */
		STATUP2(data->nsd, rcode, RCODE((&q)));
		if (TC((&q)))
			STATUP(data->nsd, truncated);
#endif /* BIND8_STATS */
	} else {
		STATUP(data->nsd, dropped);
	}
}


/*
 * The TCP handlers use non-blocking I/O.  This is necessary to avoid
 * blocking the entire server on a slow TCP connection, but does make
 * reading from and writing to the socket more complicated.
 *
 * Basically, whenever a read/write would block (indicated by the
 * EAGAIN errno variable) we remember the position we were reading
 * from/writing to and return from the TCP reading/writing event
 * handler.  When the socket becomes readable/writable again we
 * continue from the same position.
 *
 */
struct tcp_handler_data
{
	region_type     *region;
	struct nsd      *nsd;
	struct query     query;

	/*
	 * The query_state is used to remember if we are performing an
	 * AXFR, if we're done processing, or if we should discard the
	 * query and connection.
	 */
	query_state_type query_state;

	/*
	 * The bytes_transmitted field is used to remember the
	 * position and includes the two additional bytes used to
	 * specify the packet length on a TCP connection.
	 */
	size_t           bytes_transmitted;
};

static void
cleanup_tcp_handler(netio_type *netio, netio_handler_type *handler)
{
	struct tcp_handler_data *data = handler->user_data;
	netio_remove_handler(netio, handler);
	close(handler->fd);

	/*
	 * Keep track of the total number of TCP handlers installed so
	 * we can stop accepting connections when the maximum number
	 * of simultaneous TCP connections is reached.
	 */
	--data->nsd->current_tcp_count;
	assert(data->nsd->current_tcp_count >= 0);
	
	region_destroy(data->region);
}

static void
handle_tcp_reading(netio_type *netio,
		   netio_handler_type *handler,
		   netio_event_types_type event_types)
{
	struct tcp_handler_data *data = handler->user_data;
	ssize_t received;
	struct query *q = &data->query;

	if (event_types & NETIO_EVENT_TIMEOUT) {
		/* Connection timed out.  */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	assert(event_types & NETIO_EVENT_READ);

	/*
	 * Check if we received the leading packet length bytes yet.
	 */
	if (data->bytes_transmitted < sizeof(q->tcplen)) {
		received = read(handler->fd,
				(char *) &q->tcplen + data->bytes_transmitted,
				sizeof(q->tcplen) - data->bytes_transmitted);
		if (received == -1) {
			if (errno == EAGAIN) {
				/* Read would block, wait until more data is available.  */
				return;
			} else {
				log_msg(LOG_ERR, "failed reading from tcp: %s", strerror(errno));
				cleanup_tcp_handler(netio, handler);
				return;
			}
		} else if (received == 0) {
			/* EOF */
			cleanup_tcp_handler(netio, handler);
			return;
		}

		data->bytes_transmitted += received;
		if (data->bytes_transmitted < sizeof(q->tcplen)) {
			/*
			 * Not done with the tcplen yet, wait for more
			 * data to become available.
			 */
			return;
		}

		assert(data->bytes_transmitted == sizeof(q->tcplen));

		q->tcplen = ntohs(q->tcplen);

		/*
		 * Minimum query size is:
		 *
		 *     Size of the header (12)
		 *   + Root domain name   (1)
		 *   + Query class        (2)
		 *   + Query type         (2)
		 */
		if (q->tcplen < QHEADERSZ + 1 + sizeof(uint16_t) + sizeof(uint16_t)) {
			log_msg(LOG_WARNING, "dropping bogus tcp connection");
			cleanup_tcp_handler(netio, handler);
			return;
		}

		if (q->tcplen > q->maxlen) {
			log_msg(LOG_ERR, "insufficient tcp buffer, dropping connection");
			cleanup_tcp_handler(netio, handler);
			return;
		}
	}

	assert(data->bytes_transmitted < q->tcplen + sizeof(q->tcplen));

	/* Read the (remaining) query data.  */
	received = read(handler->fd, q->iobufptr, q->tcplen - query_used_size(q));
	if (received == -1) {
		if (errno == EAGAIN) {
			/* Read would block, wait until more data is available.  */
			return;
		} else {
			log_msg(LOG_ERR, "failed reading from tcp: %s", strerror(errno));
			cleanup_tcp_handler(netio, handler);
			return;
		}
	} else if (received == 0) {
		/* EOF */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	data->bytes_transmitted += received;
	q->iobufptr += received;
	if (query_used_size(q) < q->tcplen) {
		/*
		 * Message not yet complete, wait for more data to
		 * become available.
		 */
		return;
	}

	assert(query_used_size(q) == q->tcplen);

	/* We have a complete query, process it.  */
	data->query_state = process_query(data->nsd, q);
	if (data->query_state == QUERY_DISCARDED) {
		/* Drop the entire connection... */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	if (RCODE(q) == RCODE_OK && !AA(q)) {
		STATUP(data->nsd, nona);
	}
		
	query_addedns(q, data->nsd);

	/* Switch to the tcp write handler.  */
	q->tcplen = query_used_size(q);
	data->bytes_transmitted = 0;
	
	handler->timeout->tv_sec = TCP_TIMEOUT;
	handler->timeout->tv_nsec = 0L;
	timespec_add(handler->timeout, netio_current_time(netio));
	
	handler->event_types = NETIO_EVENT_WRITE | NETIO_EVENT_TIMEOUT;
	handler->event_handler = handle_tcp_writing;
}

static void
handle_tcp_writing(netio_type *netio,
		   netio_handler_type *handler,
		   netio_event_types_type event_types)
{
	struct tcp_handler_data *data = handler->user_data;
	ssize_t sent;
	struct query *q = &data->query;

	if (event_types & NETIO_EVENT_TIMEOUT) {
		/* Connection timed out.  */
		cleanup_tcp_handler(netio, handler);
		return;
	}

	assert(event_types & NETIO_EVENT_WRITE);

	if (data->bytes_transmitted < sizeof(q->tcplen)) {
		/* Writing the response packet length.  */
		uint16_t n_tcplen = htons(q->tcplen);
		sent = write(handler->fd,
			     (const char *) &n_tcplen + data->bytes_transmitted,
			     sizeof(n_tcplen) - data->bytes_transmitted);
		if (sent == -1) {
			if (errno == EAGAIN) {
				/*
				 * Write would block, wait until
				 * socket becomes writable again.
				 */
				return;
			} else {
				log_msg(LOG_ERR, "failed writing to tcp: %s", strerror(errno));
				cleanup_tcp_handler(netio, handler);
				return;
			}
		}

		data->bytes_transmitted += sent;
		if (data->bytes_transmitted < sizeof(q->tcplen)) {
			/*
			 * Writing not complete, wait until socket
			 * becomes writable again.
			 */
			return;
		}

		assert(data->bytes_transmitted == sizeof(q->tcplen));
	}

	assert(data->bytes_transmitted < q->tcplen + sizeof(q->tcplen));

	sent = write(handler->fd,
		     q->iobuf + data->bytes_transmitted - sizeof(q->tcplen),
		     query_used_size(q) - data->bytes_transmitted + sizeof(q->tcplen));
	if (sent == -1) {
		if (errno == EAGAIN) {
			/*
			 * Write would block, wait until
			 * socket becomes writable again.
			 */
			return;
		} else {
			log_msg(LOG_ERR, "failed writing to tcp: %s", strerror(errno));
			cleanup_tcp_handler(netio, handler);
			return;
		}
	}

	data->bytes_transmitted += sent;
	if (data->bytes_transmitted < q->tcplen + sizeof(q->tcplen)) {
		/*
		 * Still more data to write when socket becomes
		 * writable again.
		 */
		return;
	}

	assert(data->bytes_transmitted == q->tcplen + sizeof(q->tcplen));
	       
	if (data->query_state == QUERY_IN_AXFR) {
		/* Continue processing AXFR and writing back results.  */
		data->query_state = query_axfr(data->nsd, q);
		if (data->query_state != QUERY_PROCESSED) {
			/* Reset data. */
			q->tcplen = query_used_size(q);
			data->bytes_transmitted = 0;
			/* Reset timeout.  */
			handler->timeout->tv_sec = TCP_TIMEOUT;
			handler->timeout->tv_nsec = 0;
			timespec_add(handler->timeout, netio_current_time(netio));

			/*
			 * Write data if/when the socket is writable
			 * again.
			 */
			return;
		}
	}

	/*
	 * Done sending, wait for the next request to arrive on the
	 * TCP socket by installing the TCP read handler.
	 */
	query_init(&data->query);
	data->bytes_transmitted = 0;
	
	handler->timeout->tv_sec = TCP_TIMEOUT;
	handler->timeout->tv_nsec = 0;
	timespec_add(handler->timeout, netio_current_time(netio));

	handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
	handler->event_handler = handle_tcp_reading;
}


/*
 * Handle an incoming TCP connection.  The connection is accepted and
 * a new TCP reader event handler is added to NETIO.  The TCP handler
 * is responsible for cleanup when the connection is closed.
 */
static void
handle_accept(netio_type *netio,
	      netio_handler_type *handler,
	      netio_event_types_type event_types)
{
	struct handler_data *data = handler->user_data;
	int s;
	struct tcp_handler_data *tcp_data;
	region_type *tcp_region;
	netio_handler_type *tcp_handler;
#ifdef INET6
	struct sockaddr_storage addr;
#else
	struct sockaddr_in addr;
#endif
	socklen_t addrlen;
	
	if (!(event_types & NETIO_EVENT_READ)) {
		return;
	}

	if (data->nsd->current_tcp_count >= data->nsd->maximum_tcp_count) {
		return;
	}
	
	/* Account... */
	if (data->socket->addr->ai_family == AF_INET) {
		STATUP(data->nsd, ctcp);
	} else if (data->socket->addr->ai_family == AF_INET6) {
		STATUP(data->nsd, ctcp6);
	}

	/* Accept it... */
	addrlen = sizeof(addr);
	if ((s = accept(handler->fd, (struct sockaddr *)&addr, &addrlen)) == -1) {
		if (errno != EINTR) {
			log_msg(LOG_ERR, "accept failed: %s", strerror(errno));
		}
		return;
	}

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
		log_msg(LOG_ERR, "fcntl failed: %s", strerror(errno));
		return;
	}
	
	/*
	 * This region is deallocated when the TCP connection is
	 * closed by the TCP handler.
	 */
	tcp_region = region_create(xalloc, free);
	tcp_data = region_alloc(tcp_region, sizeof(struct tcp_handler_data));
	tcp_data->region = tcp_region;
	tcp_data->nsd = data->nsd;
	
	query_init(&tcp_data->query);
	tcp_data->query.region = data->query_region;
	tcp_data->query.compressed_dname_offsets = compressed_dname_offsets;
	tcp_data->query.maxlen = (MAX_PACKET_SIZE < data->nsd->tcp_max_msglen
				  ? MAX_PACKET_SIZE
				  : data->nsd->tcp_max_msglen);
	tcp_data->query.tcp = 1;
	tcp_data->query_state = QUERY_PROCESSED;
	tcp_data->bytes_transmitted = 0;
	memcpy(&tcp_data->query.addr, &addr, addrlen);
	tcp_data->query.addrlen = addrlen;
	
	tcp_handler = region_alloc(tcp_region, sizeof(netio_handler_type));
	tcp_handler->fd = s;
	tcp_handler->timeout = region_alloc(tcp_region, sizeof(struct timespec));
	tcp_handler->timeout->tv_sec = TCP_TIMEOUT;
	tcp_handler->timeout->tv_nsec = 0L;
	timespec_add(tcp_handler->timeout, netio_current_time(netio));

	tcp_handler->user_data = tcp_data;
	tcp_handler->event_types = NETIO_EVENT_READ | NETIO_EVENT_TIMEOUT;
	tcp_handler->event_handler = handle_tcp_reading;

	netio_add_handler(netio, tcp_handler);

	/*
	 * Keep track of the total number of TCP handlers installed so
	 * we can stop accepting connections when the maximum number
	 * of simultaneous TCP connections is reached.
	 */
	++data->nsd->current_tcp_count;
}



/*
 * Serve DNS requests.
 */
void
server_child(struct nsd *nsd)
{
	size_t i;
	sigset_t block_sigmask;
	sigset_t default_sigmask;
	region_type *server_region = region_create(xalloc, free);
	region_type *query_region = region_create(xalloc, free);
	netio_type *netio = netio_create(server_region);
	netio_handler_type *tcp_accept_handlers;
	
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

	if (nsd->server_kind & NSD_SERVER_UDP) {
		for (i = 0; i < nsd->ifs; ++i) {
			struct handler_data *data;
			netio_handler_type *handler;

			data = region_alloc(server_region, sizeof(struct handler_data));
			data->query_region = query_region;
			data->nsd = nsd;
			data->socket = &nsd->udp[i];
			
			handler = region_alloc(server_region, sizeof(netio_handler_type));
			handler->fd = nsd->udp[i].s;
			handler->timeout = NULL;
			handler->user_data = data;
			handler->event_types = NETIO_EVENT_READ;
			handler->event_handler = handle_udp;
			netio_add_handler(netio, handler);
		}
	}

	/*
	 * Keep track of all the TCP accept handlers so we can enable
	 * and disable them based on the current number of active TCP
	 * connections.
	 */
	tcp_accept_handlers = region_alloc(server_region,
					   nsd->ifs * sizeof(netio_handler_type));
	if (nsd->server_kind & NSD_SERVER_TCP) {
		for (i = 0; i < nsd->ifs; ++i) {
			struct handler_data *data;
			netio_handler_type *handler;
			
			data = region_alloc(server_region, sizeof(struct handler_data));
			data->query_region = query_region;
			data->nsd = nsd;
			data->socket = &nsd->tcp[i];

			handler = &tcp_accept_handlers[i];
			handler->fd = nsd->tcp[i].s;
			handler->timeout = NULL;
			handler->user_data = data;
			handler->event_types = NETIO_EVENT_READ;
			handler->event_handler = handle_accept;
			netio_add_handler(netio, handler);
		}
	}
	
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

		/*
		 * Release all memory allocated while processing the
		 * previous request.
		 */
		region_free_all(query_region);

		/*
		 * Enable/disable TCP accept handlers when the maximum
		 * number of concurrent TCP connections is reached/not
		 * reached.
		 */
		if (nsd->server_kind & NSD_SERVER_TCP) {
			netio_event_types_type tcp_accept_event_types
				= (nsd->current_tcp_count < nsd->maximum_tcp_count
				   ? NETIO_EVENT_READ
				   : NETIO_EVENT_NONE);
			for (i = 0; i < nsd->ifs; ++i) {
				tcp_accept_handlers[i].event_types = tcp_accept_event_types;
			}
		}

		/* Wait for a query... */
		if (netio_dispatch(netio, NULL, &default_sigmask) == -1) {
			if (errno != EINTR) {
				log_msg(LOG_ERR, "select failed: %s", strerror(errno));
				break;
			}
		}
	}

#ifdef	BIND8_STATS
	bind8_stats(nsd);
#endif /* BIND8_STATS */

	region_destroy(query_region);
	region_destroy(server_region);
	
	server_shutdown(nsd);
}
