/*
 * $Id: server.c,v 1.35 2002/05/07 17:33:45 alexis Exp $
 *
 * server.c -- nsd(8) network input/output
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

int 
answer_udp (int s, struct nsd *nsd)
{
	int received, sent;
	struct query q;

	/* Initialize the query... */
	query_init(&q);

	if((received = recvfrom(s, q.iobuf, q.iobufsz, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		syslog(LOG_ERR, "recvfrom failed: %s", strerror(errno));
		return -1;
	}
	q.iobufptr = q.iobuf + received;
	q.tcp = 0;

	if(query_process(&q, nsd->db) != -1) {
 		if(q.edns == 1) {
 			if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
 				bcopy(nsd->edns.opt, q.iobufptr, OPT_LEN);
 				q.iobufptr += OPT_LEN;
 				ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
 			}
 		}
		if((sent = sendto(s, q.iobuf, q.iobufptr - q.iobuf, 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
			syslog(LOG_ERR, "sendto failed: %s", strerror(errno));
			return -1;
		} else if(sent != q.iobufptr - q.iobuf) {
			syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr - q.iobuf);
			return -1;
		}
	}

	return 0;
}

/*
 *
 * XXX This function must always be called from inside of a fork() since it uses alarm()
 *
 *
 */
int 
answer_tcp (int s, struct sockaddr *addr, size_t addrlen, struct nsd *nsd)
{
	struct query q;
	u_int16_t tcplen;
	int received, sent, axfr;

	/* Initialize the query... */
	query_init(&q);

	bcopy(addr, &q.addr, addrlen);
	q.addrlen = addrlen;

	q.maxlen = (q.iobufsz > nsd->tcp.max_msglen) ? nsd->tcp.max_msglen : q.iobufsz;
	q.tcp = 1;

	/* Until we've got end of file */
	while((received = read(s, &tcplen, 2)) == 2) {
		/* XXX Why 17???? */
		if(ntohs(tcplen) < 17) {
			syslog(LOG_WARNING, "dropping bogus tcp connection");
			return -1;
		}

		if(ntohs(tcplen) > q.iobufsz) {
			syslog(LOG_ERR, "insufficient tcp buffer, truncating incoming message");
			tcplen = htons(q.iobufsz);
		}

		/* We should use select or settimer() */
		alarm(120);

		if((received = read(s, q.iobuf, ntohs(tcplen))) == -1) {
			if(errno == EINTR) {
				syslog(LOG_WARNING, "timed out reading tcp connection");
				return -1;
			} else {
				syslog(LOG_ERR, "failed reading tcp connection: %s", strerror(errno));
				return -1;
			}
		}

		if(received == 0) {
			syslog(LOG_WARNING, "remote closed connection");
			return -1;
		}

		if(received != ntohs(tcplen)) {
			syslog(LOG_WARNING, "couldnt read entire tcp message");
		}

		alarm(0);

		q.iobufptr = q.iobuf + received;

		if((axfr = query_process(&q, nsd->db)) != -1) {
			do {
				alarm(120);

				if(q.edns == 1) {
					if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
						bcopy(nsd->edns.opt, q.iobufptr, OPT_LEN);
						q.iobufptr += OPT_LEN;
						ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
					}
				}

				tcplen = htons(q.iobufptr - q.iobuf);
				if(((sent = write(s, &tcplen, 2)) == -1) ||
					((sent = write(s, q.iobuf, q.iobufptr - q.iobuf)) == -1)) {
						syslog(LOG_ERR, "write failed: %s", strerror(errno));
						return -1;
				}
				if(sent != q.iobufptr - q.iobuf) {
					syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr - q.iobuf);
					return -1;
				}

				/* Do we have AXFR in progress? */
				if(axfr) {
					axfr = query_axfr(&q, nsd->db, NULL, NULL, 0);
				}
			} while(axfr);
		}
		alarm(120);
	}

	if(received == -1) {
		if(errno == EINTR) {
			syslog(LOG_WARNING, "timed out reading tcp connection");
			return -1;
		} else {
			syslog(LOG_ERR, "failed reading tcp connection: %s", strerror(errno));
			return -1;
		}
	}

	/* Shut down the connection.... */
	close(s);

	return 0;
}


int 
server (struct nsd *nsd)
{
	int udp_s, tcp_s, tcpc_s, maxfd;
#ifdef INET6
	int udp6_s, tcp6_s;
#endif
	struct sockaddr_in udp_addr, tcp_addr;
#ifdef INET6
	struct sockaddr_in6 udp6_addr, tcp6_addr;
	struct sockaddr_storage tcpc_addr;
#else
	struct sockaddr_in tcpc_addr;
#endif
	size_t tcpc_addrlen;
	fd_set peer;

	/* UDP */
	bzero(&udp_addr, sizeof(udp_addr));
	udp_addr.sin_addr.s_addr = INADDR_ANY;
	udp_addr.sin_port = htons(nsd->udp.port);
	udp_addr.sin_family = AF_INET;

	/* Make a socket... */
	if((udp_s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %s", strerror(errno));
		return -1;
	}

	/* Bind it... */
	if(bind(udp_s, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %s", strerror(errno));
		return -1;
	}

#ifdef INET6
	/* UDP */
	bzero(&udp6_addr, sizeof(udp6_addr));
	udp6_addr.sin6_port = htons(nsd->udp.port);
	udp6_addr.sin6_family = AF_INET6;

	/* Make a socket... */
	if((udp6_s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %s", strerror(errno));
		return -1;
	}

	/* Bind it... */
	if(bind(udp6_s, (struct sockaddr *)&udp6_addr, sizeof(udp6_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %s", strerror(errno));
		return -1;
	}
#endif

	/* TCP */
	bzero(&tcp_addr, sizeof(tcp_addr));
	tcp_addr.sin_addr.s_addr = INADDR_ANY;
	tcp_addr.sin_port = htons(nsd->tcp.port);
	tcp_addr.sin_family = AF_INET;

	/* Make a socket... */
	if((tcp_s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %s", strerror(errno));
		return -1;
	}

	/* Bind it... */
	if(bind(tcp_s, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %s", strerror(errno));
		return -1;
	}

	/* Listen to it... */
	if(listen(tcp_s, nsd->tcp.max_conn) == -1) {
		syslog(LOG_ERR, "cant listen: %s", strerror(errno));
		return -1;
	}

#ifdef INET6
	/* TCP */
	bzero(&tcp6_addr, sizeof(tcp6_addr));
	tcp6_addr.sin6_port = htons(nsd->tcp.port);
	tcp6_addr.sin6_family = AF_INET6;

	/* Make a socket... */
	if((tcp6_s = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %s", strerror(errno));
		return -1;
	}

	/* Bind it... */
	if(bind(tcp6_s, (struct sockaddr *)&tcp6_addr, sizeof(tcp6_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %s", strerror(errno));
		return -1;
	}

	/* Listen to it... */
	if(listen(tcp6_s, nsd->tcp.max_conn) == -1) {
		syslog(LOG_ERR, "cant listen: %s", strerror(errno));
		return -1;
	}
#endif

	/* The main loop... */	
	while(nsd->mode != NSD_SHUTDOWN) {
		/* Do we need to reload the database? */
		switch(nsd->mode) {
		case NSD_RELOAD:
			nsd->mode = NSD_RUN;

			switch(nsd->debug ? 0 : fork()) {
			case -1:
				syslog(LOG_ERR, "fork failed: %s", strerror(errno));
				break;
			case 0:
				/* CHILD */

				namedb_close(nsd->db);
				if((nsd->db = namedb_open(nsd->dbfile)) == NULL) {
					syslog(LOG_ERR, "unable to reload the database: %s", strerror(errno));
					exit(1);
				}

				if(!nsd->debug) {
					/* Send the child SIGINT to the parent to terminate quitely... */
					if(kill(nsd->pid, SIGINT) != 0) {
						syslog(LOG_ERR, "cannot kill %d: %s", nsd->pid,
									strerror(errno));
						exit(1);
					}

					nsd->pid  = getpid();

					/* Overwrite pid... */
					if(writepid(nsd->pid, nsd->pidfile) == -1) {
						syslog(LOG_ERR, "cannot overwrite the pidfile %s: %s", nsd->pidfile, strerror(errno));
					}
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

		/* Set it up */
		FD_ZERO(&peer);
		FD_SET(udp_s, &peer); maxfd = udp_s;
		maxfd = tcp_s > maxfd ? tcp_s : maxfd;
#ifdef INET6
		FD_SET(udp6_s, &peer); maxfd = udp6_s > maxfd ? udp6_s : maxfd;
		maxfd = tcp6_s > maxfd ? tcp6_s : maxfd;
#endif

		/* don't accept TCP if i'm already serving max # of clients */
		if (nsd->tcp.open_conn < nsd->tcp.max_conn) {
			FD_SET(tcp_s, &peer);
#ifdef INET6
			FD_SET(tcp6_s, &peer);
#endif
		}

		/* Wait for a query or tcp connection... */
		if(select(maxfd + 1, &peer, NULL, NULL, NULL) == -1) {
			if(errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %s", strerror(errno));
				break;
			}
		}

		/* Process it... */
		if(FD_ISSET(udp_s, &peer)) {
			/* UDP query... */
			answer_udp(udp_s, nsd);
		}
#ifdef INET6
		else if (FD_ISSET(udp6_s, &peer)) {
			/* UDP query... */
			answer_udp(udp6_s, nsd);
		}
#endif
		else if (FD_ISSET(tcp_s, &peer)) {
			/* Accept the tcp connection */
			tcpc_addrlen = sizeof(tcpc_addr);
			if((tcpc_s = accept(tcp_s, (struct sockaddr *)&tcpc_addr, &tcpc_addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %s", strerror(errno));
			} else {
				/* Fork and answer it... */
				switch(nsd->debug ? 0 : fork()) {
				case -1:
					syslog(LOG_ERR, "fork failed: %s", strerror(errno));
					break;
				case 0:
					/* CHILD */
					answer_tcp(tcpc_s, (struct sockaddr *)&tcpc_addr, tcpc_addrlen, nsd);
					if(!nsd->debug)
						exit(0);
				default:
					/* PARENT */
					nsd->tcp.open_conn++;
				}
			}
		}
#ifdef INET6
		else if (FD_ISSET(tcp6_s, &peer)) {
			/* Accept the tcp6 connection */
			tcpc_addrlen = sizeof(tcpc_addr);
			if((tcpc_s = accept(tcp6_s, (struct sockaddr *)&tcpc_addr, &tcpc_addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %s", strerror(errno));
			} else {
				/* Fork and answer it... */
				switch(fork()) {
				case -1:
					syslog(LOG_ERR, "fork failed: %s", strerror(errno));
					break;
				case 0:
					/* CHILD */
					answer_tcp(tcpc_s, (struct sockaddr *)&tcpc_addr, tcpc_addrlen, nsd);
					exit(0);
				default:
					/* PARENT */
					nsd->tcp.open_conn++;
				}
			}
		}
#endif
		else {
			/* Time out... */
			syslog(LOG_ERR, "select timed out");
		}
	}

	/* Clean up */
	close(tcp_s);
	close(udp_s);

	return 0;
}
