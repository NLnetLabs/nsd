/*
 * $Id: server.c,v 1.45 2002/09/18 13:00:11 alexis Exp $
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
answer_udp(s, nsd)
	int s;
	struct nsd *nsd;
{
	int received, sent;
	struct query q;

	/* Initialize the query... */
	query_init(&q);

	if((received = recvfrom(s, q.iobuf, q.iobufsz, 0, (struct sockaddr *)&q.addr, &q.addrlen)) == -1) {
		syslog(LOG_ERR, "recvfrom failed: %m");
		return -1;
	}
	q.iobufptr = q.iobuf + received;
	q.tcp = 0;

	if(query_process(&q, nsd) != -1) {
 		switch(q.edns) {
		case 1:	/* EDNS(0) packet... */
 			if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
 				bcopy(nsd->edns.opt_ok, q.iobufptr, OPT_LEN);
 				q.iobufptr += OPT_LEN;
 				ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
 			}

			STATUP(nsd, edns);

			break;
		case -1: /* EDNS(0) error... */
 			if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
 				bcopy(nsd->edns.opt_err, q.iobufptr, OPT_LEN);
 				q.iobufptr += OPT_LEN;
 				ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
 			}

			STATUP(nsd, ednserr);

			break;
 		}

		if((sent = sendto(s, q.iobuf, q.iobufptr - q.iobuf, 0, (struct sockaddr *)&q.addr, q.addrlen)) == -1) {
			syslog(LOG_ERR, "sendto failed: %m");
			STATUP(nsd, txerr);
			return -1;
		} else if(sent != q.iobufptr - q.iobuf) {
			syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q.iobufptr - q.iobuf);
			return -1;
		}

#ifdef NAMED8_STATS
		/* Account the rcode & TC... */
		STATUP2(nsd, rcode, RCODE((&q)));
		if(TC((&q)))
			STATUP(nsd, truncated);
#endif /* NAMED8_STATS */
	} else {
		STATUP(nsd, dropped);
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
answer_tcp(s, addr, addrlen, nsd)
	int s;
	struct sockaddr *addr;
	size_t addrlen;
	struct nsd *nsd;
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
			syslog(LOG_ERR, "insufficient tcp buffer, dropping connection");
			return -1;
		}

		/* We should use select or settimer() */
		alarm(120);

		if((received = read(s, q.iobuf, ntohs(tcplen))) == -1) {
			if(errno == EINTR) {
				syslog(LOG_WARNING, "timed out reading tcp connection");
				return -1;
			} else {
				syslog(LOG_ERR, "failed reading tcp connection: %m");
				return -1;
			}
		}

		if(received == 0) {
			syslog(LOG_WARNING, "remote closed connection");
			return -1;
		}

		if(received != ntohs(tcplen)) {
			syslog(LOG_WARNING, "couldnt read entire tcp message, dropping connection");
			return -1;
		}

		alarm(0);

		q.iobufptr = q.iobuf + received;

		if((axfr = query_process(&q, nsd)) != -1) {
			do {
				alarm(120);

				switch(q.edns) {
				case 1:
					if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
						bcopy(nsd->edns.opt_ok, q.iobufptr, OPT_LEN);
						q.iobufptr += OPT_LEN;
						ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
					}

					break;
				case -1:
					if((q.iobufptr - q.iobuf + OPT_LEN) <= q.iobufsz) {
						bcopy(nsd->edns.opt_err, q.iobufptr, OPT_LEN);
						q.iobufptr += OPT_LEN;
						ARCOUNT((&q)) = htons(ntohs(ARCOUNT((&q))) + 1);
					}

					break;
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
					axfr = query_axfr(&q, nsd, NULL, NULL, 0);
				}
			} while(axfr);
		} else {
			/* Drop the entire connection... */
			break;
		}

		alarm(120);
	}

	if(received == -1) {
		if(errno == EINTR) {
			syslog(LOG_WARNING, "timed out reading tcp connection");
			return -1;
		} else {
			syslog(LOG_ERR, "failed reading tcp connection: %m");
			return -1;
		}
	}

	/* Shut down the connection.... */
	/* Will be closed elsewhere: close(s); */

	return 0;
}


int
server(nsd)
	struct nsd *nsd;
{
	int udp_s, tcp_s, tcpc_s, maxfd;
#ifdef INET6
	int udp6_s, tcp6_s;
#endif
	struct sockaddr_in udp_addr, tcp_addr;
#ifdef INET6
	struct sockaddr_in6 udp6_addr, tcp6_addr;
	struct sockaddr_storage tcpc_addr;
# ifdef IPV6_V6ONLY
	int v6only = 1;
# endif
#else
	struct sockaddr_in tcpc_addr;
#endif

#ifdef NAMED8_STATS
	FILE *stf;
#endif /* NAMED8_STATS */


	size_t tcpc_addrlen;
	fd_set peer;
	pid_t pid;

	/* UDP */
	bzero(&udp_addr, sizeof(udp_addr));
	udp_addr.sin_addr.s_addr = nsd->udp.addr;
	udp_addr.sin_port = htons(nsd->udp.port);
	udp_addr.sin_family = AF_INET;

	/* Make a socket... */
	if((udp_s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(udp_s, (struct sockaddr *)&udp_addr, sizeof(udp_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

#ifdef INET6
	/* UDP */
	bzero(&udp6_addr, sizeof(udp6_addr));
	udp6_addr.sin6_port = htons(nsd->udp.port);
	udp6_addr.sin6_family = AF_INET6;

	/* Make a socket... */
	if((udp6_s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

# ifdef IPV6_V6ONLY
	if (setsockopt(udp6_s, IPPROTO_IPV6, IPV6_V6ONLY,
			&v6only, sizeof (v6only)) < 0) {
		syslog(LOG_ERR, "setsockopt() failed: %m");
		return -1;
	}
# endif

	/* Bind it... */
	if(bind(udp6_s, (struct sockaddr *)&udp6_addr, sizeof(udp6_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}
#endif

	/* TCP */
	bzero(&tcp_addr, sizeof(tcp_addr));
	tcp_addr.sin_addr.s_addr = nsd->tcp.addr;
	tcp_addr.sin_port = htons(nsd->tcp.port);
	tcp_addr.sin_family = AF_INET;

	/* Make a socket... */
	if((tcp_s = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(tcp_s, (struct sockaddr *)&tcp_addr, sizeof(tcp_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* Listen to it... */
	if(listen(tcp_s, nsd->tcp.max_conn) == -1) {
		syslog(LOG_ERR, "cant listen: %m");
		return -1;
	}

#ifdef INET6
	/* TCP */
	bzero(&tcp6_addr, sizeof(tcp6_addr));
	tcp6_addr.sin6_port = htons(nsd->tcp.port);
	tcp6_addr.sin6_family = AF_INET6;

	/* Make a socket... */
	if((tcp6_s = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

# ifdef IPV6_V6ONLY
	if (setsockopt(tcp6_s, IPPROTO_IPV6, IPV6_V6ONLY,
			(char *)&v6only, sizeof (v6only)) < 0) {
		syslog(LOG_ERR, "setsockopt() failed: %m");
		return -1;
	}
# endif

	/* Bind it... */
	if(bind(tcp6_s, (struct sockaddr *)&tcp6_addr, sizeof(tcp6_addr)) != 0) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* Listen to it... */
	if(listen(tcp6_s, nsd->tcp.max_conn) == -1) {
		syslog(LOG_ERR, "cant listen: %m");
		return -1;
	}
#endif

	/* Chroot */
	if(nsd->chrootdir) {
		int l = strlen(nsd->chrootdir);

		nsd->dbfile += l;
		nsd->pidfile += l;
		nsd->named8_stats += l;

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

#ifdef	NAMED8_STATS
	/* Initialize times... */
	time(&nsd->st.reload);
#endif /* NAMED8_STATS */

	/* The main loop... */	
	while(nsd->mode != NSD_SHUTDOWN) {
		/* Do we need to reload the database? */
		switch(nsd->mode) {
		case NSD_STATS:
			nsd->mode = NSD_RUN;
#ifdef NAMED8_STATS
			/* Open the file */
			if((stf = fopen(nsd->named8_stats, "a")) == NULL) {
				syslog(LOG_ERR, "unable to open %s: %m", NAMED8_STATS);
				break;
			}

			/* Dump the statistics */
			stats(nsd, stf);

			fclose(stf);
#else /* NAMED8_STATS */
			syslog(LOG_NOTICE, "No statistics available, recompile with -DNAMED8_STATS");
#endif /* NAMED8_STATS */
			break;
		case NSD_RELOAD:
			nsd->mode = NSD_RUN;

			switch((pid = fork())) {
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
				if(kill(nsd->pid, SIGINT) != 0) {
					syslog(LOG_ERR, "cannot kill %d: %m", pid);
					exit(1);
				}

				nsd->pid  = getpid();

				/* Overwrite pid... */
				if(writepid(nsd) == -1) {
					syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd->pidfile);
				}
#ifdef NAMED8_STATS
				/* Remeber the time of the reload... */
				time(&nsd->st.reload);
#endif /* NAMED8_STATS */
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
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}

		/* Process it... */
		if(FD_ISSET(udp_s, &peer)) {
			/* Account... */
			STATUP(nsd, qudp);

			/* UDP query... */
			answer_udp(udp_s, nsd);
		}
#ifdef INET6
		else if (FD_ISSET(udp6_s, &peer)) {
			/* Account... */
			STATUP(nsd, qudp6);
			/* UDP query... */
			answer_udp(udp6_s, nsd);
		}
#endif
		else if (FD_ISSET(tcp_s, &peer)) {
			/* Account... */
			STATUP(nsd, ctcp);

			/* Accept the tcp connection */
			tcpc_addrlen = sizeof(tcpc_addr);
			if((tcpc_s = accept(tcp_s, (struct sockaddr *)&tcpc_addr, &tcpc_addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %m");
			} else {
				/* Fork and answer it... */
				switch(nsd->debug ? 0 : fork()) {
				case -1:
					syslog(LOG_ERR, "fork failed: %m");
					break;
				case 0:
					/* CHILD */
					answer_tcp(tcpc_s, (struct sockaddr *)&tcpc_addr, tcpc_addrlen, nsd);
					close(tcpc_s);
					exit(0);
				default:
					/* PARENT */
					nsd->tcp.open_conn++;
				}
			}
		}
#ifdef INET6
		else if (FD_ISSET(tcp6_s, &peer)) {
			/* Account... */
			STATUP(nsd, ctcp6);

			/* Accept the tcp6 connection */
			tcpc_addrlen = sizeof(tcpc_addr);
			if((tcpc_s = accept(tcp6_s, (struct sockaddr *)&tcpc_addr, &tcpc_addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %m");
			} else {
				/* Fork and answer it... */
				switch(nsd->debug? 0 : fork()) {
				case -1:
					syslog(LOG_ERR, "fork failed: %m");
					break;
				case 0:
					/* CHILD */
					answer_tcp(tcpc_s, (struct sockaddr *)&tcpc_addr, tcpc_addrlen, nsd);
					close(tcpc_s);
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
