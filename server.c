/*
 * $Id: server.c,v 1.1 2002/01/08 16:06:20 alexis Exp $
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
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>


#include "nsd.h"
#include "query.h"
#include "db.h"

int
server(port, db)
	u_short port;
	struct db *db;
{
	struct query *q;
	struct sockaddr_in addr;
	int s_udp, s_tcp, s_tcpio;
	u_short tcplen;
	int received, sent;
	fd_set peer;

	/* UDP */
	bzero(&addr, sizeof(struct sockaddr_in));
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);
	addr.sin_family = AF_INET;

	/* Make a socket... */
	if((s_udp = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(s_udp, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* TCP */
	if((s_tcp = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		syslog(LOG_ERR, "cant create a socket: %m");
		return -1;
	}

	/* Bind it... */
	if(bind(s_tcp, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
		syslog(LOG_ERR, "cant bind the socket: %m");
		return -1;
	}

	/* Listen to it... */
	if(listen(s_tcp, 16) == -1) {
		syslog(LOG_ERR, "cant listen: %m");
		return -1;
	}

	/* Setup... */
	if((q = query_new()) == NULL) {
		syslog(LOG_ERR, "failed to allocate a query: %m");
		return -1;
	}


	/* The main loop... */	
	while(1) {
		/* Set it up */
		FD_ZERO(&peer);
		FD_SET(s_udp, &peer);
		FD_SET(s_tcp, &peer);

		if(select(s_tcp + 1, &peer, NULL, NULL, NULL) == -1) {
			if(errno == EINTR) {
				/* We'll fall out of the loop if we need to shut down */
				continue;
			} else {
				syslog(LOG_ERR, "select failed: %m");
				break;
			}
		}
		if(FD_ISSET(s_udp, &peer)) {
#if DEBUG > 2
			printf("udp packet!\n");
#endif
			query_init(q);
			if((received = recvfrom(s_udp, q->iobuf, q->iobufsz, 0,
					(struct sockaddr *)&q->addr, &q->addrlen)) == -1) {
				syslog(LOG_ERR, "recvfrom failed: %m");
				break;
			}
			q->iobufptr = q->iobuf + received;

			if(query_process(q, db) != -1) {
				if((sent = sendto(s_udp, q->iobuf, q->iobufptr - q->iobuf, 0,
					(struct sockaddr *)&q->addr, q->addrlen)) == -1) {
					syslog(LOG_ERR, "sendto failed: %m");
					break;
				}
				if(sent != q->iobufptr - q->iobuf) {
					syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q->iobufptr - q->iobuf);
				}
			}
		} else if(FD_ISSET(s_tcp, &peer)) {
			query_init(q);
#if DEBUG
			syslog(LOG_NOTICE, "tcp connection!");
#endif
			if((s_tcpio = accept(s_tcp, (struct sockaddr *)&q->addr, &q->addrlen)) == -1) {
				syslog(LOG_ERR, "accept failed: %m");
				break;
			}

			switch(fork()) {
			case -1:
				syslog(LOG_ERR, "fork failed: %m");
				break;
			case 0:
				alarm(120);

				/* Until we've got end of file */
				while((received = read(s_tcpio, &tcplen, 2)) == 2) {
					if(ntohs(tcplen < 17)) {
						syslog(LOG_WARNING, "dropping bogus tcp connection");
						exit(0);
					}

					if(ntohs(tcplen) > q->iobufsz) {
						syslog(LOG_ERR, "insufficient tcp buffer, truncating incoming message");
						tcplen = htons(q->iobufsz);
					}

					/* We should use select or settimer() */
					alarm(120);

					if((received = read(s_tcpio, q->iobuf, ntohs(tcplen))) == -1) {
						if(errno == EINTR) {
							syslog(LOG_WARNING, "timed out reading tcp connection");
							exit(0);
						} else {
							syslog(LOG_ERR, "failed reading tcp connection: %m");
							exit(0);
						}
					}

					if(received == 0) {
						syslog(LOG_WARNING, "remote closed connection");
						exit(0);
					}

					if(received != ntohs(tcplen)) {
						syslog(LOG_WARNING, "couldnt read entire tcp message");
					}

					alarm(0);

					q->iobufptr = q->iobuf + received;

					if(query_process(q, db) != -1) {
						alarm(120);
						tcplen = htons(q->iobufptr - q->iobuf);
						if(((sent = write(s_tcpio, &tcplen, 2)) == -1) ||
							((sent = write(s_tcpio, q->iobuf, q->iobufptr - q->iobuf)) == -1)) {
								syslog(LOG_ERR, "write failed: %m");
								exit(0);
						}
						if(sent != q->iobufptr - q->iobuf) {
							syslog(LOG_ERR, "sent %d in place of %d bytes", sent, q->iobufptr - q->iobuf);
						}
					}
					alarm(120);
				}
				if(received == -1) {
					if(errno == EINTR) {
						syslog(LOG_WARNING, "timed out reading tcp connection");
						exit(0);
					} else {
						syslog(LOG_ERR, "failed reading tcp connection: %m");
						exit(0);
					}
				}
				close(s_tcpio);
				exit(0);
			default:
				/* PARENT */
			}
		} else {
			/* Time out... */
			syslog(LOG_ERR, "select timed out");
		}
	}

	/* Clean up */
	query_destroy(q);
	close(s_tcp);
	close(s_udp);
	return -1;
}
