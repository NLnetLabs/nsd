#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>

struct session {
	int s;
	uint8_t* sendbuf;
	uint8_t  recvbuf[65536];
	uint8_t *recvptr;
	ssize_t tosend;
	ssize_t torecv;
	int     nzones;
};
typedef struct session session_t;

int main(int argc, const char** argv)
{
	const char* service;
	int nzones = 10001;
	int nsessions = 1;
	const char* host = "localhost";

	int bufsz = ( nzones <= 10
		    ? 25 * nzones
		    : 250 + ( nzones <= 100
			    ? 26 * (nzones - 10)
			    : 2340 + ( nzones <= 1000
				     ? 27 * (nzones - 100)
				     : 24300 + ( nzones <= 10000
					       ? 28 * (nzones - 1000)
					       : 252000 + 29 * (nzones - 10000)
					       )
				    )
			    )
		    );
	uint8_t* sendbuf;
	uint8_t* start;
	uint8_t* cursor;
	ssize_t tosend;
	ssize_t written;
	ssize_t received;
	int zones_read = 0;
	int prev_zones_read = 0;

	session_t* sessions;
	session_t* S;
	int zones_per_session;

	int i, j, k;

	struct addrinfo hints;
	struct addrinfo *result, *rp;

	int e, s;

	struct timeval t;
	double prev_time;
	double cur_time;
	double d_time;

	fd_set rfds;
	fd_set wfds;

	if (argc < 2 || argc > 5) {
		fprintf( stderr
		       , "usage: %s <port> "
		         "[ <# zones> [ <# tcp sessions> [ <host> ]]]\n"
		       , *argv
		       );
		exit(EXIT_FAILURE);
	}
	argc--;
	service = *++argv;
	if (--argc) {
		nzones = atoi(*++argv);
		if (--argc) {
			nsessions = atoi(*++argv);
			if (--argc) {
				host = *++argv;
			}
		}
	}
	sessions = malloc(sizeof(session_t) * (nsessions + 1));

	zones_per_session = nzones / nsessions;

	start = cursor = sendbuf = malloc(bufsz);

	j = 0;
	k = 0;
	for (i = 0; i < nzones; i++, k++) {
		if (i % zones_per_session == 0) {
			sessions[j].sendbuf = cursor;
			if (i > 0) {
				sessions[j-1].tosend = cursor 
						       - sessions[j-1].sendbuf;
				sessions[j-1].nzones = k;
				k = 0;
			}
			j++;
		}
		cursor += 2;
		*(uint16_t*)cursor = htons(i); /* ID      */ cursor += 2;
		*cursor++ = 0; *cursor++ = 0; /* Flags   */
		*cursor++ = 0; *cursor++ = 1; /* QDCOUNT */
		*cursor++ = 0; *cursor++ = 0; /* ANCOUNT */
		*cursor++ = 0; *cursor++ = 0; /* NSCOUNT */
		*cursor++ = 0; *cursor++ = 0; /* ARCOUNT */
		*cursor = (uint8_t)snprintf( (char*)cursor + 1
					   , sendbuf + bufsz - cursor
					   , "%d"
					   , i
					   );
		cursor += *cursor + 1;
		*cursor++ = 3;
		*cursor++ = 't'; *cursor++ = 'l'; *cursor++ = 'd';
		*cursor++ = 0;
		*cursor++ = 0; *cursor++ = 252; /* QTYPE: SOA */
		*cursor++ = 0; *cursor++ =   1; /* CLASS: IN  */
		*(uint16_t*)start = htons(cursor - start - 2);
		start = cursor;
	}
	if (i % zones_per_session == 0) {
		sessions[j-1].tosend = cursor - sessions[j-1].sendbuf;
		sessions[j-1].nzones = k;
	} else {
		sessions[j-2].tosend = cursor - sessions[j-2].sendbuf;
		sessions[j-2].nzones += k;
	}
	tosend = cursor - sendbuf;

	for (i = 0; i < nsessions; i++) {
		S = &sessions[i];

		memset(&hints, 0, sizeof(struct addrinfo));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;

		e = getaddrinfo(host, service, &hints, &result);
		if (e != 0) {
			fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(e));
			exit(EXIT_FAILURE);
		}

		for (rp = result; rp != NULL; rp = rp->ai_next) {
			s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
			if (s == -1)
				continue;
			if (connect(s, rp->ai_addr, rp->ai_addrlen) == 0) {
				break;
			}
			close(s);
		}
		if (rp == NULL) {
			fprintf(stderr, "Could not connect\n");
			exit(EXIT_FAILURE);
		}
		freeaddrinfo(result);

		if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {
			perror("fcntl(s, F_SETFL, O_NONBLOCK)");
		}
		S->s = s;
		S->recvptr = S->recvbuf;
		S->torecv = 0;
	}

	gettimeofday(&t, NULL);
	prev_time = t.tv_sec + t.tv_usec / 1000000.0;

	j = 0;
	while(zones_read < nzones || tosend) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		s = 0;
		for (i = 0; i < nsessions; i++) {
			S = &sessions[i];
			if (S->nzones) {
				FD_SET(sessions[i].s, &rfds);
				if (S->s > s) {
					s = S->s;
				}
			}
			if (S->tosend) {
				FD_SET(S->s, &wfds);
				if (S->s > s) {
					s = S->s;
				}
			}
		}
		e = select(s + 1, &rfds, &wfds, NULL, NULL);
		if (e == -1) {
			perror("select");
			exit(EXIT_FAILURE);
		}
		for (i = 0; i < nsessions; i++) {
			S = &sessions[i];
			if (FD_ISSET(S->s, &rfds)) {
				while (S->nzones) {
					if (S->torecv == 0) {
						S->recvptr = S->recvbuf;
						S->torecv = 2;
					}
					received = read( S->s
					               , S->recvptr
						       , S->torecv
						       );
					if (received == -1) {
						if (errno == EAGAIN 
						||  errno == EWOULDBLOCK) {
							break;
						} else {
							perror("read");
							exit(EXIT_FAILURE);
						}
					} else if (received == 0) {
						fprintf(stderr, "read done\n");
						break;
					}
					S->recvptr += received;
					S->torecv -= received;
					if (S->torecv > 0) {
						continue;
					}
					if (S->recvptr - S->recvbuf == 2) {
						S->torecv = ntohs(*(uint16_t*)
								  (char*)
								  S->recvbuf);
						continue;
					}
					S->torecv = 0;
					S->recvptr = S->recvbuf;
					S->nzones--;
					zones_read++;
				}
			}
			if (FD_ISSET(S->s, &wfds)) {
				while (S->tosend) {
					written = write( S->s
						       , S->sendbuf
						       , S->tosend
						       );
					if (written == -1) {
						if (errno == EAGAIN 
						||  errno == EINTR) {
							break;
						} else {
							perror("write");
							exit(EXIT_FAILURE);
						}
					} else if (written == 0) {
						fprintf(stderr, "write done\n");
						break;
					}
					S->sendbuf += written;
					S->tosend -= written;
					tosend -= written;
					fprintf( stderr
					       , "session %d "
					         "written %d, "
						 "remaining %d\n"
					       , i
					       , (int)written
					       , (int)S->tosend 
					       );
				}
			}
		}
		gettimeofday(&t, NULL);
		cur_time = t.tv_sec + t.tv_usec / 1000000.0;
		d_time = cur_time - prev_time;
		if (d_time >= 1) {
			
			fprintf( stderr
				, "%3d. read %4d zones, %7.2f zps\n"
				, j++
				, zones_read
				, (zones_read - prev_zones_read) / d_time
				);
			prev_zones_read = zones_read;
			prev_time = cur_time;
		}
	}
	gettimeofday(&t, NULL);
	cur_time = t.tv_sec + t.tv_usec / 1000000.0;
	d_time = cur_time - prev_time;
	fprintf( stderr
	       , "%3d. read %4d zones, %7.2f zps.\n"
	       , j++, zones_read
	       , (zones_read - prev_zones_read) / d_time
	       );
	return 0;
}

