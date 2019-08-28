/*
 * microdrill: send udp msg and print output
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

/* print error, errno(if set) and exit */
void error(const char* e)
{
	fprintf(stderr, "error: %s %s\n", e, errno?strerror(errno):"");
	exit(1);
}

/* create UDP socket to localhost */
int makefd(char* port)
{
	struct sockaddr_in sa;
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1) error("socket() failed");
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(atoi(port));
	sa.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	if(connect(fd, (struct sockaddr*)&sa, sizeof(sa)) == -1)
		error("connect() failed");
	return fd;
}

/* read and send the packet */
void sendpkt(int fd, FILE* in)
{
	char buf[65535];
	int c, sz = 0;
	while( (c=fgetc(in)) != EOF) {
		buf[sz++]=(char)c;
	}
	if(send(fd, buf, sz, 0) != sz)
		error("send() failed");
}

/* wait for activity on fd */
void waitpkt(int fd, int sec)
{
	fd_set rs, es;
	struct timeval timeout;
	int r;
	timeout.tv_sec = sec;
	timeout.tv_usec = 0;
	FD_ZERO(&rs);
	FD_SET(fd, &rs);
	FD_ZERO(&es);
	FD_SET(fd, &es);
	r = select(fd+1, &rs, NULL, &es, &timeout);
	if(r == -1)
		error("select() failed");
	if(r == 0)
		error("no reply, timed out");
}

/* receive and print reply */
void recvpkt(int fd, FILE* out)
{
	char buf[65535];
	int sz;
	sz = recv(fd, buf, sizeof(buf), 0);
	if(sz == -1) error("recv() failed");
	fwrite(buf, 1, sz, out);
}

int main(int argc, char* argv[])
{
	int fd;
	if(argc != 2)
		error("usage: <portnr> <inputfile >outputfile\n"
			"connects over UDP to 127.0.0.1@portnr");
	fd = makefd(argv[1]);
	sendpkt(fd, stdin);
	waitpkt(fd, 5);
	recvpkt(fd, stdout);
	close(fd);
	return 0;
}
