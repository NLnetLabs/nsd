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

/* parseip4 */
int parseip(char* s)
{
	int ip = 0;
	if(strchr(s, '.')) {
		int i;
		uint8_t b[4];
		char* p, *n;
		n = s;
		for(i=0; i<4; i++) {
			p = strchr(n, '.');
			if(p)
				*p = 0;
			b[i] = atoi(n);
			if(p)
				*p = '.';
			if(p)
				n = p+1;
		}
		ip = (b[0]<<24) | (b[1]<<16) | (b[2]<<8) | (b[3]);
	} else {
		ip = atoi(s);
	}
	return ip;
}

/* create UDP socket to localhost@port, ip@port, ip@53 */
int makefd(char* spec)
{
	int port = 53;
	int ip4 = 0x7f000001; /* 127.0.0.1 */
	struct sockaddr_in sa;
	int fd = -1;
	if(strchr(spec, '@')) {
		char* p = strchr(spec, '@');
		port = atoi(p+1);
		*p = 0;
		ip4 = parseip(spec);
		*p = '@';
	} else if(strchr(spec, '.')) {
		ip4 = parseip(spec);
	} else {
		port = atoi(spec);
	}
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd == -1) error("socket() failed");
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	sa.sin_addr.s_addr = htonl(ip4);
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
		error("usage: <dest> <inputfile >outputfile\n"
			"connects over UDP to dest: portnr, ip@port, ip");
	fd = makefd(argv[1]);
	sendpkt(fd, stdin);
	waitpkt(fd, 5);
	recvpkt(fd, stdout);
	close(fd);
	return 0;
}
