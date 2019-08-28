/*
 * reflect.c : send a few packets to hit a very low ratelmit, and report.
 * LICENSE see the tarball license (BSD licensed).
 * Copyright 2012, Wouter Wijngaards, NLnet Labs.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

static FILE* out;

static void fatal(const char* s)
{
	fprintf(out, "fatal: %s %s\n", s, strerror(errno));
	exit(1);
}

static void sendpkts(int num, int s, struct sockaddr_in* sa, socklen_t salen)
{
	int i;
	/* DNS query to send */
	/* drill -q blabla nxdomain.example.nl IN A */
	unsigned char buf[] = {
		0x85, 0x54, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x08, 0x6e, 0x78, 0x64,
		0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x07, 0x65, 0x78,
		0x61, 0x6d, 0x70, 0x6c, 0x65, 0x02, 0x6e, 0x6c,
		0x00, 0x00, 0x01, 0x00, 0x01
	};
	for(i=0; i<num; i++) {
		if(sendto(s, buf, sizeof(buf), 0, (struct sockaddr*)sa,
			salen) < 0)
			fatal("sendto()");
	}
}

static void runtest(int port, int numsec, int qps)
{
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in sa;
	time_t start;
	if(s == -1) fatal("socket()");
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
	if(bind(s, (struct sockaddr*)&sa, (socklen_t)sizeof(sa)) < 0)
		fatal("bind()");
	sa.sin_port = htons(port);

	start = time(NULL);
	while(time(NULL) < start+numsec) {
		time_t pre = time(NULL), post;
		sendpkts(qps, s, &sa, (socklen_t)sizeof(sa));
		sendpkts(qps, s, &sa, (socklen_t)sizeof(sa));
		post = time(NULL);
		/* we have to send qps in this one second */
		if(post != pre) fatal("could not achieve rate");
		/* wait for the next second */
		if(time(NULL) < start+numsec)
			sleep(1);
	}
	fprintf(out, "rate %d has been reached\n", qps);

	close(s);
}

int main(int argc, const char** argv)
{
	/* <port> <numseconds> <qps> <output> */
	int port, numsec, qps;
	const char* outf;
	out = stdout;
	if(argc != 5)
		fatal("wrong arguments: <port> <numseconds> <qps> <output>");
	port = atoi(argv[1]);
	numsec = atoi(argv[2]);
	qps = atoi(argv[3]);
	outf = argv[4];
	out = fopen(outf, "a");
	if(!out) fatal("could not open output file");
	if(numsec > 10000) fatal("numsec too large");
	if(qps > 1000) fatal("qps too large");
	runtest(port, numsec, qps);
	fprintf(out, "done\n");
	fclose(out);
	return 0;
}

