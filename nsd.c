/*
 * $Id: nsd.c,v 1.56 2002/10/14 13:35:44 alexis Exp $
 *
 * nsd.c -- nsd(8)
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

/* The server handler... */
struct nsd nsd;
char hostname[MAXHOSTNAMELEN];

/*
 * Allocates ``size'' bytes of memory, returns the
 * pointer to the allocated memory or NULL and errno
 * set in case of error. Also reports the error via
 * syslog().
 *
 */
void *
xalloc(size)
	register size_t size;
{
	register void *p;

	if((p = malloc(size)) == NULL) {
		syslog(LOG_ERR, "malloc failed: %m");
		exit(1);
	}
	return p;
}

void *
xrealloc(p, size)
	register void *p;
	register size_t size;
{

	if((p = realloc(p, size)) == NULL) {
		syslog(LOG_ERR, "realloc failed: %m");
		exit(1);
	}
	return p;
}

int
usage()
{
	fprintf(stderr, "usage: nsd [-d] [-p port] [-i identity] [-n tcp_servers ] [-u user|uid] [-t chrootdir] -f database\n");
	exit(1);
}

pid_t
readpid(file)
	char *file;
{
	int fd;
	pid_t pid;
	char pidbuf[16];
	char *t;
	int l;

	if((fd = open(file, O_RDONLY)) == -1) {
		return -1;
	}

	if(((l = read(fd, pidbuf, sizeof(pidbuf)))) == -1) {
		close(fd);
		return -1;
	}

	close(fd);

	/* Empty pidfile means no pidfile... */
	if(l == 0) {
		errno = ENOENT;
		return -1;
	}

	pid = strtol(pidbuf, &t, 10);

	if(*t && *t != '\n') {
		return -1;
	}
	return pid;
}

int
writepid(nsd)
	struct nsd *nsd;
{
	int fd;
	char pidbuf[16];

	snprintf(pidbuf, sizeof(pidbuf), "%u\n", nsd->pid[0]);

	if((fd = open(nsd->pidfile, O_WRONLY | O_TRUNC | O_CREAT, 0644)) == -1) {
		return -1;
	}

	if((write(fd, pidbuf, strlen(pidbuf))) == -1) {
		close(fd);
		return -1;
	}
	close(fd);

	if(chown(nsd->pidfile, nsd->uid, nsd->gid) == -1) {
		syslog(LOG_ERR, "cannot chown %u.%u %s: %m", nsd->uid, nsd->gid, nsd->pidfile);
		return -1;
	}

	return 0;
}
	

void
sig_handler(sig)
	int sig;
{
	int status, i;

	/* Are we a tcp child? */
	if(nsd.pid[0] == 0) {
		switch(sig) {
		case SIGALRM:
			return;
		case SIGHUP:
		case SIGINT:
		case SIGTERM:
			nsd.mode = NSD_QUIT;
			return;
		case SIGILL:
			nsd.mode = NSD_STATS;
			return;
		}
		return;
	}

	switch(sig) {
	case SIGCHLD:
		/* Any tcp children willing to report? */
		if(waitpid(0, &status, WNOHANG) != 0) {
			if(nsd.tcp.open_conn)
				nsd.tcp.open_conn--;
		}
		return;
	case SIGHUP:
		syslog(LOG_WARNING, "signal %d received, reloading...", sig);
		nsd.mode = NSD_RELOAD;
		return;
	case SIGALRM:
#ifdef BIND8_STATS
		alarm(nsd.st.period);
#endif
		sig = SIGILL;
	case SIGILL:
		/* Dump statistics... */
		nsd.mode = NSD_STATS;
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_QUIT;
		break;
	case SIGTERM:
	default:
		nsd.mode = NSD_SHUTDOWN;
		syslog(LOG_WARNING, "signal %d received, shutting down...", sig);
		break;
	}

	/* Distribute the signal to the servers... */
	for(i = nsd.tcp.open_conn; i > 0; i--) {
		if(kill(nsd.pid[i], sig) == -1) {
			syslog(LOG_ERR, "problems killing %d: %m", nsd.pid[i]);
		}
	}
}

/*
 * Statistic output...
 *
 */
#ifdef BIND8_STATS
void
bind8_stats(nsd)
	struct nsd *nsd;
{
	time_t now;
	time(&now);

	/* NSTATS */

	/* fprintf(f, "+++ Statistics Dump +++ (%lu) %s", now, ctime(&now));
	fprintf(f, "%lu	time since boot (secs)\n", now - nsd->st.boot);
	fprintf(f, "%lu	time since reset (secs)\n", now - nsd->st.boot);
	fprintf(f, "%lu	Unknown query types\n", nsd->st.qtype[LASTELEM(nsd->st.qtype)]); */

	syslog(LOG_INFO, "NSTATS %lu %lu"
		" A=%lu NS=%lu MD=%lu MF=%lu CNAME=%lu SOA=%lu MB=%lu MG=%lu"
		" MR=%lu NULL=%lu WKS=%lu PTR=%lu HINFO=%lu MINFO=%lu MX=%lu TXT=%lu"
		" RP=%lu AFSDB=%lu X25=%lu ISDN=%lu RT=%lu NSAP=%lu NSAP_PTR=%lu SIG=%lu"
		" KEY=%lu PX=%lu GPOS=%lu AAAA=%lu LOC=%lu NXT=%lu EID=%lu NIMLOC=%lu"
		" SRV=%lu ATMA=%lu NAPTR=%lu KX=%lu CERT=%lu A6=%lu DNAME=%lu SINK=%lu"
		" OPT=%lu TYPE42=%lu TYPE43=%lu TYPE44=%lu TYPE45=%lu TYPE46=%lu TYPE47=%lu TYPE48=%lu"
		" TYPE49=%lu TYPE50=%lu TYPE51=%lu TYPE52=%lu TYPE53=%lu TYPE54=%lu TYPE55=%lu TYPE56=%lu"
		" TYPE57=%lu TYPE58=%lu TYPE59=%lu TYPE60=%lu TYPE61=%lu TYPE62=%lu TYPE63=%lu TYPE64=%lu",
		now, nsd->st.boot,
		nsd->st.qtype[1], nsd->st.qtype[2], nsd->st.qtype[3], nsd->st.qtype[4],
		nsd->st.qtype[5], nsd->st.qtype[6], nsd->st.qtype[7], nsd->st.qtype[8],
		nsd->st.qtype[9], nsd->st.qtype[10], nsd->st.qtype[11], nsd->st.qtype[12],
		nsd->st.qtype[13], nsd->st.qtype[14], nsd->st.qtype[15], nsd->st.qtype[16],
		nsd->st.qtype[17], nsd->st.qtype[18], nsd->st.qtype[19], nsd->st.qtype[20],
		nsd->st.qtype[21], nsd->st.qtype[22], nsd->st.qtype[23], nsd->st.qtype[24],
		nsd->st.qtype[25], nsd->st.qtype[26], nsd->st.qtype[27], nsd->st.qtype[28],
		nsd->st.qtype[29], nsd->st.qtype[30], nsd->st.qtype[31], nsd->st.qtype[32],
		nsd->st.qtype[33], nsd->st.qtype[34], nsd->st.qtype[35], nsd->st.qtype[36],
		nsd->st.qtype[37], nsd->st.qtype[38], nsd->st.qtype[39], nsd->st.qtype[40],
		nsd->st.qtype[41], nsd->st.qtype[42], nsd->st.qtype[43], nsd->st.qtype[44],
		nsd->st.qtype[45], nsd->st.qtype[46], nsd->st.qtype[47], nsd->st.qtype[48],
		nsd->st.qtype[49], nsd->st.qtype[50], nsd->st.qtype[51], nsd->st.qtype[52],
		nsd->st.qtype[53], nsd->st.qtype[54], nsd->st.qtype[55], nsd->st.qtype[56],
		nsd->st.qtype[57], nsd->st.qtype[58], nsd->st.qtype[59], nsd->st.qtype[60],
		nsd->st.qtype[61], nsd->st.qtype[62], nsd->st.qtype[63], nsd->st.qtype[64]);

	syslog(LOG_INFO, "NSTATS %lu %lu"
		" TYPE65=%lu TYPE66=%lu TYPE67=%lu TYPE68=%lu TYPE69=%lu TYPE70=%lu TYPE71=%lu TYPE72=%lu"
		" TYPE73=%lu TYPE74=%lu TYPE75=%lu TYPE76=%lu TYPE77=%lu TYPE78=%lu TYPE79=%lu TYPE80=%lu"
		" TYPE81=%lu TYPE82=%lu TYPE83=%lu TYPE84=%lu TYPE85=%lu TYPE86=%lu TYPE87=%lu TYPE88=%lu"
		" TYPE89=%lu TYPE90=%lu TYPE91=%lu TYPE92=%lu TYPE93=%lu TYPE94=%lu TYPE95=%lu TYPE96=%lu"
		" TYPE97=%lu TYPE98=%lu TYPE99=%lu TYPE100=%lu TYPE101=%lu TYPE102=%lu TYPE103=%lu TYPE104=%lu"
		" TYPE105=%lu TYPE106=%lu TYPE107=%lu TYPE108=%lu TYPE109=%lu TYPE110=%lu TYPE111=%lu TYPE112=%lu"
		" TYPE113=%lu TYPE114=%lu TYPE115=%lu TYPE116=%lu TYPE117=%lu TYPE118=%lu TYPE119=%lu TYPE120=%lu"
		" TYPE121=%lu TYPE122=%lu TYPE123=%lu TYPE124=%lu TYPE125=%lu TYPE126=%lu TYPE127=%lu TYPE128=%lu",
		now, nsd->st.boot,
		nsd->st.qtype[65], nsd->st.qtype[66], nsd->st.qtype[67], nsd->st.qtype[68],
		nsd->st.qtype[69], nsd->st.qtype[70], nsd->st.qtype[71], nsd->st.qtype[72],
		nsd->st.qtype[73], nsd->st.qtype[74], nsd->st.qtype[75], nsd->st.qtype[76],
		nsd->st.qtype[77], nsd->st.qtype[78], nsd->st.qtype[79], nsd->st.qtype[80],
		nsd->st.qtype[81], nsd->st.qtype[82], nsd->st.qtype[83], nsd->st.qtype[84],
		nsd->st.qtype[85], nsd->st.qtype[86], nsd->st.qtype[87], nsd->st.qtype[88],
		nsd->st.qtype[89], nsd->st.qtype[90], nsd->st.qtype[91], nsd->st.qtype[92],
		nsd->st.qtype[93], nsd->st.qtype[94], nsd->st.qtype[95], nsd->st.qtype[96],
		nsd->st.qtype[97], nsd->st.qtype[98], nsd->st.qtype[99], nsd->st.qtype[100],	
		nsd->st.qtype[101], nsd->st.qtype[102], nsd->st.qtype[103], nsd->st.qtype[104],
		nsd->st.qtype[105], nsd->st.qtype[106], nsd->st.qtype[107], nsd->st.qtype[108],
		nsd->st.qtype[109], nsd->st.qtype[110], nsd->st.qtype[111], nsd->st.qtype[112],
		nsd->st.qtype[113], nsd->st.qtype[114], nsd->st.qtype[115], nsd->st.qtype[116],
		nsd->st.qtype[117], nsd->st.qtype[118], nsd->st.qtype[119], nsd->st.qtype[120],
		nsd->st.qtype[121], nsd->st.qtype[122], nsd->st.qtype[123], nsd->st.qtype[124],
		nsd->st.qtype[125], nsd->st.qtype[126], nsd->st.qtype[127], nsd->st.qtype[128]);

	syslog(LOG_INFO, "NSTATS %lu %lu"
		" TYPE129=%lu TYPE130=%lu TYPE131=%lu TYPE132=%lu TYPE133=%lu TYPE134=%lu TYPE135=%lu TYPE136=%lu"
		" TYPE137=%lu TYPE138=%lu TYPE139=%lu TYPE140=%lu TYPE141=%lu TYPE142=%lu TYPE143=%lu TYPE144=%lu"
		" TYPE145=%lu TYPE146=%lu TYPE147=%lu TYPE148=%lu TYPE149=%lu TYPE150=%lu TYPE151=%lu TYPE152=%lu"
		" TYPE153=%lu TYPE154=%lu TYPE155=%lu TYPE156=%lu TYPE157=%lu TYPE158=%lu TYPE159=%lu TYPE160=%lu"
		" TYPE161=%lu TYPE162=%lu TYPE163=%lu TYPE164=%lu TYPE165=%lu TYPE166=%lu TYPE167=%lu TYPE168=%lu"
		" TYPE169=%lu TYPE170=%lu TYPE171=%lu TYPE172=%lu TYPE173=%lu TYPE174=%lu TYPE175=%lu TYPE176=%lu"
		" TYPE177=%lu TYPE178=%lu TYPE179=%lu TYPE180=%lu TYPE181=%lu TYPE182=%lu TYPE183=%lu TYPE184=%lu"
		" TYPE185=%lu TYPE186=%lu TYPE187=%lu TYPE188=%lu TYPE189=%lu TYPE190=%lu TYPE191=%lu TYPE192=%lu",
		now, nsd->st.boot,
		nsd->st.qtype[129], nsd->st.qtype[130], nsd->st.qtype[131], nsd->st.qtype[132],
		nsd->st.qtype[133], nsd->st.qtype[134], nsd->st.qtype[135], nsd->st.qtype[136],
		nsd->st.qtype[137], nsd->st.qtype[138], nsd->st.qtype[139], nsd->st.qtype[140],
		nsd->st.qtype[141], nsd->st.qtype[142], nsd->st.qtype[143], nsd->st.qtype[144],
		nsd->st.qtype[145], nsd->st.qtype[146], nsd->st.qtype[147], nsd->st.qtype[148],
		nsd->st.qtype[149], nsd->st.qtype[150], nsd->st.qtype[151], nsd->st.qtype[152],	
		nsd->st.qtype[153], nsd->st.qtype[154], nsd->st.qtype[155], nsd->st.qtype[156],
		nsd->st.qtype[157], nsd->st.qtype[158], nsd->st.qtype[159], nsd->st.qtype[160],
		nsd->st.qtype[161], nsd->st.qtype[162], nsd->st.qtype[163], nsd->st.qtype[164],	
		nsd->st.qtype[165], nsd->st.qtype[166], nsd->st.qtype[167], nsd->st.qtype[168],
		nsd->st.qtype[169], nsd->st.qtype[170], nsd->st.qtype[171], nsd->st.qtype[172],
		nsd->st.qtype[173], nsd->st.qtype[174], nsd->st.qtype[175], nsd->st.qtype[176],
	 	nsd->st.qtype[177], nsd->st.qtype[178], nsd->st.qtype[179], nsd->st.qtype[180],
		nsd->st.qtype[181], nsd->st.qtype[182], nsd->st.qtype[183], nsd->st.qtype[184],
		nsd->st.qtype[185], nsd->st.qtype[186], nsd->st.qtype[187], nsd->st.qtype[188],
		nsd->st.qtype[189], nsd->st.qtype[190], nsd->st.qtype[191], nsd->st.qtype[192]);

	syslog(LOG_INFO, "NSTATS %lu %lu"
		" TYPE193=%lu TYPE194=%lu TYPE195=%lu TYPE196=%lu TYPE197=%lu TYPE198=%lu TYPE199=%lu TYPE200=%lu"
		" TYPE201=%lu TYPE202=%lu TYPE203=%lu TYPE204=%lu TYPE205=%lu TYPE206=%lu TYPE207=%lu TYPE208=%lu"
		" TYPE209=%lu TYPE210=%lu TYPE211=%lu TYPE212=%lu TYPE213=%lu TYPE214=%lu TYPE215=%lu TYPE216=%lu"
		" TYPE217=%lu TYPE218=%lu TYPE219=%lu TYPE220=%lu TYPE221=%lu TYPE222=%lu TYPE223=%lu TYPE224=%lu"
		" TYPE225=%lu TYPE226=%lu TYPE227=%lu TYPE228=%lu TYPE229=%lu TYPE230=%lu TYPE231=%lu TYPE232=%lu"
		" TYPE233=%lu TYPE234=%lu TYPE235=%lu TYPE236=%lu TYPE237=%lu TYPE238=%lu TYPE239=%lu TYPE240=%lu"
		" TYPE241=%lu TYPE242=%lu TYPE243=%lu TYPE244=%lu TYPE245=%lu TYPE246=%lu TYPE247=%lu TYPE248=%lu"
		" TKEY=%lu TSIG=%lu IXFR=%lu AXFR=%lu MAILB=%lu MAILA=%lu ANY=%lu",
		now, nsd->st.boot,
		nsd->st.qtype[193], nsd->st.qtype[194], nsd->st.qtype[195], nsd->st.qtype[196],
		nsd->st.qtype[197], nsd->st.qtype[198], nsd->st.qtype[199], nsd->st.qtype[200],
		nsd->st.qtype[201], nsd->st.qtype[202], nsd->st.qtype[203], nsd->st.qtype[204],
		nsd->st.qtype[205], nsd->st.qtype[206], nsd->st.qtype[207], nsd->st.qtype[208],
	 	nsd->st.qtype[209], nsd->st.qtype[210], nsd->st.qtype[211], nsd->st.qtype[212],
		nsd->st.qtype[213], nsd->st.qtype[214], nsd->st.qtype[215], nsd->st.qtype[216],
		nsd->st.qtype[217], nsd->st.qtype[218], nsd->st.qtype[219], nsd->st.qtype[220],
		nsd->st.qtype[221], nsd->st.qtype[222], nsd->st.qtype[223], nsd->st.qtype[224],
		nsd->st.qtype[225], nsd->st.qtype[226], nsd->st.qtype[227], nsd->st.qtype[228],
		nsd->st.qtype[229], nsd->st.qtype[230], nsd->st.qtype[231], nsd->st.qtype[232],
		nsd->st.qtype[233], nsd->st.qtype[234], nsd->st.qtype[235], nsd->st.qtype[236],
		nsd->st.qtype[237], nsd->st.qtype[238], nsd->st.qtype[239], nsd->st.qtype[240],
		nsd->st.qtype[241], nsd->st.qtype[242], nsd->st.qtype[243], nsd->st.qtype[244],
		nsd->st.qtype[245], nsd->st.qtype[246], nsd->st.qtype[247], nsd->st.qtype[248],
		nsd->st.qtype[249], nsd->st.qtype[250], nsd->st.qtype[251], nsd->st.qtype[252],
		nsd->st.qtype[253], nsd->st.qtype[254], nsd->st.qtype[255]);

	/* XSTATS */
	syslog(LOG_INFO, "XSTATS %lu %lu"
		" RR=%lu RNXD=%lu RFwdR=%lu RDupR=%lu RFail=%lu RFErr=%lu RErr=%lu RAXFR=%lu"
		" RLame=%lu ROpts=%lu SSysQ=%lu SAns=%lu SFwdQ=%lu SDupQ=%lu SErr=%lu RQ=%lu"
		" RIQ=%lu RFwdQ=%lu RDupQ=%lu RTCP=%lu SFwdR=%lu SFail=%lu SFErr=%lu SNaAns=%lu"
		" SNXD=%lu RUQ=%lu RURQ=%lu RUXFR=%lu RUUpd=%lu",
		now, nsd->st.boot,
		nsd->st.dropped, (unsigned long)0, (unsigned long)0, (unsigned long)0, (unsigned long)0,
		(unsigned long)0, (unsigned long)0, nsd->st.raxfr, (unsigned long)0, (unsigned long)0,
		(unsigned long)0, nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped, (unsigned long)0,
			(unsigned long)0, nsd->st.txerr,
		nsd->st.opcode[OPCODE_QUERY], nsd->st.opcode[OPCODE_IQUERY], nsd->st.wrongzone,
			(unsigned long)0, nsd->st.ctcp + nsd->st.ctcp6,
		(unsigned long)0, nsd->st.rcode[RCODE_SERVFAIL], nsd->st.rcode[RCODE_FORMAT],
			(unsigned long)0, nsd->st.rcode[RCODE_NXDOMAIN],
		(unsigned long)0, (unsigned long)0, (unsigned long)0, nsd->st.opcode[OPCODE_UPDATE]);

}
#endif /* BIND8_STATS */

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	/* Scratch variables... */
	int i, c;
	pid_t	oldpid;

	/* Initialize the server handler... */
	bzero(&nsd, sizeof(struct nsd));
	nsd.dbfile	= CF_DBFILE;
	nsd.pidfile	= CF_PIDFILE;
	nsd.tcp.open_conn = 1;

        nsd.udp.addr.sin_addr.s_addr = INADDR_ANY;
        nsd.udp.addr.sin_port = htons(CF_UDP_PORT);
        nsd.udp.addr.sin_family = AF_INET;

        nsd.tcp.addr.sin_addr.s_addr = INADDR_ANY;
        nsd.tcp.addr.sin_port = htons(CF_TCP_PORT);
        nsd.tcp.addr.sin_family = AF_INET;

#ifdef INET6
        nsd.udp6.addr.sin6_port = htons(CF_UDP_PORT);	/* XXX: SHOULD BE CF_UDP6_PORT? */
        nsd.udp6.addr.sin6_family = AF_INET6;

        nsd.tcp6.addr.sin6_port = htons(CF_TCP_PORT);	/* XXX: SHOULD BE CF_TCP6_PORT? */
        nsd.tcp6.addr.sin6_family = AF_INET6;
#endif /* INET6 */

	nsd.tcp.max_msglen = CF_TCP_MAX_MESSAGE_LEN;
	nsd.udp.max_msglen = CF_UDP_MAX_MESSAGE_LEN;
	nsd.identity	= CF_IDENTITY;
	nsd.version	= CF_VERSION;
	nsd.username	= CF_USERNAME;
	nsd.chrootdir	= NULL;

	/* EDNS0 */
	nsd.edns.max_msglen = CF_EDNS_MAX_MESSAGE_LEN;
	nsd.edns.opt_ok[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_ok[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_ok[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_ok[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */

	nsd.edns.opt_err[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	nsd.edns.opt_err[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	nsd.edns.opt_err[3] = (nsd.edns.max_msglen & 0xff00) >> 8; 	/* size_hi */
	nsd.edns.opt_err[4] = nsd.edns.max_msglen & 0x00ff; 	/* size_lo */
	nsd.edns.opt_err[5] = 1;			/* XXX Extended RCODE=BAD VERS */

/* XXX A hack to let us compile without a change on systems which dont have LOG_PERROR option... */

#	ifndef	LOG_PERROR
#		define	LOG_PERROR 0
#	endif

#	ifndef LOG_PID
#		define LOG_PID	0
#endif

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR | LOG_PID, CF_FACILITY);

	/* Set up our default identity to gethostname(2) */
	if(gethostname(hostname, MAXHOSTNAMELEN) == 0) {
		nsd.identity = hostname;
	} else {
                syslog(LOG_ERR, "failed to get the host name: %m - using default identity");
	}


	/* Parse the command line... */
	while((c = getopt(argc, argv, "a:df:p:i:u:t:s:n:")) != -1) {
		switch (c) {
		case 'a':
			if((nsd.tcp.addr.sin_addr.s_addr = nsd.udp.addr.sin_addr.s_addr
					= inet_addr(optarg)) == -1)
				usage();
			break;
		case 'd':
			nsd.debug = 1;
			break;
		case 'f':
			nsd.dbfile = optarg;
			break;
		case 'p':
			nsd.udp.addr.sin_port = htons(atoi(optarg));
			nsd.tcp.addr.sin_port = htons(atoi(optarg));
#ifdef INET6
			nsd.udp6.addr.sin6_port = htons(atoi(optarg));
			nsd.tcp6.addr.sin6_port = htons(atoi(optarg));
#endif /* INET6 */
			break;
		case 'i':
			nsd.identity = optarg;
			break;
		case 'u':
			nsd.username = optarg;
			break;
		case 't':
			nsd.chrootdir = optarg;
			break;
		case 'n':
			i = atoi(optarg);
			if(i <= 0) {
				syslog(LOG_ERR, "max number of tcp connections must be greather than zero");
			} else if(i > CF_TCP_MAX_CONNECTIONS) {
				syslog(LOG_ERR, "max number of tcp connections must be less than %d",
					CF_TCP_MAX_CONNECTIONS);
			} else {
				nsd.tcp.open_conn = i;
			}
			break;
		case 's':
#ifdef BIND8_STATS
			nsd.st.period = atoi(optarg);
#else /* BIND8_STATS */
			syslog(LOG_ERR, "option unavailabe, recompile with -DBIND8_STATS");
#endif /* BIND8_STATS */
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if(argc != 0)
		usage();

	/* Parse the username into uid and gid */
	nsd.gid = getgid();
	nsd.uid = getuid();
	if(*nsd.username) {
		struct passwd *pwd;
		if(isdigit(*nsd.username)) {
			char *t;
			nsd.uid = strtol(nsd.username, &t, 10);
			if(*t != 0) {
				if(*t != '.' || !isdigit(*++t)) {
					syslog(LOG_ERR, "usage: -u user or -u uid  or -u uid.gid");
					exit(1);
				}
				nsd.gid = strtol(t, &t, 10);
			} else {
				/* Lookup the group id in /etc/passwd */
				if((pwd = getpwuid(nsd.uid)) == NULL) {
					syslog(LOG_ERR, "user id %d doesnt exist, will not setgid", nsd.uid);
				} else {
					nsd.gid = pwd->pw_gid;
				}
				endpwent();
			}
		} else {
			/* Lookup the user id in /etc/passwd */
			if((pwd = getpwnam(nsd.username)) == NULL) {
				syslog(LOG_ERR, "user %s doesnt exist, will not setuid", nsd.username);
			} else {
				nsd.uid = pwd->pw_uid;
				nsd.gid = pwd->pw_gid;
			}
			endpwent();
		}
	}

	/* Relativize the pathnames for chroot... */
	if(nsd.chrootdir) {
		int l = strlen(nsd.chrootdir);

		if(strncmp(nsd.chrootdir, nsd.pidfile, l) != 0) {
			syslog(LOG_ERR, "%s isnt relative to %s: wont chroot",
				nsd.pidfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		} else if(strncmp(nsd.chrootdir, nsd.dbfile, l) != 0) {
			syslog(LOG_ERR, "%s isnt relative to %s: wont chroot",
				nsd.dbfile, nsd.chrootdir);
			nsd.chrootdir = NULL;
		}
	}

	/* Do we have a running nsd? */
	if((oldpid = readpid(nsd.pidfile)) == -1) {
		if(errno != ENOENT) {
			syslog(LOG_ERR, "cant read pidfile %s: %m", nsd.pidfile);
		}
	} else {
		if(kill(oldpid, 0) == 0 || errno == EPERM) {
			syslog(LOG_ERR, "nsd is already running as %u, stopping", oldpid);
			exit(0);
		} else {
			syslog(LOG_ERR, "...stale pid file from process %u", oldpid);
		}
	}

	/* Unless we're debugging, fork... */
	if(!nsd.debug) {
		/* Take off... */
		switch((nsd.pid[0] = fork())) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "fork failed: %m");
			unlink(nsd.pidfile);
			exit(1);
		default:
			syslog(LOG_NOTICE, "nsd started, pid %d", nsd.pid[0]);
			exit(0);
		}

		/* Detach ourselves... */
		if(setsid() == -1) {
			syslog(LOG_ERR, "setsid() failed: %m");
			exit(1);
		}

		if((i = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(i, STDIN_FILENO);
			(void)dup2(i, STDOUT_FILENO);
			(void)dup2(i, STDERR_FILENO);
			if (i > 2)
				(void)close(i);
		}
	}

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGILL, &sig_handler);
	signal(SIGALRM, &sig_handler);

	/* Get our process id */
	nsd.pid[0] = getpid();

	/* Overwrite pid... */
	if(writepid(&nsd) == -1) {
		syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd.pidfile);
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	if(server_init(&nsd) != 0)
		exit(1);
	if(server_start_tcp(&nsd) != 0) {
		kill(nsd.pid[0], SIGTERM);
		exit(1);
	}

	server_udp(&nsd);

	/* NOTREACH */
	exit(0);
}
