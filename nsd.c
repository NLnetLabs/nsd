/*
 * $Id: nsd.c,v 1.45 2002/09/11 13:58:34 alexis Exp $
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
	fprintf(stderr, "usage: nsd [-d] [-p port] [-n identity] [-u user|uid] -f database\n");
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

	snprintf(pidbuf, sizeof(pidbuf), "%u\n", nsd->pid);

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
	int status;
	switch(sig) {
	case SIGCHLD:
		/* Any tcp children willing to report? */
		if(waitpid(0, &status, WNOHANG) != 0) {
			if(nsd.tcp.open_conn)
				nsd.tcp.open_conn--;
		}
		break;
	case SIGHUP:
		syslog(LOG_WARNING, "signal %d received, reloading...", sig);
		nsd.mode = NSD_RELOAD;
		break;
	case SIGINT:
		/* Silent shutdown... */
		nsd.mode = NSD_SHUTDOWN;
		break;
	case SIGILL:
		/* Dump statistics... */
		nsd.mode = NSD_STATS;
		break;
	case SIGTERM:
	default:
		syslog(LOG_WARNING, "signal %d received, shutting down...", sig);
		nsd.mode = NSD_SHUTDOWN;
		break;
		
	}
}

/*
 * Statistic output...
 *
 */
#ifdef NAMED8_STATS
void
stats(nsd, f)
	struct nsd *nsd;
	FILE *f;
{
	time_t now;

	/* Get the current time... */
	time(&now);

	/* Produce BIND8 like statistics */
	fprintf(f, "+++ Statistics Dump +++ (%lu) %s", now, ctime(&now));
	fprintf(f, "%lu	time since boot (secs)\n", now - nsd->st.reload);
	fprintf(f, "%lu	time since reset (secs)\n", now - nsd->st.reload);
	fprintf(f, "%lu	Unknown query types\n", nsd->st.qtype[LASTELEM(nsd->st.qtype)]);
	fprintf(f, "%lu	A queries\n", nsd->st.qtype[1]);
	fprintf(f, "%lu	NS queries\n", nsd->st.qtype[2]);
	fprintf(f, "%lu	MD queries\n", nsd->st.qtype[3]);
	fprintf(f, "%lu	MF queries\n", nsd->st.qtype[4]);
	fprintf(f, "%lu	CNAME queries\n", nsd->st.qtype[5]);
	fprintf(f, "%lu	SOA queries\n", nsd->st.qtype[6]);
	fprintf(f, "%lu	MB queries\n", nsd->st.qtype[7]);
	fprintf(f, "%lu	MG queries\n", nsd->st.qtype[8]);
	fprintf(f, "%lu	MR queries\n", nsd->st.qtype[9]);
	fprintf(f, "%lu	NULL queries\n", nsd->st.qtype[10]);
	fprintf(f, "%lu	WKS queries\n", nsd->st.qtype[11]);
	fprintf(f, "%lu	PTR queries\n", nsd->st.qtype[12]);
	fprintf(f, "%lu	HINFO queries\n", nsd->st.qtype[13]);
	fprintf(f, "%lu	MINFO queries\n", nsd->st.qtype[14]);
	fprintf(f, "%lu	MX queries\n", nsd->st.qtype[15]);
	fprintf(f, "%lu	TXT queries\n", nsd->st.qtype[16]);
	fprintf(f, "%lu	RP queries\n", nsd->st.qtype[17]);
	fprintf(f, "%lu	AFSDB queries\n", nsd->st.qtype[18]);
	fprintf(f, "%lu	X25 queries\n", nsd->st.qtype[19]);
	fprintf(f, "%lu	ISDN queries\n", nsd->st.qtype[20]);
	fprintf(f, "%lu	RT queries\n", nsd->st.qtype[21]);
	fprintf(f, "%lu	NSAP queries\n", nsd->st.qtype[22]);
	fprintf(f, "%lu	NSAP_PTR queries\n", nsd->st.qtype[23]);
	fprintf(f, "%lu	SIG queries\n", nsd->st.qtype[24]);
	fprintf(f, "%lu	KEY queries\n", nsd->st.qtype[25]);
	fprintf(f, "%lu	PX queries\n", nsd->st.qtype[26]);
	fprintf(f, "%lu	GPOS queries\n", nsd->st.qtype[27]);
	fprintf(f, "%lu	AAAA queries\n", nsd->st.qtype[28]);
	fprintf(f, "%lu	LOC queries\n", nsd->st.qtype[29]);
	fprintf(f, "%lu	NXT queries\n", nsd->st.qtype[30]);
	fprintf(f, "%lu	EID queries\n", nsd->st.qtype[31]);
	fprintf(f, "%lu	NIMLOC queries\n", nsd->st.qtype[32]);
	fprintf(f, "%lu	SRV queries\n", nsd->st.qtype[33]);
	fprintf(f, "%lu	ATMA queries\n", nsd->st.qtype[34]);
	fprintf(f, "%lu	NAPTR queries\n", nsd->st.qtype[35]);
	fprintf(f, "%lu	KX queries\n", nsd->st.qtype[36]);
	fprintf(f, "%lu	CERT queries\n", nsd->st.qtype[37]);
	fprintf(f, "%lu	A6 queries\n", nsd->st.qtype[38]);
	fprintf(f, "%lu	DNAME queries\n", nsd->st.qtype[39]);
	fprintf(f, "%lu	SINK queries\n", nsd->st.qtype[40]);
	fprintf(f, "%lu	OPT queries\n", nsd->st.qtype[41]);
	fprintf(f, "%lu	TYPE42 queries\n", nsd->st.qtype[42]);
	fprintf(f, "%lu	TYPE43 queries\n", nsd->st.qtype[43]);
	fprintf(f, "%lu	TYPE44 queries\n", nsd->st.qtype[44]);
	fprintf(f, "%lu	TYPE45 queries\n", nsd->st.qtype[45]);
	fprintf(f, "%lu	TYPE46 queries\n", nsd->st.qtype[46]);
	fprintf(f, "%lu	TYPE47 queries\n", nsd->st.qtype[47]);
	fprintf(f, "%lu	TYPE48 queries\n", nsd->st.qtype[48]);
	fprintf(f, "%lu	TYPE49 queries\n", nsd->st.qtype[49]);
	fprintf(f, "%lu	TYPE50 queries\n", nsd->st.qtype[50]);
	fprintf(f, "%lu	TYPE51 queries\n", nsd->st.qtype[51]);
	fprintf(f, "%lu	TYPE52 queries\n", nsd->st.qtype[52]);
	fprintf(f, "%lu	TYPE53 queries\n", nsd->st.qtype[53]);
	fprintf(f, "%lu	TYPE54 queries\n", nsd->st.qtype[54]);
	fprintf(f, "%lu	TYPE55 queries\n", nsd->st.qtype[55]);
	fprintf(f, "%lu	TYPE56 queries\n", nsd->st.qtype[56]);
	fprintf(f, "%lu	TYPE57 queries\n", nsd->st.qtype[57]);
	fprintf(f, "%lu	TYPE58 queries\n", nsd->st.qtype[58]);
	fprintf(f, "%lu	TYPE59 queries\n", nsd->st.qtype[59]);
	fprintf(f, "%lu	TYPE60 queries\n", nsd->st.qtype[60]);
	fprintf(f, "%lu	TYPE61 queries\n", nsd->st.qtype[61]);
	fprintf(f, "%lu	TYPE62 queries\n", nsd->st.qtype[62]);
	fprintf(f, "%lu	TYPE63 queries\n", nsd->st.qtype[63]);
	fprintf(f, "%lu	TYPE64 queries\n", nsd->st.qtype[64]);
	fprintf(f, "%lu	TYPE65 queries\n", nsd->st.qtype[65]);
	fprintf(f, "%lu	TYPE66 queries\n", nsd->st.qtype[66]);
	fprintf(f, "%lu	TYPE67 queries\n", nsd->st.qtype[67]);
	fprintf(f, "%lu	TYPE68 queries\n", nsd->st.qtype[68]);
	fprintf(f, "%lu	TYPE69 queries\n", nsd->st.qtype[69]);
	fprintf(f, "%lu	TYPE70 queries\n", nsd->st.qtype[70]);
	fprintf(f, "%lu	TYPE71 queries\n", nsd->st.qtype[71]);
	fprintf(f, "%lu	TYPE72 queries\n", nsd->st.qtype[72]);
	fprintf(f, "%lu	TYPE73 queries\n", nsd->st.qtype[73]);
	fprintf(f, "%lu	TYPE74 queries\n", nsd->st.qtype[74]);
	fprintf(f, "%lu	TYPE75 queries\n", nsd->st.qtype[75]);
	fprintf(f, "%lu	TYPE76 queries\n", nsd->st.qtype[76]);
	fprintf(f, "%lu	TYPE77 queries\n", nsd->st.qtype[77]);
	fprintf(f, "%lu	TYPE78 queries\n", nsd->st.qtype[78]);
	fprintf(f, "%lu	TYPE79 queries\n", nsd->st.qtype[79]);
	fprintf(f, "%lu	TYPE80 queries\n", nsd->st.qtype[80]);
	fprintf(f, "%lu	TYPE81 queries\n", nsd->st.qtype[81]);
	fprintf(f, "%lu	TYPE82 queries\n", nsd->st.qtype[82]);
	fprintf(f, "%lu	TYPE83 queries\n", nsd->st.qtype[83]);
	fprintf(f, "%lu	TYPE84 queries\n", nsd->st.qtype[84]);
	fprintf(f, "%lu	TYPE85 queries\n", nsd->st.qtype[85]);
	fprintf(f, "%lu	TYPE86 queries\n", nsd->st.qtype[86]);
	fprintf(f, "%lu	TYPE87 queries\n", nsd->st.qtype[87]);
	fprintf(f, "%lu	TYPE88 queries\n", nsd->st.qtype[88]);
	fprintf(f, "%lu	TYPE89 queries\n", nsd->st.qtype[89]);
	fprintf(f, "%lu	TYPE90 queries\n", nsd->st.qtype[90]);
	fprintf(f, "%lu	TYPE91 queries\n", nsd->st.qtype[91]);
	fprintf(f, "%lu	TYPE92 queries\n", nsd->st.qtype[92]);
	fprintf(f, "%lu	TYPE93 queries\n", nsd->st.qtype[93]);
	fprintf(f, "%lu	TYPE94 queries\n", nsd->st.qtype[94]);
	fprintf(f, "%lu	TYPE95 queries\n", nsd->st.qtype[95]);
	fprintf(f, "%lu	TYPE96 queries\n", nsd->st.qtype[96]);
	fprintf(f, "%lu	TYPE97 queries\n", nsd->st.qtype[97]);
	fprintf(f, "%lu	TYPE98 queries\n", nsd->st.qtype[98]);
	fprintf(f, "%lu	TYPE99 queries\n", nsd->st.qtype[99]);
	fprintf(f, "%lu	TYPE100 queries\n", nsd->st.qtype[100]);
	fprintf(f, "%lu	TYPE101 queries\n", nsd->st.qtype[101]);
	fprintf(f, "%lu	TYPE102 queries\n", nsd->st.qtype[102]);
	fprintf(f, "%lu	TYPE103 queries\n", nsd->st.qtype[103]);
	fprintf(f, "%lu	TYPE104 queries\n", nsd->st.qtype[104]);
	fprintf(f, "%lu	TYPE105 queries\n", nsd->st.qtype[105]);
	fprintf(f, "%lu	TYPE106 queries\n", nsd->st.qtype[106]);
	fprintf(f, "%lu	TYPE107 queries\n", nsd->st.qtype[107]);
	fprintf(f, "%lu	TYPE108 queries\n", nsd->st.qtype[108]);
	fprintf(f, "%lu	TYPE109 queries\n", nsd->st.qtype[109]);
	fprintf(f, "%lu	TYPE110 queries\n", nsd->st.qtype[110]);
	fprintf(f, "%lu	TYPE111 queries\n", nsd->st.qtype[111]);
	fprintf(f, "%lu	TYPE112 queries\n", nsd->st.qtype[112]);
	fprintf(f, "%lu	TYPE113 queries\n", nsd->st.qtype[113]);
	fprintf(f, "%lu	TYPE114 queries\n", nsd->st.qtype[114]);
	fprintf(f, "%lu	TYPE115 queries\n", nsd->st.qtype[115]);
	fprintf(f, "%lu	TYPE116 queries\n", nsd->st.qtype[116]);
	fprintf(f, "%lu	TYPE117 queries\n", nsd->st.qtype[117]);
	fprintf(f, "%lu	TYPE118 queries\n", nsd->st.qtype[118]);
	fprintf(f, "%lu	TYPE119 queries\n", nsd->st.qtype[119]);
	fprintf(f, "%lu	TYPE120 queries\n", nsd->st.qtype[120]);
	fprintf(f, "%lu	TYPE121 queries\n", nsd->st.qtype[121]);
	fprintf(f, "%lu	TYPE122 queries\n", nsd->st.qtype[122]);
	fprintf(f, "%lu	TYPE123 queries\n", nsd->st.qtype[123]);
	fprintf(f, "%lu	TYPE124 queries\n", nsd->st.qtype[124]);
	fprintf(f, "%lu	TYPE125 queries\n", nsd->st.qtype[125]);
	fprintf(f, "%lu	TYPE126 queries\n", nsd->st.qtype[126]);
	fprintf(f, "%lu	TYPE127 queries\n", nsd->st.qtype[127]);
	fprintf(f, "%lu	TYPE128 queries\n", nsd->st.qtype[128]);
	fprintf(f, "%lu	TYPE129 queries\n", nsd->st.qtype[129]);
	fprintf(f, "%lu	TYPE130 queries\n", nsd->st.qtype[130]);
	fprintf(f, "%lu	TYPE131 queries\n", nsd->st.qtype[131]);
	fprintf(f, "%lu	TYPE132 queries\n", nsd->st.qtype[132]);
	fprintf(f, "%lu	TYPE133 queries\n", nsd->st.qtype[133]);
	fprintf(f, "%lu	TYPE134 queries\n", nsd->st.qtype[134]);
	fprintf(f, "%lu	TYPE135 queries\n", nsd->st.qtype[135]);
	fprintf(f, "%lu	TYPE136 queries\n", nsd->st.qtype[136]);
	fprintf(f, "%lu	TYPE137 queries\n", nsd->st.qtype[137]);
	fprintf(f, "%lu	TYPE138 queries\n", nsd->st.qtype[138]);
	fprintf(f, "%lu	TYPE139 queries\n", nsd->st.qtype[139]);
	fprintf(f, "%lu	TYPE140 queries\n", nsd->st.qtype[140]);
	fprintf(f, "%lu	TYPE141 queries\n", nsd->st.qtype[141]);
	fprintf(f, "%lu	TYPE142 queries\n", nsd->st.qtype[142]);
	fprintf(f, "%lu	TYPE143 queries\n", nsd->st.qtype[143]);
	fprintf(f, "%lu	TYPE144 queries\n", nsd->st.qtype[144]);
	fprintf(f, "%lu	TYPE145 queries\n", nsd->st.qtype[145]);
	fprintf(f, "%lu	TYPE146 queries\n", nsd->st.qtype[146]);
	fprintf(f, "%lu	TYPE147 queries\n", nsd->st.qtype[147]);
	fprintf(f, "%lu	TYPE148 queries\n", nsd->st.qtype[148]);
	fprintf(f, "%lu	TYPE149 queries\n", nsd->st.qtype[149]);
	fprintf(f, "%lu	TYPE150 queries\n", nsd->st.qtype[150]);
	fprintf(f, "%lu	TYPE151 queries\n", nsd->st.qtype[151]);
	fprintf(f, "%lu	TYPE152 queries\n", nsd->st.qtype[152]);
	fprintf(f, "%lu	TYPE153 queries\n", nsd->st.qtype[153]);
	fprintf(f, "%lu	TYPE154 queries\n", nsd->st.qtype[154]);
	fprintf(f, "%lu	TYPE155 queries\n", nsd->st.qtype[155]);
	fprintf(f, "%lu	TYPE156 queries\n", nsd->st.qtype[156]);
	fprintf(f, "%lu	TYPE157 queries\n", nsd->st.qtype[157]);
	fprintf(f, "%lu	TYPE158 queries\n", nsd->st.qtype[158]);
	fprintf(f, "%lu	TYPE159 queries\n", nsd->st.qtype[159]);
	fprintf(f, "%lu	TYPE160 queries\n", nsd->st.qtype[160]);
	fprintf(f, "%lu	TYPE161 queries\n", nsd->st.qtype[161]);
	fprintf(f, "%lu	TYPE162 queries\n", nsd->st.qtype[162]);
	fprintf(f, "%lu	TYPE163 queries\n", nsd->st.qtype[163]);
	fprintf(f, "%lu	TYPE164 queries\n", nsd->st.qtype[164]);
	fprintf(f, "%lu	TYPE165 queries\n", nsd->st.qtype[165]);
	fprintf(f, "%lu	TYPE166 queries\n", nsd->st.qtype[166]);
	fprintf(f, "%lu	TYPE167 queries\n", nsd->st.qtype[167]);
	fprintf(f, "%lu	TYPE168 queries\n", nsd->st.qtype[168]);
	fprintf(f, "%lu	TYPE169 queries\n", nsd->st.qtype[169]);
	fprintf(f, "%lu	TYPE170 queries\n", nsd->st.qtype[170]);
	fprintf(f, "%lu	TYPE171 queries\n", nsd->st.qtype[171]);
	fprintf(f, "%lu	TYPE172 queries\n", nsd->st.qtype[172]);
	fprintf(f, "%lu	TYPE173 queries\n", nsd->st.qtype[173]);
	fprintf(f, "%lu	TYPE174 queries\n", nsd->st.qtype[174]);
	fprintf(f, "%lu	TYPE175 queries\n", nsd->st.qtype[175]);
	fprintf(f, "%lu	TYPE176 queries\n", nsd->st.qtype[176]);
	fprintf(f, "%lu	TYPE177 queries\n", nsd->st.qtype[177]);
	fprintf(f, "%lu	TYPE178 queries\n", nsd->st.qtype[178]);
	fprintf(f, "%lu	TYPE179 queries\n", nsd->st.qtype[179]);
	fprintf(f, "%lu	TYPE180 queries\n", nsd->st.qtype[180]);
	fprintf(f, "%lu	TYPE181 queries\n", nsd->st.qtype[181]);
	fprintf(f, "%lu	TYPE182 queries\n", nsd->st.qtype[182]);
	fprintf(f, "%lu	TYPE183 queries\n", nsd->st.qtype[183]);
	fprintf(f, "%lu	TYPE184 queries\n", nsd->st.qtype[184]);
	fprintf(f, "%lu	TYPE185 queries\n", nsd->st.qtype[185]);
	fprintf(f, "%lu	TYPE186 queries\n", nsd->st.qtype[186]);
	fprintf(f, "%lu	TYPE187 queries\n", nsd->st.qtype[187]);
	fprintf(f, "%lu	TYPE188 queries\n", nsd->st.qtype[188]);
	fprintf(f, "%lu	TYPE189 queries\n", nsd->st.qtype[189]);
	fprintf(f, "%lu	TYPE190 queries\n", nsd->st.qtype[190]);
	fprintf(f, "%lu	TYPE191 queries\n", nsd->st.qtype[191]);
	fprintf(f, "%lu	TYPE192 queries\n", nsd->st.qtype[192]);
	fprintf(f, "%lu	TYPE193 queries\n", nsd->st.qtype[193]);
	fprintf(f, "%lu	TYPE194 queries\n", nsd->st.qtype[194]);
	fprintf(f, "%lu	TYPE195 queries\n", nsd->st.qtype[195]);
	fprintf(f, "%lu	TYPE196 queries\n", nsd->st.qtype[196]);
	fprintf(f, "%lu	TYPE197 queries\n", nsd->st.qtype[197]);
	fprintf(f, "%lu	TYPE198 queries\n", nsd->st.qtype[198]);
	fprintf(f, "%lu	TYPE199 queries\n", nsd->st.qtype[199]);
	fprintf(f, "%lu	TYPE200 queries\n", nsd->st.qtype[200]);
	fprintf(f, "%lu	TYPE201 queries\n", nsd->st.qtype[201]);
	fprintf(f, "%lu	TYPE202 queries\n", nsd->st.qtype[202]);
	fprintf(f, "%lu	TYPE203 queries\n", nsd->st.qtype[203]);
	fprintf(f, "%lu	TYPE204 queries\n", nsd->st.qtype[204]);
	fprintf(f, "%lu	TYPE205 queries\n", nsd->st.qtype[205]);
	fprintf(f, "%lu	TYPE206 queries\n", nsd->st.qtype[206]);
	fprintf(f, "%lu	TYPE207 queries\n", nsd->st.qtype[207]);
	fprintf(f, "%lu	TYPE208 queries\n", nsd->st.qtype[208]);
	fprintf(f, "%lu	TYPE209 queries\n", nsd->st.qtype[209]);
	fprintf(f, "%lu	TYPE210 queries\n", nsd->st.qtype[210]);
	fprintf(f, "%lu	TYPE211 queries\n", nsd->st.qtype[211]);
	fprintf(f, "%lu	TYPE212 queries\n", nsd->st.qtype[212]);
	fprintf(f, "%lu	TYPE213 queries\n", nsd->st.qtype[213]);
	fprintf(f, "%lu	TYPE214 queries\n", nsd->st.qtype[214]);
	fprintf(f, "%lu	TYPE215 queries\n", nsd->st.qtype[215]);
	fprintf(f, "%lu	TYPE216 queries\n", nsd->st.qtype[216]);
	fprintf(f, "%lu	TYPE217 queries\n", nsd->st.qtype[217]);
	fprintf(f, "%lu	TYPE218 queries\n", nsd->st.qtype[218]);
	fprintf(f, "%lu	TYPE219 queries\n", nsd->st.qtype[219]);
	fprintf(f, "%lu	TYPE220 queries\n", nsd->st.qtype[220]);
	fprintf(f, "%lu	TYPE221 queries\n", nsd->st.qtype[221]);
	fprintf(f, "%lu	TYPE222 queries\n", nsd->st.qtype[222]);
	fprintf(f, "%lu	TYPE223 queries\n", nsd->st.qtype[223]);
	fprintf(f, "%lu	TYPE224 queries\n", nsd->st.qtype[224]);
	fprintf(f, "%lu	TYPE225 queries\n", nsd->st.qtype[225]);
	fprintf(f, "%lu	TYPE226 queries\n", nsd->st.qtype[226]);
	fprintf(f, "%lu	TYPE227 queries\n", nsd->st.qtype[227]);
	fprintf(f, "%lu	TYPE228 queries\n", nsd->st.qtype[228]);
	fprintf(f, "%lu	TYPE229 queries\n", nsd->st.qtype[229]);
	fprintf(f, "%lu	TYPE230 queries\n", nsd->st.qtype[230]);
	fprintf(f, "%lu	TYPE231 queries\n", nsd->st.qtype[231]);
	fprintf(f, "%lu	TYPE232 queries\n", nsd->st.qtype[232]);
	fprintf(f, "%lu	TYPE233 queries\n", nsd->st.qtype[233]);
	fprintf(f, "%lu	TYPE234 queries\n", nsd->st.qtype[234]);
	fprintf(f, "%lu	TYPE235 queries\n", nsd->st.qtype[235]);
	fprintf(f, "%lu	TYPE236 queries\n", nsd->st.qtype[236]);
	fprintf(f, "%lu	TYPE237 queries\n", nsd->st.qtype[237]);
	fprintf(f, "%lu	TYPE238 queries\n", nsd->st.qtype[238]);
	fprintf(f, "%lu	TYPE239 queries\n", nsd->st.qtype[239]);
	fprintf(f, "%lu	TYPE240 queries\n", nsd->st.qtype[240]);
	fprintf(f, "%lu	TYPE241 queries\n", nsd->st.qtype[241]);
	fprintf(f, "%lu	TYPE242 queries\n", nsd->st.qtype[242]);
	fprintf(f, "%lu	TYPE243 queries\n", nsd->st.qtype[243]);
	fprintf(f, "%lu	TYPE244 queries\n", nsd->st.qtype[244]);
	fprintf(f, "%lu	TYPE245 queries\n", nsd->st.qtype[245]);
	fprintf(f, "%lu	TYPE246 queries\n", nsd->st.qtype[246]);
	fprintf(f, "%lu	TYPE247	queries\n", nsd->st.qtype[247]);
	fprintf(f, "%lu	TYPE248 queries\n", nsd->st.qtype[248]);
	fprintf(f, "%lu	TKEY queries\n", nsd->st.qtype[249]);
	fprintf(f, "%lu	TSIG queries\n", nsd->st.qtype[250]);
	fprintf(f, "%lu	IXFR queries\n", nsd->st.qtype[251]);
	fprintf(f, "%lu	AXFR queries\n", nsd->st.qtype[252]);
	fprintf(f, "%lu	MAILB queries\n", nsd->st.qtype[253]);
	fprintf(f, "%lu	MAILA queries\n", nsd->st.qtype[254]);
	fprintf(f, "%lu	ANY queries\n", nsd->st.qtype[255]);
	fprintf(f, "++ Name Server Statistics ++\n");
	fprintf(f, "(Legend)\n");
	fprintf(f, "	RR	RNXD	RFwdR	RDupR	RFail\n");
	fprintf(f, "	RFErr	RErr	RAXFR	RLame	ROpts\n");
	fprintf(f, "	SSysQ	SAns	SFwdQ	SDupQ	SErr\n");
	fprintf(f, "	RQ	RIQ	RFwdQ	RDupQ	RTCP\n");
	fprintf(f, "	SFwdR	SFail	SFErr	SNaAns	SNXD\n");
	fprintf(f, "	RUQ	RURQ	RUXFR	RUUpd\n");
	fprintf(f, "(Global)\n");
	fprintf(f, "	%lu %lu %lu %lu %lu", nsd->st.dropped, (unsigned long)0, (unsigned long)0,
			(unsigned long)0, (unsigned long)0);
	fprintf(f, "  %lu %lu %lu %lu %lu", (unsigned long)0, (unsigned long)0, (unsigned long)0, (unsigned long)0,
			(unsigned long)0);
	fprintf(f, "  %lu %lu %lu %lu %lu", (unsigned long)0, nsd->st.qudp + nsd->st.qudp6 - nsd->st.dropped,
			(unsigned long)0, (unsigned long)0, nsd->st.txerr);
	fprintf(f, "  %lu %lu %lu %lu %lu", nsd->st.opcode[OPCODE_QUERY], nsd->st.opcode[OPCODE_IQUERY],
			(unsigned long)0, (unsigned long)0, nsd->st.ctcp + nsd->st.ctcp6);
	fprintf(f, "  %lu %lu %lu %lu %lu\n", (unsigned long)0,
			nsd->st.rcode[RCODE_SERVFAIL], nsd->st.rcode[RCODE_FORMAT],
						(unsigned long)0, nsd->st.rcode[RCODE_NXDOMAIN]);
	fprintf(f, "  %lu %lu %lu %lu\n", (unsigned long)0, (unsigned long)0, (unsigned long)0,
			nsd->st.opcode[OPCODE_UPDATE]);
	fprintf(f, "-- Name Server Statistics --\n");
	fprintf(f, "--- Statistics Dump --- (%lu) %s", now, ctime(&now));
}
#endif /* NAMED8_STATS */

extern char *optarg;
extern int optind;

int
main(argc, argv)
	int argc;
	char *argv[];
{
	/* Scratch variables... */
	int fd, c;
	pid_t	oldpid;

	/* Initialize the server handler... */
	bzero(&nsd, sizeof(struct nsd));
	nsd.dbfile	= CF_DBFILE;
	nsd.pidfile	= CF_PIDFILE;
	nsd.tcp.port	= CF_TCP_PORT;
	nsd.tcp.addr	= INADDR_ANY;
	nsd.tcp.max_conn = CF_TCP_MAX_CONNECTIONS;
	nsd.tcp.max_msglen = CF_TCP_MAX_MESSAGE_LEN;
	nsd.udp.port	= CF_UDP_PORT;
	nsd.udp.addr	= INADDR_ANY;
	nsd.udp.max_msglen = CF_UDP_MAX_MESSAGE_LEN;
	nsd.identity	= CF_IDENTITY;
	nsd.version	= CF_VERSION;
	nsd.username	= CF_USERNAME;

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

	/* Set up the logging... */
	openlog("nsd", LOG_PERROR, CF_FACILITY);

	/* Set up our default identity to gethostname(2) */
	if(gethostname(hostname, MAXHOSTNAMELEN) == 0) {
		nsd.identity = hostname;
	} else {
                syslog(LOG_ERR, "failed to get the host name: %m - using default identity");
	}


	/* Parse the command line... */
	while((c = getopt(argc, argv, "a:df:p:i:u:")) != -1) {
		switch (c) {
		case 'a':
			if((nsd.tcp.addr = nsd.udp.addr = inet_addr(optarg)) == -1)
				usage();
			break;
		case 'd':
			nsd.debug = 1;
			break;
		case 'f':
			nsd.dbfile = optarg;
			break;
		case 'p':
			nsd.udp.port = atoi(optarg);
			nsd.tcp.port = atoi(optarg);
			break;
		case 'i':
			nsd.identity = optarg;
			break;
		case 'u':
			nsd.username = optarg;
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
		switch((nsd.pid = fork())) {
		case 0:
			break;
		case -1:
			syslog(LOG_ERR, "fork failed: %m");
			unlink(nsd.pidfile);
			exit(1);
		default:
			syslog(LOG_NOTICE, "nsd started, pid %d", nsd.pid);
			exit(0);
		}

		/* Detach ourselves... */
		if(setsid() == -1) {
			syslog(LOG_ERR, "setsid() failed: %m");
			exit(1);
		}

		if((fd = open("/dev/null", O_RDWR, 0)) != -1) {
			(void)dup2(fd, STDIN_FILENO);
			(void)dup2(fd, STDOUT_FILENO);
			(void)dup2(fd, STDERR_FILENO);
			if (fd > 2)
				(void)close(fd);
		}
	}

	/* Setup the signal handling... */
	signal(SIGTERM, &sig_handler);
	signal(SIGHUP, &sig_handler);
	signal(SIGCHLD, &sig_handler);
	signal(SIGINT, &sig_handler);
	signal(SIGILL, &sig_handler);

	/* Get our process id */
	nsd.pid = getpid();

	/* Overwrite pid... */
	if(writepid(&nsd) == -1) {
		syslog(LOG_ERR, "cannot overwrite the pidfile %s: %m", nsd.pidfile);
	}

	/* Initialize... */
	nsd.mode = NSD_RUN;

	/* Run the server... */
	server(&nsd);

	/* Not needed since we terminate anyway... */
	/* namedb_close(nsd.db); */

	if((fd = open(nsd.pidfile, O_WRONLY | O_TRUNC, 0644)) == -1) {
		syslog(LOG_ERR, "canot truncate the pid file %s: %m", nsd.pidfile);
	}
	close(fd);

	exit(0);
}
