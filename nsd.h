/*
 * nsd.h -- nsd(8) definitions and prototypes
 *
 * Alexis Yushin, <alexis@nlnetlabs.nl>
 *
 * Copyright (c) 2001, 2002, 2003, NLnet Labs. All rights reserved.
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

#ifndef	_NSD_H_
#define	_NSD_H_

#define	NSD_RUN	0
#define	NSD_RELOAD 1
#define	NSD_SHUTDOWN 2
#define	NSD_STATS 3
#define	NSD_QUIT 4

#define NSD_SERVER_MAIN 0x0U
#define NSD_SERVER_UDP  0x1U
#define NSD_SERVER_TCP  0x2U
#define NSD_SERVER_BOTH (NSD_SERVER_UDP | NSD_SERVER_TCP)

#ifdef INET6
#define DEFAULT_AI_FAMILY AF_UNSPEC
#else
#define DEFAULT_AI_FAMILY AF_INET
#endif

#define	OPT_LEN	11U	 /* Length of the NSD EDNS response record. */

#ifdef BIND8_STATS

/* Counter for statistics */
typedef	unsigned long stc_t;

#define	LASTELEM(arr)	(sizeof(arr) / sizeof(arr[0]) - 1)

#define	STATUP(nsd, stc) nsd->st.stc++
/* #define	STATUP2(nsd, stc, i)  ((i) <= (LASTELEM(nsd->st.stc) - 1)) ? nsd->st.stc[(i)]++ : \
				nsd->st.stc[LASTELEM(nsd->st.stc)]++ */

#define	STATUP2(nsd, stc, i) nsd->st.stc[(i) <= (LASTELEM(nsd->st.stc) - 1) ? i : LASTELEM(nsd->st.stc)]++
#else	/* BIND8_STATS */

#define	STATUP(nsd, stc) /* Nothing */
#define	STATUP2(nsd, stc, i) /* Nothing */

#endif /* BIND8_STATS */

struct nsd_socket
{
	struct addrinfo	*	addr;
	int			s;
};

struct nsd_child
{
	int   kind;
	pid_t pid;
};

/* NSD configuration and run-time variables */
struct	nsd {
	/* Run-time variables */
	pid_t		pid;
	int		mode;
	unsigned        server_kind;
	struct namedb	*db;
	int		debug;
	size_t		tcp_max_msglen;

	size_t            child_count;
	struct nsd_child *children;
	
	/* Configuration */
	const char	*dbfile;
	const char	*pidfile;
	const char	*username;
	uid_t	uid;
	gid_t	gid;
	const char	*chrootdir;
	const char	*version;
	const char	*identity;
	size_t	ifs;

	/* TCP specific configuration */
	struct nsd_socket tcp[MAX_INTERFACES];

	/* UDP specific configuration */
	struct nsd_socket udp[MAX_INTERFACES];

	struct {
		uint16_t	max_msglen;
		char		opt_ok[OPT_LEN];
		char		opt_err[OPT_LEN];
	} edns;

#ifdef	BIND8_STATS

	char	*named8_stats;

	struct nsdst {
		time_t	boot;
		int	period;		/* Produce statistics dump every st_period seconds */
		stc_t	qtype[257];	/* Counters per qtype */
		stc_t	qclass[4];	/* Class IN or Class CH or other */
		stc_t	qudp, qudp6;	/* Number of queries udp and udp6 */
		stc_t	ctcp, ctcp6;	/* Number of tcp and tcp6 connections */
		stc_t	rcode[17], opcode[6]; /* Rcodes & opcodes */
		/* Dropped, truncated, queries for nonconfigured zone, tx errors */
		stc_t	dropped, truncated, wrongzone, txerr, rxerr;
		stc_t 	edns, ednserr, raxfr, nona;
	} st;
#endif /* BIND8_STATS */
};

/* nsd.c */
pid_t readpid(const char *file);
int writepid(struct nsd *nsd);
void sig_handler(int sig);
void bind8_stats(struct nsd *nsd);

/* server.c */
int server_init(struct nsd *nsd);
void server_main(struct nsd *nsd);
void server_child(struct nsd *nsd);
  
#endif	/* _NSD_H_ */
