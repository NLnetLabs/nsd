/*
 * $Id: nsd.h,v 1.55 2003/06/16 15:13:16 erik Exp $
 *
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

#define	OPT_LEN	11U

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

/* NSD configuration and run-time variables */
struct	nsd {
	/* Run-time variables */
	pid_t		pid[TCP_MAX_CONNECTIONS + 1];
	int		mode;
	struct namedb	*db;
	int		debug;

	/* Configuration */
	const char	*dbfile;
	const char	*pidfile;
	const char	*username;
	uid_t	uid;
	gid_t	gid;
	const char	*chrootdir;
	const char	*version;
	const char	*identity;
	int	ifs;

	/* TCP specific configuration */
	struct	{
		int		open_conn;
		time_t		timeout;
		size_t		max_msglen;
		struct sockaddr_in	addr;
		int		s;
	} tcp;

	/* UDP specific configuration */
	struct	{
		struct sockaddr_in	addr;
		int		s;
	} udp[MAX_INTERFACES];

#ifdef INET6
	struct {
		struct sockaddr_in6 addr;
		int	s;
	} udp6;

	struct {
		struct sockaddr_in6 addr;
		int s;
	} tcp6;

#endif /* INET6 */

	struct {
		u_int16_t	max_msglen;
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
void *xalloc(register size_t size);
void *xrealloc(register void *p, register size_t size);
void usage(void);
pid_t readpid(const char *file);
int writepid(struct nsd *nsd);
void sig_handler(int sig);
void bind8_stats(struct nsd *nsd);

/* server.c */
int server_init(struct nsd *nsd);
int server_start_tcp(struct nsd *nsd);
void server_shutdown(struct nsd *nsd);
void server_udp(struct nsd *nsd);
void server_tcp(struct nsd *nsd);
int delete_tcp_child_pid(struct nsd *nsd, pid_t pid);
int restart_tcp_child_servers(struct nsd *nsd);
  
#endif	/* _NSD_H_ */
