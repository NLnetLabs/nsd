/*
 * $Id: nsd.h,v 1.35 2002/09/11 13:19:35 alexis Exp $
 *
 * nsd.h -- nsd(8) definitions and prototypes
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

#ifndef	_NSD_H_
#define	_NSD_H_

#include "config.h"

#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define	NSD_RUN	0
#define	NSD_RELOAD 1
#define	NSD_SHUTDOWN 2
#define	NSD_STATS 3

#define	OPT_LEN	11

#ifdef NAMED8_STATS

typedef	unsigned long stc_t;

#define	LASTELEM(arr)	(sizeof(arr) / sizeof(arr[0]) - 1)

#define	STATUP(nsd, stc) nsd->st.stc++
#define	STATUP2(nsd, stc, i)  ((i) <= (LASTELEM(nsd->st.stc) - 1)) ? nsd->st.stc[(i)]++ : \
				nsd->st.stc[LASTELEM(nsd->st.stc)]++
#else	/* NAMED8_STATS */

#define	STATUP(nsd, stc) /* Nothing */
#define	STATUP2(nsd, stc, i) /* Nothing */

#endif /* NAMED8_STATS */

/* NSD configuration and run-time variables */
struct	nsd {
	/* Run-time variables */
	pid_t		pid;
	int		mode;
	struct namedb	*db;
	int		debug;

	/* Configuration */
	char	*dbfile;
	char	*pidfile;
	char	*username;
	uid_t	uid;
	gid_t	gid;
	char	*version;
	char	*identity;

	/* TCP specific configuration */
	struct	{
		u_int16_t	port;
		int		open_conn;
		int		max_conn;
		time_t		timeout;
		size_t		max_msglen;
		in_addr_t	addr;
	} tcp;

	/* UDP specific configuration */
	struct	{
		u_int16_t	port;
		size_t		max_msglen;
		in_addr_t	addr;
	} udp;

	struct {
		u_int16_t	max_msglen;
		char		opt_ok[OPT_LEN];
		char		opt_err[OPT_LEN];
	} edns;

#ifdef	NAMED8_STATS
	struct nsdst {
		time_t	reload;
		stc_t	qtype[4];	/* Counters per qtype */
		stc_t	qclass[257];	/* Class IN or Class CH or other */
		stc_t	qudp, qudp6;	/* Number of queries udp and udp6 */
		stc_t	ctcp, ctcp6;	/* Number of tcp and tcp6 connections */
		stc_t	rcode[17], opcode[5]; /* Rcodes & opcodes */
		/* Dropped, truncated, queries for nonconfigured zone, tx errors */
		stc_t	dropped, truncated, wrongzone, txerr;
		stc_t 	edns, ednserr;
	} st;
#endif /* NAMED8_STATS */
};

#include "dns.h"
#include "namedb.h"
#include "query.h"

void *xalloc __P((size_t));
void *xrealloc __P((void *, size_t));
int server __P((struct nsd *));
int writepid __P((struct nsd *));
void stats __P((struct nsd *, FILE *f));

#endif	/* _NSD_H_ */
