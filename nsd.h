/*
 * nsd.h -- nsd(8) definitions and prototypes
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef	_NSD_H_
#define	_NSD_H_

#include <signal.h>

#include "dns.h"
#include "edns.h"
#include "options.h"

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
	 /* The type of child process (UDP or TCP handler). */
	int   kind;

	/* The child's process id.  */
	pid_t pid;
};

/* NSD configuration and run-time variables */
typedef struct nsd nsd_type;
struct	nsd
{
	/*
	 * Global region that is not deallocated until NSD shuts down.
	 */
	region_type    *region;

	/* Run-time variables */
	pid_t		pid;
	volatile sig_atomic_t mode;
	unsigned        server_kind;
	struct namedb	*db;
	int		debug;

	/*
	 * Number of servers is specified in the 'options'
	 * structure.
	 */
	struct nsd_child *children;

	/* Configuration */
	const char       *options_file;
	nsd_options_type *options;

	uid_t	uid;
	gid_t	gid;
	const char	*chrootdir;

	size_t	ifs;

	/* TCP specific configuration */
	struct nsd_socket tcp[MAX_INTERFACES];

	/* UDP specific configuration */
	struct nsd_socket udp[MAX_INTERFACES];

	edns_data_type edns_ipv4;
#if defined(INET6)
	edns_data_type edns_ipv6;
#endif

	/* Maximum is specified in the 'options' structure.  */
	size_t current_tcp_connection_count;

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
