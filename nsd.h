/*
 * $Id: nsd.h,v 1.4 2002/01/28 16:02:59 alexis Exp $
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
#if !defined(__P)
#	if defined(__STDC__)
#		define __P(protos)     protos          /* full-blown ANSI C */
# 	else
# 		define __P(protos)
# 	endif
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <db3/db.h>

#include "dns.h"
#include "namedb.h"
#include "query.h"

#define	NCLASS_IN	_nshorts[1]	/* Class IN */
#define	NCLASS_ANY	_nshorts[255]	/* Class IN */

#define NTYPE_A		_nshorts[1]	/* a host address */
#define NTYPE_NS	_nshorts[2]	/* an authoritative name server */
#define NTYPE_MD	_nshorts[3]	/* a mail destination (Obsolete - use MX) */
#define NTYPE_MF	_nshorts[4]	/* a mail forwarder (Obsolete - use MX) */
#define NTYPE_CNAME	_nshorts[5]	/* the canonical name for an alias */
#define NTYPE_SOA	_nshorts[6]	/* marks the start of a zone of authority */
#define NTYPE_MB	_nshorts[7]	/* a mailbox domain name (EXPERIMENTAL) */
#define NTYPE_MG	_nshorts[8]	/* a mail group member (EXPERIMENTAL) */
#define NTYPE_MR	_nshorts[9]	/* a mail rename domain name (EXPERIMENTAL) */
#define NTYPE_NULL	_nshorts[10]	/* a null RR (EXPERIMENTAL) */
#define NTYPE_WKS	_nshorts[11]	/* a well known service description */
#define NTYPE_PTR	_nshorts[12]	/* a domain name pointer */
#define NTYPE_HINFO	_nshorts[13]	/* host information */
#define NTYPE_MINFO	_nshorts[14]	/* mailbox or mail list information */
#define NTYPE_MX	_nshorts[15]	/* mail exchange */
#define NTYPE_TXT	_nshorts[16]	/* text strings */
#define NTYPE_AAAA	_nshorts[28]	/* ipv6 address */
#define	NTYPE_AXFR	_nshorts[252]
#define	NTYPE_IXFR	_nshorts[251]
#define	NTYPE_MAILB	_nshorts[253] 	/* A request for mailbox-related records (MB, MG or MR) */
#define	NTYPE_MAILA	_nshorts[254]	/* A request for mail agent RRs (Obsolete - see MX) */
#define NTYPE_ANY	_nshorts[255]	/* any type (wildcard) */

#define	NSHORTSLEN	256

extern u_char authmask[NAMEDB_BITMASKLEN];
extern u_char datamask[NAMEDB_BITMASKLEN];
extern u_char starmask[NAMEDB_BITMASKLEN];

void *xalloc __P((size_t));
void *xrealloc __P((void *, size_t));
int server __P((u_short, DB *));
struct domain *lookup __P((DB *, u_char *, int));
