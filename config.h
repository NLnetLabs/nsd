/*
 * $Id: config.h,v 1.8 2002/05/25 09:40:42 alexis Exp $
 *
 * config.h -- nsd(8) local configuration
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

#ifndef	_CONFIG_H_
#define	_CONFIG_H_

#ifndef CF_VERSION
#define	CF_VERSION	"NSD-1.0.1 Alpha"
#endif

#ifndef	CF_IDENTITY
#define	CF_IDENTITY	"unidentified nameserver"
#endif

#ifndef	CF_USERNAME
#define	CF_USERNAME	""
#endif

#ifndef	AXFR_DAEMON
#define	AXFR_DAEMON	"axfr"
#endif

#ifdef	DEBUG

#ifndef CF_DBFILE
#define	CF_DBFILE	"nsd.db"
#endif

#ifndef CF_PIDFILE
#define	CF_PIDFILE	"nsd.pid"
#endif

#define	CF_TCP_MAX_CONNECTIONS	8
#define	CF_TCP_PORT		4096
#define	CF_TCP_MAX_MESSAGE_LEN	16384
#define	CF_UDP_PORT		4096
#define	CF_UDP_MAX_MESSAGE_LEN	512
#define	CF_EDNS_MAX_MESSAGE_LEN	4096

#else	/* DEBUG */

#ifndef CF_DBFILE
#define	CF_DBFILE	"/var/db/nsd.db"
#endif

#ifndef CF_PIDFILE
#define	CF_PIDFILE	"/var/run/nsd.pid"
#endif

#define	CF_TCP_MAX_CONNECTIONS	8
#define	CF_TCP_PORT		53
#define	CF_TCP_MAX_MESSAGE_LEN	16384
#define	CF_UDP_PORT		53
#define	CF_UDP_MAX_MESSAGE_LEN	512
#define	CF_EDNS_MAX_MESSAGE_LEN	4096

#endif	/* DEBUG */

#ifdef __sun
typedef          char  int8_t;
typedef          short int16_t;
typedef          int   int32_t;
typedef unsigned char  u_int8_t;
typedef unsigned short u_int16_t;
typedef unsigned int   u_int32_t;
#endif

#ifdef __linux__
#include <sys/select.h>
#ifndef u_char_defined
typedef __u_long u_long;
typedef __u_char u_char;
#endif /* u_char */
#define u_char_defined
#endif /* __linux__ */

#endif /* _CONFIG_H_ */
