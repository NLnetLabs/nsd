#
# $Id: Makefile,v 1.78 2002/09/19 14:36:35 alexis Exp $
#
# Makefile -- one file to make them all, nsd(8)
#
# Alexis Yushin, <alexis@nlnetlabs.nl>
#
# Copyright (c) 2001, NLnet Labs. All rights reserved.
#
# This software is an open source.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# Neither the name of the NLNET LABS nor the names of its contributors may
# be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
# TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
SHELL = /bin/sh

#
#
#	LOCAL SITE CONFIGURATION
#
#

# The flags to pass to the NSD on startup
NSDFLAGS        = 

# The username for nsd to switch to before answering queries
# Either	user
#	or	id
#	or	id.gid
#
NSDUSER		= nsd

# This has to be set to the path of named-xfer program from bind if you
# want ``nsdc update'' functionality
NAMEDXFER	= /usr/libexec/named-xfer

# A directory where the crypto keys are kept. For now only used to store TSIG keys for
# named-xfer
NSDKEYSDIR	= ${NSDZONESDIR}/keys

#
# Pathnames
#

# The directory where the nsd nsdc and zonec binaries will be installed
PREFIX		= /usr/local
NSDBINDIR	= ${PREFIX}/sbin
NSDMANDIR	= ${PREFIX}/man/man8

# The directory where the master zone files are located
NSDZONESDIR     = ${PREFIX}/etc/nsd

# The file containing the list of the zones to be compiled into the NSD database
NSDZONES	= ${NSDZONESDIR}/nsd.zones

# The pid file of the nsd
NSDPIDFILE      = /var/run/nsd.pid

# The NSD run-time database
NSDDB           = ${NSDZONESDIR}/nsd.db

# The place to install nsd-notify
NSDNOTIFY	= ${NSDBINDIR}/nsd-notify

# Optional configuration file for nsdc.sh
NSDCCONF	= ${NSDZONESDIR}/nsdc.conf

#
# Use the following compile options to modify features set of NSD
#
#	-DINET6		Include IPv6 transport (tcp6 and udp6).
#
#	-DDNSSEC	Not yet implemented.
#
#	-DNAMEDB_UPPERCASE
#			Uppercase all the domain names in the internal
#			database.
#
#	-DNAMEDB_LOWERCASE	(default)
#			Lowercase all the domain names in the internal
#			database.
#
#	-DUSE_MMAP	XXX: DONT USE IT, IT IS BROKEN!!! For experimental
#			purposes only! (nsdc reload will dump core)
#
#			Use mmap() in place of malloc() to load the
#			database into memory. (Usefull for extremely
#			large databases)
#
#	-DSTRICT_MESSAGE_PARSE
#
#			Respond with ``format error'' to the queries with
#			trailing garbage, instead of stripping them.
#
#	-DDISABLE_AXFR
#			Disable AXFR zone transfers. Might be handy if
#			you dont use -DUSE_LIBWRAP
#
#	-DHOSTS_ACCESS
#			Use TCP wrappers for AXFR access control
#			Requires adding -lwrap to $LIBS
#
#	-DAXFR_DAEMON_PREFIX
#
#			Use this prefix in combination with the zone name
#			to check if a particular peer is allowed to tranfer
#			the zone.
#
#	-DLOG_NOTIFIES
#
#			Log the incoming notifies along with the remote
#			ip address.
#
#	-DNAMED8_STATS=\"/var/tmp/named.stats\"
#
#			Enable collection of statistics and dump statistics
#			into the specified file bind8 style on ``nsdc stats''.
#
#	Please see DBFLAGS below to switch the internal database type.
#
FEATURES	= -DLOG_NOTIFIES -DINET6 -DHOSTS_ACCESS -DNAMED8_STATS=\"/var/tmp/nsd.stats\"
LIBWRAP		= -lwrap

# To compile NSD with internal red-black tree database
# uncomment the following two lines
DBFLAGS		= -DUSE_HEAP_RBTREE
LIBS		= 

# To compile NSD with internal hash database
# uncomment the following two lines
#DBFLAGS	= -DUSE_HEAP_HASH
#LIBS		=

# To compile NSD with Berkeley DB uncomment the following two lines
#
# XXX Not supported at this moment, dont use it!
#
#DBFLAGS	= -I/usr/local/include/db4 -DUSE_BERKELEY_DB -DUSE_HEAP_RBTREE
#LIBS		= -L/usr/local/lib -ldb4

# Compile environment settings
DEBUG		= -pg # -g -DDEBUG=1
CC=gcc
CFLAGS		= -ansi -pipe -O6 -Wall ${DEBUG} ${DBFLAGS} ${FEATURES} \
	-DCF_PIDFILE=\"${NSDPIDFILE}\" -DCF_DBFILE=\"${NSDDB}\" -DCF_USERNAME=\"${NSDUSER}\"
LDFLAGS= ${LIBS}
INSTALL = install -c

# This might be necessary for a system like SunOS 4.x
COMPAT_O =	#	basename.o

#
#
# NO USER FRIENDLY CHARACTERS BELOW THIS LINE
#
#
CLEANFILES+=*.core *.gmon

all:	nsd zonec nsdc.sh nsd-notify nsdc.conf.sample

.c.o:
	${CC} -c ${CFLAGS} $<

install: nsd zonec nsdc.sh
	[ -d ${NSDBINDIR} ] || mkdir ${NSDBINDIR}
	[ -d ${NSDZONESDIR} ] || mkdir ${NSDZONESDIR}
	[ -d ${NSDMANDIR} ] || mkdir ${NSDMANDIR}
	${INSTALL} -s nsd ${NSDBINDIR}/nsd
	${INSTALL} -s zonec ${NSDBINDIR}/zonec
	${INSTALL} -s nsd-notify ${NSDNOTIFY}
	${INSTALL} nsdc.sh ${NSDBINDIR}/nsdc
	${INSTALL} nsd.8 ${NSDMANDIR}
	${INSTALL} nsdc.8 ${NSDMANDIR}
	${INSTALL} zonec.8 ${NSDMANDIR}

nsdc.sh: nsdc.sh.in Makefile
	rm -f $@
	sed -e "s,@@NSDBINDIR@@,${NSDBINDIR},g" -e "s,@@NSDZONESDIR@@,${NSDZONESDIR},g" \
		-e "s,@@NSDFLAGS@@,${NSDFLAGS},g" -e "s,@@NSDPIDFILE@@,${NSDPIDFILE},g" \
		-e "s,@@NSDDB@@,${NSDDB},g" -e "s,@@NSDZONES@@,${NSDZONES},g" \
		-e "s,@@NAMEDXFER@@,${NAMEDXFER},g" -e "s,@@NSDKEYSDIR@@,${NSDKEYSDIR},g" \
		-e "s,@@NSDNOTIFY@@,${NSDNOTIFY},g" -e "s,@@NSDCCONF@@,${NSDCCONF},g" $@.in > $@
	chmod a+x $@

nsdc.conf.sample: nsdc.conf.sample.in Makefile
	rm -f $@
	sed -e "s,@@NSDBINDIR@@,${NSDBINDIR},g" -e "s,@@NSDZONESDIR@@,${NSDZONESDIR},g" \
		-e "s,@@NSDFLAGS@@,${NSDFLAGS},g" -e "s,@@NSDDB@@,${NSDDB},g" \
		-e "s,@@NSDZONES@@,${NSDZONES},g" -e "s,@@NAMEDXFER@@,${NAMEDXFER},g" \
		-e "s,@@NSDKEYSDIR@@,${NSDKEYSDIR},g" -e "s,@@NSDNOTIFY@@,${NSDNOTIFY},g" $@.in > $@

nsd:	nsd.h dns.h nsd.o server.o query.o dbaccess.o rbtree.o hash.o
	${CC} ${CFLAGS} ${LDFLAGS} ${LIBWRAP} -o $@ nsd.o server.o query.o dbaccess.o rbtree.o hash.o

zonec:	zf.h dns.h zonec.h zf.o zonec.o dbcreate.o rbtree.o hash.o rfc1876.o ${COMPAT_O}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ zonec.o zf.o dbcreate.o rbtree.o hash.o rfc1876.o ${COMPAT_O}

nsd-notify:	nsd-notify.c query.o dbaccess.o zf.o rbtree.o rfc1876.o
	${CC} ${CFLAGS} ${LDFLAGS} ${LIBWRAP} -o $@ nsd-notify.c query.o dbaccess.o zf.o rbtree.o rfc1876.o

clean:
	rm -f zonec nsd zf hash rbtree nsd-notify *.o y.* *.core *.gmon nsd.db nsdc.sh nsdc.conf.sample

basename.o:	compat/basename.c
	${CC} -c ${CFLAGS} compat/basename.c -o basename.o

# Test programs
rbtree:	rbtree.c rbtree.h
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ rbtree.c

hash:	hash.c hash.h
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ hash.c

zf:	zf.h dns.h zf.c
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ zf.c

${OBJS}:	${HDRS}

# Dependencies (gcc -MM)
dbaccess.o: dbaccess.c namedb.h config.h heap.h rbtree.h
dbcreate.o: dbcreate.c namedb.h config.h heap.h rbtree.h
hash.o: hash.c hash.h
nsd.o: nsd.c nsd.h config.h dns.h namedb.h heap.h rbtree.h query.h
query.o: query.c nsd.h config.h dns.h namedb.h heap.h rbtree.h query.h
rbtree.o: rbtree.c rbtree.h
server.o: server.c nsd.h config.h dns.h namedb.h heap.h rbtree.h \
 query.h
zf.o: zf.c dns.h nsd.h config.h namedb.h heap.h rbtree.h query.h zf.h
zonec.o: zonec.c zonec.h config.h heap.h rbtree.h dns.h zf.h namedb.h
