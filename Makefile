#
# $Id: Makefile,v 1.67 2002/05/30 13:07:56 alexis Exp $
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
#	or	user.group
#	or	id
#	or	id.gid
#
NSDUSER		= nobody

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
NSDZONES	= ${PREFIX}/etc/nsd/nsd.zones

# The pid file of the nsd
NSDPIDFILE      = /var/run/nsd.pid

# The NSD run-time database
NSDDB           = /var/db/nsd.db

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
#			puposes only! (nsdc reload will dump core)
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
#	Please see DBFLAGS below to switch the internal database type.
#
FEATURES	= -DINET6 -DHOSTS_ACCESS

# To compile NSD with internal red-black tree database
# uncomment the following two lines
DBFLAGS		= -DUSE_HEAP_RBTREE
LIBS		= -lwrap

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
DEBUG		= # -g -DDEBUG=1
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

all:	nsd zonec nsdc.sh

.c.o:
	${CC} -c ${CFLAGS} $<

install: nsd zonec nsdc.sh
	[ -d ${NSDBINDIR} ] || mkdir ${NSDBINDIR}
	[ -d ${NSDZONESDIR} ] || mkdir ${NSDZONESDIR}
	[ -d ${NSDMANDIR} ] || mkdir ${NSDMANDIR}
	${INSTALL} nsd ${NSDBINDIR}/nsd
	${INSTALL} nsdc.sh ${NSDBINDIR}/nsdc
	${INSTALL} zonec ${NSDBINDIR}/zonec
	${INSTALL} nsd.8 ${NSDMANDIR}
	${INSTALL} nsdc.8 ${NSDMANDIR}
	${INSTALL} zonec.8 ${NSDMANDIR}

nsdc.sh: nsdc.sh.in Makefile
	rm -f $@
	sed -e "s,@@NSDBINDIR@@,${NSDBINDIR},g" -e "s,@@NSDZONESDIR@@,${NSDZONESDIR},g" \
		-e "s,@@NSDFLAGS@@,${NSDFLAGS},g" -e "s,@@NSDPIDFILE@@,${NSDPIDFILE},g" \
		-e "s,@@NSDDB@@,${NSDDB},g" -e "s,@@NSDZONES@@,${NSDZONES},g" $@.in > $@
	chmod a+x $@

nsd:	nsd.h dns.h nsd.o server.o query.o dbaccess.o rbtree.o hash.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ nsd.o server.o query.o dbaccess.o rbtree.o hash.o

zonec:	zf.h dns.h zonec.h zf.o zonec.o dbcreate.o rbtree.o hash.o ${COMPAT_O}
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ zonec.o zf.o dbcreate.o rbtree.o hash.o ${COMPAT_O}

clean:
	rm -f zonec nsd zf hash rbtree *.o y.* *.core *.gmon nsd.db nsdc.sh

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
