#
# $Id: Makefile,v 1.40 2002/02/20 14:54:25 alexis Exp $
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

# Run-time enviroment settings

# The directory where the nsd nsdc and zonec binaries will be installed
NSDBINDIR       = /usr/local/sbin

# The directory where the master zone files are located
NSDZONESDIR     = /usr/local/etc/nsd

# The file containing the list of the zones to be compiled into the NSD database
nsdzones	= /usr/local/etc/nsd/nsd.zones

# The flags to pass to the NSD on startup
NSDFLAGS        = 

# The pid file of the nsd
NSDPIDFILE      = /var/run/nsd.pid

# The NSD run-time database
NSDDB           = /var/db/nsd.db

# Compile environment settings
DEBUG=	#-g -DDEBUG=1
CC=gcc
CFLAGS= -pipe -Wall ${DEBUG} -DUSE_HEAP_HASH # -DCF_PIDFILE=\"${NSDPIDFILE}\" -DCF_DBFILE=\"${NSDDB}\" # -I/usr/local/include/db4 -DMIMIC_BIND8 -DUSE_BERKELEY_DB 
LDFLAGS= # -L/usr/local/lib -ldb4
LDADD=
LIBS =
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
	${INSTALL} nsd ${NSDBINDIR}/nsd
	${INSTALL} nsdc.sh ${NSDBINDIR}/nsdc
	${INSTALL} zonec ${NSDBINDIR}/zonec

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
