#
# $Id: Makefile,v 1.32 2002/02/15 19:08:47 erik Exp $
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

# Compile environment settings
DEBUG=	-g -DDEBUG=1
CC=gcc
CFLAGS= -pipe -ansi -O -Wall -W -Wunused -D_BSD_SOURCE -D_POSIX_C_SOURCE=2 -DUSE_HEAP_HASH ${DEBUG} # -I/usr/local/include/db4 -DMIMIC_BIND8 -DUSE_BERKELEY_DB 
LDFLAGS= # -L/usr/local/lib -ldb4
LDADD=
LIBS =
INSTALL = install -c

# Run-time enviroment settings
NSDBINDIR       = /home/alexis/nsd.bin
NSDZONESDIR     = /home/alexis/nsd.zones
NSDFLAGS        = 
NSDPIDFILE      = /home/alexis/nsd.run/nsd.pid
NSDDB           = /home/alexis/nsd.run/nsd.db

#
#
# NO USER FRIENDLY CHARACTERS BELOW THIS LINE
#
#
CLEANFILES+=*.core *.gmon

all:	nsd zonec #nsdc.sh

.c.o:
	${CC} -c ${CFLAGS} $<

install: nsd zonec nsdc.sh
	[ -d ${NSDBINDIR} ] || mkdir ${NSDBINDIR}
	[ -d ${NSDZONESDIR} ] || mkdir ${NSDZONESDIR}
	${INSTALL} nsd ${NSDBINDIR}/nsd
	${INSTALL} nsdc.sh ${NSDBINDIR}/nsdc
	${INSTALL} zonec ${NSDBINDIR}/zonec

nsdc.sh: nsdc.sh.in Makefile
	rm -f -- $@
	sed -e "s,@@NSDBINDIR@@,${NSDBINDIR},g" -e "s,@@NSDZONESDIR@@,${NSDZONESDIR},g" \
		-e "s,@@NSDFLAGS@@,${NSDFLAGS},g" -e "s,@@NSDPIDFILE@@,${NSDPIDFILE},g" \
		-e "s,@@NSDDB@@,${NSDDB},g" $@.in > $@
	chmod a+x $@

nsd:	nsd.h dns.h nsd.o server.o query.o dbaccess.o rbtree.o hash.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ nsd.o server.o query.o dbaccess.o rbtree.o hash.o

zonec:	zf.h dns.h zonec.h zf.o zonec.o dbcreate.o rbtree.o hash.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ zonec.o zf.o dbcreate.o rbtree.o hash.o

clean:
	rm -f zonec nsd zf hash rbtree *.o y.* core *.core *.gmon nsd.db nsd.sh

# Test programs
rbtree:	rbtree.c rbtree.h
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ rbtree.c

hash:	hash.c hash.h
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ hash.c

zf:	zf.h dns.h zf.c
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ zf.c

${OBJS}:	${HDRS}

# Dependencies
dbaccess.o: dbaccess.c namedb.h heap.h rbtree.h
dbcreate.o: dbcreate.c namedb.h heap.h rbtree.h
hash.o: hash.c hash.h
nsd.o: nsd.c nsd.h dns.h namedb.h heap.h rbtree.h query.h
query.o: query.c nsd.h dns.h namedb.h heap.h rbtree.h query.h
rbtree.o: rbtree.c rbtree.h
server.o: server.c nsd.h dns.h namedb.h heap.h rbtree.h query.h
zf.o: zf.c dns.h nsd.h namedb.h heap.h rbtree.h query.h zf.h
zonec.o: zonec.c zonec.h heap.h rbtree.h dns.h zf.h namedb.h
