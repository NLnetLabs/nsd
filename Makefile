#
# $Id: Makefile,v 1.12 2002/01/28 16:02:59 alexis Exp $
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

DEBUG=	-g -DDEBUG=1
CC=gcc
CFLAGS= -pipe -Wall ${DEBUG} -I/usr/local/include
LDFLAGS= -L/usr/local/lib
LDADD=
LIBS =

CLEANFILES+=*.core *.gmon

all:	nsd zonec

.c.o:
	${CC} -c ${CFLAGS} $<


nsd:	nsd.h dns.h nsd.o server.o query.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ nsd.o server.o query.o -ldb3

zf:	zf.h dns.h zf.c
	${CC} ${CFLAGS} ${LDFLAGS} -DTEST -o $@ zf.c

zonec:	zf.h dns.h zonec.h zf.o dict.o zonec.o
	${CC} ${CFLAGS} ${LDFLAGS} -o $@ zonec.o zf.o dict.o -ldb3

clean:
	rm -f zf zonec nsd *.o y.* *.core *.gmon nsd.db

${OBJS}:	${HDRS}
