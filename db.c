/*
 * $Id: db.c,v 1.2 2002/01/08 15:35:34 alexis Exp $
 *
 * db.c -- namespace database, nsd(8)
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
#include <sys/types.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <db.h>
#include "dns.h"
#include "nsd.h"
#include "zf.h"


/*
 * Opens specified database for reading
 *
 */
struct db *
db_open(filename)
	char *filename;
{
}

/*
 * Closes specified database
 *
 */
void
db_close(db)
	struct db *db;
{
}

/*
 * Creates a database and opens it for writing.
 */
struct db *
db_create(filename)
	char *filename;
{
}

/*
 * Creates a new domain in memory
 */
char *
db_newdomain(dname, dnamelen)
	char *dname;
	int dnamelen;
{
}

/*
 * Creates a new answer in memory
 *
 */
char *
db_newanswer(type)
	u_short type;
{
}

/*
 * Adds an rsset and associated glue to an answer.
 *
 * Returns number of resource records added.
 *
 */
u_short
db_addrrset(answer, rrset)
	struct answer *answer;
	struct rrset *rrset;
{
}

/*
 * Adds an answer to a domain
 *
 */
void
db_addanswer(domain, answer)
{
}

/*
 * Writes a domain into a database.
 *
 */
void
db_write(db, domain)
{
}

/*
 * Looks up domain in an open database.
 */
char *
db_lookupdomain(db, dname, dnamelen)
	struct db *db;
	char *dname;
	int dnamelen;
{
}

/*
 * Looks up type in a domain
 */
char *
db_lookuptype(domain, type)
	char *domain;
	u_short type;
{
}
