/*
 * $Id: db.h,v 1.7 2002/01/09 15:19:50 alexis Exp $
 *
 * db.h -- nsd(8) internal namespace database
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

#include <db.h>

#define	DB_DELEGATION	1
#define	DB_WILDCARD	2

struct answer {
	size_t size;
	u_short type;
	u_short	ancount;
	u_short nscount;
	u_short arcount;
	u_short ptrlen;
	/* u_short ptrs[0]; */
};

struct domain {
	size_t size;
	u_short	flags;
};

struct db {
	DB *db;
	u_char mask[16];
};

#define	DB_PROBE(db, depth) (db->mask[depth/8] & (1 << (depth % 8)))

void db_write __P((struct db *, u_char *, struct domain *));
struct db *db_create __P((char *));
void db_close __P((struct db *));
struct db *db_open __P((char *));
struct domain *db_lookup __P((struct db *, u_char *, u_char));
/* void db_addanswer __P((struct domain *, struct message *, u_short)); */
struct domain *db_newdomain __P((u_short));
struct answer *db_answer __P((struct domain *, u_short));
void db_sync __P((struct db *));
