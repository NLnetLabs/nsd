/*
 * verify.c -- running verifiers and serving the zone to be verified.
 *
 * Copyright (c) 2012, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef NSD_VERIFY_H
#define NSD_VERIFY_H

struct nsd;

/*
 * verify_zones is called by a "reload-server" process (in server_reload) just
 * after the updates (transfers) from the difffile are merged in the database
 * in memory, but just before the process will begin its role as the new
 * main server process to execute verifiers on zones that need to be verified.
 */
void verify_zones(struct nsd* nsd, int cmdsocket,
		size_t* good_zones, size_t* bad_zones);

#endif /* NSD_VERIFY_H */

