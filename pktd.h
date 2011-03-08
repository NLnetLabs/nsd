/*
 * pktd.h -- packet decompiler definitions.
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef PKTD_H
#define PKTD_H
struct nsd;
struct query;

/** answer query with pktd */
void pktd_answer_query(struct nsd* nsd, struct query* q);

#endif /* PKTD_H */
