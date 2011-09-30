/*
 * nsec4.h -- nsec4 handling.
 *
 * Copyright (c) 2001-2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef NSEC4_H
#define NSEC4_H

#include <config.h>
#ifdef NSEC4

struct domain;
struct dname;
struct region;
struct zone;
struct namedb;
struct query;
struct answer;

/*
 * Create the hashed name of the nsec4 record
 * for the given dname.
 */
const struct dname *nsec4_hash_dname(struct region *region,
	struct zone *zone, const struct dname *dname);

/*
 * calculate prehash information for all zones,
 * selects only updated=1 zones if bool set.
 */
void nsec4_prehash(struct namedb* db, int updated_only);

/*
 * finds nsec4 that covers the given domain dname.
 * returns true if the find is exact.
 * hashname is the already hashed dname for the NSEC4.
 */
int nsec4_find_cover(struct namedb* db, struct zone* zone,
	const struct dname* hashname, struct domain** result);

/*
 * _answer_ Routines used to add the correct nsec4 record to a query answer.
 * cnames etc may have been followed, hence original name.
 */
/*
 * add proof for wildcards that the name below the wildcard.parent
 * does not exist
 */
void nsec4_answer_wildcard(struct query *query, struct answer *answer,
        struct domain *wildcard, struct namedb* db,
	const struct dname *qname);

/*
 * add nsec4 to provide domain name but not rrset exists,
 * this could be a query for a DS or NSEC4 type
 */
void nsec4_answer_nodata(struct query *query, struct answer *answer,
	struct domain *original);

/*
 * add nsec4 for a delegation (optout stuff)
 */
void nsec4_answer_delegation(struct query *query, struct answer *answer);

/*
 * add nsec4 for authoritative answers.
 * match==0 is an nxdomain.
 */
void nsec4_answer_authoritative(struct domain** match, struct query *query,
	struct answer *answer, struct domain* closest_encloser,
	struct namedb* db, const struct dname* qname);

/*
 * True if domain is a nsec4 (+RRSIG) data only variety.
 * pass nonNULL zone to filter for particular zone.
 */
int domain_has_only_NSEC4(struct domain* domain, struct zone* zone);

#endif /* NSEC4 */
#endif /* NSEC4_H*/
