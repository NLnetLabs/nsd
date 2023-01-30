/*
 * cat-zones.h -- generic catalog zone implementation
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#ifndef _CAT_ZONES_H_
#define _CAT_ZONES_H_

#define CATZ_SUCCESS                   0
#define CATZ_ASSOCIATED_STATE_RESET    1
#define CATZ_NOT_IMPLEMENTED          -1
#define CATZ_ALREADY_IN_OTHER_CATALOG -2
#define CATZ_ALREADY_EXISTS           -3
/**
 * A dname. Implementation specification needed.
 */
typedef struct catz_dname catz_dname;

/**
 * A struct representing the catalog zone.
 * Implementation specification needed.
 */
typedef struct catz_catalog_zone catz_catalog_zone;

/**
 * A struct representing a member zone.
 */
typedef struct catz_member_zone {
	catz_dname *member_id; /* fqdn: <unique-1>.zones.$CATZ */
} catz_member_zone;

/**
 * Are the dnames equal. Implementation specification needed.
 *
 * @param  a  dname 1
 * @param  b  dname 2
 * @return 0  when a and b are equal
 */
int catz_dname_equal(const catz_dname *a, const catz_dname *b);

/**
 * Add this zone to the nameserver.
 *
 * @param  catalog_zone  The catalog zone which had this member added.
 * @param  member_id     Fqdn of the member zone in the catalog:
 *                       <unique-1>.zones.$CATZ
 * @param  member_zone   The name of the zone to add. This is the rdata part of
 *                       the PTR RR in the catalog zone.
 * @param  arg           Implementation specific context (for lookups etc.)
 * @return               CATZ_SUCCESS on success, otherwise error.
 */
int catz_consumer_member_added(catz_catalog_zone *catalog_zone,
	const catz_dname *member_id, const catz_dname *member_zone_name,
	void *arg);

/**
 * Remove this zone to the nameserver.
 *
 * @param  catalog_zone  The catalog zone from which this member was removed.
 * @param  member_id     Fqdn of the member zone in the catalog:
 *                       <unique-1>.zones.$CATZ
 * @param  member_zone   The name of the zone to remove. This is the rdata part
 *                       of the PTR RR in the catalog zone.
 * @param  arg           Implementation specific context (for lookups etc.)
 * @return               CATZ_SUCCESS on success, otherwise error.
 */
int catz_consumer_member_removed(catz_catalog_zone *catalog_zone,
	const catz_dname *member_id, const catz_dname *member_zone_name,
	void *arg);


/**
 * Lookup the member zone by dname.
 * Implementation needed.
 *
 * @param  member_zone_name  The name of the member zone to lookup.
 * @param  arg               Implementation specific context (for lookups etc.)
 * @return                   The member zone struct or NULL if the zone did not
 *                           exist or is not a member zone.
 */
catz_member_zone *catz_member_by_dname(
		const catz_dname *member_zone_name, void *arg);

/**
 * Get the catalog zone associated with this member zone struct.
 * Implementation needed.
 *
 * @param  member_zone  The member zone from which to get the associated
 *                      catalog.
 * @param  arg          Implementation specific context (for lookups etc.)
 * @return              The catalog zone struct. If the implementation is
 *                      consistent, this cannot be NULL.
 */
catz_catalog_zone *catz_catalog_from_member(
		const catz_member_zone *member_zone, void *arg);

/**
 * Add a new zone to the authoritative.
 * Implementation needed.
 *
 * @param  member_zone_name  Name of the zone to be added
 * @param  member_id         Id of the associated member in the catalog.
 * @param  catalog_zone      The catalog zone which already has this as member.
 *                           This can be deduced from the member_id too.
 * @param  arg               Implementation specific context (for lookups etc.)
 * @return                   CATZ_SUCCESS on succes.
 */
int catz_add_zone(const catz_dname *member_zone_name,
	const catz_dname *member_id, catz_catalog_zone *catalog_zone,
	void *arg);

/**
 * Remove a zone from the authoritative.
 * Implementation needed.
 *
 * @param  member_zone_name  Name of the zone to be removed.
 * @param  arg               Implementation specific context (for lookups etc.)
 * @return                   CATZ_SUCCESS on succes.
 */
int catz_remove_zone(const catz_dname *member_zone_name, void *arg);


#endif
