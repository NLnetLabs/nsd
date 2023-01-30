/*
 * cat-zones.c -- generic catalog zone implementation
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include "cat-zones.h"

int
catz_consumer_member_added(catz_catalog_zone *catalog_zone,
		const catz_dname *member_id,
		const catz_dname *member_zone_name, void *arg)
{
	catz_catalog_zone *member_catalog_zone = 0;
	catz_member_zone *member_zone
		= catz_member_by_dname(member_zone_name, arg);

	if (!member_zone) {
		/* No member zone existed yet. Create a new one. */
		return catz_add_zone(member_zone_name, member_id,
				catalog_zone, arg);
	}
	/* The member already existed.
	 * Is it associated with *this* catalog zone?
	 */
	member_catalog_zone = catz_catalog_from_member(member_zone, arg);
	if (member_catalog_zone == catalog_zone) {
		/* Yes, the existing member zone is associated with
		 * this catalog zone. Is this a associated state reset?
		 */
		if (catz_dname_equal(              member_id
				    , member_zone->member_id) != 0) {

			/* Yes, the ID has changes, so state reset */
			return CATZ_ASSOCIATED_STATE_RESET;
		}
		/* No state reset, nothing changed, do nothing */
		return CATZ_SUCCESS;
	}
	/* No the existing member is associated with another catalog
	 * zone. Is this a migration?
	 */
	/* TODO: Lookup coo property, see if it points to this catalog
	 *       zone, if so, migrate the zone to this catalog,
	 *       otherwise fail because the member belongs to a
	 *       different catalog. For now we just fail.
	 */
	return CATZ_ALREADY_IN_OTHER_CATALOG;
}

int
catz_consumer_member_removed(catz_catalog_zone *catalog_zone,
		const catz_dname *member_id,
		const catz_dname *member_zone_name, void *arg)
{
	catz_catalog_zone *member_catalog_zone = 0;
	catz_member_zone *member_zone
		= catz_member_by_dname(member_zone_name, arg);

	if (!member_zone) {
		/* No member zone existed, or it wasn't associated with a
		 * catalog zone in the first place. Don't remove anything.
		 * Should this be logged? If so with a very low level (NOTICE)
		 * For now just ignore.
		 */
		return CATZ_SUCCESS;
	}
	/* The member already existed.
	 * Is it associated with *this* catalog zone?
	 */
	member_catalog_zone = catz_catalog_from_member(member_zone, arg);
	if (member_catalog_zone != catalog_zone) {
		/* No, The member is associated with a different catalog.
		 * maybe this is part of a migration.
		 * In any case, it's not associated with this catalog (anymore)
		 * so we can safely do nothing.
		 */
		return CATZ_SUCCESS;
	}
	/* Yes this member is associated with this catalog.
	 * Does the member_id match?
	 */
	if (catz_dname_equal(              member_id
			    , member_zone->member_id) != 0) {
		/* No, the member_id is different. Perhaps this zone appears
		 * twice in the catalog zone. Then this remove is at least
		 * recovering from that faulty situation.
		 * In any case, we can not remove and must do nothing.
		 */
		return CATZ_SUCCESS;
	}
	return catz_remove_zone(member_zone_name, arg);
}

