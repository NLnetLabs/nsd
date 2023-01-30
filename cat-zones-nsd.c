/*
 * cat-zones-nsd.c -- catalog zone implementation for NSD
 *
 * Copyright (c) 2023, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */

#include "cat-zones-nsd.h"

int
catz_dname_equal(const catz_dname *a, const catz_dname *b)
{
	return dname_compare(&a->dname, &b->dname);
}

catz_member_zone *
catz_member_by_dname(const catz_dname *ATTR_UNUSED(member_zone_name),
		void *ATTR_UNUSED(arg))
{

	return NULL;
}

catz_catalog_zone *
catz_catalog_from_member(const catz_member_zone *ATTR_UNUSED(member_zone),
		void *ATTR_UNUSED(arg))
{
	return NULL;
}

int
catz_add_zone(const catz_dname *ATTR_UNUSED(member_zone_name),
	const catz_dname *ATTR_UNUSED(member_id),
	catz_catalog_zone *ATTR_UNUSED(catalog_zone), void *ATTR_UNUSED(arg))
{
	return CATZ_NOT_IMPLEMENTED;
}

int
catz_remove_zone(const catz_dname *ATTR_UNUSED(member_zone_name),
	void *ATTR_UNUSED(arg))
{
	return CATZ_NOT_IMPLEMENTED;
}

