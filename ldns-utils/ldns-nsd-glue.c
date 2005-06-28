/*
 * ldns-nsd-glue.c -- compat layer between NSD and ldns
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>


#include <nsd.h>
#include <options.h>

#include <ldns/dns.h>

#include "ldns-nsd-glue.h"

/*
 * convert a ldns_rdf dname type to something
 * NSD can understand
 */
const dname_type *
ldns_dname2dname(ldns_rdf *ldns_dname)
{
	return NULL;
}

/*
 * convert a dname_type * to something
 * ldns can use
 */
const ldns_rdf *
dname2ldns_dname(const dname_type *nsd_dname)
{
	return NULL;

}

