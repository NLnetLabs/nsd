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

dname_type *
ldns_dname2dname_clone(const ldns_rdf *ldns_dname)
{
	/* forget canonical name for now */
	return NULL;
}

ldns_rdf *
dname2ldns_dname_clone(const dname_type *nsd_dname)
{
	ldns_rdf *r;
	
	/* I'm subtracting 1 here - is valid because 'we' (ldns) 
	 * don't store the final null label */
	r = ldns_rdf_new_frm_data(LDNS_RDF_TYPE_DNAME, 
		(uint16_t)(dname_length(nsd_dname) - 1),
		(void*)dname_name(nsd_dname));
	return r;
}

ldns_rdf *
options_address_type2rdf_clone(nsd_options_address_type *a)
{
 	ldns_rdf *ns = NULL;

	ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_AAAA, a->address);

	if (!ns) {
		ns = ldns_rdf_new_frm_str(LDNS_RDF_TYPE_A, a->address);
		if (!ns) {
			/* all conversions failed */
			return NULL;
		}
	}
	return ns;
}
