/*
 * ldns-nsd-glue.h -- compat layer between NSD and ldns
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _LDNS_NSD_GLUE_H_
#define _LDNS_NSD_GLUE_H_

/*
 * convert a ldns_rdf dname type to something
 * NSD can understand. 
 */
dname_type *ldns_dname2dname_clone(const ldns_rdf *ldns_dname);

/*
 * convert a dname_type * to something
 * ldns can use. 
 */
ldns_rdf *dname2ldns_dname_clone(const dname_type *nsd_dname);

#endif /* ! _LDNS_NSD_GLUE_H_ */
