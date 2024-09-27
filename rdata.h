/*
 * rdata.h -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef RDATA_H
#define RDATA_H

#include "dns.h"
#include "namedb.h"

/* High bit of the APL length field is the negation bit.  */
#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

extern lookup_table_type dns_certificate_types[];
extern lookup_table_type dns_algorithms[];
extern const char *svcparamkey_strs[];

int print_unknown_rdata(
	buffer_type *output, rrtype_descriptor_type *descriptor, const rr_type *rr);

/* print rdata to a text string (as for a zone file) returns 0
  on a failure (bufpos is reset to original position).
  returns 1 on success, bufpos is moved. */
int print_rdata(
	buffer_type *output, rrtype_descriptor_type *descriptor, const rr_type *rr);

#endif /* RDATA_H */
