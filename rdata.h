/*
 * rdata.h -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _RDATA_H_
#define _RDATA_H_

#include "buffer.h"
#include "dns.h"
#include "namedb.h"

extern lookup_table_type dns_certificate_types[];
extern lookup_table_type dns_algorithms[];

int rdata_atom_to_string(buffer_type *output, rdata_zoneformat_type type,
			 rdata_atom_type rdata);

/*
 * Split the wireformat RDATA into an array of rdata atoms. Domain
 * names are inserted into the OWNERS table. The number of rdata atoms
 * is returned and the array itself is allocated in REGION and stored
 * in RDATAS.
 *
 * Returns -1 on failure.
 */
ssize_t rdata_wireformat_to_rdata_atoms(region_type *region,
					domain_table_type *owners,
					uint16_t rrtype,
					uint16_t rdata_size,
					buffer_type *packet,
					rdata_atom_type **rdatas);
	
#endif /* _DNS_H_ */
