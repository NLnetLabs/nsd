/*
 * tsig.h -- TSIG definitions (RFC 2845).
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _TSIG_H_
#define _TSIG_H_

#ifdef TSIG

#include <openssl/hmac.h>

#include "dname.h"
#include "nsd.h"

#define TSIG_ERROR_NOERROR  0
#define TSIG_ERROR_BADSIG   16
#define TSIG_ERROR_BADKEY   17
#define TSIG_ERROR_BADTIME  18

enum tsig_status
{
	TSIG_NOT_PRESENT,
	TSIG_OK,
	TSIG_ERROR
};
typedef enum tsig_status tsig_status_type;

struct tsig_algorithm
{
	const char       *short_name;
	const dname_type *wireformat_name;
	const EVP_MD     *openssl_algorithm;
	size_t            digest_size;
};
typedef struct tsig_algorithm tsig_algorithm_type;

struct tsig_key
{
	const dname_type *name;
	size_t            size;
	const uint8_t    *data;
};
typedef struct tsig_key tsig_key_type;

struct tsig_record
{
	region_type      *region;
	tsig_status_type  status;
	size_t            position;
	size_t            response_count;
	HMAC_CTX          context;
	const tsig_algorithm_type *algorithm;
	const tsig_key_type *key;
	
	const dname_type *key_name;
	const dname_type *algorithm_name;
	uint16_t          signed_time_high;
	uint32_t          signed_time_low;
	uint16_t          signed_time_fudge;
	uint16_t          mac_size;
	uint8_t          *mac_data;
	uint16_t          original_query_id;
	uint16_t          error_code;
	uint16_t          other_size;
	uint8_t          *other_data;
};
typedef struct tsig_record tsig_record_type;

int tsig_init(region_type *region);

/*
 * Call this before starting to analyze a query. If the region is
 * free'd than tsig_init_record must be called again.
 */
void tsig_init_record(tsig_record_type *data, region_type *query_region);

/*
 * Call this to analyze the TSIG record starting at the current
 * location of PACKET.
 */
int tsig_parse_record(tsig_record_type *data, buffer_type *packet);

/*
 * Verify the contents of the TSIG record against the data in packet.
 */
nsd_rc_type tsig_validate_record(tsig_record_type *data, buffer_type *packet);

/*
 * Create the data necessary to include a TSIG record in the response
 * based on the data in PACKET.
 */
int tsig_update_record(tsig_record_type *data, buffer_type *packet);

/*
 * Append the TSIG record to the response.
 */
void tsig_append_record(tsig_record_type *data, buffer_type *packet);

/*
 * The amount of space to reserve in the response for the EDNS data
 * (if required).
 */
size_t tsig_reserved_space(tsig_record_type *data);

#endif /* TSIG */

#endif /* _TSIG_H_ */
