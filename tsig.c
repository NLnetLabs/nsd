/*
 * tsig.h -- TSIG definitions (RFC 2845).
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


#include <config.h>

#include "buffer.h"
#include "region-allocator.h"
#include "tsig.h"
#include "query.h"

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

/* Number of supported algorithms. */
#define TSIG_ALGORITHM_COUNT 1

static tsig_algorithm_type tsig_algorithm_table[TSIG_ALGORITHM_COUNT];

static tsig_key_type test_key;

static void
print_hex(FILE *out, const unsigned char *data, size_t size)
{
    static char hexdigits[] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    size_t i;
    
    for (i = 0; i < size; ++i) {
        fputc(hexdigits[data[i] >> 4], out);
        fputc(hexdigits[data[i] & 0xf], out);
    }
}

int
tsig_init(region_type *region)
{
	uint8_t key_data[100];
	int key_size;
	const EVP_MD *hmac_md5_algorithm;
	
	OpenSSL_add_all_digests();
	hmac_md5_algorithm = EVP_get_digestbyname("md5");
	if (!hmac_md5_algorithm) {
		log_msg(LOG_ERR, "hmac-md5 algorithm not available");
		return 0;
	}
	
	tsig_algorithm_table[0].short_name = "hmac-md5";
	tsig_algorithm_table[0].wireformat_name
		= dname_parse(region, "hmac-md5.sig-alg.reg.int.", NULL);
	tsig_algorithm_table[0].openssl_algorithm = hmac_md5_algorithm;
	tsig_algorithm_table[0].digest_size = 16;

	key_size = b64_pton("EcN8HVgD03r7kBzMZuXhhw==", key_data, sizeof(key_data));
	test_key.name = dname_parse(region, "tsig-test.", NULL);
	test_key.data = region_alloc_init(region, key_data, key_size);
	test_key.size = key_size;
	
	return 1;
}

void
tsig_init_record(tsig_record_type *tsig, region_type *query_region)
{
	tsig->region = query_region;
	tsig->status = TSIG_NOT_PRESENT;
	tsig->position = 0;
	tsig->response_count = 0;
	tsig->algorithm = NULL;
	tsig->key = NULL;
}

int
tsig_parse_record(tsig_record_type *tsig, buffer_type *packet)
{
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t rdlen;

	tsig->position = buffer_position(packet);
	
	tsig->key_name = dname_make_from_packet(tsig->region, packet, 1, 1);
	if (!tsig->key_name) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}

	if (!buffer_available(packet, 10)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}

	type = buffer_read_u16(packet);
	klass = buffer_read_u16(packet);
	if (type == TYPE_TSIG && klass == CLASS_ANY) {
		tsig->status = TSIG_OK;
	} else {
		buffer_set_position(packet, tsig->position);
		return 0;
	}
	
	ttl = buffer_read_u32(packet);
	rdlen = buffer_read_u16(packet);
	
	tsig->status = TSIG_ERROR;
	if (ttl != 0 || !buffer_available(packet, rdlen)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}

	tsig->algorithm_name = dname_make_from_packet(tsig->region, packet, 1, 1);
	if (!tsig->algorithm_name || !buffer_available(packet, 10)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}

	tsig->signed_time_high = buffer_read_u16(packet);
	tsig->signed_time_low = buffer_read_u32(packet);
	tsig->signed_time_fudge = buffer_read_u16(packet);
	tsig->mac_size = buffer_read_u16(packet);
	if (!buffer_available(packet, tsig->mac_size)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}
	tsig->mac_data = region_alloc_init(
		tsig->region, buffer_current(packet), tsig->mac_size);
	buffer_skip(packet, tsig->mac_size);
	if (!buffer_available(packet, 6)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}
	tsig->original_query_id = buffer_read_u16(packet);
	tsig->error_code = buffer_read_u16(packet);
	tsig->other_size = buffer_read_u16(packet);
	if (!buffer_available(packet, tsig->other_size))
	{
		buffer_set_position(packet, tsig->position);
		return 0;
	}
	tsig->other_data = region_alloc_init(
		tsig->region, buffer_current(packet), tsig->other_size);
	buffer_skip(packet, tsig->other_size);
	tsig->status = TSIG_OK;

	fprintf(stderr, "tsig: %s ", dname_to_string(tsig->key_name));
	fprintf(stderr, "%s\n", dname_to_string(tsig->algorithm_name));
	
	return 1;
}

static void
tsig_calculate_digest(tsig_record_type *tsig, buffer_type *packet,
		      size_t request_digest_size, uint8_t *request_digest_data,
		      unsigned *digest_size, uint8_t *digest_data,
		      int tsig_timers_only)
{
	uint16_t original_query_id = htons(tsig->original_query_id);
	uint16_t klass = htons(CLASS_ANY);
	uint32_t ttl = htonl(0);
	uint16_t signed_time_high = htons(tsig->signed_time_high);
	uint32_t signed_time_low = htonl(tsig->signed_time_low);
	uint16_t signed_time_fudge = htons(tsig->signed_time_fudge);
	uint16_t error_code = htons(tsig->error_code);
	uint16_t other_size = htons(tsig->other_size);
	
	HMAC_Init_ex(&tsig->context, tsig->key->data, tsig->key->size,
		     tsig_algorithm_table[0].openssl_algorithm, NULL);

	if (request_digest_data) {
		uint16_t mac_size = htons(request_digest_size);
		HMAC_Update(&tsig->context, (uint8_t *) &mac_size,
			    sizeof(mac_size));
		HMAC_Update(&tsig->context, request_digest_data,
			    request_digest_size);
	}
	
	HMAC_Update(&tsig->context, (uint8_t *) &original_query_id,
		    sizeof(original_query_id));
	HMAC_Update(&tsig->context,
		    buffer_at(packet, sizeof(original_query_id)),
		    buffer_position(packet) - sizeof(original_query_id));

	if (!tsig_timers_only) {
		HMAC_Update(&tsig->context, dname_name(tsig->key_name),
			    tsig->key_name->name_size);
		HMAC_Update(&tsig->context, (uint8_t *) &klass, sizeof(klass));
		HMAC_Update(&tsig->context, (uint8_t *) &ttl, sizeof(ttl));
		HMAC_Update(&tsig->context, dname_name(tsig->algorithm_name),
			    tsig->algorithm_name->name_size);
	}
	HMAC_Update(&tsig->context, (uint8_t *) &signed_time_high,
		    sizeof(signed_time_high));
	HMAC_Update(&tsig->context, (uint8_t *) &signed_time_low,
		    sizeof(signed_time_low));
	HMAC_Update(&tsig->context, (uint8_t *) &signed_time_fudge,
		    sizeof(signed_time_fudge));
	if (!tsig_timers_only) {
		HMAC_Update(&tsig->context, (uint8_t *) &error_code,
			    sizeof(error_code));
		HMAC_Update(&tsig->context, (uint8_t *) &other_size,
			    sizeof(other_size));
		HMAC_Update(&tsig->context, tsig->other_data, tsig->other_size);
	}
	
	HMAC_Final(&tsig->context, digest_data, digest_size);

	fprintf(stderr, "tsig: calculated digest: ");
	print_hex(stderr, digest_data, *digest_size);
	fprintf(stderr, "\n");
}

static void
tsig_cleanup_hmac_context(void *data)
{
	HMAC_CTX *context = (HMAC_CTX *) data;
	HMAC_CTX_cleanup(context);
}

nsd_rc_type
tsig_validate_record(tsig_record_type *tsig, buffer_type *packet)
{
	unsigned digest_size;
	uint8_t digest_data[EVP_MAX_MD_SIZE];
	size_t i;

	assert(tsig->status == TSIG_OK);
	assert(!tsig->algorithm);
	assert(!tsig->key);
	
	for (i = 0; i < TSIG_ALGORITHM_COUNT; ++i) {
		if (dname_compare(tsig->algorithm_name,
				  tsig_algorithm_table[i].wireformat_name) == 0)
		{
			tsig->algorithm = &tsig_algorithm_table[i];
			break;
		}
	}

	/* XXX: Todo */
	tsig->key = &test_key;
	
	if (!tsig->algorithm || !tsig->key) {
		/* Algorithm or key is unknown, cannot authenticate.  */
		tsig->error_code = TSIG_ERROR_BADKEY;
		return NSD_RC_NOTAUTH;
	}
	
	HMAC_CTX_init(&tsig->context);
	region_add_cleanup(tsig->region,
			   tsig_cleanup_hmac_context,
			   &tsig->context);
	
	fprintf(stderr, "tsig: expected digest: ");
	print_hex(stderr, tsig->mac_data, tsig->mac_size);
	fprintf(stderr, "\n");
	tsig_calculate_digest(tsig, packet, 0, NULL, &digest_size, digest_data, 0);
	if (digest_size == tsig->mac_size
	    && memcmp(digest_data, tsig->mac_data, digest_size) == 0)
	{
		return NSD_RC_OK;
	} else {
		/* Digest is incorrect, cannot authenticate.  */
		tsig->error_code = TSIG_ERROR_BADSIG;
		return NSD_RC_NOTAUTH;
	}
}

int
tsig_update_record(tsig_record_type *tsig, buffer_type *packet)
{
	unsigned digest_size;
	uint8_t digest_data[EVP_MAX_MD_SIZE];

	if (!tsig->algorithm || !tsig->key) {
		tsig->mac_size = 0;
		tsig->mac_data = region_alloc(tsig->region, 0);
	} else {
		tsig_calculate_digest(tsig, packet,
				      tsig->mac_size, tsig->mac_data,
				      &digest_size, digest_data,
				      tsig->response_count > 0);
		
		tsig->mac_size = digest_size;
		tsig->mac_data = region_alloc_init(
			tsig->region, digest_data, digest_size);
	}
	++tsig->response_count;
	
	return 1;
}

void
tsig_append_record(tsig_record_type *tsig, buffer_type *packet)
{
	size_t rdlength_pos;

	/* XXX: key name compression? */
	buffer_write(packet, dname_name(tsig->key_name),
		     tsig->key_name->name_size);
	buffer_write_u16(packet, TYPE_TSIG);
	buffer_write_u16(packet, CLASS_ANY);
	buffer_write_u32(packet, 0); /* TTL */
	rdlength_pos = buffer_position(packet);
	buffer_skip(packet, sizeof(uint16_t));
	buffer_write(packet, dname_name(tsig->algorithm_name),
		     tsig->algorithm_name->name_size);
	buffer_write_u16(packet, tsig->signed_time_high);
	buffer_write_u32(packet, tsig->signed_time_low);
	buffer_write_u16(packet, tsig->signed_time_fudge);
	buffer_write_u16(packet, tsig->mac_size);
	buffer_write(packet, tsig->mac_data, tsig->mac_size);
	buffer_write_u16(packet, tsig->original_query_id);
	buffer_write_u16(packet, tsig->error_code);
	buffer_write_u16(packet, tsig->other_size);
	buffer_write(packet, tsig->other_data, tsig->other_size);

	buffer_write_u16_at(packet, rdlength_pos,
			    buffer_position(packet) - rdlength_pos
			    - sizeof(uint16_t));
}

size_t
tsig_reserved_space(tsig_record_type *tsig)
{
	if (tsig->status == TSIG_NOT_PRESENT)
		return 0;

	return (tsig->key_name->name_size   /* Owner */
		+ sizeof(uint16_t)	    /* Type */
		+ sizeof(uint16_t)	    /* Class */
		+ sizeof(uint32_t)	    /* TTL */
		+ sizeof(uint16_t)	    /* RDATA length */
		+ tsig->algorithm_name->name_size
		+ sizeof(uint16_t)	    /* Signed time (high) */
		+ sizeof(uint32_t)	    /* Signed time (low) */
		+ sizeof(uint16_t)	    /* Signed time fudge */
		+ sizeof(uint16_t)	    /* MAC size */
		+ tsig->algorithm->digest_size /* MAC data */
		+ sizeof(uint16_t)	    /* Original query ID */
		+ sizeof(uint16_t)	    /* Error code */
		+ sizeof(uint16_t)	    /* Other size */
		+ tsig->other_size);	    /* Other data */
}
