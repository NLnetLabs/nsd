/*
 * tsig.h -- TSIG definitions (RFC 2845).
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


#include <config.h>

#ifdef TSIG

#include "tsig.h"
#include "dns.h"
#include "query.h"

struct tsig_key_table
{
	struct tsig_key_table *next;
	tsig_key_type *key;
};
typedef struct tsig_key_table tsig_key_table_type;

static region_type *tsig_region;
static tsig_key_table_type *tsig_key_table;

/* Number of supported algorithms. */
#define TSIG_ALGORITHM_COUNT 1

static tsig_algorithm_type tsig_algorithm_table[TSIG_ALGORITHM_COUNT];
const tsig_algorithm_type *tsig_algorithm_md5 = NULL;

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

int
tsig_init(region_type *region)
{
	uint8_t key_data[100];
	int key_size;
	const EVP_MD *hmac_md5_algorithm;

	tsig_region = region;
	tsig_key_table = NULL;
	
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
	tsig_algorithm_md5 = &tsig_algorithm_table[0];
	
	key_size = b64_pton("EcN8HVgD03r7kBzMZuXhhw==", key_data, sizeof(key_data));
	test_key.name = dname_parse(region, "tsig-test.", NULL);
	test_key.data = region_alloc_init(region, key_data, key_size);
	test_key.size = key_size;
	
	return 1;
}

void
tsig_add_key(tsig_key_type *key)
{
	tsig_key_table_type *entry = region_alloc(
		tsig_region, sizeof(tsig_key_table_type));
	entry->key = key;
	entry->next = tsig_key_table;
	tsig_key_table = entry;
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

void
tsig_configure_record(tsig_record_type *tsig,
		      const tsig_algorithm_type *algorithm,
		      const tsig_key_type *key)
{
	tsig->algorithm = algorithm;
	tsig->key = key;
	tsig->key_name = key->name;
	tsig->algorithm_name = algorithm->wireformat_name;
	tsig->signed_time_high = 0; /* XXX */
	tsig->signed_time_low = (uint32_t) time(NULL);
	tsig->signed_time_fudge = 300; /* XXX */
	tsig->mac_size = 0;
	tsig->mac_data = NULL;
	tsig->error_code = TSIG_ERROR_NOERROR;
	tsig->other_size = 0;
	tsig->other_data = NULL;
}

void
tsig_sign_record(tsig_record_type *tsig, buffer_type *packet)
{
	unsigned digest_size;
	uint8_t digest_data[EVP_MAX_MD_SIZE];
	tsig->original_query_id = buffer_read_u16_at(packet, 0);
	tsig_calculate_digest(
		tsig, packet, 0, NULL, &digest_size, digest_data, 1);
	tsig->mac_size = digest_size;
	tsig->mac_data = region_alloc_init(
		tsig->region, digest_data, digest_size);
}

static int
skip_dname(buffer_type *packet)
{
	while (1) {
		uint8_t label_size;
		if (!buffer_available(packet, 1))
			return 0;
		
		label_size = buffer_read_u8(packet);
		if (label_size == 0) {
			return 1;
		} else if ((label_size & 0xc0) != 0) {
			if (!buffer_available(packet, 1))
				return 0;
			buffer_skip(packet, 1);
			return 1;
		} else if (!buffer_available(packet, label_size)) {
			return 0;
		} else {
			buffer_skip(packet, label_size);
		}
	}
}

static int
skip_rr(buffer_type *packet, int question_section)
{
	if (!skip_dname(packet))
		return 0;

	if (question_section) {
		if (!buffer_available(packet, 4))
			return 0;
		buffer_skip(packet, 4);
	} else {
		uint16_t rdata_size;
		if (!buffer_available(packet, 10))
			return 0;
		buffer_skip(packet, 8);
		rdata_size = buffer_read_u16(packet);
		if (!buffer_available(packet, rdata_size))
			return 0;
		buffer_skip(packet, rdata_size);
	}

	return 1;
}

int
tsig_find_record(tsig_record_type *tsig, query_type *query)
{
	size_t saved_position = buffer_position(query->packet);
	size_t rrcount = (QDCOUNT(query) + ANCOUNT(query) +
			  NSCOUNT(query) + ARCOUNT(query));
	size_t i;
	int result;

	if (ARCOUNT(query) == 0) {
		return 0;
	}
			  
	buffer_set_position(query->packet, QHEADERSZ);

	/* TSIG must be the last record, so skip all others.  */
	for (i = 0; i < rrcount - 1; ++i) {
		if (!skip_rr(query->packet, i < QDCOUNT(query))) {
			buffer_set_position(query->packet, saved_position);
			return 0;
		}
	}

	result = tsig_parse_record(tsig, query->packet);
	buffer_set_position(query->packet, saved_position);
	return result;
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
	if (type != TYPE_TSIG || klass != CLASS_ANY) {
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
	tsig_key_table_type *key_entry;
	
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
	for (key_entry = tsig_key_table;
	     key_entry;
	     key_entry = key_entry->next)
	{
		if (dname_compare(tsig->key_name, key_entry->key->name) == 0) {
			tsig->key = key_entry->key;
		}
	}
	
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

#endif /* TSIG */
