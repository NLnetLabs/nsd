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
tsig_digest_variables(tsig_record_type *tsig, int tsig_timers_only)
{
	uint16_t klass = htons(CLASS_ANY);
	uint32_t ttl = htonl(0);
	uint16_t signed_time_high = htons(tsig->signed_time_high);
	uint32_t signed_time_low = htonl(tsig->signed_time_low);
	uint16_t signed_time_fudge = htons(tsig->signed_time_fudge);
	uint16_t error_code = htons(tsig->error_code);
	uint16_t other_size = htons(tsig->other_size);
	
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
}

int
tsig_init(region_type *region)
{
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

const char *
tsig_error(int error_code)
{
	static char message[1000];

	switch (error_code) {
	case TSIG_ERROR_NOERROR:
		strcpy(message, "No Error");
		break;
	case TSIG_ERROR_BADSIG:
		strcpy(message, "Bad Signature");
		break;
	case TSIG_ERROR_BADKEY:
		strcpy(message, "Bad Key");
		break;
	case TSIG_ERROR_BADTIME:
		strcpy(message, "Bad Time");
		break;
	default:
		snprintf(message, sizeof(message),
			 "Unknown Error %d", error_code);
		break;
	}
	return message;
}

static void
tsig_cleanup_hmac_context(void *data)
{
	HMAC_CTX *context = (HMAC_CTX *) data;
	HMAC_CTX_cleanup(context);
}

void
tsig_init_record(tsig_record_type *tsig,
		 region_type *region,
		 const tsig_algorithm_type *algorithm,
		 const tsig_key_type *key)
{
	tsig->region = region;
	tsig->status = TSIG_NOT_PRESENT;
	tsig->position = 0;
	tsig->response_count = 0;
	tsig->algorithm = algorithm;
	tsig->key = key;
	tsig->prior_mac_size = 0;
	tsig->prior_mac_data = NULL;

	HMAC_CTX_init(&tsig->context);
	region_add_cleanup(tsig->region,
			   tsig_cleanup_hmac_context,
			   &tsig->context);
}

int
tsig_from_query(tsig_record_type *tsig)
{
	size_t i;
	tsig_key_table_type *key_entry;
	tsig_key_type *key = NULL;
	tsig_algorithm_type *algorithm = NULL;
	
	assert(tsig->status == TSIG_OK);
	assert(!tsig->algorithm);
	assert(!tsig->key);
	
	/* XXX: Todo */
	for (key_entry = tsig_key_table;
	     key_entry;
	     key_entry = key_entry->next)
	{
		if (dname_compare(tsig->key_name, key_entry->key->name) == 0) {
			key = key_entry->key;
			break;
		}
	}
	
	for (i = 0; i < TSIG_ALGORITHM_COUNT; ++i) {
		if (dname_compare(tsig->algorithm_name,
				  tsig_algorithm_table[i].wireformat_name) == 0)
		{
			algorithm = &tsig_algorithm_table[i];
			break;
		}
	}

	if (!algorithm || !key) {
		/* Algorithm or key is unknown, cannot authenticate.  */
		tsig->error_code = TSIG_ERROR_BADKEY;
		return 0;
	}

	tsig->algorithm = algorithm;
	tsig->key = key;
	tsig->response_count = 0;
	tsig->prior_mac_size = 0;
	tsig->prior_mac_data = NULL;
	
	return 1;
}

void
tsig_init_query(tsig_record_type *tsig, uint16_t original_query_id)
{
	assert(tsig);
	assert(tsig->algorithm);
	assert(tsig->key);
	
	tsig->response_count = 0;
	tsig->prior_mac_size = 0;
	tsig->prior_mac_data = NULL;
	tsig->algorithm_name = tsig->algorithm->wireformat_name;
	tsig->key_name = tsig->key->name;
	tsig->mac_size = 0;
	tsig->mac_data = NULL;
	tsig->original_query_id = original_query_id;
	tsig->error_code = TSIG_ERROR_NOERROR;
	tsig->other_size = 0;
	tsig->other_data = NULL;
}

void
tsig_prepare(tsig_record_type *tsig)
{
	HMAC_Init_ex(&tsig->context,
		     tsig->key->data, tsig->key->size,
		     tsig->algorithm->openssl_algorithm, NULL);

	if (tsig->prior_mac_data) {
		uint16_t mac_size = htons(tsig->prior_mac_size);
		HMAC_Update(&tsig->context,
			    (uint8_t *) &mac_size,
			    sizeof(mac_size));
		HMAC_Update(&tsig->context,
			    tsig->prior_mac_data,
			    tsig->prior_mac_size);
	}

	tsig->updates_since_last_prepare = 0;
}

void
tsig_update(tsig_record_type *tsig, query_type *query, size_t length)
{
	uint16_t original_query_id = htons(tsig->original_query_id);

	assert(length <= buffer_limit(query->packet));
	
	HMAC_Update(&tsig->context, (uint8_t *) &original_query_id,
		    sizeof(original_query_id));
	HMAC_Update(&tsig->context,
		    buffer_at(query->packet, sizeof(original_query_id)),
		    length - sizeof(original_query_id));
	if (QR(query)) {
		++tsig->response_count;
	}

	++tsig->updates_since_last_prepare;
}

void
tsig_sign(tsig_record_type *tsig)
{
	unsigned digest_size;
	uint8_t digest_data[EVP_MAX_MD_SIZE];

	tsig->signed_time_high = 0; /* XXX */
	tsig->signed_time_low = (uint32_t) time(NULL);
	tsig->signed_time_fudge = 300; /* XXX */

	tsig_digest_variables(tsig, tsig->response_count > 1);
	
	HMAC_Final(&tsig->context, digest_data, &digest_size);

#if 0
	fprintf(stderr, "tsig_sign: calculated digest: ");
	print_hex(stderr, digest_data, digest_size);
	fprintf(stderr, "\n");
#endif
	
	tsig->prior_mac_size = tsig->mac_size = digest_size;
	tsig->prior_mac_data = tsig->mac_data = region_alloc_init(
		tsig->region, digest_data, digest_size);
}

int
tsig_verify(tsig_record_type *tsig)
{
	unsigned digest_size;
	uint8_t digest_data[EVP_MAX_MD_SIZE];

	tsig_digest_variables(tsig, tsig->response_count > 1);
	
	HMAC_Final(&tsig->context, digest_data, &digest_size);

#if 0
	fprintf(stderr, "tsig_verify: calculated digest: ");
	print_hex(stderr, digest_data, digest_size);
	fprintf(stderr, "\n");
#endif
	
	tsig->prior_mac_size = digest_size;
	tsig->prior_mac_data = region_alloc_init(
		tsig->region, digest_data, digest_size);

	if (tsig->mac_size == digest_size 
	    && memcmp(tsig->mac_data, digest_data, digest_size) == 0)
	{
		return 1;
	} else {
		/* Digest is incorrect, cannot authenticate.  */
		tsig->error_code = TSIG_ERROR_BADSIG;
		return 0;
	}
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
tsig_find_rr(tsig_record_type *tsig, query_type *query)
{
	size_t saved_position = buffer_position(query->packet);
	size_t rrcount = (QDCOUNT(query) + ANCOUNT(query) +
			  NSCOUNT(query) + ARCOUNT(query));
	size_t i;
	int result;

	if (ARCOUNT(query) == 0) {
		tsig->status = TSIG_NOT_PRESENT;
		return 1;
	}
			  
	buffer_set_position(query->packet, QHEADERSZ);

	/* TSIG must be the last record, so skip all others.  */
	for (i = 0; i < rrcount - 1; ++i) {
		if (!skip_rr(query->packet, i < QDCOUNT(query))) {
			buffer_set_position(query->packet, saved_position);
			return 0;
		}
	}

	result = tsig_parse_rr(tsig, query->packet);
	buffer_set_position(query->packet, saved_position);
	return result;
}

int
tsig_parse_rr(tsig_record_type *tsig, buffer_type *packet)
{
	uint16_t type;
	uint16_t klass;
	uint32_t ttl;
	uint16_t rdlen;

	tsig->status = TSIG_NOT_PRESENT;
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
		return 1;
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
	if (!buffer_available(packet, tsig->other_size)) {
		buffer_set_position(packet, tsig->position);
		return 0;
	}
	tsig->other_data = region_alloc_init(
		tsig->region, buffer_current(packet), tsig->other_size);
	buffer_skip(packet, tsig->other_size);
	tsig->status = TSIG_OK;

	return 1;
}

void
tsig_append_rr(tsig_record_type *tsig, buffer_type *packet)
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
