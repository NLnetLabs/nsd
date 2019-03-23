/*
 * edns.c -- EDNS definitions (RFC 2671).
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


#include "config.h"

#include <string.h>
#ifdef HAVE_SSL
#include <openssl/opensslv.h>
#include <openssl/evp.h>
#endif

#include "dns.h"
#include "edns.h"
#include "nsd.h"
#include "query.h"

void
edns_init_data(edns_data_type *data, uint16_t max_length)
{
	memset(data, 0, sizeof(edns_data_type));
	/* record type: OPT */
	data->ok[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	data->ok[2] = TYPE_OPT & 0x00ff;	/* type_lo */
	/* udp payload size */
	data->ok[3] = (max_length & 0xff00) >> 8; /* size_hi */
	data->ok[4] = max_length & 0x00ff;	  /* size_lo */

	data->error[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	data->error[2] = TYPE_OPT & 0x00ff;		/* type_lo */
	data->error[3] = (max_length & 0xff00) >> 8;	/* size_hi */
	data->error[4] = max_length & 0x00ff;		/* size_lo */
	data->error[5] = 1;	/* XXX Extended RCODE=BAD VERS */

	/* COOKIE OPT HDR */
	data->cookie[0] = (COOKIE_CODE & 0xff00) >> 8;
	data->cookie[1] = (COOKIE_CODE & 0x00ff);
	data->cookie[2] = (24 & 0xff00) >> 8;
	data->cookie[3] = (24 & 0x00ff);
}

void
edns_init_nsid(edns_data_type *data, uint16_t nsid_len)
{
       /* NSID OPT HDR */
       data->nsid[0] = (NSID_CODE & 0xff00) >> 8;
       data->nsid[1] = (NSID_CODE & 0x00ff);
       data->nsid[2] = (nsid_len & 0xff00) >> 8;
       data->nsid[3] = (nsid_len & 0x00ff);
}

void
edns_init_record(edns_record_type *edns)
{
	edns->status = EDNS_NOT_PRESENT;
	edns->position = 0;
	edns->maxlen = 0;
	edns->opt_reserved_space = 0;
	edns->dnssec_ok = 0;
	edns->nsid = 0;
	edns->cookie_status = COOKIE_NOT_PRESENT;
	edns->cookie_len = 0;
}

/** handle a single edns option in the query */
static int
edns_handle_option(uint16_t optcode, uint16_t optlen, buffer_type* packet,
	edns_record_type* edns, struct query* query, nsd_type* nsd)
{
	(void) query; /* in case edns options need the query structure */
	/* handle opt code and read the optlen bytes from the packet */
	switch(optcode) {
	case NSID_CODE:
		/* is NSID enabled? */
		if(nsd->nsid_len > 0) {
			edns->nsid = 1;
			/* we have to check optlen, and move the buffer along */
			buffer_skip(packet, optlen);
			/* in the reply we need space for optcode+optlen+nsid_bytes */
			edns->opt_reserved_space += OPT_HDR + nsd->nsid_len;
		} else {
			/* ignore option */
			buffer_skip(packet, optlen);
		}
		break;
	case COOKIE_CODE:
		/* Cookies enabled? */
		if(nsd->do_answer_cookie) {
			if (optlen == 8) 
				edns->cookie_status = COOKIE_INVALID;
			else if (optlen < 16 || optlen > 40)
				return 0; /* FORMERR */
			else
				edns->cookie_status = COOKIE_UNVERIFIED;

			edns->cookie_len = optlen;
			memcpy(edns->cookie, buffer_current(packet), optlen);
			buffer_skip(packet, optlen);
			edns->opt_reserved_space += OPT_HDR + 24;
		} else {
			buffer_skip(packet, optlen);
		}
	default:
		buffer_skip(packet, optlen);
		break;
	}
	return 1;
}

int
edns_parse_record(edns_record_type *edns, buffer_type *packet,
	query_type* query, nsd_type* nsd)
{
	/* OPT record type... */
	uint8_t  opt_owner;
	uint16_t opt_type;
	uint16_t opt_class;
	uint8_t  opt_version;
	uint16_t opt_flags;
	uint16_t opt_rdlen;

	edns->position = buffer_position(packet);

	if (!buffer_available(packet, (OPT_LEN + OPT_RDATA)))
		return 0;

	opt_owner = buffer_read_u8(packet);
	opt_type = buffer_read_u16(packet);
	if (opt_owner != 0 || opt_type != TYPE_OPT) {
		/* Not EDNS.  */
		buffer_set_position(packet, edns->position);
		return 0;
	}

	opt_class = buffer_read_u16(packet);
	(void)buffer_read_u8(packet); /* opt_extended_rcode */
	opt_version = buffer_read_u8(packet);
	opt_flags = buffer_read_u16(packet);
	opt_rdlen = buffer_read_u16(packet);

	if (opt_version != 0) {
		/* The only error is VERSION not implemented */
		edns->status = EDNS_ERROR;
		return 1;
	}

	if (opt_rdlen > 0) {
		if(!buffer_available(packet, opt_rdlen))
			return 0;
		/* there is more to come, read opt code */
		while(opt_rdlen >= 4) {
			uint16_t optcode = buffer_read_u16(packet);
			uint16_t optlen = buffer_read_u16(packet);
			if(opt_rdlen < 4+optlen)
				return 0; /* opt too long, formerr */
			opt_rdlen -= (4+optlen);
			if(!edns_handle_option(optcode, optlen, packet,
				edns, query, nsd))
				return 0;
		}
		if(opt_rdlen != 0)
			return 0;
	}

	edns->status = EDNS_OK;
	edns->maxlen = opt_class;
	edns->dnssec_ok = opt_flags & DNSSEC_OK_MASK;
	return 1;
}

size_t
edns_reserved_space(edns_record_type *edns)
{
	/* MIEK; when a pkt is too large?? */
	return edns->status == EDNS_NOT_PRESENT ? 0 : (OPT_LEN + OPT_RDATA + edns->opt_reserved_space);
}

int siphash(const uint8_t *in, const size_t inlen,
                const uint8_t *k, uint8_t *out, const size_t outlen);

static int aes_server_cookie(uint8_t *server_cookie_out,
		const uint8_t *secret, size_t secret_len, const uint8_t *in)
{
#ifndef HAVE_SSL
	(void)server_cookie_out;
	(void)secret;
	(void)secret_len;
	(void)in;
	return 0;
#else
# if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_CIPHER_CTX evp_ctx_spc;
	EVP_CIPHER_CTX *evp_ctx = &evp_ctx_spc;
# else
	EVP_CIPHER_CTX *evp_ctx;
# endif
	const EVP_CIPHER *aes_ecb;
	uint8_t out[16];
	int out_len, success;

	switch(secret_len) {
	case 16: aes_ecb = EVP_aes_128_ecb(); break;
	case 24: aes_ecb = EVP_aes_192_ecb(); break;
	case 32: aes_ecb = EVP_aes_256_ecb(); break;
	default: return 0;
	}
# if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_CIPHER_CTX_init(evp_ctx);
# else
	if (!(evp_ctx = EVP_CIPHER_CTX_new()))
		return 0;
# endif
	if((success = EVP_EncryptInit(evp_ctx, aes_ecb, secret, NULL)
		   && EVP_EncryptUpdate(evp_ctx, out, &out_len, in, 16)
		   && out_len == 16)) {
		size_t i;

		for (i = 0; i < 8; i++)
			server_cookie_out[i] = out[i] ^ out[i + 8];
	}
# if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
	EVP_CIPHER_CTX_cleanup(evp_ctx);
# else
	EVP_CIPHER_CTX_free(evp_ctx);
# endif
	return success;
#endif
}

/** RFC 1982 comparison, uses unsigned integers, and tries to avoid
 * compiler optimization (eg. by avoiding a-b<0 comparisons),
 * this routine matches compare_serial(), for SOA serial number checks */
static int
compare_1982(uint32_t a, uint32_t b)
{
	/* for 32 bit values */
	const uint32_t cutoff = ((uint32_t) 1 << (32 - 1));

	if (a == b) {
		return 0;
	} else if ((a < b && b - a < cutoff) || (a > b && a - b > cutoff)) {
		return -1;
	} else {
		return 1;
	}
}

/** if we know that b is larger than a, return the difference between them,
 * that is the distance between them. in RFC1982 arith */
static uint32_t
subtract_1982(uint32_t a, uint32_t b)
{
	/* for 32 bit values */
	const uint32_t cutoff = ((uint32_t) 1 << (32 - 1));

	if(a == b)
		return 0;
	if(a < b && b - a < cutoff) {
		return b-a;
	}
	if(a > b && a - b > cutoff) {
		return ((uint32_t)0xffffffff) - (a-b-1);
	}
	/* wrong case, b smaller than a */
	return 0;
}

void cookie_verify(edns_record_type *data, struct nsd* nsd, uint32_t *now_p)
{
	uint8_t server_cookie[8];
	uint32_t cookie_time, now_uint32;
#ifdef HAVE_SSL
	const EVP_CIPHER *aes_ecb;
#endif
	/* We support only draft-sury-toorop-dns-cookies-algorithms sizes */
	if(data->cookie_len != 24)
		return;

	if(data->cookie[8] != 1)
		return;

	cookie_time = (data->cookie[12] << 24)
	            | (data->cookie[13] << 16)
	            | (data->cookie[14] <<  8)
	            |  data->cookie[15];
	
	now_uint32 = *now_p ? *now_p : (*now_p = (uint32_t)time(NULL));

	if(compare_1982(now_uint32, cookie_time) > 0)
		if (subtract_1982(cookie_time, now_uint32) > 3600) {
			return;
	} else if (subtract_1982(now_uint32, cookie_time) > 300)
                /* ignore cookies > 5 minutes in future */
                return;

	switch(data->cookie[9]) {
	case 3: if (aes_server_cookie(server_cookie, nsd->cookie_secret,
				nsd->cookie_secret_len, data->cookie))
			break;
		else	return;
	case 4:	if (nsd->cookie_secret_len != 16)
			return;
		siphash(data->cookie, 16, nsd->cookie_secret, server_cookie, 8);
		break;
	default:
		return;
	}
	data->cookie_status = memcmp(data->cookie + 16, server_cookie, 8) == 0
	                    ? COOKIE_VALID : COOKIE_INVALID;
}

void cookie_create(edns_record_type *data, struct nsd* nsd, uint32_t *now_p)
{
	uint32_t now_uint32 = *now_p ? *now_p : (*now_p = (uint32_t)time(NULL));

	data->cookie[ 8] = 1;
	data->cookie[ 9] = nsd->cookie_secret_len == 16 ? 4 : 3;
	data->cookie[10] = 0;
	data->cookie[11] = 0;
	data->cookie[12] = (now_uint32 & 0xFF000000) >> 24;
	data->cookie[13] = (now_uint32 & 0x00FF0000) >> 16;
	data->cookie[14] = (now_uint32 & 0x0000FF00) >>  8;
	data->cookie[15] =  now_uint32 & 0x000000FF;
	if (data->cookie[9] == 4)
		siphash(data->cookie, 16,
				nsd->cookie_secret, data->cookie + 16, 8);
	else
		aes_server_cookie(data->cookie + 16, nsd->cookie_secret,
                                nsd->cookie_secret_len, data->cookie);
}

