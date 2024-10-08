/*
 * rdata.c -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "rdata.h"
#include "zonec.h"

/* Taken from RFC 4398, section 2.1.  */
lookup_table_type dns_certificate_types[] = {
/*	0		Reserved */
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
	{ 3, "PGP" },	/* OpenPGP packet */
	{ 4, "IPKIX" },	/* The URL of an X.509 data object */
	{ 5, "ISPKI" },	/* The URL of an SPKI certificate */
	{ 6, "IPGP" },	/* The fingerprint and URL of an OpenPGP packet */
	{ 7, "ACPKIX" },	/* Attribute Certificate */
	{ 8, "IACPKIX" },	/* The URL of an Attribute Certificate */
	{ 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
/*	255 		Reserved */
/* 	256-65279	Available for IANA assignment */
/*	65280-65534	Experimental */
/*	65535		Reserved */
	{ 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
lookup_table_type dns_algorithms[] = {
	{ 1, "RSAMD5" },	/* RFC 2537 */
	{ 2, "DH" },		/* RFC 2539 */
	{ 3, "DSA" },		/* RFC 2536 */
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* RFC 3110 */
	{ 6, "DSA-NSEC3-SHA1" },	/* RFC 5155 */
	{ 7, "RSASHA1-NSEC3-SHA1" },	/* RFC 5155 */
	{ 8, "RSASHA256" },		/* RFC 5702 */
	{ 10, "RSASHA512" },		/* RFC 5702 */
	{ 12, "ECC-GOST" },		/* RFC 5933 */
	{ 13, "ECDSAP256SHA256" },	/* RFC 6605 */
	{ 14, "ECDSAP384SHA384" },	/* RFC 6605 */
	{ 15, "ED25519" },		/* RFC 8080 */
	{ 16, "ED448" },		/* RFC 8080 */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

const char *svcparamkey_strs[] = {
		"mandatory", "alpn", "no-default-alpn", "port",
		"ipv4hint", "ech", "ipv6hint", "dohpath", "ohttp",
		"tls-supported-groups"
	};


static int32_t print_name(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset == 0)
		return 0;

  const uint8_t *name = rdata + *offset;
  const uint8_t *label = name;
  const uint8_t *limit = rdata + rdlength;

  do {
    if (label - name > 255 || *label > 63 || limit - label < 1 + *label)
      return 0;
    label += 1 + *label;
  } while (*label);

  buffer_printf(output, "%s", wiredname2str(name));
  *offset += label - name;
	return 1;
}

static int32_t print_domain(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	uint16_t length = 0;
	const struct dname *dname;
	const struct domain *domain;
	memcpy(&domain, rdata, sizeof(void*));
	dname = domain_dname(domain);
  buffer_printf(output, "%s", wiredname2str(name));
	*offset += sizeof(void*);
	return 1;
}

static int32_t print_string(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	size_t n = data[0];
	buffer_printf(output, "\"");
	for (size_t i = 1; i <= n; i++) {
		char ch = (char) data[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\') {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) data[i]);
		}
	}
	buffer_printf(output, "\"");
	return 1 + (int32_t)n;
}

static int32_t print_text(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	buffer_printf(output, "\"");
	for (size_t i = offset; i < length; ++i) {
		char ch = (char) rdata[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\') {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) rdata[i]);
		}
	}
	buffer_printf(output, "\"");
	return rdlength - offset;
}

static int
rdata_unquoted_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	const uint8_t *data = rdata_atom_data(rdata);
	uint8_t length = data[0];
	size_t i;

	for (i = 1; i <= length; ++i) {
		char ch = (char) data[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\'
			||  isspace((unsigned char)ch)) {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) data[i]);
		}
	}
	return 1;
}

static int
rdata_unquoteds_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
	uint16_t pos = 0;
	const uint8_t *data = rdata_atom_data(rdata);
	uint16_t length = rdata_atom_size(rdata);
	size_t i;

	while (pos < length && pos + data[pos] < length) {
		for (i = 1; i <= data[pos]; ++i) {
			char ch = (char) data[pos + i];
			if (isprint((unsigned char)ch)) {
				if (ch == '"' || ch == '\\'
				||  isspace((unsigned char)ch)) {
					buffer_printf(output, "\\");
				}
				buffer_printf(output, "%c", ch);
			} else {
				buffer_printf(output, "\\%03u", (unsigned) data[pos+i]);
			}
		}
		pos += data[pos]+1;
		buffer_printf(output, pos < length?" ":"");
	}
	return 1;
}

static int32_t print_ip4(
	struct buffer *output, size_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;
	char str[INET_ADDRSTRLEN + 1];
	if (!inet_ntop(AF_INET, rdata + *offset, str, sizeof(str)))
		return 0;
	buffer_printf(output, "%s", str);
	*offset += 4;
	return 1;
}

static int32_t print_ip6(
	struct buffer *output, size_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset < 16)
		return 0;
	char str[INET6_ADDRSTRLEN + 1];
	if (!inet_ntop(AF_INET6, rdata + *offset, str, sizeof(str)))
		return 0;
	buffer_printf(output, "%s", str);
	*offset += 16;
	return 1;
}

static int32_t print_ilnp64(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset < 8)
		return 0;
	uint16_t a1 = read_uint16(rdata + *offset);
	uint16_t a2 = read_uint16(rdata + *offset + 2);
	uint16_t a3 = read_uint16(rdata + *offset + 4);
	uint16_t a4 = read_uint16(rdata + *offset + 6);

	buffer_printf(output, "%.4x:%.4x:%.4x:%.4x", a1, a2, a3, a4);
	*offset += 8;
	return 1;
}

static int32_t print_certificate_type(
	struct buffer *output, size_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	if (rdlength < *offset || rdlength - *offset > 2)
		return 0;
	uint16_t id = read_uint16(rdata + *offset);
	lookup_table_type *type = lookup_by_id(dns_certificate_types, id);
	if (type)
		buffer_printf(output, "%s", type->name);
	else
		buffer_printf(output, "%u", (unsigned) id);
	return 2;
}

static int32_t print_time(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;
	time_t time = (time_t)read_uint32(rdata + *offset);
	struct tm *tm = gmtime(&time);
	char buf[15];
	if (!strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm))
		return 0;
	buffer_printf(output, "%s", buf);
	*offset += 4;
	return 1;
}

static int32_t print_base32(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	uint8_t length = rdata[*offset];
	if (rdlength < *offset || rdlength - *offset > 1 + length)
		return 0;

	if (length == 0) {
		buffer_write(output, "-", 1);
		return 1;
	} else {
	}
	//
	buffer_reserve(output, size * 2 + 1);
	length = b32_ntop(rdata + offset + 1, size,
			  (char *)buffer_current(output), size * 2);
	if (length == -1)
		return -1;
	buffer_skip(output, length);
	return 1 + size;
}

static int32_t print_base64(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	int length;
	size_t size = rdlength - offset;
	if(size == 0) {
		/* single zero represents empty buffer */
		buffer_write(output, "0", 1);
		return 0;
	}
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata + offset, size,
			  (char *) buffer_current(output), size * 2);
	if (length == -1)
		return -1;
	buffer_skip(output, length);
	return size;
}

static void
hex_to_string(buffer_type *output, const uint8_t *data, size_t size)
{ 
	static const char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	size_t i;

	buffer_reserve(output, size * 2);
	for (i = 0; i < size; ++i) {
		uint8_t octet = *data++;
		buffer_write_u8(output, hexdigits[octet >> 4]);
		buffer_write_u8(output, hexdigits[octet & 0x0f]);
	}
}

static int print_base16(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
//	if(rdata_atom_size(rdata) == 0) {
//		/* single zero represents empty buffer, such as CDS deletes */
//		buffer_printf(output, "0");
//	} else {
//		hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
//	}
//	return 1;
}

static int32_t print_salt(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	assert(rdlength >= *offset);
	if (rdlength - *offset == 0)
		return 0;

	uint8_t length = rdata[*offset];
	if (rdlength - *offset < 1 + length)
		return 0;
	if (!length)
		/* NSEC3 salt hex can be empty */
		buffer_printf(output, "-");
	else
		hex_to_string(output, rdata + *offset + 1, length);
	*offset += 1 + length;
	return 1;
}

static int32_t print_nsec(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	size_t saved_position = buffer_position(output);
	buffer_type packet;
	int insert_space = 0;

// not going to use this...
//	buffer_create_from(&packet, rdata + offset, rdlength - offset);

	while (buffer_available(&packet, 2)) {
		uint8_t window = buffer_read_u8(&packet);
		uint8_t bitmap_size = buffer_read_u8(&packet);
		uint8_t *bitmap = buffer_current(&packet);
		int i;

		if (!buffer_available(&packet, bitmap_size)) {
			buffer_set_position(output, saved_position);
			return 0;
		}

		for (i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				buffer_printf(output,
					      "%s%s",
					      insert_space ? " " : "",
					      rrtype_to_string(
						      window * 256 + i));
				insert_space = 1;
			}
		}
		buffer_skip(&packet, bitmap_size);
	}

	return 1;
}

static int
rdata_loc_to_string(buffer_type *ATTR_UNUSED(output),
		    rdata_atom_type ATTR_UNUSED(rdata),
		    rr_type* ATTR_UNUSED(rr))
{
	/*
	 * Returning 0 forces the record to be printed in unknown
	 * format.
	 */
	return 0;
}

static int
rdata_svcparam_port_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	if (val_len != 2)
		return 0; /* wireformat error, a short is 2 bytes */
	buffer_printf(output, "=%d", (int)ntohs(data[0]));
	return 1;
}

static int
rdata_svcparam_ipv4hint_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	char ip_str[INET_ADDRSTRLEN + 1];
	
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if ((val_len % IP4ADDRLEN) == 0) {
		if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP4ADDRLEN / sizeof(uint16_t);

		while ((val_len -= IP4ADDRLEN) > 0) {
			if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str)) == NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP4ADDRLEN / sizeof(uint16_t);
		}
		return 1;
	} else
		return 0;
}

static int
rdata_svcparam_ipv6hint_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	char ip_str[INET6_ADDRSTRLEN + 1];
	
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if ((val_len % IP6ADDRLEN) == 0) {
		if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP6ADDRLEN / sizeof(uint16_t);

		while ((val_len -= IP6ADDRLEN) > 0) {
			if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str)) == NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP6ADDRLEN / sizeof(uint16_t);
		}
		return 1;
	} else
		return 0;
}

static int32_t print_svcparam_mandatory(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
//rdata_svcparam_mandatory_to_string(buffer_type *output, uint16_t val_len,
//	uint16_t *data)
{
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if (val_len % sizeof(uint16_t))
		return 0; /* wireformat error, val_len must be multiple of shorts */
	buffer_write_u8(output, '=');
	buffer_print_svcparamkey(output, ntohs(*data));
	data += 1;

	while ((val_len -= sizeof(uint16_t))) {
		buffer_write_u8(output, ',');
		buffer_print_svcparamkey(output, ntohs(*data));
		data += 1;
	}

	return 1;
}

static int
rdata_svcparam_ech_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	int length;

	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	buffer_write_u8(output, '=');

	buffer_reserve(output, val_len * 2 + 1);
	length = b64_ntop((uint8_t*) data, val_len,
			  (char *) buffer_current(output), val_len * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}

	return length != -1;
}

static int
rdata_svcparam_alpn_to_string(buffer_type *output, uint16_t val_len,
	uint16_t *data)
{
	uint8_t *dp = (void *)data;

	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	buffer_write_u8(output, '=');
	buffer_write_u8(output, '"');
	while (val_len) {
		uint8_t i, str_len = *dp++;

		if (str_len > --val_len)
			return 0;

		for (i = 0; i < str_len; i++) {
			if (dp[i] == '"' || dp[i] == '\\')
				buffer_printf(output, "\\\\\\%c", dp[i]);

			else if (dp[i] == ',')
				buffer_printf(output, "\\\\%c", dp[i]);

			else if (!isprint(dp[i]))
				buffer_printf(output, "\\%03u", (unsigned) dp[i]);

			else
				buffer_write_u8(output, dp[i]);
		}
		dp += str_len;
		if ((val_len -= str_len))
			buffer_write_u8(output, ',');
	}
	buffer_write_u8(output, '"');
	return 1;
}

static int
rdata_svcparam_tls_supported_groups_to_string(buffer_type *output,
		uint16_t val_len, uint16_t *data)
{
	assert(val_len > 0); /* Guaranteed by rdata_svcparam_to_string */

	if ((val_len % sizeof(uint16_t)) == 1)
		return 0; /* A series of uint16_t is an even number of bytes */

	buffer_printf(output, "=%d", (int)ntohs(*data++));
	while ((val_len -= sizeof(uint16_t)) > 0) 
		buffer_printf(output, ",%d", (int)ntohs(*data++));
	return 1;
}

typedef struct nsd_svcparam_descriptor nsd_svcparam_descriptor_t;
struct nsd_svcparam_descriptor {
	uint16_t key;
	const char *name;
	nsd_print_svcparam_rdata_t print_rdata;
};

static const nsd_svcparam_descriptor_t svcparams[] = {
	{ SVCB_KEY_MANDATORY, "mandatory", print_svcparam_mandatory },
	{ SVCB_KEY_ALPN, "alpn", print_svcparam_alpn },
	{ SVCB_KEY_NO_DEFAULT_ALPN, "no-default-alpn", print_svcparam_no_default_alpn },
	{ SVCB_KEY_PORT, "port", print_svcparam_port },
	{ SVCB_KEY_IPV4HINT, "ipv4hint", print_svcparam_ipv4hint },
	{ SVCB_KEY_ECH, "ech", print_svcparam_ech },
	{ SVCB_KEY_IPV6HINT, "ipv6hint", print_svcparam_ipv6hint },
	{ SVCB_KEY_DOHPATH, "dohpath", print_svcparam_dohpath },
};

static int32_t print_svcparam(
	struct buffer *output, uint16_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	uint16_t key, length;

	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;

	key = read_uint16(rdata + *offset);
	length = read_uint16(rdata + *offset + 2);

	if (rdlength - *offset <= length + 4)
		return 0; /* wireformat error */

	if (key < svcparams/svcparams[0])
		return svcparams[key].print_rdata(output, rdlength, rdata, offset);

	buffer_printf(output, "key%" PRIu16, key);
	if (!length)
		return 1;

	buffer_write(output, "=\"", 2);
		dp = (void*) (data + 2);

		for (i = 0; i < val_len; i++) {
			if (dp[i] == '"' || dp[i] == '\\')
				buffer_printf(output, "\\%c", dp[i]);

			else if (!isprint(dp[i]))
				buffer_printf(output, "\\%03u", (unsigned) dp[i]);

			else
				buffer_write_u8(output, dp[i]);
		}
		buffer_write_u8(output, '"');


//static void
//buffer_print_svcparamkey(buffer_type *output, uint16_t svcparamkey)
//{
//	if (svcparamkey < SVCPARAMKEY_COUNT)
//		buffer_printf(output, "%s", svcparamkey_strs[svcparamkey]);
//	else
//}

//	buffer_print_svcparamkey(output, key);
//	val_len = ntohs(read_uin16(rdata + *offset + 2));

	if (!length) {
		/* Some SvcParams MUST have values */
		switch (svcparamkey) {
		case SVCB_KEY_ALPN:
		case SVCB_KEY_PORT:
		case SVCB_KEY_IPV4HINT:
		case SVCB_KEY_IPV6HINT:
		case SVCB_KEY_MANDATORY:
		case SVCB_KEY_DOHPATH:
		case SVCB_KEY_TLS_SUPPORTED_GROUPS:
			return 0;
		default:
			return 1;
		}
	}
	data = rdata + rdlength +4;
	switch (svcparamkey) {
	case SVCB_KEY_PORT:
		return rdata_svcparam_port_to_string(output, val_len, data);
	case SVCB_KEY_IPV4HINT:
		return rdata_svcparam_ipv4hint_to_string(output, val_len, data);
	case SVCB_KEY_IPV6HINT:
		return rdata_svcparam_ipv6hint_to_string(output, val_len, data);
	case SVCB_KEY_MANDATORY:
		return rdata_svcparam_mandatory_to_string(output, val_len, data);
	case SVCB_KEY_NO_DEFAULT_ALPN:
		return 0; /* wireformat error, should not have a value */
	case SVCB_KEY_ALPN:
		return rdata_svcparam_alpn_to_string(output, val_len, data);
	case SVCB_KEY_ECH:
		return rdata_svcparam_ech_to_string(output, val_len, data);
	case SVCB_KEY_OHTTP:
		return 0; /* wireformat error, should not have a value */
	case SVCB_KEY_TLS_SUPPORTED_GROUPS:
		return rdata_svcparam_tls_supported_groups_to_string(output, val_len, data+2);
	case SVCB_KEY_DOHPATH:
		/* fallthrough */
	default:
	}
	return val_len + 4;
}

static int
rdata_hip_to_string(buffer_type *output, rdata_atom_type rdata,
	rr_type* ATTR_UNUSED(rr))
{
 	uint16_t size = rdata_atom_size(rdata);
	uint8_t hit_length;
	uint16_t pk_length;
	int length = 0;

	if(size < 4)
		return 0;
	hit_length = rdata_atom_data(rdata)[0];
	pk_length  = read_uint16(rdata_atom_data(rdata) + 2);
	length     = 4 + hit_length + pk_length;
	if(hit_length == 0 || pk_length == 0 || size < length)
		return 0;
	buffer_printf(output, "%u ", (unsigned)rdata_atom_data(rdata)[1]);
	hex_to_string(output, rdata_atom_data(rdata) + 4, hit_length);
	buffer_printf(output, " ");
	buffer_reserve(output, pk_length * 2 + 1);
	length = b64_ntop(rdata_atom_data(rdata) + 4 + hit_length, pk_length,
			  (char *) buffer_current(output), pk_length * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}
	return length != -1;
}

static int
rdata_unknown_to_string(
	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
{
 	size_t size = rdlength - offset;
 	buffer_printf(output, "\\# %lu ", (unsigned long)size);
	hex_to_string(output, rdata + offset, size);
	return size;
}

int print_unknown_rdata(
	buffer_type *output, rrtype_descriptor_type *descriptor, rr_type *rr)
{
	// get descriptor, make sure domains are printed correctly!
	size_t i;
	rdata_atom_type temp_rdatas[MAXRDATALEN];
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
	region_type *temp_region;

	assert(descriptor->maximum <= MAXRDATALEN);

	if (!buffer_available(packet, data_size)) {
		return -1;
	}

	temp_region = region_create(xalloc, free);

	for (i = 0; i < descriptor->maximum; ++i) {
		int is_domain = 0;
		int is_normalized = 0;
		int is_wirestore = 0;
		size_t length = 0;
		int required = i < descriptor->minimum;

		switch (rdata_atom_wireformat_type(rrtype, i)) {
		case RDATA_WF_COMPRESSED_DNAME:
		case RDATA_WF_UNCOMPRESSED_DNAME:
			is_domain = 1;
			is_normalized = 1;
			break;
		case RDATA_WF_LITERAL_DNAME:
			is_domain = 1;
			is_wirestore = 1;
			break;
		case RDATA_WF_BYTE:
			length = sizeof(uint8_t);
			break;
		case RDATA_WF_SHORT:
			length = sizeof(uint16_t);
			break;
		case RDATA_WF_LONG:
			length = sizeof(uint32_t);
			break;
		case RDATA_WF_TEXTS:
		case RDATA_WF_LONG_TEXT:
			length = end - buffer_position(packet);
			break;
		case RDATA_WF_TEXT:
		case RDATA_WF_BINARYWITHLENGTH:
			/* Length is stored in the first byte.  */
			length = 1;
			if (buffer_position(packet) + length <= end) {
				length += buffer_current(packet)[length - 1];
			}
			break;
		case RDATA_WF_A:
			length = sizeof(in_addr_t);
			break;
		case RDATA_WF_AAAA:
			length = IP6ADDRLEN;
			break;
		case RDATA_WF_ILNP64:
			length = IP6ADDRLEN/2;
			break;
		case RDATA_WF_EUI48:
			length = EUI48ADDRLEN;
			break;
		case RDATA_WF_EUI64:
			length = EUI64ADDRLEN;
			break;
		case RDATA_WF_BINARY:
			/* Remaining RDATA is binary.  */
			length = end - buffer_position(packet);
			break;
		case RDATA_WF_APL:
			length = (sizeof(uint16_t)    /* address family */
				  + sizeof(uint8_t)   /* prefix */
				  + sizeof(uint8_t)); /* length */
			if (buffer_position(packet) + length <= end) {
				/* Mask out negation bit.  */
				length += (buffer_current(packet)[length - 1]
					   & APL_LENGTH_MASK);
			}
			break;
		case RDATA_WF_IPSECGATEWAY:
			assert(i>1); /* we are past the gateway type */
			switch(rdata_atom_data(temp_rdatas[1])[0]) /* gateway type */ {
			default:
			case IPSECKEY_NOGATEWAY:
				length = 0;
				break;
			case IPSECKEY_IP4:
				length = IP4ADDRLEN;
				break;
			case IPSECKEY_IP6:
				length = IP6ADDRLEN;
				break;
			case IPSECKEY_DNAME:
				is_domain = 1;
				is_normalized = 1;
				is_wirestore = 1;
				break;
			}
			break;
		case RDATA_WF_SVCPARAM:
			length = 4;
			if (buffer_position(packet) + 4 <= end) {
				length +=
				    read_uint16(buffer_current(packet) + 2);
			}
			break;
		case RDATA_WF_HIP:
			/* Length is stored in the first byte (HIT length)
			 * plus the third and fourth byte (PK length) */
			length = 4;
			if (buffer_position(packet) + length <= end) {
				length += buffer_current(packet)[0];
				length += read_uint16(buffer_current(packet) + 2);
			}
			break;
		}
		if (is_domain) {
			const dname_type *dname;

			if (!required && buffer_position(packet) == end) {
				break;
			}

			dname = dname_make_from_packet(
				temp_region, packet, 1, is_normalized);
			if (!dname || buffer_position(packet) > end) {
				/* Error in domain name.  */
				region_destroy(temp_region);
				return -1;
			}
			if(is_wirestore) {
				temp_rdatas[i].data = (uint16_t *) region_alloc(
                                	region, sizeof(uint16_t) + ((size_t)dname->name_size));
				temp_rdatas[i].data[0] = dname->name_size;
				memcpy(temp_rdatas[i].data+1, dname_name(dname),
					dname->name_size);
			} else {
				temp_rdatas[i].domain
					= domain_table_insert(owners, dname);
				temp_rdatas[i].domain->usage ++;
			}
		} else {
			if (buffer_position(packet) + length > end) {
				if (required) {
					/* Truncated RDATA.  */
					region_destroy(temp_region);
					return -1;
				} else {
					break;
				}
			}
			if (!required && buffer_position(packet) == end) {
				break;
			}

			temp_rdatas[i].data = (uint16_t *) region_alloc(
				region, sizeof(uint16_t) + length);
			temp_rdatas[i].data[0] = length;
			buffer_read(packet, temp_rdatas[i].data + 1, length);
		}
	}

	if (buffer_position(packet) < end) {
		/* Trailing garbage.  */
		region_destroy(temp_region);
		return -1;
	}

	*rdatas = (rdata_atom_type *) region_alloc_array_init(
		region, temp_rdatas, i, sizeof(rdata_atom_type));
	region_destroy(temp_region);
	return (ssize_t)i;
}

size_t
rdata_maximum_wireformat_size(rrtype_descriptor_type *descriptor,
			      size_t rdata_count,
			      rdata_atom_type *rdatas)
{
	size_t result = 0;
	size_t i;
	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(descriptor->type, i)) {
			result += domain_dname(rdata_atom_domain(rdatas[i]))->name_size;
		} else {
			result += rdata_atom_size(rdatas[i]);
		}
	}
	return result;
}

int
rdata_atoms_to_unknown_string(buffer_type *output,
			      rrtype_descriptor_type *descriptor,
			      size_t rdata_count,
			      rdata_atom_type *rdatas)
{
	size_t i;
	size_t size = rr_marshal_rdata_length(rr);
	buffer_printf(output, " \\# %lu ", (unsigned long) size);
	for (i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(descriptor->type, i)) {
			const dname_type *dname =
				domain_dname(rdata_atom_domain(rdatas[i]));
			hex_to_string(
				output, dname_name(dname), dname->name_size);
		} else {
			hex_to_string(output, rdata_atom_data(rdatas[i]),
				rdata_atom_size(rdatas[i]));
		}
	}
	return 1;
}


int32_t print_a_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == 4);
	return print_ip4(output, rr->rdlength, rr->rdata, &length);
}

int32_t print_ns_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == sizeof(void*));
	return print_domain(output, rr->rdlength, rr->rdata, &length);
}

int32_t print_soa_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	uint32_t serial, refresh, retry, expire, minimum;
	assert(rr->rdlength == 2 * sizeof(void*) + 20);
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(buffer, " ");
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;

	assert(length == 2 * sizeof(void*));
	serial = read_uint32(rr->rdata + length);
	refresh = read_uint32(rr->rdata + length + 4);
	retry = read_uint32(rr->rdata + length + 8);
	expire = read_uint32(rr->rdata + length + 12);
	minimum = read_uint32(rr->rdata + length + 16);

	buffer_printf(
		buffer, " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
		serial, refresh, retry, expire, minimum);
	return 1;
}

/*
 * Print protocol and service numbers rather than names for Well-Know Services
 * (WKS) RRs. WKS RRs are deprecated, though not technically, and should not
 * be used. The parser supports tcp/udp for protocols and a small subset of
 * services because getprotobyname and/or getservbyname are marked MT-Unsafe
 * and locale. getprotobyname_r and getservbyname_r exist on some platforms,
 * but are still marked locale (meaning the locale object is used without
 * synchonization, which is a problem for a library). Failure to load a zone
 * on a primary server because of an unknown protocol or service name is
 * acceptable as the operator can opt to use the numeric value. Failure to
 * load a zone on a secondary server is problematic because "unsupported"
 * protocols and services might be written. Print the numeric value for
 * maximum compatibility.
 *
 * (see simdzone/generic/wks.h for details).
 */
int32_t print_wks_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	uint8_t protocol;

	assert(rr->rdlength >= 5);
	if (!print_ip4(output, rr->rdlength, rr->rdata, &length))
		return 0;

	protocol = rr->rdata[4];
	buffer_printf(buffer, "%s %" PRIu8, address, protocol);

	int bits = (rr->rdlength - 5) * 8;
	const uint8_t *bitmap = rr->rdata + 5;
	for (int service = 0; service < bits; service++) {
		if (get_bit(bitmap, service))
			buffer_printf(buffer, " %d", service);
	}
	return 1;
}

int32_t print_hinfo_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_minfo_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == 2 * sizeof(void*));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_mx_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;
	assert(rr->rdlength > length);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_txt_rdata(struct buffer *output, const struct rr *rr)
{
	int32_t code;
	uint16_t offset = 0;
	if (offset < rr->rdlength) {
		if ((code = print_string(buffer, rr->rdata+offset, rr->rdlength-offset)) < 0)
			return code;
		assert(code <= rr->rdlength);
		offset += (uint16_t)code;
		while (offset < rr->rdlength) {
			buffer_printf(buffer, " ");
			if ((code = print_string(buffer, rr->rdata+offset, rr->rdlength-offset)) < 0)
				return code;
			assert(code <= rr->rdlength);
			offset += (uint16_t)code;
		}
	}
	return 0;
}

static int32_t print_afsdb_rdata(struct buffer *output, const struct rr *rr)
{
	int32_t code;
	uint16_t subtype;
	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(&subtype, rr->rdata, sizeof(subtype));
	subtype = ntohs(subtype);
	buffer_printf(buffer, "%" PRIu16 " ", subtype);
	if ((code = print_domain(buffer, rr->rdata + 2, rr->rdlength - 2)) < 0)
		return code;
	return 0;
}

int32_t print_x25_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_isdn_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(buffer, " ");
	if (!print_string(buffer, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_nsap_rdata(struct buffer *output, const struct rr *rr)
{
	buffer_printf(output, "0x");
	hex_to_string(output, rr->rdata, rr->rdlength);
	return 0;
}

int32_t print_key_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;
	assert(rr->rdata > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu8 " %" PRIu8 " ",
		read_uint16(rr->rdata), rr->rdata[2], rr->rdata[3]);
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_px_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 2;
	assert(rr->rdlength > 3);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_aaaa_rdata(struct buffer *output, const struct rr *rr);
{
	assert(rr->rdlength == 16);
	return print_ip6(output, rr->rdlength, rr->rdata, &length);
}

int32_t print_nxt_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	assert(rr->rdlength > sizeof(void*));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;

	int bits = rdlength - length;
	const uint8_t *bitmap = rr->rdata + length;
	for (int type = 0; type < bitmap_size * 8; type++)
		if (get_bit(bitmap, type)) {
			buffer_printf(output, "%s ", rrtype_to_string(type));

	buffer_skip(output, -1);
	return 1;
}

int32_t print_srv_rdata(struct buffer *output, const struct rr *rr);
{
	int16_t length = 6;
	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu16 " %" PRIu16 " ",
		read_uint16(rr->rdata), read_uint16(rr->rdata+2),
	 	read_uint16(rr->rdata+4));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_naptr_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > 4);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu16 " ",
	 	read_uint16(rr->rdata), read_uint16(rr->rdata+2));
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_cert_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 5;
	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu16 " %" PRIu8 " ",
		read_uint16(rr->rdata), read_uint16(rr->rdata+2), rr->rdata[4]);
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_a6_rdata(struct buffer *output, const struct rr *rr);
{
	//
}

int32_t print_dname_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_apl(
	struct buffer *output, size_t rdlength, const uint8_t *rdata, uint16_t *offset)
{
	size_t size = rdlength - *offset;

	if (size < 4)
		return 0;

	uint16_t address_family = read_uint16(rdata + *offset);
	uint8_t prefix = rdata[*offset + 2];
	uint8_t length = rdata[*offset + 3] & APL_LENGTH_MASK;
	uint8_t negated = rdata[*offset + 3] & APL_NEGATION_MASK;
	int af = -1;

	switch (address_family) {
	case 1: af = AF_INET; break;
	case 2: af = AF_INET6; break;
	}

	if (af == -1 || size - 4 < length)
		return 0;

	char text_address[INET6_ADDRSTRLEN + 1];
	uint8_t address[16];
	memset(address, 0, sizeof(address));
	memmove(address, rdata + *offset + 4, length);

	if (!inet_ntop(af, address, text_address, sizeof(text_address)))
		return 0;

	buffer_printf(
		output, "%s%" PRIu16 ":%s/%" PRIu8,
		negated ? "!" : "", address_family, text_address, prefix);
	*offset += 4 + length;
	return 1;
}

int32_t print_apl_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	while (length < rr->rdlength) {
		if (!print_apl(output, rr->rdlength, rr->rdata, &length))
			return 0;
	}
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_ds_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > 4);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu8 " %" PRIu8 " ",
		read_uint16(rr->rdata), rr->rdata[2], rr->rdata[3]);
	if (!print_base16(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_sshfp_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 2;
	uint8_t algorithm, ftype;

	assert(rr->rdlength > length);
	algorithm = rr->rdata[0];
	ftype = rr->rdata[1];

	buffer_printf(output, "%" PRIu8 " %" PRIu8 " ", algorithm, ftype);
	if (!print_base16(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_ipseckey_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 3;

	assert(rdlength >= length);
	buffer_printf(
		output, "%" PRIu8 " %" PRIu8 " %" PRIu8 " ",
		rr->rdata[0], rr->rdata[1], rr->rdata[2]);
	switch (gateway_type) {
	case IPSECKEY_NOGATEWAY:
		buffer_printf(output, ".");
		break;
	case IPSECKEY_IP4:
		if (!print_ip4(output, rr->rdlength, rr->rdata, &length))
			return 0;
		break;
	case IPSECKEY_IP6:
		if (!print_ip6(output, rr->rdlength, rr->rdata, &length))
			return 0;
		break;
	case IPSECKEY_DNAME:
		if (!print_name(output, rr->rdlength, rr->rdata, &length))
			return 0;
		break;
	default:
		return 0;
	}

	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_rrsig_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu8 " %" PRIu8 " %" PRIu32 " ",
		read_uint16(rr->rdata), rr->rdata[2], rr->rdata[3],
		read_uint32(rr->rdata+4));
	if (!print_time(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_time(output, rr->rdlength, rr->rdata, &length))
		return 0;

	buffer_printf(output, " %" PRIu16 " ", read_uint16(rr->rdata+length));
	length += 2;

	if (!print_name(output, rr->rdlength, rr-rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_nsec_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	assert(rr->rdlength > length);
	if (!print_name(output, rr->rdlength, rr->rdata, &length))
		return 0;
	if (!print_nsec(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_dnskey_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu8 " %" PRIu8 " ",
		read_uint16(rr->rdata), rr->rdata[2], rr->rdata[3]);
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_dhcid_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_nsec3_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu8 " %" PRIu8 " %" PRIu16 " ",
		rr->rdata[0], rr->rdata[1], read_uint16(rr->rdata + 2));
	if (!print_salt(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_base32(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_nsec(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_nsec3param_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu8 " %" PRIu8 " %" PRIu16 " ",
		rr->rdata[0], rr->rdata[1], read_uint16(rr->rdata + 2));

	if (!print_salt(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_tlsa_rdata(struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 3;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu8 " %" PRIu8 " %" PRIu8 " ",
		rr->rdata[0], rr->rdata[1], rr->rdata[2]);

	if (!print_base16(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_openpgpkey_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 0;

	assert(rr->rdlength > 0);
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_csync_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 6;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu32 " %" PRIu16 " ",
		read_uint32(rr->rdata), read_uint16(rr->rdata + 4));
	if (!print_nsec(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_zonemd_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 6;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu32 " %" PRIu8 " %" PRIu8 " ",
		read_uint32(rr->rdata), rr->rdata[4], rr->rdata[5]);
	if (!print_base16(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength != length);
	return 1;
}

int32_t print_svcb_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 2;

	assert(rr->rdlength > length);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	while (length < rr->rdlength)
		if (!print_svcparam(output, rr->rdlength, rr->rdata, &length))
			return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_nid_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilpn64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_l32_rdata(
	struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 2;

	assert(rr->rdlength == 6);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ip4(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_l64_rdata(
	struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilpn64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_lp_rdata(
	struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 2;

	assert(rr->rdlength > 2);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_name(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t print_eui48_rdata(struct buffer *output, const struct rr *rr);
{
	assert(rr->rdlength == 6);
	const uint8_t *x = rr->rdata;
	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		x[0], x[1], x[2], x[3], x[4], x[5]);
	return 1;
}

int32_t print_eui64_rdata(struct buffer *buffer, const struct rr *rr);
{
	assert(rr->rdlength == 8);
	const uint8_t *x = rr->rdata;
	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);
	return 1;
}

int32_t print_uri_rdata(struct buffer *output, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu16 " ",
		read_uint16(rr->rdata), read_uint16(rr->rdata + 2));
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_caa_rdata(
	struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 1;

	assert(rr->rdlength > length);
	buffer_printf(output, "%" PRIu8 " ", rr->rdata[0]);

	length = 1 + rr->rdata[1];
	if (rr->rdlength < length)
		return 0;

	for (uint16_t i = 2; i <= length; ++i) {
		char ch = (char) rr->rdata[i];
		if (isdigit((unsigned char)ch) || islower((unsigned char)ch))
			buffer_printf(output, "%c", ch);
		else	return 0;
	}

	buffer_printf(output, " ");
	if (!print_text(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

static int32_t print_dlv_rdata(
	struct buffer *buffer, const struct rr *rr);
{
	uint16_t length = 4;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu16 " %" PRIu8 " %" PRIu8 " ",
		read_uint16(rr->rdata), rr->rdata[2], rr->rdata[3]);
	if (!print_base16(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}
