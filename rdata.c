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

static int32_t
print_name(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	const uint8_t* name, *label, *limit;
	assert(rdlength >= *offset);
	if (rdlength - *offset == 0)
		return 0;

	name = rdata + *offset;
	label = name;
	limit = rdata + rdlength;

	do {
		if (label - name > 255 || *label > 63
			|| limit - label < 1 + *label)
			return 0;
		label += 1 + *label;
	} while (*label);

	buffer_printf(output, "%s", wiredname2str(name));
	*offset += label - name;
	return 1;
}

static int32_t
print_domain(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	const struct dname *dname;
	struct domain *domain;
	if(rdlength < sizeof(void*))
		return 0;
	memcpy(&domain, rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_printf(output, "%s", dname_to_string(dname, NULL));
	*offset += sizeof(void*);
	return 1;
}

/* Return length of string or -1 on wireformat error. offset is moved +len. */
static inline int32_t
skip_string(uint16_t rdlength, const uint8_t* rdata, uint16_t *offset)
{
	uint8_t length;
	if (rdlength < 1)
		return -1;
	length = rdata[0];
	if (1 + length > rdlength)
		return -1;
	*offset += 1;
	*offset += length;
	return 1 + length;
}

/* Return length of strings or -1 on wireformat error. offset is moved +len. */
static inline int32_t
skip_strings(uint16_t rdlength, const uint8_t* rdata, uint16_t *offset)
{
	int32_t olen = 0;
	while(*offset < rdlength) {
		int32_t slen = skip_string(rdlength, rdata, offset);
		if(slen < 0)
			return slen;
		olen += 1 + slen;
	}
	return olen;
}

static int32_t
print_string(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	size_t n;
	if(rdlength < 1)
		return 0;
	n = rdata[0];
	if(rdlength < 1 + n)
		return 0;
	buffer_printf(output, "\"");
	for (size_t i = 1; i <= n; i++) {
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
	return 1 + (int32_t)n;
}

static int32_t
print_text(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	buffer_printf(output, "\"");
	for (size_t i = *offset; i < rdlength; ++i) {
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
	return rdlength - *offset;
}

static int
print_unquoted(buffer_type *output, uint16_t rdlength,
	const uint8_t* rdata, uint16_t* length)
{
	uint8_t len;
	size_t i;

	if(rdlength < 1)
		return 0;
	len = rdata[0];
	if(((size_t)len) + 1 > rdlength)
		return 0;

	for (i = 1; i <= (size_t)len; ++i) {
		char ch = (char) rdata[i];
		if (isprint((unsigned char)ch)) {
			if (ch == '"' || ch == '\\'
			||  isspace((unsigned char)ch)) {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u", (unsigned) rdata[i]);
		}
	}
	*length += 1;
	*length += len;
	return 1;
}

static int
print_unquoteds(buffer_type *output, uint16_t rdlength,
	const uint8_t* rdata, uint16_t* length)
{
	uint16_t pos = 0;

	while (pos < rdlength) {
		if(!print_unquoted(output, rdlength, rdata+pos, length))
			return 0;
		pos = *length;
		if(pos < rdlength)
			buffer_printf(output, " ");
	}
	return 1;
}

/*
 * Print IP4 address.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_ip4(struct buffer *output, size_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	char str[INET_ADDRSTRLEN + 1];
	if(*offset + 4 > rdlength)
		return 0;
	if(!inet_ntop(AF_INET, rdata + *offset, str, sizeof(str)))
		return 0;
	buffer_printf(output, "%s", str);
	*offset += 4;
	return 1;
}

/*
 * Print IP6 address.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_ip6(struct buffer *output, size_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	char str[INET6_ADDRSTRLEN + 1];
	assert(rdlength >= *offset);
	if (rdlength - *offset < 16)
		return 0;
	if (!inet_ntop(AF_INET6, rdata + *offset, str, sizeof(str)))
		return 0;
	buffer_printf(output, "%s", str);
	*offset += 16;
	return 1;
}

static int32_t
print_ilnp64(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	uint16_t a1, a2, a3, a4;
	assert(rdlength >= *offset);
	if (rdlength - *offset < 8)
		return 0;
	a1 = read_uint16(rdata + *offset);
	a2 = read_uint16(rdata + *offset + 2);
	a3 = read_uint16(rdata + *offset + 4);
	a4 = read_uint16(rdata + *offset + 6);

	buffer_printf(output, "%.4x:%.4x:%.4x:%.4x", a1, a2, a3, a4);
	*offset += 8;
	return 1;
}

static int32_t
print_certificate_type(struct buffer *output, size_t rdlength,
	const uint8_t *rdata, uint16_t *offset)
{
	uint16_t id;
	lookup_table_type* type;
	if (rdlength < *offset || rdlength - *offset > 2)
		return 0;
	id = read_uint16(rdata + *offset);
	type = lookup_by_id(dns_certificate_types, id);
	if (type)
		buffer_printf(output, "%s", type->name);
	else
		buffer_printf(output, "%u", (unsigned) id);
	return 2;
}

static int32_t
print_time(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	time_t time;
	struct tm* tm;
	char buf[15];

	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;
	time = (time_t)read_uint32(rdata + *offset);
	tm = gmtime(&time);
	if (!strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm))
		return 0;
	buffer_printf(output, "%s", buf);
	*offset += 4;
	return 1;
}

static int32_t
print_base32(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	size_t length, size = rdata[*offset];
	if (rdlength < *offset || rdlength - *offset > 1 + size)
		return 0;

	if (size == 0) {
		buffer_write(output, "-", 1);
		return 1;
	} else {
	}

	buffer_reserve(output, length * 2 + 1);
	length = b32_ntop(rdata + *offset + 1, size,
			  (char *)buffer_current(output), size * 2);
	if (length == -1)
		return -1;
	buffer_skip(output, length);
	return 1 + size;
}

static int32_t
print_base64(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	int length;
	size_t size = rdlength - *offset;
	if(size == 0) {
		/* single zero represents empty buffer */
		buffer_write(output, "0", 1);
		return 0;
	}
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata + *offset, size,
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

static int
print_base16(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
//	if(rdata_atom_size(rdata) == 0) {
//		/* single zero represents empty buffer, such as CDS deletes */
//		buffer_printf(output, "0");
//	} else {
//		hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
//	}
//	return 1;
}

static int32_t
print_salt(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	uint8_t length;
	assert(rdlength >= *offset);
	if (rdlength - *offset == 0)
		return 0;

	length = rdata[*offset];
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

static inline int32_t
skip_nsec(struct buffer *packet, uint16_t rdlength)
{
	uint16_t length = 0;
	uint8_t last_window;

	while (rdlength - length > 2) {
		uint8_t window = rdata[count];
		uint8_t blocks = rdata[count + 1];
		if (window <= last_window)
			return -1; // could make this a semantic error...
		if (!blocks || blocks > 32)
			return -1;
		if (rdlength - length < 2 + blocks)
			return -1;
		length += 2 + blocks;
		last_window = window;
	}

	if (rdlength != length)
		return -1;

	return length;
}

static int32_t
print_nsec(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
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

static inline int32_t
skip_svcparams(struct buffer *packet, uint16_t *length)
{
//	const uint8_t *params = rdata + length;
//	const uint16_t params_offset = length;
//	while (rdlength - length >= 4) {
//		const uint16_t count = read_uint16(rdata + length + 2);
//		if (rdlength - (4 + length) < count)
//			return -1;
//		length += count;
//	}
//	if (length != rdlength)
//		return -1;
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

static int32_t
print_svcparam_mandatory(struct buffer *output, uint16_t rdlength,
	const uint8_t *rdata, uint16_t *offset)
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

static int32_t
print_svcparam(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
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

static inline int32_t
read_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (buffer_remaining(packet) < rdlength)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	buffer_read(packet, (*rr)->rdata, rdlength);
	rr->rdlength = rdlength;
	return rdlength;
}

int32_t
read_generic_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	return read_rdata(domains, rdlength, packet, rr);
}

void
write_generic_rdata(struct query *query, const struct rr *rr)
{
	buffer_write(query->packet, rr->rdata, rr->rdlength);
}

//static int
//rdata_unknown_to_string(
//	buffer_type *output, uint16_t rdlength, const uint8_t *rdata, size_t offset)
//{
// 	size_t size = rdlength - offset;
// 	buffer_printf(output, "\\# %lu ", (unsigned long)size);
//	hex_to_string(output, rdata + offset, size);
//	return size;
//}

// >> probably better name print_generic_rdata?!?!
int
print_unknown_rdata(buffer_type *output, rrtype_descriptor_type *descriptor,
	rr_type *rr)
{
	// get descriptor, make sure domains are printed correctly!
	// >> wait, we're printing generic rdata right?!?!
	size_t i;
	rdata_atom_type temp_rdatas[MAXRDATALEN];
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
	region_type *temp_region;

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

int32_t
read_compressed_name_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;

	const size_t mark = buffer_position(packet);
	if (!dname_make_wire_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength != buffer_position(packet) - mark)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	(*rr)->rdlength = sizeof(void*);
	return rdlength;
}

int32_t
read_uncompressed_name_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;

	if (!dname_make_wire_from_packet_buffered(&dname, packet, 0, 1) ||
			rdlength != dname.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	(*rr)->rdlength = sizeof(void*);
	return rdlength;
}

static void
encode_dname(query_type *q, domain_type *domain)
{
	while (domain->parent && query_get_dname_offset(q, domain) == 0) {
		query_put_dname_offset(q, domain, buffer_position(q->packet));
		DEBUG(DEBUG_NAME_COMPRESSION, 2,
		      (LOG_INFO, "dname: %s, number: %lu, offset: %u\n",
		       domain_to_string(domain),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		buffer_write(q->packet, dname_name(domain_dname(domain)),
			     label_length(dname_name(domain_dname(domain))) + 1U);
		domain = domain->parent;
	}
	if (domain->parent) {
		DEBUG(DEBUG_NAME_COMPRESSION, 2,
		      (LOG_INFO, "dname: %s, number: %lu, pointer: %u\n",
		       domain_to_string(domain),
		       (unsigned long) domain->number,
		       query_get_dname_offset(q, domain)));
		assert(query_get_dname_offset(q, domain) <= MAX_COMPRESSION_OFFSET);
		buffer_write_u16(q->packet,
				 0xc000 | query_get_dname_offset(q, domain));
	} else {
		buffer_write_u8(q->packet, 0);
	}
}

void
write_compressed_name_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	assert(rr->rdlength == sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	encode_dname(query, domain);
}

void
write_uncompressed_name_rdata(struct query *query, const struct rr *rr)
{
	const struct dname *dname;
	const struct domain *domain;
	assert(rdlength >= sizeof(void*));
	memcpy(domain, rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t
print_name_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == sizeof(void*));
	return print_domain(output, rr->rdlength, rr->rdata, &length);
}

int32_t
read_a_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 4)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_a_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == 4);
	return print_ip4(output, rr->rdlength, rr->rdata, &length);
}

int32_t
read_soa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length;
	struct domain *primary_domain, *mailbox_domain;
	struct dname_buffer primary, mailbox;

	/* name + name + long + long + long + long + long */
	const size_t mark = buffer_position(packet);
	if (!dname_make_from_packet_buffered(&primary, packet, 1, 1) ||
	    !dname_make_from_packet_buffered(&mailbox, packet, 1, 1) ||
	    rdlength != (buffer_position(packet) - mark) + 20)
		return MALFORMED;

	static const size_t size = sizeof(**rr) + 2 * sizeof(struct domain *) + 20;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	primary_domain = domain_table_insert(domains, (void*)&primary);
	primary_domain->usage++;
	mailbox_domain = domain_table_insert(domains, (void*)&mailbox);
	mailbox_domain->usage++;

	memcpy((*rr)->rdata, primary_domain, sizeof(void*));
	memcpy((*rr)->rdata + sizeof(void*), mailbox_domain, sizeof(void*));
	buffer_read(packet, (*rr)->rdata + 2 * sizeof(void*), 20);
	(*rr)->rdlength = 2 * sizeof(void*) + 20;
	return rdlength;
}

void
write_soa_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *primary, *mailbox;
	/* domain + domain + long + long + long + long + long */
	assert(rr->rdlength == 2 * sizeof(void*) + 20);
	memcpy(primary, rr->rdata, sizeof(void*));
	memcpy(mailbox, rr->rdata + sizeof(void*), sizeof(void*));
	encode_dname(query, primary);
	encode_dname(query, mailbox);
	buffer_write(query->packet, rr->rdata + (2 * sizeof(void*)), 20);
}

int32_t
print_soa_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_wks_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
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
int32_t
print_wks_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_hinfo_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	//
	// implement
	//
}

int32_t
print_hinfo_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_minfo_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	//
	// implement
	//
}

void
write_minfo_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *rmailbx, *emailbx;
	assert(rdlength == 2 * sizeof(void*));
	memcpy(rmailbx, rdata, sizeof(void*));
	memcpy(emailbx, rdata + sizeof(void*), sizeof(void*));
	encode_dname(query, rmailbx);
	encode_dname(query, emailbx);
}

int32_t
print_minfo_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_mx_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer exchange;

	/* short + name */
	const size_t mark = buffer_position(packet);
	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&exchange, packet, 1, 1))
		return MALFORMED;
	if (rdlength != 2 + exchange.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return -1;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void
write_mx_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;
	assert(rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	buffer_write(query->packet, rr->rdata, 2);
	encode_dname(query, domain);
}

int32_t
print_mx_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;
	assert(rr->rdlength > length);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_txt_rdata(struct domain_table *owners, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const size_t mark = buffer_position(packet);
	if (skip_strings(packet, &length) < 0 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(owners, rdlength, buffer, rr);
}

int32_t
print_txt_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_rp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *mbox_domain, *txt_domain;
	struct dname_buffer mbox, txt;

	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&mbox, packet, 0, 1) ||
			!dname_make_from_packet_buffered(&txt, packet, 0, 1) ||
	    rdlength != mbox.dname.name_size + txt.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 * sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	mbox_domain = domain_table_insert(domains, (void*)&mbox);
	mbox_domain->usage++;
	txt_domain = domain_table_insert(domain, (void*)&txt);
	txt_domain->usage++;
	memcpy((*rr)->rdata, mbox_domain, sizeof(void*));
	memcpy((*rr)->rdata + sizeof(void*), txt_domain, sizeof(void*));
	(*rr)->rdlength = 2 * sizeof(void*);
	return rdlength;
}

void
write_rp_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *mbox_domain, *txt_domain;
	const struct dname *mbox, *txt;

	assert(rr->rdlength == 2 * sizeof(void*));
	memcpy(mbox_domain, rr->rdata, sizeof(void*));
	memcpy(txt_domain, rr->rdata + sizeof(void*), sizeof(void*));
	mbox = domain_dname(mbox_domain);
	txt = domain_dname(txt_domain);
	buffer_write(packet, dname_name(mbox), mbox->name_size);
	buffer_write(packet, dname_name(txt), txt->name_size);
}

int32_t
read_afsdb_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer hostname;
	/* short + uncompressed name */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&hostname, packet, 0, 1) ||
	    rdlength != 2 + hostname.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&hostname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void
write_afsdb_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(packet, rr->rdata, 2);
	buffer_write(packet, dname_name(dname), dname->name_size);
}

int32_t
print_afsdb_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_x25_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const size_t mark = buffer_position(packet);
	if (skip_string(packet, &length) < 0 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_x25_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	if (!print_string(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_isdn_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const size_t mark = buffer_position(packet);

	if (skip_string(packet, &length) < 0
	 || skip_string(packet, &length) < 0
	 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_isdn_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_rt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const size_t mark = buffer_position(packet);

	if (rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&dname, packet, 0, 1))
		return MALFORMED;
	if (rdlength != 2 + dname.dname.name_size)
		return MALFORMED;
	static const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return -1;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void
write_rt_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rdlength == 2 + sizeof(void*));
	memcpy(domain, (*rr)->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	const uint16_t rdlength = 2 + dname->name_size;
	if (!try_buffer_write_u16(query->packet, rdlength) ||
	    !try_buffer_write(query->packet, rr->rdata, 2) ||
			!try_buffer_write(query->packet, dname_name(dname), dname->name_size))
		return TRUNCATED;
	return rdlength;
}

int32_t
print_nsap_rdata(struct buffer *output, const struct rr *rr)
{
	buffer_printf(output, "0x");
	hex_to_string(output, rr->rdata, rr->rdlength);
	return 0;
}

int32_t
print_key_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_px_rdata(struct domain_table *domains, struct buffer *packet,
	struct rr **rr)
{
	struct domain *map822_domain, *mapx400_domain;
	struct dname_buffer map822, mapx400;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + uncompressed name + uncompressed name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < 2 ||
	    !dname_make_from_packet_buffered(&map822, packet, 0, 1) ||
	    !dname_make_from_packet_buffered(&mapx400, packet, 0, 1) ||
	    rdlength != 2 + map822.dname.name_size + mapx400.dname.name_size)
		return MALFORMED;

	static const size_t size = sizeof(**rr) + 2 + 2*sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	map822_domain = domain_table_insert(domains, (void*)&map822);
	map822_domain->usage++;
	mapx400_domain = domain_table_insert(domains, (void*)&mapx400);
	mapx400_domain->usage++;

	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata, map822_domain, sizeof(void*));
	memcpy((*rr)->rdata, mapx400_domain, sizeof(void*));
	(*rr)->rdlength = 2 + 2*sizeof(void*);
	return rdlength;
}

void
write_px_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *map822_domain, *mapx400_domain;
	const struct dname *map822, *mapx400;

	memcpy(map822_domain, rr->rdata + 2, sizeof(void*));
	memcpy(mapx400_domain, rr->rdata + 2 + sizeof(void*), sizeof(void*));
	map822 = domain_dname(map822_domain);
	mapx400 = domain_dname(mapx400_domain);
	const uint16_t rdlength = 2 + map822->name_size + mapx400->name_size;
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(map822), map822->name_size);
	buffer_write(query->packet, dname_name(mapx400), mapx400->name_size);
}

int32_t
print_px_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_aaaa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 16)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_aaaa_rdata(struct buffer *output, const struct rr *rr)
{
	assert(rr->rdlength == 16);
	return print_ip6(output, rr->rdlength, rr->rdata, &length);
}

int32_t
read_loc_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* version (byte) */
	if (rdlength < 1)
		return MALFORMED;
	/* version (byte) + size (byte) + horiz pre (byte) + vert pre (byte)
	 * latitude (long) + longitude (long) + altitude (long) */
	const size_t mask = buffer_position(packet);
	const uint8_t version = buffer_read_u8_at(packet, mark + 2);
	static const uint16_t size_version_0 = 16u;
	if (version == 0 && rdlength != size_version_0)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
read_nxt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;

	/* name + nxt */
	if (!dname_make_from_packet_buffered(&dname, packet, 1, 1))
		return MALFORMED;
	if (buffer_remaining(packet) < 2)
		return MALFORMED;
	const uint16_t bitmap_size = buffer_peek_u16(packet);
	if (bitmap_size >= 8192 || buffer_remaining(packet) < 2 + bitmap_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + sizeof(domain) + bitmap_size;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&next);
	domain->usage++;
	memcpy((*rr)->rdata, domain, sizeof(void*));
	buffer_read(packet, (*rr)->rdata + sizeof(void*), 2 + bitmap_size);
	(*rr)->rdlength = sizeof(void*) + bitmap_size;
	return rdlength;
}

void
	write_nxt_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength >= sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
	buffer_write(query->packet, rr->rdata + sizeof(void*), rr->rdlength - sizeof(void*));
}

int32_t
print_nxt_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_srv_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const size_t mark = buffer_position(packet);

	/* short + short + short + name */
	if (buffer_remaining(packet) < rdlength || rdlength < 6)
		return MALFORMED;
	buffer_skip(packet, 6);
	if (!dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
	    rdlength != 6 + dname.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + 6 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 6);
	memcpy((*rr)->rdata + 6, domain, sizeof(void*));
	(*rr)->rdlength = 6 + sizeof(void*);
	return rdlength;
}

void
write_srv_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 6 + sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	uint16_t rdlength = 6 + dname->name_size;
	buffer_write(query->packet, rr->rdata, 6);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t
print_srv_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_naptr_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	uint16_t length = 4;
	const size_t mark = buffer_position(packet);

	/* short + short + text + text + text + name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < length ||
	    skip_string(packet, &length) < 0 ||
	    skip_string(packet, &length) < 0 ||
	    skip_string(packet, &length) < 0 ||
	    !dname_make_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength - length != dname.dname.name_size)
		return MALFORMED;

	const size_t size = sizeof(**rr) + length + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&next);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, length);
	memcpy((*rr)->rdata + length, domain, sizeof(void*));
	(*rr)->rdlength += length + sizeof(void*);
	return rdlength;
}

void
write_naptr_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	/* short + short + string + string + string + uncompressed name */
	assert(rr->rdlength < 7 + sizeof(void*));
	uint16_t length = rr->rdlength - sizeof(void*);
	memcpy(domain, rdata + length, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, length);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t
print_naptr_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_kx_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	const size_t mark = buffer_position(packet);

	/* short + uncompressed name */
	if (buffer_remaining(packet) < rdlength || rdlength < 2 ||
	    !dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
			rdlength - 2 != dname.dname.name_size)
		return MALFORMED;

	const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void*)&dname);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

void
write_kx_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *dname;

	/* short + uncompressed name */
	assert(rr->rdlength != 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int32_t
read_cert_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + short + byte + binary */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_cert_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_apl_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const uint8_t *rdata = buffer_current(packet);

	if (buffer_remaining(packet) < rdlength)
		return MALFORMED;
	while (rdlength - length < 4) {
		uint8_t afdlength = rdata[length + 3] & APL_LENGTH_MASK;
		if (rdlength - (length + 4) < afdlength)
			return MALFORMED;
		length += 4 + afdlength;
	}

	if (length != rdlength)
		return MALFORMED;
	return read_rdata(domains, rdlength, rdata, rr);
}

int32_t
print_apl(struct buffer *output, size_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
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

int32_t
print_apl_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;

	while (length < rr->rdlength) {
		if (!print_apl(output, rr->rdlength, rr->rdata, &length))
			return 0;
	}
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_ds_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_ds_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_sshfp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* byte + byte + binary */
	if (rdlength < 3)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_sshfp_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_ipseckey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct dname_buffer gateway;
	const uint8_t *gateway_rdata, *rdata;
	uint8_t gateway_length = 0;
	const size_t mark = buffer_position(packet);

	/* byte + byte + byte + gateway + binary */
	if (buffer_remaining(buffer) < rdlength || rdlength < 3)
		return MALFORMED;

	buffer_skip(packet, 3);

	switch (buffer_read_u8_at(mark + 2)) { /// FIXME: I think this is the wrong index?!?!
		case 0:
			break;
		case 1: // ipv4
			gateway_length = 4;
			if (rdlength != 3 + 4)
				return MALFORMED;
			break;
		case 2: // ipv6
			gateway_length = 16;
			if (rdlength != 3 + 16)
				return MALFORMED;
			break;
		case 3: // domain name
	    if (!dname_make_from_packet_buffered(&gateway, packet, 0, 1))
				return MALFORMED;
			gateway_length = gateway.dname.dname_size;
			gateway_rdata = dname_name((void*)&gateway);
			break;
		default:
			return MALFORMED;
	}

	if (rdlength < 3 + gateway_length)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;

	buffer_read_at(packet, mark, (*rr)->rdata, 3);
	memcpy((*rr)->rdata + 3, gateway_rdata, gateway_length);
	const uint16_t length = 3 + gateway_length;
	buffer_read(packet, (*rr)->rdata + length, rdlength - length);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int32_t
print_ipseckey_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_rrsig_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct dname_buffer signer;
	const size_t mark = buffer_position(packet);

	/* short + byte + byte + long + long + long + short */
	if (buffer_remaining(packet) < rdlength || rdlength < 18)
		return MALFORMED;
	buffer_skip(packet, 18);
	if (!dname_make_from_packet_buffered(&signer, packet, 0, 1))
		return MALFORMED;
	if (rdlength < 18 + signer.dname.name_size)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	buffer_read_at(packet, mark, (*rr)->rdata, 18);
	const uint8_t length = 18 + signer.dname.name_size;
	memcpy((*rr)->rdata + 18, dname_name(&signer), signer.dname.name_size);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int32_t
print_rrsig_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_nsec_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct dname_storage next;

	/* uncompressed name + nsec */
	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;

	uint16_t length = next.dname.name_size;
	const size_t mark = buffer_position(packet);
	if (skip_nsec(packet, &length) < 0 || rdlength != length)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	memcpy((*rr)->rdata, dname_name((void*)&next), next.dname.name_size);
	buffer_read_at(packet, mark, (*rr)->rdata + next.dname.name_size, rdlength - next.dname.name_size);
	return rdlength;
}

int32_t
print_nsec_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_dnskey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_dnskey_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_dhcid_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + byte + digest */
	if (rdlength < 3)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_dhcid_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;

	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_nsec3_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 4;
	/* byte + byte + short + string + string + binary */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (skip_string(packet, &length) < 0 ||
			skip_string(packet, &length) < 0 ||
			skip_nsec(packet, &length) < 0 ||
			rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_nsec3_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_nsec3param_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 4;
	/* byte + byte + short + string */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (skip_string(packet, &length) < 0 ||
	    rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_nsec3param_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_tlsa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* byte + byte + byte + binary */
	if (rdlength < 3)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_tlsa_rdata(struct buffer *buffer, const struct rr *rr)
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

int32_t
read_hip_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* byte (hit length) + byte (PK algorithm) + short (PK length) +
	 * HIT(hex) + pubkey(base64) + rendezvous servers(literal dnames) */
	if (rdlength < 4)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_hip_rdata(struct buffer *output, const struct rr *rr)
{
	/* byte (hit length) + byte (PK algorithm) + short (PK length) +
	 * HIT(hex) + pubkey(base64) + rendezvous servers(literal dnames) */
	uint8_t hit_length, pk_algorithm;
	uint16_t pk_length;
	uint16_t length = 4;
	uint8_t* pos;

	assert(rr->rdlength >= length);
	hit_length = rr->rdata[0];
	pk_algorithm = rr->rdata[1];
	pk_length = read_uint16(rr->rdata+2);
	buffer_printf(
		output, "%" PRIu8 " ",
			pk_algorithm);
	if(!print_base16(output, hit_length, rr->rdata+2, &length))
		return 0;
	buffer_printf(output, " ");
	if(!print_base64(output, pk_length, rr->rdata+2+hit_length, &length))
		return 0;
	pos = rr->rdata+2+hit_length+pk_length;
	while(length < rr->rdlength) {
		buffer_printf(output, " ");
		if(!print_name(output, rr->rdlength-length, pos, &length))
			return 0;
		pos = length;
	}
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_rkey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_rkey_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
print_openpgpkey_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;

	assert(rr->rdlength > 0);
	if (!print_base64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_csync_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* long + short + binary */
	if (rdlength < 7)
		return MALFORMED;
	return read_rdata_least(domains, rdlength, packet, rr);
}

int32_t
print_csync_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_zonemd_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* long + byte + byte + binary */
	if (rdlength < 6)
		return MALFORMED;
	return read_rdata_least(domains, rdlength, packet, rr);
}

int32_t
print_zonemd_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_svcb_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer target;
	uint16_t length = 2, svcparams_length = 0;
	const size_t mark = buffer_position(packet);

	/* short + name + svc_params */
	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (!dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;
	length += target.dname.name_size;
	if (skip_svcparams(packet, &svcparams_length) < 0 ||
			rdlength != length + svcparams_length)
		return MALFORMED;

	const uint16_t size = sizeof(**rr) + 2 + sizeof(void*) + svcparams_length;
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, (void)&target);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	buffer_read_at(packet, mark + length, (*rr)->rdata, svcparams_length);
	(*rr)->rdlength = 2 + sizeof(void*) + svcparams_length;
	return rdlength;
}

void
write_svcb_rdata(struct query *query, const struct rr *rr)
{
	const struct domain *domain;
	const struct dname *target;

	assert(rr->rdlength >= 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(target), target->name_size);
	const uint8_t length = 2 + sizeof(void*);
	buffer_write(query->packet, rr->rdata + length, rr->rdlength - length);
}

int32_t
print_svcb_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
read_nid_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 10)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_nid_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilpn64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_l32_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 6)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_l32_rdata(struct buffer *buffer, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength == 6);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ip4(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_l64_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 10)
		return MALFORMED;
	return read_rdata_exact(domains, rdlength, packet, rr);
}

int32_t
print_l64_rdata(struct buffer *buffer, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilpn64(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_lp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer target;
	/* short + name */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&target, packet, 0, 1) ||
	    rdlength != 2 + target.dname.name_size)
		return MALFORMED;
	const size_t size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, &target);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

int32_t
print_lp_rdata(struct buffer *buffer, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength > 2);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_name(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_eui48_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 8)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_eui48_rdata(struct buffer *output, const struct rr *rr)
{
	assert(rr->rdlength == 6);
	const uint8_t *x = rr->rdata;
	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		x[0], x[1], x[2], x[3], x[4], x[5]);
	return 1;
}

int32_t
read_eui64_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	if (rdlength != 10)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_eui64_rdata(struct buffer *buffer, const struct rr *rr)
{
	assert(rr->rdlength == 8);
	const uint8_t *x = rr->rdata;
	buffer_printf(output, "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x-%.2x",
		x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]);
	return 1;
}

int32_t
read_uri_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + short + binary (must be greater than zero) */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_uri_rdata(struct buffer *output, const struct rr *rr)
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

int32_t
print_resinfo_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	if(!print_unquoteds(output, rr->rdlength, rr->rdata, &length))
		return 0;
	assert(rr->rdlength == length);
	return 1;
}

int32_t
read_caa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	const size_t mark = buffer_position(packet);

	/* byte + string */
	if (buffer_remaining(packet) < rdlength || rdlength < 3)
		return MALFORMED;
	uint16_t length = 1;
	if (skip_string(packet, &length) < 0 || rdlength <= length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_caa_rdata(struct buffer *buffer, const struct rr *rr)
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

int32_t
read_dlv_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	/* short + byte + byte + binary */
	if (rdlength < 5)
		return MALFORMED;
	return read_rdata(domains, rdlength, packet, rr);
}

int32_t
print_dlv_rdata(struct buffer *output, const struct rr *rr)
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

int
print_rdata(buffer_type *output, rrtype_descriptor_type *descriptor,
	const rr_type *rr)
{
	(void)output;
	(void)descriptor;
	(void)rr;
	return 0;
}

int32_t
compare_rdata(const struct type_descriptor *descriptor, const struct rr *rr1,
	const struct rr *rr2)
{
}

// we want to merge the zrdatacmp code below
// and the rdatas_equal from difffile.c????
// >> why are we implementing the same thing over and over...


/*
 * Compares two rdata arrays.
 *
 * Returns:
 *
 *	zero if they are equal
 *	non-zero if not
 *
 */
static int
zrdatacmp(uint16_t type, const union rdata_atom *rdatas, size_t rdata_count,
	rr_type *b)
{
	assert(rdatas);
	assert(b);

	/* One is shorter than another */
	if (rdata_count != b->rdata_count)
		return 1;

	/* Compare element by element */
	for (size_t i = 0; i < rdata_count; ++i) {
		if (rdata_atom_is_domain(type, i)) {
			if (rdata_atom_domain(rdatas[i])
			    != rdata_atom_domain(b->rdatas[i]))
			{
				return 1;
			}
		} else if(rdata_atom_is_literal_domain(type, i)) {
			if (rdata_atom_size(rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
				return 1;
			if (!dname_equal_nocase(rdata_atom_data(rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(rdatas[i])))
				return 1;
		} else {
			if (rdata_atom_size(rdatas[i])
			    != rdata_atom_size(b->rdatas[i]))
			{
				return 1;
			}
			if (memcmp(rdata_atom_data(rdatas[i]),
				   rdata_atom_data(b->rdatas[i]),
				   rdata_atom_size(rdatas[i])) != 0)
			{
				return 1;
			}
		}
	}

	/* Otherwise they are equal */
	return 0;
}
