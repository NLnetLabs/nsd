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
#include "query.h"

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

/* Print svcparam key without a value */
static int print_svcparam_no_value(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen);

/* Print svcparam mandatory */
static int print_svcparam_mandatory(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam alpn */
static int print_svcparam_alpn(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam port */
static int print_svcparam_port(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam ipv4hint */
static int print_svcparam_ipv4hint(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam ech */
static int print_svcparam_ech(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam ipv6hint */
static int print_svcparam_ipv6hint(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam dohpath */
static int print_svcparam_dohpath(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

/* Print svcparam tls-supported-groups */
static int print_svcparam_tls_supported_groups(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen);

static const nsd_svcparam_descriptor_t svcparams[] = {
	{ SVCB_KEY_MANDATORY, "mandatory", print_svcparam_mandatory },
	{ SVCB_KEY_ALPN, "alpn", print_svcparam_alpn },
	{ SVCB_KEY_NO_DEFAULT_ALPN, "no-default-alpn",
		print_svcparam_no_value },
	{ SVCB_KEY_PORT, "port", print_svcparam_port },
	{ SVCB_KEY_IPV4HINT, "ipv4hint", print_svcparam_ipv4hint },
	{ SVCB_KEY_ECH, "ech", print_svcparam_ech },
	{ SVCB_KEY_IPV6HINT, "ipv6hint", print_svcparam_ipv6hint },
	{ SVCB_KEY_DOHPATH, "dohpath", print_svcparam_dohpath },
	{ SVCB_KEY_OHTTP, "ohttp", print_svcparam_no_value },
	{ SVCB_KEY_TLS_SUPPORTED_GROUPS, "tls-supported-groups",
		print_svcparam_tls_supported_groups },
};

/*
 * Print domain name, as example.com. with escapes.
 * The domain name is wireformat in the rdata. That is a literal dname
 * in the rdata.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_name_literal(struct buffer *output, uint16_t rdlength,
	const uint8_t *rdata, uint16_t *offset)
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

/*
 * Print domain name, as example.com. with escapes.
 * The domain must be a reference in the rdata. That is a stored pointer
 * to struct domain.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
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
skip_string(struct buffer* output, uint16_t rdlength, uint16_t* offset)
{
	int32_t length;
	if (rdlength - *offset < 1)
		return -1;
	length = buffer_read_u8(output);
	if (length + 1 > rdlength - *offset)
		return -1;
	buffer_skip(output, length);
	*offset += length + 1;
	return length + 1;
}

/* Return length of strings or -1 on wireformat error. offset is moved +len. */
static inline int32_t
skip_strings(struct buffer* output, uint16_t rdlength, uint16_t* offset)
{
	int32_t olen = 0;
	while(*offset < rdlength) {
		int32_t slen = skip_string(output, rdlength, offset);
		if(slen < 0)
			return slen;
		olen += slen;
	}
	return olen;
}

/*
 * Print string, as "string" with escapes.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
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
	*offset += 1;
	*offset += n;
	return 1;
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
	if(((size_t)*offset) + 4 > rdlength)
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

/*
 * Print ilnp64 field.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
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

/*
 * Print certificate type.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
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
	*offset += 2;
	return 1;
}

/*
 * Print time field.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_time(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	time_t time;
	struct tm tmbuf;
	struct tm* tm;
	char buf[15];

	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;
	time = (time_t)read_uint32(rdata + *offset);
	tm = gmtime_r(&time, &tmbuf);
	if (!strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm))
		return 0;
	buffer_printf(output, "%s", buf);
	*offset += 4;
	return 1;
}

/*
 * Print base32 output for a b32 field length uint8_t, like for NSEC3.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_base32(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	size_t size;
	int length;
	if(rdlength - *offset == 0)
		return 0;
	size = rdata[*offset];
	if (rdlength - ((size_t)*offset) < 1 + size)
		return 0;

	if (size == 0) {
		buffer_write(output, "-", 1);
		*offset += 1;
		return 1;
	}

	buffer_reserve(output, length * 2 + 1);
	length = b32_ntop(rdata + *offset + 1, size,
			  (char *)buffer_current(output), size * 2);
	if (length == -1)
		return 0;
	buffer_skip(output, length);
	*offset += 1 + size;
	return 1;
}

/*
 * Print base64 output for the remainder of rdata.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_base64(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	int length;
	size_t size = rdlength - *offset;
	if(size == 0) {
		/* single zero represents empty buffer */
		buffer_write(output, "0", 1);
		return 1;
	}
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata + *offset, size,
			  (char *) buffer_current(output), size * 2);
	if (length == -1)
		return 0;
	buffer_skip(output, length);
	*offset += size;
	return 1;
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

/*
 * Print base16 output for the remainder of rdata, in hex lowercase.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_base16(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	size_t size = rdlength - *offset;
	if(size == 0) {
		/* single zero represents empty buffer, such as CDS deletes */
		buffer_write(output, "0", 1);
		return 1;
	} else {
		hex_to_string(output, rdata+*offset, size);
	}
	*offset += size;
	return 1;
}

/*
 * Print salt, for NSEC3, in hex lowercase.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
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
	*offset += 1 + (uint16_t)length;
	return 1;
}

/* Return length of nsec type bitmap or -1 on wireformat error. offset is
 * moved +len. rdlength is the length of the rdata, offset is offset in it. */
static inline int32_t
skip_nsec(struct buffer* packet, uint16_t rdlength, uint16_t *offset)
{
	uint16_t length = 0;
	uint8_t last_window;

	while (rdlength - *offset - length > 2) {
		uint8_t window = buffer_read_u8(packet);
		uint8_t blocks = buffer_read_u8(packet);
		if (window <= last_window)
			return -1; // could make this a semantic error...
		if (!blocks || blocks > 32)
			return -1;
		if (rdlength - *offset - length < 2 + blocks)
			return -1;
		buffer_skip(packet, blocks);
		length += 2 + blocks;
		last_window = window;
	}

	if (rdlength != length)
		return -1;

	*offset += length;
	return length;
}

/*
 * Print nsec type bitmap, for the remainder of rdata.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_nsec_bitmap(struct buffer *output, uint16_t rdlength,
	const uint8_t *rdata, uint16_t *offset)
{
	int insert_space = 0;

	while(rdlength - *offset > 0) {
		uint8_t window, bitmap_size;
		const uint8_t* bitmap;
		int i;

		if(rdlength - *offset < 2)
			return 0;
		window = rdata[0];
		bitmap_size = rdata[1];
		*offset += 2;

		if(rdlength - *offset < bitmap_size)
			return 0;

		bitmap = rdata + 2;
		rdata += 2;
		for(i=0; i<((int)bitmap_size)*8; i++) {
			if(get_bit(bitmap, i)) {
				buffer_printf(output,
					      "%s%s",
					      insert_space ? " " : "",
					      rrtype_to_string(
						      window * 256 + i));
				insert_space = 1;
			}
		}
		rdata += bitmap_size;
		*offset += bitmap_size;
	}
	return 1;
}

/* If an svcparam must have a value */
static int
svcparam_must_have_value(uint16_t svcparamkey)
{
	switch (svcparamkey) {
	case SVCB_KEY_ALPN:
	case SVCB_KEY_PORT:
	case SVCB_KEY_IPV4HINT:
	case SVCB_KEY_IPV6HINT:
	case SVCB_KEY_MANDATORY:
	case SVCB_KEY_DOHPATH:
	case SVCB_KEY_TLS_SUPPORTED_GROUPS:
		return 1;
	default:
	}
	return 0;
}

/* If an svcparam must not have a value */
static int
svcparam_must_not_have_value(uint16_t svcparamkey)
{
	switch (svcparamkey) {
	case SVCB_KEY_NO_DEFAULT_ALPN:
	case SVCB_KEY_OHTTP:
		return 1;
	default:
	}
	return 0;
};

/*
 * Skip over the svcparams in the packet. Moves position.
 * @param packet: wire packet, position at rdata fields of svcparams.
 * @param rdlength: remaining rdata length in the packet.
 * @return 0 on wireformat error.
 */
static inline int
skip_svcparams(struct buffer *packet, uint16_t rdlength)
{
	unsigned pos = 0;
	uint16_t key, count;
	while(pos < rdlength) {
		if(pos+4 > (unsigned)rdlength)
			return 0;
		if(!buffer_available(packet, 4))
			return 0;
		key = buffer_read_u16(packet);
		count = buffer_read_u16(packet);
		if(count == 0 && svcparam_must_have_value(key))
			return 0;
		if(count != 0 && svcparam_must_not_have_value(key))
			return 0;
		pos += 4;
		if(pos+count > (unsigned)rdlength)
			return 0;
		if(!buffer_available(packet, count))
			return 0;
		buffer_skip(packet, count);
		pos += count;
	}
	return 1;
}

/*
 * Print svcparamkey name to the buffer, or unknown as key<NUM>.
 * @param output: printed to string.
 * @param svcparamkey: the key to print.
 */
static void
buffer_print_svcparamkey(buffer_type *output, uint16_t svcparamkey)
{
	if (svcparamkey < sizeof(svcparams)/sizeof(svcparams[0]))
		buffer_printf(output, "%s", svcparams[svcparamkey].name);
	else
		buffer_printf(output, "key%" PRIu16, svcparamkey);
}

static int
print_svcparam_no_value(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* ATTR_UNUSED(data), uint16_t ATTR_UNUSED(datalen))
{
	buffer_print_svcparamkey(output, svcparamkey);
	return 1;
}

static int
print_svcparam_mandatory(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	assert(datalen > 0); /* Guaranteed by svcparam_print */

	if (datalen % sizeof(uint16_t))
		return 0; /* wireformat error, val_len must be multiple of shorts */
	buffer_print_svcparamkey(output, svcparamkey);
	buffer_write_u8(output, '=');
	buffer_print_svcparamkey(output, read_uint16(data));
	data += 2;

	while ((datalen -= sizeof(uint16_t))) {
		buffer_write_u8(output, ',');
		buffer_print_svcparamkey(output, read_uint16(data));
		data += 2;
	}

	return 1;
}

static int
print_svcparam_alpn(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	uint8_t *dp = (void *)data;

	assert(datalen > 0); /* Guaranteed by svcparam_print */

	buffer_print_svcparamkey(output, svcparamkey);
	buffer_write_u8(output, '=');
	buffer_write_u8(output, '"');
	while (datalen) {
		uint8_t i, str_len = *dp++;

		if (str_len > --datalen)
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
		if ((datalen -= str_len))
			buffer_write_u8(output, ',');
	}
	buffer_write_u8(output, '"');
	return 1;
}

static int
print_svcparam_port(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	if (datalen != 2)
		return 0; /* wireformat error, a short is 2 bytes */
	buffer_print_svcparamkey(output, svcparamkey);
	buffer_printf(output, "=%d", (int)read_uint16(data));
	return 1;
}

static int
print_svcparam_ipv4hint(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	char ip_str[INET_ADDRSTRLEN + 1];
	
	assert(datalen > 0); /* Guaranteed by svcparam_print */

	buffer_print_svcparamkey(output, svcparamkey);
	if ((datalen % IP4ADDRLEN) == 0) {
		if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP4ADDRLEN;

		while ((datalen -= IP4ADDRLEN) > 0) {
			if (inet_ntop(AF_INET, data, ip_str, sizeof(ip_str))
				== NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP4ADDRLEN;
		}
		return 1;
	}
	return 0;
}

static int
print_svcparam_ech(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	int length;

	assert(datalen > 0); /* Guaranteed by svcparam_print */

	buffer_print_svcparamkey(output, svcparamkey);
	buffer_write_u8(output, '=');

	buffer_reserve(output, datalen * 2 + 1);
	length = b64_ntop(data, datalen, (char*)buffer_current(output),
		datalen * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}

	return length != -1;
}

static int
print_svcparam_ipv6hint(struct buffer *output, uint16_t svcparamkey,
	const uint8_t* data, uint16_t datalen)
{
	char ip_str[INET6_ADDRSTRLEN + 1];

	assert(datalen > 0); /* Guaranteed by svcparam_print */

	buffer_print_svcparamkey(output, svcparamkey);
	if ((datalen % IP6ADDRLEN) == 0) {
		if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str)) == NULL)
			return 0; /* wireformat error, incorrect size or inet family */

		buffer_printf(output, "=%s", ip_str);
		data += IP6ADDRLEN;

		while ((datalen -= IP6ADDRLEN) > 0) {
			if (inet_ntop(AF_INET6, data, ip_str, sizeof(ip_str))
				== NULL)
				return 0; /* wireformat error, incorrect size or inet family */

			buffer_printf(output, ",%s", ip_str);
			data += IP6ADDRLEN;
		}
		return 1;
	}
	return 0;
}

static int
print_svcparam_tls_supported_groups(struct buffer *output,
	uint16_t svcparamkey, const uint8_t* data, uint16_t datalen)
{
	assert(datalen > 0); /* Guaranteed by svcparam_print */

	if ((datalen % sizeof(uint16_t)) == 1)
		return 0; /* A series of uint16_t is an even number of bytes */

	buffer_print_svcparamkey(output, svcparamkey);
	buffer_printf(output, "=%d", (int)read_uint16(data));
	data += 2;
	while ((datalen -= sizeof(uint16_t)) > 0) {
		buffer_printf(output, ",%d", (int)read_uint16(data));
		data += 2;
	}
	return 1;
}

/*
 * Print svcparam.
 * @param output: the string is output here.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata. The rdata+*offset is where the field is.
 * @param offset: the current position on input. The position is updated to
 *	be incremented with the length of rdata that was used.
 * @return false on failure.
 */
static int
print_svcparam(struct buffer *output, uint16_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	uint16_t key, length;
	const uint8_t* dp;
	unsigned i;

	assert(rdlength >= *offset);
	if (rdlength - *offset < 4)
		return 0;

	key = read_uint16(rdata + *offset);
	length = read_uint16(rdata + *offset + 2);

	if (rdlength - *offset <= length + 4)
		return 0; /* wireformat error */

	if(length == 0 && svcparam_must_have_value(key))
		return 0;
	if(length != 0 && svcparam_must_not_have_value(key))
		return 0;
	if (key < sizeof(svcparams)/sizeof(svcparams[0])) {
		if(!svcparams[key].print_rdata(output, key, rdata+4, length))
			return 0;
		*offset += length+4;
		return 1;
	}

	buffer_printf(output, "key%" PRIu16, key);
	if (!length)
		return 1;

	buffer_write(output, "=\"", 2);
	dp = rdata + *offset + 4;

	for (i = 0; i < length; i++) {
		if (dp[i] == '"' || dp[i] == '\\')
			buffer_printf(output, "\\%c", dp[i]);

		else if (!isprint(dp[i]))
			buffer_printf(output, "\\%03u", (unsigned) dp[i]);

		else
			buffer_write_u8(output, dp[i]);
	}
	buffer_write_u8(output, '"');
	*offset += length + 4;
	return 1;
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
	(*rr)->rdlength = rdlength;
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

int
lookup_rdata_field(const nsd_type_descriptor_t* descriptor, size_t index,
	const rr_type* rr, uint16_t offset, uint16_t* field_len,
	struct domain** domain)
{
	const nsd_rdata_descriptor_t* field = &descriptor->rdata.fields[index];
	if(field->calculate_length) {
		/* Call field length function. */
		*field_len = field->calculate_length(rr->rdlength, rr->rdata,
			offset);
		*domain = NULL;
	} else if(field->length >= 0) {
		*field_len = field->length;
		*domain = NULL;
	} else {
		size_t dlen;
		int32_t flen;
		/* Handle the specialized value cases. */
		switch(field->length) {
		case RDATA_COMPRESSED_DNAME:
		case RDATA_UNCOMPRESSED_DNAME:
			if(rr->rdlength - offset <
				(uint16_t)sizeof(void*))
				return 0;
			*field_len = sizeof(void*);
			memcpy(domain, rr->rdata+offset, sizeof(void*));
			break;
		case RDATA_LITERAL_DNAME:
			dlen = buf_dname_length(rr->rdata+offset,
				rr->rdlength-offset);
			if(dlen == 0)
				return 0;
			*field_len = dlen;
			*domain = NULL;
			break;
		case RDATA_STRING:
		case RDATA_BINARY:
			if(rr->rdlength - offset < 1)
				return 0;
			flen = (rr->rdata+offset)[0];
			if(rr->rdlength - offset < flen+1)
				return 0;
			*field_len = flen+1;
			*domain = NULL;
			break;
		case RDATA_IPSECGATEWAY:
			return 0; /* Has a callback function. */
		case RDATA_REMAINDER:
			*field_len = rr->rdlength - offset;
			*domain = NULL;
			break;
		default:
			/* Unknown specialized value. */
			return 0;
		}
	}
	return 1;
}

int32_t
rr_calculate_uncompressed_rdata_length(const rr_type* rr)
{
	size_t i;
	const nsd_type_descriptor_t* descriptor =
		nsd_type_descriptor(rr->type);
	uint16_t offset = 0;
	int32_t result = 0;
	for(i=0; i < descriptor->rdata.length; i++) {
		uint16_t field_len;
		struct domain* domain;
		if(rr->rdlength == offset &&
			descriptor->rdata.fields[i].is_optional)
			break; /* There are no more rdata fields. */
		if(!lookup_rdata_field(descriptor, i, rr, offset, &field_len,
			&domain))
			return -1; /* malformed rdata buffer */
		if(domain != NULL) {
			/* Handle RDATA_COMPRESSED_DNAME and
			 * RDATA_UNCOMPRESSED_DNAME fields. */
			const struct dname* dname = domain_dname(domain);
			result += dname->name_size;
		} else {
			result += field_len;
		}
		offset += field_len;
	}
	return result;
}

int print_unknown_rdata(buffer_type *output,
	const nsd_type_descriptor_t *descriptor, const rr_type *rr)
{
	size_t i;
	int32_t size;
	uint16_t length = 0;

	if(!descriptor->has_references) {
		/* There are no references to the domain table, the
		 * rdata can be printed literally. */
		buffer_printf(output, " \\# %lu ", (unsigned long)rr->rdlength);
		hex_to_string(output, rr->rdata, rr->rdlength);
		return 1;
	}

	size = rr_calculate_uncompressed_rdata_length(rr);
	if(size < 0)
		return 0;
	buffer_printf(output, " \\# %lu ", (unsigned long) size);

	for(i=0; i < descriptor->rdata.length; i++) {
		uint16_t field_len;
		struct domain* domain;
		const uint8_t* to_print;
		size_t to_print_len;
		if(rr->rdlength == length &&
			descriptor->rdata.fields[i].is_optional)
			break; /* There are no more rdata fields. */
		if(!lookup_rdata_field(descriptor, i, rr, length, &field_len,
			&domain))
			return 0; /* malformed rdata buffer */
		if(domain != NULL) {
			/* Handle RDATA_COMPRESSED_DNAME and
			 * RDATA_UNCOMPRESSED_DNAME fields. */
			const struct dname* dname = domain_dname(domain);
			to_print = dname_name(dname);
			to_print_len = dname->name_size;
		} else {
			to_print = rr->rdata+length;
			to_print_len = field_len;
		}
		hex_to_string(output, to_print, to_print_len);
		length += field_len;
	}
	return 1;
}

/* This structure is sufficient in size for a struct dname. It can
 * be cast to a struct dname*, since it has the same data. */
struct dname_buffer {
	struct dname dname;
	/* storage for labelcount, and for the wireformat name.
	 * The labelcount can be 1 byte per label, maxlen/2 + 1(root label).
	 * The wireformat name, MAXDOMAINLEN+1.
	 * This allocates storage for it, due to alignment, the struct
	 * dname may have padding. The actual content would be after the
	 * sizeof(struct dname), of label_offsets and name. */
	uint8_t storage[MAXDOMAINLEN/2 + 1 + MAXDOMAINLEN+1 ];
};

/*
 * Parse a domain name from packet and store it in the buffer.
 * @param dname: the buffer with sufficient size for the dname.
 * @param packet: packet, at the position of the dname. The position is moved.
 * @param allow_pointers: set to true if compression pointers are allowed.
 * @param normalize: set to true if the domain name has to be normalized.
 * @return 0 on failure, or name_length when done.
 */
int
dname_make_from_packet_buffered(struct dname_buffer* dname,
	buffer_type *packet, int allow_pointers, int normalize)
{
	int wirelen = dname_make_wire_from_packet(dname->storage,
		packet, allow_pointers);
	return wirelen;
}

int32_t
read_compressed_name_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	size_t size;
	const size_t mark = buffer_position(packet);

	if (!dname_make_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength < buffer_position(packet) - mark)
		return MALFORMED;
	size = sizeof(**rr) + sizeof(void*);
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
	size_t size;

	if (!dname_make_from_packet_buffered(&dname, packet,
		1 /* Lenient, allows pointers. */, 1) ||
			rdlength < dname.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + sizeof(void*);
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
	struct domain *domain;
	assert(rr->rdlength == sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	encode_dname(query, domain);
}

void
write_uncompressed_name_rdata(struct query *query, const struct rr *rr)
{
	const struct dname *dname;
	struct domain *domain;
	assert(rr->rdlength >= sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int
print_name_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength == sizeof(void*));
	/* This prints a reference to a name stored as a pointer. */
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

int
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
	struct domain *primary_domain, *mailbox_domain;
	struct dname_buffer primary, mailbox;
	size_t size;

	/* name + name + long + long + long + long + long */
	const size_t mark = buffer_position(packet);
	if (!dname_make_from_packet_buffered(&primary, packet, 1, 1) ||
	    !dname_make_from_packet_buffered(&mailbox, packet, 1, 1) ||
	    rdlength != (buffer_position(packet) - mark) + 20)
		return MALFORMED;

	size = sizeof(**rr) + 2 * sizeof(struct domain *) + 20;
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
	struct domain *primary, *mailbox;
	/* domain + domain + long + long + long + long + long */
	assert(rr->rdlength == 2 * sizeof(void*) + 20);
	memcpy(primary, rr->rdata, sizeof(void*));
	memcpy(mailbox, rr->rdata + sizeof(void*), sizeof(void*));
	encode_dname(query, primary);
	encode_dname(query, mailbox);
	buffer_write(query->packet, rr->rdata + (2 * sizeof(void*)), 20);
}

int
print_soa_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	uint32_t serial, refresh, retry, expire, minimum;
	assert(rr->rdlength == 2 * sizeof(void*) + 20);
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, " ");
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;

	assert(length == 2 * sizeof(void*));
	serial = read_uint32(rr->rdata + length);
	refresh = read_uint32(rr->rdata + length + 4);
	retry = read_uint32(rr->rdata + length + 8);
	expire = read_uint32(rr->rdata + length + 12);
	minimum = read_uint32(rr->rdata + length + 16);

	buffer_printf(
		output, " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32 " %" PRIu32,
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
int
print_wks_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	uint8_t protocol;
	int bits;
	const uint8_t* bitmap;

	assert(rr->rdlength >= 5);
	if (!print_ip4(output, rr->rdlength, rr->rdata, &length))
		return 0;

	protocol = rr->rdata[4];
	if(protocol == 6)
		buffer_printf(output, "tcp");
	else if(protocol == 17)
		buffer_printf(output, "udp");
	else
		buffer_printf(output, "%" PRIu8, protocol);

	bits = (rr->rdlength - 5) * 8;
	bitmap = rr->rdata + 5;
	for (int service = 0; service < bits; service++) {
		if (get_bit(bitmap, service))
			buffer_printf(output, " %d", service);
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

int
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
	struct domain *rmailbx, *emailbx;
	assert(rr->rdlength == 2 * sizeof(void*));
	memcpy(rmailbx, rr->rdata, sizeof(void*));
	memcpy(emailbx, rr->rdata + sizeof(void*), sizeof(void*));
	encode_dname(query, rmailbx);
	encode_dname(query, emailbx);
}

int
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
	size_t size;

	/* short + name */
	const size_t mark = buffer_position(packet);
	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&exchange, packet, 1, 1))
		return MALFORMED;
	if (rdlength != 2 + exchange.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 2 + sizeof(void*);
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
	struct domain *domain;
	const struct dname *dname;
	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	buffer_write(query->packet, rr->rdata, 2);
	encode_dname(query, domain);
}

int
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
	if (skip_strings(packet, rdlength, &length) < 0 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(owners, rdlength, packet, rr);
}

int
print_txt_rdata(struct buffer *output, const struct rr *rr)
{
	int32_t code;
	uint16_t offset = 0;
	if (offset < rr->rdlength) {
		if (!print_string(output, rr->rdlength, rr->rdata, &length))
			return 0;
		while (offset < rr->rdlength) {
			buffer_printf(output, " ");
			if (!print_string(output, rr->rdlength, rr->rdata,
				&length))
				return 0;
		}
	}
	return 1;
}

int32_t
read_rp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *mbox_domain, *txt_domain;
	struct dname_buffer mbox, txt;
	size_t size;

	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&mbox, packet, 0, 1) ||
			!dname_make_from_packet_buffered(&txt, packet, 0, 1) ||
	    rdlength != mbox.dname.name_size + txt.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 2 * sizeof(void*);
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
	struct domain *mbox_domain, *txt_domain;
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
	size_t size;
	/* short + uncompressed name */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&hostname, packet, 0, 1) ||
	    rdlength != 2 + hostname.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 2 + sizeof(void*);
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
	struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(packet, rr->rdata, 2);
	buffer_write(packet, dname_name(dname), dname->name_size);
}

int
print_afsdb_rdata(struct buffer *output, const struct rr *rr)
{
	int32_t code;
	uint16_t subtype, length=2;
	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(&subtype, rr->rdata, sizeof(subtype));
	subtype = ntohs(subtype);
	buffer_printf(output, "%" PRIu16 " ", subtype);
	if(!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;
	return 0;
}

int32_t
read_x25_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	uint16_t length = 0;
	const size_t mark = buffer_position(packet);
	if (skip_string(packet, rdlength, &length) < 0 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int
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

	if (skip_string(packet, rdlength, &length) < 0
	 || skip_string(packet, rdlength, &length) < 0
	 || rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int
print_isdn_rdata(struct buffer *output, const struct rr *rr)
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
read_rt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	size_t size;
	const size_t mark = buffer_position(packet);

	if (rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&dname, packet, 0, 1))
		return MALFORMED;
	if (rdlength != 2 + dname.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 2 + sizeof(void*);
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
	struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 2 + sizeof(void*));
	memcpy(domain, (*rr)->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	if (!try_buffer_write_u16(query->packet, rdlength) ||
	    !try_buffer_write(query->packet, rr->rdata, 2) ||
			!try_buffer_write(query->packet, dname_name(dname), dname->name_size))
		return TRUNCATED;
	return rdlength;
}

int
print_nsap_rdata(struct buffer *output, const struct rr *rr)
{
	buffer_printf(output, "0x");
	hex_to_string(output, rr->rdata, rr->rdlength);
	return 0;
}

int
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
	size_t size;
	const uint16_t rdlength = buffer_read_u16(packet);
	const size_t mark = buffer_position(packet);

	/* short + uncompressed name + uncompressed name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < 2 ||
	    !dname_make_from_packet_buffered(&map822, packet, 0, 1) ||
	    !dname_make_from_packet_buffered(&mapx400, packet, 0, 1) ||
	    rdlength != 2 + map822.dname.name_size + mapx400.dname.name_size)
		return MALFORMED;

	size = sizeof(**rr) + 2 + 2*sizeof(void*);
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
	struct domain *map822_domain, *mapx400_domain;
	const struct dname *map822, *mapx400;

	memcpy(map822_domain, rr->rdata + 2, sizeof(void*));
	memcpy(mapx400_domain, rr->rdata + 2 + sizeof(void*), sizeof(void*));
	map822 = domain_dname(map822_domain);
	mapx400 = domain_dname(mapx400_domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(map822), map822->name_size);
	buffer_write(query->packet, dname_name(mapx400), mapx400->name_size);
}

int
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

int
print_aaaa_rdata(struct buffer *output, const struct rr *rr)
{
	assert(rr->rdlength == 16);
	return print_ip6(output, rr->rdlength, rr->rdata, &length);
}

int32_t
read_loc_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	size_t mark;
	uint8_t version;
	uint16_t size_version_0;

	/* version (byte) */
	if (rdlength < 1)
		return MALFORMED;
	/* version (byte) + size (byte) + horiz pre (byte) + vert pre (byte)
	 * latitude (long) + longitude (long) + altitude (long) */
	mark = buffer_position(packet);
	version = buffer_read_u8_at(packet, mark + 2);
	size_version_0 = 16u;
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
	size_t size;
	uint16_t bitmap_size;

	/* name + nxt */
	if (!dname_make_from_packet_buffered(&dname, packet, 1, 1))
		return MALFORMED;
	if (buffer_remaining(packet) < 2)
		return MALFORMED;
	bitmap_size = buffer_peek_u16(packet);
	if (bitmap_size >= 8192 || buffer_remaining(packet) < 2 + bitmap_size)
		return MALFORMED;
	size = sizeof(**rr) + sizeof(domain) + bitmap_size;
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
	struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength >= sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
	buffer_write(query->packet, rr->rdata + sizeof(void*), rr->rdlength - sizeof(void*));
}

int
print_nxt_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	int bitmap_size;
	const uint8_t* bitmap;

	assert(rr->rdlength > sizeof(void*));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
		return 0;

	bitmap_size = rr->rdlength - length;
	bitmap = rr->rdata + length;
	for (int type = 0; type < bitmap_size * 8; type++) {
		if (get_bit(bitmap, type)) {
			buffer_printf(output, "%s ", rrtype_to_string(type));
		}
	}

	buffer_skip(output, -1);
	return 1;
}

int32_t
read_srv_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	size_t size;
	const size_t mark = buffer_position(packet);

	/* short + short + short + name */
	if (buffer_remaining(packet) < rdlength || rdlength < 6)
		return MALFORMED;
	buffer_skip(packet, 6);
	if (!dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
	    rdlength != 6 + dname.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 6 + sizeof(void*);
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
	struct domain *domain;
	const struct dname *dname;

	assert(rr->rdlength == 6 + sizeof(void*));
	memcpy(domain, rr->rdata, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 6);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int
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

int
print_atma_rdata(struct buffer *output, const struct rr *rr)
{
	uint8_t format;
	if(rr->rdlength < 1)
		return 0;
	format = rr->rdata[0];
	if(format == 0) {
		/* AESA format (ATM End System Address). */
		uint16_t length = 1;
		if (!print_base16(output, rr->rdlength, rr->rdata, &length))
			return 0;
		assert(rr->rdlength == length);
		return 1;
	} else if(format == 1) {
		/* E.164 format. */
		/* '+' and then digits '0'-'9' from the rdata string. */
		buffer_printf(output, "+");
		for (size_t i = 1; i < rr->rdlength; i++) {
			char ch = (char)rr->rdata[i];
			if(!isdigit((unsigned char)ch))
				return 0;
			buffer_printf(output, "%c", ch);
		}
		return 1;
	}
	/* Unknown format. */
	return 0;
}

int32_t
read_naptr_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr)
{
	struct domain *domain;
	struct dname_buffer dname;
	uint16_t length = 4;
	size_t size;
	const size_t mark = buffer_position(packet);

	/* short + short + text + text + text + name */
	if (buffer_remaining(packet) < rdlength ||
	    rdlength < length ||
	    skip_string(packet, rdlength, &length) < 0 ||
	    skip_string(packet, rdlength, &length) < 0 ||
	    skip_string(packet, rdlength, &length) < 0 ||
	    !dname_make_from_packet_buffered(&dname, packet, 1, 1) ||
	    rdlength - length != dname.dname.name_size)
		return MALFORMED;

	size = sizeof(**rr) + length + sizeof(void*);
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
	struct domain *domain;
	const struct dname *dname;
	uint16_t length;

	/* short + short + string + string + string + uncompressed name */
	assert(rr->rdlength < 7 + sizeof(void*));
	length = rr->rdlength - sizeof(void*);
	memcpy(domain, rr->rdata + length, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, length);
	buffer_write(query->packet, dname_name(dname), dname->name_size);
}

int
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
	size_t size;

	/* short + uncompressed name */
	if (buffer_remaining(packet) < rdlength || rdlength < 2 ||
	    !dname_make_from_packet_buffered(&dname, packet, 0, 1) ||
			rdlength - 2 != dname.dname.name_size)
		return MALFORMED;

	size = sizeof(**rr) + 2 + sizeof(void*);
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
	struct domain *domain;
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

int
print_cert_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;
	assert(rr->rdlength > 5);
	if(!print_certificate_type(output, rr->rdlength, rr->rdata, &length))
		return 0;
	buffer_printf(output, "%" PRIu16 " %" PRIu8 " ",
		read_uint16(rr->rdata+2), rr->rdata[4]);
	length += 3;
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

/*
 * Print one ALP field.
 * @param output: string is printed to the buffer.
 * @param rdlength: length of rdata.
 * @param rdata: the rdata
 * @param offset: on input the current position, adjusted on output to
 *	increment for the rdata used.
 * @return false on failure.
 */
static int
print_apl(struct buffer *output, size_t rdlength, const uint8_t *rdata,
	uint16_t *offset)
{
	size_t size = rdlength - *offset;
	uint16_t address_family;
	uint8_t prefix, length, negated;
	int af;
	char text_address[INET6_ADDRSTRLEN + 1];
	uint8_t address[16];

	if (size < 4)
		return 0;

	address_family = read_uint16(rdata + *offset);
	prefix = rdata[*offset + 2];
	length = rdata[*offset + 3] & APL_LENGTH_MASK;
	negated = rdata[*offset + 3] & APL_NEGATION_MASK;
	af = -1;

	switch (address_family) {
	case 1: af = AF_INET; break;
	case 2: af = AF_INET6; break;
	}

	if (af == -1 || size - 4 < length)
		return 0;

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

int
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

int
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

int
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
	uint16_t length;

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
	length = 3 + gateway_length;
	buffer_read(packet, (*rr)->rdata + length, rdlength - length);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int
print_ipseckey_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 3;
	uint8_t gateway_type;

	assert(rr->rdlength >= length);
	buffer_printf(
		output, "%" PRIu8 " %" PRIu8 " %" PRIu8 " ",
		rr->rdata[0], rr->rdata[1], rr->rdata[2]);
	gateway_type = rr->rdata[1];
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
		if (!print_name_literal(output, rr->rdlength, rr->rdata,
			&length))
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
ipseckey_gateway_length(uint16_t rdlength, const uint8_t *rdata,
	uint16_t offset)
{
	uint8_t gateway_type;
	/* Calculate the gateway length, based on the gateway type.
	 * That is stored in an earlier field. */
	if(rdlength < 3 || offset < 3)
		return -1; /* too short */
	gateway_type = rdata[1];
	switch(gateway_type) {
	case IPSECKEY_NOGATEWAY:
		return 0;
	case IPSECKEY_IP4:
		return 4;
	case IPSECKEY_IP6:
		return 16;
	case IPSECKEY_DNAME:
		return buf_dname_length(rdata+offset, rdlength-offset);
	default:
		/* Unknown gateway type. */
		break;
	}
	return -1;
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
	memcpy((*rr)->rdata + 18, dname_name(&signer), signer.dname.name_size);
	(*rr)->rdlength = rdlength;
	return rdlength;
}

int
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

	if (!print_name_literal(output, rr->rdlength, rr-rdata, &length))
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
	uint16_t length;
	size_t mark;

	/* uncompressed name + nsec */
	if (buffer_remaining(packet) < rdlength ||
	    !dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;

	length = next.dname.name_size;
	mark = buffer_position(packet);
	if (skip_nsec(packet, rdlength, &length) < 0 || rdlength != length)
		return MALFORMED;
	if (!(*rr = region_alloc(domains->region, sizeof(**rr) + rdlength)))
		return TRUNCATED;
	memcpy((*rr)->rdata, dname_name((void*)&next), next.dname.name_size);
	buffer_read_at(packet, mark, (*rr)->rdata + next.dname.name_size, rdlength - next.dname.name_size);
	return rdlength;
}

int
print_nsec_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 0;

	assert(rr->rdlength > length);
	if (!print_name_literal(output, rr->rdlength, rr->rdata, &length))
		return 0;
	if (!print_nsec_bitmap(output, rr->rdlength, rr->rdata, &length))
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

int
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

int
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
	if (skip_string(packet, rdlength, &length) < 0 ||
			skip_string(packet, rdlength, &length) < 0 ||
			skip_nsec(packet, rdlength, &length) < 0 ||
			rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int
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
	if (!print_nsec_bitmap(output, rr->rdlength, rr->rdata, &length))
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
	if (skip_string(packet, rdlength, &length) < 0 ||
	    rdlength != length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int
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

int
print_tlsa_rdata(struct buffer *output, const struct rr *rr)
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

int
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
	if(!print_base16(output, hit_length, rr->rdata+4, &length))
		return 0;
	buffer_printf(output, " ");
	if(!print_base64(output, pk_length, rr->rdata+4+hit_length, &length))
		return 0;
	pos = rr->rdata+4+hit_length+pk_length;
	while(length < rr->rdlength) {
		buffer_printf(output, " ");
		if(!print_name_literal(output, rr->rdlength-length, pos,
			&length))
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

int
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

int
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

int
print_csync_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 6;

	assert(rr->rdlength > length);
	buffer_printf(
		output, "%" PRIu32 " %" PRIu16 " ",
		read_uint32(rr->rdata), read_uint16(rr->rdata + 4));
	if (!print_nsec_bitmap(output, rr->rdlength, rr->rdata, &length))
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

int
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
	uint16_t size;
	const size_t mark = buffer_position(packet);

	/* short + name + svc_params */
	if (buffer_remaining(packet) < rdlength || rdlength < length)
		return MALFORMED;
	buffer_skip(packet, length);
	if (!dname_make_from_packet_buffered(&next, packet, 0, 1))
		return MALFORMED;
	length += target.dname.name_size;
	if(!skip_svcparams(packet, rdlength-length))
		return MALFORMED;
	svcparams_length = rdlength - length;

	size = sizeof(**rr) + 2 + sizeof(void*) + svcparams_length;
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
	struct domain *domain;
	const struct dname *target;
	uint8_t length;

	assert(rr->rdlength >= 2 + sizeof(void*));
	memcpy(domain, rr->rdata + 2, sizeof(void*));
	dname = domain_dname(domain);
	buffer_write(query->packet, rr->rdata, 2);
	buffer_write(query->packet, dname_name(target), target->name_size);
	length = 2 + sizeof(void*);
	buffer_write(query->packet, rr->rdata + length, rr->rdlength - length);
}

int
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

int
print_nid_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_printf(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilnp64(output, rr->rdlength, rr->rdata, &length))
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

int
print_l32_rdata(struct buffer *output, const struct rr *rr)
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

int
print_l64_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength == 10);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_ilnp64(output, rr->rdlength, rr->rdata, &length))
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
	size_t size;
	/* short + name */
	const size_t mark = buffer_position(packet);

	if (buffer_remaining(packet) < rdlength || rdlength < 2)
		return MALFORMED;
	buffer_skip(packet, 2);
	if (!dname_make_from_packet_buffered(&target, packet, 0, 1) ||
	    rdlength != 2 + target.dname.name_size)
		return MALFORMED;
	size = sizeof(**rr) + 2 + sizeof(void*);
	if (!(*rr = region_alloc(domains->region, size)))
		return TRUNCATED;
	domain = domain_table_insert(domains, &target);
	domain->usage++;
	buffer_read_at(packet, mark, (*rr)->rdata, 2);
	memcpy((*rr)->rdata + 2, domain, sizeof(void*));
	(*rr)->rdlength = 2 + sizeof(void*);
	return rdlength;
}

int
print_lp_rdata(struct buffer *output, const struct rr *rr)
{
	uint16_t length = 2;

	assert(rr->rdlength > 2);
	buffer_output(output, "%" PRIu16 " ", read_uint16(rr->rdata));
	if (!print_domain(output, rr->rdlength, rr->rdata, &length))
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

int
print_eui48_rdata(struct buffer *output, const struct rr *rr)
{
	const uint8_t *x = rr->rdata;
	assert(rr->rdlength == 6);
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

int
print_eui64_rdata(struct buffer *output, const struct rr *rr)
{
	const uint8_t *x = rr->rdata;
	assert(rr->rdlength == 8);
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

int
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

int
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
	uint16_t length = 1;

	/* byte + string */
	if (buffer_remaining(packet) < rdlength || rdlength < 3)
		return MALFORMED;
	if (skip_string(packet, rdlength, &length) < 0 || rdlength <= length)
		return MALFORMED;
	buffer_set_position(packet, mark);
	return read_rdata(domains, rdlength, packet, rr);
}

int
print_caa_rdata(struct buffer *output, const struct rr *rr)
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

int
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
print_rdata(buffer_type *output, const nsd_type_descriptor_t *descriptor,
	const rr_type *rr)
{
	return descriptor->print_rdata(output, rr);
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
