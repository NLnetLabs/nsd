/*
 * rdata.h -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netdb.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "dns.h"
#include "rdata.h"
#include "namedb.h"
#include "zonec.h"
#include "zparser.h"

#ifndef B64_PTON
int b64_ntop(uint8_t const *src, size_t srclength,
	     char *target, size_t targsize);
#endif /* !B64_PTON */
#ifndef B64_NTOP
int b64_pton(char const *src, uint8_t *target, size_t targsize);
#endif /* !B64_NTOP */

/* Taken from RFC 2538, section 2.1.  */
lookup_table_type dns_certificate_types[] = {
	{ 1, "PKIX" },	/* X.509 as per PKIX */
	{ 2, "SPKI" },	/* SPKI cert */
        { 3, "PGP" },	/* PGP cert */
        { 253, "URI" },	/* URI private */
	{ 254, "OID" },	/* OID private */
	{ 0, NULL }
};

/* Taken from RFC 2535, section 7.  */
lookup_table_type dns_algorithms[] = {
	{ 1, "RSAMD5" },
	{ 2, "DS" },
	{ 3, "DSA" },
	{ 4, "ECC" },
	{ 5, "RSASHA1" },	/* XXX: Where is this specified? */
	{ 252, "INDIRECT" },
	{ 253, "PRIVATEDNS" },
	{ 254, "PRIVATEOID" },
	{ 0, NULL }
};

typedef int (*rdata_to_string_type)(buffer_type *output,
				    rdata_atom_type rdata);

static int
rdata_dname_to_string(buffer_type *output, rdata_atom_type rdata)
{
	buffer_printf(output,
		      "%s",
		      dname_to_string(domain_dname(rdata_atom_domain(rdata))));
	return 1;
}

static int
rdata_text_to_string(buffer_type *output, rdata_atom_type rdata)
{
	const uint8_t *data = rdata_atom_data(rdata);
	uint8_t length = data[0];
	size_t i;

	buffer_printf(output, "\"");
	for (i = 1; i <= length; ++i) {
		char ch = (char) data[i];
		if (isprint(ch)) {
			if (ch == '"' || ch == '\\') {
				buffer_printf(output, "\\");
			}
			buffer_printf(output, "%c", ch);
		} else {
			buffer_printf(output, "\\%03u",
				      (unsigned) ch);
		}
	}
	buffer_printf(output, "\"");
	return 1;
}

static int
rdata_byte_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint8_t data = * (uint8_t *) rdata_atom_data(rdata);
	buffer_printf(output, "%lu", (unsigned long) data);
	return 1;
}

static int
rdata_short_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint16_t data = read_uint16(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) data);
	return 1;
}

static int
rdata_long_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint32_t data = read_uint32(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) data);
	return 1;
}

static int
rdata_a_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int result = 0;
	char str[200];
	if (inet_ntop(AF_INET, rdata_atom_data(rdata), str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_aaaa_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int result = 0;
	char str[200];
	if (inet_ntop(AF_INET6, rdata_atom_data(rdata), str, sizeof(str))) {
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_rrtype_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint16_t type = read_uint16(rdata_atom_data(rdata));
	buffer_printf(output, "%s", rrtype_to_string(type));
	return 1;
}

static int
rdata_algorithm_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint8_t id = * (uint8_t *) rdata_atom_data(rdata);
	lookup_table_type *alg
		= lookup_by_id(dns_algorithms, id);
	if (alg) {
		buffer_printf(output, "%s", alg->name);
	} else {
		buffer_printf(output, "%u", (unsigned) id);
	}
	return 1;
}

static int
rdata_certificate_type_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint16_t id = read_uint16(rdata_atom_data(rdata));
	lookup_table_type *type
		= lookup_by_id(dns_certificate_types, id);
	if (type) {
		buffer_printf(output, "%s", type->name);
	} else {
		buffer_printf(output, "%u", (unsigned) id);
	}
	return 1;
}

static int
rdata_period_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint32_t period = read_uint32(rdata_atom_data(rdata));
	buffer_printf(output, "%lu", (unsigned long) period);
	return 1;
}

static int
rdata_time_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int result = 0;
	time_t time = (time_t) read_uint32(rdata_atom_data(rdata));
	struct tm *tm = gmtime(&time);
	char buf[15];
	if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm)) {
		buffer_printf(output, "%s", buf);
		result = 1;
	}
	return result;
}

static int
rdata_base64_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int length;
	size_t size = rdata_atom_size(rdata);
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(rdata_atom_data(rdata), size,
			  (char *) buffer_current(output), size * 2);
	if (length > 0) {
		buffer_skip(output, length);
	}
	return length != -1;
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
rdata_hex_to_string(buffer_type *output, rdata_atom_type rdata)
{
	hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
	return 1;
}

static int
rdata_nsap_to_string(buffer_type *output, rdata_atom_type rdata)
{
	buffer_printf(output, "0x");
	hex_to_string(output, rdata_atom_data(rdata), rdata_atom_size(rdata));
	return 1;
}

static int
rdata_apl_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int result = 0;
	buffer_type packet;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));
	
	if (buffer_available(&packet, 4)) {
		uint16_t address_family = buffer_read_u16(&packet);
		uint8_t prefix = buffer_read_u8(&packet);
		uint8_t length = buffer_read_u8(&packet);
		int negated = length & 0x80;
		int af = -1;
		
		length &= 0x7f;
		switch (address_family) {
		case 1: af = AF_INET; break;
		case 2: af = AF_INET6; break;
		}
		if (af != -1 && buffer_available(&packet, length)) {
			char text_address[1000];
			uint8_t address[128];
			memset(address, 0, sizeof(address));
			buffer_read(&packet, address, length);
			if (inet_ntop(af, address, text_address, sizeof(text_address))) {
				buffer_printf(output, "%s%d:%s/%d",
					      negated ? "!" : "",
					      (int) address_family,
					      text_address,
					      (int) prefix);
				result = 1;
			}
		}
	}
	return result;
}

static int
rdata_services_to_string(buffer_type *output, rdata_atom_type rdata)
{
	int result = 0;
	buffer_type packet;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));
	
	if (buffer_available(&packet, 1)) {
		uint8_t protocol_number = buffer_read_u8(&packet);
		ssize_t bitmap_size = buffer_remaining(&packet);
		uint8_t *bitmap = buffer_current(&packet);
		struct protoent *proto = getprotobynumber(protocol_number);
		
		if (proto) {
			int i;

			buffer_printf(output, "%s", proto->p_name);

			for (i = 0; i < bitmap_size * 8; ++i) {
				if (get_bit(bitmap, i)) {
					struct servent *service = getservbyport(i, proto->p_name);
					if (service) {
						buffer_printf(output, " %s", service->s_name);
					} else {
						buffer_printf(output, " %d", i);
					}
				}
			}
			buffer_skip(&packet, bitmap_size);
			result = 1;
		}
	}
	return result;
}

static int
rdata_nxt_to_string(buffer_type *output, rdata_atom_type rdata)
{
	size_t i;
	uint8_t *bitmap = rdata_atom_data(rdata);
	size_t bitmap_size = rdata_atom_size(rdata);
	
	for (i = 0; i < bitmap_size * 8; ++i) {
		if (get_bit(bitmap, i)) {
			buffer_printf(output, "%s ", rrtype_to_string(i));
		}
	}

	buffer_skip(output, -1);

	return 1;
}

static int
rdata_nsec_to_string(buffer_type *output, rdata_atom_type rdata)
{
	size_t saved_position = buffer_position(output);
	buffer_type packet;

	buffer_create_from(
		&packet, rdata_atom_data(rdata), rdata_atom_size(rdata));

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
				buffer_printf(output, "%s ", rrtype_to_string(
						      window * 256 + i));
			}
		}
		buffer_skip(&packet, bitmap_size);
	}

	buffer_skip(output, -1);

	return 1;
}

static int
rdata_loc_to_string(buffer_type *output ATTR_UNUSED,
		    rdata_atom_type rdata ATTR_UNUSED)
{
	/*
	 * Returning 0 forces the record to be printed in unknown
	 * format.
	 */
	return 0;
}

static int
rdata_unknown_to_string(buffer_type *output, rdata_atom_type rdata)
{
	uint16_t size = rdata_atom_size(rdata);
	buffer_printf(output, "\\# %lu ", (unsigned long) size);
	hex_to_string(output, rdata_atom_data(rdata), size);
	return 1;
}

static rdata_to_string_type rdata_to_string_table[RDATA_ZF_UNKNOWN + 1] = {
	rdata_dname_to_string,
	rdata_text_to_string,
	rdata_byte_to_string,
	rdata_short_to_string,
	rdata_long_to_string,
	rdata_a_to_string,
	rdata_aaaa_to_string,
	rdata_rrtype_to_string,
	rdata_algorithm_to_string,
	rdata_certificate_type_to_string,
	rdata_period_to_string,
	rdata_time_to_string,
	rdata_base64_to_string,
	rdata_hex_to_string,
	rdata_nsap_to_string,
	rdata_apl_to_string,
	rdata_services_to_string,
	rdata_nxt_to_string,
	rdata_nsec_to_string,
	rdata_loc_to_string,
	rdata_unknown_to_string
};

int
rdata_to_string(buffer_type *output, rdata_zoneformat_type type,
		rdata_atom_type rdata)
{
	return rdata_to_string_table[type](output, rdata);
}

ssize_t
rdata_wireformat_to_rdatas(region_type *region,
			   domain_table_type *owners,
			   uint16_t rrtype,
			   uint16_t data_size,
			   buffer_type *packet,
			   rdata_atom_type **rdatas)
{
	size_t end = buffer_position(packet) + data_size;
	ssize_t i;
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
		size_t length = 0;

		if (buffer_position(packet) == end) {
			if (i < descriptor->minimum) {
				region_destroy(temp_region);
				return -1;
			} else {
				break;
			}
		}
		
		switch (rdata_atom_wireformat_type(rrtype, i)) {
		case RDATA_WF_COMPRESSED_DNAME:
		case RDATA_WF_UNCOMPRESSED_DNAME:
			is_domain = 1;
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
		case RDATA_WF_TEXT:
			/* Length is stored in the first byte.  */
			length = 1 + buffer_current(packet)[0];
			break;
		case RDATA_WF_A:
			length = sizeof(in_addr_t);
			break;
		case RDATA_WF_AAAA:
			length = IP6ADDRLEN;
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
				length += buffer_current(packet)[sizeof(uint16_t) + sizeof(uint8_t)];
			}

			break;
		}

		if (is_domain) {
			const dname_type *dname = dname_make_from_packet(
				temp_region, packet, 1, 1);
			if (!dname) {
				region_destroy(temp_region);
				return -1;
			}
			temp_rdatas[i].domain
				= domain_table_insert(owners, dname);
		} else {
			if (buffer_position(packet) + length > end) {
/* 				zc_error_prev_line("unknown RDATA is truncated"); */
				region_destroy(temp_region);
				return -1;
			}
			
			temp_rdatas[i].data = (uint16_t *) region_alloc(
				region, sizeof(uint16_t) + length);
			temp_rdatas[i].data[0] = length;
			buffer_read(packet, temp_rdatas[i].data + 1, length);
		}
	}

	if (buffer_position(packet) < end) {
/* 		zc_error_prev_line("unknown RDATA has trailing garbage"); */
		region_destroy(temp_region);
		return -1;
	}

	*rdatas = (rdata_atom_type *) region_alloc_init(
		region, temp_rdatas, i * sizeof(rdata_atom_type));
	region_destroy(temp_region);
	return i;
}
