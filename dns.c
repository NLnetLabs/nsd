/*
 * dns.c -- DNS definitions.
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

rrtype_descriptor_type rrtype_descriptors[RRTYPE_DESCRIPTORS_LENGTH] = {
	/* 0 */
	{ 0, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 1 */
	{ TYPE_A, "A", T_A, 1, 1,
	  { RDATA_WF_A }, { RDATA_ZF_A } },
	/* 2 */
	{ TYPE_NS, "NS", T_NS, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 3 */
	{ TYPE_MD, "MD", T_MD, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 4 */
	{ TYPE_MF, "MF", T_MF, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 5 */
	{ TYPE_CNAME, "CNAME", T_CNAME, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 6 */
	{ TYPE_SOA, "SOA", T_SOA, 7, 7,
	  { RDATA_WF_COMPRESSED_DNAME, RDATA_WF_COMPRESSED_DNAME, RDATA_WF_LONG,
	    RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_LONG },
	  { RDATA_ZF_DNAME, RDATA_ZF_DNAME, RDATA_ZF_PERIOD, RDATA_ZF_PERIOD,
	    RDATA_ZF_PERIOD, RDATA_ZF_PERIOD, RDATA_ZF_PERIOD } },
	/* 7 */
	{ TYPE_MB, "MB", T_MB, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 8 */
	{ TYPE_MG, "MG", T_MG, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 9 */
	{ TYPE_MR, "MR", T_MR, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 10 */
	{ TYPE_NULL, "NULL", T_UTYPE, 1, 1,
	  { RDATA_WF_BINARY }, { RDATA_ZF_DNAME } },
	/* 11 */
	{ TYPE_WKS, "WKS", T_WKS, 2, 2,
	  { RDATA_WF_A, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_A, RDATA_ZF_SERVICES } },
	/* 12 */
	{ TYPE_PTR, "PTR", T_PTR, 1, 1,
	  { RDATA_WF_COMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 13 */
	{ TYPE_HINFO, "HINFO", T_HINFO, 2, 2,
	  { RDATA_WF_TEXT, RDATA_WF_TEXT }, { RDATA_ZF_TEXT, RDATA_ZF_TEXT } },
	/* 14 */
	{ TYPE_MINFO, "MINFO", T_MINFO, 2, 2,
	  { RDATA_WF_COMPRESSED_DNAME, RDATA_WF_COMPRESSED_DNAME },
	  { RDATA_ZF_DNAME, RDATA_ZF_DNAME } },
	/* 15 */
	{ TYPE_MX, "MX", T_MX, 2, 2,
	  { RDATA_WF_SHORT, RDATA_WF_COMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_DNAME } },
	/* 16 */
	{ TYPE_TXT, "TXT", T_TXT, 1, MAXRDATALEN,
	  { RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT, RDATA_WF_TEXT },
	  { RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT, RDATA_ZF_TEXT } },
	/* 17 */
	{ TYPE_RP, "RP", T_RP, 2, 2,
	  { RDATA_WF_COMPRESSED_DNAME, RDATA_WF_COMPRESSED_DNAME },
	  { RDATA_ZF_DNAME, RDATA_ZF_DNAME } },
	/* 18 */
	{ TYPE_AFSDB, "AFSDB", T_AFSDB, 2, 2,
	  { RDATA_WF_SHORT, RDATA_WF_COMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_DNAME } },
	/* 19 */
	{ TYPE_X25, "X25", T_X25, 1, 1,
	  { RDATA_WF_TEXT },
	  { RDATA_ZF_TEXT } },
	/* 20 */
	{ TYPE_ISDN, "ISDN", T_ISDN, 1, 2,
	  { RDATA_WF_TEXT, RDATA_WF_TEXT },
	  { RDATA_ZF_TEXT, RDATA_ZF_TEXT } },
	/* 21 */
	{ TYPE_RT, "RT", T_RT, 2, 2,
	  { RDATA_WF_SHORT, RDATA_WF_COMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_DNAME } },
	/* 22 */
	{ TYPE_NSAP, "NSAP", T_NSAP, 1, 1,
	  { RDATA_WF_BINARY },
	  { RDATA_ZF_NSAP } },
	/* 23 */
	{ 23, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 24 */
	{ TYPE_SIG, "SIG", T_SIG, 9, 9,
	  { RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_LONG,
	    RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_SHORT,
	    RDATA_WF_UNCOMPRESSED_DNAME, RDATA_WF_BINARY },
	  { RDATA_ZF_RRTYPE, RDATA_ZF_BYTE, RDATA_ZF_BYTE, RDATA_ZF_PERIOD,
	    RDATA_ZF_TIME, RDATA_ZF_TIME, RDATA_ZF_SHORT, RDATA_ZF_DNAME,
	    RDATA_ZF_BASE64 } },
	/* 25 */
	{ TYPE_KEY, "KEY", T_KEY, 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_SHORT, RDATA_ZF_BYTE, RDATA_ZF_ALGORITHM,
	    RDATA_ZF_BASE64 } },
	/* 26 */
	{ TYPE_PX, "PX", T_PX, 3, 3,
	  { RDATA_WF_SHORT, RDATA_WF_UNCOMPRESSED_DNAME,
	    RDATA_WF_UNCOMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_DNAME, RDATA_ZF_DNAME } },
	/* 27 */
	{ 27, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 28 */
	{ TYPE_AAAA, "AAAA", T_AAAA, 1, 1,
	  { RDATA_WF_AAAA },
	  { RDATA_ZF_AAAA } },
	/* 29 */
	{ TYPE_LOC, "LOC", T_LOC, 1, 1,
	  { RDATA_WF_BINARY },
	  { RDATA_ZF_LOC } },
	/* 30 */
	{ TYPE_NXT, "NXT", T_NXT, 2, 2,
	  { RDATA_WF_UNCOMPRESSED_DNAME, RDATA_WF_BINARY },
	  { RDATA_ZF_DNAME, RDATA_ZF_NXT } },
	/* 31 */
	{ 31, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 32 */
	{ 32, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 33 */
	{ TYPE_SRV, "SRV", T_SRV, 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_SHORT, RDATA_WF_SHORT,
	    RDATA_WF_UNCOMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_SHORT, RDATA_ZF_SHORT, RDATA_ZF_DNAME } },
	/* 34 */
	{ 34, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 35 */
	{ TYPE_NAPTR, "NAPTR", T_NAPTR, 6, 6,
	  { RDATA_WF_SHORT, RDATA_WF_SHORT, RDATA_WF_TEXT, RDATA_WF_TEXT,
	    RDATA_WF_TEXT, RDATA_WF_UNCOMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_SHORT, RDATA_ZF_TEXT, RDATA_ZF_TEXT,
	    RDATA_ZF_TEXT, RDATA_ZF_DNAME } },
	/* 36 */
	{ TYPE_KX, "KX", T_KX, 2, 2,
	  { RDATA_WF_SHORT, RDATA_WF_UNCOMPRESSED_DNAME },
	  { RDATA_ZF_SHORT, RDATA_ZF_DNAME } },
	/* 37 */
	{ TYPE_CERT, "CERT", T_CERT, 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_CERTIFICATE_TYPE, RDATA_ZF_SHORT, RDATA_ZF_ALGORITHM,
	    RDATA_ZF_BASE64 } },
	/* 38 */
	{ 38, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 39 */
	{ TYPE_DNAME, "DNAME", T_DNAME, 1, 1,
	  { RDATA_WF_UNCOMPRESSED_DNAME }, { RDATA_ZF_DNAME } },
	/* 40 */
	{ 40, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 41 */
	{ TYPE_OPT, "OPT", T_UTYPE, 1, 1,
	  { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 42 */
	{ TYPE_APL, "APL", T_APL, 0, MAXRDATALEN,
	  { RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL,
	    RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL, RDATA_WF_APL },
	  { RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL,
	    RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL, RDATA_ZF_APL } },
	/* 43 */
	{ TYPE_DS, "DS", T_DS, 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_SHORT, RDATA_ZF_BYTE, RDATA_ZF_BYTE, RDATA_ZF_HEX } },
	/* 44 */
	{ TYPE_SSHFP, "SSHFP", T_SSHFP, 3, 3,
	  { RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_BYTE, RDATA_ZF_BYTE, RDATA_ZF_HEX } },
	/* 45 */
	{ 45, NULL, T_UTYPE, 1, 1, { RDATA_WF_BINARY }, { RDATA_ZF_UNKNOWN } },
	/* 46 */
	{ TYPE_RRSIG, "RRSIG", T_RRSIG, 9, 9,
	  { RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_LONG,
	    RDATA_WF_LONG, RDATA_WF_LONG, RDATA_WF_SHORT,
	    RDATA_WF_UNCOMPRESSED_DNAME, RDATA_WF_BINARY },
	  { RDATA_ZF_RRTYPE, RDATA_ZF_BYTE, RDATA_ZF_BYTE, RDATA_ZF_PERIOD,
	    RDATA_ZF_TIME, RDATA_ZF_TIME, RDATA_ZF_SHORT, RDATA_ZF_DNAME,
	    RDATA_ZF_BASE64 } },
	/* 47 */
	{ TYPE_NSEC, "NSEC", T_NSEC, 2, 2,
	  { RDATA_WF_UNCOMPRESSED_DNAME, RDATA_WF_BINARY },
	  { RDATA_ZF_DNAME, RDATA_ZF_NSEC } },
	/* 48 */
	{ TYPE_DNSKEY, "DNSKEY", T_DNSKEY, 4, 4,
	  { RDATA_WF_SHORT, RDATA_WF_BYTE, RDATA_WF_BYTE, RDATA_WF_BINARY },
	  { RDATA_ZF_SHORT, RDATA_ZF_BYTE, RDATA_ZF_ALGORITHM,
	    RDATA_ZF_BASE64 } }
};

rrtype_descriptor_type *
rrtype_descriptor_by_name(const char *name)
{
	int i;

	for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
		if (rrtype_descriptors[i].name
		    && strcasecmp(rrtype_descriptors[i].name, name) == 0)
		{
			return &rrtype_descriptors[i];
		}
	}

	return NULL;
}

const char *
rrtype_to_string(uint16_t rrtype)
{
	static char buf[20];
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
	if (descriptor->name) {
		return descriptor->name;
	} else {
		snprintf(buf, sizeof(buf), "TYPE%d", (int) rrtype);
		return buf;
	}
}

const char *
rrclass_to_string(uint16_t rrclass)
{
	static char buf[20];
	if (rrclass == CLASS_IN) {
		return "IN";
	} else {
		snprintf(buf, sizeof(buf), "CLASS%d", (int) rrclass);
		return buf;
	}
}

typedef int(*rdata_to_string_type)(buffer_type *output, buffer_type *packet);

static int
rdata_dname_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	region_type *region = region_create(xalloc, free);
	const dname_type *dname = dname_make_from_packet(region, packet, 0);
	if (dname) {
		buffer_printf(output, "%s", dname_to_string(dname));
		result = 1;
	}
	region_destroy(region);
	return result;
}

static int
rdata_text_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 1)) {
		uint8_t length = buffer_read_u8(packet);
		if (buffer_available(packet, length)) {
			int i;
			buffer_printf(output, "\"");
			for (i = 0; i < length; ++i) {
				char ch = (char) buffer_read_u8(packet);
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
			result = 1;
		}
	}
	return result;
}

static int
rdata_byte_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 1)) {
		uint8_t data = buffer_read_u8(packet);
		buffer_printf(output, "%lu", (unsigned long) data);
		result = 1;
	}
	return result;
}

static int
rdata_short_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 2)) {
		uint16_t data = buffer_read_u16(packet);
		buffer_printf(output, "%lu", (unsigned long) data);
		result = 1;
	}
	return result;
}

static int
rdata_long_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 4)) {
		uint32_t data = buffer_read_u32(packet);
		buffer_printf(output, "%lu", (unsigned long) data);
		result = 1;
	}
	return result;
}

static int
rdata_a_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	char str[200];
	if (buffer_available(packet, IP4ADDRLEN)
	    && inet_ntop(AF_INET, buffer_current(packet), str, sizeof(str)))
	{
		buffer_skip(packet, IP4ADDRLEN);
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_aaaa_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	char str[200];
	if (buffer_available(packet, IP6ADDRLEN)
	    && inet_ntop(AF_INET6, buffer_current(packet), str, sizeof(str)))
	{
		buffer_skip(packet, IP6ADDRLEN);
		buffer_printf(output, "%s", str);
		result = 1;
	}
	return result;
}

static int
rdata_rrtype_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 2)) {
		uint16_t type = buffer_read_u16(packet);
		buffer_printf(output, "%s", rrtype_to_string(type));
		result = 1;
	}
	return result;
}

static int
rdata_algorithm_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 1)) {
		uint8_t id = buffer_read_u8(packet);
		lookup_table_type *alg
			= lookup_by_id(dns_algorithms, id);
		if (alg) {
			buffer_printf(output, "%s", alg->name);
		} else {
			buffer_printf(output, "%u", (unsigned) id);
		}
		result = 1;
	}
	return result;
}

static int
rdata_certificate_type_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 2)) {
		uint16_t id = buffer_read_u16(packet);
		lookup_table_type *type
			= lookup_by_id(dns_certificate_types, id);
		if (type) {
			buffer_printf(output, "%s", type->name);
		} else {
			buffer_printf(output, "%u", (unsigned) id);
		}
		result = 1;
	}
	return result;
}

static int
rdata_period_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 4)) {
		uint32_t period = buffer_read_u32(packet);
		buffer_printf(output, "%lu", (unsigned long) period);
		result = 1;
	}
	return result;
}

static int
rdata_time_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 4)) {
		time_t time = (time_t) buffer_read_u32(packet);
		struct tm *tm = gmtime(&time);
		char buf[15];
		if (strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", tm)) {
			buffer_printf(output, "%s", buf);
			result = 1;
		}
	}
	return result;
}

static int
rdata_base64_to_string(buffer_type *output, buffer_type *packet)
{
	int length;
	size_t size = buffer_remaining(packet);
	buffer_reserve(output, size * 2 + 1);
	length = b64_ntop(buffer_current(packet), size,
			  (char *) buffer_current(output), size * 2);
	buffer_skip(packet, size);
	if (length > 0) {
		buffer_skip(output, length);
	}
	return length != -1;
}

static void
hex_to_string(buffer_type *output, buffer_type *input, size_t size)
{
	static const char hexdigits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
	};
	size_t i;

	buffer_reserve(output, size * 2);
	for (i = 0; i < size; ++i) {
		uint8_t octet = buffer_read_u8(input);
		buffer_write_u8(output, hexdigits[octet >> 4]);
		buffer_write_u8(output, hexdigits[octet & 0x0f]);
	}
}

static int
rdata_hex_to_string(buffer_type *output, buffer_type *packet)
{
	hex_to_string(output, packet, buffer_remaining(packet));
	return 1;
}

static int
rdata_nsap_to_string(buffer_type *output, buffer_type *packet)
{
	buffer_printf(output, "0x");
	hex_to_string(output, packet, buffer_remaining(packet));
	return 1;
}

static int
rdata_apl_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 4)) {
		uint16_t address_family = buffer_read_u16(packet);
		uint8_t prefix = buffer_read_u8(packet);
		uint8_t length = buffer_read_u8(packet);
		int negated = length & 0x80;
		int af = -1;
		
		length &= 0x7f;
		switch (address_family) {
		case 1: af = AF_INET; break;
		case 2: af = AF_INET6; break;
		}
		if (af != -1 && buffer_available(packet, length)) {
			char text_address[1000];
			uint8_t address[128];
			memset(address, 0, sizeof(address));
			buffer_read(packet, address, length);
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
rdata_services_to_string(buffer_type *output, buffer_type *packet)
{
	int result = 0;
	if (buffer_available(packet, 1)) {
		uint8_t protocol_number = buffer_read_u8(packet);
		ssize_t bitmap_size = buffer_remaining(packet);
		uint8_t *bitmap = buffer_current(packet);
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
			buffer_skip(packet, bitmap_size);
			result = 1;
		}
	}
	return result;
}

static int
rdata_nxt_to_string(buffer_type *output, buffer_type *packet)
{
	size_t i;
	uint8_t *bitmap = buffer_current(packet);
	size_t bitmap_size = buffer_remaining(packet);
	
	for (i = 0; i < bitmap_size * 8; ++i) {
		if (get_bit(bitmap, i)) {
			buffer_printf(output, "%s ", rrtype_to_string(i));
		}
	}

	buffer_skip(packet, bitmap_size);
	buffer_skip(output, -1);

	return 1;
}

static int
rdata_nsec_to_string(buffer_type *output, buffer_type *packet)
{
	size_t saved_position = buffer_position(output);

	while (buffer_available(packet, 2)) {
		uint8_t window = buffer_read_u8(packet);
		uint8_t bitmap_size = buffer_read_u8(packet);
		uint8_t *bitmap = buffer_current(packet);
		int i;
		
		if (!buffer_available(packet, bitmap_size)) {
			buffer_set_position(output, saved_position);
			return 0;
		}

		for (i = 0; i < bitmap_size * 8; ++i) {
			if (get_bit(bitmap, i)) {
				buffer_printf(output, "%s ", rrtype_to_string(
						      window * 256 + i));
			}
		}
		buffer_skip(packet, bitmap_size);
	}

	buffer_skip(output, -1);

	return 1;
}

static int
rdata_loc_to_string(buffer_type *output ATTR_UNUSED,
		    buffer_type *packet ATTR_UNUSED)
{
	/*
	 * Returning 0 forces the record to be printed in unknown
	 * format.
	 */
	return 0;
}

static int
rdata_unknown_to_string(buffer_type *output, buffer_type *packet)
{
	size_t size = buffer_remaining(packet);
	buffer_printf(output, "\\# %lu ", (unsigned long) size);
	hex_to_string(output, packet, size);
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
		buffer_type *packet)
{
	return rdata_to_string_table[type](output, packet);
}
