/*
 * dns.c -- DNS definitions.
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
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "dns.h"
#include "zonec.h"

/* Taken from RFC 1035, section 3.2.4.  */
static lookup_table_type dns_rrclasses[] = {
	{ CLASS_IN, "IN" },	/* the Internet */
	{ CLASS_CS, "CS" },	/* the CSNET class (Obsolete) */
	{ CLASS_CH, "CH" },	/* the CHAOS class */
	{ CLASS_HS, "HS" },	/* Hesiod */
	{ 0, NULL }
};

#define FIELD(name, is_optional, size /*, calc_len, print*/ ) \
	{ name, is_optional, size, NULL, NULL /* ,calc_len, print*/ }

static const struct nsd_rdata_descriptor generic_rdata_fields[] = {
	FIELD("", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor a_rdata_fields[] = {
	FIELD("address", 0, 4)
};

static const struct nsd_rdata_descriptor ns_rdata_fields[] = {
	FIELD("host", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor md_rdata_fields[] = {
	FIELD("madname", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor mf_rdata_fields[] = {
	FIELD("madname", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor cname_rdata_fields[] = {
	FIELD("host", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor soa_rdata_fields[] = {
	FIELD("primary", RDATA_COMPRESSED_DNAME, false),
	FIELD("mailbox", RDATA_COMPRESSED_DNAME, false),
	FIELD("serial", 4, false),
	FIELD("refresh", 4, false),
	FIELD("retry", 4, false),
	FIELD("expire", 4, false),
	FIELD("minimum", 4, false)
};

static const struct nsd_rdata_descriptor mb_rdata_fields[] = {
	FIELD("madname", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor mg_rdata_fields[] = {
	FIELD("mgmname", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor mr_rdata_fields[] = {
	FIELD("newname", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor wks_rdata_fields[] = {
	FIELD("address", 0, 4),
	FIELD("protocol", 0, 1),
	FIELD("bitmap", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor ptr_rdata_fields[] = {
	FIELD("ptrdname", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor hinfo_rdata_fields[] = {
	FIELD("cpu", 0, RDATA_STRING),
	FIELD("os", 0, RDATA_STRING)
};

static const struct nsd_rdata_descriptor minfo_rdata_fields[] = {
	FIELD("rmailbx", 0, RDATA_COMPRESSED_DNAME),
	FIELD("emailbx", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor mx_rdata_fields[] = {
	FIELD("priority", 0, 2),
	FIELD("hostname", 0, RDATA_COMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor txt_rdata_fields[] = {
	FIELD("text", 0, 0)
};

static const struct nsd_rdata_descriptor rp_rdata_fields[] = {
	FIELD("mailbox", 0, RDATA_UNCOMPRESSED_DNAME),
	FIELD("text", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor afsdb_rdata_fields[] = {
	FIELD("subtype", 0, 2),
	FIELD("hostname", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor x25_rdata_fields[] = {
	FIELD("address", 0, RDATA_STRING)
};

static const struct nsd_rdata_descriptor isdn_rdata_fields[] = {
	FIELD("address", 0, RDATA_STRING),
	FIELD("subaddress", 1, RDATA_STRING)
};

static const struct nsd_rdata_descriptor rt_rdata_fields[] = {
	FIELD("preference", 0, 2),
	FIELD("hostname", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor nsap_rdata_fields[] = {
	FIELD("address", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor sig_rdata_fields[] = {
	FIELD("sigtype", 0, 2),
	FIELD("algorithm", 0, 1),
	FIELD("labels", 0, 1),
	FIELD("origttl", 0, 4),
	FIELD("expire", 0, 4),
	FIELD("inception", 0, 4),
	FIELD("keytag", 0, 2),
	FIELD("signer", 0, RDATA_LITERAL_DNAME),
	FIELD("signature", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor key_rdata_fields[] = {
	FIELD("flags", 0, 2),
	FIELD("protocol", 0, 1),
	FIELD("algorithm", 0, 1),
	FIELD("publickey", 0, RDATA_BINARY)
};

static const struct nsd_rdata_descriptor px_rdata_fields[] = {
	FIELD("preference", 0, 2),
	FIELD("map822", 0, RDATA_UNCOMPRESSED_DNAME),
	FIELD("mapx400", 0, RDATA_UNCOMPRESSED_DNAME)
};

static const struct nsd_rdata_descriptor aaaa_rdata_fields[] = {
	FIELD("address", 0, 16)
};

static const struct nsd_rdata_descriptor loc_rdata_fields[] = {
	FIELD("version", 0, 1),
	FIELD("size", 0, 1),
	FIELD("horizontal precision", 0, 1),
	FIELD("vertical precision", 0, 1),
	FIELD("latitude", 0, 4),
	FIELD("longitude", 0, 4),
	FIELD("altitude", 0, 4),
};

static const struct nsd_rdata_descriptor nxt_rdata_fields[] = {
	FIELD("next domain name", 0, RDATA_UNCOMPRESSED_DNAME, name_length),
	FIELD("type bit map", 0, RDATA_BINARY, nxt_length)
};

static const struct nsd_rdata_descriptor srv_rdata_fields[] = {
	FIELD("priority", 0, 2, 0),
	FIELD("weight", 0, 2, 0),
	FIELD("port", 0, 2, 0),
	FIELD("target", 0, RDATA_UNCOMPRESSED_DNAME, name_length)
};

static const struct nsd_rdata_descriptor naptr_rdata_fields[] = {
	FIELD("order", 0, 2, 0),
	FIELD("preference", 0, 2, 0),
	FIELD("flags", 0, RDATA_STRING, string_length),
	FIELD("services", 0, RDATA_STRING, string_length),
	FIELD("regex", 0, RDATA_STRING, string_length),
	FIELD("replacement", 0, RDATA_UNCOMPRESSED_DNAME, name_length)
};

static const struct nsd_rdata_descriptor kx_rdata_fields[] = {
	FIELD("preference", 0, 2, 0),
	FIELD("exchanger", 0, RDATA_UNCOMPRESSED_DNAME, name_length)
};

static const struct nsd_rdata_descriptor cert_rdata_fields[] = {
	FIELD("type", 0, 2, 0),
	FIELD("key tag", 0, 2, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("certificate", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor dname_rdata_fields[] = {
	FIELD("source", 0, RDATA_UNCOMPRESSED_DNAME, name_length)
};

static const struct nsd_rdata_descriptor apl_rdata_fields[] = {
	FIELD("prefix", 1, RDATA_BINARY, apl_length)
};

static const struct nsd_rdata_descriptor ds_rdata_fields[] = {
	FIELD("keytag", 0, 2, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("digtype", 0, 1, 0),
	FIELD("digest", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor sshfp_rdata_fields[] = {
	FIELD("algorithm", 0, 1, 0),
	FIELD("ftype", 0, 1, 0),
	FIELD("fingerprint", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor ipseckey_rdata_fields[] = {
	FIELD("precedence", 0, 1, 0),
	FIELD("gateway type", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("gateway", 0, RDATA_IPSECGATEWAY, gateway_length),
	FIELD("public key", 1, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor rrsig_rdata_fields[] = {
	FIELD("rrtype", 0, 2),
	FIELD("algorithm", 0, 1),
	FIELD("labels", 0, 1),
	FIELD("origttl", 0, 4),
	FIELD("expire", 0, 4),
	FIELD("inception", 0, 4),
	FIELD("keytag", 0, 2),
	FIELD("signer", 0, RDATA_LITERAL_DNAME),
	FIELD("signature", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor nsec_rdata_fields[] = {
	FIELD("next", 0, RDATA_LITERAL_DNAME),
	FIELD("types", 0, RDATA_REMAINDER)
};

static const struct nsd_rdata_descriptor dnskey_rdata_fields[] = {
	FIELD("flags", 0, 2, 0),
	FIELD("protocol", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("publickey", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor dhcid_rdata_fields[] = {
	FIELD("dhcpinfo", RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor nsec3_rdata_fields[] = {
	FIELD("algorithm", 0, 1, 0),
	FIELD("flags", 0, 1, 0),
	FIELD("iterations", 0, 2, 0),
	FIELD("salt", 0, RDATA_STRING, string_length),
	FIELD("next", 0, RDATA_STRING, string_length),
	FIELD("types", 0, RDATA_BINARY, nsec_length)
};

static const struct nsd_rdata_descriptor nsec3param_rdata_fields[] = {
	FIELD("algorithm", 0, 1, 0),
	FIELD("flags", 0, 1, 0),
	FIELD("iterations", 0, 2, 0),
	FIELD("salt", 0, RDATA_STRING, string_length)
};

static const struct nsd_rdata_descriptor tlsa_rdata_fields[] = {
	FIELD("usage", 0, 1, 0),
	FIELD("selector", 0, 1, 0),
	FIELD("matching type", 0, 1, 0),
	FIELD("certificate association data", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor smimea_rdata_fields[] = {
	FIELD("usage", 0, 1, 0),
	FIELD("selector", 0, 1, 0),
	FIELD("matching type", 0, 1, 0),
	FIELD("certificate association data", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor cds_rdata_fields[] = {
	FIELD("keytag", 0, 2, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("digtype", 0, 1, 0),
	FIELD("digest", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor cdnskey_rdata_fields[] = {
	FIELD("flags", 0, 2, 0),
	FIELD("protocol", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("publickey", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor openpgpkey_rdata_fields[] = {
	FIELD("key", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor csync_rdata_fields[] = {
	FIELD("serial", 0, 4, 0),
	FIELD("flags", 0, 2, 0),
	FIELD("types", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor zonemd_rdata_fields[] = {
	FIELD("serial", 0, 4, 0),
	FIELD("scheme", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("digest", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor svcb_rdata_fields[] = {
	FIELD("priority", 0, 2, 0),
	FIELD("target", 0, RDATA_UNCOMPRESSED_DNAME, name_length),
	FIELD("params", 0, RDATA_BINARY, svcparams_length)
};

static const struct nsd_rdata_descriptor https_rdata_fields[] = {
	FIELD("priority", 0, 2, 0),
	FIELD("target", 0, RDATA_UNCOMPRESSED_DNAME, name_length),
	FIELD("params", 0, RDATA_BINARY, svcparams_length)
};

static const struct nsd_rdata_descriptor spf_rdata_fields[] = {
	FIELD("text", 0, RDATA_BINARY, strings_length)
};

static const struct nsd_rdata_descriptor nid_rdata_fields[] = {
	FIELD("nid", 0, 2, 0),
	FIELD("locator", 0, 8, 0)
};

static const struct nsd_rdata_descriptor l32_rdata_fields[] = {
	FIELD("preference", 0, 2, 0),
	FIELD("locator", 0, 8, 0)
};

static const struct nsd_rdata_descriptor l64_rdata_fields[] = {
	FIELD("preference", 0, 2, 0),
	FIELD("locator", 0, 8, 0)
};

static const struct nsd_rdata_descriptor lp_rdata_fields[] = {
	FIELD("preference", 0, 2, 0),
	FIELD("pointer", 0, RDATA_UNCOMPRESSED_DNAME, name_length)
};

static const struct nsd_rdata_descriptor eui48_rdata_fields[] = {
	FIELD("address", 0, 6, 0)
};

static const struct nsd_rdata_descriptor eui64_rdata_fields[] = {
	FIELD("address", 0, 8, 0)
};

static const struct nsd_rdata_descriptor uri_rdata_fields[] = {
	FIELD("priority", 0, 2, 0),
	FIELD("weight", 0, 2, 0),
	FIELD("target", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor caa_rdata_fields[] = {
	FIELD("flags", 0, 1, 0),
	FIELD("tag", 0, RDATA_STRING, string_length),
	FIELD("value", 0, RDATA_BINARY, binary_length)
};

static const struct nsd_rdata_descriptor avc_rdata_fields[] = {
	FIELD("text", 0, RDATA_BINARY, strings_length)
};

static const struct nsd_rdata_descriptor dlv_rdata_fields[] = {
	FIELD("key", 0, 2, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("type", 0, 1, 0),
	FIELD("digest", 0, RDATA_BINARY)
};

#undef FIELD


#define TYPE(name, code, read, write, print, fields) \
  { code, name, read, write, print, { sizeof(fields)/sizeof(fields[0]), fields } }

#define UNKNOWN_TYPE(code) \
  { code, NULL, read_generic_rdata, write_generic_rdata, print_generic_rdata }

static const nsd_type_descriptor_t type_descriptors[] = {
	UNKNOWN_TYPE(0),
	TYPE("A", TYPE_A,
		read_a_rdata, write_generic_rdata,
		print_a_rdata, a_rdata_fields),
	TYPE("NS", TYPE_NS,
		read_compressed_name_rdata, write_compressed_name_rdata,
		print_name_rdata, ns_rdata_fields),
	TYPE("MD", TYPE_MD,
		read_uncompressed_name_rdata, write_uncompressed_name_rdata,
		print_name_rdata, md_rdata_fields),
	TYPE("MF", TYPE_MF,
		read_uncompressed_name_rdata, write_uncompressed_name_rdata,
		print_name_rdata, mf_rdata_fields),
	TYPE("CNAME", TYPE_CNAME,
		read_uncompressed_name_rdata, write_uncompressed_name_rdata,
		print_name_rdata, cname_rdata_fields),
	TYPE("SOA", TYPE_SOA,
		read_soa_rdata, write_soa_rdata,
		print_soa_rdata, soa_rdata_fields),
	TYPE("MB", TYPE_MB,
		read_compressed_name_rdata, write_compressed_name_rdata,
		print_name_rdata, mb_rdata_fields),
	TYPE("MG", TYPE_MG,
		read_compressed_name_rdata, write_compressed_name_rdata,
		print_name_rdata, mg_rdata_fields),
	TYPE("MR", TYPE_MR,
		read_compressed_name_rdata, write_compressed_name_rdata,
		print_name_rdata, mr_rdata_fields),
	TYPE("NULL", TYPE_NULL,
		read_generic_rdata, write_generic_rdata,
		print_generic_rdata, generic_rdata_fields),
	TYPE("WKS", TYPE_WKS,
		read_wks_rdata, write_generic_rdata,
		print_wks_rdata, wks_rdata_fields),
	TYPE("PTR", TYPE_PTR,
		read_compressed_name_rdata, write_compressed_name_rdata,
		print_name_rdata, ptr_rdata_fields),
	TYPE("HINFO", TYPE_HINFO,
		read_hinfo_rdata, write_generic_rdata,
		print_hinfo_rdata, hinfo_rdata_fields),
	TYPE("MINFO", TYPE_MINFO,
		read_minfo_rdata, write_minfo_rdata,
		print_minfo_rdata, minfo_rdata_fields),
	TYPE("MX", TYPE_MX,
		read_mx_rdata, write_mx_rdata,
		print_mx_rdata, mx_rdata_fields),
	TYPE("TXT", TYPE_TXT,
		read_txt_rdata, write_generic_rdata,
		print_txt_rdata, txt_rdata_fields),
	TYPE("RP", TYPE_RP,
		read_rp_rdata, write_rp_rdata, print_rp_rdata,
		rp_rdata_fields),
	TYPE("AFSDB", TYPE_AFSDB,
		read_afsdb_rdata, write_afsdb_rdata, print_afsdb_rdata,
		afsdb_rdata_fields),
	TYPE("X25", TYPE_X25,
		read_x25_rdata, write_generic_rdata, print_x25_rdata,
		x25_rdata_fields),
	TYPE("ISDN", TYPE_ISDN,
		read_isdn_rdata, write_generic_rdata, print_isdn_rdata,
		isdn_rdata_fields),
	TYPE("RT", TYPE_RT,
		read_rt_rdata, write_rt_rdata, print_mx_rdata,
		rt_rdata_fields),
	TYPE("NSAP", TYPE_NSAP,
		read_generic_rdata, write_generic_rdata, print_nsap_rdata,
		nsap_rdata_fields),

	UNKNOWN_TYPE(23),

	TYPE("SIG", TYPE_SIG,
		read_rrsig_rdata, write_rrsig_rdata, print_rrsig_rdata,
		sig_rdata_fields),
	TYPE("KEY", TYPE_KEY,
		read_key_rdata, write_key_rdata, print_key_rdata,
		key_rdata_fields),
	TYPE("PX", TYPE_PX,
		read_px_rdata, write_px_rdata, print_px_rdata,
		px_rdata_fields),

	UNKNOWN_TYPE(27),

	TYPE("AAAA", TYPE_AAAA,
		read_aaaa_rdata, write_generic_rdata, print_aaaa_rdata,
		aaaa_rdata_fields),
	TYPE("LOC", TYPE_LOC,
		read_loc_rdata, write_generic_rdata, print_generic_rdata,
		loc_rdata_fields),
	TYPE("NXT", TYPE_NXT,
		read_nxt_rdata, write_nxt_rdata, print_nxt_rdata,
		nxt_rdata_fields),

	UNKNOWN_TYPE(31),
	UNKNOWN_TYPE(32),

	TYPE("SRV", TYPE_SRV,
		read_srv_rdata, write_srv_rdata,
		print_srv_rdata, srv_rdata_fields),

	UNKNOWN_TYPE(34),

	TYPE("NAPTR", TYPE_NAPTR,
		read_naptr_rdata, write_naptr_rdata,
		print_naptr_rdata, naptr_rdata_fields),
	TYPE("KX", TYPE_KX,
		read_kx_rdata, write_kx_rdata,
		print_mx_rdata, kx_rdata_fields),
	TYPE("CERT", TYPE_CERT,
		read_cert_rdata, write_generic_rdata,
		print_cert_rdata, cert_rdata_fields),
	TYPE("A6", TYPE_A6,
		read_a6_rdata, write_generic_rdata,
		print_a6_rdata, a6_rdata_fields),
	TYPE("DNAME", TYPE_DNAME,
		read_uncompressed_name_rdata, write_uncompressed_name_rdata,
		print_name_rdata, dname_rdata_fields),

	UNKNOWN_TYPE(40),
	UNKNOWN_TYPE(41),

	TYPE("APL", TYPE_APL,
		read_apl_rdata, write_generic_rdata,
		print_apl_rdata, apl_rdata_fields),
	TYPE("DS", TYPE_DS,
		read_ds_rdata, write_generic_rdata,
		print_ds_rdata, ds_rdata_fields),
	TYPE("SSHFP", TYPE_SSHFP,
		read_sshfp_rdata, write_generic_rdata,
		print_sshfp_rdata, sshfp_rdata_fields),
	TYPE("IPSECKEY", TYPE_IPSECKEY,
		read_ipseckey_rdata, write_generic_rdata,
		print_ipseckey_rdata, ipseckey_rdata_fields),
	TYPE("RRSIG", TYPE_RRSIG,
		read_rrsig_rdata, write_generic_rdata,
		print_rrsig_rdata, rrsig_rdata_fields),
	TYPE("NSEC", TYPE_NSEC,
		read_nsec_rdata, write_generic_rdata,
		print_nsec_rdata, nsec_rdata_fields),
	TYPE("DNSKEY", TYPE_DNSKEY,
		read_dnskey_rdata, write_generic_rdata,
		print_dnskey_rdata, dnskey_rdata_fields),
	TYPE("DHCID", TYPE_DHCID,
		read_dhcid_rdata, write_generic_rdata,
		print_dhcid_rdata, dhcid_rdata_fields),
	TYPE("NSEC3", TYPE_NSEC3,
		read_nsec3_rdata, write_generic_rdata,
		print_nsec3_rdata, nsec3_rdata_fields),
	TYPE("NSEC3PARAM", TYPE_NSEC3PARAM,
		read_nsec3param_rdata, write_generic_rdata,
		print_nsec3param_rdata, nsec3param_rdata_fields),
	TYPE("TLSA", TYPE_TLSA,
		read_tlsa_rdata, write_generic_rdata,
		print_tlsa_rdata, tlsa_rdata_fields),
	TYPE("SMIMEA", TYPE_SMIMEA,
		read_tlsa_rdata, write_generic_rdata,
		print_tlsa_rdata, smimea_rdata_fields),

	UNKNOWN_TYPE(54),
	UNKNOWN_TYPE(55), // HIP RFC 5305
	UNKNOWN_TYPE(56),
	UNKNOWN_TYPE(57),
	UNKNOWN_TYPE(58),

	TYPE("CDS", TYPE_CDS,
		read_ds_rdata, write_generic_rdata,
		print_ds_rdata, cds_rdata_fields),
	TYPE("CDNSKEY", TYPE_CDNSKEY,
		read_dnskey_rdata, write_generic_rdata,
		print_dnskey_rdata, cdnskey_rdata_fields),
	TYPE("OPENPGPKEY", TYPE_OPENPGPKEY,
		read_generic_rdata, write_generic_rdata,
		print_openpgpkey_rdata, openpgpkey_rdata_fields),
	TYPE("CSYNC", TYPE_CSYNC,
		read_csync_rdata, write_generic_rdata,
		print_csync_rdata, csync_rdata_fields),
	TYPE("ZONEMD", TYPE_ZONEMD,
		read_zonemd_rdata, write_generic_rdata,
		print_zonemd_rdata, zonemd_rdata_fields),
	TYPE("SVCB", TYPE_SVCB,
		read_svcb_rdata, write_svcb_rdata,
		print_svcb_rdata, svcb_rdata_fields),
	TYPE("HTTPS", TYPE_HTTPS,
		read_svcb_rdata, write_svcb_rdata,
		print_svcb_rdata, svcb_rdata_fields),

	UNKNOWN_TYPE(66),
	UNKNOWN_TYPE(67),
	UNKNWON_TYPE(68),
	UNKNOWN_TYPE(69),
	UNKNWON_TYPE(70),
	UNKNOWN_TYPE(71),
	UNKNOWN_TYPE(72),
	UNKNOWN_TYPE(73),
	UNKNOWN_TYPE(74),
	UNKNOWN_TYPE(75),
	UNKNOWN_TYPE(76),
	UNKNOWN_TYPE(77),
	UNKNOWN_TYPE(78),
	UNKNOWN_TYPE(79),
	UNKNOWN_TYPE(80),
	UNKNOWN_TYPE(81),
	UNKNOWN_TYPE(82),
	UNKNOWN_TYPE(83),
	UNKNOWN_TYPE(84),
	UNKNOWN_TYPE(85),
	UNKNOWN_TYPE(86),
	UNKNOWN_TYPE(87),
	UNKNOWN_TYPE(88),
	UNKNOWN_TYPE(89),
	UNKNOWN_TYPE(90),
	UNKNOWN_TYPE(91),
	UNKNOWN_TYPE(92),
	UNKNOWN_TYPE(93),
	UNKNOWN_TYPE(94),
	UNKNOWN_TYPE(95),
	UNKNOWN_TYPE(96),
	UNKNOWN_TYPE(97),
	UNKNOWN_TYPE(98),

	TYPE("SPF", TYPE_SPF,
		read_txt_rdata, write_generic_rdata,
		print_txt_rdata, spf_rdata_fields),

	UNKNOWN_TYPE(100),
	UNKNOWN_TYPE(101),
	UNKNOWN_TYPE(102),
	UNKNOWN_TYPE(103),

	TYPE("NID", TYPE_NID,
		read_nid_rdata, write_generic_rdata,
		print_nid_rdata, nid_rdata_fields),
	TYPE("L32", TYPE_L32,
		read_l32_rdata, write_generic_rdata,
		print_l32_rdata, l32_rdata_fields),
	TYPE("L64", TYPE_L64,
		read_l64_rdata, write_generic_rdata,
		print_l64_rdata, l64_rdata_fields),
	TYPE("LP", TYPE_LP,
		read_lp_rdata, write_lp_rdata,
		print_lp_rdata, lp_rdata_fields),
	TYPE("EUI48", TYPE_EUI48,
		read_eui48_rdata, write_generic_rdata,
		print_eui48_rdata, eui48_rdata_fields),
	TYPE("EUI64", TYPE_EUI64,
		read_eui64_rdata, write_generic_rdata,
		print_eui64_rdata, eui64_rdata_fields),

	UNKNOWN_TYPE(110),
	UNKNOWN_TYPE(111),
	UNKNOWN_TYPE(112),
	UNKNOWN_TYPE(113),
	UNKNOWN_TYPE(114),
	UNKNOWN_TYPE(115),
	UNKNOWN_TYPE(116),
	UNKNOWN_TYPE(117),
	UNKNOWN_TYPE(118),
	UNKNOWN_TYPE(119),
	UNKNOWN_TYPE(120),
	UNKNOWN_TYPE(121),
	UNKNOWN_TYPE(122),
	UNKNOWN_TYPE(123),
	UNKNOWN_TYPE(124),
	UNKNOWN_TYPE(125),
	UNKNOWN_TYPE(126),
	UNKNOWN_TYPE(127),
	UNKNOWN_TYPE(128),
	UNKNOWN_TYPE(129),
	UNKNOWN_TYPE(130),
	UNKNOWN_TYPE(131),
	UNKNOWN_TYPE(132),
	UNKNOWN_TYPE(133),
	UNKNOWN_TYPE(134),
	UNKNOWN_TYPE(135),
	UNKNOWN_TYPE(136),
	UNKNOWN_TYPE(137),
	UNKNOWN_TYPE(138),
	UNKNOWN_TYPE(139),
	UNKNOWN_TYPE(140),
	UNKNOWN_TYPE(141),
	UNKNOWN_TYPE(142),
	UNKNOWN_TYPE(143),
	UNKNOWN_TYPE(144),
	UNKNOWN_TYPE(145),
	UNKNOWN_TYPE(146),
	UNKNOWN_TYPE(147),
	UNKNOWN_TYPE(148),
	UNKNOWN_TYPE(149),
	UNKNOWN_TYPE(150),
	UNKNOWN_TYPE(151),
	UNKNOWN_TYPE(152),
	UNKNOWN_TYPE(153),
	UNKNOWN_TYPE(154),
	UNKNOWN_TYPE(155),
	UNKNOWN_TYPE(156),
	UNKNOWN_TYPE(157),
	UNKNOWN_TYPE(158),
	UNKNOWN_TYPE(159),
	UNKNOWN_TYPE(160),
	UNKNOWN_TYPE(161),
	UNKNOWN_TYPE(162),
	UNKNOWN_TYPE(163),
	UNKNOWN_TYPE(164),
	UNKNOWN_TYPE(165),
	UNKNOWN_TYPE(166),
	UNKNOWN_TYPE(167),
	UNKNOWN_TYPE(168),
	UNKNOWN_TYPE(169),
	UNKNOWN_TYPE(170),
	UNKNOWN_TYPE(171),
	UNKNOWN_TYPE(172),
	UNKNOWN_TYPE(173),
	UNKNOWN_TYPE(174),
	UNKNOWN_TYPE(175),
	UNKNOWN_TYPE(176),
	UNKNOWN_TYPE(177),
	UNKNOWN_TYPE(178),
	UNKNOWN_TYPE(179),
	UNKNOWN_TYPE(180),
	UNKNOWN_TYPE(181),
	UNKNOWN_TYPE(182),
	UNKNOWN_TYPE(183),
	UNKNOWN_TYPE(184),
	UNKNOWN_TYPE(185),
	UNKNOWN_TYPE(186),
	UNKNOWN_TYPE(187),
	UNKNOWN_TYPE(188),
	UNKNOWN_TYPE(189),
	UNKNOWN_TYPE(190),
	UNKNOWN_TYPE(191),
	UNKNOWN_TYPE(192),
	UNKNOWN_TYPE(193),
	UNKNOWN_TYPE(194),
	UNKNOWN_TYPE(195),
	UNKNOWN_TYPE(196),
	UNKNOWN_TYPE(197),
	UNKNOWN_TYPE(198),
	UNKNOWN_TYPE(199),
	UNKNOWN_TYPE(200),
	UNKNOWN_TYPE(201),
	UNKNOWN_TYPE(202),
	UNKNOWN_TYPE(203),
	UNKNOWN_TYPE(204),
	UNKNOWN_TYPE(205),
	UNKNOWN_TYPE(206),
	UNKNOWN_TYPE(207),
	UNKNOWN_TYPE(208),
	UNKNOWN_TYPE(209),
	UNKNOWN_TYPE(210),
	UNKNOWN_TYPE(211),
	UNKNOWN_TYPE(212),
	UNKNOWN_TYPE(213),
	UNKNOWN_TYPE(214),
	UNKNOWN_TYPE(215),
	UNKNOWN_TYPE(216),
	UNKNOWN_TYPE(217),
	UNKNOWN_TYPE(218),
	UNKNOWN_TYPE(219),
	UNKNOWN_TYPE(220),
	UNKNOWN_TYPE(221),
	UNKNOWN_TYPE(222),
	UNKNOWN_TYPE(223),
	UNKNOWN_TYPE(224),
	UNKNOWN_TYPE(225),
	UNKNOWN_TYPE(226),
	UNKNOWN_TYPE(227),
	UNKNOWN_TYPE(228),
	UNKNOWN_TYPE(229),
	UNKNOWN_TYPE(230),
	UNKNOWN_TYPE(231),
	UNKNOWN_TYPE(232),
	UNKNOWN_TYPE(233),
	UNKNOWN_TYPE(234),
	UNKNOWN_TYPE(235),
	UNKNOWN_TYPE(236),
	UNKNOWN_TYPE(237),
	UNKNOWN_TYPE(238),
	UNKNOWN_TYPE(239),
	UNKNOWN_TYPE(240),
	UNKNOWN_TYPE(241),
	UNKNOWN_TYPE(242),
	UNKNOWN_TYPE(243),
	UNKNOWN_TYPE(244),
	UNKNOWN_TYPE(245),
	UNKNOWN_TYPE(246),
	UNKNOWN_TYPE(247),
	UNKNOWN_TYPE(248),
	UNKNOWN_TYPE(249),
	UNKNOWN_TYPE(250),
	UNKNOWN_TYPE(251),
	UNKNOWN_TYPE(252),
	UNKNOWN_TYPE(253),
	UNKNOWN_TYPE(254),
	UNKNOWN_TYPE(255),

	TYPE("URI", TYPE_URI,
		read_uri_rdata, write_generic_rdata,
		print_uri_rdata, uri_rdata_fields),
	TYPE("CAA", TYPE_CAA,
		read_caa_rdata, write_generic_rdata,
		print_caa_rdata, caa_rdata_fields),
	TYPE("AVC", TYPE_AVC,
		read_txt_rdata, write_generic_rdata,
		print_txt_rdata, avc_rdata_fields),
	TYPE("DLV", TYPE_DLV,
		read_dlv_rdata, write_generic_rdata,
		print_dlv_rdata, dlv_rdata_fields)
};

// the rdata states the type of field... very inconvenient!

static const nsd_rdata_descriptor_t ipseckey_ip4_rdata_fields[] = {
	FIELD("precedence", 0, 1, 0),
	FIELD("gateway type", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("gateway", 0, 4, 0),
	FIELD("public key", 1, RDATA_BINARY, binary_length, print_base64)
};

static const nsd_type_descriptor_t ipseckey_ip4_descriptor[] = {
	TYPE("IPSECKEY", TYPE_IPSECKEY,
		read_ipseckey_rdata, write_generic_rdata,
		print_ipseckey_rdata, ipseckey_ip4_rdata_fields)
};

static const nsd_rdata_descriptor_t ipseckey_ip6_rdata_fields[] = {
	FIELD("precedence", 0, 1, 0),
	FIELD("gateway type", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("gateway", 0, 16, 0),
	FIELD("public key", 1, RDATA_BINARY, binary_length, print_base64)
};

static const nsd_type_descriptor_t ipseckey_ip6_descriptor[] = {
	TYPE("IPSECKEY", TYPE_IPSECKEY,
		read_ipseckey_rdata, write_generic_rdata,
		print_ipseckey_rdata, ipseckey_ip6_rdata_fields)
};

static const nsd_rdata_descriptor_t ipseckey_name_rdata_fields[] = {
	FIELD("precedence", 0, 1, 0),
	FIELD("gateway type", 0, 1, 0),
	FIELD("algorithm", 0, 1, 0),
	FIELD("gateway", 0, RDATA_LITERAL_DNAME, name_length),
	FIELD("public key", 1, RDATA_BINARY, binary_length, print_base64)
};

static const nsd_type_descriptor_t ipseckey_name_descriptor[] = {
	TYPE("IPSECKEY", TYPE_IPSECKEY,
		read_ipseckey_rdata, write_generic_rdata,
		print_ipseckey_rdata, ipseckey_name_rdata_fields)
};

#undef UNKNOWN_TYPE
#undef TYPE


nsd_nonnull((2))
static nsd_always_inline const nsd_type_descriptor_t *
nsd_type_descriptor(uint16_t type, uint16_t rdlength const uint8_t *rdata)
{
	/* IPSECKEY RDATA schema is determined by the gateway type */
	if (type == TYPE_IPSECKEY && rdata && rdlength >= 2)
		switch (rdata[1]) {
			case 0: /* no gateway */
				break;
			case 1: /* ipv4 address */
				return &ipseckey_ip4_descriptor[0];
			case 2: /* ipv6 address */
				return &ipseckey_ip6_descriptor[0];
			case 3: /* domain name */
				return &ipseckey_name_descriptor[0];
			default:
				break;
		}
	if (type == TYPE_DLV)
		return &descriptors[TYPE_AVC + 1];
	if (type < TYPE_AVC)
		return &descriptors[type];
	return &descriptors[0];
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

/*
 * Lookup the type in the ztypes lookup table.  If not found, check if
 * the type uses the "TYPExxx" notation for unknown types.
 *
 * Return 0 if no type matches.
 */
uint16_t
rrtype_from_string(const char *name)
{
	char *end;
	long rrtype;
	const rrtype_descriptor_type *entry;

	/* Because this routine is called during zone parse for every record,
	 * we optimise for frequently occurring records.
	 * Also, we optimise for 'IN' and numbers are not rr types, because
	 * during parse this routine is called for every rr class and TTL
	 * to determine that it is not an RR type */
	switch(name[0]) {
	case 'r':
	case 'R':
		if(strcasecmp(name+1, "RSIG") == 0) return TYPE_RRSIG;
		break;
	case 'n':
	case 'N':
		switch(name[1]) {
		case 's':
		case 'S':
			switch(name[2]) {
			case 0: return TYPE_NS;
			case 'e':
			case 'E':
				if(strcasecmp(name+2, "EC") == 0) return TYPE_NSEC;
				if(strcasecmp(name+2, "EC3") == 0) return TYPE_NSEC3;
				if(strcasecmp(name+2, "EC3PARAM") == 0) return TYPE_NSEC3PARAM;
				break;
			}
			break;
		}
		break;
	case 'd':
	case 'D':
		switch(name[1]) {
		case 's':
		case 'S':
			if(name[2]==0) return TYPE_DS;
			break;
		case 'n':
		case 'N':
			if(strcasecmp(name+2, "SKEY") == 0) return TYPE_DNSKEY;
			break;
		}
		break;
	case 'a':
	case 'A':
		switch(name[1]) {
		case 0:	return TYPE_A;
		case 'a':
		case 'A':
			if(strcasecmp(name+2, "AA") == 0) return TYPE_AAAA;
			break;
		}
		break;
	case 's':
	case 'S':
		if(strcasecmp(name+1, "OA") == 0) return TYPE_SOA;
		break;
	case 't':
	case 'T':
		if(strcasecmp(name+1, "XT") == 0) return TYPE_TXT;
		break;
	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		return 0; /* no RR types start with 0-9 */
	case 'i':
	case 'I':
		switch(name[1]) {
		case 'n':
		case 'N':
			return 0; /* 'IN' is a class not a type */
		}
		break;
	}

	for (int i=0, n=sizeof(descriptors)/sizeof(descriptors[0]); i < n; i++) {
		if (descriptors[i].name && strcasecmp(descriptors[i].name, name) == 0)
			return descriptors[i].code;
	}

	if (strlen(name) < 5)
		return 0;

	if (strncasecmp(name, "TYPE", 4) != 0)
		return 0;

	if (!isdigit((unsigned char)name[4]))
		return 0;

	/* The rest from the string must be a number.  */
	rrtype = strtol(name + 4, &end, 10);
	if (*end != '\0')
		return 0;
	if (rrtype < 0 || rrtype > 65535L)
		return 0;

	return (uint16_t) rrtype;
}

const char *
rrclass_to_string(uint16_t rrclass)
{
	static char buf[20];
	lookup_table_type *entry = lookup_by_id(dns_rrclasses, rrclass);
	if (entry) {
		assert(strlen(entry->name) < sizeof(buf));
		strlcpy(buf, entry->name, sizeof(buf));
	} else {
		snprintf(buf, sizeof(buf), "CLASS%d", (int) rrclass);
	}
	return buf;
}

uint16_t
rrclass_from_string(const char *name)
{
        char *end;
        long rrclass;
	lookup_table_type *entry;

	entry = lookup_by_name(dns_rrclasses, name);
	if (entry) {
		return (uint16_t) entry->id;
	}

	if (strlen(name) < 6)
		return 0;

	if (strncasecmp(name, "CLASS", 5) != 0)
		return 0;

	if (!isdigit((unsigned char)name[5]))
		return 0;

	/* The rest from the string must be a number.  */
	rrclass = strtol(name + 5, &end, 10);
	if (*end != '\0')
		return 0;
	if (rrclass < 0 || rrclass > 65535L)
		return 0;

	return (uint16_t) rrclass;
}

int32_t compare_rdata(
	const struct type_descriptor *descriptor,
	const struct rr *rr1,
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
zrdatacmp(uint16_t type, const union rdata_atom *rdatas, size_t rdata_count, rr_type *b)
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


































