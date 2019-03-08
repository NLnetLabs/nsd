#include "dnsextlang.h"
static dnsextlang_field t0001_fields[1] = {
	{ del_ftype_A, 0, { NULL }, NULL, "addr"
	, "IPv4 address" }
};
static const dnsextlang_stanza t0001 = {
	"A", 1, (del_option_I),
	"a host address [RFC1035]",
	1, t0001_fields
};
static dnsextlang_field t0002_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t0002 = {
	"NS", 2, (del_option_A),
	"an authoritative name server [RFC1035]",
	1, t0002_fields
};
static dnsextlang_field t0003_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t0003 = {
	"MD", 3, (del_option_A|del_option_O),
	"a mail destination (OBSOLETE - use MX) [RFC1035]",
	1, t0003_fields
};
static dnsextlang_field t0004_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t0004 = {
	"MF", 4, (del_option_A|del_option_O),
	"a mail forwarder (OBSOLETE - use MX) [RFC1035]",
	1, t0004_fields
};
static dnsextlang_field t0005_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t0005 = {
	"CNAME", 5, (del_option_A),
	"the canonical name for an alias [RFC1035]",
	1, t0005_fields
};
static dnsextlang_field t0006_fields[7] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "primary"
	, "Primary server name" },
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "mailbox"
	, "Responsible mailbox" },
	{ del_ftype_I4, 0, { NULL }, NULL, "serial"
	, "Serial number" },
	{ del_ftype_I4, (del_qual_P), { NULL }, NULL, "refresh"
	, "Refresh time (seconds)" },
	{ del_ftype_I4, (del_qual_P), { NULL }, NULL, "retry"
	, "Retry time (seconds)" },
	{ del_ftype_I4, (del_qual_P), { NULL }, NULL, "expire"
	, "Expire time (seconds)" },
	{ del_ftype_I4, (del_qual_P), { NULL }, NULL, "minimum"
	, "Minium time (seconds)" }
};
static const dnsextlang_stanza t0006 = {
	"SOA", 6, (del_option_A),
	"marks the start of a zone of authority [RFC1035]",
	7, t0006_fields
};
static dnsextlang_field t0007_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t0007 = {
	"MB", 7, (del_option_A|del_option_E),
	"a mailbox domain name (EXPERIMENTAL) [RFC1035]",
	1, t0007_fields
};
static dnsextlang_field t0008_fields[1] = {
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "mailbox"
	, "Mailbox name" }
};
static const dnsextlang_stanza t0008 = {
	"MG", 8, (del_option_A|del_option_E),
	"a mail group member (EXPERIMENTAL) [RFC1035]",
	1, t0008_fields
};
static dnsextlang_field t0009_fields[1] = {
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "mailbox"
	, "Mailbox name" }
};
static const dnsextlang_stanza t0009 = {
	"MR", 9, (del_option_A|del_option_E),
	"a mail rename domain name (EXPERIMENTAL) [RFC1035]",
	1, t0009_fields
};
static dnsextlang_field t000a_fields[1] = {
	{ del_ftype_X, 0, { NULL }, NULL, "anything"
	, "Anything" }
};
static const dnsextlang_stanza t000a = {
	"NULL", 10, (del_option_E),
	"a null RR (EXPERIMENTAL) [RFC1035]",
	1, t000a_fields
};
static dnsextlang_field t000b_fields[3] = {
	{ del_ftype_A, 0, { NULL }, NULL, NULL
	, "IPv4 address" },
	{ del_ftype_I1, 0, { NULL }, NULL, NULL
	, "Protocol number" },
	{ del_ftype_Z, (del_qual_WKS), { NULL }, NULL, "bitmap"
	, "Bit Map" }
};
static const dnsextlang_stanza t000b = {
	"WKS", 11, (del_option_I),
	"a well known service description [RFC1035]",
	3, t000b_fields
};
static dnsextlang_field t000c_fields[1] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "host"
	, "Host name" }
};
static const dnsextlang_stanza t000c = {
	"PTR", 12, (del_option_A),
	"a domain name pointer [RFC1035]",
	1, t000c_fields
};
static dnsextlang_field t000d_fields[2] = {
	{ del_ftype_S, 0, { NULL }, NULL, "cpu"
	, "CPU type" },
	{ del_ftype_S, 0, { NULL }, NULL, "os"
	, "Operating system" }
};
static const dnsextlang_stanza t000d = {
	"HINFO", 13, (del_option_A),
	"host information [RFC1035]",
	2, t000d_fields
};
static dnsextlang_field t000e_fields[2] = {
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "respbox"
	, "Responsible mailbox" },
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "errbox"
	, "Error mailbox" }
};
static const dnsextlang_stanza t000e = {
	"MINFO", 14, (del_option_A),
	"mailbox or mail list information [RFC1035]",
	2, t000e_fields
};
static dnsextlang_field t000f_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "priority"
	, "Priority (lower values are higher priority)" },
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "hostname"
	, "Host name" }
};
static const dnsextlang_stanza t000f = {
	"MX", 15, (del_option_A),
	"mail exchange [RFC1035]",
	2, t000f_fields
};
static dnsextlang_field t0010_fields[1] = {
	{ del_ftype_S, (del_qual_M), { NULL }, NULL, "text"
	, "Strings" }
};
static const dnsextlang_stanza t0010 = {
	"TXT", 16, (del_option_A),
	"text strings [RFC1035]",
	1, t0010_fields
};
static dnsextlang_field t0011_fields[2] = {
	{ del_ftype_N, (del_qual_A), { NULL }, NULL, "mailbox"
	, "Mailbox" },
	{ del_ftype_N, 0, { NULL }, NULL, "text"
	, "Text location" }
};
static const dnsextlang_stanza t0011 = {
	"RP", 17, (del_option_A),
	"for Responsible Person [RFC1183]",
	2, t0011_fields
};
static dnsextlang_field t0012_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "subtype"
	, "Subtype" },
	{ del_ftype_N, 0, { NULL }, NULL, "hostname"
	, "Hostname" }
};
static const dnsextlang_stanza t0012 = {
	"AFSDB", 18, (del_option_A),
	"for AFS Data Base location [RFC1183][RFC5864]",
	2, t0012_fields
};
static dnsextlang_field t0013_fields[1] = {
	{ del_ftype_S, 0, { NULL }, NULL, "address"
	, "PSDN address" }
};
static const dnsextlang_stanza t0013 = {
	"X25", 19, (del_option_A),
	"for X.25 PSDN address [RFC1183]",
	1, t0013_fields
};
static dnsextlang_field t0014_fields[1] = {
	{ del_ftype_S, (del_qual_M), { NULL }, NULL, "address"
	, "ISDN address, and optional subaddress" }
};
static const dnsextlang_stanza t0014 = {
	"ISDN", 20, (del_option_A),
	"for ISDN address [RFC1183]",
	1, t0014_fields
};
static dnsextlang_field t0015_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "preference"
	, "Preference" },
	{ del_ftype_N, 0, { NULL }, NULL, "hostname"
	, "Intermediate host" }
};
static const dnsextlang_stanza t0015 = {
	"RT", 21, (del_option_A),
	"for Route Through [RFC1183]",
	2, t0015_fields
};
static dnsextlang_field t0016_fields[1] = {
	{ del_ftype_Z, (del_qual_NSAP), { NULL }, NULL, "address"
	, "NSAP Address" }
};
static const dnsextlang_stanza t0016 = {
	"NSAP", 22, (del_option_I),
	"for NSAP address, NSAP style A record [RFC1706]",
	1, t0016_fields
};
static dnsextlang_field t0017_fields[1] = {
	{ del_ftype_N, 0, { NULL }, NULL, "hostname"
	, "Host name" }
};
static const dnsextlang_stanza t0017 = {
	"NSAP-PTR", 23, (del_option_I),
	"for domain name pointer, NSAP style [RFC1348][RFC1637]",
	1, t0017_fields
};
static dnsextlang_field t0018_fields[9] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "sigtype"
	, "Type covered" },
	{ del_ftype_I1, 0, { NULL }, NULL, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0, { NULL }, NULL, "labels"
	, "Labels" },
	{ del_ftype_I4, 0, { NULL }, NULL, "ttl"
	, "Original TTL" },
	{ del_ftype_T, 0, { NULL }, NULL, "expires"
	, "Signature expiration time" },
	{ del_ftype_T, 0, { NULL }, NULL, "signed"
	, "Time signed" },
	{ del_ftype_I2, 0, { NULL }, NULL, "footprint"
	, "Key footprint" },
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "name"
	, "Signer's name" },
	{ del_ftype_B64, 0, { NULL }, NULL, "signature"
	, "Signature data" }
};
static const dnsextlang_stanza t0018 = {
	"SIG", 24, (del_option_A),
	"for security signature [RFC4034]",
	9, t0018_fields
};
static dnsextlang_field t0019_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_I1, 0, { NULL }, NULL, "protocol"
	, "Protocol" },
	{ del_ftype_I1, 0, { NULL }, NULL, "algorithm"
	, "Algorithm" },
	{ del_ftype_B64, 0, { NULL }, NULL, "data"
	, "Key data" }
};
static const dnsextlang_stanza t0019 = {
	"KEY", 25, (del_option_A),
	"for security key [RFC4034]",
	4, t0019_fields
};
static dnsextlang_field t001a_fields[3] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "pref"
	, "Preference" },
	{ del_ftype_N, 0, { NULL }, NULL, "idomain"
	, "Internet mail domain" },
	{ del_ftype_N, 0, { NULL }, NULL, "xdomain"
	, "X.400 mail domain" }
};
static const dnsextlang_stanza t001a = {
	"PX", 26, (del_option_I),
	"X.400 mail mapping information [RFC2163]",
	3, t001a_fields
};
static dnsextlang_field t001b_fields[3] = {
	{ del_ftype_S, 0, { NULL }, NULL, "longitude"
	, "Longitude (decimal degrees)" },
	{ del_ftype_S, 0, { NULL }, NULL, "latitude"
	, "Latitude (decimal degrees)" },
	{ del_ftype_S, 0, { NULL }, NULL, "altitude"
	, "Altitude (meters)" }
};
static const dnsextlang_stanza t001b = {
	"GPOS", 27, (del_option_A),
	"Geographical Position [RFC1712]",
	3, t001b_fields
};
static dnsextlang_field t001c_fields[1] = {
	{ del_ftype_AAAA, 0, { NULL }, NULL, "address"
	, "Address" }
};
static const dnsextlang_stanza t001c = {
	"AAAA", 28, (del_option_I),
	"IP6 Address [RFC3596]",
	1, t001c_fields
};
static dnsextlang_field t001d_fields[7] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "version"
	, "Version" },
	{ del_ftype_I1, 0, { NULL }, NULL, "sphere"
	, "Sphere size" },
	{ del_ftype_I2, 0, { NULL }, NULL, "hprecision"
	, "Horiz precision" },
	{ del_ftype_I2, 0, { NULL }, NULL, "vprecision"
	, "Vert precision" },
	{ del_ftype_I4, 0, { NULL }, NULL, "latitude"
	, "Latitude (offset milliseconds)" },
	{ del_ftype_I4, 0, { NULL }, NULL, "longitude"
	, "Longitude (offset milliseconds)" },
	{ del_ftype_I4, 0, { NULL }, NULL, "altitude"
	, "Altitude (offset cm)" }
};
static const dnsextlang_stanza t001d = {
	"LOC", 29, (del_option_A),
	"Location Information [RFC1876]",
	7, t001d_fields
};
static dnsextlang_field t001e_fields[2] = {
	{ del_ftype_N, (del_qual_C), { NULL }, NULL, "next"
	, "Domain" },
	{ del_ftype_Z, (del_qual_NXT), { NULL }, NULL, "rrtypes"
	, "Bitmap of rrtypes" }
};
static const dnsextlang_stanza t001e = {
	"NXT", 30, (del_option_A|del_option_O),
	"Next Domain (OBSOLETE) [RFC3755][RFC2535]",
	2, t001e_fields
};
static dnsextlang_field t001f_fields[1] = {
	{ del_ftype_X, 0, { NULL }, NULL, "identifier"
	, "Endpoint identifier" }
};
static const dnsextlang_stanza t001f = {
	"EID", 31, (del_option_P),
	"Endpoint Identifier",
	1, t001f_fields
};
static dnsextlang_field t0020_fields[1] = {
	{ del_ftype_X, 0, { NULL }, NULL, "locator"
	, "Nimrod locator" }
};
static const dnsextlang_stanza t0020 = {
	"NIMLOC", 32, (del_option_P),
	"Nimrod Locator",
	1, t0020_fields
};
static dnsextlang_field t0021_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "priority"
	, "Priority" },
	{ del_ftype_I2, 0, { NULL }, NULL, "weight"
	, "Weight" },
	{ del_ftype_I2, 0, { NULL }, NULL, "port"
	, "Port" },
	{ del_ftype_N, 0, { NULL }, NULL, "target"
	, "Target host name" }
};
static const dnsextlang_stanza t0021 = {
	"SRV", 33, (del_option_I),
	"Server Selection [1][RFC2782]",
	4, t0021_fields
};
static dnsextlang_field t0022_fields[1] = {
	{ del_ftype_X, 0, { NULL }, NULL, "format"
	, "Format" }
};
static const dnsextlang_stanza t0022 = {
	"ATMA", 34, (del_option_P),
	"ATM Address",
	1, t0022_fields
};
static dnsextlang_field t0023_fields[6] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "order"
	, "Order" },
	{ del_ftype_I2, 0, { NULL }, NULL, "pref"
	, "Preference" },
	{ del_ftype_S, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_S, 0, { NULL }, NULL, "services"
	, "Services" },
	{ del_ftype_S, 0, { NULL }, NULL, "regex"
	, "Regular expression" },
	{ del_ftype_N, 0, { NULL }, NULL, "replacement"
	, "Replacement" }
};
static const dnsextlang_stanza t0023 = {
	"NAPTR", 35, (del_option_I),
	"Naming Authority Pointer [RFC2915][RFC2168][RFC3403]",
	6, t0023_fields
};
static dnsextlang_field t0024_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "pref"
	, "Preference" },
	{ del_ftype_N, 0, { NULL }, NULL, "exchanger"
	, "Exchanger" }
};
static const dnsextlang_stanza t0024 = {
	"KX", 36, (del_option_I),
	"Key Exchanger [RFC2230]",
	2, t0024_fields
};
static const char *t0025_0_00xx[256] = {
	  NULL, "PKIX", "SPKI", "PGP", "IPKIX", "ISPKI", "IPGP", "ACPKIX",
	 "IACPKIX", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, "URI", "OID", NULL};
static const char **t0025_0_xxxx[256] = {
	  t0025_0_00xx, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL};
static const long long int t0025_0_ACPKIX_ll = 7;
static ldh_radix t0025_0_ACPKIX = { "ACPKIX", 6, &t0025_0_ACPKIX_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_IACPKIX_ll = 8;
static ldh_radix t0025_0_IACPKIX = { "ACPKIX", 6, &t0025_0_IACPKIX_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_IPGP_ll = 6;
static ldh_radix t0025_0_IPGP = { "GP", 2, &t0025_0_IPGP_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_IPKIX_ll = 4;
static ldh_radix t0025_0_IPKIX = { "KIX", 3, &t0025_0_IPKIX_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_0_IP = { "P", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t0025_0_IPGP, NULL, NULL, NULL,
	 &t0025_0_IPKIX, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t0025_0_ISPKI_ll = 5;
static ldh_radix t0025_0_ISPKI = { "SPKI", 4, &t0025_0_ISPKI_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_0_I = { "I", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t0025_0_IACPKIX, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t0025_0_IP, NULL, NULL,
	 &t0025_0_ISPKI, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t0025_0_OID_ll = 254;
static ldh_radix t0025_0_OID = { "OID", 3, &t0025_0_OID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_PGP_ll = 3;
static ldh_radix t0025_0_PGP = { "GP", 2, &t0025_0_PGP_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_PKIX_ll = 1;
static ldh_radix t0025_0_PKIX = { "KIX", 3, &t0025_0_PKIX_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_0_P = { "P", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t0025_0_PGP, NULL, NULL, NULL,
	 &t0025_0_PKIX, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t0025_0_SPKI_ll = 2;
static ldh_radix t0025_0_SPKI = { "SPKI", 4, &t0025_0_SPKI_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_0_URI_ll = 253;
static ldh_radix t0025_0_URI = { "URI", 3, &t0025_0_URI_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_0_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t0025_0_ACPKIX, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t0025_0_I, NULL, NULL, NULL, NULL, NULL,&t0025_0_OID,&t0025_0_P,
	  NULL, NULL,&t0025_0_SPKI, NULL,&t0025_0_URI, NULL, NULL, NULL,
	  NULL, NULL } };
static const char *t0025_2_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t0025_2_DH_ll = 2;
static ldh_radix t0025_2_DH = { "H", 1, &t0025_2_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_2_DSA_ll = 3;
static ldh_radix t0025_2_DSA = { "SA", 2, &t0025_2_DSA_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_2_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t0025_2_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t0025_2_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t0025_2_ECC_ll = 4;
static ldh_radix t0025_2_ECC = { "ECC", 3, &t0025_2_ECC_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_2_INDIRECT_ll = 252;
static ldh_radix t0025_2_INDIRECT = { "INDIRECT", 8, &t0025_2_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_2_PRIVATEDNS_ll = 253;
static ldh_radix t0025_2_PRIVATEDNS = { "DNS", 3, &t0025_2_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_2_PRIVATEOID_ll = 254;
static ldh_radix t0025_2_PRIVATEOID = { "OID", 3, &t0025_2_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_2_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t0025_2_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t0025_2_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t0025_2_RSAMD5_ll = 1;
static ldh_radix t0025_2_RSAMD5 = { "MD5", 3, &t0025_2_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0025_2_RSASHA1_ll = 5;
static ldh_radix t0025_2_RSASHA1 = { "SHA1", 4, &t0025_2_RSASHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0025_2_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t0025_2_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t0025_2_RSASHA1,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t0025_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t0025_2_D,&t0025_2_ECC, NULL, NULL, NULL,&t0025_2_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t0025_2_PRIVATE, NULL,
	 &t0025_2_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t0025_fields[4] = {
	{ del_ftype_I2, 0
	, { (void *)t0025_0_xxxx }, &t0025_0_ldh_radix, "type"
	, "Type" },
	{ del_ftype_I2, 0, { NULL }, NULL, "tag"
	, "Key tag" },
	{ del_ftype_I1, 0
	, { (void *)t0025_2_xx }, &t0025_2_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_B64, 0, { NULL }, NULL, "certificate"
	, "Certificate or CRL" }
};
static const dnsextlang_stanza t0025 = {
	"CERT", 37, (del_option_A),
	"CERT [RFC4398]",
	4, t0025_fields
};
static dnsextlang_field t0026_fields[3] = {
	{ del_ftype_Z, (del_qual_A6P), { NULL }, NULL, "preflen"
	, "Prefix length" },
	{ del_ftype_Z, (del_qual_A6S), { NULL }, NULL, "suffix"
	, "Address suffix" },
	{ del_ftype_N, 0, { NULL }, NULL, "prefname"
	, "Prefix name" }
};
static const dnsextlang_stanza t0026 = {
	"A6", 38, (del_option_I|del_option_O),
	"A6 (OBSOLETE - use AAAA) [RFC3226][RFC2874][RFC6563]",
	3, t0026_fields
};
static dnsextlang_field t0027_fields[1] = {
	{ del_ftype_N, 0, { NULL }, NULL, "source"
	, "Source name" }
};
static const dnsextlang_stanza t0027 = {
	"DNAME", 39, (del_option_A),
	"DNAME [RFC6672]",
	1, t0027_fields
};
static dnsextlang_field t0028_fields[3] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "coding"
	, "Coding" },
	{ del_ftype_I2, 0, { NULL }, NULL, "subcoding"
	, "Subcoding" },
	{ del_ftype_B64, 0, { NULL }, NULL, "data"
	, "Data" }
};
static const dnsextlang_stanza t0028 = {
	"SINK", 40, (del_option_P),
	"SINK",
	3, t0028_fields
};
static dnsextlang_field t0029_fields[2] = {
	{ del_ftype_I2, (del_qual_M), { NULL }, NULL, "code"
	, "Option code" },
	{ del_ftype_X, (del_qual_L), { NULL }, NULL, "data"
	, "Option data" }
};
static const dnsextlang_stanza t0029 = {
	"OPT", 41, (del_option_W),
	"OPT [RFC6891][RFC3225]",
	2, t0029_fields
};
static dnsextlang_field t002a_fields[1] = {
	{ del_ftype_Z, (del_qual_APL), { NULL }, NULL, "prefixes"
	, "Prefixes" }
};
static const dnsextlang_stanza t002a = {
	"APL", 42, (del_option_I),
	"APL [RFC3123]",
	1, t002a_fields
};
static const char *t002b_1_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", "DSA-NSEC-SHA1",
	 "RSASHA1-NSEC3-SHA1", "RSASHA256", NULL, "RSASHA512", NULL,
	 "ECC-GOST", "ECDSAP256SHA256", "ECDSAP384SHA384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t002b_1_DH_ll = 2;
static ldh_radix t002b_1_DH = { "H", 1, &t002b_1_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_DSA_NSEC_SHA1_ll = 6;
static ldh_radix t002b_1_DSA_NSEC_SHA1 = { "-NSEC-SHA1", 10, &t002b_1_DSA_NSEC_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_DSA_ll = 3;
static ldh_radix t002b_1_DSA = { "SA", 2, &t002b_1_DSA_ll,
	{&t002b_1_DSA_NSEC_SHA1, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002b_1_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t002b_1_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t002b_1_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t002b_1_ECC_GOST_ll = 12;
static ldh_radix t002b_1_ECC_GOST = { "-GOST", 5, &t002b_1_ECC_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_ECC_ll = 4;
static ldh_radix t002b_1_ECC = { "C", 1, &t002b_1_ECC_ll,
	{&t002b_1_ECC_GOST, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t002b_1_ECDSAP256SHA256_ll = 13;
static ldh_radix t002b_1_ECDSAP256SHA256 = { "256SHA256", 9, &t002b_1_ECDSAP256SHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_ECDSAP384SHA384_ll = 14;
static ldh_radix t002b_1_ECDSAP384SHA384 = { "384SHA384", 9, &t002b_1_ECDSAP384SHA384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002b_1_ECDSAP = { "DSAP", 4, NULL,
	{ NULL, NULL, NULL, NULL, NULL,&t002b_1_ECDSAP256SHA256,
	 &t002b_1_ECDSAP384SHA384, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002b_1_EC = { "EC", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t002b_1_ECC,&t002b_1_ECDSAP, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static const long long int t002b_1_INDIRECT_ll = 252;
static ldh_radix t002b_1_INDIRECT = { "INDIRECT", 8, &t002b_1_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_PRIVATEDNS_ll = 253;
static ldh_radix t002b_1_PRIVATEDNS = { "DNS", 3, &t002b_1_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_PRIVATEOID_ll = 254;
static ldh_radix t002b_1_PRIVATEOID = { "OID", 3, &t002b_1_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002b_1_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t002b_1_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t002b_1_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t002b_1_RSAMD5_ll = 1;
static ldh_radix t002b_1_RSAMD5 = { "MD5", 3, &t002b_1_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_RSASHA1_NSEC3_SHA1_ll = 7;
static ldh_radix t002b_1_RSASHA1_NSEC3_SHA1 = { "-NSEC3-SHA1", 11, &t002b_1_RSASHA1_NSEC3_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_RSASHA1_ll = 5;
static ldh_radix t002b_1_RSASHA1 = { "1", 1, &t002b_1_RSASHA1_ll,
	{&t002b_1_RSASHA1_NSEC3_SHA1, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t002b_1_RSASHA256_ll = 8;
static ldh_radix t002b_1_RSASHA256 = { "256", 3, &t002b_1_RSASHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_1_RSASHA512_ll = 10;
static ldh_radix t002b_1_RSASHA512 = { "512", 3, &t002b_1_RSASHA512_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002b_1_RSASHA = { "SHA", 3, NULL,
	{ NULL, NULL, NULL, NULL,&t002b_1_RSASHA1,&t002b_1_RSASHA256, NULL,
	  NULL,&t002b_1_RSASHA512, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002b_1_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t002b_1_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t002b_1_RSASHA,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002b_1_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t002b_1_D,&t002b_1_EC, NULL, NULL, NULL,&t002b_1_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t002b_1_PRIVATE, NULL,
	 &t002b_1_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const char *t002b_2_xx[256] = {
	  NULL, "SHA-1", "SHA-256", "GOST", "SHA-384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL};
static const long long int t002b_2_GOST_ll = 3;
static ldh_radix t002b_2_GOST = { "GOST", 4, &t002b_2_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_2_SHA_1_ll = 1;
static ldh_radix t002b_2_SHA_1 = { "1", 1, &t002b_2_SHA_1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_2_SHA_256_ll = 2;
static ldh_radix t002b_2_SHA_256 = { "256", 3, &t002b_2_SHA_256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002b_2_SHA_384_ll = 4;
static ldh_radix t002b_2_SHA_384 = { "384", 3, &t002b_2_SHA_384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002b_2_SHA_ = { "SHA-", 4, NULL,
	{ NULL, NULL, NULL, NULL,&t002b_2_SHA_1,&t002b_2_SHA_256,
	 &t002b_2_SHA_384, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002b_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t002b_2_GOST, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL,&t002b_2_SHA_, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t002b_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "keytag"
	, "Key tag" },
	{ del_ftype_I1, 0
	, { (void *)t002b_1_xx }, &t002b_1_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0
	, { (void *)t002b_2_xx }, &t002b_2_ldh_radix, "digtype"
	, "Digest type" },
	{ del_ftype_X, 0, { NULL }, NULL, "digest"
	, "Digest" }
};
static const dnsextlang_stanza t002b = {
	"DS", 43, (del_option_A),
	"Delegation Signer [RFC4034][RFC3658]",
	4, t002b_fields
};
static dnsextlang_field t002c_fields[3] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0, { NULL }, NULL, "ftype"
	, "Fingerprint type" },
	{ del_ftype_X, 0, { NULL }, NULL, "fingerprint"
	, "Fingerprint" }
};
static const dnsextlang_stanza t002c = {
	"SSHFP", 44, (del_option_A),
	"SSH Key Fingerprint [RFC4255]",
	3, t002c_fields
};
static dnsextlang_field t002d_fields[5] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "prec"
	, "Precedence" },
	{ del_ftype_I1, 0, { NULL }, NULL, "gtype"
	, "Gateway type" },
	{ del_ftype_I1, 0, { NULL }, NULL, "algorithm"
	, "Algorithm" },
	{ del_ftype_Z, (del_qual_IPSECKEY), { NULL }, NULL, "gateway"
	, "Gateway" },
	{ del_ftype_B64, 0, { NULL }, NULL, "key"
	, "Public key" }
};
static const dnsextlang_stanza t002d = {
	"IPSECKEY", 45, (del_option_I),
	"IPSECKEY [RFC4025]",
	5, t002d_fields
};
static const char *t002e_1_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t002e_1_DH_ll = 2;
static ldh_radix t002e_1_DH = { "H", 1, &t002e_1_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002e_1_DSA_ll = 3;
static ldh_radix t002e_1_DSA = { "SA", 2, &t002e_1_DSA_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002e_1_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t002e_1_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t002e_1_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t002e_1_ECC_ll = 4;
static ldh_radix t002e_1_ECC = { "ECC", 3, &t002e_1_ECC_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002e_1_INDIRECT_ll = 252;
static ldh_radix t002e_1_INDIRECT = { "INDIRECT", 8, &t002e_1_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002e_1_PRIVATEDNS_ll = 253;
static ldh_radix t002e_1_PRIVATEDNS = { "DNS", 3, &t002e_1_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002e_1_PRIVATEOID_ll = 254;
static ldh_radix t002e_1_PRIVATEOID = { "OID", 3, &t002e_1_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002e_1_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t002e_1_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t002e_1_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t002e_1_RSAMD5_ll = 1;
static ldh_radix t002e_1_RSAMD5 = { "MD5", 3, &t002e_1_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t002e_1_RSASHA1_ll = 5;
static ldh_radix t002e_1_RSASHA1 = { "SHA1", 4, &t002e_1_RSASHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t002e_1_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t002e_1_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t002e_1_RSASHA1,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t002e_1_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t002e_1_D,&t002e_1_ECC, NULL, NULL, NULL,&t002e_1_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t002e_1_PRIVATE, NULL,
	 &t002e_1_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t002e_fields[9] = {
	{ del_ftype_R, 0, { NULL }, NULL, "rrtype"
	, "Type covered (Type mnemonic)" },
	{ del_ftype_I1, 0
	, { (void *)t002e_1_xx }, &t002e_1_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0, { NULL }, NULL, "labels"
	, "Labels" },
	{ del_ftype_I4, 0, { NULL }, NULL, "origttl"
	, "Original TTL" },
	{ del_ftype_T, 0, { NULL }, NULL, "expire"
	, "Signature expiration (timestamp)" },
	{ del_ftype_T, 0, { NULL }, NULL, "inception"
	, "Signature inception (timestamp)" },
	{ del_ftype_I2, 0, { NULL }, NULL, "keytag"
	, "Key tag" },
	{ del_ftype_N, (del_qual_L), { NULL }, NULL, "signer"
	, "Signer's name" },
	{ del_ftype_B64, 0, { NULL }, NULL, "signature"
	, "Signature" }
};
static const dnsextlang_stanza t002e = {
	"RRSIG", 46, (del_option_A),
	"RRSIG [RFC4034][RFC3755]",
	9, t002e_fields
};
static dnsextlang_field t002f_fields[2] = {
	{ del_ftype_N, (del_qual_L), { NULL }, NULL, "next"
	, "Next domain name" },
	{ del_ftype_R, (del_qual_L), { NULL }, NULL, "types"
	, "Type bitmaps (as window blocks)" }
};
static const dnsextlang_stanza t002f = {
	"NSEC", 47, (del_option_A),
	"NSEC [RFC4034][RFC3755]",
	2, t002f_fields
};
static const char *t0030_2_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t0030_2_DH_ll = 2;
static ldh_radix t0030_2_DH = { "H", 1, &t0030_2_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0030_2_DSA_ll = 3;
static ldh_radix t0030_2_DSA = { "SA", 2, &t0030_2_DSA_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0030_2_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t0030_2_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t0030_2_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t0030_2_ECC_ll = 4;
static ldh_radix t0030_2_ECC = { "ECC", 3, &t0030_2_ECC_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0030_2_INDIRECT_ll = 252;
static ldh_radix t0030_2_INDIRECT = { "INDIRECT", 8, &t0030_2_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0030_2_PRIVATEDNS_ll = 253;
static ldh_radix t0030_2_PRIVATEDNS = { "DNS", 3, &t0030_2_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0030_2_PRIVATEOID_ll = 254;
static ldh_radix t0030_2_PRIVATEOID = { "OID", 3, &t0030_2_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0030_2_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t0030_2_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t0030_2_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t0030_2_RSAMD5_ll = 1;
static ldh_radix t0030_2_RSAMD5 = { "MD5", 3, &t0030_2_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t0030_2_RSASHA1_ll = 5;
static ldh_radix t0030_2_RSASHA1 = { "SHA1", 4, &t0030_2_RSASHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t0030_2_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t0030_2_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t0030_2_RSASHA1,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t0030_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t0030_2_D,&t0030_2_ECC, NULL, NULL, NULL,&t0030_2_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t0030_2_PRIVATE, NULL,
	 &t0030_2_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t0030_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_I1, 0, { NULL }, NULL, "protocol"
	, "Protocol (must be 3)" },
	{ del_ftype_I1, 0
	, { (void *)t0030_2_xx }, &t0030_2_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_B64, 0, { NULL }, NULL, "publickey"
	, "Public key" }
};
static const dnsextlang_stanza t0030 = {
	"DNSKEY", 48, (del_option_A),
	"DNSKEY [RFC4034][RFC3755]",
	4, t0030_fields
};
static dnsextlang_field t0031_fields[1] = {
	{ del_ftype_B64, 0, { NULL }, NULL, "dhcpinfo"
	, "DHCP information" }
};
static const dnsextlang_stanza t0031 = {
	"DHCID", 49, (del_option_I),
	"DHCID [RFC4701]",
	1, t0031_fields
};
static const char *t0032_0_xx[256] = {
	  NULL, "SHA-1", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL};
static const long long int t0032_0_SHA_1_ll = 1;
static ldh_radix t0032_0_SHA_1 = { "SHA-1", 5, &t0032_0_SHA_1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const char *t0032_1_xx[256] = {
	  NULL, "OPTOUT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL};
static const long long int t0032_1_OPTOUT_ll = 1;
static ldh_radix t0032_1_OPTOUT = { "OPTOUT", 6, &t0032_1_OPTOUT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static dnsextlang_field t0032_fields[6] = {
	{ del_ftype_I1, 0
	, { (void *)t0032_0_xx }, &t0032_0_SHA_1, "algorithm"
	, "Hash algorithm" },
	{ del_ftype_I1, 0
	, { (void *)t0032_1_xx }, &t0032_1_OPTOUT, "flags"
	, "Flags" },
	{ del_ftype_I2, 0, { NULL }, NULL, "iterations"
	, "Iterations" },
	{ del_ftype_X, (del_qual_C), { NULL }, NULL, "salt"
	, "Salt" },
	{ del_ftype_B32, 0, { NULL }, NULL, "next"
	, "Next hashed owner" },
	{ del_ftype_R, (del_qual_L), { NULL }, NULL, "types"
	, "Type bitmaps (as window blocks)" }
};
static const dnsextlang_stanza t0032 = {
	"NSEC3", 50, (del_option_A),
	"NSEC3 [RFC5155]",
	6, t0032_fields
};
static const char *t0033_0_xx[256] = {
	  NULL, "SHA-1", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL};
static const long long int t0033_0_SHA_1_ll = 1;
static ldh_radix t0033_0_SHA_1 = { "SHA-1", 5, &t0033_0_SHA_1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const char *t0033_1_xx[256] = {
	  NULL, "OPTOUT", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL};
static const long long int t0033_1_OPTOUT_ll = 1;
static ldh_radix t0033_1_OPTOUT = { "OPTOUT", 6, &t0033_1_OPTOUT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static dnsextlang_field t0033_fields[4] = {
	{ del_ftype_I1, 0
	, { (void *)t0033_0_xx }, &t0033_0_SHA_1, "algorithm"
	, "Hash algorithm" },
	{ del_ftype_I1, 0
	, { (void *)t0033_1_xx }, &t0033_1_OPTOUT, "flags"
	, "Flags" },
	{ del_ftype_I2, 0, { NULL }, NULL, "iterations"
	, "Iterations" },
	{ del_ftype_X, (del_qual_C), { NULL }, NULL, "salt"
	, "Salt" }
};
static const dnsextlang_stanza t0033 = {
	"NSEC3PARAM", 51, (del_option_A),
	"NSEC3PARAM [RFC5155]",
	4, t0033_fields
};
static dnsextlang_field t0034_fields[4] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "usage"
	, "Certificate usage" },
	{ del_ftype_I1, 0, { NULL }, NULL, "selector"
	, "Certificate selector" },
	{ del_ftype_I1, 0, { NULL }, NULL, "mtype"
	, "Matching Type" },
	{ del_ftype_X, 0, { NULL }, NULL, "cert"
	, "Certificate association data" }
};
static const dnsextlang_stanza t0034 = {
	"TLSA", 52, (del_option_A),
	"TLSA [RFC6698]",
	4, t0034_fields
};
static dnsextlang_field t0035_fields[4] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "usage"
	, "Certificate usage" },
	{ del_ftype_I1, 0, { NULL }, NULL, "selector"
	, "Certificate selector" },
	{ del_ftype_I1, 0, { NULL }, NULL, "mtype"
	, "Matching Type" },
	{ del_ftype_X, 0, { NULL }, NULL, "cert"
	, "Certificate association data" }
};
static const dnsextlang_stanza t0035 = {
	"SMIMEA", 53, (del_option_A),
	"S/MIME cert association [RFC8162]",
	4, t0035_fields
};
static dnsextlang_field t0037_fields[4] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "pkalg"
	, "PK algorithm" },
	{ del_ftype_Z, (del_qual_HIPHIT), { NULL }, NULL, "hit"
	, "HIT" },
	{ del_ftype_Z, (del_qual_HIPPK), { NULL }, NULL, "pubkey"
	, "Public Key" },
	{ del_ftype_N, (del_qual_O|del_qual_M), { NULL }, NULL, "servers"
	, "Rendezvous servers" }
};
static const dnsextlang_stanza t0037 = {
	"HIP", 55, (del_option_A),
	"Host Identity Protocol [RFC8005]",
	4, t0037_fields
};
static dnsextlang_field t0038_fields[1] = {
	{ del_ftype_S, 0, { NULL }, NULL, "status"
	, "Status of zone" }
};
static const dnsextlang_stanza t0038 = {
	"NINFO", 56, (del_option_P),
	"NINFO",
	1, t0038_fields
};
static dnsextlang_field t0039_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_I1, 0, { NULL }, NULL, "protocol"
	, "Protocol" },
	{ del_ftype_I1, 0, { NULL }, NULL, "algorithm"
	, "Algorithm" },
	{ del_ftype_B64, 0, { NULL }, NULL, "data"
	, "Key data" }
};
static const dnsextlang_stanza t0039 = {
	"RKEY", 57, (del_option_P),
	"RKEY",
	4, t0039_fields
};
static dnsextlang_field t003a_fields[2] = {
	{ del_ftype_N, 0, { NULL }, NULL, "previous"
	, "Previous" },
	{ del_ftype_N, 0, { NULL }, NULL, "next"
	, "Next" }
};
static const dnsextlang_stanza t003a = {
	"TALINK", 58, (del_option_P),
	"Trust Anchor LINK",
	2, t003a_fields
};
static const char *t003b_1_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", "DSA-NSEC-SHA1",
	 "RSASHA1-NSEC3-SHA1", "RSASHA256", NULL, "RSASHA512", NULL,
	 "ECC-GOST", "ECDSAP256SHA256", "ECDSAP384SHA384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t003b_1_DH_ll = 2;
static ldh_radix t003b_1_DH = { "H", 1, &t003b_1_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_DSA_NSEC_SHA1_ll = 6;
static ldh_radix t003b_1_DSA_NSEC_SHA1 = { "-NSEC-SHA1", 10, &t003b_1_DSA_NSEC_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_DSA_ll = 3;
static ldh_radix t003b_1_DSA = { "SA", 2, &t003b_1_DSA_ll,
	{&t003b_1_DSA_NSEC_SHA1, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003b_1_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t003b_1_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t003b_1_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t003b_1_ECC_GOST_ll = 12;
static ldh_radix t003b_1_ECC_GOST = { "-GOST", 5, &t003b_1_ECC_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_ECC_ll = 4;
static ldh_radix t003b_1_ECC = { "C", 1, &t003b_1_ECC_ll,
	{&t003b_1_ECC_GOST, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t003b_1_ECDSAP256SHA256_ll = 13;
static ldh_radix t003b_1_ECDSAP256SHA256 = { "256SHA256", 9, &t003b_1_ECDSAP256SHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_ECDSAP384SHA384_ll = 14;
static ldh_radix t003b_1_ECDSAP384SHA384 = { "384SHA384", 9, &t003b_1_ECDSAP384SHA384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003b_1_ECDSAP = { "DSAP", 4, NULL,
	{ NULL, NULL, NULL, NULL, NULL,&t003b_1_ECDSAP256SHA256,
	 &t003b_1_ECDSAP384SHA384, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003b_1_EC = { "EC", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t003b_1_ECC,&t003b_1_ECDSAP, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static const long long int t003b_1_INDIRECT_ll = 252;
static ldh_radix t003b_1_INDIRECT = { "INDIRECT", 8, &t003b_1_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_PRIVATEDNS_ll = 253;
static ldh_radix t003b_1_PRIVATEDNS = { "DNS", 3, &t003b_1_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_PRIVATEOID_ll = 254;
static ldh_radix t003b_1_PRIVATEOID = { "OID", 3, &t003b_1_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003b_1_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t003b_1_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t003b_1_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t003b_1_RSAMD5_ll = 1;
static ldh_radix t003b_1_RSAMD5 = { "MD5", 3, &t003b_1_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_RSASHA1_NSEC3_SHA1_ll = 7;
static ldh_radix t003b_1_RSASHA1_NSEC3_SHA1 = { "-NSEC3-SHA1", 11, &t003b_1_RSASHA1_NSEC3_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_RSASHA1_ll = 5;
static ldh_radix t003b_1_RSASHA1 = { "1", 1, &t003b_1_RSASHA1_ll,
	{&t003b_1_RSASHA1_NSEC3_SHA1, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t003b_1_RSASHA256_ll = 8;
static ldh_radix t003b_1_RSASHA256 = { "256", 3, &t003b_1_RSASHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_1_RSASHA512_ll = 10;
static ldh_radix t003b_1_RSASHA512 = { "512", 3, &t003b_1_RSASHA512_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003b_1_RSASHA = { "SHA", 3, NULL,
	{ NULL, NULL, NULL, NULL,&t003b_1_RSASHA1,&t003b_1_RSASHA256, NULL,
	  NULL,&t003b_1_RSASHA512, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003b_1_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t003b_1_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t003b_1_RSASHA,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003b_1_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t003b_1_D,&t003b_1_EC, NULL, NULL, NULL,&t003b_1_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t003b_1_PRIVATE, NULL,
	 &t003b_1_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const char *t003b_2_xx[256] = {
	  NULL, "SHA-1", "SHA-256", "GOST", "SHA-384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL};
static const long long int t003b_2_GOST_ll = 3;
static ldh_radix t003b_2_GOST = { "GOST", 4, &t003b_2_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_2_SHA_1_ll = 1;
static ldh_radix t003b_2_SHA_1 = { "1", 1, &t003b_2_SHA_1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_2_SHA_256_ll = 2;
static ldh_radix t003b_2_SHA_256 = { "256", 3, &t003b_2_SHA_256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003b_2_SHA_384_ll = 4;
static ldh_radix t003b_2_SHA_384 = { "384", 3, &t003b_2_SHA_384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003b_2_SHA_ = { "SHA-", 4, NULL,
	{ NULL, NULL, NULL, NULL,&t003b_2_SHA_1,&t003b_2_SHA_256,
	 &t003b_2_SHA_384, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003b_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t003b_2_GOST, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL,&t003b_2_SHA_, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t003b_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "keytag"
	, "Key tag" },
	{ del_ftype_I1, 0
	, { (void *)t003b_1_xx }, &t003b_1_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0
	, { (void *)t003b_2_xx }, &t003b_2_ldh_radix, "digtype"
	, "Digest type" },
	{ del_ftype_X, 0, { NULL }, NULL, "digest"
	, "Digest" }
};
static const dnsextlang_stanza t003b = {
	"CDS", 59, (del_option_A),
	"Child DS [RFC7344]",
	4, t003b_fields
};
static const char *t003c_2_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t003c_2_DH_ll = 2;
static ldh_radix t003c_2_DH = { "H", 1, &t003c_2_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003c_2_DSA_ll = 3;
static ldh_radix t003c_2_DSA = { "SA", 2, &t003c_2_DSA_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003c_2_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t003c_2_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t003c_2_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t003c_2_ECC_ll = 4;
static ldh_radix t003c_2_ECC = { "ECC", 3, &t003c_2_ECC_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003c_2_INDIRECT_ll = 252;
static ldh_radix t003c_2_INDIRECT = { "INDIRECT", 8, &t003c_2_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003c_2_PRIVATEDNS_ll = 253;
static ldh_radix t003c_2_PRIVATEDNS = { "DNS", 3, &t003c_2_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003c_2_PRIVATEOID_ll = 254;
static ldh_radix t003c_2_PRIVATEOID = { "OID", 3, &t003c_2_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003c_2_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t003c_2_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t003c_2_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t003c_2_RSAMD5_ll = 1;
static ldh_radix t003c_2_RSAMD5 = { "MD5", 3, &t003c_2_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t003c_2_RSASHA1_ll = 5;
static ldh_radix t003c_2_RSASHA1 = { "SHA1", 4, &t003c_2_RSASHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t003c_2_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t003c_2_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t003c_2_RSASHA1,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t003c_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t003c_2_D,&t003c_2_ECC, NULL, NULL, NULL,&t003c_2_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t003c_2_PRIVATE, NULL,
	 &t003c_2_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t003c_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_I1, 0, { NULL }, NULL, "protocol"
	, "Protocol (must be 3)" },
	{ del_ftype_I1, 0
	, { (void *)t003c_2_xx }, &t003c_2_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_B64, 0, { NULL }, NULL, "publickey"
	, "Public key" }
};
static const dnsextlang_stanza t003c = {
	"CDNSKEY", 60, (del_option_A),
	"DNSKEY(s) the Child wants reflected in DS [RFC7344]",
	4, t003c_fields
};
static dnsextlang_field t003d_fields[1] = {
	{ del_ftype_B64, 0, { NULL }, NULL, "key"
	, "PGP key" }
};
static const dnsextlang_stanza t003d = {
	"OPENPGPKEY", 61, (del_option_A),
	"OpenPGP Key [RFC7929]",
	1, t003d_fields
};
static dnsextlang_field t003e_fields[3] = {
	{ del_ftype_I4, 0, { NULL }, NULL, "serial"
	, "SOA serial" },
	{ del_ftype_I2, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_R, (del_qual_L), { NULL }, NULL, "Types", NULL }
};
static const dnsextlang_stanza t003e = {
	"CSYNC", 62, (del_option_A),
	"Child-To-Parent Synchronization [RFC7477]",
	3, t003e_fields
};
static const char *t003f_1_xx[256] = {
	  NULL, "SHA384", NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL};
static const long long int t003f_1_SHA384_ll = 1;
static ldh_radix t003f_1_SHA384 = { "SHA384", 6, &t003f_1_SHA384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static dnsextlang_field t003f_fields[4] = {
	{ del_ftype_I4, 0, { NULL }, NULL, "serial"
	, "SOA serial" },
	{ del_ftype_I1, 0
	, { (void *)t003f_1_xx }, &t003f_1_SHA384, "digtype"
	, "Digest type" },
	{ del_ftype_I1, 0, { NULL }, NULL, "reserved"
	, "Reserved" },
	{ del_ftype_X, 0, { NULL }, NULL, "digest"
	, "Digest" }
};
static const dnsextlang_stanza t003f = {
	"ZONEMD", 63, (del_option_A),
	"Message Digest for DNS Zones [draft-wessels-dns-zone-digest]",
	4, t003f_fields
};
static dnsextlang_field t0063_fields[1] = {
	{ del_ftype_S, (del_qual_M), { NULL }, NULL, "text"
	, "SPF data" }
};
static const dnsextlang_stanza t0063 = {
	"SPF", 99, (del_option_A|del_option_O),
	"[RFC7208]",
	1, t0063_fields
};
static const dnsextlang_stanza t0064 = {
	"UINFO", 100, (del_option_R),
	"[IANA-Reserved]",
	0, NULL
};
static const dnsextlang_stanza t0065 = {
	"UID", 101, (del_option_R),
	"[IANA-Reserved]",
	0, NULL
};
static const dnsextlang_stanza t0066 = {
	"GID", 102, (del_option_R),
	"[IANA-Reserved]",
	0, NULL
};
static const dnsextlang_stanza t0067 = {
	"UNSPEC", 103, (del_option_R),
	"[IANA-Reserved]",
	0, NULL
};
static dnsextlang_field t0068_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "preference"
	, "Preference" },
	{ del_ftype_AA, 0, { NULL }, NULL, "nodeid"
	, "Node ID" }
};
static const dnsextlang_stanza t0068 = {
	"NID", 104, (del_option_A),
	"[RFC6742]",
	2, t0068_fields
};
static dnsextlang_field t0069_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "preference"
	, "Preference" },
	{ del_ftype_A, 0, { NULL }, NULL, "locator"
	, "Locator32" }
};
static const dnsextlang_stanza t0069 = {
	"L32", 105, (del_option_A),
	"[RFC6742]",
	2, t0069_fields
};
static dnsextlang_field t006a_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "preference"
	, "Preference" },
	{ del_ftype_AA, 0, { NULL }, NULL, "locator"
	, "Locator64" }
};
static const dnsextlang_stanza t006a = {
	"L64", 106, (del_option_A),
	"[RFC6742]",
	2, t006a_fields
};
static dnsextlang_field t006b_fields[2] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "preference"
	, "Preference" },
	{ del_ftype_N, 0, { NULL }, NULL, "pointer"
	, "Pointer" }
};
static const dnsextlang_stanza t006b = {
	"LP", 107, (del_option_A),
	"[RFC6742]",
	2, t006b_fields
};
static dnsextlang_field t006c_fields[1] = {
	{ del_ftype_EUI48, 0, { NULL }, NULL, "address"
	, "Address (digit pairs separated by hyphens)" }
};
static const dnsextlang_stanza t006c = {
	"EUI48", 108, (del_option_A),
	"an EUI-48 address [RFC7043]",
	1, t006c_fields
};
static dnsextlang_field t006d_fields[1] = {
	{ del_ftype_EUI64, 0, { NULL }, NULL, "address"
	, "Address (digit pairs separated by hyphens)" }
};
static const dnsextlang_stanza t006d = {
	"EUI64", 109, (del_option_A),
	"an EUI-64 address [RFC7043]",
	1, t006d_fields
};
static const dnsextlang_stanza t00f9 = {
	"TKEY", 249, (del_option_W),
	"Transaction Key [RFC2930]",
	0, NULL
};
static const dnsextlang_stanza t00fa = {
	"TSIG", 250, (del_option_W),
	"Transaction Signature [RFC2845]",
	0, NULL
};
static const dnsextlang_stanza t00fb = {
	"IXFR", 251, (del_option_Q),
	"Incremental transfer [RFC1995]",
	0, NULL
};
static const dnsextlang_stanza t00fc = {
	"AXFR", 252, (del_option_Q),
	"Transfer of an entrire zone [RFC1035][RFC5936]",
	0, NULL
};
static const dnsextlang_stanza t00fd = {
	"MAILB", 253, (del_option_E|del_option_Q),
	"Mailbox-related RRs (MB, MG or MR) [RFC1035]",
	0, NULL
};
static const dnsextlang_stanza t00fe = {
	"MAILA", 254, (del_option_O|del_option_Q),
	"Mail agent RRs (OBSOLETE - see MX) [RFC1035]",
	0, NULL
};
static const dnsextlang_stanza t00ff = {
	"ANY", 255, (del_option_Q),
	"Some or all records the server has available",
	0, NULL
};
static const dnsextlang_stanza *t00xx[256] = {
	  NULL ,&t0001,&t0002,&t0003,&t0004,&t0005,&t0006,&t0007,&t0008,&t0009
	,&t000a,&t000b,&t000c,&t000d,&t000e,&t000f,&t0010,&t0011,&t0012,&t0013
	,&t0014,&t0015,&t0016,&t0017,&t0018,&t0019,&t001a,&t001b,&t001c,&t001d
	,&t001e,&t001f,&t0020,&t0021,&t0022,&t0023,&t0024,&t0025,&t0026,&t0027
	,&t0028,&t0029,&t002a,&t002b,&t002c,&t002d,&t002e,&t002f,&t0030,&t0031
	,&t0032,&t0033,&t0034,&t0035, NULL ,&t0037,&t0038,&t0039,&t003a,&t003b
	,&t003c,&t003d,&t003e,&t003f, NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL ,&t0063
	,&t0064,&t0065,&t0066,&t0067,&t0068,&t0069,&t006a,&t006b,&t006c,&t006d
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL ,&t00f9
	,&t00fa,&t00fb,&t00fc,&t00fd,&t00fe,&t00ff};
static dnsextlang_field t0100_fields[3] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "priority"
	, "Priority" },
	{ del_ftype_I2, 0, { NULL }, NULL, "weight"
	, "Weight" },
	{ del_ftype_S, (del_qual_X), { NULL }, NULL, "target"
	, "Target" }
};
static const dnsextlang_stanza t0100 = {
	"URI", 256, (del_option_A),
	"URI [RFC7553]",
	3, t0100_fields
};
static dnsextlang_field t0101_fields[3] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "flags"
	, "Flags" },
	{ del_ftype_S, 0, { NULL }, NULL, "tag"
	, "Tag" },
	{ del_ftype_S, (del_qual_X), { NULL }, NULL, "value"
	, "Value" }
};
static const dnsextlang_stanza t0101 = {
	"CAA", 257, (del_option_A),
	"Certification Authority Restriction [RFC6844]",
	3, t0101_fields
};
static dnsextlang_field t0102_fields[1] = {
	{ del_ftype_S, 0, { NULL }, NULL, "meta_data"
	, "Meta data" }
};
static const dnsextlang_stanza t0102 = {
	"AVC", 258, (del_option_P),
	"Application Visibility and Control",
	1, t0102_fields
};
static dnsextlang_field t0103_fields[5] = {
	{ del_ftype_I4, 0, { NULL }, NULL, "enterprise"
	, "Enterprise" },
	{ del_ftype_I4, 0, { NULL }, NULL, "type"
	, "Type" },
	{ del_ftype_I1, 0, { NULL }, NULL, "location"
	, "Location" },
	{ del_ftype_S, 0, { NULL }, NULL, "media_type"
	, "Media type" },
	{ del_ftype_B64, 0, { NULL }, NULL, "data"
	, "Data" }
};
static const dnsextlang_stanza t0103 = {
	"DOA", 259, (del_option_D),
	"Digital Object Architecture [draft-durand-doa-over-dns]",
	5, t0103_fields
};
static dnsextlang_field t0104_fields[4] = {
	{ del_ftype_I1, 0, { NULL }, NULL, "precedence"
	, "Precedence" },
	{ del_ftype_I1, 0, { NULL }, NULL, "relay_type"
	, "Relay type" },
	{ del_ftype_I1, 0, { NULL }, NULL, "discobery_optional"
	, "Discovery Optional" },
	{ del_ftype_Z, (del_qual_IPSECKEY), { NULL }, NULL, "relay"
	, "Relay" }
};
static const dnsextlang_stanza t0104 = {
	"AMTRELAY", 260, (del_option_D),
	"Automatic Multicast Tunneling Relay [draft-ietf-mboned-driad-amt-discovery]",
	4, t0104_fields
};
static const dnsextlang_stanza *t01xx[256] = {
	 &t0100,&t0101,&t0102,&t0103,&t0104, NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL };
static const char *t8000_1_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", "DSA-NSEC-SHA1",
	 "RSASHA1-NSEC3-SHA1", "RSASHA256", NULL, "RSASHA512", NULL,
	 "ECC-GOST", "ECDSAP256SHA256", "ECDSAP384SHA384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t8000_1_DH_ll = 2;
static ldh_radix t8000_1_DH = { "H", 1, &t8000_1_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_DSA_NSEC_SHA1_ll = 6;
static ldh_radix t8000_1_DSA_NSEC_SHA1 = { "-NSEC-SHA1", 10, &t8000_1_DSA_NSEC_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_DSA_ll = 3;
static ldh_radix t8000_1_DSA = { "SA", 2, &t8000_1_DSA_ll,
	{&t8000_1_DSA_NSEC_SHA1, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8000_1_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t8000_1_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t8000_1_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t8000_1_ECC_GOST_ll = 12;
static ldh_radix t8000_1_ECC_GOST = { "-GOST", 5, &t8000_1_ECC_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_ECC_ll = 4;
static ldh_radix t8000_1_ECC = { "C", 1, &t8000_1_ECC_ll,
	{&t8000_1_ECC_GOST, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t8000_1_ECDSAP256SHA256_ll = 13;
static ldh_radix t8000_1_ECDSAP256SHA256 = { "256SHA256", 9, &t8000_1_ECDSAP256SHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_ECDSAP384SHA384_ll = 14;
static ldh_radix t8000_1_ECDSAP384SHA384 = { "384SHA384", 9, &t8000_1_ECDSAP384SHA384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8000_1_ECDSAP = { "DSAP", 4, NULL,
	{ NULL, NULL, NULL, NULL, NULL,&t8000_1_ECDSAP256SHA256,
	 &t8000_1_ECDSAP384SHA384, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8000_1_EC = { "EC", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t8000_1_ECC,&t8000_1_ECDSAP, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static const long long int t8000_1_INDIRECT_ll = 252;
static ldh_radix t8000_1_INDIRECT = { "INDIRECT", 8, &t8000_1_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_PRIVATEDNS_ll = 253;
static ldh_radix t8000_1_PRIVATEDNS = { "DNS", 3, &t8000_1_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_PRIVATEOID_ll = 254;
static ldh_radix t8000_1_PRIVATEOID = { "OID", 3, &t8000_1_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8000_1_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t8000_1_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t8000_1_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t8000_1_RSAMD5_ll = 1;
static ldh_radix t8000_1_RSAMD5 = { "MD5", 3, &t8000_1_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_RSASHA1_NSEC3_SHA1_ll = 7;
static ldh_radix t8000_1_RSASHA1_NSEC3_SHA1 = { "-NSEC3-SHA1", 11, &t8000_1_RSASHA1_NSEC3_SHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_RSASHA1_ll = 5;
static ldh_radix t8000_1_RSASHA1 = { "1", 1, &t8000_1_RSASHA1_ll,
	{&t8000_1_RSASHA1_NSEC3_SHA1, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t8000_1_RSASHA256_ll = 8;
static ldh_radix t8000_1_RSASHA256 = { "256", 3, &t8000_1_RSASHA256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_1_RSASHA512_ll = 10;
static ldh_radix t8000_1_RSASHA512 = { "512", 3, &t8000_1_RSASHA512_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8000_1_RSASHA = { "SHA", 3, NULL,
	{ NULL, NULL, NULL, NULL,&t8000_1_RSASHA1,&t8000_1_RSASHA256, NULL,
	  NULL,&t8000_1_RSASHA512, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8000_1_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t8000_1_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t8000_1_RSASHA,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8000_1_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t8000_1_D,&t8000_1_EC, NULL, NULL, NULL,&t8000_1_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t8000_1_PRIVATE, NULL,
	 &t8000_1_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const char *t8000_2_xx[256] = {
	  NULL, "SHA-1", "SHA-256", "GOST", "SHA-384", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL};
static const long long int t8000_2_GOST_ll = 3;
static ldh_radix t8000_2_GOST = { "GOST", 4, &t8000_2_GOST_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_2_SHA_1_ll = 1;
static ldh_radix t8000_2_SHA_1 = { "1", 1, &t8000_2_SHA_1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_2_SHA_256_ll = 2;
static ldh_radix t8000_2_SHA_256 = { "256", 3, &t8000_2_SHA_256_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8000_2_SHA_384_ll = 4;
static ldh_radix t8000_2_SHA_384 = { "384", 3, &t8000_2_SHA_384_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8000_2_SHA_ = { "SHA-", 4, NULL,
	{ NULL, NULL, NULL, NULL,&t8000_2_SHA_1,&t8000_2_SHA_256,
	 &t8000_2_SHA_384, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8000_2_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t8000_2_GOST, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL,&t8000_2_SHA_, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t8000_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "keytag"
	, "Key tag" },
	{ del_ftype_I1, 0
	, { (void *)t8000_1_xx }, &t8000_1_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0
	, { (void *)t8000_2_xx }, &t8000_2_ldh_radix, "digtype"
	, "Digest type" },
	{ del_ftype_X, 0, { NULL }, NULL, "digest"
	, "Digest" }
};
static const dnsextlang_stanza t8000 = {
	"TA", 32768, (del_option_P),
	"DNSSEC Trust Authorities",
	4, t8000_fields
};
static const char *t8001_1_xx[256] = {
	  NULL, "RSAMD5", "DH", "DSA", "ECC", "RSASHA1", NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, "INDIRECT", "PRIVATEDNS", "PRIVATEOID", NULL};
static const long long int t8001_1_DH_ll = 2;
static ldh_radix t8001_1_DH = { "H", 1, &t8001_1_DH_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8001_1_DSA_ll = 3;
static ldh_radix t8001_1_DSA = { "SA", 2, &t8001_1_DSA_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8001_1_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&t8001_1_DH, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t8001_1_DSA, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static const long long int t8001_1_ECC_ll = 4;
static ldh_radix t8001_1_ECC = { "ECC", 3, &t8001_1_ECC_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8001_1_INDIRECT_ll = 252;
static ldh_radix t8001_1_INDIRECT = { "INDIRECT", 8, &t8001_1_INDIRECT_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8001_1_PRIVATEDNS_ll = 253;
static ldh_radix t8001_1_PRIVATEDNS = { "DNS", 3, &t8001_1_PRIVATEDNS_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8001_1_PRIVATEOID_ll = 254;
static ldh_radix t8001_1_PRIVATEOID = { "OID", 3, &t8001_1_PRIVATEOID_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8001_1_PRIVATE = { "PRIVATE", 7, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t8001_1_PRIVATEDNS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&t8001_1_PRIVATEOID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static const long long int t8001_1_RSAMD5_ll = 1;
static ldh_radix t8001_1_RSAMD5 = { "MD5", 3, &t8001_1_RSAMD5_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static const long long int t8001_1_RSASHA1_ll = 5;
static ldh_radix t8001_1_RSASHA1 = { "SHA1", 4, &t8001_1_RSASHA1_ll,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix t8001_1_RSA = { "RSA", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &t8001_1_RSAMD5, NULL, NULL, NULL, NULL, NULL,&t8001_1_RSASHA1,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix t8001_1_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&t8001_1_D,&t8001_1_ECC, NULL, NULL, NULL,&t8001_1_INDIRECT,
	  NULL, NULL, NULL, NULL, NULL, NULL,&t8001_1_PRIVATE, NULL,
	 &t8001_1_RSA, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL } };
static dnsextlang_field t8001_fields[4] = {
	{ del_ftype_I2, 0, { NULL }, NULL, "key"
	, "Key tag" },
	{ del_ftype_I1, 0
	, { (void *)t8001_1_xx }, &t8001_1_ldh_radix, "algorithm"
	, "Algorithm" },
	{ del_ftype_I1, 0, { NULL }, NULL, "type"
	, "Digest type" },
	{ del_ftype_X, 0, { NULL }, NULL, "digest"
	, "Digest" }
};
static const dnsextlang_stanza t8001 = {
	"DLV", 32769, (del_option_A),
	"DNSSEC Lookaside Validation [RFC4431]",
	4, t8001_fields
};
static const dnsextlang_stanza *t80xx[256] = {
	 &t8000,&t8001, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL };
static const dnsextlang_stanza **rrtypes_table[256] = {
	  t00xx, t01xx, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , t80xx, NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL , NULL 
	, NULL , NULL , NULL , NULL , NULL , NULL };
static ldh_radix rr_A6 = { "6", 1, &t0026,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_AAAA = { "AAA", 3, &t001c,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_AFSDB = { "FSDB", 4, &t0012,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_AMTRELAY = { "MTRELAY", 7, &t0104,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_ANY = { "NY", 2, &t00ff,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_APL = { "PL", 2, &t002a,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_ATMA = { "TMA", 3, &t0022,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_AVC = { "VC", 2, &t0102,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_AXFR = { "XFR", 3, &t00fc,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_A = { "A", 1, &t0001,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_A6, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_AAAA,
	  NULL, NULL, NULL, NULL,&rr_AFSDB, NULL, NULL, NULL, NULL, NULL,
	  NULL,&rr_AMTRELAY,&rr_ANY, NULL,&rr_APL, NULL, NULL, NULL,
	 &rr_ATMA, NULL,&rr_AVC, NULL,&rr_AXFR, NULL, NULL } };
static ldh_radix rr_CAA = { "AA", 2, &t0101,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_CDNSKEY = { "NSKEY", 5, &t003c,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_CDS = { "S", 1, &t003b,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_CD = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &rr_CDNSKEY, NULL, NULL, NULL, NULL,&rr_CDS, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_CERT = { "ERT", 3, &t0025,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_CNAME = { "NAME", 4, &t0005,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_CSYNC = { "SYNC", 4, &t003e,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_C = { "C", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_CAA,
	  NULL, NULL,&rr_CD,&rr_CERT, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_CNAME, NULL, NULL, NULL, NULL,&rr_CSYNC, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix rr_DHCID = { "HCID", 4, &t0031,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_DLV = { "LV", 2, &t8001,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_DNAME = { "AME", 3, &t0027,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_DNSKEY = { "SKEY", 4, &t0030,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_DN = { "N", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_DNAME,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_DNSKEY, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_DOA = { "OA", 2, &t0103,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_DS = { "S", 1, &t002b,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_D = { "D", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,&rr_DHCID, NULL, NULL, NULL,&rr_DLV,
	  NULL,&rr_DN,&rr_DOA, NULL, NULL, NULL,&rr_DS, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_EID = { "ID", 2, &t001f,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_EUI48 = { "48", 2, &t006c,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_EUI64 = { "64", 2, &t006d,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_EUI = { "UI", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_EUI48, NULL,
	 &rr_EUI64, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix rr_E = { "E", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_EID, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_EUI, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_GID = { "ID", 2, &t0066,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_GPOS = { "POS", 3, &t001b,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_G = { "G", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_GID, NULL, NULL, NULL,
	  NULL, NULL, NULL,&rr_GPOS, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_HINFO = { "NFO", 3, &t000d,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_HIP = { "P", 1, &t0037,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_HI = { "HI", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &rr_HINFO, NULL,&rr_HIP, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL } };
static ldh_radix rr_IPSECKEY = { "PSECKEY", 7, &t002d,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_ISDN = { "SDN", 3, &t0014,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_IXFR = { "XFR", 3, &t00fb,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_I = { "I", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_IPSECKEY, NULL, NULL,&rr_ISDN, NULL, NULL, NULL,
	  NULL,&rr_IXFR, NULL, NULL } };
static ldh_radix rr_KEY = { "EY", 2, &t0019,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_KX = { "X", 1, &t0024,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_K = { "K", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_KEY, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &rr_KX, NULL, NULL } };
static ldh_radix rr_L32 = { "32", 2, &t0069,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_L64 = { "64", 2, &t006a,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_LOC = { "OC", 2, &t001d,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_LP = { "P", 1, &t006b,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_L = { "L", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL,&rr_L32, NULL, NULL,&rr_L64,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_LOC,&rr_LP, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_MAILA = { "A", 1, &t00fe,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MAILB = { "B", 1, &t00fd,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MAIL = { "AIL", 3, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_MAILA,
	 &rr_MAILB, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_MB = { "B", 1, &t0007,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MD = { "D", 1, &t0003,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MF = { "F", 1, &t0004,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MG = { "G", 1, &t0008,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MINFO = { "INFO", 4, &t000e,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MR = { "R", 1, &t0009,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_MX = { "X", 1, &t000f,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_M = { "M", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_MAIL,
	 &rr_MB, NULL,&rr_MD, NULL,&rr_MF,&rr_MG, NULL,&rr_MINFO, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_MR, NULL, NULL, NULL,
	  NULL, NULL,&rr_MX, NULL, NULL } };
static ldh_radix rr_NAPTR = { "APTR", 4, &t0023,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NID = { "D", 1, &t0068,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NIMLOC = { "MLOC", 4, &t0020,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NINFO = { "NFO", 3, &t0038,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NI = { "I", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&rr_NID, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	 &rr_NIMLOC,&rr_NINFO, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix rr_NSAP_PTR = { "-PTR", 4, &t0017,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NSAP = { "AP", 2, &t0016,
	{&rr_NSAP_PTR, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL } };
static ldh_radix rr_NSEC3PARAM = { "PARAM", 5, &t0033,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NSEC3 = { "3", 1, &t0032,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_NSEC3PARAM, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_NSEC = { "EC", 2, &t002f,
	{ NULL, NULL, NULL, NULL, NULL, NULL,&rr_NSEC3, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL } };
static ldh_radix rr_NS = { "S", 1, &t0002,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_NSAP,
	  NULL, NULL, NULL,&rr_NSEC, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_NULL = { "ULL", 3, &t000a,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_NXT = { "XT", 2, &t001e,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_N = { "N", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_NAPTR,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_NI, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_NS, NULL,&rr_NULL, NULL,
	  NULL,&rr_NXT, NULL, NULL } };
static ldh_radix rr_OPENPGPKEY = { "ENPGPKEY", 8, &t003d,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_OPT = { "T", 1, &t0029,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_OP = { "OP", 2, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL,&rr_OPENPGPKEY, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_OPT, NULL,
	  NULL, NULL, NULL, NULL, NULL } };
static ldh_radix rr_PTR = { "TR", 2, &t000c,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_PX = { "X", 1, &t001a,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_P = { "P", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_PTR, NULL, NULL, NULL,
	 &rr_PX, NULL, NULL } };
static ldh_radix rr_RKEY = { "KEY", 3, &t0039,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_RP = { "P", 1, &t0011,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_RRSIG = { "RSIG", 4, &t002e,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_RT = { "T", 1, &t0015,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_R = { "R", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_RKEY, NULL,
	  NULL, NULL, NULL,&rr_RP, NULL,&rr_RRSIG, NULL,&rr_RT, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_SIG = { "G", 1, &t0018,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SINK = { "NK", 2, &t0028,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SI = { "I", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL,&rr_SIG, NULL, NULL, NULL, NULL, NULL,
	  NULL,&rr_SINK, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_SMIMEA = { "MIMEA", 5, &t0035,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SOA = { "OA", 2, &t0006,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SPF = { "PF", 2, &t0063,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SRV = { "RV", 2, &t0021,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_SSHFP = { "SHFP", 4, &t002c,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_S = { "S", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_SI, NULL, NULL, NULL,
	 &rr_SMIMEA, NULL,&rr_SOA,&rr_SPF, NULL,&rr_SRV,&rr_SSHFP, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL } };
static ldh_radix rr_TALINK = { "LINK", 4, &t003a,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_TA = { "A", 1, &t8000,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_TALINK,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL } };
static ldh_radix rr_TKEY = { "KEY", 3, &t00f9,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_TLSA = { "LSA", 3, &t0034,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_TSIG = { "SIG", 3, &t00fa,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_TXT = { "XT", 2, &t0010,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_T = { "T", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_TA, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_TKEY,&rr_TLSA,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_TSIG, NULL, NULL, NULL,
	  NULL,&rr_TXT, NULL, NULL } };
static ldh_radix rr_UID = { "D", 1, &t0065,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_UINFO = { "NFO", 3, &t0064,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_UI = { "I", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&rr_UID, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL,&rr_UINFO, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL } };
static ldh_radix rr_UNSPEC = { "NSPEC", 5, &t0067,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_URI = { "RI", 2, &t0100,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_U = { "U", 1, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL,&rr_UI, NULL, NULL, NULL, NULL,
	 &rr_UNSPEC, NULL, NULL, NULL,&rr_URI, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL } };
static ldh_radix rr_WKS = { "WKS", 3, &t000b,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_X25 = { "X25", 3, &t0013,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_ZONEMD = { "ZONEMD", 6, &t003f,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL } };
static ldh_radix rr_ldh_radix = { "", 0, NULL,
	{ NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,&rr_A, NULL,
	 &rr_C,&rr_D,&rr_E, NULL,&rr_G,&rr_HI,&rr_I, NULL,&rr_K,&rr_L,&rr_M,
	 &rr_N,&rr_OP,&rr_P, NULL,&rr_R,&rr_S,&rr_T,&rr_U, NULL,&rr_WKS,
	 &rr_X25, NULL,&rr_ZONEMD } };
static dnsextlang_def p_dns_default_rrtypes = {
	(void *)rrtypes_table, &rr_ldh_radix, NULL };
dnsextlang_def *dns_default_rrtypes = &p_dns_default_rrtypes;
 
static const dnsextlang_stanza *p_dnsextlang_lookup_(
    const char *s, size_t len)
{
	switch (len) {
	case  2: switch (s[0]) {
	         case 'N': 
	         case 'n': switch (s[1]) {
	                   case 'S': 
	                   case 's': return &t0002;
	                   };
	                   break;
	         case 'D': 
	         case 'd': switch (s[1]) {
	                   case 'S': 
	                   case 's': return &t002b;
	                   };
	                   break;
	         case 'M': 
	         case 'm': switch (s[1]) {
	                   case 'X': 
	                   case 'x': return &t000f;
	                   case 'R': 
	                   case 'r': return &t0009;
	                   case 'G': 
	                   case 'g': return &t0008;
	                   case 'B': 
	                   case 'b': return &t0007;
	                   case 'F': 
	                   case 'f': return &t0004;
	                   case 'D': 
	                   case 'd': return &t0003;
	                   };
	                   break;
	         case 'A': 
	         case 'a': switch (s[1]) {
	                   case '6': return &t0026;
	                   };
	                   break;
	         case 'L': 
	         case 'l': switch (s[1]) {
	                   case 'P': 
	                   case 'p': return &t006b;
	                   };
	                   break;
	         case 'K': 
	         case 'k': switch (s[1]) {
	                   case 'X': 
	                   case 'x': return &t0024;
	                   };
	                   break;
	         case 'P': 
	         case 'p': switch (s[1]) {
	                   case 'X': 
	                   case 'x': return &t001a;
	                   };
	                   break;
	         case 'R': 
	         case 'r': switch (s[1]) {
	                   case 'T': 
	                   case 't': return &t0015;
	                   case 'P': 
	                   case 'p': return &t0011;
	                   };
	                   break;
	         case 'T': 
	         case 't': switch (s[1]) {
	                   case 'A': 
	                   case 'a': return &t8000;
	                   };
	                   break;
	         };
	         break;
	case  1: switch (s[0]) {
	         case 'A': 
	         case 'a': return &t0001;
	         };
	         break;
	case  4: switch (s[0]) {
	         case 'A': 
	         case 'a': switch (s[1]) {
	                   case 'A': 
	                   case 'a': if (strncasecmp(s + 2, "AA", 2)) break;
	                             return &t001c;
	                   case 'T': 
	                   case 't': if (strncasecmp(s + 2, "MA", 2)) break;
	                             return &t0022;
	                   case 'X': 
	                   case 'x': if (strncasecmp(s + 2, "FR", 2)) break;
	                             return &t00fc;
	                   };
	                   break;
	         case 'N': 
	         case 'n': switch (s[1]) {
	                   case 'S': 
	                   case 's': switch (s[2]) {
	                             case 'E': 
	                             case 'e': switch (s[3]) {
	                                       case 'C': 
	                                       case 'c': return &t002f;
	                                       };
	                                       break;
	                             case 'A': 
	                             case 'a': switch (s[3]) {
	                                       case 'P': 
	                                       case 'p': return &t0016;
	                                       };
	                                       break;
	                             };
	                             break;
	                   case 'U': 
	                   case 'u': if (strncasecmp(s + 2, "LL", 2)) break;
	                             return &t000a;
	                   };
	                   break;
	         case 'C': 
	         case 'c': if (strncasecmp(s + 1, "ERT", 3)) break;
	                   return &t0025;
	         case 'T': 
	         case 't': switch (s[1]) {
	                   case 'L': 
	                   case 'l': if (strncasecmp(s + 2, "SA", 2)) break;
	                             return &t0034;
	                   case 'K': 
	                   case 'k': if (strncasecmp(s + 2, "EY", 2)) break;
	                             return &t00f9;
	                   case 'S': 
	                   case 's': if (strncasecmp(s + 2, "IG", 2)) break;
	                             return &t00fa;
	                   };
	                   break;
	         case 'G': 
	         case 'g': if (strncasecmp(s + 1, "POS", 3)) break;
	                   return &t001b;
	         case 'I': 
	         case 'i': switch (s[1]) {
	                   case 'S': 
	                   case 's': if (strncasecmp(s + 2, "DN", 2)) break;
	                             return &t0014;
	                   case 'X': 
	                   case 'x': if (strncasecmp(s + 2, "FR", 2)) break;
	                             return &t00fb;
	                   };
	                   break;
	         case 'S': 
	         case 's': if (strncasecmp(s + 1, "INK", 3)) break;
	                   return &t0028;
	         case 'R': 
	         case 'r': if (strncasecmp(s + 1, "KEY", 3)) break;
	                   return &t0039;
	         };
	         break;
	case  3: switch (s[0]) {
	         case 'P': 
	         case 'p': if (strncasecmp(s + 1, "TR", 2)) break;
	                   return &t000c;
	         case 'T': 
	         case 't': if (strncasecmp(s + 1, "XT", 2)) break;
	                   return &t0010;
	         case 'S': 
	         case 's': switch (s[1]) {
	                   case 'R': 
	                   case 'r': switch (s[2]) {
	                             case 'V': 
	                             case 'v': return &t0021;
	                             };
	                             break;
	                   case 'O': 
	                   case 'o': switch (s[2]) {
	                             case 'A': 
	                             case 'a': return &t0006;
	                             };
	                             break;
	                   case 'P': 
	                   case 'p': switch (s[2]) {
	                             case 'F': 
	                             case 'f': return &t0063;
	                             };
	                             break;
	                   case 'I': 
	                   case 'i': switch (s[2]) {
	                             case 'G': 
	                             case 'g': return &t0018;
	                             };
	                             break;
	                   };
	                   break;
	         case 'C': 
	         case 'c': switch (s[1]) {
	                   case 'A': 
	                   case 'a': switch (s[2]) {
	                             case 'A': 
	                             case 'a': return &t0101;
	                             };
	                             break;
	                   case 'D': 
	                   case 'd': switch (s[2]) {
	                             case 'S': 
	                             case 's': return &t003b;
	                             };
	                             break;
	                   };
	                   break;
	         case 'U': 
	         case 'u': switch (s[1]) {
	                   case 'R': 
	                   case 'r': switch (s[2]) {
	                             case 'I': 
	                             case 'i': return &t0100;
	                             };
	                             break;
	                   case 'I': 
	                   case 'i': switch (s[2]) {
	                             case 'D': 
	                             case 'd': return &t0065;
	                             };
	                             break;
	                   };
	                   break;
	         case 'L': 
	         case 'l': switch (s[1]) {
	                   case '6': switch (s[2]) {
	                             case '4': return &t006a;
	                             };
	                             break;
	                   case '3': switch (s[2]) {
	                             case '2': return &t0069;
	                             };
	                             break;
	                   case 'O': 
	                   case 'o': switch (s[2]) {
	                             case 'C': 
	                             case 'c': return &t001d;
	                             };
	                             break;
	                   };
	                   break;
	         case 'N': 
	         case 'n': switch (s[1]) {
	                   case 'I': 
	                   case 'i': switch (s[2]) {
	                             case 'D': 
	                             case 'd': return &t0068;
	                             };
	                             break;
	                   case 'X': 
	                   case 'x': switch (s[2]) {
	                             case 'T': 
	                             case 't': return &t001e;
	                             };
	                             break;
	                   };
	                   break;
	         case 'D': 
	         case 'd': switch (s[1]) {
	                   case 'L': 
	                   case 'l': switch (s[2]) {
	                             case 'V': 
	                             case 'v': return &t8001;
	                             };
	                             break;
	                   case 'O': 
	                   case 'o': switch (s[2]) {
	                             case 'A': 
	                             case 'a': return &t0103;
	                             };
	                             break;
	                   };
	                   break;
	         case 'H': 
	         case 'h': if (strncasecmp(s + 1, "IP", 2)) break;
	                   return &t0037;
	         case 'A': 
	         case 'a': switch (s[1]) {
	                   case 'P': 
	                   case 'p': switch (s[2]) {
	                             case 'L': 
	                             case 'l': return &t002a;
	                             };
	                             break;
	                   case 'V': 
	                   case 'v': switch (s[2]) {
	                             case 'C': 
	                             case 'c': return &t0102;
	                             };
	                             break;
	                   case 'N': 
	                   case 'n': switch (s[2]) {
	                             case 'Y': 
	                             case 'y': return &t00ff;
	                             };
	                             break;
	                   };
	                   break;
	         case 'K': 
	         case 'k': if (strncasecmp(s + 1, "EY", 2)) break;
	                   return &t0019;
	         case 'X': 
	         case 'x': if (strncasecmp(s + 1, "25", 2)) break;
	                   return &t0013;
	         case 'W': 
	         case 'w': if (strncasecmp(s + 1, "KS", 2)) break;
	                   return &t000b;
	         case 'G': 
	         case 'g': if (strncasecmp(s + 1, "ID", 2)) break;
	                   return &t0066;
	         case 'O': 
	         case 'o': if (strncasecmp(s + 1, "PT", 2)) break;
	                   return &t0029;
	         case 'E': 
	         case 'e': if (strncasecmp(s + 1, "ID", 2)) break;
	                   return &t001f;
	         };
	         break;
	case  5: switch (s[0]) {
	         case 'C': 
	         case 'c': switch (s[1]) {
	                   case 'N': 
	                   case 'n': if (strncasecmp(s + 2, "AME", 3)) break;
	                             return &t0005;
	                   case 'S': 
	                   case 's': if (strncasecmp(s + 2, "YNC", 3)) break;
	                             return &t003e;
	                   };
	                   break;
	         case 'R': 
	         case 'r': if (strncasecmp(s + 1, "RSIG", 4)) break;
	                   return &t002e;
	         case 'N': 
	         case 'n': switch (s[1]) {
	                   case 'S': 
	                   case 's': if (strncasecmp(s + 2, "EC3", 3)) break;
	                             return &t0032;
	                   case 'A': 
	                   case 'a': if (strncasecmp(s + 2, "PTR", 3)) break;
	                             return &t0023;
	                   case 'I': 
	                   case 'i': if (strncasecmp(s + 2, "NFO", 3)) break;
	                             return &t0038;
	                   };
	                   break;
	         case 'D': 
	         case 'd': switch (s[1]) {
	                   case 'N': 
	                   case 'n': if (strncasecmp(s + 2, "AME", 3)) break;
	                             return &t0027;
	                   case 'H': 
	                   case 'h': if (strncasecmp(s + 2, "CID", 3)) break;
	                             return &t0031;
	                   };
	                   break;
	         case 'E': 
	         case 'e': switch (s[1]) {
	                   case 'U': 
	                   case 'u': switch (s[2]) {
	                             case 'I': 
	                             case 'i': switch (s[3]) {
	                                       case '6': switch (s[4]) {
	                                                 case '4': return &t006d;
	                                                 };
	                                                 break;
	                                       case '4': switch (s[4]) {
	                                                 case '8': return &t006c;
	                                                 };
	                                                 break;
	                                       };
	                                       break;
	                             };
	                             break;
	                   };
	                   break;
	         case 'S': 
	         case 's': if (strncasecmp(s + 1, "SHFP", 4)) break;
	                   return &t002c;
	         case 'A': 
	         case 'a': if (strncasecmp(s + 1, "FSDB", 4)) break;
	                   return &t0012;
	         case 'M': 
	         case 'm': switch (s[1]) {
	                   case 'I': 
	                   case 'i': if (strncasecmp(s + 2, "NFO", 3)) break;
	                             return &t000e;
	                   case 'A': 
	                   case 'a': switch (s[2]) {
	                             case 'I': 
	                             case 'i': switch (s[3]) {
	                                       case 'L': 
	                                       case 'l': switch (s[4]) {
	                                                 case 'A': 
	                                                 case 'a': return &t00fe;
	                                                 case 'B': 
	                                                 case 'b': return &t00fd;
	                                                 };
	                                                 break;
	                                       };
	                                       break;
	                             };
	                             break;
	                   };
	                   break;
	         case 'U': 
	         case 'u': if (strncasecmp(s + 1, "INFO", 4)) break;
	                   return &t0064;
	         case 'H': 
	         case 'h': if (strncasecmp(s + 1, "INFO", 4)) break;
	                   return &t000d;
	         };
	         break;
	case  6: switch (s[0]) {
	         case 'D': 
	         case 'd': if (strncasecmp(s + 1, "NSKEY", 5)) break;
	                   return &t0030;
	         case 'Z': 
	         case 'z': if (strncasecmp(s + 1, "ONEMD", 5)) break;
	                   return &t003f;
	         case 'S': 
	         case 's': if (strncasecmp(s + 1, "MIMEA", 5)) break;
	                   return &t0035;
	         case 'U': 
	         case 'u': if (strncasecmp(s + 1, "NSPEC", 5)) break;
	                   return &t0067;
	         case 'T': 
	         case 't': if (strncasecmp(s + 1, "ALINK", 5)) break;
	                   return &t003a;
	         case 'N': 
	         case 'n': if (strncasecmp(s + 1, "IMLOC", 5)) break;
	                   return &t0020;
	         };
	         break;
	case  7: if (strncasecmp(s, "CDNSKEY", 7)) break;
	         return &t003c;
	case  8: switch (s[0]) {
	         case 'I': 
	         case 'i': if (strncasecmp(s + 1, "PSECKEY", 7)) break;
	                   return &t002d;
	         case 'N': 
	         case 'n': if (strncasecmp(s + 1, "SAP-PTR", 7)) break;
	                   return &t0017;
	         case 'A': 
	         case 'a': if (strncasecmp(s + 1, "MTRELAY", 7)) break;
	                   return &t0104;
	         };
	         break;
	case 10: switch (s[0]) {
	         case 'N': 
	         case 'n': if (strncasecmp(s + 1, "SEC3PARAM", 9)) break;
	                   return &t0033;
	         case 'O': 
	         case 'o': if (strncasecmp(s + 1, "PENPGPKEY", 9)) break;
	                   return &t003d;
	         };
	         break;
	};
	return NULL;
	
}

const dnsextlang_stanza *dnsextlang_lookup_(
    const char *s, size_t len, return_status *st)
{
	const dnsextlang_stanza *r;
	int t;
	
	if ((r = p_dnsextlang_lookup_(s, len)))
		return r;

	if ((t = dnsextlang_get_TYPE_rrtype(s, len, st)) < 0)
		return NULL;
	
	if ((r = dnsextlang_get_stanza_(dns_default_rrtypes, t)))
		return r;
	
	(void) RETURN_NOT_FOUND_ERR(st, "rrtype not found");
	return NULL;
}

int dnsextlang_get_type_(const char *s, size_t len, return_status *st)
{
	const dnsextlang_stanza *r;

	if ((r = p_dnsextlang_lookup_(s, len)))
		return r->number;

	return dnsextlang_get_TYPE_rrtype(s, len, st);
}

