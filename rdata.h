/*
 * rdata.h -- RDATA conversion functions.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef RDATA_H
#define RDATA_H

#include "dns.h"
#include "namedb.h"

/* High bit of the APL length field is the negation bit.  */
#define APL_NEGATION_MASK      0x80U
#define APL_LENGTH_MASK	       (~APL_NEGATION_MASK)

extern lookup_table_type dns_certificate_types[];
extern lookup_table_type dns_algorithms[];

/*
 * Function signature for svcparam print. Input offset is at key uint16_t
 * in rdata.
 * @param output: the string is printed to the buffer.
 * @param svcparamkey: the key that is printed.
 * @param data: the data for the svcparam, from rdata.
 * @param datalen: length of data in bytes.
 * @return false on failure.
 */
typedef int(*nsd_print_svcparam_rdata_t)(
	struct buffer* output,
	uint16_t svcparamkey,
	const uint8_t* data,
	uint16_t datalen);

typedef struct nsd_svcparam_descriptor nsd_svcparam_descriptor_t;

/* Descriptor for svcparam rdata fields. With type, name and print func. */
struct nsd_svcparam_descriptor {
	/* The svc param key */
	uint16_t key;
	/* The name of the key */
	const char *name;
	/* Print function that prints the key, from rdata. */
	nsd_print_svcparam_rdata_t print_rdata;
};

int print_unknown_rdata(
	buffer_type *output, nsd_type_descriptor_t *descriptor, const rr_type *rr);

/* print rdata to a text string (as for a zone file) returns 0
  on a failure (bufpos is reset to original position).
  returns 1 on success, bufpos is moved. */
int print_rdata(
	buffer_type *output, nsd_type_descriptor_t *descriptor, const rr_type *rr);

/* Determine length of IPSECKEY gateway field. */
int32_t gateway_length(uint16_t rdlength, const uint8_t *rdata,
	uint16_t offset);

/* Read rdata for an unknown RR type. */
int32_t read_generic_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for an unknown RR type. */
void write_generic_rdata(struct query *query, const struct rr *rr);

/* Print rdata for an unknown RR type. */
int print_generic_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for an RR type with one compressed dname. */
int32_t read_compressed_name_rdata(struct domain_table *domains,
	uint16_t rdlength, struct buffer *packet, struct rr **rr);

/* Write rdata for an RR type with one compressed dname. */
void write_compressed_name_rdata(struct query *query, const struct rr *rr);

/* Print rdata for an RR type with one compressed or uncompressed dname.
 * But not a dname type literal. */
int print_name_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for an RR type with one uncompressed dname. */
int32_t read_uncompressed_name_rdata(struct domain_table *domains,
	uint16_t rdlength, struct buffer *packet, struct rr **rr);

/* Write rdata for an RR type with one uncompressed dname. */
void write_uncompressed_name_rdata(struct query *query, const struct rr *rr);

/* Read rdata for type A. */
int32_t read_a_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type A. */
int print_a_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type SOA. */
int32_t read_soa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type SOA. */
void write_soa_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type SOA. */
int print_soa_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type WKS. */
int32_t read_wks_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type WKS. */
int print_wks_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type HINFO. */
int32_t read_hinfo_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type HINFO. */
int print_hinfo_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type MINFO. */
int32_t read_minfo_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type MINFO. */
void write_minfo_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type MINFO. */
int print_minfo_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type MX. */
int32_t read_mx_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type MX. */
void write_mx_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type MX. */
int print_mx_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type TXT. */
int32_t read_txt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type TXT. */
int print_txt_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type RP. */
int32_t read_rp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type RP. */
void write_rp_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type RP. */
int print_rp_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type AFSDB. */
int32_t read_afsdb_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type AFSDB. */
void write_afsdb_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type AFSDB. */
int print_afsdb_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type X25. */
int32_t read_x25_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type X25. */
int print_x25_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type ISDN. */
int32_t read_isdn_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type ISDN. */
int print_isdn_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type RT. */
int32_t read_rt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type RT. */
void write_rt_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type NSAP. */
int print_nsap_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type RRSIG. */
int32_t read_rrsig_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type RRSIG. */
void write_rrsig_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type RRSIG. */
int print_rrsig_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type KEY. */
int32_t read_key_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type KEY. */
void write_key_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type KEY. */
int print_key_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type PX. */
int32_t read_px_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type PX. */
void write_px_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type PX. */
int print_px_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type AAAA. */
int32_t read_aaaa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type AAAA. */
int print_aaaa_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type LOC. */
int32_t read_loc_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Read rdata for type NXT. */
int32_t read_nxt_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type NXT. */
void write_nxt_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type NXT. */
int print_nxt_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type SRV. */
int32_t read_srv_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type SRV. */
void write_srv_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type SRV. */
int print_srv_rdata(struct buffer *buffer, const struct rr *rr);

/* Print rdata for type ATMA. */
int print_atma_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type NAPTR. */
int32_t read_naptr_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type NAPTR. */
void write_naptr_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type NAPTR. */
int print_naptr_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type KX. */
int32_t read_kx_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type KX. */
void write_kx_rdata(struct query *query, const struct rr *rr);

/* Read rdata for type CERT. */
int32_t read_cert_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type CERT. */
int print_cert_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type A6. */
int32_t read_a6_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type A6. */
int print_a6_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type APL. */
int32_t read_apl_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type APL. */
int print_apl_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type DS. */
int32_t read_ds_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type DS. */
int print_ds_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type SSHFP. */
int32_t read_sshfp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type SSHFP. */
int print_sshfp_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type IPSECKEY. */
int32_t read_ipseckey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type IPSECKEY. */
int print_ipseckey_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type RRSIG. */
int32_t read_rrsig_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type RRSIG. */
int print_rrsig_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type NSEC. */
int32_t read_nsec_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type NSEC. */
int print_nsec_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type DNSKEY. */
int32_t read_dnskey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type DNSKEY. */
int print_dnskey_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type DHCID. */
int32_t read_dhcid_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type DHCID. */
int print_dhcid_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type NSEC3. */
int32_t read_nsec3_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type NSEC3. */
int print_nsec3_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type NSEC3PARAM. */
int32_t read_nsec3param_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type NSEC3PARAM. */
int print_nsec3param_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type TLSA. */
int32_t read_tlsa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type TLSA. */
int print_tlsa_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type SMIMEA. */
int32_t read_smimea_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type SMIMEA. */
int print_smimea_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type HIP. */
int32_t read_hip_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type HIP. */
int print_hip_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type RKEY. */
int32_t read_rkey_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type RKEY. */
int print_rkey_rdata(struct buffer *buffer, const struct rr *rr);

/* Print rdata for type OPENPGPKEY. */
int print_openpgpkey_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type CSYNC. */
int32_t read_csync_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type CSYNC. */
int print_csync_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type ZONEMD. */
int32_t read_zonemd_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type ZONEMD. */
int print_zonemd_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type SVCB. */
int32_t read_svcb_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type SVCB. */
void write_svcb_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type SVCB. */
int print_svcb_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type NID. */
int32_t read_nid_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type NID. */
int print_nid_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type L32. */
int32_t read_l32_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type L32. */
int print_l32_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type L64. */
int32_t read_l64_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type L64. */
int print_l64_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type LP. */
int32_t read_lp_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Write rdata for type LP. */
void write_lp_rdata(struct query *query, const struct rr *rr);

/* Print rdata for type LP. */
int print_lp_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type EUI48. */
int32_t read_eui48_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type EUI48. */
int print_eui48_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type EUI64. */
int32_t read_eui64_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type EUI64. */
int print_eui64_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type URI. */
int32_t read_uri_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type URI. */
int print_uri_rdata(struct buffer *buffer, const struct rr *rr);

/* Print rdata for type resinfo. */
int print_resinfo_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type CAA. */
int32_t read_caa_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type CAA. */
int print_caa_rdata(struct buffer *buffer, const struct rr *rr);

/* Read rdata for type DLV. */
int32_t read_dlv_rdata(struct domain_table *domains, uint16_t rdlength,
	struct buffer *packet, struct rr **rr);

/* Print rdata for type DLV. */
int print_dlv_rdata(struct buffer *buffer, const struct rr *rr);

#endif /* RDATA_H */
