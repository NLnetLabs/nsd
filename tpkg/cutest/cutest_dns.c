/*
	test dns.c
*/

#include "config.h"

#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include "tpkg/cutest/cutest.h"
#include "region-allocator.h"
#include "dns.h"

static void dns_1(CuTest *tc);
static void dns_2(CuTest *tc);

CuSuite* reg_cutest_dns(void)
{
        CuSuite* suite = CuSuiteNew();

	SUITE_ADD_TEST(suite, dns_1);
	SUITE_ADD_TEST(suite, dns_2);
	return suite;
}

static void dns_1(CuTest *tc)
{
	/* Check consistency of rrtype descriptor table. */
	int i;
	const struct nsd_type_descriptor* d;
	const struct nsd_type_descriptor* start = nsd_type_descriptor(0);
	for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
		const struct nsd_type_descriptor* d = start+i;
		const struct nsd_type_descriptor* lookup = nsd_type_descriptor(
			d->type);

		if(i <= 264) {
			CuAssert(tc, "dns rrtype descriptor: index",
				i == d->type);
			CuAssert(tc, "dns rrtype descriptor: offset",
				i == d - start);
		}
		CuAssert(tc, "dns rrtype descriptor: type",
			lookup->type == d->type);
	}

	d = nsd_type_descriptor(TYPE_NSEC3);
	CuAssert(tc, "dns rrtype descriptor: type nsec3", d->type == TYPE_NSEC3);
}

static void dns_2(CuTest *tc)
{
	/* Check that fields and the descriptor bools are correct */
	int i;
	const struct nsd_type_descriptor* start = nsd_type_descriptor(0);
	for (i = 0; i < RRTYPE_DESCRIPTORS_LENGTH; ++i) {
		const struct nsd_type_descriptor* d = start+i;
		size_t f;
		int saw_reference = 0, saw_compressed = 0, saw_dname = 0,
			saw_optional = 0;
		CuAssert(tc, "read_rdata func ptr",
			d->read_rdata != NULL);
		CuAssert(tc, "write_rdata func ptr",
			d->write_rdata != NULL);
		CuAssert(tc, "print_rdata func ptr",
			d->print_rdata != NULL);
		for(f = 0; f < d->rdata.length; f++) {
			const struct nsd_rdata_descriptor* field =
				&d->rdata.fields[f];

			/* check that the field has a name */
			CuAssert(tc, "field name", field->name != NULL);

			/* check has_references */
			if(!d->has_references) {
				/* If the type has no references, the field
				 * cannot be a reference to a domain name. */
				CuAssert(tc, "type has no references",
					field->length != RDATA_COMPRESSED_DNAME
					&& field->length != RDATA_UNCOMPRESSED_DNAME);
			}
			if(field->length == RDATA_COMPRESSED_DNAME ||
				field->length == RDATA_UNCOMPRESSED_DNAME)
				saw_reference = 1;

			/* check is_compressible */
			if(!d->is_compressible) {
				/* If the type is not compressible, the field
				 * cannot be a compressed dname. */
				CuAssert(tc, "type is not compressible",
					field->length != RDATA_COMPRESSED_DNAME);
			}
			if(field->length == RDATA_COMPRESSED_DNAME)
				saw_compressed = 1;

			/* check has_dnames */
			if(!d->has_dnames) {
				/* If the type has no dnames, then the field
				 * cannot be a dname. */
				CuAssert(tc, "type has no dnames",
					field->length != RDATA_COMPRESSED_DNAME
					&& field->length != RDATA_UNCOMPRESSED_DNAME
					&& field->length != RDATA_LITERAL_DNAME);
			}
			if(field->length == RDATA_COMPRESSED_DNAME ||
				field->length == RDATA_UNCOMPRESSED_DNAME ||
				field->length == RDATA_LITERAL_DNAME ||
				/* The IPSECKEY and AMTRELAY types can have
				 * a literal dname in the field. */
				field->length == RDATA_IPSECGATEWAY ||
				field->length == RDATA_AMTRELAY_RELAY)
				saw_dname = 1;
			/* The HIP remainder type contains literal dnames. */
			if(d->type == TYPE_HIP)
				saw_dname = 1;

			/* check is_optional has only is_optional after
			 * it or it is the last field. */
			if(saw_optional) {
				/* After an optional field, the remainder
				 * of fields are also optional. */
				CuAssert(tc, "field is optional",
					field->is_optional);
			} else if(field->is_optional) {
				saw_optional = 1;
			}

			/* check field length */
			if(field->length < 0) {
				/* Allowed special field types */
				CuAssert(tc, "special field types",
				   field->length == RDATA_COMPRESSED_DNAME
				|| field->length == RDATA_UNCOMPRESSED_DNAME
				|| field->length == RDATA_LITERAL_DNAME
				|| field->length == RDATA_STRING
				|| field->length == RDATA_BINARY
				|| field->length == RDATA_IPSECGATEWAY
				|| field->length == RDATA_REMAINDER
				|| field->length == RDATA_AMTRELAY_RELAY);
			}

			/* check calculate_length and calculate_length_uncompressed_wire */
			if(field->length == RDATA_IPSECGATEWAY ||
				field->length == RDATA_AMTRELAY_RELAY) {
				CuAssert(tc, "field has calc len func ptr",
					field->calculate_length != NULL);
				CuAssert(tc, "field has calc uncompr len func ptr",
					field->calculate_length_uncompressed_wire != NULL);
			} else {
				CuAssert(tc, "field has no calc len func ptr",
					field->calculate_length == NULL);
				CuAssert(tc, "field has no calc uncompr len func ptr",
					field->calculate_length_uncompressed_wire == NULL);
			}
		}
		if(d->has_references) {
			/* If the type has references, the fields should have
			 * a reference. */
			CuAssert(tc, "type has references", saw_reference);
		}
		if(d->is_compressible) {
			/* If the type is compressed, the fields should have
			 * a compressed dname. */
			CuAssert(tc, "type is compressed", saw_compressed);
		}
		if(d->has_dnames) {
			/* If the type has dnames, the fields should have
			 * a dname. */
			CuAssert(tc, "type has dnames", saw_dname);
		}
	}
}
