/*
 * edns.h -- EDNS definitions (RFC 2671).
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */


#include <config.h>

#include <string.h>

#include "dns.h"
#include "edns.h"

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
	/* add more so that nsid fits */
	/* EXTENDED RCODE AND FLAGS, bytes 5-8 */
	/* RDATA LENGTH */
	data->ok[9] = ((4 + NSID_LEN) & 0xff00) >> 8; /* length_hi */
	data->ok[10] = ((4 + NSID_LEN) & 0x00ff);     /* length_lo */

	/* Miek, NSID stuff needs to be put here */
	data->nsid[0] = (NSID_CODE & 0xff00) >> 8;
	data->nsid[1] = (NSID_CODE & 0x00ff);
	data->nsid[2] = (NSID_LEN & 0xff00) >> 8;
	data->nsid[3] = (NSID_LEN & 0x00ff);
	memcpy(data->nsid + 4, NSID_DATA, 8);
	
	data->error[1] = (TYPE_OPT & 0xff00) >> 8;	/* type_hi */
	data->error[2] = TYPE_OPT & 0x00ff;		/* type_lo */
	data->error[3] = (max_length & 0xff00) >> 8;	/* size_hi */
	data->error[4] = max_length & 0x00ff;		/* size_lo */
	data->error[5] = 1;	/* XXX Extended RCODE=BAD VERS */
}

void
edns_init_record(edns_record_type *edns)
{
	edns->status = EDNS_NOT_PRESENT;
	edns->position = 0;
	edns->maxlen = 0;
	edns->dnssec_ok = 0;
}

int
edns_parse_record(edns_record_type *edns, buffer_type *packet)
{
	/* OPT record type... */
	uint8_t  opt_owner;
	uint16_t opt_type;
	uint16_t opt_class;
	uint8_t  opt_extended_rcode;
	uint8_t  opt_version;
	uint16_t opt_flags;
	uint16_t opt_rdlen;

	edns->position = buffer_position(packet);
	
	if (!buffer_available(packet, OPT_LEN))
		return 0;

	opt_owner = buffer_read_u8(packet);
	opt_type = buffer_read_u16(packet);
	if (opt_owner != 0 || opt_type != TYPE_OPT) {
		/* Not EDNS.  */
		buffer_set_position(packet, edns->position);
		return 0;
	}
	
	opt_class = buffer_read_u16(packet);
	opt_extended_rcode = buffer_read_u8(packet);
	opt_version = buffer_read_u8(packet);
	opt_flags = buffer_read_u16(packet);
	opt_rdlen = buffer_read_u16(packet);

	/* nsid: here we should read more and check
	 * for the nsid option
	 */
	
	if (opt_rdlen != 0 || opt_version != 0) {
		edns->status = EDNS_ERROR;
		return 1;
	}

	edns->status = EDNS_OK;
	edns->maxlen = opt_class;
	edns->dnssec_ok = !!(opt_flags & DNSSEC_OK_MASK);
	return 1;
}

size_t
edns_reserved_space(edns_record_type *edns)
{
	return edns->status == EDNS_NOT_PRESENT ? 0 : OPT_LEN;
}
