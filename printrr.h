/*
 * printrr.h -- print RRs.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "zonec.h"

/* print_rr and helper functions */
uint8_t * wire_conv_string(rdata_atom_type);
uint8_t * wire_conv_domain(rdata_atom_type);
uint8_t * wire_conv_labels(rdata_atom_type);
uint8_t * wire_conv_a(rdata_atom_type);
uint8_t * wire_conv_aaaa(rdata_atom_type);
uint8_t * wire_conv_b64(rdata_atom_type);
uint8_t * wire_conv_hex(rdata_atom_type);
uint8_t * wire_conv_time(rdata_atom_type);
uint16_t wire_conv_rrtype(rdata_atom_type);
long int wire_conv_long(rdata_atom_type);
short int wire_conv_byte(rdata_atom_type);
int wire_conv_short(rdata_atom_type);
int print_rr(rr_type *);
int print_rrset(rrset_type *,domain_type *); 
int print_rrdata(rrdata_type *, uint16_t);
