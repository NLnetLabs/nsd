/*
 * ldns-nsd-glue.c -- compat layer between NSD and ldns
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>


#include <nsd.h>
#include <options.h>

#include <ldns/dns.h>

