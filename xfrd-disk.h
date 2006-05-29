/*
 * xfrd-disk.h - XFR (transfer) Daemon TCP system header file. Save/Load state to disk.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef XFRD_DISK_H
#define XFRD_DISK_H

#include <config.h>
struct xfrd_state;

void xfrd_read_state(struct xfrd_state* xfrd);
void xfrd_write_state(struct xfrd_state* xfrd);

#endif /* XFRD_DISK_H */
