/*
 * client.c -- contains all client (nsdc/nsd-xfer) code
 *
 * Copyright (c) 2001-2005, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "packet.h"
#include "query.h"
#include "rdata.h"
#include "region-allocator.h"
#include "tsig.h"
#include "tsig-openssl.h"
#include "util.h"
#include "zonec.h"
#include "client.h"

void
error(int exitcode, const char *format, ...)
{
        va_list args;
        va_start(args, format);
        log_vmsg(LOG_ERR, format, args);
        va_end(args);
        exit(exitcode);
}

void
warning(const char *format, ...)
{
        va_list args;
        va_start(args, format);
        log_vmsg(LOG_WARNING, format, args);
        va_end(args);
}

int      
read_socket(int s, void *buf, size_t size)
{               
        char *data = (char *) buf;
        size_t total_count = 0;

        while (total_count < size) {
                ssize_t count = read(s, data + total_count, size - total_count);
                if (count == -1) {
                        /* Error or interrupt.  */
                        if (errno != EAGAIN) {
                                error(XFER_FAIL, "network read failed: %s",
                                      strerror(errno));
                                return 0;
                        } else {
                                continue;
                        }
                } else if (count == 0) {
                        /* End of file (connection closed?)  */
                        error(XFER_FAIL, "network read failed: Connection closed by peer");
                        return 0;
                }
                total_count += count;
        }       

        return 1;
}       

int
write_socket(int s, const void *buf, size_t size)
{
        const char *data = (const char *) buf;
        size_t total_count = 0;

        while (total_count < size) {
                ssize_t count
                        = write(s, data + total_count, size - total_count);
                if (count == -1) {
                        if (errno != EAGAIN) {
                                error(XFER_FAIL, "network write failed: %s",
                                      strerror(errno));
                                return 0;
                        } else {
                                continue;
                        }
                }
                total_count += count;
        }

        return 1;
}               

int
send_query(int s, query_type *q)
{
        uint16_t size = htons(buffer_remaining(q->packet));

        if (!write_socket(s, &size, sizeof(size))) {
                return 0;
        }
        if (!write_socket(s, buffer_begin(q->packet), buffer_limit(q->packet)))
        {
                return 0;
        }
        return 1;
}

int
print_rr_region(FILE *out, region_type *region, rr_type *record)
{
        buffer_type *output = buffer_create(region, 1000);
        rrtype_descriptor_type *descriptor
                = rrtype_descriptor_by_type(record->type);
        int result;
        const dname_type *owner = domain_dname(record->owner);
#if 0
        const dname_type *owner_origin
                = dname_origin(state->rr_region, owner);
        int owner_changed
                = (!state->previous_owner
                   || dname_compare(state->previous_owner, owner) != 0);
        if (owner_changed) {
                int origin_changed = (!state->previous_owner_origin
                                      || dname_compare(
                                              state->previous_owner_origin,
                                              owner_origin) != 0);
                if (origin_changed) {
                        buffer_printf(
                                output,
                                "$ORIGIN %s\n",
                                dname_to_string(owner_origin, NULL));
                }

                set_previous_owner(state, owner);
                buffer_printf(output,
                              "%s",
                              dname_to_string(owner,
                                              state->previous_owner_origin));
        }
#endif

        buffer_printf(output,
                      "\t%lu\t%s\t%s",
                      (unsigned long) record->ttl,
                      rrclass_to_string(record->klass),
                      rrtype_to_string(record->type));

        result = print_rdata(output, descriptor, record);
        if (!result) {
                /*
                 * Some RDATA failed to print, so print the record's
                 * RDATA in unknown format.
                 */
                result = rdata_atoms_to_unknown_string(output,
                                                       descriptor,
                                                       record->rdata_count,
                                                       record->rdatas);
        }

        if (result) {
                buffer_printf(output, "\n");
                buffer_flip(output);
                fwrite(buffer_current(output), buffer_remaining(output), 1,
                       out);
/*              fflush(out); */
        }
        return result;
}

int
print_rdata(buffer_type *output, rrtype_descriptor_type *descriptor,
            rr_type *record)
{
        size_t i;
        size_t saved_position = buffer_position(output);

        for (i = 0; i < record->rdata_count; ++i) {
                if (i == 0) {
                        buffer_printf(output, "\t");
                } else if (descriptor->type == TYPE_SOA && i == 2) {
                        buffer_printf(output, " (\n\t\t");
                } else {
                        buffer_printf(output, " ");
                }
                if (!rdata_atom_to_string(
                            output,
                            (rdata_kind_type) descriptor->rdata_kinds[i],
                            record->rdatas[i]))
                {
                        buffer_set_position(output, saved_position);
                        return 0;
                }
        }
        if (descriptor->type == TYPE_SOA) {
                buffer_printf(output, " )");
        }

        return 1;
}

