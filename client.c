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
