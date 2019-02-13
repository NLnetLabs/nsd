/* Copyright (c) 2019, NLnet Labs. All rights reserved.
 * 
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DNS_CONFIG_H_ 
#define DNS_CONFIG_H_
#include <stdint.h>

#ifndef DNS_DEFAULT_TTL
#define DNS_DEFAULT_TTL     3600
#endif
#ifndef DNS_DEFAULT_CLASS
#define DNS_DEFAULT_CLASS   1
#endif
#ifndef DNS_DEFAULT_ORIGIN
#define DNS_DEFAULT_ORIGIN  ""
#endif
#ifndef DNS_DEFAULT_RRTYPES
struct dnsextlang_def;
#define DNS_DEFAULT_RRTYPES NULL
#endif

#define DNS_CONFIG_DEFAULTS { DNS_DEFAULT_TTL   , DNS_DEFAULT_CLASS \
                            , DNS_DEFAULT_ORIGIN, DNS_DEFAULT_RRTYPES }

typedef struct dns_config {
	uint32_t               default_ttl;
	uint16_t               default_class;
	const char            *default_origin;
	struct dnsextlang_def *rrtypes;
} dns_config;

#endif /* #ifndef DNS_CONFIG_H_ */
