/*
 * dnstap.h - dnstap for NSD.
 *
 * Copyright (c) 2013-2014, Farsight Security, Inc.
 * Copyright (c) 2014, NLnet Labs.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef DNSTAP_H
#define DNSTAP_H

#include "config.h"

#ifdef DNSTAP

#include "buffer.h"

/** dnstap environment. */
struct dnstap_env {
	/** dnstap I/O socket */
	struct fstrm_io *fio;
	/** dnstap I/O queue */
	struct fstrm_queue *fq;
	/** dnstap file */
	struct fstrm_writer *fw;

	/** identity field, NULL if disabled */
	char *identity;
	/** version field, NULL if disabled */
	char *version;
	/** length of identity field */
	unsigned len_identity;
	/** length of version field */
	unsigned len_version;
	/** whether to log AUTH_QUERY */
	unsigned send_auth_query : 1;
	/** whether to log AUTH_RESPONSE */
	unsigned send_auth_response : 1;
};

/**
 * Create dnstap environment object.
 *
 */
struct dnstap_env* dnstap_create(const char* sockpath);

/**
 * Initialize per-worker state in dnstap environment object.
 *
 */
int dnstap_init(struct dnstap_env* env);

/**
 * Delete dnstap environment object.
 *
 */
void dnstap_delete(struct dnstap_env* env);

/**
 * Create and send a new dnstap "Message" event of type AUTH_QUERY.
 *
 */
void dnstap_send_auth_query(struct dnstap_env* env, buffer_type* msg);

/**
 * Create and send a new dnstap "Message" event of type AUTH_RESPONSE.
 *
 */
void dnstap_send_auth_response(struct dnstap_env* env, buffer_type* msg);

#endif /* DNSTAP */

#endif /* DNSTAP_H */
