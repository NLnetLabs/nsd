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

#include "config.h"

#ifdef DNSTAP

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <strings.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>

#include <fstrm.h>
#include <protobuf-c/protobuf-c.h>

#include "buffer.h"
#include "dnstap.h"
#include "dnstap.pb-c.h"
#include "options.h"
#include "util.h"

#define DNSTAP_CONTENT_TYPE		"protobuf:dnstap.Dnstap"
#define DNSTAP_INITIAL_BUF_SIZE		256
#define DNSTAP_UDP 1
#define DNSTAP_TCP 2

struct dt_msg {
	void		*buf;
	size_t		len_buf;
	Dnstap__Dnstap	d;
	Dnstap__Message	m;
};

static int
dt_pack(const Dnstap__Dnstap *d, void **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf;

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
	sbuf.data = malloc(sbuf.alloced);
	if (sbuf.data == NULL)
		return 0;
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL)
		return 0;
	*buf = sbuf.data;

	return 1;
}

static void
dt_send(const struct dnstap_env *env, void *buf, size_t len_buf)
{
	fstrm_res res;
	if (!buf)
		return;
	res = fstrm_io_submit(env->fio, env->fq, buf, len_buf,
			      fstrm_free_wrapper, NULL);
	if (res != fstrm_res_success)
		free(buf);
}

static void
dt_msg_init(const struct dnstap_env *env,
	    struct dt_msg *dm,
	    Dnstap__Message__Type mtype)
{
	memset(dm, 0, sizeof(*dm));
	dm->d.base.descriptor = &dnstap__dnstap__descriptor;
	dm->m.base.descriptor = &dnstap__message__descriptor;
	dm->d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dm->d.message = &dm->m;
	dm->m.type = mtype;
	if (env->identity != NULL) {
		dm->d.identity.data = (uint8_t *) env->identity;
		dm->d.identity.len = (size_t) env->len_identity;
		dm->d.has_identity = 1;
	}
	if (env->version != NULL) {
		dm->d.version.data = (uint8_t *) env->version;
		dm->d.version.len = (size_t) env->len_version;
		dm->d.has_version = 1;
	}
}


static void
dt_fill_timeval(const struct timeval *tv,
		uint64_t *time_sec, protobuf_c_boolean *has_time_sec,
		uint32_t *time_nsec, protobuf_c_boolean *has_time_nsec)
{
	*time_sec = tv->tv_sec;
	*time_nsec = tv->tv_usec * 1000;
	*has_time_sec = 1;
	*has_time_nsec = 1;
}


static void
dt_fill_buffer(buffer_type *b, ProtobufCBinaryData *p, protobuf_c_boolean *has)
{
	assert(b != NULL);
	p->len = buffer_limit(b);
	p->data = buffer_begin(b);
	*has = 1;
}

static void
dt_msg_fill_net(struct dt_msg *dm,
		struct sockaddr_storage *ss,
		int cptype,
		ProtobufCBinaryData *addr, protobuf_c_boolean *has_addr,
		uint32_t *port, protobuf_c_boolean *has_port)
{
	log_assert(ss->ss_family == AF_INET6 || ss->ss_family == AF_INET);
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) ss;

		/* socket_family */
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;
		dm->m.has_socket_family = 1;

		/* addr: query_address or response_address */
		addr->data = s->sin6_addr.s6_addr;
		addr->len = 16; /* IPv6 */
		*has_addr = 1;

		/* port: query_port or response_port */
		*port = ntohs(s->sin6_port);
		*has_port = 1;
	} else if (ss->ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *) ss;

		/* socket_family */
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
		dm->m.has_socket_family = 1;

		/* addr: query_address or response_address */
		addr->data = (uint8_t *) &s->sin_addr.s_addr;
		addr->len = 4; /* IPv4 */
		*has_addr = 1;

		/* port: query_port or response_port */
		*port = ntohs(s->sin_port);
		*has_port = 1;
	}

	log_assert(cptype == DNSTAP_UDP || cptype == DNSTAP_TCP);
	if (cptype == DNSTAP_UDP) {
		/* socket_protocol */
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;
		dm->m.has_socket_protocol = 1;
	} else if (cptype == DNSTAP_TCP) {
		/* socket_protocol */
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
		dm->m.has_socket_protocol = 1;
	}
}


/**
 * Create dnstap environment object.
 *
 */
struct dnstap_env*
dnstap_create(const char* sockpath)
{
	struct dnstap_env* env;
	struct fstrm_file_options* fopt;
	struct fstrm_writer_options* fwopt;

	assert(sockpath);
	log_msg(LOG_INFO, "dnstap: initialize file %s", sockpath);
	env = (struct dnstap_env*) calloc(1, sizeof(struct dnstap_env));
	if (!env)
		return NULL;

	fopt = fstrm_file_options_init();
	if (!fopt) {
		log_msg(LOG_ERR, "dnstap: fstrm_file_options_init() failed");
		free(env);
		return NULL;
	}
	fwopt = fstrm_writer_options_init();
	if (!fwopt) {
		log_msg(LOG_ERR, "dnstap: fstrm_writer_options_init() failed");
		free(env);
		env = NULL;
	}

	fstrm_file_options_set_file_path(fopt, sockpath);
	env->fw = fstrm_file_writer_init(fopt, NULL);
	if (env->fw == NULL) {
		log_msg(LOG_ERR, "dnstap: fstrm_file_writer_init() failed");
		free(env);
		env = NULL;
	}
	fstrm_writer_options_destroy(&fwopt);
	fstrm_file_options_destroy(&fopt);
	return env;
}


/**
 * Initialize per-worker state in dnstap environment object.
 *
 */
int
dnstap_init(struct dnstap_env* env)
{
/*
	env->fq = fstrm_io_get_queue(env->fio);
	if (env->fq == NULL)
		return 0;
*/
	return 1;
}


/**
 * Delete dnstap environment object.
 *
 */
void
dnstap_delete(struct dnstap_env* env)
{
	if (!env)
		return;
	log_msg(LOG_INFO, "dnstap: shutdown");
	fstrm_writer_destroy(&env->fw);
	free(env->identity);
	free(env->version);
	free(env);
	return;
}

/**
 * Create and send a new dnstap "Message" event of type AUTH_QUERY.
 *
 */
void
dnstap_send_auth_query(struct dnstap_env* env, buffer_type* msg)
{
	struct dt_msg dm;
	struct timeval mtime;
	fstrm_res res;
	if (!env || !env->send_auth_query)
		return;
	gettimeofday(&mtime, NULL);
	dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__AUTH_QUERY);
	dt_fill_timeval(&mtime,
		&dm.m.query_time_sec, &dm.m.has_query_time_sec,
		&dm.m.query_time_nsec, &dm.m.has_query_time_nsec);
	dt_fill_buffer(msg, &dm.m.query_message, &dm.m.has_query_message);

        if (dt_pack(&dm.d, &dm.buf, &dm.len_buf)) {
		res = fstrm_writer_write(env->fw, dm.buf, dm.len_buf);
		if (res != fstrm_res_success)
			log_msg(LOG_ERR, "dnstap: fstrm_writer_write() failed");
	} else
		log_msg(LOG_ERR, "dnstap: dt_pack() failed");
	return;
}

/*
 * Create and send a new dnstap "Message" event of type AUTH_RESPONSE.
 *
 */
void
dnstap_send_auth_response(struct dnstap_env* env, buffer_type* msg)
{
	struct dt_msg dm;
	struct timeval mtime;
	fstrm_res res;
	if (!env || !env->send_auth_response)
		return;
	gettimeofday(&mtime, NULL);
	dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE);
	dt_fill_timeval(&mtime,
		&dm.m.response_time_sec, &dm.m.has_response_time_sec,
		&dm.m.response_time_nsec, &dm.m.has_response_time_nsec);
	dt_fill_buffer(msg, &dm.m.response_message, &dm.m.has_response_message);

        if (dt_pack(&dm.d, &dm.buf, &dm.len_buf)) {
		res = fstrm_writer_write(env->fw, dm.buf, dm.len_buf);
		if (res != fstrm_res_success)
			log_msg(LOG_ERR, "dnstap: fstrm_writer_write() failed");
	} else
		log_msg(LOG_ERR, "dnstap: dt_pack() failed");
	return;
}

#endif /* DNSTAP */
