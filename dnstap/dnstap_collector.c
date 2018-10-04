/*
 * dnstap/dnstap_collector.c -- nsd collector process for dnstap information
 *
 * Copyright (c) 2018, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>
#ifndef USE_MINI_EVENT
#  ifdef HAVE_EVENT_H
#    include <event.h>
#  else
#    include <event2/event.h>
#    include "event2/event_struct.h"
#    include "event2/event_compat.h"
#  endif
#else
#  include "mini_event.h"
#endif
#include "dnstap/dnstap_collector.h"
// these and other // need to be removed to call dnstap to write stuff.
//#include "dnstap/dnstap.h"
#include "util.h"
#include "nsd.h"

struct dt_collector* dt_collector_create(struct nsd* nsd)
{
	int i, sv[2];
	struct dt_collector* dt_col = (struct dt_collector*)xalloc_zero(
		sizeof(*dt_col));
	dt_col->count = nsd->child_count;
	dt_col->dt_env = NULL;
	/* get config from struct nsd and nsd.options,
	 * socket_path, nsd.child_count */

	/* open pipes in struct nsd */
	nsd->dt_collector_fd_send = (int*)xalloc_array_zero(dt_col->count,
		sizeof(int));
	nsd->dt_collector_fd_recv = (int*)xalloc_array_zero(dt_col->count,
		sizeof(int));
	for(i=0; i<dt_col->count; i++) {
		int fd[2];
		fd[0] = -1;
		fd[1] = -1;
		if(pipe(fd) < 0) {
			error("dnstap_collector: cannot create pipe: %s",
				strerror(errno));
		}
		nsd->dt_collector_fd_recv[i] = fd[0];
		nsd->dt_collector_fd_send[i] = fd[1];
	}

	/* open socketpair */
	if(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == -1) {
		error("dnstap_collector: cannot create socketpair: %s",
			strerror(errno));
	}
	dt_col->cmd_socket_dt = sv[0];
	dt_col->cmd_socket_nsd = sv[1];

	return dt_col;
}

void dt_collector_destroy(struct dt_collector* dt_col, struct nsd* nsd)
{
	if(!dt_col) return;
	free(nsd->dt_collector_fd_recv);
	nsd->dt_collector_fd_recv = NULL;
	free(nsd->dt_collector_fd_send);
	nsd->dt_collector_fd_send = NULL;
	free(dt_col);
}

void dt_collector_close(struct dt_collector* dt_col, struct nsd* nsd)
{
	int i;
	if(!dt_col) return;
	if(dt_col->cmd_socket_dt != -1) {
		close(dt_col->cmd_socket_dt);
		dt_col->cmd_socket_dt = -1;
	}
	if(dt_col->cmd_socket_nsd != -1) {
		close(dt_col->cmd_socket_nsd);
		dt_col->cmd_socket_nsd = -1;
	}
	for(i=0; i<dt_col->count; i++) {
		if(nsd->dt_collector_fd_recv[i] != -1) {
			close(nsd->dt_collector_fd_recv[i]);
			nsd->dt_collector_fd_recv[i] = -1;
		}
		if(nsd->dt_collector_fd_send[i] != -1) {
			close(nsd->dt_collector_fd_send[i]);
			nsd->dt_collector_fd_send[i] = -1;
		}
	}
}

/* handle command from nsd to dt collector.
 * mostly, check for fd closed, this means we have to exit */
void
dt_handle_cmd_from_nsd(int ATTR_UNUSED(fd), short event, void* arg)
{
	struct dt_collector* dt_col = (struct dt_collector*)arg;
	if((event&EV_READ) != 0) {
		event_base_loopexit(dt_col->event_base, NULL);
	}
}

/* handle input from worker for dnstap */
void
dt_handle_input(int fd, short event, void* arg)
{
	struct dt_collector_input* dt_input = (struct dt_collector_input*)arg;
	if((event&EV_READ) != 0) {
		/* read */
		(void)fd; (void)dt_input;

		/* once data is complete, write it to dnstap */
		//dt_write();
	}
}

/* init dnstap */
static void dt_init_dnstap(struct dt_collector* dt_col)
{
	dt_col->dt_env = NULL;
	//dt_env = dt_create(const char *socket_path, unsigned num_workers);
	//dt_apply_cfg(struct dt_env *env, struct config_file *cfg);
	//dt_init
}

/* cleanup dt collector process for exit */
static void dt_collector_cleanup(struct dt_collector* dt_col, struct nsd* nsd)
{
	int i;
	//dt_delete(dt_col->dt_env);
	event_del(dt_col->cmd_event);
	for(i=0; i<dt_col->count; i++) {
		event_del(dt_col->inputs[i].event);
	}
	dt_collector_close(dt_col, nsd);
#ifdef MEMCLEAN
	free(dt_col->cmd_event);
	for(i=0; i<dt_col->count; i++) {
		free(dt_col->inputs[i].event);
	}
	free(dt_col->inputs);
	event_base_free(dt_col->event_base);
	dt_collector_destroy(dt_col, nsd);
#endif
}

/* attach events to the event base to listen to the workers and cmd channel */
static void dt_attach_events(struct dt_collector* dt_col, struct nsd* nsd)
{
	int i;
	/* create event base */
	dt_col->event_base = nsd_child_event_base();
	if(!dt_col->event_base) {
		error("dnstap collector: event_base create failed");
	}

	/* add command handler */
	dt_col->cmd_event = (struct event*)xalloc_zero(
		sizeof(*dt_col->cmd_event));
	event_set(dt_col->cmd_event, dt_col->cmd_socket_dt,
		EV_PERSIST|EV_READ, dt_handle_cmd_from_nsd, dt_col);
	if(event_base_set(dt_col->event_base, dt_col->cmd_event) != 0)
		log_msg(LOG_ERR, "dnstap collector: event_base_set failed");
	if(event_add(dt_col->cmd_event, NULL) != 0)
		log_msg(LOG_ERR, "dnstap collector: event_add failed");
	
	/* add worker input handlers */
	dt_col->inputs = xalloc_array_zero(dt_col->count,
		sizeof(*dt_col->inputs));
	for(i=0; i<dt_col->count; i++) {
		dt_col->inputs[i].dt_collector = dt_col;
		dt_col->inputs[i].event = (struct event*)xalloc_zero(
			sizeof(struct event));
		event_set(dt_col->inputs[i].event,
			nsd->dt_collector_fd_recv[i], EV_PERSIST|EV_READ,
			dt_handle_input, &dt_col->inputs[i]);
		if(event_base_set(dt_col->event_base,
			dt_col->inputs[i].event) != 0)
			log_msg(LOG_ERR, "dnstap collector: event_base_set failed");
		if(event_add(dt_col->inputs[i].event, NULL) != 0)
			log_msg(LOG_ERR, "dnstap collector: event_add failed");
		
		//dt_col->inputs[i].buffer = 
	}
}

/* the dnstap collector process main routine */
static void dt_collector_run(struct dt_collector* dt_col, struct nsd* nsd)
{
	/* init dnstap */
	VERBOSITY(1, (LOG_INFO, "dnstap collector started"));
	dt_init_dnstap(dt_col);
	dt_attach_events(dt_col, nsd);

	/* run */
	if(event_base_loop(dt_col->event_base, 0) == -1) {
		error("dnstap collector: event_base_loop failed");
	}

	/* cleanup and done */
	VERBOSITY(1, (LOG_INFO, "dnstap collector stopped"));
	dt_collector_cleanup(dt_col, nsd);
	exit(0);
}

void dt_collector_start(struct dt_collector* dt_col, struct nsd* nsd)
{
	/* fork */
	dt_col->dt_pid = fork();
	if(dt_col->dt_pid == -1) {
		error("dnstap_collector: fork failed: %s", strerror(errno));
	}
	if(dt_col->dt_pid == 0) {
		/* the dt collector process is this */
		/* close the nsd side of the command channel */
		close(dt_col->cmd_socket_nsd);
		dt_col->cmd_socket_nsd = -1;
		dt_collector_run(dt_col, nsd);
		/* NOTREACH */
		exit(0);
	} else {
		/* the parent continues on, with starting NSD */
		/* close the dt side of the command channel */
		close(dt_col->cmd_socket_dt);
		dt_col->cmd_socket_dt = -1;
	}
}

void dt_collector_submit_auth_query(struct nsd* nsd,
#ifdef INET6
        struct sockaddr_storage* addr,
#else
        struct sockaddr_in* addr,
#endif
	socklen_t addrlen, int is_tcp, struct buffer* packet)
{
	VERBOSITY(4, (LOG_INFO, "dnstap submit auth query"));
	(void)nsd;
	(void)addr;
	(void)addrlen;
	(void)is_tcp;
	(void)packet;
}

void dt_collector_submit_auth_response(struct nsd* nsd,
#ifdef INET6
        struct sockaddr_storage* addr,
#else
        struct sockaddr_in* addr,
#endif
	socklen_t addrlen, int is_tcp, struct buffer* packet,
	struct zone* zone)
{
	VERBOSITY(4, (LOG_INFO, "dnstap submit auth response"));
	(void)nsd;
	(void)addr;
	(void)addrlen;
	(void)is_tcp;
	(void)packet;
	(void)zone;
}
