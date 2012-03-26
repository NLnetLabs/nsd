/*
 * verify.c -- running verifiers and serving the zone to be verified.
 *
 * Copyright (c) 2012, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif /* HAVE_SYSLOG_H */
#include <unistd.h>

#include "region-allocator.h"
#include "namedb.h"
#include "nsd.h"
#include "options.h"
#include "difffile.h"
#include "server.h"
#include "verify.h"


/* ----------- Functions on the database (maybe in namedb.[ch]?) ----------- */

struct zone_iter {
	zone_type*   zone;
	domain_type* domain;
	rrset_type*  rrset;
	size_t i;
};
typedef struct zone_iter zone_iter_type;

static rr_type*
zone_iter_next(zone_iter_type* iter, zone_type** zone)
{
	if (zone && *zone) {
		iter->zone   = *zone;
		*zone        = NULL;
		iter->i      = 0;
		if (iter->zone->soa_rrset && iter->zone->soa_rrset->rr_count) {
			iter->domain = NULL;
			iter->rrset  = iter->zone->soa_rrset;
			goto next;
		} else {
			iter->domain = iter->zone->apex;
			iter->rrset  = iter->domain->rrsets;
			goto skip_soa;
		}
	}
next:
	if (iter->i < iter->rrset->rr_count)
		return &iter->rrset->rrs[iter->i++];

	iter->i = 0;
	if (iter->domain == NULL) { /* prev rrset was soa_rrset */
		if ((iter->domain = iter->zone->apex)) {
			iter->rrset = iter->domain->rrsets;
			goto skip_soa;
		}
		else {
			return NULL;
		}
	}
	iter->rrset = iter->rrset->next;

skip_soa:

	while (iter->rrset && (iter->rrset->zone != iter->zone
			   ||  iter->rrset == iter->zone->soa_rrset)) {
		iter->rrset = iter->rrset->next;
	}
	if (iter->rrset) {
		goto next;
	}
	iter->domain = domain_next(iter->domain);
	if (iter->domain &&  dname_is_subdomain( domain_dname(iter->domain)
					       , domain_dname(iter->zone->apex)
					       )) {
		iter->rrset = iter->domain->rrsets;
		goto skip_soa;
	}
	return NULL;
}

/* ----------- Functions handling processes and servers (core) ------------- */

/*
 * Execute a program (command) with arguments (given as a NULL-terminated 
 * array of pointers to string). 
 * When given, writefd is set to a file descriptor for the write end of a pipe 
 * to the stdin for the program, and readfd and errfd to file descriptors for
 * the read end of pipes from the stdout and stderr of the program.
 *
 * 2011 implementation of popen3() by Mike Bourgeous
 * https://gist.github.com/1022231
 * Adapted for use in nsd-sexy by Willem Toorop in December 2011
 */
static pid_t 
nsd_popen3( char* const* command
	  , int* writefd
	  , int* readfd
	  , int* errfd
	  , nsd_type* nsd
	  , zone_type* zone
	  )
{
	int in_pipe[2] = {-1, -1};
	int out_pipe[2] = {-1, -1};
	int err_pipe[2] = {-1, -1};
	pid_t pid;

	if (command == NULL || *command == NULL) {
		log_msg(LOG_ERR, "Cannot popen3() a NULL command.");
		goto error;
	}

	if (writefd && pipe(in_pipe)) {
		log_msg( LOG_ERR
		       , "Error creating pipe for stdin: %s"
		       , strerror(errno)
		       );
		goto error;
	}
	if (readfd && pipe(out_pipe)) {
		log_msg( LOG_ERR
		       , "Error creating pipe for stdout: %s"
		       , strerror(errno)
		       );
		goto error;
	}
	if (errfd && pipe(err_pipe)) {
		log_msg( LOG_ERR
		       , "Error creating pipe for stderr: %s"
		       , strerror(errno)
		       );
		goto error;
	}

	pid = fork();
	switch(pid) {
		case -1: log_msg( LOG_ERR
				, "Error creating child process: %s"
				, strerror(errno)
				);
			 goto error;

		case  0: if(writefd) {
				 close(in_pipe[1]);
				 if(dup2(in_pipe[0], 0) == -1) {
					 log_msg( LOG_ERR
						, "Error assigning "
						  "stdin in child process: %s"
						, strerror(errno)
						);
					 exit(-1);
				 }
				 close(in_pipe[0]);
			 }
			 if(readfd) {
				 close(out_pipe[0]);
				 if(dup2(out_pipe[1], 1) == -1) {
					 log_msg( LOG_ERR
						, "Error assigning "
						  "stdout in child process: %s"
						, strerror(errno)
						);
					 exit(-1);
				 }
				 close(out_pipe[1]);
			 }
			 if(errfd) {
				 close(err_pipe[0]);
				 if(dup2(err_pipe[1], 2) == -1) {
					 log_msg( LOG_ERR
						, "Error assigning "
						  "stderr in child process: %s"
						, strerror(errno)
						);
					 exit(-1);
				 }
				 close(err_pipe[1]);
			 }

			 /* We are calling external programs that we don't
			  * trust with our sockets.
			  *
			  * Also there was a problem that child processes
			  * of verifies didn't exit. nsd couldn't start then
			  * anymore because the addresses were already in use.
			  */
			 close_all_sockets(nsd->udp, nsd->ifs);
			 close_all_sockets(nsd->tcp, nsd->ifs);
			 close_all_sockets(nsd->verify_udp, nsd->verify_ifs);
			 close_all_sockets(nsd->verify_tcp, nsd->verify_ifs);

			 setenv("VERIFY_ZONE", zone->opts->name, 1);

			 execvp(*command, command);

			 log_msg( LOG_ERR
				, "Error executing command "
				  "in child process: %s"
				, strerror(errno)
				);
			 exit(-1);

		default: break;
	}

	if(writefd) {
		close(in_pipe[0]);
		*writefd = in_pipe[1];
	}
	if(readfd) {
		close(out_pipe[1]);
		*readfd = out_pipe[0];
	}
	if(errfd) {
		close(err_pipe[1]);
		*errfd = err_pipe[0];
	}
	return pid;

error:
	if(in_pipe[0] >= 0) {
		close(in_pipe[0]);
	}
	if(in_pipe[1] >= 0) {
		close(in_pipe[1]);
	}
	if(out_pipe[0] >= 0) {
		close(out_pipe[0]);
	}
	if(out_pipe[1] >= 0) {
		close(out_pipe[1]);
	}
	if(err_pipe[0] >= 0) {
		close(err_pipe[0]);
	}
	if(err_pipe[1] >= 0) {
		close(err_pipe[1]);
	}
	return -1;
}

/*
 * handle_log_from_fd logs data read from the *lfd->fd with lfd->priority.
 * It is used to log data from the zone-verifier to stdout and stderr
 * in server_verify_zone, and is not intended to be used from another function.
 * The asumptions server_log_from_fd makes are therefor quiet specefic. 
 *
 * It is assumed that select is called first with the fd_set *lfd->rfds (which
 * should have contained *lfd->fd). It is also assumed that *lfd->fd can be
 * excluded from further calls to select by assigning it a value -1.
 *
 * server_log_from_fd logs each line (terminated by '\n'). But is a line is
 * longer then LOGLINELEN, it is split over multiple log-lines (which is
 * indicated in the log with ... at the end and start of line around a split).
 *
 * The struct log_from_fd_t is used to do the bookkeeping.
 */

#define LOGLINELEN (MAXSYSLOGMSGLEN-40) 
/* 40 is (estimated) space already used on each logline.
 * (time, pid, priority, etc) 
 */

struct log_from_fd_t {
	int     priority;
	int	fd;
	char    buf[LOGLINELEN*2+1];
	char*	pos;                 /* buffer is filled up to this pos.
				      * pos should never be larger than
				      * LOGLINELEN (part of the data would
				      * already have been logged then).
				      */
};

static void
handle_log_from_fd( netio_type* netio
		  , netio_handler_type* handler
		  , netio_event_types_type event_types
		  )
{
	struct log_from_fd_t*  lfd
     = (struct log_from_fd_t*) handler->user_data;
	ssize_t len;
	char* sol;
	char* eol;
	char* split;
	char  tmp_c;

	assert( lfd != NULL );
	assert( lfd->fd >= 0 );
	assert( lfd->pos < lfd->buf + LOGLINELEN );

	if (! (event_types & NETIO_EVENT_READ)) {
		return;
	}

	len = read(lfd->fd, lfd->pos, LOGLINELEN);
	if (len == 0) {
		close(lfd->fd);
		lfd->fd = -1;
		netio_remove_handler(netio, handler);
		return;
	}

	*(lfd->pos += len) = 0;

	sol = lfd->buf;
	eol = strchr(sol, '\n');

	while (eol) { /* lines to log */
		*eol = 0;
		if (eol - sol <= LOGLINELEN) {
			log_msg(lfd->priority, "%s", sol);
		} else {
			split = sol + LOGLINELEN - 4;
			tmp_c  = *split;
			*split = 0;
			log_msg(lfd->priority, "%s ...", sol);
			*split = tmp_c;
			log_msg(lfd->priority, "... %s", split);
		}
		sol = eol + 1;
		eol = strchr(sol, '\n');
	}

	if (sol < lfd->pos) { /* last character was not '\n' */
		if (lfd->pos - sol > LOGLINELEN) {
			split = sol + LOGLINELEN - 4;
			tmp_c  = *split;
			*split = 0;
			log_msg(lfd->priority, "%s ...", sol);
			sol = split -= 4;
			*split++ = '.'; *split++ = '.'; *split++ = '.';
			*split++ = ' '; *split = tmp_c;
		}
		eol = lfd->pos;
		lfd->pos = lfd->buf;
		while (sol < eol) {
			*lfd->pos++ = *sol++;
		}
	} else {
		lfd->pos = lfd->buf;
	}
}

/*
 * handler_zone2verifier feeds the zone to the verifiers standard input.
 */
struct zone2verifier_user_data {
	int to_stdin;
	FILE* to_stdin_f;
	struct state_pretty_rr* state;
	zone_type* zone;
	zone_iter_type iter;
};

static void
handle_zone2verifier( netio_type* netio
		    , netio_handler_type* handler
		    , netio_event_types_type event_types
		    )
{
	struct zone2verifier_user_data*  data
     = (struct zone2verifier_user_data*) handler->user_data;
	rr_type* rr;

	assert( data != NULL );

	if (! (event_types & NETIO_EVENT_WRITE)) {
		return;
	}

	rr = zone_iter_next(&data->iter, &data->zone);

	if (rr) {
		print_rr(data->to_stdin_f, data->state, rr);
	} else {
		fclose(data->to_stdin_f);
		data->to_stdin_f = NULL;

		close(data->to_stdin);
		data->to_stdin = -1;

		handler->user_data = NULL;
		netio_remove_handler(netio, handler);
	}
}

struct verifier_state_struct {
	zone_type*           zone;
	pid_t                pid;

	netio_handler_type             to_stdin_handler;
	struct zone2verifier_user_data to_stdin_user_data;

	netio_handler_type   from_stdout_handler;
	netio_handler_type   from_stderr_handler;
	struct log_from_fd_t lfdout;
	struct log_from_fd_t lfderr;

	struct timespec      timeout_spec;
	netio_handler_type   timeout_handler;
};
typedef struct verifier_state_struct verifier_state_type;

struct server_verify_zone_state_struct {
	region_type*        region;
	nsd_type*           nsd;
	netio_type*         netio;
	FILE*               df;
	verifier_state_type verifiers[];
};
typedef struct server_verify_zone_state_struct server_verify_zone_state_type;

static void
cleanup_verifier( netio_type* netio
		, verifier_state_type* v
		, int kill_verifier
		)
{
	assert( netio != NULL && v != NULL );

	if (v->lfderr.fd >= 0) {
		netio_remove_handler(netio, &v->from_stderr_handler);
		close(v->lfderr.fd);
	}
	if (v->lfdout.fd >= 0) {
		netio_remove_handler(netio, &v->from_stdout_handler);
		close(v->lfdout.fd);
	}
	if (v->to_stdin_user_data.to_stdin >= 0) {
		netio_remove_handler(netio, &v->to_stdin_handler);
		close(v->to_stdin_user_data.to_stdin);
	}
	if (v->to_stdin_user_data.to_stdin_f) {
		fclose(v->to_stdin_user_data.to_stdin_f);
	}
	if (v->timeout_spec.tv_sec > 0 || v->timeout_spec.tv_nsec > 0) {
		netio_remove_handler(netio, &v->timeout_handler);
	}
	if (kill_verifier && v->pid > 0) {
		if (kill(v->pid, SIGTERM) == -1) {
			log_msg( LOG_ERR
				, "could not kill verifier %d: %s"
				, v->pid
				, strerror(errno)
				);
		}

	}
	v->pid = -1;
	v->zone = NULL;
}

static void
handle_verifier_timeout( netio_type* netio
		       , netio_handler_type* handler
		       , netio_event_types_type event_types
		       )
{
	verifier_state_type* v = (verifier_state_type*) handler->user_data;

	assert( v != NULL );

	if (! (event_types & NETIO_EVENT_TIMEOUT)) {
		return;
	}

	log_msg( LOG_INFO
	       , "Timeout for verifier for zone %s with pid %d. Killing..."
	       , v->zone->opts->name
	       , v->pid
	       );

	if (kill(v->pid, SIGTERM) == -1) {
		log_msg( LOG_ERR
			, "could not kill verifier %d: %s"
			, v->pid
			, strerror(errno)
			);
	}
	v->timeout_spec.tv_nsec = 0;
	v->timeout_spec.tv_sec  = 0;

	netio_remove_handler(netio, &v->timeout_handler);
}


static void
verify_handle_parent_command( netio_type* netio
			    , netio_handler_type* handler
			    , netio_event_types_type event_types
			    )
{
	server_verify_zone_state_type*  s
     = (server_verify_zone_state_type*) handler->user_data;

	sig_atomic_t mode;
	int len;
	size_t i;

	assert( s != NULL );

	if (! (event_types & NETIO_EVENT_READ)) {
		return;
	}
	if ((len = read(handler->fd, &mode, sizeof(mode))) == -1) {
		log_msg( LOG_ERR
		       , "verifiers_handle_parent_command: read: %s"
		       , strerror(errno)
		       );
		return;
	}
	/* also exit when parent closed the connection (len == 0) */
	if (len == 0 || mode == NSD_QUIT) {

		/* kill all verifiers */

		for (i = 0; i < s->nsd->options->verifier_count; i++) {
			if (s->verifiers[i].zone) {
				cleanup_verifier(s->netio, &s->verifiers[i], 1);

			}
		}
		exit(0);

	} else {
		log_msg( LOG_ERR
		       , "verifiers_handle_parent_command: bad mode %d"
		       , (int) mode
		       );
	}
}

static void
verifier_revoke(server_verify_zone_state_type* s, verifier_state_type* v)
{
	write_commit_trail(  s->nsd->db->region
			  ,  s->nsd->options->difffile
			  , &s->df
			  ,  v->zone
			  ,  SURE_PART_BAD
			  );
}

static int
verifier_commit(server_verify_zone_state_type* s, verifier_state_type* v)
{
	log_msg( LOG_INFO
	       , "Zone %s verified successfully."
	       , v->zone->opts->name
	       );

	if (write_commit_trail(  s->nsd->db->region
			      ,  s->nsd->options->difffile
			      , &s->df
			      ,  v->zone
			      ,  SURE_PART_VERIFIED)) {
		return 1;
	} else {
		log_msg(  LOG_ERR
		       , "Zone %s did validate, but there was a problem "
			 "committing to that fact. Considering bad in stead."
		       , v->zone->opts->name
		       );

		return 0;
	}
}

static void 
server_verify_zone( server_verify_zone_state_type* s
		  , size_t* good_zones
		  , size_t* bad_zones
		  )
{
	pid_t exited;       /* the pid of the verifier that exited */
	int status, result; /* exit codes */

	size_t i;
	verifier_state_type* v;

        struct timespec timeout_spec;

	for (;;) {
		exited = waitpid(-1, &status, WNOHANG);
		if (exited > 0) {
			v = NULL;
			for (i = 0; i < s->nsd->options->verifier_count; i++) {

				if (s->verifiers[i].zone
				&&  s->verifiers[i].pid == exited) {

					v = &s->verifiers[i];
					break;
				}
			}
			if (v) {
				/* commit the zone if the status was ok */
				if (!WIFEXITED(status)) {

					log_msg( LOG_ERR
					       , "Zone verifier for zone %s "
					         "(pid %d) exited abnormally."
					       , v->zone->opts->name
					       , v->pid
					       ); 
					verifier_revoke(s, v);
					(*bad_zones)++;

				} else if ((result = WEXITSTATUS(status))) {

					log_msg( LOG_ERR
					       , "Zone verifier for zone %s "
					         "exited with status: %d"
					       , v->zone->opts->name
					       , result
					       ); 
					verifier_revoke(s, v);
					(*bad_zones)++;

				} else if (verifier_commit( s, v)) {
					(*good_zones)++;

				} else {
					(*bad_zones)++;
				}
				cleanup_verifier(s->netio, v, 0);

				return; /* slot available for next verifier */
			} else {
				log_msg( LOG_ERR
				       , "Expected verifier to exit, but"
				         "in stead an unknown child process, "
					 "with pid %d, exited with code %d."
				       , exited
				       , WEXITSTATUS(status)
				       );
			}

		} else if (exited == -1 && errno != EINTR) {
			log_msg(LOG_ERR, "wait failed: %s", strerror(errno));
		}

		timeout_spec.tv_sec  = 1;
		timeout_spec.tv_nsec = 0;
		if (netio_dispatch(s->netio, &timeout_spec, NULL) == -1
		&&  errno != EINTR) {
			log_msg( LOG_ERR
				, "server_verify_zone netio_dispatch failed: %s"
				, strerror(errno)
				);
			/* How to handle this error? */
		}
	}
}

static void
server_verifiers_add( server_verify_zone_state_type** state
		    , size_t* good_zones
		    , size_t* bad_zones
		    , nsd_type* nsd
		    , int cmdsocket
		    , zone_type* zone
		    )
{
	region_type* region = NULL;
	server_verify_zone_state_type* s = NULL; /* for convenience */
	FILE* df = NULL;
	size_t i;
	verifier_state_type* v = NULL;
	netio_handler_type* parent_handler = NULL;

	assert( state && good_zones && bad_zones && nsd && zone );

	/* May we run verifiers at all? */
	if (nsd->options->verifier_count <= 0) {
		goto error;
	}
	/* Initialize the verify zone state when needed */
	if ((s = *state) == NULL) {
		/* For easy disposal of everything we need */
		region = region_create(xalloc, free);
		if (! region) {
			goto error;
		}
		*state = (server_verify_zone_state_type*) 
			region_alloc( region
			            , sizeof(server_verify_zone_state_type)
				      /* 
				       * the struct has an array of 
				       * verifier_state_types at the end
				       */
				      + nsd->options->verifier_count
				        * sizeof(verifier_state_type)
				    );
		if (! *state) {
			goto error;
		}
		s = *state;
		if (! (s->netio = netio_create(region))) {
			goto error;
		} else {
			s->netio->have_current_time = 0;
		}
		s->region = region;
		s->nsd    = nsd;
		s->df     = NULL;
		/* mark verifier slots as available */
		for (i = 0; i < nsd->options->verifier_count; i++) {
			s->verifiers[i].zone = NULL;
		}

		/* and start serving the new zones */
		if (nsd->verify_ifs) {
			netio_add_udp_handlers( s->netio
					      , nsd
					      , region
					      , nsd->verify_udp
					      , nsd->verify_ifs
					      );
			netio_add_tcp_handlers( s->netio
					      , nsd
					      , region
					      , nsd->verify_tcp
					      , nsd->verify_ifs
					      );
		}

		/* parent may send us the NSD_QUIT command */

		parent_handler = REGION_MALLOC(region, netio_handler_type);
		parent_handler->fd = cmdsocket;
		parent_handler->timeout = NULL;
		parent_handler->user_data = s;
		parent_handler->event_types = NETIO_EVENT_READ;
		parent_handler->event_handler = verify_handle_parent_command;

		netio_add_handler(s->netio, parent_handler);

	}
	/* find first available verifier slot */
	for (i = 0; i < nsd->options->verifier_count; i++) {
		if (s->verifiers[i].zone == NULL) {
			v = &s->verifiers[i];
			break;
		}
	}
	/* because we wait when all verifier slots are filled, 
	 * at least one has to be available
	 */
	assert( v != NULL );

	/* startup the verifier initializing the filehandles to the process. */
	v->pid = nsd_popen3( zone->opts->verifier
			   , &v->to_stdin_user_data.to_stdin
			   , &v->lfdout.fd
			   , &v->lfderr.fd
			   , nsd
			   , zone
			   );

	if (v->pid == -1) {
		goto error;
	}
	v->zone = zone;
	/* will we feed the zone on stdin? */
	if (zone->opts->verifier_feed_zone == 1
	|| (     zone->opts->verifier_feed_zone == 2 
	    && nsd->options->verifier_feed_zone == 1)) {

		v->to_stdin_user_data.state = create_pretty_rr(s->region);
		v->to_stdin_user_data.to_stdin_f 
			  = fdopen(v->to_stdin_user_data.to_stdin, "w");
		setbuf(v->to_stdin_user_data.to_stdin_f, NULL);
		v->to_stdin_user_data.zone  = zone;

		/* v->to_stdin_user_data.iter will be automatically initialized
		 * by zone_iter_next usage.
		 */

		v->to_stdin_handler.fd = v->to_stdin_user_data.to_stdin;
		v->to_stdin_handler.user_data     = &v->to_stdin_user_data;
		v->to_stdin_handler.event_types   =  NETIO_EVENT_WRITE;
		v->to_stdin_handler.event_handler = &handle_zone2verifier;
		v->to_stdin_handler.timeout       =  NULL;

		netio_add_handler(s->netio, &v->to_stdin_handler);
	} else {
		/* No zone feeding. Close stdin for the verifier */
		close(v->to_stdin_user_data.to_stdin);
		v->to_stdin_user_data.to_stdin = -1;
		v->to_stdin_user_data.state = NULL;
		v->to_stdin_user_data.to_stdin_f = NULL;
		v->to_stdin_user_data.zone = NULL;
	}

	/* But we always log stdout and stderr */

	v->lfdout.priority                   =  LOG_INFO;
       *v->lfdout.buf                        =  0;
	v->lfdout.pos                        =  v->lfdout.buf;
	v->from_stdout_handler.fd            =  v->lfdout.fd;
	v->from_stdout_handler.user_data     = &v->lfdout;
	v->from_stdout_handler.event_types   =  NETIO_EVENT_READ;
	v->from_stdout_handler.event_handler = &handle_log_from_fd;
	v->from_stdout_handler.timeout       =  NULL;

	netio_add_handler(s->netio, &v->from_stdout_handler);

	v->lfderr.priority                   =  LOG_ERR;
       *v->lfderr.buf                        =  0;
	v->lfderr.pos                        =  v->lfderr.buf;
	v->from_stderr_handler.fd            =  v->lfderr.fd;
	v->from_stderr_handler.user_data     = &v->lfderr;
	v->from_stderr_handler.event_types   =  NETIO_EVENT_READ;
	v->from_stderr_handler.event_handler = &handle_log_from_fd;
	v->from_stderr_handler.timeout       =  NULL;

	netio_add_handler(s->netio, &v->from_stderr_handler);

	/* how long may this verifier take? */
	
	v->timeout_spec.tv_nsec = 0;
	v->timeout_spec.tv_sec  =   v->zone->opts->verifier_timeout >= 0
				  ? v->zone->opts->verifier_timeout
				  : s->nsd->options->verifier_timeout;

	if (v->timeout_spec.tv_sec > 0) {
		log_msg( LOG_INFO
		       , "Verifier should take no longer than %d seconds."
		       , (int) v->timeout_spec.tv_sec
		       );
		v->timeout_handler.fd            = -1;
		v->timeout_handler.user_data     =  v;
		v->timeout_handler.event_types   =  NETIO_EVENT_TIMEOUT;
		v->timeout_handler.event_handler = &handle_verifier_timeout;
		v->timeout_handler.timeout       = &v->timeout_spec;
		timespec_add( v->timeout_handler.timeout
			    , netio_current_time(s->netio)
			    );

		netio_add_handler(s->netio, &v->timeout_handler);
	}

	/* More slots available? Then return so more zones can be added. */
	for (i = 0; i < nsd->options->verifier_count; i++) {
		if (s->verifiers[i].zone == NULL) {
			return;
		}
	}

	/* Otherwise start serving until a verifier finishes and a 
	 * slot becomes available again.
	 */
	server_verify_zone(s, good_zones, bad_zones);
	return;
error:
	if (s && s->region) {
		region = s->region;
	}
	if (region) {
		region_destroy(region);
	}
	*state = NULL;
	write_commit_trail( nsd->db->region
			  , nsd->options->difffile
			  , &df
			  , zone
			  , SURE_PART_BAD
			  );
	(*bad_zones)++;
	if (df) {
		fclose(df);
	}
	return;
}

static void
server_verifiers_wait( server_verify_zone_state_type** state
		     , size_t* good_zones
		     , size_t* bad_zones
		)
{
	server_verify_zone_state_type* s = NULL;
	size_t i;

	assert( state && good_zones && bad_zones );

	if ((s = *state) != NULL) {
wait:
		for (i = 0; i < s->nsd->options->verifier_count; i++) {
			if (s->verifiers[i].zone) {
				server_verify_zone(s, good_zones, bad_zones);
				goto wait;
			}
		}
		if (s->df) {
			fclose(s->df);
		}
		if (s->region) {
			region_destroy(s->region);
		}
		*state = NULL;
	}
}

void
verify_zones( nsd_type* nsd
	    , int cmdsocket
	    , size_t* good_zones
	    , size_t* bad_zones
	    )
{
	/* The verifiers_state will be allocated by server_verifiers_add
	* only when verifiers are spawn and the state is needed to keep track.
	*/
	server_verify_zone_state_type* verifiers_state = NULL;
	zone_type* zone;

	/* 
	 * Assess updated zones that have a verifier program.
	 */
	*good_zones = *bad_zones = 0;
	for(zone = nsd->db->zones; zone; zone = zone->next) {
		if ( zone->updated == 0) continue;

		/* Zone updates that are already verified will have 
		 * SURE_PART_VERIFIED at the commit positions and will not
		 * leave a commit trail. A commit trail is only build with 
		 * SURE_PART_UNVERIFIED statusses when a verifier is configured
		 * for the zone.
		 */
		if (! zone->commit_trail || ! zone->soa_rrset) {
			good_zones++;
			continue;
		}

		log_msg( LOG_INFO
		       , "Zone %s has changed."
		       , zone->opts->name
		       );
		server_verifiers_add( &verifiers_state
				    ,  good_zones
				    ,  bad_zones
				    ,  nsd
				    ,  cmdsocket
				    ,  zone
				    );
        }
	server_verifiers_wait(&verifiers_state, good_zones, bad_zones);
}

