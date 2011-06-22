/*
 * remote.h - remote control for the NSD daemon.
 *
 * Copyright (c) 2008, NLnet Labs. All rights reserved.
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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * This file contains the remote control functionality for the daemon.
 * The remote control can be performed using either the commandline
 * nsd-control tool, or a SSLv3/TLS capable web browser. 
 * The channel is secured using SSLv3 or TLSv1, and certificates.
 * Both the server and the client(control tool) have their own keys.
 */

#ifndef DAEMON_REMOTE_H
#define DAEMON_REMOTE_H
struct xfrd_state;
struct nsd_options;

/* private, defined in remote.c to keep ssl.h out of this header */
struct daemon_remote;
struct rc_state;

/**
 * Create new remote control state for the daemon.
 * Also setups the control port.
 * @param cfg: config file with key file settings.
 * @return new state, or NULL on failure.
 */
struct daemon_remote* daemon_remote_create(struct nsd_options* cfg);

/**
 * remote control state to delete.
 * @param rc: state to delete.
 */
void daemon_remote_delete(struct daemon_remote* rc);

/**
 * Close remote control ports.  Clears up busy connections.
 * Does not delete the rc itself, or the ssl context (with its keys).
 * @param rc: state to close.
 */
void daemon_remote_close(struct daemon_remote* rc);

/**
 * Open and create listening ports for remote control.
 * @param rc: rc state that contains list of accept port sockets.
 * @param cfg: config options.
 * @return false on failure.
 */
int daemon_remote_open_ports(struct daemon_remote* rc,
	struct nsd_options* cfg);

#if 0 /* TODO */
/**
 * Setup comm points for accepting remote control connections.
 * @param rc: state
 * @param ports: already opened ports.
 * @param worker: worker with communication base. and links to command channels.
 * @return false on error.
 */
int daemon_remote_open_accept(struct daemon_remote* rc, 
	struct listen_port* ports, struct worker* worker);

/**
 * Handle nonthreaded remote cmd execution.
 * @param worker: this worker (the remote worker).
 */
void daemon_remote_exec(struct worker* worker);

/** handle remote control accept callbacks */
int remote_accept_callback(struct comm_point*, void*, int, struct comm_reply*);

/** handle remote control data callbacks */
int remote_control_callback(struct comm_point*, void*, int, struct comm_reply*);

/** routine to printout option values over SSL */
void remote_get_opt_ssl(char* line, void* arg);
#endif /* TODO */

#endif /* DAEMON_REMOTE_H */
