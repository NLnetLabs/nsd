/*
 * metrics.h -- prometheus metrics endpoint
 *
 * Copyright (c) 2001-2025, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef DAEMON_METRICS_H
#define DAEMON_METRICS_H

struct xfrd_state;
struct nsd_options;
struct daemon_metrics;

/* the metrics daemon needs little backlog */
#define TCP_BACKLOG_METRICS 16 /* listen() tcp backlog */

/**
 * Create new metrics endpoint for the daemon.
 * @param cfg: config.
 * @return new state, or NULL on failure.
 */
struct daemon_metrics* daemon_metrics_create(struct nsd_options* cfg);

/**
 * Delete metrics daemon and close HTTP listeners.
 * @param m: daemon to delete.
 */
void daemon_metrics_delete(struct daemon_metrics* m);

/**
 * Close metrics HTTP listener ports.
 * Does not delete the object itself.
 * @param m: state to close.
 */
void daemon_metrics_close(struct daemon_metrics* m);

/**
 * Open and create HTTP listeners for metrics daemon.
 * @param m: metrics state that contains list of accept sockets.
 * @param cfg: config options.
 * @return false on failure.
 */
int daemon_metrics_open_ports(struct daemon_metrics* m,
	struct nsd_options* cfg);

/**
 * Setup HTTP listener.
 * @param m: state
 * @param xfrd: the process that hosts the daemon.
 *	m's HTTP listener is attached to its event base.
 */
void daemon_metrics_attach(struct daemon_metrics* m, struct xfrd_state* xfrd);

#endif /* DAEMON_METRICS_H */
