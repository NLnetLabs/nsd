/*
 * plugins.h -- set of routines to manage plugins.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _PLUGINS_H_
#define _PLUGINS_H_

#ifdef PLUGINS

#include "nsd-plugin.h"

extern nsd_plugin_id_type maximum_plugin_count;

void plugin_init(struct nsd *nsd);
int plugin_load(struct nsd *nsd, const char *name, const char *arg);
void plugin_finalize_all(void);
nsd_plugin_callback_result_type plugin_database_reloaded(void);

nsd_plugin_callback_result_type query_received_callbacks(
	nsd_plugin_callback_args_type *args,
	void **data);
nsd_plugin_callback_result_type query_processed_callbacks(
	nsd_plugin_callback_args_type *args,
	void **data);
query_state_type handle_callback_result(
	nsd_plugin_callback_result_type result,
	nsd_plugin_callback_args_type *args);

#endif /* PLUGINS */

#endif /* _PLUGINS_H_ */
