/*
 * plugins.c -- set of routines to manage plugins.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2003-2004, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
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
 *
 */

#include <config.h>

#ifdef PLUGINS

#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>

#include "namedb.h"
#include "plugins.h"
#include "util.h"

nsd_plugin_id_type maximum_plugin_count = 0;
static nsd_plugin_id_type plugin_count = 0;

struct nsd_plugin
{
	struct nsd_plugin *next;
	void *handle;
	nsd_plugin_id_type id;
	const nsd_plugin_descriptor_type *descriptor;
};
typedef struct nsd_plugin nsd_plugin_type;

static nsd_plugin_type *first_plugin = NULL;
static nsd_plugin_type **last_plugin = &first_plugin;

static int
register_data(
	const nsd_plugin_interface_type *nsd,
	nsd_plugin_id_type               plugin_id,
	const dname_type *               domain_name,
	void *                           data)
{
	domain_type *domain;
	
	assert(plugin_id < maximum_plugin_count);
	assert(domain_name);

	domain = domain_table_find(nsd->nsd->db->domains, domain_name);
	if (!domain)
		return 0;

	if (!domain->plugin_data) {
		domain->plugin_data
			= (void **) region_alloc_zero(
				nsd->nsd->db->region,
				maximum_plugin_count * sizeof(void *));
	}
	domain->plugin_data[plugin_id] = data;
	
	return 1;
}

static nsd_plugin_interface_type plugin_interface;

void
plugin_init(struct nsd *nsd)
{
	plugin_interface.nsd = nsd;
	plugin_interface.root_dname = dname_make(nsd->region, (const uint8_t *) "");
	plugin_interface.register_data = register_data;
	plugin_interface.log_msg = log_msg;
	plugin_interface.xalloc = xalloc;
	plugin_interface.xrealloc = xrealloc;
	plugin_interface.free = free;
	plugin_interface.region_create = region_create;
	plugin_interface.region_destroy = region_destroy;
	plugin_interface.region_alloc = region_alloc;
	plugin_interface.region_free_all = region_free_all;
	plugin_interface.dname_parse = dname_parse;
	plugin_interface.dname_to_string = dname_to_string;
}

#define STR2(x) #x
#define STR(x) STR2(x)
int
plugin_load(struct nsd *nsd, const char *name, const char *arg)
{
	struct nsd_plugin *plugin;
	nsd_plugin_init_type *init;
	void *handle;
	const char *error;
	const char *init_name = STR(NSD_PLUGIN_INIT);
	const nsd_plugin_descriptor_type *descriptor;

	dlerror();		/* Discard previous errors (FreeBSD hack).  */
	
	handle = dlopen(name, RTLD_NOW);
	error = dlerror();
	if (error) {
		log_msg(LOG_ERR, "failed to load plugin: %s", error);
		return 0;
	}

	init = (nsd_plugin_init_type *) dlsym(handle, init_name);
	error = dlerror();
	if (error) {
		log_msg(LOG_ERR, "no plugin init function: %s", error);
		dlclose(handle);
		return 0;
	}

	descriptor = init(&plugin_interface, plugin_count, arg);
	if (!descriptor) {
		log_msg(LOG_ERR, "plugin initialization failed");
		dlclose(handle);
		return 0;
	}

	plugin = (nsd_plugin_type *) region_alloc(nsd->region,
					     sizeof(struct nsd_plugin));
	plugin->next = NULL;
	plugin->handle = handle;
	plugin->id = plugin_count;
	plugin->descriptor = descriptor;

	assert(*last_plugin == NULL);
	*last_plugin = plugin;
	last_plugin = &plugin->next;
	assert(*last_plugin == NULL);

	++plugin_count;
	
	log_msg(LOG_INFO, "Plugin %s %s loaded", descriptor->name, descriptor->version);
	
	return 1;
}

void
plugin_finalize_all(void)
{
	nsd_plugin_type *plugin;
	nsd_plugin_type *next;

	plugin = first_plugin;
	while (plugin) {
		if (plugin->descriptor->finalize) {
			plugin->descriptor->finalize(&plugin_interface,
						     plugin->id);
		}
		dlclose(plugin->handle);
		next = plugin->next;
		free(plugin);
		plugin = next;
	}
}

nsd_plugin_callback_result_type
plugin_database_reloaded(void)
{
	nsd_plugin_callback_result_type rc;
	nsd_plugin_type *plugin;

	for (plugin = first_plugin; plugin; plugin = plugin->next) {
		if (plugin->descriptor->reload) {
			rc = plugin->descriptor->reload(&plugin_interface,
							plugin->id);
			if (rc != NSD_PLUGIN_CONTINUE)
				return rc;
		}
	}
	return NSD_PLUGIN_CONTINUE;
}

#define MAKE_PERFORM_CALLBACKS(function_name, callback_name)		\
nsd_plugin_callback_result_type						\
function_name(								\
	nsd_plugin_callback_args_type *args,				\
	void **data)							\
{									\
	nsd_plugin_type *plugin;					\
	nsd_plugin_callback_type *callback;				\
	nsd_plugin_callback_result_type result;				\
									\
	args->data = NULL;						\
	for (plugin = first_plugin; plugin; plugin = plugin->next) {	\
		callback = plugin->descriptor->callback_name;		\
		if (callback) {						\
			if (data) {					\
				args->data = data[plugin->id];		\
			} else {					\
				args->data = NULL;			\
			}						\
			result = callback(&plugin_interface,		\
					  plugin->id, args);		\
			if (result != NSD_PLUGIN_CONTINUE) {		\
				return result;				\
			}						\
		}							\
	}								\
									\
	return NSD_PLUGIN_CONTINUE;					\
}

MAKE_PERFORM_CALLBACKS(query_received_callbacks, query_received)
MAKE_PERFORM_CALLBACKS(query_processed_callbacks, query_processed)

query_state_type
handle_callback_result(
	nsd_plugin_callback_result_type result,
	nsd_plugin_callback_args_type *args)
{
	switch (result) {
	case NSD_PLUGIN_CONTINUE:
	case NSD_PLUGIN_ANSWER:
		return QUERY_PROCESSED;
	case NSD_PLUGIN_ERROR:
		query_error(args->query, args->result_code);
		return QUERY_PROCESSED;
	case NSD_PLUGIN_ABANDON:
		return QUERY_DISCARDED;
	default:
		log_msg(LOG_WARNING, "bad callback result code %d from plugin",
			(int) result);
		return QUERY_DISCARDED;
	}
}

#endif /* PLUGINS */
