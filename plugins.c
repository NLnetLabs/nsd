/*
 * plugins.c -- set or routines to manage plugins.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2003, NLnet Labs. All rights reserved.
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
#include <syslog.h>

#include "namedb.h"
#include "plugins.h"

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
	struct nsd        *nsd,
	nsd_plugin_id_type plugin_id,
	const u_char *     domain_name,
	void *             data)
{
	struct domain *d;

	assert(plugin_id < maximum_plugin_count);
	assert(domain_name);

	d = namedb_lookup(nsd->db, domain_name);
	if (d) {
		void **plugin_data;
		if (!d->runtime_data) {
			d->runtime_data = xalloc(maximum_plugin_count * sizeof(void *));
			memset(d->runtime_data, 0, maximum_plugin_count * sizeof(void *));
		}
		plugin_data = (void **) d->runtime_data;
		plugin_data[plugin_id] = data;
		return 1;
	} else {
		return 0;
	}
}

static nsd_plugin_interface_type plugin_interface = {
	register_data
};

#define STR2(x) #x
#define STR(x) STR2(x)
int
load_plugin(struct nsd *nsd, const char *name, const char *arg)
{
	struct nsd_plugin *plugin;
	nsd_plugin_init_type *init;
	void *handle;
	const char *error;
	const char *init_name = "nsd_plugin_init_" STR(NSD_PLUGIN_INTERFACE_VERSION);
	const nsd_plugin_descriptor_type *descriptor;
		
	dlerror();		/* Discard previous errors (FreeBSD hack).  */
	
	handle = dlopen(name, RTLD_NOW);
	error = dlerror();
	if (error) {
		syslog(LOG_ERR, "failed to load plugin: %s", error);
		return 0;
	}

	init = dlsym(handle, init_name);
	error = dlerror();
	if (error) {
		syslog(LOG_ERR, "no plugin init function: %s", error);
		dlclose(handle);
		return 0;
	}

	descriptor = init(nsd, plugin_count, &plugin_interface, arg);
	if (!descriptor) {
		syslog(LOG_ERR, "plugin initialization failed");
		dlclose(handle);
		return 0;
	}

	plugin = xalloc(sizeof(struct nsd_plugin));
	plugin->next = NULL;
	plugin->handle = handle;
	plugin->id = plugin_count;
	plugin->descriptor = descriptor;

	assert(*last_plugin == NULL);
	*last_plugin = plugin;
	last_plugin = &plugin->next;
	assert(*last_plugin == NULL);

	++plugin_count;
	
	syslog(LOG_INFO, "Plugin %s %s loaded", descriptor->name, descriptor->version);
	
	return 1;
}

#define MAKE_PERFORM_CALLBACKS(function_name, callback_name)		\
nsd_plugin_callback_result_type						\
function_name(								\
	struct nsd *nsd,						\
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
			result = callback(nsd, plugin->id, args);	\
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

int
handle_callback_result(
	struct nsd *nsd,
	nsd_plugin_callback_result_type result,
	nsd_plugin_callback_args_type *args)
{
	switch (result) {
	case NSD_PLUGIN_CONTINUE:
	case NSD_PLUGIN_ANSWER:
		return 0;
	case NSD_PLUGIN_ERROR:
		query_error(args->query, args->result_code);
		return 0;
	case NSD_PLUGIN_ABANDON:
		return -1;
	default:
		/* XXX bad callback result code */
		abort();
	}
}

#endif /* PLUGINS */
