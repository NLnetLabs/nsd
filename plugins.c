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

nsd_plugin_id_type plugin_count = 0;
const nsd_plugin_descriptor_type *plugin_descriptors[MAX_PLUGIN_COUNT];
static void *plugin_handles[MAX_PLUGIN_COUNT];

static nsd_plugin_callback_type plugin_callbacks[MAX_PLUGIN_COUNT][NSD_PLUGIN_CALLBACK_ID_COUNT];

static int
register_callback(
	struct nsd                 *nsd,
	nsd_plugin_id_type          plugin_id,
	nsd_plugin_callback_id_type callback_id,
	nsd_plugin_callback_type    callback_function)
{
	assert(plugin_id < MAX_PLUGIN_COUNT);
	assert(callback_id < NSD_PLUGIN_CALLBACK_ID_COUNT);

	plugin_callbacks[plugin_id][callback_id] = callback_function;
	return 0;
}

static int
register_data(
	struct nsd        *nsd,
	nsd_plugin_id_type plugin_id,
	const u_char *     domain_name,
	void *             data)
{
	struct domain *d;

	assert(plugin_id < MAX_PLUGIN_COUNT);
	assert(domain_name);

	d = namedb_lookup(nsd->db, domain_name);
	if (d) {
		void **plugin_data;
		if (!d->runtime_data) {
			d->runtime_data = xalloc(MAX_PLUGIN_COUNT * sizeof(void *));
			memset(d->runtime_data, 0, MAX_PLUGIN_COUNT * sizeof(void *));
		}
		plugin_data = (void **) d->runtime_data;
		plugin_data[plugin_id] = data;
		return 1;
	} else {
		return 0;
	}
}

static nsd_plugin_interface_type plugin_interface = {
	register_callback,
	register_data
};

#define STR2(x) #x
#define STR(x) STR2(x)
int
load_plugin(struct nsd *nsd, const char *name, const char *arg)
{
	nsd_plugin_init_type *init;
	void *handle;
	const char *error;
	const char *init_name = "nsd_plugin_init_" STR(NSD_PLUGIN_INTERFACE_VERSION);
	const nsd_plugin_descriptor_type *descriptor;
		
	if (plugin_count == MAX_PLUGIN_COUNT) {
		syslog(LOG_ERR, "maximum number of plugins exceeded");
		return 0;
	}

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

	plugin_descriptors[plugin_count] = descriptor;
	plugin_handles[plugin_count] = handle;
	++plugin_count;

	syslog(LOG_INFO, "Plugin %s %s loaded", descriptor->name, descriptor->version);
	
	return 1;
}

nsd_plugin_callback_result_type
perform_callbacks(
	struct nsd *nsd,
	nsd_plugin_callback_id_type callback_id,
	nsd_plugin_callback_args_type *args,
	void *data[MAX_PLUGIN_COUNT])
{
	nsd_plugin_id_type plugin_id;
	nsd_plugin_callback_type callback;
	nsd_plugin_callback_result_type result;

	args->data = NULL;
	for (plugin_id = 0; plugin_id < plugin_count; ++plugin_id) {
		callback = plugin_callbacks[plugin_id][callback_id];
		if (callback) {
			if (data) {
				args->data = data[plugin_id];
			}
			result = callback(nsd, plugin_id, callback_id, args);
			if (result != NSD_PLUGIN_CONTINUE) {
				return result;
			}
		}
	}

	return NSD_PLUGIN_CONTINUE;
}

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
