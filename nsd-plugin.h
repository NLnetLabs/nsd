/*
 * $Id: nsd-plugin.h,v 1.2 2003/06/26 12:51:37 erik Exp $
 *
 * nsd-plugin.h -- interface to NSD for a plugin.
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

#ifndef _NSD_PLUGIN_H_
#define _NSD_PLUGIN_H_

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "nsd.h"
#include "namedb.h"
#include "query.h"

#ifndef PLUGINS
#error "Plugin support not enabled."
#endif

/*
 * The version of the plugin interface.
 */
#define NSD_PLUGIN_INTERFACE_VERSION 1

/*
 * Every plugin is assigned a unique id when loaded.  If a single
 * plugin is loaded multiple times it will have multiple unique ids.
 */
typedef unsigned nsd_plugin_id_type;


/*
 * NSD provides specific callbacks that a plugin can hook into.
 * Currently there are three defined callbacks.
 */
enum nsd_plugin_callback_id
{
	/*
	 * Called right after a query has been received but before
	 * being NSD does _any_ processing.
	 */
	NSD_PLUGIN_QUERY_RECEIVED,

	/*
	 * Called right after the answer has been constructed but
	 * before it has been send to the client.
	 */
	NSD_PLUGIN_QUERY_PROCESSED,

	NSD_PLUGIN_CALLBACK_ID_COUNT
};
typedef enum nsd_plugin_callback_id nsd_plugin_callback_id_type;


/*
 * A plugin can control how further processing should be done after
 * returning from a callback.
 */
enum nsd_plugin_callback_result
{
	/*
	 * Continue processing, everything is ok.
	 */
	NSD_PLUGIN_CONTINUE,
	
	/*
	 * Send the current answer to the client without further
	 * processing.
	 */
	NSD_PLUGIN_ANSWER,
	
	/*
	 * Plugin failed.  Return an error to the client.  The error
	 * code must be in the result_code field of the
	 * nsd_plugin_callback_args_type structure.
	 */
	NSD_PLUGIN_ERROR,
	
	/*
	 * Abandon client request (no answer is send at all).
	 */
	NSD_PLUGIN_ABANDON
	
};
typedef enum nsd_plugin_callback_result nsd_plugin_callback_result_type;


/*
 * Arguments passed to a plugin callback.
 */
struct nsd_plugin_callback_args
{
	/* Always non-NULL.  */
	struct query        *query;
	
	/*
	 * NULL for the NSD_PLUGIN_QUERY_RECEIVED callback.  This is
	 * the normalized domain name.  DOMAIN_NAME points to the
	 * start of the first label.
	 */
	const u_char        *domain_name;

	/*
	 * NULL for the NSD_PLUGIN_QUERY_RECEIVED callback and for plugins
	 * that have not registered any data for the domain_name.
	 */
	void                *data;

	/*
	 * Set this if the callback returns NSD_PLUGIN_ERROR.
	 */
	int                  result_code;
};
typedef struct nsd_plugin_callback_args nsd_plugin_callback_args_type;


/*
 * The type of a plugin callback function.
 */
typedef nsd_plugin_callback_result_type (*nsd_plugin_callback_type)(
	struct nsd                    *nsd,
	nsd_plugin_id_type             plugin_id,
	nsd_plugin_callback_id_type    callback_id,
	nsd_plugin_callback_args_type *args);


/*
 * The interface provided by NSD to plugins.
 */
struct nsd_plugin_interface
{
	/*
	 * Register a callback.
	 */
	int (*register_callback)(
		struct nsd                 *nsd,
		nsd_plugin_id_type          plugin_id,
		nsd_plugin_callback_id_type callback_id,
		nsd_plugin_callback_type    callback_function);

	/*
	 * Register plugin specific data for the specified
	 * domain_name.
	 */
	int (*register_data)(
		struct nsd        *nsd,
		nsd_plugin_id_type plugin_id,
		const u_char *     domain_name,
		void *             data);
};
typedef struct nsd_plugin_interface nsd_plugin_interface_type;


/*
 * Human readable descriptor for a plugin.
 */
struct nsd_plugin_descriptor
{
	const char *name;
	const char *version;
};
typedef struct nsd_plugin_descriptor nsd_plugin_descriptor_type;


typedef const nsd_plugin_descriptor_type *(nsd_plugin_init_type)(
	struct nsd *nsd,
	nsd_plugin_id_type plugin_id,
	const nsd_plugin_interface_type *interface,
	const char *arg);


/*
 * The following function must be defined by the plugin.  It is called
 * by NSD when the plugin is loaded.  Return NULL if the plugin cannot
 * be initialized.
 */
#define PASTE2(x, y) x##y
#define PASTE(x, y) PASTE2(x, y)
extern nsd_plugin_init_type PASTE(nsd_plugin_init_, NSD_PLUGIN_INTERFACE_VERSION);
#undef PASTE
#undef PASTE2

#endif /* _PLUGINS_H_ */
