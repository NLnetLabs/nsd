/*
 * Example plugin for NSD.
 *
 * Compile with something like:
 *
 *   gcc -shared -Insd-src-dir example-plugin.c -o example-plugin.so
 *
 */

#include <nsd-plugin.h>

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>

static nsd_plugin_callback_result_type reload(
	const nsd_plugin_interface_type *nsd,
	nsd_plugin_id_type id);
static nsd_plugin_callback_type query_received;
static nsd_plugin_callback_type query_processed;

static
void finalize(const nsd_plugin_interface_type *nsd, nsd_plugin_id_type id)
{
	syslog(LOG_NOTICE, "finalizing plugin");
}

/*
 * Define the plugin descriptor.
 */
static nsd_plugin_descriptor_type descriptor = {
	"Example plugin",
	"0.1",
	finalize,
	reload,
	query_received,
	query_processed
};

const nsd_plugin_descriptor_type *
NSD_PLUGIN_INIT(const nsd_plugin_interface_type *nsd,
		nsd_plugin_id_type id,
                const char *arg)
{
	syslog(LOG_NOTICE, "Example plugin initializing (arg = %s)", arg);

	if (reload(nsd, id) != NSD_PLUGIN_CONTINUE) {
		return NULL;
	} else {
		return &descriptor;
	}
}

static nsd_plugin_callback_result_type
reload(const nsd_plugin_interface_type *nsd,
       nsd_plugin_id_type id)
{
	syslog(LOG_NOTICE, "registering data");
	if (!nsd->register_data(nsd, id, "\004\002nl", "hello, world!"))
	{
		syslog(LOG_ERR, "Failed to register data");
		return NSD_PLUGIN_ERROR;
	} else {
		return NSD_PLUGIN_CONTINUE;
	}
}


static nsd_plugin_callback_result_type
query_received(
	const nsd_plugin_interface_type *nsd,
	nsd_plugin_id_type               id,
	nsd_plugin_callback_args_type   *args)
{
	switch (fork()) {
	case -1:
		/* error */
		syslog(LOG_ERR, "Plugin fork failed: %m");
		return NSD_PLUGIN_ABANDON;
	case 0:
		/* child */
		syslog(LOG_NOTICE, "Plugin forked child");
		exit(0);
	default:
		/* parent */
		return NSD_PLUGIN_CONTINUE;
	}
}

static nsd_plugin_callback_result_type
query_processed(
	const nsd_plugin_interface_type *nsd,
	nsd_plugin_id_type               id,
	nsd_plugin_callback_args_type   *args)
{
	if (args->data) {
		syslog(LOG_NOTICE, "Received query with plugin data %s", (char *) args->data);
		args->result_code = RCODE_FORMAT;
		return NSD_PLUGIN_ERROR;
	} else {
		syslog(LOG_NOTICE, "Received query without plugin data");
		return NSD_PLUGIN_CONTINUE;
	}
}
