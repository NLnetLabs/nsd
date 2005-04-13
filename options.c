/*
 * options.c -- maintain NSD configuration information.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include "options.h"

#include <assert.h>
#include <libxml/parser.h>
#include <libxml/relaxng.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <string.h>
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "nsd.h"
#include "util.h"

/*
 * Validates OPTIONS_DOC against the RelaxNG SCHEMA_DOC.  Returns
 * non-zero on success, zero on failure.
 */
static int validate_config(xmlDocPtr schema_doc, xmlDocPtr options_doc);

static const char *lookup_text(region_type *region,
			       xmlXPathContextPtr context,
			       const char *expr);
static int lookup_integer(xmlXPathContextPtr context,
			  const char *expr,
			  int default_value);

static nsd_options_address_type *parse_address(region_type *region,
					       xmlNodePtr address_node);
static nsd_options_key_type *parse_key(region_type *region,
				       xmlNodePtr key_node);

static int parse_listen_on_addresses(nsd_options_type *options,
				     xmlXPathContextPtr context);
static int parse_controls_addresses(nsd_options_type *options,
				    xmlXPathContextPtr context);
static int parse_keys(nsd_options_type *options, xmlXPathContextPtr context);
static int parse_zones(nsd_options_type *options, xmlXPathContextPtr context);


/*
 * Load the NSD configuration from FILENAME.
 */
nsd_options_type *
nsd_load_config(region_type *region, const char *filename)
{
	xmlDocPtr schema_doc = NULL;
	xmlDocPtr options_doc = NULL;
	xmlXPathContextPtr xpath_context = NULL;
	nsd_options_type *options = NULL;
	nsd_options_type *result = NULL;

	assert(filename);

	xmlLineNumbersDefault(1);

	schema_doc = xmlParseFile(DATADIR "/nsd.rng");
	if (!schema_doc) {
		log_msg(LOG_WARNING, "cannot parse XML schema '%s', "
			"configuration file will not be validated",
			DATADIR "/nsd.rng");
	}

	options_doc = xmlParseFile(filename);
	if (!options_doc) {
		log_msg(LOG_ERR, "cannot parse NSD configuration '%s'",
			filename);
		goto exit;
	}

	if (schema_doc && options_doc) {
		if (!validate_config(schema_doc, options_doc)) {
			goto exit;
		} else {
			log_msg(LOG_INFO,
				"nsd configuration successfully validated");
		}
	}

	xpath_context = xmlXPathNewContext(options_doc);
	if (!xpath_context) {
		log_msg(LOG_ERR, "cannot create XPath context");
		goto exit;
	}

	options = region_alloc(region, sizeof(nsd_options_type));
	options->region = region;
	options->user_id = lookup_text(region, xpath_context,
				       "/nsd/options/user-id/text()");
	options->database = lookup_text(region, xpath_context,
				       "/nsd/options/database/text()");
	options->version = lookup_text(region, xpath_context,
				       "/nsd/options/version/text()");
	options->identity = lookup_text(region, xpath_context,
					"/nsd/options/identity/text()");
	options->directory = lookup_text(region, xpath_context,
					 "/nsd/options/directory/text()");
	options->chroot_directory = lookup_text(
		region, xpath_context, "/nsd/options/chroot-directory/text()");
	options->log_file = lookup_text(region, xpath_context,
					"/nsd/options/log-file/text()");
	options->pid_file = lookup_text(region, xpath_context,
					"/nsd/options/pid-file/text()");
	options->statistics_period = lookup_integer(
		xpath_context, "/nsd/options/statistics-period/text()", 0);
	options->server_count = lookup_integer(
		xpath_context, "/nsd/options/server-count/text()", 1);
	options->maximum_tcp_connection_count = lookup_integer(
		xpath_context,
		"/nsd/options/maximum-tcp-connection-count/text()",
		10);
	options->listen_on_count = 0;
	options->listen_on = NULL;
	options->controls_count = 0;
	options->controls = NULL;
	options->key_count = 0;
	options->keys = NULL;
	options->zone_count = 0;
	options->zones = NULL;

	if (!parse_listen_on_addresses(options, xpath_context)) {
		goto exit;
	}
	if (!parse_controls_addresses(options, xpath_context)) {
		goto exit;
	}
	if (!parse_keys(options, xpath_context)) {
		goto exit;
	}
	if (!parse_zones(options, xpath_context)) {
		goto exit;
	}

	result = options;
exit:
	xmlXPathFreeContext(xpath_context);
	xmlFreeDoc(schema_doc);
	xmlFreeDoc(options_doc);

	return result;
}


static int
validate_config(xmlDocPtr schema_doc, xmlDocPtr options_doc)
{
	xmlRelaxNGParserCtxtPtr schema_parser_ctxt = NULL;
	xmlRelaxNGPtr schema = NULL;
	xmlRelaxNGValidCtxtPtr schema_validator_ctxt = NULL;
	int valid;
	int result = 0;

	schema_parser_ctxt = xmlRelaxNGNewDocParserCtxt(schema_doc);
	if (!schema_parser_ctxt) {
		log_msg(LOG_ERR, "cannot create RelaxNG validation schema");
		goto exit;
	}

	schema = xmlRelaxNGParse(schema_parser_ctxt);
	if (!schema) {
		log_msg(LOG_ERR, "cannot parse RelaxNG schema");
		goto exit;
	}

	schema_validator_ctxt = xmlRelaxNGNewValidCtxt(schema);
	if (!schema_validator_ctxt) {
		log_msg(LOG_ERR, "cannot create RelaxNG validator");
		goto exit;
	}

	valid = xmlRelaxNGValidateDoc(schema_validator_ctxt, options_doc);
	if (valid == -1) {
		log_msg(LOG_ERR, "error while validating");
	} else if (valid == 0) {
		result = 1;
	} else {
		result = 0;
	}

exit:
	xmlRelaxNGFreeValidCtxt(schema_validator_ctxt);
	xmlRelaxNGFree(schema);
	xmlRelaxNGFreeParserCtxt(schema_parser_ctxt);

	return result;
}

static const char *
lookup_text(region_type *region,
	    xmlXPathContextPtr context,
	    const char *expr)
{
	xmlXPathObjectPtr object = NULL;
	const char *result = NULL;

	assert(context);
	assert(expr);

	object = xmlXPathEvalExpression((const xmlChar *) expr, context);
	if (!object) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			(const char *) expr);
		goto exit;
	}

	if (!object->nodesetval) {
		/* Option not specified, return NULL.  */
	} else if (object->nodesetval->nodeNr == 0) {
		/* Empty option, return empty string.  */
		result = "";
	} else if (object->nodesetval->nodeNr == 1) {
		xmlNodePtr node = object->nodesetval->nodeTab[0];
		if (node->type != XML_TEXT_NODE) {
			log_msg(LOG_ERR,
				"xpath expression '%s' did not evaluate to a "
				"text node",
				(const char *) expr);
		} else {
			xmlChar *content = xmlNodeGetContent(node);
			if (content) {
				result = region_strdup(region,
						       (const char *) content);
				xmlFree(content);
			}
		}
	} else {
		log_msg(LOG_ERR,
			"xpath expression '%s' returned multiple results",
			(const char *) expr);
	}

exit:
	xmlXPathFreeObject(object);
	return result;
}

static int
lookup_integer(xmlXPathContextPtr context,
	       const char *expr,
	       int default_value)
{
	region_type *temp = region_create(xalloc, free);
	const char *text = lookup_text(temp, context, expr);
	int result = default_value;

	if (text) {
		result = atoi(text);
	}

	region_destroy(temp);
	return result;
}

static const char *
get_attribute_text(xmlNodePtr node, const char *attribute)
{
	xmlAttrPtr attr = xmlHasProp(node, (const xmlChar *) attribute);
	if (attr && attr->children && attr->children->type == XML_TEXT_NODE) {
		return (const char *) attr->children->content;
	} else {
		return NULL;
	}
}

static const char *
get_element_text(xmlNodePtr node, const char *element)
{
	xmlNodePtr current;
	for (current = node->children; current; current = current->next) {
		if (current->type == XML_ELEMENT_NODE
		    && strcmp((const char *) current->name, element) == 0
		    && current->children
		    && current->children->type == XML_TEXT_NODE)
		{
			return (const char *) current->children->content;
		}
	}
	return NULL;
}

static nsd_options_address_type *
parse_address(region_type *region, xmlNodePtr address_node)
{
	nsd_options_address_type *result = NULL;
	const char *port = get_attribute_text(address_node, "port");
	const char *family_text = get_attribute_text(address_node, "family");
	int family;

	if (!address_node->children
	    || address_node->children->type != XML_TEXT_NODE)
	{
		log_msg(LOG_ERR, "address not specified at line %d",
			address_node->line);
		goto exit;
	}

	if (family_text) {
		if (strcasecmp(family_text, "ipv4") == 0) {
			family = AF_INET;
		} else if (strcasecmp(family_text, "ipv6") == 0) {
			family = AF_INET6;
		} else {
			log_msg(LOG_ERR, "unrecognized protocol family '%s'",
				family_text);
			goto exit;
		}
	} else {
		family = DEFAULT_AI_FAMILY;
	}

	result = region_alloc(region, sizeof(nsd_options_address_type));
	result->family = family;
	result->port = region_strdup(region, port);
	result->address = region_strdup(
		region,	(const char *) address_node->children->content);

exit:
	return result;
}


static nsd_options_key_type *
parse_key(region_type *region, xmlNodePtr key_node)
{
	nsd_options_key_type *result = NULL;
	const char *name = get_attribute_text(key_node, "name");
	const char *algorithm = get_element_text(key_node, "algorithm");
	const char *secret = get_element_text(key_node, "secret");

	if (!name || !algorithm || !secret) {
		log_msg(LOG_ERR,
			"key does not define one of name, algorithm, or secret at line %d",
			key_node->line);
		goto exit;
	}

	result = region_alloc(region, sizeof(nsd_options_key_type));
	result->name = region_strdup(region, name);
	result->algorithm = region_strdup(region, algorithm);
	result->secret = region_strdup(region, secret);

exit:
	return result;
}


nsd_options_address_type *
options_address_make(region_type *region,
		     int family,
		     const char *port,
		     const char *address)
{
	nsd_options_address_type *result
		= region_alloc(region, sizeof(nsd_options_address_type));
	result->family = family;
	result->port = region_strdup(region, port);
	result->address = region_strdup(region, address);
	return result;
}

static int
parse_listen_on_addresses(nsd_options_type *options, xmlXPathContextPtr context)
{
	int result = 0;
	xmlXPathObjectPtr listen_on_addresses = NULL;

	listen_on_addresses = xmlXPathEvalExpression(
		(const xmlChar *) "/nsd/options/listen-on/address",
		context);
	if (!listen_on_addresses) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			"/nsd/options/listen-on/address");
		goto exit;
	} else if (listen_on_addresses->nodesetval) {
		int i;

		assert(listen_on_addresses->type == XPATH_NODESET);

		result = 1;
		options->listen_on_count
			= listen_on_addresses->nodesetval->nodeNr;
		options->listen_on = region_alloc(
			options->region,
			(options->listen_on_count
			 * sizeof(nsd_options_address_type *)));
		for (i = 0; i < listen_on_addresses->nodesetval->nodeNr; ++i) {
			options->listen_on[i] = parse_address(
				options->region,
				listen_on_addresses->nodesetval->nodeTab[i]);
			if (!options->listen_on[i]) {
				result = 0;
			}
		}
	}

exit:
	xmlXPathFreeObject(listen_on_addresses);
	return result;
}

static int
parse_controls_addresses(nsd_options_type *options, xmlXPathContextPtr context)
{
	int result = 0;
	xmlXPathObjectPtr controls_addresses = NULL;

	controls_addresses = xmlXPathEvalExpression(
		(const xmlChar *) "/nsd/options/controls/address",
		context);
	if (!controls_addresses) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			"/nsd/options/controls/address");
		goto exit;
	} else if (controls_addresses->nodesetval) {
		int i;

		assert(controls_addresses->type == XPATH_NODESET);

		result = 1;
		options->controls_count
			= controls_addresses->nodesetval->nodeNr;
		options->controls = region_alloc(
			options->region,
			(options->controls_count
			 * sizeof(nsd_options_address_type *)));
		for (i = 0; i < controls_addresses->nodesetval->nodeNr; ++i) {
			options->controls[i] = parse_address(
				options->region,
				controls_addresses->nodesetval->nodeTab[i]);
			if (!options->controls[i]) {
				result = 0;
			}
		}
	}

exit:
	xmlXPathFreeObject(controls_addresses);
	return result;
}

static int
parse_keys(nsd_options_type *options, xmlXPathContextPtr context)
{
	int result = 0;
	xmlXPathObjectPtr keys = NULL;

	keys = xmlXPathEvalExpression(
		(const xmlChar *) "/nsd/key",
		context);
	if (!keys) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			"/nsd/key");
		goto exit;
	} else if (keys->nodesetval) {
		int i;

		assert(keys->type == XPATH_NODESET);

		result = 1;
		options->key_count
			= keys->nodesetval->nodeNr;
		options->keys = region_alloc(
			options->region,
			(options->key_count
			 * sizeof(nsd_options_key_type *)));
		for (i = 0; i < keys->nodesetval->nodeNr; ++i) {
			options->keys[i] = parse_key(
				options->region,
				keys->nodesetval->nodeTab[i]);
			if (!options->keys[i]) {
				result = 0;
			}
		}
	}

exit:
	xmlXPathFreeObject(keys);
	return result;
}

static int
parse_zones(nsd_options_type *options, xmlXPathContextPtr context)
{
	int result = 1;
	xmlXPathObjectPtr zones = NULL;
exit:
	xmlXPathFreeObject(zones);
	return result;
}
