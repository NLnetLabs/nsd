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
static int validate_configuration(xmlDocPtr schema_doc, xmlDocPtr options_doc);

static const char *lookup_text(region_type *region,
			       xmlXPathContextPtr context,
			       const char *expr);
static int lookup_integer(xmlXPathContextPtr context,
			  const char *expr,
			  int default_value);

static nsd_options_address_type *parse_address(region_type *region,
					       xmlNodePtr address_node);

/*
 * Load the NSD configuration from FILENAME.
 */
nsd_options_type *
load_configuration(region_type *region, const char *filename)
{
	xmlDocPtr schema_doc = NULL;
	xmlDocPtr options_doc = NULL;
	xmlXPathContextPtr xpath_context = NULL;
	xmlXPathObjectPtr listen_on_addresses = NULL;
	nsd_options_type *options = NULL;

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
		if (!validate_configuration(schema_doc, options_doc)) {
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
	options->pid_file = lookup_text(region, xpath_context,
					"/nsd/options/pid-file/text()");
	options->server_count = lookup_integer(
		xpath_context,
		"/nsd/options/server-count/text()",
		1);
	options->maximum_tcp_connection_count = lookup_integer(
		xpath_context,
		"/nsd/options/maximum-tcp-connection-count/text()",
		10);

	options->listen_on = NULL; /* TODO */

	listen_on_addresses = xmlXPathEvalExpression(
		(const xmlChar *) "/nsd/options/listen-on/*",
		xpath_context);
	if (!listen_on_addresses) {
		log_msg(LOG_ERR, "unable to evaluate xpath expression '%s'",
			"/nsd/options/listen-on/*");
		goto exit;
	} else if (listen_on_addresses->nodesetval) {
		int i;

		assert(listen_on_addresses->type == XPATH_NODESET);

		options->listen_on_count
			= listen_on_addresses->nodesetval->nodeNr;
		options->listen_on = region_alloc(
			region,	(options->listen_on_count
				 * sizeof(nsd_options_address_type *)));
		for (i = 0; i < listen_on_addresses->nodesetval->nodeNr; ++i) {
			options->listen_on[i] = parse_address(
				region,
				listen_on_addresses->nodesetval->nodeTab[i]);
		}
	}

exit:
	xmlXPathFreeObject(listen_on_addresses);
	xmlXPathFreeContext(xpath_context);
	xmlFreeDoc(schema_doc);
	xmlFreeDoc(options_doc);

	return options;
}


static int
validate_configuration(xmlDocPtr schema_doc, xmlDocPtr options_doc)
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

	if (!port) {
		port = DEFAULT_PORT;
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
	result->port = port;
	result->address = region_strdup(
		region,	(const char *) address_node->children->content);

exit:
	return result;
}

