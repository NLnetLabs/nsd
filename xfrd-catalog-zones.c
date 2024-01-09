/*
 * xfrd-catalog-zones.c -- catalog zone implementation for NSD
 *
 * Copyright (c) 2024, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 */
#include "config.h"
#include "difffile.h"
#include "nsd.h"
#include "packet.h"
#include "xfrd-catalog-zones.h"
#include "xfrd-notify.h"


/******************                                        ******************
 ******************    catalog consumer zone processing    ******************
 ******************                                        ******************/

/** process a catalog consumer zone, load if needed */
static void xfrd_process_catalog_consumer_zone(
		struct xfrd_catalog_consumer_zone* catz);

/** make the catalog consumer zone invalid for given reason */
static void vmake_catalog_consumer_invalid(
	struct xfrd_catalog_consumer_zone *catz,
	const char *format, va_list args);

/** return (static) dname with label prepended to dname */
static dname_type* label_plus_dname(const char* label, const dname_type* dname);

/** delete the catalog member zone */
static void catalog_del_member_zone(struct catalog_member_zone* member_zone);

#ifndef MULTIPLE_CATALOG_CONSUMER_ZONES
/* return a single catalog consumer zone from xfrd struct */
static inline struct xfrd_catalog_consumer_zone*
xfrd_one_catalog_consumer_zone()
{
	return xfrd
	    && xfrd->catalog_consumer_zones
	    && xfrd->catalog_consumer_zones->count == 1
	     ? (struct xfrd_catalog_consumer_zone*)
	       rbtree_first(xfrd->catalog_consumer_zones) : NULL;
}
#endif

/** return the catalog-member-pattern or NULL on error if not present */
static inline struct pattern_options*
catalog_member_pattern(struct xfrd_catalog_consumer_zone* catz)
{
	if (!catz->options->pattern
	||  !catz->options->pattern->catalog_member_pattern)
		return NULL;
	return pattern_options_find(xfrd->nsd->options,
		catz->options->pattern->catalog_member_pattern);
}

/** see if we have more zonestatistics entries and it has to be incremented */
static inline void
zonestat_inc_ifneeded()
{
#ifdef USE_ZONE_STATS
        if(xfrd->nsd->options->zonestatnames->count != xfrd->zonestat_safe)
                task_new_zonestat_inc(xfrd->nsd->task[xfrd->nsd->mytask],
                        xfrd->last_task,
                        xfrd->nsd->options->zonestatnames->count);
#endif /* USE_ZONE_STATS */
}


/******************                                        ******************
 ******************    catalog producer zone processing    ******************
 ******************                                        ******************/

/** process catalog producer zone producer_zone */
static void xfrd_process_catalog_producer_zone(
		struct xfrd_catalog_producer_zone* producer_zone);

/** rbnode must be struct catalog_member_zone*; compares (key->member_id) */
static int member_id_compare(const void *left, const void *right);

/** return xfrd_catalog_producer_zone* pointed to by cmz's catalog-producer-zone
 * pattern option. struct is created if necessary. returns NULL on failure. */
static struct xfrd_catalog_producer_zone* xfrd_get_catalog_producer_zone(
		struct catalog_member_zone* cmz);

/** helper struct for generating XFR files, for conveying the catalog producer
 *  zone content to the server process.
 */
struct xfrd_xfr_writer {
	struct xfrd_catalog_producer_zone* producer_zone;
	char packet_space[16384];
	buffer_type packet;
	uint32_t seq_nr; /* number of messages already handled */
	uint32_t old_serial, new_serial; /* host byte order */
	uint64_t xfrfilenumber; /* identifier for file to store xfr into */
};

/** initialize xfrd_xfr_writer struct xw */
static void xfr_writer_init(struct xfrd_xfr_writer* xw,
		struct xfrd_catalog_producer_zone* producer_zone);

/** write packet from xfrd_xfr_writer struct xw to xfr file */
static void xfr_writer_write_packet(struct xfrd_xfr_writer* xw);

/** commit xfr file (send to server process), with provided log message */
static void xfr_writer_commit(struct xfrd_xfr_writer* xw, const char *fmt,
		...);

/** try writing SOA RR with serial to packet buffer. returns 0 on failure */
static int try_buffer_write_SOA(buffer_type* packet, const dname_type* owner,
		uint32_t serial);

/** try writing RR to packet buffer. returns 0 on failure */
static int try_buffer_write_RR(buffer_type* packet, const dname_type* owner,
		uint16_t rr_type, uint16_t rdata_len, const void* rdata);

/** try writing PTR RR to packet buffer. returns 0 on failure */
static inline int try_buffer_write_PTR(buffer_type* packet,
		const dname_type* owner, const dname_type* name);

/** try writing TXT RR to packet buffer. returns 0 on failure */
static int try_buffer_write_TXT(buffer_type* packet, const dname_type* name,
		const char *txt);

/** add SOA RR with serial serial to xfrd_xfr_writer xw */
static inline void xfr_writer_add_SOA(struct xfrd_xfr_writer* xw,
		const dname_type* owner, uint32_t serial)
{
	if(try_buffer_write_SOA(&xw->packet, owner, serial))
		return;
	xfr_writer_write_packet(xw);
	assert(buffer_position(&xw->packet) == 12);
	try_buffer_write_SOA(&xw->packet, owner, serial);
}

/** add RR to xfrd_xfr_writer xw */
static inline void xfr_writer_add_RR(struct xfrd_xfr_writer* xw,
		const dname_type* owner,
		uint16_t rr_type, uint16_t rdata_len, const void* rdata)
{
	if(try_buffer_write_RR(&xw->packet, owner, rr_type, rdata_len, rdata))
		return;
	xfr_writer_write_packet(xw);
	assert(buffer_position(&xw->packet) == 12);
	try_buffer_write_RR(&xw->packet, owner, rr_type, rdata_len, rdata);
}

/** add PTR RR to xfrd_xfr_writer xw */
static inline void xfr_writer_add_PTR(struct xfrd_xfr_writer* xw,
		const dname_type* owner, const dname_type* name)
{
	if(try_buffer_write_PTR(&xw->packet, owner, name))
		return;
	xfr_writer_write_packet(xw);
	assert(buffer_position(&xw->packet) == 12);
	try_buffer_write_PTR(&xw->packet, owner, name);
}

/** add TXT RR to xfrd_xfr_writer xw */
static inline void xfr_writer_add_TXT(struct xfrd_xfr_writer* xw,
		const dname_type* owner, const char* txt)
{
	if(try_buffer_write_TXT(&xw->packet, owner, txt))
		return;
	xfr_writer_write_packet(xw);
	assert(buffer_position(&xw->packet) == 12);
	try_buffer_write_TXT(&xw->packet, owner, txt);
}


/******************                                        ******************
 ******************    catalog consumer zone processing    ******************
 ******************                                        ******************/

void
xfrd_init_catalog_consumer_zone(xfrd_state_type* xfrd,
		struct zone_options* zone)
{
	struct xfrd_catalog_consumer_zone* catz;

	if ((catz = (struct xfrd_catalog_consumer_zone*)rbtree_search(
			xfrd->catalog_consumer_zones, zone->node.key))) {
		log_msg(LOG_ERR, "cannot initialize new catalog consumer zone:"
				" '%s: it already exists in xfrd's catalog "
				" consumer zones index", zone->name);
		/* Maybe we need to reprocess it? */
		make_catalog_consumer_valid(catz);
		return;
	}
       	catz = (struct xfrd_catalog_consumer_zone*)
		region_alloc(xfrd->region,
			sizeof(struct xfrd_catalog_consumer_zone));
        memset(catz, 0, sizeof(struct xfrd_catalog_consumer_zone));
        catz->node.key = zone->node.key;
        catz->options = zone;
	catz->mtime.tv_sec = 0;
	catz->mtime.tv_nsec = 0;
	catz->member_zones = NULL;
	catz->n_member_zones = 0;
	catz->invalid = NULL;
	rbtree_insert(xfrd->catalog_consumer_zones, (rbnode_type*)catz);
#ifndef MULTIPLE_CATALOG_CONSUMER_ZONES
	if ((int)xfrd->catalog_consumer_zones->count > 1) {
		log_msg(LOG_ERR, "catalog consumer processing disabled: "
			"only one single catalog consumer zone allowed");
	}
#endif
}

void
xfrd_deinit_catalog_consumer_zone(xfrd_state_type* xfrd,
		const dname_type* dname)
{
	struct xfrd_catalog_consumer_zone* catz;
	zone_type* zone;

	if (!(catz = (struct xfrd_catalog_consumer_zone*)rbtree_delete(
			xfrd->catalog_consumer_zones, dname))) {
		log_msg(LOG_ERR, "cannot de-initialize catalog consumer zone:"
				" '%s: it did not exist in xfrd's catalog "
				" consumer zones index",
				dname_to_string(dname, NULL));
		return;
	}
	if (catz->member_zones) {
		log_msg(LOG_WARNING, "de-initialize catalog consumer zone:"
				" '%s: will cause all member zones to be "
				" deleted", catz->options->name);

		/* catz->member_zones will become NULL because the member zone
		 * will reset the reference to itself (in prev_next_ptr) to
		 * it's next pointer.
		 */
		while (catz->member_zones) {
			log_msg(LOG_INFO, "deleting member zone '%s' on "
				"de-initializing catalog consumer zone '%s'",
				catz->member_zones->options.name,
				catz->options->name);
			catalog_del_member_zone(catz->member_zones);
			catz->n_member_zones -= 1;
		}
	}
	if ((zone = namedb_find_zone(xfrd->nsd->db, dname))) {
		namedb_zone_delete(xfrd->nsd->db, zone);
	}
	region_recycle(xfrd->region, catz, sizeof(*catz));
}

/** make the catalog consumer zone invalid for given reason */
static void
vmake_catalog_consumer_invalid(struct xfrd_catalog_consumer_zone *catz,
		const char *format, va_list args)
{
	char message[MAXSYSLOGMSGLEN];
	if (!catz || catz->invalid) return;
        vsnprintf(message, sizeof(message), format, args);
	log_msg(LOG_ERR, "invalid catalog consumer zone '%s': %s",
		catz->options->name, message);
	catz->invalid = region_strdup(xfrd->region, message);
}

void
make_catalog_consumer_invalid(struct xfrd_catalog_consumer_zone *catz,
		const char *format, ...)
{
	va_list args;
	if (!catz || catz->invalid) return;
	va_start(args, format);
	vmake_catalog_consumer_invalid(catz, format, args);
	va_end(args);
}

void
make_catalog_consumer_valid(struct xfrd_catalog_consumer_zone *catz)
{
	if (catz->invalid) {
		region_recycle(xfrd->region,
				catz->invalid, strlen(catz->invalid)+1);
		catz->invalid = NULL;
	}
}

static dname_type*
label_plus_dname(const char* label, const dname_type* dname)
{
	static struct {
		dname_type dname;
		uint8_t bytes[MAXDOMAINLEN + 128 /* max number of labels */];
	} ATTR_PACKED name;
	size_t i, ll;

	if (!label || !dname || dname->label_count > 127)
		return NULL;
	ll = strlen(label);
	if ((int)dname->name_size + ll + 1 > MAXDOMAINLEN)
		return NULL;

	/* In reversed order and first copy with memmove, so we can nest.
	 * i.e. label_plus_dname(label1, label_plus_dname(label2, dname))
	 */
	memmove(name.bytes + dname->label_count + 2 + ll,
		((void*)dname) + 2 + dname->label_count, dname->name_size + 1);
	memcpy(name.bytes + dname->label_count + 2, label, ll);
	name.bytes[dname->label_count + 1] = ll;
	name.bytes[dname->label_count] = 0;
	for (i = 0; i < dname->label_count; i++)
		name.bytes[i] = ((uint8_t*)(void*)dname)[2+i] + ll + 1;
	name.dname.label_count = dname->label_count + 1;
	name.dname.name_size   = dname->name_size   + ll + 1;
	return &name.dname;
}

static void
catalog_del_member_zone(struct catalog_member_zone* member_zone)
{
	const dname_type* dname = member_zone->options.node.key;

	/* create deletion task */
	task_new_del_zone(xfrd->nsd->task[xfrd->nsd->mytask],
			xfrd->last_task, dname);
	xfrd_set_reload_now(xfrd);
	/* delete it in xfrd */
	if(zone_is_slave(&member_zone->options)) {
		xfrd_del_slave_zone(xfrd, dname);
	}
	xfrd_del_notify(xfrd, dname);
#ifdef MULTIPLE_CATALOG_CONSUMER_ZONES
	/* delete it in xfrd's catalog consumers list */
	if(zone_is_catalog_consumer(&member_zone->options)) {
		xfrd_deinit_catalog_consumer_zone(xfrd, dname);
	}
#endif
	zone_options_delete(xfrd->nsd->options, &member_zone->options);
}

void xfrd_check_catalog_consumer_zonefiles(const dname_type* zone)
{
	struct xfrd_catalog_consumer_zone* catz;

#ifndef MULTIPLE_CATALOG_CONSUMER_ZONES
       	catz = xfrd_one_catalog_consumer_zone();
	if (!catz)
		return;
	if (zone && dname_compare(zone, catz->node.key) != 0)
		return;
	DEBUG(DEBUG_XFRD,1, (LOG_INFO, "Mark %s "
		"for checking", catz->options->name));
	make_catalog_consumer_valid(catz);
	namedb_read_zonefile(xfrd->nsd,
		namedb_find_or_create_zone(xfrd->nsd->db, zone, catz->options),
		NULL, NULL);
#else
	if (!zone) {
		RBTREE_FOR(catz, struct xfrd_catalog_consumer_zone*,
				xfrd->catalog_consumer_zones) {
			make_catalog_consumer_valid(catz);
			namedb_read_zonefile(xfrd->nsd,
				namedb_find_or_create_zone(
					xfrd->nsd->db, catz->options->node.key,
					catz->options),
				NULL, NULL);
		}
	} else if ((catz = (struct xfrd_catalog_consumer_zone*)
			rbtree_search(xfrd->catalog_consumer_zones, zone))) {
		make_catalog_consumer_valid(catz);
		namedb_read_zonefile(xfrd->nsd,
			namedb_find_or_create_zone(
				xfrd->nsd->db, zone, catz->options),
			NULL, NULL);
	}
#endif
}

const char *invalid_catalog_consumer_zone(struct zone_options* zone)
{
	struct xfrd_catalog_consumer_zone* catz;
	const char *msg;

	if (!zone || !zone_is_catalog_consumer(zone))
		msg = NULL;

	else if (!xfrd) 
		msg = "asked for catalog information outside of xfrd process";

	else if (!xfrd->catalog_consumer_zones)
		msg = "zone not found: "
		      "xfrd's catalog consumer zones index is empty";

#ifndef MULTIPLE_CATALOG_CONSUMER_ZONES
	else if (xfrd->catalog_consumer_zones->count > 1)
		return "not processing: more than one catalog consumer zone "
		       "configured and only a single one allowed";
#endif
	else if (!(catz = (struct xfrd_catalog_consumer_zone*)
	         rbtree_search(xfrd->catalog_consumer_zones, zone->node.key)))
		msg = "zone not found in xfrd's catalog consumer zones index";
	else
		return catz->invalid;

	if (msg)
		log_msg(LOG_ERR, "catalog consumer zone '%s': %s",
				zone->name, msg);

	return msg;
}

void xfrd_process_catalog_consumer_zones()
{
#ifndef MULTIPLE_CATALOG_CONSUMER_ZONES
	xfrd_process_catalog_consumer_zone(xfrd_one_catalog_consumer_zone());
#else
	struct xfrd_catalog_consumer_zone* catz;

	RBTREE_FOR(catz, struct xfrd_catalog_consumer_zone*,
			xfrd->catalog_consumer_zones) {
		xfrd_process_catalog_consumer_zone(catz);
	}
#endif
}

static void
xfrd_process_catalog_consumer_zone(struct xfrd_catalog_consumer_zone* catz)
{
	zone_type* zone;
	const dname_type* dname;
	domain_type *match, *closest_encloser, *member_id, *group;
	rrset_type *rrset;
	size_t i;
	uint8_t version_2_found;
	struct catalog_member_zone** next_member_ptr;
	struct catalog_member_zone*  cmz;
	struct pattern_options *default_pattern = NULL;

	if (!catz)
		return;
	if (!xfrd->nsd->db) {
		xfrd->nsd->db = namedb_open(xfrd->nsd->options);
	}
	dname = (const dname_type*)catz->node.key;
	if (dname->name_size > 247) {
		make_catalog_consumer_invalid(catz, "name too long");
		return;
	}
	if (dname->label_count > 126) {
		make_catalog_consumer_invalid(catz, "too many labels");
		return;
	}
	zone = namedb_find_zone(xfrd->nsd->db, dname);
	if (!zone) {
		zone = namedb_zone_create(xfrd->nsd->db, dname, catz->options);
		namedb_read_zonefile(xfrd->nsd, zone, NULL, NULL);
	}
	if (timespec_compare(&catz->mtime, &zone->mtime) == 0) {
		/* DEBUG(DEBUG_XFRD,1, (LOG_INFO, "Not processing unchanged "
		 *	"catalog consumer zone %s", catz->options->name));
		 */
		return;
	}
	catz->mtime = zone->mtime;
	/* start processing */
	/* Lookup version.<catz> TXT and check that it is version 2 */
	if(!namedb_lookup(xfrd->nsd->db, label_plus_dname("version", dname),
				&match, &closest_encloser)
	|| !(rrset = domain_find_rrset(match, zone, TYPE_TXT))) {
		make_catalog_consumer_invalid(catz,
			"'version.%s TXT RRset not found",
			catz->options->name);
		return;
	}
	version_2_found = 0;
	for (i = 0; i < rrset->rr_count; i++) {
		if (rrset->rrs[i].rdata_count != 1)
			continue;
		if (rrset->rrs[i].rdatas[0].data[0] == 2
		&&  ((uint8_t*)(rrset->rrs[i].rdatas[0].data + 1))[0] == 1
		&&  ((uint8_t*)(rrset->rrs[i].rdatas[0].data + 1))[1] == '2') {
			version_2_found = 1;
			break;
		}
	}
	if (!version_2_found) {
		make_catalog_consumer_invalid(catz,
			"'version.%s' TXT RR with value \"2\" not found",
			catz->options->name);
		return;
	}
	/* Walk over all names under zones.<catz> */
	if(!namedb_lookup(xfrd->nsd->db, label_plus_dname("zones", dname),
				&match, &closest_encloser)) {
		/* zones.<catz> does not exist, so the catalog has no members.
		 * This is just fine.
		 */
		make_catalog_consumer_valid(catz);
		return;
	}
	next_member_ptr = &catz->member_zones;
	for ( member_id = domain_next(match)
	    ; member_id && domain_is_subdomain(member_id, match)
	    ; member_id = domain_next(member_id)) {
		domain_type *member_domain;
		char member_domain_str[5 * MAXDOMAINLEN];
		struct zone_options* zopt;
		int valid_group_values;
		struct pattern_options *pattern = NULL;

		if (domain_dname(member_id)->label_count > dname->label_count + 2
		||  !(rrset = domain_find_rrset(member_id, zone, TYPE_PTR)))
			continue;

		/* RFC9432 Section 4.1. Member Zones:
		 *
		 * `` This PTR record MUST be the only record in the PTR RRset
		 *    with the same name. The presence of more than one record
		 *    in the RRset indicates a broken catalog zone that MUST
		 *    NOT be processed (see Section 5.1).
		 */
		if (rrset->rr_count != 1) {
			make_catalog_consumer_invalid(catz, 
				"only a single PTR RR expected on '%s'",
				domain_to_string(member_id));
			return;
		}
		/* A PTR rr always has 1 rdata element which is a dname */
		if (rrset->rrs[0].rdata_count != 1)
			continue;
		member_domain = rrset->rrs[0].rdatas[0].domain;
		domain_to_string_buf(member_domain, member_domain_str);
		/* remove trailing dot */
		member_domain_str[strlen(member_domain_str) - 1] = 0;

		valid_group_values = 0;
		/* Lookup group.<member_id> TXT for matching patterns  */
		if(!namedb_lookup(xfrd->nsd->db, label_plus_dname("group",
						domain_dname(member_id)),
					&group, &closest_encloser)
		|| !(rrset = domain_find_rrset(group, zone, TYPE_TXT))) {
			; /* pass */

		} else for (i = 0; i < rrset->rr_count; i++) {
			/* Max single TXT rdata field length + '\x00' == 256 */
			char group_value[256];

			/* Looking for a single TXT rdata field */
			if (rrset->rrs[i].rdata_count != 1

			    /* rdata field should be at least 1 char */
			||  rrset->rrs[i].rdatas[0].data[0] < 2

			    /* single rdata atom with single TXT rdata field */
			||  ((uint8_t*)(rrset->rrs[i].rdatas[0].data + 1))[0]
			  != (uint8_t) (rrset->rrs[i].rdatas[0].data[0]-1))
				continue;

			memcpy( group_value
			      , (uint8_t*)(rrset->rrs[i].rdatas[0].data+1) + 1
			      ,((uint8_t*)(rrset->rrs[i].rdatas[0].data+1))[0]
			      );
			group_value[
			       ((uint8_t*)(rrset->rrs[i].rdatas[0].data+1))[0]
			] = 0;
			if ((pattern = pattern_options_find(
					xfrd->nsd->options, group_value)))
				valid_group_values += 1;
		}
		if (valid_group_values > 1) {
	                log_msg(LOG_ERR, "member zone '%s': only a single "
				"group property that matches a pattern is "
				"allowed."
				"The pattern from \"catalog-member-patter\" "
				"will be used instead.",
				domain_to_string(member_id));
			valid_group_values = 0;
		}
		if (valid_group_values == 1) {
			/* pass: pattern is already set */
			assert(pattern);

		} else if (default_pattern)
			pattern = default_pattern; /* pass */

		else if (!(pattern = default_pattern =
					catalog_member_pattern(catz))) {
			make_catalog_consumer_invalid(catz, 
				"missing 'group.%s' TXT RR and "
				"no default pattern from \"catalog-member-pattern\"",
				domain_to_string(member_id));
			return;
		}
		if (!*next_member_ptr)
			; /* End of the current member zones list.
			   * From here onwards, zones will only be added.
			   */
		else {
			int cmp;
#ifndef NDEBUF
			char member_id_str[5 * MAXDOMAINLEN];
			domain_to_string_buf(member_id, member_id_str);
#endif
			while (*next_member_ptr && 
			       (cmp = dname_compare(
					domain_dname(member_id),
					(*next_member_ptr)->member_id)) > 0) {
				/* member_id is ahead of the current catalog
				 * member zone pointed to by next_member_ptr.
				 * The member zone must be deleted.
				 */
				DEBUG(DEBUG_XFRD,1, (LOG_INFO,
					"Compare (%s, %s) = %d: delete member",
				       	member_id_str, dname_to_string(
					(*next_member_ptr)->member_id, NULL),
					cmp));

				catalog_del_member_zone(*next_member_ptr);
				catz->n_member_zones -= 1;
			};
			if (*next_member_ptr && cmp == 0) {
				/* member_id is also in an current catalog
				 * member zone, and next_member_ptr is pointing
				 * to it. So, move along ...
				 */
				/* ... but first check if the pattern needs
				 * a change
				 */
				if ((*next_member_ptr)->options.pattern == pattern)
					; /* pass: Pattern remains the same */
				else {
					/* Changing patterns is basically
					 * deleting and adding the zone again
					 */
					zopt  = &(*next_member_ptr)->options;
					dname = (dname_type *)zopt->node.key;
					task_new_del_zone( xfrd->nsd->task[xfrd->nsd->mytask]
					                 , xfrd->last_task
							 , dname);
					xfrd_set_reload_now(xfrd);
					if(zone_is_slave(zopt)) {
						xfrd_del_slave_zone(xfrd, dname);
					}
					xfrd_del_notify(xfrd, dname);
#ifdef MULTIPLE_CATALOG_CONSUMER_ZONES
					if(zone_is_catalog_consumer(zopt)) {
						xfrd_deinit_catalog_consumer_zone(xfrd, dname);
					}
#endif
					/* It is a catalog consumer member,
					 * so no need to check if it was a
					 * catalog producer member zone to 
					 * delete and add
					 */
					zopt->pattern = pattern;
					task_new_add_zone(xfrd->nsd->task[xfrd->nsd->mytask],
						xfrd->last_task, zopt->name,
						pattern->pname,
						getzonestatid(xfrd->nsd->options, zopt));
					zonestat_inc_ifneeded(xfrd);
					xfrd_set_reload_now(xfrd);
#ifdef MULTIPLE_CATALOG_CONSUMER_ZONES
					if(zone_is_catalog_consumer(zopt)) {
						xfrd_init_catalog_consumer_zone(xfrd, zopt);
					}
#endif
					init_notify_send(xfrd->notify_zones, xfrd->region, zopt);
					if(zone_is_slave(zopt)) {
						xfrd_init_slave_zone(xfrd, zopt);
					}
				}
				next_member_ptr = &(*next_member_ptr)->next;
				continue;
			}
			/* member_id is not in the current catalog member zone
			 * list, so it must be added
			 */
			assert(*next_member_ptr == NULL || cmp < 0);
		}
		/* See if the zone already exists */
		zopt = zone_options_find(xfrd->nsd->options,
				domain_dname(member_domain));
		if (zopt) {
			/* Produce warning if zopt is from other catalog.
			 * Give debug message if zopt is not from this catalog.
			 */
			DEBUG(DEBUG_XFRD,1, (LOG_INFO, "Cannot add catalog "
				"member zone %s (from %s): "
				"zone already exists",
				member_domain_str, domain_to_string(member_id)));
			continue;
		}
		/* Add member zone if not already there */
		cmz =  catalog_member_zone_create(xfrd->nsd->options->region);
		cmz->options.name = region_strdup(xfrd->nsd->options->region,
				member_domain_str);
		cmz->options.pattern = pattern;
		if (!nsd_options_insert_zone(xfrd->nsd->options, &cmz->options)) {
	                log_msg(LOG_ERR, "bad domain name or duplicate zone "
				"'%s' pattern %s", member_domain_str,
				( pattern->pname ? pattern->pname: "<NULL>"));
			zone_options_delete(xfrd->nsd->options, &cmz->options);
			continue;
		}
		cmz->member_id = dname_copy( xfrd->nsd->options->region
		                           , domain_dname(member_id));
		/* Insert into the double linked list */
		cmz->next = *next_member_ptr;
		if (cmz->next) {
			cmz->next->prev_next_ptr = &cmz->next;
		}
		cmz->prev_next_ptr = next_member_ptr;
		*next_member_ptr = cmz;
		next_member_ptr = &cmz->next;
		catz->n_member_zones += 1;
		/* make addzone task and schedule reload */
        	task_new_add_zone(xfrd->nsd->task[xfrd->nsd->mytask],
                	xfrd->last_task, member_domain_str,
			pattern->pname,
                	getzonestatid(xfrd->nsd->options, &cmz->options));
		zonestat_inc_ifneeded(xfrd);
		xfrd_set_reload_now(xfrd);
#ifdef MULTIPLE_CATALOG_CONSUMER_ZONES
		/* add to xfrd - catalog consumer zones */
		if(zone_is_catalog_consumer(&cmz->options)) {
			xfrd_init_catalog_consumer_zone(xfrd, &cmz->options);
		}
#endif
		/* add to xfrd - notify (for master and slaves) */
		init_notify_send(xfrd->notify_zones, xfrd->region, &cmz->options);
		/* add to xfrd - slave */
		if(zone_is_slave(&cmz->options)) {
			xfrd_init_slave_zone(xfrd, &cmz->options);
		}
		DEBUG(DEBUG_XFRD,1, (LOG_INFO, "Added catalog "
			"member zone %s (from %s)",
			member_domain_str, domain_to_string(member_id)));
	}
	while (*next_member_ptr) {
		/* Any current catalog member zones remaining, don't have an
		 * member_id in the catalog anymore, so should be deleted too.
		 */
		catalog_del_member_zone(*next_member_ptr);
		catz->n_member_zones -= 1;
	}
#if !defined(NDEBUG) && 0 /* Only disable for seriously slow debugging */
	for ( cmz = catz->member_zones, i = 0
	    ; cmz ; i++, cmz = cmz->next) {
		DEBUG(DEBUG_XFRD,1, (LOG_INFO, "Catalog member %.2zu: %s = %s",
		      i, dname_to_string(cmz->member_id, NULL),
		      cmz->options.name));
	}
#endif
	make_catalog_consumer_valid(catz);
}


/******************                                        ******************
 ******************    catalog producer zone processing    ******************
 ******************                                        ******************/

static int member_id_compare(const void *left, const void *right)
{
	return dname_compare( ((struct catalog_member_zone*)left )->member_id
	                    , ((struct catalog_member_zone*)right)->member_id);
}

static struct xfrd_catalog_producer_zone*
xfrd_get_catalog_producer_zone(struct catalog_member_zone* cmz)
{
	struct zone_options *producer_zopt;
	struct xfrd_catalog_producer_zone* producer_zone;
	const dname_type* producer_name;
	const char* producer_name_str;

	assert(xfrd);
	if(!cmz || !cmz->options.pattern->catalog_producer_zone)
		return NULL;

	/* TODO: Store as dname in pattern->catalog_producer_zone */
	producer_name = dname_parse(xfrd->nsd->options->region,
			cmz->options.pattern->catalog_producer_zone);
	producer_zopt = zone_options_find(xfrd->nsd->options, producer_name);
	producer_name_str = dname_to_string(producer_name, NULL);
	region_recycle( xfrd->nsd->options->region, (void *)producer_name
	              , dname_total_size(producer_name));
	if(!producer_zopt) {
		log_msg(LOG_ERR, "catalog producer zone '%s' not found for "
			"zone '%s'", producer_name_str, cmz->options.name);
		return NULL;
	}
if(!zone_is_catalog_producer(producer_zopt)) {
		log_msg(LOG_ERR, "cannot add catalog producer member "
			"zone '%s' to non producer zone '%s'",
			cmz->options.name, producer_zopt->name);
		return NULL;
	}
	producer_name = (dname_type*)producer_zopt->node.key;
	producer_zone = (struct xfrd_catalog_producer_zone*)
		rbtree_search(xfrd->catalog_producer_zones, producer_name);
	if (!producer_zone) {
		/* Create a new one */
		DEBUG(DEBUG_XFRD, 1, (LOG_INFO,"creating catalog producer zone"
			" '%s'", producer_zopt->name));
		producer_zone = (struct xfrd_catalog_producer_zone*)
			region_alloc(xfrd->region,
				   sizeof(struct xfrd_catalog_producer_zone));
		memset(producer_zone,0,sizeof(struct xfrd_catalog_producer_zone));
		producer_zone->node.key = producer_zopt->node.key;
		producer_zone->options = producer_zopt;
		producer_zone->serial = 0;
		producer_zone->to_delete = NULL;
		producer_zone->to_add = NULL;
		producer_zone->member_ids.region = xfrd->region;
		producer_zone->member_ids.root = RBTREE_NULL;
		producer_zone->member_ids.count = 0;
		producer_zone->member_ids.cmp = member_id_compare;
		producer_zone->latest_pxfr = NULL;
		producer_zone->axfr = 1;

		rbtree_insert(xfrd->catalog_producer_zones,
				(rbnode_type*)producer_zone);
	}
	return producer_zone;
}

void
xfrd_add_catalog_producer_member(struct catalog_member_zone* cmz)
{
	struct xfrd_catalog_producer_zone* producer_zone;
	const dname_type* producer_name;
	struct xfrd_producer_member* to_add;

	assert(xfrd);
	if(cmz->next) {
		log_msg(LOG_ERR, "cannot add catalog producer member "
			"zone '%s': already being added",
			cmz->options.name);
		return;
	}
	if (!(producer_zone = xfrd_get_catalog_producer_zone(cmz))) {
		return;
	}
	producer_name = producer_zone->node.key;
	while(!cmz->member_id) {
		/* Make new member_id with this catalog producer */
		char id_label[sizeof(uint32_t)*2+1];
		uint32_t new_id = (uint32_t)random_generate(0x7fffffff);

		id_label[hex_ntop( (void *)&new_id
		                 , sizeof(uint32_t)
		                 , id_label
		                 , sizeof(id_label))] = 0;
		cmz->member_id = label_plus_dname(id_label,
				label_plus_dname("zones", producer_name));
		DEBUG(DEBUG_XFRD, 1, (LOG_INFO, "does member_id %s exist?",
			dname_to_string(cmz->member_id, NULL)));
		if (!rbtree_search(&producer_zone->member_ids, cmz)) {
			cmz->member_id = dname_copy(xfrd->nsd->options->region,
				       	cmz->member_id);
			break;
		}
		cmz->member_id = NULL;
	}
	rbtree_insert(&producer_zone->member_ids, &cmz->node);

	/* Put data to be added to the producer zone to the to_add stack */
	to_add = (struct xfrd_producer_member*)region_alloc(xfrd->region,
			sizeof(struct xfrd_producer_member));
	to_add->member_id = cmz->member_id;
	to_add->member_zone_name = (dname_type*)cmz->options.node.key;
	to_add->group_name = cmz->options.pattern->pname;
	to_add->next = producer_zone->to_add;
	producer_zone->to_add = to_add;
}

int
xfrd_del_catalog_producer_member(struct xfrd_state* xfrd,
	       	const dname_type* member_zone_name)
{
	struct xfrd_producer_member* to_delete;
	struct catalog_member_zone* cmz;
	struct xfrd_catalog_producer_zone* producer_zone;

	if(!(cmz = as_catalog_member_zone(zone_options_find(xfrd->nsd->options,
						member_zone_name)))
	|| !(producer_zone = xfrd_get_catalog_producer_zone(cmz))
	|| !rbtree_delete(&producer_zone->member_ids, cmz))
		return 0;
	to_delete = (struct xfrd_producer_member*)region_alloc(xfrd->region,
			sizeof(struct xfrd_producer_member));
	to_delete->member_id = cmz->member_id; cmz->member_id = NULL;
	to_delete->member_zone_name = member_zone_name;
	to_delete->group_name = cmz->options.pattern->pname;
	to_delete->next = producer_zone->to_delete;
	producer_zone->to_delete = to_delete;
	return 1;
}

static int
try_buffer_write_SOA(buffer_type* packet, const dname_type* owner,
		uint32_t serial)
{
	size_t mark = buffer_position(packet);

	if(try_buffer_write(packet, dname_name(owner), owner->name_size)
	&& try_buffer_write_u16(packet, TYPE_SOA)
	&& try_buffer_write_u16(packet, CLASS_IN)
	&& try_buffer_write_u32(packet, 0) /* TTL*/
	&& try_buffer_write_u16(packet, 9 + 9 + 5 * sizeof(uint32_t))
	&& try_buffer_write(packet, "\007invalid\000", 9) /* primary */
	&& try_buffer_write(packet, "\007invalid\000", 9) /* mailbox */
	&& try_buffer_write_u32(packet,     serial)       /* serial */
	&& try_buffer_write_u32(packet,       3600)       /* refresh*/
	&& try_buffer_write_u32(packet,        600)       /* retry */
	&& try_buffer_write_u32(packet, 2147483646)       /* expire */
	&& try_buffer_write_u32(packet,          0)       /* minimum */) {
		ANCOUNT_SET(packet, ANCOUNT(packet) + 1);
		return 1;
	}
	buffer_set_position(packet, mark);
	return 0;
}

static int
try_buffer_write_RR(buffer_type* packet, const dname_type* owner,
		uint16_t rr_type, uint16_t rdata_len, const void* rdata)
{
	size_t mark = buffer_position(packet);

	if(try_buffer_write(packet, dname_name(owner), owner->name_size)
	&& try_buffer_write_u16(packet, rr_type)
	&& try_buffer_write_u16(packet, CLASS_IN)
	&& try_buffer_write_u32(packet, 0) /* TTL*/
	&& try_buffer_write_u16(packet, rdata_len)
	&& try_buffer_write(packet, rdata, rdata_len)) {
		ANCOUNT_SET(packet, ANCOUNT(packet) + 1);
		return 1;
	}
	buffer_set_position(packet, mark);
	return 0;
}

static inline int
try_buffer_write_PTR(buffer_type* packet, const dname_type* owner,
		const dname_type* name)
{
	return try_buffer_write_RR(packet, owner, TYPE_PTR,
			name->name_size, dname_name(name));
}

static int
try_buffer_write_TXT(buffer_type* packet, const dname_type* name, const char *txt)
{
	size_t mark = buffer_position(packet);
	size_t len = strlen(txt);

	if(len > 255) {
		log_msg(LOG_ERR, "cannot make '%s 0 IN TXT \"%s\"': rdata "
			"field too long", dname_to_string(name, NULL), txt);
		return 1;
	}
	if(try_buffer_write(packet, dname_name(name), name->name_size)
	&& try_buffer_write_u16(packet, TYPE_TXT)
	&& try_buffer_write_u16(packet, CLASS_IN)
	&& try_buffer_write_u32(packet, 0) /* TTL*/
	&& try_buffer_write_u16(packet, len + 1)
	&& try_buffer_write_u8(packet, len)
	&& try_buffer_write_string(packet, txt)) {
		ANCOUNT_SET(packet, ANCOUNT(packet) + 1);
		return 1;
	}
	buffer_set_position(packet, mark);
	return 0; 
}

static void
xfr_writer_init(struct xfrd_xfr_writer* xw,
		struct xfrd_catalog_producer_zone* producer_zone)
{
	xw->producer_zone = producer_zone;
	buffer_create_from( &xw->packet, &xw->packet_space
	                               , sizeof(xw->packet_space));
	buffer_write(&xw->packet, "\000\000\000\000\000\000"
	                          "\000\000\000\000\000\000", 12); /* header */
	xw->seq_nr = 0;
	xw->old_serial = xw->producer_zone->serial;
	xw->new_serial = (uint32_t)xfrd_time();
	if(xw->new_serial <= xw->old_serial)
		xw->new_serial = xw->old_serial + 1;
	if(producer_zone->axfr) {
		xw->old_serial = 0;
		producer_zone->axfr = 0;
	}
	xw->xfrfilenumber = xfrd->xfrfilenumber++;
}

static void
xfr_writer_write_packet(struct xfrd_xfr_writer* xw)
{
	const dname_type* producer_name =
		(const dname_type*)xw->producer_zone->options->node.key;

	/* We want some content at least, so not just a header
	 * This can occur when final SOA was already written.
	 */
	if(buffer_position(&xw->packet) == 12)
		return;
	buffer_flip(&xw->packet);
	diff_write_packet( dname_to_string(producer_name, NULL)
			 , xw->producer_zone->options->pattern->pname
			 , xw->old_serial, xw->new_serial, xw->seq_nr
			 , buffer_begin(&xw->packet), buffer_limit(&xw->packet)
			 , xfrd->nsd, xw->xfrfilenumber);
	xw->seq_nr += 1;
	buffer_clear(&xw->packet);
	buffer_write(&xw->packet, "\000\000\000\000\000\000"
	                          "\000\000\000\000\000\000", 12); /* header */
}


static void
xfr_writer_commit(struct xfrd_xfr_writer* xw, const char *fmt, ...)
{
	va_list args;
	char msg[1024];
	const dname_type* producer_name =
		(const dname_type*)xw->producer_zone->options->node.key;

	va_start(args, fmt);
	if (vsnprintf(msg, sizeof(msg), fmt, args) >= (int)sizeof(msg)) {
		log_msg(LOG_WARNING, "truncated diff commit message: '%s'",
				msg);
	}
	xfr_writer_write_packet(xw); /* Write remaining data */
	diff_write_commit( dname_to_string(producer_name, NULL)
			 , xw->old_serial, xw->new_serial
			 , xw->seq_nr /* Number of packets */
			 , 1, msg, xfrd->nsd, xw->xfrfilenumber);
	task_new_apply_xfr( xfrd->nsd->task[xfrd->nsd->mytask], xfrd->last_task
			  , producer_name
			  , xw->old_serial, xw->new_serial, xw->xfrfilenumber);
	xfrd_set_reload_now(xfrd);
}

static void
xfrd_process_catalog_producer_zone(
		struct xfrd_catalog_producer_zone* producer_zone)
{
	struct xfrd_xfr_writer xw;
	dname_type* producer_name;
	struct xfrd_producer_xfr* pxfr;

	if(!producer_zone->to_add && !producer_zone->to_delete)
		return; /* No changes */

	producer_name = (dname_type*)producer_zone->node.key;
	xfr_writer_init(&xw, producer_zone);
	xfr_writer_add_SOA(&xw, producer_name, xw.new_serial);

	if(xw.old_serial == 0) {
		/* initial deployment */
		assert(producer_zone->to_add && !producer_zone->to_delete);

		xfr_writer_add_RR (&xw, producer_name
		                      , TYPE_NS, 9, "\007invalid\000");
		xfr_writer_add_TXT(&xw, label_plus_dname("version"
		                                        , producer_name), "2");
		goto add_member_zones;
	} 
	/* IXFR */
	xfr_writer_add_SOA(&xw, producer_name, xw.old_serial);
	while(producer_zone->to_delete) {
		struct xfrd_producer_member* to_delete =
			producer_zone->to_delete;

		/* Pop to_delete from stack */
		producer_zone->to_delete = to_delete->next;
		to_delete->next = NULL;

		/* Write <member_id> PTR <member_name> */
		xfr_writer_add_PTR(&xw, to_delete->member_id
				      , to_delete->member_zone_name);

		/* Write group.<member_id> TXT <pattern> */
		xfr_writer_add_TXT( &xw
				  , label_plus_dname("group"
						    , to_delete->member_id)
				  , to_delete->group_name);

		region_recycle( xfrd->nsd->options->region
		              , (void *)to_delete->member_id
			      , dname_total_size(to_delete->member_id));
		region_recycle( xfrd->region /* allocated in perform_delzone */
		              , (void *)to_delete->member_zone_name
			      , dname_total_size(to_delete->member_zone_name));
		/* Don't recycle to_delete->group_name it's pattern->pname */
		region_recycle( xfrd->region, to_delete, sizeof(*to_delete));
	}
	xfr_writer_add_SOA(&xw, producer_name, xw.new_serial);

add_member_zones:
	while(producer_zone->to_add) {
		struct xfrd_producer_member* to_add = producer_zone->to_add;

		/* Pop to_add from stack */
		producer_zone->to_add = to_add->next;
		to_add->next = NULL;

		/* Write <member_id> PTR <member_name> */
		xfr_writer_add_PTR(&xw, to_add->member_id, to_add->member_zone_name);

		/* Write group.<member_id> TXT <pattern> */
		xfr_writer_add_TXT( &xw
				  , label_plus_dname("group"
						    , to_add->member_id)
				  , to_add->group_name);

		/* Don't recycle any of the struct attributes as they come
		 * from zone_option's that are in use
		 */
		region_recycle(xfrd->region, to_add, sizeof(*to_add));
	}
	xfr_writer_add_SOA(&xw, producer_name, xw.new_serial);
	xfr_writer_commit(&xw, "xfr for catalog producer zone "
			"'%s' with %d members from %u to %u",
			dname_to_string(producer_name, NULL),
			producer_zone->member_ids.count,
			xw.old_serial, xw.new_serial);
	producer_zone->serial = xw.new_serial;

	/* Hook up an xfrd_producer_xfr, to delete the xfr file when applied */
	pxfr = (struct xfrd_producer_xfr*)region_alloc(xfrd->region,
			sizeof(struct xfrd_producer_xfr));
	pxfr->serial = xw.new_serial;
	pxfr->xfrfilenumber = xw.xfrfilenumber;
	if((pxfr->next = producer_zone->latest_pxfr))
		pxfr->next->prev_next_ptr = &pxfr->next;
	pxfr->prev_next_ptr = &producer_zone->latest_pxfr;
	producer_zone->latest_pxfr = pxfr;
}

void xfrd_process_catalog_producer_zones()
{
	struct xfrd_catalog_producer_zone* producer_zone;

	RBTREE_FOR(producer_zone, struct xfrd_catalog_producer_zone*,
			xfrd->catalog_producer_zones) {
		xfrd_process_catalog_producer_zone(producer_zone);
	}
}

