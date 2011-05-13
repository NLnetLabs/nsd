/*
 * dbaccess.c -- access methods for nsd(8) database
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <sys/types.h>
#include <sys/stat.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>		/* DEBUG */

#include "dns.h"
#include "namedb.h"
#include "util.h"
#include "options.h"
#include "rdata.h"
#include "udb.h"
#include "udbradtree.h"
#include "udbzone.h"
#include "zonec.h"
#include "nsec3.h"
#include "difffile.h"

void
namedb_close (struct namedb *db)
{
	namedb_fd_close(db);
	if (db) {
		udb_base_free(db->udb);
		radix_tree_delete(db->zonetree);
		region_destroy(db->region);
		zonec_desetup_parser();
	}
}

void
namedb_close_udb (struct namedb *db)
{
	if(db) {
		/* we cannot actually munmap the data, because other
		 * processes still need to access the udb, so cleanup the
		 * udb */
		udb_base_free_keep_mmap(db->udb);
		db->udb = NULL;
	}
}

void
namedb_fd_close (struct namedb *db)
{
	if(db && db->udb)
		udb_base_close(db->udb);
}

void
apex_rrset_checks(namedb_type* db, rrset_type* rrset, domain_type* domain)
{
	uint32_t soa_minimum;
	unsigned i;
	zone_type* zone = rrset->zone;
	assert(domain == zone->apex);
	if (rrset_rrtype(rrset) == TYPE_SOA) {
		zone->soa_rrset = rrset;

		/* BUG #103 add another soa with a tweaked ttl */
		if(zone->soa_nx_rrset == 0) {
			zone->soa_nx_rrset = region_alloc(db->region,
				sizeof(rrset_type));
			zone->soa_nx_rrset->rr_count = 1;
			zone->soa_nx_rrset->next = 0;
			zone->soa_nx_rrset->zone = zone;
			zone->soa_nx_rrset->rrs = region_alloc(db->region,
				sizeof(rr_type));
		}
		memcpy(zone->soa_nx_rrset->rrs, rrset->rrs, sizeof(rr_type));

		/* check the ttl and MINIMUM value and set accordinly */
		memcpy(&soa_minimum, rdata_atom_data(rrset->rrs->rdatas[6]),
				rdata_atom_size(rrset->rrs->rdatas[6]));
		if (rrset->rrs->ttl > ntohl(soa_minimum)) {
			zone->soa_nx_rrset->rrs[0].ttl = ntohl(soa_minimum);
		}
	} else if (rrset_rrtype(rrset) == TYPE_NS) {
		zone->ns_rrset = rrset;
	} else if (rrset_rrtype(rrset) == TYPE_RRSIG) {
		for (i = 0; i < rrset->rr_count; ++i) {
			if(rr_rrsig_type_covered(&rrset->rrs[i])==TYPE_DNSKEY){
				zone->is_secure = 1;
				break;
			}
		}
	}
}

/** read rr */
static void
read_rr(namedb_type* db, rr_type* rr, udb_ptr* urr, domain_type* domain)
{
	buffer_type buffer;
	ssize_t c;
	assert(udb_ptr_get_type(urr) == udb_chunk_type_rr);
	rr->owner = domain;
	rr->type = RR(urr)->type;
	rr->klass = RR(urr)->klass;
	rr->ttl = RR(urr)->ttl;

	buffer_create_from(&buffer, RR(urr)->wire, RR(urr)->len);
	c = rdata_wireformat_to_rdata_atoms(db->region, db->domains,
		rr->type, RR(urr)->len, &buffer, &rr->rdatas);
	if(c == -1) {
		/* safe on error */
		rr->rdata_count = 0;
		rr->rdatas = NULL;
		return;
	}
	rr->rdata_count = c;
}

/** calculate rr count */
static uint16_t
calculate_rr_count(udb_base* udb, udb_ptr* rrset)
{
	udb_ptr rr;
	uint16_t num = 0;
	udb_ptr_new(&rr, udb, &RRSET(rrset)->rrs);
	while(rr.data) {
		num++;
		udb_ptr_set_rptr(&rr, udb, &RR(&rr)->next);
	}
	udb_ptr_unlink(&rr, udb);
	return num;
}

/** read rrset */
static void
read_rrset(udb_base* udb, namedb_type* db, zone_type* zone,
	domain_type* domain, udb_ptr* urrset)
{
	rrset_type* rrset;
	udb_ptr urr;
	unsigned i;
	assert(udb_ptr_get_type(urrset) == udb_chunk_type_rrset);
	/* if no RRs, do not create anything (robust) */
	if(RRSET(urrset)->rrs.data == 0)
		return;
	rrset = (rrset_type *) region_alloc(db->region, sizeof(rrset_type));
	rrset->zone = zone;
	rrset->rr_count = calculate_rr_count(udb, urrset);
	rrset->rrs = (rr_type *) region_alloc(
		db->region, rrset->rr_count * sizeof(rr_type));
	/* add the RRs */
	udb_ptr_new(&urr, udb, &RRSET(urrset)->rrs);
	for(i=0; i<rrset->rr_count; i++) {
		read_rr(db, &rrset->rrs[i], &urr, domain);
		udb_ptr_set_rptr(&urr, udb, &RR(&urr)->next);
	}
	udb_ptr_unlink(&urr, udb);
	domain_add_rrset(domain, rrset);
	if(domain == zone->apex)
		apex_rrset_checks(db, rrset, domain);
}

#ifdef NSEC3
/** setup nsec3 hashes for a domain */
static void
read_nsec3_hashes(domain_type* domain, zone_type* zone, udb_ptr* d)
{
	if(domain_find_rrset(domain, zone, TYPE_NS) && domain != zone->apex) {
		if(DOMAIN(d)->have_hash) {
			memmove(domain->nsec3_ds_parent_hash,
				DOMAIN(d)->hash, NSEC3_HASH_LEN);
			domain->have_nsec3_ds_parent_hash = 1;
		}
	} else {
		if(DOMAIN(d)->have_hash) {
			memmove(domain->nsec3_hash, DOMAIN(d)->hash,
				NSEC3_HASH_LEN);
			domain->have_nsec3_hash = 1;
		}
		if(DOMAIN(d)->have_wc_hash) {
			memmove(domain->nsec3_wc_hash,
				DOMAIN(d)->wc_hash, NSEC3_HASH_LEN);
			domain->have_nsec3_wc_hash = 1;
		}
	}
}
#endif /* NSEC3 */

/** read zone data */
static void
read_zone_data(udb_base* udb, namedb_type* db, region_type* dname_region,
	udb_ptr* z, zone_type* zone)
{
	udb_ptr dtree, n, d, urrset;
	udb_ptr_init(&urrset, udb);
	udb_ptr_init(&d, udb);
	udb_ptr_new(&dtree, udb, &ZONE(z)->domains);
	/* walk over domain names */
	for(udb_radix_first(udb,&dtree,&n); n.data; udb_radix_next(udb,&n)) {
		const dname_type* dname;
		domain_type* domain;

		/* add the domain */
		udb_ptr_set_rptr(&d, udb, &RADNODE(&n)->elem);
		dname = dname_make(dname_region, DOMAIN(&d)->name, 0);
		if(!dname) continue;
		domain = domain_table_insert(db->domains, dname);
		assert(udb_ptr_get_type(&d) == udb_chunk_type_domain);

		/* add rrsets */
		udb_ptr_set_rptr(&urrset, udb, &DOMAIN(&d)->rrsets);
		while(urrset.data) {
			read_rrset(udb, db, zone, domain, &urrset);
			udb_ptr_set_rptr(&urrset, udb, &RRSET(&urrset)->next);
		}
		region_free_all(dname_region);
		
#ifdef NSEC3
		/* setup nsec3 hashes */
		read_nsec3_hashes(domain, zone, &d);
#endif
	}
	udb_ptr_unlink(&dtree, udb);
	udb_ptr_unlink(&d, udb);
	udb_ptr_unlink(&n, udb);
	udb_ptr_unlink(&urrset, udb);
}

/** create a zone */
zone_type*
namedb_zone_create(namedb_type* db, const dname_type* dname,
	zone_options_t* zo, size_t num_children)
{
	zone_type* zone = (zone_type *) region_alloc(db->region,
		sizeof(zone_type));
	zone->node = radname_insert(db->zonetree, dname_name(dname),
		dname->name_size, zone);
	assert(zone->node);
	zone->apex = domain_table_insert(db->domains, dname);
	zone->apex->usage++; /* the zone.apex reference */
	zone->soa_rrset = NULL;
	zone->soa_nx_rrset = NULL;
	zone->ns_rrset = NULL;
#ifdef NSEC3
	zone->nsec3_param = NULL;
	zone->nsec3_last = NULL;
	zone->nsec3tree = NULL;
	zone->hashtree = NULL;
	zone->wchashtree = NULL;
	zone->dshashtree = NULL;
#endif
	zone->opts = zo;
	zone->is_secure = 0;
	zone->updated = 1;
	zone->is_ok = 1;
	zone->dirty = region_alloc(db->region, sizeof(uint8_t)*num_children);
	memset(zone->dirty, 0, sizeof(uint8_t)*num_children);
	return zone;
}

/** read a zone */
static void
read_zone(udb_base* udb, namedb_type* db, nsd_options_t* opt,
	size_t num_children, region_type* dname_region, udb_ptr* z)
{
	/* construct dname */
	const dname_type* dname = dname_make(dname_region, ZONE(z)->name, 0);
	zone_options_t* zo = dname?zone_options_find(opt, dname):NULL;
	zone_type* zone;
	assert(dname);
	assert(udb_ptr_get_type(z) == udb_chunk_type_zone);
	if(!zo) {
		/* deleted from the options, remove it from the nsd.db too */
		VERBOSITY(2, (LOG_WARNING, "zone %s is deleted",
			dname_to_string(dname, NULL)));
		udb_zone_delete(udb, z);
		region_free_all(dname_region);
		return;
	}
	zone = namedb_zone_create(db, dname, zo, num_children);
	region_free_all(dname_region);
	read_zone_data(udb, db, dname_region, z, zone);
}

/** read zones from nsd.db */
static void
read_zones(udb_base* udb, namedb_type* db, nsd_options_t* opt,
	size_t num_children, region_type* dname_region)
{
	udb_ptr ztree, n, z;
	udb_ptr_init(&z, udb);
	udb_ptr_new(&ztree, udb, udb_base_get_userdata(udb));
	udb_radix_first(udb,&ztree,&n);
	while(n.data) {
		udb_ptr_set_rptr(&z, udb, &RADNODE(&n)->elem);
		udb_radix_next(udb, &n); /* store in case n is deleted */
		read_zone(udb, db, opt, num_children, dname_region, &z);
		udb_ptr_zero(&z, udb);
	}
	udb_ptr_unlink(&ztree, udb);
	udb_ptr_unlink(&n, udb);
	udb_ptr_unlink(&z, udb);
}

/** try to read the udb file or fail */
static int
try_read_udb(namedb_type* db, int fd, const char *filename,
	nsd_options_t* opt, size_t num_children)
{
	/*
	 * Temporary region used while loading domain names from the
	 * database.  The region is freed after each time a dname is
	 * read from the database.
	 */
	region_type *dname_region;

	assert(fd != -1);
	if(!(db->udb=udb_base_create_fd(filename, fd, &namedb_walkfunc,
		NULL))) {
		/* fd is closed by failed udb create call */
		VERBOSITY(1, (LOG_WARNING, "can not use %s, "
			"will create anew", filename));
		return 0;
	}
	/* sanity check if can be opened */
	if(udb_base_get_userflags(db->udb) != 0) {
		log_msg(LOG_WARNING, "%s was not closed properly, it might "
			"be corrupted, will create anew", filename);
		udb_base_free(db->udb);
		db->udb = NULL;
		return 0;
	}
	/* read if it can be opened */
	dname_region = region_create(xalloc, free);
	/* this operation does not fail, we end up with
	 * something, even if that is an empty namedb */
	read_zones(db->udb, db, opt, num_children, dname_region);
	region_destroy(dname_region);
	return 1;
}

struct namedb *
namedb_open (const char *filename, nsd_options_t* opt, size_t num_children)
{
	namedb_type *db;

	/*
	 * Region used to store the loaded database.  The region is
	 * freed in namedb_close.
	 */
	region_type *db_region;
	int fd;

	/* attempt to open, if does not exist, create a new one */
	fd = open(filename, O_RDWR);
	if(fd == -1) {
		if(errno != ENOENT) {
			log_msg(LOG_ERR, "%s: %s", filename, strerror(errno));
			return NULL;
		}
	}

#ifdef USE_MMAP_ALLOC
	db_region = region_create_custom(mmap_alloc, mmap_free, MMAP_ALLOC_CHUNK_SIZE,
		MMAP_ALLOC_LARGE_OBJECT_SIZE, MMAP_ALLOC_INITIAL_CLEANUP_SIZE, 1);
#else /* !USE_MMAP_ALLOC */
	db_region = region_create_custom(xalloc, free, DEFAULT_CHUNK_SIZE,
		DEFAULT_LARGE_OBJECT_SIZE, DEFAULT_INITIAL_CLEANUP_SIZE, 1);
#endif /* !USE_MMAP_ALLOC */
	db = (namedb_type *) region_alloc(db_region, sizeof(struct namedb));
	db->region = db_region;
	db->domains = domain_table_create(db->region);
	db->zonetree = radix_tree_create();
	db->diff_skip = 0;
	db->diff_pos = 0;

	if (gettimeofday(&(db->diff_timestamp), NULL) != 0) {
		log_msg(LOG_ERR, "unable to load %s: cannot initialize"
				 "timestamp", filename);
		region_destroy(db_region);
		close(fd);
                return NULL;
        }

	/* attempt to read the file (if it exists) */
	if(fd != -1) {
		if(!try_read_udb(db, fd, filename, opt, num_children))
			fd = -1;
	}
	/* attempt to create the file (if necessary or failed read) */
	if(fd == -1) {
		if(!(db->udb=udb_base_create_new(filename, &namedb_walkfunc,
			NULL))) {
			region_destroy(db_region);
			return NULL;
		}
		if(!udb_dns_init_file(db->udb)) {
			region_destroy(db->region);
			return NULL;
		}
	}
	zonec_setup_parser(db);
	return db;
}

/** the the file mtime stat (or nonexist or error) */
static int
file_get_mtime(const char* file, time_t* mtime, int* nonexist)
{
	struct stat s;
	if(stat(file, &s) != 0) {
		*mtime = 0;
		*nonexist = (errno == ENOENT);
		return 0;
	}
	*nonexist = 0;
	*mtime = s.st_mtime;
	return 1;
}

/** zone one zonefile into memory and revert one parse error, write to udb */
static void
namedb_read_zonefile(struct namedb* db, struct zone* zone)
{
	time_t mtime = 0;
	int nonexist = 0;
	unsigned int errors;
	if(!db || !zone || !zone->opts) return;
	if(!file_get_mtime(zone->opts->zonefile, &mtime, &nonexist)) {
		if(nonexist) {
			VERBOSITY(2, (LOG_INFO, "zonefile %s does not exist",
				zone->opts->zonefile));
		} else
			log_msg(LOG_ERR, "zonefile %s: %s",
				zone->opts->zonefile, strerror(errno));
		return;
	} else {
		/* check the mtime */
		if(udb_zone_get_mtime(db->udb, dname_name(domain_dname(
			zone->apex)), domain_dname(zone->apex)->name_size)
			>= (uint64_t)mtime) {
			VERBOSITY(3, (LOG_INFO, "zonefile %s is not modified",
				zone->opts->zonefile));
			return;
		}
	}

	assert(parser);
	zone->updated = 1;
	/* wipe zone from memory */
	delete_zone_rrs(db, zone);
#ifdef NSEC3
	nsec3_clear_precompile(db, zone);
	zone->nsec3_param = NULL;
#endif /* NSEC3 */
	errors = zonec_read(zone->opts->name, zone->opts->zonefile, zone);
	if(errors > 0) {
		region_type* dname_region;
		udb_ptr z;
		log_msg(LOG_ERR, "zone %s file %s read with %u errors",
			zone->opts->name, zone->opts->zonefile, errors);
		/* wipe (partial) zone from memory */
		zone->is_ok = 0;
		delete_zone_rrs(db, zone);
#ifdef NSEC3
		nsec3_clear_precompile(db, zone);
		zone->nsec3_param = NULL;
#endif /* NSEC3 */
		/* see if we can revert to the udb stored version */
		if(!udb_zone_search(db->udb, &z, dname_name(domain_dname(
			zone->apex)), domain_dname(zone->apex)->name_size)) {
			return;
		}
		/* read from udb */
		dname_region = region_create(xalloc, free);
		read_zone_data(db->udb, db, dname_region, &z, zone);
		region_destroy(dname_region);
		udb_ptr_unlink(&z, db->udb);
	} else {
		VERBOSITY(1, (LOG_INFO, "zone %s read with no errors",
			zone->opts->name));
		zone->is_ok = 1;
		/* store zone into udb */
		if(!write_zone_to_udb(db->udb, zone, mtime)) {
			log_msg(LOG_ERR, "failed to store zone in udb");
		}
	}
#ifdef NSEC3
	prehash_zone_complete(db, zone);
#endif
}

void namedb_check_zonefiles(struct namedb* db, nsd_options_t* opt,
	size_t num_children)
{
	zone_options_t* zo;
	zone_type* zone;
	region_type* dname_region = region_create(xalloc, free);
	/* check all zones in opt, create if not exist in main db */
	RBTREE_FOR(zo, zone_options_t*, opt->zone_options) {
		const dname_type* dname = dname_parse(dname_region, zo->name);
		if(!dname) {
			log_msg(LOG_ERR, "cannot parse name %s", zo->name);
			region_free_all(dname_region);
			continue;
		}
		/* find zone to go with it, or create it */
		zone = namedb_find_zone(db, dname);
		if(!zone) {
			zone = namedb_zone_create(db, dname, zo, num_children);
			region_free_all(dname_region);
		}
		namedb_read_zonefile(db, zone);
		region_free_all(dname_region);
	}
	region_destroy(dname_region);
}
