/*
 * difffile.h - nsd.diff file handling header file. Read/write diff files.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef DIFFFILE_H
#define DIFFFILE_H

#include "rbtree.h"
#include "namedb.h"
#include "options.h"
#include "udb.h"
struct nsd;
struct nsdst;

#define DIFF_PART_IXFR ('I'<<24 | 'X'<<16 | 'F'<<8 | 'R')
#define DIFF_PART_SURE ('S'<<24 | 'U'<<16 | 'R'<<8 | 'E')

/*
 * Used to pass commit logs
 */
struct diff_log {
	char* zone_name;
	char* error;
	char* comment;
	struct diff_log* next;
};

/* write an xfr packet data to the diff file, type=IXFR.
   The diff file is created if necessary. */
void diff_write_packet(const char* zone, uint32_t new_serial, uint16_t id,
	uint32_t seq_nr, uint8_t* data, size_t len, nsd_options_t* opt);

/*
 * Write a commit packet to the diff file, type=SURE.
 * The zone data (preceding ixfr packets) are committed.
 * See NSD-DIFFFILE for meaning of the arguments.
 */
void diff_write_commit(const char* zone, uint32_t old_serial,
	uint32_t new_serial, uint16_t id, uint32_t num_parts,
	uint8_t commit, const char* log_msg, const char* patname,
	nsd_options_t* opt);

/* read the diff file and apply to the database in memory.
   It will attempt to skip bad data.
   If you pass a non-null value log, log comments are alloced in namedb.region
   then, *log must be 0 on start of call (entries are prepended).
   returns 0 on an unrecoverable error. */
int diff_read_file(namedb_type* db, nsd_options_t* opt, struct diff_log** log,
	udb_base* taskudb, udb_ptr* last_task);

/* check the diff file for garbage at the end (bad type, partial write)
 * and snip it off.
 */
void diff_snip_garbage(namedb_type* db, nsd_options_t* opt);

/*
 * These functions read parts of the diff file.
 */
int diff_read_32(FILE *in, uint32_t* result);
int diff_read_16(FILE *in, uint16_t* result);
int diff_read_8(FILE *in, uint8_t* result);
int diff_read_str(FILE* in, char* buf, size_t len);

/* delete the RRs for a zone from memory */
void delete_zone_rrs(namedb_type* db, zone_type* zone);
/* delete an RR */
int delete_RR(namedb_type* db, const dname_type* dname,
	uint16_t type, uint16_t klass,
	buffer_type* packet, size_t rdatalen, zone_type *zone,
	region_type* temp_region, struct udb_ptr* udbz);
/* add an RR */
int add_RR(namedb_type* db, const dname_type* dname,
	uint16_t type, uint16_t klass, uint32_t ttl,
	buffer_type* packet, size_t rdatalen, zone_type *zone,
	struct udb_ptr* udbz);

/* task udb structure */
struct task_list_d {
	/** next task in list */
	udb_rel_ptr next;
	/** task type */
	enum {
		/** expire or un-expire a zone */
		task_expire,
		/** apply an ixfr or axfr to a zone */
		task_apply_xfr,
		/** soa info for zone */
		task_soa_info,
		/** done with apply xfr */
		task_done_apply_xfr,
		/** check mtime of zonefiles and read them, done on SIGHUP */
		task_check_zonefiles,
		/** set verbosity */
		task_set_verbosity,
		/** statistic info */
		task_stat_info,
		/** add a zone */
		task_add_zone,
		/** delete zone */
		task_del_zone
	} task_type;
	uint32_t size; /* size of this struct */

	/** soainfo: zonename dname, soaRR wireform */
	/** expire: zonename, boolyesno */
	/** apply_xfr: zonename, filename-serial */
	/** done_apply_xfr: zonename, filename-serial */
	uint32_t serial;
	uint64_t yesno;
	struct dname zname[0];
};
#define TASKLIST(ptr) ((struct task_list_d*)UDB_PTR(ptr))
/** create udb for tasks */
struct udb_base* task_file_create(const char* file);
void task_remap(udb_base* udb);
void task_process_sync(udb_base* udb);
void task_clear(udb_base* udb);
void task_new_soainfo(udb_base* udb, udb_ptr* last, struct zone* z);
void task_new_expire(udb_base* udb, udb_ptr* last,
	const struct dname* z, int expired);
void* task_new_stat_info(udb_base* udb, udb_ptr* last, struct nsdst* stat,
	size_t child_count);
void task_new_check_zonefiles(udb_base* udb, udb_ptr* last);
void task_new_set_verbosity(udb_base* udb, udb_ptr* last, int v);
void task_new_add_zone(udb_base* udb, udb_ptr* last, const char* zone,
	const char* pattern);
void task_new_del_zone(udb_base* udb, udb_ptr* last, const dname_type* dname);
void task_process_in_reload(struct nsd* nsd, udb_base* udb, udb_ptr *last_task,
	udb_ptr* task);
void task_process_expire(namedb_type* db, struct task_list_d* task);

#endif /* DIFFFILE_H */
