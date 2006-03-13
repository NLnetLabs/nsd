/*
 * difffile.x - DIFF file handling source code. Read and write diff files.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "difffile.h"
#include "util.h"
#include "packet.h"

#define DIFFFILE "nsd.diff"

static int write_32(FILE *out, uint32_t val)
{
	val = htonl(val);
	return write_data(out, &val, sizeof(val));
}

static int write_8(FILE *out, uint8_t val)
{
	return write_data(out, &val, sizeof(val));
}

static int write_str(FILE *out, const char* str)
{
	uint32_t len = strlen(str);
	if(!write_32(out, len)) return 0;
	return write_data(out, str, len);
}

void diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	if(opt->difffile) filename = opt->difffile;

	df = fopen(filename, "a");
	if(!df) {
		log_msg(LOG_ERR, "could not open file %s for append: %s",
			filename, strerror(errno));
		return;
	}

	if(!write_32(df, DIFF_PART_IXFR) ||
		!write_32(df, len) ||
		!write_data(df, data, len) ||
		!write_32(df, len)) 
	{
		log_msg(LOG_ERR, "could not write to file %s: %s",
			filename, strerror(errno));
	}
	fclose(df);
}

void diff_write_commit(const char* zone, uint32_t new_serial,
        uint8_t commit, const char* log_str,
        nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	uint32_t len;
	if(opt->difffile) filename = opt->difffile;

	df = fopen(filename, "a");
	if(!df) {
		log_msg(LOG_ERR, "could not open file %s for append: %s",
			filename, strerror(errno));
		return;
	}

	len = strlen(zone)+sizeof(len) + sizeof(new_serial) + 
		sizeof(commit) + strlen(log_str)+sizeof(len);

	if(!write_32(df, DIFF_PART_SURE) ||
		!write_32(df, len) ||
		!write_str(df, zone) ||
		!write_32(df, new_serial) ||
		!write_8(df, commit) ||
		!write_str(df, log_str) ||
		!write_32(df, len)) 
	{
		log_msg(LOG_ERR, "could not write to file %s: %s",
			filename, strerror(errno));
	}
	fclose(df);
}

int db_crc_different(namedb_type* db)
{
	FILE *fd = fopen(db->filename, "r");
	uint32_t crc_file;
	char buf[NAMEDB_MAGIC_SIZE];
	if(fd == NULL) {
		log_msg(LOG_ERR, "unable to load %s: %s",
			db->filename, strerror(errno));
		return -1;
	}
	
	/* seek to position of CRC, check it and magic no */
	if(fsetpos(fd, &db->crc_pos)==-1) {
		log_msg(LOG_ERR, "unable to fsetpos %s: %s. db changed?",
			db->filename, strerror(errno));
		fclose(fd);
		return -1;
	}

	if(fread(&crc_file, sizeof(crc_file), 1, fd) != 1) {
		log_msg(LOG_ERR, "could not read %s CRC. db changed?", db->filename);
		fclose(fd);
		return -1;
	}
	crc_file = ntohl(crc_file);

	if(fread(buf, sizeof(char), sizeof(buf), fd) != sizeof(buf)
	   || memcmp(buf, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) != 0) {
		log_msg(LOG_ERR, "could not read %s magic. db changed?", db->filename);
		fclose(fd);
		return -1;
	}

	fclose(fd);

	if(db->crc == crc_file)
		return 0;
	return 1;
}

static int read_32(FILE *in, uint32_t* result)
{
        if (fread(result, sizeof(*result), 1, in) == 1) {
                *result = ntohl(*result);
                return 1;
        } else {
                return 0;
        }
}

static int read_8(FILE *in, uint8_t* result)
{
        if (fread(result, sizeof(*result), 1, in) == 1) {
                return 1;
        } else {
                return 0;
        }
}

static int read_str(FILE* in, char* buf, size_t len)
{
	uint32_t disklen;
	if(!read_32(in, &disklen)) return 0;
	if(disklen >= len) return 0;
	if(fread(buf, disklen, 1, in) != 1) return 0;
	buf[disklen] = 0;
	return 1;
}

static void delete_RR(namedb_type* db, const dname_type* dname_zone, 
	const dname_type* dname, 
	uint16_t type, uint16_t klass)
{
	domain_type *domain;
	domain = domain_table_find(db->domains, dname);
	if(!domain) {
		log_msg(LOG_ERR, "diff: domain %s does not exist", 
			dname_to_string(dname,0));
		return;
	}
}

static void add_RR(namedb_type* db, const dname_type* dname_zone, 
	const dname_type* dname, 
	uint16_t type, uint16_t klass, uint32_t ttl, 
	uint8_t* rdata, size_t rdatalen)
{
	domain_type *domain;
	domain = domain_table_find(db->domains, dname);
	if(!domain) {
		log_msg(LOG_ERR, "diff: domain %s does not exist", 
			dname_to_string(dname,0));
		return;
	}
	
}

static void delete_zone(namedb_type* db, const dname_type* zone_name)
{
	/* delete all RRs in the zone */
	domain_type *domain;
	zone_type* zone;

	domain = domain_table_find(db->domains, zone_name);
	if(!domain) {
		log_msg(LOG_ERR, "axfr: domain %s does not exist",
			dname_to_string(zone_name,0));
		return;
	}
	zone = namedb_find_zone(db, domain);
	if(!zone) {
		log_msg(LOG_ERR, "axfr: zone %s does not exist",
			dname_to_string(zone_name,0));
		return;
	}
	
	/* some way to list all RRs in a zone */
	zone->apex = 0;
	zone->soa_rrset = 0;
	zone->soa_nx_rrset = 0;
	zone->ns_rrset = 0;
}

static int apply_ixfr(namedb_type* db, FILE *in,
	const fpos_t* startpos, const char* zone, uint32_t serialno)
{
	int delete_mode;
	int is_axfr;
	uint32_t type, msglen;
	int qcount, ancount, rrcount;
	buffer_type* packet;
	region_type* region;
	int i;
	uint16_t rrlen;
	const dname_type *dname_zone, *dname;

	if(fsetpos(in, startpos) == -1) {
		log_msg(LOG_INFO, "could not fsetpos: %s.", strerror(errno));
		return 0;
	}
	/* read ixfr packet RRs and apply to in memory db */

	if(!read_32(in, &type) ||
		!read_32(in, &msglen)) return 0;
	assert(type == DIFF_PART_IXFR);

	/* read header */
	if(msglen < QHEADERSZ) return 0;

	region = region_create(xalloc, free);
	if(!region) return 0;
	packet = buffer_create(region, QIOBUFSZ);
	dname_zone = dname_parse(region, zone);
	
	if(msglen > QIOBUFSZ) return 0;
	buffer_clear(packet);
	if(fread(buffer_begin(packet), msglen, 1, in) != 1) return 0;
	buffer_set_limit(packet, msglen);

	qcount = QDCOUNT(packet);
	ancount = ANCOUNT(packet);
	buffer_skip(packet, QHEADERSZ);

	/* skip queries */
	for(i=0; i<qcount; ++i)
		if(!packet_skip_dname(packet)) return 0;

	/* first RR: check if SOA and correct zone & serialno */
	dname = dname_make_from_packet(region, packet, 1, 1);
	if(!dname) return 0;
	if(dname_compare(dname_zone, dname) != 0) return 0;
	if(!buffer_available(packet, 10)) return 0;
	if(buffer_read_u16(packet) != TYPE_SOA ||
		buffer_read_u16(packet) != CLASS_IN) return 0;
	buffer_skip(packet, sizeof(uint32_t)); /* ttl */
	rrlen = buffer_read_u16(packet);
	if(!buffer_available(packet, rrlen)) return 0;
	if(buffer_read_u32(packet) != serialno) return 0;
	buffer_skip(packet, sizeof(uint32_t)*4);

	delete_mode = 0;
	is_axfr = 0;
	for(rrcount = 1; rrcount < ancount; ++rrcount)
	{
		uint16_t type, klass;
		uint32_t ttl;

		if(!(dname=dname_make_from_packet(region, packet, 1,1))) return 0;
		if(!buffer_available(packet, 10)) return 0;
		type = buffer_read_u16(packet);
		klass = buffer_read_u16(packet);
		ttl = buffer_read_u32(packet);
		rrlen = buffer_read_u16(packet);
		if(!buffer_available(packet, rrlen)) return 0;

		if(rrcount == 1 && type != TYPE_SOA) {
			/* second RR: if not SOA: this is an AXFR; delete all zone contents */
			delete_zone(db, dname_zone);
			/* add everything else (incl end SOA) */
			delete_mode = 0;
			is_axfr = 1;
		}
		if(type == TYPE_SOA && !is_axfr) {
			/* switch from delete-part to add-part and back again,
			   just before soa - so it gets deleted and added too */
			delete_mode = !delete_mode;
		}
		if(delete_mode) {
			/* delete this rr */
			delete_RR(db, dname_zone, dname, type, klass);
		}
		else
		{
			/* add this rr */
			add_RR(db, dname_zone, dname, type, klass, ttl, 
				buffer_current(packet), rrlen);
		}
		buffer_skip(packet, rrlen);
	}
	region_destroy(region);
	return 1;
}

static fpos_t last_ixfr_pos;
static int saw_ixfr = 0;

static int read_sure_part(namedb_type* db, FILE *in)
{
	char zone_buf[512];
	char log_buf[5120];
	uint32_t serial;
	uint8_t committed;
	fpos_t resume_pos;
	if(!saw_ixfr) {
		log_msg(LOG_ERR, "diff file commit without IXFR");
		return 0;
	}
	/* read zone name and serial */
	if(!read_str(in, zone_buf, sizeof(zone_buf)) ||
		!read_32(in, &serial) ||
		!read_8(in, &committed) ||
		!read_str(in, log_buf, sizeof(log_buf)) )
	{
		log_msg(LOG_ERR, "diff file bad commit part");
		return 0;
	}

	/* read in completely */
	if(fgetpos(in, &resume_pos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos: %s.", strerror(errno));
		return 0;
	}
	if(committed)
	{
		log_msg(LOG_INFO, "processing xfr: %s", log_buf);
		if(!apply_ixfr(db, in, &last_ixfr_pos, zone_buf, serial)) {
			log_msg(LOG_ERR, "bad ixfr packet");
		}
	}
	else 	log_msg(LOG_INFO, "skipping xfr: %s", log_buf);
	
	if(fsetpos(in, &resume_pos) == -1) {
		log_msg(LOG_INFO, "could not fsetpos: %s.", strerror(errno));
		return 0;
	}
	
	return 1;
}

static int read_process_part(namedb_type* db, FILE *in)
{
	uint32_t type, len, len2;
	fpos_t startpos;

	if(fgetpos(in, &startpos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos: %s.", strerror(errno));
		return 0;
	}

	if(!read_32(in, &type) || !read_32(in, &len)) return 0;
	log_msg(LOG_INFO, "Part %x len %d", type, len);

	if(type == DIFF_PART_IXFR) {
		saw_ixfr = 1;
		last_ixfr_pos = startpos;
		fseek(in, len, SEEK_CUR);
	}
	else if(type == DIFF_PART_SURE) {
		if(!read_sure_part(db, in)) return 0;
	}

	if(!read_32(in, &len2) || len != len2) return 0;
	return 1;
}

int diff_read_file(namedb_type* db, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	if(opt->difffile) filename = opt->difffile;

	saw_ixfr = 0;
	df = fopen(filename, "r");
	if(!df) {
		log_msg(LOG_INFO, "could not open file %s for reading: %s",
			filename, strerror(errno));
		return 1;
	}
	if(db->diff_skip) {
		if(fsetpos(df, &db->diff_pos)==-1) {
			log_msg(LOG_INFO, "could not fsetpos file %s: %s. Reread from start.",
				filename, strerror(errno));
		}
	}

	while(!feof(df)) {
		if(!read_process_part(db, df))
		{
			if(feof(df)) return 1;
			else return 0;
		}
	}
	
	if(fgetpos(df, &db->diff_pos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos file %s: %s.",
			filename, strerror(errno));
	}
	else db->diff_skip = 1;
	
	fclose(df);
	return 1;
}
