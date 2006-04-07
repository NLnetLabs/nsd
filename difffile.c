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
#include "rdata.h"

static int 
write_32(FILE *out, uint32_t val)
{
	val = htonl(val);
	return write_data(out, &val, sizeof(val));
}

static int 
write_8(FILE *out, uint8_t val)
{
	return write_data(out, &val, sizeof(val));
}

static int 
write_str(FILE *out, const char* str)
{
	uint32_t len = strlen(str);
	if(!write_32(out, len)) 
		return 0;
	return write_data(out, str, len);
}

void 
diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	if(opt->difffile) 
		filename = opt->difffile;

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

void 
diff_write_commit(const char* zone, uint32_t new_serial,
        uint8_t commit, const char* log_str, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	uint32_t len;
	if(opt->difffile) 
		filename = opt->difffile;

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

int 
db_crc_different(namedb_type* db)
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

static int 
read_32(FILE *in, uint32_t* result)
{
        if (fread(result, sizeof(*result), 1, in) == 1) {
                *result = ntohl(*result);
                return 1;
        } else {
                return 0;
        }
}

static int 
read_8(FILE *in, uint8_t* result)
{
        if (fread(result, sizeof(*result), 1, in) == 1) {
                return 1;
        } else {
                return 0;
        }
}

static int 
read_str(FILE* in, char* buf, size_t len)
{
	uint32_t disklen;
	if(!read_32(in, &disklen)) 
		return 0;
	if(disklen >= len) 
		return 0;
	if(fread(buf, disklen, 1, in) != 1) 
		return 0;
	buf[disklen] = 0;
	return 1;
}

static void 
rrset_delete(domain_type* domain, rrset_type* rrset)
{
	/* find previous */
	rrset_type** pp = &domain->rrsets;
	while(*pp && *pp != rrset) {
		pp = &( (*pp)->next );
	}
	if(!*pp) {
		/* rrset does not exist for domain */
		return;
	}
	*pp = rrset->next;

	log_msg(LOG_INFO, "delete rrset of %s type %s", 
		dname_to_string(domain_dname(domain),0),
		rrtype_to_string(rrset_rrtype(rrset)));

	/* is this a SOA rrset ? */
	if(rrset->zone->soa_rrset == rrset) {
		rrset->zone->soa_rrset = 0;
		rrset->zone->updated = 1;
	}
	if(rrset->zone->ns_rrset == rrset) {
		rrset->zone->ns_rrset = 0;
	}
#ifdef DNSSEC
	if(domain == rrset->zone->apex && rrset_rrtype(rrset) == TYPE_RRSIG) {
		int i;
		for (i = 0; i < rrset->rr_count; ++i) {
			if (rr_rrsig_type_covered(&rrset->rrs[i]) == TYPE_SOA) {
				rrset->zone->is_secure = 0;
				break;
			}
		}
	}
#endif
	/* is the node now an empty node (completely deleted) */
	if(domain->rrsets == 0) {
		domain->is_existing = 0;
	}
	rrset->rr_count = 0;
}

static int 
rdatas_equal(rdata_atom_type *a, rdata_atom_type *b, int num, uint16_t type)
{
	int k;
	for(k = 0; k < num; k++)
	{
		if(rdata_atom_is_domain(type, k)) {
			/* check dname */
			if(dname_compare(domain_dname(a[k].domain),
				domain_dname(b[k].domain))!=0)
				return 0;
		} else {
			/* check length */
			if(a[k].data[0] != b[k].data[0]) 
				return 0;
			/* check data */
			if(memcmp(a[k].data+1, b[k].data+1, a[k].data[0])!=0)
				return 0;
		}
	}
	return 1;
}

static int 
find_rr_num(rrset_type* rrset,
	uint16_t type, uint16_t klass, uint32_t ttl, 
	rdata_atom_type *rdatas, ssize_t rdata_num)
{
	int i;
	for(i=0; i<rrset->rr_count; ++i) {
		if(rrset->rrs[i].ttl == ttl &&
		   rrset->rrs[i].type == type &&
		   rrset->rrs[i].klass == klass &&
		   rrset->rrs[i].rdata_count == rdata_num &&
		   rdatas_equal(rdatas, rrset->rrs[i].rdatas, rdata_num, type))
			return i;
	}
	return -1;
}

static void 
delete_RR(namedb_type* db, const dname_type* dname, 
	uint16_t type, uint16_t klass, uint32_t ttl, 
	buffer_type* packet, size_t rdatalen, zone_type *zone,
	region_type* temp_region)
{
	domain_type *domain;
	rrset_type *rrset;
	domain = domain_table_find(db->domains, dname);
	if(!domain) {
		log_msg(LOG_ERR, "diff: domain %s does not exist", 
			dname_to_string(dname,0));
		return;
	}
	rrset = domain_find_rrset(domain, zone, type);
	if(!rrset) {
		log_msg(LOG_ERR, "diff: rrset %s does not exist", 
			dname_to_string(dname,0));
		return;
	} else {
		/* find the RR in the rrset */
		domain_table_type *temptable;
		rdata_atom_type *rdatas;
		ssize_t rdata_num;
		int rrnum;
		temptable = domain_table_create(temp_region);
		rdata_num = rdata_wireformat_to_rdata_atoms(
			temp_region, temptable, type, rdatalen, packet, &rdatas);
		if(rdata_num == -1) {
			log_msg(LOG_ERR, "diff: bad rdata for %s", 
				dname_to_string(dname,0));
			return;
		}
		rrnum = find_rr_num(rrset, type, klass, ttl, rdatas, rdata_num);
		if(rrnum == -1) {
			log_msg(LOG_ERR, "diff: RR %s does not exist", 
				dname_to_string(dname,0));
			return;
		}
		if(rrset->rr_count == 1) {
			/* delete entire rrset */
			rrset_delete(domain, rrset);
		} else {
			/* swap out the bad RR and decrease the count */
			if(rrnum < rrset->rr_count-1)
				rrset->rrs[rrnum] = rrset->rrs[rrset->rr_count-1];
			memset(&rrset->rrs[rrset->rr_count-1], 0, sizeof(rr_type));
			rrset->rr_count --;
		}
	}
}

static void 
add_RR(namedb_type* db, const dname_type* dname, 
	uint16_t type, uint16_t klass, uint32_t ttl, 
	buffer_type* packet, size_t rdatalen, zone_type *zone)
{
	domain_type* domain;
	rrset_type* rrset;
	domain = domain_table_find(db->domains, dname);
	rdata_atom_type *rdatas;
	rr_type *rrs_old;
	ssize_t rdata_num;
	int rrnum;
	if(!domain) {
		/* create the domain */
		domain = domain_table_insert(db->domains, dname);
	}
	rrset = domain_find_rrset(domain, zone, type);
	if(!rrset) {
		/* create the rrset */
		rrset = region_alloc(db->region, sizeof(rrset_type));
		rrset->zone = zone;
		rrset->rrs = 0;
		rrset->rr_count = 0;
		domain_add_rrset(domain, rrset);
	}

	rdata_num = rdata_wireformat_to_rdata_atoms(
		db->region, db->domains, type, rdatalen, packet, &rdatas);
	if(rdata_num == -1) {
		log_msg(LOG_ERR, "diff: bad rdata for %s", 
			dname_to_string(dname,0));
		return;
	}
	rrnum = find_rr_num(rrset, type, klass, ttl, rdatas, rdata_num);
	if(rrnum != -1) {
		log_msg(LOG_ERR, "diff: RR %s already exists", 
			dname_to_string(dname,0));
		/* ignore already existing RR: lenient accepting of messages */
		return;
	}
	
	/* re-alloc the rrs and add the new */
	rrs_old = rrset->rrs;
	rrset->rrs = region_alloc(db->region, 
		(rrset->rr_count+1) * sizeof(rr_type));
	if(rrs_old)
		memcpy(rrset->rrs, rrs_old, rrset->rr_count * sizeof(rr_type));
	rrset->rr_count ++;

	rrset->rrs[rrset->rr_count - 1].owner = domain;
	rrset->rrs[rrset->rr_count - 1].rdatas = rdatas;
	rrset->rrs[rrset->rr_count - 1].ttl = ttl;
	rrset->rrs[rrset->rr_count - 1].type = type;
	rrset->rrs[rrset->rr_count - 1].klass = klass;
	rrset->rrs[rrset->rr_count - 1].rdata_count = rdata_num;

	/* see if it is a SOA */
	if(domain == zone->apex) {
		if(type == TYPE_SOA) {
			uint32_t soa_minimum;
			zone->soa_rrset = rrset;
			zone->updated = 1;
			/* BUG #103 tweaked SOA ttl value */
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
			memcpy(&soa_minimum, rdata_atom_data(rrset->rrs->rdatas[6]),
				rdata_atom_size(rrset->rrs->rdatas[6]));
			if (rrset->rrs->ttl > ntohl(soa_minimum)) {
				rrset->zone->soa_nx_rrset->rrs[0].ttl = ntohl(soa_minimum);
			}
		}
		if(type == TYPE_NS) {
			zone->ns_rrset = rrset;
		}
#ifdef DNSSEC
		if(type == TYPE_RRSIG) {
			int i;
			for (i = 0; i < rrset->rr_count; ++i) {
				if (rr_rrsig_type_covered(&rrset->rrs[i]) == TYPE_SOA) {
					zone->is_secure = 1;
					break;
				}
			}
		}
#endif
	}
}

static zone_type* 
find_zone(namedb_type* db, const dname_type* zone_name, nsd_options_t* opt)
{
	domain_type *domain;
	zone_type* zone;
	domain = domain_table_find(db->domains, zone_name);
	if(!domain) {
		log_msg(LOG_INFO, "xfr: creating domain %s",
			dname_to_string(zone_name,0));
		/* create the zone and domain of apex (zone has config options) */
		domain = domain_table_insert(db->domains, zone_name);
	} else {
		zone = namedb_find_zone(db, domain);
		/* check apex to make sure we don't find a parent zone */
		if(zone && zone->apex == domain)
			return zone;
	}
	/* create the zone */
	log_msg(LOG_INFO, "xfr: creating zone_type %s",
		dname_to_string(zone_name,0));
	zone = (zone_type *) region_alloc(db->region, sizeof(zone_type));
	zone->next = db->zones;
	db->zones = zone;
	db->zone_count++;
	zone->apex = domain;
	zone->soa_rrset = 0;
	zone->soa_nx_rrset = 0;
	zone->ns_rrset = 0;
	zone->opts = zone_options_find(opt, domain_dname(zone->apex)); 
	if(!zone->opts) {
		log_msg(LOG_ERR, "xfr: zone %s not in config.",
			dname_to_string(zone_name,0));
		return 0;
	}
	zone->number = db->zone_count;
	zone->is_secure = 0;
	zone->updated = 1;
	return zone;
}

static void 
delete_zone_rrs(zone_type* zone)
{
	rrset_type *rrset;
	domain_type *domain = zone->apex;
	/* go through entire tree below the zone apex (incl subzones) */
	while(domain && dname_is_subdomain(
		domain_dname(domain), domain_dname(zone->apex)))
	{
		log_msg(LOG_INFO, "delete zone visit %s",
			dname_to_string(domain_dname(domain),0));
		/* delete all rrsets of the zone */
		while((rrset = domain_find_any_rrset(domain, zone))) {
			rrset_delete(domain, rrset);
		}
		domain = domain_next(domain);
	}

	assert(zone->soa_rrset == 0);
	/* keep zone->soa_nx_rrset alloced */
	assert(zone->ns_rrset == 0);
	assert(zone->is_secure == 0);
	assert(zone->updated == 1);
}

static int 
apply_ixfr(namedb_type* db, FILE *in, const fpos_t* startpos, 
	const char* zone, uint32_t serialno, nsd_options_t* opt)
{
	int delete_mode;
	int is_axfr;
	uint32_t msglen;
	int qcount, ancount, rrcount;
	buffer_type* packet;
	region_type* region;
	int i;
	uint16_t rrlen;
	const dname_type *dname_zone, *dname;
	zone_type* zone_db;

	if(fsetpos(in, startpos) == -1) {
		log_msg(LOG_INFO, "could not fsetpos: %s.", strerror(errno));
		return 0;
	}
	/* read ixfr packet RRs and apply to in memory db */

	if(!read_32(in, &msglen)) {
		log_msg(LOG_ERR, "could not read len");
		return 0;
	}

	/* read header */
	if(msglen < QHEADERSZ) {
		log_msg(LOG_ERR, "msg too short");
		return 0;
	}

	region = region_create(xalloc, free);
	if(!region) {
		log_msg(LOG_ERR, "out of memory");
		return 0;
	}
	packet = buffer_create(region, QIOBUFSZ);
	dname_zone = dname_parse(region, zone);
	zone_db = find_zone(db, dname_zone, opt);
	if(!zone_db) {
		log_msg(LOG_ERR, "no zone exists");
		region_destroy(region);
		return 0;
	}
	
	if(msglen > QIOBUFSZ) {
		log_msg(LOG_ERR, "msg too long");
		region_destroy(region);
		return 0;
	}
	buffer_clear(packet);
	if(fread(buffer_begin(packet), msglen, 1, in) != 1) {
		log_msg(LOG_ERR, "short fread: %s", strerror(errno));
		region_destroy(region);
		return 0;
	}
	buffer_set_limit(packet, msglen);

	/* only answer section is really used, question, additional and 
	   authority section RRs are skipped */
	qcount = QDCOUNT(packet);
	ancount = ANCOUNT(packet);
	buffer_skip(packet, QHEADERSZ);

	/* skip queries */
	for(i=0; i<qcount; ++i)
		if(!packet_skip_rr(packet, 1)) {
			log_msg(LOG_ERR, "bad RR in question section");
			region_destroy(region);
			return 0;
		}

	/* first RR: check if SOA and correct zone & serialno */
	dname = dname_make_from_packet(region, packet, 1, 1);
	if(!dname) {
		log_msg(LOG_ERR, "could not parse dname");
		region_destroy(region);
		return 0;
	}
	if(dname_compare(dname_zone, dname) != 0) {
		log_msg(LOG_ERR, "SOA dname %s not equal to zone",
			dname_to_string(dname,0));
		log_msg(LOG_ERR, "zone dname is %s",
			dname_to_string(dname_zone,0));
		region_destroy(region);
		return 0;
	}
	if(!buffer_available(packet, 10)) {
		log_msg(LOG_ERR, "bad SOA RR");
		region_destroy(region);
		return 0;
	}
	if(buffer_read_u16(packet) != TYPE_SOA ||
		buffer_read_u16(packet) != CLASS_IN) {
		log_msg(LOG_ERR, "first RR not SOA IN");
		region_destroy(region);
		return 0;
	}
	buffer_skip(packet, sizeof(uint32_t)); /* ttl */
	if(!buffer_available(packet, buffer_read_u16(packet)) ||
		!packet_skip_dname(packet) /* skip prim_ns */ ||
		!packet_skip_dname(packet) /* skip email */) {
		log_msg(LOG_ERR, "bad SOA RR");
		region_destroy(region);
		return 0;
	}
	if(buffer_read_u32(packet) != serialno) {
		buffer_skip(packet, -4);
		log_msg(LOG_ERR, "SOA serial %d different from commit %d",
			buffer_read_u32(packet), serialno);
		region_destroy(region);
		return 0;
	}
	buffer_skip(packet, sizeof(uint32_t)*4);

	delete_mode = 0;
	is_axfr = 0;
	for(rrcount = 1; rrcount < ancount; ++rrcount)
	{
		uint16_t type, klass;
		uint32_t ttl;

		if(!(dname=dname_make_from_packet(region, packet, 1,1))) {
			log_msg(LOG_ERR, "bad xfr RR dname %d", rrcount);
			region_destroy(region);
			return 0;
		}
		if(!buffer_available(packet, 10)) {
			log_msg(LOG_ERR, "bad xfr RR format %d", rrcount);
			region_destroy(region);
			return 0;
		}
		type = buffer_read_u16(packet);
		klass = buffer_read_u16(packet);
		ttl = buffer_read_u32(packet);
		rrlen = buffer_read_u16(packet);
		if(!buffer_available(packet, rrlen)) {
			log_msg(LOG_ERR, "bad xfr RR rdata %d, len %d have %d", 
				rrcount, rrlen, buffer_remaining(packet));
			region_destroy(region);
			return 0;
		}

		if(rrcount == 1 && type != TYPE_SOA) {
			/* second RR: if not SOA: this is an AXFR; delete all zone contents */
			delete_zone_rrs(zone_db);
			/* add everything else (incl end SOA) */
			delete_mode = 0;
			is_axfr = 1;
		}
		if(type == TYPE_SOA && !is_axfr) {
			/* switch from delete-part to add-part and back again,
			   just before soa - so it gets deleted and added too */
			/* this means we switch to delete mode for the final SOA */
			delete_mode = !delete_mode;
		}
		if(type == TYPE_TSIG || type == TYPE_OPT) {
			/* ignore pseudo RRs */
			continue;
		}
		log_msg(LOG_INFO, "xfr %s RR dname is %s type %s", 
			delete_mode?"del":"add",
			dname_to_string(dname,0), rrtype_to_string(type));
		if(delete_mode) {
			/* delete this rr */
			if(!is_axfr && type == TYPE_SOA && rrcount==ancount-1)
				continue; /* do not delete final SOA RR for IXFR */
			delete_RR(db, dname, type, klass, ttl, packet, rrlen, zone_db,
				region);
		}
		else
		{
			/* add this rr */
			add_RR(db, dname, type, klass, ttl, packet, rrlen, zone_db);
		}
	}
	region_destroy(region);
	return 1;
}

/* for multiple tcp packets use a data structure that has
 * a rbtree (zone_names) with for each zone:
 * 	has a rbtree by sequence number
 *		with inside a serial_number and ID (for checking only)
 *		and contains a fpos_t to the IXFR packet in the file.
 * so when you get a commit for a zone, get zone obj, find sequence,
 * then check if you have all sequence numbers available. Apply all packets.
 */
static fpos_t last_ixfr_pos;
static int saw_ixfr = 0;

static int 
read_sure_part(namedb_type* db, FILE *in, nsd_options_t* opt)
{
	char zone_buf[512];
	char log_buf[5120];
	uint32_t serial;
	uint8_t committed;
	fpos_t resume_pos;
	if(!saw_ixfr) {
		log_msg(LOG_ERR, "diff file commit without IXFR");
		return 1;
	}
	/* read zone name and serial */
	if(!read_str(in, zone_buf, sizeof(zone_buf)) ||
		!read_32(in, &serial) ||
		!read_8(in, &committed) ||
		!read_str(in, log_buf, sizeof(log_buf)) )
	{
		log_msg(LOG_ERR, "diff file bad commit part");
		return 1;
	}

	/* read in completely */
	if(fgetpos(in, &resume_pos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos: %s.", strerror(errno));
		return 0;
	}
	if(committed)
	{
		log_msg(LOG_INFO, "processing xfr: %s", log_buf);
		if(!apply_ixfr(db, in, &last_ixfr_pos, zone_buf, serial, opt)) {
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

static int 
read_process_part(namedb_type* db, FILE *in, uint32_t type,
	nsd_options_t* opt)
{
	uint32_t len, len2;
	fpos_t startpos;

	if(fgetpos(in, &startpos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos: %s.", strerror(errno));
		return 0;
	}

	if(!read_32(in, &len)) return 1;

	if(type == DIFF_PART_IXFR) {
		log_msg(LOG_INFO, "part IXFR len %d", len);
		saw_ixfr = 1;
		last_ixfr_pos = startpos;
		if(fseeko(in, len, SEEK_CUR) == -1)
			log_msg(LOG_INFO, "fseek failed: %s", strerror(errno));
	}
	else if(type == DIFF_PART_SURE) {
		log_msg(LOG_INFO, "part SURE len %d", len);
		if(!read_sure_part(db, in, opt)) 
			return 0;
	} else {
		log_msg(LOG_INFO, "unknown part %x len %d", type, len);
		return 0;
	}
	if(!read_32(in, &len2) || len != len2) 
		return 1;

	/* part was OK, we can skip to here next time. */
	if(fgetpos(in, &db->diff_pos) == -1) {
		log_msg(LOG_INFO, "could not fgetpos: %s.",
			strerror(errno));
		db->diff_skip = 0;
	}
	else 
		db->diff_skip = 1;
	return 1;
}

int 
diff_read_file(namedb_type* db, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	uint32_t type;

	if(opt->difffile) 
		filename = opt->difffile;

	saw_ixfr = 0;
	df = fopen(filename, "r");
	if(!df) {
		log_msg(LOG_INFO, "could not open file %s for reading: %s",
			filename, strerror(errno));
		return 1;
	}
	if(db->diff_skip) {
		log_msg(LOG_INFO, "skip diff file");
		if(fsetpos(df, &db->diff_pos)==-1) {
			log_msg(LOG_INFO, "could not fsetpos file %s: %s. Reread from start.",
				filename, strerror(errno));
		}
	}

	while(read_32(df, &type)) 
	{
		log_msg(LOG_INFO, "iter loop");
		if(!read_process_part(db, df, type, opt))
		{
			log_msg(LOG_INFO, "error processing diff file");
			return 0;
		}
	}
	log_msg(LOG_INFO, "end of diff file read");
	
	fclose(df);
	return 1;
}

static int diff_broken(FILE *df, off_t* break_pos)
{
	uint32_t type, len, len2;
	*break_pos = ftello(df);

	/* try to read and validate parts of the file */
	while(read_32(df, &type)) /* cannot read type is no error, normal EOF */
	{
		log_msg(LOG_INFO, "garb part");
		/* check type */
		if(type != DIFF_PART_IXFR && type != DIFF_PART_SURE)
			return 1;
		/* check length */
		if(!read_32(df, &len))
			return 1; /* EOF inside the part is error */
		if(fseeko(df, len, SEEK_CUR) == -1)
		{
			log_msg(LOG_INFO, "fseeko failed: %s", strerror(errno));
			return 1;
		}
		/* fseek clears EOF flag, but try reading length value,
		   if EOF, the part is truncated */
		if(!read_32(df, &len2))
			return 1;
		if(len != len2)
			return 1; /* bad part, lengths must agree */
		/* this part is ok */
		*break_pos = ftello(df);
	}
	return 0;
}

void diff_snip_garbage(namedb_type* db, nsd_options_t* opt)
{
	off_t break_pos;
	const char* filename = DIFFFILE;
	FILE *df;

	/* open file here and keep open, so it cannot change under our nose */
	if(opt->difffile)
		filename = opt->difffile;
	df = fopen(filename, "r+");
	if(!df) {
		log_msg(LOG_INFO, "could not open file %s for garbage collecting: %s",
			filename, strerror(errno));
		return;
	}
	/* and skip into file, since nsd does not read anything before the pos */
	if(db->diff_skip) {
		log_msg(LOG_INFO, "garbage collect skip diff file");
		if(fsetpos(df, &db->diff_pos)==-1) {
			log_msg(LOG_INFO, "could not fsetpos file %s: %s.", 
				filename, strerror(errno));
			fclose(df);
			return;
		}
	}

	/* detect break point */
	if(diff_broken(df, &break_pos))
	{
		/* snip off at break_pos */
		log_msg(LOG_INFO, "snipping off trailing partial part of %s", 
			filename);
		ftruncate(fileno(df), break_pos);
	}

	fclose(df);
}

