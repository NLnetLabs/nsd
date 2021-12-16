/*
 * ixfrcreate.c -- generating IXFR differences from zone files.
 *
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include "ixfrcreate.h"
#include "namedb.h"
#include "ixfr.h"

/* spool a uint16_t to file */
static int spool_u16(FILE* out, uint16_t val)
{
	if(!fwrite(&val, sizeof(val), 1, out)) {
		return 0;
	}
	return 1;
}

/* spool a uint32_t to file */
static int spool_u32(FILE* out, uint32_t val)
{
	if(!fwrite(&val, sizeof(val), 1, out)) {
		return 0;
	}
	return 1;
}

/* spool dname to file */
static int spool_dname(FILE* out, dname_type* dname)
{
	uint16_t namelen = dname->name_size;
	if(!fwrite(&namelen, sizeof(namelen), 1, out)) {
		return 0;
	}
	if(!fwrite(dname_name(dname), namelen, 1, out)) {
		return 0;
	}
	return 1;
}

/* calculate the rdatalen of an RR */
static size_t rr_rdatalen_uncompressed(rr_type* rr)
{
	int i;
	size_t rdlen_uncompressed = 0;
	for(i=0; i<rr->rdata_count; i++) {
		if(rdata_atom_is_domain(rr->type, i)) {
			rdlen_uncompressed += domain_dname(rr->rdatas[i].domain)
				->name_size;
		} else {
			rdlen_uncompressed += rr->rdatas[i].data[0];
		}
	}
	return rdlen_uncompressed;
}

/* spool the data for one rr into the file */
static int spool_rr_data(FILE* out, rr_type* rr)
{
	int i;
	uint16_t rdlen;
	if(!spool_u32(out, rr->ttl))
		return 0;
	rdlen = rr_rdatalen_uncompressed(rr);
	if(!spool_u16(out, rdlen))
		return 0;
	for(i=0; i<rr->rdata_count; i++) {
		if(rdata_atom_is_domain(rr->type, i)) {
			if(!fwrite(dname_name(domain_dname(
				rr->rdatas[i].domain)), domain_dname(
				rr->rdatas[i].domain)->name_size, 1, out))
				return 0;
		} else {
			if(!fwrite(&rr->rdatas[i].data[1],
				rr->rdatas[i].data[0], 1, out))
				return 0;
		}
	}
	return 1;
}

/* spool one rrset to file */
static int spool_rrset(FILE* out, rrset_type* rrset)
{
	int i;
	if(rrset->rr_count == 0)
		return 1;
	if(!spool_u16(out, rrset->rrs[0].type))
		return 0;
	if(!spool_u16(out, rrset->rrs[0].klass))
		return 0;
	if(!spool_u16(out, rrset->rr_count))
		return 0;
	for(i=0; i<rrset->rr_count; i++) {
		if(!spool_rr_data(out, &rrset->rrs[i]))
			return 0;
	}
	return 1;
}

/* spool rrsets to file */
static int spool_rrsets(FILE* out, rrset_type* rrsets, struct zone* zone)
{
	rrset_type* s;
	for(s=rrsets; s; s=s->next) {
		if(s->zone != zone)
			continue;
		if(!spool_rrset(out, s)) {
			return 0;
		}
	}
	return 1;
}

/* count number of rrsets for a domain */
static size_t domain_count_rrsets(domain_type* domain, zone_type* zone)
{
	rrset_type* s;
	size_t count = 0;
	for(s=domain->rrsets; s; s=s->next) {
		if(s->zone == zone)
			count++;
	}
	return count;
}

/* spool the domain names to file, each one in turn. end with enddelimiter */
static int spool_domains(FILE* out, struct zone* zone)
{
	domain_type* domain;
	for(domain = zone->apex; domain && domain_is_subdomain(domain,
		zone->apex); domain = domain_next(domain)) {
		uint32_t count = domain_count_rrsets(domain, zone);
		if(count == 0)
			continue;
		/* write the name */
		if(!spool_dname(out, domain_dname(domain)))
			return 0;
		if(!spool_u32(out, count))
			return 0;
		/* write the rrsets */
		if(!spool_rrsets(out, domain->rrsets, zone))
			return 0;
	}
	/* the end delimiter is a 0 length. domain names are not zero length */
	if(!spool_u16(out, 0))
		return 0;
	return 1;
}

/* spool the namedb zone to the file. print error on failure. */
static int spool_zone_to_file(struct zone* zone, char* file_name,
	uint32_t serial)
{
	FILE* out;
	out = fopen(file_name, "w");
	if(!out) {
		log_msg(LOG_ERR, "could not open %s for writing: %s",
			file_name, strerror(errno));
		return 0;
	}
	if(!spool_dname(out, domain_dname(zone->apex))) {
		log_msg(LOG_ERR, "could not write %s: %s",
			file_name, strerror(errno));
		return 0;
	}
	if(!spool_u32(out, serial)) {
		log_msg(LOG_ERR, "could not write %s: %s",
			file_name, strerror(errno));
		return 0;
	}
	if(!spool_domains(out, zone)) {
		log_msg(LOG_ERR, "could not write %s: %s",
			file_name, strerror(errno));
		return 0;
	}
	fclose(out);
	return 1;
}

/* create ixfr spool file name */
static int create_ixfr_spool_name(struct ixfr_create* ixfrcr, char* zfile)
{
	char buf[1024];
	snprintf(buf, sizeof(buf), "%s.spoolzone.%u", zfile,
		(unsigned)getpid());
	ixfrcr->file_name = strdup(buf);
	if(!ixfrcr->file_name)
		return 0;
	return 1;
}

/* start ixfr creation */
struct ixfr_create* ixfr_create_start(struct zone* zone, char* zfile)
{
	struct ixfr_create* ixfrcr = (struct ixfr_create*)calloc(1,
		sizeof(*ixfrcr));
	if(!ixfrcr) {
		log_msg(LOG_ERR, "malloc failure");
		return NULL;
	}
	ixfrcr->zone_name_len = domain_dname(zone->apex)->name_size;
	ixfrcr->zone_name = (uint8_t*)malloc(ixfrcr->zone_name_len);
	if(!ixfrcr->zone_name) {
		free(ixfrcr);
		log_msg(LOG_ERR, "malloc failure");
		return NULL;
	}
	memmove(ixfrcr->zone_name, dname_name(domain_dname(zone->apex)),
		ixfrcr->zone_name_len);

	if(!create_ixfr_spool_name(ixfrcr, zfile)) {
		ixfr_create_free(ixfrcr);
		log_msg(LOG_ERR, "malloc failure");
		return NULL;
	}
	ixfrcr->old_serial = zone_get_current_serial(zone);
	if(!spool_zone_to_file(zone, ixfrcr->file_name, ixfrcr->old_serial)) {
		ixfr_create_free(ixfrcr);
		return NULL;
	}
	return ixfrcr;
}

/* free ixfr create */
void ixfr_create_free(struct ixfr_create* ixfrcr)
{
	if(!ixfrcr)
		return;
	free(ixfrcr->file_name);
	free(ixfrcr->zone_name);
	free(ixfrcr);
}

/* read uint16_t from spool */
static int read_spool_u16(FILE* spool, uint16_t* val)
{
	if(!fread(val, sizeof(*val), 1, spool))
		return 0;
	return 1;
}

/* read uint32_t from spool */
static int read_spool_u32(FILE* spool, uint32_t* val)
{
	if(!fread(val, sizeof(*val), 1, spool))
		return 0;
	return 1;
}

/* read dname from spool */
static int read_spool_dname(FILE* spool, uint8_t* buf, size_t buflen,
	size_t* dname_len)
{
	uint16_t len;
	if(!fread(&len, sizeof(len), 1, spool))
		return 0;
	if(len > buflen) {
		log_msg(LOG_ERR, "dname too long");
		return 0;
	}
	if(!fread(buf, len, 1, spool))
		return 0;
	*dname_len = len;
	return 1;
}

/* read and check the spool file header */
static int read_spool_header(FILE* spool, struct ixfr_create* ixfrcr)
{
	uint8_t dname[MAXDOMAINLEN+1];
	size_t dname_len;
	uint32_t serial;
	/* read apex */
	if(!read_spool_dname(spool, dname, sizeof(dname), &dname_len)) {
		log_msg(LOG_ERR, "error reading file %s: %s",
			ixfrcr->file_name, strerror(errno));
		return 0;
	}
	/* read serial */
	if(!read_spool_u32(spool, &serial)) {
		log_msg(LOG_ERR, "error reading file %s: %s",
			ixfrcr->file_name, strerror(errno));
		return 0;
	}

	/* check */
	if(ixfrcr->zone_name_len != dname_len ||
		memcmp(ixfrcr->zone_name, dname, ixfrcr->zone_name_len) != 0) {
		log_msg(LOG_ERR, "error file %s does not contain the correct zone apex",
			ixfrcr->file_name);
		return 0;
	}
	if(ixfrcr->old_serial != serial) {
		log_msg(LOG_ERR, "error file %s does not contain the correct zone serial",
			ixfrcr->file_name);
		return 0;
	}
	return 1;
}

/* spool read an rrset, it is a deleted RRset */
static int process_diff_rrset(FILE* spool, struct ixfr_create* ixfrcr,
	uint16_t tp, uint16_t kl, uint16_t rrcount, struct rrset* rrset)
{
	/* read RRs from file and see if they are added, deleted or in both */
	(void)spool;
	(void)ixfrcr;
	(void)tp;
	(void)kl;
	(void)rrcount;
	(void)rrset;
	return 1;
}

/* spool read an rrset, it is a deleted RRset */
static int process_spool_delrrset(FILE* spool, struct ixfr_create* ixfrcr,
	uint16_t tp, uint16_t kl, uint16_t rrcount)
{
	/* read the RRs from file and add to del list. */
	(void)spool;
	(void)ixfrcr;
	(void)tp;
	(void)kl;
	(void)rrcount;
	return 1;
}

/* add the rrset to the added list */
static int process_add_rrset(struct ixfr_create* ixfrcr, struct rrset* rrset)
{
	(void)ixfrcr;
	(void)rrset;
	return 1;
}

/* add the RR types that are not in the marktypes list from the new zone */
static int process_marktypes(struct ixfr_create* ixfrcr, struct zone* zone,
	struct domain* domain, uint16_t* marktypes, size_t marktypes_used)
{
	/* walk through the rrsets in the zone, if it is not in the
	 * marktypes list, then it is new and an added RRset */
	rrset_type* s;
	size_t i;
	for(s=domain->rrsets; s; s=s->next) {
		uint16_t tp;
		int found = 0;
		if(s->zone != zone)
			continue;
		tp = rrset_rrtype(s);
		for(i=0; i<marktypes_used; i++) {
			if(marktypes[i] == tp) {
				found = 1;
				break;
			}
		}
		if(found)
			continue;
		if(!process_add_rrset(ixfrcr, s))
			return 0;
	}
	return 1;
}

/* check the difference between the domain and RRs from spool */
static int process_diff_domain(FILE* spool, struct ixfr_create* ixfrcr,
	struct zone* zone, struct domain* domain)
{
	/* Read the RR types from spool. Mark off the ones seen,
	 * later, the notseen ones from the new zone are added RRsets.
	 * For the ones not in the new zone, they are deleted RRsets.
	 * If they exist in old and new, check for RR differences. */
	uint32_t spool_type_count, i; 
	uint16_t marktypes[65536];
	size_t marktypes_used = 0;
	if(!read_spool_u32(spool, &spool_type_count)) {
		log_msg(LOG_ERR, "error reading file %s: %s",
			ixfrcr->file_name, strerror(errno));
		return 0;
	}
	for(i=0; i<spool_type_count; i++) {
		uint16_t tp, kl, rrcount;
		struct rrset* rrset;
		if(!read_spool_u16(spool, &tp) ||
		   !read_spool_u16(spool, &kl) ||
		   !read_spool_u16(spool, &rrcount)) {
			log_msg(LOG_ERR, "error reading file %s: %s",
				ixfrcr->file_name, strerror(errno));
			return 0;
		}
		rrset = domain_find_rrset(domain, zone, tp);
		if(!rrset) {
			/* rrset in spool but not in new zone, deleted RRset */
			if(!process_spool_delrrset(spool, ixfrcr, tp, kl,
				rrcount))
				return 0;
		} else {
			/* add to the marked types, this one is present in
			 * spool */
			marktypes[marktypes_used++] = tp;
			/* rrset in old and in new zone, diff the RRset */
			if(!process_diff_rrset(spool, ixfrcr, tp, kl, rrcount,
				rrset))
				return 0;
		}
	}
	/* process markoff to see if new zone has RRsets not in spool,
	 * those are added RRsets. */
	if(!process_marktypes(ixfrcr, zone, domain, marktypes, marktypes_used))
		return 0;
	return 1;
}

/* add the RRs for the domain in new zone */
static int process_domain_add_RRs(struct ixfr_create* ixfrcr,
	struct zone* zone, struct domain* domain)
{
	rrset_type* s;
	for(s=domain->rrsets; s; s=s->next) {
		if(s->zone != zone)
			continue;
		if(!process_add_rrset(ixfrcr, s))
			return 0;
	}
	return 1;
}

/* process the spool input before the domain */
static int process_spool_before_domain(FILE* spool, struct ixfr_create* ixfrcr,
	struct domain* domain, uint8_t* spool_dname, size_t* spool_dname_len,
	int* spool_read_first)
{
	/* read the domains and rrsets before the domain and those are from
	 * the old zone. If the domain is equal, return to have that processed
	 * if we bypass, that means the domain does not exist, do that */
	(void)domain;
	(void)spool;
	(void)ixfrcr;
	(void)spool_dname;
	(void)spool_dname_len;
	(void)spool_read_first;
	return 1;
}

/* process the spool input for the domain */
static int process_spool_for_domain(FILE* spool, struct ixfr_create* ixfrcr,
	struct zone* zone, struct domain* domain, uint8_t* spool_dname,
	size_t* spool_dname_len, int* spool_read_first)
{
	/* process all the spool that is not the domain, that is before the
	 * domain in the new zone */
	if(!process_spool_before_domain(spool, ixfrcr, domain, spool_dname,
		spool_dname_len, spool_read_first))
		return 0;
	
	/* are we at the correct domain now? */
	if(*spool_dname_len != domain_dname(domain)->name_size ||
		memcmp(spool_dname, dname_name(domain_dname(domain)),
			*spool_dname_len) != 0) {
		/* the domain from the new zone is not present in the old zone,
		 * the content is in the added RRs set */
		if(!process_domain_add_RRs(ixfrcr, zone, domain))
			return 0;
		return 1;
	}

	/* process the domain */
	/* the domain exists both in the old and new zone,
	 * check for RR differences */
	if(!process_diff_domain(spool, ixfrcr, zone, domain))
		return 0;

	return 1;
}

/* process remaining spool items */
static int process_spool_remaining(FILE* spool, struct ixfr_create* ixfrcr,
	uint8_t* spool_dname, size_t* spool_dname_len, int* spool_read_first)
{
	/* the remaining domain names in the spool file, that is after
	 * the last domain in the new zone. */
	(void)spool;
	(void)ixfrcr;
	(void)spool_dname;
	(void)spool_dname_len;
	(void)spool_read_first;
	return 1;
}

/* walk through the zone and find the differences */
static int ixfr_create_walk_zone(FILE* spool, struct ixfr_create* ixfrcr,
	struct zone* zone)
{
	struct domain* domain;
	uint8_t spool_dname[MAXDOMAINLEN+1];
	size_t spool_dname_len = 0; /* start with no spool_dname */
	int spool_read_first = 0;
	for(domain = zone->apex; domain && domain_is_subdomain(domain,
		zone->apex); domain = domain_next(domain)) {
		uint32_t count = domain_count_rrsets(domain, zone);
		if(count == 0)
			continue;

		/* the domain is a domain in the new zone */
		if(!process_spool_for_domain(spool, ixfrcr, zone, domain,
			spool_dname, &spool_dname_len, &spool_read_first))
			return 0;
	}
	if(!process_spool_remaining(spool, ixfrcr,
		spool_dname, &spool_dname_len, &spool_read_first))
		return 0;
	return 1;
}

int ixfr_create_perform(struct ixfr_create* ixfrcr, struct zone* zone)
{
	struct ixfr_store store_mem, *store;
	FILE* spool;
	spool = fopen(ixfrcr->file_name, "r");
	if(!spool) {
		log_msg(LOG_ERR, "could not open %s for reading: %s",
			ixfrcr->file_name, strerror(errno));
		return 0;
	}
	if(!read_spool_header(spool, ixfrcr)) {
		fclose(spool);
		return 0;
	}
	ixfrcr->new_serial = zone_get_current_serial(zone);
	store = ixfr_store_start(zone, &store_mem, ixfrcr->old_serial,
		ixfrcr->new_serial);

	if(!ixfr_create_walk_zone(spool, ixfrcr, zone)) {
		fclose(spool);
		ixfr_store_free(store);
		return 0;
	}

	ixfr_store_free(store);
	fclose(spool);
	return 1;
}
