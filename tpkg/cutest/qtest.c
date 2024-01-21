/* 
   qtest : test query answers
*/
#include "config.h"
#include <errno.h>
#include <stdlib.h>
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include "tpkg/cutest/qtest.h"
#include "query.h"
#include "namedb.h"
#include "util.h"
#include "nsec3.h"
#include "options.h"
#include "packet.h"
#include "dname.h"
#include "rdata.h"

static uint16_t *compressed_dname_offsets = 0;
static uint32_t compression_table_capacity = 0;
static uint32_t compression_table_size = 0;
static domain_type* compressed_dnames[MAXRRSPP];

/* fake compression table implementation, copy from server.c */
static void init_dname_compr(nsd_type* nsd)
{
	size_t needed = domain_table_count(nsd->db->domains) + 1;
	needed += EXTRA_DOMAIN_NUMBERS;
	if(compression_table_capacity < needed) {
		compressed_dname_offsets = (uint16_t *) xalloc(
					needed * sizeof(uint16_t));
		compression_table_capacity = needed;
		compression_table_size=domain_table_count(nsd->db->domains)+1;
	}
	memset(compressed_dname_offsets, 0, needed * sizeof(uint16_t));
        compressed_dname_offsets[0] = QHEADERSZ; /* The original query name */
}

/* create the answer to one query */
static int run_query(query_type* q, nsd_type* nsd, buffer_type* in, int bsz)
{
	uint32_t now = 0;
	int received;
	query_reset(q, bsz, 0);
	/* recvfrom, in q->packet */
	received = (int)buffer_remaining(in);
	buffer_write_at(q->packet, 0, buffer_begin(in), received);
	buffer_skip(q->packet, received);
	buffer_flip(q->packet);
	if (query_process(q, nsd, &now) != QUERY_DISCARDED) {
		/* Add EDNS0 and TSIG info if necessary.  */
		query_add_optional(q, nsd, &now);
		buffer_flip(q->packet);
		/* result is buffer_begin(q->packet),
		   buffer_remaining(q->packet),
		 */
		return 1;
	}
	/* dropped */
	return 0;
}

/* initialize */
static void
qsetup(nsd_type* nsd, region_type* region, query_type** query, char* config)
{
	/* setup nsd */
	memset(nsd, 0, sizeof(*nsd));
	nsd->region = region;
#ifdef BIND8_STATS
	nsd->st = (struct nsdst*)region_alloc_zero(nsd->region,
		sizeof(struct nsdst));
#endif

	/* options */
	printf("read %s\n", config);
	nsd->options = nsd_options_create(region);
	if(!parse_options_file(nsd->options, config, NULL, NULL, NULL)) {
		printf("failed to read %s\n", config);
		exit(1);
	}
	/* EDNS0 */
	edns_init_data(&nsd->edns_ipv4, nsd->options->ipv4_edns_size);
#if defined(INET6)
#if defined(IPV6_USE_MIN_MTU) || defined(IPV6_MTU)
	edns_init_data(&nsd->edns_ipv6, nsd->options->ipv6_edns_size);
#else /* no way to set IPV6 MTU, send no bigger than that. */
	if (nsd->options->ipv6_edns_size < IPV6_MIN_MTU)
		edns_init_data(&nsd->edns_ipv6, nsd->options->ipv6_edns_size);
	else
		edns_init_data(&nsd->edns_ipv6, IPV6_MIN_MTU);
#endif /* IPV6 MTU) */
#endif /* defined(INET6) */

	/* read db */
	printf("open namedb (%d zones)\n", (int)nsd_options_num_zones(nsd->options));
	nsd->db = namedb_open(nsd->options);
	if(!nsd->db) {
		printf("failed to open namedb\n");
		exit(1);
	}
	namedb_check_zonefiles(nsd, nsd->options, NULL, NULL);

	/* setup query */
	compression_table_capacity = 0;
	init_dname_compr(nsd);
	*query = query_create(region, compressed_dname_offsets,
		compression_table_size, compressed_dnames);
}

void
debug_hex(char* desc, uint8_t* d, size_t s)
{
	char buf[10240];
	hex_ntop(d, s, buf, sizeof(buf));
	printf("%s: %s\n", desc, buf);
}

static void
qfree(struct qs* qs)
{
	struct qtodo* p, *next;
	if(!qs) return;
	p = qs->qlist;
	while(p) {
		next = p->next;
		if(p->q) {
			free(p->q->_data);
			free(p->q);
		}
		free(p->title);
		free(p->txt);
		free(p);
		p = next;
	}
	free(qs);
}

/* create a buffer with a regular query */
static buffer_type*
create_normal_query(char* desc, int withdo)
{
	uint8_t* data;
	uint8_t dname[MAXDOMAINLEN];
	int dlen;
	size_t size = 0;
	uint16_t t, c;
	char* p;
	buffer_type* buf = xalloc(sizeof(*buf));

	/* parse dname */
	p = strchr(desc, ' ');
	if(!p) {
		printf("need space: name cl tp: %s\n", desc);
		exit(1);
	}
	*p = 0;
	if((dlen=dname_parse_wire(dname, desc))==0) {
		printf("cannot parse dname in '%s'\n", desc);
		exit(1);
	}
	desc = p+1;
	p = strchr(desc, ' ');
	if(!p) {
		printf("need space: class type: %s\n", desc);
		exit(1);
	}
	*p = 0;
	if(strcmp(desc, "CLASS0") == 0)
		c = 0;
	else if(strcmp(desc, "ANY") == 0)
		c = 255;
	else {
		if(!(c = rrclass_from_string(desc))) {
			printf("bad class: %s\n", desc);
			exit(1);
		}
	}
	desc = p+1;
	if(strcmp(desc, "TYPE0") == 0)
		t = 0;
	else if(strcmp(desc, "ANY") == 0)
		t = 255;
	else {
		if(!(t = rrtype_from_string(desc))) {
			printf("bad type: %s\n", desc);
			exit(1);
		}
	}

	/* fill data */
	size = QHEADERSZ + 4 + dlen;
	if(withdo) size += 11;
	data = xalloc(size);
	memset(data, 0, size);
	buffer_create_from(buf, data, size);

	QDCOUNT_SET(buf, 1);
	buffer_skip(buf, QHEADERSZ);
	buffer_write(buf, dname, dlen);
	buffer_write_u16(buf, t);
	buffer_write_u16(buf, c);
	if(withdo) {
		ARCOUNT_SET(buf, 1);
		buffer_write_u8(buf, 0);
		buffer_write_u16(buf, TYPE_OPT);
		buffer_write_u16(buf, 4096);
		buffer_write_u8(buf, 0); /* rcode */
		buffer_write_u8(buf, 0); /* version */
		buffer_write_u16(buf, 0x8000); /* DO flag */
		buffer_write_u16(buf, 0);
	}
	buffer_flip(buf);
	return buf;
}

/* read text to check */
static void
read_txt(FILE* in, struct qtodo* e)
{
	char line[10240];
	char zestring[102400];
	zestring[0]=0;
	while(fgets(line, sizeof(line), in) != 0) {
		if(strcmp(line, "end_reply\n") == 0) {
			e->txt = strdup(zestring);
			return;
		} else if(strcmp(line, "no_reply\n") == 0) {
			e->txt = NULL;
			return;
		}
		if(strlen(zestring) + strlen(line) + 1 > sizeof(zestring)) {
			printf("reply too long\n");
			exit(1);
		}
		strlcat(zestring, line, sizeof(zestring));
	}
	printf("unexpected eof in reply\n");
	exit(1);
}

/* read one query */
static void
read_query(char* line, FILE* in, struct qs* qs, int withdo)
{
	struct qtodo* e = xalloc(sizeof(*e));
	memset(e, 0, sizeof(*e));
	e->next = NULL;
	e->title = strdup(line);
	e->withdo = withdo;
	e->q = create_normal_query(line, withdo);
	read_txt(in, e);
	qs->num++;
	if(qs->qlast)
		qs->qlast->next = e;
	else
		qs->qlist = e;
	qs->qlast = e;
}

/* read qfile */
static struct qs*
qread(char* qfile)
{
	char line[1024];
	struct qs* qs;
	FILE* in = fopen(qfile, "r");
	if(!in) {
		printf("could not open %s: %s\n", qfile, strerror(errno));
		exit(1);
	}
	qs = xalloc(sizeof(*qs));
	memset(qs, 0, sizeof(*qs));
	qs->bufsize = 512;
	while(fgets(line, sizeof(line), in) != NULL) {
		if(line[0]==0 || line[0] == '\n' || line[0] == '#')
			continue;
		/* remove trailing newline */
		if(line[0]!=0 && line[strlen(line)-1]=='\n')
			line[strlen(line)-1]=0;

		if(strncmp(line, "query ", 6) == 0) {
			read_query(line+6, in, qs, 0);
		} else if(strncmp(line, "query_do ", 9) == 0) {
			read_query(line+9, in, qs, 1);
		} else if(strncmp(line, "speed ", 6) == 0) {
			qs->speed = atoi(line+6);
		} else if(strncmp(line, "check ", 6) == 0) {
			qs->check = atoi(line+6);
		} else if(strncmp(line, "write ", 6) == 0) {
			qs->write = atoi(line+6);
		} else if(strncmp(line, "bufsize ", 8) == 0) {
			qs->bufsize = atoi(line+8);
		} else {
			printf("cannot parse '%s' in %s\n", line, qfile);
			exit(1);
		}
	}
	printf("qfile has %d queries\n", qs->num);

	fclose(in);
	return qs;
}

/* spool rr to buffer in text format */
static void
buffer_spool_rr(buffer_type* output, rr_type* rr, int qsection)
{
	rrtype_descriptor_type *d = rrtype_descriptor_by_type(rr->type);
	int result;
	const dname_type *owner = domain_dname(rr->owner);
	buffer_printf(output, "%s", dname_to_string(owner, NULL));
	if(qsection)
		buffer_printf(output, "\t%s\t%s",
		rrclass_to_string(rr->klass), rrtype_to_string(rr->type));
	else if(rr->type != TYPE_OPT)
		buffer_printf(output, "\t%lu\t%s\t%s", (unsigned long) rr->ttl,
		rrclass_to_string(rr->klass), rrtype_to_string(rr->type));
	else {
		/* print OPT */
		int flags = (rr->ttl&0xffff);
		buffer_printf(output, " size:%d rcode:%d vs:%d",
			(int)rr->klass, (int)((rr->ttl& 0xff000000)>>24),
			(int)((rr->ttl& 0x00ff0000)>>16));
		if( (flags&0x8000) ) {
			buffer_printf(output, " DO");
			flags ^= 0x8000;
		}
		if(flags) {
			buffer_printf(output, " unknown-flags:%x", flags);
		}
		buffer_printf(output, " OPT");
	}
	if(!qsection) {
		result = print_rdata(output, d, rr);
		if (!result) {
			/* Some RDATA failed to print, so do unknown format. */
			result = rdata_atoms_to_unknown_string(output, d,
				rr->rdata_count, rr->rdatas);
			if(!result) {
				buffer_printf(output,
					"rdata_atoms_to_unknown_string failed");
			}
		}
	}
	buffer_printf(output, "\n");
}

static void
buffer_print_packet(buffer_type* output, buffer_type* buf)
{
	int i;
	domain_table_type* fake;
	rr_type* rr;
	region_type* region = region_create(xalloc, free);

	buffer_printf(output, 
		";; opcode %d ; rcode %d %s ; id %d ; flags", (int)OPCODE(buf),
		(int)RCODE(buf), rcode2str(RCODE(buf)), (int)ID(buf));
	if(QR(buf)) buffer_printf(output, " QR");
	if(AA(buf)) buffer_printf(output, " AA");
	if(TC(buf)) buffer_printf(output, " TC");
	if(RD(buf)) buffer_printf(output, " RD");
	if(RA(buf)) buffer_printf(output, " RA");
	if(Z(buf)) buffer_printf(output, " Z");
	if(AD(buf)) buffer_printf(output, " AD");
	if(CD(buf)) buffer_printf(output, " CD");
	buffer_printf(output, " ; QD:%d AN:%d NS:%d AR:%d\n", (int)QDCOUNT(buf),
		(int)ANCOUNT(buf), (int)NSCOUNT(buf), (int)ARCOUNT(buf));
	/* walk through query section */
	buffer_skip(buf, QHEADERSZ);
	fake = domain_table_create(region);
	if(QDCOUNT(buf)!=0) {
		buffer_printf(output, "; QUERY SECTION\n");
		for(i=0; i<QDCOUNT(buf); i++) {
			rr = packet_read_rr(region, fake, buf, 1);
			if(!rr) buffer_printf(output, "RR parse error %d\n", i);
			else buffer_spool_rr(output, rr, 1);
		}
	}
	if(ANCOUNT(buf)!=0) {
		buffer_printf(output, "; ANSWER SECTION\n");
		for(i=0; i<ANCOUNT(buf); i++) {
			rr = packet_read_rr(region, fake, buf, 0);
			if(!rr) buffer_printf(output, "RR parse error %d\n", i);
			else buffer_spool_rr(output, rr, 0);
		}
	}
	if(NSCOUNT(buf)!=0) {
		buffer_printf(output, "; AUTHORITY SECTION\n");
		for(i=0; i<NSCOUNT(buf); i++) {
			rr = packet_read_rr(region, fake, buf, 0);
			if(!rr) buffer_printf(output, "RR parse error %d\n", i);
			else buffer_spool_rr(output, rr, 0);
		}
	}
	if(ARCOUNT(buf)!=0) {
		buffer_printf(output, "; ADDITIONAL SECTION\n");
		for(i=0; i<ARCOUNT(buf); i++) {
			rr = packet_read_rr(region, fake, buf, 0);
			if(!rr) buffer_printf(output, "RR parse error %d\n", i);
			else buffer_spool_rr(output, rr, 0);
		}
	}
	buffer_set_position(buf, 0);
	region_destroy(region);
}

/* printout debug buffer with DNS packet */
void
print_buffer(buffer_type* buf)
{
	region_type* region = region_create(xalloc, free);
	buffer_type *output = buffer_create(region, MAX_RDLENGTH);
	buffer_print_packet(output, buf);
	buffer_write_u8(output, 0);
	printf("%s", buffer_begin(output));
	region_destroy(region);
}

/* write a qfile with answers filled in ,.*/
static void
do_write(struct qs* qs, query_type* query, nsd_type* nsd, char* name)
{
	FILE* out = NULL;
	buffer_type* output = buffer_create(nsd->region, MAX_RDLENGTH);
	struct qtodo* e;
	out = fopen(name, "w");
	if(!out) {
		perror(name);
		exit(1);
	}
	fprintf(out, "# qfile\n");
	for(e = qs->qlist; e; e = e->next) {
		fprintf(out, "query%s %s\n", e->withdo?"_do":"", e->title);
		if(run_query(query, nsd, e->q, qs->bufsize)) {
			buffer_clear(output);
			buffer_print_packet(output, query->packet);
			buffer_write_u8(output, 0);
			fprintf(out, "%send_reply\n", buffer_begin(output));
		} else {
			fprintf(out, "no_reply\n");
		}
	}
	fprintf(out, "\n");
	fprintf(out, "bufsize %d\n", qs->bufsize);
	fprintf(out, "speed %d\n", qs->speed);
	fprintf(out, "check %d\n", qs->check);
	fprintf(out, "write 0\n");
	fclose(out);
	printf("written qfile.out\n");
}

/* do run of tests */
static void
do_run(struct qs* qs, query_type* query, nsd_type* nsd, int verbose)
{
	buffer_type* output = buffer_create(nsd->region, MAX_RDLENGTH);
	struct qtodo* e;
	for(e = qs->qlist; e; e = e->next) {
		if(verbose)
			printf("query %s (size %d)\n", e->title,
				(int)buffer_remaining(e->q));
		if(verbose >= 2)
			print_buffer(e->q);
		if(verbose >= 3)
			debug_hex("query", buffer_begin(e->q),
				buffer_remaining(e->q));

		if(run_query(query, nsd, e->q, qs->bufsize)) {
			/* answer in q->packet buffer */
			if(verbose) printf("answer (size %d)\n",
				(int)buffer_remaining(query->packet));
			if(verbose >= 2)
				print_buffer(query->packet);
			if(verbose >= 3)
				debug_hex("answer", buffer_begin(query->packet),
					buffer_remaining(query->packet));
			if(!e->txt) {
				printf("q: %s\n", e->title);
				printf("error: answer, but expected none\n");
				printf("got: \n");
				print_buffer(query->packet);
				exit(1);
			} else {
				buffer_clear(output);
				buffer_print_packet(output, query->packet);
				buffer_write_u8(output, 0);
				if(strcmp((char*)buffer_begin(output),
					e->txt)!=0) {
					size_t i;
					printf("q: %s\n", e->title);
					printf("error: wrong answer\n");
					printf("got: \n%s\n",
						buffer_begin(output));
					printf("wanted: \n%s\n", e->txt);
					printf("strlens %d %d\n",
						(int)strlen((char*)buffer_begin(output)),
						(int)strlen(e->txt));
					for(i=0; i<strlen((char*)buffer_begin(output)); i++) {
					  printf("[%d] '%c' '%c'\n", (int)i,
						((char*)buffer_begin(output))[i],
						((char*)e->txt)[i]);
					}
					exit(1);
				}
			}
		} else {
			/* dropped answer */
			if(verbose) printf("answer discarded\n");
			if(e->txt) {
				printf("q: %s\n", e->title);
				printf("error: no answer, but expected one\n");
				exit(1);
			}
		}
		if(verbose >= 2)
			printf("\n");
	}
	printf("check OK\n");
}

/** timeval subtract, t1 -= t2 */
static void
timeval_subtract(struct timeval* t1, struct timeval* t2)
{
	t1->tv_sec -= t2->tv_sec;
	if(t1->tv_usec >= t2->tv_usec) {
		t1->tv_usec -= t2->tv_usec;
	} else {
		t1->tv_sec--;
		t1->tv_usec = 1000000-(t2->tv_usec-t1->tv_usec);
	}
}


/* do speed test */
static void
do_speed(struct qs* qs, query_type* query, nsd_type* nsd)
{
	struct qtodo* e;
	int i, max=qs->speed;
	struct timeval start, stop;
	int taken, did;
	double qps;
	if(gettimeofday(&start, NULL) != 0)
		printf("cannot gettimeofday\n");
	for(i=0; i<max; i++) {
		for(e = qs->qlist; e; e = e->next) {
			(void)run_query(query, nsd, e->q, qs->bufsize);
		}
	}
	if(gettimeofday(&stop, NULL) != 0)
		printf("cannot gettimeofday\n");
	timeval_subtract(&stop, &start);
	taken = stop.tv_sec*1000000 + stop.tv_usec;
	did = qs->num * max;
	qps = ((double)did)/((double)taken);
	qps *= 1000000.; /* 1/msec to 1/sec */
	printf("did %d in %d.%6.6d sec: %f qps\n", did, 
		(int)stop.tv_sec, (int)stop.tv_usec, qps);
}

/* main qtest routine */
int runqtest(char* config, char* qfile, int verbose)
{
	struct qs* qs;
	nsd_type nsd;
	region_type *region = region_create(xalloc, free);
	query_type* query;
	log_init("qtest");

	qsetup(&nsd, region, &query, config);
	qs = qread(qfile);
	if(qs->check)
		do_run(qs, query, &nsd, verbose);
	if(qs->speed)
		do_speed(qs, query, &nsd);
	if(qs->write)
		do_write(qs, query, &nsd, "qfile.out");

	qfree(qs);
	free(compressed_dname_offsets);
	region_destroy(region);
	return 0;
}

