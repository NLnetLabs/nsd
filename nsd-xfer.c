/*
 * nsd-xfer.c -- nsd-xfer(8).
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "packet.h"
#include "query.h"
#include "rdata.h"
#include "region-allocator.h"
#include "tsig.h"
#include "tsig-openssl.h"
#include "util.h"
#include "zonec.h"

/*
 * Exit codes are based on named-xfer for now.  See ns_defs.h in
 * bind8.
 */
enum nsd_xfer_exit_codes
{
	XFER_UPTODATE = 0,
	XFER_SUCCESS  = 1,
	XFER_FAIL     = 3
};

struct axfr_state
{
	int s;			/* AXFR socket.  */
	query_type *q;		/* Query buffer.  */
	uint16_t query_id;	/* AXFR query ID.  */
	tsig_record_type *tsig;	/* TSIG data.  */
	
	int    done;		/* AXFR is complete.  */
	size_t rr_count;	/* Number of RRs received so far.  */

	/*
	 * Region used to allocate data needed to process a single RR.
	 */
	region_type *rr_region;

	/*
	 * Region used to store owner and origin of previous RR (used
	 * for pretty printing of zone data).
	 */
	region_type *previous_owner_region;
	const dname_type *previous_owner;
	const dname_type *previous_owner_origin;
};
typedef struct axfr_state axfr_state_type;

extern char *optarg;
extern int optind;

static uint16_t init_query(query_type *q,
			   const dname_type *dname,
			   uint16_t type,
			   uint16_t klass,
			   tsig_record_type *tsig);

/*
 * Log an error message and exit.
 */
static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(XFER_FAIL);
}


/*
 * Log a warning message.
 */
static void warning(const char *format, ...) ATTR_FORMAT(printf, 1, 2);
static void
warning(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_WARNING, format, args);
	va_end(args);
}


/*
 * Display usage information and exit.
 */
static void
usage (void)
{
	fprintf(stderr,
		"Usage: nsd-xfer [OPTION]... -z zone -f file server...\n"
		"NSD AXFR client.\n\nSupported options:\n"
		"  -4           Only use IPv4 connections.\n"
		"  -6           Only use IPv6 connections.\n"
		"  -f file      Output zone file name.\n"
		"  -p port      The port to connect to.\n"
		"  -s serial    The current zone serial.\n"
		"  -T tsiginfo  The TSIG key file name.  The file is removed "
		"after reading the\n               key.\n"
		"  -z zone      Specify the name of the zone to transfer.\n");
	fprintf(stderr,
		"  server       The name or IP address of the master server.\n"
		"\nReport bugs to <%s>.\n", PACKAGE_BUGREPORT);
	exit(XFER_FAIL);
}

static void
cleanup_addrinfo(void *data)
{
	freeaddrinfo((struct addrinfo *) data);
}

/*
 * Read a line from IN.  If successful, the line is stripped of
 * leading and trailing whitespace and non-zero is returned.
 */
static int
read_line(FILE *in, char *line, size_t size)
{
	if (!fgets(line, size, in)) {
		return 0;
	} else {
		strip_string(line);
		return 1;
	}
}

static tsig_key_type *
read_tsig_key_data(region_type *region, FILE *in, int default_family)
{
	char line[4000];
	tsig_key_type *key = (tsig_key_type *) region_alloc(
		region, sizeof(tsig_key_type));
	struct addrinfo hints;
	int gai_rc;
	int size;
	uint8_t data[4000];
	
	if (!read_line(in, line, sizeof(line))) {
		error("failed to read TSIG key server address: %s\n",
		      strerror(errno));
		return NULL;
	}
	
	memset(&hints, 0, sizeof(hints));
	hints.ai_flags |= AI_NUMERICHOST;
	hints.ai_family = default_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	gai_rc = getaddrinfo(line, NULL, &hints, &key->server);
	if (gai_rc) {
		error("cannot parse address '%s': %s",
		      line,
		      gai_strerror(gai_rc));
		return NULL;
	}

	region_add_cleanup(region, cleanup_addrinfo, key->server);
	
	if (!read_line(in, line, sizeof(line))) {
		error("failed to read TSIG key name: %s\n", strerror(errno));
		return NULL;
	}
	
	key->name = dname_parse(region, line, NULL);
	if (!key->name) {
		error("failed to parse TSIG key name %s", line);
		return NULL;
	}

	if (!read_line(in, line, sizeof(line))) {
		error("failed to read TSIG key type: %s\n", strerror(errno));
		return NULL;
	}

	if (!read_line(in, line, sizeof(line))) {
		error("failed to read TSIG key data: %s\n", strerror(errno));
		return NULL;
	}
	
	size = b64_pton(line, data, sizeof(data));
	if (size == -1) {
		error("failed to parse TSIG key data");
		return NULL;
	}

	key->size = size;
	key->data = (uint8_t *) region_alloc_init(region, data, key->size);

	return key;
}

/*
 * Read the TSIG key from a .tsiginfo file and remove the file.
 */
static tsig_key_type *
read_tsig_key(region_type *region,
	      const char *tsiginfo_filename,
	      int default_family)
{
	FILE *in;
	tsig_key_type *key;
	
	in = fopen(tsiginfo_filename, "r");
	if (!in) {
		error("failed to open %s: %s",
		      tsiginfo_filename,
		      strerror(errno));
		return NULL;
	}

	key = read_tsig_key_data(region, in, default_family);

	fclose(in);
	
#if 0
	if (unlink(tsiginfo_filename) == -1) {
		warning("failed to remove %s: %s",
			tsiginfo_filename,
			strerror(errno));
	}
#endif

	return key;
}

/*
 * Write the complete buffer to the socket, irrespective of short
 * writes or interrupts.
 */
static int
write_socket(int s, const void *buf, size_t size)
{
	const char *data = (const char *) buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = write(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				return 0;
			} else {
				continue;
			}
		}
		total_count += count;
	}

	return 1;
}

/*
 * Read SIZE bytes from the socket into BUF.  Keep reading unless an
 * error occurs (except for EAGAIN and EINTR) or EOF is reached.
 */
static int
read_socket(int s, void *buf, size_t size)
{
	char *data = (char *) buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = read(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EAGAIN && errno != EINTR) {
				return 0;
			} else {
				continue;
			}
		}
		total_count += count;
	}

	return 1;
}

static int
print_rdata(buffer_type *output, rrtype_descriptor_type *descriptor,
	    rr_type *record)
{
	size_t i;
	size_t saved_position = buffer_position(output);
	
	for (i = 0; i < record->rdata_count; ++i) {
		if (i == 0) {
			buffer_printf(output, "\t");
		} else if (descriptor->type == TYPE_SOA && i == 2) {
			buffer_printf(output, " (\n\t\t");
		} else {
			buffer_printf(output, " ");
		}
		if (!rdata_atom_to_string(
			    output,
			    (rdata_zoneformat_type) descriptor->zoneformat[i],
			    record->rdatas[i]))
		{
			buffer_set_position(output, saved_position);
			return 0;
		}
	}
	if (descriptor->type == TYPE_SOA) {
		buffer_printf(output, " )");
	}
	
	return 1;
}

static void
set_previous_owner(axfr_state_type *state, const dname_type *dname)
{
	region_free_all(state->previous_owner_region);
	state->previous_owner = dname_copy(state->previous_owner_region, dname);
	state->previous_owner_origin = dname_origin(
		state->previous_owner_region, state->previous_owner);
}
	

static int
print_rr(FILE *out,
	 axfr_state_type *state,
	 rr_type *record)
{
	buffer_type *output = buffer_create(state->rr_region, 1000);
	rrtype_descriptor_type *descriptor
		= rrtype_descriptor_by_type(record->type);
	int result;
	const dname_type *owner = domain_dname(record->owner);
	const dname_type *owner_origin
		= dname_origin(state->rr_region, owner);
	int owner_changed
		= (!state->previous_owner
		   || dname_compare(state->previous_owner, owner) != 0);
	if (owner_changed) {
		int origin_changed = (!state->previous_owner_origin
				      || dname_compare(
					      state->previous_owner_origin,
					      owner_origin) != 0);
		if (origin_changed) {
			buffer_printf(
				output,
				"$ORIGIN %s\n",
				dname_to_string(owner_origin, NULL));
		}
	
		set_previous_owner(state, owner);
		buffer_printf(output,
			      "%s",
			      dname_to_string(owner,
					      state->previous_owner_origin));
	}
	
	buffer_printf(output,
		      "\t%lu\t%s\t%s",
		      (unsigned long) record->ttl,
		      rrclass_to_string(record->klass),
		      rrtype_to_string(record->type));

	result = print_rdata(output, descriptor, record);
	if (!result) {
		/*
		 * Some RDATA failed to print, so print the record's
		 * RDATA in unknown format.
		 */
		result = rdata_atoms_to_unknown_string(output,
						       descriptor,
						       record->rdata_count,
						       record->rdatas);
	}
	
	if (result) {
		buffer_printf(output, "\n");
		buffer_flip(output);
		fwrite(buffer_current(output), buffer_remaining(output), 1,
		       out);
/* 		fflush(out); */
	}
	
	return result;
}


static int
parse_response(FILE *out, axfr_state_type *state)
{
	size_t rr_count;
	size_t qdcount = QDCOUNT(state->q->packet);
	size_t ancount = ANCOUNT(state->q->packet);

	/* Skip question section.  */
	for (rr_count = 0; rr_count < qdcount; ++rr_count) {
		if (!packet_skip_rr(state->q->packet, 1)) {
			error("bad RR in question section");
			return 0;
		}
	}

	/* Read RRs from answer section and print them.  */
	for (rr_count = 0; rr_count < ancount; ++rr_count) {
		domain_table_type *owners
			= domain_table_create(state->rr_region);
		rr_type *record = packet_read_rr(
			state->rr_region, owners, state->q->packet, 0);
		if (!record) {
			error("bad RR in answer section");
			return 0;
		}

		if (state->rr_count == 0
		    && (record->type != TYPE_SOA || record->klass != CLASS_IN))
		{
			error("First RR must be the SOA record, but is a %s record",
			      rrtype_to_string(record->type));
			return 0;
		} else if (state->rr_count > 0
			   && record->type == TYPE_SOA
			   && record->klass == CLASS_IN)
		{
			state->done = 1;
			return 1;
		}
		
		++state->rr_count;
		
		if (!print_rr(out, state, record)) {
			return 0;
		}
		
		region_free_all(state->rr_region);
	}

	return 1;
}

static int
send_query(int s, query_type *q)
{
	uint16_t size = htons(buffer_remaining(q->packet));

	if (!write_socket(s, &size, sizeof(size))) {
		error("failed to send query size: %s", strerror(errno));
		return 0;
	}
	if (!write_socket(s, buffer_begin(q->packet), buffer_limit(q->packet)))
	{
		error("failed to send query data: %s", strerror(errno));
		return 0;
	}
	return 1;
}

static int
receive_response(int s, query_type *q)
{
	uint16_t size;
	
	buffer_clear(q->packet);
	if (!read_socket(s, &size, sizeof(size))) {
		error("failed to read response size: %s", strerror(errno));
		return 0;
	}
	size = ntohs(size);
	if (size > q->maxlen) {
		error("response size (%d) exceeds maximum (%d)",
		      (int) size, (int) q->maxlen);
		return 0;
	}
	if (!read_socket(s, buffer_begin(q->packet), size)) {
		error("failed to read response data: %s", strerror(errno));
		return 0;
	}

	buffer_set_position(q->packet, size);

	return 1;
}

static int
check_response_tsig(query_type *q, tsig_record_type *tsig)
{
	if (!tsig)
		return 1;

	if (!tsig_find_rr(tsig, q)) {
		error("error parsing response");
		return 0;
	}
	if (tsig->status == TSIG_NOT_PRESENT) {
		if (tsig->response_count == 0) {
			error("required TSIG not present");
			return 0;
		}
		if (tsig->updates_since_last_prepare > 100) {
			error("too many response packets without TSIG");
			return 0;
		}
		tsig_update(tsig, q, buffer_limit(q->packet));
		return 1;
	}
	
	ARCOUNT_SET(q->packet, ARCOUNT(q->packet) - 1);
	
	if (tsig->status == TSIG_ERROR) {
		error("TSIG record is not correct");
		return 0;
	} else if (tsig->error_code != TSIG_ERROR_NOERROR) {
		error("TSIG error code: %s",
		      tsig_error(tsig->error_code));
		return 0;
	} else {
		tsig_update(tsig, q, tsig->position);
		if (!tsig_verify(tsig)) {
			error("TSIG record did not authenticate");
			return 0;
		}
		tsig_prepare(tsig);
	}

	return 1;
}


/*
 * Query the server for the zone serial. Return 1 if the zone serial
 * is higher than the current serial, 0 if the zone serial is lower or
 * equal to the current serial, and -1 on error.
 *
 * On success, the zone serial is returned in ZONE_SERIAL.
 */
static int
check_serial(int s,
	     query_type *q,
	     const dname_type *zone,
	     const uint32_t current_serial,
	     uint32_t *zone_serial,
	     tsig_record_type *tsig)
{
	region_type *local;
	uint16_t query_id;
	uint16_t i;
	domain_table_type *owners;
	
	query_id = init_query(q, zone, TYPE_SOA, CLASS_IN, tsig);
	
	if (!send_query(s, q)) {
		return -1;
	}

	if (tsig) {
		/* Prepare for checking responses. */
		tsig_prepare(tsig);
	}
	
	if (!receive_response(s, q)) {
		return -1;
	}
	buffer_flip(q->packet);

	if (buffer_limit(q->packet) <= QHEADERSZ) {
		error("response size (%d) is too small",
		      (int) buffer_limit(q->packet));
		return -1;
	}

	if (!QR(q->packet)) {
		error("response is not a response");
		return -1;
	}

	if (TC(q->packet)) {
		error("response is truncated");
		return -1;
	}
	
	if (ID(q->packet) != query_id) {
		error("bad response id (%d), expected (%d)",
		      (int) ID(q->packet), (int) query_id);
		return -1;
	}
	
	if (RCODE(q->packet) != RCODE_OK) {
		error("error response %d", (int) RCODE(q->packet));
		return -1;
	}
	
	if (QDCOUNT(q->packet) != 1) {
		error("question section count not equal to 1");
		return -1;
	}
	
	if (ANCOUNT(q->packet) == 0) {
		error("answer section is empty");
		return -1;
	}

	if (!check_response_tsig(q, tsig)) {
		return -1;
	}
	
	buffer_set_position(q->packet, QHEADERSZ);

	local = region_create(xalloc, free);
	owners = domain_table_create(local);
	
	/* Skip question records. */
	for (i = 0; i < QDCOUNT(q->packet); ++i) {
		rr_type *record = packet_read_rr(local, owners, q->packet, 1);
		if (!record) {
			error("bad RR in question section");
			region_destroy(local);
			return -1;
		}

		if (dname_compare(zone, domain_dname(record->owner)) != 0
		    || record->type != TYPE_SOA
		    || record->klass != CLASS_IN)
		{
			error("response does not match query");
			region_destroy(local);
			return -1;
		}
	}
	
	/* Find the SOA record in the response.  */
	for (i = 0; i < ANCOUNT(q->packet); ++i) {
		rr_type *record = packet_read_rr(local, owners, q->packet, 0);
		if (!record) {
			error("bad RR in answer section");
			region_destroy(local);
			return -1;
		}

		if (dname_compare(zone, domain_dname(record->owner)) == 0
		    && record->type == TYPE_SOA
		    && record->klass == CLASS_IN)
		{
			assert(record->rdata_count == 7);
			assert(rdata_atom_size(record->rdatas[2]) == 4);
			*zone_serial = read_uint32(rdata_atom_data(
							   record->rdatas[2]));
			region_destroy(local);
			return *zone_serial > current_serial;
		}
	}

	error("SOA not found in answer");
	region_destroy(local);
	return -1;
}

/*
 * Receive and parse the AXFR response packets.
 */
static int
handle_axfr_response(FILE *out, axfr_state_type *axfr)
{
	while (!axfr->done) {
		if (!receive_response(axfr->s, axfr->q)) {
			return 0;
		}
		buffer_flip(axfr->q->packet);
		
		if (buffer_limit(axfr->q->packet) <= QHEADERSZ) {
			error("response size (%d) is too small",
			      (int) buffer_limit(axfr->q->packet));
			return 0;
		}

		if (!QR(axfr->q->packet)) {
			error("response is not a response");
			return 0;
		}

		if (ID(axfr->q->packet) != axfr->query_id) {
			error("bad response id (%d), expected (%d)",
			      (int) ID(axfr->q->packet),
			      (int) axfr->query_id);
			return 0;
		}

		if (RCODE(axfr->q->packet) != RCODE_OK) {
			error("error response %d",
			      (int) RCODE(axfr->q->packet));
			return 0;
		}

		if (QDCOUNT(axfr->q->packet) > 1) {
			error("query section count greater than 1");
			return 0;
		}

		if (ANCOUNT(axfr->q->packet) == 0) {
			error("answer section is empty");
			return 0;
		}

		if (!check_response_tsig(axfr->q, axfr->tsig)) {
			return 0;
		}
	
		buffer_set_position(axfr->q->packet, QHEADERSZ);
		
		if (!parse_response(out, axfr)) {
			return 0;
		}
	}
	return 1;
}

static int
axfr(int s,
     query_type *q,
     const dname_type *zone,
     FILE *out,
     tsig_record_type *tsig)
{
	axfr_state_type state;
	int result;
	
	state.query_id = init_query(q, zone, TYPE_AXFR, CLASS_IN, tsig);

	if (!send_query(s, q)) {
		return 0;
	}

	if (tsig) {
		/* Prepare for checking responses.  */
		tsig_prepare(tsig);
	}
	
	state.s = s;
	state.q = q;
	state.tsig = tsig;
	state.done = 0;
	state.rr_count = 0;
	state.rr_region = region_create(xalloc, free);
	state.previous_owner_region = region_create(xalloc, free);
	state.previous_owner = NULL;
	state.previous_owner_origin = NULL;

	result = handle_axfr_response(out, &state);

	region_destroy(state.previous_owner_region);
	region_destroy(state.rr_region);

	return result;
}

static uint16_t
init_query(query_type *q,
	   const dname_type *dname,
	   uint16_t type,
	   uint16_t klass,
	   tsig_record_type *tsig)
{
	uint16_t query_id = (uint16_t) random();
	
	buffer_clear(q->packet);
	
	/* Set up the header */
	ID_SET(q->packet, query_id);
	FLAGS_SET(q->packet, 0);
	OPCODE_SET(q->packet, OPCODE_QUERY);
	AA_SET(q->packet);
	QDCOUNT_SET(q->packet, 1);
	ANCOUNT_SET(q->packet, 0);
	NSCOUNT_SET(q->packet, 0);
	ARCOUNT_SET(q->packet, 0);
	buffer_skip(q->packet, QHEADERSZ);

	/* The question record.  */
	buffer_write(q->packet, dname_name(dname), dname->name_size);
	buffer_write_u16(q->packet, type);
	buffer_write_u16(q->packet, klass);

	if (tsig) {
		tsig_init_query(tsig, query_id);
		tsig_prepare(tsig);
		tsig_update(tsig, q, buffer_position(q->packet));
		tsig_sign(tsig);
		tsig_append_rr(tsig, q->packet);
		ARCOUNT_SET(q->packet, 1);
	}
	
	buffer_flip(q->packet);

	return ID(q->packet);
}

int 
main (int argc, char *argv[])
{
	int c;
	query_type q;
	struct addrinfo hints, *res0, *res;
	const dname_type *zone = NULL;
	const char *file = NULL;
	const char *serial = NULL;
	uint32_t current_serial = 0;
	const char *port = TCP_PORT;
	region_type *region = region_create(xalloc, free);
	int default_family = DEFAULT_AI_FAMILY;
	FILE *zone_file;
	const char *tsig_key_filename = NULL;
	tsig_key_type *tsig_key = NULL;
	tsig_record_type *tsig = NULL;
	
	log_init("nsd-xfer");

	srandom((unsigned long) getpid() * (unsigned long) time(NULL));

	if (!tsig_init(region)) {
		error("TSIG initialization failed");
	}

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46f:hp:s:T:z:")) != -1) {
		switch (c) {
		case '4':
			default_family = AF_INET;
			break;
		case '6':
#ifdef INET6
			default_family = AF_INET6;
#else /* !INET6 */
			error("IPv6 support not enabled.");
#endif /* !INET6 */
			break;
		case 'f':
			file = optarg;
			break;
		case 'h':
			usage();
			break;
		case 'p':
			port = optarg;
			break;
		case 's':
			serial = optarg;
			break;
		case 'T':
			tsig_key_filename = optarg;
			break;
		case 'z':
			zone = dname_parse(region, optarg, NULL);
			break;
		case '?':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0 || !zone || !file)
		usage();

	if (serial) {
		const char *t;
		current_serial = strtottl(serial, &t);
		if (*t != '\0') {
			error("bad serial '%s'\n", serial);
			exit(XFER_FAIL);
		}
	}
	
	if (tsig_key_filename) {
		tsig_algorithm_type *md5
			= tsig_get_algorithm_by_name("hmac-md5");
		if (!md5) {
			error("cannot initialize hmac-md5: TSIG support not"
			      " enabled");
			exit(XFER_FAIL);
		}
		
		tsig_key = read_tsig_key(
			region, tsig_key_filename, default_family);
		if (!tsig_key) {
			exit(XFER_FAIL);
		}

		tsig_add_key(tsig_key);
		
		tsig = (tsig_record_type *) region_alloc(
			region, sizeof(tsig_record_type));
		tsig_init_record(tsig, region, md5, tsig_key);
	}
	
	/* Initialize the query */
	memset(&q, 0, sizeof(query_type));
	q.region = region;
	q.addrlen = sizeof(q.addr);
	q.packet = buffer_create(region, QIOBUFSZ);
	q.maxlen = MAX_PACKET_SIZE;

	for (; *argv; ++argv) {
		/* Try each server separately until one succeeds.  */
		int rc;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		rc = getaddrinfo(*argv, port, &hints, &res0);
		if (rc) {
			warning("skipping bad address %s: %s\n",
				*argv,
				gai_strerror(rc));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			uint32_t zone_serial = (uint32_t) -1;
			int s;
			
			if (res->ai_addrlen > sizeof(q.addr))
				continue;

			s = socket(res->ai_family, res->ai_socktype,
				   res->ai_protocol);
			if (s == -1)
				continue;

			if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
				warning("cannot connect to %s: %s\n",
					*argv,
					strerror(errno));
				close(s);
				if (!res->ai_next) {
					error("failed to connect to master servers");
				}
				continue;
			}
			
			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

			rc = check_serial(s,
					  &q,
					  zone,
					  current_serial,
					  &zone_serial,
					  tsig);
			if (rc == -1) {
				close(s);
				continue;
			}

			printf("Current serial %lu, zone serial %lu\n",
			       (unsigned long) current_serial,
			       (unsigned long) zone_serial);

			if (rc == 0) {
				printf("Zone up-to-date, done.\n");
				close(s);
				exit(XFER_UPTODATE);
			} else if (rc > 0) {
				printf("Transferring zone.\n");
				
				zone_file = fopen(file, "w");
				if (!zone_file) {
					error("cannot open or create zone file '%s' for writing: %s",
					      file, strerror(errno));
					close(s);
					exit(XFER_FAIL);
				}
	
				if (axfr(s, &q, zone, zone_file, tsig)) {
					/* AXFR succeeded, done.  */
					fclose(zone_file);
					close(s);
					exit(XFER_SUCCESS);
				}
			}
			
			close(s);
		}

		freeaddrinfo(res0);
	}

	exit(0);
}
