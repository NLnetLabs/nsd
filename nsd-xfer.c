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
#include <unistd.h>

#include "dname.h"
#include "dns.h"
#include "query.h"
#include "region-allocator.h"
#include "util.h"
#include "zonec.h"

extern char *optarg;
extern int optind;

static void error(const char *format, ...) ATTR_FORMAT(printf, 1, 2);

static void
usage (void)
{
	fprintf(stderr,
		"Usage: nsd-xfer [-4] [-6] [-p port] [-s serial] -z zone"
		" -f file servers...\n");
	exit(1);
}

static void
error(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	log_vmsg(LOG_ERR, format, args);
	va_end(args);
	exit(1);
}

static int
write_socket(int s, const void *buf, size_t size)
{
	const char *data = buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = write(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EINTR) {
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
read_socket(int s, void *buf, size_t size)
{
	char *data = buf;
	size_t total_count = 0;

	while (total_count < size) {
		ssize_t count = read(s, data + total_count, size - total_count);
		if (count == -1) {
			if (errno != EINTR) {
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
skip_dname(buffer_type *packet)
{
	int done = 0;
	const uint8_t *label;
	uint8_t visited[MAX_PACKET_SIZE];
	size_t mark = buffer_position(packet);
	
	memset(visited, 0, buffer_limit(packet));
	
	while (!done) {
		if (!buffer_available(packet, 1)) {
			error("dname out of bounds");
			buffer_set_position(packet, mark);
			return 0;
		}

		if (visited[buffer_position(packet)]) {
			error("dname loops");
			buffer_set_position(packet, mark);
			return 0;
		}
		visited[buffer_position(packet)] = 1;

		label = buffer_current(packet);
		if (label_is_pointer(label)) {
			if (!buffer_available(packet, 2)) {
				error("dname out of bounds");
				buffer_set_position(packet, mark);
				return 0;
			}
			buffer_skip(packet, 2);
			done = 1;
		} else if (label_is_root(label)) {
			buffer_skip(packet, 1);
			done = 1;
		} else if (label_is_normal(label)) {
			size_t length = label_length(label) + 1;
			if (!buffer_available(packet, length)) {
				error("dname out of bounds");
				buffer_set_position(packet, mark);
				return 0;
			}
			buffer_skip(packet, length);
		} else {
			error("bad dname label");
			buffer_set_position(packet, mark);
			return 0;
		}
	}

	return 1;
}

const dname_type *
parse_dname(region_type *region, buffer_type *packet)
{
	uint8_t buf[MAXDOMAINLEN + 1];
	int done = 0;
	uint8_t visited[MAX_PACKET_SIZE];
	size_t dname_length = 0;
	const uint8_t *label;
	size_t mark = buffer_position(packet);
	
	memset(visited, 0, buffer_limit(packet));
	
	while (!done) {
		if (!buffer_available(packet, 1)) {
			error("dname out of bounds");
			buffer_set_position(packet, mark);
			return NULL;
		}

		if (visited[buffer_position(packet)]) {
			error("dname loops");
			buffer_set_position(packet, mark);
			return NULL;
		}
		visited[buffer_position(packet)] = 1;

		label = buffer_current(packet);
		if (label_is_pointer(label)) {
			size_t pointer;
			if (!buffer_available(packet, 2)) {
				error("dname pointer out of bounds");
				buffer_set_position(packet, mark);
				return NULL;
			}
			pointer = label_pointer_location(label);
			if (!buffer_available_at(packet, pointer, 0)) {
				error("dname pointer points outside packet");
				buffer_set_position(packet, mark);
				return NULL;
			}
			buffer_set_position(packet, pointer);
		} else if (label_is_normal(label)) {
			size_t length = label_length(label) + 1;
			done = label_is_root(label);
			if (!buffer_available(packet, length)) {
				error("dname label out of bounds");
				buffer_set_position(packet, mark);
				return NULL;
			}
			if (dname_length + length >= sizeof(buf)) {
				error("dname too large");
				buffer_set_position(packet, mark);
				return NULL;
			}
			buffer_read(packet, buf + dname_length, length);
			dname_length += length;
		} else {
			error("bad label type");
			buffer_set_position(packet, mark);
			return NULL;
		}
	}

	buffer_set_position(packet, mark);
	return dname_make(region, buf);
}

static int
print_rr(region_type *region, buffer_type *packet, FILE *out,
	 const dname_type *owner, uint16_t rrtype, uint16_t rrclass,
	 uint32_t rrttl, uint16_t rdlength)
{
	int i;
	rrtype_descriptor_type *descriptor = rrtype_descriptor_by_type(rrtype);
	const dname_type *dname;
	char buf[100];
	size_t end = buffer_position(packet) + rdlength;
	size_t length;
	
	if (!buffer_available(packet, rdlength)) {
		error("RDATA truncated");
		region_destroy(region);
		return 0;
	}
	
	fprintf(out, "%s %lu", dname_to_string(owner), (unsigned long) rrttl);
	if (rrclass == CLASS_IN) {
		fprintf(out, " IN");
	} else {
		fprintf(out, " CLASS%d", rrclass);
	}
	if (descriptor->name) {
		fprintf(out, " %s", descriptor->name);
	} else {
		fprintf(out, " TYPE%d", rrtype);
	}

	for (i = 0; i < descriptor->maximum; ++i) {
		if (buffer_position(packet) >= end) {
			if (i < descriptor->minimum) {
				error("RDATA is not complete");
				return 0;
			} else {
				break;
			}
		}

		switch (descriptor->zoneformat[i]) {
		case RDATA_ZF_DNAME:
			dname = parse_dname(region, packet);
			if (!dname) {
				return 0;
			}
			skip_dname(packet);
			fprintf(out, " %s", dname_to_string(dname));
			break;
		case RDATA_ZF_TEXT:
			/* FIXME */
			length = buffer_read_u8(packet);
			if (!buffer_available(packet, length)) {
				error("Text data out of bounds");
				return 0;
			}
			fprintf(out, " \"");
			fwrite(buffer_current(packet), length, 1, out);
			fprintf(out, "\"");
			buffer_skip(packet, length);
			break;
		case RDATA_ZF_BYTE:
			fprintf(out, " %u", buffer_read_u8(packet));
			break;
		case RDATA_ZF_SHORT:
			fprintf(out, " %u", buffer_read_u16(packet));
			break;
		case RDATA_ZF_LONG:
			fprintf(out, " %lu",
				(unsigned long) buffer_read_u32(packet));
			break;
		case RDATA_ZF_A:
			fprintf(out, " %s",
				inet_ntop(AF_INET, buffer_current(packet),
					  buf, sizeof(buf)));
			buffer_skip(packet, 4);
			break;
		case RDATA_ZF_AAAA:
			fprintf(out, " %s", inet_ntop(AF_INET6, buffer_current(packet), buf, sizeof(buf)));
			buffer_skip(packet, IP6ADDRLEN);
			break;

		case RDATA_ZF_PERIOD:
			fprintf(out, " %lu",
				(unsigned long) buffer_read_u32(packet));
			break;
		default:
			fprintf(stderr, "unimplemented zone format: %d\n", descriptor->zoneformat[i]);
			abort();
		}
	}
	
	fprintf(out, "\n");
	return 1;
}

	
static int
parse_response(struct query *q, FILE *out, int first, int *done)
{
	region_type *rr_region = region_create(xalloc, free);
	size_t rr_count;

	size_t qdcount = ntohs(QDCOUNT(q));
	size_t ancount = ntohs(ANCOUNT(q));
	size_t nscount = ntohs(NSCOUNT(q));
	size_t arcount = ntohs(ARCOUNT(q));
	
	const dname_type *owner;
	uint16_t rrtype;
	uint16_t rrclass;
	uint32_t rrttl;
	uint16_t rdlength;

	for (rr_count = 0; rr_count < qdcount + ancount; ++rr_count) {
		owner = parse_dname(rr_region, q->packet);
		if (!owner) {
			region_destroy(rr_region);
			return 0;
		}
		skip_dname(q->packet);

		if (rr_count < qdcount) {
			if (!buffer_available(q->packet, 4)) {
				error("RR out of bounds 1");
				region_destroy(rr_region);
				return 0;
			}
			buffer_skip(q->packet, 4);
			continue;
		} else {
			if (!buffer_available(q->packet, 10)) {
				error("RR out of bounds 2");
				region_destroy(rr_region);
				return 0;
			}
			rrtype = buffer_read_u16(q->packet);
			rrclass = buffer_read_u16(q->packet);
			rrttl = buffer_read_u32(q->packet);
			rdlength = buffer_read_u16(q->packet);

			if (first && rrtype != TYPE_SOA) {
				error("First RR is not SOA, but %u", rrtype);
				region_destroy(rr_region);
				return 0;
			} else if (!first && rrtype == TYPE_SOA) {
				*done = 1;
				region_destroy(rr_region);
				return 1;
			}

			first = 0;
			if (!print_rr(rr_region, q->packet, out, owner, rrtype, rrclass, rrttl, rdlength)) {
				region_destroy(rr_region);
				return 0;
			}
		}

		region_free_all(rr_region);
	}

	region_destroy(rr_region);
	return 1;
}

static int
do_axfr(int s, struct query *q, FILE *out)
{
	int done = 0;
	int first = 1;
	uint16_t size = htons(buffer_remaining(q->packet));
	uint16_t query_id = ID(q);
	
	assert(q->maxlen <= QIOBUFSZ);
	
	if (!write_socket(s, &size, sizeof(size))) {
		error("failed to send query size: %s", strerror(errno));
		return 0;
	}
	if (!write_socket(s, buffer_current(q->packet), buffer_remaining(q->packet))) {
		error("failed to send query data: %s", strerror(errno));
		return 0;
	}

	while (!done) {
		buffer_clear(q->packet);
		if (!read_socket(s, &size, sizeof(size))) {
			error("failed to read response size: %s",
			      strerror(errno));
			return 0;
		}
		size = ntohs(size);
		if (size > q->maxlen) {
			error("response size (%d) exceeds maximum (%d)",
			      (int) size, (int) q->maxlen);
			return 0;
		}
		if (!read_socket(s, buffer_begin(q->packet), size)) {
			error("failed to read response data: %s",
			      strerror(errno));
			return 0;
		}

		buffer_skip(q->packet, size);
		buffer_flip(q->packet);
		
		if (size <= QHEADERSZ) {
			error("response size (%d) is too small", (int) size);
			return 0;
		}

		if (!QR(q)) {
			error("response is not a response");
			return 0;
		}

		if (ID(q) != query_id) {
			error("bad response id (%d), expected (%d)",
			      (int) ntohs(ID(q)), (int) ntohs(query_id));
			return 0;
		}

		if (RCODE(q) != RCODE_OK) {
			error("error response %d", (int) RCODE(q));
			return 0;
		}

		if (ntohs(QDCOUNT(q)) > 1) {
			error("query section count greater than 1");
			return 0;
		}

		if (ntohs(ANCOUNT(q)) == 0) {
			error("answer section is empty");
			return 0;
		}

		buffer_skip(q->packet, QHEADERSZ);
		
		if (!parse_response(q, out, first, &done))
			return 0;

		first = 0;
		
		fprintf(stderr, "Received response size %d\n", (int) size);
	}
	return 1;
}

int 
main (int argc, char *argv[])
{
	/* Scratch variables... */
	int c;
	struct query q;
	struct addrinfo hints, *res0, *res;
	const dname_type *zone = NULL;
	const char *file = NULL;
	const char *serial = NULL;
	const char *port = TCP_PORT;
	region_type *region = region_create(xalloc, free);
	int default_family = DEFAULT_AI_FAMILY;
	FILE *zone_file;
	
	log_init("nsd-xfer");
	
	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46f:hp:s:z:")) != -1) {
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

	zone_file = fopen(file, "w");
	if (!zone_file) {
		error("cannot open zone file '%s' for writing: %s",
		      file, strerror(errno));
		exit(1);
	}
	
	/* Initialize the query */
	memset(&q, 0, sizeof(struct query));
	q.addrlen = sizeof(q.addr);
	q.packet = buffer_create(region, QIOBUFSZ);
	q.maxlen = MAX_PACKET_SIZE;

	/* Set up the header */
	OPCODE_SET(&q, OPCODE_QUERY);
	ID(&q) = 42;          /* Does not need to be random. */
	AA_SET(&q);

	buffer_skip(q.packet, QHEADERSZ);
	buffer_write(q.packet, dname_name(zone), zone->name_size);
	buffer_write_u16(q.packet, TYPE_AXFR);
	buffer_write_u16(q.packet, CLASS_IN);

	/* Set QDCOUNT=1 */
	QDCOUNT(&q) = htons(1);

	buffer_flip(q.packet);
	
	for (; *argv; ++argv) {
		/* Try each server separately until one succeeds.  */
		int error;
		
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		error = getaddrinfo(*argv, port, &hints, &res0);
		if (error) {
			fprintf(stderr, "skipping bad address %s: %s\n", *argv,
				gai_strerror(error));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			int s;
			if (res->ai_addrlen > sizeof(q.addr))
				continue;

			s = socket(res->ai_family, res->ai_socktype,
				   res->ai_protocol);
			if (s == -1)
				continue;

			if (connect(s, res->ai_addr, res->ai_addrlen) < 0)
				continue;
			
			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);

			if (do_axfr(s, &q, zone_file)) {
				/* AXFR succeeded, done.  */
				fclose(zone_file);
				exit(0);
			}
			
			close(s);
		}

		freeaddrinfo(res0);
	}

	exit(0);
}
