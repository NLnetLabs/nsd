/*
 * nsd-notify.c -- sends notify(rfc1996) message to a list of servers
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>

#include <sys/types.h>
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <tsig.h>
#include <unistd.h>
#include <netdb.h>

#include "query.h"

extern char *optarg;
extern int optind;

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

static void
usage (void)
{
	fprintf(stderr, "usage: nsd-notify [-4] [-6] [-h] [-p port] [-y key:secret[:algo]] "
		"-z zone servers\n\n");
	fprintf(stderr, "\tSend NOTIFY to secondary servers to force a zone update.\n");
	fprintf(stderr, "\tVersion %s. Report bugs to <%s>.\n\n",
		PACKAGE_VERSION, PACKAGE_BUGREPORT);
	fprintf(stderr, "\t-4\t\tSend using IPv4.\n");
	fprintf(stderr, "\t-6\t\tSend using IPv6.\n");
	fprintf(stderr, "\t-h\t\tPrint this help information.\n");
	fprintf(stderr, "\t-p port\t\tPort number of secondary server.\n");
	fprintf(stderr, "\t-y key:secret[:algo]\tTSIG keyname, base64 secret \
blob and HMAC algorithm. If algo is not provided, HMAC-MD5 is assumed.\n");
	fprintf(stderr, "\t-z zone\t\tName of zone to be updated.\n");
	fprintf(stderr, "\tservers\t\tIP addresses of the secondary server(s).\n");
	exit(1);
}

/*
 * Send NOTIFY messages to the host, as in struct q,
 * waiting for ack packet (received in buffer answer).
 * Will retry transmission after a timeout.
 * addrstr is the string describing the address of the host.
 */
static void
notify_host(int udp_s, struct query* q, struct query *answer,
	struct addrinfo* res, const dname_type *zone, const char* addrstr)
{
	int timeout_retry = 1; /* seconds */
	int num_retry = 6; /* times to try */
	fd_set rfds;
	struct timeval tv;
	int retval = 0;
	ssize_t received = 0;
	int got_ack = 0;
	socklen_t addrlen = 0;

	while(!got_ack) {
		/* WE ARE READY SEND IT OUT */
		if (sendto(udp_s,
		   	buffer_current(q->packet),
		   	buffer_remaining(q->packet), 0,
		   	res->ai_addr, res->ai_addrlen) == -1) {
			warning("send to %s failed: %s\n", addrstr,
				strerror(errno));
			close(udp_s);
			return;
		}

		/* wait for ACK packet */
		FD_ZERO(&rfds);
		FD_SET(udp_s, &rfds);
		tv.tv_sec = timeout_retry; /* seconds */
		tv.tv_usec = 0; /* microseconds */
		retval = select(udp_s + 1, &rfds, NULL, NULL, &tv);
		if (retval == -1) {
			warning("error waiting for reply from %s: %s\n",
				addrstr, strerror(errno));
			close(udp_s);
			return;
		}
		if (retval == 0) {
			num_retry--;
			if(num_retry == 0) {
				warning("error: failed to send notify to %s.\n",
					addrstr);
				exit(1);
			}
			warning("timeout (%d s) expired, retry notify to %s.\n",
				timeout_retry, addrstr);
		}
		if (retval == 1) {
			got_ack = 1;
		}
		/* Exponential backoff */
		timeout_retry *= 2;
	}

	/* receive reply */
	addrlen = res->ai_addrlen;
	received = recvfrom(udp_s, buffer_begin(answer->packet),
		buffer_remaining(answer->packet), 0,
		res->ai_addr, &addrlen);
	res->ai_addrlen = addrlen;

	if (received == -1) {
		warning("recv %s failed: %s\n", addrstr, strerror(errno));
	} else {
		/* check the answer */
		if ((ID(q->packet) == ID(answer->packet)) &&
			(OPCODE(answer->packet) == OPCODE_NOTIFY) &&
			AA(answer->packet) &&
			QR(answer->packet) && (RCODE(answer->packet) == RCODE_OK)) {
			/* no news is good news */
			/* info("reply from: %s, acknowledges notify.\n",
				addrstr); */
		} else {
			warning("bad reply from %s for zone %s, error response %s (%d).\n",
				addrstr, dname_to_string(zone, NULL), rcode2str(RCODE(answer->packet)),
				RCODE(answer->packet));
		}
	}
	close(udp_s);
}

#ifdef TSIG
static tsig_key_type*
add_key(region_type* region, const char* opt, tsig_algorithm_type** algo)
{
	/* parse -y key:secret_base64 format option */
	char* delim = strchr(opt, ':');
	char* delim2 = NULL;

	if (delim)
		delim2 = strchr(delim+1, ':');

	tsig_key_type *key = (tsig_key_type*)region_alloc(
		region, sizeof(tsig_key_type));
	size_t len;
	int sz;
	if(!delim) {
		log_msg(LOG_ERR, "bad key syntax %s", opt);
		return 0;
	}
	*delim = '\0';
	key->name = dname_parse(region, opt);
	if(!key->name) {
		log_msg(LOG_ERR, "bad key name %s", opt);
		return 0;
	}
	*delim = ':';

	if (!delim2)
		*algo = tsig_get_algorithm_by_name("hmac-md5");
	else {
		char* by_name = (char*) malloc(sizeof(char)*(5+strlen(delim2)));
		sprintf(by_name, "hmac-%s", delim2+1);
		*algo = tsig_get_algorithm_by_name(by_name);
		free(by_name);
		*delim2 = '\0';
	}

	if (!(*algo)) {
		*delim2 = ':';
		log_msg(LOG_ERR, "bad tsig algorithm %s", opt);
		return 0;
	}

	len = strlen(delim+1);
	key->data = region_alloc(region, len+1);
	sz= b64_pton(delim+1, (uint8_t*)key->data, len);
	if(sz == -1) {
		log_msg(LOG_ERR, "bad key syntax %s", opt);
		return 0;
	}
	key->size = sz;
	tsig_add_key(key);
	return key;
}
#endif /* TSIG */

int
main (int argc, char *argv[])
{
	int c, udp_s;
	struct query q;
	struct query answer;
	const dname_type *zone = NULL;
	struct addrinfo hints, *res0, *res;
	int error;
	int default_family = DEFAULT_AI_FAMILY;
	const char *port = UDP_PORT;
	region_type *region = region_create(xalloc, free);
#ifdef TSIG
	tsig_key_type *tsig_key = 0;
	tsig_record_type tsig;
	tsig_algorithm_type* algo = NULL;
#endif /* TSIG */
	log_init("nsd-notify");
#ifdef TSIG
	if(!tsig_init(region)) {
		log_msg(LOG_ERR, "could not init tsig\n");
		exit(1);
	}
#endif /* TSIG */

	/* Parse the command line... */
	while ((c = getopt(argc, argv, "46hp:y:z:")) != -1) {
		switch (c) {
		case '4':
			default_family = AF_INET;
			break;
		case '6':
#ifdef INET6
			default_family = AF_INET6;
			break;
#else /* !INET6 */
			log_msg(LOG_ERR, "IPv6 support not enabled\n");
			exit(1);
#endif /* !INET6 */
		case 'p':
			port = optarg;
			break;
		case 'y':
#ifdef TSIG
			if (!(tsig_key = add_key(region, optarg, &algo)))
				exit(1);
#else
			log_msg(LOG_ERR, "option -y given but TSIG not enabled");
#endif /* TSIG */
			break;
		case 'z':
			zone = dname_parse(region, optarg);
			if (!zone) {
				log_msg(LOG_ERR,
					"incorrect domain name '%s'",
					optarg);
				exit(1);
			}
			break;
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc == 0 || zone == NULL) {
		usage();
	}

	/* Initialize the query */
	memset(&q, 0, sizeof(struct query));
	q.addrlen = sizeof(q.addr);
	q.maxlen = 512;
	q.packet = buffer_create(region, QIOBUFSZ);
	memset(buffer_begin(q.packet), 0, buffer_remaining(q.packet));

	/* Set up the header */
	OPCODE_SET(q.packet, OPCODE_NOTIFY);
	ID_SET(q.packet, 42);	/* Does not need to be random. */
	AA_SET(q.packet);
	QDCOUNT_SET(q.packet, 1);
	buffer_skip(q.packet, QHEADERSZ);
	buffer_write(q.packet, dname_name(zone), zone->name_size);
	buffer_write_u16(q.packet, TYPE_SOA);
	buffer_write_u16(q.packet, CLASS_IN);
#ifdef TSIG
	if(tsig_key) {
		assert(algo);
		tsig_create_record(&tsig, region);
		tsig_init_record(&tsig, algo, tsig_key);
		tsig_init_query(&tsig, ID(q.packet));
		tsig_prepare(&tsig);
		tsig_update(&tsig, q.packet, buffer_position(q.packet));
		tsig_sign(&tsig);
		tsig_append_rr(&tsig, q.packet);
		ARCOUNT_SET(q.packet, ARCOUNT(q.packet) + 1);
	}
#endif
	buffer_flip(q.packet);

	/* initialize buffer for ack */
	memset(&answer, 0, sizeof(struct query));
	answer.addrlen = sizeof(answer.addr);
	answer.maxlen = 512;
	answer.packet = buffer_create(region, QIOBUFSZ);
	memset(buffer_begin(answer.packet), 0, buffer_remaining(answer.packet));

	for (/*empty*/; *argv; argv++) {
		/* Set up UDP */
		memset(&hints, 0, sizeof(hints));
		hints.ai_family = default_family;
		hints.ai_socktype = SOCK_DGRAM;
		hints.ai_protocol = IPPROTO_UDP;
		error = getaddrinfo(*argv, port, &hints, &res0);
		if (error) {
			warning("skipping bad address %s: %s\n", *argv,
			    gai_strerror(error));
			continue;
		}

		for (res = res0; res; res = res->ai_next) {
			if (res->ai_addrlen > sizeof(q.addr)) {
				continue;
			}

			udp_s = socket(res->ai_family, res->ai_socktype,
				       res->ai_protocol);
			if (udp_s == -1) {
				continue;
			}

			memcpy(&q.addr, res->ai_addr, res->ai_addrlen);
			notify_host(udp_s, &q, &answer, res, zone, *argv);
		}
		freeaddrinfo(res0);
	}
	exit(0);
}
