/*
 * nsd-ldnsd. Light-weight DNS daemon, which sends IXFRs
 *
 * Tiny dns server to show how a real one could be built.
 * This version is used for NSD test, send out IXFR's only.
 *
 * (c) NLnet Labs, 2005, 2006
 * See the file LICENSE for the license
 */

#include "config.h"
#include <ldns/dns.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <netinet/igmp.h>
#include <errno.h>

#define INBUF_SIZE 4096
#define MAX_LEN    1024

void usage(FILE *output)
{
	fprintf(output, "Usage: nsd-ldnsd -# <port> <ixfr-zone-file>\n");
	fprintf(output, "Listens on the specified port and answer every query with an IXFR\n");
	fprintf(output, "This is NOT a full-fledged authoritative nameserver! It is NOTHING.\n");
	fprintf(output, "-# quit after this many queries.\n");
}

static int udp_bind(int sock, int port, const char *my_address)
{
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = (in_port_t)htons((uint16_t)port);
		addr.sin_addr.s_addr = INADDR_ANY;
    return bind(sock, (struct sockaddr *)&addr, (socklen_t) sizeof(addr));
}

int
main(int argc, char **argv)
{
	/* arguments */
	int port;
	int soa;
	ldns_rdf *zone_name;
	size_t count;
	size_t maxcount;

	/* network */
	int sock;
	size_t nb;
	struct sockaddr addr_me;
	struct sockaddr addr_him;
	socklen_t hislen;
	const char *my_address;
	uint8_t inbuf[INBUF_SIZE];
	uint8_t *outbuf;

	/* dns */
	ldns_status status;
	ldns_pkt *query_pkt;
	ldns_pkt *answer_pkt;
	size_t answer_size;
	ldns_rr *query_rr;
	ldns_rr *rr;
	char rr_string[MAX_LEN + 1];
	ldns_rr *soa_rr;
	char soa_string[MAX_LEN + 1];
	
	/* use this to listen on specified interfaces later? */
	my_address = NULL;

	if(argc == 5) {
		/* -# num given */
		if (argv[1][0] == '-') {
			maxcount = atoi(argv[1] + 1);
			if (maxcount == 0) {
				usage(stdout);
				exit(EXIT_FAILURE);
			} else {
				fprintf(stderr, "quiting after %d qs\n", maxcount);
			}
		} else {
			fprintf(stderr, "Use -Number for max count\n");
			exit(EXIT_FAILURE);
		}
		argc--;
		argv++;
	} else {
		maxcount = 0;
	}
	
	if (argc != 4) {
		usage(stdout);
		exit(EXIT_FAILURE);
	} else {
		port = atoi(argv[1]);
		if (port < 1) {
			fprintf(stderr, "Use a number for the port\n");
			usage(stdout);
			exit(EXIT_FAILURE);
		}
		
		zone_name = ldns_dname_new_frm_str(argv[2]);
		if (!zone_name) {
			fprintf(stderr, "Illegal domain name: %s\n", argv[2]);
			usage(stdout);
			exit(EXIT_FAILURE);
		}
		soa =  atoi(argv[3]);
		if (soa < 1) {
			fprintf(stderr, "Illegal soa number\n");
			usage(stdout);
			exit(EXIT_FAILURE);
		}
			
	}
	
	printf("Listening on port %d\n", port);
	sock =  socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf(stderr, "%s: socket(): %s\n", argv[0], strerror(errno));
		exit(EXIT_FAILURE);
	}

	memset(&addr_me, 0, sizeof(addr_me));

	/* bind: try all ports in that range */
	if (udp_bind(sock, port, my_address)) {
		fprintf(stderr, "%s: cannot bind(): %s\n", argv[0], strerror(errno));
	}

	/* create our ixfr answer */
	answer_pkt = ldns_pkt_new();

	snprintf(rr_string, MAX_LEN, "%s IN IXFR", argv[2]);
	(void)ldns_rr_new_frm_str(&rr, rr_string , 0, NULL, NULL);
	(void)ldns_pkt_push_rr(answer_pkt, LDNS_SECTION_QUESTION, rr);

	 /* next add some rrs, with SOA stuff so that we mimic or ixfr reply */
	snprintf(soa_string, MAX_LEN, "%s IN SOA miek.miek.nl elektron.atoom.net %d 1 2 3 4",
			argv[2], soa);

        (void)ldns_rr_new_frm_str(&soa_rr, soa_string, 0, NULL, NULL);
	snprintf(rr_string, MAX_LEN, "%s IN A 127.0.0.1", argv[2]);
        (void)ldns_rr_new_frm_str(&rr, rr_string , 0, NULL, NULL);

        /* compose the ixfr pkt */
        (void)ldns_pkt_push_rr(answer_pkt, LDNS_SECTION_ANSWER, soa_rr);
        (void)ldns_pkt_push_rr(answer_pkt, LDNS_SECTION_ANSWER, rr);
        (void)ldns_pkt_push_rr(answer_pkt, LDNS_SECTION_ANSWER, soa_rr);

	/* Done. Now receive */
	count = 0;
	while (1) {
		nb = (size_t) recvfrom(sock, inbuf, INBUF_SIZE, 0, &addr_him, &hislen);
		if (nb < 1) {
			fprintf(stderr, "%s: recvfrom(): %s\n",
			argv[0], strerror(errno));
			exit(EXIT_FAILURE);
		}
		
		printf("Got query of %u bytes\n", (unsigned int) nb);
		status = ldns_wire2pkt(&query_pkt, inbuf, nb);
		if (status != LDNS_STATUS_OK) {
			printf("Got bad packet: %s\n", ldns_get_errorstr_by_id(status));
			continue;
		}
		
		query_rr = ldns_rr_list_rr(ldns_pkt_question(query_pkt), 0);
		printf("%d QUERY RR +%d: \n", ++count, ldns_pkt_id(query_pkt));
		ldns_rr_print(stdout, query_rr);
		
		ldns_pkt_set_id(answer_pkt, ldns_pkt_id(query_pkt));

		status = ldns_pkt2wire(&outbuf, answer_pkt, &answer_size);
		
		printf("Answer packet size: %u bytes.\n", (unsigned int) answer_size);
		if (status != LDNS_STATUS_OK) {
			printf("Error creating answer: %s\n", ldns_get_errorstr_by_id(status));
		} else {
			nb = (size_t) sendto(sock, outbuf, answer_size, 0, &addr_him, hislen);
		}

		if (maxcount > 0  && count >= maxcount) {
			fprintf(stderr, "%d queries seen... goodbye\n", count);
			exit(EXIT_SUCCESS);
		}
	}
        return 0;
}
