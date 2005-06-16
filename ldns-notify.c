/* 
 * send a notify packet to a server
 */


#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <stdbool.h>

#include <stdint.h>

#include <ldns/dns.h>

int
main(int argc, char **argv)
{
	ldns_pkt *notify;
	ldns_rr *question;
	ldns_rdf *helper;
	ldns_resolver *res;
	
	notify = ldns_pkt_new();
	question = ldns_rr_new();
	res = ldns_resolver_new();

	if (!notify || !question || !res) {
		/* bail out */
		return EXIT_FAILURE;
	}
	/* get the port and nameserver ip from the config */
	ldns_resolver_set_port(res, LDNS_PORT);
	/* ldns_resolver_push_nameserver(res, ns); */

	/* create the rr */
	ldns_rr_set_class(question, LDNS_RR_CLASS_IN);

	helper = ldns_dname_new_frm_str("miek.nl");
	ldns_rr_set_owner(question, helper);

	ldns_rr_set_type(question, LDNS_RR_TYPE_SOA);

	ldns_pkt_set_opcode(notify, LDNS_PACKET_NOTIFY);
	ldns_pkt_push_rr(notify, LDNS_PACKET_QUESTION, question);
	ldns_pkt_set_aa(notify, true);
	ldns_pkt_set_id(notify, 42); /* from nsd-notify... */

	ldns_pkt_print(stdout, notify);

	/*ldns_resolver_send_pkt(NULL, res, notify)*/
        return EXIT_SUCCESS;
}
