/*
 * answer.h -- manipulating query answers and encoding them.
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _ANSWER_H_
#define _ANSWER_H_

#include <sys/types.h>

#include "namedb.h"
#include "query.h"
#include "util.h"

enum rr_section {
	QUESTION_SECTION,
	ANSWER_SECTION,
	AUTHORITY_SECTION,
	ADDITIONAL_SECTION,
	/*
	 * Use a split additional section to ensure A records appear
	 * before any AAAA records (this is recommended practice to
	 * avoid truncating the additional section for IPv4 clients
	 * that do not specify EDNS0), and AAAA records before other
	 * types of additional records (such as X25 and ISDN).
	 * Encode_answer sets the ARCOUNT field of the response packet
	 * correctly.
	 */
	ADDITIONAL_A_SECTION = ADDITIONAL_SECTION,
	ADDITIONAL_AAAA_SECTION,
	ADDITIONAL_OTHER_SECTION,

	RR_SECTION_COUNT
};
typedef enum rr_section rr_section_type;

/*
 * Structure used to keep track of RRsets that need to be stored in
 * the answer packet.
 */
typedef struct answer answer_type;
struct answer {
	size_t rrset_count;
	rrset_type *rrsets[MAXRRSPP];
	domain_type *domains[MAXRRSPP];
	rr_section_type section[MAXRRSPP];
};


int encode_rr(struct query *query, domain_type  *owner, rr_type *rr);
void encode_answer(struct query *q, const answer_type *answer);


void answer_init(answer_type *answer);

/*
 * Add the specified RRset to the answer in the specified section.  If
 * the RRset is already present and in the same (or "higher") section
 * return 0, otherwise return 1.
 */
int answer_add_rrset(answer_type *answer, rr_section_type section,
		     domain_type *domain, rrset_type *rrset);


#ifdef __cplusplus
inline rr_section_type
operator++(rr_section_type &lhs)
{
	lhs = (rr_section_type) ((int) lhs + 1);
	return lhs;
}
#endif /* __cplusplus */

#endif /* _ANSWER_H_ */
