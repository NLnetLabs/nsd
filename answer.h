/*
 * answer.h -- manipulating query answers and encoding them.
 *
 * Erik Rozendaal, <erik@nlnetlabs.nl>
 *
 * Copyright (c) 2001-2004, NLnet Labs. All rights reserved.
 *
 * This software is an open source.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _ANSWER_H_
#define _ANSWER_H_

#include <sys/types.h>

#include "namedb.h"
#include "query.h"
#include "util.h"

enum answer_section {
	QUESTION_SECTION,
	ANSWER_SECTION,
	AUTHORITY_SECTION,
	/*
	 * Use a split additional section to ensure A records appear
	 * before any AAAA records (this is recommended practice to
	 * avoid truncating the additional section for IPv4 clients
	 * that do not specify EDNS0).  Encode_answer sets the ARCOUNT
	 * field of the response packet correctly.
	 */
	ADDITIONAL_A_SECTION, ADDITIONAL_AAAA_SECTION
};
typedef enum answer_section answer_section_type;

/*
 * Structure used to keep track of RRsets that need to be stored in
 * the answer packet.
 */
typedef struct answer answer_type;
struct answer {
	size_t rrset_count;
	rrset_type *rrsets[MAXRRSPP];
	domain_type *domains[MAXRRSPP];
	answer_section_type section[MAXRRSPP];
};


int encode_rr(struct query *query,
	      domain_type  *owner,
	      rrset_type   *rrset,
	      uint16_t      rr);
void encode_answer(struct query *q, const answer_type *answer);


void answer_init(answer_type *answer);

/*
 * Add the specified RRset to the answer in the specified section.  If
 * the RRset is already present and in the same (or "higher") section
 * return 0, otherwise return 1.
 */
int answer_add_rrset(answer_type *answer, answer_section_type section,
		     domain_type *domain, rrset_type *rrset);

#endif /* _ANSWER_H_ */
