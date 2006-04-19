/*
 * iterated_hash.c -- nsec3 hash calculation.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 * With thanks to Ben Laurie.
 */
#include <config.h>
#ifdef NSEC3
#include <openssl/sha.h>
#include <stdio.h>

#include "iterated_hash.h"
#include "namedb.h"
#include "nsd.h"

int 
iterated_hash(unsigned char out[SHA_DIGEST_LENGTH],
	const unsigned char *salt, int saltlength,
	const unsigned char *in, int inlength, int iterations)
{
	SHA_CTX ctx;
	int n;
	for(n=0 ; n <= iterations ; ++n)
	{
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, in, inlength);
		SHA1_Update(&ctx, salt, saltlength);
		SHA1_Final(out, &ctx);
		in=out;
		inlength=SHA_DIGEST_LENGTH;
	}
	return SHA_DIGEST_LENGTH;
}

const dname_type *
nsec3_hash_dname(region_type *region, domain_type *apex,
	const dname_type *dname)
{
	unsigned char hash[SHA_DIGEST_LENGTH];
	char b32[HASHED_NAME_LENGTH+1];

	/* need to detect from apex NSEC3 RRset */
	const unsigned char* nsec3_salt = NULL;
	int nsec3_saltlength = 0;
	int nsec3_iterations = 0;

	iterated_hash(hash, nsec3_salt, nsec3_saltlength, dname_name(dname),
		dname->name_size, nsec3_iterations);
	b32_ntop(hash, sizeof(hash), b32, sizeof(b32));
	dname=dname_parse(region, b32);
	dname=dname_concatenate(region, dname, domain_dname(apex));
	return dname;
}

#endif /* NSEC3 */
