/*
 * ixfrcreate.h -- generating IXFR differences from zonefiles.
 *
 * Copyright (c) 2021, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef _IXFRCREATE_H_
#define _IXFRCREATE_H_
struct zone;

/* the ixfr create data structure while the ixfr difference from zone files
 * is created. */
struct ixfr_create {
	/* the old serial and new serial */
	uint32_t old_serial, new_serial;
	/* the file with the spooled old zone data */
	char* file_name;
	/* zone name in uncompressed wireformat */
	uint8_t* zone_name;
	/* length of zone name */
	size_t zone_name_len;
};

/* start ixfr creation */
struct ixfr_create* ixfr_create_start(struct zone* zone, char* zfile);

/* free ixfr create */
void ixfr_create_free(struct ixfr_create* ixfrcr);

/* create the IXFR from differences. The old zone is spooled to file
 * and the new zone is in memory now. */
int ixfr_create_perform(struct ixfr_create* ixfrcr, struct zone* zone);

#endif /* _IXFRCREATE_H_ */
