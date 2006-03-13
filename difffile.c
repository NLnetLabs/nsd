/*
 * difffile.x - DIFF file handling source code. Read and write diff files.
 *
 * Copyright (c) 2001-2006, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include <config.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "difffile.h"

#define DIFFFILE "nsd.diff"

void diff_write_packet(uint8_t* data, size_t len, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	uint32_t val;
	if(opt->difffile) filename = opt->difffile;

	df = fopen(filename, "a");
	if(!df) {
		log_msg(LOG_ERR, "could not open file %s for append: %s",
			filename, strerror(errno));
		return;
	}

	write_data(df, "IXFR", sizeof(uint32_t));
	val = htonl(len);
	write_data(df, &val, sizeof(val));
	write_data(df, data, len);
	write_data(df, &val, sizeof(val));
	
	fclose(df);
}

int db_crc_different(namedb_type* db)
{
	FILE *fd = fopen(db->filename, "r");
	uint32_t crc_file;
	char buf[NAMEDB_MAGIC_SIZE];
	if(fd == NULL) {
		log_msg(LOG_ERR, "unable to load %s: %s",
			db->filename, strerror(errno));
		return -1;
	}
	
	/* seek to position of CRC, check it and magic no */
	if(fsetpos(fd, &db->crc_pos)==-1) {
		log_msg(LOG_ERR, "unable to fsetpos %s: %s. db changed?",
			db->filename, strerror(errno));
		fclose(fd);
		return -1;
	}

	if(fread(&crc_file, sizeof(crc_file), 1, fd) != 1) {
		log_msg(LOG_ERR, "could not read %s CRC. db changed?", db->filename);
		fclose(fd);
		return -1;
	}
	crc_file = ntohl(crc_file);

	if(fread(buf, sizeof(char), sizeof(buf), fd) != sizeof(buf)
	   || memcmp(buf, NAMEDB_MAGIC, NAMEDB_MAGIC_SIZE) != 0) {
		log_msg(LOG_ERR, "could not read %s magic. db changed?", db->filename);
		fclose(fd);
		return -1;
	}

	fclose(fd);

	if(db->crc == crc_file)
		return 0;
	return 1;
}

int diff_read_file(namedb_type* db, nsd_options_t* opt)
{
	const char* filename = DIFFFILE;
	FILE *df;
	if(opt->difffile) filename = opt->difffile;

	df = fopen(filename, "r");
	if(!df) {
		log_msg(LOG_INFO, "could not open file %s for reading: %s",
			filename, strerror(errno));
		return 1;
	}
	if(db->diff_skip) {
		if(fsetpos(df, &db->diff_pos)==-1) {
			log_msg(LOG_INFO, "could not fsetpos file %s: %s. Reread from start.",
				filename, strerror(errno));
		}
	}
	
	fclose(df);
	return 1;
}
