/*
 * client.h - client (nsdc) code header file
 *
 * Copyright (c) 2001-2005, NLnet Labs, All right reserved
 *
 * See LICENSE for the license
 *
 */

#ifndef _CLIENT_H_
#define _CLIENT_H_

/* the port where NSD listen for control messages */
#define DEFAULT_CONTROL_PORT	"853"
#define DEFAULT_CONTROL_TTL	0
#define DEFAULT_CONTROL_HOST	"localhost"

/* the following commands are understood by NSD */
enum control_msg {
	CONTROL_UNKNOWN,
	CONTROL_STATUS,
	CONTROL_VERSION
};


/* Log a warning message. */
void warning(const char *format, ...) ATTR_FORMAT(printf, 1, 2);

/* Log a error message and exit */
void
error(int exitcode, const char *format, ...);

#endif /* _CLIENT_H_ */
