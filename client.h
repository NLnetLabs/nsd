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
#define DEFAULT_CONTROL_PORT	853

/* the following commands are understood by NSD */
enum control_msg {
	CONTROL_UNKNOWN,
	CONTROL_STATUS,
	CONTROL_VERSION
};

#endif /* _CLIENT_H_ */
