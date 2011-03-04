/*
 * pktc.h -- packet compiler definitions.
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#ifndef PKTC_H
#define PKTC_H
#include "answer.h"
struct radtree;
struct radnode;
struct cpkt;
struct zone;
struct domain_table;
struct domain;
struct region;
struct rr;

/**
 * Tree with compiled packets
 */
struct comptree {
	/** radix tree by name to a struct compname */
	struct radtree* nametree;
	/** tree of zones, for every zone an nsec3 tree, to compzone */
	struct radtree* zonetree;
};

/**
 * Compiled info for a zone
 * There are pointers to this structure for nsec3 content (NXDOMAINs),
 * from the compname structure.
 */
struct compzone {
	/** radix node for this element */
	struct radnode* rnode;
	/** zone name */
	uint8_t* name;
	/** the tree of nsec3 hashes to compnsec3, for this zone */
	struct radtree* nsec3tree;
	/** nsec3 parameters for hashing */
	/* todo */
	/** soa serial number to insert into negative answers, network order,
	 * negative compiled packets have pointers to this value. */
	uint32_t serial;
};

/**
 * Compiled packets for an NSEC3-hash.
 */
struct compnsec3 {
	/** radix node for this element */
	struct radnode* rnode;
	/** the nxdomain packet for this hash span */
	struct cpkt* nx;
};

#define BELOW_NORMAL 0 /* below is a cpkt */
#define BELOW_NSEC3NX 1 /* below is compzone, do nsec3 hashed nxdomain */
#define BELOW_WILDCARD 2 /* below is compname, do wildcard processing */
#define BELOW_SYNTHC 3 /* below is cpkt with DNAME. perform CNAME synth */

/**
 * Compiled packets for a domain name.
 * irrespective of zone.
 */
struct compname {
	/** radix node for this element */
	struct radnode* rnode;
	/** length of specifics array */
	size_t typelen;
	/** specifics array, by qtype, to compiled packets for this qtype.
	 * includes TYPE_ANY, TYPE_RRSIG, ...  The array is sorted by qtype.
	 * also contains separate DS-denial if parent-zone, or referral-here.
	 * or DS-positive if secure-referral here. */
	struct cpkt** types;
	/** no type match, have name match, packet, to nodata or referral */
	struct cpkt* notype;
	/** match below the name, qname is below this name, to nxdomain,
	 * dname or referral packet.
	 * For nsec3 need to go hash at compzone, for wildcard special todo */
	struct cpkt* below;
	/** side match, the qname is after this name, for NSEC nxdomains.
	 * side is NULL if the closest-encloser below is (wildcard,nsec3nx). */
	struct cpkt* side;
	/** length of the wirefmt of this name, to calculate the prefix of
	 * the qname for nsec3 hashing and wildcards */
	uint8_t namelen;
	/** type of the below pointer.
	 *  BELOW_NORMAL use it, unless you have a side-match
	 *      set for referrals, and for nsec, nsec3 zones.
	 *      for the zone apex the below has the NSEC for first NSEC,
	 *      and the lower side ptrs have the other NSECs for nxdomain.
	 *  BELOW_NSEC3NX ptr to compzone, do nsec3 hashing for nxdomain. 
	 *  BELOW_WILDCARD ptr to the *.x name below this.
	 *  BELOW_SYNTHC  ptr to cpkt with DNAME, perform CNAME synthesis.
	 */
	uint8_t belowtype;
};

/**
 * precompiled packet, the answer to a given name, type, class.
 * It needs to be adjusted for
 * 	o the qname
 * 	o the EDNS-OPT record.
 * 	o length (TC).
 * 	o flags RD, CD.
 * 	o serial number (in nodata, nxdomain).
 * Allocated in packed format in the order.
 * 	cpktstruct, truncpkts_u16, ptrs_u16, pktdata_u8
 */
struct cpkt {
	/** ptr to soa serial number to use, in network format (or NULL) */
	uint32_t* serial;
	/** packet data (often allocated behind this struct),
	 * contains answer,authority,additional section octets. */
	uint8_t* data;
	/** array of truncation points: length, arcount,
	 * goes down, first one is the whole packet. */
	uint16_t* truncpts;
	/** array of compression ptrs to adjust in the packet, offset in data.
	 * ends with a 0.  They point to host-order u16 offset values. */
	uint16_t* ptrs;
	/** qtype of the packet, 0 for nxdomains, referrals */
	uint16_t qtype;
	/** length of the packet data */
	uint16_t datalen;
	/** flagcode, the u16 with flags, rcode, opcode for the result,
	 * needs to have RD,CD flags copied from query */
	uint16_t flagcode;
	/** the answer count. */
	uint16_t ancount;
	/** the authority count. Note flagcode, ancount, nscount are
	 * consecutive so a memcpy can do them at once */
	uint16_t nscount;
	/** truncation points, and the additional count that goes with it,
	 * if none fit, set TC flag on answer.
	 * number of truncation points. */
	uint16_t numtrunc;
	/** soa serial location in packet data (or 0 if none) */
	uint16_t serial_pos;
};

/** create comp tree, empty,
 * @return the new commptree. */
struct comptree* comptree_create(void);

/** delete comptree, frees all contents. */
void comptree_delete(struct comptree* ct);

/** create comp zone, add to tree,
 * @param ct: comptree to add it into.
 * @param zname: zone name, dname.
 * @return compzone object that has been added. */
struct compzone* compzone_create(struct comptree* ct, uint8_t* zname);

/** delete compzone, frees all contents. does not edit the zonetree. */
void compzone_delete(struct compzone* cz);

/** find a compzone by name, NULL if not found */
struct compzone* compzone_search(struct comptree* ct, uint8_t* name);

/** find a compzone by name, also returns closest-encloser if not found */
struct compzone* compzone_find(struct comptree* ct, uint8_t* name, int* ce);

/** add a new name to the nametree.
 * @param ct: comptree to add it into.
 * @param name: name, dname to add.
 * @return compname object that has been added. */
struct compname* compname_create(struct comptree* ct, uint8_t* name);

/** delete compname, frees all contents. does not edit the nametree. */
void compname_delete(struct compname* cn);

/** find a compname by name, NULL if not found */
struct compname* compname_search(struct comptree* ct, uint8_t* name);

/** delete compnsec3, frees contents, does not edit tree */
void compnsec3_delete(struct compnsec3* c3);

/** packer compiling input, the answer to compile */
struct answer_info {
	/** qname, or ce */
	uint8_t* qname;
	/** qtype or 0 */
	uint16_t qtype;
	/** can this answer compressptrs be adjusted after compilation */
	int adjust;
	/** flags and rcode */
	uint16_t flagcode;
	/** rrsets in sections */
	struct answer answer;
	/** temp region during answer compilation (for wildcards in the
	 * additional and so on) */
	struct region* region;
};

/** precompile environment */
struct prec_env {
	/** the compile tree */
	struct comptree* ct;
	/** the compile zone */
	struct compzone* cz;
	/** the compiled name */ 
	struct compname* cn;

	/** the domain table */
	struct domain_table* table;
	/** the  */

	/** the current answer under development */
	struct answer_info ai;
	
};

/** create a compiled packet structure, encode from RR data.
 * creates compression pointers.
 * @param qname: the qname for this packet.
 * @param qtype: qtype or 0.
 * @param adjust: if true, a compression pointer adjustment list is created.
 * 	set this to true for NXDOMAINs, DNAME, referrals, wildcard.
 * @param flagcode: flagcode to set on packet
 * @param num_an: number an rrs.
 * @param num_ns: number ns rrs.
 * @param num_ar: number ar rrs.
 * @param rrname: array of pointers to RR name
 * @param rrinfo: array of RR data elements.
 * @param cz: compiled zone for soa serial.
 * @return compiled packet, allocated.
 */
struct cpkt* compile_packet(uint8_t* qname, uint16_t qtype, int adjust,
	uint16_t flagcode, uint16_t num_an, uint16_t num_ns, uint16_t num_ar,
	uint8_t** rrname, struct rr** rrinfo, struct compzone* cz);

/** delete a compiled packet structure, frees its contents */
void cpkt_delete(struct cpkt* cp);

/** compare two cpkts and return if -, 0, + for sort order by qtype */
int cpkt_compare_qtype(const void* a, const void* b);

/** determine packets to compile, based on zonelist and nametree to lookup.
 * @param ct: the compiled packet tree that is filled up.
 * @param zonelist: list of zones.
 * @param table: namelookup structure.
 */
void compile_zones(struct comptree* ct, struct zone* zonelist,
	struct domain_table* table);

/** add a zone and determine packets to compile for this zone.
 * @param ct: compiled packet tree that is filled up.
 * @param cz: compiled zone structure for the zone.
 * @param zone: the zone.
 * @param table: namelookup structure.
 */
void compile_zone(struct comptree* ct, struct compzone* cz, struct zone* zone,
	struct domain_table* table);

/** compile the packets for one name in one zone. It may or may not add
 * the compiled-name to the tree (not for occluded items, glue).
 * @param ct: compiled packet tree.
 * @param cz: the zone to compile the name for.
 * @param zone: the zone
 * @param table: the namelookup structure.
 * @param domain: the named domain in the namelookup structure.
 */
void compile_name(struct comptree* ct, struct compzone* cz, struct zone* zone,
	struct domain_table* table, struct domain* domain);

enum domain_type_enum {
	dtype_normal, /* a normal domain name */
	dtype_notexist, /* notexist, nsec3, glue, occluded */
	dtype_delegation, /* not apex, has type NS */
	dtype_cname, /* has CNAME */
	dtype_dname /* has DNAME */
};

/** determine the type of the domain */
enum domain_type_enum determine_domain_type(struct domain* domain,
        struct zone* zone, int* apex);

#endif /* PKTC_H */
