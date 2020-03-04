/*
 * nametree.h -- adaptive radix tree optimized for domain name data
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#ifndef _NAMETREE_H_
#define _NAMETREE_H_

#include <stdint.h>

#include "dname.h"
#include "region-allocator.h"

/* Adaptive Radix Tree (ART) structures cannot store prefixes of other keys.
 * Therefore the tree cannot be used to store domain name data by default. The
 * recommended solution is to terminate every key with a value that does not
 * occur anywhere else in the set. However, domain names consist of labels of
 * octets and each octet can have any value between 0x00 and 0xff. Domain
 * names must therefore be transformed before they can serve as keys. The fact
 * that comparisons between character strings must be done in a
 * case-insensitive manner (RFC 1035 section 2.3.3) is used to avoid
 * multi-byte encoding schemes. Uppercase letters are converted to lowercase
 * letters and 0x01 is added to any octet with a value less* than 0x41. 0x00
 * can then be used to terminate keys and separate labels, preserving
 * canonical name order (RFC 4034 secion 6.1). 0x19 is subtracted from every
 * octet with a value greater than 0x90 so that nodes require less space. The
 * fact that paths to domain names under each cut pass through a single node
 * is also a useful property for concurrent access scenarios and improves
 * lookup speeds.
 *
 * Transformations:
 *  - Order of labels is reversed to maintain hierarchy.
 *  - Uppercase letters are converted to lowercase letters.
 *  - 0x01 is added to octets with values less than 0x41.
 *  - Length octets are converted to 0x00 to preserve order.
 *     Eliminates the need to keep pointers to adjacent domain names.
 *  - 0x19 is subtracted from octets with values greater than 0x90.
 *  - Key is null-terminated so that it is never a prefix for subsequent keys.
 *     0 (zero) serves as an index in inner nodes as well.
 *
 * Examples (numbers are bytes, letters are ascii):
 *  - root:        dname: "0",             key: "0"
 *  - fOo.:        dname: "3fOo0",         key: "MVV00"
 *  - bAr.foo:     dname: "3bAr3foo0",     key: "MVV0IHY00"
 *  - a.bar.fOo:   dname: "1a3bar3fOo0",   key: "MVV0IHY0H00"
 *  - ab.bAr.foo:  dname: "2ab3bAr3foo0",  key: "MVV0IHY0HI00"
 *  - b.bar.fOo:   dname: "1b3bar3fOo0",   key: "MVV0IHY0I00"
 */
#define NAMETREE_MAX_HEIGHT (255) /* Domain names are limited to 255 octets */

/* The nametree is not a general-purpose ART implementation, it can only be
 * used to store domain name data.
 */

typedef uint8_t namekey[NAMETREE_MAX_HEIGHT];

uint8_t nametree_make_key(namekey key, const struct dname *dname);

#define NAMENODE4 (0)
#define NAMENODE16 (1)
#define NAMENODE32 (2)
#define NAMENODE38 (3)
#define NAMENODE48 (4)
#define NAMENODE256 (5)

/* Octets can have any value between 0 and 255, but uppercase letters are
 * converted to lowercase for lookup and 0 is reserved as a terminator, hence
 * the maximum width after conversion is 230.
 */
#define NAMETREE_MAX_WIDTH (230)

/* Whitepaper prescribes a prefix length of 10 octets, but domain names have a
 * a maximum length of 255 octets. Therefore the unsigned 32-bit integer used
 * to store the length can be replaced by an unsigned 8-bit integer. By
 * lowering the maximum length of a prefix (disregarding optimistic path
 * compression) to 9, the header size is lowered by 4 bytes.
 */
#define NAMETREE_MAX_PREFIX (9)

struct namenode {
  uint8_t type;
  uint8_t width;
  uint8_t prefix_len; /* Domain names are limited to 255 octets */
  uint8_t prefix[NAMETREE_MAX_PREFIX];
};

/* document that the domain and zone types themselves are the leafs */
typedef void nameleaf;

struct namenode4 {
  struct namenode base;
  uint8_t keys[4];
  struct namenode *children[4];
};

struct namenode16 {
  struct namenode base;
  uint8_t keys[16];
  struct namenode *children[16];
};

/* FIXME: verify node32 is warranted */
struct namenode32 {
  struct namenode base;
  uint8_t keys[32];
  struct namenode *children[32];
};

/* FIXME: verify node38 is warranted */
struct namenode38 {
  struct namenode base;
  struct namenode *children[38];
};

struct namenode48 {
  struct namenode base;
  uint8_t keys[NAMETREE_MAX_WIDTH];
  struct namenode *children[48];
};

struct namenode256 {
  struct namenode base;
  struct namenode *children[NAMETREE_MAX_WIDTH];
};

/* Domain names are limited to 255 octets, the worst-case maximum height of a
 * path is therefore 255 levels. This limitation can be used to record the
 * entire path leading up to a leaf, which can be used to iterate a zone in
 * canonical name order without keeping parent pointers in child nodes and
 * allows fast resolving of enclosing nodes by traveling up the path. Apart
 * from that it can also be used to enable quick insertion of zone data as
 * paths in adaptive radix trees are fixed and can thus be reused. This
 * property may also be beneficial for concurrent access scenarios in the
 * future. e.g. in read-copy-update scenarios.
 *
 * Nodes are guaranteed to store child nodes in cononical name order. The path
 * stores node-references, i.e. the address where the pointer to a child is
 * kept. This ensures that the tree can be iterated in-order without the need
 * for a key.
 */
struct namepath {
  uint8_t height;
  struct {
    uint8_t depth;
    /** Location of pointer to node */
    struct namenode **noderef;
  } levels[NAMETREE_MAX_HEIGHT];
};

struct nametree {
  struct namenode *root;
  /** Region for allocation */
  struct region *region;
  /** Function to extract dname from leaf (domain or zone) */
  const struct dname *(*leaf_name)(const nameleaf *);
};

// mention that we use pointer tagging
inline int
nametree_is_leaf(const struct namenode *node)
{
  return ((uintptr_t)node & 1);
}

inline struct namenode *
nametree_tag_leaf(const nameleaf *leaf)
{
  return ((struct namenode *)((uintptr_t)leaf | 1u));
}

inline nameleaf *
nametree_untag_leaf(const struct namenode *node)
{
  return ((nameleaf *)((uintptr_t)node & ~1u));
}

inline const struct dname *
nametree_leaf_name(const struct nametree *tree, const struct namenode *leaf)
{
  return tree->leaf_name(nametree_untag_leaf(leaf));
}

const struct dname *
nametree_domain_name(const nameleaf *leaf)
__attribute__((nonnull));

const struct dname *
nametree_zone_name(const nameleaf *leaf)
__attribute__((nonnull));

/**
 * @brief Create a nametree for storing domains or zones
 *
 * @param[in]  region     Region to use when allocating nodes
 * @param[in]  leaf_name  Function to use for extracting dname from a leaf
 */
struct nametree *
nametree_create(
  struct region *region,
  const struct dname *(*leaf_name)(const nameleaf *));

/* FIXME: implement nametree_destroy */

/** Return closest previous node if no node with the given key exists */
#define NAMETREE_PREVIOUS (-1)
/** Return closest next node if no node with the given key exists */
#define NAMETREE_NEXT (1)

/**
 * @brief Search tree for leaf matching key
 *
 * @param[in]      tree     Tree to search for leaf
 * @param[in,out]  path     ..
 * @param[in]      key      ..
 * @param[in]      key_len  ..
 * @param[in]      name     ..
 * @param[in]      flags    Specify 0 to record maximum path up to leaf
 *                          (default), NAMETREE_PREVIOUS or NAMETREE_NEXT to
 *                          record the path to the corresponding closest leaf
 *                          if the actual leaf does not exist
 *
 * @returns Leaf (without tag) or NULL if no such leaf exists
 */
nameleaf *
nametree_search(
  const struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const struct dname *name,
  int32_t flags)
__attribute__((nonnull(1,2,3,5)));

/**
 * @brief Return previous node in tree (canonical name order)
 *
 * Lookup previous node in tree and update path to point to the leaf that is
 * returned.
 *
 * @param[in]      tree  ..
 * @param[in,out]  path  ..
 *
 * @returns Leaf (without tag) or NULL if no previous leaf exists
 */
nameleaf *
nametree_previous_leaf(
  const struct nametree *tree,
  struct namepath *path)
__attribute__((nonnull));

/**
 * @brief Return next node in tree (canonical name order)
 *
 * Lookup next node in tree and update path to point to the leaf that is
 * returned.
 *
 * @param[in]      tree  ..
 * @param[in,out]  path  ..
 *
 * @returns Leaf (without tag) or NULL if no next leaf exists
 */
nameleaf *
nametree_next_leaf(
  const struct nametree *tree,
  struct namepath *path)
__attribute__((nonnull));

/**
 * @brief Insert leaf in location specified by key
 *
 * @param[in]      tree     ..
 * @param[in,out]  path     ..
 * @param[in]      key      ..
 * @param[in]      key_len  ..
 * @param[in]      leaf     Domain or zone (pre-determined) to insert
 *
 * @returns Pointer to existing leaf (without tag) if key was already
 *          associated with a value, leaf (without tag) if operation was
 *          successful or NULL an error occurred
 */
nameleaf *
nametree_insert(
  struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const nameleaf *leaf)
__attribute__((nonnull(1,2,3,5)));

/**
 * @brief Delete leaf matching key from tree
 *
 * @param[in]      tree    Tree to delete leaf from
 * @param[in,out]  path    ..
 * @param[in]      key     ..
 * @param[in]      length  ..
 * @param[in]      dname   ..
 *
 * @returns Leaf (without tag) or NULL if no such exists
 */
nameleaf *
nametree_delete(
  struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const struct dname *dname)
__attribute__((nonnull(1,2,3,5)));

#endif /* _NAMETREE_H_ */
