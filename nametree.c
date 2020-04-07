/*
 * nametree.c -- adaptive radix tree optimized for domain name data
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"

#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#if defined(__i386__) || defined(__x86_64__)
# include <cpuid.h> /* detect if SSE2 and AVX2 extensions are available */
# include <immintrin.h> /* Intel SSE2 and AVX2 intrinsics */
#elif defined(__arm__)
# include <arm_neon.h> /* ARM NEON intrinsics */
#endif

#include "nametree.h"
#include "namedb.h"

static int have_simd128 = -1;
static int have_simd256 = -1;

static inline uint8_t min(uint8_t a, uint8_t b)
{
  return a > b ? b : a;
}

#if defined(__i386__) || defined(__x86_64__)
static void cpuid(int32_t func, int32_t info[4]){
  __cpuid_count(func, 0, info[0], info[1], info[2], info[3]);
}

static void detect_simd(void)
{
  if (have_simd128 == -1) {
    int32_t nids, info[4];

    cpuid(0, info);
    nids = info[0];

    if (nids >= 1) {
      cpuid(1, info);
      have_simd128 = info[3] & (1<<26); /* SSE2 */
    }
    if (nids >= 7) {
      cpuid(7, info);
      have_simd256 = info[1] & (1<<5); /* AVX2 */
    }
  }
}

static inline uint8_t
findeq_16u8_simd(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
  __m128i cmp;
  uint16_t mask;

  cmp = _mm_cmpeq_epi8(_mm_set1_epi8(chr), _mm_loadu_si128((__m128i*)vec));
  mask = _mm_movemask_epi8(cmp) & (cnt < 16u ? (1u<<cnt) - 1u : UINT16_MAX);
  return mask ? __builtin_ctz(mask) + 1 : 0;
}

static inline uint8_t
findgt_16u8_simd(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
  __m128i cmp;
  uint16_t mask;

  cmp = _mm_cmpgt_epi8(_mm_loadu_si128((__m128i*)vec), _mm_set1_epi8(chr));
  mask = _mm_movemask_epi8(cmp) & (cnt < 16u ? (1u<<cnt) - 1u : UINT16_MAX);
  return mask ? __builtin_ctz(mask) + 1 : 0;
}

static inline uint8_t
findeq_32u8_simd(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
  __m256i cmp;
  uint32_t mask;

  cmp = _mm256_cmpeq_epi8(
    _mm256_set1_epi8(chr), _mm256_loadu_si256((__m256i*)vec));
  mask = _mm256_movemask_epi8(cmp) & (cnt < 32u ? (1u<<cnt) - 1u : UINT32_MAX);
  return mask ? __builtin_ctz(mask) + 1 : 0;
}

static uint8_t
findgt_32u8_simd(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
  __m256i cmp;
  uint32_t mask;

  cmp = _mm256_cmpgt_epi8(
    _mm256_set1_epi8(chr), _mm256_loadu_si256((__m256i*)vec));
  mask = _mm256_movemask_epi8(cmp) & (cnt < 32u ? (1u<<cnt) - 1u : UINT32_MAX);
  return mask ? __builtin_ctz(mask) + 1 : 0;
}
#endif

static inline uint8_t
findeq_16u8_non_simd(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
  cnt = min(cnt, 16);
  for (uint8_t idx = 0; idx < cnt; idx++) {
    if (vec[idx] >= chr) {
      return vec[idx] == chr ? idx + 1 : 0;
    }
  }
  return 0;
}

static inline uint8_t
findgt_16u8_non_simd(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
  cnt = min(cnt, 16);
  for (uint8_t idx = 0; idx < cnt; idx++) {
    if (vec[idx] > chr) {
      return idx + 1;
    }
  }
  return 0;
}

static inline uint8_t
findeq_16u8(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
#if defined(__i386__) || defined(__x86_64__)
  if (have_simd128 == 1) {
    return findeq_16u8_simd(vec, chr, cnt);
  }
#endif
  return findeq_16u8_non_simd(vec, chr, cnt);
}

static inline uint8_t
findgt_16u8(const uint8_t vec[16], uint8_t chr, uint8_t cnt)
{
#if defined(__i386__) || defined(__x86_64__)
  if (have_simd128 == 1) {
    return findgt_16u8_simd(vec, chr, cnt);
  }
#endif
  return findgt_16u8_non_simd(vec, chr, cnt);
}

static inline uint8_t
findeq_32u8_non_simd(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
  uint8_t idx;

  if ((idx = findeq_16u8(vec, chr, min(cnt, 16))) != 0) {
    return idx;
  } else if (cnt > 16 && (idx = findeq_16u8(vec+16, chr, cnt-16)) != 0) {
    return idx+16;
  }
  return 0;
}

static inline uint8_t
findgt_32u8_non_simd(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
  uint8_t idx;

  return (idx = findgt_16u8(vec, chr, min(cnt, 16))) ? idx :
         (cnt > 16 && (idx = findgt_16u8(vec+16, chr, cnt-16))) ? idx + 16 : 0;
}

static uint8_t
findeq_32u8(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
#if defined(__i386__) || defined(__x86_64__)
  if (have_simd256 == 1) {
    return findeq_32u8_simd(vec, chr, cnt);
  }
#endif
  return findeq_32u8_non_simd(vec, chr, cnt);
}

static inline uint8_t
findgt_32u8(const uint8_t vec[32], uint8_t chr, uint8_t cnt)
{
#if defined(__i386__) || defined(__x86_64__)
  if (have_simd256 == 1) {
    return findgt_32u8_simd(vec, chr, cnt);
  }
#endif
  return findgt_32u8_non_simd(vec, chr, cnt);
}

extern inline int
nametree_is_leaf(const struct namenode *);

extern inline struct namenode *
nametree_tag_leaf(const nameleaf *);

extern inline nameleaf *
nametree_untag_leaf(const struct namenode *);

extern inline const struct dname *
nametree_leaf_name(const struct nametree *tree, const struct namenode *leaf);

static inline uint8_t xlat(uint8_t chr)
{
  if (chr < 0x41u) {
    return chr + 0x01u;
  } else if (chr < 0x5bu) {
    return chr + 0x07u;
  }
  return chr - 0x19u;
}

/* translate key to node38 index */
static inline uint8_t node38_xlat(uint8_t key)
{
  if (key >= 0x48u && key <= 0x61u) { /* "a..z" */
    return key - 0x3cu;
  } else if (key >= 0x31u && key <= 0x3au) { /* "0..9" */
    return key - 0x2fu;
  } else if (key == 0x2eu) { /* "-" */
    return 0x01u;
  } else if (key == 0x00u) {
    return 0x00u;
  }

  return (uint8_t)-1;
}

/* translate key to greater node38 index */
static inline uint8_t node38_xlatgt(uint8_t key)
{
  if (key < 0x2eu) { /* < "-" */
    return 0x01u;
  } else if (key < 0x31u) { /* < "0" */
    return 0x02u;
  } else if (key < 0x3au) { /* < "9" */
    return (key - 0x2fu) + 1;
  } else if (key < 0x48u) { /* < "a" */
    return 0x0cu;
  } else if (key < 0x61u) { /* < "z" */
    return (key - 0x3cu) + 1;
  }

  return (uint8_t)-1;
}

/* translate key to lesser node38 index */
static inline uint8_t node38_xlatlt(uint8_t key)
{
  if (key > 0x61u) { /* > "z" */
    return 0x25u;
  } else if (key > 0x48u) { /* > "a" */
    return (key - 0x3cu) - 1;
  } else if (key > 0x3au) { /* > "9" */
    return 0x0bu;
  } else if (key > 0x31u) { /* > "0" */
    return (key - 0x2fu) - 1;
  } else if (key > 0x2eu) { /* > "-" */
    return 0x01u;
  } else if (key > 0x00u) { /* > "\0" */
    return 0x00u;
  }

  return (uint8_t)-1;
}

/* translate node38 index to key */
static inline uint8_t node38_unxlat(uint8_t key)
{
  if (key >= 0x0cu && key <= 0x25u) { /* "a..z" */
    return key + 0x3cu;
  } else if (key >= 0x02u && key <= 0x0bu) { /* "0..9" */
    return key + 0x2fu;
  } else if (key == 0x01u) { /* "-" */
    return 0x2eu;
  } else if (key == 0x00u) {
    return 0x00u;
  }

  return (uint8_t)-1;
}

uint8_t nametree_make_key(namekey key, const struct dname *dname)
{
  size_t cnt = 0, len = 1;
  const uint8_t *label;
  uint8_t labno, labcnt, lablen;

  assert(key != NULL);
  assert(dname != NULL);

  for (labno = 1; labno < dname->label_count; labno++) {
    label = dname_label(dname, labno);
    if (label[0] & 0xc0u) {
      return 0;
    }
    lablen = label[0] + 1;
    if ((len += lablen) > 0xffu) {
      return 0;
    }
    for (labcnt = 1; labcnt < lablen; labcnt++) {
      key[cnt++] = xlat(label[labcnt]);
    }
    key[cnt++] = 0x00u;
  }
  key[cnt++] = 0x00u;

  return cnt;
}

static inline size_t sizeof_node(uint8_t type)
{
  switch (type) {
    case NAMENODE4:
      return sizeof(struct namenode4);
    case NAMENODE16:
      return sizeof(struct namenode16);
    case NAMENODE32:
      return sizeof(struct namenode32);
    case NAMENODE38:
      return sizeof(struct namenode38);
    case NAMENODE48:
      return sizeof(struct namenode48);
    case NAMENODE256:
      return sizeof(struct namenode256);
    default:
      abort();
  }
}

static void *alloc_node(struct nametree *tree, uint8_t type)
{
  size_t size;
  struct namenode *node;

  assert(tree != NULL);

  size = sizeof_node(type);
  node = region_alloc_zero(tree->region, size);
  node->type = type;

  return node;
}

static void free_node(struct nametree *tree, struct namenode *node)
{
  size_t size;

  assert(tree != NULL);

  size = sizeof_node(((struct namenode *)node)->type);
  region_recycle(tree->region, node, size);
}

static void copy_header(struct namenode *dest, struct namenode *src)
{
  dest->width = src->width;
  dest->prefix_len = src->prefix_len;
  memcpy(dest->prefix, src->prefix, min(src->prefix_len, NAMETREE_MAX_PREFIX));
}

static inline struct namenode **
find_child256(const struct namenode256 *node, uint8_t key)
{
  assert(key < NAMETREE_MAX_WIDTH);
  return node->children[key] != NULL
    ? (struct namenode **)&node->children[key] : NULL;
}

static inline struct namenode **
find_child48(const struct namenode48 *node, uint8_t key)
{
  assert(key < NAMETREE_MAX_WIDTH);
  return node->keys[key] != 0
    ? (struct namenode **)&node->children[node->keys[key] - 1] : NULL;
}

static inline struct namenode **
find_child38(const struct namenode38 *node, uint8_t key)
{
  uint8_t idx = node38_xlat(key);
  return idx != (uint8_t)-1 && node->children[idx]
    ? (struct namenode **)&node->children[idx] : NULL;
}

static inline struct namenode **
find_child32(const struct namenode32 *node, uint8_t key)
{
  uint8_t idx = findeq_32u8(node->keys, key, node->base.width);
  return idx != 0
    ? (struct namenode **)&node->children[idx - 1] : NULL;
}

static inline struct namenode **
find_child16(const struct namenode16 *node, uint8_t key)
{
  uint8_t idx = findeq_16u8(node->keys, key, node->base.width);
  return idx != 0
    ? (struct namenode **)&node->children[idx - 1] : NULL;
}

static inline struct namenode **
find_child4(const struct namenode4 *node, uint8_t key)
{
  for (uint8_t idx = 0; idx < node->base.width; idx++) {
    if (node->keys[idx] >= key) {
      return node->keys[idx] == key
        ? (struct namenode **)&node->children[idx] : NULL;
    }
  }
  return NULL;
}

static struct namenode **
find_child(const struct namenode *node, uint8_t key)
{
  assert(node != NULL);
  switch (node->type) {
    case NAMENODE4:
      return find_child4((const struct namenode4 *)node, key);
    case NAMENODE16:
      return find_child16((const struct namenode16 *)node, key);
    case NAMENODE32:
      return find_child32((const struct namenode32 *)node, key);
    case NAMENODE38:
      return find_child38((const struct namenode38 *)node, key);
    case NAMENODE48:
      return find_child48((const struct namenode48 *)node, key);
    case NAMENODE256:
      return find_child256((const struct namenode256 *)node, key);
    default:
      break;
  }

  abort();
}

static inline struct namenode **
next_child256(const struct namenode256 *node, uint8_t key)
{
  if (key < NAMETREE_MAX_WIDTH) {
    for (uint8_t idx = key + 1; idx < NAMETREE_MAX_WIDTH; idx++) {
      if (node->children[idx] != NULL) {
        return (struct namenode **)&node->children[idx];
      }
    }
  }
  return NULL;
}

static inline struct namenode **
next_child48(const struct namenode48 *node, uint8_t key)
{
  if (key < NAMETREE_MAX_WIDTH && node->keys[key] != node->base.width) {
    for (uint8_t idx = key + 1; idx < NAMETREE_MAX_WIDTH; idx++) {
      if (node->keys[idx] != 0) {
        return (struct namenode **)&node->children[node->keys[idx] - 1];
      }
    }
  }
  return NULL;
}

static inline struct namenode **
next_child38(const struct namenode38 *node, uint8_t key)
{
  uint8_t idx = node38_xlatgt(key);
  if (idx != (uint8_t)-1) {
    for (; idx < 38; idx++) {
      if (node->children[idx] != NULL) {
        return (struct namenode **)&node->children[idx];
      }
    }
  }
  return NULL;
}

static inline struct namenode **
next_child32(const struct namenode32 *node, uint8_t key)
{
  uint8_t idx = findgt_32u8(node->keys, key, node->base.width);
  return idx != 0 ? (struct namenode **)&node->children[idx - 1] : NULL;
}

static inline struct namenode **
next_child16(const struct namenode16 *node, uint8_t key)
{
  uint8_t idx = findgt_16u8(node->keys, key, node->base.width);
  return idx != 0 ? (struct namenode **)&node->children[idx - 1] : NULL;
}

static inline struct namenode **
next_child4(const struct namenode4 *node, uint8_t key)
{
  if (key < (NAMETREE_MAX_WIDTH - 1)) {
    for (uint8_t idx = 0; idx < node->base.width; idx++) {
      if (node->keys[idx] > key) {
        assert(node->keys[idx] < NAMETREE_MAX_WIDTH);
        return (struct namenode **)&node->children[idx];
      }
    }
  }
  return NULL;
}

static struct namenode **
next_child(const struct namenode *node, uint8_t key)
{
  switch (node->type) {
    case NAMENODE4:
      return next_child4((const struct namenode4 *)node, key);
    case NAMENODE16:
      return next_child16((const struct namenode16 *)node, key);
    case NAMENODE32:
      return next_child32((const struct namenode32 *)node, key);
    case NAMENODE38:
      return next_child38((const struct namenode38 *)node, key);
    case NAMENODE48:
      return next_child48((const struct namenode48 *)node, key);
    case NAMENODE256:
      return next_child256((const struct namenode256 *)node, key);
    default:
      break;
  }
  abort();
}

static inline struct namenode **
previous_child256(const struct namenode256 *node, uint8_t key)
{
  if (key > 0) {
    for (int32_t idx = (int32_t)key - 1; idx >= 0; idx--) {
      if (node->children[idx] != NULL) {
        return (struct namenode **)&node->children[idx];
      }
    }
  }
  return NULL;
}

static inline struct namenode **
previous_child48(const struct namenode48 *node, uint8_t key)
{
  if (key > 0) {
    for (int32_t idx = (int32_t)key - 1; idx >= 0; idx--) {
      if (node->keys[idx] != 0) {
        return (struct namenode **)&node->children[node->keys[idx] - 1];
      }
    }
  }
  return NULL;
}

static inline struct namenode **
previous_child38(const struct namenode38 *node, uint8_t key)
{
  uint8_t idx = node38_xlatlt(key);
  if (idx != (uint8_t)-1) {
    for (; idx > 0; idx--) {
      if (node->children[idx] != NULL) {
        return (struct namenode **)&node->children[idx];
      }
    }
    if (node->children[idx] != NULL) {
      return (struct namenode **)&node->children[idx];
    }
  }
  return NULL;
}

static inline struct namenode **
previous_child32(const struct namenode32 *node, uint8_t key)
{
  int32_t idx = (int32_t)findgt_32u8(node->keys, key, node->base.width);
  if (idx == 0) {
    idx = node->base.width;
  } else if (--idx == 0) {
    return NULL;
  }

  idx -= (node->keys[idx - 1] == key ? 2 : 1);
  return idx >= 0 ? (struct namenode **)&node->children[idx] : NULL;
}

static inline struct namenode **
previous_child16(const struct namenode16 *node, uint8_t key)
{
  int32_t idx = (int32_t)findgt_16u8(node->keys, key, node->base.width);
  if (idx == 0) {
    idx = node->base.width;
  } else if (--idx == 0) {
    return NULL;
  }

  idx -= (node->keys[idx - 1] == key ? 2 : 1);
  return idx >= 0 ? (struct namenode **)&node->children[idx] : NULL;
}

static inline struct namenode **
previous_child4(const struct namenode4 *node, uint8_t key)
{
  assert(node->base.width != 0);
  if (key > node->keys[0]) {
    int32_t idx;
    for (idx = 1; idx < node->base.width; idx++) {
      if (node->keys[idx] > key) {
        idx -= (node->keys[idx - 1] == key ? 2 : 1);
        return idx >= 0 ? (struct namenode **)&node->children[idx] : NULL;
      }
    }
    idx = node->base.width - (node->keys[node->base.width - 1] == key ? 2 : 1);
    return idx >= 0 ? (struct namenode **)&node->children[idx] : NULL;
  }
  return NULL;
}

static struct namenode **
previous_child(const struct namenode *node, uint8_t key)
{
  assert(key < NAMETREE_MAX_WIDTH);
  switch (node->type) {
    case NAMENODE4:
      return previous_child4((const struct namenode4 *)node, key);
    case NAMENODE16:
      return previous_child16((const struct namenode16 *)node, key);
    case NAMENODE32:
      return previous_child32((const struct namenode32 *)node, key);
    case NAMENODE38:
      return previous_child38((const struct namenode38 *)node, key);
    case NAMENODE48:
      return previous_child48((const struct namenode48 *)node, key);
    case NAMENODE256:
      return previous_child256((const struct namenode256 *)node, key);
    default:
      break;
  }
  abort();
}

static struct namenode **
previous_node(struct namenode *node, struct namenode **noderef)
{
  size_t idx;
  struct namenode **nodes;

  assert(node != NULL);
  assert(noderef != NULL);
  assert(!nametree_is_leaf(node));

  switch (node->type) {
    case NAMENODE4:
      nodes = ((struct namenode4 *)node)->children;
      break;
    case NAMENODE16:
      nodes = ((struct namenode16 *)node)->children;
      break;
    case NAMENODE32:
      nodes = ((struct namenode32 *)node)->children;
      break;
    case NAMENODE38:
      nodes = ((struct namenode38 *)node)->children;
      break;
    case NAMENODE48:
      nodes = ((struct namenode48 *)node)->children;
      break;
    case NAMENODE256:
      nodes = ((struct namenode256 *)node)->children;
      break;
    default:
      abort();
  }

  idx = ((uintptr_t)noderef - (uintptr_t)nodes) / sizeof(*nodes);
  assert(idx < UINT8_MAX);

  while (idx > 0) {
    if (nodes[--idx] != NULL) {
      return &nodes[idx];
    }
  }
  return NULL;
}

static struct namenode **
next_node(struct namenode *node, struct namenode **noderef)
{
  size_t idx;
  struct namenode **nodes;

  assert(node != NULL);
  assert(noderef != NULL);
  assert(!nametree_is_leaf(node));

  switch (node->type) {
    case NAMENODE4:
      nodes = ((struct namenode4 *)node)->children;
      break;
    case NAMENODE16:
      nodes = ((struct namenode16 *)node)->children;
      break;
    case NAMENODE32:
      nodes = ((struct namenode32 *)node)->children;
      break;
    case NAMENODE38:
      nodes = ((struct namenode38 *)node)->children;
      break;
    case NAMENODE48:
      nodes = ((struct namenode48 *)node)->children;
      break;
    case NAMENODE256:
      nodes = ((struct namenode256 *)node)->children;
      break;
    default:
      abort();
  }

  idx = ((uintptr_t)noderef - (uintptr_t)nodes) / sizeof(*nodes);
  assert(idx < UINT8_MAX);

  while (idx < node->width) {
    if (nodes[++idx] != NULL) {
      return &nodes[idx];
    }
  }
  return NULL;
}

static struct namenode **
find_leaf(const struct namenode *node)
{
  struct namenode **noderef = NULL;

  assert(!nametree_is_leaf(node));

  do {
    switch (node->type) {
      case NAMENODE4:
        noderef = &((struct namenode4*)node)->children[0];
        break;
      case NAMENODE16:
        noderef = &((struct namenode16*)node)->children[0];
        break;
      case NAMENODE32:
        noderef = &((struct namenode32*)node)->children[0];
        break;
      case NAMENODE38:
        for (uint8_t idx = 0; idx < 38; idx++) {
          if (((struct namenode38*)node)->children[idx] != NULL) {
            noderef = &((struct namenode38*)node)->children[idx];
            break;
          }
        }
        break;
      case NAMENODE48:
        noderef = &((struct namenode48 *)node)->children[0];
        break;
      case NAMENODE256:
        for (uint8_t idx = 0; idx < NAMETREE_MAX_WIDTH; idx++) {
          if (((struct namenode256*)node)->children[idx] != NULL) {
            noderef = &((struct namenode256*)node)->children[idx];
            break;
          }
        }
        break;
      default:
        abort();
    }
    assert(!(*noderef == NULL || *noderef == node));
    node = *noderef;
  } while (!nametree_is_leaf(node));

  assert(noderef != NULL);
  return noderef;
}

static nameleaf *
minimum_leaf(const struct nametree *tree, struct namepath *path)
{
  struct namenode *node, **noderef;

  (void)tree;
  node = *path->levels[path->height - 1].noderef;

  while (!nametree_is_leaf(node)) {
    switch (node->type) {
      case NAMENODE4:
        noderef = &((struct namenode4 *)node)->children[0];
        break;
      case NAMENODE16:
        noderef = &((struct namenode16 *)node)->children[0];
        break;
      case NAMENODE32:
        noderef = &((struct namenode32 *)node)->children[0];
        break;
      case NAMENODE38:
        for (uint8_t idx = 0; idx < 38; idx++) {
          if (((struct namenode38 *)node)->children[idx] != NULL) {
            noderef = &((struct namenode38 *)node)->children[idx];
            break;
          }
        }
        break;
      case NAMENODE48:
        noderef = &((struct namenode48 *)node)->children[0];
        break;
      case NAMENODE256:
        for (uint8_t idx = 0; idx < NAMETREE_MAX_WIDTH; idx++) {
          if (((struct namenode256 *)node)->children[idx] != NULL) {
            noderef = &((struct namenode256 *)node)->children[idx];
            break;
          }
        }
        break;
    }

    assert(!(*noderef == NULL || *noderef == node));

    path->levels[path->height].depth =
      path->levels[path->height - 1].depth + node->prefix_len + 1;
    path->levels[path->height].noderef = noderef;
    path->height++;

    node = *noderef;
  }

  assert(nametree_is_leaf(node));
  return nametree_untag_leaf(node);
}

static nameleaf *
maximum_leaf(const struct nametree *tree, struct namepath *path)
{
  struct namenode *node, **noderef;

  (void)tree;
  node = *path->levels[path->height - 1].noderef;

  while (!nametree_is_leaf(node)) {
    switch (node->type) {
      case NAMENODE4:
        noderef = &((struct namenode4 *)node)->children[node->width - 1];
        break;
      case NAMENODE16:
        noderef = &((struct namenode16 *)node)->children[node->width - 1];
        break;
      case NAMENODE32:
        noderef = &((struct namenode32 *)node)->children[node->width - 1];
        break;
      case NAMENODE38:
        for (uint8_t idx = node->width - 1; idx < 38; idx++) {
          if (((struct namenode38 *)node)->children[idx] != NULL) {
            noderef = &((struct namenode38 *)node)->children[idx];
            break;
          }
        }
        break;
      case NAMENODE48:
        noderef = &((struct namenode48 *)node)->children[node->width - 1];
        break;
      case NAMENODE256:
        for (uint8_t idx = node->width - 1; idx < NAMETREE_MAX_WIDTH; idx++) {
          if (((struct namenode256 *)node)->children[idx] != NULL) {
            noderef = &((struct namenode256 *)node)->children[idx];
            break;
          }
        }
        break;
    }

    assert(!(*noderef == NULL || *noderef == node));

    path->levels[path->height].depth =
      path->levels[path->height - 1].depth + node->prefix_len + 1;
    path->levels[path->height].noderef = noderef;
    path->height++;

    node = *noderef;
  }

  assert(nametree_is_leaf(node));
  return nametree_untag_leaf(node);
}

static nameleaf *
previous_leaf(const struct nametree *tree, struct namepath *path)
{
  struct namenode **noderef;

  while (path->height > 1) {
    noderef = previous_node(*path->levels[path->height - 2].noderef,
                             path->levels[path->height - 1].noderef);
    if (noderef != NULL) {
      path->levels[path->height - 1].noderef = noderef;
      return maximum_leaf(tree, path);
    } else {
      path->height--;
    }
  }

  path->height = 0;
  return NULL;
}

static nameleaf *
next_leaf(const struct nametree *tree, struct namepath *path)
{
  struct namenode **noderef;

  while (path->height > 1) {
    noderef = next_node(*path->levels[path->height - 2].noderef,
                         path->levels[path->height - 1].noderef);
    if (noderef != NULL) {
      path->levels[path->height - 1].noderef = noderef;
      return minimum_leaf(tree, path);
    } else {
      path->height--;
    }
  }

  path->height = 0;
  return NULL;
}

nameleaf *
nametree_previous_leaf(const struct nametree *tree, struct namepath *path)
{
  assert(tree != NULL);
  assert(path != NULL);

  if (tree->root == NULL) {
    path->height = 0;
    return NULL;
  } else if (path->height == 0) {
    path->height = 1;
    path->levels[0].depth = 0;
    path->levels[0].noderef = (struct namenode **)&tree->root;
    return maximum_leaf(tree, path);
  }

  assert(path->levels[0].depth == 0);
  assert(path->levels[0].noderef == &tree->root);
  return previous_leaf(tree, path);
}

nameleaf *
nametree_next_leaf(const struct nametree *tree, struct namepath *path)
{
  assert(tree != NULL);
  assert(path != NULL);

  if (tree->root == NULL) {
    path->height = 0;
    return NULL;
  } else if (path->height == 0) {
    path->height = 1;
    path->levels[0].depth = 0;
    path->levels[0].noderef = (struct namenode **)&tree->root;
    return minimum_leaf(tree, path);
  }

  assert(path->levels[0].depth == 0);
  assert(path->levels[0].noderef == &tree->root);
  return next_leaf(tree, path);
}

static inline int
match_node(
  const struct nametree *tree,
  const struct namenode *node,
  const namekey key,
  uint8_t key_len,
  uint8_t depth)
{
  if (node->prefix_len > NAMETREE_MAX_PREFIX) {
    /* slow path (optimistic path compression) */
    struct namenode **noderef;
    namekey buf;
    uint8_t len;

    noderef = find_leaf(node);
    len = nametree_make_key(buf, nametree_leaf_name(tree, *noderef));
    assert(len >= depth);
    return memcmp(
      key + depth, buf + depth, min((key_len-1) - depth, node->prefix_len));
  } else {
    /* fast path */
    return memcmp(
      key + depth, node->prefix, min((key_len-1) - depth, node->prefix_len));
  }
}

nameleaf *
nametree_search(
  const struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const struct dname *name,
  int32_t flags)
{
  int cmp;
  uint8_t depth;
  struct namenode *node, **noderef;

  if (tree->root == NULL) {
    path->height = 0;
    return NULL;
  } else if (path->height == 0) {
    path->levels[0].depth = 0;
    path->levels[0].noderef = (struct namenode **)&tree->root;
    path->height++;
  }

  assert(path->levels[0].depth == 0);
  assert(path->levels[0].noderef == &tree->root);
  noderef = path->levels[path->height - 1].noderef;
  depth = path->levels[path->height - 1].depth;
  assert(depth < key_len);

  for (node = *noderef; depth < key_len; node = *noderef) {
    if (nametree_is_leaf(node)) {
      cmp = dname_compare(name, nametree_leaf_name(tree, node));
      if (cmp == 0) {
        break;
      } else {
        if (cmp < 0 && flags < 0) {
          previous_leaf(tree, path);
        } else if (cmp > 0 && flags > 0) {
          next_leaf(tree, path);
        } else if (flags == 0) {
          path->height--;
        }
        return NULL;
      }
    } else if (node->prefix_len != 0) {
      cmp = match_node(tree, node, key, key_len, depth);
      if (cmp == 0) {
        depth += node->prefix_len;
      } else {
        if (flags < 0) {
          cmp > 0 ? maximum_leaf(tree, path) : previous_leaf(tree, path);
        } else if (flags > 0) {
          cmp < 0 ? minimum_leaf(tree, path) : next_leaf(tree, path);
        } else {
          path->height--;
        }
        return NULL;
      }
    }

    if ((noderef = find_child(node, key[depth])) == NULL) {
      if (flags != 0) {
        if (flags < 0) {
          noderef = previous_child(node, key[depth]);
        } else {
          noderef = next_child(node, key[depth]);
        }
        if (noderef != NULL) {
          path->levels[path->height].depth = ++depth;
          path->levels[path->height].noderef = noderef;
          path->height++;
          flags < 0 ? maximum_leaf(tree, path) : minimum_leaf(tree, path);
        } else {
          flags < 0 ? previous_leaf(tree, path) : next_leaf(tree, path);
        }
      }
      return NULL;
    }

    path->levels[path->height].depth = ++depth;
    path->levels[path->height].noderef = noderef;
    path->height++;
  }

  return nametree_untag_leaf(node);
}

static inline struct namenode **
add_child256(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  const struct namenode *child)
{
  struct namenode256 *node256 = (struct namenode256 *)*noderef;

  (void)tree;
  assert(node256->base.type == NAMENODE256);
  assert(node256->children[key] == NULL);

  node256->base.width++;
  node256->children[key] = (struct namenode *)child;
  return &node256->children[key];
}

static inline struct namenode **
add_child48(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  const struct namenode *child)
{
  uint8_t cnt, idx;
  struct namenode48 *node48 = (struct namenode48 *)*noderef;

  assert(node48->base.type == NAMENODE48);
  assert(node48->keys[key] == 0);

  if (node48->base.width == 48) {
    struct namenode256 *node256;

    if ((node256 = alloc_node(tree, NAMENODE256)) == NULL) {
      return NULL;
    }
    copy_header((struct namenode *)node256, (struct namenode *)node48);
    for (uint8_t idx = 0, cnt = 0; idx < NAMETREE_MAX_WIDTH; idx++) {
      if (node48->keys[idx] != 0) {
        node256->children[idx] = node48->children[node48->keys[idx] - 1];
        if (++cnt == node48->base.width) {
          break;
        }
      }
    }

    *noderef = (struct namenode *)node256;
    free_node(tree, (struct namenode *)node48);
    return add_child256(tree, noderef, key, child);
  }

  assert(node48->base.width < 48);
  /* nametree sorts nodes of type NAMENODE48 to ensure the tree can be
   * iterated with previous/next without a key */
  if (key < NAMETREE_MAX_WIDTH) {
    for (cnt = key; cnt < NAMETREE_MAX_WIDTH && !node48->keys[cnt]; cnt++) ;

    if (cnt == NAMETREE_MAX_WIDTH) {
      idx = node48->base.width;
    } else {
      idx = node48->keys[cnt] - 1;
      assert(idx < node48->base.width);
      memmove(&node48->children[idx + 1],
              &node48->children[idx],
              sizeof(struct namenode *) * (node48->base.width - idx));
      for (; cnt < NAMETREE_MAX_WIDTH; cnt++) {
        if (node48->keys[cnt] != 0) {
          node48->keys[cnt]++;
          if (node48->keys[cnt] > node48->base.width) {
            break;
          }
        }
      }
    }
  }

  node48->base.width++;
  node48->keys[key] = idx + 1;
  node48->children[idx] = (struct namenode *)child;
  return &node48->children[idx];
}

static inline struct namenode **
add_child38(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  const struct namenode *child)
{
  uint8_t idx;
  struct namenode38 *node38 = (struct namenode38 *)*noderef;

  assert(node38 != NULL);
  assert(node38->base.type == NAMENODE38);

  if ((idx = node38_xlat(key)) == (uint8_t)-1) {
    uint8_t cnt;
    struct namenode48 *node48;

    if ((node48 = alloc_node(tree, NAMENODE48)) == NULL) {
      return NULL;
    }
    copy_header((struct namenode *)node48, (struct namenode *)node38);
    for (idx = 0, cnt = 0; idx < 38; idx++) {
      if (node38->children[idx] != NULL) {
        node48->children[cnt++] = node38->children[idx];
        node48->keys[ node38_unxlat(idx) ] = cnt;
        if (cnt == node38->base.width) {
          break;
        }
      }
    }

    assert(cnt == node38->base.width);
    *noderef = (struct namenode *)node48;
    free_node(tree, (struct namenode *)node38);
    return add_child48(tree, noderef, key, child);
  }

  assert(node38->base.width < 38);
  assert(node38->children[idx] == NULL);
  node38->children[idx] = (struct namenode *)child;
  node38->base.width++;
  return &node38->children[idx];
}

static inline struct namenode **
add_child32(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  const struct namenode *child)
{
  uint8_t idx;
  struct namenode32 *node32 = (struct namenode32 *)*noderef;

  if (node32->base.width == 32) {
    int ishost = node38_xlat(key) != (uint8_t)-1;

    /* determine if node consists of all hostname keys */
    for (idx = 0; ishost && idx < 32; idx++) {
      uint8_t key = node32->keys[idx];
      ishost = node38_xlat(key) != (uint8_t)-1;
    }
    if (ishost) {
      struct namenode38 *node38;

      if ((node38 = alloc_node(tree, NAMENODE38)) == NULL) {
        return NULL;
      }
      copy_header((struct namenode *)node38, (struct namenode *)node32);
      for (idx = 0; idx < 32; idx++) {
        node38->children[ node38_xlat(node32->keys[idx]) ]
          = node32->children[idx];
      }
      *noderef = (struct namenode *)node38;
      free_node(tree, (struct namenode *)node32);
      return add_child38(tree, noderef, key, child);
    } else {
      uint8_t cnt;
      struct namenode48 *node48;

      if ((node48 = alloc_node(tree, NAMENODE48)) == NULL) {
        return NULL;
      }
      copy_header((struct namenode *)node48, (struct namenode *)node32);
      for (idx = 0, cnt = 0; idx < 32; idx++) {
        node48->children[cnt++] = node32->children[idx];
        node48->keys[ node32->keys[idx] ] = cnt;
      }
      *noderef = (struct namenode *)node48;
      free_node(tree, (struct namenode *)node32);
      return add_child48(tree, noderef, key, child);
    }
  }

  assert(node32->base.width < 32);
  if ((idx = findgt_32u8(node32->keys, key, node32->base.width)) != 0) {
    idx--;
    assert(idx < node32->base.width);
    memmove(&node32->keys[idx + 1],
            &node32->keys[idx],
            sizeof(uint8_t) * (node32->base.width - idx));
    memmove(&node32->children[idx + 1],
            &node32->children[idx],
            sizeof(struct namenode *) * (node32->base.width - idx));
  } else {
    idx = node32->base.width;
  }

  node32->keys[idx] = key;
  node32->children[idx] = (struct namenode *)child;
  node32->base.width++;
  return &node32->children[idx];
}

static inline struct namenode **
add_child16(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  const struct namenode *child)
{
  uint16_t idx;
  struct namenode16 *node16 = (struct namenode16 *)*noderef;

  assert(node16->base.type == NAMENODE16);

  if (node16->base.width == 16) {
    struct namenode32 *node32;

    if ((node32 = alloc_node(tree, NAMENODE32)) == NULL) {
      return NULL;
    }
    copy_header((struct namenode *)node32, (struct namenode *)node16);
    memcpy(node32->keys, node16->keys, 16*sizeof(uint8_t));
    memcpy(node32->children, node16->children, 16*sizeof(struct namenode *));
    *noderef = (struct namenode *)node32;
    free_node(tree, (struct namenode *)node16);
    return add_child32(tree, noderef, key, child);
  }

  assert(node16->base.width < 16);
  if ((idx = findgt_16u8(node16->keys, key, node16->base.width)) != 0) {
    idx--;
    assert(idx <= node16->base.width);
    memmove(&node16->keys[idx + 1],
            &node16->keys[idx],
            sizeof(uint8_t) * (node16->base.width - idx));
    memmove(&node16->children[idx + 1],
            &node16->children[idx],
            sizeof(struct namenode *) * (node16->base.width - idx));
  } else {
    idx = node16->base.width;
  }

  node16->keys[idx] = key;
  node16->children[idx] = (struct namenode *)child;
  node16->base.width++;
  return &node16->children[idx];
}

static inline struct namenode **
add_child4(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  struct namenode *child)
{
  uint8_t idx;
  struct namenode4 *node4 = (struct namenode4 *)*noderef;

  if (node4->base.width == 4) {
    struct namenode16 *node16;

    if ((node16 = alloc_node(tree, NAMENODE16)) == NULL) {
      return NULL;
    }
    copy_header((struct namenode *)node16, (struct namenode *)node4);
    memcpy(node16->keys, node4->keys, 4*sizeof(uint8_t));
    memcpy(node16->children, node4->children, 4*sizeof(struct namenode *));
    *noderef = (struct namenode *)node16;
    free_node(tree, (struct namenode *)node4);
    return add_child16(tree, noderef, key, child);
  }

  assert(node4->base.width < 4);

  for (idx = 0; idx < node4->base.width && key > node4->keys[idx]; idx++) { }

  if (idx < node4->base.width) {
    assert(key != node4->keys[idx]);
    memmove(&node4->keys[idx + 1],
            &node4->keys[idx],
            sizeof(uint8_t) * (node4->base.width - idx));
    memmove(&node4->children[idx + 1],
            &node4->children[idx],
            sizeof(struct namenode *) * (node4->base.width - idx));
  }

  node4->keys[idx] = key;
  node4->children[idx] = child;
  node4->base.width++;
  return &node4->children[idx];
}

static inline struct namenode **
add_child(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  struct namenode *child)
{
  assert(noderef != NULL);
  switch ((*noderef)->type) {
    case NAMENODE4:
      return add_child4(tree, noderef, key, child);
    case NAMENODE16:
      return add_child16(tree, noderef, key, child);
    case NAMENODE32:
      return add_child32(tree, noderef, key, child);
    case NAMENODE38:
      return add_child38(tree, noderef, key, child);
    case NAMENODE48:
      return add_child48(tree, noderef, key, child);
    case NAMENODE256:
      return add_child256(tree, noderef, key, child);
    default:
      break;
  }

  abort();
}

static inline uint8_t
compare_keys(
  const uint8_t *left,
  const uint8_t *right,
  uint8_t len)
{
  uint8_t cnt = 0;

  while (cnt < len && left[cnt] == right[cnt]) cnt++;

  return cnt;
}

static inline int32_t
split_leaf(
  struct nametree *tree,
  struct namenode **noderef,
  const namekey key,
  uint8_t key_len,
  const struct dname *name,
  uint8_t depth)
{
  int32_t cmp;
  struct namenode *node = *noderef;

  cmp = dname_compare(name, nametree_leaf_name(tree, node));
  if (cmp != 0) {
    /* mismatch, split leaf */
    namekey buf;
    uint8_t cnt, len;
    struct namenode *child = node;

    if ((node = alloc_node(tree, NAMENODE4)) == NULL) {
      return -1;
    }
    /* fill prefix */
    len = nametree_make_key(buf, nametree_leaf_name(tree, child));
    assert(len >= depth);
    cnt = compare_keys(
      key + depth, buf + depth, min(key_len - 1, len - 1) - depth);
    node->prefix_len = cnt;
    memcpy(node->prefix, buf + depth, min(cnt, NAMETREE_MAX_PREFIX));
    /* update edges */
    add_child(tree, &node, buf[depth + cnt], child);
    *noderef = node;
    return 1;
  }

  return 0;
}

/* match_node cannot be used because a leaf must be resolved twice if
 * optimistic path compression is used and the prefix does not match */
static inline int32_t
split_node(
  struct nametree *tree,
  struct namenode **noderef,
  const namekey key,
  uint8_t key_len,
  const struct dname *name,
  uint8_t depth)
{
  int32_t cmp;
  struct namenode *node = *noderef;

  (void)name;

  if (node->prefix_len > NAMETREE_MAX_PREFIX) {
    /* slow path (optimistic path compression) */
    struct namenode **leafref;
    namekey buf;
    uint8_t len;

    leafref = find_leaf(node);
    len = nametree_make_key(buf, nametree_leaf_name(tree, *leafref));
    assert(len > depth);
    cmp = memcmp(
      key + depth, buf + depth, min((key_len-1) - depth, node->prefix_len));
    if (cmp != 0) {
      /* mismatch, split node */
      uint8_t cnt;
      struct namenode *child = *noderef;

      if ((node = alloc_node(tree, NAMENODE4)) == NULL) {
        return -1;
      }
      /* fill prefix */
      /* leafs can match beyond the prefix. i.e. a tree can contain "y1.z."
       * and "y2.z." nodes. when "x.y1.z." is inserted, the leaf "y1.z." is
       * used to create a temporary key and the number of matched characters
       * is greater than the current prefix */
      cnt = compare_keys(
        key + depth, buf + depth, min((key_len-1) - depth, child->prefix_len));
      node->prefix_len = cnt;
      memcpy(node->prefix, buf + depth, min(cnt, NAMETREE_MAX_PREFIX));
      /* update edge */
      add_child(tree, &node, buf[depth + cnt], child);
      /* adjust prefix */
      child->prefix_len -= cnt + 1;
      if (child->prefix_len != 0) {
        memcpy(child->prefix,
               buf + (depth + cnt + 1),
               min(child->prefix_len, NAMETREE_MAX_PREFIX));
      }
      *noderef = node;
      return 1;
    }
  } else {
    /* fast path */
    cmp = memcmp(
      key + depth, node->prefix, min((key_len-1) - depth, node->prefix_len));
    if (cmp != 0) {
      /* mismatch, split node */
      uint8_t cnt;
      struct namenode *child = *noderef;

      if ((node = alloc_node(tree, NAMENODE4)) == NULL) {
        return -1;
      }
      /* fill prefix */
      cnt = compare_keys(
        key + depth, child->prefix, min((key_len-1) - depth, child->prefix_len));
      node->prefix_len = cnt;
      memcpy(node->prefix, child->prefix, min(cnt, NAMETREE_MAX_PREFIX));
      /* update edge */
      add_child(tree, &node, child->prefix[cnt], child);
      /* adjust prefix */
      child->prefix_len -= cnt + 1;
      if (child->prefix_len != 0) {
        memmove(child->prefix,
                child->prefix + (cnt + 1),
                child->prefix_len);
      }
      *noderef = node;
      return 1;
    }
  }

  return 0;
}

nameleaf *
nametree_insert(
  struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const nameleaf *leaf)
{
  uint8_t depth;
  int32_t split;
  const struct dname *name;
  struct namenode *node, **noderef = NULL, **childref;

  if (path->height == 0) {
    path->levels[0].depth = 0;
    path->levels[0].noderef = &tree->root;
    path->height++;
  }

  if (tree->root == NULL) {
    tree->root = nametree_tag_leaf(leaf);
    return (nameleaf *)leaf;
  }

  assert(path->levels[0].depth == 0);
  assert(path->levels[0].noderef == &tree->root);
  depth = path->levels[path->height - 1].depth;
  noderef = path->levels[path->height - 1].noderef;
  assert(depth < key_len);

  name = nametree_leaf_name(tree, leaf);
  for (node = *noderef; depth < key_len; node = *noderef) {
    if (nametree_is_leaf(node)) {
      split = split_leaf(tree, noderef, key, key_len, name, depth);
      if (split == -1) {
        path->height--;
        return NULL;
      } else if (split == 1) {
        /* leaf cannot exist, short-circuit */
        depth += (*noderef)->prefix_len;
        goto add_leaf;
      }
      break;
    } else if (node->prefix_len != 0) {
      split = split_node(tree, noderef, key, key_len, name, depth);
      if (split == -1) {
        return NULL;
      } else if (split == 1) {
        /* leaf cannot exist if prefix did not match, short-circuit */
        depth += (*noderef)->prefix_len;
        goto add_leaf;
      }

      depth += node->prefix_len;
    }

    childref = find_child(node, key[depth]);
    if (childref != NULL) {
      noderef = childref;
      path->levels[path->height].depth = ++depth;
      path->levels[path->height].noderef = noderef;
      path->height++;
    } else {
add_leaf:
      node = nametree_tag_leaf(leaf);
      childref = add_child(tree, noderef, key[depth], node);
      if (childref == NULL) {
        return NULL;
      }
      path->levels[path->height].depth = key_len;
      path->levels[path->height].noderef = childref;
      path->height++;
      break;
    }
  }

  assert(nametree_is_leaf(node));
  return nametree_untag_leaf(node);
}

static inline void
merge_child(
  struct nametree *tree,
  struct namenode **noderef,
  uint8_t key,
  struct namenode *child)
{
  struct namenode *node = *noderef;

  if (!nametree_is_leaf(child)) {
    /* concatenate prefixes */
    if (node->prefix_len < NAMETREE_MAX_PREFIX) {
      node->prefix[node->prefix_len] = key;
    }
    node->prefix_len++;
    if (node->prefix_len < NAMETREE_MAX_PREFIX) {
      memcpy(node->prefix + node->prefix_len,
             child->prefix,
             min(child->prefix_len, NAMETREE_MAX_PREFIX - node->prefix_len));
    }
    node->prefix_len += child->prefix_len;
    memcpy(child->prefix,
           node->prefix,
           min(node->prefix_len, NAMETREE_MAX_PREFIX));
    child->prefix_len = node->prefix_len;
  }

  free_node(tree, node);
  *noderef = child;
}

static inline void
remove_child256(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx;
  struct namenode256 *node256 = (struct namenode256 *)*noderef;

  assert(node256->children[key] != NULL);
  node256->children[key] = NULL;
  node256->base.width--;

  if (node256->base.width == 1) {
    for (idx = 0; idx < NAMETREE_MAX_WIDTH && node256->children[idx] == NULL; idx++) ;
    merge_child(tree, noderef, idx, node256->children[idx]);
  } else if (node256->base.width < 45) {
    uint8_t cnt;
    struct namenode48 *node48;
    if ((node48 = alloc_node(tree, NAMENODE48)) != NULL) {
      copy_header((struct namenode *)node48, (struct namenode *)node256);
      for (idx = 0, cnt = 0; idx < NAMETREE_MAX_WIDTH; idx++) {
        if (node256->children[idx] != NULL) {
          node48->children[cnt] = node256->children[idx];
          node48->keys[idx] = ++cnt;
          if (cnt == node256->base.width) {
            break;
          }
        }
      }
      *noderef = (struct namenode *)node48;
      free_node(tree, (struct namenode *)node256);
    }
  }
}

static inline void
remove_child48(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx, cnt;
  struct namenode48 *node48 = (struct namenode48 *)*noderef;

  idx = node48->keys[key];
  assert(idx != 0);
  node48->keys[key] = 0;
  if (idx == node48->base.width) {
    node48->children[idx - 1] = NULL;
  } else {
    memmove(node48->children + (idx - 1),
            node48->children + idx,
            sizeof(struct namenode *) * (node48->base.width - idx));
    for (idx = key + 1; idx < NAMETREE_MAX_WIDTH; idx++) {
      if (node48->keys[idx] != 0 &&
          node48->keys[idx]-- == node48->base.width)
      {
        break;
      }
    }
  }
  node48->base.width--;

  if (node48->base.width == 1) {
    for (idx = 0; idx < NAMETREE_MAX_WIDTH && node48->keys[idx] == 0; idx++) ;
    merge_child(tree, noderef, idx, node48->children[node48->keys[idx]]);
  } else if (node48->base.width < 29) {
    struct namenode32 *node32;

    if ((node32 = alloc_node(tree, NAMENODE32)) != NULL) {
      copy_header((struct namenode *)node32, (struct namenode *)node48);
      for (idx = 0, cnt = 0; idx < NAMETREE_MAX_WIDTH; idx++) {
        if (node48->keys[idx] != 0) {
          node32->keys[cnt] = idx;
          node32->children[cnt] = node48->children[node48->keys[idx] - 1];
          if (++cnt == node48->base.width) {
            break;
          }
        }
      }
      *noderef = (struct namenode *)node32;
      free_node(tree, (struct namenode *)node48);
    }
  } else if (node48->base.width < 35) {
    struct namenode38 *node38;

    for (idx = 0; idx < 38; idx++) {
      if (node48->keys[node38_unxlat(idx)] != 0) {
        if (++cnt == node48->base.width) {
           break;
        }
      }
    }

    if (cnt < node48->base.width) {
      return; /* non-hostname keys exist */
    } else if ((node38 = alloc_node(tree, NAMENODE38)) != NULL) {
      copy_header((struct namenode *)node38, (struct namenode *)node48);
      for (idx = 0, cnt = 0; idx < 38; idx++) {
        key = node38_unxlat(idx);
        if (node48->keys[key] != 0) {
          node38->children[idx] = node48->children[node48->keys[key] - 1];
          if (++cnt == node48->base.width) {
            break;
          }
        }
      }
      *noderef = (struct namenode *)node38;
      free_node(tree, (struct namenode *)node48);
    }
  }
}

static inline void
remove_child38(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx;
  struct namenode38 *node38 = (struct namenode38 *)*noderef;

  idx = node38_xlat(key);
  node38->children[idx] = NULL;
  node38->base.width--;

  if (node38->base.width == 1) {
    for (idx = 0; idx < 38 && node38->children[idx] == NULL; idx++) ;
    merge_child(tree, noderef, node38_unxlat(idx), node38->children[idx]);
  } else if (node38->base.width < 29) {
    uint8_t cnt = 0;
    struct namenode32 *node32;
    if ((node32 = alloc_node(tree, NAMENODE32)) != NULL) {
      copy_header((struct namenode *)node32, (struct namenode *)node38);
      for (idx = 0; idx < 38 && cnt < node38->base.width; idx++) {
        if (node38->children[idx] != NULL) {
          node32->children[cnt] = node38->children[idx];
          node32->keys[cnt] = node38_unxlat(idx);
          cnt++;
        }
      }
      *noderef = (struct namenode *)node32;
      free_node(tree, (struct namenode *)node38);
    }
  }
}

static inline void
remove_child32(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx;
  struct namenode32 *node32 = (struct namenode32 *)*noderef;

  idx = findeq_32u8(node32->keys, key, node32->base.width);
  if (idx < node32->base.width) {
    memmove(node32->keys + (idx - 1),
            node32->keys + idx,
            sizeof(uint8_t) * (node32->base.width - idx));
    memmove(node32->children + (idx - 1),
            node32->children + idx,
            sizeof(struct namenode *) * (node32->base.width - idx));
  }

  node32->base.width--;

  if (node32->base.width == 1) {
    merge_child(tree, noderef, node32->keys[0], node32->children[0]);
  } else if (node32->base.width < 13) {
    struct namenode16 *node16;
    if ((node16 = alloc_node(tree, NAMENODE16)) != NULL) {
      copy_header((struct namenode *)node16, (struct namenode *)node32);
      memcpy(node16->keys,
             node32->keys,
             node32->base.width * sizeof(uint8_t));
      memcpy(node16->children,
             node32->children,
             node32->base.width * sizeof(struct namenode *));
      *noderef = (struct namenode *)node16;
      free_node(tree, (struct namenode *)node32);
    }
  }
}

static inline void
remove_child16(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx;
  struct namenode16 *node16 = (struct namenode16 *)*noderef;

  idx = findeq_16u8(node16->keys, key, node16->base.width);
  if (idx < node16->base.width) {
    memmove(node16->keys + (idx - 1),
            node16->keys + idx,
            sizeof(uint8_t) * (node16->base.width - idx));
    memmove(node16->children + (idx - 1),
            node16->children + idx,
            sizeof(struct namenode *) * (node16->base.width - idx));
  }

  node16->base.width--;

  if (node16->base.width == 1) {
    merge_child(tree, noderef, node16->keys[0], node16->children[0]);
  } else if (node16->base.width < 4) {
    struct namenode4 *node4;
    if ((node4 = alloc_node(tree, NAMENODE4)) != NULL) {
      copy_header((struct namenode *)node4, (struct namenode *)node16);
      memcpy(node4->keys,
             node16->keys,
             node16->base.width * sizeof(uint8_t));
      memcpy(node4->children,
             node16->children,
             node16->base.width * sizeof(struct namenode*));
      *noderef = (struct namenode *)node4;
      free_node(tree, (struct namenode *)node16);
    }
  }
}

static inline void
remove_child4(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  uint8_t idx;
  struct namenode4 *node4 = (struct namenode4 *)*noderef;

  for (idx = 0; idx < node4->base.width && key > node4->keys[idx]; idx++) ;

  assert(node4->keys[idx] == key);

  if ((idx + 1) < node4->base.width) {
    memmove(node4->keys + idx,
            node4->keys + (idx + 1),
            sizeof(uint8_t) * (node4->base.width - (idx + 1)));
    memmove(node4->children + idx,
            node4->children + (idx + 1),
            sizeof(struct namenode *) * (node4->base.width - (idx + 1)));
  }

  node4->base.width--;

  if (node4->base.width == 1) {
    merge_child(tree, noderef, node4->keys[0], node4->children[0]);
  }
}

static void
remove_child(struct nametree *tree, struct namenode **noderef, uint8_t key)
{
  switch ((*noderef)->type) {
    case NAMENODE4:
      return remove_child4(tree, noderef, key);
    case NAMENODE16:
      return remove_child16(tree, noderef, key);
    case NAMENODE32:
      return remove_child32(tree, noderef, key);
    case NAMENODE38:
      return remove_child38(tree, noderef, key);
    case NAMENODE48:
      return remove_child48(tree, noderef, key);
    case NAMENODE256:
      return remove_child256(tree, noderef, key);
    default:
      break;
  }

  abort();
}

nameleaf *
nametree_delete(
  struct nametree *tree,
  struct namepath *path,
  const namekey key,
  uint8_t key_len,
  const struct dname *name)
{
  uint8_t depth;
  int32_t cmp;
  struct namenode *node, **noderef;

  if (tree->root == NULL) {
    path->height = 0;
    return NULL;
  } else if (path->height == 0) {
    path->levels[0].depth = 0;
    path->levels[0].noderef = &tree->root;
    path->height++;
  }

  assert(path->levels[0].depth == 0);
  assert(path->levels[0].noderef == &tree->root);
  depth = path->levels[path->height - 1].depth;
  noderef = path->levels[path->height - 1].noderef;
  assert(depth < key_len);

  for (node = *noderef; depth < key_len; node = *noderef) {
    if (nametree_is_leaf(node)) {
      cmp = dname_compare(name, nametree_leaf_name(tree, node));
      if (cmp == 0) {
        break;
      } else {
        path->height--;
        return NULL;
      }
    } else if (node->prefix_len != 0) {
      cmp = match_node(tree, node, key, key_len, depth);
      if (cmp == 0) {
        depth += node->prefix_len;
      } else {
        path->height--;
        return NULL;
      }
    }

    if ((noderef = find_child(node, key[depth])) == NULL) {
      return NULL;
    }

    path->levels[path->height].depth = ++depth;
    path->levels[path->height].noderef = noderef;
    path->height++;
  }

  assert(path->height > 0);
  assert(nametree_is_leaf(node));

  if (path->height == 1) {
    tree->root = NULL;
    path->height = 0;
  } else {
    depth = path->levels[path->height - 2].depth;
    noderef = path->levels[path->height - 2].noderef;
    /* update height beforehand as nodes may be merged */
    path->height -= 1 + ((*noderef)->width <= 2);
    remove_child(tree, noderef, key[depth]);
  }

  return nametree_untag_leaf(node);
}

struct nametree *
nametree_create(
  struct region *region,
  const struct dname *(*leaf_name)(const nameleaf *))
{
  struct nametree *tree;

  assert(region != NULL);

  detect_simd();
  if ((tree = region_alloc(region, sizeof(*tree))) != NULL) {
    tree->region = region;
    tree->root = NULL;
    tree->leaf_name = leaf_name;
  }

  return tree;
}

//void
//nametree_destroy(struct nametree *tree)
//{
// .. implement ..
//}

const struct dname *
nametree_domain_dname(const nameleaf *leaf)
{
  return domain_dname((struct domain *)leaf);
}

const struct dname *
nametree_zone_dname(const nameleaf *leaf)
{
  return domain_dname(((struct zone *)leaf)->apex);
}
