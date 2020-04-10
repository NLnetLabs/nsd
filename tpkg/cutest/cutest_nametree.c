/*
 * cutest_nametree.c -- test nametree.h
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "config.h"
#include "cutest.h"

#include "nametree.c" /* test static functions */

#include <stdio.h>


static struct namenode dummies[49];

static uint8_t order[48] = { /*  0 - 15 */
                             10u, 15u, 11u,  6u,
                              8u,  0u,  3u,  7u,
                              9u, 14u,  2u, 13u,
                              1u,  4u,  5u, 12u,
                             /* 16 - 31 */
                             23u, 20u, 28u, 27u,
                             22u, 21u, 24u, 31u,
                             29u, 17u, 25u, 16u,
                             18u, 30u, 26u, 19u,
                             /* 32 - 47 */
                             47u, 44u, 33u, 39u,
                             34u, 36u, 40u, 32u,
                             43u, 35u, 42u, 38u,
                             45u, 41u, 37u, 46u };

static struct region *region = NULL;

static void setup(CuTest *tc)
{
  detect_simd();
  CuAssertTrue(tc, region == NULL);
  region = region_create(xalloc, free);
  CuAssertTrue(tc, region != NULL);
}

static void teardown(CuTest *tc)
{
  (void)tc;
  region_destroy(region);
  region = NULL;
}

static struct nametree *create_tree(CuTest *tc)
{
  struct nametree *tree;
  tree = nametree_create(region, &nametree_domain_name);
  CuAssertTrue(tc, tree != NULL);
  CuAssertTrue(tc, tree->leaf_name == &nametree_domain_name);
  CuAssertTrue(tc, tree->region == region);
  CuAssertTrue(tc, tree->root == NULL);
  return tree;
}

static struct domain *create_domain(CuTest *tc, const char *name)
{
  struct domain *domain;
  domain = region_alloc_zero(region, sizeof(struct domain));
  CuAssertTrue(tc, domain != NULL);
  domain->dname = dname_parse(region, name);
  CuAssertTrue(tc, domain->dname != NULL);
  return domain;
}

/* have_simd128 and have_simd256 are defined in nametree.c */

static void test_nametree_findeq_16u8(CuTest *tc)
{
  int duplicates = 0;
  int res[3] = { 1, 9, 16 };
  uint8_t vec[16] = { '0', '1', '2', '3',
                      '4', '5', '6', '7',
                      '8', '9', 'a', 'b',
                      'c', 'd', 'e', 'f' };

  setup(tc);

again:
  CuAssert(tc, "findeq_16u8_non_simd: 1st byte",
    findeq_16u8_non_simd(vec, '0', 16) == res[0]);
  CuAssert(tc, "findeq_16u8_non_simd: 8th byte",
    findeq_16u8_non_simd(vec, '8', 16) == res[1]);
  CuAssert(tc, "findeq_16u8_non_simd: 16th byte",
    findeq_16u8_non_simd(vec, 'f', 16) == res[2]);
  CuAssert(tc, "findeq_16u8_non_simd: non-existent byte",
    findeq_16u8_non_simd(vec, 'g', 16) == 0);


#if defined(__i386__) || defined(__x86_64__)
  if (have_simd128) {
    CuAssert(tc, "findeq_16u8_simd: 1st byte",
      findeq_16u8_simd(vec, '0', sizeof(vec)) == res[0]);
    CuAssert(tc, "findeq_16u8_simd: 8th byte",
      findeq_16u8_simd(vec, '8', sizeof(vec)) == res[1]);
    CuAssert(tc, "findeq_16u8_simd: 16th byte",
      findeq_16u8_simd(vec, 'f', sizeof(vec)) == res[2]);
    CuAssert(tc, "findeq_16u8_simd: non-existent byte",
      findeq_16u8_simd(vec, 'g', sizeof(vec)) == 0);
  }
#endif

  if (duplicates == 0) {
    /* duplicate entries */
    vec[res[0] + 1] = vec[res[0]];
    vec[res[1] + 1] = vec[res[1]];
    res[2]--;
    vec[res[2] - 1] = vec[res[2]];
    duplicates = 1;
    goto again;
  }

  CuAssert(tc, "findeq_16u8_non_simd: out-of-bounds vector",
    findeq_16u8_non_simd(vec, '4', 4) == 0);

#if defined(__i386__) || defined(__x86_64__)
  CuAssert(tc, "findeq_16u8_simd: out-of-bounds vector",
    findeq_16u8_simd(vec, '4', 4) == 0);
#endif

  teardown(tc);
}

static void test_nametree_findgt_16u8(CuTest *tc)
{
  uint8_t vec[16] = { 0x01u, 0x02u, 0x03u, 0x04u,
                      0x05u, 0x06u, 0x07u, 0x08u,
                      0x09u, 0x0au, 0x0bu, 0x0cu,
                      0x0du, 0x0eu, 0x0fu, 0x10u };

  setup(tc);

  CuAssert(tc, "findgt_16u8_non_simd: larger than 16th",
    findgt_16u8_non_simd(vec, 0x11u, 16) ==  0);
  CuAssert(tc, "findgt_16u8_non_simd: smaller than 1st",
    findgt_16u8_non_simd(vec, 0x00u, 16) ==  1);
  CuAssert(tc, "findgt_16u8_non_simd: smaller than 9th",
    findgt_16u8_non_simd(vec, 0x08u, 16) ==  9);
  CuAssert(tc, "findgt_16u8_non_simd: smaller than 16th",
    findgt_16u8_non_simd(vec, 0x0fu, 16) == 16);
  CuAssert(tc, "findgt_16u8_non_simd: smaller than 9th, but maximum at 8th",
    findgt_16u8_non_simd(vec, 0x08u,  8) ==  0);

#if defined(__i386__) || defined(__x86_64__)
  if (have_simd128) {
    CuAssert(tc, "findgt_16u8_simd: larger than 16th",
      findgt_16u8_simd(vec, 0x11u, 16) ==  0);
    CuAssert(tc, "findgt_16u8_simd: smaller than 1st",
      findgt_16u8_simd(vec, 0x00u, 16) ==  1);
    CuAssert(tc, "findgt_16u8_simd: smaller than 9th",
      findgt_16u8_simd(vec, 0x08u, 16) ==  9);
    CuAssert(tc, "findgt_16u8_simd: smaller than 16th",
      findgt_16u8_simd(vec, 0x0fu, 16) == 16);
    CuAssert(tc, "findgt_16u8_simd: smaller than 9th, but maximum at 8th",
      findgt_16u8_simd(vec, 0x08u,  8) ==  0);
  }
#endif

  teardown(tc);
}

static void test_nametree_findeq_32u8(CuTest *tc)
{
  static uint8_t vec[32] = { 0x01u, 0x01u, 0x03u, 0x04u,
                             0x05u, 0x06u, 0x07u, 0x08u,
                             0x09u, 0x09u, 0x0bu, 0x0cu,
                             0x0du, 0x0eu, 0x0fu, 0x10u,
                             0x11u, 0x12u, 0x13u, 0x14u,
                             0x15u, 0x16u, 0x17u, 0x18u,
                             0x19u, 0x19u, 0x1bu, 0x1cu,
                             0x1du, 0x1eu, 0x1fu, 0x20u };

  setup(tc);

  CuAssert(tc, "findeq_32u8_non_simd: 1st byte",
    findeq_16u8_non_simd(vec, 0x01u, 32) == 0x01u);
  CuAssert(tc, "findeq_32u8_non_simd: 8th byte",
    findeq_16u8_non_simd(vec, 0x09u, 32) == 0x09u);
  CuAssert(tc, "findeq_32u8_non_simd: 16th byte",
    findeq_16u8_non_simd(vec, 0x10u, 32) == 0x10u);
  CuAssert(tc, "findeq_32u8_non_simd: 17th byte",
    findeq_32u8_non_simd(vec, 0x11u, 32) == 0x11u);
  CuAssert(tc, "findeq_32u8_non_simd: 25th byte",
    findeq_32u8_non_simd(vec, 0x19u, 32) == 0x19u);
  CuAssert(tc, "findeq_32u8_non_simd: 32nd byte",
    findeq_32u8_non_simd(vec, 0x20u, 32) == 0x20u);
  CuAssert(tc, "findeq_32u8_non_simd: non-existent smaller value",
    findeq_32u8_non_simd(vec, 0x00u, 32) == 0x00u);
  CuAssert(tc, "findeq_16u8_non_simd: non-existent greater value",
    findeq_16u8_non_simd(vec, 0x21u, 32) == 0);
  CuAssert(tc, "findeq_16u8_non_simd: existent out-of-bounds value",
    findeq_16u8_non_simd(vec, 0x11u, 16) == 0);

#if defined(__i386__) || defined(__x86_64__)
  if (have_simd256) {
    CuAssert(tc, "findeq_32u8_simd: 1st byte",
      findeq_16u8_simd(vec, 0x01u, 32) == 0x01u);
    CuAssert(tc, "findeq_32u8_simd: 8th byte",
      findeq_16u8_simd(vec, 0x09u, 32) == 0x09u);
    CuAssert(tc, "findeq_32u8_simd: 16th byte",
      findeq_16u8_simd(vec, 0x10u, 32) == 0x10u);
    CuAssert(tc, "findeq_32u8_simd: 17th byte",
      findeq_32u8_simd(vec, 0x11u, 32) == 0x11u);
    CuAssert(tc, "findeq_32u8_simd: 25th byte",
      findeq_32u8_simd(vec, 0x19u, 32) == 0x19u);
    CuAssert(tc, "findeq_32u8_simd: 32nd byte",
      findeq_32u8_simd(vec, 0x20u, 32) == 0x20u);
    CuAssert(tc, "findeq_32u8_simd: non-existent smaller value",
      findeq_32u8_simd(vec, 0x00u, 32) == 0x00u);
    CuAssert(tc, "findeq_16u8_simd: non-existent greater value",
      findeq_16u8_simd(vec, 0x21u, 32) == 0x00u);
    CuAssert(tc, "findeq_16u8_simd: existent out-of-bounds value",
      findeq_16u8_simd(vec, 0x11u, 16) == 0x00u);
  }
#endif

  teardown(tc);
}

static void test_nametree_findgt_32u8(CuTest *tc)
{
  static uint8_t vec[32] = { 0x01u, 0x01u, 0x03u, 0x04u,
                             0x05u, 0x06u, 0x07u, 0x08u,
                             0x09u, 0x09u, 0x0bu, 0x0cu,
                             0x0du, 0x0eu, 0x0fu, 0x10u,
                             0x11u, 0x12u, 0x13u, 0x14u,
                             0x15u, 0x16u, 0x17u, 0x18u,
                             0x19u, 0x19u, 0x1bu, 0x1cu,
                             0x1du, 0x1eu, 0x1fu, 0x20u };

  setup(tc);

  CuAssert(tc, "findgt_32u8_non_simd: larger than 32nd",
    findgt_32u8_non_simd(vec, 0x21u, 32) == 0x00u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 1st",
    findgt_32u8_non_simd(vec, 0x00u, 32) == 0x01u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 9th",
    findgt_32u8_non_simd(vec, 0x08u, 32) == 0x09u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 16th",
    findgt_32u8_non_simd(vec, 0x0fu, 32) == 0x10u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 17th",
    findgt_32u8_non_simd(vec, 0x10u, 32) == 0x11u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 25th",
    findgt_32u8_non_simd(vec, 0x18u, 32) == 0x19u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 32nd",
    findgt_32u8_non_simd(vec, 0x1fu, 32) == 0x20u);
  CuAssert(tc, "findgt_32u8_non_simd: smaller than 17th, but maximum at 16th",
    findgt_32u8_non_simd(vec, 0x11u, 16) == 0x00u);

#if defined(__i386__) || defined(__x86_64__)
  if (have_simd256) {
    CuAssert(tc, "findgt_32u8_non_simd: larger than 32nd",
      findgt_32u8_non_simd(vec, 0x21u, 32) == 0x00u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 1st",
      findgt_32u8_non_simd(vec, 0x00u, 32) == 0x01u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 9th",
      findgt_32u8_non_simd(vec, 0x08u, 32) == 0x09u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 16th",
      findgt_32u8_non_simd(vec, 0x0fu, 32) == 0x10u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 17th",
      findgt_32u8_non_simd(vec, 0x10u, 32) == 0x11u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 25th",
      findgt_32u8_non_simd(vec, 0x18u, 32) == 0x19u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 32nd",
      findgt_32u8_non_simd(vec, 0x1fu, 32) == 0x20u);
    CuAssert(tc, "findgt_32u8_non_simd: smaller than 17th, but maximum at 16th",
      findgt_32u8_non_simd(vec, 0x11u, 16) == 0x00u);
  }
#endif

  teardown(tc);
}

static void test_nametree_find_child4(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode4 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE4);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = find_child4(node, 0x01u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if width is zero */
  node->keys[0] = 0x01u;
  node->children[0] = &dummies[1];
  noderef = find_child4(node, 0x01u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify key is found if width is correct */
  node->base.width++;
  noderef = find_child4(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  /* verify correct ordering of keys is required */
  node->keys[1] = 0x00u;
  node->children[1] = &dummies[0];
  node->base.width++;
  noderef = find_child4(node, 0x00u);
  CuAssertTrue(tc, noderef == NULL);
  /* swap positions, verify both are found */
  node->keys[0] = 0x00u;
  node->children[0] = &dummies[0];
  node->keys[1] = 0x01u;
  node->children[1] = &dummies[1];
  noderef = find_child4(node, 0x00u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = find_child4(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);

  teardown(tc);
}

static void test_nametree_previous_child4(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode4 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE4);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if no previous node exists */
  node->keys[0] = 2u;
  node->children[0] = &dummies[2];
  node->base.width++;
  noderef = previous_child4(node, 2u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct ordering of keys is required */
  node->keys[1] = 0u;
  node->children[1] = &dummies[0];
  node->base.width++;
  noderef = previous_child4(node, 2u);
  CuAssertTrue(tc, noderef == NULL);
  /* swap positions, verify both are found */
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->keys[1] = 2u;
  node->children[1] = &dummies[2];
  noderef = previous_child4(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child4(node, 2u);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = previous_child4(node, 3u);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_next_child4(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode4 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE4);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if no next node exists */
  node->keys[0] = 2u;
  node->children[0] = &dummies[0];
  node->base.width = 1u;
  noderef = next_child4(node, 2u);
  CuAssertTrue(tc, noderef == NULL);
  /* order cannot be verified with next_child4 */
  node->keys[0] = NAMETREE_MAX_WIDTH - 1;
  node->children[0] = &dummies[0];
  node->base.width = 1u;
  noderef = next_child4(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child4(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, *noderef == &dummies[0]);

  teardown(tc);
}

static void test_nametree_find_child16(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode16 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE16);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = find_child16(node, 0x01u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if width is zero */
  node->keys[0] = 1u;
  node->children[0] = &dummies[1];
  noderef = find_child16(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify key is found if width is correct */
  node->base.width++;
  noderef = find_child16(node, 1u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  /* verify correct ordering of keys is required */
  node->keys[1] = 0u;
  node->children[1] = &dummies[0];
  node->base.width++;
  noderef = find_child16(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  /* swap positions, verfiy both are found */
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->keys[1] = 1u;
  node->children[1] = &dummies[1];
  noderef = find_child16(node, 0u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = find_child16(node, 1u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);

  teardown(tc);
}

static void test_nametree_previous_child16(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode16 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE16);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = previous_child16(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child16(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no previous node exists */
  node->keys[0] = 1u;
  node->children[0] = &dummies[1];
  node->base.width = 1;
  noderef = previous_child16(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct ordening is required */
  node->keys[0] = 2u;
  node->children[0] = &dummies[2];
  node->keys[1] = 1u;
  node->children[1] = &dummies[1];
  node->base.width = 2;
  noderef = previous_child16(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->keys[1] = 2u;
  node->children[1] = &dummies[2];
  node->base.width = 2;
  noderef = previous_child16(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child16(node, 1u);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = previous_child16(node, 2u);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = previous_child16(node, 3u);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_next_child16(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode16 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE16);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = next_child16(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child16(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no next node exists */
  node->keys[0] = NAMETREE_MAX_WIDTH - 1;
  node->children[0] = &dummies[0];
  node->base.width = 1;
  noderef = next_child16(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = next_child16(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->base.width = 1u;
  noderef = next_child16(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  node->keys[1] = 2u;
  node->children[1] = &dummies[2];
  node->base.width = 2u;
  noderef = next_child16(node, 1u);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_find_child32(CuTest *tc)
{
  struct nametree *tree;
  struct namenode dummies[2], **noderef;
  struct namenode32 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE32);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = find_child32(node, 0x01u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if width is zero */
  node->keys[0] = 0x01u;
  node->children[0] = &dummies[1];
  noderef = find_child32(node, 0x01u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify key is found if width is correct */
  node->base.width++;
  noderef = find_child32(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  /* verify correct ordering of keys is required */
  node->keys[1] = 0x00u;
  node->children[1] = &dummies[0];
  node->base.width++;
  noderef = find_child32(node, 0x00u);
  CuAssertTrue(tc, noderef == NULL);
  /* swap positions, verfiy both are found */
  node->keys[0] = 0x00u;
  node->children[0] = &dummies[0];
  node->keys[1] = 0x01u;
  node->children[1] = &dummies[1];
  noderef = find_child32(node, 0x00u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = find_child32(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);

  teardown(tc);
}

static void test_nametree_previous_child32(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode32 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE32);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = previous_child32(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child32(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no previous node exists */
  node->keys[0] = 1u;
  node->children[0] = &dummies[1];
  node->base.width = 1;
  noderef = previous_child32(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct ordening is required */
  node->keys[0] = 2u;
  node->children[0] = &dummies[2];
  node->keys[1] = 1u;
  node->children[1] = &dummies[1];
  node->base.width = 2;
  noderef = previous_child32(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->keys[1] = 2u;
  node->children[1] = &dummies[2];
  node->base.width = 2;
  noderef = previous_child32(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child32(node, 1u);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = previous_child32(node, 2u);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = previous_child32(node, 3u);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_next_child32(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode32 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE16);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = next_child32(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child32(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no next node exists */
  node->keys[0] = NAMETREE_MAX_WIDTH - 1;
  node->children[0] = &dummies[0];
  node->base.width = 1;
  noderef = next_child32(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = next_child32(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  node->keys[0] = 0u;
  node->children[0] = &dummies[0];
  node->base.width = 1u;
  noderef = next_child32(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  node->keys[1] = 2u;
  node->children[1] = &dummies[2];
  node->base.width = 2u;
  noderef = next_child32(node, 1u);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_find_child38(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode38 *node;
  uint8_t keys[3] = { 0x00u, 0x2eu, 0x62u /* "z" + 1 */ };

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE38);
  CuAssertTrue(tc, node != NULL);

  noderef = find_child38(node, keys[1]);
  CuAssertTrue(tc, noderef == NULL);
  /* lookup of non-hostname keys must always result in NULL */
  noderef = find_child38(node, keys[2]);
  CuAssertTrue(tc, noderef == NULL);
  /* width does not need to be checked for nodes of type NAMENODE38 */
  node->children[0] = &dummies[0];
  node->base.width++;
  node->children[1] = &dummies[1];
  node->base.width++;
  noderef = find_child38(node, keys[0]);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = find_child38(node, keys[1]);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);

  teardown(tc);
}

static void test_nametree_previous_child38(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode38 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE38);
  CuAssertTrue(tc, node != NULL);

  /* verify conversion function behaves as expected (minimal) */
  CuAssertTrue(tc, node38_xlatlt(xlat('z') + 1) == node38_xlat(xlat('z')));
  CuAssertTrue(tc, node38_xlatlt(xlat('a') + 1) == node38_xlat(xlat('a')));
  CuAssertTrue(tc, node38_xlatlt(xlat('9') + 1) == node38_xlat(xlat('9')));
  CuAssertTrue(tc, node38_xlatlt(xlat('0') + 1) == node38_xlat(xlat('0')));
  CuAssertTrue(tc, node38_xlatlt(xlat('-') + 1) == node38_xlat(xlat('-')));
  CuAssertTrue(tc, node38_xlatlt(1) == node38_xlat(0));
  CuAssertTrue(tc, node38_xlatlt(0) == (uint8_t)-1);

  /* verify nothing is found if node is empty */
  noderef = previous_child38(node, xlat('a'));
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child38(node, node38_unxlat(0));
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no previous node exists */
  node->children[0] = &dummies[0];
  node->base.width++;
  noderef = previous_child38(node, node38_unxlat(0));
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = previous_child38(node, node38_unxlat(1));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = previous_child38(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  node->children[2] = &dummies[2];
  node->base.width++;
  noderef = previous_child38(node, node38_unxlat(3));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);
  noderef = previous_child38(node, node38_unxlat(2));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = previous_child38(node, node38_unxlat(1));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);

  teardown(tc);
}

static void test_nametree_next_child38(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode38 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE38);
  CuAssertTrue(tc, node != NULL);

  /* verify conversion function behaves as expected (minimal) */
  CuAssertTrue(tc, node38_xlatgt(xlat('z')) == (uint8_t)-1);
  CuAssertTrue(tc, node38_xlatgt(xlat('z') - 1) == node38_xlat(xlat('z')));
  CuAssertTrue(tc, node38_xlatgt(xlat('a') - 1) == node38_xlat(xlat('a')));
  CuAssertTrue(tc, node38_xlatgt(xlat('9') - 1) == node38_xlat(xlat('9')));
  CuAssertTrue(tc, node38_xlatgt(xlat('0') - 1) == node38_xlat(xlat('0')));
  CuAssertTrue(tc, node38_xlatgt(xlat('-') - 1) == node38_xlat(xlat('-')));
  CuAssertTrue(tc, node38_xlatgt(0) == 1);

  /* verify nothing is found if node is empty */
  noderef = next_child38(node, xlat('z'));
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child38(node, 0);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no next node exists */
  CuAssertTrue(tc, node38_xlat(xlat('z')) == 37);
  node->children[37] = &dummies[37];
  node->base.width++;
  noderef = next_child38(node, node38_unxlat(37));
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = next_child38(node, node38_unxlat(36));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[37]);
  node->children[35] = &dummies[35];
  node->base.width++;
  noderef = next_child38(node, node38_unxlat(35));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[37]);
  noderef = next_child38(node, node38_unxlat(34));
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[35]);

  teardown(tc);
}

static void test_nametree_find_child48(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode48 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE48);
  CuAssertTrue(tc, node != NULL);

  noderef = find_child48(node, 0x01);
  CuAssertTrue(tc, noderef == NULL);
  /* width does not need to be checked for nodes of type NAMENODE48 */
  /* add_child48 ensures children are ordered for previous/next operations */
  node->keys[1] = 1u;
  node->children[0] = &dummies[1];
  node->base.width++;
  node->keys[0] = 2u;
  node->children[1] = &dummies[0];
  node->base.width++;
  node->keys[NAMETREE_MAX_WIDTH - 1] = 3u;
  node->children[2] = &dummies[2];
  node->base.width++;
  noderef = find_child48(node, 0x00u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = find_child48(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  noderef = find_child48(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_previous_child48(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode48 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE48);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = previous_child48(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child48(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child48(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no previous node exists */
  node->keys[0] = 1;
  node->children[0] = &dummies[0];
  node->base.width++;
  noderef = previous_child48(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = previous_child48(node, 1u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  node->keys[2] = 3;
  node->children[2] = &dummies[2];
  node->base.width++;
  noderef = previous_child48(node, 3u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);
  noderef = previous_child48(node, 2u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = previous_child48(node, 1u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);

  teardown(tc);
}

static void test_nametree_next_child48(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode48 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE48);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = next_child48(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no next node exists */
  node->keys[NAMETREE_MAX_WIDTH - 3] = 1;
  node->children[0] = &dummies[0];
  node->base.width++;
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 3);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = next_child48(node, 0);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 4);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  node->keys[NAMETREE_MAX_WIDTH - 1] = 2;
  node->children[1] = &dummies[1];
  node->base.width++;
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  noderef = next_child48(node, NAMETREE_MAX_WIDTH - 3);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);

  teardown(tc);
}

static void test_nametree_find_child256(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode256 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE256);
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->base.type == NAMENODE256);

  noderef = find_child256(node, 0x01);
  CuAssertTrue(tc, noderef == NULL);
  /* width does not need to be checked for NAMENODE256 nodes */
  node->children[0x00] = &dummies[0];
  node->base.width++;
  node->children[0x01] = &dummies[1];
  node->base.width++;
  node->children[NAMETREE_MAX_WIDTH - 1] = &dummies[2];
  node->base.width++;
  noderef = find_child256(node, 0x00u);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[0]);
  noderef = find_child256(node, 0x01u);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[1]);
  noderef = find_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_previous_child256(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode256 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE256);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = previous_child256(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child256(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no previous node exists */
  node->children[2] = &dummies[2];
  node->base.width++;
  noderef = previous_child256(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child256(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child256(node, 2u);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = previous_child256(node, 3u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);
  node->children[0] = &dummies[0];
  node->base.width++;
  noderef = previous_child256(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = previous_child256(node, 1u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = previous_child256(node, 2u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  noderef = previous_child256(node, 3u);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);
  noderef = previous_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[2]);

  teardown(tc);
}

static void test_nametree_next_child256(CuTest *tc)
{
  struct nametree *tree;
  struct namenode **noderef;
  struct namenode256 *node;

  setup(tc);

  tree = create_tree(tc);
  node = alloc_node(tree, NAMENODE256);
  CuAssertTrue(tc, node != NULL);

  /* verify nothing is found if node is empty */
  noderef = next_child256(node, 0u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, 1u);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  /* verify nothing is found if no next node exists */
  node->children[NAMETREE_MAX_WIDTH - 3] = &dummies[0];
  node->base.width++;
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 3);
  CuAssertTrue(tc, noderef == NULL);
  /* verify correct normal operation */
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 4);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);
  node->children[NAMETREE_MAX_WIDTH - 1] = &dummies[1];
  node->base.width++;
  noderef = next_child256(node, NAMETREE_MAX_WIDTH);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 1);
  CuAssertTrue(tc, noderef == NULL);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 2);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 3);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[1]);
  noderef = next_child256(node, NAMETREE_MAX_WIDTH - 4);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[0]);

  teardown(tc);
}

static void test_nametree_add_child4(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode4 *node4;
  struct namenode16 *node16;

  setup(tc);

  tree = create_tree(tc);
  /* create node, fill unordered */
  node4 = alloc_node(tree, NAMENODE4);
  node = (struct namenode *)node4;
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->width == 0);
  for (int key = 3; key >= 0; key--) {
    noderef = add_child4(tree, &node, (uint8_t)key, &dummies[key]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[key]);
    CuAssertTrue(tc, node == (struct namenode *)node4);
    CuAssertTrue(tc, node->type == NAMENODE4);
  }
  CuAssertTrue(tc, node->width == 4);
  /* verify node is properly ordered */
  for (uint8_t key = 0u; key < 4u; key++) {
    CuAssertTrue(tc, node4->keys[key] == key);
    CuAssertTrue(tc, node4->children[key] == &dummies[key]);
  }
  /* add child, ensure node is promoted to NAMENODE16 */
  noderef = add_child4(tree, &node, 4u, &dummies[4u]);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[4u]);
  CuAssertTrue(tc, node->type == NAMENODE16);
  CuAssertTrue(tc, node->width == 5);
  node16 = (struct namenode16 *)node;
  for (uint8_t key = 0u; key < 5u; key++) {
    CuAssertTrue(tc, node16->keys[key] == key);
    CuAssertTrue(tc, node16->children[key] == &dummies[key]);
  }

  teardown(tc);
}

static void test_nametree_add_child16(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode16 *node16;
  struct namenode32 *node32;

  setup(tc);

  tree = create_tree(tc);
  /* create node, fill unordered */
  node16 = alloc_node(tree, NAMENODE16);
  node = (struct namenode *)node16;
  CuAssertTrue(tc, node != NULL && node->type == NAMENODE16);
  for (uint8_t idx = 0u; idx < 16u; idx++) {
    uint8_t key = order[idx];
    noderef = add_child16(tree, &node, key, &dummies[key]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[key]);
    CuAssertTrue(tc, node == (struct namenode *)node16);
    CuAssertTrue(tc, node->type == NAMENODE16);
  }
  CuAssertTrue(tc, node->width == 16u);
  /* verify node is properly ordered */
  for (uint8_t key = 0u; key < 16u; key++) {
    CuAssertTrue(tc, node16->keys[key] == key);
    CuAssertTrue(tc, node16->children[key] == &dummies[key]);
  }
  /* add child, ensure node is promoted to NAMENODE32 */
  noderef = add_child16(tree, &node, 16u, &dummies[16u]);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[16u]);
  CuAssertTrue(tc, node->type == NAMENODE32);
  CuAssertTrue(tc, node->width == 17u);
  node32 = (struct namenode32 *)node;
  for (uint8_t key = 0u; key < 17u; key++) {
    CuAssertTrue(tc, node32->keys[key] == key);
    CuAssertTrue(tc, node32->children[key] == &dummies[key]);
  }

  teardown(tc);
}

static void test_nametree_add_child32_hostonly(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode32 *node32;
  struct namenode38 *node38;

  setup(tc);

  tree = create_tree(tc);
  /* create node, fill unordered */
  node32 = alloc_node(tree, NAMENODE32);
  node = (struct namenode *)node32;
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->type == NAMENODE32);
  for (uint8_t idx = 0u; idx < 32u; idx++) {
    uint8_t key = node38_unxlat(order[idx]);
    noderef = add_child32(tree, &node, key, &dummies[order[idx]]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[order[idx]]);
    CuAssertTrue(tc, node == (struct namenode *)node32);
    CuAssertTrue(tc, node->type == NAMENODE32);
  }
  CuAssertTrue(tc, node->width == 32);
  /* verify node is properly ordered */
  for (uint8_t idx = 0u; idx < 32u; idx++) {
    uint8_t key = node38_unxlat(idx);
    CuAssertTrue(tc, node32->keys[idx] == key);
    CuAssertTrue(tc, node32->children[idx] == &dummies[idx]);
  }
  /* add child, ensure node is promoted to NAMENODE38 */
  noderef = add_child32(tree, &node, node38_unxlat(32u), &dummies[32]);
  CuAssertTrue(tc, noderef != NULL && *noderef == &dummies[32]);
  CuAssertTrue(tc, node->type == NAMENODE38);
  CuAssertTrue(tc, node->width == 33u);
  node38 = (struct namenode38 *)node;
  for (uint8_t idx = 0u; idx < 33u; idx++) {
    CuAssertTrue(tc, node38->children[idx] == &dummies[idx]);
  }

  teardown(tc);
}

static void test_nametree_add_child32(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode32 *node32;
  struct namenode48 *node48;

  setup(tc);

  tree = create_tree(tc);
  /* create node, fill unordered */
  node32 = alloc_node(tree, NAMENODE32);
  node = (struct namenode *)node32;
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->type == NAMENODE32);
  CuAssertTrue(tc, node->width == 0);
  for (uint8_t idx = 0u; idx < 32u; idx++) {
    uint8_t key = order[idx];
    noderef = add_child32(tree, &node, key, &dummies[key]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[key]);
    CuAssertTrue(tc, node == (struct namenode *)node32);
    CuAssertTrue(tc, node->type == NAMENODE32);
  }
  CuAssertTrue(tc, node->width == 32);
  /* verify node is properly ordered */
  for (uint8_t key = 0u; key < 32u; key++) {
    CuAssertTrue(tc, node32->keys[key] == key);
    CuAssertTrue(tc, node32->children[key] == &dummies[key]);
  }
  /* add child, ensure node is promoted to NAMENODE48 */
  noderef = add_child32(tree, &node, 32u, &dummies[32u]);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[32u]);
  CuAssertTrue(tc, node->type == NAMENODE48);
  CuAssertTrue(tc, node->width == 33u);
  node48 = (struct namenode48 *)node;
  for (uint8_t key = 0u; key < 33u; key++) {
    CuAssertTrue(tc, node48->keys[key] != 0);
    CuAssertTrue(tc, node48->children[node48->keys[key]-1] == &dummies[key]);
  }

  teardown(tc);
}

static void test_nametree_add_child38(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode38 *node38;
  struct namenode48 *node48;
  uint8_t key;

  setup(tc);

  tree = create_tree(tc);
  /* create node, order is not important for NAMENODE38 */
  node38 = alloc_node(tree, NAMENODE38);
  node = (struct namenode *)node38;
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->type == NAMENODE38);
  CuAssertTrue(tc, node->width == 0);
  for (uint8_t idx = 0u; idx < 38u; idx++) {
    key = node38_unxlat(idx);
    noderef = add_child38(tree, &node, key, &dummies[idx]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[idx]);
    CuAssertTrue(tc, node == (struct namenode *)node38);
    CuAssertTrue(tc, node->type == NAMENODE38);
  }
  CuAssertTrue(tc, node->width == 38u);
  noderef = add_child38(tree, &node, node38_unxlat(37u)+1, &dummies[38u]);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[38u]);
  CuAssertTrue(tc, node->type == NAMENODE48);
  CuAssertTrue(tc, node->width == 39u);
  node48 = (struct namenode48 *)node;
  for (uint8_t idx = 0u; idx < 38u; idx++) {
    key = node38_unxlat(idx);
    CuAssertTrue(tc, node48->keys[key] != 0);
    CuAssertTrue(tc, node48->children[node48->keys[key]-1] == &dummies[idx]);
  }
  key = node38_unxlat(37u)+1;
  CuAssertTrue(tc, node48->keys[key] != 0);
  CuAssertTrue(tc, node48->children[node48->keys[key]-1] == &dummies[38u]);

  teardown(tc);
}

static void test_nametree_add_child48(CuTest *tc)
{
  struct nametree *tree;
  struct namenode *node, **noderef;
  struct namenode48 *node48;
  struct namenode256 *node256;

  setup(tc);

  tree = create_tree(tc);
  /* create node */
  node48 = alloc_node(tree, NAMENODE48);
  node = (struct namenode *)node48;
  CuAssertTrue(tc, node != NULL);
  CuAssertTrue(tc, node->type == NAMENODE48);
  CuAssertTrue(tc, node->width == 0);
  for (uint8_t idx = 0u; idx < 48u; idx++) {
    uint8_t key = order[idx];
    noderef = add_child48(tree, &node, key, &dummies[key]);
    CuAssertTrue(tc, noderef != NULL);
    CuAssertTrue(tc, *noderef == &dummies[key]);
    CuAssertTrue(tc, node == (struct namenode *)node48);
    CuAssertTrue(tc, node->type == NAMENODE48);
  }
  CuAssertTrue(tc, node->width == 48u);
  /* verify node is properly ordered */
  for (uint8_t key = 0u; key < 48u; key++) {
    CuAssertTrue(tc, node48->keys[key] == key + 1);
    CuAssertTrue(tc, node48->children[key] == &dummies[key]);
  }
  noderef = add_child48(tree, &node, 48u, &dummies[48u]);
  CuAssertTrue(tc, noderef != NULL);
  CuAssertTrue(tc, *noderef == &dummies[48u]);
  CuAssertTrue(tc, node->type == NAMENODE256);
  CuAssertTrue(tc, node->width == 49u);
  node256 = (struct namenode256 *)node;
  for (uint8_t idx = 0u; idx < 49u; idx++) {
    CuAssertTrue(tc, node256->children[idx] == &dummies[idx]);
  }

  teardown(tc);
}

static void test_nametree_make_key(CuTest *tc)
{
  const struct dname *dname;
  namekey key;
  uint8_t key_len;

  setup(tc);

  dname = dname_parse(region, "BaZ.bAr.FoO.");
  CuAssertTrue(tc, dname != NULL);
  key_len = nametree_make_key(key, dname);
  CuAssertTrue(tc, key_len == 13);
  CuAssertTrue(tc, key[ 0] == 0x4du && /* f */
                   key[ 1] == 0x56u && /* o */
                   key[ 2] == 0x56u && /* o */
                   key[ 3] == 0x00u && /* end of label */
                   key[ 4] == 0x49u && /* b */
                   key[ 5] == 0x48u && /* a */
                   key[ 6] == 0x59u && /* r */
                   key[ 7] == 0x00u && /* end of label */
                   key[ 8] == 0x49u && /* b */
                   key[ 9] == 0x48u && /* a */
                   key[10] == 0x61u && /* z */
                   key[11] == 0x00u && /* end of label */
                   key[12] == 0x00u);  /* end of key */

  teardown(tc);
}

static void test_nametree_make_prefix(CuTest *tc)
{
  const struct dname *dname;
  namekey prefix;
  uint8_t prefix_len;

  setup(tc);

  dname = dname_parse(region, "BaZ.bAr.FoO.");
  /* key: foo0bar0baz00 */
  CuAssertTrue(tc, dname != NULL);
  prefix_len = nametree_make_prefix(prefix, dname, 0, 0);
  CuAssertTrue(tc, prefix_len == 13);
  CuAssertTrue(tc, prefix[ 0] == 0x4du && /* f */
                   prefix[ 1] == 0x56u && /* o */
                   prefix[ 2] == 0x56u && /* o */
                   prefix[ 3] == 0x00u && /* end of label */
                   prefix[ 4] == 0x49u && /* b */
                   prefix[ 5] == 0x48u && /* a */
                   prefix[ 6] == 0x59u && /* r */
                   prefix[ 7] == 0x00u && /* end of label */
                   prefix[ 8] == 0x49u && /* b */
                   prefix[ 9] == 0x48u && /* a */
                   prefix[10] == 0x61u && /* z */
                   prefix[11] == 0x00u && /* end of label */
                   prefix[12] == 0x00u);  /* end of key */
  prefix_len = nametree_make_prefix(prefix, dname, 1, 4);
  CuAssertTrue(tc, prefix_len == 4);
  CuAssertTrue(tc, prefix[0] == xlat('o'));
  CuAssertTrue(tc, prefix[1] == xlat('o'));
  CuAssertTrue(tc, prefix[2] == 0x00u);
  CuAssertTrue(tc, prefix[3] == xlat('b'));
  prefix_len = nametree_make_prefix(prefix, dname, 0, 1);
  CuAssertTrue(tc, prefix_len == 1);
  CuAssertTrue(tc, prefix[0] == xlat('f'));
  prefix_len = nametree_make_prefix(prefix, dname, 12, 0);
  CuAssertTrue(tc, prefix_len == 1);
  CuAssertTrue(tc, prefix[0] == 0x00u);
  prefix_len = nametree_make_prefix(prefix, dname, 12, 1);
  CuAssertTrue(tc, prefix_len == 1);
  CuAssertTrue(tc, prefix[0] == 0x00u);
  prefix_len = nametree_make_prefix(prefix, dname, 3, 5);
  CuAssertTrue(tc, prefix_len == 5);
  CuAssertTrue(tc, prefix[0] == 0x00u);
  CuAssertTrue(tc, prefix[1] == xlat('b'));
  CuAssertTrue(tc, prefix[2] == xlat('a'));
  CuAssertTrue(tc, prefix[3] == xlat('r'));
  CuAssertTrue(tc, prefix[4] == 0x00u);
  prefix_len = nametree_make_prefix(prefix, dname, 3, 1);
  CuAssertTrue(tc, prefix_len == 1);
  CuAssertTrue(tc, prefix[0] == 0x00u);

  teardown(tc);
}

static void test_nametree_insert_single_leaf(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domain;
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);
  tree = create_tree(tc);
  domain = create_domain(tc, "foo.");

  key_len = nametree_make_key(key, domain->dname);
  CuAssertTrue(tc, key_len == 5);

  memset(&path, 0, sizeof(path));

  leaf = nametree_insert(tree, &path, key, key_len, domain);
  CuAssertTrue(tc, path.height == 1);
  CuAssertTrue(tc, path.levels[0].depth == 0);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[0].noderef));
  CuAssertTrue(tc, leaf == domain);

  teardown(tc);
}

static void test_nametree_insert_single(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *root, *foo;
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  root = create_domain(tc, ".");

  key_len = nametree_make_key(key, root->dname);
  CuAssertTrue(tc, key_len == 1);
  memset(&path, 0, sizeof(path));

  leaf = nametree_insert(tree, &path, key, key_len, root);
  CuAssertTrue(tc, path.height == 1);
  CuAssertTrue(tc, path.levels[0].depth == 0);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[0].noderef));
  CuAssertTrue(tc, leaf == root);

  foo = create_domain(tc, "foo.");

  key_len = nametree_make_key(key, foo->dname);
  CuAssertTrue(tc, key_len == 5);
  memset(&path, 0, sizeof(path));

  leaf = nametree_insert(tree, &path, key, key_len, foo);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, path.levels[0].depth == 0);
  CuAssertTrue(tc, !nametree_is_leaf(*path.levels[0].noderef));
  CuAssertTrue(tc, (*path.levels[0].noderef)->prefix_len == 0);
  CuAssertTrue(tc, path.levels[1].depth == key_len);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[1].noderef) == foo);
  CuAssertTrue(tc, leaf == foo);

  teardown(tc);
}

static void test_nametree_insert_single_comp(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "lorumipsum.");
  key_len = nametree_make_key(key, domains[0]->dname);
  CuAssertTrue(tc, key_len == 12);

  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == domains[0]);

  domains[1] = create_domain(tc, "lorumipsumdolor.");
  key_len = nametree_make_key(key, domains[1]->dname);
  CuAssertTrue(tc, key_len == 17);

  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, path.levels[0].depth == 0);
  CuAssertTrue(tc, !nametree_is_leaf(*path.levels[0].noderef));
  CuAssertTrue(tc, (*path.levels[0].noderef)->prefix_len == 10);
  CuAssertTrue(tc, (*path.levels[0].noderef)->prefix_len > NAMETREE_MAX_PREFIX);
  CuAssertTrue(tc, memcmp((*path.levels[0].noderef)->prefix, key, NAMETREE_MAX_PREFIX) == 0);
  CuAssertTrue(tc, path.levels[1].depth == key_len);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[1].noderef) == domains[1]);
  CuAssertTrue(tc, leaf == domains[1]);

  teardown(tc);
}

static void test_nametree_insert_multi(CuTest *tc)
{
  int cnt;
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[7];
  nameleaf *leaf;
  namekey key;
  uint8_t key_len;
  struct namenode *node, *nodeb1, *nodeb2;

  static const char *names[7] = {
    "a.",
    "b1.a.",
    "b2.a.",
    "c.b1.a.",
    "d.b1.a.",
    "c.b2.a.",
    "d.b2.a."
  };

  setup(tc);

  tree = create_tree(tc);
  for (cnt=0; cnt<7; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    leaf = nametree_insert(tree, &path, key, key_len, domains[cnt]);
    CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
    CuAssertTrue(tc, leaf == domains[cnt]);
  }

  node = tree->root;
  CuAssertTrue(tc, node->prefix_len == 2);
  CuAssertTrue(tc, node->prefix[0] == xlat('a'));
  CuAssertTrue(tc, node->prefix[1] == 0);
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[0] == 0);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[1] == xlat('b'));
  node = ((struct namenode4 *)tree->root)->children[0];
  CuAssertTrue(tc, nametree_is_leaf(node));
  node = ((struct namenode4 *)tree->root)->children[1];
  CuAssertTrue(tc, node->prefix_len == 0);
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[0] == xlat('1'));
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[1] == xlat('2'));
  nodeb1 = ((struct namenode4 *)node)->children[0];
  nodeb2 = ((struct namenode4 *)node)->children[1];
  CuAssertTrue(tc, nodeb1->prefix_len == 1);
  CuAssertTrue(tc, nodeb1->prefix[0] == 0);
  CuAssertTrue(tc, nodeb1->width == 3);
  CuAssertTrue(tc, nodeb2->prefix_len == 1);
  CuAssertTrue(tc, nodeb2->prefix[0] == 0);
  CuAssertTrue(tc, nodeb2->width == 3);

  teardown(tc);
}

static void test_nametree_insert_multi_comp(CuTest *tc)
{
  int cnt;
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[7];
  nameleaf *leaf;
  namekey key;
  uint8_t key_len;
  struct namenode *node, *nodeb1, *nodeb2;

#define A "aaaaaaaaaa"
#define B "bbbbbbbbbbbb"
#define C "cccccccccc"
#define D "dddddddddd"

  static const char *names[7] = {
    A ".",
    B "1." A ".",
    B "2." A ".",
    C "." B "1." A ".",
    D "." B "1." A ".",
    C "." B "2." A ".",
    D "." B "2." A "."
  };

  setup(tc);

  tree = create_tree(tc);
  for (cnt=0; cnt<7; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    leaf = nametree_insert(tree, &path, key, key_len, domains[cnt]);
    CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
    CuAssertTrue(tc, leaf == domains[cnt]);
  }

  node = tree->root;
  CuAssertTrue(tc, node->prefix_len == 11);
  for (cnt=0; cnt < NAMETREE_MAX_PREFIX; cnt++) {
    CuAssertTrue(tc, node->prefix[cnt] == xlat('a'));
  }
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[0] == 0);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[1] == xlat('b'));
  node = ((struct namenode4 *)tree->root)->children[0];
  CuAssertTrue(tc, nametree_is_leaf(node));
  node = ((struct namenode4 *)tree->root)->children[1];
  CuAssertTrue(tc, node->prefix_len == 11);
  for (cnt=0; cnt < NAMETREE_MAX_PREFIX; cnt++) {
    CuAssertTrue(tc, node->prefix[cnt] == xlat('b'));
  }
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[0] == xlat('1'));
  CuAssertTrue(tc, ((struct namenode4 *)node)->keys[1] == xlat('2'));
  nodeb1 = ((struct namenode4 *)node)->children[0];
  nodeb2 = ((struct namenode4 *)node)->children[1];
  CuAssertTrue(tc, nodeb1->prefix_len == 1);
  CuAssertTrue(tc, nodeb1->prefix[0] == 0);
  CuAssertTrue(tc, nodeb1->width == 3);
  CuAssertTrue(tc, nodeb2->prefix_len == 1);
  CuAssertTrue(tc, nodeb2->prefix[0] == 0);
  CuAssertTrue(tc, nodeb2->width == 3);

  teardown(tc);
}

static void test_nametree_insert_existing(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  const char *name = "x.y.z.";

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, name);
  domains[1] = create_domain(tc, name);

  key_len = nametree_make_key(key, domains[0]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == domains[0]);
  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == domains[0]);

  teardown(tc);
}

static void test_nametree_search(CuTest *tc)
{
  int cnt;
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[7];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  /* arbitrarily chosen domain names (some must use path compression) */
  const char *names[7] = {
    "z.",
    "x.y1.z.",
    "x.xxxxxxxxxxxxxxx.y1.z.",
    "y.xxxxxxxxxxxxxxx.y1.z.",
    "x.y2.z.",
    "x.yy.z.",
    "z.y.xxxxxxxxxxx."
  };

  setup(tc);

  tree = create_tree(tc);
  for (cnt = 0; cnt < 7; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    leaf = nametree_insert(tree, &path, key, key_len, domains[cnt]);
    CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
    CuAssertTrue(tc, leaf == domains[cnt]);
  }

  for (cnt = 0; cnt < 7; cnt++) {
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    leaf = nametree_search(tree, &path, key, key_len, domains[cnt]->dname, 0);
    CuAssertTrue(tc, leaf == domains[cnt]);
    CuAssertTrue(tc, path.height > 1);
    CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  }

  teardown(tc);
}

static void test_nametree_search_non_existing(CuTest *tc)
{
  int cnt;
  struct nametree *tree;
  struct namepath path;
  struct domain *domain, *domains[6];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  const char *names[6] = {
    "a.",
    A ".",
    B "1." A ".",
    B "2." A ".",
    /* not inserted */
    B ".",
    B "3." A "."
  };

  setup(tc);

  tree = create_tree(tc);
  domain = create_domain(tc, "foo.");
  key_len = nametree_make_key(key, domain->dname);
  memset(&path, 0, sizeof(path));

  leaf = nametree_search(tree, &path, key, key_len, domain->dname, 0);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);

  for (cnt=0; cnt < 6; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    if (cnt < 4) {
      leaf = nametree_insert(tree, &path, key, key_len, domains[cnt]);
      CuAssertTrue(tc, leaf == domains[cnt]);
    }
  }

  key_len = nametree_make_key(key, domains[4]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_search(tree, &path, key, key_len, domains[4]->dname, 0);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 1);

  key_len = nametree_make_key(key, domains[5]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_search(tree, &path, key, key_len, domains[5]->dname, 0);
  /* no leaf with the given name must exist */
  CuAssertTrue(tc, leaf == NULL);
  /* path must not be empty */
  CuAssertTrue(tc, path.height == 3);
  CuAssertTrue(tc, (*path.levels[path.height - 1].noderef)->width == 2);

  teardown(tc);
}

static void test_nametree_search_previous(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[5];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;
  int32_t cmp = NAMETREE_PREVIOUS_CLOSEST;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "foo1.");
  domains[1] = create_domain(tc, "bar.foo1.");
  domains[2] = create_domain(tc, "foo2.");
  domains[3] = create_domain(tc, "bar.foo2.");
  domains[4] = create_domain(tc, "foo3.");

  /* ensure nothing is returned if tree is empty */
  key_len = nametree_make_key(key, domains[1]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[1]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);
  /* ensure nothing is returned if tree is searched with a lesser key */
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == domains[1]);
  CuAssertTrue(tc, path.height == 1);
  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[0]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);
  /* ensure leaf is returned if tree is searched with a greater key */
  key_len = nametree_make_key(key, domains[2]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[2]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 1);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[1]);
  /* insert greater leaf */
  key_len = nametree_make_key(key, domains[3]->dname);
  path.height = 0;
  leaf = nametree_insert(tree, &path, key, key_len, domains[3]);
  CuAssertTrue(tc, leaf == domains[3]);
  CuAssertTrue(tc, path.height == 2);
  /* ensure greatest leaf is returned if tree is searched with greatest key */
  key_len = nametree_make_key(key, domains[4]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[4]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[3]);
  /* ensure lesser leaf is returned if tree is searched with middle key */
  key_len = nametree_make_key(key, domains[2]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[2]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[1]);
  /* ensure NULL is returned if tree is searched with smallest key */
  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[0]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);

  teardown(tc);
}

static void test_nametree_search_next(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[5];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;
  int32_t cmp = NAMETREE_NEXT_CLOSEST;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "foo1.");
  domains[1] = create_domain(tc, "bar.foo1.");
  domains[2] = create_domain(tc, "foo2.");
  domains[3] = create_domain(tc, "bar.foo2.");
  domains[4] = create_domain(tc, "foo3.");

  /* ensure nothing is returned if tree is empty */
  key_len = nametree_make_key(key, domains[1]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[1]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);
  /* ensure nothing is returned if tree is searched with a greater key */
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == domains[1]);
  CuAssertTrue(tc, path.height == 1);
  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[2]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);
  /* ensure leaf is returned if tree is searched with a smaller key */
  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[0]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 1);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[1]);
  /* insert greater leaf */
  key_len = nametree_make_key(key, domains[3]->dname);
  path.height = 0;
  leaf = nametree_insert(tree, &path, key, key_len, domains[3]);
  CuAssertTrue(tc, leaf == domains[3]);
  CuAssertTrue(tc, path.height == 2);
  /* ensure nothing is returned if tree is searched with greatest key */
  key_len = nametree_make_key(key, domains[4]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[4]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);
  /* ensure greatest leaf is returned if tree is searched with middle key */
  key_len = nametree_make_key(key, domains[2]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[2]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[3]);
  /* ensure smallest is returned if tree is searched with smallest key */
  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_search(tree, &path, key, key_len, domains[0]->dname, cmp);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 2);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[path.height - 1].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[path.height - 1].noderef) == domains[1]);

  teardown(tc);
}

static void test_nametree_remove_child4(CuTest *tc)
{
  struct nametree *tree;
  struct namenode4 *nodes[2];
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  /* create one actual child node to verify path merger works */
  nodes[0] = alloc_node(tree, NAMENODE4);
  node = (struct namenode *)nodes[0];
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, 1, nametree_tag_leaf(&dummies[1]));
  node->prefix_len = 2;
  node->prefix[0] = xlat('a');
  node->prefix[1] = xlat('r');
  nodes[1] = alloc_node(tree, NAMENODE4);
  node = (struct namenode *)nodes[1];
  add_child(tree, &node, xlat('b'), (struct namenode *)nodes[0]);
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[2]));
  add_child(tree, &node, 1, nametree_tag_leaf(&dummies[3]));
  node->prefix_len = 3;
  node->prefix[0] = xlat('f');
  node->prefix[1] = xlat('o');
  node->prefix[2] = xlat('o');

  CuAssertTrue(tc, nodes[1]->base.width == 3);
  /* remove two dummies and verify paths are merged */
  node = (struct namenode *)nodes[1];
  /* remove middle (dummy) node to verify keys are kept in order */
  remove_child4(tree, &node, 1);
  CuAssertTrue(tc, node == (struct namenode *)nodes[1]);
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, nodes[1]->keys[0] == 0);
  CuAssertTrue(tc, nodes[1]->keys[1] == xlat('b'));
  CuAssertTrue(tc, nodes[1]->children[1] == (struct namenode *)nodes[0]);
  /* remove first (dummy) node to verify nodes are merged */
  remove_child4(tree, &node, 0);
  CuAssertTrue(tc, node == (struct namenode *)nodes[0]);
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, node->prefix_len == 6);
  CuAssertTrue(tc, node->prefix[0] == xlat('f'));
  CuAssertTrue(tc, node->prefix[1] == xlat('o'));
  CuAssertTrue(tc, node->prefix[2] == xlat('o'));
  CuAssertTrue(tc, node->prefix[3] == xlat('b'));
  CuAssertTrue(tc, node->prefix[4] == xlat('a'));
  CuAssertTrue(tc, node->prefix[5] == xlat('r'));

  teardown(tc);
}

static void test_nametree_remove_child4_comp(CuTest *tc)
{
  uint8_t cnt;
  struct nametree *tree;
  struct namenode4 *nodes[2];
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  nodes[0] = alloc_node(tree, NAMENODE4);
  node = (struct namenode *)nodes[0];
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, 1, nametree_tag_leaf(&dummies[1]));
  node->prefix_len = NAMETREE_MAX_PREFIX * 2;
  for (cnt=0; cnt < NAMETREE_MAX_PREFIX; cnt++) {
    node->prefix[cnt] = xlat('c');
  }
  nodes[1] = alloc_node(tree, NAMENODE4);
  node = (struct namenode *)nodes[1];
  node->prefix_len = 4;
  for (cnt=0; cnt < NAMETREE_MAX_PREFIX; cnt++) {
    node->prefix[cnt] = xlat('a');
  }
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[2]));
  add_child(tree, &node, xlat('b'), (struct namenode *)nodes[0]);

  CuAssertTrue(tc, node->width == 2);
  /* remove dummy node and verify nodes are merged */
  remove_child4(tree, &node, 0);
  CuAssertTrue(tc, node == (struct namenode *)nodes[0]);
  CuAssertTrue(tc, node->width == 2);
  CuAssertTrue(tc, node->prefix_len == (4 + 1 + (NAMETREE_MAX_PREFIX * 2)));
  CuAssertTrue(tc, node->prefix[0] == xlat('a'));
  CuAssertTrue(tc, node->prefix[1] == xlat('a'));
  CuAssertTrue(tc, node->prefix[2] == xlat('a'));
  CuAssertTrue(tc, node->prefix[3] == xlat('a'));
  CuAssertTrue(tc, node->prefix[4] == xlat('b'));
  CuAssertTrue(tc, node->prefix[5] == xlat('c'));
  CuAssertTrue(tc, node->prefix[6] == xlat('c'));
  CuAssertTrue(tc, node->prefix[7] == xlat('c'));
  CuAssertTrue(tc, node->prefix[8] == xlat('c'));

  teardown(tc);
}

static void test_nametree_remove_child16(CuTest *tc)
{
  struct nametree *tree;
  struct namenode16 *node16;
  struct namenode4 *node4;
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  node16 = alloc_node(tree, NAMENODE16);
  node = (struct namenode *)node16;
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, 1, nametree_tag_leaf(&dummies[1]));
  add_child(tree, &node, 2, nametree_tag_leaf(&dummies[2]));

  CuAssertTrue(tc, node->width == 3);
  remove_child16(tree, &node, 1);
  CuAssertTrue(tc, node != (struct namenode *)node16);
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->width == 2);
  node4 = (struct namenode4 *)node;
  CuAssertTrue(tc, node4->keys[0] == 0);
  CuAssertTrue(tc, node4->keys[1] == 2);
  CuAssertTrue(tc, node4->children[0] == nametree_tag_leaf(&dummies[0]));
  CuAssertTrue(tc, node4->children[1] == nametree_tag_leaf(&dummies[2]));

  teardown(tc);
}

static void test_nametree_remove_child32(CuTest *tc)
{
  struct nametree *tree;
  struct namenode32 *node32;
  struct namenode16 *node16;
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  node32 = alloc_node(tree, NAMENODE32);
  node = (struct namenode *)node32;
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, 1, nametree_tag_leaf(&dummies[1]));
  add_child(tree, &node, 2, nametree_tag_leaf(&dummies[2]));

  CuAssertTrue(tc, node->width == 3);
  remove_child32(tree, &node, 1);
  CuAssertTrue(tc, node != (struct namenode *)node32);
  CuAssertTrue(tc, node->type == NAMENODE16);
  CuAssertTrue(tc, node->width == 2);
  node16 = (struct namenode16 *)node;
  CuAssertTrue(tc, node16->keys[0] == 0);
  CuAssertTrue(tc, node16->keys[1] == 2);
  CuAssertTrue(tc, node16->children[0] == nametree_tag_leaf(&dummies[0]));
  CuAssertTrue(tc, node16->children[1] == nametree_tag_leaf(&dummies[2]));

  teardown(tc);
}

static void test_nametree_remove_child38(CuTest *tc)
{
  struct nametree *tree;
  struct namenode38 *node38;
  struct namenode32 *node32;
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  node38 = alloc_node(tree, NAMENODE38);
  node = (struct namenode *)node38;
  add_child(tree, &node, xlat('a'), nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, xlat('b'), nametree_tag_leaf(&dummies[1]));
  add_child(tree, &node, xlat('c'), nametree_tag_leaf(&dummies[2]));

  CuAssertTrue(tc, node->width == 3);
  remove_child38(tree, &node, xlat('b'));
  CuAssertTrue(tc, node != (struct namenode *)node38);
  CuAssertTrue(tc, node->type == NAMENODE32);
  CuAssertTrue(tc, node->width == 2);
  node32 = (struct namenode32 *)node;
  CuAssertTrue(tc, node32->keys[0] == xlat('a'));
  CuAssertTrue(tc, node32->keys[1] == xlat('c'));
  CuAssertTrue(tc, node32->children[0] == nametree_tag_leaf(&dummies[0]));
  CuAssertTrue(tc, node32->children[1] == nametree_tag_leaf(&dummies[2]));

  teardown(tc);
}

static void test_nametree_remove_child48(CuTest *tc)
{
  struct nametree *tree;
  struct namenode48 *node48;
  struct namenode32 *node32;
  struct namenode *node;

  setup(tc);
// FIXME: !!!!verify correct ordering is maintained!!!!
  tree = create_tree(tc);
  node48 = alloc_node(tree, NAMENODE48);
  node = (struct namenode *)node48;
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, xlat('a'), nametree_tag_leaf(&dummies[1]));
  add_child(tree, &node, xlat('b'), nametree_tag_leaf(&dummies[2]));

  CuAssertTrue(tc, node->width == 3);
  remove_child48(tree, &node, xlat('a'));
  CuAssertTrue(tc, node != (struct namenode *)node48);
  CuAssertTrue(tc, node->type == NAMENODE32);
  CuAssertTrue(tc, node->width == 2);
  node32 = (struct namenode32 *)node;
  CuAssertTrue(tc, node32->keys[0] == 0);
  CuAssertTrue(tc, node32->keys[1] == xlat('b'));
  CuAssertTrue(tc, node32->children[0] == nametree_tag_leaf(&dummies[0]));
  CuAssertTrue(tc, node32->children[1] == nametree_tag_leaf(&dummies[2]));

  teardown(tc);
}

static void test_nametree_remove_child48_hostonly(CuTest *tc)
{
  uint8_t idx, key;
  struct nametree *tree;
  struct namenode48 *node48;
  struct namenode38 *node38;
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  node48 = alloc_node(tree, NAMENODE48);
  node = (struct namenode *)node48;
  for (idx = 0; idx < 35; idx++) {
    key = node38_unxlat(idx);
    add_child(tree, &node, key, nametree_tag_leaf(&dummies[idx]));
  }

  CuAssertTrue(tc, node->width == 35);
  remove_child48(tree, &node, xlat('a'));
  CuAssertTrue(tc, node != (struct namenode *)node48);
  CuAssertTrue(tc, node->type == NAMENODE38);
  CuAssertTrue(tc, node->width == 34);
  node38 = (struct namenode38 *)node;
  for (idx = 0; idx < 35; idx++) {
    key = node38_unxlat(idx);
    if (key == xlat('a')) {
      CuAssertTrue(tc, node38->children[idx] == NULL);
    } else {
      CuAssertTrue(tc, node38->children[idx] == nametree_tag_leaf(&dummies[idx]));
    }
  }

  teardown(tc);
}

static void test_nametree_remove_child256(CuTest *tc)
{
  uint8_t idx;
  struct nametree *tree;
  struct namenode256 *node256;
  struct namenode48 *node48;
  struct namenode *node;

  setup(tc);

  tree = create_tree(tc);
  node256 = alloc_node(tree, NAMENODE256);
  node = (struct namenode *)node256;
  add_child(tree, &node, 0, nametree_tag_leaf(&dummies[0]));
  add_child(tree, &node, 50, nametree_tag_leaf(&dummies[1]));
  add_child(tree, &node, 150, nametree_tag_leaf(&dummies[2]));

  CuAssertTrue(tc, node->width == 3);
  remove_child256(tree, &node, 50);
  CuAssertTrue(tc, node != (struct namenode *)node256);
  CuAssertTrue(tc, node->type == NAMENODE48);
  CuAssertTrue(tc, node->width == 2);
  node48 = (struct namenode48 *)node;
  CuAssertTrue(tc, node48->keys[0] != 0);
  idx = node48->keys[0] - 1;
  CuAssertTrue(tc, node48->children[idx] == nametree_tag_leaf(&dummies[0]));
  CuAssertTrue(tc, node48->keys[150] != 0);
  idx = node48->keys[150] - 1;
  CuAssertTrue(tc, node48->children[idx] == nametree_tag_leaf(&dummies[2]));

  teardown(tc);
}

static void test_nametree_delete_single_leaf(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domain;
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  domain = create_domain(tc, "foobar.");
  key_len = nametree_make_key(key, domain->dname);
  memset(&path, 0, sizeof(path));

  leaf = nametree_insert(tree, &path, key, key_len, domain);
  CuAssertTrue(tc, leaf == (nameleaf *)domain);
  CuAssertTrue(tc, path.height == 1);
  CuAssertTrue(tc, path.levels[0].depth == 0);
  CuAssertTrue(tc, nametree_is_leaf(*path.levels[0].noderef));
  CuAssertTrue(tc, nametree_untag_leaf(*path.levels[0].noderef) == domain);
  CuAssertTrue(tc, nametree_untag_leaf(tree->root) == domain);

  leaf = nametree_delete(tree, &path, key, key_len, domain->dname);
  CuAssertTrue(tc, leaf == (nameleaf *)domain);
  CuAssertTrue(tc, path.height == 0);
  CuAssertTrue(tc, tree->root == NULL);

  teardown(tc);
}

static void test_nametree_delete_one_of_two_in_root(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct namenode *node;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "foo.");
  domains[1] = create_domain(tc, "bar.");

  key_len = nametree_make_key(key, domains[0]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == (nameleaf *)domains[0]);

  key_len = nametree_make_key(key, domains[1]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == (nameleaf *)domains[1]);
  CuAssertTrue(tc, path.height == 2);

  /* verify tree is as expected */
  node = tree->root;
  CuAssertTrue(tc, !nametree_is_leaf(node));
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->prefix_len == 0);
  CuAssertTrue(tc, node->width == 2);

  memset(&path, 0, sizeof(path));
  leaf = nametree_delete(tree, &path, key, key_len, domains[1]->dname);
  CuAssertTrue(tc, leaf == (nameleaf *)domains[1]);
  CuAssertTrue(tc, path.height == 0);
  node = tree->root;
  CuAssertTrue(tc, nametree_is_leaf(node));
  CuAssertTrue(tc, nametree_untag_leaf(node) == (nameleaf *)domains[0]);

  teardown(tc);
}

static void test_nametree_delete_middle_leaf(CuTest *tc)
{
  uint8_t cnt;
  struct nametree *tree;
  struct namepath path;
  struct namenode4 *node4;
  struct namenode *node;
  struct domain *domains[3];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  const char *names[3] = { "z.", "y.z.", "x.y.z." };

  setup(tc);

  tree = create_tree(tc);
  for (cnt = 0; cnt < 3; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    leaf = nametree_insert(tree, &path, key, key_len, domains[cnt]);
    CuAssertTrue(tc, leaf == (nameleaf *)domains[cnt]);
  }

  key_len = nametree_make_key(key, domains[1]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_delete(tree, &path, key, key_len, domains[1]->dname);
  CuAssertTrue(tc, leaf == (nameleaf *)domains[1]);
  CuAssertTrue(tc, path.height == 1);

  node = tree->root;
  CuAssertTrue(tc, !nametree_is_leaf(node));
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->prefix_len == 2);
  CuAssertTrue(tc, node->width == 2);
  node4 = (struct namenode4 *)node;
  CuAssertTrue(tc, nametree_is_leaf(node4->children[0]));
  CuAssertTrue(tc, nametree_is_leaf(node4->children[1]));

  teardown(tc);
}

static void test_nametree_delete_middle(CuTest *tc)
{
  uint8_t cnt;
  struct nametree *tree;
  struct namepath path;
  struct namenode4 *node4;
  struct namenode *node;
  struct domain *domains[4];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  const char *names[4] = { "z.", "y1.z.", "x1.y2.z.", "x2.y2.z." };

  setup(tc);

  tree = create_tree(tc);
  for (cnt = 0; cnt < 4; cnt++) {
    domains[cnt] = create_domain(tc, names[cnt]);
    key_len = nametree_make_key(key, domains[cnt]->dname);
    memset(&path, 0, sizeof(path));
    nametree_insert(tree, &path, key, key_len, domains[cnt]);
  }

  key_len = nametree_make_key(key, domains[1]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_delete(tree, &path, key, key_len, domains[1]->dname);
  CuAssertTrue(tc, leaf == (nameleaf *)domains[1]);
  CuAssertTrue(tc, path.height == 1);

  node = tree->root;
  CuAssertTrue(tc, !nametree_is_leaf(node));
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->prefix_len == 2);
  CuAssertTrue(tc, node->width == 2);
  node4 = (struct namenode4 *)node;
  CuAssertTrue(tc, nametree_is_leaf(node4->children[0]));
  CuAssertTrue(tc, !nametree_is_leaf(node4->children[1]));
  node = node4->children[1];
  CuAssertTrue(tc, node->type == NAMENODE4);
  CuAssertTrue(tc, node->prefix_len == 3);
  CuAssertTrue(tc, node->width == 2);
  node4 = (struct namenode4 *)node;
  CuAssertTrue(tc, nametree_is_leaf(node4->children[0]));
  CuAssertTrue(tc, nametree_untag_leaf(node4->children[0]) == domains[2]);
  CuAssertTrue(tc, nametree_is_leaf(node4->children[1]));
  CuAssertTrue(tc, nametree_untag_leaf(node4->children[1]) == domains[3]);

  teardown(tc);
}

static void test_nametree_delete_non_existing(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  const char *names[2] = { "y.z.", "x.z." };

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, names[0]);
  domains[1] = create_domain(tc, names[1]);

  /* delete with no tree nodes at all */
  key_len = nametree_make_key(key, domains[0]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_delete(tree, &path, key, key_len, domains[0]->dname);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);

  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == domains[0]);
  CuAssertTrue(tc, path.height == 1);

  /* delete with only non-matching key nodes */
  key_len = nametree_make_key(key, domains[1]->dname);
  memset(&path, 0, sizeof(path));
  leaf = nametree_delete(tree, &path, key, key_len, domains[1]->dname);
  CuAssertTrue(tc, leaf == NULL);
  CuAssertTrue(tc, path.height == 0);

  teardown(tc);
}

static void test_nametree_minimum_leaf(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "bar.foo.");
  domains[1] = create_domain(tc, "baz.foo.");

  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == domains[0]);
  key_len = nametree_make_key(key, domains[1]->dname);
  path.height = 1;
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == domains[1]);

  path.height = 1;
  path.levels[0].depth = 0;
  path.levels[0].noderef = &tree->root;

  leaf = minimum_leaf(tree, &path);
  CuAssertTrue(tc, leaf == domains[0]);
  leaf = next_leaf(tree, &path);
  CuAssertTrue(tc, leaf == domains[1]);
  leaf = next_leaf(tree, &path);
  CuAssertTrue(tc, leaf == NULL);

  teardown(tc);
}

static void test_nametree_maximum_leaf(CuTest *tc)
{
  struct nametree *tree;
  struct namepath path;
  struct domain *domains[2];
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;

  setup(tc);

  tree = create_tree(tc);
  domains[0] = create_domain(tc, "bar.foo.");
  domains[1] = create_domain(tc, "baz.foo.");

  key_len = nametree_make_key(key, domains[0]->dname);
  path.height = 0;
  leaf = nametree_insert(tree, &path, key, key_len, domains[0]);
  CuAssertTrue(tc, leaf == domains[0]);
  key_len = nametree_make_key(key, domains[1]->dname);
  path.height = 0;
  leaf = nametree_insert(tree, &path, key, key_len, domains[1]);
  CuAssertTrue(tc, leaf == domains[1]);

  path.height = 1;
  path.levels[0].depth = 0;
  path.levels[0].noderef = &tree->root;

  leaf = maximum_leaf(tree, &path);
  CuAssertTrue(tc, leaf == domains[1]);
  leaf = previous_leaf(tree, &path);
  CuAssertTrue(tc, leaf == domains[0]);
  leaf = previous_leaf(tree, &path);
  CuAssertTrue(tc, leaf == NULL);

  teardown(tc);
}

CuSuite* reg_cutest_nametree(void) 
{
  CuSuite* suite = CuSuiteNew();
  SUITE_ADD_TEST(suite, test_nametree_findeq_16u8);
  SUITE_ADD_TEST(suite, test_nametree_findgt_16u8);
  SUITE_ADD_TEST(suite, test_nametree_findeq_32u8);
  SUITE_ADD_TEST(suite, test_nametree_findgt_32u8);
  SUITE_ADD_TEST(suite, test_nametree_find_child4);
  SUITE_ADD_TEST(suite, test_nametree_previous_child4);
  SUITE_ADD_TEST(suite, test_nametree_next_child4);
  SUITE_ADD_TEST(suite, test_nametree_find_child16);
  SUITE_ADD_TEST(suite, test_nametree_previous_child16);
  SUITE_ADD_TEST(suite, test_nametree_next_child16);
  SUITE_ADD_TEST(suite, test_nametree_find_child32);
  SUITE_ADD_TEST(suite, test_nametree_previous_child32);
  SUITE_ADD_TEST(suite, test_nametree_next_child32);
  SUITE_ADD_TEST(suite, test_nametree_find_child38);
  SUITE_ADD_TEST(suite, test_nametree_previous_child38);
  SUITE_ADD_TEST(suite, test_nametree_next_child38);
  SUITE_ADD_TEST(suite, test_nametree_find_child48);
  SUITE_ADD_TEST(suite, test_nametree_previous_child48);
  SUITE_ADD_TEST(suite, test_nametree_next_child48);
  SUITE_ADD_TEST(suite, test_nametree_find_child256);
  SUITE_ADD_TEST(suite, test_nametree_previous_child256);
  SUITE_ADD_TEST(suite, test_nametree_next_child256);
  SUITE_ADD_TEST(suite, test_nametree_add_child4);
  SUITE_ADD_TEST(suite, test_nametree_add_child16);
  SUITE_ADD_TEST(suite, test_nametree_add_child32_hostonly);
  SUITE_ADD_TEST(suite, test_nametree_add_child32);
  SUITE_ADD_TEST(suite, test_nametree_add_child38);
  SUITE_ADD_TEST(suite, test_nametree_add_child48);
  SUITE_ADD_TEST(suite, test_nametree_make_key);
  SUITE_ADD_TEST(suite, test_nametree_make_prefix);
  SUITE_ADD_TEST(suite, test_nametree_minimum_leaf);
  SUITE_ADD_TEST(suite, test_nametree_maximum_leaf);
  SUITE_ADD_TEST(suite, test_nametree_insert_single_leaf);
  SUITE_ADD_TEST(suite, test_nametree_insert_single);
  SUITE_ADD_TEST(suite, test_nametree_insert_single_comp);
  SUITE_ADD_TEST(suite, test_nametree_insert_multi);
  SUITE_ADD_TEST(suite, test_nametree_insert_multi_comp);
  SUITE_ADD_TEST(suite, test_nametree_insert_existing);
  SUITE_ADD_TEST(suite, test_nametree_search);
  SUITE_ADD_TEST(suite, test_nametree_search_non_existing);
  SUITE_ADD_TEST(suite, test_nametree_search_previous);
  SUITE_ADD_TEST(suite, test_nametree_search_next);
  SUITE_ADD_TEST(suite, test_nametree_remove_child4);
  SUITE_ADD_TEST(suite, test_nametree_remove_child4_comp);
  SUITE_ADD_TEST(suite, test_nametree_remove_child16);
  SUITE_ADD_TEST(suite, test_nametree_remove_child32);
  SUITE_ADD_TEST(suite, test_nametree_remove_child38);
  SUITE_ADD_TEST(suite, test_nametree_remove_child48);
  SUITE_ADD_TEST(suite, test_nametree_remove_child48_hostonly);
  SUITE_ADD_TEST(suite, test_nametree_remove_child256);
  SUITE_ADD_TEST(suite, test_nametree_delete_single_leaf);
  SUITE_ADD_TEST(suite, test_nametree_delete_one_of_two_in_root);
  SUITE_ADD_TEST(suite, test_nametree_delete_middle_leaf);
  SUITE_ADD_TEST(suite, test_nametree_delete_middle);
  SUITE_ADD_TEST(suite, test_nametree_delete_non_existing);
  return suite;
}
