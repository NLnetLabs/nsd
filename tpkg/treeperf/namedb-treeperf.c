/*
 * namedb.c -- common namedb operations.
 *
 * Copyright (c) 2001-2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

/* incomplete implementation of namedb used for testing */

#include "config.h"

#include <assert.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>

#include "namedb-treeperf.h"
#include "dns.h"
#include "region-allocator.h"

#if defined(TREEPERF_USE_NAMETREE)
static domain_type *
alloc_domain(struct region *region, const uint8_t *name)
{
  size_t labcnt, namelen, size;
  uint8_t laboffs[MAXDOMAINLEN];
  const uint8_t *label;
  struct dname *dname;
  struct domain *domain;

  labcnt = 0;
  namelen = 0;

  label = name;
  for (;;) {
    assert(!label_is_pointer(label));
    laboffs[MAXDOMAINLEN - ++labcnt] = (uint8_t)(label - name);
    namelen += 1 + label_length(label);
    if (label_is_root(label)) {
      break;
    }
    label = label_next(label);
  }

  size = sizeof(struct domain) + ((labcnt + namelen) * sizeof(uint8_t));
  domain = region_alloc(region, size);
  dname = domain_dname(domain);
  dname->label_count = labcnt;
  dname->name_size = namelen;
  memcpy((uint8_t *)dname_label_offsets(dname),
         &laboffs[MAXDOMAINLEN - labcnt],
         labcnt * sizeof(uint8_t));
  memcpy((uint8_t *)dname_name(dname), name, namelen * sizeof(uint8_t));

  return domain;
}

static const struct dname *
namedb_domain_name(const nameleaf *leaf)
{
  return domain_dname((struct domain *)leaf);
}
#endif

static domain_type *
allocate_domain_info(
  domain_table_type* table,
  const dname_type* dname,
  domain_type* parent)
{
  domain_type *domain;

  assert(dname);
  assert(parent);

#if defined(TREEPERF_USE_NAMETREE)
  domain = alloc_domain(
    table->region, dname_label(dname, domain_dname(parent)->label_count));
#else
  domain = region_alloc(table->region, sizeof(domain_type));
#if defined(TREEPERF_USE_RADTREE)
  domain->dname
#else
  domain->node.key
#endif
    = dname_partial_copy(
        table->region, dname, domain_dname(parent)->label_count + 1);
#endif /* TREEPERF_USE_NAMETREE */
  domain->parent = parent;
  domain->wildcard_child_closest_match = domain;
  domain->is_existing = 0;
  domain->is_apex = 0;

  return domain;
}

domain_table_type *domain_table_create(region_type *region)
{
#if !defined(TREEPERF_USE_NAMETREE)
  const dname_type *origin;
#endif
  domain_type *root;
  domain_table_type *table;

  table = region_alloc(region, sizeof(*table));
  table->region = region;

#if defined(TREEPERF_USE_NAMETREE)
  root = alloc_domain(region, (const uint8_t *)"\0");
#else
  origin = dname_make(region, (uint8_t *) "", 0);
  root = region_alloc(region, sizeof(*root));
#if defined(TREEPERF_USE_RADTREE)
  root->dname = origin;
#else
  root->node.key = origin;
#endif /* TREEPERF_USE_RADTREE */
#endif /* TREEPERF_USE_NAMETREE */

  root->parent = NULL;
  root->wildcard_child_closest_match = root;
  root->is_existing = 0;
  root->is_apex = 0;

#if defined(TREEPERF_USE_NAMETREE)
  table->nametree = nametree_create(region, &namedb_domain_name);
  table->nametree->root = nametree_tag_leaf(root);
#elif defined(TREEPERF_USE_RADTREE)
  table->nametree = radix_tree_create(region);
  root->rnode = radname_insert(
    table->nametree, dname_name(root->dname), root->dname->name_size, root);
#else
  table->names_to_domains = rbtree_create(
    region, (int (*)(const void *, const void *))dname_compare);
  rbtree_insert(table->names_to_domains, (rbnode_type *)root);
#endif

  return table;
}

int
domain_table_search(
  domain_table_type *table,
  const dname_type *dname,
  domain_type **closest_match,
  domain_type **closest_encloser)
{
  int exact;
  uint8_t label_match_count;
#if defined(TREEPERF_USE_NAMETREE)
  struct namepath path;
  namekey key;
  uint8_t key_len;
#endif

  assert(table);
  assert(dname);
  assert(closest_match);
  assert(closest_encloser);

#if defined(TREEPERF_USE_NAMETREE)
  path.height = 0;
  key_len = nametree_make_key(key, dname);
  *closest_match = nametree_search(
    table->nametree, &path, key, key_len, dname, NAMETREE_PREVIOUS_CLOSEST);
  exact = (*closest_match != NULL);
  *closest_match = nametree_untag_leaf(*path.levels[path.height - 1].noderef);
#elif defined(TREEPERF_USE_RADTREE)
  exact = radname_find_less_equal(
    table->nametree,
    dname_name(dname),
    dname->name_size,
    (struct radnode**)closest_match);
  *closest_match = (domain_type*)((*(struct radnode**)closest_match)->elem);
#else
  exact = rbtree_find_less_equal(table->names_to_domains, dname, (rbnode_type **) closest_match);
#endif

  assert(*closest_match != NULL);
  *closest_encloser = *closest_match;
  if (exact) {
    return exact;
  }

  label_match_count = dname_label_match_count(
    domain_dname(*closest_encloser), dname);
  assert(label_match_count < dname->label_count);
  while (label_match_count < domain_dname(*closest_encloser)->label_count) {
    (*closest_encloser) = (*closest_encloser)->parent;
    assert(*closest_encloser);
  }

  return 0;
}

domain_type *
domain_table_insert(
  domain_table_type* table,
  const dname_type* dname)
{
  domain_type* closest_encloser;
  domain_type* result;
  int exact;

#if defined(TREEPERF_USE_NAMETREE)
  struct namepath path;
  namekey key;
  uint8_t key_len;
  nameleaf *leaf;
#else
  domain_type* closest_match;
#endif

  assert(table);
  assert(dname);

#if defined(TREEPERF_USE_NAMETREE)
  path.height = 0;
  key_len = nametree_make_key(key, dname);
  closest_encloser = nametree_search(
    table->nametree, &path, key, key_len, dname, 0);
  exact = (closest_encloser != NULL);
#else
  exact = domain_table_search(
    table, dname, &closest_match, &closest_encloser);
#endif

  if (exact) {
    assert(closest_encloser != NULL);
    return closest_encloser;
  }

#if defined(TREEPERF_USE_NAMETREE)
  closest_encloser = nametree_closest_encloser(
    table->nametree, &path, key, key_len, dname);
  path.height--; /* reuse path */
#endif

  assert(closest_encloser != NULL);
  assert(domain_dname(closest_encloser)->label_count < dname->label_count);

  /* Insert new node(s). */
  do {
    result = allocate_domain_info(table, dname, closest_encloser);
#if defined(TREEPERF_USE_NAMETREE)
    key_len = nametree_make_key(key, domain_dname(result));
    leaf = nametree_insert(table->nametree, &path, key, key_len, result);
    assert(leaf == result);
    path.height--; /* reuse path */
#elif defined(TREEPERF_USE_RADTREE)
    result->rnode = radname_insert(
      table->nametree,
      dname_name(result->dname),
      result->dname->name_size,
      result);
#else
    rbtree_insert(table->names_to_domains, (rbnode_type *) result);
#endif

    /*
     * If the newly added domain name is larger than the parent's current
     * wildcard_child_closest_match but smaller or equal to the wildcard
     * domain name, update the parent's wildcard_child_closest_match field.
     */
    if (label_compare(dname_name(domain_dname(result)),
                      (const uint8_t *) "\001*") <= 0
     && dname_compare(domain_dname(result),
                      domain_dname(closest_encloser->wildcard_child_closest_match)) > 0)
    {
      closest_encloser->wildcard_child_closest_match = result;
    }
    closest_encloser = result;
  } while (domain_dname(closest_encloser)->label_count < dname->label_count);

  return result;
}
