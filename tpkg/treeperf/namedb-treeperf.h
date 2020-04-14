/*
 * namedb.h -- nsd(8) internal namespace database definitions
 *
 * Copyright (c) 2001-2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

/* incomplete implementation of namedb used for testing */

#ifndef _NAMEDB_H
#define _NAMEDB_H

#include "dname.h"
#if defined(TREEPERF_USE_NAMETREE)
# include "nametree.h"
#elif defined(TREEPERF_USE_RADTREE)
# include "radtree.h"
#else
# include "rbtree.h"
#endif

typedef struct domain domain_type;

struct domain
{
#if defined(TREEPERF_USE_RADTREE)
  struct radnode* rnode;
  const dname_type* dname;
#elif defined(TREEPERF_USE_RBTREE)
  rbnode_type node;
#endif
  domain_type* parent;
  domain_type* wildcard_child_closest_match;

  /* other members left out for convenience */

  /* domain name exists (see wildcard clarification draft) */
  unsigned is_existing : 1;
  unsigned is_apex : 1;
#if defined(TREEPERF_USE_NAMETREE)
  const dname_type dname;
#endif
};

static inline dname_type *
domain_dname(domain_type* domain)
{
#if defined(TREEPERF_USE_NAMETREE)
  return (dname_type *)&domain->dname;
#elif defined(TREEPERF_USE_RADTREE)
  return (dname_type *) domain->dname;
#else
  return (dname_type *) domain->node.key;
#endif
}

static inline const dname_type *
domain_dname_const(const domain_type* domain)
{
#if defined(TREEPERF_USE_NAMETREE)
  return &domain->dname;
#elif defined(TREEPERF_USE_RADTREE)
  return domain->dname;
#else
  return (const dname_type *) domain->node.key;
#endif
}

typedef struct domain_table domain_table_type;

struct domain_table {
  region_type *region;
#if defined(TREEPERF_USE_NAMETREE)
  struct nametree *nametree;
#elif defined(TREEPERF_USE_RADTREE)
  struct radtree *nametree;
#else
  rbtree_type *names_to_domains;
#endif
  /* other members left out for convenience */
};

domain_table_type *
domain_table_create(
  region_type *region);

int
domain_table_search(
  domain_table_type* table,
  const dname_type* dname,
  domain_type **closest_match,
  domain_type **closest_encloser);

domain_type *domain_table_insert(
  domain_table_type *table,
  const dname_type *dname);

#endif /* _NAMEDB_H_ */
