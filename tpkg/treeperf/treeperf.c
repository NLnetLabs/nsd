/*
 * treeperf.c -- simple program to measure memory usage per backend
 *
 * Copyright (c) 2001-2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "talloc.h"
#include "util.h"
#include "dname.h"
#include "namedb-treeperf.h"

static void usage(const char *prog)
{
  fprintf(stderr, "Usage: %s READ|COUNT|TIME FILE\n", prog);
  exit(1);
}

#define READ (0)
#define COUNT (1)
#define TIME (2)

int main(int argc, char *argv[])
{
  FILE *file;
  char line[256];
  int mode;
  struct dname *dname;
  struct region *dname_region, *table_region;
  struct domain_table *table = NULL;
  struct domain *domain;

  dname_region = region_create(xalloc, free);
  if (argc != 3) {
    usage(argv[0]);
  } else if (strcmp(argv[1], "read") == 0) {
    mode = READ;
  } else if (strcmp(argv[1], "count") == 0) {
    table_region = region_create(talloc, tfree);
    mode = COUNT;
  } else if (strcmp(argv[1], "time") == 0) {
    table_region = region_create(xalloc, free);
    mode = TIME;
  } else {
    usage(argv[0]);
  }

  assert(dname_region != NULL);
  if (mode == COUNT || mode == TIME) {
    assert(table_region != NULL);
    table = domain_table_create(table_region);
  }

  if ((file = fopen(argv[2], "rb")) == NULL) {
    fprintf(stderr, "Cannot open %s, %s\n", argv[2], strerror(errno));
    exit(1);
  }

  while (fgets(line, sizeof(line), file) != NULL) {
    dname = (struct dname *)dname_parse(dname_region, line);
    if (dname == NULL) {
      fprintf(stderr, "Cannot make dname from %s\n", line);
      exit(1);
    }
    if (mode != READ) {
      domain = domain_table_insert(table, dname);
      if (domain == NULL) {
        fprintf(stderr, "Cannot insert %s\n", line);
        exit(1);
      }
    }
    region_recycle(dname_region, dname, dname_total_size(dname));
  }

  if (mode == COUNT) {
    print_talloc_stats();
  }

  return 0;
}
