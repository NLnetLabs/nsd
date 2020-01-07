/*
 * cpuset.c -- CPU affinity.
 *
 * Copyright (c) 2020, NLnet Labs. All rights reserved.
 *
 * See LICENSE for the license.
 *
 */
#include "cpuset.h"

#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef HAVE_CPUSET_CREATE
#if __linux__ || __FreeBSD__
cpuset_t *cpuset_create(void)
{
  cpuset_t *set = calloc(1, sizeof(*set));
  return set;
}
#endif
#endif /* !HAVE_CPUSET_CREATE */

#ifndef HAVE_CPUSET_DESTROY
#if __linux__ || __FreeBSD__
void cpuset_destroy(cpuset_t *set)
{
  free(set);
}
#endif
#endif /* !HAVE_CPUSET_DESTROY */

#ifndef HAVE_CPUSET_ZERO
#if __linux__ || __FreeBSD__
void cpuset_zero(cpuset_t *set)
{
  CPU_ZERO(set);
}
#endif
#endif /* !HAVE_CPUSET_ZERO */

#ifndef HAVE_CPUSET_SET
#if __linux__ || __FreeBSD__
int cpuset_set(cpuid_t cpu, cpuset_t *set)
{
  CPU_SET(cpu, set);
  return 0;
}
#endif
#endif /* !HAVE_CPUSET_SET */

#ifndef HAVE_CPUSET_CLR
#if __linux__ || __FreeBSD__
int cpuset_clr(cpuid_t cpu, cpuset_t *set)
{
  CPU_CLR(cpu, set);
  return 0;
}
#endif
#endif /* !HAVE_CPUSET_CLR */

#ifndef HAVE_CPUSET_ISSET
#if __linux__ || __FreeBSD__
int cpuset_isset(cpuid_t cpu, const cpuset_t *set)
{
  return CPU_ISSET(cpu, set);
}
#endif
#endif /* !HAVE_CPUSET_ISSET */

#ifndef HAVE_CPUSET_SIZE
#if __linux__ || __FreeBSD__
size_t cpuset_size(const cpuset_t *set)
{
  return sizeof(*set);
}
#endif
#endif /* !HAVE_CPUSET_SIZE */

#if __linux__
void cpuset_or(cpuset_t *destset, const cpuset_t *srcset)
{
  CPU_OR(destset, destset, srcset);
}
#endif
#if __FreeBSD__
void cpuset_or(cpuset_t *destset, const cpuset_t *srcset)
{
  CPU_OR(destset, srcset);
}
#endif
