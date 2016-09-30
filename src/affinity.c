/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "affinity.h"

#if defined (__APPLE__)
static void CPU_ZERO (cpu_set_t *cs)
{
  cs->count = 0;
}

static void CPU_SET (int num, cpu_set_t *cs)
{
  cs->count |= (1 << num);
}

static int CPU_ISSET (int num, cpu_set_t *cs)
{
  return (cs->count & (1 << num));
}

static int pthread_setaffinity_np (pthread_t thread, size_t cpu_size, cpu_set_t *cpu_set)
{
  int core;

  for (core = 0; core < (8 * (int) cpu_size); core++)
  {
    if (CPU_ISSET (core, cpu_set)) break;
  }

  thread_affinity_policy_data_t policy = { core };

  const int rc = thread_policy_set (pthread_mach_thread_np (thread), THREAD_AFFINITY_POLICY, (thread_policy_t) &policy, 1);

  if (rc != KERN_SUCCESS)
  {
    log_error ("ERROR: %s : %d", "thread_policy_set()", rc);

    exit (-1);
  }

  return rc;
}
#endif

void set_cpu_affinity (char *cpu_affinity)
{
  #if   defined(_WIN)
  DWORD_PTR aff_mask = 0;
  #elif defined(__FreeBSD__)
  cpuset_t cpuset;
  CPU_ZERO (&cpuset);
  #elif defined(_POSIX)
  cpu_set_t cpuset;
  CPU_ZERO (&cpuset);
  #endif

  if (cpu_affinity)
  {
    char *devices = mystrdup (cpu_affinity);

    char *next = strtok (devices, ",");

    do
    {
      int cpu_id = atoi (next);

      if (cpu_id == 0)
      {
        #if defined (_WIN)
        aff_mask = 0;
        #elif defined (_POSIX)
        CPU_ZERO (&cpuset);
        #endif

        break;
      }

      if (cpu_id > 32)
      {
        log_error ("ERROR: Invalid cpu_id %u specified", cpu_id);

        exit (-1);
      }

      #if defined (_WIN)
      aff_mask |= 1u << (cpu_id - 1);
      #elif defined (_POSIX)
      CPU_SET ((cpu_id - 1), &cpuset);
      #endif

    } while ((next = strtok (NULL, ",")) != NULL);

    myfree (devices);
  }

  #if   defined( _WIN)
  SetProcessAffinityMask (GetCurrentProcess (), aff_mask);
  SetThreadAffinityMask (GetCurrentThread (), aff_mask);
  #elif defined(__FreeBSD__)
  pthread_t thread = pthread_self ();
  pthread_setaffinity_np (thread, sizeof (cpuset_t), &cpuset);
  #elif defined(_POSIX)
  pthread_t thread = pthread_self ();
  pthread_setaffinity_np (thread, sizeof (cpu_set_t), &cpuset);
  #endif
}
