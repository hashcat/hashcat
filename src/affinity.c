/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
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

  return thread_policy_set (pthread_mach_thread_np (thread), THREAD_AFFINITY_POLICY, (thread_policy_t) &policy, 1);
}
#endif

#if defined (__FreeBSD__)
#include <pthread_np.h>
typedef cpuset_t cpu_set_t;
#endif

int set_cpu_affinity (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
#if defined (__CYGWIN__)
  return 0;
#else
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->cpu_affinity == NULL) return 0;

  #if defined (_WIN)
  DWORD_PTR aff_mask = 0;
  #else
  cpu_set_t cpuset;
  CPU_ZERO (&cpuset);
  #endif

  char *devices = hcstrdup (user_options->cpu_affinity);

  if (devices == NULL) return -1;

  char *saveptr = NULL;

  char *next = strtok_r (devices, ",", &saveptr);

  do
  {
    const int cpu_id = (const int) strtol (next, NULL, 10);

    if (cpu_id == 0)
    {
      #if defined (_WIN)
      aff_mask = 0;
      #else
      CPU_ZERO (&cpuset);
      #endif

      break;
    }

    if (cpu_id > 32)
    {
      event_log_error (hashcat_ctx, "Invalid cpu_id %d specified.", cpu_id);

      hcfree (devices);

      return -1;
    }

    #if defined (_WIN)
    aff_mask |= 1u << (cpu_id - 1);
    #else
    CPU_SET ((cpu_id - 1), &cpuset);
    #endif

  } while ((next = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

  hcfree (devices);

  #if defined (_WIN)

  SetProcessAffinityMask (GetCurrentProcess (), aff_mask);

  if (SetThreadAffinityMask (GetCurrentThread (), aff_mask) == 0)
  {
    event_log_error (hashcat_ctx, "%s", "SetThreadAffinityMask().");

    return -1;
  }

  #else

  pthread_t thread = pthread_self ();

  if (pthread_setaffinity_np (thread, sizeof (cpu_set_t), &cpuset) == -1)
  {
    event_log_error (hashcat_ctx, "%s", "pthread_setaffinity_np().");

    return -1;
  }

  #endif

  return 0;
#endif
}
