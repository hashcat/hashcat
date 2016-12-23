/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "shared.h"

bool is_power_of_2 (const u32 v)
{
  return (v && !(v & (v - 1)));
}

u32 get_random_num (const u32 min, const u32 max)
{
  if (min == max) return (min);

  return (((u32) rand () % (max - min)) + min);
}

u32 mydivc32 (const u32 dividend, const u32 divisor)
{
  u32 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

u64 mydivc64 (const u64 dividend, const u64 divisor)
{
  u64 quotient = dividend / divisor;

  if (dividend % divisor) quotient++;

  return quotient;
}

char *filename_from_filepath (char *filepath)
{
  char *ptr = NULL;

  if ((ptr = strrchr (filepath, '/')) != NULL)
  {
    ptr++;
  }
  else if ((ptr = strrchr (filepath, '\\')) != NULL)
  {
    ptr++;
  }
  else
  {
    ptr = filepath;
  }

  return ptr;
}

void naive_replace (char *s, const char key_char, const char replace_char)
{
  const size_t len = strlen (s);

  for (size_t in = 0; in < len; in++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s[in] = replace_char;
    }
  }
}

void naive_escape (char *s, size_t s_max, const char key_char, const char escape_char)
{
  char s_escaped[1024] = { 0 };

  size_t s_escaped_max = sizeof (s_escaped);

  const size_t len = strlen (s);

  for (size_t in = 0, out = 0; in < len; in++, out++)
  {
    const char c = s[in];

    if (c == key_char)
    {
      s_escaped[out] = escape_char;

      out++;
    }

    if (out == s_escaped_max - 2) break;

    s_escaped[out] = c;
  }

  strncpy (s, s_escaped, s_max - 1);
}

void hc_asprintf (char **strp, const char *fmt, ...)
{
  va_list args;
  va_start (args, fmt);
  int rc __attribute__((unused));
  rc = vasprintf (strp, fmt, args);
  va_end (args);
}

#if defined (_POSIX)
int hc_stat (const char *pathname, hc_stat_t *buf)
{
  return stat (pathname, buf);
}

int hc_fstat (int fd, hc_stat_t *buf)
{
  return fstat (fd, buf);
}
#endif

#if defined (_WIN)
int hc_stat (const char *pathname, hc_stat_t *buf)
{
  return stat64 (pathname, buf);
}

int hc_fstat (int fd, hc_stat_t *buf)
{
  return fstat64 (fd, buf);
}
#endif

void hc_sleep_msec (const u32 msec)
{
  #if defined (_WIN)
  Sleep (msec);
  #else
  usleep (msec * 1000);
  #endif
}

void hc_sleep (const u32 sec)
{
  #if defined (_WIN)
  Sleep (sec * 1000);
  #else
  sleep (sec);
  #endif
}

#if defined (_WIN)
#define __WINDOWS__
#endif
#include "sort_r.h"
#if defined (_WIN)
#undef __WINDOWS__
#endif

void hc_qsort_r (void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  sort_r (base, nmemb, size, compar, arg);
}

void *hc_bsearch_r (const void *key, const void *base, size_t nmemb, size_t size, int (*compar) (const void *, const void *, void *), void *arg)
{
  for (size_t l = 0, r = nmemb; r; r >>= 1)
  {
    const size_t m = r >> 1;

    const size_t c = l + m;

    const char *next = (char *) base + (c * size);

    const int cmp = (*compar) (key, next, arg);

    if (cmp > 0)
    {
      l += m + 1;

      r--;
    }

    if (cmp == 0) return ((void *) next);
  }

  return (NULL);
}

void setup_environment_variables ()
{
  char *compute = getenv ("COMPUTE");

  if (compute)
  {
    static char display[100];

    snprintf (display, sizeof (display) - 1, "DISPLAY=%s", compute);

    putenv (display);
  }
  else
  {
    if (getenv ("DISPLAY") == NULL)
      putenv ((char *) "DISPLAY=:0");
  }

  if (getenv ("GPU_FORCE_64BIT_PTR") == NULL)
    putenv ((char *) "GPU_FORCE_64BIT_PTR=1");

  if (getenv ("GPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("GPU_SINGLE_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_SINGLE_ALLOC_PERCENT=100");

  if (getenv ("GPU_MAX_HEAP_SIZE") == NULL)
    putenv ((char *) "GPU_MAX_HEAP_SIZE=100");

  if (getenv ("CPU_FORCE_64BIT_PTR") == NULL)
    putenv ((char *) "CPU_FORCE_64BIT_PTR=1");

  if (getenv ("CPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("CPU_SINGLE_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_SINGLE_ALLOC_PERCENT=100");

  if (getenv ("CPU_MAX_HEAP_SIZE") == NULL)
    putenv ((char *) "CPU_MAX_HEAP_SIZE=100");

  if (getenv ("GPU_USE_SYNC_OBJECTS") == NULL)
    putenv ((char *) "GPU_USE_SYNC_OBJECTS=1");

  if (getenv ("CUDA_CACHE_DISABLE") == NULL)
    putenv ((char *) "CUDA_CACHE_DISABLE=1");

  if (getenv ("POCL_KERNEL_CACHE") == NULL)
    putenv ((char *) "POCL_KERNEL_CACHE=0");
}

void setup_umask ()
{
  umask (077);
}

void setup_seeding (const bool rp_gen_seed_chgd, const u32 rp_gen_seed)
{
  if (rp_gen_seed_chgd == true)
  {
    srand (rp_gen_seed);
  }
  else
  {
    time_t ts;

    time (&ts);

    srand (ts);
  }
}