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

void hc_sleep_ms (const u32 msec)
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

  if (getenv ("GPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "GPU_MAX_ALLOC_PERCENT=100");

  if (getenv ("CPU_MAX_ALLOC_PERCENT") == NULL)
    putenv ((char *) "CPU_MAX_ALLOC_PERCENT=100");

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