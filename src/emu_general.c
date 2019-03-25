/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "emu_general.h"

u32 atomic_dec (u32 *p)
{
  return *p--;
}

u32 atomic_inc (u32 *p)
{
  return *p++;
}

size_t get_global_id (uint dimindx __attribute__((unused)))
{
  return 0;
}

size_t get_local_id (uint dimindx __attribute__((unused)))
{
  return 0;
}

size_t get_local_size (uint dimindx __attribute__((unused)))
{
  return 0;
}
