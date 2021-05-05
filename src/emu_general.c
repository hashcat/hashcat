/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "emu_general.h"

u32 hc_atomic_dec (u32 *p)
{
  return p[0]--;
}

u32 hc_atomic_inc (u32 *p)
{
  return p[0]++;
}

size_t get_global_id (u32 dimindx __attribute__((unused)))
{
  return 0;
}

size_t get_local_id (u32 dimindx __attribute__((unused)))
{
  return 0;
}

size_t get_local_size (u32 dimindx __attribute__((unused)))
{
  return 0;
}
