/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "emu_general.h"

// These two are declared by inc_platform.h, which says HC_PLUGIN_API through DECLSPEC like every
// other kernel declaration. It says it over an address space qualifier and a volatile the host body
// does not carry, so the two cannot be in one translation unit and the macro is written here as
// well. The bodies are the whole of the host's atomics: one thread runs them.

HC_PLUGIN_API u32 hc_atomic_dec (u32 *p)
{
  return p[0]--;
}

HC_PLUGIN_API u32 hc_atomic_inc (u32 *p)
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
