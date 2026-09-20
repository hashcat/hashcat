/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * The hashconfig a parser sees, built the way interface.c builds it.
 *
 * Both harnesses need this and neither can call hashconfig_init (): it wants a
 * hashcat_ctx, a backend and a folder layout, none of which a parser reads.
 * tools/asan/parse_harness.c and tools/fuzz/fuzz_parse.c share this one copy.
 */

#include "common.h"
#include "types.h"
#include "modules.h"

#include "hashconfig.h"

#include <string.h>

#define IS_SET(f) ((f) != NULL && (f) != MODULE_DEFAULT)

void harness_build_hashconfig (hashconfig_t *hashconfig, module_ctx_t *m,
                              user_options_t *uo, user_options_extra_t *uoe,
                              const int hash_mode)
{
  memset (hashconfig, 0, sizeof (hashconfig_t));

  hashconfig->hash_mode = (u32) hash_mode;

  // Mirrors the subset of hashconfig_init() that a parser can actually
  // observe. Anything a parser reads that is not set here would be read as
  // zero, which is why the harness reports a parser that depends on
  // something it should not, rather than silently guessing a value.

  if (IS_SET (m->module_separator))       hashconfig->separator      = m->module_separator       (hashconfig, uo, uoe);
  else                                    hashconfig->separator      = ':';

  if (IS_SET (m->module_dgst_size))       hashconfig->dgst_size      = m->module_dgst_size       (hashconfig, uo, uoe);
  if (IS_SET (m->module_salt_type))       hashconfig->salt_type      = m->module_salt_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_opts_type))       hashconfig->opts_type      = m->module_opts_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_opti_type))       hashconfig->opti_type      = m->module_opti_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_kern_type))       hashconfig->kern_type      = m->module_kern_type       (hashconfig, uo, uoe);
  if (IS_SET (m->module_esalt_size))      hashconfig->esalt_size     = m->module_esalt_size      (hashconfig, uo, uoe);
  if (IS_SET (m->module_hook_salt_size))  hashconfig->hook_salt_size = m->module_hook_salt_size  (hashconfig, uo, uoe);
  if (IS_SET (m->module_tmp_size))        hashconfig->tmp_size       = m->module_tmp_size        (hashconfig, uo, uoe);
  // Defaults, mirroring default_pw_max()/default_salt_max() in interface.c.
  // These are NOT optional: most modules leave these fields to the defaults,
  // and a zero salt_max makes every generic salted parser reject its own
  // example hash with PARSER_SALT_LENGTH, which would look like the harness
  // "passing" while never exercising a single line of parser code.
  // The interface.c versions are not exported (-fvisibility=hidden), so the
  // logic is restated here; keep in sync with src/interface.c:820,910.

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;
  const bool utf16_salt       = (hashconfig->opts_type & (OPTS_TYPE_ST_UTF16LE | OPTS_TYPE_ST_UTF16BE)) != 0;

  if (IS_SET (m->module_pw_min))   hashconfig->pw_min   = m->module_pw_min   (hashconfig, uo, uoe);
  else                             hashconfig->pw_min   = PW_MIN;

  if (IS_SET (m->module_pw_max))   hashconfig->pw_max   = m->module_pw_max   (hashconfig, uo, uoe);
  else                             hashconfig->pw_max   = optimized_kernel ? PW_MAX_OLD : PW_MAX;

  if (IS_SET (m->module_salt_min)) hashconfig->salt_min = m->module_salt_min (hashconfig, uo, uoe);
  else                             hashconfig->salt_min = SALT_MIN;

  if (IS_SET (m->module_salt_max))
  {
    hashconfig->salt_max = m->module_salt_max (hashconfig, uo, uoe);
  }
  else
  {
    u32 salt_max = SALT_MAX;

    if (optimized_kernel == true)
    {
      salt_max = SALT_MAX_OLD;

      if (utf16_salt == true) salt_max /= 2;
    }

    if (hashconfig->salt_type == SALT_TYPE_GENERIC)
    {
      if (hashconfig->opts_type & OPTS_TYPE_ST_HEX) salt_max *= 2;
    }

    hashconfig->salt_max = salt_max;
  }

  if (hashconfig->dgst_size == 0) hashconfig->dgst_size = 64;
}
