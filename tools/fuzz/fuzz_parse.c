/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * libFuzzer entry point for one mode's hash line parser.
 *
 * module_hash_decode () is the function that reads a hash file, which is the
 * most attacker controlled input hashcat takes: hand written C with a lot of
 * pointer arithmetic, hex decoding and fixed size buffers, fed a line from
 * wherever the user got their hashes.
 *
 * One mode per binary, because every src/modules/module_XXXXX.c defines
 * module_init, module_hash_decode and the rest of the API with external
 * linkage: two of them in one link is a duplicate symbol. The mode is chosen
 * at build time by FUZZ_HASH_MODE and the module is linked in statically, so
 * there is no dlopen and no plugin to ship beside the binary. tools/fuzz/
 * build.sh builds the list in FUZZ_MODES.
 *
 * Buffers are sized from the module's own dgst_size, esalt_size and
 * hook_salt_size, so an overflow here is an overflow of what hashcat would
 * allocate. The line is copied into an allocation of exactly its length: see
 * the note in tools/fuzz/fuzz_rule.c about what that means for a read one byte
 * past the end, and about -DFUZZ_NUL_TERMINATE.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "modules.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef FUZZ_HASH_MODE
#error "build with -DFUZZ_HASH_MODE=<mode>"
#endif

// no hash line in the tree comes close, and a parser that walks a megabyte of
// separators only makes the campaign slower

#define FUZZ_LINE_MAX 8192

#define IS_SET(f) ((f) != NULL && (f) != MODULE_DEFAULT)

extern void module_init (module_ctx_t *);

static module_ctx_t module_ctx;
static hashconfig_t hashconfig;

// Lifted from tools/asan/parse_harness.c in #4774, which builds the same thing
// for the same reason. Whichever of the two lands second should drop its copy
// and share one.

static void build_hashconfig (hashconfig_t *hashconfig, module_ctx_t *m,
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

int LLVMFuzzerInitialize (int *argc, char ***argv);
int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerInitialize (int *argc, char ***argv)
{
  (void) argc;
  (void) argv;

  user_options_t       uo;
  user_options_extra_t uoe;

  memset (&uo,  0, sizeof (uo));
  memset (&uoe, 0, sizeof (uoe));

  uo.hash_mode = FUZZ_HASH_MODE;

  memset (&module_ctx, 0, sizeof (module_ctx));

  module_init (&module_ctx);

  build_hashconfig (&hashconfig, &module_ctx, &uo, &uoe, FUZZ_HASH_MODE);

  return 0;
}

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0) return 0;
  if (size > FUZZ_LINE_MAX) return 0;

  if (IS_SET (module_ctx.module_hash_decode) == false) return 0;

  // hashcat zeroes these before parsing, in hashes.c, so a parser that writes
  // only some of a field is not reported as reading uninitialised memory

  void   *digest_buf    = calloc (1, hashconfig.dgst_size ? hashconfig.dgst_size : 1);
  salt_t *salt          = (salt_t *) calloc (1, sizeof (salt_t));
  void   *esalt_buf     = hashconfig.esalt_size     ? calloc (1, hashconfig.esalt_size)     : NULL;
  void   *hook_salt_buf = hashconfig.hook_salt_size ? calloc (1, hashconfig.hook_salt_size) : NULL;

  hashinfo_t *hash_info = (hashinfo_t *) calloc (1, sizeof (hashinfo_t));

  #ifdef FUZZ_NUL_TERMINATE
  char *line_buf = (char *) malloc (size + 1);

  line_buf[size] = 0;
  #else
  char *line_buf = (char *) malloc (size);
  #endif

  memcpy (line_buf, data, size);

  module_ctx.module_hash_decode (&hashconfig, digest_buf, salt, esalt_buf,
                                 hook_salt_buf, hash_info, line_buf, (int) size);

  free (line_buf);
  free (hash_info);
  free (hook_salt_buf);
  free (esalt_buf);
  free (salt);
  free (digest_buf);

  return 0;
}
