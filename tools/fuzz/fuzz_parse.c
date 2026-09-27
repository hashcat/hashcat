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
 * allocate. The hashconfig itself comes from tools/asan/hashconfig.c, which
 * the harness in tools/asan/ uses for the same reason. The line is copied into an allocation of exactly its length: see
 * the note in tools/fuzz/fuzz_rule.c about what that means for a read one byte
 * past the end, and about -DFUZZ_NUL_TERMINATE.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "modules.h"

#include "hashconfig.h"

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

  harness_build_hashconfig (&hashconfig, &module_ctx, &uo, &uoe, FUZZ_HASH_MODE);

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
