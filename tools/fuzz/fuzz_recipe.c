/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * libFuzzer entry point for the hash recipe compiler.
 *
 * recipe_compile () parses a --hash-recipe string, the small language mode 4000
 * uses to say how a hash is built: md5_bin (salt . pass), loops, pbkdf2, aes,
 * cut, trunc and so on. It is hand written text parsing over a user supplied
 * string, the same class of input the rule and mask parsers take. Nothing
 * fuzzes it today: the mode 4000 parse target compiles one fixed recipe and
 * then fuzzes the hash line, so the recipe grammar itself sees one input ever.
 *
 * The input is the recipe, NUL terminated because recipe_compile () takes a C
 * string and every caller hands it one.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "recipe.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0) return 0;

  // recipe_compile () parses a source of any length. module_recipe () caches the compiled program
  // in a 4096 byte buffer, but a source that does not fit is still compiled on every line rather
  // than skipped, so there is no length to bound the input to here.

  char *src = (char *) malloc (size + 1);

  memcpy (src, data, size);

  src[size] = 0;

  recipe_prog_t prog;

  memset (&prog, 0, sizeof (prog));

  recipe_compile (&prog, src);

  free (src);

  return 0;
}
