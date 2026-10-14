/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * libFuzzer entry point for the mask parser.
 *
 * mask_css_parse () turns a mask, the ?d?l?u?1 language -a 3 and the hybrid
 * attacks take, into the per position charset table the engine walks. It
 * expands the ?x groups, folds in the custom charsets, and handles the literal
 * and escape bytes, all by hand over a user supplied string. A mask is as
 * attacker controlled as a rule or a hash line: it comes off the command line
 * or an hcmask file and is parsed before anything is checked.
 *
 * The mask is the input, NUL terminated because the parser takes a C string.
 * The parser lives in a core build file, so build.sh compiles src/mpsp.c with
 * HC_CORE_BUILD and drops the functions this does not reach at link time.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "mpsp.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// mask_css_parse wants at least this many css entries and rejects a shorter buffer. The table is
// allocated at exactly this size so a write past the last position is a write past the allocation.
#define CSS_CNT 256

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size == 0) return 0;

  // every position of a mask takes one css entry, and a literal is one byte for one position, so a
  // mask longer than the table holds is out of range and only wastes executions

  if (size > CSS_CNT) return 0;

  char *mask = (char *) malloc (size + 1);

  memcpy (mask, data, size);

  mask[size] = 0;

  // The parser reads the custom charsets off user_options and its scratch flags off mask_ctx, and
  // checks that hashconfig is present. A zeroed set of each is a valid empty configuration. The
  // four charsets are filled so the ?1 to ?4 groups in the mask are reachable rather than rejected.

  hashcat_ctx_t   hashcat_ctx;
  mask_ctx_t      mask_ctx;
  hashconfig_t    hashconfig;
  user_options_t  user_options;

  memset (&hashcat_ctx,  0, sizeof (hashcat_ctx));
  memset (&mask_ctx,     0, sizeof (mask_ctx));
  memset (&hashconfig,   0, sizeof (hashconfig));
  memset (&user_options, 0, sizeof (user_options));

  user_options.custom_charset_1 = (char *) "?l?d";
  user_options.custom_charset_2 = (char *) "?u?d";
  user_options.custom_charset_3 = (char *) "abc?s";
  user_options.custom_charset_4 = (char *) "0123456789";

  hashcat_ctx.mask_ctx     = &mask_ctx;
  hashcat_ctx.hashconfig   = &hashconfig;
  hashcat_ctx.user_options = &user_options;

  cs_t *css_buf = (cs_t *) calloc (CSS_CNT, sizeof (cs_t));

  u32 css_cnt = 0;

  mask_css_parse (&hashcat_ctx, mask, css_buf, CSS_CNT, &css_cnt);

  free (css_buf);
  free (mask);

  return 0;
}
