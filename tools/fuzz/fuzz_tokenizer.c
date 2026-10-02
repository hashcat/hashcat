/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * libFuzzer entry point for the token splitter.
 *
 * input_tokenizer () sits under most of the 600 hash line parsers: a module
 * declares how many fields its format has, what separates them, how long each
 * one may be and what it must look like, and the tokenizer cuts the line up
 * and checks it against that. A parser sweep reaches it only along the paths
 * one valid example hash takes, and only with the token spec that one module
 * declares.
 *
 * So the spec is part of the input here. The first bytes describe the token
 * layout and the rest is the line, which lets the fuzzer reach combinations of
 * attributes, separators and lengths that no module in the tree declares today
 * but the next one might.
 *
 * Layout of the input:
 *
 *   byte 0        token_cnt, 1 to MAX_FUZZ_TOKENS
 *   byte 1        which signature from SIGNATURES the first token must carry
 *   then per token, 5 bytes:
 *     0, 1        attribute bits, TOKEN_ATTR_* as a 13 bit mask
 *     2           separator byte
 *     3           len_min, and the fixed length where the token is fixed
 *     4           len_max, as an offset above len_min
 *   the rest      the line to split
 *
 * The line is copied into an allocation of exactly its length. See the note in
 * tools/fuzz/fuzz_rule.c about what that means for a read one byte past the
 * end, and about -DFUZZ_NUL_TERMINATE.
 *
 * See tools/fuzz/README.md for how to build and run it.
 */

#include "common.h"
#include "types.h"
#include "parser.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define MAX_FUZZ_TOKENS 8

// Real signatures, so the fuzzer does not have to guess one byte at a time to
// get past TOKEN_ATTR_VERIFY_SIGNATURE. They are the shapes the tree uses: a
// dollar wrapped tag, a bare prefix, a single character and the empty one.

static const char *SIGNATURES[] =
{
  "$test$",
  "$1$",
  "$pkzip2$",
  "SCRYPT:",
  "*",
  "",
};

#define SIGNATURES_CNT (sizeof (SIGNATURES) / sizeof (SIGNATURES[0]))

// every TOKEN_ATTR_* bit that exists, so an unknown bit is never fuzzed in

#define TOKEN_ATTR_MASK (TOKEN_ATTR_FIXED_LENGTH       \
                       | TOKEN_ATTR_SEPARATOR_FARTHEST \
                       | TOKEN_ATTR_OPTIONAL_ROUNDS    \
                       | TOKEN_ATTR_VERIFY_SIGNATURE   \
                       | TOKEN_ATTR_VERIFY_LENGTH      \
                       | TOKEN_ATTR_VERIFY_DIGIT       \
                       | TOKEN_ATTR_VERIFY_FLOAT       \
                       | TOKEN_ATTR_VERIFY_HEX         \
                       | TOKEN_ATTR_VERIFY_BASE64A     \
                       | TOKEN_ATTR_VERIFY_BASE64B     \
                       | TOKEN_ATTR_VERIFY_BASE64C     \
                       | TOKEN_ATTR_VERIFY_BASE58      \
                       | TOKEN_ATTR_VERIFY_BECH32)

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput (const uint8_t *data, size_t size)
{
  if (size < 2) return 0;

  size_t pos = 0;

  const int token_cnt = 1 + (data[pos++] % MAX_FUZZ_TOKENS);

  hc_token_t token;

  memset (&token, 0, sizeof (token));

  token.token_cnt      = token_cnt;
  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURES[data[pos++] % SIGNATURES_CNT];

  for (int i = 0; i < token_cnt; i++)
  {
    if ((size - pos) < 5) return 0;

    const int attr = ((data[pos] << 8) | data[pos + 1]) & TOKEN_ATTR_MASK;

    pos += 2;

    token.attr[i]    = attr;
    token.sep[i]     = data[pos++];
    token.len_min[i] = data[pos++];
    token.len_max[i] = token.len_min[i] + data[pos++];

    // A token with no separator is advanced over by its length, so the length
    // is the only thing that can keep it inside the line. Two specs are held
    // back here, both of which say something about the token spec rather than
    // about the line:
    //
    //   length zero, which leaves the next token pointing at nothing and is
    //   dereferenced rather than rejected,
    //
    //   and a length the tokenizer does not measure against what is left,
    //   which walks the next token past the end of a short line. Only
    //   TOKEN_ATTR_FIXED_LENGTH makes it measure, so that is set here.
    //
    // Both are reachable from a module, not from a hash line: module_34300.c
    // declares exactly the second one and guards it with its own line_len
    // check before the tokenizer is called. Fuzzing them would report the
    // same two non findings for the length of the campaign.

    if (token.sep[i] == 0)
    {
      if (token.len_min[i] == 0) token.len_min[i] = 1;

      token.attr[i] |= TOKEN_ATTR_FIXED_LENGTH;
    }

    // a fixed length token is measured by len, not by len_min

    token.len[i]     = token.len_min[i];
  }

  const size_t line_len = size - pos;

  #ifdef FUZZ_NUL_TERMINATE
  u8 *line_buf = (u8 *) malloc (line_len + 1);

  line_buf[line_len] = 0;
  #else
  u8 *line_buf = (u8 *) malloc (line_len ? line_len : 1);
  #endif

  memcpy (line_buf, data + pos, line_len);

  input_tokenizer (line_buf, (int) line_len, &token);

  free (line_buf);

  return 0;
}
