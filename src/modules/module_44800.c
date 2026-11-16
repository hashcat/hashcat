/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "parser.h"
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FBE;
static const char *HASH_NAME      = "bcrypt file encryption (.bfe)";
static const u64   KERN_TYPE      = 44800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_COMBI_PURE_SWAP
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1";
static const char *ST_HASH        = "$bfe$0$1$3df99b78ab57b6bebdf53f2b66b69c0b";

#include "hooks_common.c"

// bcrypt (https://bcrypt.sourceforge.net/) is a Blowfish based file encryption
// utility writing .bfe files, not to be confused with the bcrypt password hash.
//
// The passphrase (8 to 56 bytes, longer ones are silently truncated to 56) runs
// through one Blowfish key schedule, then the first 8 passphrase bytes are
// chain-encrypted into the 56 byte key the data is encrypted with, and that key
// is appended to the plaintext so a decrypt can tell a right passphrase from a
// wrong one. The last two encrypted blocks therefore carry the end of that key
// plus up to 7 padding zero bytes, which is what the kernel checks.
//
// Hash format: $bfe$endian$comp$ct
//
//   endian  0 if the file was written on a little-endian machine, else 1
//   comp    compression flag byte of the file
//   ct      the last 16 bytes of the encrypted payload, hex encoded

typedef struct bfe
{
  u32 endian;
  u32 comp;

  u32 ct[4];

} bfe_t;

#include "blowfish_common.c"

static const char *SIGNATURE_BFE = "$bfe$";

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Use tools/bfe2hashcat.py to extract the hash from a .bfe file";
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bfe_t);

  return esalt_size;
}

static const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?a?a?a?a?a?a?a?a";

  return mask;
}

static u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bfe_t *bfe = (bfe_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BFE;

  // signature
  token.len[0]     = 5;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // endian
  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // comp
  token.sep[2]     = '$';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // ct
  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u32 endian = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (endian > 1) return (PARSER_HASH_VALUE);

  const u32 comp = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (comp > 1) return (PARSER_HASH_VALUE);

  memset (bfe, 0, sizeof (bfe_t));

  bfe->endian = endian;
  bfe->comp   = comp;

  for (u32 i = 0; i < 4; i++)
  {
    bfe->ct[i] = hex_to_u32 (token.buf[3] + (i * 8));
  }

  u8 *salt_ptr = (u8 *) salt->salt_buf;

  salt_ptr[0] = (endian == 0) ? 0x54 : 0x45;
  salt_ptr[1] = (u8) comp;

  memcpy (salt_ptr + 2, bfe->ct, 16);

  salt->salt_len = 18;

  digest[0] = bfe->ct[0];
  digest[1] = bfe->ct[1];
  digest[2] = bfe->ct[2];
  digest[3] = bfe->ct[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const bfe_t *bfe = (const bfe_t *) esalt_buf;

  int line_len = snprintf (line_buf, line_size, "%s%u$%u$", SIGNATURE_BFE, bfe->endian, bfe->comp);

  for (u32 i = 0; i < 4; i++)
  {
    u32_to_hex (bfe->ct[i], (u8 *) line_buf + line_len);

    line_len += 8;
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = blowfish_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = blowfish_module_jit_cache_disable;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_usage_notice             = module_usage_notice;
}
