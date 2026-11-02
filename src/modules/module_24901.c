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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_SERVER;
static const char *HASH_NAME      = "Besder Authentication MD5";
static const u64   KERN_TYPE      = 24901;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14;
static const u32   SALT_TYPE      = SALT_TYPE_NONE;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "GRmHbqVh";

#include "hooks_common.c"

u32 dahua_decode (const u32 in)
{
  // chars used (alphabet):
  // 0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz

  if (            in < '0') return -1;
  if (in > '9' && in < 'A') return -1;
  if (in > 'Z' && in < 'a') return -1;
  if (in > 'z'            ) return -1;

  if (in >= 'a')
  {
    return (in - 61);
  }
  else if (in >= 'A')
  {
    return (in - 55);
  }

  return (in - 48);
}

u32 dahua_encode (const u32 in)
{
  if (in < 10)
  {
    return (in + 48);
  }
  else if (in < 36)
  {
    return (in + 55);
  }
  else
  {
    return (in + 61);
  }

  return -1;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 1;

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  const u32 a0 = dahua_decode (hash_pos[0]);
  const u32 a1 = dahua_decode (hash_pos[1]);
  const u32 b0 = dahua_decode (hash_pos[2]);
  const u32 b1 = dahua_decode (hash_pos[3]);
  const u32 c0 = dahua_decode (hash_pos[4]);
  const u32 c1 = dahua_decode (hash_pos[5]);
  const u32 d0 = dahua_decode (hash_pos[6]);
  const u32 d1 = dahua_decode (hash_pos[7]);

  if (a0 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (a1 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (b0 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (b1 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (c0 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (c1 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (d0 == (u32) -1) return (PARSER_HASH_ENCODING);
  if (d1 == (u32) -1) return (PARSER_HASH_ENCODING);

  digest[0] = (a0 << 0) | (a1 << 8);
  digest[1] = (b0 << 0) | (b1 << 8);
  digest[2] = (c0 << 0) | (c1 << 8);
  digest[3] = (d0 << 0) | (d1 << 8);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  out_buf[0] = (u8) dahua_encode ((digest[0] >> 0) & 0xff);
  out_buf[1] = (u8) dahua_encode ((digest[0] >> 8) & 0xff);
  out_buf[2] = (u8) dahua_encode ((digest[1] >> 0) & 0xff);
  out_buf[3] = (u8) dahua_encode ((digest[1] >> 8) & 0xff);
  out_buf[4] = (u8) dahua_encode ((digest[2] >> 0) & 0xff);
  out_buf[5] = (u8) dahua_encode ((digest[2] >> 8) & 0xff);
  out_buf[6] = (u8) dahua_encode ((digest[3] >> 0) & 0xff);
  out_buf[7] = (u8) dahua_encode ((digest[3] >> 8) & 0xff);

  const int out_len = 8;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}


