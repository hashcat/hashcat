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
#include "emu_inc_hash_sha256.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 3;
static const u32   DGST_POS1      = 7;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 6;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_SERVER;
static const char *HASH_NAME      = "ColdFusion 10+";
static const char *HASH_RECIPE    = "sha256(salt . sha1_uc(pass))";
static const u64   KERN_TYPE      = 12600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_BE
                                  | OPTS_TYPE_PT_ADD80;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "3f3473a071b1fb955544e80c81853ca0f1e4f9ee4ca3bf4d2a8a10b5ef5be1f6:6058321484538505215534207835727413038041028036676832416353152201";

#include "hooks_common.c"

const char *module_hash_recipe    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_RECIPE;     }

u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_min = 64;

  return salt_min;
}

u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 salt_max = 64;

  return salt_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len[0]     = 64;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[1]     = 64;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // hash

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);
  digest[4] = hex_to_u32 (hash_pos + 32);
  digest[5] = hex_to_u32 (hash_pos + 40);
  digest[6] = hex_to_u32 (hash_pos + 48);
  digest[7] = hex_to_u32 (hash_pos + 56);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  /**
   * we can precompute the first sha256 transform
   */

  u32 w[16] = { 0 };

  w[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  w[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  w[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  w[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  w[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  w[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  w[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  w[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  w[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  w[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  w[10] = byte_swap_32 (salt->salt_buf[10]);
  w[11] = byte_swap_32 (salt->salt_buf[11]);
  w[12] = byte_swap_32 (salt->salt_buf[12]);
  w[13] = byte_swap_32 (salt->salt_buf[13]);
  w[14] = byte_swap_32 (salt->salt_buf[14]);
  w[15] = byte_swap_32 (salt->salt_buf[15]);

  u32 pc256[8] = { SHA256M_A, SHA256M_B, SHA256M_C, SHA256M_D, SHA256M_E, SHA256M_F, SHA256M_G, SHA256M_H };

  sha256_transform (w + 0, w + 4, w + 8, w + 12, pc256);

  salt->salt_buf_pc[0] = pc256[0];
  salt->salt_buf_pc[1] = pc256[1];
  salt->salt_buf_pc[2] = pc256[2];
  salt->salt_buf_pc[3] = pc256[3];
  salt->salt_buf_pc[4] = pc256[4];
  salt->salt_buf_pc[5] = pc256[5];
  salt->salt_buf_pc[6] = pc256[6];
  salt->salt_buf_pc[7] = pc256[7];

  // Optimized kernels compare the digest before its final addition. Recipe kernels compare the
  // complete digest.

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= pc256[0];
    digest[1] -= pc256[1];
    digest[2] -= pc256[2];
    digest[3] -= pc256[3];
    digest[4] -= pc256[4];
    digest[5] -= pc256[5];
    digest[6] -= pc256[6];
    digest[7] -= pc256[7];
  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[8];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];
  tmp[4] = digest[4];
  tmp[5] = digest[5];
  tmp[6] = digest[6];
  tmp[7] = digest[7];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += salt->salt_buf_pc[0];
    tmp[1] += salt->salt_buf_pc[1];
    tmp[2] += salt->salt_buf_pc[2];
    tmp[3] += salt->salt_buf_pc[3];
    tmp[4] += salt->salt_buf_pc[4];
    tmp[5] += salt->salt_buf_pc[5];
    tmp[6] += salt->salt_buf_pc[6];
    tmp[7] += salt->salt_buf_pc[7];
  }

  tmp[0] = byte_swap_32 (tmp[0]);
  tmp[1] = byte_swap_32 (tmp[1]);
  tmp[2] = byte_swap_32 (tmp[2]);
  tmp[3] = byte_swap_32 (tmp[3]);
  tmp[4] = byte_swap_32 (tmp[4]);
  tmp[5] = byte_swap_32 (tmp[5]);
  tmp[6] = byte_swap_32 (tmp[6]);
  tmp[7] = byte_swap_32 (tmp[7]);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[4], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[5], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[6], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[7], out_buf + out_len); out_len += 8;

  out_buf[out_len] = hashconfig->separator;

  out_len += 1;

  out_len += generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_recipe              = module_hash_recipe;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
}
