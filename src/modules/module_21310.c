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
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH_SALTED;
static const char *HASH_NAME      = "md5($salt1.sha1($salt2.$pass))";
static const u64   KERN_TYPE      = 21310;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14;
static const u32   SALT_TYPE      = SALT_TYPE_GENERIC;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "dc91b5a658ef4b7d859e90742f340e24:708237:d270e9eea5802e346bcaa9b229f37766";

#include "hooks_common.c"

typedef struct md5_double_salt
{
  u32 salt1_buf[64];
  int salt1_len;

  u32 salt2_buf[64];
  int salt2_len;

} md5_double_salt_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (md5_double_salt_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  md5_double_salt_t *md5_double_salt = (md5_double_salt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.sep[0]     = ':';
  token.len[0]     = 32;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[1]     = ':';
  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]     = ':';
  token.len_min[2] = SALT_MIN;
  token.len_max[2] = SALT_MAX;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  if (hashconfig->opts_type & OPTS_TYPE_ST_HEX)
  {
    token.len_min[1] *= 2;
    token.len_max[1] *= 2;

    token.attr[1] |= TOKEN_ATTR_VERIFY_HEX;

    token.len_min[2] *= 2;
    token.len_max[2] *= 2;

    token.attr[2] |= TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  memset (md5_double_salt->salt1_buf, 0, sizeof (md5_double_salt->salt1_buf));

  const bool parse_rc1 = generic_salt_decode (hashconfig, token.buf[1], token.len[1], (u8 *) md5_double_salt->salt1_buf, &md5_double_salt->salt1_len);

  if (parse_rc1 == false) return (PARSER_SALT_LENGTH);

  memset (md5_double_salt->salt2_buf, 0, sizeof (md5_double_salt->salt2_buf));

  const bool parse_rc2 = generic_salt_decode (hashconfig, token.buf[2], token.len[2], (u8 *) md5_double_salt->salt2_buf, &md5_double_salt->salt2_len);

  if (parse_rc2 == false) return (PARSER_SALT_LENGTH);

  for (int i = 0; i < 64; i++)
  {
    md5_double_salt->salt2_buf[i] = byte_swap_32 (md5_double_salt->salt2_buf[i]);
  }

  // make salt sorter happy

  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, md5_double_salt->salt1_buf, md5_double_salt->salt1_len);
  md5_update (&md5_ctx, md5_double_salt->salt2_buf, md5_double_salt->salt2_len);
  md5_final  (&md5_ctx);

  salt->salt_buf[0] = md5_ctx.h[0];
  salt->salt_buf[1] = md5_ctx.h[1];
  salt->salt_buf[2] = md5_ctx.h[2];
  salt->salt_buf[3] = md5_ctx.h[3];

  salt->salt_len = 16;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const md5_double_salt_t *md5_double_salt = (const md5_double_salt_t *) esalt_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[4];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += MD5M_A;
    tmp[1] += MD5M_B;
    tmp[2] += MD5M_C;
    tmp[3] += MD5M_D;
  }

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  u32_to_hex (tmp[0], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[1], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[2], out_buf + out_len); out_len += 8;
  u32_to_hex (tmp[3], out_buf + out_len); out_len += 8;

  out_buf[out_len] = ':';

  out_len += 1;

  out_len += generic_salt_encode (hashconfig, (const u8 *) md5_double_salt->salt1_buf, md5_double_salt->salt1_len, out_buf + out_len);

  out_buf[out_len] = ':';

  out_len += 1;

  u32 salt2_buf[64];

  for (int i = 0; i < 64; i++)
  {
    salt2_buf[i] = byte_swap_32 (md5_double_salt->salt2_buf[i]);
  }

  out_len += generic_salt_encode (hashconfig, (const u8 *) salt2_buf, md5_double_salt->salt2_len, out_buf + out_len);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
}
