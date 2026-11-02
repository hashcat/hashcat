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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RFID;
static const char *HASH_NAME      = "iClass Legacy (partial div_key + iClass Cipher, dual-MAC)";
static const u64   KERN_TYPE      = 36901;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "\x1f\xf5\x89\xb2\xe1";
static const char *ST_HASH        = "$iclass_leg$0003020102060301$feffffffffffffff00000000$1d49c9da$feffffffffffffff00000000$1d49c9da";

static const char *SIGNATURE_ICLASS_LEG = "$iclass_leg$";

#include "hooks_common.c"

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 5;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 5;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?b?b?b?b?b";

  return mask;
}

static void cpu_gen_key (const u8 *partial_key, u64 index, u8 *key_out)
{
  for (int i = 0; i < 8; i++)
  {
    key_out[i] = partial_key[i];
  }

  u64 carry = index;

  for (int j = 7; j >= 0; j--)
  {
    key_out[j] = (u8) ((partial_key[j] & 0x07) | ((carry & 0x1F) << 3));

    carry >>= 5;

    if (carry == 0) break;
  }
}

int module_build_plain_postprocess (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const void *tmps, const u32 *src_buf, MAYBE_UNUSED const size_t src_sz, MAYBE_UNUSED const int src_len, u32 *dst_buf, MAYBE_UNUSED const size_t dst_sz)
{
  const u8 *pw = (const u8 *) src_buf;

  u64 index = (u64) pw[0]
            | ((u64) pw[1] <<  8)
            | ((u64) pw[2] << 16)
            | ((u64) pw[3] << 24)
            | ((u64) pw[4] << 32);

  const char *ob = (const char *) hashes->out_buf;

  u8 pk[8] = { 0 };

  if (ob != NULL && strncmp (ob, SIGNATURE_ICLASS_LEG, 12) == 0)
  {
    hex_decode ((const u8 *) (ob + 12), 16, pk);
  }

  u8 div_key[8];

  cpu_gen_key (pk, index, div_key);

  return snprintf ((char *) dst_buf, dst_sz,
                   "%02X%02X%02X%02X%02X%02X%02X%02X",
                   div_key[0], div_key[1], div_key[2], div_key[3],
                   div_key[4], div_key[5], div_key[6], div_key[7]);
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt         = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ICLASS_LEG;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '$';
  token.len[2]     = 24;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 8;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len[4]     = 24;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[5]     = 8;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer == PARSER_SEPARATOR_UNMATCHED)
  {
    token.token_cnt = 4;

    token.sep[1]     = '$';
    token.len[1]     = 16;
    token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.sep[2]     = '$';
    token.len[2]     = 24;
    token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len[3]     = 8;
    token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  }

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *pk_pos = token.buf[1];

  salt->salt_buf[0] = byte_swap_32 (hex_to_u32 (pk_pos + 0));
  salt->salt_buf[1] = byte_swap_32 (hex_to_u32 (pk_pos + 8));

  const u8 *ccnr1_pos = token.buf[2];

  salt->salt_buf[2] = byte_swap_32 (hex_to_u32 (ccnr1_pos +  0));
  salt->salt_buf[3] = byte_swap_32 (hex_to_u32 (ccnr1_pos +  8));
  salt->salt_buf[4] = byte_swap_32 (hex_to_u32 (ccnr1_pos + 16));

  const u8 *mac1_pos = token.buf[3];

  digest[0] = byte_swap_32 (hex_to_u32 (mac1_pos));
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  if (token.token_cnt == 6)
  {
    const u8 *ccnr2_pos = token.buf[4];

    salt->salt_buf[5] = byte_swap_32 (hex_to_u32 (ccnr2_pos +  0));
    salt->salt_buf[6] = byte_swap_32 (hex_to_u32 (ccnr2_pos +  8));
    salt->salt_buf[7] = byte_swap_32 (hex_to_u32 (ccnr2_pos + 16));

    const u8 *mac2_pos = token.buf[5];

    salt->salt_buf[8] = byte_swap_32 (hex_to_u32 (mac2_pos));
  }
  else
  {
    salt->salt_buf[5] = salt->salt_buf[2];
    salt->salt_buf[6] = salt->salt_buf[3];
    salt->salt_buf[7] = salt->salt_buf[4];
    salt->salt_buf[8] = digest[0];
  }

  salt->salt_len  = 36;
  salt->salt_iter = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  memcpy (out_buf, SIGNATURE_ICLASS_LEG, 12);

  out_len += 12;

  u32_to_hex (byte_swap_32 (salt->salt_buf[0]), out_buf + out_len); out_len += 8;
  u32_to_hex (byte_swap_32 (salt->salt_buf[1]), out_buf + out_len); out_len += 8;

  out_buf[out_len] = '$'; out_len++;

  u32_to_hex (byte_swap_32 (salt->salt_buf[2]), out_buf + out_len); out_len += 8;
  u32_to_hex (byte_swap_32 (salt->salt_buf[3]), out_buf + out_len); out_len += 8;
  u32_to_hex (byte_swap_32 (salt->salt_buf[4]), out_buf + out_len); out_len += 8;

  out_buf[out_len] = '$'; out_len++;

  u32_to_hex (byte_swap_32 (digest[0]), out_buf + out_len); out_len += 8;

  out_buf[out_len] = '$'; out_len++;

  u32_to_hex (byte_swap_32 (salt->salt_buf[5]), out_buf + out_len); out_len += 8;
  u32_to_hex (byte_swap_32 (salt->salt_buf[6]), out_buf + out_len); out_len += 8;
  u32_to_hex (byte_swap_32 (salt->salt_buf[7]), out_buf + out_len); out_len += 8;

  out_buf[out_len] = '$'; out_len++;

  u32_to_hex (byte_swap_32 (salt->salt_buf[8]), out_buf + out_len); out_len += 8;

  out_buf[out_len] = 0;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_build_plain_postprocess  = module_build_plain_postprocess;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
}
