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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5; // because kernel uses _SHA1;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "1Password, agilekeychain";
static const u64   KERN_TYPE      = 6600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "1000:d61a54f1efdfcf57:000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000afdb51c887d14df6200bbde872aabfd9e12a1f163eed40e6b3ec33ba394c47e9";

#include "hooks_common.c"

typedef struct agilekey
{
  u8 cipher[1040];

} agilekey_t;

typedef struct agilekey_tmp
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[5];
  u32 out[5];

} agilekey_tmp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (agilekey_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (agilekey_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  agilekey_t *agilekey = (agilekey_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.sep[0]     = ':';
  token.len_min[0] = 1;
  token.len_max[0] = 6;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[1]     = ':';
  token.len[1]     = 16;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = ':';
  token.len[2]     = 2080;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * pbkdf2 iterations
   */

  const u8 *iter_pos = token.buf[0];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  /**
   * handle salt encoding
   */

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  u8 *saltbuf_ptr = (u8 *) salt->salt_buf;

  if (salt_len & 1) return (PARSER_TOKEN_LENGTH);

  // i + 1, not i: the loop reads two characters per byte, so an odd salt_len read one past the
  // token, which is the next field of the line or the caller's terminator

  for (int i = 0; (i + 1) < salt_len; i += 2)
  {
    const u8 p0 = salt_pos[i + 0];
    const u8 p1 = salt_pos[i + 1];

    *saltbuf_ptr++ = hex_convert (p1) << 0
                   | hex_convert (p0) << 4;
  }

  salt->salt_len = salt_len / 2;

  /**
   * handle cipher encoding
   */

  const u8 *cipher_pos = token.buf[2];
  const int cipher_len = token.len[2];

  u32 tmp[32] = { 0 };

  u8 *cipherbuf_ptr = (u8 *) tmp;

  for (int i = 2016; i < cipher_len; i += 2)
  {
    const u8 p0 = cipher_pos[i + 0];
    const u8 p1 = cipher_pos[i + 1];

    *cipherbuf_ptr++ = hex_convert (p1) << 0
                     | hex_convert (p0) << 4;
  }

  // iv   is stored at salt_buf 4 (length 16)
  // data is stored at salt_buf 8 (length 16)

  salt->salt_buf[ 4] = byte_swap_32 (tmp[0]);
  salt->salt_buf[ 5] = byte_swap_32 (tmp[1]);
  salt->salt_buf[ 6] = byte_swap_32 (tmp[2]);
  salt->salt_buf[ 7] = byte_swap_32 (tmp[3]);

  salt->salt_buf[ 8] = byte_swap_32 (tmp[4]);
  salt->salt_buf[ 9] = byte_swap_32 (tmp[5]);
  salt->salt_buf[10] = byte_swap_32 (tmp[6]);
  salt->salt_buf[11] = byte_swap_32 (tmp[7]);

  for (int i = 0, j = 0; i < 1040; i += 1, j += 2)
  {
    const u8 p0 = cipher_pos[j + 0];
    const u8 p1 = cipher_pos[j + 1];

    agilekey->cipher[i] = hex_convert (p1) << 0
                        | hex_convert (p0) << 4;
  }

  /**
   * digest buf
   */

  digest[0] = 0x10101010;
  digest[1] = 0x10101010;
  digest[2] = 0x10101010;
  digest[3] = 0x10101010;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const agilekey_t *agilekey = (const agilekey_t *) esalt_buf;

  int line_len = snprintf (line_buf, line_size, "%u:%08x%08x:", salt->salt_iter + 1, byte_swap_32 (salt->salt_buf[0]), byte_swap_32 (salt->salt_buf[1]));

  for (u32 i = 0; i < 1040; i++)
  {
    line_len += snprintf (line_buf + line_len, line_size - line_len, "%02x", agilekey->cipher[i]);
  }

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
