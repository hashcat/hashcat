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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "Apple DMG (encrcdsa v2, PBKDF2-HMAC-SHA1 + 3DES key)";
static const u64   KERN_TYPE      = 38301;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$dmg$2*20*d5a8b5c49c9e5c2f0f2f6e1d4c3b2a1908f7e6d5*32*0123456789abcdef000000000000000000000000000000000000000000000000*48*a1933cbe0c2e058e2cb461699cf4ca28e356eedeba184f0c97e483212662157f6c6e2cbbd3c5fcdb79e89605e6b0ca2f*1*16*913bbac2f8cef4efe5cddb4fc0c74068*0*1000";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Extract $dmg$2 hashes with dmg2john from John the Ripper and keep only the part from $dmg$2 to the iteration count";
}

typedef struct dmg2_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} dmg2_tmp_t;

typedef struct dmg2
{
  u32 blob[16];
  u32 blob_len;

} dmg2_t;

static const char *SIGNATURE_DMG2 = "$dmg$2";

// the chunk dmg2john writes from near the end of the image, and the first chunk when present

#define DMG2_CHUNK_MAX  8192
#define DMG2_ZCHUNK_LEN 4096

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (dmg2_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (dmg2_tmp_t);

  return tmp_size;
}

static u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }
static u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dmg2_t *dmg2 = (dmg2_t *) esalt_buf;

  // dmg2john writes the first chunk of the image (scp 1) or leaves it out (scp 0), which changes
  // the number of fields

  u32 sep_cnt = 0;

  for (u32 i = 0; i < (u32) line_len; i++)
  {
    if (line_buf[i] == '*') sep_cnt++;
  }

  if ((sep_cnt != 11) && (sep_cnt != 12)) return (PARSER_SEPARATOR_UNMATCHED);

  const bool has_zchunk = (sep_cnt == 12);

  hc_token_t token;

  token.token_cnt  = (has_zchunk == true) ? 13 : 12;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DMG2;

  token.sep[0]     = '*';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // salt length and salt

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // iv length and iv, of which 3DES uses the first 8 bytes

  token.sep[3]     = '*';
  token.len_min[3] = 2;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len_min[4] = 64;
  token.len_max[4] = 64;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // wrapped key blob length and blob

  token.sep[5]     = '*';
  token.len_min[5] = 2;
  token.len_max[5] = 2;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';
  token.len_min[6] = 96;
  token.len_max[6] = 128;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // chunk number, chunk size and chunk

  token.sep[7]     = '*';
  token.len_min[7] = 1;
  token.len_max[7] = 10;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[8]     = '*';
  token.len_min[8] = 1;
  token.len_max[8] = 4;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]     = '*';
  token.len_min[9] = 2;
  token.len_max[9] = DMG2_CHUNK_MAX * 2;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // start chunk present, then the first chunk itself when it is

  token.sep[10]     = '*';
  token.len_min[10] = 1;
  token.len_max[10] = 1;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  u32 iter_pos = 11;

  if (has_zchunk == true)
  {
    token.sep[11]     = '*';
    token.len_min[11] = DMG2_ZCHUNK_LEN * 2;
    token.len_max[11] = DMG2_ZCHUNK_LEN * 2;
    token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;

    iter_pos = 12;
  }

  // iterations

  token.len_min[iter_pos] = 1;
  token.len_max[iter_pos] = 8;
  token.attr[iter_pos]    = TOKEN_ATTR_VERIFY_LENGTH
                          | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the declared lengths have to describe the fields that follow them

  const u32 salt_len  = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 iv_len    = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 blob_len  = hc_strtoul ((const char *) token.buf[5], NULL, 10);
  const u32 data_size = hc_strtoul ((const char *) token.buf[8], NULL, 10);
  const u32 scp       = hc_strtoul ((const char *) token.buf[10], NULL, 10);

  if (salt_len != 20) return (PARSER_SALT_LENGTH);
  if (iv_len   != 32) return (PARSER_IV_LENGTH);

  // AES-128 or AES-256 volume key, a 20 byte HMAC-SHA1 key and the "CKIE" marker, padded to 8 bytes

  if ((blob_len != 48) && (blob_len != 64)) return (PARSER_HASH_LENGTH);

  if ((u32) token.len[6] != (blob_len * 2)) return (PARSER_HASH_LENGTH);

  if (data_size == 0)              return (PARSER_HASH_LENGTH);
  if (data_size > DMG2_CHUNK_MAX)  return (PARSER_HASH_LENGTH);

  if ((u32) token.len[9] != (data_size * 2)) return (PARSER_HASH_LENGTH);

  if (scp > 1) return (PARSER_HASH_VALUE);

  if ((scp == 1) && (has_zchunk == false)) return (PARSER_SEPARATOR_UNMATCHED);
  if ((scp == 0) && (has_zchunk == true))  return (PARSER_SEPARATOR_UNMATCHED);

  const u32 iter = hc_strtoul ((const char *) token.buf[iter_pos], NULL, 10);

  if (iter == 0) return (PARSER_SALT_ITERATION);

  // salt

  salt->salt_len  = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);
  salt->salt_iter = iter - 1;

  // esalt. The iv only takes part in decrypting the first block of the blob, which the kernel
  // does not need

  dmg2->blob_len = hex_decode (token.buf[6], token.len[6], (u8 *) dmg2->blob);

  // the digest identifies the wrapped key blob, which the kernel checks and reports

  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, dmg2->blob, dmg2->blob_len);
  md5_final  (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_salt_max                 = module_salt_max;
  module_ctx->module_salt_min                 = module_salt_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
