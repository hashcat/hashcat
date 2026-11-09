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
static const char *HASH_NAME      = "Apple DMG (cdsaencr v1, PBKDF2-HMAC-SHA1 + 3DES key wrap)";
static const u64   KERN_TYPE      = 38302;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "vilefault";
static const char *ST_HASH        = "$dmg$1*20*9c82b419bdac1b3e6b71f8a6b99a7501f34b6950*40*5da479e292e0acf67a9fa3e24d0a767cae2f645ff63836665068637188f4b80295de79aabdbc2536*48*9b136165ee73418631ccf28d5e77073788ae921df596649a7a7789585db0f13f446d5927967e2ede20ce8a4f5389185d*1000";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "Extract $dmg$1 hashes with dmg2john from John the Ripper and keep only the part from $dmg$1 to the iteration count";
}

typedef struct dmg_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[10];
  u32  out[10];

} dmg_tmp_t;

typedef struct dmg
{
  u32 wrapped_aes_key[74];  // up to 296 bytes
  u32 wrapped_hmac_key[75]; // up to 300 bytes

  int wrapped_aes_key_len;
  int wrapped_hmac_key_len;

} dmg_t;

static const char *SIGNATURE_DMG = "$dmg$1";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (dmg_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (dmg_tmp_t);

  return tmp_size;
}

static u32 module_salt_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }
static u32 module_salt_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return 20; }

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  dmg_t *dmg = (dmg_t *) esalt_buf;

  // the iterations field is optional (defaults to 1000), so the line carries 6 or 7 separators

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == '*') sep_cnt++;
  }

  if ((sep_cnt != 6) && (sep_cnt != 7)) return (PARSER_SEPARATOR_UNMATCHED);

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = sep_cnt + 1;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_DMG;

  token.sep[0]     = '*';   // separator after the "$dmg$1" signature
  token.len[0]     = 6; // "$dmg$1"
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';   // salt len (bytes)
  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';   // salt hex (20 bytes)
  token.len_min[2] = 40;
  token.len_max[2] = 40;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';   // wrapped aes key len (bytes)
  token.len_min[3] = 1;
  token.len_max[3] = 3;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';   // wrapped aes key hex (up to 296 bytes)
  token.len_min[4] = 32;
  token.len_max[4] = 592;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';   // wrapped hmac key len (bytes)
  token.len_min[5] = 1;
  token.len_max[5] = 3;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  if (sep_cnt == 6)
  {
    token.len_min[6] = 32;  // wrapped hmac key hex (up to 300 bytes)
    token.len_max[6] = 600;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;
  }
  else
  {
    token.sep[6]     = '*';
    token.len_min[6] = 32;
    token.len_max[6] = 600;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[7] = 1;   // iterations (last token, no separator)
    token.len_max[7] = 8;
    token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // the declared lengths have to describe the fields that follow them

  const u32 salt_len = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  const u32 blob1_len = hc_strtoul ((const char *) token.buf[3], NULL, 10);
  const u32 blob2_len = hc_strtoul ((const char *) token.buf[5], NULL, 10);

  // JtR always feeds PBKDF2 a 20 byte salt

  if (salt_len != 20) return (PARSER_SALT_LENGTH);

  // 24 bytes is the smallest blob that can verify: 8 bytes of wrap IV and one full
  // PKCS#7 pad block around at least one block of payload

  if (blob1_len < 24 || blob1_len > 296)         return (PARSER_HASH_LENGTH);
  if (blob1_len % 8 != 0)                        return (PARSER_HASH_LENGTH);
  if ((u32) token.len[4] != (blob1_len * 2))     return (PARSER_HASH_LENGTH);

  if (blob2_len < 24 || blob2_len > 300)         return (PARSER_HASH_LENGTH);
  if (blob2_len % 8 != 0)                        return (PARSER_HASH_LENGTH);
  if ((u32) token.len[6] != (blob2_len * 2))     return (PARSER_HASH_LENGTH);

  // salt

  salt->salt_len = hex_decode (token.buf[2], token.len[2], (u8 *) salt->salt_buf);

  // iterations

  u32 iter = 1000;

  if (sep_cnt == 7)
  {
    iter = hc_strtoul ((const char *) token.buf[7], NULL, 10);
  }

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // wrapped keys -> esalt

  dmg->wrapped_aes_key_len  = hex_decode (token.buf[4], token.len[4], (u8 *) dmg->wrapped_aes_key);
  dmg->wrapped_hmac_key_len = hex_decode (token.buf[6], token.len[6], (u8 *) dmg->wrapped_hmac_key);

  // identity digest = MD5 of both wrapped key blobs, so distinct blobs that share a salt
  // still get distinct identities for dedup/potfile. The kernel reports the same MD5 on a
  // match; the real password check is the 3DES unwrap in the kernel.

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);

  md5_update (&md5_ctx, dmg->wrapped_aes_key,  dmg->wrapped_aes_key_len);
  md5_update (&md5_ctx, dmg->wrapped_hmac_key, dmg->wrapped_hmac_key_len);

  md5_final (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const dmg_t *dmg = (const dmg_t *) esalt_buf;

  char salt_buf[97] = { 0 };
  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  char aes_buf[593] = { 0 };
  hex_encode ((const u8 *) dmg->wrapped_aes_key, dmg->wrapped_aes_key_len, (u8 *) aes_buf);

  char hmac_buf[601] = { 0 };
  hex_encode ((const u8 *) dmg->wrapped_hmac_key, dmg->wrapped_hmac_key_len, (u8 *) hmac_buf);

  const int out_len = snprintf (line_buf, line_size, "%s*%d*%s*%d*%s*%d*%s*%u",
    SIGNATURE_DMG,
    salt->salt_len,
    salt_buf,
    dmg->wrapped_aes_key_len,
    aes_buf,
    dmg->wrapped_hmac_key_len,
    hmac_buf,
    salt->salt_iter + 1);

  return out_len;
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
