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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Jaxx Liberty Wallet (PBKDF2-SHA256 5000, AES-256-GCM)";
static const u64   KERN_TYPE      = 79610;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
// produced with the wallet's own WebCrypto path: PBKDF2-HMAC-SHA256(pass, sb,
// 5000, 32) -> AES-256-GCM seal of the BIP39 entropy hex
static const char *ST_PASS        = "RealJaxx!2026";
static const char *ST_HASH        = "$jaxx$RO5HkXu2IErJqz1A$EJWUYIGocRBO94iC$3rPAO6UiOqneokSBy/FDtg4vL7q4ZlXvll9fiA9OwVYw/2W5q/z/UzGO7prxA1J5";

static const u32   ROUNDS_JAXX    = 5000;

// field ceilings: sb <= 128B (forge fallback), iv <= 16B, ct <= 512B
// (a Liberty record is the entropy hex - 32/64B pt - never KB-size).
#define JAXX_SALT_MAX 128
#define JAXX_IV_MAX   16
#define JAXX_CT_MAX   512


typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct jaxx
{
  u32 salt_buf[32]; // 128B
  u32 iv_buf[4];    // 16B
  u32 iv_len;
  u32 ct_buf[128];  // 512B
  u32 ct_len;

} jaxx_t;

static const char *SIGNATURE_JAXX = "$jaxx$";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (jaxx_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  jaxx_t *jaxx = (jaxx_t *) esalt_buf;

  #define CT_MAX_LEN_BASE64 (((JAXX_CT_MAX + 16) * 8) / 6) + 3

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_JAXX;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 16;  // 12B -> 16 b64 chars
  token.len_max[1] = ((JAXX_SALT_MAX * 8) / 6) + 3;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[2]     = '$';
  token.len_min[2] = 16;  // 12B -> 16 chars
  token.len_max[2] = ((JAXX_IV_MAX * 8) / 6) + 3;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.sep[3]     = '$';
  token.len_min[3] = 44;  // 16B ct + 16B tag -> 44 chars
  token.len_max[3] = CT_MAX_LEN_BASE64;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 tmp_buf[CT_MAX_LEN_BASE64] = { 0 };

  size_t tmp_len = 0;

  // iter - fixed, no rounds field in the line

  salt->salt_iter = ROUNDS_JAXX - 1;

  // salt (sb): 12..128B

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, salt_pos, salt_len, tmp_buf);

  if (tmp_len < 12 || tmp_len > JAXX_SALT_MAX) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp_buf, tmp_len);

  salt->salt_len = tmp_len;

  const u32 salt_words = (tmp_len + 3) / 4;

  for (u32 i = 0; i < salt_words; i++) jaxx->salt_buf[i] = salt->salt_buf[i];

  // iv: 12..16B

  const u8 *iv_pos = token.buf[2];
  const int iv_len = token.len[2];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, iv_pos, iv_len, tmp_buf);

  if (tmp_len < 12 || tmp_len > JAXX_IV_MAX) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) jaxx->iv_buf, tmp_buf, tmp_len);

  jaxx->iv_buf[0] = byte_swap_32 (jaxx->iv_buf[0]);
  jaxx->iv_buf[1] = byte_swap_32 (jaxx->iv_buf[1]);
  jaxx->iv_buf[2] = byte_swap_32 (jaxx->iv_buf[2]);
  jaxx->iv_buf[3] = byte_swap_32 (jaxx->iv_buf[3]);

  jaxx->iv_len = tmp_len;

  // ciphertext (et): ct || 16B tag

  const u8 *ct_pos = token.buf[3];
  const int ct_len = token.len[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, ct_pos, ct_len, tmp_buf);

  if (tmp_len <= 16) return (PARSER_CT_LENGTH);

  tmp_len -= 16;

  if (tmp_len < 16 || tmp_len > JAXX_CT_MAX) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) jaxx->ct_buf, tmp_buf, tmp_len);

  u32 j = tmp_len / 4;

  if ((tmp_len % 4) > 0) j++;

  for (u32 i = 0; i < j; i++) jaxx->ct_buf[i] = byte_swap_32 (jaxx->ct_buf[i]);

  jaxx->ct_len = tmp_len;

  // tag

  u32 tag_buf[4] = { 0 };

  memcpy ((u8 *) tag_buf, tmp_buf + jaxx->ct_len, 16);

  digest[0] = byte_swap_32 (tag_buf[0]);
  digest[1] = byte_swap_32 (tag_buf[1]);
  digest[2] = byte_swap_32 (tag_buf[2]);
  digest[3] = byte_swap_32 (tag_buf[3]);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const jaxx_t *jaxx = (const jaxx_t *) esalt_buf;

  // salt

  #define SALT_LEN_BASE64   ((JAXX_SALT_MAX * 8) / 6) + 3
  #define IV_LEN_BASE64     ((JAXX_IV_MAX * 8) / 6) + 3

  u8 salt_buf[SALT_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, (const int) salt->salt_len, salt_buf);

  // iv

  u32 tmp_iv_buf[4] = { 0 };

  tmp_iv_buf[0] = byte_swap_32 (jaxx->iv_buf[0]);
  tmp_iv_buf[1] = byte_swap_32 (jaxx->iv_buf[1]);
  tmp_iv_buf[2] = byte_swap_32 (jaxx->iv_buf[2]);
  tmp_iv_buf[3] = byte_swap_32 (jaxx->iv_buf[3]);

  u8 iv_buf[IV_LEN_BASE64 + 1] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_iv_buf, (const int) jaxx->iv_len, iv_buf);

  // ct

  u32 ct_len = jaxx->ct_len;

  u32 j = ct_len / 4;

  if ((ct_len % 4) > 0) j++;

  u32 tmp_buf[(JAXX_CT_MAX / 4) + 4] = { 0 };

  for (u32 i = 0; i < j; i++) tmp_buf[i] = byte_swap_32 (jaxx->ct_buf[i]);

  u32 tmp_tag[4] = { 0 };

  tmp_tag[0] = byte_swap_32 (digest[0]);
  tmp_tag[1] = byte_swap_32 (digest[1]);
  tmp_tag[2] = byte_swap_32 (digest[2]);
  tmp_tag[3] = byte_swap_32 (digest[3]);

  u8 *tmp_buf_str = (u8 *) tmp_buf;
  u8 *tmp_tag_str = (u8 *) tmp_tag;

  memcpy (tmp_buf_str + jaxx->ct_len, tmp_tag_str, 16);

  u8 ct_buf[CT_MAX_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, (const int) jaxx->ct_len + 16, ct_buf);

  u8 *out_buf = (u8 *) line_buf;

  return snprintf ((char *) out_buf, line_size, "%s%s$%s$%s",
    SIGNATURE_JAXX,
    salt_buf,
    iv_buf,
    ct_buf);
}

#include "hooks_common.c"

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
