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
static const char *HASH_NAME      = "Brave Wallet (PBKDF2-HMAC-SHA256, AES-256-GCM-SIV)";
static const u64   KERN_TYPE      = 79630;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
// self-made vector (pure-python RFC 8452 reference, validated against
// Appendix C.2): PBKDF2-HMAC-SHA256("hashcat", salt, 310000, 32) ->
// AES-256-GCM-SIV seal of a 12-word BIP39 mnemonic
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$brave$*310000*101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f*a0a1a2a3a4a5a6a7a8a9aaab*0f8b91de5a7f678b135ccaaa6741ebe88a01ef2917661e3c2226fe206e54f1406aa1a95b40a49485f40efe062876dfd375a42f3cbc450ad8e4d2ac34cc112df809d0c5960fb4dfefb2107c5768096da195742875fd024a3df25cbb";

#define BRAVE_SALT_LEN 32
#define BRAVE_NONCE_LEN 12
#define BRAVE_CT_MAX   512


typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

typedef struct brave
{
  u32 nonce[3];     // 12B, LE-packed bytes
  u32 ct_buf[128];  // 512B max, LE-packed bytes, tag stripped
  u32 ct_len;

} brave_t;

static const char *SIGNATURE_BRAVE = "$brave$*";

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (brave_t);

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

  brave_t *brave = (brave_t *) esalt_buf;

  #define CT_MAX_LEN_HEX ((BRAVE_CT_MAX + 16) * 2)

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BRAVE;

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = BRAVE_SALT_LEN * 2;
  token.len_max[2] = BRAVE_SALT_LEN * 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len_min[3] = BRAVE_NONCE_LEN * 2;
  token.len_max[3] = BRAVE_NONCE_LEN * 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 32; // ct may be empty, tag 16B -> 32 hex
  token.len_max[4] = CT_MAX_LEN_HEX;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  u8 tmp_buf[BRAVE_CT_MAX + 16];

  // iterations

  const u32 iter = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt: 32B fixed, LE-packed words for sha256_hmac_update_global_swap

  const u8 *salt_pos = token.buf[2];

  for (u32 i = 0; i < BRAVE_SALT_LEN / 4; i++)
  {
    salt->salt_buf[i] = hex_to_u32 (salt_pos + i * 8);
  }

  salt->salt_len = BRAVE_SALT_LEN;

  // nonce: 12B fixed, LE-packed words (no swap - kernel reads bytes as-is)

  const u8 *nonce_pos = token.buf[3];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  int tmp_len = hex_decode (nonce_pos, BRAVE_NONCE_LEN * 2, tmp_buf);

  if (tmp_len != BRAVE_NONCE_LEN) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) brave->nonce, tmp_buf, tmp_len);

  // ciphertext || tag

  const u8 *ct_pos = token.buf[4];
  const int ct_hex_len = token.len[4];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = hex_decode (ct_pos, ct_hex_len, tmp_buf);

  if (tmp_len < 16) return (PARSER_CT_LENGTH);

  tmp_len -= 16;

  if (tmp_len > BRAVE_CT_MAX) return (PARSER_CT_LENGTH);

  memset (brave->ct_buf, 0, sizeof (brave->ct_buf));

  memcpy ((u8 *) brave->ct_buf, tmp_buf, tmp_len);

  brave->ct_len = tmp_len;

  // tag - BE words, kernel compares raw AES output words

  digest[0] = byte_swap_32 (hex_to_u32 (ct_pos + (tmp_len * 2) +  0));
  digest[1] = byte_swap_32 (hex_to_u32 (ct_pos + (tmp_len * 2) +  8));
  digest[2] = byte_swap_32 (hex_to_u32 (ct_pos + (tmp_len * 2) + 16));
  digest[3] = byte_swap_32 (hex_to_u32 (ct_pos + (tmp_len * 2) + 24));

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const brave_t *brave = (const brave_t *) esalt_buf;

  u8 salt_buf[BRAVE_SALT_LEN * 2 + 1];

  for (u32 i = 0; i < BRAVE_SALT_LEN / 4; i++)
  {
    u32_to_hex (salt->salt_buf[i], salt_buf + i * 8);
  }

  salt_buf[BRAVE_SALT_LEN * 2] = 0;

  u8 nonce_buf[BRAVE_NONCE_LEN * 2 + 1] = { 0 };

  hex_encode ((const u8 *) brave->nonce, BRAVE_NONCE_LEN, nonce_buf);

  u8 ct_buf[(BRAVE_CT_MAX + 16) * 2 + 1];

  hex_encode ((const u8 *) brave->ct_buf, (const int) brave->ct_len, ct_buf);

  u32_to_hex (byte_swap_32 (digest[0]), ct_buf + brave->ct_len * 2 +  0);
  u32_to_hex (byte_swap_32 (digest[1]), ct_buf + brave->ct_len * 2 +  8);
  u32_to_hex (byte_swap_32 (digest[2]), ct_buf + brave->ct_len * 2 + 16);
  u32_to_hex (byte_swap_32 (digest[3]), ct_buf + brave->ct_len * 2 + 24);

  ct_buf[(brave->ct_len + 16) * 2] = 0;

  return snprintf ((char *) line_buf, line_size, "%s%u*%s*%s*%s",
    SIGNATURE_BRAVE,
    salt->salt_iter + 1,
    salt_buf,
    nonce_buf,
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
