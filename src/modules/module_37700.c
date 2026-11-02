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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Cardano Eternl Wallet (PBKDF2-HMAC-SHA512, ChaCha20)";
static const u64   KERN_TYPE      = 37700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat01852";
static const char *ST_HASH        = "ETERNL:42391a067b83d88e429c63da8004599b1f8b0e94ed47f1acea9c274b55d8b311b38cc419fd3b63c12ed48cd8b307651fd4e4be4a400f19df778146d7e392d8bb5811e376cff1bd71810f4c92ac973d6eb3e390ade856febd97c067e5cf40e9fe23c3655c25dc406686679e601a544acda56a51553f57305c969a2eb58331db5b215023b0de63e7cc15fe1de0afdb9cc45e45d6e127c20c28c63ccb32c8d6346240e7b81dfe7367a0e3a2f6f9f20c4b6e75a8486d5c052e42a085be2f41817ccbc6c0be5e9518253f7e0a66d33fdea5966aca494d6230a92092349d8659d982e346";

#include "hooks_common.c"

static const u32 ITER_V2 = 210012;

static const char *SIGNATURE_ETERNL = "ETERNL";

typedef struct eternl
{
  u32 salt_buf[8];
  u32 nonce[3]; // 12 bytes
  u32 tag[4];   // 16 bytes
  u32 encrypted[42]; // 165 bytes (padded to 168 bytes. 3 bytes unused)
} eternl_t;

typedef struct pbkdf2_sha512_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];
} pbkdf2_sha512_tmp_t;

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (eternl_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  eternl_t *eternl = (eternl_t *) esalt_buf;

  memset (eternl, 0, sizeof (eternl_t));

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ETERNL;

  // signature
  token.sep[0]  = ':';
  token.len[0]  = 6;
  token.attr[0] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_SIGNATURE;

  // salt
  token.len[1]  = 64;
  token.attr[1] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // nonce
  token.len[2]  = 24;
  token.attr[2] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // tag
  token.len[3]  = 32;
  token.attr[3] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // ciphertext
  token.len[4]  = 330;
  token.attr[4] = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
  {
    return (rc_tokenizer);
  }

  // Salt iterations
  salt->salt_iter = ITER_V2 - 1;

  // Salt information
  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // Also store in esalt for consistency
  memcpy (eternl->salt_buf, salt->salt_buf, 32);

  // Nonce information
  const u8 *nonce_pos = token.buf[2];
  const int nonce_len = token.len[2];
  hex_decode (nonce_pos, nonce_len, (u8 *) eternl->nonce);

  // Tag information
  const u8 *tag_pos = token.buf[3];
  const int tag_len = token.len[3];
  hex_decode (tag_pos, tag_len, (u8 *) eternl->tag);

  digest[0] = eternl->tag[0];
  digest[1] = eternl->tag[1];
  digest[2] = eternl->tag[2];
  digest[3] = eternl->tag[3];

  // ciphertext
  const u8 *encrypted_pos = token.buf[4];
  const int encrypted_len = token.len[4];
  hex_decode (encrypted_pos, encrypted_len, (u8 *) eternl->encrypted);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const eternl_t *eternl = (const eternl_t *) esalt_buf;

  char salt_hex[65] = { 0 };
  hex_encode ((const u8 *) eternl->salt_buf, 32, (u8 *) salt_hex);

  char nonce_hex[25] = { 0 };
  hex_encode ((const u8 *) eternl->nonce, 12, (u8 *) nonce_hex);

  char tag_hex[33] = { 0 };
  hex_encode ((const u8 *) eternl->tag, 16, (u8 *) tag_hex);

  char encrypted_hex[331] = { 0 };
  hex_encode ((const u8 *) eternl->encrypted, 165, (u8 *) encrypted_hex);

  const int out_len = snprintf (line_buf, line_size, "%s:%s%s%s%s",
    SIGNATURE_ETERNL,
    salt_hex,
    nonce_hex,
    tag_hex,
    encrypted_hex
  );

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
