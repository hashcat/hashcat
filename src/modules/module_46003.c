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
static const char *HASH_NAME      = "Cardano EMIP-003 Wallet (PBKDF2-HMAC-SHA512, ChaCha20-Poly1305)";
static const u64   KERN_TYPE      = 46003;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_ITERATION_OVERRIDE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "Emip3Test2026!";
static const char *ST_HASH        = "$emip3$19162$decafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbaddecafbad0102030405060708090a0b0ce2557667591699504ab20f550ecec86001f078574c2beefeebeff381cd389c55f2ecebc205c359ffc946805819edf8f5";

#include "hooks_common.c"

static const char *SIGNATURE_EMIP3 = "$emip3$";

#define EMIP3_HEADER_LEN  60    // salt(32) + nonce(12) + tag(16)
#define EMIP3_CT_MIN      1
#define EMIP3_CT_MAX      2048

// MUST match m46003-pure.cl field-for-field
typedef struct emip3
{
  u32 salt_buf[8];            // 32 bytes
  u32 nonce[3];               // 12 bytes
  u32 ct[EMIP3_CT_MAX / 4];   // ct only (tag rides in the digest)
  u32 ct_len;

} emip3_t;

typedef struct pbkdf2_sha512_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[16];
  u64 out[16];

} pbkdf2_sha512_tmp_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (emip3_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  emip3_t *emip3 = (emip3_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_EMIP3;

  token.sep[0]     = 0;
  token.len[0]     = 7; // strlen("$emip3$")
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // iterations
  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // envelope: salt(32) + nonce(12) + tag(16) + ct, hex
  token.sep[2]     = '$';
  token.len_min[2] = (EMIP3_HEADER_LEN + EMIP3_CT_MIN) * 2;
  token.len_max[2] = (EMIP3_HEADER_LEN + EMIP3_CT_MAX) * 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iterations

  const u32 iter = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // envelope

  u8 tmp[EMIP3_HEADER_LEN + EMIP3_CT_MAX + 16];

  const int env_len = hex_decode (token.buf[2], token.len[2], tmp);

  if (env_len < EMIP3_HEADER_LEN + EMIP3_CT_MIN) return (PARSER_HASH_LENGTH);

  // salt (32 bytes)

  memcpy (salt->salt_buf, tmp, 32);

  salt->salt_len = 32;

  memcpy (emip3->salt_buf, tmp, 32);

  // nonce (12 bytes at offset 32), LE-packed

  memcpy ((u8 *) emip3->nonce, tmp + 32, 12);

  // tag (16 bytes at offset 44), LE-packed into the digest (same convention as
  // the computed MAC in comp)

  const u8 *tag = tmp + 44;

  digest[0] = (u32) tag[0]  | ((u32) tag[1]  << 8) | ((u32) tag[2]  << 16) | ((u32) tag[3]  << 24);
  digest[1] = (u32) tag[4]  | ((u32) tag[5]  << 8) | ((u32) tag[6]  << 16) | ((u32) tag[7]  << 24);
  digest[2] = (u32) tag[8]  | ((u32) tag[9]  << 8) | ((u32) tag[10] << 16) | ((u32) tag[11] << 24);
  digest[3] = (u32) tag[12] | ((u32) tag[13] << 8) | ((u32) tag[14] << 16) | ((u32) tag[15] << 24);

  // ct from offset 60

  const int ct_len = env_len - EMIP3_HEADER_LEN;

  if (ct_len < EMIP3_CT_MIN || ct_len > EMIP3_CT_MAX) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) emip3->ct, tmp + EMIP3_HEADER_LEN, ct_len);

  emip3->ct_len = ct_len;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const emip3_t *emip3 = (const emip3_t *) esalt_buf;

  const u32 *digest = (const u32 *) digest_buf;

  u8 env[EMIP3_HEADER_LEN + EMIP3_CT_MAX];

  memcpy (env, salt->salt_buf, 32);

  memcpy (env + 32, (const u8 *) emip3->nonce, 12);

  u8 tag_raw[16];

  memcpy (tag_raw, digest, 16); // LE-packed words -> raw tag bytes on LE hosts

  memcpy (env + 44, tag_raw, 16);

  memcpy (env + EMIP3_HEADER_LEN, (const u8 *) emip3->ct, emip3->ct_len);

  const int env_len = EMIP3_HEADER_LEN + emip3->ct_len;

  // hex_encode does not terminate the string; the zeroed buffer ends it

  u8 hex[2 * (EMIP3_HEADER_LEN + EMIP3_CT_MAX) + 1] = { 0 };

  hex_encode (env, env_len, hex);

  return snprintf (line_buf, line_size, "%s%u$%s",
    SIGNATURE_EMIP3,
    salt->salt_iter + 1,
    hex);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_attack_exec              = module_attack_exec;
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
