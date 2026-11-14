/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
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
static const char *HASH_NAME      = "SubWallet / polkadot-js keyring (scrypt + XSalsa20-Poly1305)";
static const u64   KERN_TYPE      = 79100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "PolkaTest1!";
static const char *ST_HASH        = "$subwallet$131072,8,1$jyLMQ5+FCfziqZEecYltDckmEuop4wdNrHEerHHR5DI=$TRHbWLheBcbuKWumAE+kH6s3wbqi1yOs$sM0NRnurOEjqqzkopqYOiw==$mSz/xDAIsYBduR8CMkrGAkiWLxvcI68aVoc2+rE74vUZ76RlLqhZxgQOYBTqmzoPDrPx8uIQBWKpUJqCBj/Alhjr+XBRH7UDMeslFTisoiTQN3LXfta/MV+K+R9H69C7eYOXtzEuJfTNSSQmmTKzNoobm0t4";

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_SUBWALLET = "$subwallet$";

static const u32 SCRYPT_THREADS = 4;

// MUST match m79100-pure.cl field-for-field
typedef struct subwallet_scrypt
{
  u32 nonce[6];         // 24 bytes
  u32 ciphertext[128];  // ct only (tag rides in the digest), up to 512 bytes
  u32 ciphertext_len;

} subwallet_scrypt_t;

#define SALT_LEN_BASE64   (((32 * 8) / 6) + 4)
#define NONCE_LEN_BASE64  (((24 * 8) / 6) + 4)
#define TAG_LEN_BASE64    (((16 * 8) / 6) + 4)
#define CT_MAX_LEN_BASE64 (((512 * 8) / 6) + 4)

#include "hooks_common.c"
#include "scrypt_common.c"

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (subwallet_scrypt_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  subwallet_scrypt_t *sw = (subwallet_scrypt_t *) esalt_buf;

    hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SUBWALLET;

  token.len[0]     = 11; // strlen("$subwallet$")
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // scrypt "N,r,p" (CSV - parsed manually below)
  token.sep[1]     = '$';
  token.len_min[1] = 5;
  token.len_max[1] = 24;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // salt (32 bytes -> 44 base64 chars)
  token.sep[2]     = '$';
  token.len[2]     = 44;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // nonce (24 bytes -> 32 base64 chars)
  token.sep[3]     = '$';
  token.len[3]     = 32;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // tag (16 bytes -> 24 base64 chars)
  token.sep[4]     = '$';
  token.len[4]     = 24;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // ciphertext (no tag - that rides in its own field above)
  token.sep[5]     = '$';
  token.len_min[5] = 8;
  token.len_max[5] = CT_MAX_LEN_BASE64;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // scrypt settings: "N,r,p"

  const u8 *nrp = token.buf[1];

  const u8 *comma1 = (const u8 *) strchr ((const char *) nrp, ',');
  if (comma1 == NULL) return (PARSER_SALT_VALUE);
  const u8 *comma2 = (const u8 *) strchr ((const char *) comma1 + 1, ',');
  if (comma2 == NULL) return (PARSER_SALT_VALUE);

  salt->scrypt_N = hc_strtoul ((const char *) nrp, NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) comma1 + 1, NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) comma2 + 1, NULL, 10);

  if (salt->scrypt_N == 0 || salt->scrypt_r == 0 || salt->scrypt_p == 0) return (PARSER_SALT_VALUE);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  if (salt->scrypt_N % 1024) return (PARSER_SALT_VALUE); // loop count fixed to 1024 (scrypt_common)

  if ((salt->scrypt_N & (salt->scrypt_N - 1)) != 0) return (PARSER_SALT_VALUE); // the kernel indexes with & (N - 1)

  u8 tmp[600];

  // salt (32 bytes) - raw into salt_t and esalt

  int salt_len = base64_decode (base64_to_int, token.buf[2], token.len[2], tmp);

  if (salt_len != 32) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp, salt_len);

  salt->salt_len = salt_len;

  // nonce (24 bytes) - raw; comp's xsalsa20 reads it as a byte string

  int nonce_len = base64_decode (base64_to_int, token.buf[3], token.len[3], tmp);

  if (nonce_len != 24) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) sw->nonce, tmp, nonce_len);

  // tag (16 bytes) -> digest, LE-packed (same convention as the computed MAC
  // in comp: crypto_onetimeauth writes tag bytes into a u32 array, which an
  // LE host reads back as LE-packed words)

  int tag_len = base64_decode (base64_to_int, token.buf[4], token.len[4], tmp);

  if (tag_len != 16) return (PARSER_HASH_LENGTH);

  digest[0] = (u32) tmp[0]  | ((u32) tmp[1]  << 8) | ((u32) tmp[2]  << 16) | ((u32) tmp[3]  << 24);
  digest[1] = (u32) tmp[4]  | ((u32) tmp[5]  << 8) | ((u32) tmp[6]  << 16) | ((u32) tmp[7]  << 24);
  digest[2] = (u32) tmp[8]  | ((u32) tmp[9]  << 8) | ((u32) tmp[10] << 16) | ((u32) tmp[11] << 24);
  digest[3] = (u32) tmp[12] | ((u32) tmp[13] << 8) | ((u32) tmp[14] << 16) | ((u32) tmp[15] << 24);

  // ciphertext - raw bytes; comp's poly1305 authenticates them as a byte
  // string from offset 0 (tag is NOT prepended here, unlike $phantom$)

  int ct_len = base64_decode (base64_to_int, token.buf[5], token.len[5], tmp);

  if (ct_len < 6 || ct_len > 512) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) sw->ciphertext, tmp, ct_len);

  sw->ciphertext_len = ct_len;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const subwallet_scrypt_t *sw = (const subwallet_scrypt_t *) esalt_buf;

  #define SALT_LEN_BASE64   ((32 * 8) / 6) + 3
  #define NONCE_LEN_BASE64  ((24 * 8) / 6) + 3
  #define TAG_LEN_BASE64    ((16 * 8) / 6) + 4 // 24 chars + NUL; +3 undershoots by one
    u8 salt_buf[SALT_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, (const int) salt->salt_len, salt_buf);

  u8 nonce_buf[NONCE_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) sw->nonce, 24, nonce_buf);

  const u32 *digest = (const u32 *) digest_buf;

  u8 tag_raw[16];

  memcpy (tag_raw, digest, 16); // LE-packed words -> raw tag bytes on LE hosts

  u8 tag_buf[TAG_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, tag_raw, 16, tag_buf);

  u8 ct_buf[CT_MAX_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) sw->ciphertext, (const int) sw->ciphertext_len, ct_buf);

  return snprintf (line_buf, line_size, "%s%u,%u,%u$%s$%s$%s$%s",
    SIGNATURE_SUBWALLET,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    salt_buf,
    nonce_buf,
    tag_buf,
    ct_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kernel_accel_max         = scrypt_module_kernel_accel_max;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_tune_variants            = scrypt_module_tune_variants;
}
