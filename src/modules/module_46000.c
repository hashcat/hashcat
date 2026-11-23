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

#include <inttypes.h>

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Phantom Wallet (scrypt + XSalsa20-Poly1305)";
static const u64   KERN_TYPE      = 45600; // runs the m45600 kernels; the Phantom box is split into tag + ct at decode, which is exactly the SubWallet layout
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "PhantomTest1!";
static const char *ST_HASH        = "$phantom$s*4096*8*1*obLD1OX2BxgpOktcbX6PkA==*AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY*ETbq2mlmAglcsIWoGP0Eq8jVgZh7+6bAXSTBepuwX0lfZrRrOh5ZjUFhdbwmnW6e";

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_PHANTOM_SCRYPT = "$phantom$s";

static const u32 SCRYPT_THREADS = 4;

// MUST match m45600-pure.cl field-for-field (this mode runs those kernels)
typedef struct phantom_scrypt
{
  u32 nonce[6];         // 24 bytes
  u32 ciphertext[128];  // ct only (tag rides in the digest), up to 512 bytes
  u32 ciphertext_len;

} phantom_scrypt_t;

#define SALT_LEN_MAX      64
#define SALT_LEN_BASE64   (((SALT_LEN_MAX * 8) / 6) + 4)
#define NONCE_LEN_BASE64  (((24 * 8) / 6) + 4)
#define CT_LEN_MAX        512  // the limit of the m45600 kernels this mode runs
#define BOX_LEN_MAX_BASE64 (((16 + CT_LEN_MAX) * 8) / 6) + 4

#include "hooks_common.c"
#include "scrypt_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/phantom2hashcat.py to extract the hashes";
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (phantom_scrypt_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  phantom_scrypt_t *ph = (phantom_scrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PHANTOM_SCRYPT;

  token.sep[0]     = '*';
  token.len[0]     = 10; // strlen("$phantom$s")
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // scrypt N
  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // scrypt r
  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // scrypt p
  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // salt (16 bytes -> 24 base64 chars, but accept what the vault carries)
  token.sep[4]     = '*';
  token.len_min[4] = 4;
  token.len_max[4] = SALT_LEN_BASE64;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // nonce (24 bytes -> 32 base64 chars)
  token.sep[5]     = '*';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  // box (tag || ct, 48 bytes for a 32-byte secret -> 64 base64 chars)
  token.sep[6]     = '*';
  token.len_min[6] = 24;
  token.len_max[6] = BOX_LEN_MAX_BASE64;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  salt->scrypt_N = hc_strtoul ((const char *) token.buf[1], NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) token.buf[2], NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (salt->scrypt_N == 0 || salt->scrypt_r == 0 || salt->scrypt_p == 0) return (PARSER_SALT_VALUE);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  if (salt->scrypt_N % 1024) return (PARSER_SALT_VALUE); // loop count fixed to 1024 (scrypt_common)

  if ((salt->scrypt_N & (salt->scrypt_N - 1)) != 0) return (PARSER_SALT_VALUE); // the kernel indexes with & (N - 1)

  u8 tmp[800];

  // salt - raw into salt_t

  const int salt_len = base64_decode (base64_to_int, token.buf[4], token.len[4], tmp);

  if (salt_len < 1 || salt_len > SALT_LEN_MAX) return (PARSER_SALT_LENGTH);

  memcpy (salt->salt_buf, tmp, salt_len);

  salt->salt_len = salt_len;

  // nonce (24 bytes) - raw; comp's xsalsa20 reads it as a byte string

  const int nonce_len = base64_decode (base64_to_int, token.buf[5], token.len[5], tmp);

  if (nonce_len != 24) return (PARSER_IV_LENGTH);

  memcpy ((u8 *) ph->nonce, tmp, nonce_len);

  // box: tag(16) || ct, the way NaCl secretbox lays it out; the tag rides in
  // the digest, LE-packed (same convention as the computed MAC in comp), and
  // the ct goes to esalt without it, which is exactly what m45600 expects

  const int box_len = base64_decode (base64_to_int, token.buf[6], token.len[6], tmp);

  if (box_len < 22 || box_len > 16 + CT_LEN_MAX) return (PARSER_CT_LENGTH);

  digest[0] = (u32) tmp[0]  | ((u32) tmp[1]  << 8) | ((u32) tmp[2]  << 16) | ((u32) tmp[3]  << 24);
  digest[1] = (u32) tmp[4]  | ((u32) tmp[5]  << 8) | ((u32) tmp[6]  << 16) | ((u32) tmp[7]  << 24);
  digest[2] = (u32) tmp[8]  | ((u32) tmp[9]  << 8) | ((u32) tmp[10] << 16) | ((u32) tmp[11] << 24);
  digest[3] = (u32) tmp[12] | ((u32) tmp[13] << 8) | ((u32) tmp[14] << 16) | ((u32) tmp[15] << 24);

  memcpy ((u8 *) ph->ciphertext, tmp + 16, box_len - 16);

  ph->ciphertext_len = box_len - 16;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const phantom_scrypt_t *ph = (const phantom_scrypt_t *) esalt_buf;

  const u32 *digest = (const u32 *) digest_buf;

  u8 salt_buf[SALT_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) salt->salt_buf, (const int) salt->salt_len, salt_buf);

  u8 nonce_buf[NONCE_LEN_BASE64] = { 0 };

  base64_encode (int_to_base64, (const u8 *) ph->nonce, 24, nonce_buf);

  u8 box[16 + CT_LEN_MAX];

  u8 tag_raw[16];

  memcpy (tag_raw, digest, 16); // LE-packed words -> raw tag bytes on LE hosts

  memcpy (box, tag_raw, 16);

  memcpy (box + 16, (const u8 *) ph->ciphertext, (const int) ph->ciphertext_len);

  u8 box_buf[BOX_LEN_MAX_BASE64] = { 0 };

  base64_encode (int_to_base64, box, 16 + (const int) ph->ciphertext_len, box_buf);

  return snprintf (line_buf, line_size, "%s*%u*%u*%u*%s*%s*%s",
    SIGNATURE_PHANTOM_SCRYPT,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    salt_buf,
    nonce_buf,
    box_buf);
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
  module_ctx->module_usage_notice             = module_usage_notice;
}
