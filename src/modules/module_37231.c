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
static const char *HASH_NAME      = "BitGo Wallet Key (sjcl, AES-CCM)";
static const u64   KERN_TYPE      = 37231;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bitgo$1*10000*256*7b4fa2ad3e8b6e4a*0f1e2d3c4b5a69788796a5b4c3d2e1f0*8ee5e9900936f4c80015c10df3666d34";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the password of a BitGo wallet key, the encryptedPrv of a keychain or keycard, which is an sjcl blob of the form {\"iv\":...,\"iter\":...,\"ks\":...,\"ct\":...}. tools/bitgo2hashcat.py writes the line. It carries the iteration count, the key size in bits, the salt, the iv and only the first 16 bytes of the ciphertext, so it holds nothing of the key. The password is verified against the 16 characters every BIP32 master key opens with as an xprv, xprv9s21ZrQH143K, or tprv8ZgxMBicQKsP on testnet, so any sjcl blob of a master xprv can be cracked here. Key sizes of 128 and 256 bits are read";
}

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[32];
  u32 out[32];

} pbkdf2_sha256_tmp_t;

typedef struct sjcl
{
  u32 iv_buf[4];
  u32 ct_buf[4];

  u32 key_size;

} sjcl_t;

static const char *SIGNATURE_BITGO = "$bitgo$";

static char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // HIP
  if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  // ROCM
  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

static u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sjcl_t);

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

  sjcl_t *sjcl = (sjcl_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BITGO;

  token.len[0]     = 7;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 7;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len[3]     = 3;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len[4]     = 16;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';
  token.len[5]     = 32;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '*';
  token.len[6]     = 32;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  if (token.buf[1][0] != '1') return (PARSER_SIGNATURE_UNMATCHED);

  // iter

  const u32 iter = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // the key size in bits. One PBKDF2 block covers both, so only the AES key schedule differs

  const u32 key_size = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if ((key_size != 128) && (key_size != 256)) return (PARSER_SALT_VALUE);

  sjcl->key_size = key_size;

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  salt->salt_len = hex_decode (salt_pos, salt_len, (u8 *) salt->salt_buf);

  // iv. The AES helpers read big endian words, and the kernel takes the first 13 bytes of this as
  // the CCM nonce.

  const u8 *iv_pos = token.buf[5];
  const int iv_len = token.len[5];

  hex_decode (iv_pos, iv_len, (u8 *) sjcl->iv_buf);

  for (int i = 0; i < 4; i++) sjcl->iv_buf[i] = byte_swap_32 (sjcl->iv_buf[i]);

  // the first block of the ciphertext

  const u8 *ct_pos = token.buf[6];
  const int ct_len = token.len[6];

  hex_decode (ct_pos, ct_len, (u8 *) sjcl->ct_buf);

  for (int i = 0; i < 4; i++) sjcl->ct_buf[i] = byte_swap_32 (sjcl->ct_buf[i]);

  // the verifier is a known plaintext rather than a stored digest, so the ciphertext block stands
  // in for one, as hash-modes 26610 and 37240 do

  digest[0] = sjcl->ct_buf[0];
  digest[1] = sjcl->ct_buf[1];
  digest[2] = sjcl->ct_buf[2];
  digest[3] = sjcl->ct_buf[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sjcl_t *sjcl = (const sjcl_t *) esalt_buf;

  char salt_hex[(8 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_hex);

  u32 tmp_iv_buf[4];

  for (int i = 0; i < 4; i++) tmp_iv_buf[i] = byte_swap_32 (sjcl->iv_buf[i]);

  char iv_hex[(16 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) tmp_iv_buf, 16, (u8 *) iv_hex);

  u32 tmp_ct_buf[4];

  for (int i = 0; i < 4; i++) tmp_ct_buf[i] = byte_swap_32 (sjcl->ct_buf[i]);

  char ct_hex[(16 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) tmp_ct_buf, 16, (u8 *) ct_hex);

  const int line_len = snprintf (line_buf, line_size, "%s1*%u*%u*%s*%s*%s",
    SIGNATURE_BITGO,
    salt->salt_iter + 1,
    sjcl->key_size,
    salt_hex,
    iv_hex,
    ct_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
