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
static const char *HASH_NAME      = "Block.io Wallet Key (Secret PIN)";
static const u64   KERN_TYPE      = 37232;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$blockio$1*0*2048*-*-*43c003fa3c4d44a5837d4130bedff2fc";

#include "hooks_common.c"

static const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "This mode cracks the Secret PIN of a Block.io backup wallet, the encrypted_passphrase of a user_key. tools/blockio2hashcat.py writes the line. It carries the cipher (0 = AES-256-ECB, 1 = AES-256-CBC, 2 = AES-256-GCM), the iteration count, the salt, the iv and the first 16 bytes of the ciphertext, with - for empty fields. The key is PBKDF2-HMAC-SHA256 run twice over half the iterations each, where the key of the second phase is the hex encoding of the 16 bytes the first phase produced. The PIN is verified against the first plaintext block, which is hex encoded and so holds only 0-9a-f";
}

typedef struct pbkdf2_sha256_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

  // the padded message block of the phase 2 U1, salt || INT32_BE (1), built once in init

  u32 msg[16];

} pbkdf2_sha256_tmp_t;

typedef struct blockio
{
  u32 cipher;

  u32 iv_buf[4];
  u32 ct_buf[4];

} blockio_t;

static const char *SIGNATURE_BLOCKIO = "$blockio$";

static const u32 BLOCKIO_CIPHER_ECB = 0;
static const u32 BLOCKIO_CIPHER_CBC = 1;
static const u32 BLOCKIO_CIPHER_GCM = 2;

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
  const u64 esalt_size = (const u64) sizeof (blockio_t);

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

  blockio_t *blockio = (blockio_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BLOCKIO;

  token.len[0]     = 9;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 1;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 1;
  token.len_max[3] = 7;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 50;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 32;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[6]     = '*';
  token.len[6]     = 32;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  if (token.buf[1][0] != '1') return (PARSER_SIGNATURE_UNMATCHED);

  // cipher

  const u32 cipher = token.buf[2][0] - '0';

  if (cipher > BLOCKIO_CIPHER_GCM) return (PARSER_SALT_VALUE);

  blockio->cipher = cipher;

  // iter, split evenly over the two pbkdf2 phases

  const u32 iter = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if (iter < 2) return (PARSER_SALT_ITERATION);

  if ((iter % 2) != 0) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter - 1;

  // salt. The pbkdf2 salt is the hex string from the backup itself, taken as ascii, so it is
  // stored as is rather than decoded. Legacy backups carry an empty one, written as -.

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  if ((salt_len == 1) && (salt_pos[0] == '-'))
  {
    salt->salt_len = 0;
  }
  else
  {
    if ((salt_len % 2) != 0) return (PARSER_SALT_VALUE);

    if (is_valid_hex_string (salt_pos, salt_len) == false) return (PARSER_SALT_VALUE);

    memcpy (salt->salt_buf, salt_pos, salt_len);

    salt->salt_len = salt_len;
  }

  // iv. The token cannot take TOKEN_ATTR_VERIFY_HEX, because a legacy ECB line writes - here,
  // which is not hex, so the hex check is done by hand, as the salt above does

  const u8 *iv_pos = token.buf[5];
  const int iv_len = token.len[5];

  memset (blockio->iv_buf, 0, sizeof (blockio->iv_buf));

  if ((iv_len == 1) && (iv_pos[0] == '-'))
  {
    if (cipher != BLOCKIO_CIPHER_ECB) return (PARSER_SALT_VALUE);
  }
  else
  {
    const int iv_len_want = (cipher == BLOCKIO_CIPHER_CBC) ? 32 : 24;

    if (cipher == BLOCKIO_CIPHER_ECB) return (PARSER_SALT_VALUE);

    if (iv_len != iv_len_want) return (PARSER_SALT_VALUE);

    if (is_valid_hex_string (iv_pos, iv_len) == false) return (PARSER_SALT_VALUE);

    hex_decode (iv_pos, iv_len, (u8 *) blockio->iv_buf);

    for (int i = 0; i < 4; i++) blockio->iv_buf[i] = byte_swap_32 (blockio->iv_buf[i]);
  }

  // the first block of the ciphertext. The AES helpers read big endian words.

  const u8 *ct_pos = token.buf[6];
  const int ct_len = token.len[6];

  hex_decode (ct_pos, ct_len, (u8 *) blockio->ct_buf);

  for (int i = 0; i < 4; i++) blockio->ct_buf[i] = byte_swap_32 (blockio->ct_buf[i]);

  // the verifier is a known plaintext rather than a stored digest, so the ciphertext block stands
  // in for one, as hash-mode 37231 does

  digest[0] = blockio->ct_buf[0];
  digest[1] = blockio->ct_buf[1];
  digest[2] = blockio->ct_buf[2];
  digest[3] = blockio->ct_buf[3];

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const blockio_t *blockio = (const blockio_t *) esalt_buf;

  char salt_enc[50 + 1];

  if (salt->salt_len == 0)
  {
    salt_enc[0] = '-';
    salt_enc[1] = 0;
  }
  else
  {
    memcpy (salt_enc, salt->salt_buf, salt->salt_len);

    salt_enc[salt->salt_len] = 0;
  }

  char iv_enc[32 + 1];

  if (blockio->cipher == BLOCKIO_CIPHER_ECB)
  {
    iv_enc[0] = '-';
    iv_enc[1] = 0;
  }
  else
  {
    u32 tmp_iv_buf[4];

    for (int i = 0; i < 4; i++) tmp_iv_buf[i] = byte_swap_32 (blockio->iv_buf[i]);

    const u32 iv_len = (blockio->cipher == BLOCKIO_CIPHER_GCM) ? 12 : 16;

    memset (iv_enc, 0, sizeof (iv_enc));

    hex_encode ((const u8 *) tmp_iv_buf, iv_len, (u8 *) iv_enc);
  }

  u32 tmp_ct_buf[4];

  for (int i = 0; i < 4; i++) tmp_ct_buf[i] = byte_swap_32 (blockio->ct_buf[i]);

  char ct_hex[(16 * 2) + 1] = { 0 };

  hex_encode ((const u8 *) tmp_ct_buf, 16, (u8 *) ct_hex);

  const int line_len = snprintf (line_buf, line_size, "%s1*%u*%u*%s*%s*%s",
    SIGNATURE_BLOCKIO,
    blockio->cipher,
    salt->salt_iter + 1,
    salt_enc,
    iv_enc,
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
