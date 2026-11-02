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
static const char *HASH_NAME      = "MetaMask Mobile Wallet";
static const u64   KERN_TYPE      = 31900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat1";
static const char *ST_HASH        = "$metamaskMobile$JV4j2dUDl7n+sujyqW3Wvg==$398f9b04c822d36bfcbdd1e68c82d1e8$auj3J2TwOZ4ev3UIGmNa7VXLh0Nmzr3rDbpXRRrONr4=";

#include "hooks_common.c"

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/metamask2hashcat.py to extract the hashes";
}

typedef struct pbkdf2_sha512_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[32];
  u64 out[32];

} pbkdf2_sha512_tmp_t;

typedef struct pbkdf2_sha512_aes_cbc
{
  u32 salt_buf[64];
  u32 iv_buf[4];
  u32 iv_len;
  u32 ct_buf[8];
  u32 ct_len;

} pbkdf2_sha512_aes_cbc_t;

static const u32   ROUNDS_METAMASK_WALLET    = 5000;
static const char *SIGNATURE_METAMASK_WALLET = "$metamaskMobile$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
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

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha512_aes_cbc_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 8;

  return pw_min;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pbkdf2_sha512_aes_cbc_t *metamask = (pbkdf2_sha512_aes_cbc_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));
  
  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_METAMASK_WALLET;

  token.len[0]     = 16;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 0;
  token.len_max[1] = 60;   //includes 44 bytes salt
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_OPTIONAL_ROUNDS;

  token.sep[2]     = '$';
  token.len[2]     = 32;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 44;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);
  
  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);
  
  salt->salt_iter = ROUNDS_METAMASK_WALLET - 1;
  
  if (token.opt_len != -1)
  {
    const u32 iter = hc_strtoul ((const char *) token.opt_buf + 7, NULL, 10); // 7 = "rounds="

    if (iter < 1) return (PARSER_SALT_ITERATION);

    salt->salt_iter = iter - 1;
  }
  
  size_t tmp_len = 0;

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  memcpy ((u8 *) metamask->salt_buf, salt_pos, salt_len);

  salt->salt_len = salt_len;

  memcpy ((u8 *) salt->salt_buf, metamask->salt_buf, salt->salt_len);

  // iv

  const u8 *iv_pos = token.buf[2];
  const int iv_len = token.len[2] / 2;

  metamask->iv_buf[0] = hex_to_u32 (iv_pos +  0);
  metamask->iv_buf[1] = hex_to_u32 (iv_pos +  8);
  metamask->iv_buf[2] = hex_to_u32 (iv_pos + 16);
  metamask->iv_buf[3] = hex_to_u32 (iv_pos + 24);

  metamask->iv_buf[0] = byte_swap_32 (metamask->iv_buf[0]);
  metamask->iv_buf[1] = byte_swap_32 (metamask->iv_buf[1]);
  metamask->iv_buf[2] = byte_swap_32 (metamask->iv_buf[2]);
  metamask->iv_buf[3] = byte_swap_32 (metamask->iv_buf[3]);

  metamask->iv_len = iv_len;

  // ciphertext

  const u8 *ct_pos = token.buf[3];
  const int ct_len = token.len[3];

  u8 tmp_buf[44+1];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  tmp_len = base64_decode (base64_to_int, ct_pos, ct_len, tmp_buf);

  if (tmp_len != 32) return (PARSER_CT_LENGTH);

  memcpy ((u8 *) metamask->ct_buf, tmp_buf, tmp_len);

  metamask->ct_buf[0] = byte_swap_32 (metamask->ct_buf[0]);
  metamask->ct_buf[1] = byte_swap_32 (metamask->ct_buf[1]);
  metamask->ct_buf[2] = byte_swap_32 (metamask->ct_buf[2]);
  metamask->ct_buf[3] = byte_swap_32 (metamask->ct_buf[3]);
  metamask->ct_buf[4] = byte_swap_32 (metamask->ct_buf[4]);
  metamask->ct_buf[5] = byte_swap_32 (metamask->ct_buf[5]);
  metamask->ct_buf[6] = byte_swap_32 (metamask->ct_buf[6]);
  metamask->ct_buf[7] = byte_swap_32 (metamask->ct_buf[7]);

  metamask->ct_len = tmp_len / 4;

  // digest

  digest[0] = metamask->ct_buf[0];
  digest[1] = metamask->ct_buf[1];
  digest[2] = metamask->ct_buf[2];
  digest[3] = metamask->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  pbkdf2_sha512_aes_cbc_t *metamask = (pbkdf2_sha512_aes_cbc_t *) esalt_buf;

  // salt

  u8 *salt_buf = (u8 *) salt->salt_buf;

  // iv

  u8 iv_buf[32+1];

  memset (iv_buf, 0, sizeof (iv_buf));

  u32_to_hex (byte_swap_32 (metamask->iv_buf[0]), iv_buf +  0);
  u32_to_hex (byte_swap_32 (metamask->iv_buf[1]), iv_buf +  8);
  u32_to_hex (byte_swap_32 (metamask->iv_buf[2]), iv_buf + 16);
  u32_to_hex (byte_swap_32 (metamask->iv_buf[3]), iv_buf + 24);

  // ct

  u32 tmp_buf[8];

  tmp_buf[0] = byte_swap_32 (metamask->ct_buf[0]);
  tmp_buf[1] = byte_swap_32 (metamask->ct_buf[1]);
  tmp_buf[2] = byte_swap_32 (metamask->ct_buf[2]);
  tmp_buf[3] = byte_swap_32 (metamask->ct_buf[3]);
  tmp_buf[4] = byte_swap_32 (metamask->ct_buf[4]);
  tmp_buf[5] = byte_swap_32 (metamask->ct_buf[5]);
  tmp_buf[6] = byte_swap_32 (metamask->ct_buf[6]);
  tmp_buf[7] = byte_swap_32 (metamask->ct_buf[7]);

  u8 ct_buf[44+1];

  memset (ct_buf, 0, sizeof (ct_buf));

  base64_encode (int_to_base64, (const u8 *) tmp_buf, (const int) metamask->ct_len * 4, ct_buf);

  u8 *out_buf = (u8 *) line_buf;

  if (salt->salt_iter + 1 != ROUNDS_METAMASK_WALLET)
    return snprintf ((char *) out_buf, line_size, "%srounds=%d$%s$%s$%s",
      SIGNATURE_METAMASK_WALLET,
      salt->salt_iter + 1,
      salt_buf,
      iv_buf,
      ct_buf);
  else
    return snprintf ((char *) out_buf, line_size, "%s%s$%s$%s",
        SIGNATURE_METAMASK_WALLET,
        salt_buf,
        iv_buf,
        ct_buf);
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_usage_notice             = module_usage_notice;
}
