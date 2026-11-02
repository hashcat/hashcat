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
static const char *HASH_NAME      = "Bitcoin/Litecoin wallet.dat";
static const u64   KERN_TYPE      = 11300;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_ST_ADD80
                                  | OPTS_TYPE_HASH_COPY
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$bitcoin$96$c265931309b4a59307921cf054b4ec6b6e4554369be79802e94e16477645777d948ae1d375191831efc78e5acd1f0443$16$8017214013543185$200460$96$480008005625057442352316337722323437108374245623701184230273883222762730232857701607167815448714$66$014754433300175043011633205413774877455616682000536368706315333388";

#include "hooks_common.c"

typedef struct bitcoin_wallet
{
  u32 cry_master_buf[64];
  u32 cry_master_len;

  u32 cry_salt_buf[16];
  u32 cry_salt_len;

} bitcoin_wallet_t;

typedef struct bitcoin_wallet_tmp
{
  u64 dgst[8];

} bitcoin_wallet_tmp_t;

static const char *SIGNATURE_BITCOIN_WALLET = "$bitcoin$";

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // Extra treatment for Apple systems
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  // NVIDIA GPU
  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
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

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_3;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (bitcoin_wallet_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bitcoin_wallet_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  bitcoin_wallet_t *bitcoin_wallet = (bitcoin_wallet_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_BITCOIN_WALLET;

  token.len[0]     = 9;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 2;
  token.len_max[1] = 3;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 64;
  token.len_max[2] = 256;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = 2;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 16;
  token.len_max[4] = 36;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len_min[5] = 1;
  token.len_max[5] = 6;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len_min[6] = 0;
  token.len_max[6] = 6;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '$';
  token.len_min[7] = 0;
  token.len_max[7] = 999999;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[8]     = '$';
  token.len_min[8] = 0;
  token.len_max[8] = 6;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[9]     = '$';
  token.len_min[9] = 0;
  token.len_max[9] = 999999;
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *cry_master_len_pos  = token.buf[1];
  const u8 *cry_master_buf_pos  = token.buf[2];
  const u8 *cry_salt_len_pos    = token.buf[3];
  const u8 *cry_salt_buf_pos    = token.buf[4];
  const u8 *cry_rounds_pos      = token.buf[5];
  const u8 *ckey_len_pos        = token.buf[6];
  const u8 *public_key_len_pos  = token.buf[8];

  const int cry_master_buf_len  = token.len[2];
  const int cry_salt_buf_len    = token.len[4];
  const int ckey_buf_len        = token.len[7];
  const int public_key_buf_len  = token.len[9];

  // verify

  const int cry_master_len = hc_strtoul ((const char *) cry_master_len_pos, NULL, 10);
  const int cry_salt_len   = hc_strtoul ((const char *) cry_salt_len_pos,   NULL, 10);
  const int ckey_len       = hc_strtoul ((const char *) ckey_len_pos,       NULL, 10);
  const int public_key_len = hc_strtoul ((const char *) public_key_len_pos, NULL, 10);

  if (cry_master_buf_len != cry_master_len) return (PARSER_SALT_VALUE);
  if (cry_salt_buf_len   != cry_salt_len)   return (PARSER_SALT_VALUE);
  if (ckey_buf_len       != ckey_len)       return (PARSER_SALT_VALUE);
  if (public_key_buf_len != public_key_len) return (PARSER_SALT_VALUE);

  if (cry_master_len < 64) return (PARSER_SALT_VALUE);
  if (cry_master_len % 32) return (PARSER_SALT_VALUE);

  if (cry_salt_len != 16 && cry_salt_len != 36) return (PARSER_SALT_VALUE);

  // esalt

  for (int i = 0, j = 0; j < cry_master_len; i += 1, j += 8)
  {
    bitcoin_wallet->cry_master_buf[i] = hex_to_u32 (&cry_master_buf_pos[j]);
  }

  bitcoin_wallet->cry_master_len = cry_master_len / 2;

  // hash

  digest[0] = bitcoin_wallet->cry_master_buf[0];
  digest[1] = bitcoin_wallet->cry_master_buf[1];
  digest[2] = bitcoin_wallet->cry_master_buf[2];
  digest[3] = bitcoin_wallet->cry_master_buf[3];

  // iter

  const int cry_rounds = hc_strtoul ((const char *) cry_rounds_pos, NULL, 10);

  if (cry_rounds < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = cry_rounds - 1;

  // esalt

  const bool parse_rc = generic_salt_decode (hashconfig, cry_salt_buf_pos, cry_salt_buf_len, (u8 *) bitcoin_wallet->cry_salt_buf, (int *) &bitcoin_wallet->cry_salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  // salt

  salt->salt_buf[0] = bitcoin_wallet->cry_salt_buf[0];
  salt->salt_buf[1] = bitcoin_wallet->cry_salt_buf[1];

  salt->salt_len = 8;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
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
}
