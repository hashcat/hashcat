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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "GPG (AES-128/AES-256 (SHA-512($pass)))";
static const u64   KERN_TYPE      = 17020;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_AUX2
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$gpg$*1*668*2048*57e1f19c69a86038e23d7e5af5d810f4f86d32e9aaaf04b54281cda2194dcca99ee1f23f4aa3a011d5d2dc9e47689c449f398d315f91a03f4765742d20a7046e986a9696f0e07380a73fdd61e7ab2caa463a049a5869e008e16bb30d22f93f9aa8b0fdd41d2b19e669d58ca462498905e79944bff578c24139a88ef44582aef93f94fe22406a3ae32dcc0f0602e2f4345db2bd9d775eaeb14a8d7aff963e1ca8c29bab2fc3d459941587f4242af6e100e2e668a6c9247c19969ba294f6f2ab60ef84d42aab2e3512153a283d321442840189733dc6024dab0ea5d10d2e07fee914fc2e7177b310e8835bf8a5ffe1bde5ce0a74d3dd570c1b2652672873d3c520364acc0af35f5f7d0e0e95df8c2db3855936e0a4a24cc463bf277b0c5ea37d4ac1ddae6ef9da18852620de15ab648306f3d7acbb918e79f3ab7a3eaf4f59416560c4d31d8a0220c3301c95db4b8fe6b69348657aed52d5e15aefb17fedd15a50630a4edbad362ba9b79a048b4966a70643d8fa31fb397a531db85e8ad5bb169f5188449dbcc1bbaf42440d1794a34296c2407092c76e59544133959309ce42a05899162c55a865018085a4c57068294a5389cf6fbf1c93b5ab7732625fb6a465bd7ec51a128c2f9b0cf3fd0367f92667098b3a8af40f9f434a2a727b09bddbad1762127cc785eda419ac3ff24c8724e04ea2d330b0b441f34623955efd383f20578cdc527f3076ee068b727cd399ce17ff9d5233409b2d16d55c5c80cb8ca01019cd068c6e803217d6f2b7124e354b89de0eb0dfd241384026a1cdca529b6fed37aa0ececb0d6c26de06407d75a6e3108b0d25621db418206291a67216306e1a18c992736e45ef7f87373c0a3f28ddc1b4543604cd154f6b79265a6d8c13550078c3bcf55063263e5bc5cae6b925c1dbb67f972e234006867849e653*3*254*10*9*16*d1547688c9cc944482d16dff17df0858*20971520*1fef4e57e302d34e";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
u32         module_hash_category  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_CATEGORY;   }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_salt_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return SALT_TYPE;       }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }
const char *module_st_pass        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_PASS;         }

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];
  u32 modulus_size;
  u32 encrypted_data[384];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  u32 salted_pw_block[96];

  u32 salted_pw_block_len;

  u64 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];
  u32 w4[4];
  u32 w5[4];
  u32 w6[4];
  u32 w7[4];

  int len;

} gpg_tmp_t;

static const char *SIGNATURE_GPG = "$gpg$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (gpg_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (gpg_tmp_t);

  return tmp_size;
}

bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = true;

  return hlfmt_disable;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 65536;

  return kernel_loops_max;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

  gpg_t *gpgs = (gpg_t *) hashes->esalts_buf;

  gpg_t *gpg = &gpgs[digests_offset + digest_pos];

  if (gpg->cipher_algo == 7)
  {
    return KERN_RUN_AUX1;
  }
  else if (gpg->cipher_algo == 9)
  {
    return KERN_RUN_AUX2;
  }

  return 0;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  gpg_t *gpg = (gpg_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 13;

  // signature $gpg$
  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_GPG;

  // signature $gpg$
  token.sep[0]      = '*';
  token.len[0]      = 5;
  token.attr[0]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  // "1" -- unknown option
  token.sep[1]      = '*';
  token.len[1]      = 1;
  token.attr[1]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of the encrypted data in bytes
  token.sep[2]      = '*';
  token.len_min[2]  = 3;
  token.len_max[2]  = 4;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of the key: 1024, 2048, 4096, etc.
  token.sep[3]      = '*';
  token.len_min[3]  = 3;
  token.len_max[3]  = 4;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // encrypted key -- twice the amount of byte because its interpreted as characters
  token.sep[4]      = '*';
  token.len_min[4]  = 256;
  token.len_max[4]  = 3072;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  // "3" - String2Key parameter
  token.sep[5]      = '*';
  token.len[5]      = 1;
  token.attr[5]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // "254" - String2Key parameters
  token.sep[6]      = '*';
  token.len[6]      = 3;
  token.attr[6]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // "10" - String2Key parameters
  token.sep[7]      = '*';
  token.len[7]      = 2;
  token.attr[7]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // cipher mode: 7 or 9
  token.sep[8]      = '*';
  token.len[8]      = 1;
  token.attr[8]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of initial vector in bytes: 16
  token.sep[9]      = '*';
  token.len[9]      = 2;
  token.attr[9]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // initial vector - twice the amount of bytes because its interpreted as characters
  token.sep[10]     = '*';
  token.len[10]     = 32;
  token.attr[10]    = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  // iteration count
  token.sep[11]     = '*';
  token.len_min[11] = 1;
  token.len_max[11] = 8;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // salt - 8 bytes / 16 characters
  token.len[12]     = 16;
  token.attr[12]    = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Modulus size

  const int modulus_size = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if ((modulus_size < 256) || (modulus_size > 16384)) return (PARSER_SALT_LENGTH);

  gpg->modulus_size = modulus_size;

  // Encrypted data

  const int enc_data_size = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  const int encrypted_data_size = hex_decode ((const u8 *) token.buf[4], token.len[4], (u8 *) gpg->encrypted_data);

  if (enc_data_size != encrypted_data_size) return (PARSER_CT_LENGTH);

  gpg->encrypted_data_size = encrypted_data_size;

  // Check String2Key parameters

  if (hc_strtoul ((const char *) token.buf[5], NULL, 10) !=   3) return (PARSER_HASH_VALUE);
  if (hc_strtoul ((const char *) token.buf[6], NULL, 10) != 254) return (PARSER_HASH_VALUE);
  if (hc_strtoul ((const char *) token.buf[7], NULL, 10) !=  10) return (PARSER_HASH_VALUE);

  // Cipher algo

  const int cipher_algo = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if ((cipher_algo != 7) && (cipher_algo != 9)) return (PARSER_CIPHER);

  gpg->cipher_algo = cipher_algo;

  // IV (size)

  if (hc_strtoul ((const char *) token.buf[9], NULL, 10) != sizeof (gpg->iv)) return (PARSER_IV_LENGTH);

  const int iv_size = hex_decode ((const u8 *) token.buf[10], token.len[10], (u8 *) gpg->iv);

  if (iv_size != sizeof (gpg->iv)) return (PARSER_IV_LENGTH);

  // Salt Iter

  const u32 salt_iter = hc_strtoul ((const char *) token.buf[11], NULL, 10);

  if (salt_iter < 8 || salt_iter > 65011712) return (PARSER_SALT_ITERATION);

  salt->salt_iter = salt_iter;

  // Salt Value

  salt->salt_len = hex_decode ((const u8 *) token.buf[12], token.len[12], (u8 *) salt->salt_buf);

  if (salt->salt_len != 8) return (PARSER_SALT_LENGTH);

  // hash fake
  digest[0] = gpg->iv[0];
  digest[1] = gpg->iv[1];
  digest[2] = gpg->iv[2];
  digest[3] = gpg->iv[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const gpg_t *gpg = (const gpg_t *) esalt_buf;

  u8 encrypted_data[(384 * 8) + 1];

  hex_encode ((const u8 *) gpg->encrypted_data, gpg->encrypted_data_size, (u8 *) encrypted_data);

  const int line_len = snprintf (line_buf, line_size, "%s*%d*%d*%d*%s*%d*%d*%d*%d*%d*%08x%08x%08x%08x*%d*%08x%08x",
    SIGNATURE_GPG,
    1, /* unknown field */
    gpg->encrypted_data_size,
    gpg->modulus_size,
    encrypted_data,
    3, /* version (major?) */
    254, /* version (minor?) */
    10, /* key hash (sha-512) */
    gpg->cipher_algo,
    16, /*iv_size*/
    byte_swap_32 (gpg->iv[0]),
    byte_swap_32 (gpg->iv[1]),
    byte_swap_32 (gpg->iv[2]),
    byte_swap_32 (gpg->iv[3]),
    salt->salt_iter,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]));

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
  module_ctx->module_deprecated_notice        = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_extra_tuningdb_block     = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
  module_ctx->module_hash_decode_postprocess  = MODULE_DEFAULT;
  module_ctx->module_hash_decode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_decode_zero_hash    = MODULE_DEFAULT;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode_status       = MODULE_DEFAULT;
  module_ctx->module_hash_encode_potfile      = MODULE_DEFAULT;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hashes_count_min         = MODULE_DEFAULT;
  module_ctx->module_hashes_count_max         = MODULE_DEFAULT;
  module_ctx->module_hlfmt_disable            = module_hlfmt_disable;
  module_ctx->module_hook_extra_param_size    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_init    = MODULE_DEFAULT;
  module_ctx->module_hook_extra_param_term    = MODULE_DEFAULT;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = MODULE_DEFAULT;
  module_ctx->module_outfile_check_nocomp     = MODULE_DEFAULT;
  module_ctx->module_potfile_custom_check     = MODULE_DEFAULT;
  module_ctx->module_potfile_disable          = MODULE_DEFAULT;
  module_ctx->module_potfile_keep_all_hashes  = MODULE_DEFAULT;
  module_ctx->module_pwdump_column            = MODULE_DEFAULT;
  module_ctx->module_pw_max                   = MODULE_DEFAULT;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
