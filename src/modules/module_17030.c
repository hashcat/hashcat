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
static const char *HASH_NAME      = "GPG (AES-128/AES-256 (SHA-256($pass)))";
static const u64   KERN_TYPE      = 17030;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_AUX2
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "8CdhZ2J8umrHg0tMjB0NDRDpKKFeL7i";
static const char *ST_HASH        = "$gpg$*1*668*2048*e75985b4e7d0bce9e38925a5cf69494ae9a2ccfe2973f077d9423642fffec8bee0e327178a4a3431875ca1f377b9f89269e7c42b94150859d9e5bf5c4504d63076b270118183dda75d253492be8b680c0061e7f130010a00a09a0456710051f2483052ad209fcb9f194f78ecd04fd04953fa1cd6f7ce9babca8b2ee6432730de069648460b2822fe355ed19e0055c69251097681901d7183626019d938727399df47f5249f25b1c73e8654bf935014533845f278e6dd94b8c2964ad6a87c718967686f39a88b21a0e5a93321d4733c81d9310955db6990d8cd02bcf73159b1f48f5615def601aa3e12bf30384da41b558b1eef1111cfc85c8772c123a7b977e2ba399f65679c35b9a2abfde0230a5706fe99f5460c700b1498b1661353ec30eab25defb9af2e7e744fd050d2e7c87542d8bc49e728a7734accf2801dc5972192670858f2004308f3afdd94acd44e1161c44dd372296ca7fe40cbb541c21d640a10df34460c4f5c7cd1bf3b3282668d7edb53be4d843aef4b6f0357526d9c4432aa2a45e113a73e75bfec98cb4cc020ab6cca35336fd188140fd16183dbe288707421e698b6e4801508ae903de3e5d600bd613ea612af92780e53be37722897edb8a588193e7d28819c2f0cbb4e97c3e830113ce14ab05ddb82552fc5e82c386ec2fe9b2d86fc7ade39e341e3dd828502cc3dd038cb21cb0512e79dca9f5a9eae78b2e91aa0732ac77fbc3bc5575c210f519c178669ea99bef62eb6761dfa76407d0d501b07a696a0214dafde7b0bfb48e8ba445b6b42a859a63cb91c9d991ed030ef9e6c63f53b395e14821d7039e4455e0e3712f77f64b7abaa04467bd5b9be26c5e098430187676d0aa7206e2e4fa2e5b7bd486d18b0f3859e94319ccac587574a7bae6ccb3e9414cc769761cf6a0fa1b33cccd1a4b0b04c0d52cd*3*254*8*9*16*343d26cf2c10a8f8a161874fbb218c12*65536*666ae8d1c98404b0";

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

  u32 h[8];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

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
  token.len[7]      = 1;
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
  if (hc_strtoul ((const char *) token.buf[7], NULL, 10) !=   8) return (PARSER_HASH_VALUE);

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
    8, /* key hash (sha-256) */
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
