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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "AxCrypt 2 AES-128";
static const u64   KERN_TYPE      = 23500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_INIT2
                                  | OPTS_TYPE_LOOP2;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$axcrypt$*2*10000*6d44c6d19076bce9920c5fb76b246c161926ce65abb93ec2003919d78898aadd5bc6e5754201ff25d681ad89fa2861d20ef7c3fd7bde051909dfef8adcb50491*68f78a1b80291a42b2a117d6209d3eb3541a8d47ed6b970b2b8294b2bc78347fc2b494a0599f8cba6d45e88fd8fbc5b4dd7e888f6c9543e679489de132167222e130d5925278693ad8599284705fdf99360b2199ed0005be05867b9b7aa6bb4be76f5f979819eb27cf590a47d81830575b2af09dda756360c844b89c7dcec099cfdd27d2d0c95d24f143405f303e4843*1000*debdeb8ea7b9800b01855de09b105fdb8840efc1f67dc742283d13a5570165f8";

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

typedef struct axcrypt2
{
  u32 salt[16];
  u32 data[36];

} axcrypt2_t;

typedef struct axcrypt2_tmp
{
  u64 ipad[8];
  u64 opad[8];

  u64 dgst[8];
  u64 out[8];

  u32 KEK[4];
  u32 data[10];

} axcrypt2_tmp_t;

static const char *SIGNATURE_AXCRYPT2 = "$axcrypt$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (axcrypt2_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (axcrypt2_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  // this overrides the reductions of PW_MAX in case optimized kernel is selected
  // IOW, even in optimized kernel mode it support length 256

  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  axcrypt2_t *axcrypt2 = (axcrypt2_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_AXCRYPT2;

  token.sep[0]     = '*';
  token.len_min[0] = 9;
  token.len_max[0] = 9;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 7;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 128;
  token.len_max[3] = 128;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 288;
  token.len_max[4] = 288;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 7;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[6]     = 64;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  if (version_pos[0] != '2') return (PARSER_SIGNATURE_UNMATCHED);

  // iterations wrap

  const u8 *iter_wrap_pos = token.buf[2];

  const u32 iter_wrap = hc_strtoul ((const char *) iter_wrap_pos, NULL, 10);

  if (iter_wrap <       1) return (PARSER_SALT_ITERATION);
  if (iter_wrap > 9999999) return (PARSER_SALT_ITERATION);

  salt->salt_iter2 = iter_wrap;

  // salt wrap

  const u8 *salt_wrap_pos = token.buf[3];
  const int salt_wrap_len = token.len[3];

  hex_decode (salt_wrap_pos, salt_wrap_len, (u8 *) axcrypt2->salt);

  for (int i = 0; i < 16; i++)
  {
    axcrypt2->salt[i] = byte_swap_32 (axcrypt2->salt[i]);
  }

  // data wrap

  const u8 *data_pos = token.buf[4];
  const int data_len = token.len[4];

  hex_decode (data_pos, data_len, (u8 *) axcrypt2->data);

  for (int i = 0; i < 36; i++)
  {
    axcrypt2->data[i] = byte_swap_32 (axcrypt2->data[i]);
  }

  // iterations KDF

  const u8 *iter_kdf_pos = token.buf[5];

  const u32 iter_kdf = hc_strtoul ((const char *) iter_kdf_pos, NULL, 10);

  if (iter_kdf <       1) return (PARSER_SALT_ITERATION);
  if (iter_kdf > 9999999) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter_kdf - 1;

  // salt KDF

  const u8 *salt_kdf_pos = token.buf[6];
  const int salt_kdf_len = token.len[6];

  salt->salt_len = hex_decode (salt_kdf_pos, salt_kdf_len, (u8 *) salt->salt_buf);

  for (int i = 0; i < 8; i++)
  {
    salt->salt_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  if (salt->salt_len != 32) return (PARSER_SALT_LENGTH);

  // fake hash

  digest[0] = axcrypt2->data[0];
  digest[1] = axcrypt2->data[1];
  digest[2] = axcrypt2->data[2];
  digest[3] = axcrypt2->data[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  axcrypt2_t *axcrypt2 = (axcrypt2_t *) esalt_buf;

  // salt wrap buffer

  u32 tmp_buf[256 + 1] = { 0 };

  for (int i = 0; i < 16; i++)
  {
    tmp_buf[i] = byte_swap_32 (axcrypt2->salt[i]);
  }

  u8 salt_wrap_buf[128 + 1] = { 0 };

  hex_encode ((const u8 *) tmp_buf, 64, salt_wrap_buf);

  // data wrap buffer

  memset (tmp_buf, 0, sizeof (tmp_buf));

  for (int i = 0; i < 36; i++)
  {
    tmp_buf[i] = byte_swap_32 (axcrypt2->data[i]);
  }

  u8 data_wrap_buf[288 + 1] = { 0 };

  hex_encode ((const u8 *) tmp_buf, 144, data_wrap_buf);

  // salt kdf buffer

  memset (tmp_buf, 0, sizeof (tmp_buf));

  for (int i = 0; i < 8; i++)
  {
    tmp_buf[i] = byte_swap_32 (salt->salt_buf[i]);
  }

  u8 salt_kdf_buf[64 + 1] = { 0 };

  hex_encode ((const u8 *) tmp_buf, 32, salt_kdf_buf);

  const int line_len = snprintf (line_buf, line_size, "%s*2*%i*%s*%s*%i*%s",
    SIGNATURE_AXCRYPT2,
    salt->salt_iter2,
    salt_wrap_buf,
    data_wrap_buf,
    salt->salt_iter + 1,
    salt_kdf_buf);

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
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
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
  module_ctx->module_hlfmt_disable            = MODULE_DEFAULT;
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
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
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
  module_ctx->module_pw_max                   = module_pw_max;
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
