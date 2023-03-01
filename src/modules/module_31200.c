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
static const char *HASH_NAME      = "Veeam VBK";
static const u64   KERN_TYPE      = 31200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$vbk$*54731702769149752741495960625996207399688284541933702394775960978730695504382155223405444342855920150089170058956647576461877712*10000*78cf7df8f1ed8bb50bda1129ec8e6810";

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

typedef struct veeam_vbk
{
  u32 ct_buf[4];

} veeam_vbk_t;

static const char *SIGNATURE_VEEAM_VBK = "$vbk$";

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

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (veeam_vbk_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  veeam_vbk_t *veeam_vbk = (veeam_vbk_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_VEEAM_VBK;

  token.sep[0]     = '*';
  token.len_min[0] = 5;
  token.len_max[0] = 5;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '*';
  token.len_min[1]  = 128;
  token.len_max[1]  = 128;
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 10;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_HEX
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // salt

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  if (salt_len != 128) return (PARSER_SALT_LENGTH);

  salt->salt_buf[ 0] = hex_to_u32 (salt_pos +   0);
  salt->salt_buf[ 1] = hex_to_u32 (salt_pos +   8);
  salt->salt_buf[ 2] = hex_to_u32 (salt_pos +  16);
  salt->salt_buf[ 3] = hex_to_u32 (salt_pos +  24);
  salt->salt_buf[ 4] = hex_to_u32 (salt_pos +  32);
  salt->salt_buf[ 5] = hex_to_u32 (salt_pos +  40);
  salt->salt_buf[ 6] = hex_to_u32 (salt_pos +  48);
  salt->salt_buf[ 7] = hex_to_u32 (salt_pos +  56);
  salt->salt_buf[ 8] = hex_to_u32 (salt_pos +  64);
  salt->salt_buf[ 9] = hex_to_u32 (salt_pos +  72);
  salt->salt_buf[10] = hex_to_u32 (salt_pos +  80);
  salt->salt_buf[11] = hex_to_u32 (salt_pos +  88);
  salt->salt_buf[12] = hex_to_u32 (salt_pos +  96);
  salt->salt_buf[13] = hex_to_u32 (salt_pos + 104);
  salt->salt_buf[14] = hex_to_u32 (salt_pos + 112);
  salt->salt_buf[15] = hex_to_u32 (salt_pos + 120);

  salt->salt_buf[ 0] = byte_swap_32 (salt->salt_buf[ 0]);
  salt->salt_buf[ 1] = byte_swap_32 (salt->salt_buf[ 1]);
  salt->salt_buf[ 2] = byte_swap_32 (salt->salt_buf[ 2]);
  salt->salt_buf[ 3] = byte_swap_32 (salt->salt_buf[ 3]);
  salt->salt_buf[ 4] = byte_swap_32 (salt->salt_buf[ 4]);
  salt->salt_buf[ 5] = byte_swap_32 (salt->salt_buf[ 5]);
  salt->salt_buf[ 6] = byte_swap_32 (salt->salt_buf[ 6]);
  salt->salt_buf[ 7] = byte_swap_32 (salt->salt_buf[ 7]);
  salt->salt_buf[ 8] = byte_swap_32 (salt->salt_buf[ 8]);
  salt->salt_buf[ 9] = byte_swap_32 (salt->salt_buf[ 9]);
  salt->salt_buf[10] = byte_swap_32 (salt->salt_buf[10]);
  salt->salt_buf[11] = byte_swap_32 (salt->salt_buf[11]);
  salt->salt_buf[12] = byte_swap_32 (salt->salt_buf[12]);
  salt->salt_buf[13] = byte_swap_32 (salt->salt_buf[13]);
  salt->salt_buf[14] = byte_swap_32 (salt->salt_buf[14]);
  salt->salt_buf[15] = byte_swap_32 (salt->salt_buf[15]);

  salt->salt_len = 64;

  // iter

  const u8 *iter_pos = token.buf[2];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // ct

  const u8 *ct_pos = token.buf[3];
  const int ct_len = token.len[3];

  if (ct_len != 32) return (PARSER_HASH_LENGTH);

  veeam_vbk->ct_buf[0] = hex_to_u32 (ct_pos +  0);
  veeam_vbk->ct_buf[1] = hex_to_u32 (ct_pos +  8);
  veeam_vbk->ct_buf[2] = hex_to_u32 (ct_pos + 16);
  veeam_vbk->ct_buf[3] = hex_to_u32 (ct_pos + 24);

  veeam_vbk->ct_buf[0] = byte_swap_32 (veeam_vbk->ct_buf[0]);
  veeam_vbk->ct_buf[1] = byte_swap_32 (veeam_vbk->ct_buf[1]);
  veeam_vbk->ct_buf[2] = byte_swap_32 (veeam_vbk->ct_buf[2]);
  veeam_vbk->ct_buf[3] = byte_swap_32 (veeam_vbk->ct_buf[3]);

  // hash

  digest[0] = veeam_vbk->ct_buf[0];
  digest[1] = veeam_vbk->ct_buf[1];
  digest[2] = veeam_vbk->ct_buf[2];
  digest[3] = veeam_vbk->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  //const u32 *digest = (const u32 *) digest_buf;

  const veeam_vbk_t *veeam_vbk = (const veeam_vbk_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x*%d*%08x%08x%08x%08x",
    SIGNATURE_VEEAM_VBK,
    salt->salt_buf[ 0],
    salt->salt_buf[ 1],
    salt->salt_buf[ 2],
    salt->salt_buf[ 3],
    salt->salt_buf[ 4],
    salt->salt_buf[ 5],
    salt->salt_buf[ 6],
    salt->salt_buf[ 7],
    salt->salt_buf[ 8],
    salt->salt_buf[ 9],
    salt->salt_buf[10],
    salt->salt_buf[11],
    salt->salt_buf[12],
    salt->salt_buf[13],
    salt->salt_buf[14],
    salt->salt_buf[15],
    salt->salt_iter + 1,
    veeam_vbk->ct_buf[0],
    veeam_vbk->ct_buf[1],
    veeam_vbk->ct_buf[2],
    veeam_vbk->ct_buf[3]);

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
