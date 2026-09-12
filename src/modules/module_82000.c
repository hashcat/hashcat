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
#include "emu_inc_cipher_des.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_CIPHER_KPA;
static const char *HASH_NAME      = "MIFARE Ultralight C 3DES Key Recovery";
static const u64   KERN_TYPE      = 82000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_TM_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = " N@B";
static const char *ST_HASH        = "$mfulc$1$3$0$ec9c5cf763244367$2283bfe8debe1780$922327794d0706ef$48444c4a4044524200000000544e5846";

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

typedef struct mfulc
{
  u32 mode;
  u32 segment;
  u32 lfsr_type;

  u32 ct0;
  u32 ct1;

  u32 erndb0;
  u32 erndb1;

  u32 iv0;
  u32 iv1;

  u32 k1_0;
  u32 k1_1;

  u32 k2_0;
  u32 k2_1;

} mfulc_t;

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE && device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    return true;
  }

  return false;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
  {
    return jit_build_options;
  }

  if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) && (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }
  else if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP)
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }
  else if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == true))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }
  else if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == false))
  {
    hc_asprintf (&jit_build_options, "-D _unroll");
  }

  return jit_build_options;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u32 kernel_loops_max = KERNEL_LOOPS_MAX;

  if (user_options->slow_candidates == false)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      kernel_loops_max = 1024;
    }
  }

  return kernel_loops_max;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u32 kernel_loops_min = KERNEL_LOOPS_MIN;

  if (user_options->slow_candidates == false)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      kernel_loops_min = 1024;
    }
  }

  return kernel_loops_min;
}

u32 module_pw_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_min = 4;

  return pw_min;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 4;

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?b?b?b?b";

  return mask;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (mfulc_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  mfulc_t *esalt = (mfulc_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // $mfulc$<mode>$<segment>$<lfsr_type>$<ERndB>$<CBC_Block1>$<CBC_Block2>$<base_key>
  //
  // Reader mode (-r):
  //   ERndB      = tag's encrypted RndB
  //   CBC_Block1 = first 8 bytes of reader's E(RndA||RndB') response
  //   CBC_Block2 = second 8 bytes of reader's E(RndA||RndB') response
  //
  // Counterfeit mode (-c):
  //   ERndB      = zeroed (unused)
  //   CBC_Block1 = zeroed (unused)
  //   CBC_Block2 = target key ERndB (encrypted RndB under unknown key)

  token.token_cnt = 8;

  // signature
  token.signatures_cnt = 1;
  token.signatures_buf[0] = "$mfulc$";

  token.len[0]     = 7;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // mode: 0 = counterfeit, 1 = reader
  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  // segment: 1-4 (which 4-byte key segment to brute-force)
  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // lfsr_type: 0 = unused, 1 = ULCG, 2 = MFC
  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 1;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // ERndB (16 hex = 8 bytes)
  token.sep[4]     = '$';
  token.len[4]     = 16;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // CBC_Block1 (16 hex = 8 bytes)
  token.sep[5]     = '$';
  token.len[5]     = 16;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // CBC_Block2 / target_key_ERndB (16 hex = 8 bytes)
  token.sep[6]     = '$';
  token.len[6]     = 16;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  // base_key: K1||K2 with unknown segment zeroed (32 hex = 16 bytes)
  token.sep[7]     = '$';
  token.len[7]     = 32;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // mode

  const u8 *mode_pos = token.buf[1];
  const u32 mode = mode_pos[0] - '0';

  if (mode > 1) return (PARSER_SALT_VALUE);

  esalt->mode = mode;

  // segment

  const u8 *seg_pos = token.buf[2];
  const u32 seg = seg_pos[0] - '0';

  if (seg < 1 || seg > 4) return (PARSER_SALT_VALUE);

  esalt->segment = seg - 1;

  // lfsr_type

  const u8 *lfsr_pos = token.buf[3];
  const u32 lfsr = lfsr_pos[0] - '0';

  if (lfsr > 2) return (PARSER_SALT_VALUE);

  esalt->lfsr_type = lfsr;

  // ERndB

  const u8 *erndb_pos = token.buf[4];

  esalt->erndb0 = hex_to_u32 (erndb_pos + 0);
  esalt->erndb1 = hex_to_u32 (erndb_pos + 8);

  // CBC_Block1

  const u8 *blk1_pos = token.buf[5];

  esalt->iv0 = hex_to_u32 (blk1_pos + 0);
  esalt->iv1 = hex_to_u32 (blk1_pos + 8);

  // CBC_Block2 / target_key_ERndB

  const u8 *blk2_pos = token.buf[6];

  esalt->ct0 = hex_to_u32 (blk2_pos + 0);
  esalt->ct1 = hex_to_u32 (blk2_pos + 8);

  // base_key

  const u8 *key_pos = token.buf[7];

  esalt->k1_0 = hex_to_u32 (key_pos +  0);
  esalt->k1_1 = hex_to_u32 (key_pos +  8);
  esalt->k2_0 = hex_to_u32 (key_pos + 16);
  esalt->k2_1 = hex_to_u32 (key_pos + 24);

  u32 ct0_ip = esalt->ct0;
  u32 ct1_ip = esalt->ct1;

  DES_IP (ct0_ip, ct1_ip);

  salt->salt_buf_pc[0] = ct0_ip;
  salt->salt_buf_pc[1] = ct1_ip;

  u32 er0_ip = esalt->erndb0;
  u32 er1_ip = esalt->erndb1;

  DES_IP (er0_ip, er1_ip);

  salt->salt_buf_pc[2]  = er0_ip;
  salt->salt_buf_pc[3]  = er1_ip;
  salt->salt_buf_pc[4]  = esalt->iv0;
  salt->salt_buf_pc[5]  = esalt->iv1;
  salt->salt_buf_pc[6]  = esalt->k1_0;
  salt->salt_buf_pc[7]  = esalt->k1_1;
  salt->salt_buf_pc[8]  = esalt->k2_0;
  salt->salt_buf_pc[9]  = esalt->k2_1;
  salt->salt_buf_pc[10] = esalt->mode;
  salt->salt_buf_pc[11] = esalt->segment;
  salt->salt_buf_pc[12] = esalt->lfsr_type;

  // salt for unique grouping

  salt->salt_buf[0] = esalt->ct0;
  salt->salt_buf[1] = esalt->ct1;
  salt->salt_buf[2] = esalt->erndb0;
  salt->salt_buf[3] = esalt->erndb1;
  salt->salt_buf[4] = esalt->iv0;
  salt->salt_buf[5] = esalt->iv1;
  salt->salt_buf[6] = esalt->mode | (esalt->segment << 8) | (esalt->lfsr_type << 16);

  salt->salt_len = 28;

  digest[0] = esalt->ct0;
  digest[1] = esalt->ct1;
  digest[2] = esalt->erndb0;
  digest[3] = esalt->erndb1;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const mfulc_t *esalt = (const mfulc_t *) esalt_buf;

  int out_len = snprintf (line_buf, line_size,
    "$mfulc$%u$%u$%u$%08x%08x$%08x%08x$%08x%08x$%08x%08x%08x%08x",
    esalt->mode,
    esalt->segment + 1,
    esalt->lfsr_type,
    esalt->erndb0, esalt->erndb1,
    esalt->iv0, esalt->iv1,
    esalt->ct0, esalt->ct1,
    esalt->k1_0, esalt->k1_1,
    esalt->k2_0, esalt->k2_1);

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
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
  module_ctx->module_jit_build_options        = module_jit_build_options;
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
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = module_pw_min;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
