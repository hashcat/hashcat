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
static const u32   DGST_SIZE      = DGST_SIZE_4_6;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FORUM_SOFTWARE;
static const char *HASH_NAME      = "bcrypt(sha512($pass)) / bcryptsha512";
static const u64   KERN_TYPE      = 28400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$2a$12$KhivLhCuLhSyMBOxLxCyLu78x4z2X/EJdZNfS3Gy36fvRt56P2jbS";

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

static const char *SIGNATURE_BCRYPT1 = "$2a$";
static const char *SIGNATURE_BCRYPT2 = "$2b$";
static const char *SIGNATURE_BCRYPT3 = "$2x$";
static const char *SIGNATURE_BCRYPT4 = "$2y$";

typedef struct bcrypt_tmp
{
  u32 E[18];

  u32 P[18];

  u32 S0[256];
  u32 S1[256];
  u32 S2[256];
  u32 S3[256];

} bcrypt_tmp_t;

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (bcrypt_tmp_t);

  return tmp_size;
}

bool module_jit_cache_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  return true;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // this mode heavily depends on the available shared memory size
  // note the kernel need to have some special code changes in order to make use to use post-48k memory region
  // we need to set some macros

  bool use_dynamic = false;

  if (device_param->is_cuda == true)
  {
    use_dynamic = true;
  }

  // this uses some nice feedback effect.
  // based on the device_local_mem_size the reqd_work_group_size in the kernel is set to some value
  // which is then is read from the opencl host in the kernel_preferred_wgs_multiple1/2/3 result.
  // therefore we do not need to set module_kernel_threads_min/max except for CPU, where the threads are set to fixed 1.

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", 1);
  }
  else
  {
    u32 overhead = 0;

    if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
    {
      // note we need to use device_param->device_local_mem_size - 4 because opencl jit returns with:
      // Entry function '...' uses too much shared data (0xc004 bytes, 0xc000 max)
      // on my development system. no clue where the 4 bytes are spent.
      // I did some research on this and it seems to be related with the datatype.
      // For example, if i used u8 instead, there's only 1 byte wasted.

      if (device_param->is_opencl == true)
      {
        overhead = 1;
      }
    }

    if (user_options->kernel_threads_chgd == true)
    {
      u32 fixed_local_size = user_options->kernel_threads;

      if (use_dynamic == true)
      {
        if ((fixed_local_size * 4096) > device_param->kernel_dynamic_local_mem_size_memset)
        {
          // otherwise out-of-bound reads

          fixed_local_size = device_param->kernel_dynamic_local_mem_size_memset / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        if ((fixed_local_size * 4096) > (device_param->device_local_mem_size - overhead))
        {
          // otherwise out-of-bound reads

          fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", fixed_local_size);
      }
    }
    else
    {
      if (use_dynamic == true)
      {
        // using kernel_dynamic_local_mem_size_memset is a bit hackish.
        // we had to brute-force this value out of an already loaded CUDA function.
        // there's no official way to query for this value.

        const u32 fixed_local_size = device_param->kernel_dynamic_local_mem_size_memset / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        const u32 fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", fixed_local_size);
      }
    }
  }

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  token.token_cnt  = 4;

  token.signatures_cnt    = 4;
  token.signatures_buf[0] = SIGNATURE_BCRYPT1;
  token.signatures_buf[1] = SIGNATURE_BCRYPT2;
  token.signatures_buf[2] = SIGNATURE_BCRYPT3;
  token.signatures_buf[3] = SIGNATURE_BCRYPT4;

  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 2;
  token.len_max[1] = 2;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len[2]     = 22;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[3]     = 31;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *iter_pos = token.buf[1];
  const u8 *salt_pos = token.buf[2];
  const u8 *hash_pos = token.buf[3];

  const int salt_len = token.len[2];
  const int hash_len = token.len[3];

  salt->salt_len  = 16;
  salt->salt_iter = 1u << hc_strtoul ((const char *) iter_pos, NULL, 10);

  memcpy ((char *) salt->salt_sign, line_buf, 6);

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  u8 tmp_buf[100];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, (const u8 *) salt_pos, salt_len, tmp_buf);

  memcpy (salt_buf_ptr, tmp_buf, 16);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);

  memset (tmp_buf, 0, sizeof (tmp_buf));

  base64_decode (bf64_to_int, (const u8 *) hash_pos, hash_len, tmp_buf);

  memcpy (digest, tmp_buf, 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);

  digest[5] &= ~0xffu; // its just 23 not 24 !

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  u32 tmp_digest[6];

  tmp_digest[0] = byte_swap_32 (digest[0]);
  tmp_digest[1] = byte_swap_32 (digest[1]);
  tmp_digest[2] = byte_swap_32 (digest[2]);
  tmp_digest[3] = byte_swap_32 (digest[3]);
  tmp_digest[4] = byte_swap_32 (digest[4]);
  tmp_digest[5] = byte_swap_32 (digest[5]);

  u32 tmp_salt[4];

  tmp_salt[0] = byte_swap_32 (salt->salt_buf[0]);
  tmp_salt[1] = byte_swap_32 (salt->salt_buf[1]);
  tmp_salt[2] = byte_swap_32 (salt->salt_buf[2]);
  tmp_salt[3] = byte_swap_32 (salt->salt_buf[3]);

  char tmp_buf[64];

  base64_encode (int_to_bf64, (const u8 *) tmp_salt,   16, (u8 *) tmp_buf +  0);
  base64_encode (int_to_bf64, (const u8 *) tmp_digest, 23, (u8 *) tmp_buf + 22);

  tmp_buf[22 + 31] = 0; // base64_encode wants to pad

  return snprintf (line_buf, line_size, "%s$%s", (char *) salt->salt_sign, tmp_buf);
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
  module_ctx->module_esalt_size               = MODULE_DEFAULT;
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
  module_ctx->module_jit_cache_disable        = module_jit_cache_disable;
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
