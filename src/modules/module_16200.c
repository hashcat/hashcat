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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // originally DGST_SIZE_4_;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_DOCUMENTS;
static const char *HASH_NAME      = "Apple Secure Notes";
static const u64   KERN_TYPE      = 16200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$ASN$*1*20000*80771171105233481004850004085037*d04b17af7f6b184346aad3efefe8bec0987ee73418291a41";

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

typedef struct apple_secure_notes
{
  u32 Z_PK;
  u32 ZCRYPTOITERATIONCOUNT;
  u32 ZCRYPTOSALT[16];
  u32 ZCRYPTOWRAPPEDKEY[16];

} apple_secure_notes_t;

typedef struct apple_secure_notes_tmp
{
  u32 ipad[8];
  u32 opad[8];

  u32 dgst[8];
  u32 out[8];

} apple_secure_notes_tmp_t;

static const char *SIGNATURE_APPLE_SECURE_NOTES = "$ASN$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (apple_secure_notes_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (apple_secure_notes_tmp_t);

  return tmp_size;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  if (device_param->is_cuda == true)
  {
    hc_asprintf (&jit_build_options, "-D NO_UNROLL");
  }

  if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
  {
    hc_asprintf (&jit_build_options, "-D NO_UNROLL");
  }

  if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD) && (device_param->has_vperm == false))
  {
    hc_asprintf (&jit_build_options, "-D NO_UNROLL");
  }

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  apple_secure_notes_t *apple_secure_notes = (apple_secure_notes_t *) esalt_buf;

  token_t token;

  token.token_cnt  = 5;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_APPLE_SECURE_NOTES;

  token.sep[0]     = '*';
  token.len_min[0] = 5;
  token.len_max[0] = 5;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len_min[2] = 1;
  token.len_max[2] = 6;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '*';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 48;
  token.len_max[4] = 48;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /**
   * parse line
   */

  // Z_PK

  const u8 *Z_PK_pos = token.buf[1];

  const u32 Z_PK = hc_strtoul ((const char *) Z_PK_pos, NULL, 10);

  apple_secure_notes->Z_PK = Z_PK;

  // ZCRYPTOITERATIONCOUNT

  const u8 *ZCRYPTOITERATIONCOUNT_pos = token.buf[2];

  const u32 ZCRYPTOITERATIONCOUNT = hc_strtoul ((const char *) ZCRYPTOITERATIONCOUNT_pos, NULL, 10);

  apple_secure_notes->ZCRYPTOITERATIONCOUNT = ZCRYPTOITERATIONCOUNT;

  // ZCRYPTOSALT

  const u8 *ZCRYPTOSALT_pos = token.buf[3];

  apple_secure_notes->ZCRYPTOSALT[ 0] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[ 0]);
  apple_secure_notes->ZCRYPTOSALT[ 1] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[ 8]);
  apple_secure_notes->ZCRYPTOSALT[ 2] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[16]);
  apple_secure_notes->ZCRYPTOSALT[ 3] = hex_to_u32 ((const u8 *) &ZCRYPTOSALT_pos[24]);
  apple_secure_notes->ZCRYPTOSALT[ 4] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 5] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 6] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 7] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 8] = 0;
  apple_secure_notes->ZCRYPTOSALT[ 9] = 0;
  apple_secure_notes->ZCRYPTOSALT[10] = 0;
  apple_secure_notes->ZCRYPTOSALT[11] = 0;
  apple_secure_notes->ZCRYPTOSALT[12] = 0;
  apple_secure_notes->ZCRYPTOSALT[13] = 0;
  apple_secure_notes->ZCRYPTOSALT[14] = 0;
  apple_secure_notes->ZCRYPTOSALT[15] = 0;

  // ZCRYPTOWRAPPEDKEY

  const u8 *ZCRYPTOWRAPPEDKEY_pos = token.buf[4];

  apple_secure_notes->ZCRYPTOWRAPPEDKEY[0] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[ 0]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[1] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[ 8]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[2] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[16]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[3] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[24]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[4] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[32]);
  apple_secure_notes->ZCRYPTOWRAPPEDKEY[5] = hex_to_u32 ((const u8 *) &ZCRYPTOWRAPPEDKEY_pos[40]);

  // fake salt

  salt->salt_buf[0] = apple_secure_notes->ZCRYPTOSALT[0];
  salt->salt_buf[1] = apple_secure_notes->ZCRYPTOSALT[1];
  salt->salt_buf[2] = apple_secure_notes->ZCRYPTOSALT[2];
  salt->salt_buf[3] = apple_secure_notes->ZCRYPTOSALT[3];
  salt->salt_buf[4] = apple_secure_notes->Z_PK;

  salt->salt_iter = apple_secure_notes->ZCRYPTOITERATIONCOUNT - 1;
  salt->salt_len  = 20;

  // fake hash

  digest[0] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[0];
  digest[1] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[1];
  digest[2] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[2];
  digest[3] = apple_secure_notes->ZCRYPTOWRAPPEDKEY[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const apple_secure_notes_t *apple_secure_notes = (const apple_secure_notes_t *) esalt_buf;

  const int line_len = snprintf (line_buf, line_size, "%s*%u*%u*%08x%08x%08x%08x*%08x%08x%08x%08x%08x%08x",
    SIGNATURE_APPLE_SECURE_NOTES,
    apple_secure_notes->Z_PK,
    apple_secure_notes->ZCRYPTOITERATIONCOUNT,
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[0]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[1]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[2]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOSALT[3]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[0]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[1]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[2]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[3]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[4]),
    byte_swap_32 (apple_secure_notes->ZCRYPTOWRAPPEDKEY[5]));

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
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = MODULE_DEFAULT;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = MODULE_DEFAULT;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = MODULE_DEFAULT;
  module_ctx->module_extra_tmp_size           = MODULE_DEFAULT;
  module_ctx->module_forced_outfile_format    = MODULE_DEFAULT;
  module_ctx->module_hash_binary_count        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_parse        = MODULE_DEFAULT;
  module_ctx->module_hash_binary_save         = MODULE_DEFAULT;
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
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = MODULE_DEFAULT;
  module_ctx->module_hook_salt_size           = MODULE_DEFAULT;
  module_ctx->module_hook_size                = MODULE_DEFAULT;
  module_ctx->module_jit_build_options        = module_jit_build_options;
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
