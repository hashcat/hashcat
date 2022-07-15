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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "Juniper NetScreen/SSG (ScreenOS)";
static const u64   KERN_TYPE      = 20;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_PREPENDED_SALT
                                  | OPTI_TYPE_RAW_HASH;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "nKjiFErqK7TPcZdFZsZMNWPtw4Pv8n:26506173";

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

static const char *adm = ":Administration Tools:";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  hc_token_t token;

  token.token_cnt  = 2;

  token.sep[0]     = hashconfig->separator;
  token.len_min[0] = 30;
  token.len_max[0] = 30;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[1] = SALT_MIN;
  token.len_max[1] = SALT_MAX - 23;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  // unscramble

  u8 clean_input_buf[32] = { 0 };

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };
  int  pos[6] = {   0,   6,  12,  17,  23,  29 };

  for (int i = 0, j = 0, k = 0; i < 30; i++)
  {
    if (i == pos[j])
    {
      if (sig[j] != hash_pos[i]) return (PARSER_SIGNATURE_UNMATCHED);

      j++;
    }
    else
    {
      clean_input_buf[k] = hash_pos[i];

      k++;
    }
  }

  // base64 decode

  u32 a, b, c, d, e, f;

  a = base64_to_int (clean_input_buf[ 0] & 0x7f);
  b = base64_to_int (clean_input_buf[ 1] & 0x7f);
  c = base64_to_int (clean_input_buf[ 2] & 0x7f);
  d = base64_to_int (clean_input_buf[ 3] & 0x7f);
  e = base64_to_int (clean_input_buf[ 4] & 0x7f);
  f = base64_to_int (clean_input_buf[ 5] & 0x7f);

  digest[0] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[ 6] & 0x7f);
  b = base64_to_int (clean_input_buf[ 7] & 0x7f);
  c = base64_to_int (clean_input_buf[ 8] & 0x7f);
  d = base64_to_int (clean_input_buf[ 9] & 0x7f);
  e = base64_to_int (clean_input_buf[10] & 0x7f);
  f = base64_to_int (clean_input_buf[11] & 0x7f);

  digest[1] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[12] & 0x7f);
  b = base64_to_int (clean_input_buf[13] & 0x7f);
  c = base64_to_int (clean_input_buf[14] & 0x7f);
  d = base64_to_int (clean_input_buf[15] & 0x7f);
  e = base64_to_int (clean_input_buf[16] & 0x7f);
  f = base64_to_int (clean_input_buf[17] & 0x7f);

  digest[2] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  a = base64_to_int (clean_input_buf[18] & 0x7f);
  b = base64_to_int (clean_input_buf[19] & 0x7f);
  c = base64_to_int (clean_input_buf[20] & 0x7f);
  d = base64_to_int (clean_input_buf[21] & 0x7f);
  e = base64_to_int (clean_input_buf[22] & 0x7f);
  f = base64_to_int (clean_input_buf[23] & 0x7f);

  digest[3] = (((a << 12) | (b << 6) | (c)) << 16)
            | (((d << 12) | (e << 6) | (f)) <<  0);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    digest[0] -= MD5M_A;
    digest[1] -= MD5M_B;
    digest[2] -= MD5M_C;
    digest[3] -= MD5M_D;
  }

  const u8 *salt_pos = token.buf[1];
  const int salt_len = token.len[1];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    // max. salt length: 55 (max for MD5) - 22 (":Administration Tools:") - 1 (0x80) = 32

    if (salt->salt_len > 32) return (PARSER_SALT_LENGTH);
  }

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  memcpy (salt_buf_ptr + salt->salt_len, adm, strlen (adm));

  salt->salt_len += strlen (adm);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  u32 *digest = (u32 *) digest_buf;

  char sig[6] = { 'n', 'r', 'c', 's', 't', 'n' };

  u32 tmp[4];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];

  if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    tmp[0] += MD5M_A;
    tmp[1] += MD5M_B;
    tmp[2] += MD5M_C;
    tmp[3] += MD5M_D;
  }

  tmp[0] = byte_swap_32 (tmp[0]);
  tmp[1] = byte_swap_32 (tmp[1]);
  tmp[2] = byte_swap_32 (tmp[2]);
  tmp[3] = byte_swap_32 (tmp[3]);

  u8 tmp_buf[32];

  tmp_buf[ 0] = sig[0];
  tmp_buf[ 1] = int_to_base64 (((v16b_from_v32 (tmp[0])) >> 12) & 0x3f);
  tmp_buf[ 2] = int_to_base64 (((v16b_from_v32 (tmp[0])) >>  6) & 0x3f);
  tmp_buf[ 3] = int_to_base64 (((v16b_from_v32 (tmp[0])) >>  0) & 0x3f);
  tmp_buf[ 4] = int_to_base64 (((v16a_from_v32 (tmp[0])) >> 12) & 0x3f);
  tmp_buf[ 5] = int_to_base64 (((v16a_from_v32 (tmp[0])) >>  6) & 0x3f);
  tmp_buf[ 6] = sig[1];
  tmp_buf[ 7] = int_to_base64 (((v16a_from_v32 (tmp[0])) >>  0) & 0x3f);
  tmp_buf[ 8] = int_to_base64 (((v16b_from_v32 (tmp[1])) >> 12) & 0x3f);
  tmp_buf[ 9] = int_to_base64 (((v16b_from_v32 (tmp[1])) >>  6) & 0x3f);
  tmp_buf[10] = int_to_base64 (((v16b_from_v32 (tmp[1])) >>  0) & 0x3f);
  tmp_buf[11] = int_to_base64 (((v16a_from_v32 (tmp[1])) >> 12) & 0x3f);
  tmp_buf[12] = sig[2];
  tmp_buf[13] = int_to_base64 (((v16a_from_v32 (tmp[1])) >>  6) & 0x3f);
  tmp_buf[14] = int_to_base64 (((v16a_from_v32 (tmp[1])) >>  0) & 0x3f);
  tmp_buf[15] = int_to_base64 (((v16b_from_v32 (tmp[2])) >> 12) & 0x3f);
  tmp_buf[16] = int_to_base64 (((v16b_from_v32 (tmp[2])) >>  6) & 0x3f);
  tmp_buf[17] = sig[3];
  tmp_buf[18] = int_to_base64 (((v16b_from_v32 (tmp[2])) >>  0) & 0x3f);
  tmp_buf[19] = int_to_base64 (((v16a_from_v32 (tmp[2])) >> 12) & 0x3f);
  tmp_buf[20] = int_to_base64 (((v16a_from_v32 (tmp[2])) >>  6) & 0x3f);
  tmp_buf[21] = int_to_base64 (((v16a_from_v32 (tmp[2])) >>  0) & 0x3f);
  tmp_buf[22] = int_to_base64 (((v16b_from_v32 (tmp[3])) >> 12) & 0x3f);
  tmp_buf[23] = sig[4];
  tmp_buf[24] = int_to_base64 (((v16b_from_v32 (tmp[3])) >>  6) & 0x3f);
  tmp_buf[25] = int_to_base64 (((v16b_from_v32 (tmp[3])) >>  0) & 0x3f);
  tmp_buf[26] = int_to_base64 (((v16a_from_v32 (tmp[3])) >> 12) & 0x3f);
  tmp_buf[27] = int_to_base64 (((v16a_from_v32 (tmp[3])) >>  6) & 0x3f);
  tmp_buf[28] = int_to_base64 (((v16a_from_v32 (tmp[3])) >>  0) & 0x3f);
  tmp_buf[29] = sig[5];
  tmp_buf[30] = 0;

  char tmp_salt[SALT_MAX * 2];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt->salt_buf, (const int) salt->salt_len - strlen (adm), (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s%c%s", tmp_buf, hashconfig->separator, tmp_salt);

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
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
