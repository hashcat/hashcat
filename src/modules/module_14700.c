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
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // we actually do not have a digest
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "iTunes backup < 10.0";
static const u64   KERN_TYPE      = 14700;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$itunes_backup$*9*ebd7f9b33293b2511f0a4139d5b213feff51476968863cef60ec38d720497b6ff39a0bb63fa9f84e*10000*2202015774208421818002001652122401871832**";

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

typedef struct itunes_backup
{
  u32 wpky[10];
  u32 dpsl[5];

} itunes_backup_t;

typedef struct pbkdf2_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha1_tmp_t;

static const char *SIGNATURE_ITUNES_BACKUP = "$itunes_backup$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (itunes_backup_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_tmp_t);

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

  itunes_backup_t *itunes_backup = (itunes_backup_t *) esalt_buf;

  token_t token;

  token.token_cnt = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ITUNES_BACKUP;

  token.len_min[0] = 15;
  token.len_max[0] = 15;
  token.sep[0]     = '*';
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len_min[1] = 1;
  token.len_max[1] = 2;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[2] = 80;
  token.len_max[2] = 80;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[4] = 40;
  token.len_max[4] = 40;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len_min[5] = 0;
  token.len_max[5] = 10;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.len_min[6] = 0;
  token.len_max[6] = 40;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const u8 *version_pos = token.buf[1];

  u32 version = hc_strtoul ((const char *) version_pos, NULL, 10);

  const u32 hash_mode = hashconfig->hash_mode;

  if (hash_mode == 14700)
  {
    if (version != 9) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (version != 10) return (PARSER_SEPARATOR_UNMATCHED);
  }

  salt->salt_sign[0] = (char) version;

  // wpky

  const u8 *wpky_pos = token.buf[2];

  u32 *wpky_buf_ptr = (u32 *) itunes_backup->wpky;

  wpky_buf_ptr[0] = hex_to_u32 ((const u8 *) &wpky_pos[ 0]);
  wpky_buf_ptr[1] = hex_to_u32 ((const u8 *) &wpky_pos[ 8]);
  wpky_buf_ptr[2] = hex_to_u32 ((const u8 *) &wpky_pos[16]);
  wpky_buf_ptr[3] = hex_to_u32 ((const u8 *) &wpky_pos[24]);
  wpky_buf_ptr[4] = hex_to_u32 ((const u8 *) &wpky_pos[32]);
  wpky_buf_ptr[5] = hex_to_u32 ((const u8 *) &wpky_pos[40]);
  wpky_buf_ptr[6] = hex_to_u32 ((const u8 *) &wpky_pos[48]);
  wpky_buf_ptr[7] = hex_to_u32 ((const u8 *) &wpky_pos[56]);
  wpky_buf_ptr[8] = hex_to_u32 ((const u8 *) &wpky_pos[64]);
  wpky_buf_ptr[9] = hex_to_u32 ((const u8 *) &wpky_pos[72]);

  wpky_buf_ptr[0] = byte_swap_32 (wpky_buf_ptr[0]);
  wpky_buf_ptr[1] = byte_swap_32 (wpky_buf_ptr[1]);
  wpky_buf_ptr[2] = byte_swap_32 (wpky_buf_ptr[2]);
  wpky_buf_ptr[3] = byte_swap_32 (wpky_buf_ptr[3]);
  wpky_buf_ptr[4] = byte_swap_32 (wpky_buf_ptr[4]);
  wpky_buf_ptr[5] = byte_swap_32 (wpky_buf_ptr[5]);
  wpky_buf_ptr[6] = byte_swap_32 (wpky_buf_ptr[6]);
  wpky_buf_ptr[7] = byte_swap_32 (wpky_buf_ptr[7]);
  wpky_buf_ptr[8] = byte_swap_32 (wpky_buf_ptr[8]);
  wpky_buf_ptr[9] = byte_swap_32 (wpky_buf_ptr[9]);

  // iter

  const u8 *iter_pos = token.buf[3];

  u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  if (iter < 1) return (PARSER_SALT_ITERATION);

  if (hash_mode == 14700)
  {
    salt->salt_iter  = iter - 1;
  }
  else if (hash_mode == 14800)
  {
    salt->salt_iter  = 0; // set later
    salt->salt_iter2 = iter - 1;
  }

  // salt

  const u8 *salt_pos = token.buf[4];
  const int salt_len = token.len[4];

  const bool parse_rc = generic_salt_decode (hashconfig, salt_pos, salt_len, (u8 *) salt->salt_buf, (int *) &salt->salt_len);

  if (parse_rc == false) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = byte_swap_32 (salt->salt_buf[0]);
  salt->salt_buf[1] = byte_swap_32 (salt->salt_buf[1]);
  salt->salt_buf[2] = byte_swap_32 (salt->salt_buf[2]);
  salt->salt_buf[3] = byte_swap_32 (salt->salt_buf[3]);
  salt->salt_buf[4] = byte_swap_32 (salt->salt_buf[4]);

  // dpic + dpsl

  const u8 *dpic_pos = token.buf[5];
  const int dpic_len = token.len[5];

  const u8 *dpsl_pos = token.buf[6];
  const int dpsl_len = token.len[6];

  u32 dpic = 0;

  if (hash_mode == 14700)
  {
    if (dpic_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
    if (dpsl_len > 0) return (PARSER_SEPARATOR_UNMATCHED);
  }
  else if (hash_mode == 14800)
  {
    if (dpic_len < 1) return (PARSER_SALT_ITERATION);
    if (dpic_len > 9) return (PARSER_SALT_ITERATION);

    dpic = hc_strtoul ((const char *) dpic_pos, NULL, 10);

    if (dpic < 1) return (PARSER_SALT_ITERATION);

    salt->salt_iter = dpic - 1;

    if (dpsl_len != 40) return (PARSER_SEPARATOR_UNMATCHED);

    u32 *dpsl_buf_ptr = (u32 *) itunes_backup->dpsl;

    dpsl_buf_ptr[0] = hex_to_u32 ((const u8 *) &dpsl_pos[ 0]);
    dpsl_buf_ptr[1] = hex_to_u32 ((const u8 *) &dpsl_pos[ 8]);
    dpsl_buf_ptr[2] = hex_to_u32 ((const u8 *) &dpsl_pos[16]);
    dpsl_buf_ptr[3] = hex_to_u32 ((const u8 *) &dpsl_pos[24]);
    dpsl_buf_ptr[4] = hex_to_u32 ((const u8 *) &dpsl_pos[32]);

    dpsl_buf_ptr[0] = byte_swap_32 (dpsl_buf_ptr[ 0]);
    dpsl_buf_ptr[1] = byte_swap_32 (dpsl_buf_ptr[ 1]);
    dpsl_buf_ptr[2] = byte_swap_32 (dpsl_buf_ptr[ 2]);
    dpsl_buf_ptr[3] = byte_swap_32 (dpsl_buf_ptr[ 3]);
    dpsl_buf_ptr[4] = byte_swap_32 (dpsl_buf_ptr[ 4]);
  }

  digest[0] = itunes_backup->dpsl[0] ^ itunes_backup->wpky[0];
  digest[1] = itunes_backup->dpsl[1] ^ itunes_backup->wpky[1];
  digest[2] = itunes_backup->dpsl[2] ^ itunes_backup->wpky[2];
  digest[3] = itunes_backup->dpsl[3] ^ itunes_backup->wpky[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const itunes_backup_t *itunes_backup = (const itunes_backup_t *) esalt_buf;

  // WPKY

  u32 wkpy_u32[10];

  wkpy_u32[0] = byte_swap_32 (itunes_backup->wpky[0]);
  wkpy_u32[1] = byte_swap_32 (itunes_backup->wpky[1]);
  wkpy_u32[2] = byte_swap_32 (itunes_backup->wpky[2]);
  wkpy_u32[3] = byte_swap_32 (itunes_backup->wpky[3]);
  wkpy_u32[4] = byte_swap_32 (itunes_backup->wpky[4]);
  wkpy_u32[5] = byte_swap_32 (itunes_backup->wpky[5]);
  wkpy_u32[6] = byte_swap_32 (itunes_backup->wpky[6]);
  wkpy_u32[7] = byte_swap_32 (itunes_backup->wpky[7]);
  wkpy_u32[8] = byte_swap_32 (itunes_backup->wpky[8]);
  wkpy_u32[9] = byte_swap_32 (itunes_backup->wpky[9]);

  u8 wpky[80 + 1];

  u32_to_hex (wkpy_u32[0], wpky +  0);
  u32_to_hex (wkpy_u32[1], wpky +  8);
  u32_to_hex (wkpy_u32[2], wpky + 16);
  u32_to_hex (wkpy_u32[3], wpky + 24);
  u32_to_hex (wkpy_u32[4], wpky + 32);
  u32_to_hex (wkpy_u32[5], wpky + 40);
  u32_to_hex (wkpy_u32[6], wpky + 48);
  u32_to_hex (wkpy_u32[7], wpky + 56);
  u32_to_hex (wkpy_u32[8], wpky + 64);
  u32_to_hex (wkpy_u32[9], wpky + 72);

  wpky[80] = 0;

  u32 salt_in[6];

  salt_in[0] = byte_swap_32 (salt->salt_buf[0]);
  salt_in[1] = byte_swap_32 (salt->salt_buf[1]);
  salt_in[2] = byte_swap_32 (salt->salt_buf[2]);
  salt_in[3] = byte_swap_32 (salt->salt_buf[3]);
  salt_in[4] = byte_swap_32 (salt->salt_buf[4]);
  salt_in[5] = 0;

  char tmp_salt[SALT_MAX * 2];

  const int salt_len = generic_salt_encode (hashconfig, (const u8 *) salt_in, (const int) salt->salt_len, (u8 *) tmp_salt);

  tmp_salt[salt_len] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s*%u*%s*%u*%s**",
    SIGNATURE_ITUNES_BACKUP,
    salt->salt_sign[0],
    wpky,
    salt->salt_iter + 1,
    tmp_salt);

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
