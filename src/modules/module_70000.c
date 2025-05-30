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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_RAW_HASH;
static const char *HASH_NAME      = "argon2id [Bridged: reference implementation + tunings]";
static const u64   KERN_TYPE      = 70000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const u64   BRIDGE_TYPE    = BRIDGE_TYPE_MATCH_TUNINGS // optional - improves performance
                                  | BRIDGE_TYPE_LAUNCH_LOOP;
static const char *BRIDGE_NAME    = "argon2id_reference";
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$argon2id$v=19$m=4096,t=3,p=1$FoIjFnZlM2JSJWYXUgMFAw$eYKMzhbW8uyT1LLtKRdRcJj2CQeRrdr2pKv/Y71YbAQ";

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
const char *module_bridge_name    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_NAME;     }
u64         module_bridge_type    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return BRIDGE_TYPE;     }

typedef struct
{
  // input

  u32 pw_buf[64];
  u32 pw_len;

  // output

  u32 h[64];

} argon2_reference_tmp_t;

typedef struct
{
  u32 salt_buf[64];
  u32 salt_len;

  u32 digest_buf[64];
  u32 digest_len;

  u32 m;
  u32 t;
  u32 p;

} argon2_t;

static const char *SIGNATURE_ARGON2ID= "$argon2id$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (argon2_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (argon2_reference_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  argon2_t *argon2id = (argon2_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 7;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ARGON2ID;

  token.len[0]     = 10;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.len[1]     = 4;
  token.sep[1]     = '$';
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  token.len_min[2] = 3;
  token.len_max[2] = 12;
  token.sep[2]     = ','; // our tokenizer shines here
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[3] = 3;
  token.len_max[3] = 5;
  token.sep[3]     = ','; // ... and here
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[4] = 3;
  token.len_max[4] = 5;
  token.sep[4]     = '$';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.len_min[5] = ((SALT_MIN * 8) / 6) + 0;
  token.len_max[5] = ((SALT_MAX * 8) / 6) + 3;
  token.sep[5]     = '$';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  token.len_min[6] = ((SALT_MIN * 8) / 6) + 0;
  token.len_max[6] = ((SALT_MAX * 8) / 6) + 3;
  token.sep[6]     = '$';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // version

  const int version_len = token.len[1];
  const u8 *version_pos = token.buf[1];

  if (version_len != 4) return (PARSER_HASH_VALUE);

  if (memcmp (version_pos, "v=19", 4)) return (PARSER_HASH_VALUE);

  // argon2id config

  const u8 *m_pos = token.buf[2];
  const u8 *t_pos = token.buf[3];
  const u8 *p_pos = token.buf[4];

  argon2id->m = hc_strtoul ((const char *) m_pos + 2, NULL, 10);
  argon2id->t = hc_strtoul ((const char *) t_pos + 2, NULL, 10);
  argon2id->p = hc_strtoul ((const char *) p_pos + 2, NULL, 10);

  if (argon2id->m < 1) return (PARSER_HASH_VALUE);
  if (argon2id->t < 1) return (PARSER_HASH_VALUE);
  if (argon2id->p < 1) return (PARSER_HASH_VALUE);

  // salt

  const int salt_len = token.len[5];
  const u8 *salt_pos = token.buf[5];

  argon2id->salt_len = base64_decode (base64_to_int, (const u8 *) salt_pos, salt_len, (u8 *) argon2id->salt_buf);

  // digest

  const int digest_len = token.len[6];
  const u8 *digest_pos = token.buf[6];

  argon2id->digest_len = base64_decode (base64_to_int, (const u8 *) digest_pos, digest_len, (u8 *) argon2id->digest_buf);

  // comparison digest

  digest[0] = argon2id->digest_buf[0];
  digest[1] = argon2id->digest_buf[1];
  digest[2] = argon2id->digest_buf[2];
  digest[3] = argon2id->digest_buf[3];

  // fake salt, we just need to make this unique

  salt->salt_buf[0] = digest[0];
  salt->salt_buf[1] = digest[1];
  salt->salt_buf[2] = digest[2];
  salt->salt_buf[3] = digest[3];
  salt->salt_buf[4] = argon2id->m;
  salt->salt_buf[5] = argon2id->t;
  salt->salt_buf[6] = argon2id->p;
  salt->salt_buf[7] = 0;

  salt->salt_len  = 32;
  salt->salt_iter = 1;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  // const u32 *digest = (const u32 *) digest_buf;

  const argon2_t *argon2 = (const argon2_t *) esalt_buf;

  // salt

  char base64_salt[512] = { 0 };

  int len1 = base64_encode (int_to_base64, (const u8 *) argon2->salt_buf, argon2->salt_len, (u8 *) base64_salt);

  for (int i = len1 - 1; i >=0; i--) if (base64_salt[i] == '=') base64_salt[i] = 0;

  // digest

  char base64_digest[512] = { 0 };

  int len2 = base64_encode (int_to_base64, (const u8 *) argon2->digest_buf, argon2->digest_len, (u8 *) base64_digest);

  for (int i = len2 - 1; i >=0; i--) if (base64_digest[i] == '=') base64_digest[i] = 0;

  // out

  u8 *out_buf = (u8 *) line_buf;

  const int out_len = snprintf ((char *) out_buf, line_size, "%sv=19$m=%d,t=%d,p=%d$%s$%s",
    SIGNATURE_ARGON2ID,
    argon2->m,
    argon2->t,
    argon2->p,
    base64_salt,
    base64_digest);

  return out_len;
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
  module_ctx->module_bridge_name              = module_bridge_name;
  module_ctx->module_bridge_type              = module_bridge_type;
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
