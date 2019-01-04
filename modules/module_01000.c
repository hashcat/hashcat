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

static const u32   MODULE_VERSION_CURRENT = 520;

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const char *HASH_NAME      = "NTLM";
static const u32   HASH_TYPE      = HASH_TYPE_MD4;
static const u64   KERN_TYPE      = 1000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_PRECOMPUTE_INIT
                                  | OPTI_TYPE_PRECOMPUTE_MERKLE
                                  | OPTI_TYPE_MEET_IN_MIDDLE
                                  | OPTI_TYPE_EARLY_SKIP
                                  | OPTI_TYPE_NOT_ITERATED
                                  | OPTI_TYPE_NOT_SALTED
                                  | OPTI_TYPE_RAW_HASH;
static const u32   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_PT_ADDBITS14
                                  | OPTS_TYPE_PT_UTF16LE;
static const u32   PWDUMP_COLUMN  = PWDUMP_COLUMN_NTLM_HASH;
static const char *ST_HASH        = "b4b9b02e6f09a9bd760f388b67351e2b";

u32         module_attack_exec    (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ATTACK_EXEC;     }
u32         module_dgst_pos0      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS0;       }
u32         module_dgst_pos1      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS1;       }
u32         module_dgst_pos2      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS2;       }
u32         module_dgst_pos3      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_POS3;       }
u32         module_dgst_size      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return DGST_SIZE;       }
const char *module_hash_name      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_NAME;       }
u32         module_hash_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return HASH_TYPE;       }
u64         module_kern_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_TYPE;       }
u32         module_opti_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTI_TYPE;       }
u64         module_opts_type      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return OPTS_TYPE;       }
u32         module_pwdump_column  (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return PWDUMP_COLUMN;   }
const char *module_st_hash        (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return ST_HASH;         }

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  token_t token;

  token.token_cnt  = 1;

  token.len_min[0] = 32;
  token.len_max[0] = 32;
  token.attr[0]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *hash_pos = token.buf[0];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  decoder_apply_options (hashconfig, digest);

  decoder_apply_optimizer (hashconfig, digest);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 tmp[4];

  tmp[0] = digest[0];
  tmp[1] = digest[1];
  tmp[2] = digest[2];
  tmp[3] = digest[3];

  encoder_apply_optimizer (hashconfig, tmp);

  encoder_apply_options (hashconfig, tmp);

  u8 *out_buf = (u8 *) line_buf;

  u32_to_hex (tmp[0], out_buf +  0);
  u32_to_hex (tmp[1], out_buf +  8);
  u32_to_hex (tmp[2], out_buf + 16);
  u32_to_hex (tmp[3], out_buf + 24);

  const int out_len = 32;

  return out_len;
}

void module_init (module_ctx_t *module_ctx)
{
  // undefined functions automatically call corresponding default functions

  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = NULL;
  module_ctx->module_benchmark_hook_salt      = NULL;
  module_ctx->module_benchmark_mask           = NULL;
  module_ctx->module_benchmark_salt           = NULL;
  module_ctx->module_build_plain_postprocess  = NULL;
  module_ctx->module_dgst_pos0                = module_dgst_pos0;
  module_ctx->module_dgst_pos1                = module_dgst_pos1;
  module_ctx->module_dgst_pos2                = module_dgst_pos2;
  module_ctx->module_dgst_pos3                = module_dgst_pos3;
  module_ctx->module_dgst_size                = module_dgst_size;
  module_ctx->module_dictstat_disable         = NULL;
  module_ctx->module_esalt_size               = NULL;
  module_ctx->module_extra_buffer_size        = NULL;
  module_ctx->module_forced_kernel_loops      = NULL;
  module_ctx->module_forced_kernel_threads    = NULL;
  module_ctx->module_forced_outfile_format    = NULL;
  module_ctx->module_hash_decode_outfile      = NULL;
  module_ctx->module_hash_decode_zero_hash    = NULL;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_hash_mode                = NULL;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_type                = module_hash_type;
  module_ctx->module_hlfmt_disable            = NULL;
  module_ctx->module_hook12                   = NULL;
  module_ctx->module_hook23                   = NULL;
  module_ctx->module_hook_salt_size           = NULL;
  module_ctx->module_hook_size                = NULL;
  module_ctx->module_jit_build_options        = NULL;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_opti_type                = module_opti_type;
  module_ctx->module_opts_type                = module_opts_type;
  module_ctx->module_outfile_check_disable    = NULL;
  module_ctx->module_outfile_check_nocomp     = NULL;
  module_ctx->module_potfile_disable          = NULL;
  module_ctx->module_potfile_keep_all_hashes  = NULL;
  module_ctx->module_pwdump_column            = module_pwdump_column;
  module_ctx->module_pw_max                   = NULL;
  module_ctx->module_pw_min                   = NULL;
  module_ctx->module_salt_max                 = NULL;
  module_ctx->module_salt_min                 = NULL;
  module_ctx->module_salt_type                = NULL;
  module_ctx->module_separator                = NULL;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = NULL;
  module_ctx->module_tmp_size                 = NULL;
  module_ctx->module_version_current          = MODULE_VERSION_CURRENT;
  module_ctx->module_warmup_disable           = NULL;
}
