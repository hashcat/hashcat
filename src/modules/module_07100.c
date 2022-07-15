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
static const u32   DGST_SIZE      = DGST_SIZE_8_16;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_OS;
static const char *HASH_NAME      = "macOS v10.8+ (PBKDF2-SHA512)";
static const u64   KERN_TYPE      = 7100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_USES_BITS_64
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$ml$1024$2484380731132131624506271467162123576077004878124365203837706482$89a3a979ee186c0c837ca4551f32e951e6564c7ac6798aa35baf4427fbf6bd1d630642c12cfd5c236c7b0104782237db95e895f7c0e372cd81d58f0448daf958";

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

typedef struct pbkdf2_sha512
{
  u32 salt_buf[64];

} pbkdf2_sha512_t;

typedef struct pbkdf2_sha512_tmp
{
  u64  ipad[8];
  u64  opad[8];

  u64  dgst[16];
  u64  out[16];

} pbkdf2_sha512_tmp_t;

static const char *SIGNATURE_SHA512MACOS = "$ml$";

static const char *SIGNATURE_SHA512MACOS_JOHN = "$pbkdf2-hmac-sha512$";

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha512_tmp_t);

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha512_t);

  return esalt_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D NO_UNROLL");

  return jit_build_options;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u64 *digest = (u64 *) digest_buf;

  pbkdf2_sha512_t *pbkdf2_sha512 = (pbkdf2_sha512_t *) esalt_buf;

  char sigchk[21];
  sigchk[20] = '\0';
  memcpy (sigchk, line_buf, 20);

  if (strncmp (sigchk, SIGNATURE_SHA512MACOS, 4) == 0)
  {
    hc_token_t token;

    token.token_cnt  = 4;

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_SHA512MACOS;

    token.len[0]     = 4;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_SIGNATURE;

    token.len_min[1] = 1;
    token.len_max[1] = 6;
    token.sep[1]     = '$';
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    token.len_min[2] = 64;
    token.len_max[2] = 64;
    token.sep[2]     = '$';
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[3] = 128;
    token.len_max[3] = 256;
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    const int hash_len = token.len[3];

    if ((hash_len != 128) && (hash_len != 256)) return (PARSER_HASH_LENGTH);

    const u8 *hash_pos = token.buf[3];

    digest[0] = hex_to_u64 (hash_pos +   0);
    digest[1] = hex_to_u64 (hash_pos +  16);
    digest[2] = hex_to_u64 (hash_pos +  32);
    digest[3] = hex_to_u64 (hash_pos +  48);
    digest[4] = hex_to_u64 (hash_pos +  64);
    digest[5] = hex_to_u64 (hash_pos +  80);
    digest[6] = hex_to_u64 (hash_pos +  96);
    digest[7] = hex_to_u64 (hash_pos + 112);

    digest[0] = byte_swap_64 (digest[0]);
    digest[1] = byte_swap_64 (digest[1]);
    digest[2] = byte_swap_64 (digest[2]);
    digest[3] = byte_swap_64 (digest[3]);
    digest[4] = byte_swap_64 (digest[4]);
    digest[5] = byte_swap_64 (digest[5]);
    digest[6] = byte_swap_64 (digest[6]);
    digest[7] = byte_swap_64 (digest[7]);

    const u8 *salt_pos = token.buf[2];
    const int salt_len = token.len[2] / 2;

    pbkdf2_sha512->salt_buf[0] = hex_to_u32 (salt_pos +  0);
    pbkdf2_sha512->salt_buf[1] = hex_to_u32 (salt_pos +  8);
    pbkdf2_sha512->salt_buf[2] = hex_to_u32 (salt_pos + 16);
    pbkdf2_sha512->salt_buf[3] = hex_to_u32 (salt_pos + 24);
    pbkdf2_sha512->salt_buf[4] = hex_to_u32 (salt_pos + 32);
    pbkdf2_sha512->salt_buf[5] = hex_to_u32 (salt_pos + 40);
    pbkdf2_sha512->salt_buf[6] = hex_to_u32 (salt_pos + 48);
    pbkdf2_sha512->salt_buf[7] = hex_to_u32 (salt_pos + 56);

    salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
    salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
    salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
    salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
    salt->salt_buf[4] = pbkdf2_sha512->salt_buf[4];
    salt->salt_buf[5] = pbkdf2_sha512->salt_buf[5];
    salt->salt_buf[6] = pbkdf2_sha512->salt_buf[6];
    salt->salt_buf[7] = pbkdf2_sha512->salt_buf[7];
    salt->salt_len    = salt_len;

    const u8 *iter_pos = token.buf[1];

    salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10) - 1;

    return (PARSER_OK);
  }

  if (strncmp (sigchk, SIGNATURE_SHA512MACOS_JOHN, 20) == 0)
  {
    hc_token_t token;

    token.token_cnt  = 7;

    token.signatures_cnt    = 1;
    token.signatures_buf[0] = SIGNATURE_SHA512MACOS_JOHN;

    token.len[0]     = 20;
    token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                     | TOKEN_ATTR_VERIFY_SIGNATURE;

    token.len_min[1] = 1;
    token.len_max[1] = 6;
    token.sep[1]     = '.';
    token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_DIGIT;

    token.len_min[2] = 64;
    token.len_max[2] = 64;
    token.sep[2]     = '.';
    token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[3] = 128;
    token.len_max[3] = 256;
    token.sep[3]     = ':';
    token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                     | TOKEN_ATTR_VERIFY_HEX;

    token.len_min[4] = 0;
    token.len_max[4] = 16;
    token.sep[4]     = ':';
    token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len_min[5] = 0;
    token.len_max[5] = 16;
    token.sep[5]     = ':';
    token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH;

    token.len_min[6] = 0;
    token.len_max[6] = 32;
    token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH;

    const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

    if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

    const int hash_len = token.len[3];

    if ((hash_len != 128) && (hash_len != 256)) return (PARSER_HASH_LENGTH);

    const u8 *hash_pos = token.buf[3];

    digest[0] = hex_to_u64 (hash_pos +   0);
    digest[1] = hex_to_u64 (hash_pos +  16);
    digest[2] = hex_to_u64 (hash_pos +  32);
    digest[3] = hex_to_u64 (hash_pos +  48);
    digest[4] = hex_to_u64 (hash_pos +  64);
    digest[5] = hex_to_u64 (hash_pos +  80);
    digest[6] = hex_to_u64 (hash_pos +  96);
    digest[7] = hex_to_u64 (hash_pos + 112);

    digest[0] = byte_swap_64 (digest[0]);
    digest[1] = byte_swap_64 (digest[1]);
    digest[2] = byte_swap_64 (digest[2]);
    digest[3] = byte_swap_64 (digest[3]);
    digest[4] = byte_swap_64 (digest[4]);
    digest[5] = byte_swap_64 (digest[5]);
    digest[6] = byte_swap_64 (digest[6]);
    digest[7] = byte_swap_64 (digest[7]);

    const u8 *salt_pos = token.buf[2];
    const int salt_len = token.len[2] / 2;

    pbkdf2_sha512->salt_buf[0] = hex_to_u32 (salt_pos +  0);
    pbkdf2_sha512->salt_buf[1] = hex_to_u32 (salt_pos +  8);
    pbkdf2_sha512->salt_buf[2] = hex_to_u32 (salt_pos + 16);
    pbkdf2_sha512->salt_buf[3] = hex_to_u32 (salt_pos + 24);
    pbkdf2_sha512->salt_buf[4] = hex_to_u32 (salt_pos + 32);
    pbkdf2_sha512->salt_buf[5] = hex_to_u32 (salt_pos + 40);
    pbkdf2_sha512->salt_buf[6] = hex_to_u32 (salt_pos + 48);
    pbkdf2_sha512->salt_buf[7] = hex_to_u32 (salt_pos + 56);

    salt->salt_buf[0] = pbkdf2_sha512->salt_buf[0];
    salt->salt_buf[1] = pbkdf2_sha512->salt_buf[1];
    salt->salt_buf[2] = pbkdf2_sha512->salt_buf[2];
    salt->salt_buf[3] = pbkdf2_sha512->salt_buf[3];
    salt->salt_buf[4] = pbkdf2_sha512->salt_buf[4];
    salt->salt_buf[5] = pbkdf2_sha512->salt_buf[5];
    salt->salt_buf[6] = pbkdf2_sha512->salt_buf[6];
    salt->salt_buf[7] = pbkdf2_sha512->salt_buf[7];
    salt->salt_len    = salt_len;

    const u8 *iter_pos = token.buf[1];

    salt->salt_iter = hc_strtoul ((const char *) iter_pos, NULL, 10) - 1;

    return (PARSER_OK);
  }
  return (PARSER_SIGNATURE_UNMATCHED);
}

/* replaced with OPTS_TYPE_HASH_COPY version

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const pbkdf2_sha512_t *pbkdf2_sha512 = (const pbkdf2_sha512_t *) esalt_buf;

  // we can not change anything in the original buffer, otherwise destroying sorting
  // therefore create some local buffer

  u32 esalt[8] = { 0 };

  esalt[0] = byte_swap_32 (pbkdf2_sha512->salt_buf[0]);
  esalt[1] = byte_swap_32 (pbkdf2_sha512->salt_buf[1]);
  esalt[2] = byte_swap_32 (pbkdf2_sha512->salt_buf[2]);
  esalt[3] = byte_swap_32 (pbkdf2_sha512->salt_buf[3]);
  esalt[4] = byte_swap_32 (pbkdf2_sha512->salt_buf[4]);
  esalt[5] = byte_swap_32 (pbkdf2_sha512->salt_buf[5]);
  esalt[6] = byte_swap_32 (pbkdf2_sha512->salt_buf[6]);
  esalt[7] = byte_swap_32 (pbkdf2_sha512->salt_buf[7]);

  const int line_len = snprintf (line_buf, line_size, "%s%u$%08x%08x%08x%08x%08x%08x%08x%08x$%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x%08x",
    SIGNATURE_SHA512MACOS,
    salt->salt_iter + 1,
    esalt[ 0], esalt[ 1],
    esalt[ 2], esalt[ 3],
    esalt[ 4], esalt[ 5],
    esalt[ 6], esalt[ 7],
    digest[ 1], digest[ 0],
    digest[ 3], digest[ 2],
    digest[ 5], digest[ 4],
    digest[ 7], digest[ 6],
    digest[ 9], digest[ 8],
    digest[11], digest[10],
    digest[13], digest[12],
    digest[15], digest[14]);

  return line_len;
}
*/

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const int line_len = snprintf (line_buf, line_size, "%s", hash_info->orighash);

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
