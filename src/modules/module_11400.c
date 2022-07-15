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
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_INSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 3;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 1;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_PROTOCOL;
static const char *HASH_NAME      = "SIP digest authentication (MD5)";
static const u64   KERN_TYPE      = 11400;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sip$*72087*1215344588738747***342210558720*737232616*1215344588738747*8867133055*65600****MD5*e9980869221f9d1182c83b0d5e56a7db";

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

typedef struct sip
{
  u32 salt_buf[32];
  u32 salt_len;

  u32 esalt_buf[256];
  u32 esalt_len;

} sip_t;

static const char *SIGNATURE_SIP_AUTH = "$sip$";

static void md5_complete_no_limit (u32 digest[4], const u32 *plain, const u32 plain_len)
{
  // plain = u32 tmp_md5_buf[64] so this is compatible

  md5_ctx_t md5_ctx;

  md5_init (&md5_ctx);
  md5_update (&md5_ctx, plain, plain_len);
  md5_final (&md5_ctx);

  digest[0] = md5_ctx.h[0];
  digest[1] = md5_ctx.h[1];
  digest[2] = md5_ctx.h[2];
  digest[3] = md5_ctx.h[3];
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sip_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sip_t *sip = (sip_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 15;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SIP_AUTH;

  token.sep[0]      = '*';
  token.len_min[0]  = 5;
  token.len_max[0]  = 5;
  token.attr[0]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]      = '*';
  token.len_min[1]  = 0;
  token.len_max[1]  = 512;
  token.attr[1]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[2]      = '*';
  token.len_min[2]  = 0;
  token.len_max[2]  = 512;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[3]      = '*';
  token.len_min[3]  = 0;
  token.len_max[3]  = 116;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[4]      = '*';
  token.len_min[4]  = 0;
  token.len_max[4]  = 116;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[5]      = '*';
  token.len_min[5]  = 0;
  token.len_max[5]  = 246;
  token.attr[5]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[6]      = '*';
  token.len_min[6]  = 0;
  token.len_max[6]  = 245;
  token.attr[6]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[7]      = '*';
  token.len_min[7]  = 1;
  token.len_max[7]  = 246;
  token.attr[7]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[8]      = '*';
  token.len_min[8]  = 0;
  token.len_max[8]  = 245;
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[9]      = '*';
  token.len_min[9]  = 1;
  token.len_max[9]  = 1024;
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[10]     = '*';
  token.len_min[10] = 0;
  token.len_max[10] = 1024;
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[11]     = '*';
  token.len_min[11] = 0;
  token.len_max[11] = 1024;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[12]     = '*';
  token.len_min[12] = 0;
  token.len_max[12] = 1024;
  token.attr[12]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[13]     = '*';
  token.len_min[13] = 3;
  token.len_max[13] = 3;
  token.attr[13]    = TOKEN_ATTR_VERIFY_LENGTH;

  token.sep[14]     = '*';
  token.len_min[14] = 32;
  token.len_max[14] = 32;
  token.attr[14]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *user_pos          = token.buf[ 3];
  const u8 *realm_pos         = token.buf[ 4];
  const u8 *method_pos        = token.buf[ 5];
  const u8 *URI_prefix_pos    = token.buf[ 6];
  const u8 *URI_resource_pos  = token.buf[ 7];
  const u8 *URI_suffix_pos    = token.buf[ 8];
  const u8 *nonce_pos         = token.buf[ 9];
  const u8 *nonce_client_pos  = token.buf[10];
  const u8 *nonce_count_pos   = token.buf[11];
  const u8 *qop_pos           = token.buf[12];
  const u8 *directive_pos     = token.buf[13];
  const u8 *digest_pos        = token.buf[14];

  const int user_len          = token.len[ 3];
  const int realm_len         = token.len[ 4];
  const int method_len        = token.len[ 5];
  const int URI_prefix_len    = token.len[ 6];
  const int URI_resource_len  = token.len[ 7];
  const int URI_suffix_len    = token.len[ 8];
  const int nonce_len         = token.len[ 9];
  const int nonce_client_len  = token.len[10];
  const int nonce_count_len   = token.len[11];
  const int qop_len           = token.len[12];

  // verify

  if (memcmp (directive_pos, "MD5", 3) != 0) return (PARSER_SIP_AUTH_DIRECTIVE);

  /*
   * first (pre-)compute: HA2 = md5 ($method . ":" . $uri)
   */

  static u8 *pcsep = (u8 *) ":";

  int md5_len = method_len + 1 + URI_prefix_len + URI_resource_len + URI_suffix_len;

  if (URI_prefix_len) md5_len++;
  if (URI_suffix_len) md5_len++;

  const int md5_max_len = 4 * 64;

  if (md5_len >= md5_max_len) return (PARSER_SALT_LENGTH);

  u32 tmp_md5_buf[64] = { 0 };

  u8 *tmp_md5_ptr = (u8 *) tmp_md5_buf;

  // method

  hc_strncat (tmp_md5_ptr, method_pos, method_len);

  hc_strncat (tmp_md5_ptr, pcsep, 1);

  // URI_prefix

  if (URI_prefix_len > 0)
  {
    hc_strncat (tmp_md5_ptr, URI_prefix_pos, URI_prefix_len);

    hc_strncat (tmp_md5_ptr, pcsep, 1);
  }

  // URI_resource

  hc_strncat (tmp_md5_ptr, URI_resource_pos, URI_resource_len);

  hc_strncat (tmp_md5_ptr, pcsep, 1);

  // URI_suffix

  if (URI_suffix_len > 0)
  {
    hc_strncat (tmp_md5_ptr, URI_suffix_pos, URI_suffix_len);

    hc_strncat (tmp_md5_ptr, pcsep, 1);
  }

  memset (tmp_md5_ptr + md5_len, 0, sizeof (tmp_md5_buf) - md5_len);

  u32 tmp_digest[4];

  md5_complete_no_limit (tmp_digest, tmp_md5_buf, md5_len);

  tmp_digest[0] = byte_swap_32 (tmp_digest[0]);
  tmp_digest[1] = byte_swap_32 (tmp_digest[1]);
  tmp_digest[2] = byte_swap_32 (tmp_digest[2]);
  tmp_digest[3] = byte_swap_32 (tmp_digest[3]);

  /*
   * esalt
   */

  u8 *esalt_buf_ptr = (u8 *) sip->esalt_buf;

  int esalt_len = 0;

  const int max_esalt_len = sizeof (sip->esalt_buf);

  // there are 2 possibilities for the esalt:

  bool with_auth = false;

  if (qop_len == 4)
  {
    if (memcmp ((const char *) qop_pos, "auth", 4) == 0)
    {
      with_auth = true;
    }
  }

  if (qop_len == 8)
  {
    if (memcmp ((const char *) qop_pos, "auth-int", 8) == 0)
    {
      with_auth = true;
    }
  }

  if (with_auth == true)
  {
    esalt_len = 1 + nonce_len + 1 + nonce_count_len + 1 + nonce_client_len + 1 + qop_len + 1 + 32;

    if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    // init

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce

    hc_strncat (esalt_buf_ptr, nonce_pos, nonce_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce_count

    hc_strncat (esalt_buf_ptr, nonce_count_pos, nonce_count_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce_client

    hc_strncat (esalt_buf_ptr, nonce_client_pos, nonce_client_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // qop

    hc_strncat (esalt_buf_ptr, qop_pos, qop_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);
  }
  else
  {
    esalt_len = 1 + nonce_len + 1 + 32;

    if (esalt_len > max_esalt_len) return (PARSER_SALT_LENGTH);

    // init

    hc_strncat (esalt_buf_ptr, pcsep, 1);

    // nonce

    hc_strncat (esalt_buf_ptr, nonce_pos, nonce_len);

    hc_strncat (esalt_buf_ptr, pcsep, 1);
  }

  // tmp_digest

  u8 tmp[64];

  snprintf ((char *) tmp, sizeof (tmp), "%08x%08x%08x%08x",
    tmp_digest[0],
    tmp_digest[1],
    tmp_digest[2],
    tmp_digest[3]);

  hc_strncat (esalt_buf_ptr, tmp, 32);

  // add 0x80 to esalt

  esalt_buf_ptr[esalt_len] = 0x80;

  sip->esalt_len = esalt_len;

  /*
   * actual salt
   */

  u8 *sip_salt_ptr = (u8 *) sip->salt_buf;

  int salt_len = user_len + 1 + realm_len + 1;

  int max_salt_len = 119;

  if (salt_len > max_salt_len) return (PARSER_SALT_LENGTH);

  // user_pos

  hc_strncat (sip_salt_ptr, user_pos, user_len);

  hc_strncat (sip_salt_ptr, pcsep, 1);

  // realm_pos

  hc_strncat (sip_salt_ptr, realm_pos, realm_len);

  hc_strncat (sip_salt_ptr, pcsep, 1);

  sip->salt_len = salt_len;

  /*
   * fake salt (for sorting)
   */

  u8 *salt_buf_ptr = (u8 *) salt->salt_buf;

  max_salt_len = 55;

  int fake_salt_len = salt_len;

  if (fake_salt_len > max_salt_len)
  {
    fake_salt_len = max_salt_len;
  }

  memcpy (salt_buf_ptr, sip_salt_ptr, fake_salt_len);

  salt->salt_len = fake_salt_len;

  /*
   * digest
   */

  digest[0] = hex_to_u32 ((const u8 *) &digest_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &digest_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &digest_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &digest_pos[24]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  return snprintf (line_buf, line_size, "%s", hash_info->orighash);
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
  module_ctx->module_tmp_size                 = MODULE_DEFAULT;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
