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
static const char *HASH_NAME      = "SASL DIGEST-MD5";
static const u64   KERN_TYPE      = 61000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_PT_ADD80
                                  | OPTS_TYPE_HASH_COPY;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sasl$DIGEST-MD5$WORKGROUP$admin$OA9BSXrbuRhWay$YDgMb0MHFhY9LOl9Tg5hH4GD8JHF8MaZ$00000001$auth$ldap/dc01.workgroup.local$ce9c97bcd0f0bf9d00c456514496814f";

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

typedef struct digest_md5
{
  u32 salt_buf[64];
  u32 salt_len;

  u32 a1_buf[64];
  u32 a1_len;

  u32 esalt_buf[64];
  u32 esalt_len;

} digest_md5_t;

static const char *SIGNATURE_SASL_DIGEST_MD5 = "$sasl$";

static void md5_complete_no_limit (u32 digest[4], const u32 *plain, const u32 plain_len)
{
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
  const u64 esalt_size = (const u64) sizeof (digest_md5_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  digest_md5_t *digest_md5 = (digest_md5_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  // $sasl$DIGEST-MD5$realm$username$nonce$cnonce$nc$qop$uri$response

  token.token_cnt  = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SASL_DIGEST_MD5;

  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // DIGEST-MD5
  token.sep[1]     = '$';
  token.len[1]     = 10;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH;

  // realm
  token.sep[2]     = '$';
  token.len_min[2] = 0;
  token.len_max[2] = 128;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH;

  // username
  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 128;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH;

  // nonce
  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 128;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH;

  // cnonce
  token.sep[5]     = '$';
  token.len_min[5] = 1;
  token.len_max[5] = 128;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH;

  // nc
  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 16;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH;

  // qop
  token.sep[7]     = '$';
  token.len_min[7] = 1;
  token.len_max[7] = 16;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH;

  // uri
  token.sep[8]     = '$';
  token.len_min[8] = 1;
  token.len_max[8] = 256;
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH;

  // response
  token.len[9]     = 32;
  token.attr[9]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // verify sub-signature

  if (memcmp (token.buf[1], "DIGEST-MD5", 10) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  const u8 *realm_pos    = token.buf[2];
  const u8 *user_pos     = token.buf[3];
  const u8 *nonce_pos    = token.buf[4];
  const u8 *cnonce_pos   = token.buf[5];
  const u8 *nc_pos       = token.buf[6];
  const u8 *qop_pos      = token.buf[7];
  const u8 *uri_pos      = token.buf[8];
  const u8 *response_pos = token.buf[9];

  const int realm_len    = token.len[2];
  const int user_len     = token.len[3];
  const int nonce_len    = token.len[4];
  const int cnonce_len   = token.len[5];
  const int nc_len       = token.len[6];
  const int qop_len      = token.len[7];
  const int uri_len      = token.len[8];

  const int salt_total_len = user_len + 1 + realm_len + 1;

  if (salt_total_len > 255) return (PARSER_SALT_LENGTH);

  u8 *salt_buf_ptr = (u8 *) digest_md5->salt_buf;

  memcpy (salt_buf_ptr, user_pos, user_len);
  salt_buf_ptr[user_len] = ':';
  memcpy (salt_buf_ptr + user_len + 1, realm_pos, realm_len);
  salt_buf_ptr[user_len + 1 + realm_len] = ':';

  digest_md5->salt_len = salt_total_len;

  const int a1_total_len = 1 + nonce_len + 1 + cnonce_len;

  if (a1_total_len > 255) return (PARSER_SALT_LENGTH);

  u8 *a1_buf_ptr = (u8 *) digest_md5->a1_buf;

  a1_buf_ptr[0] = ':';
  memcpy (a1_buf_ptr + 1, nonce_pos, nonce_len);
  a1_buf_ptr[1 + nonce_len] = ':';
  memcpy (a1_buf_ptr + 1 + nonce_len + 1, cnonce_pos, cnonce_len);

  digest_md5->a1_len = a1_total_len;

  static u8 *auth_prefix = (u8 *) "AUTHENTICATE:";

  const int ha2_input_len = 13 + uri_len;

  if (ha2_input_len > 255) return (PARSER_SALT_LENGTH);

  u32 tmp_ha2_buf[64] = { 0 };

  u8 *tmp_ha2_ptr = (u8 *) tmp_ha2_buf;

  memcpy (tmp_ha2_ptr, auth_prefix, 13);
  memcpy (tmp_ha2_ptr + 13, uri_pos, uri_len);

  u32 tmp_ha2_digest[4];

  md5_complete_no_limit (tmp_ha2_digest, tmp_ha2_buf, ha2_input_len);

  tmp_ha2_digest[0] = byte_swap_32 (tmp_ha2_digest[0]);
  tmp_ha2_digest[1] = byte_swap_32 (tmp_ha2_digest[1]);
  tmp_ha2_digest[2] = byte_swap_32 (tmp_ha2_digest[2]);
  tmp_ha2_digest[3] = byte_swap_32 (tmp_ha2_digest[3]);

  const int esalt_total_len = 1 + nonce_len + 1 + nc_len + 1 + cnonce_len + 1 + qop_len + 1 + 32;

  if (esalt_total_len > 255) return (PARSER_SALT_LENGTH);

  u8 *esalt_buf_ptr = (u8 *) digest_md5->esalt_buf;

  int esalt_off = 0;

  esalt_buf_ptr[esalt_off++] = ':';
  memcpy (esalt_buf_ptr + esalt_off, nonce_pos, nonce_len);
  esalt_off += nonce_len;
  esalt_buf_ptr[esalt_off++] = ':';
  memcpy (esalt_buf_ptr + esalt_off, nc_pos, nc_len);
  esalt_off += nc_len;
  esalt_buf_ptr[esalt_off++] = ':';
  memcpy (esalt_buf_ptr + esalt_off, cnonce_pos, cnonce_len);
  esalt_off += cnonce_len;
  esalt_buf_ptr[esalt_off++] = ':';
  memcpy (esalt_buf_ptr + esalt_off, qop_pos, qop_len);
  esalt_off += qop_len;
  esalt_buf_ptr[esalt_off++] = ':';

  snprintf ((char *) esalt_buf_ptr + esalt_off, 33, "%08x%08x%08x%08x",
    tmp_ha2_digest[0],
    tmp_ha2_digest[1],
    tmp_ha2_digest[2],
    tmp_ha2_digest[3]);

  digest_md5->esalt_len = esalt_total_len;

  u8 *fake_salt_ptr = (u8 *) salt->salt_buf;

  int fake_salt_len = nonce_len;

  if (fake_salt_len > 55) fake_salt_len = 55;

  memcpy (fake_salt_ptr, nonce_pos, fake_salt_len);

  salt->salt_len = fake_salt_len;

  digest[0] = hex_to_u32 (&response_pos[ 0]);
  digest[1] = hex_to_u32 (&response_pos[ 8]);
  digest[2] = hex_to_u32 (&response_pos[16]);
  digest[3] = hex_to_u32 (&response_pos[24]);

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
