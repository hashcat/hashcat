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
static const u32   DGST_SIZE      = DGST_SIZE_4_64;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_NETWORK_SERVER;
static const char *HASH_NAME      = "RedHat 389-DS LDAP (PBKDF2-HMAC-SHA256)";
static const u64   KERN_TYPE      = 10900;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "{PBKDF2_SHA256}AACkEGhlaiBqZW5z/jtuSox0CrtV9SHiVFjYeHpQ/ki2kwDrQeSqiiTn8LOmpPCw3r6TK/JDfl+ZAXRoc3VidGxldHllIXuxBDl6ItQOMupkRn+hzi/LEdr62a7B9sNOo8BPL9Z2nOi/m9AI+nAd/qwpLD1fbeDgs2DdpCZ4QfljuCLRBdURZV3HcXDUjD7PZ1CQcIOv9VbFlbu0IBmiU7ccMyb/qoxi+rPMqE4U8f6hL0TQjTjlOzU9MpPYS+WfztpYy7lEN6QghhOz0xe+0y2rDoK+yCS4PykkNS4FFc+xeiT6SNy3r7m+0teyaQKOExLrjogWkj+t+e4bMpHNx/FL3jkjCsuZnhq/t8eshG9DKmeD9b/QMkqT8dxe0jmr0s4+GnmHpMQMAxYW3pg70TluiDp3kJrDr1/d8OQerkQRevNx";

static const u32   HASH_LEN_RAW   = 256;
static const u32   SALT_LEN_RAW   = 64;
static const u32   ITER_LEN_RAW   = 4;

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

typedef struct pbkdf2_sha256
{
  u32 salt_buf[64];

} pbkdf2_sha256_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

static const char *SIGNATURE_REDHAT_PBKDF2_SHA256 = "{PBKDF2_SHA256}";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pbkdf2_sha256_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

  return tmp_size;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = PW_MAX;

  return pw_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) esalt_buf;

  token_t token;

  token.token_cnt  = 2;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_REDHAT_PBKDF2_SHA256;

  //length of signature
  token.len[0]     = 15;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  //length of base64 encoded hash
  token.len_min[1] = 432;
  token.len_max[1] = 432;

  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64A;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  //read hash into tmp_buf

  const u8 *tmp_pos = token.buf[1];
  const int tmp_len = token.len[1];

  u8 tmp_buf[324];

  memset (tmp_buf, 0, sizeof (tmp_buf));

  const int base64_decode_len = base64_decode (base64_to_int, tmp_pos, tmp_len, tmp_buf);

  if (base64_decode_len != (4 + 64 + 256)) return (PARSER_HASH_LENGTH);

  // iter

  u8 *iter_pos = tmp_buf;

  uint32_t iters[4] = {0};

  memcpy (iters, iter_pos, ITER_LEN_RAW);

  // implementation does a ntohl(*iters)
  salt->salt_iter = byte_swap_32(*iters) - 1;

  // salt

  u8 *salt_pos = tmp_buf + ITER_LEN_RAW;

  salt->salt_len  = SALT_LEN_RAW;

  u8 *salt_buf_ptr = (u8 *) pbkdf2_sha256->salt_buf;
  memcpy (salt_buf_ptr, salt_pos, SALT_LEN_RAW);

  // hash

  u8 *hash_pos = tmp_buf + ITER_LEN_RAW + SALT_LEN_RAW;
  memcpy(digest, hash_pos, HASH_LEN_RAW);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);
  digest[8] = byte_swap_32 (digest[8]);
  digest[9] = byte_swap_32 (digest[9]);
  digest[10] = byte_swap_32 (digest[10]);
  digest[11] = byte_swap_32 (digest[11]);
  digest[12] = byte_swap_32 (digest[12]);
  digest[13] = byte_swap_32 (digest[13]);
  digest[14] = byte_swap_32 (digest[14]);
  digest[15] = byte_swap_32 (digest[15]);
  digest[16] = byte_swap_32 (digest[16]);
  digest[17] = byte_swap_32 (digest[17]);
  digest[18] = byte_swap_32 (digest[18]);
  digest[19] = byte_swap_32 (digest[19]);
  digest[20] = byte_swap_32 (digest[20]);
  digest[21] = byte_swap_32 (digest[21]);
  digest[22] = byte_swap_32 (digest[22]);
  digest[23] = byte_swap_32 (digest[23]);
  digest[24] = byte_swap_32 (digest[24]);
  digest[25] = byte_swap_32 (digest[25]);
  digest[26] = byte_swap_32 (digest[26]);
  digest[27] = byte_swap_32 (digest[27]);
  digest[28] = byte_swap_32 (digest[28]);
  digest[29] = byte_swap_32 (digest[29]);
  digest[30] = byte_swap_32 (digest[30]);
  digest[31] = byte_swap_32 (digest[31]);
  digest[32] = byte_swap_32 (digest[32]);
  digest[33] = byte_swap_32 (digest[33]);
  digest[34] = byte_swap_32 (digest[34]);
  digest[35] = byte_swap_32 (digest[35]);
  digest[36] = byte_swap_32 (digest[36]);
  digest[37] = byte_swap_32 (digest[37]);
  digest[38] = byte_swap_32 (digest[38]);
  digest[39] = byte_swap_32 (digest[39]);
  digest[40] = byte_swap_32 (digest[40]);
  digest[41] = byte_swap_32 (digest[41]);
  digest[42] = byte_swap_32 (digest[42]);
  digest[43] = byte_swap_32 (digest[43]);
  digest[44] = byte_swap_32 (digest[44]);
  digest[45] = byte_swap_32 (digest[45]);
  digest[46] = byte_swap_32 (digest[46]);
  digest[47] = byte_swap_32 (digest[47]);
  digest[48] = byte_swap_32 (digest[48]);
  digest[49] = byte_swap_32 (digest[49]);
  digest[50] = byte_swap_32 (digest[50]);
  digest[51] = byte_swap_32 (digest[51]);
  digest[52] = byte_swap_32 (digest[52]);
  digest[53] = byte_swap_32 (digest[53]);
  digest[54] = byte_swap_32 (digest[54]);
  digest[55] = byte_swap_32 (digest[55]);
  digest[56] = byte_swap_32 (digest[56]);
  digest[57] = byte_swap_32 (digest[57]);
  digest[58] = byte_swap_32 (digest[58]);
  digest[59] = byte_swap_32 (digest[59]);
  digest[60] = byte_swap_32 (digest[60]);
  digest[61] = byte_swap_32 (digest[61]);
  digest[62] = byte_swap_32 (digest[62]);
  digest[63] = byte_swap_32 (digest[63]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const pbkdf2_sha256_t *pbkdf2_sha256 = (pbkdf2_sha256_t *) esalt_buf;

  u32 tmp_digest[64];
  tmp_digest[0] = byte_swap_32 (digest[0]);
  tmp_digest[1] = byte_swap_32 (digest[1]);
  tmp_digest[2] = byte_swap_32 (digest[2]);
  tmp_digest[3] = byte_swap_32 (digest[3]);
  tmp_digest[4] = byte_swap_32 (digest[4]);
  tmp_digest[5] = byte_swap_32 (digest[5]);
  tmp_digest[6] = byte_swap_32 (digest[6]);
  tmp_digest[7] = byte_swap_32 (digest[7]);
  tmp_digest[8] = byte_swap_32 (digest[8]);
  tmp_digest[9] = byte_swap_32 (digest[9]);
  tmp_digest[10] = byte_swap_32 (digest[10]);
  tmp_digest[11] = byte_swap_32 (digest[11]);
  tmp_digest[12] = byte_swap_32 (digest[12]);
  tmp_digest[13] = byte_swap_32 (digest[13]);
  tmp_digest[14] = byte_swap_32 (digest[14]);
  tmp_digest[15] = byte_swap_32 (digest[15]);
  tmp_digest[16] = byte_swap_32 (digest[16]);
  tmp_digest[17] = byte_swap_32 (digest[17]);
  tmp_digest[18] = byte_swap_32 (digest[18]);
  tmp_digest[19] = byte_swap_32 (digest[19]);
  tmp_digest[20] = byte_swap_32 (digest[20]);
  tmp_digest[21] = byte_swap_32 (digest[21]);
  tmp_digest[22] = byte_swap_32 (digest[22]);
  tmp_digest[23] = byte_swap_32 (digest[23]);
  tmp_digest[24] = byte_swap_32 (digest[24]);
  tmp_digest[25] = byte_swap_32 (digest[25]);
  tmp_digest[26] = byte_swap_32 (digest[26]);
  tmp_digest[27] = byte_swap_32 (digest[27]);
  tmp_digest[28] = byte_swap_32 (digest[28]);
  tmp_digest[29] = byte_swap_32 (digest[29]);
  tmp_digest[30] = byte_swap_32 (digest[30]);
  tmp_digest[31] = byte_swap_32 (digest[31]);
  tmp_digest[32] = byte_swap_32 (digest[32]);
  tmp_digest[33] = byte_swap_32 (digest[33]);
  tmp_digest[34] = byte_swap_32 (digest[34]);
  tmp_digest[35] = byte_swap_32 (digest[35]);
  tmp_digest[36] = byte_swap_32 (digest[36]);
  tmp_digest[37] = byte_swap_32 (digest[37]);
  tmp_digest[38] = byte_swap_32 (digest[38]);
  tmp_digest[39] = byte_swap_32 (digest[39]);
  tmp_digest[40] = byte_swap_32 (digest[40]);
  tmp_digest[41] = byte_swap_32 (digest[41]);
  tmp_digest[42] = byte_swap_32 (digest[42]);
  tmp_digest[43] = byte_swap_32 (digest[43]);
  tmp_digest[44] = byte_swap_32 (digest[44]);
  tmp_digest[45] = byte_swap_32 (digest[45]);
  tmp_digest[46] = byte_swap_32 (digest[46]);
  tmp_digest[47] = byte_swap_32 (digest[47]);
  tmp_digest[48] = byte_swap_32 (digest[48]);
  tmp_digest[49] = byte_swap_32 (digest[49]);
  tmp_digest[50] = byte_swap_32 (digest[50]);
  tmp_digest[51] = byte_swap_32 (digest[51]);
  tmp_digest[52] = byte_swap_32 (digest[52]);
  tmp_digest[53] = byte_swap_32 (digest[53]);
  tmp_digest[54] = byte_swap_32 (digest[54]);
  tmp_digest[55] = byte_swap_32 (digest[55]);
  tmp_digest[56] = byte_swap_32 (digest[56]);
  tmp_digest[57] = byte_swap_32 (digest[57]);
  tmp_digest[58] = byte_swap_32 (digest[58]);
  tmp_digest[59] = byte_swap_32 (digest[59]);
  tmp_digest[60] = byte_swap_32 (digest[60]);
  tmp_digest[61] = byte_swap_32 (digest[61]);
  tmp_digest[62] = byte_swap_32 (digest[62]);
  tmp_digest[63] = byte_swap_32 (digest[63]);

  char tmp_buf[324] = { 0 };
  memset (tmp_buf, 0, sizeof (tmp_buf));

  uint32_t salt_iters[4] = { 0 };

  salt_iters[0] = byte_swap_32 (salt->salt_iter + 1); //htonl(salt->salt_iter);

  memcpy (tmp_buf, salt_iters, 4);
  memcpy (tmp_buf + 4, pbkdf2_sha256->salt_buf, salt->salt_len);
  memcpy (tmp_buf + 4 + 64, tmp_digest, 256);

  char ptr_plain[433] = { 0 };

  base64_encode (int_to_base64, (const u8 *) tmp_buf, 324, (u8 *) ptr_plain);

  const int line_len = snprintf (line_buf, line_size, "%s%s", SIGNATURE_REDHAT_PBKDF2_SHA256, ptr_plain);

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

