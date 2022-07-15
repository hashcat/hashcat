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
#include "memory.h"
#include "emu_inc_hash_md5.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "VirtualBox (PBKDF2-HMAC-SHA256 & AES-256-XTS)";
static const u64   KERN_TYPE      = 27600;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP2;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_ST_HEX
                                  | OPTS_TYPE_INIT2
                                  | OPTS_TYPE_LOOP2;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$vbox$0$160000$54aff69fca91c20b3b15618c6732c4a2f953dd88690cd4cc731569b6b80b5572$16$cfb003087e0c618afa9ad7e44adcd97517f039e0424dedb46db8affbb73cd064019abae19ee5e4f5b05b626e6bc5d7da65c61a5f94d7bcac521c388276e5358b$20000$2e5729055136168eea79cb3f1765450a35ab7540125f2ca2a46924a99fd0524d$b28d1db1cabe99ca989a405c33a27beeb9c0683b8b4b54b0e0d85f712f64d89c";

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

typedef struct vbox
{
  u32 salt1_buf[64];
  u32 salt1_len;
  u32 aes_key_len;
  u32 enc_pass_buf[128];
  u32 salt2_buf[64];
  u32 salt2_len;

} vbox_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[64];
  u32  out[64];

} pbkdf2_sha256_tmp_t;

static const char *SIGNATURE_VBOX = "$vbox$0$";

salt_t *module_benchmark_salt (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  salt_t *salt = (salt_t *) hcmalloc (sizeof (salt_t));

  salt->salt_iter  = 160000 - 1;
  salt->salt_iter2 = 20000 - 1;
  salt->salt_len   = 32;

  return salt;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (vbox_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha256_tmp_t);

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

  vbox_t *vbox = (vbox_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_VBOX;

  token.sep[0]     = '$';
  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 9;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 64;
  token.len_max[2] = 64;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 2;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 128;
  token.len_max[4] = 128;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len_min[5] = 1;
  token.len_max[5] = 9;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '$';
  token.len_min[6] = 64;
  token.len_max[6] = 64;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len_min[7] = 64;
  token.len_max[7] = 64;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // iter 1

  const u8 *iter1_pos = token.buf[1];

  u32 iter1 = hc_strtoul ((const char *) iter1_pos, NULL, 10);

  if (iter1 < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter = iter1 - 1;

  // salt 1

  const u8 *salt1_pos = token.buf[2];
  const u32 salt1_len = token.len[2];

  u32 *salt1_buf_ptr = (u32 *) vbox->salt1_buf;

  salt1_buf_ptr[0] = hex_to_u32 ((const u8 *) &salt1_pos[ 0]);
  salt1_buf_ptr[1] = hex_to_u32 ((const u8 *) &salt1_pos[ 8]);
  salt1_buf_ptr[2] = hex_to_u32 ((const u8 *) &salt1_pos[16]);
  salt1_buf_ptr[3] = hex_to_u32 ((const u8 *) &salt1_pos[24]);
  salt1_buf_ptr[4] = hex_to_u32 ((const u8 *) &salt1_pos[32]);
  salt1_buf_ptr[5] = hex_to_u32 ((const u8 *) &salt1_pos[40]);
  salt1_buf_ptr[6] = hex_to_u32 ((const u8 *) &salt1_pos[48]);
  salt1_buf_ptr[7] = hex_to_u32 ((const u8 *) &salt1_pos[56]);

  vbox->salt1_len = salt1_len / 2;

  // handle unique salts detection

  md5_ctx_t md5_ctx;

  md5_init   (&md5_ctx);
  md5_update (&md5_ctx, vbox->salt1_buf, vbox->salt1_len);
  md5_final  (&md5_ctx);

  // store md5(vbox->salt1_buf) in salt_buf

  salt->salt_len = 16;

  memcpy (salt->salt_buf, md5_ctx.h, salt->salt_len);

  // aes xts key len (128 or 256)

  const u8 *aes_key_len_pos = token.buf[3];

  u32 aes_key_len = hc_strtoul ((const char *) aes_key_len_pos, NULL, 10);

  if (aes_key_len != 16) return (PARSER_SALT_ITERATION); // todo: change return

  vbox->aes_key_len = aes_key_len;

  // enc pass

  const u8 *enc_pass_pos = token.buf[4];
  const u32 enc_pass_len = token.len[4];

  if (enc_pass_len != 128) return (PARSER_SALT_ITERATION); // todo: change return

  u32 *enc_pass_buf_ptr = (u32 *) vbox->enc_pass_buf;

  enc_pass_buf_ptr[ 0] = hex_to_u32 ((const u8 *) &enc_pass_pos[ 0]);
  enc_pass_buf_ptr[ 1] = hex_to_u32 ((const u8 *) &enc_pass_pos[ 8]);
  enc_pass_buf_ptr[ 2] = hex_to_u32 ((const u8 *) &enc_pass_pos[16]);
  enc_pass_buf_ptr[ 3] = hex_to_u32 ((const u8 *) &enc_pass_pos[24]);
  enc_pass_buf_ptr[ 4] = hex_to_u32 ((const u8 *) &enc_pass_pos[32]);
  enc_pass_buf_ptr[ 5] = hex_to_u32 ((const u8 *) &enc_pass_pos[40]);
  enc_pass_buf_ptr[ 6] = hex_to_u32 ((const u8 *) &enc_pass_pos[48]);
  enc_pass_buf_ptr[ 7] = hex_to_u32 ((const u8 *) &enc_pass_pos[56]);
  enc_pass_buf_ptr[ 8] = hex_to_u32 ((const u8 *) &enc_pass_pos[64]);
  enc_pass_buf_ptr[ 9] = hex_to_u32 ((const u8 *) &enc_pass_pos[72]);
  enc_pass_buf_ptr[10] = hex_to_u32 ((const u8 *) &enc_pass_pos[80]);
  enc_pass_buf_ptr[11] = hex_to_u32 ((const u8 *) &enc_pass_pos[88]);
  enc_pass_buf_ptr[12] = hex_to_u32 ((const u8 *) &enc_pass_pos[96]);
  enc_pass_buf_ptr[13] = hex_to_u32 ((const u8 *) &enc_pass_pos[104]);
  enc_pass_buf_ptr[14] = hex_to_u32 ((const u8 *) &enc_pass_pos[112]);
  enc_pass_buf_ptr[15] = hex_to_u32 ((const u8 *) &enc_pass_pos[120]);

  // iter 2

  const u8 *iter2_pos = token.buf[5];

  u32 iter2 = hc_strtoul ((const char *) iter2_pos, NULL, 10);

  if (iter2 < 1) return (PARSER_SALT_ITERATION);

  salt->salt_iter2 = iter2 - 1;

  // salt 2

  const u8 *salt2_pos = token.buf[6];
  const u32 salt2_len = token.len[6];

  u32 *salt2_buf_ptr = (u32 *) vbox->salt2_buf;

  salt2_buf_ptr[0] = hex_to_u32 ((const u8 *) &salt2_pos[ 0]);
  salt2_buf_ptr[1] = hex_to_u32 ((const u8 *) &salt2_pos[ 8]);
  salt2_buf_ptr[2] = hex_to_u32 ((const u8 *) &salt2_pos[16]);
  salt2_buf_ptr[3] = hex_to_u32 ((const u8 *) &salt2_pos[24]);
  salt2_buf_ptr[4] = hex_to_u32 ((const u8 *) &salt2_pos[32]);
  salt2_buf_ptr[5] = hex_to_u32 ((const u8 *) &salt2_pos[40]);
  salt2_buf_ptr[6] = hex_to_u32 ((const u8 *) &salt2_pos[48]);
  salt2_buf_ptr[7] = hex_to_u32 ((const u8 *) &salt2_pos[56]);

  vbox->salt2_len = salt2_len / 2;

  // hash

  const u8 *hash_pos = token.buf[7];

  digest[0] = hex_to_u32 ((const u8 *) &hash_pos[ 0]);
  digest[1] = hex_to_u32 ((const u8 *) &hash_pos[ 8]);
  digest[2] = hex_to_u32 ((const u8 *) &hash_pos[16]);
  digest[3] = hex_to_u32 ((const u8 *) &hash_pos[24]);
  digest[4] = hex_to_u32 ((const u8 *) &hash_pos[32]);
  digest[5] = hex_to_u32 ((const u8 *) &hash_pos[40]);
  digest[6] = hex_to_u32 ((const u8 *) &hash_pos[48]);
  digest[7] = hex_to_u32 ((const u8 *) &hash_pos[56]);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);
  digest[4] = byte_swap_32 (digest[4]);
  digest[5] = byte_swap_32 (digest[5]);
  digest[6] = byte_swap_32 (digest[6]);
  digest[7] = byte_swap_32 (digest[7]);

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const vbox_t *vbox = (const vbox_t *) esalt_buf;

  u8 salt1_buf[64+1] = { 0 };

  u32_to_hex (vbox->salt1_buf[0], salt1_buf +  0);
  u32_to_hex (vbox->salt1_buf[1], salt1_buf +  8);
  u32_to_hex (vbox->salt1_buf[2], salt1_buf + 16);
  u32_to_hex (vbox->salt1_buf[3], salt1_buf + 24);
  u32_to_hex (vbox->salt1_buf[4], salt1_buf + 32);
  u32_to_hex (vbox->salt1_buf[5], salt1_buf + 40);
  u32_to_hex (vbox->salt1_buf[6], salt1_buf + 48);
  u32_to_hex (vbox->salt1_buf[7], salt1_buf + 56);

  u8 enc_pass_buf[128+1] = { 0 };

  u32_to_hex (vbox->enc_pass_buf[ 0], enc_pass_buf +   0);
  u32_to_hex (vbox->enc_pass_buf[ 1], enc_pass_buf +   8);
  u32_to_hex (vbox->enc_pass_buf[ 2], enc_pass_buf +  16);
  u32_to_hex (vbox->enc_pass_buf[ 3], enc_pass_buf +  24);
  u32_to_hex (vbox->enc_pass_buf[ 4], enc_pass_buf +  32);
  u32_to_hex (vbox->enc_pass_buf[ 5], enc_pass_buf +  40);
  u32_to_hex (vbox->enc_pass_buf[ 6], enc_pass_buf +  48);
  u32_to_hex (vbox->enc_pass_buf[ 7], enc_pass_buf +  56);
  u32_to_hex (vbox->enc_pass_buf[ 8], enc_pass_buf +  64);
  u32_to_hex (vbox->enc_pass_buf[ 9], enc_pass_buf +  72);
  u32_to_hex (vbox->enc_pass_buf[10], enc_pass_buf +  80);
  u32_to_hex (vbox->enc_pass_buf[11], enc_pass_buf +  88);
  u32_to_hex (vbox->enc_pass_buf[12], enc_pass_buf +  96);
  u32_to_hex (vbox->enc_pass_buf[13], enc_pass_buf + 104);
  u32_to_hex (vbox->enc_pass_buf[14], enc_pass_buf + 112);
  u32_to_hex (vbox->enc_pass_buf[15], enc_pass_buf + 120);

  u8 salt2_buf[64+1] = { 0 };

  u32_to_hex (vbox->salt2_buf[0], salt2_buf +  0);
  u32_to_hex (vbox->salt2_buf[1], salt2_buf +  8);
  u32_to_hex (vbox->salt2_buf[2], salt2_buf + 16);
  u32_to_hex (vbox->salt2_buf[3], salt2_buf + 24);
  u32_to_hex (vbox->salt2_buf[4], salt2_buf + 32);
  u32_to_hex (vbox->salt2_buf[5], salt2_buf + 40);
  u32_to_hex (vbox->salt2_buf[6], salt2_buf + 48);
  u32_to_hex (vbox->salt2_buf[7], salt2_buf + 56);

  u8 hash[64+1] = { 0 };

  u32_to_hex (byte_swap_32 (digest[0]), hash +  0);
  u32_to_hex (byte_swap_32 (digest[1]), hash +  8);
  u32_to_hex (byte_swap_32 (digest[2]), hash + 16);
  u32_to_hex (byte_swap_32 (digest[3]), hash + 24);
  u32_to_hex (byte_swap_32 (digest[4]), hash + 32);
  u32_to_hex (byte_swap_32 (digest[5]), hash + 40);
  u32_to_hex (byte_swap_32 (digest[6]), hash + 48);
  u32_to_hex (byte_swap_32 (digest[7]), hash + 56);

  const int line_len = snprintf (line_buf, line_size, "%s%u$%s$%u$%s$%u$%s$%s",
    SIGNATURE_VBOX,
    salt->salt_iter + 1,
    salt1_buf,
    vbox->aes_key_len,
    enc_pass_buf,
    salt->salt_iter2 + 1,
    salt2_buf,
    hash);

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
  module_ctx->module_benchmark_salt           = module_benchmark_salt;
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
