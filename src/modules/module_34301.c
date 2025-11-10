/**
 * Author......: Netherlands Forensic Institute
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
// #include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PASSWORD_MANAGER;
static const char *HASH_NAME      = "KeePass AESKDF (KDBX v4)";
static const u64   KERN_TYPE      = 34301;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$keepass$*4*600000*c9d9f39a*0*0*0*824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d630*871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d628*03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d6300b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea05010000005208000000c02709000000000042010000005320000000871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d6280007100000004131c9acd9c70ac00790dc17059c1b1f00040000000d0a0d0a*6f9ccf175ddd593a654a53fd3ec50f8559fc0abb4acf03b4f2a74353058afb39"; //https://github.com/hashcat/hashcat/issues/4455

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

typedef struct keepass4_tmp
{
  u32 tmp_digest[8];

} keepass4_tmp_t;

typedef struct keepass4
{
  u32 masterseed[8];

  u32 header_len;
  u32 header[64];

  u32 keyfile_len;
  u32 keyfile[8];

} keepass4_t;

static const char *SIGNATURE_AESKDF_UUID   = "c9d9f39a";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (keepass4_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size =  (const u64) sizeof (keepass4_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  keepass4_t *keepass4 = esalt_buf;

  bool is_keyfile_present = false;

  if (line_len < 128) return (PARSER_SALT_LENGTH);

  if ((line_buf[line_len - (64 + 1 + 2 + 1 + 2)] == '*')
   && (line_buf[line_len - (64 + 1 + 2 + 1 + 1)] == '1')
   && (line_buf[line_len - (64 + 1 + 2 + 1 + 0)] == '*')) is_keyfile_present = true;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 11;

  // 0. signature
  token.signatures_cnt    = 1;
  token.signatures_buf[0] = "$keepass$*";
  token.len[0]     = 10;
  token.sep[0]     = 0;
  token.attr[0]    = TOKEN_ATTR_VERIFY_SIGNATURE;

  // 1. keepassDB version
  token.len[1]     = 1;
  token.sep[1]     = '*';
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  // 2. iterations
  token.len_min[2] = 1;
  token.len_max[2] = 10;
  token.sep[2]     = '*';
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  // 3. KDF UUID
  token.len_min[3] = 8;
  token.len_max[3] = 8;
  token.sep[3]     = '*';
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // 4. memoryUsageInBytes
  token.len_min[4] = 1; // can be 1 with AESKDF
  token.len_max[4] = 12;
  token.sep[4]     = '*';
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  // 5. Argon version
  token.len_min[5] = 1;
  token.len_max[5] = 3;
  token.sep[5]     = '*';
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  // 6. parallelism
  token.len_min[6] = 1;
  token.len_max[6] = 3;
  token.sep[6]     = '*';
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_DIGIT;

  // 7. masterseed
  token.len_min[7] = 64;
  token.len_max[7] = 64;
  token.sep[7]     = '*';
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // 8. transformseed (salt)
  token.len_min[8] = 64;
  token.len_max[8] = 64;
  token.sep[8]     = '*';
  token.attr[8]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // 9. header
  token.len_min[9] = 400;
  token.len_max[9] = 600;
  token.sep[9]     = '*';
  token.attr[9]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  // 10. headerhmac (digest)
  token.len_min[10] = 64;
  token.len_max[10] = 64;
  token.sep[10]     = '*';
  token.attr[10]    = TOKEN_ATTR_VERIFY_LENGTH | TOKEN_ATTR_VERIFY_HEX;

  if (is_keyfile_present == true)
  {
    token.token_cnt = 14;

    token.sep[11]     = '*';
    token.len[11]     = 1;
    token.attr[11]    = TOKEN_ATTR_FIXED_LENGTH
                      | TOKEN_ATTR_VERIFY_DIGIT;

    token.sep[12]     = '*';
    token.len[12]     = 2;
    token.attr[12]    = TOKEN_ATTR_FIXED_LENGTH
                      | TOKEN_ATTR_VERIFY_DIGIT;

    token.sep[13]     = '*';
    token.len[13]     = 64;
    token.attr[13]    = TOKEN_ATTR_FIXED_LENGTH
                      | TOKEN_ATTR_VERIFY_HEX;
  }

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // 0. signature:
  // $keepass$*
  const int sig_len = token.len[0];
  const u8 *sig_pos = token.buf[0];
  if (memcmp (token.signatures_buf[0],  sig_pos, sig_len) != 0) return (PARSER_SIGNATURE_UNMATCHED);

  // 1. keepassDB version
  // 4*
  const u8 *keepassdb_version_pos = token.buf[1];
  const u32 keepassdb_version = hc_strtoul ((const char *) keepassdb_version_pos, NULL, 10);
  if (keepassdb_version != 4) return (PARSER_HASH_VALUE); // we don't support anything else than 4

  // 2. iterations
  // 600000*
  const u8 *it_pos = token.buf[2];
  salt->salt_iter  = hc_strtoul ((const char *) it_pos, NULL, 10);

  // 3. KDF UUID:
  // c9d9f39a*
  const int kdf_uuid_len = token.len[3];
  const u8 *kdf_uuid_pos = token.buf[3];
  const u8 kdf_uuid[8] = { 0 };
  hex_decode ((const u8 *) kdf_uuid_pos, kdf_uuid_len, (u8 *) kdf_uuid);
  if (memcmp (SIGNATURE_AESKDF_UUID,   kdf_uuid_pos, kdf_uuid_len) != 0) return (PARSER_HASH_VALUE);

  // 4. memoryUsageInBytes
  // 0*
  const u8 *mem_pos = token.buf[4];
  u32 mem = hc_strtoul ((const char *) mem_pos, NULL, 10);
  if (mem > 0) return (PARSER_HASH_VALUE);

  // 5. Argon version
  // 0*
  const u8 *ver_pos = token.buf[5];
  u32 version = hc_strtoul ((const char *) ver_pos, NULL, 10);
  if (version > 0) return (PARSER_HASH_VALUE);

  // 6. parallelism
  // 0*
  const u8 *par_pos = token.buf[6];
  u32 par = hc_strtoul ((const char *) par_pos, NULL, 10);
  if (par > 0) return (PARSER_HASH_VALUE);

  // 7. masterseed
  // 824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d630*
  const int masterseed_len = token.len[7];
  const u8 *masterseed_pos = token.buf[7];
  hex_decode ((const u8 *) masterseed_pos, masterseed_len, (u8 *) keepass4->masterseed);
  // 8. transformseed (salt)
  // 871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d628*
  const int salt_len = token.len[8];
  const u8 *salt_pos = token.buf[8];

  salt->salt_len = hex_decode ((const u8 *) salt_pos, salt_len, (u8 *) salt->salt_buf);

  // 9. header
  // 03d9a29a67fb4bb500000400021000000031c1f2e6bf714350be5805216afc5aff0304000000010000000420000000824e99f947e7da61a3d2c4b46f59779d46695ea86e3cc6de684dc2106744d6300b5d00000000014205000000245555494410000000c9d9f39a628a4460bf740d08c18a4fea05010000005208000000c02709000000000042010000005320000000871b472ef007cd2fb03fae5b802556844e224b021ea058c94382d1f315a6d6280007100000004131c9acd9c70ac00790dc17059c1b1f00040000000d0a0d0a*
  //AESKDF length of 414hex or 207bytes instead of 507hex for argon

  keepass4->header_len = token.len[9];
  if (keepass4->header_len % 2 != 0) return (PARSER_HASH_VALUE); // hex-value needs to be multiple of 2
  keepass4->header_len = keepass4->header_len / 2;

  const u8 *header_pos = token.buf[9];
  hex_decode ((const u8 *) header_pos, keepass4->header_len*2, (u8 *) keepass4->header);

  // 10. headerhmac (digest): digest/ target hash
  // 6f9ccf175ddd593a654a53fd3ec50f8559fc0abb4acf03b4f2a74353058afb39
  const int digest_len = token.len[10];
  const u8 *digest_pos = token.buf[10];
  hex_decode ((const u8 *) digest_pos, digest_len, (u8 *) digest);

  const u8 *keyfile_pos = NULL;
  keepass4->keyfile_len = 0;

  if (is_keyfile_present == true)
  {
    const u8 *keyfile_len_pos = token.buf[12];
    const u32 keyfile_len = hc_strtoul ((const char *) keyfile_len_pos, NULL, 10);
    if (keyfile_len != 64) return (PARSER_HASH_VALUE); // we don't support anything else than 64 characters or 32 bytes
    keepass4->keyfile_len = 32;

    keyfile_pos = token.buf[13];

    keepass4->keyfile[0] = hex_to_u32 (&keyfile_pos[ 0]);
    keepass4->keyfile[1] = hex_to_u32 (&keyfile_pos[ 8]);
    keepass4->keyfile[2] = hex_to_u32 (&keyfile_pos[16]);
    keepass4->keyfile[3] = hex_to_u32 (&keyfile_pos[24]);
    keepass4->keyfile[4] = hex_to_u32 (&keyfile_pos[32]);
    keepass4->keyfile[5] = hex_to_u32 (&keyfile_pos[40]);
    keepass4->keyfile[6] = hex_to_u32 (&keyfile_pos[48]);
    keepass4->keyfile[7] = hex_to_u32 (&keyfile_pos[56]);

    keepass4->keyfile[0] = byte_swap_32 (keepass4->keyfile[0]);
    keepass4->keyfile[1] = byte_swap_32 (keepass4->keyfile[1]);
    keepass4->keyfile[2] = byte_swap_32 (keepass4->keyfile[2]);
    keepass4->keyfile[3] = byte_swap_32 (keepass4->keyfile[3]);
    keepass4->keyfile[4] = byte_swap_32 (keepass4->keyfile[4]);
    keepass4->keyfile[5] = byte_swap_32 (keepass4->keyfile[5]);
    keepass4->keyfile[6] = byte_swap_32 (keepass4->keyfile[6]);
    keepass4->keyfile[7] = byte_swap_32 (keepass4->keyfile[7]);

  }

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const keepass4_t *keepass4 = esalt_buf;

  // 7. masterseed
  char masterseed_hex[64+1] = { 0 };
  hex_encode( (const u8 *) keepass4->masterseed, 32, (u8 *) masterseed_hex);

  // 8. transformseed (salt)
  char salt_hex[64+1] = { 0 };
  hex_encode( (const u8 *) salt->salt_buf, 32, (u8 *) salt_hex);

  // 9. header
  char header_hex[(keepass4->header_len*2)+1];
  memset(header_hex, 0, (keepass4->header_len*2)+1);
  hex_encode( (const u8 *) keepass4->header, keepass4->header_len, (u8 *) header_hex);

  // 10. headerhmac (digest)
  char digest_hex[64+1] = { 0 };
  hex_encode( (const u8 *) digest, 32, (u8 *) digest_hex);

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  if (keepass4->keyfile_len)
  {
    u32 keyfile_swap[8];

    keyfile_swap[0] = byte_swap_32 (keepass4->keyfile[0]);
    keyfile_swap[1] = byte_swap_32 (keepass4->keyfile[1]);
    keyfile_swap[2] = byte_swap_32 (keepass4->keyfile[2]);
    keyfile_swap[3] = byte_swap_32 (keepass4->keyfile[3]);
    keyfile_swap[4] = byte_swap_32 (keepass4->keyfile[4]);
    keyfile_swap[5] = byte_swap_32 (keepass4->keyfile[5]);
    keyfile_swap[6] = byte_swap_32 (keepass4->keyfile[6]);
    keyfile_swap[7] = byte_swap_32 (keepass4->keyfile[7]);

    char keyfile_hex[64+1] = { 0 };
    hex_encode( (const u8 *) keyfile_swap, 32, (u8 *) keyfile_hex);

    out_len = snprintf ((char *) out_buf, line_size, "%s*%d*%d*%s*%d*%d*%d*%s*%s*%s*%s*1*%d*%s",
      "$keepass$",          // 0. signature
      4,                    // 1. keepassDB version
      salt->salt_iter,      // 2. iterations
      SIGNATURE_AESKDF_UUID,// 3. KDF UUID
      0,                    // 4. memoryUsageInBytes
      0,                    // 5. Argon version
      0,                    // 6. parallelism
      masterseed_hex,       // 7. masterseed
      salt_hex,             // 8. transformseed (salt)
      header_hex,           // 9. header
      digest_hex,           // 10. headerhmac (digest)
      keepass4->keyfile_len*2,
      keyfile_hex
    );
  }
  else
  {
    out_len = snprintf ((char *) out_buf, line_size, "%s*%d*%d*%s*%d*%d*%d*%s*%s*%s*%s",
      "$keepass$",          // 0. signature
      4,                    // 1. keepassDB version
      salt->salt_iter,      // 2. iterations
      SIGNATURE_AESKDF_UUID,// 3. KDF UUID
      0,                    // 4. memoryUsageInBytes
      0,                    // 5. Argon version
      0,                    // 6. parallelism
      masterseed_hex,       // 7. masterseed
      salt_hex,             // 8. transformseed (salt)
      header_hex,           // 9. header
      digest_hex            // 10. headerhmac (digest)
    );
  }

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
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}

