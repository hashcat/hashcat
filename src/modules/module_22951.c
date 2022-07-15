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
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "RSA/DSA/EC/OpenSSH Private Keys ($5$)";
static const u64   KERN_TYPE      = 22951;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$5$16$52935050547964524511665675049973$1232$febee392e88cea0086b3cdefd3efec8aedb6011ca4ca9884ef9776d09559109c328fd4daef62ea4094a588d90d4617bc0348cc1205ae140e5bdca4e81bf7a8ff4fcc9954d3548ba9a0d143a504750d04d41c455d6100b33dacc5f9a10036ae75be69a81471e945554a52ca12b95640a08f607eab70c4a750dc48917f3c9ee23c537e9b4a49728a9773a999dfd842cf9a38155029ea5d42f617dbec630889d078ffadaf3ff28eed65389a73528f3d0863fffd9a740edd59ca223595e330bca37ac5a003ac556d2b6232f9900fc8654586e73e7b2d83327d61b2fc561a78aacc8aff473bb3d18ddccae87d84de143a8a98550d955d01d4e6074ac62aa0af0bca58a0c53d0d7cf1a26345c1bd3eca7a0c0e711f5c7f942d50bc872be971d0c17dbc5a88f043a937ff5d28c5ef8d8d291e511d070b14a0cc696ee5088a944b113bc7e697cdc793e931c3f0f3a892b44aad1468e6c45becdcaa89febda17fcd5fe6ff430695e04b5b6271e032e3529315367e56337777a5b342c19d3ebc7441ac0f79b93749ad4526b8be0a5cf5756363aac93da6dc19dbfff15bacbbf2dae7a549afdab8e0589321ac0a612576bbfe06fde086075d1244450a3667f793ccc81fd5ccc5b1d08e6f447e3e0cd89b901049bedb1e65b23ede0d8f00ff1c984743b50342c50408e9060ed6a809a7b068972c9542cd91de0767c02a73d192ea600008bf4a6ef339c7f2db767346cc479e61abedb4ba4a67f72e91ac49a2e92bb4bacd97aed0b044c258e2004fa0fb8da3678a57d37187c1246c90a107540161462145fa7307a6d4db34694fb1b090f07bedb9ca0e71aefd3ce5601b87778fd6b66391c3c61d528a5965f91370f52a72f0622620329f96c5dd68561e0f6576f3a2bc5c21a95aed569edc4ed979746b32909178e550907c5f41d7b24480e81a874b931c23f13517ab5f9331f11819d982bf9e5b8a03034b47c8785f8902611eac26716976bccd51d19864f10ee1fbd62f8b0149c22ab06205a20f9f9fcb0a5279552a8923c3ace2e134f6b190653f430c1a4b82f762283028d9c0c8d1a3428731f4f405f40f947f297a43aa3ba2267bbc749a5677da92a63d51d24aa5ca3e9e1d35a8143d7b4bac481f0c56754e980a60cf2d330797fc81f6c6f405760f1257103ac6edf10976c9005f4a261f7aad055400c4f18dc445eb3a403740ad6c58afa4e8edb30fad907488baf0ede2eb3d3687d1e8724dd69c7bd14b90d4f113fc9f84a2c01ab00917f53cd879a4031b1c91a4d4d7d9e712a584959137001d331f6725dca81ea6cc55fac7fc0e8b578dec0983ca98c3789cdf83507e4c3ba056fdcbea26693a313077290d7c6695f4cc6de4848532f0149cc06dbf4c76d02944178520585923b636196ea2cbcacc43950b308fc7929e85de076a2ab65c9bd8ebb0c04c041281178a48d8d2165d315b3e74abf0a38505b71ae5b2a6e7f87861e174cff873a1f61980b53ef3acdd2ea6a25425b162e5dc0bc1aa2992585d2da1625a6593cc2d4fe8c86eeb4df0e27cda54685f7245e5c48063d489e8d93bd5303bebe633139dcdd04afa005d03d1185a64e8711c0b09d9d0b38b35d6ef1b1e35353a7a4396863650a3843c687a00396dd3db53e8d28baf29101abb9f628ba896b091618f24187f6eeb814e4b64130768fb37e89b9b3230e50a7e5aba852a983525c8f193deb1fe27b334cdc3bdfa4c301d04907ee29a848393";

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

typedef struct pem
{
  u32 data_buf[16384];
  int data_len;

  int cipher;

} pem_t;

static const char *SIGNATURE_SSHNG = "$sshng$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pem_t);

  return esalt_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  pem_t *pem = (pem_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_SSHNG;

  token.len[0]     = 7;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 2;
  token.len_max[2] = 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 32;
  token.len_max[3] = 32;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 64;    // 64 = minimum size (32 byte) to avoid out of boundary read in kernel
  token.len_max[5] = 65536; // 65536 = maximum asn.1 size fitting into 2 byte length integer
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // cipher

  const u8 *cipher_pos = token.buf[1];

  int cipher = hc_strtoul ((const char *) cipher_pos, NULL, 10);

  if (cipher != 5) return (PARSER_CIPHER);

  pem->cipher = cipher;

  // IV length

  const u8 *iv_len_verify_pos = token.buf[2];

  const int iv_len_verify = hc_strtoul ((const char *) iv_len_verify_pos, NULL, 10);

  if (iv_len_verify != 16) return (PARSER_SALT_LENGTH);

  // IV buffer

  const u8 *iv_pos = token.buf[3];
  const int iv_len = token.len[3];

  if (iv_len != 32) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = hex_to_u32 (iv_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (iv_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (iv_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (iv_pos + 24);

  salt->salt_len = 16;

  // data length

  const u8 *data_len_verify_pos = token.buf[4];

  const int data_len_verify = hc_strtoul ((const char *) data_len_verify_pos, NULL, 10);

  // data

  const u8 *data_pos = token.buf[5];
  const int data_len = token.len[5];

  pem->data_len = hex_decode (data_pos, data_len, (u8 *) pem->data_buf);

  if (data_len_verify != pem->data_len) return (PARSER_HASH_LENGTH);

  // data has to be a multiple of cipher block size

  if (pem->data_len % 16) return (PARSER_HASH_LENGTH);

  // hash

  digest[0] = pem->data_buf[0];
  digest[1] = pem->data_buf[1];
  digest[2] = pem->data_buf[2];
  digest[3] = pem->data_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  pem_t *pem = (pem_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  int out_len = 0;

  out_len = snprintf ((char *) out_buf, line_size, "%s%d$16$%08x%08x%08x%08x$%d$",
    SIGNATURE_SSHNG,
    pem->cipher,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    pem->data_len);

  out_len += hex_encode ((const u8 *) pem->data_buf, pem->data_len, (u8 *) out_buf + out_len);

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
