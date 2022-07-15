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
static const char *HASH_NAME      = "RSA/DSA/EC/OpenSSH Private Keys ($0$)";
static const u64   KERN_TYPE      = 22911;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_MAXIMUM_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$0$8$7532262427635482$1224$e1b1690703b83fd0ab6677c89a00dfce57fc2f345ebd2b2993bf0d8bb267449d08839213dc234dd23c7a181077e00080ced2700a161c4352ce5574b9758926f09106157715b6d756cf6dd844e473c6bb3c2b591cdbf684394a49935f7d62bcc324c1392aee499e3d6235db0556d27adc6e35ef4654ee5fc72e60dff605484e75c6fd6ae29cb476f8a658dbcce9f9591a9dad023f6d9aa223c3d56261e056c5cafa93438937e0762b989cd10e6280a09488be07423c549514ff9686338e72dbe6bdc5015944739a9f183cacf04c1c141dc8c8d8aa8636c85a6c0578a5983ed33d5ff5ee6a66a54d86defd1c4f9d6a59446861bf4cc7bd667bc92b9d328c154f442d1d03d4d370dcc065a1d5420c5b71e4c35a457e11a0c9f489636559a2ac53bb4cfee2b0058f8a9d1ccc38a844ee0d1ff5d6938427bf24d6e4c69f10e6ebce9187d51e867ac3b362b9c6149712e8378a9ac91d1aab1a7a5f088ddbdead0cc754c30961b7a71284b5c6658f7219632de6007d5145a1ae062f807234230ff73a3436ce28ae3bfa0f880d1e49ec8a288da18db14905bc7a7b061a51c429876db81ad528efb469ba2bf46c7344aadc7d082efc83ede3894bf6b1738151e642f6f60a41069ad862d2f4f8d55733bd6d85086d1d9bb1913a9d4680ea0b49f712c590a3c18b91ef745b9bdf461af67879d94f9672de4abe0b7d2e4efba1f8bb6ffbb4a095742d5cff0e225b1b5e166854bb9821e4283d97f80855c81efea1eb3e7881a6049186650bfbf68f30302c069883668e373c12ce9a39de8d7c1be22a717d9c74410c45093aae03c5de8cc0ec662fe3bb81bf952e17b854001bcad9b36cab2f473a609878a419b735c66f3732bd5540fb1cba9fe081f87cecf63a6243cd2049dfa25a763ef2e0633bfb13a411207d8ca1c8f3c0c30b8a7583436cad7bd8c28ba625b9c53dc280b314671b0a55d75a28d3b21de250e3c554b86ca5d32821ab912c6607687c4dc5b3214216a7409621ce6fb89bd5309a7dd8ec9ae4b751bdfb6b5d12d733a89d87722dbdb1b15df5463241f0f56c401e095ea5dee07c0ded1f11ffbd7c93a41add0cfd8c57b44f255fdfd1929cd7d068d6cf951ba8ab0d718996fec10aaa26a4314d4c1272f744adf3c7e4d710ae171c072a7c61c2b020a445cf32be3083d3bc62083f2385bbae4fadddf8714258b996abd574638891bb918e877fdef3a4856b910999a6dc9dbd13c0e938825cd895c96d39cb86bb283a53fac7090c71a9320c6a34af309d2218af64c895f5eff8eee28cf94e7a7437a0922d83bfa39f08bb40e354d9ace07aa586a446dc217ede98b6ca9637545cc11ef56732fc9cd3dc06e459d868137b75d39a87e6721a95f2b84e57c94ef703486a2857821e497b990c95080015d825b6dc63d666f66cfa35912e607c3b650d81dc98c0c53322796ff9249cdfe7a375e1d01607816a85bb43f3969767a9aaed07161344e714d7e875b40f3524f95e476e605dbd2ac51e36075701fa93b66f36470796ebf5d35690a297e19729f9ac59d98622e3ad3e45a2914bdd2b807446c8b430e54c1a607fd25a69bf469a61d2e3bc3697b786c047bc60dbeabe6372d71e9b7c9787bb2559c663a011f864ecf32793e65f4bdd76370d99f602ddcbc7e5aa7d2749f36e8d0f209a378782882bc06ee5b5014c2a6248469f0fe0fc5369383db0bc898c0760b8c40fe20342fa5b";

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
  token.len_min[2] = 1;
  token.len_max[2] = 1;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 16;
  token.len_max[3] = 16;
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

  if (cipher != 0) return (PARSER_CIPHER);

  pem->cipher = cipher;

  // IV length

  const u8 *iv_len_verify_pos = token.buf[2];

  const int iv_len_verify = hc_strtoul ((const char *) iv_len_verify_pos, NULL, 10);

  if (iv_len_verify != 8) return (PARSER_SALT_LENGTH);

  // IV buffer

  const u8 *iv_pos = token.buf[3];
  const int iv_len = token.len[3];

  if (iv_len != 16) return (PARSER_SALT_LENGTH);

  salt->salt_buf[0] = hex_to_u32 (iv_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (iv_pos +  8);

  salt->salt_len = 8;

  // data length

  const u8 *data_len_verify_pos = token.buf[4];

  const int data_len_verify = hc_strtoul ((const char *) data_len_verify_pos, NULL, 10);

  // data

  const u8 *data_pos = token.buf[5];
  const int data_len = token.len[5];

  pem->data_len = hex_decode (data_pos, data_len, (u8 *) pem->data_buf);

  if (data_len_verify != pem->data_len) return (PARSER_HASH_LENGTH);

  // data has to be a multiple of cipher block size

  if (pem->data_len % 8) return (PARSER_HASH_LENGTH);

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

  out_len = snprintf ((char *) out_buf, line_size, "%s%d$8$%08x%08x$%d$",
    SIGNATURE_SSHNG,
    pem->cipher,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
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
