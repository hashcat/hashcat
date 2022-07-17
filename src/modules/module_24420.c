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
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "PKCS#8 Private Keys (PBKDF2-HMAC-SHA256 + 3DES/AES)";
static const u64   KERN_TYPE      = 24420;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$PEM$2$4$ed02960b8a10b1f1$2048$a634c482a95f23bd8fada558e1bac2cf$1232$50b21db4aededb96417a9b88131e6bc3727739b4aa1413417338efaa6a756f27c32db5c339d9c3ba61c746bbe3d6c5e0a023f965e70fb617e78a00890b8c7fc7c9f5e0ab39f35bf58ab40f6ed15441338134d041ca59783437ef681a51132c085abb3830df95e9f94d11da54d61679ca6e40136da96ffe205ce191002458143f03cba3aeca6b22a3f0689d5582b3e6c01baee7a04d875ed44bb84fa0ed0a3aae1ed392645cced385498eef4ec25bf6d1399f1487f3625fad9fee25aabf18edb1ce5e640e834d31251b882601f23c2b2d77a45c84e0fc8a3a42e3ff9f75e7ac815c57a7e943ad803ab3672f85a37c6b92d0813590d47a31788643449dce67f135363a0c14f089629a1274b124539535df5f50df5d4402f7a109738f56467725a8aa3884562c8b4c42c068c3502be86e20ac9c52c0daec22e47dcbefebe902b1dc791ed3cd069c7f9211e43f5a3274450f4b0f0b7c6f59adeca8b39ed130b6cbda7cf98e15bbba21fa1758a28dc2edf2e2f17fc353853dc881458e59184f5a8f6e09456e4d71d90135a8ce67350f7bcb3d900e75585e3a87c0c8482f3917347fcfad4fdb8915991cffd20dae1502d0f69d385244e489e50cc9f24b15a5f9d0b00d62805026db5378b5408d7d719786eb043659a452096736e4a7501548655df83045dc4e86bd3319f2982e6db2bbb239019202cebf2ca68c05b578ba95cef82397b145c80208cd7ffd9b0cd5fc3d0d7ea26401c8e11c28ab8d1a524b884962e7fee597943a5e38137abb8b26a7772f0ad6dad074dcfd0b5794822aa7e43d10cab2c95e63b6459706dc21a1cbbd7ae4c96b40ee4d7039cf84c416cb879b2d30b7ac5e1860dcd2ab5479c39b748f5fd9336934c9c1e8064ffb0906c0c2898479209d1a9c97c3cd1782d7514e94d01b242a371a2df5592d620ebd6e18e63ff24ee8ba182f17e6c578431d738e955a957469e8069a919fd3a15532d460201d4e38ac04ac494b9cde1731d4511bf8faf8420a9de4f8c7d3d721fc30d8c3664683fd91ad3515e97092fb652205fb087890cb594947f5372c9b0b27f08b4b57bf610f777fcf040e6e7b8cedf85113dfd909cbac4b774c7580686f2e1f261898da4c6804d573fb22248005f5e0d3b256a0f3dcb71c47b3d674352bda82c22a513e381f990b6100328185511de9b3352126c5aedb9b0bde15743b42e231ef7227c0fe478044ce69474a740366058f07e56dde7d6089cb76e606482e7ba206355fc0fa180c4a41ae781e4723120e3d5a1dd40224db2c959ecbc9bce88bfeed64082d07b111e88a2d8a6a6fe097c9a298a6c3f76beb5b3b5aecedbbbcd404aac8fd25c069c747338ca0c81e6b63d87fc4f0bc18a86b721e3a16e9875741e0313057de8476ee84e36efe557dc33a7d23a9426f2e359781147607ad79235c9d7846320fe2d963fac79a5c92ff3067595273931174d2173f63cfceb9f62a873e7c240d3c260bcfb02b2697911321a72455cacc6929133d0af2cdf6d59a63293ac508786a4850267f90993fff3b6c07bbf3af0e3c08638148101ae1495da3360614866e238c4f60ca00f615877be80cc708da5ea1c30032acffd0e55429ba29dca409349d901a49831db44c1e58b7530b383d3f7e1cac79200cad9bdf87451783f2ffdab09b230aab52b41fa42fdd9f1f05a3dda0fa16b011c51e330d044adf394bbbb7fa25efc860f3082e42824be3b96943afbe641fe6bb";

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

#define PKCS_MIN_SALT_LEN     ( 8)
#define PKCS_MAX_SALT_LEN     (32)
#define PKCS_MIN_SALT_HEX_LEN (PKCS_MIN_SALT_LEN * 2)
#define PKCS_MAX_SALT_HEX_LEN (PKCS_MAX_SALT_LEN * 2)

#define PKCS_MIN_IV_LEN     ( 8)
#define PKCS_MAX_IV_LEN     (16)
#define PKCS_MIN_IV_HEX_LEN (PKCS_MIN_IV_LEN * 2)
#define PKCS_MAX_IV_HEX_LEN (PKCS_MAX_IV_LEN * 2)

typedef enum pkcs_cipher {
  PKCS_CIPHER_3DES        = 1,
  PKCS_CIPHER_AES_128_CBC = 2,
  PKCS_CIPHER_AES_192_CBC = 3,
  PKCS_CIPHER_AES_256_CBC = 4,
} pkcs_cipher_t;

typedef enum pkcs_cipher_block_size {
  PKCS_CIPHER_BLOCK_SIZE_3DES        =  8,
  PKCS_CIPHER_BLOCK_SIZE_AES_128_CBC = 16,
  PKCS_CIPHER_BLOCK_SIZE_AES_192_CBC = 16,
  PKCS_CIPHER_BLOCK_SIZE_AES_256_CBC = 16,
} pkcs_cipher_block_size_t;

typedef struct pkcs_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pkcs_sha256_tmp_t;

typedef struct pkcs
{
  int cipher; // pkcs_cipher_t

  u32 data_buf[16384];
  int data_len;

  u32 iv_buf[4];

} pkcs_t;

static const char *SIGNATURE_PEM = "$PEM$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (pkcs_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (pkcs_sha256_tmp_t);

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

  pkcs_t *pkcs = (pkcs_t *) esalt_buf;

  hc_token_t token;

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_PEM;

  token.len[0]     = 5;
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
  token.len_min[3] = PKCS_MIN_SALT_HEX_LEN;
  token.len_max[3] = PKCS_MAX_SALT_HEX_LEN;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = PKCS_MIN_IV_HEX_LEN;  // can be either 16 or 32
  token.len_max[5] = PKCS_MAX_IV_HEX_LEN;  // exact check deeper in decoder code
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '$';
  token.len_min[7] = 64;    // 64 = minimum size (32 byte) to avoid out of boundary read in kernel
  token.len_max[7] = 65536; // 65536 = maximum asn.1 size fitting into 2 byte length integer
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  if (type_pos[0] != '2') return (PARSER_SIGNATURE_UNMATCHED);

  // cipher

  const u8 *cipher_pos = token.buf[2];

  int cipher = hc_strtoul ((const char *) cipher_pos, NULL, 10);

  if ((cipher != PKCS_CIPHER_3DES)
   && (cipher != PKCS_CIPHER_AES_128_CBC)
   && (cipher != PKCS_CIPHER_AES_192_CBC)
   && (cipher != PKCS_CIPHER_AES_256_CBC)) return (PARSER_CIPHER);

  pkcs->cipher = cipher;

  // salt buffer

  const u8 *salt_pos = token.buf[3];

  salt->salt_len = hex_decode (salt_pos, token.len[3], (u8 *) salt->salt_buf);

  // iter

  const u8 *iter_pos = token.buf[4];

  const u32 iter = hc_strtoul ((const char *) iter_pos, NULL, 10);

  salt->salt_iter = iter - 1;

  // IV buffer

  const u8 *iv_pos = token.buf[5];
  const int iv_len = token.len[5];

  if ((cipher == PKCS_CIPHER_3DES) && (iv_len != PKCS_MIN_IV_HEX_LEN)) return (PARSER_SALT_LENGTH);
  if ((cipher != PKCS_CIPHER_3DES) && (iv_len != PKCS_MAX_IV_HEX_LEN)) return (PARSER_SALT_LENGTH);

  hex_decode (iv_pos, iv_len, (u8 *) pkcs->iv_buf);

  // data length

  const u8 *data_len_verify_pos = token.buf[6];

  const int data_len_verify = hc_strtoul ((const char *) data_len_verify_pos, NULL, 10);

  // data

  const u8 *data_pos = token.buf[7];
  const int data_len = token.len[7];

  pkcs->data_len = hex_decode (data_pos, data_len, (u8 *) pkcs->data_buf);

  if (data_len_verify != pkcs->data_len) return (PARSER_HASH_LENGTH);

  // data has to be a multiple of cipher block size

  int cipher_bs = 0;

       if (cipher == PKCS_CIPHER_3DES)        { cipher_bs = PKCS_CIPHER_BLOCK_SIZE_3DES; }
  else if (cipher == PKCS_CIPHER_AES_128_CBC) { cipher_bs = PKCS_CIPHER_BLOCK_SIZE_AES_128_CBC; }
  else if (cipher == PKCS_CIPHER_AES_192_CBC) { cipher_bs = PKCS_CIPHER_BLOCK_SIZE_AES_192_CBC; }
  else if (cipher == PKCS_CIPHER_AES_256_CBC) { cipher_bs = PKCS_CIPHER_BLOCK_SIZE_AES_256_CBC; }

  if (pkcs->data_len % cipher_bs) return (PARSER_HASH_LENGTH);

  // hash

  digest[0] = pkcs->data_buf[0];
  digest[1] = pkcs->data_buf[1];
  digest[2] = pkcs->data_buf[2];
  digest[3] = pkcs->data_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  pkcs_t *pkcs = (pkcs_t *) esalt_buf;

  // salt

  char salt_buf[PKCS_MAX_SALT_HEX_LEN + 1] = { 0 };

  hex_encode ((const u8 *) salt->salt_buf, salt->salt_len, (u8 *) salt_buf);

  // iv

  char iv[PKCS_MAX_IV_HEX_LEN + 1] = { 0 };

  int iv_len = 0;

  if (pkcs->cipher == PKCS_CIPHER_3DES)
  {
    iv_len = PKCS_MIN_IV_LEN;
  }
  else
  {
    iv_len = PKCS_MAX_IV_LEN;
  }

  hex_encode((const u8 *) pkcs->iv_buf, iv_len, (u8 *) iv);

  // output

  u8 *out_buf = (u8 *) line_buf;

  int out_len = snprintf ((char *) out_buf, line_size, "%s2$%d$%s$%d$%s$%d$",
    SIGNATURE_PEM,
    pkcs->cipher,
    salt_buf,
    salt->salt_iter + 1,
    iv,
    pkcs->data_len);

  out_len += hex_encode ((const u8 *) pkcs->data_buf, pkcs->data_len, (u8 *) out_buf + out_len);

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
