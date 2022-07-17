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
static const char *HASH_NAME      = "PKCS#8 Private Keys (PBKDF2-HMAC-SHA1 + 3DES/AES)";
static const u64   KERN_TYPE      = 24410;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$PEM$1$4$f5662bd8383b4b40$2048$2993b585d3fb2e7b235ed13d90f637e2$1232$73984f2cba4d5e1d327a3f5a538a946099976ab865349091a452a838dc6855b6e539f920a078b14d949d8c739ea7ce26769dc0ba1619a9c0ee1864d1cfca9e61ddf6d9582439f2b65d00a3ff57c78d3176e9e88fc12da7acd421b624ba76f3d5f12926a3a9acd82f502d7638cfe2063fb2c773a56299ae1ec2c85641d33f5f8b3edfc6687fa9898325d384b3db7a7686704facb880c3898f69dd353a5d5d136b58a1e00e4711d3a01e0c632a5f3d5eff64c9e88166296b9b26f072a52bdc4893377e247b5cdb052f34e0b5d4de10a5dffe443a03b1a23f1edbcb00361334dbd6a6d31e16887b5290da2f865fbe1fef7b43c8f8f3432815ca860946560cb601ab83d417e6a4734aaf75692195566bde61e04610a9eff752c08f9ff85a48959daa7c65d03a0eca62e92bf10a55fb4834a49745a6c53d9c79d0591cb13cfa54f0d437d001b7924fd9dd69c98aa25e5d3f19649f79913bca827e7636ede04bf7c41ef54c42936b4eb93c75d941853dc7dda42b51ac5e4f5602fe2c3e62f252d28e02398943780598cf2bd41d183425daf34e86099c748eda2d5372029ebd089f619dab327ea728eb90342f2b48cd364e914a6078599afdb22a6fac6b55e1bf28b3284a0edc748b59c2eaa97e35d457d4c049f86fd3fc618c4c52f08776c0efb33011b96ef6f0b0e6ecf6d37dc20da8ab7d9b8154371c8e396d9b89ee02e6e6b013a0985b1f47c91f3b5a9e6c33736840e6044f46be1dbea4ec7730eccc6e993cb522bb220de4ed55156129f821d7df19439ab86990991cfd1992681716b5ff012ffa5519ad0baa01885f77f6a522469979f449232d408379558fcdfe5253371da835e0c77706dfa67ff28b1cd8d7fdf9e386899838532d8e57ec1ed3d31a96ae03f37b976fb6c503cc247113deaa070697728e3b36ce43de051ce13a4df91d22157c6281e8f9a16de007c6dddf03ffc79a9f4cfc3eaddd637a9a902fdba1c9e857a9ccd7c318db17cd40d8b588b5d97c7d03c0404473dd201aa5c6637e952c6299e35374127276b3eb4aeba754f3176fecea1731a0f917dd049fcdab34264a8c635ba90eec941aeb449a7eca263aaec9e46758bdf21caa896adb4652e9564d75c20e296fcdf28cbdeb702a1e7acf2374d24b51e6492b0bcc72a58748666a7278e2cb54fbdb68c6736ceb85dd92cd0465b19a65f7ad47e25658a34c3531db48c37ef279574e1892d80d80f3e9dee385ab65e6a4537f6e318817a785228160939d01632b8269858ce9092359048b09ae8b9c17ceb575216988bbeb91c1b5861c931f21e07d888ceb9b89d89d17608e2d5f0ae66b6e756f1eac9f80e13749f866ea6b741158296d3ced761999ad901a2121e233bf173865b6c0b32d68e6ef1d39bb411a1ee9d4d1cde870645b9922051b31cc0df640fb01d23c613091ba538999254b873fbb5996efdfbde5c933e1b6ef6d1c7d5e1a9bff6800c8625b07aba2c14143c1a33a0661c357e5db59a2f49aab35c13531774fb5b3795ed853d7f4e38910c7eeb3435353e2cfd0c94e61c16c8126928343f86222c5ef320b9e043d3cd357af4e065500f50e6bf9c260ca298bd5507c9498dbcea4ceec834449b7fb7249fdf199f66aa98d0a820b1057df1d67c43f49c6d18c3c902466b2b2b528075489261ef73bf711c7988fed65693798568bed43e4d70a800cd25b1773c455aaa153cea8f7013eae1e8f24c6793f590c8f6a112b46";

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

typedef struct pkcs_sha1_tmp
{
  u32  ipad[5];
  u32  opad[5];

  u32  dgst[32];
  u32  out[32];

} pkcs_sha1_tmp_t;

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
  const u64 tmp_size = (const u64) sizeof (pkcs_sha1_tmp_t);

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

  if (type_pos[0] != '1') return (PARSER_SIGNATURE_UNMATCHED);

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

  int out_len = snprintf ((char *) out_buf, line_size, "%s1$%d$%s$%d$%s$%d$",
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
