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
static const char *HASH_NAME      = "RSA/DSA/EC/OpenSSH Private Keys ($1, $3$)";
static const u64   KERN_TYPE      = 22931;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_SUGGEST_KG
                                  | OPTS_TYPE_MAXIMUM_THREADS;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$1$16$14987802644369864387956120434709$1232$ffa56007ed83e49fdc439c776a9dec9656521385073bf71931a2c6503c93917e560cc98940c8cdcf2c709265e9ba20783a3bacc63423a98e40ea8999182613e1f5a80084719ca0e5c390299de1ea947df41f2ff1489bddfe13c6128612c5c82b7fc1ef5105ea28adda7b415729c66fb6cbc4b6b51ef518f74e1971f88e0cfabd69e8c4270678e360149ce15716fef4736df296a20d2607ef269a3c69896fc423683d6057e00064f84e04caf4d4663b51b307cfb1d1dbd6b3bf67764a08847c7b83fa5544e6a1e950f16acda8c8bac30675bc3cea9c7e06790ddc7cd1e4177b93bdd0d9edf9cdceb4a4444b437d967acdb92274a7b10d9cd1073ab4e9b5dd468aabe1f40a02b2e51f19840798c2311b625037eba5f0a0256638b42577385f4d4c730a9cedf4e244ce74656a21bf16756857866433dbb1feff9c4323d234d4235b72ed5a3adc3a6c9bae373472d64b7882d1762911326f330cb42d8ab7931f1ad2de56c4e6e8a6e838108cf9a2728ffa356796f63d94723b1d0aad5b4fcea16ab0730e7553804ad9ffb6ecdbdd925fca05ca1c076ed09a30df8a5add44a43c36b92248dc8dd4605bc2ee557e6e4438abf9ea7d047f764c55a5ba46a41719b9c55e54ad5fbfce6a89b9283c163d8464ecdda5aaf113d038b659950b8c79e87abad019eb77535cc8e63f760a4c87ca344a563475361766df718519b1b7e4b3ab511952fcc9b011f1d8971f9261509139b739afcc2c9acd006ee714dffc8c9a4df0d54770d70c8c28c27cdf9ee7301fd64530ef0ec3eb044fb891b193a7aaa9158625ed9f5a842c86ed09e5377d90a69aea4c5fd321bc3ac9b2a0d34509a5de0b72ac3f81304895c4381e01136b1e8654cec20c220c0ac6a1300f031ffc68ddeab554279024c122589b91556feef394a1663b42fb8460af5fe881cb1cd4984b84be75125411b1d3fc236dd81f99b872aad511d28944e91d2f8853f11be85b6930a15b4d0b3d215d76416970ade5726979c1d737980fb68ecb03d1196a69f4013dd2e296a75a4c69664b0162cb8b22af18c536a8ce51f39b1282f2fe07e6b034627f075cfb20dffee62817aabeea60befea1ac93ba608d957e4030e41be7bc55275bc4037300f6ba736370eb7c9240629853c95f9304b7ffd26a10d55ae735fa943e29aa9ed437b61955fc16cde9ea7a3658d831bdbc38befa45cec80da9ccb6d21da83ff666e32d7c5c0ca0ade2cd685407ee701c1c707fc5c80b22f3af42ac1353fcdc09a459086434db7c78792decdc91572363478a14d1256346a9ac6336b8183ed6252106aa546dd092c0bbb464cdb44ae165d67d1be135877587de3bbbd02b5ef6473f125366f6dae0536ebbe18ab8de8ce2ef3d26d6dd400319e7d07ae276b081e94446e9a72877cf23e9ba52406b1842e3a0dcf7bbdc63a1336b894be475613cc917eb47724f64e621bfc3053d7423e3e2fb141a3368dc8881fa20e040e9a6bc2e7348e923e4c20e506566b8663bf7d557e792cbe4adffcf9c520d58565d77f6bf1c9ed5fa3209f8047765d01b9c264e97a3ef9ff90766ad69a4f508041e168bf0f7419e54ec88bdc4c858231cdba60774a27cc459cd65b46e26a620a43033788c6e2ee8916670568d6e6c700515f2cbca3eef62028ce75245cf8f99cd6e0ba7839a7b335c797a06ff80571950ebec2fccebb89265025b3250e4a5c9c3a62f471324556fc4db044cebe97f62c86913";

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

  if ((cipher != 1) && (cipher != 3)) return (PARSER_CIPHER);

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
