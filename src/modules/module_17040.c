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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "GPG (CAST5 (SHA-1($pass)))";
static const u64   KERN_TYPE      = 17040;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "Hashcat1!";
static const char *ST_HASH        = "$gpg$*1*1308*4096*ddf02802e2d06319bcf5962745b73677ecfa229649fed991e3360bdf2fffe71f521b8f877bccfcdce9a4fb4aeb63bd21fed6e37f96f193a6f7d3c476f4a7e01e7421d0eba5bfcd59544e37887572cd40e8d03e901574ec0f3afdff35ad3f25cb818ddadee84ddfef636207febd8d12d8a98983c86afa46608d178dba5ec51e98a182bd9687b6431fba87b5a16b5e0cf872db7dc12c55bfe7faaa443044d5a84ddf034198e5bc6b4b707b5f4a4c5999ff3885975113fca02693620f36f8f20570bdaf581726053b6c982cb988a3091dc206624f9d36372b151b22c7dc2cb71b9aaed95dc5630c4c4b045f80c403836cc9c84951fc04b8d6e413e1d4f6b3815508f43cf80c25c7db3882b5b6572f1395a00dcda7fe65ce2155f9ea2cfe13588e0fb10316e7dd978e1d89cffc06a5e722ec765315926d2ee9060d8f449ead31cbacea88a5251be3b518d23984530da9f930114e614b7ed30f748c7512bddca8604bb5310ed76b9982eb88acaf49a29325e9db6987c6dea3878e2cb7daf3800177579ddcaafeacdba8edd147fae61bae36ab83a98db69a6c92017b3db8cff68985db989a03ee1bd045e6a577151486cdaeaf26517027b2f140b8493e2f401ea222511c2ce61c7057d64e8c3568e3f547f4b2875db59bc8c4f3346e0faf54e30745f583494b59e570bacb2b9eb71eb834e57f68aadda9af4bdb03276f71770c611aad0278033bb8c108471c4f4a2aa9070774367b9334661daf8a5e3eaf3d8dcca723d64ae7264c8709987a6cee9f42287b6e20d1d753262ff74886f3995412e59d09c61e4c637b6e97e6a3b08f9fa6adf9a1ec44a0372e893febd6712decc00bbd9cdacaf6bb9302fe8bd2ca27fdf5156c33582d56781ab0e5bd14da4b1edd73edd8f2a034a56d1a6f836724b605657f4714d59d522805e0ab02c6c5daed0973f93120ae01623ce0a96fbdf4402ce20ebb4f97fabbc90da5bb12aac3cd5f15c1add2d3863be59e843dca564ce9aa25b43ca1044b1e7e65d03d1f55f77d2a39cd85536ff38058837a23743c4e252f7de5654a562506b55d2b8fa29c7f4ecd307a8ae686cbb73fea6a8f72775d9e417ec346415024263a9f339dda286b682ccc8f93f7d4f59921620dd276188441fd44fc63925d18caa30a75c79c37a2ea45d14f6e423d2146281f9c6699a0658e50d69cfbc174090a0420bbb6f4e6b5b1f2b81b26f035aaf5c2e558c812496cb494587c78bf75350fb1a36e8c88076b4684094e0cba5dcdc4f672dbd2b432306b75077ae07b8fd88ba5b829eaed3fd2959a09b162329b75ac8fc20d4eea6e5971f54b31a23952dd4c111765822182cd60ee0de3cce3752c648918e3ec4c52643223132dcc885140faf8108230ebf4ef4149cbfa3070c91ec013404c15c1cecaa1efd544ab8313d378ef0e77c615b76b8ec07769960873ce9c7bdb1d75e7faef4c8a0b015c95a4e2bcd9ff7f5dfddd9a243fc0688db09e534ef1f3ebebd0c73b75bd57b8e02667da5744b1400dc695d4ae1e255d3487d1dead115de7d48962a15c7aecb97444173c40c028a46a7cfdd8cc7421f71d757cb809341c5148aedeab16f9289bc55b7475d646ae4993ab36fe5609a05121d140d4390289c94e4d87fd902fe03c8bfa13e7cfc9c21355ab6461d214137e4d90dff4a8f599020f12d7560fa4b5aaee1727f21c873fde76415b65357ecb923a547ddcdb20dde0880a287ed26d5ea4ce45514b907e368527c62e39ffdf2efeb817cd59694d23bafd48862e723f45e3c258cff3c804c5d2f17e24be8fe81a00f11f519beb9cde7be95226ac2a7f11e0f4f09dc040c11e1bf63172aa0f8a*1*254*2*3*8*0000000000000000*0*a11df265e4e54bee";


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

typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];  // TODO make this dynamic based on the input hash.. iv_size can be 8 bytes or 16 bytes
  u32 modulus_size;
  u32 encrypted_data[384];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  u32 salted_pw_block[80];

  u32 salted_pw_block_len;

  u32 h[10];

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  u32 len;

} gpg_tmp_t;

static const char *SIGNATURE_GPG = "$gpg$";

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (gpg_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (gpg_tmp_t);

  return tmp_size;
}

bool module_hlfmt_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool hlfmt_disable = true;

  return hlfmt_disable;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 65536;

  return kernel_loops_max;
}

u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

  gpg_t *gpgs = (gpg_t *) hashes->esalts_buf;

  gpg_t *gpg = &gpgs[digests_offset + digest_pos];

  if (gpg->cipher_algo == 3) // CAST5
  {
    return KERN_RUN_AUX1;
  }
  return 0;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  gpg_t *gpg = (gpg_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 13;

  // signature $gpg$
  token.signatures_cnt = 1;
  token.signatures_buf[0] = SIGNATURE_GPG;

  // signature $gpg$
  token.sep[0]      = '*';
  token.len[0]      = 5;
  token.attr[0]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_SIGNATURE;

  // "1" -- unknown option
  token.sep[1]      = '*';
  token.len[1]      = 1;
  token.attr[1]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of the encrypted data in bytes
  token.sep[2]      = '*';
  token.len_min[2]  = 3;
  token.len_max[2]  = 4;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of the key: 1024, 2048, 4096, etc.
  token.sep[3]      = '*';
  token.len_min[3]  = 3;
  token.len_max[3]  = 4;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // encrypted key -- twice the amount of byte because its interpreted as characters
  token.sep[4]      = '*';
  token.len_min[4]  = 256;
  token.len_max[4]  = 3072;
  token.attr[4]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  // "3" - String2Key parameter "S2K Type" https://www.rfc-editor.org/rfc/rfc4880#section-3.7
  // https://security.stackexchange.com/questions/142914/does-s2k-hold-any-use-in-symmetric-encryption-with-gnupg "OpenPGP uses the string-to-key function for both encrypting the private key with a passphrase and symmetric encryption. The function is used to derive a session key (cipher block) for symmetric encryption."
  // https://github.com/gpg/gnupg/blob/ab35d756d86438db124fa68aa633fe528ff8be50/g10/packet.h#L98
  // https://www.rfc-editor.org/rfc/rfc4880#section-3.7 so we only have a salted s2k not an iterated-and-salted
  //  ID          S2K Type
  //  --          --------
  //  0           Simple S2K
  //  1           Salted S2K
  //  2           Reserved value
  //  3           Iterated and Salted S2K
  token.sep[5]      = '*';
  token.len[5]      = 1;
  token.attr[5]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // "254" - String2Key parameter "usage" / "Secret-Key Packet Format" https://github.com/openwall/john/blob/bleeding-jumbo/src/gpg2john.c#L2424
  // 255 or 254
  // indicates that a string-to-key specifier is being given.  Any
  // other value is a symmetric-key encryption algorithm identifier.

  // If the string-to-key usage octet was
  //    254, then a 20-octet SHA-1 hash of the plaintext of the
  //    algorithm-specific portion.
  token.sep[6]      = '*';
  token.len[6]      = 3;
  token.attr[6]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // "2" - String2Key parameter "HASH_ALGS" https://github.com/openwall/john/blob/bleeding-jumbo/src/gpg2john.c#L646
  // sha1 in this case
  token.sep[7]      = '*';
  token.len[7]      = 1;
  token.attr[7]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // "3" cipher mode: String2Key parameter "SYM_ALGS" https://github.com/openwall/john/blob/bleeding-jumbo/src/gpg2john.c#L558
  // cast in this case
  token.sep[8]      = '*';
  token.len[8]      = 1;
  token.attr[8]     = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // size of initial vector in bytes: 8 or 16
  token.sep[9]      = '*';
  token.len_min[9]  = 1;
  token.len_max[9]  = 2;
  token.attr[9]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // initial vector - twice the amount of bytes because its interpreted as characters
  token.sep[10]     = '*';
  token.len_min[10]  = 16;
  token.len_max[10]  = 32;
  token.attr[10]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  // iteration count
  token.sep[11]     = '*';
  token.len_min[11] = 1;
  token.len_max[11] = 8;
  token.attr[11]    = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  // salt - 8 bytes / 16 characters
  token.len[12]     = 16;
  token.attr[12]    = TOKEN_ATTR_FIXED_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // Modulus size

  const int modulus_size = hc_strtoul ((const char *) token.buf[3], NULL, 10);

  if ((modulus_size < 256) || (modulus_size > 16384)) return (PARSER_SALT_LENGTH);

  gpg->modulus_size = modulus_size;

  // Encrypted data

  const int enc_data_size = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  const int encrypted_data_size = hex_decode (token.buf[4], token.len[4], (u8 *) gpg->encrypted_data);

  if (enc_data_size != encrypted_data_size) return (PARSER_CT_LENGTH);

  gpg->encrypted_data_size = encrypted_data_size;

  // Check String2Key parameters

  if ((hc_strtoul ((const char *) token.buf[5], NULL, 10) !=   1) && (hc_strtoul ((const char *) token.buf[5], NULL, 10) !=   3)) {
     return (PARSER_HASH_VALUE); // for us this "String2Key parameter 1" is 1 instead of 3, no idea what that means..
  }

  // 100 to 110 Private/Experimental S2K
  if (hc_strtoul ((const char *) token.buf[6], NULL, 10) != 254) return (PARSER_HASH_VALUE);
  if (hc_strtoul ((const char *) token.buf[7], NULL, 10) !=   2) return (PARSER_HASH_VALUE);

  // Cipher algo
  const int cipher_algo = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if (cipher_algo != 3) return (PARSER_CIPHER);

  gpg->cipher_algo = cipher_algo;

  // IV (size)

  // if (hc_strtoul ((const char *) token.buf[9], NULL, 10) != sizeof (gpg->iv)) {
  //   // printf("hc_strtoul ((const char *) token.buf[9]=%d\n", (const char *) token.buf[9], NULL, 10);
  //   // printf("sizeof (gpg->iv)=%d\n", sizeof (gpg->iv));
  //   return (PARSER_IV_LENGTH);
  // }
  // const int iv_size = hex_decode ((const u8 *) token.buf[10], token.len[10], (u8 *) gpg->iv);

  // if (iv_size != sizeof (gpg->iv)){
  //   return (PARSER_IV_LENGTH);
  // }


  // Salt Iter

  const u32 salt_iter = hc_strtoul ((const char *) token.buf[11], NULL, 10);

  if (salt_iter != 0) return (PARSER_HASH_VALUE); // only accept 0 for now
  if(salt_iter ==0){  salt->salt_iter = 8; } // just once should work? TODO not sure why I cannot change this to zero / remove the salt_iter completely..
  // else {
  //   if (salt_iter < 8 || salt_iter > 65011712){ return (PARSER_SALT_ITERATION); }
  //   else {
  //     salt->salt_iter = salt_iter;
  //   }
  // }


  // Salt Value

  salt->salt_repeats = gpg->cipher_algo == 7 ? 0 : 1; // "minus one" // TODO check this?

  salt->salt_len = hex_decode (token.buf[12], token.len[12], (u8 *) salt->salt_buf);

  if (salt->salt_len != 8) return (PARSER_SALT_LENGTH);

  // hash fake
  digest[0] = gpg->iv[0];
  digest[1] = gpg->iv[1];
  digest[2] = gpg->iv[2];
  digest[3] = gpg->iv[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const gpg_t *gpg = (const gpg_t *) esalt_buf;

  u8 encrypted_data[(384 * 8) + 1];
  memset(encrypted_data,0,384*8+1); // always initialize to zero

  hex_encode ((const u8 *) gpg->encrypted_data, gpg->encrypted_data_size, (u8 *) encrypted_data);

  const int line_len = snprintf (line_buf, line_size, "%s*%d*%d*%d*%s*%d*%d*%d*%d*%d*%08x%08x*%d*%08x%08x",
    SIGNATURE_GPG,
    1, /* unknown field */
    gpg->encrypted_data_size,
    gpg->modulus_size,
    encrypted_data,
    1, /* version (major?) */
    254, /* version (minor?) */
    2, /* key cipher (sha-1) */
    gpg->cipher_algo,
    8, /*iv_size*/
    byte_swap_32 (gpg->iv[0]),
    byte_swap_32 (gpg->iv[1]),
    0, /* salt_iter is always zero */
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]));

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
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_build_plain_postprocess  = MODULE_DEFAULT;
  module_ctx->module_deep_comp_kernel         = module_deep_comp_kernel;
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
  module_ctx->module_hlfmt_disable            = module_hlfmt_disable;
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
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
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
