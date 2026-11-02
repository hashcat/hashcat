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
#include "parser.h"
#include "memory.h"
#include "blowfish_common.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "OpenBSD softraid FDE (bcrypt-pbkdf)";
static const u64   KERN_TYPE      = 38810;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$openbsd-softraid$16$178073496b872f79303905bdd4729a84152e0a0d8aa21e69961a1fc4c8154a8bc20b7fd2d2c2b39eb5576f7b5fcc6f8f683d5d59e323aac36a431b31b080b64c30a09303a6aadea7f5351c5e23fcf7aa9f9aa91c09a436e95e5f416e597c3eb6f34c97c0577ba3b3a6403e04ff952d49819d58471d95673982a8c05f50d11f29$441433c062f69de0755a58517bb530c54a6443646052c2bb3641cf1795c95560ccee996a3ea8bfe64db497e3f779c8c2c8446b6f7cb4f2d8d27e72f19474b491c2aeaf791ada3b6adbf04326d40ec6416e905b7fdb6d275a4b77f434bf6a5c590e81b02c00a335f56e47902458b4dd0a4c6a69b04e6c066f81615253093a5d48c253e5b7b1420fa5379be7f4f3e00a427bef64611c7ea1ca4fb2342c878a008a48fcf2ee9b66ea66ba10d4785e2d7cdabc0d475aea66477006851a778d70a1875b20fababd925cef2fe50b5cda0f583891f398cf21b2fc1981da769603b3ed4cd08d98e3dacf4541fb8d22a75c08f11b44875a6da711ed1ebe2454ec3d85f18649ba066578a350049a33f8f1a3e1236454952f22c2725a036d01884690d8c3d49ec3311bdf15d5aa0adb9d913ebf17384e3ff896f6bcdb923f9eed51208d4955df43c16301a1339a5bc8598ad0315984f1622383627e87eedcbfc57b9bb1c63f7b81a54574e47171ff93aeb3562cced6380396c195277513b6bd5ac6f75562ab8465035eabd56a6e7d4126c4581100b9ac7053fe31f8e7957be2a6e31b730d132b67b34137cf9bcd90cd6ff27bd3ccd16f024a94273233544705d7acabaf015ecb3d25efd41e9585da8c412876f6041ce6198a68d5c66c1b1198d2c8bf77edd2fa28997d34bd10768fce33b5fb3a1c228f87517928c64326a904d4e56b1b7fbbec3174f1e8a76000ea0f8fa1cefe78f55cb074decafd3692326305fba49b6d8ea2f38015995b8fee4de6f0522bb06413b6f07c0974a68bf61312e99be7879428c6bef8cca9261c74088a84443420e97f81184863b27a897b383b17d61ffb4b95e47fbd84ac63bf1ba874af3eb87c0b346ea32c56e0be477c69b428f8118fa08af8d10e816b499b6dbd0db5bcadae18e170ac7ecc2b17f9b3074b097ef439c2edc03526a02b601f2a0caac715a043ee7f6d6f07e8c59abe4e4443cfc48075249eba041c01a73fbca9734130a12dd008f64bf7454935eae4cde30894f117c7efcd8167052b7ee9f5ffcbccb02886963432cebe72f9170b1e44c2bc133eef769aa4817497b52d8ad23decf1c1728700d8a3e6cc034594b65b81438f0d6159e31479d1e77abf9fbd07b8bfe8d5fd1934969b456551be0780fe3677a4e1823880577aa7c0a78252e1b8b8fa40bece18f79d18bb8dc1c8501631f009276b451595e13b8dd3ec928a939e3d08c1c67a051dde3f5a9545b5b216849d6b26b6300c58f2332eae1fc01b390629c0d849b7fe41352e7c5406a855beec9b97044a59cad00f529d422d148178dc338469d8b162d312ce10b41627709f54c42e7aa23a1a424dd2eda725a90ca43f9cd18fe613f328f17faec5ee206cd66a8c063429a4e5148a84ebf6bca1ee6ab17fe1c6319f479084842d5a107766ae262205e96d1a229023dc3fafd6c4d0cf485aa63b6103314196dde95c21dd993fbe5dcfbfa58f59aff785ee8bc605529a5a367f2fa75428e57339fe948243e01287ed13375022eccb8bb58b61d7868c157225c7241ac69b00da6f2d239bf2fb73d2315cabc38e4c44402a17aaa8506e1b79cd0c3a1ad8de50a099dc5e17b060cb17008d822b3d18a4f2780b151dc16f3cda5b912d064ae8c1d53922a045e1097ce3ff4d1e8db4310e3d17049a23627ba4f72cd5bb225d96c3ce74f6d33f810973d7c5b95238c2b77117142c89de45fb8f1e914e95a55693a929abbfda089e0d495a0a468a99b5f2237a40d18c9f535b433e9bc981e0e738003f71b259ab53183471c2837209b5880204f5e9ada332903b43e90a7b876e0d0630a2198e2bc2d6d23407b88abb38129cc360e7ac840c038c3c02ae8262e579d2f4ae9160754463db595b02b84a01d2d94b64d62cd9a291df477a2efbfc39084f860ca20ca89326509371ddd60f4b201f6b88e5462b99359973ea2af78e43954a76f07f23997eb8828f2a6dcdf772db532aae0b0a0bfa08a95128774a4da31930ff6107c4fe1993f055bb35437577ccd48a8540cef2797b450b21cbd77ea6cacf0d5d4dd382f1c5c8d85af1879880e0f03a931645e57c20c19126fbe0998942228d19bb39fd7499295f1d2f2b3a0532b8e5f06a0444975f5d19f95cbe7cb755b86de197190a02c438cd68a28f6556545bea721444c538f26eaed9fad1c73a3a25c8a12b8987b1786204078256c7421e0f781f976f4e1b36132089f7d029e8608e6c69574793a23be80217aa24676cfe3c996073c33651d41ea1d780ee652584aed36f1e15e101a51fd7e760c84ef62e9f13e280ec13296581d5115f0c4cf8a15b19ab6c16dd8babf9e5bd6dea5e16826cad16ea99152ba5362765151493715af7f44ccbefcb6f0ec53e48265b4c8782e558e385b139d5c15878714d0ea263e0dc38fbf1612d73ba0eae33dd35b4768935023cee842ec1a396d3fc5f74ee7fdb650cfff737aeaa7c2a47016d914d28a42821c31c8bf391b25b4dc12ea4d8815253bf6cb1a181f547f9d2bbd132e15e54dc4310164c92e5315b2381ace534dbc8f04171ad50f3230fbcd08e7671d5f13947a8c1ed2135349f9604ec8157fb57b21fcc7115b35ea4f2e0c6a8e4644d135eecb05b085c69b14b3a731200d0640fd46af0936c352a37138a4bde0f79bc6a8b58dd9d3bc33c6bcf72d979fe95755e07ca54d0569558e8d57c14bfd75800a74e6180a2ca45e307995c684d6683b426839eff45815ed31608a43f4a2e95f2619eb6162b7fb9637e754b9d51df729ef51d00dce46e81042bea8a113ec4bb0ed203812890969108a278a0e143bfc0feb0b73868bdd35d925b16d5d856383e8913b2a11d44e073a563ed7d53e28f2de15abb63af799764125bc933f83e115a4a3253faaca3$e3d8de0fe5bd91e2ca7fcd3bfe009a3f4cc0aa27$3";

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

static const char *SIGNATURE_OPENBSD_SOFTRAID = "$openbsd-softraid$";

// The lengths of sys/dev/softraidvar.h: the salt of scm_kdfhint, and the 32 sector keys of
// sch_meta that the mask key encrypts. sr_crypto_genkdf_type 3 is SR_CRYPTOKDFT_BCRYPT_PBKDF.

#define SR_CRYPTO_SALTLEN      128
#define SR_CRYPTO_KEYSLEN     2048
#define SR_CRYPTO_CHKLEN        20

#define SR_CRYPTOKDFT_BCRYPT     3

typedef struct openbsd_softraid
{
  u32 masked_keys[SR_CRYPTO_KEYSLEN / 4];

} openbsd_softraid_t;

// must stay identical to the copy in OpenCL/m38810-pure.cl

typedef struct openbsd_softraid_bcrypt_tmp
{
  u32 pass_hash[16];
  u32 sha2salt[16];
  u32 out[8];

} openbsd_softraid_bcrypt_tmp_t;

const char *module_usage_notice (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return "You can use https://github.com/hashcat/hashcat/blob/master/tools/openbsd_softraid2hashcat.py to extract the hashes";
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (openbsd_softraid_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (openbsd_softraid_bcrypt_tmp_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  openbsd_softraid_t *openbsd_softraid = (openbsd_softraid_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /**
   * $openbsd-softraid$<rounds>$<salt>$<masked keys>$<hmac>$<kdf>
   *
   * The fields openbsd_softraid2john.py of John the Ripper writes. A line without the kdf
   * field predates bcrypt_pbkdf and belongs to 38800.
   */

  token.token_cnt = 6;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_OPENBSD_SOFTRAID;

  token.len[0]     = (int) strlen (SIGNATURE_OPENBSD_SOFTRAID);
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 1;
  token.len_max[1] = 10;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len[2]     = SR_CRYPTO_SALTLEN * 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '$';
  token.len[3]     = SR_CRYPTO_KEYSLEN * 2;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len[4]     = SR_CRYPTO_CHKLEN * 2;
  token.attr[4]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[5]     = '$';
  token.len[5]     = 1;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return rc_tokenizer;

  // a PBKDF2 line belongs to 38800, so it must not match here

  if (hc_strtoul ((const char *) token.buf[5], NULL, 10) != SR_CRYPTOKDFT_BCRYPT) return PARSER_SIGNATURE_UNMATCHED;

  // scm_kdfhint carries the count as a u_int32_t. hc_strtoul () casts to u32, so a ten digit count
  // past UINT32_MAX is read as 64 bit to keep it from wrapping into one the bound accepts.

  const u64 rounds = hc_strtoull ((const char *) token.buf[1], NULL, 10);

  if (rounds == 0)         return PARSER_SALT_ITERATION;
  if (rounds > UINT32_MAX) return PARSER_SALT_ITERATION;

  // the init kernel only hashes the password and the salt, so the loop kernel runs every round

  salt->salt_iter = (u32) rounds;

  const u8 *salt_pos = token.buf[2];

  for (u32 i = 0, j = 0; i < SR_CRYPTO_SALTLEN / 4; i += 1, j += 8)
  {
    salt->salt_buf[i] = hex_to_u32 (&salt_pos[j]);
  }

  salt->salt_len = SR_CRYPTO_SALTLEN;

  const u8 *keys_pos = token.buf[3];

  for (u32 i = 0, j = 0; i < SR_CRYPTO_KEYSLEN / 4; i += 1, j += 8)
  {
    openbsd_softraid->masked_keys[i] = hex_to_u32 (&keys_pos[j]);
  }

  // the HMAC-SHA1 the kernel computes, in the word order SHA-1 leaves it in

  const u8 *chk_pos = token.buf[4];

  digest[0] = byte_swap_32 (hex_to_u32 (&chk_pos[ 0]));
  digest[1] = byte_swap_32 (hex_to_u32 (&chk_pos[ 8]));
  digest[2] = byte_swap_32 (hex_to_u32 (&chk_pos[16]));
  digest[3] = byte_swap_32 (hex_to_u32 (&chk_pos[24]));
  digest[4] = byte_swap_32 (hex_to_u32 (&chk_pos[32]));

  return PARSER_OK;
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const openbsd_softraid_t *openbsd_softraid = (const openbsd_softraid_t *) esalt_buf;

  char *salt_hex = (char *) hcmalloc ((SR_CRYPTO_SALTLEN * 2) + 1);

  for (u32 i = 0; i < SR_CRYPTO_SALTLEN / 4; i++)
  {
    u32_to_hex (salt->salt_buf[i], (u8 *) &salt_hex[i * 8]);
  }

  char *keys_hex = (char *) hcmalloc ((SR_CRYPTO_KEYSLEN * 2) + 1);

  for (u32 i = 0; i < SR_CRYPTO_KEYSLEN / 4; i++)
  {
    u32_to_hex (openbsd_softraid->masked_keys[i], (u8 *) &keys_hex[i * 8]);
  }

  char chk_hex[(SR_CRYPTO_CHKLEN * 2) + 1] = { 0 };

  for (u32 i = 0; i < SR_CRYPTO_CHKLEN / 4; i++)
  {
    u32_to_hex (byte_swap_32 (digest[i]), (u8 *) &chk_hex[i * 8]);
  }

  const int line_len = snprintf (line_buf, line_size, "%s%u$%s$%s$%s$%u",
    SIGNATURE_OPENBSD_SOFTRAID,
    salt->salt_iter,
    salt_hex,
    keys_hex,
    chk_hex,
    SR_CRYPTOKDFT_BCRYPT);

  hcfree (salt_hex);
  hcfree (keys_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_ctx->module_context_size             = MODULE_CONTEXT_SIZE_CURRENT;
  module_ctx->module_interface_version        = MODULE_INTERFACE_VERSION_CURRENT;

  module_ctx->module_advice_notice            = MODULE_DEFAULT;
  module_ctx->module_attack_exec              = module_attack_exec;
  module_ctx->module_benchmark_esalt          = MODULE_DEFAULT;
  module_ctx->module_benchmark_hook_salt      = MODULE_DEFAULT;
  module_ctx->module_benchmark_mask           = MODULE_DEFAULT;
  module_ctx->module_benchmark_charset        = MODULE_DEFAULT;
  module_ctx->module_benchmark_salt           = MODULE_DEFAULT;
  module_ctx->module_benchmark_cost           = MODULE_DEFAULT;
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
  module_ctx->module_hash_hints               = MODULE_DEFAULT;
  module_ctx->module_hash_init_selftest       = MODULE_DEFAULT;
  module_ctx->module_hash_mode                = MODULE_DEFAULT;
  module_ctx->module_hash_category            = module_hash_category;
  module_ctx->module_hash_name                = module_hash_name;
  module_ctx->module_hash_recipe              = MODULE_DEFAULT;
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
  module_ctx->module_jit_build_options        = blowfish_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = blowfish_module_jit_cache_disable;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_max       = MODULE_DEFAULT;
  module_ctx->module_kernel_threads_min       = MODULE_DEFAULT;
  module_ctx->module_kern_bits                = MODULE_DEFAULT;
  module_ctx->module_kern_type                = module_kern_type;
  module_ctx->module_kern_type_dynamic        = MODULE_DEFAULT;
  module_ctx->module_length_sort              = MODULE_DEFAULT;
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
  module_ctx->module_register_options         = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = MODULE_DEFAULT;
  module_ctx->module_usage_notice             = module_usage_notice;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
