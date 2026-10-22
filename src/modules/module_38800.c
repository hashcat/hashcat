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

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_5;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "OpenBSD softraid FDE (PBKDF2-HMAC-SHA1)";
static const u64   KERN_TYPE      = 38800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$openbsd-softraid$8192$9106b090975d34311921d71bc2c87e6dcc430a32671a71cacb7f2f8ec08d650c35f2fe2460d41f1be32e6883463c23590637e9cc6a2f3399756158d023e21d597bfeb05ee9ee065f1d09ad4691b6f48ee2d0bbb903274cfcb86e02836bc03d33d1ec76972882dfb5fea15c7cc3fa5ee2856d3abdf49f6bac3331d9322d03a4b6$1dd92a43ff64f2ee013df59ae96eeab8bc793eccc0764bd5ffc141cea0f66054ab61c99804b6a047a7794605e971d9fb426bab2b36f6a23435857930b392365ed505fbaf1af1e706cdf2c0f0e0e7bdfb0046db938d97ea037c225740bb00f0bee608202d0dcc218d23f8a5d703c2ef6ca0a26558dc5906a151cddf8f2513722030cd91dbb6c0af7ea8d30c0789f8ff30e4ec216b1f43bad24409199b5c937d77f2885e72a6062b066c2f91889f72771ad9387c8b36c3d4cb2ed79a2c9b4bb5a9c36a32403d38aaa9cbcfd4df504606427ec6d6f20b910840f52725c39f9a0376f8a1f8e5f032444e9aaf421547f2daffa2dbacebe157ecc481af13eba04f983413d925434379754d10a152caf996c274cae5cdc528f71ee6af6abb5eb5319b9bd60ad3c5b387fa9c2ce00bca76c94f50c5f28724fdcbb2a39c76c116a4ecfc75902f11392c87387f6ecd3dfd7991525c933eb62eebc1ac32d47173bdf2b73083644343a2034fe9af5505470d0f74e70d190ffe60cb6ce4e0e3440ab59dece37eb1292ee1f25e8109a6253163fc45aff0184aae3b70ef50ba6c16fbfe449e8d47e7389e4c6aab5f5e27cfc468f460d90f75da36301d664b531202e9c07d9c2fd5785f88290c9c878b31c4f51918f2d9cfcaefd0a50d4b2619b2b45923dd612b4d9c89d8390badfcaf4f9adc29b830652a1e01aaa352d19034a8f49888209149739b06ef3e659a989e091957179e4eba7ea13eb486821f9d256851f033d7803a64088b346452ff986ebfbdcb68191a103b59b911a15e826557e69ba934c27ba8e005d5c17e58fecaa152f9cd8e22d28c5e84a3a7237a682b71a23dad3b0e38a270e5681a18843e3ba692c79ee55ec27c3bbc6fb384d472defd83055348ba5e39b37e880520fe942aaace7926dc0db3b3b8654b8d72aceaf757f54aec2b606dc4d2854480f9fbc73bdaee2fbb3fd55dc5a2327b45930f233e65619d5425f0e8c4dec34d927d26a137bc36c8a5bb30e3ac145808593f9058a09df5759614c1a165b00de169abdd02083bb580345683d2e5d3b51067e3ca3db0c90edfec9b2c288ea5bb8e82a6e9709c0212e476111353cd335da6f59c97bfc77d097712a7f16a43a72d089f24f006406afbd71beec6238011b27a4e45383568f300f7a19eb80dad51b519c5a3bcc8b8ded80c32124ae81799592c911ea5cb7cf4a4b180d3dc5ef3b5a5e4be5d89a2612310a9271b40ca7f1328de407de57e9f1a0b785af9304ac3e1a70fcceabe9253ce08a8080f99ab8c3e3efa6432d9f5b8d9193318159487ea87a770ac7886c2665a964745f53194b66901d1607bf227a466c60ac98344f264c4f8cc36ad299cdc1c1dcc0e4b86be034324c00ab9df9fa6ec7c557a294bd2b5971229866cd92a465335251526a70a7699f89a262e9f33d61635b41a85d735fb0e88f2c632eece92c8349be1ffdca59bd912e5a7eebe63588b6fabfcdc0685a8eb95789f41f8fdb6fe22d41b6ba3551d3f05332f3ea2718b442bb09d89566afd084a796cb08fb667f853173ac52729d3d9b0db909f692bfa92bf2a33227c1d5d4754efbab0c949fae0c55f2b4c51d69bf6e058f5c7e76dffbbbebd13c483bdce3b2aa61bd84bed485ccf85563a4bb7043da2c922c4830b2292511c585f59b0ea47aa3b783cadd229091d899c4ca275f95247e3edd16a94fa3e649bcdbd5a1a6e1ae8bee3c65a1ffb1c52a58aca9c0461c7444d0958b5fd3c3c6583816570e416d0bb714177b408c37d750903c2abef6ee84e649fe07b7298feb67385b79ac649c1e7dbf2bfe3bf789ee48e950329ef358167372a1acc88c4cf29b8277826a981030fd0e7516a78bdf4beb14de061fda0a2286a4e9a3884dc5be96f106ed2265761f936a1bb2a5c9e69130263c80618eff0cab349559b8ffe032fb6bc04cb6735b7f8d4710b38fd30b2c64e7f41609d3279a017d4950acdbda42df75198ebf060c78b8f3964f7595bc13b2d4bbf82c48988e29e4e89c5c4466039e1c9262a7757741fb01be9974a8077a458ff0a908f7987f7e86bc1193d8f4e059d1371973bc4ad36909aa0152eda5cc686e8c5ce1a85a371edfdeb3c7482849c7c8af07e94c0f6801087dd5e801a8436d08cfead47f935526a3851346f75b916d1b997383a2ab73fb4cbac8d4ad5ace108f2d3223c768e94212c5a05965dd78d30070f2e045d0e96b2f1e769f35e45c3209154ea2054eb7e0367b94e8669d348dc630e65d0946246eb96bc0eb4345a286dfca8d101965dac354a925cc3ae67140b17fcf9b8259e13fa573b7734517a778d1a86dea262fd6099829a16a73142d9889ee0a0ca13d4efea79b730e59cae2b29fdf8751df9eaa98aecf160a5a2adb1f52cc0cf99699b1b3fb031f0c1a2cce50108112c927fb45a08bbbd470f1c1d7ffc82ace4fa8b897da23a02c607aed185a3fcf83d510fb164b2b9c4fae20050e45d564e637bc5d592d0013ac33925ae43a010c510e43fc3c3bde231c69d36ef070d6de568f45f8830ede285d5a68d95fafd206e7b4d3956c1c8fca04c1794fe13dc489fb61d7b2c3eac6859e12f3120f3f07e99d94ac81630637f06e0cab4a38f2245851f45be18fc7b671139055c41e1ee266fdc4faa807ca0d6fbc109fe1646c2bb2f3dc77df3c883ce47735a39e3626c68060d44fe1ec13c89120f499faf74e3afffbcc4508d91e50119d8c4164a20451cee1b6e9a8db8c841a10326d2557a5152ccb7a4f84fd74df6101f552665a372b963936aefff336507c4052bacab3ca6fe88cffa9a0b14c283a4cb5207c59d054a11ce08f3602a339ae749141036ccaf7fb4974a8c7a93715f55398487bc516611210001ddeb5fed8596125f0fb2ae20ed6d4f1fb6e8$919e5722d6e670321cebf0a581b9d65eeec6feb4$1";

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
// sch_meta that the mask key encrypts. sr_crypto_genkdf_type 1 is SR_CRYPTOKDFT_PKCS5_PBKDF2.

#define SR_CRYPTO_SALTLEN      128
#define SR_CRYPTO_KEYSLEN     2048
#define SR_CRYPTO_CHKLEN        20

#define SR_CRYPTOKDFT_PBKDF2     1

typedef struct openbsd_softraid
{
  u32 masked_keys[SR_CRYPTO_KEYSLEN / 4];

} openbsd_softraid_t;

// must stay identical to pbkdf2_sha1_state_t in OpenCL/inc_pbkdf2.h

typedef struct pbkdf2_sha1_state
{
  u32 ipad[5];
  u32 opad[5];

  u32 dgst[4 * 5];
  u32 out[4 * 5];

} pbkdf2_sha1_state_t;

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
  const u64 tmp_size = (const u64) sizeof (pbkdf2_sha1_state_t);

  return tmp_size;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  openbsd_softraid_t *openbsd_softraid = (openbsd_softraid_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /**
   * $openbsd-softraid$<iterations>$<salt>$<masked keys>$<hmac>[$<kdf>]
   *
   * The fields openbsd_softraid2john.py of John the Ripper writes. The kdf field came with
   * bcrypt_pbkdf in OpenBSD 6.1, so a line without it is a PBKDF2 one.
   */

  const int sep_cnt = count_char ((const u8 *) line_buf, line_len, '$');

  token.token_cnt = (sep_cnt == 6) ? 6 : 5;

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

  // a bcrypt_pbkdf line belongs to 38810, so it must not match here

  if (token.token_cnt == 6)
  {
    if (hc_strtoul ((const char *) token.buf[5], NULL, 10) != SR_CRYPTOKDFT_PBKDF2) return PARSER_SIGNATURE_UNMATCHED;
  }

  // scm_kdfhint carries the count as a u_int32_t. hc_strtoul () casts to u32, so a ten digit count
  // past UINT32_MAX is read as 64 bit to keep it from wrapping into one the bound accepts.

  const u64 iterations = hc_strtoull ((const char *) token.buf[1], NULL, 10);

  if (iterations == 0)         return PARSER_SALT_ITERATION;
  if (iterations > UINT32_MAX) return PARSER_SALT_ITERATION;

  // the first PBKDF2 iteration is the init kernel's

  salt->salt_iter = (u32) (iterations - 1);

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
    salt->salt_iter + 1,
    salt_hex,
    keys_hex,
    chk_hex,
    SR_CRYPTOKDFT_PBKDF2);

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
  module_ctx->module_jit_build_options        = MODULE_DEFAULT;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
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
