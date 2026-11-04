/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "Android FDE >= 4.4 (scrypt)";
static const u64   KERN_TYPE      = 44000;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$androidfde$2$32768$8$2$13371337133713371337133713371337$5dd21c96b437d15ee0872e036b10e9f2$feb569167b96053827662d19c67a1148c7f2ff9315cc0b5f9bf3ccb44571df0d749937d324f587e78d2c1df93b5c5ac1a46bea30d0cd5841caf5f00fa203ce1b407ed0bce9c65d7b6546e697efdf8b5c95bc8fc845b3221dd76a6e1e9be09c633b714fae535d3349f56ed56db9a6ceb92fef6714b8addecfd6964b18a396ee53a757fc5c73a42efafd76bd3d093986f27053d363e7534fd0327908a9031b12c07f5cd2c2b2f0ead2a639e992d31bdda60e018c9d16d5cb3ee058dcf9500bd007e3145785405c8bacbfa93c5c89b324e0176a94e312d864806af435c4c34d74fcfddc68af960caeaa6f51e1f6ffd577602066c53c3f8e5195b4c12b32108da6fdd0498ba6c50a66887664dc6394aa572067964eb84a7e93053b8f6dff41a2b3ff84a68da645ba70890d7b570b51f2cfef51d2b94088d672de0193d2232838623f3da8022128f9ef67e28926c1921731a81daa6832b54fee6683dd3b9ac145e1a1e27cc925062861664e38b51f30bcc61a41f7f44837f83fbeb5736c4cdf570592e6d76655cf350a41d09cc6e7b729d240f93a9ed1ba78566c017427058b631ff8f4f4b7bc1d81853ae04ea5a3013f8eeacb5bfea49310aa5f8c15630c7907b3109b9830c0f0f9e70c3e5234356a293df0d6ea48038e460d0e9235cdded3384fde87d0d0ace000dcebd151b016eab80935bfc043b5e059e688462b6fb34d737b8f19700ad4f0728992a95e0b29e02574b0847d202a87d2053404b5b65700ce94294aa5be64a6c27953cd0360d841516904daea8a0a96f0d330c04adad1a0c650f84d335ee004dce1e90f63b3147e678958d098a1a5fa4a40e505986bfe5761ffe21a36ea63a4026d7794194f585c37be3e0a6e3fe2d800a450c7166fc5d83d5543e573c673844121d92e26d8766b0c7ccf87dd64031dd9eff9829276142e3f91f0b617ef1a3ffcb9310326d7f78196ecacedeeebde0ed459cf296297001be38956cfe5cbedc5ee4a6ad32a01ce0c2f61fd58f1e39456aae45839556148ca516c3b0a0b56e8beab7088d7deb134f49814547f1f173d5c79f684a4c2ecf2cf05f01ab93df79f0bff5f64ce33bb5ca71b58da30a8a7d8dcea51eae887b6da630473bab5a7a92d464c9343efe5687f1c6a472f50a45d6e292b8c7906eaf70939cdab77701ee3178e8f61efeaf58da092de535ddd844b3f02c458a77cca1f3a6c64d636b4ae82695d1a457bf70f74281f3887056c3138f3bbf52c732d7d33959f47bb55d22b0ba6b2ea72b2e614f20903b2655f1c4b57091064da7594d3f4d70c9c98c7a5b36afb284186e7eecf60be532ef6ec728b413a6732c89cc520591747c023ca9e1a06dcbf1ba4c5a03293086fc4aed6ac9056c56bf6e94e2d54e11299d9ba33767cdc540eed589f62f9d6712d7687be4f43119362ff939bbea6c30e9653048fc0f27d91370858cddea4507f2935705520fce952335fcc902d3e803f9498488d33d2b10d12032b912b4a769a121e47a1e24d65bef566e9f213dc15cbb8615f6db7499298b4f2506a644f9354ef6db0c7247144b2efbd059db953365ec01d679fcfc4b11601400952770b449e79af50ae7672f06ac0b7a849b69ae99b238739e88fe0450f3aff0edc19751492af4dac1fa77566c4a32b26f24837a22e067d146dd2bb2950d870fb3c934a50b898f7bdab6c5131b8bd1907b8617fa92f0c8ea06b0818e3abdd91f43da37bea038208f68cc2a6a276db491b007f236c5b5f905ac7fc13610ed2c4a60182921cdd634262424f5d52d732babbcb93b7f4c8b34fb7eeef73270dd6e53475e0c3bc18acec920622c7813abe23d6af1bfbee44229138b4da8102a252673aa903a7034f32ca8069ff0cea4793b5c67c0a3453e56f04717600d579737836ce7bac32f5528414bf85c57dae5e9f0669c7dc32d169a4aec11a5ba9688bbfa59b1cf30dbe9c699b1a0939217547174629a0947b61e685eaeeed2cb2647d2a90c647b75b300f40ab41e0586a9163c61ce56fadad90293be016d43c4d4b37308afa301087b6142ff320f9ca509c78029906310d3f964a5b2d103a0eee815c114e3ca2ddd304af55dd592e9a43c6b898736c6f3ee0d3f51da52ae75ae115f8284148ef27c98638c91bc521704cd819bcd96f1625157e5116e71a45";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_ANDROIDFDE_SCRYPT = "$androidfde$";

static const u32 SCRYPT_THREADS = 32;

// The cryptfs.h kdf_type values this mode decides between. Only KDF_SCRYPT belongs to it:
// KDF_PBKDF2 is mode 8800 and KDF_SCRYPT_KEYMASTER needs the RSA signature step, so both are
// refused here by name rather than cracked with the wrong chain. Android 5.0 wrote 3 and 4 for two
// earlier variants of that signature step, which Android 6 dropped, and the parser refuses those
// along with 5.

#define KDF_PBKDF2           1
#define KDF_SCRYPT           2
#define KDF_SCRYPT_KEYMASTER 5

// SALT_LEN and KEY_LEN_BYTES from cryptfs.h, and the 3 sectors of the filesystem the kernel reads.

#define ANDROIDFDE_SALT_LEN 16
#define ANDROIDFDE_KEY_LEN  16
#define ANDROIDFDE_DATA_LEN 1536

#include "scrypt_common.c"

typedef struct androidfde
{
  u32 data[384];

} androidfde_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (androidfde_t);

  return esalt_size;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  androidfde_t *androidfde = (androidfde_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 8;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ANDROIDFDE_SCRYPT;

  token.len[0]     = 12;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '$';
  token.len_min[2] = 1;
  token.len_max[2] = 7;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len_min[3] = 1;
  token.len_max[3] = 6;
  token.attr[3]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 6;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len[5]     = ANDROIDFDE_SALT_LEN * 2;
  token.attr[5]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len[6]     = ANDROIDFDE_KEY_LEN * 2;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len[7]     = ANDROIDFDE_DATA_LEN * 2;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // kdf type

  const u8 *kdf_pos = token.buf[1];

  const u32 kdf_type = hc_strtoul ((const char *) kdf_pos, NULL, 10);

  if (kdf_type != KDF_SCRYPT) return (PARSER_SIGNATURE_UNMATCHED);

  // scrypt settings. The footer holds these as base 2 logarithms and the hash line holds the
  // values, so an extractor shifts them and this reads them as they are.

  const u8 *N_pos = token.buf[2];
  const u8 *r_pos = token.buf[3];
  const u8 *p_pos = token.buf[4];

  salt->scrypt_N = hc_strtoul ((const char *) N_pos, NULL, 10);
  salt->scrypt_r = hc_strtoul ((const char *) r_pos, NULL, 10);
  salt->scrypt_p = hc_strtoul ((const char *) p_pos, NULL, 10);

  if (salt->scrypt_N < 2) return (PARSER_SALT_VALUE);
  if (salt->scrypt_r < 1) return (PARSER_SALT_VALUE);
  if (salt->scrypt_p < 1) return (PARSER_SALT_VALUE);

  // the kernel reduces its index with k & (SCRYPT_N - 1), which is the modulo it is meant to be
  // only while N is a power of two

  if ((salt->scrypt_N & (salt->scrypt_N - 1)) != 0) return (PARSER_SALT_VALUE);

  salt->salt_iter    = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // salt. PBKDF2 reads it as a byte string, so the words are not swapped.

  const u8 *salt_pos = token.buf[5];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = ANDROIDFDE_SALT_LEN;

  // encrypted master key. AES reads each 4 bytes as one big-endian word.

  const u8 *hash_pos = token.buf[6];

  digest[0] = hex_to_u32 (hash_pos +  0);
  digest[1] = hex_to_u32 (hash_pos +  8);
  digest[2] = hex_to_u32 (hash_pos + 16);
  digest[3] = hex_to_u32 (hash_pos + 24);

  digest[0] = byte_swap_32 (digest[0]);
  digest[1] = byte_swap_32 (digest[1]);
  digest[2] = byte_swap_32 (digest[2]);
  digest[3] = byte_swap_32 (digest[3]);

  // the start of the encrypted filesystem, same layout and same byte order as mode 8800

  const u8 *data_pos = token.buf[7];
  const int data_len = token.len[7];

  for (int i = 0, j = 0; i < data_len; i += 8, j += 1)
  {
    androidfde->data[j] = hex_to_u32 (data_pos + i);

    androidfde->data[j] = byte_swap_32 (androidfde->data[j]);
  }

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const androidfde_t *androidfde = (const androidfde_t *) esalt_buf;

  char tmp[(ANDROIDFDE_DATA_LEN * 2) + 1];

  for (u32 i = 0, j = 0; i < (ANDROIDFDE_DATA_LEN / 4); i += 1, j += 8)
  {
    snprintf (tmp + j, 9, "%08x", androidfde->data[i]);
  }

  tmp[ANDROIDFDE_DATA_LEN * 2] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s%d$%u$%u$%u$%08x%08x%08x%08x$%08x%08x%08x%08x$%s",
    SIGNATURE_ANDROIDFDE_SCRYPT,
    KDF_SCRYPT,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    digest[0],
    digest[1],
    digest[2],
    digest[3],
    tmp);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = scrypt_module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = scrypt_module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_jit_build_options        = scrypt_module_jit_build_options;
  module_ctx->module_kernel_accel_max         = scrypt_module_kernel_accel_max;
  module_ctx->module_kernel_loops_max         = scrypt_module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = scrypt_module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = scrypt_module_kernel_threads_max;
  module_ctx->module_kern_bits                = module_kern_bits;
  module_ctx->module_register_options         = scrypt_module_register_options;
  module_ctx->module_tmp_size                 = scrypt_module_tmp_size;
  module_ctx->module_tune_variants            = scrypt_module_tune_variants;
}
