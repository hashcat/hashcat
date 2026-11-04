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
#include "emu_inc_bignum_2048.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_FDE;
static const char *HASH_NAME      = "Android FDE >= 5.0 (scrypt, keymaster RSA)";
static const u64   KERN_TYPE      = 44100;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_NATIVE_THREADS;
static const u64   KERN_BITS      = KERN_BIT_LOOP_PREPARE
                                  | KERN_BIT_INIT2
                                  | KERN_BIT_LOOP2_PREPARE
                                  | KERN_BIT_LOOP2
                                  | KERN_BIT_INIT3
                                  | KERN_BIT_LOOP3_PREPARE
                                  | KERN_BIT_LOOP3;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$androidfde$5$32768$8$2$13371337133713371337133713371337$c671211ebeebd2e4e11fa8e4dc64ecb1b3ec2dffe70775bfb88790fb41d422bf$afbe0089c719a57972e83c1f2c48fea06e4ad9b9297f435bc715c418fe9edf2dc2a4d346aeaff6062f97ce74d77470b4ace6ba75a4ba744267d66b71983e07cc3187c92b539cb766bbf31f04d29f4f868b210289099d6e408051a3d5c7367c44eb175075ee75ff752975b8607dfea60fde890fcb3626343fcd812c4347cc66b7925afda94083d9add37dfc65b2584fd61b891303153c2bd6909162c46ffd2c5c9207d4e56278cb4127828a7342f8ed408f447e8804499b5295ed15186b35fcb19840bac2fbda66a2815145213adc786a606f8bf36c0c90b0828f9498d376241eec0f2ddf61e312f55785b88e33c98a1fa65872bcced915f23a5b4d69e9093815$0f60ce2dc03b1d887cd6570a7846d3e728778ac941d915c5166cf069aa802ef1d3663669a938130c740631e5f60385a83db7fbe976f66cdd71b628d53a17f57937fd548c62c6e4228c8047fed54a64fc5638d77eb3d56f941bd669027829eba2613afb4ab288e747728f0f48fc4577f50c094cd540a203b0f093e4d2675a3ac3a0a25ed46039f66cbf2f79e3d4cc016307c12c0b1a0e10505645e1d05f94bcd311f452f70a0e8de7b3b9003271a57dc774fc7095147a7a50eed342f0f66c4b922dbb645cc0e40158e977e4321ca3e9597bce625f33cb5ed98d41cb9afd708cfa5f07fb83a011416b6d9ce5f707d5c301d400a0121598b984bfd432e42b2fc561";

#include "hooks_common.c"

static u64         module_kern_bits      (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra) { return KERN_BITS;       }

static const char *SIGNATURE_ANDROIDFDE_KEYMASTER = "$androidfde$";

static const u32 SCRYPT_THREADS = 32;

// The cryptfs.h kdf_type values this mode decides between. KDF_SCRYPT is mode 44000 and
// KDF_PBKDF2 is mode 8800, so both are refused here by that field rather than cracked with a chain
// they do not use.
//
// Android 5.0 wrote two more hardware bound values, which Android 6 dropped.
// KDF_SCRYPT_KEYMASTER_BADLY_PADDED runs the same chain with the 32 bytes at the front of the
// signed buffer rather than one byte in, so this mode takes it as well and carries the offset
// down to the kernel.
//
// KDF_SCRYPT_KEYMASTER_UNPADDED instead hands the keymaster a 32 byte message where the other two
// hand it 256, and what a vendor implementation signs when asked for that is not in AOSP, so it is
// refused rather than guessed at.
//
// Lollipop rewrites either of those two to 5 on the first unlock that succeeds, so footers carrying
// them are the ones that never unlocked again. See the upgrade block in test_mount_encrypted_fs ().

#define KDF_PBKDF2                        1
#define KDF_SCRYPT                        2
#define KDF_SCRYPT_KEYMASTER_UNPADDED     3
#define KDF_SCRYPT_KEYMASTER_BADLY_PADDED 4
#define KDF_SCRYPT_KEYMASTER              5

// SALT_LEN and SCRYPT_LEN from cryptfs.h, and the RSA key size keymaster_create_key () asks for.

#define ANDROIDFDE_SALT_LEN 16
#define ANDROIDFDE_SIK_LEN  32
#define ANDROIDFDE_RSA_LEN  256

// The derivation runs scrypt three times, so the hash-mode uses three loop kernels and all three
// iteration counts. Each transition sits in its own init kernel: init2 holds the RSA operation and
// init3 the plain rechain. No kernel has to ask which pass it is in.

#include "scrypt_common.c"

typedef struct androidfde_km
{
  u32 n[64];
  u32 d[64];
  u32 mont_one[64];

  u32 n0;

  u32 kdf_type;
  u32 to_sign_off;

} androidfde_km_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (androidfde_km_t);

  return esalt_size;
}

// The scrypt tmps plus the two values that have to outlive the kernel that made them: the 256 byte
// signature and the 16 byte intermediate key. scrypt_module_extra_tmp_size answers with the scrypt
// half and with the two configuration sentinels, which pass through untouched.

#define ANDROIDFDE_TMP_EXTRA ((64 + 4) * 4)

static u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u64 tmp_size = scrypt_module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

  if (tmp_size & (1ULL << 62)) return tmp_size;
  if (tmp_size & (1ULL << 63)) return tmp_size;

  return tmp_size + ANDROIDFDE_TMP_EXTRA;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  androidfde_km_t *androidfde = (androidfde_km_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_ANDROIDFDE_KEYMASTER;

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
  token.len[6]     = ANDROIDFDE_SIK_LEN * 2;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[7]     = '$';
  token.len[7]     = ANDROIDFDE_RSA_LEN * 2;
  token.attr[7]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[8]     = '$';
  token.len[8]     = ANDROIDFDE_RSA_LEN * 2;
  token.attr[8]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // kdf type

  const u8 *kdf_pos = token.buf[1];

  const u32 kdf_type = hc_strtoul ((const char *) kdf_pos, NULL, 10);

  if ((kdf_type != KDF_SCRYPT_KEYMASTER) && (kdf_type != KDF_SCRYPT_KEYMASTER_BADLY_PADDED)) return (PARSER_SIGNATURE_UNMATCHED);

  androidfde->kdf_type = kdf_type;

  // keymaster_sign_object () writes the 32 bytes at to_sign + 1 for KDF_SCRYPT_KEYMASTER and at
  // to_sign + 0 for KDF_SCRYPT_KEYMASTER_BADLY_PADDED, and that offset is the whole difference
  // between them. The kernel takes it as a number, so it needs neither constant nor a branch.

  androidfde->to_sign_off = 1;

  if (kdf_type == KDF_SCRYPT_KEYMASTER_BADLY_PADDED) androidfde->to_sign_off = 0;

  // scrypt settings. The footer holds these as base 2 logarithms and the hash line holds the
  // values, so an extractor shifts them once.

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
  salt->salt_iter2   = salt->scrypt_N;
  salt->salt_iter3   = salt->scrypt_N;
  salt->salt_repeats = salt->scrypt_p - 1;

  // salt. PBKDF2 reads it as a byte string, so the words are not swapped.

  const u8 *salt_pos = token.buf[5];

  salt->salt_buf[0] = hex_to_u32 (salt_pos +  0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos +  8);
  salt->salt_buf[2] = hex_to_u32 (salt_pos + 16);
  salt->salt_buf[3] = hex_to_u32 (salt_pos + 24);

  salt->salt_len = ANDROIDFDE_SALT_LEN;

  // scrypted_intermediate_key. The kernel's final PBKDF2 writes its output in the order the bytes
  // come off it, so the digest is stored the same way and not swapped.

  const u8 *sik_pos = token.buf[6];

  for (int i = 0; i < 8; i++)
  {
    digest[i] = hex_to_u32 (sik_pos + (i * 8));
  }

  // encrypt_master_key () is the only writer of scrypted_intermediate_key, so a footer written
  // before that field existed carries 32 zero bytes there until the first password change. There is
  // nothing for this mode to check a candidate against, and no derivation reaches 32 zero bytes, so
  // the line is refused rather than run to no end. Hash-mode 44000 can still crack such a device,
  // through the encrypted master key and a block of the filesystem.

  u32 sik_or = 0;

  for (int i = 0; i < 8; i++) sik_or |= digest[i];

  if (sik_or == 0) return (PARSER_SALT_VALUE);

  // the RSA key, as big-endian bytes on the line and as montgomery limbs in the esalt

  u32 be[64];

  const u8 *n_pos = token.buf[7];

  for (int i = 0; i < 64; i++)
  {
    be[i] = hex_to_u32 (n_pos + (i * 8));
  }

  bn2048_from_be (androidfde->n, be);

  const u8 *d_pos = token.buf[8];

  for (int i = 0; i < 64; i++)
  {
    be[i] = hex_to_u32 (d_pos + (i * 8));
  }

  bn2048_from_be (androidfde->d, be);

  // n0 and mont_one come from n once per hash here, rather than per candidate in the kernel, where
  // bn2048_mont_ctx_init would double 1 mod n 2048 times for every work item. It also refuses an
  // even modulus, which no RSA modulus is.

  u32 n0 = 0;

  if (bn2048_mont_ctx_init (androidfde->n, &n0, androidfde->mont_one) == false) return (PARSER_SALT_VALUE);

  androidfde->n0 = n0;

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const androidfde_km_t *androidfde = (const androidfde_km_t *) esalt_buf;

  char sik[(ANDROIDFDE_SIK_LEN * 2) + 1];

  for (int i = 0, j = 0; i < 8; i += 1, j += 8)
  {
    snprintf (sik + j, 9, "%08x", byte_swap_32 (digest[i]));
  }

  u32 be[64];

  char n_hex[(ANDROIDFDE_RSA_LEN * 2) + 1];

  bn2048_to_be (be, androidfde->n);

  for (int i = 0, j = 0; i < 64; i += 1, j += 8)
  {
    snprintf (n_hex + j, 9, "%08x", byte_swap_32 (be[i]));
  }

  char d_hex[(ANDROIDFDE_RSA_LEN * 2) + 1];

  bn2048_to_be (be, androidfde->d);

  for (int i = 0, j = 0; i < 64; i += 1, j += 8)
  {
    snprintf (d_hex + j, 9, "%08x", byte_swap_32 (be[i]));
  }

  const int line_len = snprintf (line_buf, line_size, "%s%u$%u$%u$%u$%08x%08x%08x%08x$%s$%s$%s",
    SIGNATURE_ANDROIDFDE_KEYMASTER,
    androidfde->kdf_type,
    salt->scrypt_N,
    salt->scrypt_r,
    salt->scrypt_p,
    byte_swap_32 (salt->salt_buf[0]),
    byte_swap_32 (salt->salt_buf[1]),
    byte_swap_32 (salt->salt_buf[2]),
    byte_swap_32 (salt->salt_buf[3]),
    sik,
    n_hex,
    d_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_benchmark_cost           = scrypt_module_benchmark_cost;
  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = scrypt_module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
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
