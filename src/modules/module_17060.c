/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * GPG symmetric-mode hash: SHA1-S2K + AES-256-CFB128 + SHA1-MDC
 *
 * Hash format (pk_algorithm == 0, symmetric mode):
 *   $gpg$*0*<datalen>*<data_hex>*3*18*2*9*<count>*<salt_hex>
 *
 *   - pk_algorithm = 0  : symmetric (no public key)
 *   - datalen           : byte length of the ciphertext
 *   - data_hex          : ciphertext as hex (2*datalen chars)
 *   - spec = 3          : SPEC_ITERATED_SALTED
 *   - usage = 18        : Sym.Enc.Integrity-Protected (MDC, RFC 4880 §5.13)
 *   - hash_algo = 2     : SHA1
 *   - cipher_algo = 9   : AES-256
 *   - count             : total S2K pattern bytes fed into SHA1
 *   - salt_hex          : 8-byte S2K salt (16 hex chars)
 *
 * Key derivation (RFC 4880 §3.7.1.3, Iterated and Salted S2K):
 *   pass-0 key[0..19]  = SHA1( (salt || password) repeated to `count` bytes )
 *   pass-1 key[20..31] = SHA1( 0x00 || (salt || password) repeated )
 *   AES-256 key = key[0..31]
 *
 * Decryption: AES-256-CFB128, IV = 16 zero bytes
 *
 * Verification (MDC, usage == 18):
 *   decrypt all <datalen> bytes -> out[0..datalen-1]
 *   SHA1(out[0..datalen-21]) must equal out[datalen-20..datalen-1]
 *
 * Self-test vector (from JtR / gpg_common_plug.c):
 *   $gpg$*0*63*1c890c019b24ce46afd906500094ad1afde4d56b9666dee9568cf2d47315b
 *   36e501b340813a62b8b82b72492b00a4595941ebd96de8eab636a00210bc57a13
 *   *3*18*2*9*65536*20538c8d69964d96  ->  "password"
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
static const char *HASH_NAME      = "GPG (AES-256 (SHA-1($pass)), Symmetric, MDC)";
static const u64   KERN_TYPE      = 17060;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_LOOP_PREPARE
                                  | OPTS_TYPE_AUX1
                                  | OPTS_TYPE_DEEP_COMP_KERNEL;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "password";
static const char *ST_HASH        = "$gpg$*0*63*1c890c019b24ce46afd906500094ad1afde4d56b9666dee9568cf2d47315b36e501b340813a62b8b82b72492b00a4595941ebd96de8eab636a00210bc57a13*3*18*2*9*65536*20538c8d69964d96";

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

/**
 * Struct layout must match the OpenCL kernel exactly.
 * We reuse the same layout as mode 17010 for AES-256.
 * iv[] is always zero for symmetric mode (no stored IV).
 * modulus_size is unused (set to 0).
 */
typedef struct gpg
{
  u32 cipher_algo;
  u32 iv[4];
  u32 modulus_size;
  u32 encrypted_data[384];
  u32 encrypted_data_size;

} gpg_t;

typedef struct gpg_tmp
{
  /* Pre-built repeating (salt || password) block, big-endian for SHA1 */
  u32 salted_pw_block[80];
  u32 salted_pw_block_len;

  /* SHA1 state for two passes (h[0..4] = pass-0, h[5..9] = pass-1) */
  u32 h[10];

  /* Current SHA1 block accumulator */
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

/**
 * Only AES-256 is supported for this mode — always route to aux1.
 */
u32 module_deep_comp_kernel (MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED const u32 digest_pos)
{
  return KERN_RUN_AUX1;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32   *digest = (u32   *) digest_buf;
  gpg_t *gpg    = (gpg_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  /*
   * Token layout (10 tokens, '*'-separated):
   *
   *  [0] $gpg$          -- signature
   *  [1] 0              -- pk_algorithm = 0 (symmetric mode)
   *  [2] <datalen>      -- ciphertext length in bytes
   *  [3] <data_hex>     -- ciphertext as hex (2*datalen chars)
   *  [4] 3              -- S2K specifier = SPEC_ITERATED_SALTED
   *  [5] 18             -- usage = Sym.Enc.Integrity-Protected (MDC)
   *  [6] 2              -- hash algorithm = SHA1
   *  [7] 9              -- cipher algorithm = AES-256
   *  [8] <count>        -- S2K iteration count (total pattern bytes)
   *  [9] <salt_hex>     -- S2K salt, 8 bytes (16 hex chars)
   */

  token.token_cnt  = 10;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_GPG;

  /* [0] $gpg$ */
  token.sep[0]   = '*';
  token.len[0]   = 5;
  token.attr[0]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_SIGNATURE;

  /* [1] pk_algo = "0" */
  token.sep[1]   = '*';
  token.len[1]   = 1;
  token.attr[1]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_DIGIT;

  /* [2] datalen */
  token.sep[2]      = '*';
  token.len_min[2]  = 1;
  token.len_max[2]  = 4;
  token.attr[2]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  /* [3] ciphertext hex (40..3072 hex chars = 20..1536 bytes) */
  token.sep[3]      = '*';
  token.len_min[3]  = 40;
  token.len_max[3]  = 3072;
  token.attr[3]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_HEX;

  /* [4] spec = "3" */
  token.sep[4]   = '*';
  token.len[4]   = 1;
  token.attr[4]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_DIGIT;

  /* [5] usage = "18" (2 digits) */
  token.sep[5]   = '*';
  token.len[5]   = 2;
  token.attr[5]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_DIGIT;

  /* [6] hash_algo = "2" */
  token.sep[6]   = '*';
  token.len[6]   = 1;
  token.attr[6]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_DIGIT;

  /* [7] cipher_algo = "9" */
  token.sep[7]   = '*';
  token.len[7]   = 1;
  token.attr[7]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_DIGIT;

  /* [8] S2K iteration count */
  token.sep[8]      = '*';
  token.len_min[8]  = 1;
  token.len_max[8]  = 8;
  token.attr[8]     = TOKEN_ATTR_VERIFY_LENGTH
                    | TOKEN_ATTR_VERIFY_DIGIT;

  /* [9] salt hex (8 bytes = 16 hex chars) */
  token.len[9]   = 16;
  token.attr[9]  = TOKEN_ATTR_FIXED_LENGTH
                 | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  /* Validate pk_algorithm == 0 (symmetric mode) */

  if (hc_strtoul ((const char *) token.buf[1], NULL, 10) != 0) return (PARSER_HASH_VALUE);

  /* Ciphertext */

  const u32 enc_data_size = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  const int encrypted_data_size = hex_decode (token.buf[3], token.len[3], (u8 *) gpg->encrypted_data);

  if ((u32) encrypted_data_size != enc_data_size) return (PARSER_CT_LENGTH);

  if (encrypted_data_size > (int) sizeof (gpg->encrypted_data)) return (PARSER_CT_LENGTH);

  gpg->encrypted_data_size = encrypted_data_size;

  /* Validate S2K specifier == 3 (iterated and salted) */

  if (hc_strtoul ((const char *) token.buf[4], NULL, 10) !=  3) return (PARSER_HASH_VALUE);

  /* Validate usage == 18 (Sym.Enc.Integrity-Protected with MDC) */

  if (hc_strtoul ((const char *) token.buf[5], NULL, 10) != 18) return (PARSER_HASH_VALUE);

  /* Validate hash algorithm == 2 (SHA1) */

  if (hc_strtoul ((const char *) token.buf[6], NULL, 10) !=  2) return (PARSER_HASH_VALUE);

  /* Validate cipher algorithm == 9 (AES-256) */

  const u32 cipher_algo = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  if (cipher_algo != 9) return (PARSER_CIPHER);

  gpg->cipher_algo = cipher_algo;

  /* IV is always zero for symmetric mode (no stored IV in hash) */

  gpg->iv[0] = 0;
  gpg->iv[1] = 0;
  gpg->iv[2] = 0;
  gpg->iv[3] = 0;

  /* modulus_size is unused in symmetric mode */

  gpg->modulus_size = 0;

  /* S2K iteration count */

  const u32 salt_iter = hc_strtoul ((const char *) token.buf[8], NULL, 10);

  if (salt_iter < 8 || salt_iter > 65011712) return (PARSER_SALT_ITERATION);

  salt->salt_iter = salt_iter;

  /*
   * salt_repeats = 1 means the S2K loop runs twice:
   *   pass 0 (SALT_REPEAT=0): no prefix bytes  -> key[0..19]
   *   pass 1 (SALT_REPEAT=1): one 0x00 prefix  -> key[20..31]
   * Both passes together yield the 32-byte AES-256 key.
   */
  salt->salt_repeats = 1;

  /* S2K salt (8 bytes) */

  salt->salt_len = hex_decode (token.buf[9], token.len[9], (u8 *) salt->salt_buf);

  if (salt->salt_len != 8) return (PARSER_SALT_LENGTH);

  /*
   * Fake digest: use the first 16 bytes of the ciphertext.
   * There is no stored IV for symmetric mode, so ciphertext bytes
   * serve as a unique per-hash discriminator.
   */
  digest[0] = gpg->encrypted_data[0];
  digest[1] = gpg->encrypted_data[1];
  digest[2] = gpg->encrypted_data[2];
  digest[3] = gpg->encrypted_data[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const gpg_t *gpg = (const gpg_t *) esalt_buf;

  u8 encrypted_data_hex[(384 * 8) + 1];

  memset (encrypted_data_hex, 0, sizeof (encrypted_data_hex));

  hex_encode ((const u8 *) gpg->encrypted_data, gpg->encrypted_data_size, encrypted_data_hex);

  const int line_len = snprintf (line_buf, line_size, "%s*0*%u*%s*3*18*2*9*%u*%08x%08x",
    SIGNATURE_GPG,
    gpg->encrypted_data_size,
    encrypted_data_hex,
    salt->salt_iter,
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
  module_ctx->module_bridge_name              = MODULE_DEFAULT;
  module_ctx->module_bridge_type              = MODULE_DEFAULT;
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
