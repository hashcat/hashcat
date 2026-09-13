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
#include "blowfish_common.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_PRIVATE_KEY;
static const char *HASH_NAME      = "OpenSSH Private Keys (bcrypt-pbkdf)";
static const u64   KERN_TYPE      = 37500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_SLOW_HASH_SIMD_LOOP;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_DYNAMIC_SHARED;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$sshng$6$16$89b7dac5965613fa4f2faf9284983843$274$6f70656e7373682d6b65792d7631000000000a6165733235362d63747200000006626372797074000000180000001089b7dac5965613fa4f2faf92849838430000001000000001000000330000000b7373682d6564323535313900000020979ccdbbb3f2c8b04842e77fdd5475b21963e7ddad9a4d029d712322f5c930ee000000909e38aa2f92ae189f7e4f04ef62fcd869ceb572e5c047ea0e9dfbb4657c38a13506d580ff8709a8787810a53688e3b0c7b7af155422aed8089da87a63da0147d8c8e04a6d236e70f0c6be5fbeb0b620d7abe928b10169fd3e48c1b526d3ead3a28fa4385969aebea6621baada8821a20035be97e2fa42575f5e4246e174ac3c96b19e89623ff267a2629090da6f79f7e4$16$130";

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


// The kernel reads only cipher/ct_offset/rounds/salt_buf/ct_buf, but the whole
// key blob is carried so module_hash_encode() can reproduce its input line --
// same arrangement as the legacy PEM modules. Keep this layout identical to the
// copy in OpenCL/m37500-pure.cl: esalt_bufs[] strides by sizeof(), so any
// divergence silently misreads every hash past the first.
typedef struct sshng_bcrypt
{
  u32 cipher;
  u32 ct_offset;
  u32 rounds;
  u32 salt_buf[4];      // 16 byte bcrypt salt
  u32 ct_buf[4];        // first encrypted block: the two check integers
  u32 data_buf[8192];   // the openssh-key-v1 blob, up to SSHNG_DATA_MAX bytes
  int data_len;

} sshng_bcrypt_t;

// Carried between kernels. A bcrypt_hash() cannot be split across invocations,
// so the whole derivation runs inside one _loop and only the finished 48 bytes
// need to survive it.
typedef struct sshng_bcrypt_tmp
{
  u32 pass_hash[16];   // SHA-512 of the password, 64 bytes
  u32 dk[12];          // derived 48 bytes: 32 byte AES key + 16 byte IV

} sshng_bcrypt_tmp_t;

static const char *SIGNATURE_SSHNG = "$sshng$";

// Cipher ids as emitted by ssh2john for the openssh-key-v1 container.
#define SSHNG_CIPHER_AES256_CBC 2
#define SSHNG_CIPHER_AES256_CTR 6

// bcrypt_pbkdf always uses a 16 byte salt (fixed in sshkey.c).
#define SSHNG_SALT_LEN 16

// key (32) + iv (16)
#define SSHNG_DERIVE_LEN 48

// sizeof (sshng_bcrypt_t.data_buf). An RSA-4096 key blob is around 3 KB, so
// this leaves generous headroom; the tokenizer rejects anything longer.
#define SSHNG_DATA_MAX 32768

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (sshng_bcrypt_t);

  return esalt_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (sshng_bcrypt_tmp_t);

  return tmp_size;
}

// One bcrypt_hash() per loop iteration. Each is 64 Blowfish key expansions, so
// the autotuner is kept on a short leash the way -m 3200 is.
u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 1;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1;

  return kernel_loops_max;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  sshng_bcrypt_t *sshng = (sshng_bcrypt_t *) esalt_buf;

  hc_token_t token;

  // Uninitialised sep[]/len_min[]/len_max[] entries are read for every token
  // index, so stack garbage in the ones we do not set makes the tokenizer
  // search for a separator that is not there.
  memset (&token, 0, sizeof (hc_token_t));

  // $sshng$<cipher>$<saltlen>$<salt>$<datalen>$<data>$<rounds>$<ctoffset>
  //
  // Eight tokens. The legacy PEM form handled by -m 22911..22951 has six, so
  // the count alone separates the two without ambiguity.

  token.token_cnt  = 8;

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
  token.len[2]     = 2;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[3]     = '$';
  token.len[3]     = SSHNG_SALT_LEN * 2;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '$';
  token.len_min[4] = 1;
  token.len_max[4] = 8;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '$';
  token.len_min[5] = 64;
  token.len_max[5] = 65536;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[6]     = '$';
  token.len_min[6] = 1;
  token.len_max[6] = 8;
  token.attr[6]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // last token runs to end of line: no trailing separator to match
  token.len_min[7] = 1;
  token.len_max[7] = 8;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // cipher

  const int cipher = hc_strtoul ((const char *) token.buf[1], NULL, 10);

  if ((cipher != SSHNG_CIPHER_AES256_CBC) && (cipher != SSHNG_CIPHER_AES256_CTR)) return (PARSER_CIPHER);

  sshng->cipher = cipher;

  // salt length is fixed by sshkey.c; reject anything else rather than
  // silently deriving from the wrong number of bytes

  const int salt_len_verify = hc_strtoul ((const char *) token.buf[2], NULL, 10);

  if (salt_len_verify != SSHNG_SALT_LEN) return (PARSER_SALT_LENGTH);

  // salt
  //
  // hex_to_u32() packs little-endian, but the kernel feeds salt_buf straight
  // into sha512_update(), which reads its input big-endian packed. Swap here so
  // the esalt holds the byte order the device wants.

  const u8 *salt_pos = token.buf[3];

  for (int i = 0, j = 0; i < SSHNG_SALT_LEN / 4; i += 1, j += 8)
  {
    sshng->salt_buf[i] = byte_swap_32 (hex_to_u32 (&salt_pos[j]));
  }

  // rounds -> salt_iter, so the autotuner sees the real cost

  const u32 rounds = hc_strtoul ((const char *) token.buf[6], NULL, 10);

  if (rounds == 0) return (PARSER_SALT_ITERATION);

  // the whole derivation runs in one _loop invocation for now
  salt->salt_iter = 1;

  sshng->rounds = rounds;

  // hashcat needs a salt_buf/salt_len for its own bookkeeping

  memcpy (salt->salt_buf, sshng->salt_buf, SSHNG_SALT_LEN);

  salt->salt_len = SSHNG_SALT_LEN;

  // ciphertext offset within the blob

  const u32 ct_offset = hc_strtoul ((const char *) token.buf[7], NULL, 10);

  // the blob, kept whole so the encoder can reproduce the input line

  if (token.len[5] > (SSHNG_DATA_MAX * 2)) return (PARSER_HASH_LENGTH);

  sshng->data_len = hex_decode (token.buf[5], token.len[5], (u8 *) sshng->data_buf);

  const int data_len = sshng->data_len;

  // the declared length has to agree with the blob actually supplied

  const int data_len_verify = hc_strtoul ((const char *) token.buf[4], NULL, 10);

  if (data_len_verify != data_len) return (PARSER_HASH_LENGTH);

  // The encrypted section must leave at least one AES block to verify against.

  if ((ct_offset + 16) > (u32) data_len) return (PARSER_SALT_VALUE);

  sshng->ct_offset = ct_offset;

  // encrypted blob: only the first block is needed to compare the two check
  // integers, so the rest is not copied to the device

  // integers, so the rest is not copied to the device. Big-endian packed, to
  // match the AES keystream it is XORed against in _comp.

  const u8 *data_pos = token.buf[5] + (ct_offset * 2);

  for (int i = 0, j = 0; i < 4; i += 1, j += 8)
  {
    sshng->ct_buf[i] = byte_swap_32 (hex_to_u32 (&data_pos[j]));
  }

  // fake digest: the encrypted check integers. Distinct per key, which is what
  // hashcat needs for its hash table.

  digest[0] = sshng->ct_buf[0];
  digest[1] = sshng->ct_buf[1];
  digest[2] = sshng->ct_buf[2];
  digest[3] = sshng->ct_buf[3];

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const sshng_bcrypt_t *sshng = (const sshng_bcrypt_t *) esalt_buf;

  u8 *out_buf = (u8 *) line_buf;

  u8 salt_hex[(SSHNG_SALT_LEN * 2) + 1] = { 0 };

  // u32_to_hex packs little-endian, the inverse of hex_to_u32, so the
  // big-endian words held in the esalt are swapped back before printing.

  u32_to_hex (byte_swap_32 (sshng->salt_buf[0]), salt_hex +  0);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[1]), salt_hex +  8);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[2]), salt_hex + 16);
  u32_to_hex (byte_swap_32 (sshng->salt_buf[3]), salt_hex + 24);

  int out_len = snprintf ((char *) out_buf, line_size, "%s%u$%d$%s$%d$",
    SIGNATURE_SSHNG,
    sshng->cipher,
    SSHNG_SALT_LEN,
    salt_hex,
    sshng->data_len);

  out_len += hex_encode ((const u8 *) sshng->data_buf, sshng->data_len, out_buf + out_len);

  out_len += snprintf ((char *) out_buf + out_len, line_size - out_len, "$%u$%u",
    sshng->rounds,
    sshng->ct_offset);

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
  module_ctx->module_jit_build_options        = blowfish_module_jit_build_options;
  module_ctx->module_jit_cache_disable        = blowfish_module_jit_cache_disable;
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
