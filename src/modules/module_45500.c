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
static const u32   DGST_SIZE      = DGST_SIZE_4_4;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_CRYPTOCURRENCY_WALLET;
static const char *HASH_NAME      = "Monero Wallet";
static const u64   KERN_TYPE      = 45500;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_NATIVE_THREADS
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MP_MULTI_DISABLE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "test";

// a real monero2john vector (bitmonero 0.8.6.295, 2014): chacha8, binary-format
// plaintext with the m_creation_timestamp marker

static const char *ST_HASH        = "$monero$0*982cc13dd90ed2e2970294b2a67480826acaf8eeedec74acccc5929c33d6b7cf01609f0ddb72817579c4375bd1d8f4d47c36c67d83bd3a817d1242211c6824720e430757c24238189875fbb7fe5e643b4273ac3912c7f4f6998ed1086634cebcce035a4af0122c2a6e601ff160bcfa0cfce06d8b3dd38915aa4f6067a732f954da2029ccca5664bbf5df2b2ce046918eec9b71224ec75418686eb437678ebfba50ed3e07ce0bba39f45610775b9958f44b3a53bf3294d7c55f2c455e2ada17f4426969fbc57cc659793892e558b163dd4826889c865b685ea49c54744ecbfcce9d9d39d16e8874a35ec767ab5b69e498f0989f7dd22becb2d50797e7c2867536bc6a1e9b0ecc0d864204c5114fef9ed86d962fced5cac90dbb33a72d16753075bf";

#include "hooks_common.c"

static const char *SIGNATURE_MONERO = "$monero$";

// cn_slow_hash v0 parameters (CryptoNight, 2 MiB scratchpad, 2^19 main-loop iterations
// of a two-step round, driven by hashcat's loop kernel with salt_iter below)

#define CN_MEMORY          (2 * 1024 * 1024)
#define CN_ITER            (1u << 19)
#define CN_MAX_CIPHER_LEN  4096   // same limit as JtR monero_fmt (MAX_CIPHERTEXT_LENGTH)

typedef struct monero
{
  u32 iv[2];                    // blob[0..7]
  u32 ct[8];                    // blob[10..41], first 32 bytes of ciphertext for the verify
  u32 data[CN_MAX_CIPHER_LEN/4]; // full blob, needed for hash_encode
  u32 data_len;                 // blob length in bytes
  u32 type;                     // 0 = monero2john legacy, 1 = reserved (same layout)

} monero_t;

typedef struct monero_tmp
{
  u32 a[4];
  u32 b[4];

} monero_tmp_t;

static u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 esalt_size = (const u64) sizeof (monero_t);

  return esalt_size;
}

static u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = (const u64) sizeof (monero_tmp_t);

  return tmp_size;
}

// one cn_slow_hash candidate needs one 2 MiB scratchpad; the extra buffer is split into
// four sub-buffers (d_extra0 to d_extra3) and work groups stripe across them, see the kernel.
// OPTS_TYPE_THREAD_MULTI_DISABLE keeps kernel_accel counting candidates, so this sizing holds

static u64 module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, const hc_device_param_t *device_param)
{
  const u64 size_per_accel = CN_MEMORY;

  const u64 size_monero = device_param->kernel_accel_max * size_per_accel;

  // reserve room for the self-test, which runs a single work item: it lands in one of the
  // four sub-buffers, so that sub-buffer must hold a whole scratchpad

  const u64 size_selftest = 4 * size_per_accel;

  return MAX (size_monero, size_selftest);
}

static char *module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const u64 size_per_accel = CN_MEMORY;

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_maxworkgroup_size = device_param->device_maxworkgroup_size;

  const u64 fixed_mem = (256 * 1024 * 1024); // some storage we need for pws[], tmps[], and others. Is around 72MiB in reality.

  const u64 spill_mem = 2048 * device_processors * device_maxworkgroup_size; // 1600 according to ptxas

  const u64 usable_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4));

  // a device that reports less than the reserve would underflow this on a u64, and the accel
  // computed from the wrapped value asks for far more memory than the device has

  const u64 available_mem = (usable_mem > (fixed_mem + spill_mem)) ? usable_mem - (fixed_mem + spill_mem) : 0;

  const u32 kernel_accel_max = (device_param->device_host_unified_memory == true) ? (available_mem / 2) / size_per_accel : available_mem / size_per_accel;

  u32 kernel_accel_new = device_processors;

  if (kernel_accel_user)
  {
    kernel_accel_new = MIN (kernel_accel_max, kernel_accel_user);
  }
  else
  {
    if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      kernel_accel_new = MIN (device_processors, kernel_accel_max);
    }
    else
    {
      kernel_accel_new = kernel_accel_max;
    }
  }

  char *new_device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (new_device_name); i++)
  {
    if (new_device_name[i] == ' ') new_device_name[i] = '_';
  }

  kernel_accel_new = MIN (kernel_accel_new, KERNEL_ACCEL_MAX);

  lines_pos += snprintf (lines_buf + lines_pos, lines_sz - lines_pos, "%s * %u 1 %u A\n", new_device_name, user_options->hash_mode, kernel_accel_new);

  hcfree (new_device_name);

  return lines_buf;
}

static int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  monero_t *monero = (monero_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 3;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_MONERO;

  // sig

  token.len[0]     = 8;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  // type

  token.sep[1]     = '*';
  token.len_min[1] = 1;
  token.len_max[1] = 1;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  // blob: iv (8 bytes) || 2 length bytes || ciphertext, hex encoded.
  // the verify decrypts 32 bytes at offset 10, so the blob must be at least 42 bytes long

  token.len_min[2] = 84;
  token.len_max[2] = CN_MAX_CIPHER_LEN * 2;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // type

  const u8 *type_pos = token.buf[1];

  const u32 type = hc_strtoul ((const char *) type_pos, NULL, 10);

  if (type > 1) return (PARSER_SIGNATURE_UNMATCHED);

  monero->type = type;

  // blob

  const u8 *blob_pos = token.buf[2];
  const int blob_len = token.len[2];

  u8 tmp_buf[CN_MAX_CIPHER_LEN];

  const int tmp_len = hex_decode (blob_pos, blob_len, tmp_buf);

  if (tmp_len < 42) return (PARSER_HASH_LENGTH);

  memcpy (monero->data, tmp_buf, tmp_len);

  monero->data_len = tmp_len;

  // iv and the first 32 bytes of ciphertext (blob offset 10)

  memcpy (monero->iv, tmp_buf +  0,  8);
  memcpy (monero->ct, tmp_buf + 10, 32);

  // the iv doubles as the salt so that hashes stay distinct

  memcpy (salt->salt_buf, monero->iv, 8);

  salt->salt_len = 8;

  // cn_slow_hash main loop: 2^19 iterations of the two-step round

  salt->salt_iter = CN_ITER;

  // digest: first 16 bytes of the ciphertext, used only to identify the hash

  memcpy (digest, monero->ct, 16);

  return (PARSER_OK);
}

static int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const monero_t *monero = (const monero_t *) esalt_buf;

  // hex_encode writes no terminator, so the buffer needs room for one and a clean byte there

  char blob_hex[(CN_MAX_CIPHER_LEN * 2) + 1] = { 0 };

  hex_encode ((const u8 *) monero->data, monero->data_len, (u8 *) blob_hex);

  const int line_len = snprintf (line_buf, line_size, "%s%u*%s",
    SIGNATURE_MONERO,
    monero->type,
    blob_hex);

  return line_len;
}

void module_init (module_ctx_t *module_ctx)
{
  module_init_common (module_ctx);

  module_ctx->module_esalt_size               = module_esalt_size;
  module_ctx->module_extra_buffer_size        = module_extra_buffer_size;
  module_ctx->module_extra_tuningdb_block     = module_extra_tuningdb_block;
  module_ctx->module_hash_decode              = module_hash_decode;
  module_ctx->module_hash_encode              = module_hash_encode;
  module_ctx->module_tmp_size                 = module_tmp_size;
}
