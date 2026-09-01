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
#include "event.h"
#include "emu_inc_cipher_aes.h"

// hashcat's own RAR3 decoder, included the way scrypt_common.c is: one translation unit, nothing exported.

#include "rar3_decode.c"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_4; // actually only DGST_SIZE_4_1
static const u32   HASH_CATEGORY  = HASH_CATEGORY_ARCHIVE;
static const char *HASH_NAME      = "RAR3-p (Compressed)";
static const u64   KERN_TYPE      = 23800;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE
                                  | OPTI_TYPE_REGISTER_LIMIT;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_HOOK23
                                  | OPTS_TYPE_POST_AMP_UTF16LE;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$RAR3$*1*ad56eb40219c9da2*834064ce*32*13*1*eb47b1abe17a1a75bce6c92ab1cef3f4126035ea95deaf08b3f32a0c7b8078e1*33";

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

typedef struct rar3
{
  u32 first_block_encrypted[4];

} rar3_t;

typedef struct rar3_tmp
{
  u32 dgst[5];

  u32 w[66]; // 256 byte pass + 8 byte salt

  u32 iv[4];

} rar3_tmp_t;

typedef struct rar3_tmp_optimized
{
  u32 dgst[17][5];

} rar3_tmp_optimized_t;

typedef struct rar3_hook
{
  u32 key[4];
  u32 iv[4];

  u32 first_block_decrypted[4];

  // One of the HC_RAR3_UNPACK_* values. The kernel compares crc32 only when it is HC_RAR3_UNPACK_OK.

  u32 unpack_status;

  u32 crc32;

} rar3_hook_t;

typedef struct rar3_hook_salt
{
  u32 data[81920];

  u32 pack_size;
  u32 unpack_size;

  u32 method;

} rar3_hook_salt_t;

typedef struct rar3_hook_extra
{
  // The decoder's buffers, one set per backend device. Nothing is allocated per candidate.

  void **win;
  void **stream;
  void **filter;
  void **scratch;
  void **ppm;
  void **blocks;

  // Candidates this hook thread could not test, one counter per thread.

  u64 unsupported_cnt;

} rar3_hook_extra_t;

// This runs once per hook thread from a single thread, so the counts are reported on the last call.

static u64 rar3_unsupported_total = 0;
static int rar3_term_calls        = 0;

static const int   ROUNDS_RAR3    = 262144;
static const char *SIGNATURE_RAR3 = "$RAR3$";

#define ADD_BITS(n)                                   \
{                                                     \
  if (bits < 9)                                       \
  {                                                   \
    hold |= ((unsigned int) *next++ << (24 - bits));  \
    bits += 8;                                        \
  }                                                   \
                                                      \
  hold <<= n;                                         \
  bits  -= n;                                         \
}

/*
 * The following function was implemented similar to the check_huffman ()
 * function from John The Ripper.
 * Thanks go to magnum and JTR for the permission.
 */

static int check_huffman (const unsigned char *next)
{
  unsigned int bits;
  unsigned int hold;
  unsigned int i;
  int left;
  unsigned int ncount[4];
  unsigned char *count = (unsigned char*) ncount;
  unsigned char bit_length[20];

  hold =                  next[3]
       + (((unsigned int) next[2]) <<  8)
       + (((unsigned int) next[1]) << 16)
       + (((unsigned int) next[0]) << 24);

  next  += 4;  // we already have the first 32 bits
  hold <<= 2;  // we already processed 2 bits, PPM and keepOldTable
  bits   = 32 - 2;

  /* First, read 20 pairs of (bitlength[, zerocount]) */
  for (i = 0; i < 20; i++)
  {
    int length, zero_count;

    length = hold >> 28;

    ADD_BITS (4);

    if (length == 15)
    {
      zero_count = hold >> 28;

      ADD_BITS (4);

      if (zero_count == 0)
      {
        bit_length[i] = 15;
      }
      else
      {
        zero_count += 2;

        while (zero_count-- > 0 && i < sizeof (bit_length) / sizeof (bit_length[0]))
        {
          bit_length[i++] = 0;
        }

        i--;
      }
    }
    else
    {
      bit_length[i] = length;
    }
  }

  /* Count the number of codes for each code length */
  memset (count, 0, 16);

  for (i = 0; i < 20; i++)
  {
    ++count[bit_length[i]];
  }

  count[0] = 0;

  if (!ncount[0] && !ncount[1] && !ncount[2] && !ncount[3]) return 0; /* No codes at all */

  left = 1;

  for (i = 1; i < 16; ++i)
  {
    left <<= 1;
    left -= count[i];

    if (left < 0) return 0; /* over-subscribed */
  }

  if (left) return 0; /* incomplete set */

  return 1; /* Passed this check! */
}

bool module_unstable_warning (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU))
  {
    if (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK)
    {
      // Intel Iris
      return true;
    }
  }

  return false;
}

bool module_hook_extra_param_init (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar3_hook_extra_t *rar3_hook_extra = (rar3_hook_extra_t *) hook_extra_param;

  rar3_hook_extra->win = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->win == NULL) return false;

  rar3_hook_extra->stream = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->stream == NULL) return false;

  rar3_hook_extra->filter = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->filter == NULL) return false;

  rar3_hook_extra->scratch = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->scratch == NULL) return false;

  rar3_hook_extra->ppm = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->ppm == NULL) return false;

  rar3_hook_extra->blocks = hccalloc (backend_ctx->backend_devices_cnt, sizeof (void *));

  if (rar3_hook_extra->blocks == NULL) return false;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    rar3_hook_extra->win[backend_devices_idx] = hcmalloc (RAR3_WIN_SIZE);

    if (rar3_hook_extra->win[backend_devices_idx] == NULL) return false;

    rar3_hook_extra->stream[backend_devices_idx] = hcmalloc (RAR3_PACK_MAX);

    if (rar3_hook_extra->stream[backend_devices_idx] == NULL) return false;

    rar3_hook_extra->filter[backend_devices_idx] = hcmalloc (RAR3_FILTER_SIZE);

    if (rar3_hook_extra->filter[backend_devices_idx] == NULL) return false;

    rar3_hook_extra->scratch[backend_devices_idx] = hcmalloc (2 * RAR3_FILTER_SIZE);

    if (rar3_hook_extra->scratch[backend_devices_idx] == NULL) return false;

    rar3_hook_extra->ppm[backend_devices_idx] = hcmalloc (RAR3_PPM_ARENA);

    if (rar3_hook_extra->ppm[backend_devices_idx] == NULL) return false;

    rar3_hook_extra->blocks[backend_devices_idx] = hcmalloc (RAR3_BLOCKS_BYTES);

    if (rar3_hook_extra->blocks[backend_devices_idx] == NULL) return false;
  }

  return true;
}

bool module_hook_extra_param_term (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const folder_config_t *folder_config, MAYBE_UNUSED const backend_ctx_t *backend_ctx, void *hook_extra_param)
{
  rar3_hook_extra_t *rar3_hook_extra = (rar3_hook_extra_t *) hook_extra_param;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    hcfree (rar3_hook_extra->blocks[backend_devices_idx]);
    hcfree (rar3_hook_extra->ppm[backend_devices_idx]);
    hcfree (rar3_hook_extra->win[backend_devices_idx]);
    hcfree (rar3_hook_extra->stream[backend_devices_idx]);
    hcfree (rar3_hook_extra->filter[backend_devices_idx]);
    hcfree (rar3_hook_extra->scratch[backend_devices_idx]);
  }

  hcfree (rar3_hook_extra->blocks);
  hcfree (rar3_hook_extra->ppm);
  hcfree (rar3_hook_extra->win);
  hcfree (rar3_hook_extra->stream);
  hcfree (rar3_hook_extra->filter);
  hcfree (rar3_hook_extra->scratch);

  rar3_unsupported_total += rar3_hook_extra->unsupported_cnt;

  rar3_term_calls++;

  if (rar3_term_calls < (int) user_options->hook_threads) return true;

  // These never produced a CRC32 to compare, and saying nothing would look like Exhausted.

  if (rar3_unsupported_total)
  {
    event_log_warning (hashcat_ctx, "hashcat could not decode part of a RAR3 stream in this run.");
    event_log_warning (hashcat_ctx, "Candidates that reached it and could not be tested: %" PRIu64, rar3_unsupported_total);
    event_log_warning (hashcat_ctx, "A correct password among them would not have been reported, so this result is");
    event_log_warning (hashcat_ctx, "incomplete rather than negative.");
    event_log_warning (hashcat_ctx, NULL);
  }

  rar3_unsupported_total = 0;
  rar3_term_calls        = 0;

  return true;
}

void module_hook23 (hc_device_param_t *device_param, const void *hook_extra_param, const void *hook_salts_buf, const u32 salt_pos, const u64 pw_pos)
{
  rar3_hook_t *hook_items = (rar3_hook_t *) device_param->hooks_buf;
  rar3_hook_t *hook_item  = &hook_items[pw_pos];

  const rar3_hook_salt_t *rar3s = (const rar3_hook_salt_t *) hook_salts_buf;
  const rar3_hook_salt_t *rar3  = &rar3s[salt_pos];

  // The interface hands this over as const, but it belongs to this module and this hook thread.

  rar3_hook_extra_t *rar3_hook_extra = (rar3_hook_extra_t *) hook_extra_param;

  const unsigned int pack_size   = (const unsigned int) rar3->pack_size;
  const unsigned int unpack_size = (const unsigned int) rar3->unpack_size;

  const u8 *first_block_decrypted = (const u8 *) hook_item->first_block_decrypted;

  // Nothing clears the hook buffer between candidates, so every path out of here writes a status.

  if (first_block_decrypted[0] & 0x80)
  {
    if (rar3_ppm_header_ok (first_block_decrypted) == 0)
    {
      hook_item->unpack_status = HC_RAR3_UNPACK_REJECTED_PPM;

      return;
    }
  }
  else
  {
    // LZ checks here.
    if ((first_block_decrypted[0] & 0x40)             // KeepOldTable can't be set
     || (check_huffman (first_block_decrypted)) == 0) // Huffman table check
    {
      hook_item->unpack_status = HC_RAR3_UNPACK_REJECTED_LZ;

      return;
    }
  }

  const u8 *data = (const u8 *) rar3->data;

  const u8 *key = (u8 *) hook_item->key;
  const u8 *iv  = (u8 *) hook_item->iv;

  // Set before the call, so an unpack that does not return normally still leaves an unusable status.

  hook_item->unpack_status = HC_RAR3_UNPACK_SHORT_OUTPUT;

  // The decoder is handed plain bytes, so the cipher is here rather than inside it.

  u32 *stream = (u32 *) rar3_hook_extra->stream[device_param->device_id];

  // RAR3 encrypts with AES-128 in CBC. These words are already in the order aes128_ wants.

  AES_KEY aes_key;

  memset (&aes_key, 0, sizeof (aes_key));

  aes128_set_decrypt_key (aes_key.rdk, (const u32 *) key, (u32 *) te0, (u32 *) te1, (u32 *) te2, (u32 *) te3, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3);

  u32 chain[4];

  chain[0] = ((const u32 *) iv)[0];
  chain[1] = ((const u32 *) iv)[1];
  chain[2] = ((const u32 *) iv)[2];
  chain[3] = ((const u32 *) iv)[3];

  const u32 *in = (const u32 *) data;

  // The first pass is given RAR3_FIRST_CHUNK bytes, and only a decode that wanted more gets the rest.

  u32 done = 0;

  u32 crc32 = 0;

  int ran_off_the_end = 0;

  for (u32 pass = 0; pass < 2; pass++)
  {
    const u32 want = (pass == 0) ? MIN (pack_size, RAR3_FIRST_CHUNK) : pack_size;

    for (u32 j = done / 4; done < want; done += 16, j += 4)
    {
      u32 block[4];

      block[0] = in[j + 0];
      block[1] = in[j + 1];
      block[2] = in[j + 2];
      block[3] = in[j + 3];

      u32 out[4];

      aes128_decrypt (aes_key.rdk, block, out, (u32 *) td0, (u32 *) td1, (u32 *) td2, (u32 *) td3, (u32 *) td4);

      stream[j + 0] = out[0] ^ chain[0];
      stream[j + 1] = out[1] ^ chain[1];
      stream[j + 2] = out[2] ^ chain[2];
      stream[j + 3] = out[3] ^ chain[3];

      chain[0] = block[0];
      chain[1] = block[1];
      chain[2] = block[2];
      chain[3] = block[3];
    }

    crc32 = rar3_decode (rar3_hook_extra->win[device_param->device_id], rar3_hook_extra->filter[device_param->device_id], rar3_hook_extra->scratch[device_param->device_id], rar3_hook_extra->ppm[device_param->device_id], rar3_hook_extra->blocks[device_param->device_id], (const u8 *) stream, done, unpack_size, &hook_item->unpack_status, &ran_off_the_end);

    if (ran_off_the_end == 0) break;

    if (done >= pack_size) break;
  }

  hook_item->crc32 = crc32;

  if (hook_item->unpack_status == HC_RAR3_UNPACK_UNSUPPORTED) rar3_hook_extra->unsupported_cnt++;
}

u64 module_hook_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_size = (const u64) sizeof (rar3_hook_t);

  return hook_size;
}

u64 module_hook_salt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_salt_size = (const u64) sizeof (rar3_hook_salt_t);

  return hook_salt_size;
}

u64 module_hook_extra_param_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 hook_extra_param_size = (const u64) sizeof (rar3_hook_extra_t);

  return hook_extra_param_size;
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = user_options->optimized_kernel;

  u64 tmp_size = (u64) sizeof (rar3_tmp_t);

  if (optimized_kernel == true)
  {
    tmp_size = (u64) sizeof (rar3_tmp_optimized_t);
  }

  return tmp_size;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  u64 esalt_size = (u64) sizeof (rar3_t);

  return esalt_size;
}

// The loop count is pinned: the loop kernel takes 1 byte of the 16 byte RAR3 IV per call, so there are
// exactly 16 calls. The thread count is set from the device rather than tuned, because one launch is
// 16384 SHA-1 iterations however many threads run it, so autotune settles far below the knee.
//
//   device             threads   -w 1 before   -w 1 after   -w 2 before   -w 2 after
//   -----------------  -------   -----------   ----------   -----------   ----------
//   RX 9070 XT           512      1173 H/s     77099 H/s     8926 H/s     60923 H/s
//   integrated Radeon    512        72 H/s      2022 H/s      287 H/s      2021 H/s
//   Ryzen 9 9900X          1      1200 H/s      1181 H/s     1308 H/s      1305 H/s
//
// The CPU row is why the count is not 512 everywhere: there it buys 10 percent and takes the launch
// from 2 milliseconds to 570. A work item is 16384 dependent rounds against a block in the private
// segment, so threads buy a GPU the concurrency that hides that latency, and a CPU has none to hide.

#define RAR3_THREADS_GPU 512
#define RAR3_THREADS_CPU 1

char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // FORCED_THREAD_COUNT sets the minimum and maximum together, so leaving it out is what lets -T through.

  if (user_options->kernel_threads_chgd == true) return NULL;

  const u32 threads = (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU) ? RAR3_THREADS_CPU : RAR3_THREADS_GPU;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D FORCED_THREAD_COUNT=%u", threads);

  return jit_build_options;
}

u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = ROUNDS_RAR3 / 16;

  return kernel_loops_min;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = ROUNDS_RAR3 / 16;

  return kernel_loops_max;
}

u32 module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL);

  u32 pw_max = 128;

  if (optimized_kernel == true)
  {
    pw_max = 20;
  }

  return pw_max;
}

const char *module_benchmark_mask (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const char *mask = "?l?l?l?l?l";

  return mask;
}

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  rar3_t *rar3 = (rar3_t *) esalt_buf;

  rar3_hook_salt_t *rar3_hook_salt = (rar3_hook_salt_t *) hook_salt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 9;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_RAR3;

  token.sep[0]     = '*';
  token.len[0]     = 6;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '*';
  token.len[1]     = 1;
  token.attr[1]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[2]     = '*';
  token.len[2]     = 16;
  token.attr[2]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[3]     = '*';
  token.len[3]     = 8;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.sep[4]     = '*';
  token.len_min[4] = 1;
  token.len_max[4] = 7;
  token.attr[4]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[5]     = '*';
  token.len_min[5] = 1;
  token.len_max[5] = 6;
  token.attr[5]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[6]     = '*';
  token.len[6]     = 1;
  token.attr[6]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  token.sep[7]     = '*';
  token.len_min[7] = 2;
  token.len_max[7] = 655056;
  token.attr[7]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_HEX;

  token.len[8]     = 2;
  token.attr[8]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_DIGIT;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  const u8 *type_pos    = token.buf[1];

  if (type_pos[0] != '1') return (PARSER_SIGNATURE_UNMATCHED);

  // salt

  const u8 *salt_pos = token.buf[2];

  salt->salt_buf[0] = hex_to_u32 (salt_pos + 0);
  salt->salt_buf[1] = hex_to_u32 (salt_pos + 8);

  salt->salt_len  = 8;
  salt->salt_iter = ROUNDS_RAR3;

  // CRC32

  const u8 *crc32_pos = token.buf[3];

  u32 crc32_sum = hex_to_u32 (crc32_pos);

  // pack size

  const u8 *pack_size_pos = token.buf[4];

  const u32 pack_size = hc_strtoul ((const char *) pack_size_pos, NULL, 10);

  if (pack_size <      1) return (PARSER_SALT_VALUE);
  if (pack_size > 327680) return (PARSER_SALT_VALUE);

  if ((pack_size % 16) != 0) return (PARSER_SALT_VALUE);

  rar3_hook_salt->pack_size = pack_size;

  // unpack size

  const u8 *unpack_size_pos = token.buf[5];

  const u32 unpack_size = hc_strtoul ((const char *) unpack_size_pos, NULL, 10);

  if (unpack_size <      1) return (PARSER_SALT_VALUE);
  if (unpack_size > 655360) return (PARSER_SALT_VALUE);

  rar3_hook_salt->unpack_size = unpack_size;

  // data is within the hash line

  const u8 *is_data_pos = token.buf[6];

  if (is_data_pos[0] != '1') return (PARSER_SALT_VALUE);

  // data

  const u8 *data_pos = token.buf[7];
  const u32 data_len = token.len[7];

  if (data_len != (pack_size * 2)) return (PARSER_SALT_VALUE);

  hex_decode (data_pos, data_len, (u8 *) rar3_hook_salt->data);

  rar3->first_block_encrypted[0] = rar3_hook_salt->data[0];
  rar3->first_block_encrypted[1] = rar3_hook_salt->data[1];
  rar3->first_block_encrypted[2] = rar3_hook_salt->data[2];
  rar3->first_block_encrypted[3] = rar3_hook_salt->data[3];

  // method

  const u8 *method_pos = token.buf[8];

  const u32 method = hc_strtoul ((const char *) method_pos, NULL, 10);

  if (method < 31) return (PARSER_SALT_VALUE);
  if (method > 35) return (PARSER_SALT_VALUE);

  rar3_hook_salt->method = method;

  // digest

  digest[0] = crc32_sum;
  digest[1] = 0;
  digest[2] = 0;
  digest[3] = 0;

  return (PARSER_OK);
}

int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const rar3_hook_salt_t *rar3_hook_salt = (const rar3_hook_salt_t *) hook_salt_buf;

  const u32 data_len = rar3_hook_salt->pack_size;

  u8 *data = (u8 *) hcmalloc ((data_len * 2) + 1);

  hex_encode ((const u8 *) rar3_hook_salt->data, data_len, data);

  data[data_len * 2] = 0;

  const int line_len = snprintf (line_buf, line_size, "%s*1*%08x%08x*%08x*%u*%u*1*%s*%i",
      SIGNATURE_RAR3,
      byte_swap_32 (salt->salt_buf[0]),
      byte_swap_32 (salt->salt_buf[1]),
      byte_swap_32 (digest[0]),
      rar3_hook_salt->pack_size,
      rar3_hook_salt->unpack_size,
      data,
      rar3_hook_salt->method);

  hcfree (data);

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
  module_ctx->module_benchmark_mask           = module_benchmark_mask;
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
  module_ctx->module_hook_extra_param_size    = module_hook_extra_param_size;
  module_ctx->module_hook_extra_param_init    = module_hook_extra_param_init;
  module_ctx->module_hook_extra_param_term    = module_hook_extra_param_term;
  module_ctx->module_hook12                   = MODULE_DEFAULT;
  module_ctx->module_hook23                   = module_hook23;
  module_ctx->module_hook_salt_size           = module_hook_salt_size;
  module_ctx->module_hook_size                = module_hook_size;
  module_ctx->module_jit_build_options        = module_jit_build_options;
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
  module_ctx->module_pw_max                   = module_pw_max;
  module_ctx->module_pw_min                   = MODULE_DEFAULT;
  module_ctx->module_salt_max                 = MODULE_DEFAULT;
  module_ctx->module_salt_min                 = MODULE_DEFAULT;
  module_ctx->module_salt_type                = module_salt_type;
  module_ctx->module_separator                = MODULE_DEFAULT;
  module_ctx->module_st_hash                  = module_st_hash;
  module_ctx->module_st_pass                  = module_st_pass;
  module_ctx->module_tmp_size                 = module_tmp_size;
  module_ctx->module_unstable_warning         = module_unstable_warning;
  module_ctx->module_usage_notice             = MODULE_DEFAULT;
  module_ctx->module_warmup_disable           = MODULE_DEFAULT;
}
