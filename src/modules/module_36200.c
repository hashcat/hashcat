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
#include "memory.h"

static const u32   ATTACK_EXEC    = ATTACK_EXEC_OUTSIDE_KERNEL;
static const u32   DGST_POS0      = 0;
static const u32   DGST_POS1      = 1;
static const u32   DGST_POS2      = 2;
static const u32   DGST_POS3      = 3;
static const u32   DGST_SIZE      = DGST_SIZE_4_8;
static const u32   HASH_CATEGORY  = HASH_CATEGORY_GENERIC_KDF;
static const char *HASH_NAME      = "gost-yescrypt";
static const u64   KERN_TYPE      = 36200;
static const u32   OPTI_TYPE      = OPTI_TYPE_ZERO_BYTE;
static const u64   OPTS_TYPE      = OPTS_TYPE_STOCK_MODULE
                                  | OPTS_TYPE_PT_GENERATE_LE
                                  | OPTS_TYPE_MP_MULTI_DISABLE
                                  | OPTS_TYPE_THREAD_MULTI_DISABLE
                                  | OPTS_TYPE_MULTIHASH_DESPITE_ESALT;
static const u32   SALT_TYPE      = SALT_TYPE_EMBEDDED;
static const char *ST_PASS        = "hashcat";
static const char *ST_HASH        = "$gy$j9T$HtyOX9cwJ2Dh8LlJV8IJ30$ZCSJt69pE/HLXFfIuxukRc2PlNla.tbqJxUHCp/WHVD";

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

#define COOP_THREADS 32

// The Sbox goes to local memory whenever it fits. The old limit of 15 hashes per
// multiprocessor kept it in global memory on any card with enough VRAM to hold a
// lot of hashes at once, which is exactly where the local memory copy pays off.
// Measured on an RX 9070 XT at the j9T parameters, 888 H/s global against
// 1237 H/s local, so the placement is worth about 39 percent.

#define COOP_LDS_THRESHOLD 0xffffffff
#define COOP_ACCEL_MAX 1024

typedef struct yescrypt
{
  u32 flags;
  u32 t;

  // "$gy$<params>$<salt>", the message for the inner GOST HMAC
  u32 setting_buf[64];
  u32 setting_len;

} yescrypt_t;

static u32 yescrypt_atoi64 (const u8 c)
{
  if (c >= '.' && c <= 'z') return itoa64_to_int (c);

  return 64;
}


static const u8 *yescrypt_decode64_uint32 (u32 *dst, const u8 *src, u32 min)
{
  u32 start = 0, end = 47, chars = 1, bits = 0;
  u32 c;

  c = yescrypt_atoi64 (*src++);

  if (c > 63) return NULL;

  *dst = min;

  while (c > end)
  {
    *dst += (end + 1 - start) << bits;
    start = end + 1;
    end = start + (62 - end) / 2;
    chars++;
    bits += 6;
  }

  *dst += (c - start) << bits;

  while (--chars)
  {
    c = yescrypt_atoi64 (*src++);

    if (c > 63) return NULL;

    bits -= 6;
    *dst += c << bits;
  }

  return src;
}


static u8 *yescrypt_encode64_uint32 (u8 *dst, size_t dstlen, u32 src, u32 min)
{
  u32 start = 0, end = 47, chars = 1, bits = 0;

  if (src < min) return NULL;

  src -= min;

  do
  {
    u32 count = (end + 1 - start) << bits;

    if (src < count) break;

    if (start >= 63) return NULL;

    start = end + 1;
    end = start + (62 - end) / 2;
    src -= count;
    chars++;
    bits += 6;

  } while (1);

  if (dstlen <= chars) return NULL;

  *dst++ = int_to_itoa64 (start + (src >> bits));

  while (--chars)
  {
    bits -= 6;
    *dst++ = int_to_itoa64 ((src >> bits) & 0x3f);
  }

  *dst = 0;

  return dst;
}


static int yescrypt_decode64 (u8 *dst, size_t dstlen, const u8 *src, size_t srclen)
{
  size_t dstpos = 0;
  size_t srcpos = 0;

  while (srcpos < srclen && dstpos < dstlen)
  {
    u32 value = 0;
    u32 bits = 0;

    while (srcpos < srclen && bits < 24)
    {
      u32 c = yescrypt_atoi64 (src[srcpos]);

      if (c > 63) return -1;

      srcpos++;
      value |= c << bits;
      bits += 6;
    }

    if (bits < 12) return -1;

    while (bits >= 8 && dstpos < dstlen)
    {
      dst[dstpos++] = value & 0xff;
      value >>= 8;
      bits -= 8;
    }

    if (bits > 0 && value != 0) return -1;
  }

  return (int) dstpos;
}


static int yescrypt_encode64 (u8 *dst, size_t dstlen, const u8 *src, size_t srclen)
{
  size_t dstpos = 0;
  size_t srcpos = 0;

  while (srcpos < srclen)
  {
    u32 value = 0;
    u32 bits = 0;

    while (bits < 24 && srcpos < srclen)
    {
      value |= (u32) src[srcpos++] << bits;
      bits += 8;
    }

    for (u32 emitted = 0; emitted < bits; emitted += 6)
    {
      if (dstpos >= dstlen) return -1;

      dst[dstpos++] = int_to_itoa64 (value & 0x3f);
      value >>= 6;
    }
  }

  if (dstpos >= dstlen) return -1;

  dst[dstpos] = 0;

  return (int) dstpos;
}


static u64 yescrypt_calc_nloop_all (u64 N, u32 p, u32 t, u32 flags)
{
  u64 Nchunk = N / p;

  u64 Nloop_all = Nchunk;

  if (flags & 0x002)
  {
    if (t <= 1)
    {
      if (t) Nloop_all *= 2;

      Nloop_all = (Nloop_all + 2) / 3;
    }
    else
    {
      Nloop_all *= t - 1;
    }
  }
  else if (t)
  {
    if (t == 1)
      Nloop_all += (Nloop_all + 1) / 2;

    Nloop_all *= t;
  }

  Nloop_all++;
  Nloop_all &= ~(u64) 1;

  return Nloop_all;
}


u32 module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1024;
}

u32 module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 1024;
}

u32 module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return COOP_THREADS;
}

u64 module_esalt_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return sizeof (yescrypt_t);
}

u64 module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return 0;
}

u64 module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  const yescrypt_t *ye = (hashes->esalts_buf == NULL)
    ? (const yescrypt_t *) hashes->st_esalts_buf
    : (const yescrypt_t *) hashes->esalts_buf;

  const u32 ye_flags = ye->flags;
  const u32 ye_t     = ye->t;

  for (u32 i = 1; i < hashes->salts_cnt; i++)
  {
    if ((scrypt_N != hashes->salts_buf[i].scrypt_N)
     || (scrypt_r != hashes->salts_buf[i].scrypt_r)
     || (scrypt_p != hashes->salts_buf[i].scrypt_p))
    {
      return (1ULL << 63) + i;
    }

    const yescrypt_t *ye_i = (const yescrypt_t *) ((const u8 *) hashes->esalts_buf + (hashes->salts_buf[i].digests_offset * sizeof (yescrypt_t)));

    if ((ye_flags != ye_i->flags) || (ye_t != ye_i->t))
    {
      return (1ULL << 63) + i;
    }
  }

  if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
  {
    if ((scrypt_N != hashes->st_salts_buf[0].scrypt_N)
     || (scrypt_r != hashes->st_salts_buf[0].scrypt_r)
     || (scrypt_p != hashes->st_salts_buf[0].scrypt_p))
    {
      return (1ULL << 62);
    }
  }

  const u64 P_size  = 128ULL * scrypt_r;
  const u64 S_size  = 12288;
  const u64 ctx_size = (8 + 4) * 4; // passwd + state tracking

  u64 tmp_size = P_size + S_size + ctx_size;

  return tmp_size;
}


u64 module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;

  const u64 size_per_instance = 128ULL * scrypt_r * scrypt_N;

  const u64 total_V = (u64) device_param->kernel_accel_max * size_per_instance;

  return total_V;
}


const char *module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;

  const u64 size_per_instance = 128ULL * scrypt_r * scrypt_N;

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u64 fixed_mem = (128 * 1024 * 1024);

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4)) - fixed_mem;

  u32 kernel_accel_new;

  if (kernel_accel_user)
  {
    kernel_accel_new = kernel_accel_user;
  }
  else
  {
    kernel_accel_new = (u32) (available_mem / size_per_instance);

    kernel_accel_new = (kernel_accel_new * 94) / 100;

    if (kernel_accel_new > COOP_ACCEL_MAX) kernel_accel_new = COOP_ACCEL_MAX;

    if (kernel_accel_new > device_processors)
    {
      const u32 extra = kernel_accel_new % device_processors;

      if (extra < (u32) (device_processors * 0.16))
      {
        kernel_accel_new -= extra;
      }
    }

    if (kernel_accel_new < 1) kernel_accel_new = 1;
  }

  char *new_device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (new_device_name); i++)
  {
    if (new_device_name[i] == ' ') new_device_name[i] = '_';
  }

  lines_pos += snprintf (lines_buf + lines_pos, lines_sz - lines_pos, "%s * %u 1 %u A\n", new_device_name, user_options->hash_mode, kernel_accel_new);

  hcfree (new_device_name);

  return lines_buf;
}


char *module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  const yescrypt_t *ye = (hashes->esalts_buf == NULL)
    ? (const yescrypt_t *) hashes->st_esalts_buf
    : (const yescrypt_t *) hashes->esalts_buf;

  const u32 ye_flags = ye->flags;
  const u32 ye_t     = ye->t;

  const u64 Nloop_all = yescrypt_calc_nloop_all (scrypt_N, scrypt_p, ye_t, ye_flags);
  const u64 Nloop_rw  = (ye_flags & 0x002) ? (Nloop_all / scrypt_p) : 0;
  const u64 Nloop_rw_even = ((Nloop_rw + 1) & ~(u64) 1);

  const u64 state_cnt4 = 32ULL * scrypt_r;

  u64 tmp_size = module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

  const char *placement = " -D COOP_X_GLOBAL";

  if (device_param != NULL)
  {
    const u64 v_per_hash = 128ULL * scrypt_r * scrypt_N;
    const u64 fixed_mem  = 128 * 1024 * 1024;
    const u64 maxmem4    = device_param->device_maxmem_alloc * 4;
    const u64 avail_all  = MIN (device_param->device_available_mem, maxmem4);
    const u64 avail      = (avail_all > fixed_mem) ? (avail_all - fixed_mem) : avail_all;
    const u32 procs      = (device_param->device_processors > 0) ? device_param->device_processors : 1;

    u64 hashes_total = (v_per_hash > 0) ? ((avail / v_per_hash) * 94) / 100 : 0;
    if (hashes_total > COOP_ACCEL_MAX) hashes_total = COOP_ACCEL_MAX;
    const u64 hashes_per_sm = hashes_total / procs;

    const u64 lds_per_block = (128ULL * scrypt_r) + 12288;

    if (lds_per_block <= device_param->device_local_mem_size && hashes_per_sm <= COOP_LDS_THRESHOLD)
    {
      placement = " -D COOP_SBOX_LDS";
    }
  }


  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options,
    "-D FIXED_LOCAL_SIZE=%u"
    " -D YESCRYPT_N=%u"
    " -D YESCRYPT_R=%u"
    " -D YESCRYPT_P=%u"
    " -D YESCRYPT_T=%u"
    " -D YESCRYPT_FLAGS=0x%03x"
    " -D YESCRYPT_NLOOP_ALL=%" PRIu64
    " -D YESCRYPT_NLOOP_RW=%" PRIu64
    " -D YESCRYPT_STATE_CNT4=%" PRIu64
    " -D YESCRYPT_TMP_ELEM=%" PRIu64
    "%s",
    COOP_THREADS,
    scrypt_N,
    scrypt_r,
    scrypt_p,
    ye_t,
    ye_flags,
    Nloop_all,
    Nloop_rw_even,
    state_cnt4,
    tmp_size / 4,
    placement);

  return jit_build_options;
}


static const char *SIGNATURE_YESCRYPT = "$gy$";

int module_hash_decode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED void *digest_buf, MAYBE_UNUSED salt_t *salt, MAYBE_UNUSED void *esalt_buf, MAYBE_UNUSED void *hook_salt_buf, MAYBE_UNUSED hashinfo_t *hash_info, const char *line_buf, MAYBE_UNUSED const int line_len)
{
  u32 *digest = (u32 *) digest_buf;

  yescrypt_t *yescrypt = (yescrypt_t *) esalt_buf;

  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt  = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = SIGNATURE_YESCRYPT;

  token.len[0]     = 4;
  token.attr[0]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_SIGNATURE;

  token.sep[1]     = '$';
  token.len_min[1] = 2;
  token.len_max[1] = 48;
  token.attr[1]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.sep[2]     = '$';
  token.len_min[2] = 0;
  token.len_max[2] = 86;
  token.attr[2]    = TOKEN_ATTR_VERIFY_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  token.len[3]     = 43;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK)
  {
    if (hash_info != NULL) hash_info->parser_error_msg = tokenizer_error_dup (rc_tokenizer);

    return (rc_tokenizer);
  }

  // params

  const u8 *params_pos = token.buf[1];

  u32 flavor;

  params_pos = yescrypt_decode64_uint32 (&flavor, params_pos, 0);

  if (params_pos == NULL) return (PARSER_SALT_VALUE);

  u32 flags;

  if (flavor < 2)
  {
    flags = flavor;
  }
  else if (flavor <= 2 + (0x3fc >> 2))
  {
    flags = 0x002 + ((flavor - 2) << 2);
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  u32 N_log2;

  params_pos = yescrypt_decode64_uint32 (&N_log2, params_pos, 1);

  if (params_pos == NULL) return (PARSER_SALT_VALUE);

  if (N_log2 < 1 || N_log2 > 31) return (PARSER_SALT_VALUE);

  const u64 N = (u64) 1 << N_log2;

  u32 r;

  params_pos = yescrypt_decode64_uint32 (&r, params_pos, 1);

  if (params_pos == NULL) return (PARSER_SALT_VALUE);

  if (r < 1) return (PARSER_SALT_VALUE);

  u32 p = 1;
  u32 t = 0;
  u32 g = 0;

  const u8 *params_end = token.buf[1] + token.len[1];

  if (params_pos < params_end)
  {
    u32 have;

    params_pos = yescrypt_decode64_uint32 (&have, params_pos, 1);

    if (params_pos == NULL) return (PARSER_SALT_VALUE);

    if (have & 1)
    {
      params_pos = yescrypt_decode64_uint32 (&p, params_pos, 2);

      if (params_pos == NULL) return (PARSER_SALT_VALUE);
    }

    if (have & 2)
    {
      params_pos = yescrypt_decode64_uint32 (&t, params_pos, 1);

      if (params_pos == NULL) return (PARSER_SALT_VALUE);
    }

    if (have & 4)
    {
      params_pos = yescrypt_decode64_uint32 (&g, params_pos, 1);

      if (params_pos == NULL) return (PARSER_SALT_VALUE);
    }

    if (have & 8) return (PARSER_SALT_VALUE);
  }

  if (g != 0) return (PARSER_SALT_VALUE);

  if (p != 1) return (PARSER_SALT_VALUE);

  // salt

  const u8 *salt_pos = token.buf[2];
  const int salt_len = token.len[2];

  u8 salt_raw[64];

  const int salt_raw_len = yescrypt_decode64 (salt_raw, sizeof (salt_raw), salt_pos, salt_len);

  if (salt_raw_len < 0) return (PARSER_SALT_VALUE);

  // hash

  const u8 *hash_pos = token.buf[3];
  const int hash_len = token.len[3];

  u8 hash_raw[32];

  const int hash_raw_len = yescrypt_decode64 (hash_raw, sizeof (hash_raw), hash_pos, hash_len);

  if (hash_raw_len != 32) return (PARSER_HASH_LENGTH);

  // store

  memcpy (digest, hash_raw, 32);

  memcpy (salt->salt_buf, salt_raw, salt_raw_len);

  salt->salt_len = salt_raw_len;

  salt->scrypt_N = (u32) N;
  salt->scrypt_r = r;
  salt->scrypt_p = p;

  const u64 Nloop_all = yescrypt_calc_nloop_all (N, p, t, flags);

  salt->salt_iter = (u32) (N + Nloop_all);

  yescrypt->flags = flags;
  yescrypt->t = t;

  // the inner HMAC message is "$gy$<params>$<salt>", which is everything
  // ahead of the '$' that introduces the hash

  const int setting_len = (const int) (hash_pos - (const u8 *) line_buf) - 1;

  if (setting_len > (int) sizeof (yescrypt->setting_buf)) return (PARSER_SALT_LENGTH);

  memset (yescrypt->setting_buf, 0, sizeof (yescrypt->setting_buf));
  memcpy (yescrypt->setting_buf, line_buf, setting_len);

  yescrypt->setting_len = (u32) setting_len;

  return (PARSER_OK);
}


int module_hash_encode (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const void *digest_buf, MAYBE_UNUSED const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, MAYBE_UNUSED const void *hook_salt_buf, MAYBE_UNUSED const hashinfo_t *hash_info, char *line_buf, MAYBE_UNUSED const int line_size)
{
  const u32 *digest = (const u32 *) digest_buf;

  const yescrypt_t *yescrypt = (const yescrypt_t *) esalt_buf;

  u8 *dst = (u8 *) line_buf;

  *dst++ = '$';
  *dst++ = 'g';
  *dst++ = 'y';
  *dst++ = '$';

  // flavor

  u32 flavor;

  if (yescrypt->flags < 2)
  {
    flavor = yescrypt->flags;
  }
  else
  {
    flavor = 0x002 + (yescrypt->flags >> 2);
  }

  dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), flavor, 0);

  if (dst == NULL) return 0;

  // N

  u32 N = salt->scrypt_N;
  u32 N_log2 = 0;

  while ((1u << N_log2) < N) N_log2++;

  dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), N_log2, 1);

  if (dst == NULL) return 0;

  // r

  dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), salt->scrypt_r, 1);

  if (dst == NULL) return 0;

  // optional params

  u32 have = 0;

  if (salt->scrypt_p != 1) have |= 1;
  if (yescrypt->t != 0)    have |= 2;

  if (have)
  {
    dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), have, 1);

    if (dst == NULL) return 0;

    if (salt->scrypt_p != 1)
    {
      dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), salt->scrypt_p, 2);

      if (dst == NULL) return 0;
    }

    if (yescrypt->t != 0)
    {
      dst = yescrypt_encode64_uint32 (dst, line_size - (dst - (u8 *) line_buf), yescrypt->t, 1);

      if (dst == NULL) return 0;
    }
  }

  *dst++ = '$';

  // salt

  int salt_b64_len = yescrypt_encode64 (dst, line_size - (dst - (u8 *) line_buf), (const u8 *) salt->salt_buf, salt->salt_len);

  if (salt_b64_len < 0) return 0;

  dst += salt_b64_len;

  *dst++ = '$';

  // hash

  u8 hash_raw[32];

  memcpy (hash_raw, digest, 32);

  int hash_b64_len = yescrypt_encode64 (dst, line_size - (dst - (u8 *) line_buf), hash_raw, 32);

  if (hash_b64_len < 0) return 0;

  dst += hash_b64_len;

  *dst = 0;

  return (int) (dst - (u8 *) line_buf);
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
  module_ctx->module_extra_buffer_size        = module_extra_buffer_size;
  module_ctx->module_extra_tmp_size           = module_extra_tmp_size;
  module_ctx->module_extra_tuningdb_block     = module_extra_tuningdb_block;
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
  module_ctx->module_jit_build_options        = module_jit_build_options;
  module_ctx->module_jit_cache_disable        = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_max         = MODULE_DEFAULT;
  module_ctx->module_kernel_accel_min         = MODULE_DEFAULT;
  module_ctx->module_kernel_loops_max         = module_kernel_loops_max;
  module_ctx->module_kernel_loops_min         = module_kernel_loops_min;
  module_ctx->module_kernel_threads_max       = module_kernel_threads_max;
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
