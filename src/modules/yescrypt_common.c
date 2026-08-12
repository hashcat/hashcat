
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

// The Sbox size is fixed by the yescrypt specification at 3 * (1 << Swidth) * PWXsimple * 8 bytes.
// The kernel derives it from those constants, the host only ever needs the total.

#define YESCRYPT_SBOX_SZ 12288

// passwd[8] plus phase, iter, s_state and w. Has to match yescrypt_tmp_t in the kernel.

#define YESCRYPT_CTX_SZ ((8 + 4) * 4)

// the digest is always 32 bytes, which is 43 characters of yescrypt base64

#define YESCRYPT_HASH_B64_LEN 43

// The loop kernel is cooperative: one workgroup owns one hash and threads 0 to PWXgather-1 are the
// four pwxform lanes. A workgroup narrower than that leaves lanes unprocessed and silently computes
// a wrong digest, so this is a hard floor and not a tuning preference.

#define YESCRYPT_MIN_THREADS 4

// the only flag bit that changes the shape of the computation, see YESCRYPT_FLAG_RW in the kernel

#define YESCRYPT_FLAG_RW 0x002

// one workgroup per hash, and the loop kernel indexes V by the workgroup id

#define YESCRYPT_ACCEL_MAX 1024

// yescrypt base64, most significant character last, as used for the parameter fields

static u32 yescrypt_atoi64 (const u8 c)
{
  if (c < '.') return 64;
  if (c > 'z') return 64;

  const u32 v = itoa64_to_int (c);

  return v;
}

// Reads one packed integer and returns how many characters it consumed, or -1 on a bad character or
// a truncated field. The caller advances its own offset, so no pointer walks off the end of the token.

static int yescrypt_decode64_uint32 (u32 *dst, const u8 *src, const int src_len, const u32 min)
{
  if (src_len < 1) return -1;

  u32 start = 0;
  u32 end   = 47;
  u32 chars = 1;
  u32 bits  = 0;

  u32 c = yescrypt_atoi64 (src[0]);

  if (c > 63) return -1;

  u32 value = min;

  while (c > end)
  {
    value += (end + 1 - start) << bits;

    start = end + 1;
    end   = start + (62 - end) / 2;

    chars++;
    bits += 6;
  }

  value += (c - start) << bits;

  if ((int) chars > src_len) return -1;

  for (u32 i = 1; i < chars; i++)
  {
    c = yescrypt_atoi64 (src[i]);

    if (c > 63) return -1;

    bits -= 6;

    value += c << bits;
  }

  *dst = value;

  const int consumed = (int) chars;

  return consumed;
}

// Writes one packed integer and returns how many characters it wrote, or -1 if it does not fit.

static int yescrypt_encode64_uint32 (u8 *dst, const int dst_len, const u32 src, const u32 min)
{
  if (src < min) return -1;

  u32 value = src - min;

  u32 start = 0;
  u32 end   = 47;
  u32 chars = 1;
  u32 bits  = 0;

  while (1)
  {
    const u32 count = (end + 1 - start) << bits;

    if (value < count) break;

    if (start >= 63) return -1;

    start  = end + 1;
    end    = start + (62 - end) / 2;
    value -= count;

    chars++;
    bits += 6;
  }

  if (dst_len <= (int) chars) return -1;

  dst[0] = int_to_itoa64 (start + (value >> bits));

  for (u32 i = 1; i < chars; i++)
  {
    bits -= 6;

    dst[i] = int_to_itoa64 ((value >> bits) & 0x3f);
  }

  dst[chars] = 0;

  const int written = (int) chars;

  return written;
}

static int yescrypt_decode64 (u8 *dst, const int dst_len, const u8 *src, const int src_len)
{
  int dstpos = 0;
  int srcpos = 0;

  while ((srcpos < src_len) && (dstpos < dst_len))
  {
    u32 value = 0;
    u32 bits  = 0;

    while ((srcpos < src_len) && (bits < 24))
    {
      const u32 c = yescrypt_atoi64 (src[srcpos]);

      if (c > 63) return -1;

      srcpos++;

      value |= c << bits;
      bits  += 6;
    }

    if (bits < 12) return -1;

    while ((bits >= 8) && (dstpos < dst_len))
    {
      dst[dstpos] = value & 0xff;

      dstpos++;

      value >>= 8;
      bits   -= 8;
    }

    if ((bits > 0) && (value != 0)) return -1;
  }

  return dstpos;
}

static int yescrypt_encode64 (u8 *dst, const int dst_len, const u8 *src, const int src_len)
{
  int dstpos = 0;
  int srcpos = 0;

  while (srcpos < src_len)
  {
    u32 value = 0;
    u32 bits  = 0;

    while ((bits < 24) && (srcpos < src_len))
    {
      value |= (u32) src[srcpos] << bits;

      srcpos++;

      bits += 8;
    }

    for (u32 emitted = 0; emitted < bits; emitted += 6)
    {
      if (dstpos >= dst_len) return -1;

      dst[dstpos] = int_to_itoa64 (value & 0x3f);

      dstpos++;

      value >>= 6;
    }
  }

  if (dstpos >= dst_len) return -1;

  dst[dstpos] = 0;

  return dstpos;
}

u64 yescrypt_calc_nloop_all (const u64 N, const u32 p, const u32 t, const u32 flags)
{
  const u64 Nchunk = N / p;

  u64 Nloop_all = Nchunk;

  if ((flags & YESCRYPT_FLAG_RW) != 0)
  {
    if (t >= 2)
    {
      Nloop_all *= t - 1;
    }
    else
    {
      if (t != 0) Nloop_all *= 2;

      Nloop_all = (Nloop_all + 2) / 3;
    }
  }
  else if (t != 0)
  {
    if (t == 1) Nloop_all += (Nloop_all + 1) / 2;

    Nloop_all *= t;
  }

  Nloop_all++;
  Nloop_all &= ~(u64) 1;

  return Nloop_all;
}

// Decodes everything the two modes have in common: the parameter block, the salt and the digest.
// flags and t are returned through pointers because they belong to the mode's own esalt, whose
// layout differs between yescrypt and gost-yescrypt.

int yescrypt_hash_decode (u32 *digest, salt_t *salt, u32 *flags_out, u32 *t_out, const char *signature, const int signature_len, const char *line_buf, const int line_len)
{
  hc_token_t token;

  memset (&token, 0, sizeof (hc_token_t));

  token.token_cnt = 4;

  token.signatures_cnt    = 1;
  token.signatures_buf[0] = signature;

  token.len[0]     = signature_len;
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

  token.len[3]     = YESCRYPT_HASH_B64_LEN;
  token.attr[3]    = TOKEN_ATTR_FIXED_LENGTH
                   | TOKEN_ATTR_VERIFY_BASE64B;

  const int rc_tokenizer = input_tokenizer ((const u8 *) line_buf, line_len, &token);

  if (rc_tokenizer != PARSER_OK) return (rc_tokenizer);

  // params

  const u8 *params_pos = token.buf[1];
  const int params_len = token.len[1];

  int pos = 0;

  u32 flavor;

  int rc = yescrypt_decode64_uint32 (&flavor, params_pos + pos, params_len - pos, 0);

  if (rc < 0) return (PARSER_SALT_VALUE);

  pos += rc;

  u32 flags;

  if (flavor < 2)
  {
    flags = flavor;
  }
  else if (flavor <= (2 + (0x3fc >> 2)))
  {
    flags = YESCRYPT_FLAG_RW + ((flavor - 2) << 2);
  }
  else
  {
    return (PARSER_SALT_VALUE);
  }

  u32 N_log2;

  rc = yescrypt_decode64_uint32 (&N_log2, params_pos + pos, params_len - pos, 1);

  if (rc < 0) return (PARSER_SALT_VALUE);

  pos += rc;

  if (N_log2 <  1) return (PARSER_SALT_VALUE);
  if (N_log2 > 31) return (PARSER_SALT_VALUE);

  const u64 N = (u64) 1 << N_log2;

  u32 r;

  rc = yescrypt_decode64_uint32 (&r, params_pos + pos, params_len - pos, 1);

  if (rc < 0) return (PARSER_SALT_VALUE);

  pos += rc;

  if (r < 1) return (PARSER_SALT_VALUE);

  u32 p = 1;
  u32 t = 0;
  u32 g = 0;

  if (pos < params_len)
  {
    u32 have;

    rc = yescrypt_decode64_uint32 (&have, params_pos + pos, params_len - pos, 1);

    if (rc < 0) return (PARSER_SALT_VALUE);

    pos += rc;

    if ((have & 1) != 0)
    {
      rc = yescrypt_decode64_uint32 (&p, params_pos + pos, params_len - pos, 2);

      if (rc < 0) return (PARSER_SALT_VALUE);

      pos += rc;
    }

    if ((have & 2) != 0)
    {
      rc = yescrypt_decode64_uint32 (&t, params_pos + pos, params_len - pos, 1);

      if (rc < 0) return (PARSER_SALT_VALUE);

      pos += rc;
    }

    if ((have & 4) != 0)
    {
      rc = yescrypt_decode64_uint32 (&g, params_pos + pos, params_len - pos, 1);

      if (rc < 0) return (PARSER_SALT_VALUE);

      pos += rc;
    }

    if ((have & 8) != 0) return (PARSER_SALT_VALUE);
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

  *flags_out = flags;
  *t_out     = t;

  return (PARSER_OK);
}

// Encodes the parameter block, the salt and the digest. The caller has already written its own
// signature, so this starts at line_pos and returns the total line length, or 0 on failure.

int yescrypt_hash_encode (const u32 *digest, const salt_t *salt, const u32 flags, const u32 t, char *line_buf, const int line_size, const int line_pos)
{
  u8 *dst = (u8 *) line_buf;

  int pos = line_pos;

  // flavor

  u32 flavor;

  if (flags < 2)
  {
    flavor = flags;
  }
  else
  {
    flavor = YESCRYPT_FLAG_RW + (flags >> 2);
  }

  int rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, flavor, 0);

  if (rc < 0) return 0;

  pos += rc;

  // N

  const u32 N = salt->scrypt_N;

  u32 N_log2 = 0;

  while ((1u << N_log2) < N) N_log2++;

  rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, N_log2, 1);

  if (rc < 0) return 0;

  pos += rc;

  // r

  rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, salt->scrypt_r, 1);

  if (rc < 0) return 0;

  pos += rc;

  // optional params

  u32 have = 0;

  if (salt->scrypt_p != 1) have |= 1;
  if (t != 0)              have |= 2;

  if (have != 0)
  {
    rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, have, 1);

    if (rc < 0) return 0;

    pos += rc;

    if (salt->scrypt_p != 1)
    {
      rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, salt->scrypt_p, 2);

      if (rc < 0) return 0;

      pos += rc;
    }

    if (t != 0)
    {
      rc = yescrypt_encode64_uint32 (dst + pos, line_size - pos, t, 1);

      if (rc < 0) return 0;

      pos += rc;
    }
  }

  if (pos >= line_size) return 0;

  dst[pos] = '$';

  pos++;

  // salt

  rc = yescrypt_encode64 (dst + pos, line_size - pos, (const u8 *) salt->salt_buf, salt->salt_len);

  if (rc < 0) return 0;

  pos += rc;

  if (pos >= line_size) return 0;

  dst[pos] = '$';

  pos++;

  // hash

  u8 hash_raw[32];

  memcpy (hash_raw, digest, 32);

  rc = yescrypt_encode64 (dst + pos, line_size - pos, hash_raw, 32);

  if (rc < 0) return 0;

  pos += rc;

  return pos;
}

// Reads the yescrypt parameters out of one esalt. The esalt layout differs between the modes, so the
// caller passes its own element size and the offset of the entry it wants.

static void yescrypt_esalt_params (const hashes_t *hashes, const u64 esalt_size, const u32 digests_offset, u32 *flags_out, u32 *t_out)
{
  const u8 *esalts_buf = (hashes->esalts_buf == NULL) ? (const u8 *) hashes->st_esalts_buf : (const u8 *) hashes->esalts_buf;

  const u32 *params = (const u32 *) (const void *) (esalts_buf + ((u64) digests_offset * esalt_size));

  *flags_out = params[0];
  *t_out     = params[1];
}

// Same fixed 2048 the scrypt modes use. The loop kernel carries phase and iter in tmps, so it can be
// cut at any point and resumed, and the count only decides how much work one launch does. 2048 halves
// the number of launches and measures faster: over five runs on an RX 9070 XT, 1535 to 1542 H/s at
// 1024 against 1545 to 1557 H/s at 2048, ranges that do not overlap.

u32 yescrypt_module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 2048;

  return kernel_loops_min;
}

u32 yescrypt_module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 2048;

  return kernel_loops_max;
}

u32 yescrypt_module_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_min = YESCRYPT_MIN_THREADS;

  return kernel_threads_min;
}

u32 yescrypt_module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : YESCRYPT_THREADS;

  return kernel_threads_max;
}

u32 yescrypt_expected_threads (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // scrypt collapses to a single thread on CPU because there each work item owns a whole hash.
  // yescrypt cannot do that: a whole workgroup owns one hash and the pwxform lanes are threads
  // inside it, so the thread count is the same on every device type and only the floor applies.

  const u32 threads = MAX (yescrypt_module_kernel_threads_max (hashconfig, user_options, user_options_extra), YESCRYPT_MIN_THREADS);

  return threads;
}

// V holds N blocks of 128 * r for one hash, and one hash is one workgroup, so unlike scrypt this
// does not scale with the thread count.

static u64 yescrypt_size_per_accel (const hashes_t *hashes)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;

  const u64 size_per_accel = 128ULL * scrypt_r * scrypt_N;

  return size_per_accel;
}

const char *yescrypt_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  // we enforce the same configuration for all hashes, so the next line should be fine

  const u64 size_per_accel = yescrypt_size_per_accel (hashes);

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u64 fixed_mem = (128 * 1024 * 1024); // some storage we need for pws[], tmps[], and others

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4)) - fixed_mem;

  u32 kernel_accel_new;

  if (kernel_accel_user)
  {
    kernel_accel_new = kernel_accel_user;
  }
  else
  {
    kernel_accel_new = (u32) (available_mem / size_per_accel);

    // there is no TMTO to fall back on here, so leave a margin rather than trying to reclaim it later

    kernel_accel_new = (kernel_accel_new * 94) / 100;

    kernel_accel_new = MIN (kernel_accel_new, YESCRYPT_ACCEL_MAX);

    // clamp if close to device processors, the same 16% rule the scrypt modes use

    if (kernel_accel_new > device_processors)
    {
      const u32 extra = kernel_accel_new % device_processors;

      if (extra < (u32) (device_processors * 0.16))
      {
        kernel_accel_new -= extra;
      }
    }

    kernel_accel_new = MAX (kernel_accel_new, 1);
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

u64 yescrypt_module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u64 size_per_accel = yescrypt_size_per_accel (hashes);

  const u64 size_yescrypt = device_param->kernel_accel_max * size_per_accel;

  return size_yescrypt;
}

u64 yescrypt_module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 0; // we'll add some later

  return tmp_size;
}

u64 yescrypt_module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, const u64 esalt_size)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  u32 ye_flags;
  u32 ye_t;

  yescrypt_esalt_params (hashes, esalt_size, 0, &ye_flags, &ye_t);

  // in general, since we compile the kernel based on N, r, p and the yescrypt flags, so the JIT can
  // optimize it, we can't have other configuration settings
  // we need to check that all hashes have the same settings

  for (u32 i = 1; i < hashes->salts_cnt; i++)
  {
    if ((scrypt_N != hashes->salts_buf[i].scrypt_N)
     || (scrypt_r != hashes->salts_buf[i].scrypt_r)
     || (scrypt_p != hashes->salts_buf[i].scrypt_p))
    {
      return (1ULL << 63) + i;
    }

    u32 ye_flags_i;
    u32 ye_t_i;

    yescrypt_esalt_params (hashes, esalt_size, hashes->salts_buf[i].digests_offset, &ye_flags_i, &ye_t_i);

    if ((ye_flags != ye_flags_i) || (ye_t != ye_t_i))
    {
      return (1ULL << 63) + i;
    }
  }

  // now that we know they all have the same settings, we also need to check the self-test hash is
  // different to what the user hash is using

  if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
  {
    if ((scrypt_N != hashes->st_salts_buf[0].scrypt_N)
     || (scrypt_r != hashes->st_salts_buf[0].scrypt_r)
     || (scrypt_p != hashes->st_salts_buf[0].scrypt_p))
    {
      return (1ULL << 62);
    }
  }

  // this is yescrypt_tmp_t in the kernel: the 128 * r state block, the Sbox, and the loop context

  const u64 tmp_size = (128ULL * scrypt_r) + YESCRYPT_SBOX_SZ + YESCRYPT_CTX_SZ;

  return tmp_size;
}

char *yescrypt_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param, const u64 esalt_size)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  u32 ye_flags;
  u32 ye_t;

  yescrypt_esalt_params (hashes, esalt_size, 0, &ye_flags, &ye_t);

  // The kernel only ever needs the rounded-up rw count. t is passed alongside it because it is what
  // the kernel cache key uses to tell two otherwise identical configurations apart.

  const u64 Nloop_all = yescrypt_calc_nloop_all (scrypt_N, scrypt_p, ye_t, ye_flags);

  const u64 Nloop_rw = ((ye_flags & YESCRYPT_FLAG_RW) != 0) ? (Nloop_all / scrypt_p) : 0;

  const u64 Nloop_rw_even = (Nloop_rw + 1) & ~(u64) 1;

  const u64 state_cnt4 = 32ULL * scrypt_r;

  // The Sbox and the X block move to local memory together whenever both fit. That is worth about
  // 39 percent, measured on an RX 9070 XT at the j9T parameters: 888 H/s with both in global memory
  // against 1237 H/s with both in local.

  const u64 lds_per_block = (128ULL * scrypt_r) + YESCRYPT_SBOX_SZ;

  const char *placement = (lds_per_block <= device_param->device_local_mem_size) ? " -D COOP_SBOX_LDS" : " -D COOP_X_GLOBAL";

  const u32 expected_threads = yescrypt_expected_threads (hashconfig, user_options, user_options_extra, device_param);

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options,
    "-D FIXED_LOCAL_SIZE=%u"
    " -D YESCRYPT_N=%u"
    " -D YESCRYPT_R=%u"
    " -D YESCRYPT_P=%u"
    " -D YESCRYPT_T=%u"
    " -D YESCRYPT_FLAGS=0x%03x"
    " -D YESCRYPT_NLOOP_RW=%" PRIu64
    " -D YESCRYPT_STATE_CNT4=%" PRIu64
    "%s",
    expected_threads,
    scrypt_N,
    scrypt_r,
    scrypt_p,
    ye_t,
    ye_flags,
    Nloop_rw_even,
    state_cnt4,
    placement);

  return jit_build_options;
}
