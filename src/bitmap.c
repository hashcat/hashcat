/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "bitmap.h"

#define BITMAP_TABLE_CNT      8
#define BITMAP_BITS_PER_KEY   2

#define BITMAP_STAGES_TARGET  1.02

#define BITMAP_PENALTY_L1     1.00
#define BITMAP_PENALTY_CACHE  1.25
#define BITMAP_PENALTY_MEMORY 7.00

#define BITMAP_CACHE_SHARE    0.40

#define BITMAP_CACHE_TRUST    (16 * 1024 * 1024)

#define BITMAP_COST_MARGIN    0.99

#define BITMAP_MEMORY_SHARE   0.25

static double bitmap_exp_neg (const double x)
{
  double t = x;

  int m = 0;

  while (t > 0.125)
  {
    t *= 0.5;

    m++;
  }

  const double u = -t;

  double e = 1.0 + u * (1.0 + u / 2.0 * (1.0 + u / 3.0 * (1.0 + u / 4.0 * (1.0 + u / 5.0 * (1.0 + u / 6.0)))));

  for (int i = 0; i < m; i++) e = e * e;

  return e;
}

static double bitmap_stage_pass (const u64 digests_cnt, const u32 bitmap_bits)
{
  const double m = (double) (1ULL << (bitmap_bits + 5));

  const double x = ((double) BITMAP_BITS_PER_KEY * (double) digests_cnt) / m;

  const double f = 1.0 - bitmap_exp_neg (x);

  double s = 1.0;

  for (u32 i = 0; i < BITMAP_BITS_PER_KEY; i++) s *= f;

  return s;
}

static double bitmap_stages (const u64 digests_cnt, const u32 bitmap_bits)
{
  const double s = bitmap_stage_pass (digests_cnt, bitmap_bits);

  if (s > 0.999999) return (double) BITMAP_TABLE_CNT;

  double s_all = 1.0;

  for (u32 i = 0; i < BITMAP_TABLE_CNT; i++) s_all *= s;

  return (1.0 - s_all) / (1.0 - s);
}

static u64 bitmap_hot_bytes (const u64 digests_cnt, const u32 bitmap_bits)
{
  const double s = bitmap_stage_pass (digests_cnt, bitmap_bits);

  const double bytes = (double) ((u64) (1ULL << bitmap_bits) * sizeof (u32));

  return (u64) (bytes * (1.0 + s));
}

static u64 bitmap_device_cache_size (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx == NULL) return 0;
  if (backend_ctx->enabled == false) return 0;

  u64 cache_size = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

    if (device_param->skipped         == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (device_param->device_cache_size == 0) continue;

    if ((cache_size == 0) || (device_param->device_cache_size < cache_size)) cache_size = device_param->device_cache_size;
  }

  return cache_size;
}

static u64 bitmap_device_available_mem (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx == NULL) return 0;
  if (backend_ctx->enabled == false) return 0;

  u64 available_mem = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

    if (device_param->skipped         == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (device_param->device_available_mem == 0) continue;

    if ((available_mem == 0) || (device_param->device_available_mem < available_mem)) available_mem = device_param->device_available_mem;
  }

  return available_mem;
}

static u64 bitmap_device_local_mem (hashcat_ctx_t *hashcat_ctx)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx == NULL) return 0;
  if (backend_ctx->enabled == false) return 0;

  u64 local_mem = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    const hc_device_param_t *device_param = backend_ctx->devices_param + backend_devices_idx;

    if (device_param->skipped         == true) continue;
    if (device_param->skipped_warning == true) continue;

    if (device_param->device_local_mem_size == 0) continue;

    if ((local_mem == 0) || (device_param->device_local_mem_size < local_mem)) local_mem = device_param->device_local_mem_size;
  }

  return local_mem;
}

static double bitmap_search_cost (const u64 digests_cnt, const u32 bitmap_bits)
{
  const double s = bitmap_stage_pass (digests_cnt, bitmap_bits);

  double false_positive = 1.0;

  for (u32 i = 0; i < BITMAP_TABLE_CNT; i++) false_positive *= s;

  double steps = 1.0;

  for (u64 n = digests_cnt; n > 1; n >>= 1) steps += 1.0;

  return false_positive * steps * BITMAP_PENALTY_MEMORY;
}

static double bitmap_cost (const u64 digests_cnt, const u32 bitmap_bits, const u64 local_mem, const u64 cache_size)
{
  const u64 footprint = bitmap_hot_bytes (digests_cnt, bitmap_bits);

  double penalty = BITMAP_PENALTY_MEMORY;

  if (cache_size < BITMAP_CACHE_TRUST)
  {
    penalty = BITMAP_PENALTY_CACHE;
  }
  else if ((double) footprint <= ((double) cache_size * BITMAP_CACHE_SHARE))
  {
    penalty = BITMAP_PENALTY_CACHE;
  }

  if ((local_mem != 0) && (footprint <= local_mem)) penalty = BITMAP_PENALTY_L1;

  return (bitmap_stages (digests_cnt, bitmap_bits) * penalty) + bitmap_search_cost (digests_cnt, bitmap_bits);
}

static u32 bitmap_bits_auto (const u64 digests_cnt, const u64 cache_size, const u64 local_mem, const u64 available_mem, const u32 bitmap_min, const u32 bitmap_max, bool *overflow)
{
  u32 bitmap_top = bitmap_max;

  for (u32 bits = bitmap_min; bits <= bitmap_max; bits++)
  {
    if (bitmap_stages (digests_cnt, bits) <= BITMAP_STAGES_TARGET)
    {
      bitmap_top = bits;

      break;
    }
  }

  if (local_mem != 0)
  {
    for (u32 bits = bitmap_top; bits < bitmap_max; bits++)
    {
      if (bitmap_hot_bytes (digests_cnt, bits + 1) > local_mem) break;

      bitmap_top = bits + 1;
    }
  }

  double cost_best = bitmap_cost (digests_cnt, bitmap_min, local_mem, cache_size);

  for (u32 bits = bitmap_min + 1; bits <= bitmap_top; bits++)
  {
    const double cost = bitmap_cost (digests_cnt, bits, local_mem, cache_size);

    if (cost < cost_best) cost_best = cost;
  }

  u32 bitmap_bits = bitmap_min;

  for (u32 bits = bitmap_min; bits <= bitmap_top; bits++)
  {
    if (bitmap_cost (digests_cnt, bits, local_mem, cache_size) <= (cost_best / BITMAP_COST_MARGIN)) bitmap_bits = bits;
  }

  *overflow = ((bitmap_bits == bitmap_max) && (bitmap_stages (digests_cnt, bitmap_bits) > BITMAP_STAGES_TARGET));

  if (available_mem != 0)
  {
    while ((bitmap_bits > bitmap_min) && ((double) ((u64) BITMAP_TABLE_CNT * (1ULL << bitmap_bits) * sizeof (u32)) > ((double) available_mem * BITMAP_MEMORY_SHARE)))
    {
      bitmap_bits--;

      *overflow = false;
    }
  }

  return bitmap_bits;
}

static u32 bitmap_rotl32 (const u32 x, const u32 n)
{
  return (x << n) | (x >> (32 - n));
}

// must match check() in OpenCL/inc_common.cl, a mismatch is a silent false negative

static void bitmap_set (u32 **bitmap_tabs, const u32 bitmap_mask, const u32 d0, const u32 d1, const u32 d2, const u32 d3)
{
  const u32 a = d0 ^ bitmap_rotl32 (d1, 11) ^ bitmap_rotl32 (d2, 22) ^ bitmap_rotl32 (d3,  5);
  const u32 b = d3 ^ bitmap_rotl32 (d2,  7) ^ bitmap_rotl32 (d1, 19) ^ bitmap_rotl32 (d0, 27);

  for (u32 t = 0; t < BITMAP_TABLE_CNT; t++)
  {
    const u32 ht = a + (t * b);
    const u32 pt = bitmap_rotl32 (b, ((t * 4) + 1)) ^ a;

    bitmap_tabs[t][ht & bitmap_mask] |= (1U << (pt & 31)) | (1U << ((pt >> 5) & 31));
  }
}

static void generate_bitmaps (const u32 digests_cnt, const u32 dgst_size, char *digests_buf_ptr, const u32 dgst_pos0, const u32 dgst_pos1, const u32 dgst_pos2, const u32 dgst_pos3, const u32 bitmap_nums, u32 **bitmap_tabs)
{
  for (u32 t = 0; t < BITMAP_TABLE_CNT; t++) memset (bitmap_tabs[t], 0, (size_t) bitmap_nums * sizeof (u32));

  const u32 bitmap_mask = bitmap_nums - 1;

  for (u32 i = 0; i < digests_cnt; i++)
  {
    u32 *digest_ptr = (u32 *) digests_buf_ptr;

    digests_buf_ptr += dgst_size;

    bitmap_set (bitmap_tabs, bitmap_mask, digest_ptr[dgst_pos0], digest_ptr[dgst_pos1], digest_ptr[dgst_pos2], digest_ptr[dgst_pos3]);
  }
}

int bitmap_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes       = hashcat_ctx->hashes;
  bitmap_ctx_t   *bitmap_ctx   = hashcat_ctx->bitmap_ctx;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  bitmap_ctx->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->keyspace     == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;
  if (user_options->identify     == true) return 0;

  bitmap_ctx->enabled = true;

  /**
   * pick the table size
   */

  const u32 bitmap_shift1 = 5;
  const u32 bitmap_shift2 = 13;

  const u32 bitmap_min = user_options->bitmap_min;
  const u32 bitmap_max = user_options->bitmap_max;

  bool overflow = false;

  u32 bitmap_bits;

  if (bitmap_min >= bitmap_max)
  {
    bitmap_bits = bitmap_max;
  }
  else
  {
    bitmap_bits = bitmap_bits_auto (hashes->digests_cnt, bitmap_device_cache_size (hashcat_ctx), bitmap_device_local_mem (hashcat_ctx), bitmap_device_available_mem (hashcat_ctx), bitmap_min, bitmap_max, &overflow);
  }

  if (overflow == true)
  {
    EVENT_DATA (EVENT_BITMAP_FINAL_OVERFLOW, NULL, 0);
  }

  const u32 bitmap_nums = 1U << bitmap_bits;
  const u32 bitmap_mask = bitmap_nums - 1;
  const u32 bitmap_size = bitmap_nums * sizeof (u32);

  /**
   * generate bitmap tables
   */

  u32 *bitmap_s1_a = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s1_b = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s1_c = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s1_d = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s2_a = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s2_b = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s2_c = (u32 *) hcmalloc (bitmap_size);
  u32 *bitmap_s2_d = (u32 *) hcmalloc (bitmap_size);

  if (!bitmap_s1_a || !bitmap_s1_b || !bitmap_s1_c || !bitmap_s1_d || !bitmap_s2_a || !bitmap_s2_b || !bitmap_s2_c || !bitmap_s2_d) return -1;

  u32 *bitmap_tabs[BITMAP_TABLE_CNT] = { bitmap_s1_a, bitmap_s1_b, bitmap_s1_c, bitmap_s1_d, bitmap_s2_a, bitmap_s2_b, bitmap_s2_c, bitmap_s2_d };

  generate_bitmaps (hashes->digests_cnt, hashconfig->dgst_size, (char *) hashes->digests_buf, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, bitmap_nums, bitmap_tabs);

  if (hashconfig->st_hash != NULL)
  {
    u32 *st_ptr = (u32 *) hashes->st_digests_buf;

    bitmap_set (bitmap_tabs, bitmap_mask, st_ptr[hashconfig->dgst_pos0], st_ptr[hashconfig->dgst_pos1], st_ptr[hashconfig->dgst_pos2], st_ptr[hashconfig->dgst_pos3]);
  }

  bitmap_ctx->bitmap_bits   = bitmap_bits;
  bitmap_ctx->bitmap_nums   = bitmap_nums;
  bitmap_ctx->bitmap_size   = bitmap_size;
  bitmap_ctx->bitmap_mask   = bitmap_mask;
  bitmap_ctx->bitmap_shift1 = bitmap_shift1;
  bitmap_ctx->bitmap_shift2 = bitmap_shift2;

  bitmap_ctx->bitmap_s1_a   = bitmap_s1_a;
  bitmap_ctx->bitmap_s1_b   = bitmap_s1_b;
  bitmap_ctx->bitmap_s1_c   = bitmap_s1_c;
  bitmap_ctx->bitmap_s1_d   = bitmap_s1_d;
  bitmap_ctx->bitmap_s2_a   = bitmap_s2_a;
  bitmap_ctx->bitmap_s2_b   = bitmap_s2_b;
  bitmap_ctx->bitmap_s2_c   = bitmap_s2_c;
  bitmap_ctx->bitmap_s2_d   = bitmap_s2_d;

  return 0;
}

void bitmap_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  bitmap_ctx_t *bitmap_ctx = hashcat_ctx->bitmap_ctx;

  if (bitmap_ctx->enabled == false) return;

  hcfree (bitmap_ctx->bitmap_s1_a);
  hcfree (bitmap_ctx->bitmap_s1_b);
  hcfree (bitmap_ctx->bitmap_s1_c);
  hcfree (bitmap_ctx->bitmap_s1_d);
  hcfree (bitmap_ctx->bitmap_s2_a);
  hcfree (bitmap_ctx->bitmap_s2_b);
  hcfree (bitmap_ctx->bitmap_s2_c);
  hcfree (bitmap_ctx->bitmap_s2_d);

  memset (bitmap_ctx, 0, sizeof (bitmap_ctx_t));
}
