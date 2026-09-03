/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "system.h"
#include "thread.h"
#include "bitmap.h"

#define BITMAP_TABLE_CNT      8
#define BITMAP_BITS_PER_KEY   2

#define BITMAP_STAGES_TARGET  1.02

#define BITMAP_PENALTY_L1     1.00
#define BITMAP_PENALTY_CACHE  1.25
#define BITMAP_PENALTY_MEMORY 7.00

/* The cache and L1 tiers are blended continuously rather than switched at a
   threshold: a table that is slightly larger than a tier is slightly slower,
   not seven times slower. The knees are where each blend is half, measured on
   RTX 4090, RX 7900 XTX, Radeon Pro W7800, Radeon Pro W5700X and RTX A400. */

#define BITMAP_CACHE_KNEE     0.70
#define BITMAP_L1_KNEE        1.00
#define BITMAP_BLEND_ORDER    6

/* Several devices under-report their last level cache, or report none at all:
   RDNA3 hides Infinity Cache behind a 6 MB figure and Metal reports 0. Sizing
   against those numbers would confine the tables to a fraction of the cache
   that is really there, so treat this as the smallest cache worth believing. */

#define BITMAP_CACHE_FLOOR    (24 * 1024 * 1024)

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

// x^n / (x^n + knee^n), the fraction of accesses that miss a tier of this size

static double bitmap_blend (const double x, const double knee)
{
  double xn = 1.0;
  double kn = 1.0;

  for (u32 i = 0; i < BITMAP_BLEND_ORDER; i++)
  {
    xn *= x;
    kn *= knee;
  }

  return xn / (xn + kn);
}

static double bitmap_cost (const u64 digests_cnt, const u32 bitmap_bits, const u64 local_mem, const u64 cache_size)
{
  const double footprint = (double) bitmap_hot_bytes (digests_cnt, bitmap_bits);

  const double cache = (double) ((cache_size > BITMAP_CACHE_FLOOR) ? cache_size : BITMAP_CACHE_FLOOR);

  const double miss_l1    = (local_mem != 0) ? bitmap_blend (footprint / (double) local_mem, BITMAP_L1_KNEE) : 1.0;
  const double miss_cache = bitmap_blend (footprint / cache, BITMAP_CACHE_KNEE);

  const double penalty = BITMAP_PENALTY_L1
                       + ((BITMAP_PENALTY_CACHE  - BITMAP_PENALTY_L1)    * miss_l1)
                       + ((BITMAP_PENALTY_MEMORY - BITMAP_PENALTY_CACHE) * miss_cache);

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

    __atomic_or_fetch (&bitmap_tabs[t][ht & bitmap_mask], (1U << (pt & 31)) | (1U << ((pt >> 5) & 31)), __ATOMIC_RELAXED);
  }
}

// sort the updates into cache sized buckets before applying them
//
// a digest sets two bits in each of the eight tables at an index that is a hash of the whole digest,
// so on a list this size the updates walk over the tables at random and every one of them is a miss.
// counting them into buckets first, one per region of a table, means a region is read once, updated
// from its own bucket while it sits in cache, and written once. the bucket a thread applies is the
// only one touching that region, so nothing has to be atomic there.

#define BITMAP_REGION_BITS 16
#define BITMAP_RECORDS_MAX (256 * 1024 * 1024)
#define BITMAP_FILL_CHUNK_MIN (256 * 1024)

typedef struct bitmap_fill
{
  int          phase;

  u32        **bitmap_tabs;
  const char  *digests_buf;
  u32          dgst_size;
  u32          dgst_pos0;
  u32          dgst_pos1;
  u32          dgst_pos2;
  u32          dgst_pos3;
  u32          bitmap_mask;
  u32          from;
  u32          to;

  u32         *records;
  u32         *counts;
  u32         *cursor;
  const u32   *bucket_base;
  u32          region_bits;
  u32          regions;
  u32          buckets;
  u32          bucket_from;
  u32          bucket_to;

} bitmap_fill_t;

static void *generate_bitmaps_thread (void *p)
{
  bitmap_fill_t *param = (bitmap_fill_t *) p;

  u32 **bitmap_tabs = param->bitmap_tabs;

  if (param->phase == 0)
  {
    for (u32 t = 0; t < BITMAP_TABLE_CNT; t++)
    {
      memset (bitmap_tabs[t] + param->from, 0, (size_t) (param->to - param->from) * sizeof (u32));
    }

    return NULL;
  }

  if (param->phase == 4)
  {
    const u32 *records     = param->records;
    const u32 *bucket_base = param->bucket_base;

    const u32 region_bits = param->region_bits;
    const u32 regions     = param->regions;

    for (u32 b = param->bucket_from; b < param->bucket_to; b++)
    {
      u32 *tab = bitmap_tabs[b / regions] + ((u64) (b % regions) << region_bits);

      const u32 end = bucket_base[b + 1];

      for (u32 i = bucket_base[b]; i < end; i++)
      {
        const u32 record = records[i];

        const u32 pt = record & 0x3ff;

        tab[record >> 10] |= (1U << (pt & 31)) | (1U << ((pt >> 5) & 31));
      }
    }

    return NULL;
  }

  const u32 dgst_size   = param->dgst_size;
  const u32 bitmap_mask = param->bitmap_mask;

  const char *digests_buf_ptr = param->digests_buf + ((u64) param->from * dgst_size);

  if (param->phase == 1)
  {
    for (u32 i = param->from; i < param->to; i++)
    {
      const u32 *digest_ptr = (const u32 *) digests_buf_ptr;

      digests_buf_ptr += dgst_size;

      bitmap_set (bitmap_tabs, bitmap_mask, digest_ptr[param->dgst_pos0], digest_ptr[param->dgst_pos1], digest_ptr[param->dgst_pos2], digest_ptr[param->dgst_pos3]);
    }

    return NULL;
  }

  const u32 region_bits = param->region_bits;
  const u32 regions     = param->regions;
  const u32 region_mask = (1U << region_bits) - 1;

  if (param->phase == 2)
  {
    u32 *counts = param->counts;

    memset (counts, 0, (size_t) param->buckets * sizeof (u32));

    for (u32 i = param->from; i < param->to; i++)
    {
      const u32 *digest_ptr = (const u32 *) digests_buf_ptr;

      digests_buf_ptr += dgst_size;

      const u32 d0 = digest_ptr[param->dgst_pos0];
      const u32 d1 = digest_ptr[param->dgst_pos1];
      const u32 d2 = digest_ptr[param->dgst_pos2];
      const u32 d3 = digest_ptr[param->dgst_pos3];

      const u32 a = d0 ^ bitmap_rotl32 (d1, 11) ^ bitmap_rotl32 (d2, 22) ^ bitmap_rotl32 (d3,  5);
      const u32 b = d3 ^ bitmap_rotl32 (d2,  7) ^ bitmap_rotl32 (d1, 19) ^ bitmap_rotl32 (d0, 27);

      for (u32 t = 0; t < BITMAP_TABLE_CNT; t++)
      {
        const u32 idx = (a + (t * b)) & bitmap_mask;

        counts[(t * regions) + (idx >> region_bits)]++;
      }
    }

    return NULL;
  }

  u32 *records = param->records;
  u32 *cursor  = param->cursor;

  for (u32 i = param->from; i < param->to; i++)
  {
    const u32 *digest_ptr = (const u32 *) digests_buf_ptr;

    digests_buf_ptr += dgst_size;

    const u32 d0 = digest_ptr[param->dgst_pos0];
    const u32 d1 = digest_ptr[param->dgst_pos1];
    const u32 d2 = digest_ptr[param->dgst_pos2];
    const u32 d3 = digest_ptr[param->dgst_pos3];

    const u32 a = d0 ^ bitmap_rotl32 (d1, 11) ^ bitmap_rotl32 (d2, 22) ^ bitmap_rotl32 (d3,  5);
    const u32 b = d3 ^ bitmap_rotl32 (d2,  7) ^ bitmap_rotl32 (d1, 19) ^ bitmap_rotl32 (d0, 27);

    for (u32 t = 0; t < BITMAP_TABLE_CNT; t++)
    {
      const u32 idx = (a + (t * b)) & bitmap_mask;
      const u32 pt  = bitmap_rotl32 (b, ((t * 4) + 1)) ^ a;

      const u32 bucket = (t * regions) + (idx >> region_bits);

      records[cursor[bucket]] = ((idx & region_mask) << 10) | (pt & 0x3ff);

      cursor[bucket]++;
    }
  }

  return NULL;
}

static void generate_bitmaps_run (bitmap_fill_t *params, hc_thread_t *threads, const int threads_cnt, const int phase)
{
  for (int t = 0; t < threads_cnt; t++) params[t].phase = phase;

  int threads_live = 0;

  for (int t = 1; t < threads_cnt; t++)
  {
    // a failed create leaves the handle unset, and joining that is a crash rather than a
    // slow run. Do the chunk here instead, and keep the handles that did start packed at the
    // front so the join below has no gaps to step over.

    if (hc_thread_create_ok (threads[threads_live], generate_bitmaps_thread, &params[t]) == true)
    {
      threads_live++;
    }
    else
    {
      generate_bitmaps_thread (&params[t]);
    }
  }

  generate_bitmaps_thread (&params[0]);

  for (int t = 0; t < threads_live; t++)
  {
    hc_thread_join (threads[t]);
  }
}

static void generate_bitmaps_split (bitmap_fill_t *params, const int threads_cnt, const u32 base, const u32 count)
{
  const u64 chunk = ((u64) count + (u64) threads_cnt - 1) / (u64) threads_cnt;

  for (int t = 0; t < threads_cnt; t++)
  {
    u64 from = (u64) t * chunk;
    u64 to   = from + chunk;

    if (from > count) from = count;
    if (to   > count) to   = count;

    params[t].from = base + (u32) from;
    params[t].to   = base + (u32) to;
  }
}

static bool generate_bitmaps_blocked (bitmap_fill_t *params, hc_thread_t *threads, const int threads_cnt, const u32 digests_cnt, const u32 bitmap_bits)
{
  if (bitmap_bits <= BITMAP_REGION_BITS) return false;

  const u32 region_bits = BITMAP_REGION_BITS;
  const u32 regions     = 1U << (bitmap_bits - region_bits);
  const u32 buckets     = BITMAP_TABLE_CNT * regions;

  u32 chunk = BITMAP_RECORDS_MAX / (BITMAP_TABLE_CNT * sizeof (u32));

  if (chunk > digests_cnt) chunk = digests_cnt;

  const u64 records_size = (u64) chunk * BITMAP_TABLE_CNT * sizeof (u32);
  const u64 counts_size  = (u64) threads_cnt * buckets * sizeof (u32);

  u64 free_mem = 0;

  if (get_free_memory (&free_mem) == false) return false;
  if (free_mem <= (records_size + (counts_size * 2))) return false;

  u32 *records     = (u32 *) hcmalloc (records_size);
  u32 *counts      = (u32 *) hcmalloc (counts_size);
  u32 *cursor      = (u32 *) hcmalloc (counts_size);
  u32 *bucket_base = (u32 *) hcmalloc ((u64) (buckets + 1) * sizeof (u32));

  if ((records == NULL) || (counts == NULL) || (cursor == NULL) || (bucket_base == NULL))
  {
    hcfree (records);
    hcfree (counts);
    hcfree (cursor);
    hcfree (bucket_base);

    return false;
  }

  for (int t = 0; t < threads_cnt; t++)
  {
    params[t].records     = records;
    params[t].counts      = counts + ((size_t) t * buckets);
    params[t].cursor      = cursor + ((size_t) t * buckets);
    params[t].bucket_base = bucket_base;
    params[t].region_bits = region_bits;
    params[t].regions     = regions;
    params[t].buckets     = buckets;
  }

  for (u32 base = 0; base < digests_cnt; base += chunk)
  {
    u32 count = digests_cnt - base;

    if (count > chunk) count = chunk;

    generate_bitmaps_split (params, threads_cnt, base, count);

    generate_bitmaps_run (params, threads, threads_cnt, 2);

    u32 run = 0;

    for (u32 b = 0; b < buckets; b++)
    {
      bucket_base[b] = run;

      for (int t = 0; t < threads_cnt; t++)
      {
        cursor[((size_t) t * buckets) + b] = run;

        run += counts[((size_t) t * buckets) + b];
      }
    }

    bucket_base[buckets] = run;

    generate_bitmaps_run (params, threads, threads_cnt, 3);

    u32 b = 0;

    for (int t = 0; t < threads_cnt; t++)
    {
      const u32 target = (u32) (((u64) run * (u64) (t + 1)) / (u64) threads_cnt);

      params[t].bucket_from = b;

      while ((b < buckets) && (bucket_base[b] < target)) b++;

      params[t].bucket_to = b;
    }

    params[threads_cnt - 1].bucket_to = buckets;

    generate_bitmaps_run (params, threads, threads_cnt, 4);
  }

  hcfree (records);
  hcfree (counts);
  hcfree (cursor);
  hcfree (bucket_base);

  return true;
}

static void generate_bitmaps (const u32 digests_cnt, const u32 dgst_size, char *digests_buf_ptr, const u32 dgst_pos0, const u32 dgst_pos1, const u32 dgst_pos2, const u32 dgst_pos3, const u32 bitmap_nums, u32 **bitmap_tabs)
{
  u64 threads_cnt = (u64) hc_get_processor_count ();

  if (threads_cnt < 1) threads_cnt = 1;

  const u64 threads_max = ((u64) digests_cnt / BITMAP_FILL_CHUNK_MIN) + 1;

  if (threads_cnt > threads_max) threads_cnt = threads_max;

  hc_thread_t   *threads = (hc_thread_t *)   hcmalloc ((size_t) threads_cnt * sizeof (hc_thread_t));
  bitmap_fill_t *params  = (bitmap_fill_t *) hcmalloc ((size_t) threads_cnt * sizeof (bitmap_fill_t));

  u32 bitmap_bits = 0;

  while ((1U << bitmap_bits) < bitmap_nums) bitmap_bits++;

  if ((threads == NULL) || (params == NULL))
  {
    hcfree (threads);
    hcfree (params);

    for (u32 t = 0; t < BITMAP_TABLE_CNT; t++) memset (bitmap_tabs[t], 0, (size_t) bitmap_nums * sizeof (u32));

    const u32 bitmap_mask = bitmap_nums - 1;

    for (u32 i = 0; i < digests_cnt; i++)
    {
      const u32 *digest_ptr = (const u32 *) digests_buf_ptr;

      digests_buf_ptr += dgst_size;

      bitmap_set (bitmap_tabs, bitmap_mask, digest_ptr[dgst_pos0], digest_ptr[dgst_pos1], digest_ptr[dgst_pos2], digest_ptr[dgst_pos3]);
    }

    return;
  }

  for (u64 t = 0; t < threads_cnt; t++)
  {
    memset (&params[t], 0, sizeof (bitmap_fill_t));

    params[t].bitmap_tabs = bitmap_tabs;
    params[t].digests_buf = digests_buf_ptr;
    params[t].dgst_size   = dgst_size;
    params[t].dgst_pos0   = dgst_pos0;
    params[t].dgst_pos1   = dgst_pos1;
    params[t].dgst_pos2   = dgst_pos2;
    params[t].dgst_pos3   = dgst_pos3;
    params[t].bitmap_mask = bitmap_nums - 1;
  }

  generate_bitmaps_split (params, (int) threads_cnt, 0, bitmap_nums);

  generate_bitmaps_run (params, threads, (int) threads_cnt, 0);

  if (generate_bitmaps_blocked (params, threads, (int) threads_cnt, digests_cnt, bitmap_bits) == false)
  {
    generate_bitmaps_split (params, (int) threads_cnt, 0, digests_cnt);

    generate_bitmaps_run (params, threads, (int) threads_cnt, 1);
  }

  hcfree (threads);
  hcfree (params);
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
