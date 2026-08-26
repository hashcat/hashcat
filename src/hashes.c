/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "debugfile.h"
#include "filehandling.h"
#include "hlfmt.h"
#include "terminal.h"
#include "logfile.h"
#include "loopback.h"
#include "backend.h"
#include "outfile.h"
#include "potfile.h"
#include "pubkey.h"
#include "rp.h"
#include "shared.h"
#include "path.h"
#include "parser.h"
#include "memchr.h"
#include "system.h"
#include "thread.h"
#include "locking.h"
#include "hashes.h"

#ifdef WITH_BRAIN
#include "brain.h"
#endif

int sort_by_digest_p0p1 (const void *v1, const void *v2, void *v3)
{
  const u32 *d1 = (const u32 *) v1;
  const u32 *d2 = (const u32 *) v2;

  hashconfig_t *hashconfig = (hashconfig_t *) v3;

  const u32 dgst_pos0 = hashconfig->dgst_pos0;
  const u32 dgst_pos1 = hashconfig->dgst_pos1;
  const u32 dgst_pos2 = hashconfig->dgst_pos2;
  const u32 dgst_pos3 = hashconfig->dgst_pos3;

  if (d1[dgst_pos3] > d2[dgst_pos3]) return  1;
  if (d1[dgst_pos3] < d2[dgst_pos3]) return -1;
  if (d1[dgst_pos2] > d2[dgst_pos2]) return  1;
  if (d1[dgst_pos2] < d2[dgst_pos2]) return -1;
  if (d1[dgst_pos1] > d2[dgst_pos1]) return  1;
  if (d1[dgst_pos1] < d2[dgst_pos1]) return -1;
  if (d1[dgst_pos0] > d2[dgst_pos0]) return  1;
  if (d1[dgst_pos0] < d2[dgst_pos0]) return -1;

  return 0;
}

typedef struct split_right
{
  int group;
  u32 index;

} split_right_t;

int sort_by_split_group (const void *v1, const void *v2)
{
  const split_right_t *r1 = (const split_right_t *) v1;
  const split_right_t *r2 = (const split_right_t *) v2;

  if (r1->group < r2->group) return -1;
  if (r1->group > r2->group) return  1;

  return 0;
}

int sort_by_salt (const void *v1, const void *v2)
{
  const salt_t *s1 = (const salt_t *) v1;
  const salt_t *s2 = (const salt_t *) v2;

  const int res_pos = (int) s1->orig_pos - (int) s2->orig_pos;

  if (res_pos != 0) return (res_pos);

  const int res1 = (int) s1->salt_len - (int) s2->salt_len;

  if (res1 != 0) return (res1);

  const int res2 = (int) s1->salt_iter - (int) s2->salt_iter;

  if (res2 != 0) return (res2);

  for (int n = 0; n < 64; n++)
  {
    if (s1->salt_buf[n] > s2->salt_buf[n]) return  1;
    if (s1->salt_buf[n] < s2->salt_buf[n]) return -1;
  }

  for (int n = 0; n < 64; n++)
  {
    if (s1->salt_buf_pc[n] > s2->salt_buf_pc[n]) return  1;
    if (s1->salt_buf_pc[n] < s2->salt_buf_pc[n]) return -1;
  }

  return 0;
}

int sort_by_hash (const void *v1, const void *v2, void *v3)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  hashconfig_t *hashconfig = (hashconfig_t *) v3;

  if (hashconfig->is_salted == true)
  {
    const salt_t *s1 = h1->salt;
    const salt_t *s2 = h2->salt;

    int res = sort_by_salt (s1, s2);

    if (res != 0) return (res);
  }

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2, v3);
}

int sort_by_hash_no_salt (const void *v1, const void *v2, void *v3)
{
  const hash_t *h1 = (const hash_t *) v1;
  const hash_t *h2 = (const hash_t *) v2;

  const void *d1 = h1->digest;
  const void *d2 = h2->digest;

  return sort_by_digest_p0p1 (d1, d2, v3);
}

// radix sort threshold: above this count, use radix sort instead of qsort for non-salted hashes

#define RADIX_SORT_THRESHOLD (1024 * 1024)

// in-place MSD radix sort on parallel (keys, indices) arrays
// sorts by 8-bit radix using American Flag sort partitioning

static void msd_radix_sort_u64 (u64 *keys, u32 *indices, const u32 count, const int byte_pos)
{
  if (count <= 64)
  {
    // insertion sort for small subarrays

    for (u32 i = 1; i < count; i++)
    {
      const u64 k = keys[i];
      const u32 d = indices[i];

      u32 j = i;

      while (j > 0 && keys[j - 1] > k)
      {
        keys[j]    = keys[j - 1];
        indices[j] = indices[j - 1];

        j--;
      }

      keys[j]    = k;
      indices[j] = d;
    }

    return;
  }

  // count occurrences of each byte value

  u32 counts[256];

  memset (counts, 0, sizeof (counts));

  for (u32 i = 0; i < count; i++)
  {
    const u8 b = (u8) (keys[i] >> (byte_pos * 8));

    counts[b]++;
  }

  // skip level if all elements fall in one bucket

  for (int b = 0; b < 256; b++)
  {
    if (counts[b] == count)
    {
      if (byte_pos > 0)
      {
        msd_radix_sort_u64 (keys, indices, count, byte_pos - 1);
      }

      return;
    }
  }

  // compute bucket start positions

  u32 offsets[256];
  u32 ends[256];

  offsets[0] = 0;

  for (int b = 1; b < 256; b++)
  {
    offsets[b] = offsets[b - 1] + counts[b - 1];
  }

  memcpy (ends, offsets, sizeof (offsets));

  // American Flag sort: in-place permutation via cycle following

  for (int b = 0; b < 256; b++)
  {
    const u32 limit = offsets[b] + counts[b];

    while (ends[b] < limit)
    {
      u8 target = (u8) (keys[ends[b]] >> (byte_pos * 8));

      if (target == (u8) b)
      {
        ends[b]++;

        continue;
      }

      // pick up displaced element and follow its chain

      u64 floating_key = keys[ends[b]];
      u32 floating_idx = indices[ends[b]];

      do
      {
        const u32 dest = ends[target];

        const u64 tmp_key = keys[dest];
        const u32 tmp_idx = indices[dest];

        keys[dest]    = floating_key;
        indices[dest] = floating_idx;

        floating_key = tmp_key;
        floating_idx = tmp_idx;

        ends[target]++;

        target = (u8) (floating_key >> (byte_pos * 8));

      } while (target != (u8) b);

      keys[ends[b]]    = floating_key;
      indices[ends[b]] = floating_idx;

      ends[b]++;
    }
  }

  // recurse on each non-trivial bucket

  if (byte_pos > 0)
  {
    for (int b = 0; b < 256; b++)
    {
      if (counts[b] > 1)
      {
        msd_radix_sort_u64 (keys + offsets[b], indices + offsets[b], counts[b], byte_pos - 1);
      }
    }
  }
}

// gather hashes_buf and digests_buf into fresh buffers, one disjoint destination slice per thread
// after this, hashes_buf[i] = original hashes_buf[indices[i]]

typedef struct hash_gather
{
  int           phase;

  hash_t       *dst_hashes;
  const hash_t *src_hashes;
  char         *dst_digests;
  const char   *src_digests;
  const u32    *indices;
  hash_t        entry;
  u32           dgst_size;
  u32           idx_from;
  u32           idx_to;

} hash_gather_t;

static void *apply_permutation_thread (void *p)
{
  hash_gather_t *param = (hash_gather_t *) p;

  const u32 *indices = param->indices;

  if (param->phase == 0)
  {
    hash_t       *dst_hashes = param->dst_hashes;
    const hash_t *src_hashes = param->src_hashes;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      dst_hashes[i] = src_hashes[indices[i]];
    }
  }
  else if (param->phase == 1)
  {
    hash_t     *dst_hashes  = param->dst_hashes;
    char       *dst_digests = param->dst_digests;
    const char *src_digests = param->src_digests;

    const u32 dgst_size = param->dgst_size;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      char *dst_ptr = dst_digests + ((u64) i * dgst_size);

      memcpy (dst_ptr, src_digests + ((u64) indices[i] * dgst_size), dgst_size);

      dst_hashes[i].digest = dst_ptr;
    }
  }
  else
  {
    hash_t     *dst_hashes  = param->dst_hashes;
    char       *dst_digests = param->dst_digests;
    const char *src_digests = param->src_digests;

    const hash_t entry = param->entry;

    const u32 dgst_size = param->dgst_size;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      char *dst_ptr = dst_digests + ((u64) i * dgst_size);

      memcpy (dst_ptr, src_digests + ((u64) indices[i] * dgst_size), dgst_size);

      dst_hashes[i] = entry;

      dst_hashes[i].digest        = dst_ptr;
      dst_hashes[i].orig_line_pos = indices[i];
    }
  }

  return NULL;
}

#define HASH_GATHER_CHUNK_MIN (256 * 1024)

static void apply_permutation_run (const hash_gather_t *tmpl, const u32 count)
{
  u64 threads_cnt = (u64) hc_get_processor_count ();

  if (threads_cnt < 1) threads_cnt = 1;

  const u64 threads_max = ((u64) count / HASH_GATHER_CHUNK_MIN) + 1;

  if (threads_cnt > threads_max) threads_cnt = threads_max;

  hc_thread_t   *threads = (hc_thread_t *)   hcmalloc ((size_t) threads_cnt * sizeof (hc_thread_t));
  hash_gather_t *params  = (hash_gather_t *) hcmalloc ((size_t) threads_cnt * sizeof (hash_gather_t));

  if ((threads == NULL) || (params == NULL))
  {
    hcfree (threads);
    hcfree (params);

    hash_gather_t single = *tmpl;

    single.idx_from = 0;
    single.idx_to   = count;

    apply_permutation_thread (&single);

    return;
  }

  const u64 chunk = ((u64) count + threads_cnt - 1) / threads_cnt;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    u64 idx_from = t * chunk;
    u64 idx_to   = idx_from + chunk;

    if (idx_from > count) idx_from = count;
    if (idx_to   > count) idx_to   = count;

    params[t] = *tmpl;

    params[t].idx_from = (u32) idx_from;
    params[t].idx_to   = (u32) idx_to;
  }

  for (u64 t = 1; t < threads_cnt; t++)
  {
    hc_thread_create (threads[t], apply_permutation_thread, &params[t]);
  }

  apply_permutation_thread (&params[0]);

  for (u64 t = 1; t < threads_cnt; t++)
  {
    hc_thread_join (threads[t]);
  }

  hcfree (threads);
  hcfree (params);
}

// the top level of the radix sort, run on every core
//
// one pass over the keys per thread builds a histogram of the byte being sorted on, the prefix sums
// of those give every thread a private write cursor per bucket, and the buckets that come out are
// independent, so the levels below them are sorted one bucket per thread.

#define RADIX_PARALLEL_CHUNK (256 * 1024)

typedef struct radix_part
{
  int        phase;

  u64       *keys;
  u32       *indices;
  u64       *keys_out;
  u32       *indices_out;

  const hash_t *hashes_buf;

  u32        dgst_pos2;
  u32        dgst_pos3;

  int        byte_pos;

  u32        idx_from;
  u32        idx_to;

  u32        bucket_from;
  u32        bucket_to;

  const u32 *bucket_offsets;
  const u32 *bucket_counts;

  u32        counts[256];
  u32        offsets[256];

} radix_part_t;

static void *radix_sort_thread (void *p)
{
  radix_part_t *param = (radix_part_t *) p;

  if (param->phase == 3)
  {
    const hash_t *hashes_buf = param->hashes_buf;

    const u32 dgst_pos2 = param->dgst_pos2;
    const u32 dgst_pos3 = param->dgst_pos3;

    u64 *keys    = param->keys;
    u32 *indices = param->indices;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      const u32 *d = (const u32 *) hashes_buf[i].digest;

      keys[i]    = ((u64) d[dgst_pos3] << 32) | (u64) d[dgst_pos2];
      indices[i] = i;
    }

    return NULL;
  }

  const int shift = param->byte_pos * 8;

  if (param->phase == 0)
  {
    const u64 *keys = param->keys;

    memset (param->counts, 0, sizeof (param->counts));

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      param->counts[(u8) (keys[i] >> shift)]++;
    }

    return NULL;
  }

  if (param->phase == 1)
  {
    const u64 *keys    = param->keys;
    const u32 *indices = param->indices;

    u64 *keys_out    = param->keys_out;
    u32 *indices_out = param->indices_out;

    u32 *offsets = param->offsets;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      const u8 b = (u8) (keys[i] >> shift);

      const u32 pos = offsets[b];

      offsets[b] = pos + 1;

      keys_out[pos]    = keys[i];
      indices_out[pos] = indices[i];
    }

    return NULL;
  }

  for (u32 b = param->bucket_from; b < param->bucket_to; b++)
  {
    if (param->bucket_counts[b] > 1)
    {
      msd_radix_sort_u64 (param->keys_out + param->bucket_offsets[b], param->indices_out + param->bucket_offsets[b], param->bucket_counts[b], param->byte_pos - 1);
    }
  }

  return NULL;
}

static void radix_sort_run (radix_part_t *params, hc_thread_t *threads, const int threads_cnt, const int phase)
{
  for (int t = 0; t < threads_cnt; t++) params[t].phase = phase;

  for (int t = 1; t < threads_cnt; t++)
  {
    hc_thread_create (threads[t], radix_sort_thread, &params[t]);
  }

  radix_sort_thread (&params[0]);

  for (int t = 1; t < threads_cnt; t++)
  {
    hc_thread_join (threads[t]);
  }
}

static bool hc_radix_sort_parallel (u64 **keys_ptr, u32 **indices_ptr, const u32 count, const hash_t *hashes_buf, const u32 dgst_pos2, const u32 dgst_pos3)
{
  u64 threads_cnt = (u64) hc_get_processor_count ();

  if (threads_cnt < 1) threads_cnt = 1;

  const u64 threads_max = ((u64) count / RADIX_PARALLEL_CHUNK) + 1;

  if (threads_cnt > threads_max) threads_cnt = threads_max;

  if (threads_cnt < 2) return false;

  const u64 scratch_size = ((u64) count * sizeof (u64)) + ((u64) count * sizeof (u32));

  u64 free_mem = 0;

  if (get_free_memory (&free_mem) == false) return false;
  if (free_mem <= scratch_size) return false;

  u64          *keys_out    = (u64 *)          hcmalloc ((u64) count * sizeof (u64));
  u32          *indices_out = (u32 *)          hcmalloc ((u64) count * sizeof (u32));
  radix_part_t *params      = (radix_part_t *) hcmalloc ((size_t) threads_cnt * sizeof (radix_part_t));
  hc_thread_t  *threads     = (hc_thread_t *)  hcmalloc ((size_t) threads_cnt * sizeof (hc_thread_t));

  if ((keys_out == NULL) || (indices_out == NULL) || (params == NULL) || (threads == NULL))
  {
    hcfree (keys_out);
    hcfree (indices_out);
    hcfree (params);
    hcfree (threads);

    return false;
  }

  u64 *keys    = *keys_ptr;
  u32 *indices = *indices_ptr;

  const u64 chunk = ((u64) count + threads_cnt - 1) / threads_cnt;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    u64 idx_from = t * chunk;
    u64 idx_to   = idx_from + chunk;

    if (idx_from > count) idx_from = count;
    if (idx_to   > count) idx_to   = count;

    memset (&params[t], 0, sizeof (radix_part_t));

    params[t].keys        = keys;
    params[t].indices     = indices;
    params[t].keys_out    = keys_out;
    params[t].indices_out = indices_out;
    params[t].hashes_buf  = hashes_buf;
    params[t].dgst_pos2   = dgst_pos2;
    params[t].dgst_pos3   = dgst_pos3;
    params[t].idx_from    = (u32) idx_from;
    params[t].idx_to      = (u32) idx_to;
  }

  if (hashes_buf != NULL) radix_sort_run (params, threads, (int) threads_cnt, 3);

  // the byte to split on is the highest one that is not the same in every key, which is what the
  // single threaded sort finds by skipping a level whose bucket holds everything

  int byte_pos = 7;

  u32 bucket_counts[256];

  for (;;)
  {
    for (u64 t = 0; t < threads_cnt; t++) params[t].byte_pos = byte_pos;

    radix_sort_run (params, threads, (int) threads_cnt, 0);

    memset (bucket_counts, 0, sizeof (bucket_counts));

    for (u64 t = 0; t < threads_cnt; t++)
    {
      for (int b = 0; b < 256; b++) bucket_counts[b] += params[t].counts[b];
    }

    bool one_bucket = false;

    for (int b = 0; b < 256; b++)
    {
      if (bucket_counts[b] == count) one_bucket = true;
    }

    if ((one_bucket == false) || (byte_pos == 0)) break;

    byte_pos--;
  }

  u32 bucket_offsets[256];

  bucket_offsets[0] = 0;

  for (int b = 1; b < 256; b++) bucket_offsets[b] = bucket_offsets[b - 1] + bucket_counts[b - 1];

  u32 cursor[256];

  memcpy (cursor, bucket_offsets, sizeof (cursor));

  for (u64 t = 0; t < threads_cnt; t++)
  {
    for (int b = 0; b < 256; b++)
    {
      params[t].offsets[b] = cursor[b];

      cursor[b] += params[t].counts[b];
    }
  }

  radix_sort_run (params, threads, (int) threads_cnt, 1);

  if (byte_pos > 0)
  {
    u32 b = 0;

    for (u64 t = 0; t < threads_cnt; t++)
    {
      const u32 target = (u32) (((u64) count * (t + 1)) / threads_cnt);

      params[t].bucket_from    = b;
      params[t].bucket_offsets = bucket_offsets;
      params[t].bucket_counts  = bucket_counts;

      while ((b < 256) && (bucket_offsets[b] < target)) b++;

      params[t].bucket_to = b;
    }

    params[threads_cnt - 1].bucket_to = 256;

    radix_sort_run (params, threads, (int) threads_cnt, 2);
  }

  hcfree (keys);
  hcfree (indices);
  hcfree (params);
  hcfree (threads);

  *keys_ptr    = keys_out;
  *indices_ptr = indices_out;

  return true;
}

// apply permutation to hashes_buf (and optionally digests_buf) in-place using cycle following
// after this, hashes_buf[i] = original hashes_buf[indices[i]]
// if digests_buf is non-NULL, also permutes digest entries and updates digest pointers
// indices array is destroyed (used as visited markers)

static void apply_permutation_hash_inplace (hash_t *hashes_buf, u32 *indices, const u32 count, void *digests_buf, const u32 dgst_size)
{
  char *dbase = (char *) digests_buf;

  for (u32 i = 0; i < count; i++)
  {
    if (indices[i] == i) continue;

    hash_t tmp_h;

    memcpy (&tmp_h, &hashes_buf[i], sizeof (hash_t));

    u8 tmp_d[256]; // max dgst_size is DGST_SIZE_4_64 = 256

    if (dbase != NULL)
    {
      memcpy (tmp_d, dbase + (u64) i * dgst_size, dgst_size);
    }

    u32 j = i;

    while (indices[j] != i)
    {
      const u32 k = indices[j];

      memcpy (&hashes_buf[j], &hashes_buf[k], sizeof (hash_t));

      if (dbase != NULL)
      {
        memcpy (dbase + (u64) j * dgst_size, dbase + (u64) k * dgst_size, dgst_size);
      }

      indices[j] = j;

      j = k;
    }

    memcpy (&hashes_buf[j], &tmp_h, sizeof (hash_t));

    if (dbase != NULL)
    {
      memcpy (dbase + (u64) j * dgst_size, tmp_d, dgst_size);
    }

    indices[j] = j;
  }

  if (dbase != NULL)
  {
    for (u32 i = 0; i < count; i++)
    {
      hashes_buf[i].digest = dbase + (u64) i * dgst_size;
    }
  }
}

static void apply_permutation_hash (hash_t **hashes_buf_ptr, u32 *indices, const u32 count, void **digests_buf_ptr, const u32 dgst_size, const bool uniform)
{
  hash_t *src_hashes = *hashes_buf_ptr;

  char *src_digests = (digests_buf_ptr != NULL) ? (char *) *digests_buf_ptr : NULL;

  u64 free_mem = 0;

  // every hash_t in a list of this shape holds the same thing except its digest pointer and the line
  // it came from, so nothing has to be read out of hashes_buf to write it back in the new order

  if ((uniform == true) && (src_digests != NULL) && (count > 0))
  {
    const u64 digests_size = (u64) count * dgst_size;

    if ((get_free_memory (&free_mem) == true) && (free_mem > digests_size))
    {
      char *dst_digests = (char *) hcmalloc (digests_size);

      if (dst_digests != NULL)
      {
        hash_gather_t tmpl;

        memset (&tmpl, 0, sizeof (hash_gather_t));

        tmpl.phase       = 2;
        tmpl.dst_hashes  = src_hashes;
        tmpl.dst_digests = dst_digests;
        tmpl.src_digests = src_digests;
        tmpl.indices     = indices;
        tmpl.entry       = src_hashes[0];
        tmpl.dgst_size   = dgst_size;

        apply_permutation_run (&tmpl, count);

        hcfree (src_digests);

        *digests_buf_ptr = dst_digests;

        return;
      }
    }
  }

  const u64 gather_size = ((u64) count * sizeof (hash_t)) + ((src_digests != NULL) ? ((u64) count * dgst_size) : 0);

  if ((get_free_memory (&free_mem) == true) && (free_mem > gather_size))
  {
    hash_t *dst_hashes  = (hash_t *) hcmalloc ((u64) count * sizeof (hash_t));
    char   *dst_digests = NULL;

    if (src_digests != NULL) dst_digests = (char *) hcmalloc ((u64) count * dgst_size);

    if ((dst_hashes != NULL) && ((src_digests == NULL) || (dst_digests != NULL)))
    {
      hash_gather_t tmpl;

      memset (&tmpl, 0, sizeof (hash_gather_t));

      tmpl.phase      = 0;
      tmpl.dst_hashes = dst_hashes;
      tmpl.src_hashes = src_hashes;
      tmpl.indices    = indices;

      apply_permutation_run (&tmpl, count);

      hcfree (src_hashes);

      *hashes_buf_ptr = dst_hashes;

      if (src_digests != NULL)
      {
        memset (&tmpl, 0, sizeof (hash_gather_t));

        tmpl.phase       = 1;
        tmpl.dst_hashes  = dst_hashes;
        tmpl.dst_digests = dst_digests;
        tmpl.src_digests = src_digests;
        tmpl.indices     = indices;
        tmpl.dgst_size   = dgst_size;

        apply_permutation_run (&tmpl, count);

        hcfree (src_digests);

        *digests_buf_ptr = dst_digests;
      }

      return;
    }

    hcfree (dst_hashes);
    hcfree (dst_digests);
  }

  apply_permutation_hash_inplace (src_hashes, indices, count, src_digests, dgst_size);
}

// tie-break: runs longer than this are sorted with hc_qsort_r instead of insertion sort
// keeps insertion sort for the common (tiny) runs while avoiding O(m^2) blowup on
// hash types where dgst_pos2/dgst_pos3 are constant (e.g. LM, Half MD5) and every key is equal

#define RADIX_TIE_QSORT_THRESHOLD 256

typedef struct radix_tie_ctx
{
  const hash_t *hashes_buf;
  u32           dgst_pos0;
  u32           dgst_pos1;

} radix_tie_ctx_t;

// compare two index values by their digest's (dgst_pos1, dgst_pos0)
// used only within a tied run, where dgst_pos3/dgst_pos2 are already equal

static int sort_by_digest_idx_p1p0 (const void *v1, const void *v2, void *v3)
{
  const u32 idx1 = *(const u32 *) v1;
  const u32 idx2 = *(const u32 *) v2;

  const radix_tie_ctx_t *ctx = (const radix_tie_ctx_t *) v3;

  const u32 *d1 = (const u32 *) ctx->hashes_buf[idx1].digest;
  const u32 *d2 = (const u32 *) ctx->hashes_buf[idx2].digest;

  if (d1[ctx->dgst_pos1] > d2[ctx->dgst_pos1]) return  1;
  if (d1[ctx->dgst_pos1] < d2[ctx->dgst_pos1]) return -1;
  if (d1[ctx->dgst_pos0] > d2[ctx->dgst_pos0]) return  1;
  if (d1[ctx->dgst_pos0] < d2[ctx->dgst_pos0]) return -1;

  return 0;
}

// radix sort for non-salted hash lists
// uses compact key+index arrays to minimize memory and maximize cache efficiency
// returns 0 on success, -1 on allocation failure

static int hc_radix_sort_by_digest (hash_t **hashes_buf_ptr, u32 *hashes_cnt_ptr, const hashconfig_t *hashconfig, void **digests_buf_ptr, const u32 dgst_size)
{
  hash_t *hashes_buf = *hashes_buf_ptr;

  const u32 hashes_cnt = *hashes_cnt_ptr;

  const bool uniform = ((hashconfig->is_salted == false) && (hashes_cnt > 0) && (hashes_buf[0].hash_info == NULL));

  const u32 dgst_pos0 = hashconfig->dgst_pos0;
  const u32 dgst_pos1 = hashconfig->dgst_pos1;
  const u32 dgst_pos2 = hashconfig->dgst_pos2;
  const u32 dgst_pos3 = hashconfig->dgst_pos3;

  u64 *keys    = (u64 *) hcmalloc (((u64) hashes_cnt) * sizeof (u64));

  if (keys == NULL) return -1;

  u32 *indices = (u32 *) hcmalloc (((u64) hashes_cnt) * sizeof (u32));

  if (indices == NULL)
  {
    hcfree (keys);

    return -1;
  }

  // MSD radix sort on compact arrays

  if (hc_radix_sort_parallel (&keys, &indices, hashes_cnt, hashes_buf, dgst_pos2, dgst_pos3) == false)
  {
    for (u32 i = 0; i < hashes_cnt; i++)
    {
      const u32 *d = (const u32 *) hashes_buf[i].digest;

      keys[i]    = ((u64) d[dgst_pos3] << 32) | (u64) d[dgst_pos2];
      indices[i] = i;
    }

    msd_radix_sort_u64 (keys, indices, hashes_cnt, 7);
  }

  // resolve ties (same dgst_pos3+dgst_pos2, different dgst_pos1+dgst_pos0)
  // for uniformly distributed digests this is near-zero work

  for (u32 i = 0; i < hashes_cnt; )
  {
    u32 j = i + 1;

    while (j < hashes_cnt && keys[j] == keys[i]) j++;

    if (j - i > RADIX_TIE_QSORT_THRESHOLD)
    {
      // large tied run (dgst_pos3/dgst_pos2 constant across many hashes):
      // insertion sort would be O(m^2), fall back to qsort on the index slice.
      // keys[i..j) are all equal here, so only indices[] need reordering.

      radix_tie_ctx_t ctx = { hashes_buf, dgst_pos0, dgst_pos1 };

      hc_qsort_r (&indices[i], j - i, sizeof (u32), sort_by_digest_idx_p1p0, &ctx);
    }
    else if (j - i > 1)
    {
      // sub-sort this run by dgst_pos1, dgst_pos0 using insertion sort

      for (u32 a = i + 1; a < j; a++)
      {
        const u32  idx_a = indices[a];
        const u64  key_a = keys[a];
        const u32 *da    = (const u32 *) hashes_buf[idx_a].digest;
        const u64  sub_a = ((u64) da[dgst_pos1] << 32) | (u64) da[dgst_pos0];

        u32 b = a;

        while (b > i)
        {
          const u32 *db    = (const u32 *) hashes_buf[indices[b - 1]].digest;
          const u64  sub_b = ((u64) db[dgst_pos1] << 32) | (u64) db[dgst_pos0];

          if (sub_b <= sub_a) break;

          keys[b]    = keys[b - 1];
          indices[b] = indices[b - 1];

          b--;
        }

        keys[b]    = key_a;
        indices[b] = idx_a;
      }
    }

    i = j;
  }

  // dedup - remove adjacent duplicates in sorted compact arrays
  // sequential scan on keys[] (in RAM), near-zero random I/O

  if (hashconfig->potfile_keep_all_hashes == false)
  {
    u32 write_pos = 1;

    for (u32 i = 1; i < hashes_cnt; i++)
    {
      bool is_dup = false;

      if (keys[i] == keys[write_pos - 1])
      {
        const u32 *da = (const u32 *) hashes_buf[indices[i]].digest;
        const u32 *db = (const u32 *) hashes_buf[indices[write_pos - 1]].digest;

        if (da[dgst_pos1] == db[dgst_pos1] && da[dgst_pos0] == db[dgst_pos0])
        {
          is_dup = true;
        }
      }

      if (is_dup == false)
      {
        keys[write_pos]    = keys[i];
        indices[write_pos] = indices[i];

        write_pos++;
      }
    }

    if (write_pos < hashes_cnt)
    {
      // duplicates found - build full permutation for correct in-place reordering
      // reuse keys[] (8 bytes each >= 4 bytes needed) as reverse mapping scratch

      u32 *rev_map = (u32 *) keys;

      for (u32 i = 0; i < hashes_cnt; i++) rev_map[i] = UINT32_MAX;

      for (u32 i = 0; i < write_pos; i++)
      {
        rev_map[indices[i]] = i;
      }

      // assign unused source positions to remaining destination slots

      u32 next_slot = write_pos;

      for (u32 i = 0; i < hashes_cnt; i++)
      {
        if (rev_map[i] == UINT32_MAX)
        {
          rev_map[i] = next_slot++;
        }
      }

      // invert: indices[new_pos] = old_pos

      for (u32 i = 0; i < hashes_cnt; i++)
      {
        indices[rev_map[i]] = i;
      }

      hcfree (keys);

      apply_permutation_hash (hashes_buf_ptr, indices, hashes_cnt, digests_buf_ptr, dgst_size, uniform);

      hashes_buf = *hashes_buf_ptr;

      for (u32 i = write_pos; i < hashes_cnt; i++)
      {
        memset (&hashes_buf[i], 0, sizeof (hash_t));
      }

      hcfree (indices);

      *hashes_cnt_ptr = write_pos;

      return 0;
    }
  }

  hcfree (keys);

  // apply permutation to hashes_buf and digests_buf

  apply_permutation_hash (hashes_buf_ptr, indices, hashes_cnt, digests_buf_ptr, dgst_size, uniform);

  hcfree (indices);

  return 0;
}

// sort a salted hash list with the radix sort
//
// sort_by_hash orders by the salt first and by the digest within it, and comparing two salts is a
// walk over 512 bytes that the sort pays for on nearly every comparison. whenever the fields in
// front of them are the same for every hash in the list, the leading words of the salt decide the
// order on their own, and that makes a compact key the radix sort can group by. what comes out is
// one run per salt, every hash in a run carries the same salt, and inside a run what is left is the
// digest sort the unsalted path already does.

#define RADIX_SALT_KEY_NONE 0
#define RADIX_SALT_KEY_BUF  1
#define RADIX_SALT_KEY_LEN  2
#define RADIX_SALT_KEY_ITER 3

typedef struct salt_sort
{
  int        phase;

  hash_t    *hashes_buf;
  hash_t    *dst_hashes;

  u64       *keys;
  u32       *indices;

  u32        dgst_pos0;
  u32        dgst_pos1;
  u32        dgst_pos2;
  u32        dgst_pos3;

  int        key_kind;

  u32        idx_from;
  u32        idx_to;

  const hashconfig_t *hashconfig;

  const u32 *runs;
  u32        run_from;
  u32        run_to;

  bool       orig_pos_varies;
  bool       salt_len_varies;
  bool       salt_iter_varies;

} salt_sort_t;

typedef struct salt_tie_ctx
{
  const hash_t       *hashes_buf;
  const hashconfig_t *hashconfig;

} salt_tie_ctx_t;

static int sort_by_hash_idx (const void *v1, const void *v2, void *v3)
{
  const u32 idx1 = *(const u32 *) v1;
  const u32 idx2 = *(const u32 *) v2;

  const salt_tie_ctx_t *ctx = (const salt_tie_ctx_t *) v3;

  return sort_by_hash (&ctx->hashes_buf[idx1], &ctx->hashes_buf[idx2], (void *) ctx->hashconfig);
}

static u64 salt_sort_key (const salt_t *salt, const int key_kind)
{
  if (key_kind == RADIX_SALT_KEY_LEN)  return (((u64) salt->salt_len)  << 32) | (u64) salt->salt_buf[0];
  if (key_kind == RADIX_SALT_KEY_ITER) return (((u64) salt->salt_iter) << 32) | (u64) salt->salt_buf[0];

  return (((u64) salt->salt_buf[0]) << 32) | (u64) salt->salt_buf[1];
}

static void *salt_sort_thread (void *p)
{
  salt_sort_t *param = (salt_sort_t *) p;

  hash_t *hashes_buf = param->hashes_buf;

  if (param->phase == 0)
  {
    const salt_t *first = hashes_buf[0].salt;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      const salt_t *salt = hashes_buf[i].salt;

      if (salt->orig_pos  != first->orig_pos)  param->orig_pos_varies  = true;
      if (salt->salt_len  != first->salt_len)  param->salt_len_varies  = true;
      if (salt->salt_iter != first->salt_iter) param->salt_iter_varies = true;
    }

    return NULL;
  }

  if (param->phase == 1)
  {
    u64 *keys    = param->keys;
    u32 *indices = param->indices;

    const int key_kind = param->key_kind;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      keys[i]    = salt_sort_key (hashes_buf[i].salt, key_kind);
      indices[i] = i;
    }

    return NULL;
  }

  if (param->phase == 2)
  {
    u64 *keys = param->keys;

    const u32 *indices = param->indices;

    const u32 dgst_pos2 = param->dgst_pos2;
    const u32 dgst_pos3 = param->dgst_pos3;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      const u32 *d = (const u32 *) hashes_buf[indices[i]].digest;

      keys[i] = ((u64) d[dgst_pos3] << 32) | (u64) d[dgst_pos2];
    }

    return NULL;
  }

  if (param->phase == 3)
  {
    u64 *keys    = param->keys;
    u32 *indices = param->indices;

    const u32 *runs = param->runs;

    radix_tie_ctx_t ctx = { hashes_buf, param->dgst_pos0, param->dgst_pos1 };

    salt_tie_ctx_t salt_ctx = { hashes_buf, param->hashconfig };

    for (u32 r = param->run_from; r < param->run_to; r++)
    {
      const u32 from = runs[r];
      const u32 to   = runs[r + 1];

      if ((to - from) < 2) continue;

      // every hash in a run carries the same salt unless the key could not tell two of them apart,
      // and then the whole comparator settles that run

      bool salt_same = true;

      const salt_t *first = hashes_buf[indices[from]].salt;

      for (u32 i = from + 1; i < to; i++)
      {
        if (sort_by_salt (hashes_buf[indices[i]].salt, first) != 0)
        {
          salt_same = false;

          break;
        }
      }

      if (salt_same == false)
      {
        hc_qsort_r (&indices[from], to - from, sizeof (u32), sort_by_hash_idx, &salt_ctx);

        continue;
      }

      msd_radix_sort_u64 (keys + from, indices + from, to - from, 7);

      for (u32 i = from; i < to; )
      {
        u32 j = i + 1;

        while ((j < to) && (keys[j] == keys[i])) j++;

        if ((j - i) > RADIX_TIE_QSORT_THRESHOLD)
        {
          hc_qsort_r (&indices[i], j - i, sizeof (u32), sort_by_digest_idx_p1p0, &ctx);
        }
        else if ((j - i) > 1)
        {
          for (u32 a = i + 1; a < j; a++)
          {
            const u32  idx_a = indices[a];
            const u32 *da    = (const u32 *) hashes_buf[idx_a].digest;
            const u64  sub_a = ((u64) da[param->dgst_pos1] << 32) | (u64) da[param->dgst_pos0];

            u32 b = a;

            while (b > i)
            {
              const u32 *db    = (const u32 *) hashes_buf[indices[b - 1]].digest;
              const u64  sub_b = ((u64) db[param->dgst_pos1] << 32) | (u64) db[param->dgst_pos0];

              if (sub_b <= sub_a) break;

              indices[b] = indices[b - 1];

              b--;
            }

            indices[b] = idx_a;
          }
        }

        i = j;
      }
    }

    return NULL;
  }

  hash_t *dst_hashes = param->dst_hashes;

  const u32 *indices = param->indices;

  for (u32 i = param->idx_from; i < param->idx_to; i++)
  {
    dst_hashes[i] = hashes_buf[indices[i]];
  }

  return NULL;
}

static void salt_sort_run (salt_sort_t *params, hc_thread_t *threads, const int threads_cnt, const int phase)
{
  for (int t = 0; t < threads_cnt; t++) params[t].phase = phase;

  for (int t = 1; t < threads_cnt; t++)
  {
    hc_thread_create (threads[t], salt_sort_thread, &params[t]);
  }

  salt_sort_thread (&params[0]);

  for (int t = 1; t < threads_cnt; t++)
  {
    hc_thread_join (threads[t]);
  }
}

static int hc_radix_sort_by_salt (hash_t **hashes_buf_ptr, const u32 hashes_cnt, const hashconfig_t *hashconfig)
{
  if (hashes_cnt <= RADIX_SORT_THRESHOLD) return -1;

  hash_t *hashes_buf = *hashes_buf_ptr;

  u64 threads_cnt = (u64) hc_get_processor_count ();

  if (threads_cnt < 1) threads_cnt = 1;

  const u64 threads_max = ((u64) hashes_cnt / RADIX_PARALLEL_CHUNK) + 1;

  if (threads_cnt > threads_max) threads_cnt = threads_max;

  const u64 scratch_size = ((u64) hashes_cnt * (sizeof (u64) + sizeof (u32) + sizeof (u32))) + ((u64) hashes_cnt * sizeof (hash_t));

  u64 free_mem = 0;

  if (get_free_memory (&free_mem) == false) return -1;
  if (free_mem <= scratch_size) return -1;

  u64         *keys    = (u64 *)         hcmalloc ((u64) hashes_cnt * sizeof (u64));
  u32         *indices = (u32 *)         hcmalloc ((u64) hashes_cnt * sizeof (u32));
  u32         *runs    = (u32 *)         hcmalloc (((u64) hashes_cnt + 1) * sizeof (u32));
  salt_sort_t *params  = (salt_sort_t *) hcmalloc ((size_t) threads_cnt * sizeof (salt_sort_t));
  hc_thread_t *threads = (hc_thread_t *) hcmalloc ((size_t) threads_cnt * sizeof (hc_thread_t));

  if ((keys == NULL) || (indices == NULL) || (runs == NULL) || (params == NULL) || (threads == NULL))
  {
    hcfree (keys);
    hcfree (indices);
    hcfree (runs);
    hcfree (params);
    hcfree (threads);

    return -1;
  }

  const u64 chunk = ((u64) hashes_cnt + threads_cnt - 1) / threads_cnt;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    u64 idx_from = t * chunk;
    u64 idx_to   = idx_from + chunk;

    if (idx_from > hashes_cnt) idx_from = hashes_cnt;
    if (idx_to   > hashes_cnt) idx_to   = hashes_cnt;

    memset (&params[t], 0, sizeof (salt_sort_t));

    params[t].hashes_buf = hashes_buf;
    params[t].hashconfig = hashconfig;
    params[t].keys       = keys;
    params[t].indices    = indices;
    params[t].dgst_pos0  = hashconfig->dgst_pos0;
    params[t].dgst_pos1  = hashconfig->dgst_pos1;
    params[t].dgst_pos2  = hashconfig->dgst_pos2;
    params[t].dgst_pos3  = hashconfig->dgst_pos3;
    params[t].runs       = runs;
    params[t].idx_from   = (u32) idx_from;
    params[t].idx_to     = (u32) idx_to;
  }

  salt_sort_run (params, threads, (int) threads_cnt, 0);

  bool orig_pos_varies  = false;
  bool salt_len_varies  = false;
  bool salt_iter_varies = false;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    if (params[t].orig_pos_varies  == true) orig_pos_varies  = true;
    if (params[t].salt_len_varies  == true) salt_len_varies  = true;
    if (params[t].salt_iter_varies == true) salt_iter_varies = true;
  }

  int key_kind = RADIX_SALT_KEY_NONE;

  if (orig_pos_varies == false)
  {
    if      ((salt_len_varies == false) && (salt_iter_varies == false)) key_kind = RADIX_SALT_KEY_BUF;
    else if  (salt_iter_varies == false)                                key_kind = RADIX_SALT_KEY_LEN;
    else if  (salt_len_varies  == false)                                key_kind = RADIX_SALT_KEY_ITER;
  }

  if (key_kind == RADIX_SALT_KEY_NONE)
  {
    hcfree (keys);
    hcfree (indices);
    hcfree (runs);
    hcfree (params);
    hcfree (threads);

    return -1;
  }

  for (u64 t = 0; t < threads_cnt; t++) params[t].key_kind = key_kind;

  salt_sort_run (params, threads, (int) threads_cnt, 1);

  if (hc_radix_sort_parallel (&keys, &indices, hashes_cnt, NULL, 0, 0) == false)
  {
    msd_radix_sort_u64 (keys, indices, hashes_cnt, 7);
  }

  for (u64 t = 0; t < threads_cnt; t++)
  {
    params[t].keys    = keys;
    params[t].indices = indices;
  }

  u32 runs_cnt = 0;

  runs[runs_cnt++] = 0;

  for (u32 i = 1; i < hashes_cnt; i++)
  {
    if (keys[i] != keys[i - 1]) runs[runs_cnt++] = i;
  }

  runs[runs_cnt] = hashes_cnt;

  u32 r = 0;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    const u32 target = (u32) (((u64) hashes_cnt * (t + 1)) / threads_cnt);

    params[t].run_from = r;

    while ((r < runs_cnt) && (runs[r] < target)) r++;

    params[t].run_to = r;
  }

  params[threads_cnt - 1].run_to = runs_cnt;

  salt_sort_run (params, threads, (int) threads_cnt, 2);

  salt_sort_run (params, threads, (int) threads_cnt, 3);

  hash_t *dst_hashes = (hash_t *) hcmalloc ((u64) hashes_cnt * sizeof (hash_t));

  if (dst_hashes == NULL)
  {
    hcfree (keys);
    hcfree (indices);
    hcfree (runs);
    hcfree (params);
    hcfree (threads);

    return -1;
  }

  for (u64 t = 0; t < threads_cnt; t++) params[t].dst_hashes = dst_hashes;

  salt_sort_run (params, threads, (int) threads_cnt, 4);

  hcfree (hashes_buf);

  *hashes_buf_ptr = dst_hashes;

  hcfree (keys);
  hcfree (indices);
  hcfree (runs);
  hcfree (params);
  hcfree (threads);

  return 0;
}

int hash_encode (const user_options_t *user_options, const hashconfig_t *hashconfig, const hashes_t *hashes, const module_ctx_t *module_ctx, char *out_buf, const int out_size, const u32 salt_pos, const u32 digest_pos)
{
  if (module_ctx->module_hash_encode == MODULE_DEFAULT)
  {
    return snprintf (out_buf, out_size, "%s", hashes->hashfile);
  }

  salt_t *salts_buf = hashes->salts_buf;

  salts_buf += salt_pos;

  const u32 digest_cur = salts_buf->digests_offset + digest_pos;

  void        *digests_buf    = hashes->digests_buf;
  void        *esalts_buf     = hashes->esalts_buf;
  void        *hook_salts_buf = hashes->hook_salts_buf;
  hashinfo_t **hash_info      = hashes->hash_info;

  char       *digests_buf_ptr    = (char *) digests_buf;
  char       *esalts_buf_ptr     = (char *) esalts_buf;
  char       *hook_salts_buf_ptr = (char *) hook_salts_buf;
  hashinfo_t *hash_info_ptr      = NULL;

  digests_buf_ptr    += (u64) digest_cur * hashconfig->dgst_size;
  esalts_buf_ptr     += (u64) digest_cur * hashconfig->esalt_size;
  hook_salts_buf_ptr += (u64) digest_cur * hashconfig->hook_salt_size;

  if (hash_info) hash_info_ptr = hash_info[digest_cur];

  int line_len = 0;

  if (user_options->hash_copy == true)
  {
    line_len = snprintf (out_buf, out_size, "%s", hash_info_ptr->orighash);
  }
  else
  {
    line_len = module_ctx->module_hash_encode
    (
      hashconfig,
      digests_buf_ptr,
      salts_buf,
      esalts_buf_ptr,
      hook_salts_buf_ptr,
      hash_info_ptr,
      out_buf,
      out_size
    );
  }

  return line_len;
}

int save_hash (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t        *hashes       = hashcat_ctx->hashes;
  hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;
  module_ctx_t    *module_ctx   = hashcat_ctx->module_ctx;
  user_options_t  *user_options = hashcat_ctx->user_options;

  const char *hashfile = hashes->hashfile;

  char *new_hashfile;
  char *old_hashfile;

  hc_asprintf (&new_hashfile, "%s.new", hashfile);
  hc_asprintf (&old_hashfile, "%s.old", hashfile);

  unlink (new_hashfile);

  char separator = hashconfig->separator;

  HCFILE fp;

  if (hc_fopen (&fp, new_hashfile, "wb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  if (hc_lockfile (&fp) == -1)
  {
    hc_fclose (&fp);

    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    if (hashes->salts_shown[salt_pos] == 1) continue;

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    for (u32 digest_pos = 0; digest_pos < salt_buf->digests_cnt; digest_pos++)
    {
      const u32 idx = salt_buf->digests_offset + digest_pos;

      if (hashes->digests_shown[idx] == 1) continue;

      if (module_ctx->module_hash_binary_save != MODULE_DEFAULT)
      {
        char *binary_buf = NULL;

        const int binary_len = module_ctx->module_hash_binary_save (hashes, salt_pos, digest_pos, &binary_buf);

        hc_fwrite (binary_buf, binary_len, 1, &fp);

        hcfree (binary_buf);
      }
      else
      {
        if (user_options->username == true)
        {
          user_t *user = hashes->hash_info[idx]->user;

          u32 i;

          for (i = 0; i < user->user_len; i++) hc_fputc (user->user_name[i], &fp);

          hc_fputc (separator, &fp);
        }

        if (user_options->dynamic_x == true)
        {
          dynamicx_t *dynamicx = hashes->hash_info[idx]->dynamicx;

          u32 i;

          for (i = 0; i < dynamicx->dynamicx_len; i++) hc_fputc (dynamicx->dynamicx_buf[i], &fp);

          hc_fputc (separator, &fp);
        }

        const int out_len = hash_encode (hashcat_ctx->user_options, hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_pos, digest_pos);

        out_buf[out_len] = 0;

        hc_fprintf (&fp, "%s" EOL, out_buf);
      }
    }
  }

  hcfree (out_buf);

  hc_fflush (&fp);

  if (hc_unlockfile (&fp) == -1)
  {
    hc_fclose (&fp);

    event_log_error (hashcat_ctx, "%s: %s", new_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  hc_fclose (&fp);

  unlink (old_hashfile);

  if (rename (hashfile, old_hashfile) != 0)
  {
    event_log_error (hashcat_ctx, "Rename file '%s' to '%s': %s", hashfile, old_hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  unlink (hashfile);

  if (rename (new_hashfile, hashfile) != 0)
  {
    event_log_error (hashcat_ctx, "Rename file '%s' to '%s': %s", new_hashfile, hashfile, strerror (errno));

    hcfree (new_hashfile);
    hcfree (old_hashfile);

    return -1;
  }

  unlink (old_hashfile);

  hcfree (new_hashfile);
  hcfree (old_hashfile);

  return 0;
}

int check_hash (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, plain_t *plain)
{
  const debugfile_ctx_t *debugfile_ctx = hashcat_ctx->debugfile_ctx;
  const hashes_t        *hashes        = hashcat_ctx->hashes;
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
  const loopback_ctx_t  *loopback_ctx  = hashcat_ctx->loopback_ctx;
  const module_ctx_t    *module_ctx    = hashcat_ctx->module_ctx;
  const pubkey_ctx_t    *pubkey_ctx    = hashcat_ctx->pubkey_ctx;
  const user_options_t  *user_options  = hashcat_ctx->user_options;

  const u32 salt_pos    = plain->salt_pos;
  const u32 digest_pos  = plain->digest_pos;  // relative

  void *tmps = NULL;

  cl_event opencl_event;

  int rc = -1;

  if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
  {
    tmps = hcmalloc (hashconfig->tmp_size);

    if (device_param->is_cuda == true)
    {
      rc = hc_cuMemcpyDtoH (hashcat_ctx, tmps, device_param->cuda_d_tmps + (plain->gidvid * hashconfig->tmp_size), hashconfig->tmp_size);

      if (rc == 0)
      {
        rc = hc_cuEventRecord (hashcat_ctx, device_param->cuda_event3, device_param->cuda_stream);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }

    if (device_param->is_hip == true)
    {
      rc = hc_hipMemcpyDtoH (hashcat_ctx, tmps, device_param->hip_d_tmps + (plain->gidvid * hashconfig->tmp_size), hashconfig->tmp_size);

      if (rc == 0)
      {
        rc = hc_hipEventRecord (hashcat_ctx, device_param->hip_event3, device_param->hip_stream);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      rc = hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_device, device_param->metal_command_queue, tmps, device_param->metal_d_tmps, plain->gidvid * hashconfig->tmp_size, hashconfig->tmp_size);

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }
    #endif

    if (device_param->is_opencl == true)
    {
      rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_tmps, CL_TRUE, plain->gidvid * hashconfig->tmp_size, hashconfig->tmp_size, tmps, 0, NULL, &opencl_event);

      if (rc == 0)
      {
        rc = hc_clFlush (hashcat_ctx, device_param->opencl_command_queue);
      }

      if (rc == -1)
      {
        hcfree (tmps);

        return -1;
      }
    }
  }

  // hash

  u8 *out_buf = hashes->out_buf;

  int out_len = hash_encode (hashcat_ctx->user_options, hashconfig, hashes, module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, salt_pos, digest_pos);

  out_buf[out_len] = 0;

  // plain

  u8 plain_buf[HCBUFSIZ_TINY] = { 0 }; // while the password itself can have only length 256, the module could encode it with something like base64 which inflates the requires buffer size
  u8 postprocess_buf[HCBUFSIZ_TINY] = { 0 };

  u8 *plain_ptr = plain_buf;

  int plain_len = 0;

  build_plain (hashcat_ctx, device_param, plain, (u32 *) plain_buf, &plain_len);

  if (module_ctx->module_build_plain_postprocess != MODULE_DEFAULT)
  {
    if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuEventSynchronize (hashcat_ctx, device_param->cuda_event3) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipEventSynchronize (hashcat_ctx, device_param->hip_event3) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;
      }
    }

    plain_len = module_ctx->module_build_plain_postprocess (hashconfig, hashes, tmps, (u32 *) plain_buf, sizeof (plain_buf), plain_len, (u32 *) postprocess_buf, sizeof (postprocess_buf));

    plain_ptr = postprocess_buf;
  }

  // encrypted output
  //
  // This sits after any module postprocessing on purpose. Encrypting inside build_plain would be
  // undone by the modes that swap the buffer just above, and it would also reach the status display,
  // which shows candidates rather than results. From here the encrypted form is what the outfile,
  // the potfile, the loopback file and the terminal all receive.

  u8 encrypted_buf[HCBUFSIZ_TINY] = { 0 };

  if (pubkey_ctx->enabled == true)
  {
    int encrypted_len = 0;

    if (pubkey_encrypt_plain (hashcat_ctx, out_buf, out_len, plain_ptr, plain_len, encrypted_buf, sizeof (encrypted_buf), &encrypted_len) == -1)
    {
      // Failing the run is deliberate. The caller of a protected run cannot use a result they
      // cannot decrypt, and writing the password in the clear instead would defeat the point.

      hcfree (tmps);

      return -1;
    }

    plain_ptr = encrypted_buf;
    plain_len = encrypted_len;
  }

  // crackpos

  u64 crackpos = 0;

  build_crackpos (hashcat_ctx, device_param, plain, &crackpos);

  // debug

  u8  debug_rule_buf[RP_PASSWORD_SIZE] = { 0 };
  int debug_rule_len  = 0; // -1 error

  u8  debug_plain_ptr[RP_PASSWORD_SIZE + 1] = { 0 };
  int debug_plain_len = 0;

  build_debugdata (hashcat_ctx, device_param, plain, debug_rule_buf, &debug_rule_len, debug_plain_ptr, &debug_plain_len);

  // outfile, can be either to file or stdout
  // if an error occurs opening the file, send to stdout as fallback
  // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs

  outfile_write_open (hashcat_ctx);

  u8 *tmp_buf = hashes->tmp_buf;

  tmp_buf[0] = 0;

  const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, plain_ptr, plain_len, crackpos, NULL, 0, true, (char *) tmp_buf);

  EVENT_DATA (EVENT_CRACKER_HASH_CRACKED, tmp_buf, tmp_len);

  outfile_write_close (hashcat_ctx);

  // potfile
  // we can have either used-defined hooks or reuse the same format as input format
  // no need for locking, we're in a mutex protected function

  if (module_ctx->module_hash_encode_potfile != MODULE_DEFAULT)
  {
    if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuEventSynchronize (hashcat_ctx, device_param->cuda_event3) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipEventSynchronize (hashcat_ctx, device_param->hip_event3) == -1) return -1;
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;
      }
    }

    salt_t *salts_buf = hashes->salts_buf;

    salts_buf += salt_pos;

    const u32 digest_cur = salts_buf->digests_offset + digest_pos;

    void        *digests_buf    = hashes->digests_buf;
    void        *esalts_buf     = hashes->esalts_buf;
    void        *hook_salts_buf = hashes->hook_salts_buf;
    hashinfo_t **hash_info      = hashes->hash_info;

    char       *digests_buf_ptr    = (char *) digests_buf;
    char       *esalts_buf_ptr     = (char *) esalts_buf;
    char       *hook_salts_buf_ptr = (char *) hook_salts_buf;
    hashinfo_t *hash_info_ptr      = NULL;

    digests_buf_ptr    += (u64) digest_cur * hashconfig->dgst_size;
    esalts_buf_ptr     += (u64) digest_cur * hashconfig->esalt_size;
    hook_salts_buf_ptr += (u64) digest_cur * hashconfig->hook_salt_size;

    if (hash_info) hash_info_ptr = hash_info[digest_cur];

    out_len = module_ctx->module_hash_encode_potfile
    (
      hashconfig,
      digests_buf_ptr,
      salts_buf,
      esalts_buf_ptr,
      hook_salts_buf_ptr,
      hash_info_ptr,
      (char *) out_buf,
      HCBUFSIZ_LARGE,
      tmps
    );

    out_buf[out_len] = 0;
  }

  potfile_write_append (hashcat_ctx, (char *) out_buf, out_len, plain_ptr, plain_len);

  // if enabled, update also the loopback file

  if (loopback_ctx->fp.pfp != NULL)
  {
    loopback_write_append (hashcat_ctx, plain_ptr, plain_len);
  }

  // if enabled, update also the (rule) debug file

  if (debugfile_ctx->fp.pfp != NULL)
  {
    // the next check implies that:
    // - (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    // - debug_mode > 0

    if ((debug_plain_len > 0) || (debug_rule_len > 0))
    {
      // Where the BASE word sat in the feed's keyspace, which is what says which wordlist it came out
      // of. build_crackpos takes the same number and multiplies it by the amplifier; debug mode 5
      // wants it before that.

      const u64 word_pos = (user_options->slow_candidates == true) ? plain->gidvid : device_param->words_off_launch + plain->gidvid;

      debugfile_write_append (hashcat_ctx, debug_rule_buf, debug_rule_len, plain_ptr, plain_len, debug_plain_ptr, debug_plain_len, word_pos);
    }
  }

  if (hashconfig->opts_type & OPTS_TYPE_COPY_TMPS)
  {
    hcfree (tmps);

    if (device_param->is_opencl == true)
    {
      if (hc_clReleaseEvent (hashcat_ctx, opencl_event) == -1) return -1;
    }
  }

  return 0;
}

//int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos)
int check_cracked (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  cpt_ctx_t      *cpt_ctx      = hashcat_ctx->cpt_ctx;
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  u32 num_cracked = 0;

  int rc = -1;

  if (device_param->is_cuda == true)
  {
    if (hc_cuMemcpyDtoH (hashcat_ctx, &num_cracked, device_param->cuda_d_result, sizeof (u32)) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipMemcpyDtoH (hashcat_ctx, &num_cracked, device_param->hip_d_result, sizeof (u32)) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_device, device_param->metal_command_queue, &num_cracked, device_param->metal_d_result, 0, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_result, CL_TRUE, 0, sizeof (u32), &num_cracked, 0, NULL, NULL) == -1) return -1;
  }

  if (num_cracked == 0 || user_options->speed_only == true)
  {
    // we want to get the num_cracked in benchmark mode because it has an influence in performance
    // however if the benchmark cracks the artificial hash used for benchmarks we don't want to see that!

    return 0;
  }

  plain_t *cracked = (plain_t *) hcmalloc (num_cracked * sizeof (plain_t));

  if (device_param->is_cuda == true)
  {
    rc = hc_cuMemcpyDtoH (hashcat_ctx, cracked, device_param->cuda_d_plain_bufs, num_cracked * sizeof (plain_t));

    if (rc == 0)
    {
      rc = hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream);
    }

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  if (device_param->is_hip == true)
  {
    rc = hc_hipMemcpyDtoH (hashcat_ctx, cracked, device_param->hip_d_plain_bufs, num_cracked * sizeof (plain_t));

    if (rc == 0)
    {
      rc = hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream);
    }

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    rc = hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_device, device_param->metal_command_queue, cracked, device_param->metal_d_plain_bufs, 0, num_cracked * sizeof (plain_t));

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_plain_bufs, CL_TRUE, 0, num_cracked * sizeof (plain_t), cracked, 0, NULL, NULL);

    if (rc == -1)
    {
      hcfree (cracked);

      return -1;
    }
  }

  u32 cpt_cracked = 0;

  hc_thread_mutex_lock (status_ctx->mux_display);

  for (u32 i = 0; i < num_cracked; i++)
  {
    const u32 hash_pos = cracked[i].hash_pos;

    if (hashes->digests_shown[hash_pos] == 1) continue;

    const u32 salt_pos = cracked[i].salt_pos;
    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    if ((hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK) == 0)
    {
      hashes->digests_shown[hash_pos] = 1;

      hashes->digests_done++;

      hashes->digests_done_new++;

      cpt_cracked++;

      salt_buf->digests_done++;

      if (salt_buf->digests_done == salt_buf->digests_cnt)
      {
        hashes->salts_shown[salt_pos] = 1;

        hashes->salts_done++;
      }
    }

    if (hashes->salts_done == hashes->salts_cnt) mycracked (hashcat_ctx);

    rc = check_hash (hashcat_ctx, device_param, &cracked[i]);

    if (rc == -1)
    {
      break;
    }

    if (hashconfig->opts_type & OPTS_TYPE_PT_NEVERCRACK)
    {
      // we need to reset cracked state on the device
      // otherwise host thinks again and again the hash was cracked
      // and returns invalid password each time

      if (device_param->is_cuda == true)
      {
        rc = run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_digests_shown + (salt_buf->digests_offset * sizeof (u32)), salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }

      if (device_param->is_hip == true)
      {
        rc = run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_digests_shown + (salt_buf->digests_offset * sizeof (u32)), salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        rc = run_metal_kernel_memset32 (hashcat_ctx, device_param, device_param->metal_d_digests_shown, salt_buf->digests_offset * sizeof (u32), 0, salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }
      #endif

      if (device_param->is_opencl == true)
      {
        /* NOTE: run_opencl_kernel_bzero() does not handle buffer offset */
        rc = run_opencl_kernel_memset32 (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, salt_buf->digests_offset * sizeof (u32), 0, salt_buf->digests_cnt * sizeof (u32));

        if (rc == -1)
        {
          break;
        }
      }
    }
  }

  hc_thread_mutex_unlock (status_ctx->mux_display);

  hcfree (cracked);

  if (rc == -1)
  {
    return -1;
  }

  if (cpt_cracked > 0)
  {
    hc_thread_mutex_lock (status_ctx->mux_display);

    cpt_ctx->cpt_buf[cpt_ctx->cpt_pos].timestamp = time (NULL);
    cpt_ctx->cpt_buf[cpt_ctx->cpt_pos].cracked   = cpt_cracked;

    cpt_ctx->cpt_pos++;

    cpt_ctx->cpt_total += cpt_cracked;

    if (cpt_ctx->cpt_pos == CPT_CACHE) cpt_ctx->cpt_pos = 0;

    hc_thread_mutex_unlock (status_ctx->mux_display);
  }

  if (device_param->is_cuda == true)
  {
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_result, sizeof (u32)) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_result, sizeof (u32)) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_result, sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_result, sizeof (u32)) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  return 0;
}

int hashes_init_filename (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->benchmark == true) return 0;

  /**
   * load hashes, part I: find input mode, count hashes
   */

  if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
  {
    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
    {
      if ((user_options->benchmark == false) && (user_options->keyspace == false))
      {
        hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

        if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
        {
          hashes->hashfile = user_options_extra->hc_hash;
        }
      }
    }
    else
    {
      hashes->hashlist_mode = HL_MODE_FILE_BINARY;

      if ((user_options->benchmark == false) && (user_options->keyspace == false))
      {
        if (hc_path_read (user_options_extra->hc_hash) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", user_options_extra->hc_hash, strerror (errno));

          return -1;
        }

        hashes->hashfile = user_options_extra->hc_hash;
      }
    }
  }
  else
  {
    hashes->hashlist_mode = (hc_path_exist (user_options_extra->hc_hash) == true) ? HL_MODE_FILE_PLAIN : HL_MODE_ARG;

    if (hashes->hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      hashes->hashfile = user_options_extra->hc_hash;
    }
  }

  hashes->parser_token_length_cnt = 0;

  return 0;
}

// Whether any line of the hash file has a separator on it, which is what says the file can be split
// into username and hash at all. Only the first lines are looked at, as many as the format detection
// above reads, because a file where none of those has one is not the shape the user thinks it is.

static bool hashfile_has_separator (hashcat_ctx_t *hashcat_ctx, HCFILE *fp)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  bool found = false;

  u32 num_check = 0;

  while (!hc_feof (fp))
  {
    const size_t line_len = fgetl (fp, line_buf, HCBUFSIZ_LARGE);

    if (line_len == 0) continue;

    // The username is what sits in front of the separator, so a line that starts with one has no
    // username on it and does not count as a line this file can be split at.

    if (line_buf[0] == hashconfig->separator) continue;

    if (memchr (line_buf, hashconfig->separator, line_len) != NULL)
    {
      found = true;

      break;
    }

    if (num_check == 100) break;

    num_check++;
  }

  hcfree (line_buf);

  return found;
}

static void hashes_init_entry (const hashconfig_t *hashconfig, hashes_t *hashes, const u64 hash_pos)
{
  hash_t *hash = &hashes->hashes_buf[hash_pos];

  hash->orig_line_pos = hash_pos;

  hash->digest = ((char *) hashes->digests_buf) + (hash_pos * hashconfig->dgst_size);

  if (hashconfig->is_salted == true)
  {
    hash->salt = &hashes->salts_buf[hash_pos];

    if (hashconfig->esalt_size > 0)
    {
      hash->esalt = ((char *) hashes->esalts_buf) + (hash_pos * hashconfig->esalt_size);
    }

    if (hashconfig->hook_salt_size > 0)
    {
      hash->hook_salt = ((char *) hashes->hook_salts_buf) + (hash_pos * hashconfig->hook_salt_size);
    }
  }
  else
  {
    hash->salt = &hashes->salts_buf[0];
  }
}

// parse the hash list on every core
//
// only for a plain hashcat format file of unsalted digests carrying no per hash side data, which is
// the shape every list big enough to care about has. everything else keeps the loop in
// hashes_init_stage1, which is still the only implementation of every case this one turns away.

#define HASHLIST_BLOCK_SIZE (64 * 1024 * 1024)
#define HASHLIST_PARSE_MIN  (256 * 1024)

typedef struct hashlist_error
{
  u32   line_num;
  u32   status;
  char *line;
  char *reason;

} hashlist_error_t;

typedef struct hashlist_chunk
{
  hashcat_ctx_t *hashcat_ctx;

  char   *buf;
  size_t  from;
  size_t  to;

  int     phase;

  HCFILE *fp;
  u64     file_from;
  u64     file_to;
  u64     got;
  u64     lines_seen;

  u32     line_num;
  u32     slot;
  u32     budget;

  u32     lines;
  u32     parsed;
  int     token_length_cnt;
  u64     truncated;

  salt_t *salt;

  hashlist_error_t *errors;
  u32               errors_cnt;
  u32               errors_sz;

} hashlist_chunk_t;

static void hashlist_error_add (hashlist_chunk_t *chunk, const u32 line_num, const int status, const char *line, const char *reason)
{
  if (chunk->errors_cnt == chunk->errors_sz)
  {
    const u32 errors_sz = (chunk->errors_sz == 0) ? 16 : chunk->errors_sz * 2;

    hashlist_error_t *errors = (hashlist_error_t *) hcrealloc (chunk->errors, (size_t) chunk->errors_sz * sizeof (hashlist_error_t), (size_t) (errors_sz - chunk->errors_sz) * sizeof (hashlist_error_t));

    if (errors == NULL) return;

    chunk->errors    = errors;
    chunk->errors_sz = errors_sz;
  }

  hashlist_error_t *error = &chunk->errors[chunk->errors_cnt];

  error->line_num = line_num;
  error->status   = (u32) status;
  error->line     = hcstrdup (line);
  error->reason   = hcstrdup (reason);

  chunk->errors_cnt++;
}

static void hashlist_error_report (hashcat_ctx_t *hashcat_ctx, const hashlist_error_t *error)
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  char *tmp_line_buf;

  hc_asprintf (&tmp_line_buf, "%s", error->line);

  compress_terminal_line_length (tmp_line_buf, 38, 32);

  if (user_options->machine_readable == true)
  {
    event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, error->line_num, tmp_line_buf, strparser (error->status));
  }
  else
  {
    event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, error->line_num, tmp_line_buf, error->reason);
  }

  hcfree (tmp_line_buf);
}

static void *hashlist_parse_thread (void *p)
{
  hashlist_chunk_t *chunk = (hashlist_chunk_t *) p;

  char *buf = chunk->buf;

  size_t pos = chunk->from;

  if (chunk->phase == 2)
  {
    HCFILE *fp = chunk->fp;

    chunk->got = 0;

    if (hc_fseek (fp, (off_t) chunk->file_from, SEEK_SET) == -1) return NULL;

    const u64 want = chunk->file_to - chunk->file_from;

    while (chunk->got < want)
    {
      const size_t got = hc_fread (buf + chunk->got, 1, (size_t) (want - chunk->got), fp);

      if ((got == 0) || (got == (size_t) -1)) break;

      chunk->got += got;
    }

    return NULL;
  }

  if (chunk->phase == 3)
  {
    hc_memchr_t hc_memchr = hc_memchr_get ();

    u64 lines = 0;

    while (pos < chunk->to)
    {
      const size_t step = hc_memchr ((const u8 *) buf + pos, '\n', chunk->to - pos);

      if (step == (chunk->to - pos)) break;

      lines++;

      pos += step + 1;
    }

    chunk->lines_seen = lines;

    return NULL;
  }

  if (chunk->phase == 0)
  {
    u32 lines = 0;

    while (pos < chunk->to)
    {
      size_t line_len;

      pos += hc_line_next ((const u8 *) buf + pos, chunk->to - pos, &line_len) + 1;

      lines++;
    }

    chunk->lines = lines;

    return NULL;
  }

  hashcat_ctx_t *hashcat_ctx = chunk->hashcat_ctx;

  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
        hashes_t             *hashes             = hashcat_ctx->hashes;
  const module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  hash_t *hashes_buf = hashes->hashes_buf;

  u32 line_num = chunk->line_num;
  u32 slot     = chunk->slot;
  u32 budget   = chunk->budget;

  while ((pos < chunk->to) && (budget > 0))
  {
    size_t line_len;

    const size_t step = hc_line_next ((const u8 *) buf + pos, chunk->to - pos, &line_len);

    char *line_buf = buf + pos;

    pos += step + 1;

    line_num++;
    budget--;

    if (line_len == 0) continue;

    if (line_len > (HCBUFSIZ_LARGE - 1))
    {
      chunk->truncated += line_len - (HCBUFSIZ_LARGE - 1);

      line_len = HCBUFSIZ_LARGE - 1;
    }

    line_buf[line_len] = 0;

    hashes_init_entry (hashconfig, hashes, slot);

    hash_t *hash = &hashes_buf[slot];

    salt_t *salt = chunk->salt;

    if (hashconfig->is_salted == true)
    {
      salt = hash->salt;

      const u32 orig_pos = salt->orig_pos;

      memset (salt, 0, sizeof (salt_t));

      salt->orig_pos = orig_pos;
    }

    if (hashconfig->esalt_size > 0)
    {
      memset (hash->esalt, 0, hashconfig->esalt_size);
    }

    if (hashconfig->hook_salt_size > 0)
    {
      memset (hash->hook_salt, 0, hashconfig->hook_salt_size);
    }

    parser_error_reset ();

    int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, salt, hash->esalt, hash->hook_salt, hash->hash_info, line_buf, (int) line_len);

    if (parser_status < PARSER_GLOBAL_ZERO)
    {
      hashlist_error_add (chunk, line_num, parser_status, line_buf, parser_error_string (parser_status));

      if (parser_status == PARSER_TOKEN_LENGTH) chunk->token_length_cnt++;

      continue;
    }

    if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
    {
      parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

      if (parser_status < PARSER_GLOBAL_ZERO)
      {
        hashlist_error_add (chunk, line_num, parser_status, line_buf, strparser (parser_status));

        if (parser_status == PARSER_TOKEN_LENGTH) chunk->token_length_cnt++;

        continue;
      }
    }

    slot++;
  }

  chunk->parsed = slot - chunk->slot;

  return NULL;
}

static void hashlist_chunks_run (hashlist_chunk_t *chunks, hc_thread_t *threads, const int chunks_cnt, const int phase)
{
  for (int i = 0; i < chunks_cnt; i++) chunks[i].phase = phase;

  for (int i = 1; i < chunks_cnt; i++)
  {
    hc_thread_create (threads[i], hashlist_parse_thread, &chunks[i]);
  }

  hashlist_parse_thread (&chunks[0]);

  for (int i = 1; i < chunks_cnt; i++)
  {
    hc_thread_join (threads[i]);
  }
}

// one handle per thread on the same file, so a block is read by everybody at once. reading a page
// cached file is a copy, and one core copies at half the rate the memory can serve.

typedef struct hashlist_reader
{
  HCFILE *fps;
  int     fps_cnt;
  u64     offset;
  u64     size;

} hashlist_reader_t;

static bool hashlist_reader_open (hashlist_reader_t *reader, HCFILE *fp, const int fps_cnt)
{
  memset (reader, 0, sizeof (hashlist_reader_t));

  if (fp->pfp  == NULL) return false;
  if (fp->gfp  != NULL) return false;
  if (fp->ufp  != NULL) return false;
  if (fp->xfp  != NULL) return false;
  if (fp->mfp  != NULL) return false;
  if (fp->path == NULL) return false;

  struct stat st;

  if (hc_fstat (fp, &st) == -1) return false;

  const off_t pos = hc_ftell (fp);

  if (pos < 0) return false;

  HCFILE *fps = (HCFILE *) hcmalloc ((size_t) fps_cnt * sizeof (HCFILE));

  if (fps == NULL) return false;

  for (int i = 0; i < fps_cnt; i++)
  {
    if (hc_fopen_raw (&fps[i], fp->path, "rb") == false)
    {
      for (int j = 0; j < i; j++) hc_fclose (&fps[j]);

      hcfree (fps);

      return false;
    }
  }

  reader->fps     = fps;
  reader->fps_cnt = fps_cnt;
  reader->offset  = (u64) pos;
  reader->size    = (u64) st.st_size;

  return true;
}

static void hashlist_reader_close (hashlist_reader_t *reader)
{
  if (reader->fps == NULL) return;

  for (int i = 0; i < reader->fps_cnt; i++) hc_fclose (&reader->fps[i]);

  hcfree (reader->fps);

  reader->fps = NULL;
}

static u64 hashlist_reader_read (hashlist_reader_t *reader, hashlist_chunk_t *chunks, hc_thread_t *threads, char *buf, const u64 want)
{
  u64 avail = 0;

  if (reader->offset < reader->size) avail = reader->size - reader->offset;

  if (avail > want) avail = want;

  if (avail == 0) return 0;

  const int chunks_cnt = reader->fps_cnt;

  for (int i = 0; i < chunks_cnt; i++)
  {
    const u64 from = (avail * (u64) i)       / (u64) chunks_cnt;
    const u64 to   = (avail * (u64) (i + 1)) / (u64) chunks_cnt;

    memset (&chunks[i], 0, sizeof (hashlist_chunk_t));

    chunks[i].buf       = buf + from;
    chunks[i].fp        = &reader->fps[i];
    chunks[i].file_from = reader->offset + from;
    chunks[i].file_to   = reader->offset + to;
  }

  hashlist_chunks_run (chunks, threads, chunks_cnt, 2);

  u64 nread = 0;

  for (int i = 0; i < chunks_cnt; i++)
  {
    nread += chunks[i].got;

    if (chunks[i].got < (chunks[i].file_to - chunks[i].file_from)) break;
  }

  reader->offset += nread;

  return nread;
}

// how many lines a file holds, counted the way count_lines counts them, on every core

static bool hashlist_count_lines_threaded (HCFILE *fp, u64 *lines_ptr)
{
  int chunks_cnt = hc_get_processor_count ();

  if (chunks_cnt < 1) chunks_cnt = 1;

  hashlist_reader_t reader;

  if (hashlist_reader_open (&reader, fp, chunks_cnt) == false) return false;

  char             *block   = (char *)             hcmalloc (HASHLIST_BLOCK_SIZE);
  hashlist_chunk_t *chunks  = (hashlist_chunk_t *) hcmalloc ((size_t) chunks_cnt * sizeof (hashlist_chunk_t));
  hc_thread_t      *threads = (hc_thread_t *)      hcmalloc ((size_t) chunks_cnt * sizeof (hc_thread_t));

  if ((block == NULL) || (chunks == NULL) || (threads == NULL))
  {
    hashlist_reader_close (&reader);

    hcfree (block);
    hcfree (chunks);
    hcfree (threads);

    return false;
  }

  u64  lines = 0;
  bool any   = false;
  char last  = '\n';

  for (;;)
  {
    const u64 nread = hashlist_reader_read (&reader, chunks, threads, block, HASHLIST_BLOCK_SIZE);

    if (nread == 0) break;

    any = true;

    for (int i = 0; i < chunks_cnt; i++)
    {
      const u64 from = (nread * (u64) i)       / (u64) chunks_cnt;
      const u64 to   = (nread * (u64) (i + 1)) / (u64) chunks_cnt;

      memset (&chunks[i], 0, sizeof (hashlist_chunk_t));

      chunks[i].buf  = block;
      chunks[i].from = (size_t) from;
      chunks[i].to   = (size_t) to;
    }

    hashlist_chunks_run (chunks, threads, chunks_cnt, 3);

    for (int i = 0; i < chunks_cnt; i++) lines += chunks[i].lines_seen;

    last = block[nread - 1];

    if (nread < HASHLIST_BLOCK_SIZE) break;
  }

  if ((any == true) && (last != '\n')) lines++;

  hashlist_reader_close (&reader);

  hcfree (block);
  hcfree (chunks);
  hcfree (threads);

  *lines_ptr = lines;

  return true;
}

static bool hashlist_parse_threaded_ok (hashcat_ctx_t *hashcat_ctx, const u32 hashlist_format, const u64 hashes_avail)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (hashes_avail < HASHLIST_PARSE_MIN) return false;

  if (hashlist_format != HLFMT_HASHCAT) return false;

  if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY)  return false;
  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT) return false;

  if (module_ctx->module_hash_decode == MODULE_DEFAULT) return false;

  if (user_options->username    == true) return false;
  if (user_options->dynamic_x   == true) return false;
  if (user_options->hash_copy   == true) return false;
  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION) return false;

  return true;
}

static bool hashlist_parse_threaded (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, u32 *hashes_cnt_ptr, const u64 hashes_avail, u32 *line_num_ptr)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
        hashes_t     *hashes     = hashcat_ctx->hashes;

  const u32 dgst_size = hashconfig->dgst_size;

  int chunks_cnt = hc_get_processor_count ();

  if (chunks_cnt < 1) chunks_cnt = 1;

  char             *block   = (char *)             hcmalloc (HASHLIST_BLOCK_SIZE + 2);
  hashlist_chunk_t *chunks  = (hashlist_chunk_t *) hcmalloc ((size_t) chunks_cnt * sizeof (hashlist_chunk_t));
  hc_thread_t      *threads = (hc_thread_t *)      hcmalloc ((size_t) chunks_cnt * sizeof (hc_thread_t));
  salt_t           *salts   = (salt_t *)           hcmalloc ((size_t) chunks_cnt * sizeof (salt_t));

  if ((block == NULL) || (chunks == NULL) || (threads == NULL) || (salts == NULL))
  {
    hcfree (block);
    hcfree (chunks);
    hcfree (threads);
    hcfree (salts);

    return false;
  }

  hash_t *hashes_buf  = hashes->hashes_buf;
  char   *digests_buf = (char *) hashes->digests_buf;

  hc_memchr_t hc_memchr = hc_memchr_get ();

  hashlist_reader_t reader;

  const bool reader_ok = hashlist_reader_open (&reader, fp, chunks_cnt);

  u32 hashes_cnt = *hashes_cnt_ptr;
  u32 line_num   = *line_num_ptr;

  size_t keep     = 0;
  bool   overlong = false;
  u64    dropped  = 0;
  bool   changed  = false;
  u32    changed_line = 0;

  time_t prev = 0;
  time_t now  = 0;

  while (changed == false)
  {
    const size_t room = HASHLIST_BLOCK_SIZE - keep;

    size_t nread = 0;

    if (reader_ok == true)
    {
      nread = (size_t) hashlist_reader_read (&reader, chunks, threads, block + keep, room);
    }
    else
    {
      while (nread < room)
      {
        const size_t got = hc_fread (block + keep + nread, 1, room - nread, fp);

        if ((got == 0) || (got == (size_t) -1)) break;

        nread += got;
      }
    }

    const bool eof = (nread < room);

    size_t total = keep + nread;

    if (total == 0) break;

    // a line with no ending in a whole block is already longer than four times what fgetl keeps of
    // it, so keep that much and drop the rest of it, up to and including the next line ending

    if (overlong == true)
    {
      const size_t step = hc_memchr ((const u8 *) block + keep, '\n', total - keep);

      if ((keep + step) == total)
      {
        dropped += total - keep;

        if (eof == false) continue;

        total = keep;
      }
      else
      {
        dropped += step;

        memmove (block + keep + 1, block + keep + step + 1, total - (keep + step + 1));

        total -= step;

        block[keep] = '\n';
      }

      overlong = false;

      fprintf (stderr, "\nOversized line detected! Truncated %" PRIu64 " bytes\n", dropped);

      dropped = 0;
    }

    size_t end = 0;

    for (size_t i = total; i > 0; i--)
    {
      if (block[i - 1] == '\n')
      {
        end = i;

        break;
      }
    }

    if (eof == true)
    {
      if ((total > 0) && (block[total - 1] != '\n'))
      {
        block[total] = '\n';

        total++;
      }

      end = total;
    }
    else if (end == 0)
    {
      keep = MIN (total, (size_t) (HCBUFSIZ_LARGE - 1));

      dropped  += total - keep;
      overlong  = true;

      continue;
    }

    keep = total - end;

    // one byte range per thread, each one starting right after a line ending

    size_t from = 0;

    int used = 0;

    for (int i = 0; i < chunks_cnt; i++)
    {
      size_t to = (size_t) (((u64) end * (u64) (i + 1)) / (u64) chunks_cnt);

      if (to < from) to = from;

      if (to < end)
      {
        const size_t step = hc_memchr ((const u8 *) block + to, '\n', end - to);

        to = ((to + step) == end) ? end : (to + step + 1);
      }

      if ((to == from) && (to != end)) continue;

      memset (&chunks[used], 0, sizeof (hashlist_chunk_t));

      chunks[used].hashcat_ctx = hashcat_ctx;
      chunks[used].buf         = block;
      chunks[used].from        = from;
      chunks[used].to          = to;
      chunks[used].salt        = &salts[used];

      used++;

      from = to;

      if (to == end) break;
    }

    if (used > 0)
    {
      hashlist_chunks_run (chunks, threads, used, 0);

      u32 slot   = hashes_cnt;
      u32 budget = (u32) MIN (hashes_avail - (u64) hashes_cnt, (u64) UINT32_MAX);

      for (int i = 0; i < used; i++)
      {
        chunks[i].line_num = line_num;
        chunks[i].slot     = slot;
        chunks[i].budget   = MIN (chunks[i].lines, budget);

        if ((changed == false) && (chunks[i].budget < chunks[i].lines))
        {
          changed      = true;
          changed_line = line_num + chunks[i].budget + 1;
        }

        line_num += chunks[i].lines;
        slot     += chunks[i].budget;
        budget   -= chunks[i].budget;
      }

      hashlist_chunks_run (chunks, threads, used, 1);

      // slots a chunk did not fill are holes, so every block behind the first hole moves down

      for (int i = 0; i < used; i++)
      {
        if (chunks[i].slot != hashes_cnt)
        {
          memmove (&hashes_buf[hashes_cnt], &hashes_buf[chunks[i].slot], (size_t) chunks[i].parsed * sizeof (hash_t));

          memmove (digests_buf + ((u64) hashes_cnt * dgst_size), digests_buf + ((u64) chunks[i].slot * dgst_size), (size_t) chunks[i].parsed * dgst_size);

          if (hashconfig->is_salted == true)
          {
            memmove (&hashes->salts_buf[hashes_cnt], &hashes->salts_buf[chunks[i].slot], (size_t) chunks[i].parsed * sizeof (salt_t));

            if (hashconfig->esalt_size > 0)
            {
              memmove (((char *) hashes->esalts_buf) + ((u64) hashes_cnt * hashconfig->esalt_size), ((char *) hashes->esalts_buf) + ((u64) chunks[i].slot * hashconfig->esalt_size), (size_t) chunks[i].parsed * hashconfig->esalt_size);
            }

            if (hashconfig->hook_salt_size > 0)
            {
              memmove (((char *) hashes->hook_salts_buf) + ((u64) hashes_cnt * hashconfig->hook_salt_size), ((char *) hashes->hook_salts_buf) + ((u64) chunks[i].slot * hashconfig->hook_salt_size), (size_t) chunks[i].parsed * hashconfig->hook_salt_size);
            }
          }

          for (u32 j = 0; j < chunks[i].parsed; j++)
          {
            hashes_init_entry (hashconfig, hashes, hashes_cnt + j);
          }
        }

        hashes_cnt += chunks[i].parsed;

        hashes->parser_token_length_cnt += chunks[i].token_length_cnt;

        if ((hashconfig->is_salted == false) && (chunks[i].parsed > 0)) memcpy (hashes_buf[hashes_cnt - 1].salt, &salts[i], sizeof (salt_t));

        if (chunks[i].truncated > 0)
        {
          fprintf (stderr, "\nOversized line detected! Truncated %" PRIu64 " bytes\n", chunks[i].truncated);
        }

        for (u32 j = 0; j < chunks[i].errors_cnt; j++)
        {
          hashlist_error_report (hashcat_ctx, &chunks[i].errors[j]);

          hcfree (chunks[i].errors[j].line);
          hcfree (chunks[i].errors[j].reason);
        }

        hcfree (chunks[i].errors);
      }
    }

    memmove (block, block + end, keep);

    time (&now);

    if ((now - prev) > 0)
    {
      time (&prev);

      hashlist_parse_t hashlist_parse;

      hashlist_parse.hashes_cnt   = hashes_cnt;
      hashlist_parse.hashes_avail = hashes_avail;

      EVENT_DATA (EVENT_HASHLIST_PARSE_HASH, &hashlist_parse, sizeof (hashlist_parse_t));
    }

    if (eof == true) break;
  }

  if (changed == true)
  {
    event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u: File changed during runtime. Skipping new data.", hashes->hashfile, changed_line);
  }

  // the loop the caller falls back to asks the file whether it is at its end, and reading through
  // other handles never moved this one

  if (reader_ok == true)
  {
    hashlist_reader_close (&reader);

    hc_fseek (fp, 0, SEEK_END);

    hc_fgetc (fp);
  }

  hcfree (block);
  hcfree (chunks);
  hcfree (threads);
  hcfree (salts);

  *hashes_cnt_ptr = hashes_cnt;
  *line_num_ptr   = line_num;

  return true;
}

int hashes_init_stage1 (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t              *hashes             = hashcat_ctx->hashes;
  module_ctx_t          *module_ctx         = hashcat_ctx->module_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  /**
   * load hashes, part I: find input mode, count hashes
   */

  const char *hashfile      = hashes->hashfile;
  const u32   hashlist_mode = hashes->hashlist_mode;

  u32 hashlist_format = HLFMT_HASHCAT;

  u64 hashes_avail = 0;

  bool parse_threaded = false;

  if ((user_options->benchmark == false) && (user_options->stdout_flag == false) && (user_options->keyspace == false))
  {
    if (hashlist_mode == HL_MODE_ARG)
    {
      hashes_avail = 1;

      if (user_options_extra->association_autosplit == true)
      {
        if (strchr (user_options_extra->hc_hash, hashconfig->separator) == NULL)
        {
          event_log_error (hashcat_ctx, "%s: no username followed by '%c'.", user_options_extra->hc_hash, hashconfig->separator);

          event_log_warning (hashcat_ctx, "Attack mode 9 given only a hash splits it at the first '%c', taking the username in", hashconfig->separator);
          event_log_warning (hashcat_ctx, "front of it as the candidate. Use -p to set a different separator, or name a");
          event_log_warning (hashcat_ctx, "wordlist as a second argument.");
          event_log_warning (hashcat_ctx, NULL);

          return -1;
        }
      }
    }
    else if (hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      HCFILE fp;

      if (hc_fopen (&fp, hashfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashfile, strerror (errno));

        return -1;
      }

      EVENT_DATA (EVENT_HASHLIST_COUNT_LINES_PRE, hashfile, strlen (hashfile));

      if (hashlist_count_lines_threaded (&fp, &hashes_avail) == false)
      {
        hashes_avail = count_lines (&fp);
      }

      EVENT_DATA (EVENT_HASHLIST_COUNT_LINES_POST, hashfile, strlen (hashfile));

      hc_rewind (&fp);

      if (hashes_avail == 0)
      {
        event_log_error (hashcat_ctx, "hashfile is empty or corrupt.");

        hc_fclose (&fp);

        return -1;
      }

      hashlist_format = hlfmt_detect (hashcat_ctx, &fp, 100); // 100 = max numbers to "scan". could be hashes_avail, too

      // A hash file with no separator in it cannot be split into username and hash, so every line would
      // fail to parse and the run would end on "No hashes loaded" with a warning per line and no word
      // about the separator. Said here instead, before any of that, because this is the one thing the
      // user has to change.

      if (user_options_extra->association_autosplit == true)
      {
        hc_rewind (&fp);

        if (hashfile_has_separator (hashcat_ctx, &fp) == false)
        {
          event_log_error (hashcat_ctx, "%s: no line begins with a username followed by '%c'.", hashfile, hashconfig->separator);

          event_log_warning (hashcat_ctx, "Attack mode 9 given only a hash file splits each line at the first '%c', taking the", hashconfig->separator);
          event_log_warning (hashcat_ctx, "username in front of it as the candidate. Use -p to set a different separator, or");
          event_log_warning (hashcat_ctx, "name a wordlist as a second argument to pair the two files by line number.");
          event_log_warning (hashcat_ctx, NULL);

          hc_fclose (&fp);

          return -1;
        }
      }

      hc_fclose (&fp);

      if ((user_options->remove == true) && (hashlist_format != HLFMT_HASHCAT))
      {
        event_log_error (hashcat_ctx, "Use of --remove is not supported in native hashfile-format mode.");

        return -1;
      }
    }
    else if (hashlist_mode == HL_MODE_FILE_BINARY)
    {
      struct stat st;

      if (stat (hashes->hashfile, &st) == -1)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (errno));

        return -1;
      }

      if (module_ctx->module_hash_binary_count != MODULE_DEFAULT)
      {
        const int binary_count = module_ctx->module_hash_binary_count (hashes);

        if (binary_count > 0)
        {
          hashes_avail = binary_count;
        }
        else if (binary_count == 0)
        {
          event_log_error (hashcat_ctx, "No hashes loaded.");

          return -1;
        }
        else if (binary_count == PARSER_HAVE_ERRNO)
        {
          event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (errno));

          return -1;
        }
        else
        {
          event_log_error (hashcat_ctx, "%s: %s", hashes->hashfile, strerror (binary_count));

          return -1;
        }
      }
      else
      {
        hashes_avail = 1;
      }
    }
  }
  else
  {
    hashes_avail = 1;
  }

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT) hashes_avail *= 2;

  hashes->hashlist_format = hashlist_format;

  if (hashlist_mode == HL_MODE_FILE_PLAIN)
  {
    parse_threaded = hashlist_parse_threaded_ok (hashcat_ctx, hashlist_format, hashes_avail);
  }

  /**
   * load hashes, part II: allocate required memory, set pointers
   */

  hash_t *hashes_buf     = (hash_t *) hccalloc (hashes_avail, sizeof (hash_t));
  void   *digests_buf    =            hccalloc (hashes_avail, hashconfig->dgst_size);
  salt_t *salts_buf      = NULL;
  void   *esalts_buf     = NULL;
  void   *hook_salts_buf = NULL;

  if ((user_options->dynamic_x == true) || (user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT) || (user_options->hash_copy == true))
  {
    u64 hash_pos;

    for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
    {
      hashinfo_t *hash_info = (hashinfo_t *) hcmalloc (sizeof (hashinfo_t));

      hashes_buf[hash_pos].hash_info = hash_info;

      if (user_options->dynamic_x == true)
      {
        hash_info->dynamicx = (dynamicx_t *) hcmalloc (sizeof (dynamicx_t));
      }

      if (user_options->username == true)
      {
        hash_info->user = (user_t *) hcmalloc (sizeof (user_t));
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY || user_options->hash_copy == true)
      {
        if (user_options->benchmark == false)
        {
          hash_info->orighash = (char *) hcmalloc (256);
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
      {
        hash_info->split = (split_t *) hcmalloc (sizeof (split_t));
      }
    }
  }

  if (hashconfig->is_salted == true)
  {
    salts_buf = (salt_t *) hccalloc (hashes_avail, sizeof (salt_t));

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // this disables:
      // - sorting by salt value
      // - grouping by salt value
      // - keep the salt in position relative to hashfile (not equal because of some hashes maybe failed to load)

      u64 hash_pos;

      for (hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
      {
        salt_t *salt = &salts_buf[hash_pos];

        salt->orig_pos = hash_pos;
      }
    }

    if (hashconfig->esalt_size > 0)
    {
      esalts_buf = hccalloc (hashes_avail, hashconfig->esalt_size);
    }

    if (hashconfig->hook_salt_size > 0)
    {
      hook_salts_buf = hccalloc (hashes_avail, hashconfig->hook_salt_size);
    }
  }
  else
  {
    salts_buf = (salt_t *) hccalloc (1, sizeof (salt_t));
  }

  hashes->hashes_buf     = hashes_buf;
  hashes->digests_buf    = digests_buf;
  hashes->salts_buf      = salts_buf;
  hashes->esalts_buf     = esalts_buf;
  hashes->hook_salts_buf = hook_salts_buf;

  // the threaded parse sets an entry up in the thread that fills it, so the pass over every entry
  // here would only be 4 GB of writes on one core that the parse is about to make again

  if (parse_threaded == false)
  {
    for (u64 hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
    {
      hashes_init_entry (hashconfig, hashes, hash_pos);
    }
  }

  /**
   * load hashes, part III: parse hashes
   */

  u32 hashes_cnt = 0;

  if (user_options->benchmark == true)
  {
    hashes->hashfile = "-";

    hashes_cnt = 1;
  }
  else if (user_options->hash_info > 0)
  {
  }
  else if (user_options->keyspace == true)
  {
  }
  else if (user_options->stdout_flag == true)
  {
  }
  else if (user_options->backend_info > 0)
  {
  }
  else
  {
    if (hashlist_mode == HL_MODE_ARG)
    {
      char *input_buf = user_options_extra->hc_hash;

      size_t input_len = strlen (input_buf);

      char  *hash_buf = NULL;
      int    hash_len = 0;

      hlfmt_hash (hashcat_ctx, hashlist_format, input_buf, input_len, &hash_buf, &hash_len);

      bool hash_fmt_error = false;

      if (hash_len < 1)     hash_fmt_error = true;
      if (hash_buf == NULL) hash_fmt_error = true;

      if (hash_fmt_error)
      {
        event_log_warning (hashcat_ctx, "Failed to parse hashes using the '%s' format.", strhlfmt (hashlist_format));
      }
      else
      {
        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY || user_options->hash_copy == true)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = hcstrdup (hash_buf);
        }

        if (hashconfig->is_salted == true)
        {
          memset (hashes_buf[0].salt, 0, sizeof (salt_t));
        }

        if (hashconfig->esalt_size > 0)
        {
          memset (hashes_buf[0].esalt, 0, hashconfig->esalt_size);
        }

        if (hashconfig->hook_salt_size > 0)
        {
          memset (hashes_buf[0].hook_salt, 0, hashconfig->hook_salt_size);
        }

        int parser_status = PARSER_OK;

        if (user_options->username == true)
        {
          char *user_buf = NULL;
          int   user_len = 0;

          hlfmt_user (hashcat_ctx, hashlist_format, input_buf, input_len, &user_buf, &user_len);

          // special case:
          // both hash_t need to have the username info if the pwdump format is used (i.e. we have 2 hashes for 3000, both with same user)

          u32 hashes_per_user = 1;

          if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
          {
            // the following conditions should be true if (hashlist_format == HLFMT_PWDUMP)

            if (hash_len == 32)
            {
              hashes_per_user = 2;
            }
          }

          for (u32 i = 0; i < hashes_per_user; i++)
          {
            user_t **user = &hashes_buf[hashes_cnt + i].hash_info->user;

            *user = (user_t *) hcmalloc (sizeof (user_t));

            user_t *user_ptr = *user;

            if (user_buf != NULL)
            {
              user_ptr->user_name = hcstrdup (user_buf);
            }
            else
            {
              user_ptr->user_name = hcstrdup ("");
            }

            user_ptr->user_len = (u32) user_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
        {
          if (hash_len == 32)
          {
            hash_t *hash;

            hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf +  0, 16);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_LEFT;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }

            hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf + 16, 16);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_RIGHT;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }
          }
          else
          {
            hash_t *hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

            if (parser_status == PARSER_OK)
            {
              if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
              {
                parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

                if (parser_status == PARSER_OK)
                {
                  // nothing to do
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
                }
              }

              hashes_buf[hashes_cnt].hash_info->split->split_group  = 0;
              hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_NONE;

              hashes_cnt++;
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
            }

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }
          }
        }
        else
        {
          hash_t *hash = &hashes_buf[hashes_cnt];

          parser_error_reset ();

          parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

          if (parser_status == PARSER_OK)
          {
            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status == PARSER_OK)
              {
                // nothing to do
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
              }
            }

            hashes_cnt++;
          }
          else
          {
            event_log_warning (hashcat_ctx, "Hash was parsed as a commandline argument (not as a file, maybe the file doesn't exist?)");
            event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
          }

          if (parser_status == PARSER_TOKEN_LENGTH)
          {
            hashes->parser_token_length_cnt++;
          }
        }
      }
    }
    else if (hashlist_mode == HL_MODE_FILE_PLAIN)
    {
      HCFILE fp;

      if (hc_fopen (&fp, hashfile, "rb") == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", hashfile, strerror (errno));

        return -1;
      }

      u32 line_num = 0;

      char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

      time_t prev = 0;
      time_t now  = 0;

      if (parse_threaded == true)
      {
        if (hashlist_parse_threaded (hashcat_ctx, &fp, &hashes_cnt, hashes_avail, &line_num) == false)
        {
          for (u64 hash_pos = 0; hash_pos < hashes_avail; hash_pos++)
          {
            hashes_init_entry (hashconfig, hashes, hash_pos);
          }
        }
      }

      while (!hc_feof (&fp))
      {
        line_num++;

        const size_t line_len = fgetl (&fp, line_buf, HCBUFSIZ_LARGE);

        if (line_len == 0) continue;

        if (hashes_avail == hashes_cnt)
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s' on line %u: File changed during runtime. Skipping new data.", hashes->hashfile, line_num);

          break;
        }

        char *hash_buf = NULL;
        int   hash_len = 0;

        hlfmt_hash (hashcat_ctx, hashlist_format, line_buf, line_len, &hash_buf, &hash_len);

        bool hash_fmt_error = false;

        if (hash_len < 1)     hash_fmt_error = true;
        if (hash_buf == NULL) hash_fmt_error = true;

        if (hash_fmt_error)
        {
          event_log_warning (hashcat_ctx, "Failed to parse hashes using the '%s' format.", strhlfmt (hashlist_format));

          continue;
        }

        if (user_options->username == true)
        {
          char *user_buf = NULL;
          int   user_len = 0;

          hlfmt_user (hashcat_ctx, hashlist_format, line_buf, line_len, &user_buf, &user_len);

          // special case:
          // both hash_t need to have the username info if the pwdump format is used (i.e. we have 2 hashes for 3000, both with same user)

          u32 hashes_per_user = 1;

          if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
          {
            // the following conditions should be true if (hashlist_format == HLFMT_PWDUMP)

            if (hash_len == 32)
            {
              hashes_per_user = 2;
            }
          }

          for (u32 i = 0; i < hashes_per_user; i++)
          {
            user_t **user = &hashes_buf[hashes_cnt + i].hash_info->user;

            *user = (user_t *) hcmalloc (sizeof (user_t));

            user_t *user_ptr = *user;

            if (user_buf != NULL)
            {
              user_ptr->user_name = hcstrdup (user_buf);
            }
            else
            {
              user_ptr->user_name = hcstrdup ("");
            }

            user_ptr->user_len = (u32) user_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY || user_options->hash_copy == true)
        {
          hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

          hash_info_tmp->orighash = hcstrdup (hash_buf);
        }

        if (hashconfig->is_salted == true)
        {
          const u32 orig_pos = hashes_buf[hashes_cnt].salt->orig_pos;

          memset (hashes_buf[hashes_cnt].salt, 0, sizeof (salt_t));

          hashes_buf[hashes_cnt].salt->orig_pos = orig_pos;
        }

        if (hashconfig->esalt_size > 0)
        {
          memset (hashes_buf[hashes_cnt].esalt, 0, hashconfig->esalt_size);
        }

        if (hashconfig->hook_salt_size > 0)
        {
          memset (hashes_buf[hashes_cnt].hook_salt, 0, hashconfig->hook_salt_size);
        }

        if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
        {
          if (hash_len == 32)
          {
            hash_t *hash;

            hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf +  0, 16);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, parser_error_string (parser_status));
              }

              hcfree (tmp_line_buf);

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_LEFT;

            hashes_cnt++;

            hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf + 16, 16);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, parser_error_string (parser_status));
              }

              hcfree (tmp_line_buf);

              hashes_cnt--;

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                hashes_cnt--;

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_RIGHT;

            hashes_cnt++;
          }
          else
          {
            hash_t *hash = &hashes_buf[hashes_cnt];

            parser_error_reset ();

            int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

            if (parser_status < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, parser_error_string (parser_status));
              }

              hcfree (tmp_line_buf);

              continue;
            }

            if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
            {
              int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

              if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
              {
                char *tmp_line_buf;

                hc_asprintf (&tmp_line_buf, "%s", line_buf);

                compress_terminal_line_length (tmp_line_buf, 38, 32);

                if (user_options->machine_readable == true)
                {
                  event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }
                else
                {
                  event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
                }

                hcfree (tmp_line_buf);

                continue;
              }
            }

            hashes_buf[hashes_cnt].hash_info->split->split_group  = line_num;
            hashes_buf[hashes_cnt].hash_info->split->split_origin = SPLIT_ORIGIN_NONE;

            hashes_cnt++;
          }
        }
        else
        {
          hash_t *hash = &hashes_buf[hashes_cnt];

          parser_error_reset ();

          int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, hash_buf, hash_len);

          if (parser_status < PARSER_GLOBAL_ZERO)
          {
            char *tmp_line_buf;

            hc_asprintf (&tmp_line_buf, "%s", line_buf);

            compress_terminal_line_length (tmp_line_buf, 38, 32);

            if (user_options->machine_readable == true)
            {
              event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status));
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, parser_error_string (parser_status));
            }

            hcfree (tmp_line_buf);

            if (parser_status == PARSER_TOKEN_LENGTH)
            {
              hashes->parser_token_length_cnt++;
            }

            continue;
          }

          if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
          {
            int parser_status_postprocess = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

            if (parser_status_postprocess < PARSER_GLOBAL_ZERO)
            {
              char *tmp_line_buf;

              hc_asprintf (&tmp_line_buf, "%s", line_buf);

              compress_terminal_line_length (tmp_line_buf, 38, 32);

              if (user_options->machine_readable == true)
              {
                event_log_warning (hashcat_ctx, "%s:%u:%s:%s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
              }
              else
              {
                event_log_warning (hashcat_ctx, "Hash parsing error in hashfile: '%s' on line %u (%s): %s", hashes->hashfile, line_num, tmp_line_buf, strparser (parser_status_postprocess));
              }

              hcfree (tmp_line_buf);

              if (parser_status_postprocess == PARSER_TOKEN_LENGTH)
              {
                hashes->parser_token_length_cnt++;
              }

              continue;
            }
          }

          hashes_cnt++;
        }

        time (&now);

        if ((now - prev) == 0) continue;

        time (&prev);

        hashlist_parse_t hashlist_parse;

        hashlist_parse.hashes_cnt   = hashes_cnt;
        hashlist_parse.hashes_avail = hashes_avail;

        EVENT_DATA (EVENT_HASHLIST_PARSE_HASH, &hashlist_parse, sizeof (hashlist_parse_t));
      }

      hashlist_parse_t hashlist_parse;

      hashlist_parse.hashes_cnt   = hashes_cnt;
      hashlist_parse.hashes_avail = hashes_avail;

      EVENT_DATA (EVENT_HASHLIST_PARSE_HASH, &hashlist_parse, sizeof (hashlist_parse_t));

      hcfree (line_buf);

      hc_fclose (&fp);
    }
    else if (hashlist_mode == HL_MODE_FILE_BINARY)
    {
      char *input_buf = user_options_extra->hc_hash;

      size_t input_len = strlen (input_buf);

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY || user_options->hash_copy == true)
      {
        hashinfo_t *hash_info_tmp = hashes_buf[hashes_cnt].hash_info;

        hash_info_tmp->orighash = hcstrdup (input_buf);
      }

      if (hashconfig->is_salted == true)
      {
        memset (hashes_buf[0].salt, 0, sizeof (salt_t));
      }

      if (hashconfig->esalt_size > 0)
      {
        memset (hashes_buf[0].esalt, 0, hashconfig->esalt_size);
      }

      if (hashconfig->hook_salt_size > 0)
      {
        memset (hashes_buf[0].hook_salt, 0, hashconfig->hook_salt_size);
      }

      if (module_ctx->module_hash_binary_parse != MODULE_DEFAULT)
      {
        const int hashes_parsed = module_ctx->module_hash_binary_parse (hashconfig, user_options, user_options_extra, hashes);

        if (hashes_parsed > 0)
        {
          hashes_cnt = hashes_parsed;
        }
        else if (hashes_parsed == 0)
        {
          event_log_warning (hashcat_ctx, "No hashes loaded.");
        }
        else if (hashes_parsed == PARSER_HAVE_ERRNO)
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s': %s", hashes->hashfile, strerror (errno));
        }
        else
        {
          event_log_warning (hashcat_ctx, "Hashfile '%s': %s", hashes->hashfile, strparser (hashes_parsed));
        }
      }
      else
      {
        hash_t *hash = &hashes_buf[hashes_cnt];

        parser_error_reset ();

        int parser_status = module_ctx->module_hash_decode (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, input_buf, input_len);

        if (parser_status == PARSER_OK)
        {
          if (module_ctx->module_hash_decode_postprocess != MODULE_DEFAULT)
          {
            parser_status = module_ctx->module_hash_decode_postprocess (hashconfig, hash->digest, hash->salt, hash->esalt, hash->hook_salt, hash->hash_info, user_options, user_options_extra);

            if (parser_status == PARSER_OK)
            {
              // nothing to do
            }
            else
            {
              event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
            }
          }

          hashes_cnt++;
        }
        else
        {
          event_log_warning (hashcat_ctx, "Hash parsing error: '%s': %s", input_buf, parser_error_string (parser_status));
        }

        if (parser_status == PARSER_TOKEN_LENGTH)
        {
          hashes->parser_token_length_cnt++;
        }
      }
    }
  }

  hashes->hashes_cnt = hashes_cnt;

  if (hashes_cnt)
  {
    EVENT (EVENT_HASHLIST_SORT_HASH_PRE);

    if (hashconfig->is_salted == true)
    {
      if (hc_radix_sort_by_salt (&hashes_buf, hashes_cnt, hashconfig) != 0)
      {
        hc_qsort_r (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash, (void *) hashconfig);
      }
    }
    else
    {
      if (hashes_cnt > RADIX_SORT_THRESHOLD)
      {
        if (hc_radix_sort_by_digest (&hashes_buf, &hashes_cnt, hashconfig, &hashes->digests_buf, hashconfig->dgst_size) != 0)
        {
          hc_qsort_r (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);
        }
        else
        {
          hashes->radix_digests_reordered = true;

          if (hashconfig->potfile_keep_all_hashes == false)
          {
            hashes->radix_deduped = true;
          }
        }
      }
      else
      {
        hc_qsort_r (hashes_buf, hashes_cnt, sizeof (hash_t), sort_by_hash_no_salt, (void *) hashconfig);
      }
    }

    hashes->hashes_buf = hashes_buf;
    hashes->hashes_cnt = hashes_cnt;

    EVENT (EVENT_HASHLIST_SORT_HASH_POST);
  }

  if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
  {
    // update split split_neighbor after sorting
    // see https://github.com/hashcat/hashcat/issues/1034 for good examples for testing

    u32 rights_cnt = 0;

    for (u32 i = 0; i < hashes_cnt; i++)
    {
      if (hashes_buf[i].hash_info->split->split_origin == SPLIT_ORIGIN_RIGHT) rights_cnt++;
    }

    split_right_t *rights = (split_right_t *) hcmalloc (rights_cnt * sizeof (split_right_t));

    u32 rights_pos = 0;

    for (u32 i = 0; i < hashes_cnt; i++)
    {
      if (hashes_buf[i].hash_info->split->split_origin != SPLIT_ORIGIN_RIGHT) continue;

      rights[rights_pos].group = hashes_buf[i].hash_info->split->split_group;
      rights[rights_pos].index = i;

      rights_pos++;
    }

    qsort (rights, rights_cnt, sizeof (split_right_t), sort_by_split_group);

    // for each LEFT entry, binary search for its partner in the sorted RIGHT array

    for (u32 i = 0; i < hashes_cnt; i++)
    {
      split_t *split1 = hashes_buf[i].hash_info->split;

      if (split1->split_origin != SPLIT_ORIGIN_LEFT) continue;

      const int target = split1->split_group;

      // binary search

      u32 lo = 0;
      u32 hi = rights_cnt;

      while (lo < hi)
      {
        u32 mid = lo + (hi - lo) / 2;

        if (rights[mid].group < target)
        {
          lo = mid + 1;
        }
        else
        {
          hi = mid;
        }
      }

      if (lo < rights_cnt && rights[lo].group == target)
      {
        const u32 j = rights[lo].index;

        split1->split_neighbor = j;

        hashes_buf[j].hash_info->split->split_neighbor = i;
      }
    }

    hcfree (rights);
  }

  if (hashes->parser_token_length_cnt > 0)
  {
    event_log_advice (hashcat_ctx, NULL); // we can guarantee that the previous line was not an empty line
    event_log_advice (hashcat_ctx, "* Token length exception: %u/%u hashes", hashes->parser_token_length_cnt, hashes->parser_token_length_cnt + hashes->hashes_cnt);
    event_log_advice (hashcat_ctx, "  This error happens if the wrong hash type is specified, if the hashes are");
    event_log_advice (hashcat_ctx, "  malformed, or if input is otherwise not as expected (for example, if the");
    event_log_advice (hashcat_ctx, "  --username or --dynamic-x option is used but no username or dynamic-tag is present)");
    event_log_advice (hashcat_ctx, NULL);
  }

  return 0;
}

// the two passes stage 2 makes over the sorted hash list: one drops the duplicates the sort put
// next to each other, the other groups the list by salt and copies what it keeps into the buffers
// the rest of the session reads. both ask of every entry only how it compares with the one in
// front of it, and both then copy a fixed amount per entry, so both split across threads once the
// comparing is separated from the moving.

#define HASHES_GROUP_CHUNK_MIN (256 * 1024)

typedef struct hashes_group
{
  int                 phase;

  const hashconfig_t *hashconfig;

  hash_t             *hashes_buf;
  u8                 *marks;

  const u32          *offsets;
  u32                 salts_cnt;

  salt_t             *salts_buf_new;
  char               *digests_buf_new;
  char               *esalts_buf_new;
  char               *hook_salts_buf_new;
  hashinfo_t        **hash_info;

  u32                 idx_from;
  u32                 idx_to;

} hashes_group_t;

static bool hashes_same (const hashconfig_t *hashconfig, const hash_t *h1, const hash_t *h2)
{
  if (hashconfig->is_salted == true)
  {
    if (sort_by_salt (h1->salt, h2->salt) != 0) return false;
  }

  return (sort_by_digest_p0p1 (h1->digest, h2->digest, (void *) hashconfig) == 0);
}

static void *hashes_group_thread (void *p)
{
  hashes_group_t *param = (hashes_group_t *) p;

  const hashconfig_t *hashconfig = param->hashconfig;

  hash_t *hashes_buf = param->hashes_buf;

  if (param->phase == 0)
  {
    u8 *marks = param->marks;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      marks[i] = ((i == 0) || (hashes_same (hashconfig, &hashes_buf[i], &hashes_buf[i - 1]) == false)) ? 1 : 0;
    }

    return NULL;
  }

  if (param->phase == 1)
  {
    u8 *marks = param->marks;

    for (u32 i = param->idx_from; i < param->idx_to; i++)
    {
      marks[i] = ((i == 0) || (sort_by_salt (hashes_buf[i].salt, hashes_buf[i - 1].salt) != 0)) ? 1 : 0;
    }

    return NULL;
  }

  const u32 *offsets = param->offsets;

  const u32 dgst_size      = hashconfig->dgst_size;
  const u32 esalt_size     = hashconfig->esalt_size;
  const u32 hook_salt_size = hashconfig->hook_salt_size;

  salt_t *salts_buf_new = param->salts_buf_new;

  // which salt the first entry of this range belongs to, so the walk below can carry it forward

  u32 lo = 0;
  u32 hi = param->salts_cnt;

  while (lo < hi)
  {
    const u32 mid = lo + ((hi - lo) / 2);

    if (offsets[mid] <= param->idx_from) lo = mid + 1; else hi = mid;
  }

  u32 salt_idx = lo - 1;

  for (u32 i = param->idx_from; i < param->idx_to; i++)
  {
    if (i == offsets[salt_idx + 1]) salt_idx++;

    if (i == offsets[salt_idx])
    {
      salt_t *salt_buf = &salts_buf_new[salt_idx];

      memcpy (salt_buf, hashes_buf[i].salt, sizeof (salt_t));

      salt_buf->digests_cnt    = offsets[salt_idx + 1] - offsets[salt_idx];
      salt_buf->digests_done   = 0;
      salt_buf->digests_offset = offsets[salt_idx];

      if (hook_salt_size > 0)
      {
        memcpy (param->hook_salts_buf_new + ((u64) salt_idx * hook_salt_size), hashes_buf[i].hook_salt, hook_salt_size);
      }

      hashes_buf[i].salt = salt_buf;

      if (hook_salt_size > 0) hashes_buf[i].hook_salt = param->hook_salts_buf_new + ((u64) salt_idx * hook_salt_size);
    }
    else if (hashconfig->is_salted == true)
    {
      hashes_buf[i].salt = &salts_buf_new[salt_idx];

      if (hook_salt_size > 0) hashes_buf[i].hook_salt = param->hook_salts_buf_new + ((u64) salt_idx * hook_salt_size);
    }

    if (param->digests_buf_new != NULL)
    {
      char *digests_buf_new_ptr = param->digests_buf_new + ((u64) i * dgst_size);

      memcpy (digests_buf_new_ptr, hashes_buf[i].digest, dgst_size);

      hashes_buf[i].digest = digests_buf_new_ptr;
    }

    if (esalt_size > 0)
    {
      char *esalts_buf_new_ptr = param->esalts_buf_new + ((u64) i * esalt_size);

      memcpy (esalts_buf_new_ptr, hashes_buf[i].esalt, esalt_size);

      hashes_buf[i].esalt = esalts_buf_new_ptr;
    }

    if (param->hash_info != NULL) param->hash_info[i] = hashes_buf[i].hash_info;
  }

  return NULL;
}

static void hashes_group_run (const hashes_group_t *tmpl, const u32 count, const int phase)
{
  u64 threads_cnt = (u64) hc_get_processor_count ();

  if (threads_cnt < 1) threads_cnt = 1;

  const u64 threads_max = ((u64) count / HASHES_GROUP_CHUNK_MIN) + 1;

  if (threads_cnt > threads_max) threads_cnt = threads_max;

  hc_thread_t    *threads = (hc_thread_t *)    hcmalloc ((size_t) threads_cnt * sizeof (hc_thread_t));
  hashes_group_t *params  = (hashes_group_t *) hcmalloc ((size_t) threads_cnt * sizeof (hashes_group_t));

  if ((threads == NULL) || (params == NULL))
  {
    hcfree (threads);
    hcfree (params);

    hashes_group_t single = *tmpl;

    single.phase    = phase;
    single.idx_from = 0;
    single.idx_to   = count;

    hashes_group_thread (&single);

    return;
  }

  const u64 chunk = ((u64) count + threads_cnt - 1) / threads_cnt;

  for (u64 t = 0; t < threads_cnt; t++)
  {
    u64 idx_from = t * chunk;
    u64 idx_to   = idx_from + chunk;

    if (idx_from > count) idx_from = count;
    if (idx_to   > count) idx_to   = count;

    params[t] = *tmpl;

    params[t].phase    = phase;
    params[t].idx_from = (u32) idx_from;
    params[t].idx_to   = (u32) idx_to;
  }

  for (u64 t = 1; t < threads_cnt; t++)
  {
    hc_thread_create (threads[t], hashes_group_thread, &params[t]);
  }

  hashes_group_thread (&params[0]);

  for (u64 t = 1; t < threads_cnt; t++)
  {
    hc_thread_join (threads[t]);
  }

  hcfree (threads);
  hcfree (params);
}

int hashes_init_stage2 (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
        hashes_t       *hashes       = hashcat_ctx->hashes;
  const user_options_t *user_options = hashcat_ctx->user_options;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  /**
   * Remove duplicates
   */

  EVENT (EVENT_HASHLIST_UNIQUE_HASH_PRE);

  // potfile_keep_all_hashes keeps every one of them, which is what the pass below would do anyway

  if ((hashes->radix_deduped == false) && (hashconfig->potfile_keep_all_hashes == false))
  {
    u8 *marks = (u8 *) hcmalloc (hashes_cnt);

    hashes_group_t tmpl;

    memset (&tmpl, 0, sizeof (hashes_group_t));

    tmpl.hashconfig = hashconfig;
    tmpl.hashes_buf = hashes_buf;
    tmpl.marks      = marks;

    hashes_group_run (&tmpl, hashes_cnt, 0);

    // close the gaps the duplicates leave, one run of survivors at a time

    u32 hashes_cnt_new = 0;

    for (u32 i = 0; i < hashes_cnt; )
    {
      if (marks[i] == 0)
      {
        i++;

        continue;
      }

      u32 j = i;

      while ((j < hashes_cnt) && (marks[j] != 0)) j++;

      if (hashes_cnt_new != i) memmove (&hashes_buf[hashes_cnt_new], &hashes_buf[i], (size_t) (j - i) * sizeof (hash_t));

      hashes_cnt_new += j - i;

      i = j;
    }

    for (u32 i = hashes_cnt_new; i < hashes_cnt; i++)
    {
      memset (&hashes_buf[i], 0, sizeof (hash_t));
    }

    hcfree (marks);

    hashes_cnt = hashes_cnt_new;
  }

  hashes->hashes_cnt = hashes_cnt;

  EVENT (EVENT_HASHLIST_UNIQUE_HASH_POST);

  /**
   * Now generate all the buffers required for later
   */

  void   *digests_buf_new    = NULL;

  if (hashes->radix_digests_reordered == false)
  {
    digests_buf_new = hccalloc (hashes_cnt, hashconfig->dgst_size);
  }

  salt_t *salts_buf_new      = NULL;
  void   *esalts_buf_new     = NULL;
  void   *hook_salts_buf_new = NULL;

  if (hashconfig->is_salted == true)
  {
    salts_buf_new = (salt_t *) hccalloc (hashes_cnt, sizeof (salt_t));
  }
  else
  {
    salts_buf_new = (salt_t *) hccalloc (1, sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    esalts_buf_new = hccalloc (hashes_cnt, hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hook_salts_buf_new = hccalloc (hashes_cnt, hashconfig->hook_salt_size);
  }

  EVENT (EVENT_HASHLIST_SORT_SALT_PRE);

  u32 digests_cnt  = hashes_cnt;
  u32 digests_done = 0;

  u32 *digests_shown = (u32 *) hccalloc (digests_cnt, sizeof (u32));

  u32 salts_cnt   = 0;
  u32 salts_done  = 0;

  hashinfo_t **hash_info = NULL;

  if ((user_options->username == true) || (user_options->dynamic_x == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT) || (user_options->hash_copy == true))
  {
    hash_info = (hashinfo_t **) hccalloc (hashes_cnt, sizeof (hashinfo_t *));
  }

  u32 *salts_shown = (u32 *) hccalloc (digests_cnt, sizeof (u32));

  // where each salt starts, so that a thread handed a range of hashes knows which salt they are in

  u32 *offsets = NULL;

  if (hashconfig->is_salted == true)
  {
    u8 *marks = (u8 *) hcmalloc (hashes_cnt);

    offsets = (u32 *) hcmalloc (((u64) hashes_cnt + 1) * sizeof (u32));

    hashes_group_t tmpl;

    memset (&tmpl, 0, sizeof (hashes_group_t));

    tmpl.hashconfig = hashconfig;
    tmpl.hashes_buf = hashes_buf;
    tmpl.marks      = marks;

    hashes_group_run (&tmpl, hashes_cnt, 1);

    for (u32 i = 0; i < hashes_cnt; i++)
    {
      if (marks[i] != 0) offsets[salts_cnt++] = i;
    }

    offsets[salts_cnt] = hashes_cnt;

    hcfree (marks);
  }
  else
  {
    offsets = (u32 *) hcmalloc (2 * sizeof (u32));

    offsets[0] = 0;
    offsets[1] = hashes_cnt;

    salts_cnt = 1;
  }

  {
    hashes_group_t tmpl;

    memset (&tmpl, 0, sizeof (hashes_group_t));

    tmpl.hashconfig         = hashconfig;
    tmpl.hashes_buf         = hashes_buf;
    tmpl.offsets            = offsets;
    tmpl.salts_cnt          = salts_cnt;
    tmpl.salts_buf_new      = salts_buf_new;
    tmpl.digests_buf_new    = (char *) digests_buf_new;
    tmpl.esalts_buf_new     = (char *) esalts_buf_new;
    tmpl.hook_salts_buf_new = (char *) hook_salts_buf_new;
    tmpl.hash_info          = hash_info;

    hashes_group_run (&tmpl, hashes_cnt, 2);
  }

  hcfree (offsets);

  EVENT (EVENT_HASHLIST_SORT_SALT_POST);

  if (hashes->radix_digests_reordered == false)
  {
    hcfree (hashes->digests_buf);
  }

  hcfree (hashes->salts_buf);
  hcfree (hashes->esalts_buf);
  hcfree (hashes->hook_salts_buf);

  hashes->digests_cnt       = digests_cnt;
  hashes->digests_done      = digests_done;

  if (hashes->radix_digests_reordered == false)
  {
    hashes->digests_buf     = digests_buf_new;
  }

  hashes->digests_shown     = digests_shown;

  hashes->salts_cnt         = salts_cnt;
  hashes->salts_done        = salts_done;
  hashes->salts_buf         = salts_buf_new;
  hashes->salts_shown       = salts_shown;

  hashes->esalts_buf        = esalts_buf_new;
  hashes->hook_salts_buf    = hook_salts_buf_new;

  hashes->hash_info         = hash_info;

  return 0;
}

int hashes_init_stage3 (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t *hashes = hashcat_ctx->hashes;

  u32  digests_done      = hashes->digests_done;
  u32  digests_done_zero = hashes->digests_done_zero;
  u32  digests_done_pot  = hashes->digests_done_pot;
  u32 *digests_shown     = hashes->digests_shown;

  u32  salts_cnt         = hashes->salts_cnt;
  u32  salts_done        = hashes->salts_done;
  u32 *salts_shown       = hashes->salts_shown;

  hash_t *hashes_buf     = hashes->hashes_buf;
  salt_t *salts_buf      = hashes->salts_buf;

  for (u32 salt_idx = 0; salt_idx < salts_cnt; salt_idx++)
  {
    salt_t *salt_buf = salts_buf + salt_idx;

    u32 digests_cnt = salt_buf->digests_cnt;

    for (u32 digest_idx = 0; digest_idx < digests_cnt; digest_idx++)
    {
      const u32 hashes_idx = salt_buf->digests_offset + digest_idx;

      if (hashes_buf[hashes_idx].cracked_pot == 1)
      {
        digests_shown[hashes_idx] = 1;

        digests_done++;

        digests_done_pot++;

        salt_buf->digests_done++;
      }

      if (hashes_buf[hashes_idx].cracked_zero == 1)
      {
        digests_shown[hashes_idx] = 1;

        digests_done++;

        digests_done_zero++;

        salt_buf->digests_done++;
      }
    }

    if (salt_buf->digests_done == salt_buf->digests_cnt)
    {
      salts_shown[salt_idx] = 1;

      salts_done++;
    }

    if (salts_done == salts_cnt) mycracked (hashcat_ctx);
  }

  hashes->digests_done      = digests_done;
  hashes->digests_done_zero = digests_done_zero;
  hashes->digests_done_pot  = digests_done_pot;

  hashes->salts_done        = salts_done;

  return 0;
}

int hashes_init_stage4 (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (hashes->salts_cnt == 1)
    hashconfig->opti_type |= OPTI_TYPE_SINGLE_SALT;

  if (hashes->digests_cnt == 1)
    hashconfig->opti_type |= OPTI_TYPE_SINGLE_HASH;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    hashconfig->opti_type |= OPTI_TYPE_NOT_ITERATED;

  if (user_options->attack_mode == ATTACK_MODE_BF)
    hashconfig->opti_type |= OPTI_TYPE_BRUTE_FORCE;

  if (hashconfig->opti_type & OPTI_TYPE_BRUTE_FORCE)
  {
    if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
    {
      if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
      {
        if (hashconfig->opts_type & OPTS_TYPE_ST_ADD80)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADD80;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADD80;
        }

        if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS14)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS14;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS14;
        }

        if (hashconfig->opts_type & OPTS_TYPE_ST_ADDBITS15)
        {
          hashconfig->opts_type &= ~OPTS_TYPE_ST_ADDBITS15;
          hashconfig->opts_type |=  OPTS_TYPE_PT_ADDBITS15;
        }
      }
    }
  }

  // https://github.com/hashcat/hashcat/issues/3641

  if ((hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL) == 0)
  {
    if ((hashconfig->opts_type & OPTS_TYPE_MULTIHASH_DESPITE_ESALT) == 0)
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
      {
        if (hashconfig->esalt_size > 0)
        {
          if (hashes->digests_cnt != hashes->salts_cnt)
          {
            event_log_error (hashcat_ctx, "This hash-mode plugin cannot crack multiple hashes with the same salt, please select one of the hashes.");

            return -1;
          }
        }
      }
    }
  }

  // test iteration count in association attack

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    salt_t *salts_buf = hashes->salts_buf;

    for (u32 salt_idx = 1; salt_idx < hashes->salts_cnt; salt_idx++)
    {
      if (salts_buf[salt_idx - 1].salt_iter != salts_buf[salt_idx].salt_iter)
      {
        event_log_error (hashcat_ctx, "Mixed iteration counts are not supported in association attack-mode.");

        return -1;
      }
    }
  }

  // at this point we no longer need hash_t* structure

  hash_t *hashes_buf = hashes->hashes_buf;

  hcfree (hashes_buf);

  hashes->hashes_cnt = 0;
  hashes->hashes_buf = NULL;

  // starting from here, we should allocate some scratch buffer for later use

  u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  hashes->out_buf = out_buf;

  // we need two buffers in parallel

  u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

  hashes->tmp_buf = tmp_buf;

  // brain session

  #ifdef WITH_BRAIN
  if (user_options->brain_client == true)
  {
    brain_client_check_features (hashcat_ctx);

    const u32 brain_session = brain_compute_session (hashcat_ctx);

    user_options->brain_session = brain_session;
  }
  #endif

  return 0;
}

int hashes_init_stage5 (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  module_ctx_t         *module_ctx         = hashcat_ctx->module_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  // time to update extra_tmp_size which is tmp_size value based on hash configuration

  if (module_ctx->module_extra_tmp_size != MODULE_DEFAULT)
  {
    const u64 extra_tmp_size = module_ctx->module_extra_tmp_size (hashconfig, user_options, user_options_extra, hashes);

    if ((extra_tmp_size & (1ULL << 62)) || (extra_tmp_size & (1ULL << 63)))
    {
      const u64 salt_pos = extra_tmp_size & 0xffffffff;

      char *tmp_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

      const int tmp_len = hash_encode (hashcat_ctx->user_options, hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, tmp_buf, HCBUFSIZ_LARGE, salt_pos, 0);

      tmp_buf[tmp_len] = 0;

      compress_terminal_line_length (tmp_buf, 47, 6);

      char *user_hash = strdup (tmp_buf);

      if (extra_tmp_size & (1ULL << 62))
      {
        strncpy (tmp_buf, hashconfig->st_hash, HCBUFSIZ_LARGE - 1);

        compress_terminal_line_length (tmp_buf, 47, 6);

        char *st_hash = strdup (tmp_buf);

        event_log_error (hashcat_ctx, "ERROR: Incompatible self-test configuration detected.");

        event_log_warning (hashcat_ctx, "The specified target hash:");
        event_log_warning (hashcat_ctx, "  -> %s", user_hash);
        event_log_warning (hashcat_ctx, "does not match the configuration of the self-test hash:");
        event_log_warning (hashcat_ctx, "  -> %s", st_hash);
        event_log_warning (hashcat_ctx, "The JIT-compiled kernel for this configuration may be incompatible.");
        event_log_warning (hashcat_ctx, "You must disable the self-test functionality or recompile the plugin with a matching self-test hash.");
        event_log_warning (hashcat_ctx, "To disable the self-test, use the --self-test-disable option.");
        event_log_warning (hashcat_ctx, NULL);

        hcfree (tmp_buf);
        hcfree (user_hash);
        hcfree (st_hash);

        return -1;
      }

      if (extra_tmp_size & (1ULL << 63))
      {
        const int tmp_len = hash_encode (hashcat_ctx->user_options, hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, tmp_buf, HCBUFSIZ_LARGE, 0, 0);

        tmp_buf[tmp_len] = 0;

        compress_terminal_line_length (tmp_buf, 47, 6);

        char *user_hash2 = strdup (tmp_buf);

        event_log_error (hashcat_ctx, "ERROR: Mixed configuration detected.");

        event_log_warning (hashcat_ctx, "The specified target hash:");
        event_log_warning (hashcat_ctx, "  -> %s", user_hash);
        event_log_warning (hashcat_ctx, "does not match the configuration of another target hash:");
        event_log_warning (hashcat_ctx, "  -> %s", user_hash2);
        event_log_warning (hashcat_ctx, "Please run these hashes in separate cracking sessions.");
        event_log_warning (hashcat_ctx, NULL);

        hcfree (tmp_buf);
        hcfree (user_hash);
        hcfree (user_hash2);

        return -1;
      }

      hcfree (tmp_buf);
      hcfree (user_hash);
    }

    hashconfig->tmp_size = extra_tmp_size;
  }

  return 0;
}

int hashes_init_selftest (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
  hashes_t        *hashes        = hashcat_ctx->hashes;
  module_ctx_t    *module_ctx    = hashcat_ctx->module_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  if (hashconfig->st_hash == NULL) return 0;

  void   *st_digests_buf    = NULL;
  salt_t *st_salts_buf      = NULL;
  void   *st_esalts_buf     = NULL;
  void   *st_hook_salts_buf = NULL;

  st_digests_buf =          hccalloc (1, hashconfig->dgst_size);

  st_salts_buf = (salt_t *) hccalloc (1, sizeof (salt_t));

  if (hashconfig->esalt_size > 0)
  {
    st_esalts_buf = hccalloc (1, hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    st_hook_salts_buf = hccalloc (1, hashconfig->hook_salt_size);
  }

  hash_t hash;

  hash.digest    = st_digests_buf;
  hash.salt      = st_salts_buf;
  hash.esalt     = st_esalts_buf;
  hash.hook_salt = st_hook_salts_buf;
  hash.cracked   = 0;
  hash.hash_info = NULL;
  hash.pw_buf    = NULL;
  hash.pw_len    = 0;

  int parser_status;

  parser_error_reset ();

  if (module_ctx->module_hash_init_selftest != MODULE_DEFAULT)
  {
    parser_status = module_ctx->module_hash_init_selftest (hashconfig, &hash);
  }
  else
  {
    if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE)
    {
      if (hashconfig->opts_type & OPTS_TYPE_BINARY_HASHFILE_OPTIONAL)
      {
        parser_status = module_ctx->module_hash_decode (hashconfig, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));
      }
      else
      {
        char *tmpfile_bin;

        hc_asprintf (&tmpfile_bin, "%s/selftest.hash", folder_config->session_dir);

        HCFILE fp;

        hc_fopen (&fp, tmpfile_bin, "wb");

        const size_t st_hash_len = strlen (hashconfig->st_hash);

        for (size_t i = 0; i < st_hash_len; i += 2)
        {
          const u8 c = hex_to_u8 ((const u8 *) hashconfig->st_hash + i);

          hc_fputc (c, &fp);
        }

        hc_fclose (&fp);

        parser_status = module_ctx->module_hash_decode (hashconfig, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, tmpfile_bin, strlen (tmpfile_bin));

        unlink (tmpfile_bin);

        hcfree (tmpfile_bin);
      }
    }
    else
    {
      hashconfig_t *hashconfig_st = (hashconfig_t *) hcmalloc (sizeof (hashconfig_t));

      memcpy (hashconfig_st, hashconfig, sizeof (hashconfig_t));

      hashconfig_st->separator = ':';

      if (user_options->hex_salt)
      {
        if (hashconfig->salt_type == SALT_TYPE_GENERIC)
        {
          // this is save as there's no hash mode that has both SALT_TYPE_GENERIC and OPTS_TYPE_ST_HEX by default

          hashconfig_st->opts_type &= ~OPTS_TYPE_ST_HEX;
        }
      }

      parser_status = module_ctx->module_hash_decode (hashconfig_st, hash.digest, hash.salt, hash.esalt, hash.hook_salt, hash.hash_info, hashconfig->st_hash, strlen (hashconfig->st_hash));

      hcfree (hashconfig_st);
    }
  }

  if (parser_status == PARSER_OK)
  {
    // nothing to do
  }
  else
  {
    event_log_error (hashcat_ctx, "Self-test hash parsing error: %s", parser_error_string (parser_status));

    return -1;
  }

  hashes->st_digests_buf    = st_digests_buf;
  hashes->st_salts_buf      = st_salts_buf;
  hashes->st_esalts_buf     = st_esalts_buf;
  hashes->st_hook_salts_buf = st_hook_salts_buf;

  return 0;
}

int hashes_init_benchmark (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
        hashes_t              *hashes             = hashcat_ctx->hashes;
  const module_ctx_t          *module_ctx         = hashcat_ctx->module_ctx;
  const user_options_t        *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  if (user_options->benchmark == false) return 0;

  if (hashconfig->is_salted == false) return 0;

  if (module_ctx->module_benchmark_salt != MODULE_DEFAULT)
  {
    salt_t *ptr = module_ctx->module_benchmark_salt (hashconfig, user_options, user_options_extra);

    memcpy (hashes->salts_buf, ptr, sizeof (salt_t));

    hcfree (ptr);
  }
  else
  {
    memcpy (hashes->salts_buf, hashes->st_salts_buf, sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    if (module_ctx->module_benchmark_esalt != MODULE_DEFAULT)
    {
      void *ptr = module_ctx->module_benchmark_esalt (hashconfig, user_options, user_options_extra);

      memcpy (hashes->esalts_buf, ptr, hashconfig->esalt_size);

      hcfree (ptr);
    }
    else
    {
      memcpy (hashes->esalts_buf, hashes->st_esalts_buf, hashconfig->esalt_size);
    }
  }

  if (hashconfig->hook_salt_size > 0)
  {
    if (module_ctx->module_benchmark_hook_salt != MODULE_DEFAULT)
    {
      void *ptr = module_ctx->module_benchmark_hook_salt (hashconfig, user_options, user_options_extra);

      memcpy (hashes->hook_salts_buf, ptr, hashconfig->hook_salt_size);

      hcfree (ptr);
    }
    else
    {
      memcpy (hashes->hook_salts_buf, hashes->st_hook_salts_buf, hashconfig->hook_salt_size);
    }
  }

  return 0;
}

int hashes_init_zerohash (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;

  // do not use this unless really needed, for example as in LM

  if (module_ctx->module_hash_decode_zero_hash == MODULE_DEFAULT) return 0;

  hash_t *hashes_buf = hashes->hashes_buf;
  u32     hashes_cnt = hashes->hashes_cnt;

  // no solution for these special hash types (for instance because they use hashfile in output etc)

  hash_t hash_buf;

  hash_buf.digest    = hcmalloc (hashconfig->dgst_size);
  hash_buf.salt      = NULL;
  hash_buf.esalt     = NULL;
  hash_buf.hook_salt = NULL;
  hash_buf.cracked   = 0;
  hash_buf.hash_info = NULL;
  hash_buf.pw_buf    = NULL;
  hash_buf.pw_len    = 0;

  if (hashconfig->is_salted == true)
  {
    hash_buf.salt = (salt_t *) hcmalloc (sizeof (salt_t));
  }

  if (hashconfig->esalt_size > 0)
  {
    hash_buf.esalt = hcmalloc (hashconfig->esalt_size);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hash_buf.hook_salt = hcmalloc (hashconfig->hook_salt_size);
  }

  module_ctx->module_hash_decode_zero_hash (hashconfig, hash_buf.digest, hash_buf.salt, hash_buf.esalt, hash_buf.hook_salt, hash_buf.hash_info);

  for (u32 i = 0; i < hashes_cnt; i++)
  {
    hash_t *next = &hashes_buf[i];

    int rc = sort_by_hash_no_salt (&hash_buf, next, (void *) hashconfig);

    if (rc == 0)
    {
      next->pw_buf = (char *) hcmalloc (1);
      next->pw_len = 0;

      next->cracked_zero = 1;

      // should we show the cracked zero hash to the user?

      if (false)
      {
        // digest pos

        const u32 digest_pos = next - hashes_buf;

        // show the crack

        u8 *out_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

        int out_len = hash_encode (hashcat_ctx->user_options, hashcat_ctx->hashconfig, hashcat_ctx->hashes, hashcat_ctx->module_ctx, (char *) out_buf, HCBUFSIZ_LARGE, 0, digest_pos);

        out_buf[out_len] = 0;

        // outfile, can be either to file or stdout
        // if an error occurs opening the file, send to stdout as fallback
        // the fp gets opened for each cracked hash so that the user can modify (move) the outfile while hashcat runs

        outfile_write_open (hashcat_ctx);

        const u8 *plain = (const u8 *) "";

        u8 *tmp_buf = (u8 *) hcmalloc (HCBUFSIZ_LARGE);

        tmp_buf[0] = 0;

        const int tmp_len = outfile_write (hashcat_ctx, (char *) out_buf, out_len, plain, 0, 0, NULL, 0, true, (char *) tmp_buf);

        EVENT_DATA (EVENT_CRACKER_HASH_CRACKED, tmp_buf, tmp_len);

        outfile_write_close (hashcat_ctx);

        hcfree (tmp_buf);
        hcfree (out_buf);
      }
    }
  }

  if (hashconfig->esalt_size > 0)
  {
    hcfree (hash_buf.esalt);
  }

  if (hashconfig->hook_salt_size > 0)
  {
    hcfree (hash_buf.hook_salt);
  }

  if (hashconfig->is_salted == true)
  {
    hcfree (hash_buf.salt);
  }

  hcfree (hash_buf.digest);

  return 0;
}

void hashes_destroy (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  user_options_t *user_options = hashcat_ctx->user_options;

  hcfree (hashes->digests_buf);
  hcfree (hashes->digests_shown);

  hcfree (hashes->salts_buf);
  hcfree (hashes->salts_shown);

  if ((user_options->username == true) || (hashconfig->opts_type & OPTS_TYPE_HASH_COPY) || (user_options->hash_copy == true))
  {
    for (u32 hash_pos = 0; hash_pos < hashes->hashes_cnt; hash_pos++)
    {
      if (user_options->username == true)
      {
        hcfree (hashes->hash_info[hash_pos]->user);
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_COPY || (user_options->hash_copy == true))
      {
        hcfree (hashes->hash_info[hash_pos]->orighash);
      }

      if (hashconfig->opts_type & OPTS_TYPE_HASH_SPLIT)
      {
        hcfree (hashes->hash_info[hash_pos]->split);
      }
    }
  }

  hcfree (hashes->hash_info);

  hcfree (hashes->esalts_buf);
  hcfree (hashes->hook_salts_buf);

  hcfree (hashes->out_buf);
  hcfree (hashes->tmp_buf);

  hcfree (hashes->st_digests_buf);
  hcfree (hashes->st_salts_buf);
  hcfree (hashes->st_esalts_buf);
  hcfree (hashes->st_hook_salts_buf);

  memset (hashes, 0, sizeof (hashes_t));
}

void hashes_logger (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t      *hashes      = hashcat_ctx->hashes;
  logfile_ctx_t *logfile_ctx = hashcat_ctx->logfile_ctx;

  logfile_top_string (hashes->hashfile);
  logfile_top_uint   (hashes->hashlist_mode);
  logfile_top_uint   (hashes->hashlist_format);
  logfile_top_uint   (hashes->hashes_cnt);
  logfile_top_uint   (hashes->digests_cnt);
  logfile_top_uint   (hashes->digests_done_pot);
  logfile_top_uint   (hashes->digests_done_zero);
  logfile_top_uint   (hashes->digests_done);
  logfile_top_uint   (hashes->salts_cnt);
  logfile_top_uint   (hashes->salts_done);
}
