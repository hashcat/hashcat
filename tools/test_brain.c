/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "system.h"

#ifdef NDEBUG
#error Brain tests require assertions
#endif

#include <assert.h>

// Include the implementation to test internal helpers without exporting a test API.

static i64 test_bloom_min = 65536;
static i64 test_enabled_min = 65536;
static bool fail_alloc = false;

static void *test_calloc (const size_t nmemb, const size_t size);
static int test_select_read_timeout (const int fd, const int sec);

#define BRAIN_SERVER_BLOOM_MIN (__atomic_load_n (&test_bloom_min, __ATOMIC_RELAXED))
#define hccalloc test_calloc
#define select_read_timeout test_select_read_timeout
#include "../src/brain.c"
#undef hccalloc
#undef select_read_timeout

static int test_select_read_timeout (const int fd, const int sec)
{
  int rc = 0;

  do
  {
    rc = select_read_timeout (fd, sec);
  }
  while ((rc == -1) && (errno == EINTR) && (keep_running == true));

  return rc;
}

static void *test_calloc (const size_t nmemb, const size_t size)
{
  if (fail_alloc == true)
  {
    fail_alloc = false;

    return NULL;
  }

  void *buf = hccalloc (nmemb, size);

  return buf;
}

static void test_toggle (const int sig)
{
  (void) sig;

  const int saved_errno = errno;
  const i64 current = __atomic_load_n (&test_bloom_min, __ATOMIC_RELAXED);
  const i64 next = (current == 0) ? test_enabled_min : 0;

  __atomic_store_n (&test_bloom_min, next, __ATOMIC_RELAXED);

  const ssize_t written = write (STDERR_FILENO, "Filter toggled\n", 15);

  (void) written;

  errno = saved_errno;
}

static u64 test_random (u64 *state)
{
  *state += 0x9e3779b97f4a7c15ULL;

  const u64 value = brain_server_bloom_mix (*state);

  return value;
}

static brain_server_hash_long_t test_key (const u32 shard, const i64 idx, const i64 cnt)
{
  const u64 step = (1ULL << 54) / (cnt + 1);
  const u64 jitter = brain_server_bloom_mix ((u64) idx ^ ((u64) shard << 32)) % (step / 2);
  const u64 key = ((u64) shard << 54) | (((idx + 1) * step + jitter) & ~1ULL);

  const brain_server_hash_long_t entry = { { (u32) key, (u32) (key >> 32) } };

  return entry;
}

static void test_members (const brain_server_db_shard_t *shard)
{
  for (i64 idx = 0; idx < shard->long_cnt; idx++) assert (brain_server_shard_find (shard, shard->long_buf[idx].hash) == true);
  for (i64 idx = 0; idx < shard->over_cnt; idx++) assert (brain_server_shard_find (shard, shard->over_buf[idx].hash) == true);
}

static void test_correctness (void)
{
  brain_server_db_hash_t db = { 0 };

  brain_server_db_hash_init (&db, 1);

  assert (db.shard_buf != NULL);
  assert (db.long_arena != NULL);
  assert (db.over_arena != NULL);

  brain_server_db_shard_t *shard = &db.shard_buf[0];

  brain_server_hash_long_t *run = calloc (300000, sizeof (*run));

  assert (run != NULL);

  for (u32 idx = 0; idx < 300000; idx++) run[idx].hash[0] = idx * 2;

  assert (brain_server_shard_add (shard, run, 65535) == true);
  assert (shard->bloom_buf == NULL);
  assert (brain_server_shard_add (shard, &run[65535], 1) == true);
  assert (shard->bloom_buf != NULL);

  test_members (shard);

  const u64 old_bits = shard->bloom_bits;

  assert (brain_server_shard_add (shard, &run[65536], 65536) == true);
  assert (shard->bloom_bits > old_bits);

  test_members (shard);

  assert (brain_server_shard_add (shard, &run[131072], 10) == true);
  assert (shard->over_cnt > 0);

  test_members (shard);

  assert (brain_server_shard_compact (shard) == true);
  assert (shard->over_cnt == 0);

  test_members (shard);

  u32 positives = 0;

  for (u32 idx = 0; idx < 100000; idx++)
  {
    const u32 query[2] = { idx * 2 + 1, 0 };

    positives += brain_server_bloom_contains (shard, query);

    assert (brain_server_shard_find (shard, query) == false);
  }

  assert (positives < 5000);

  // Force every negative query to be a Bloom false positive.

  memset (shard->bloom_buf, 0xff, shard->bloom_bits / 8);

  const u32 absent[2] = { 1, 0 };

  assert (brain_server_bloom_contains (shard, absent) == true);
  assert (brain_server_shard_find (shard, absent) == false);

  // A failed resize must leave exact searches usable, including the new run.

  fail_alloc = true;

  assert (brain_server_shard_add (shard, &run[131082], 100000) == true);
  assert (fail_alloc == false);
  assert (shard->bloom_buf == NULL);

  test_members (shard);

  const i64 retry = shard->bloom_retry;

  assert (brain_server_shard_add (shard, &run[231082], 1) == true);
  assert (shard->bloom_buf == NULL);
  assert (shard->bloom_retry == retry);

  shard->bloom_retry = 0;

  brain_server_bloom_update (shard, NULL, 0);

  assert (shard->bloom_buf != NULL);

  test_members (shard);

  // Exercise a compaction failure after the overflow has already changed.

  assert (brain_server_shard_compact (shard) == true);

  assert (brain_server_shard_commit (shard->long_buf, &shard->long_alloc, BRAIN_SERVER_SHARD_ENTRIES, BRAIN_SERVER_SHARD_ENTRIES) == true);

  for (i64 idx = shard->long_cnt; idx < BRAIN_SERVER_SHARD_ENTRIES; idx++) shard->long_buf[idx].hash[0] = (u32) idx * 2;

  shard->long_cnt = BRAIN_SERVER_SHARD_ENTRIES;

  for (u32 idx = 0; idx < 32768; idx++) run[idx].hash[0] = (u32) BRAIN_SERVER_SHARD_ENTRIES * 2 + idx * 2;

  assert (brain_server_shard_add (shard, run, 16384) == true);
  assert (brain_server_shard_add (shard, &run[16384], 16383) == true);
  assert (shard->bloom_buf != NULL);
  assert (brain_server_shard_add (shard, &run[32767], 1) == false);
  assert (shard->bloom_buf == NULL);
  assert (brain_server_shard_find (shard, run[32767].hash) == true);

  test_bloom_min = 8;

  brain_server_db_shard_t *other = &db.shard_buf[1];

  for (u32 idx = 0; idx < 16; idx++) run[idx].hash[1] = 1U << 22;

  fail_alloc = true;

  assert (brain_server_shard_add (other, run, 8) == true);
  assert (fail_alloc == false);
  assert (other->bloom_buf == NULL);

  fail_alloc = true;

  assert (brain_server_shard_add (other, &run[8], 7) == true);
  assert (fail_alloc == true);

  fail_alloc = false;

  assert (brain_server_shard_add (other, &run[15], 1) == true);
  assert (other->bloom_buf != NULL);

  test_members (other);

  test_bloom_min = 0;

  for (u32 idx = 0; idx < 16; idx++) run[idx].hash[1] = 2U << 22;

  assert (brain_server_shard_add (&db.shard_buf[2], run, 16) == true);
  assert (db.shard_buf[2].bloom_buf == NULL);

  free (run);

  brain_server_db_hash_free (&db);

  puts ("Brain filter correctness: passed");
}

static double test_ms (void)
{
  struct timespec now;

  clock_gettime (CLOCK_MONOTONIC, &now);

  const double ms = (double) now.tv_sec * 1000 + (double) now.tv_nsec / 1000000;

  return ms;
}

static int test_double_cmp (const void *a, const void *b)
{
  const double x = ((const double *) a)[0];
  const double y = ((const double *) b)[0];

  const int cmp = (x > y) - (x < y);

  return cmp;
}

static void test_benchmark (const i64 cnt)
{
  brain_server_db_hash_t db = { 0 };

  brain_server_db_hash_init (&db, 1);

  for (u32 s = 0; s < BRAIN_SERVER_SHARD_CNT; s++)
  {
    brain_server_db_shard_t *shard = &db.shard_buf[s];

    const i64 n = cnt / BRAIN_SERVER_SHARD_CNT + (s < cnt % BRAIN_SERVER_SHARD_CNT);
    const i64 over = MIN (n / 32, 2048);

    assert (brain_server_shard_commit (shard->long_buf, &shard->long_alloc, n - over, BRAIN_SERVER_SHARD_ENTRIES) == true);
    assert (brain_server_shard_commit (shard->over_buf, &shard->over_alloc, over, BRAIN_SERVER_OVER_ENTRIES) == true);

    shard->long_cnt = n - over;
    shard->over_cnt = over;

    for (i64 idx = 0; idx < n - over; idx++) shard->long_buf[idx] = test_key (s, idx, n);
    for (i64 idx = 0; idx < over; idx++) shard->over_buf[idx] = test_key (s, n - over + idx, n);
  }

  const double build_start = test_ms ();

  u64 *filters[BRAIN_SERVER_SHARD_CNT];

  u64 bytes = 0;

  for (u32 s = 0; s < BRAIN_SERVER_SHARD_CNT; s++)
  {
    brain_server_bloom_update (&db.shard_buf[s], NULL, 0);

    filters[s] = db.shard_buf[s].bloom_buf;

    bytes += db.shard_buf[s].bloom_bits / 8;
  }

  const double build_ms = test_ms () - build_start;

  printf ("build entries=%" PRIi64 " threshold=%" PRIi64 " ms=%.3f bytes=%" PRIu64 "\n", cnt, test_bloom_min, build_ms, bytes);

  const u32 batches[] = { 65536, 262144, 1048576 };
  const u32 duplicates[] = { 0, 50, 100 };

  for (u32 b = 0; b < 3; b++)
  {
    const u32 n = batches[b];

    brain_server_hash_unique_t *raw = calloc (n, sizeof (*raw));
    brain_server_hash_unique_t *queries = calloc (n, sizeof (*queries));

    assert (raw != NULL);
    assert (queries != NULL);

    for (u32 d = 0; d < 3; d++)
    {
      u64 state = 123456789;
      u64 expected = 0;

      for (u32 idx = 0; idx < n; idx++)
      {
        u64 key = test_random (&state) | 1;

        if (idx % 100 < duplicates[d])
        {
          const u32 s = test_random (&state) % BRAIN_SERVER_SHARD_CNT;
          const i64 entries = db.shard_buf[s].long_cnt + db.shard_buf[s].over_cnt;
          const brain_server_hash_long_t entry = test_key (s, test_random (&state) % entries, entries);

          key = ((u64) entry.hash[1] << 32) | entry.hash[0];

          expected++;
        }

        raw[idx].hash[0] = (u32) key;
        raw[idx].hash[1] = (u32) (key >> 32);
        raw[idx].hash_idx = idx;
      }

      double sorting[2][7];
      double searching[2][7];

      for (u32 r = 0; r < 8; r++)
      {
        for (u32 order = 0; order < 2; order++)
        {
          const u32 enabled = (r + order) % 2;

          for (u32 s = 0; s < BRAIN_SERVER_SHARD_CNT; s++) db.shard_buf[s].bloom_buf = (enabled == 1) ? filters[s] : NULL;

          memcpy (queries, raw, n * sizeof (*raw));

          const double start = test_ms ();

          qsort (queries, n, sizeof (*queries), brain_server_sort_hash_unique);

          const double middle = test_ms ();

          u64 found = 0;
          u32 pos = 0;

          while (pos < n)
          {
            const u32 s = brain_server_shard_idx (queries[pos].hash);

            u32 end = pos + 1;

            while ((end < n) && (brain_server_shard_idx (queries[end].hash) == s)) end++;

            brain_server_db_shard_t *shard = &db.shard_buf[s];

            hc_thread_mutex_lock (shard->mux);

            const bool use_bloom = brain_server_bloom_use (shard, &queries[pos], end - pos);

            for (u32 idx = pos; idx < end; idx++)
            {
              found += (use_bloom == true) ? brain_server_shard_find (shard, queries[idx].hash) : brain_server_shard_find_exact (shard, queries[idx].hash);
            }

            hc_thread_mutex_unlock (shard->mux);

            pos = end;
          }

          const double finish = test_ms ();

          assert (found == expected);

          if (r == 0) continue;

          sorting[enabled][r - 1] = middle - start;
          searching[enabled][r - 1] = finish - middle;
        }
      }

      for (u32 enabled = 0; enabled < 2; enabled++)
      {
        qsort (sorting[enabled], 7, sizeof (double), test_double_cmp);
        qsort (searching[enabled], 7, sizeof (double), test_double_cmp);

        printf ("lookup entries=%" PRIi64 " batch=%u duplicates=%u bloom=%u sort_ms=%.3f search_ms=%.3f\n", cnt, n, duplicates[d], enabled, sorting[enabled][3], searching[enabled][3]);
      }

      fflush (stdout);
    }

    free (queries);
    free (raw);
  }

  for (u32 s = 0; s < BRAIN_SERVER_SHARD_CNT; s++) db.shard_buf[s].bloom_buf = filters[s];

  brain_server_db_hash_free (&db);
}

static void test_dump (const i64 cnt, const char *path)
{
  FILE *fp = fopen (path, "wb");

  assert (fp != NULL);

  for (u32 s = 0; s < BRAIN_SERVER_SHARD_CNT; s++)
  {
    const i64 n = cnt / BRAIN_SERVER_SHARD_CNT + (s < cnt % BRAIN_SERVER_SHARD_CNT);

    brain_server_hash_long_t *buf = calloc (n, sizeof (*buf));

    assert (buf != NULL);

    for (i64 idx = 0; idx < n; idx++) buf[idx] = test_key (s, idx, n);

    assert (fwrite (buf, sizeof (*buf), n, fp) == (size_t) n);

    free (buf);
  }

  assert (fclose (fp) == 0);
}

int main (const int argc, char **const argv)
{
  if (argc == 1)
  {
    test_correctness ();

    return 0;
  }

  if ((argc == 4) && (strcmp (argv[1], "--bench") == 0))
  {
    test_bloom_min = strtoll (argv[3], NULL, 10);

    test_benchmark (strtoll (argv[2], NULL, 10));

    return 0;
  }

  if ((argc == 4) && (strcmp (argv[1], "--dump") == 0))
  {
    test_dump (strtoll (argv[2], NULL, 10), argv[3]);

    return 0;
  }

  if ((argc == 4) && (strcmp (argv[1], "--server") == 0))
  {
    test_bloom_min = strtoll (argv[3], NULL, 10);
    test_enabled_min = test_bloom_min;

    assert (signal (SIGUSR1, test_toggle) != SIG_ERR);

    const int rc = brain_server ("127.0.0.1", atoi (argv[2]), "brain-test", NULL, 0);

    return rc;
  }

  return 2;
}
