/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "thread.h"

#include "fpga/hcfpga.h"
#include "fpga/hcfpga_pool.h"

#define FPGA_POOL_RANGE_WAVES_MIN  32

#define FPGA_POOL_RATE_ALPHA  0.25

#define FPGA_POOL_REQUEUES_MAX  4

typedef struct pool_member
{
  struct fpga_pool *pool;

  int    idx;

  u32    grain;
  u32    capacity;

  double rate;

  u64    done;
  u64    ns;

  bool   started;

  bool   alive;

  hc_thread_t           tid;
  hc_thread_semaphore_t go;

} pool_member_t;

typedef struct pool_range
{
  u64 from;
  u64 cnt;

  int owner;

} pool_range_t;

struct fpga_pool
{
  pool_member_t members[FPGA_POOL_MAX];
  int           members_cnt;

  u32           chunks;

  u64           total;
  u64           cursor;

  pool_range_t  redo[FPGA_POOL_REDO_MAX];
  int           redo_cnt;

  bool          lost;

  fpga_pool_work_fn fn;
  void             *arg;

  bool          shutdown;

  hc_thread_mutex_t     mux;

  hc_thread_semaphore_t done;
};

static u64 pool_take_locked (fpga_pool_t *pool, pool_member_t *m, u64 *from)
{
  if (m->alive == false) return 0;

  if (pool->redo_cnt > 0)
  {
    int pick = -1;

    for (int i = pool->redo_cnt - 1; i >= 0; i--)
    {
      if (pool->redo[i].owner == m->idx) continue;

      pick = i;

      break;
    }

    if ((pick < 0) && (fpga_pool_alive_cnt (pool) == 1)) pick = pool->redo_cnt - 1;

    if (pick >= 0)
    {
      pool_range_t *r = &pool->redo[pick];

      const u64 cnt = MIN (r->cnt, (u64) m->capacity);

      *from = r->from;

      r->from += cnt;
      r->cnt  -= cnt;

      if (r->cnt == 0)
      {
        pool->redo[pick] = pool->redo[pool->redo_cnt - 1];

        pool->redo_cnt--;
      }

      return cnt;
    }
  }

  const u64 remaining = pool->total - pool->cursor;

  if (remaining == 0) return 0;

  double measured_sum = 0;

  int measured_cnt = 0;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    const pool_member_t *o = &pool->members[i];

    if (o->alive == false) continue;
    if (o->rate <= 0) continue;

    measured_sum += o->rate;

    measured_cnt++;
  }

  const double fallback = (measured_cnt > 0) ? (measured_sum / (double) measured_cnt) : 1.0;

  double wsum = 0;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    const pool_member_t *o = &pool->members[i];

    if (o->alive == false) continue;

    wsum += (o->rate > 0) ? o->rate : fallback;
  }

  const double wself = (m->rate > 0) ? m->rate : fallback;

  const double share = (wsum > 0) ? (wself / wsum) : 1.0;

  const u64 share_all = (u64) ((double) pool->total * share);

  const u64 share_waves = share_all / m->grain;

  u64 ranges = share_waves / FPGA_POOL_RANGE_WAVES_MIN;

  ranges = MIN (ranges, (u64) pool->chunks);
  ranges = MAX (ranges, 1);

  u64 want = share_all / ranges;

  want = (want / m->grain) * m->grain;

  want = MAX (want, (u64) m->grain);
  want = MIN (want, (u64) m->capacity);
  want = MIN (want, remaining);

  u32 widest = m->grain;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    if (pool->members[i].alive == false) continue;

    widest = MAX (widest, pool->members[i].grain);
  }

  bool others_started = true;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    if (i == m->idx) continue;

    if (pool->members[i].alive == false) continue;
    if (pool->members[i].started == true) continue;

    others_started = false;
  }

  const u64 leftover = remaining - want;

  if ((others_started == true) && (leftover > 0) && (leftover <= ((u64) widest * 2)))
  {
    if ((want + leftover) <= (u64) m->capacity) want += leftover;
  }

  *from = pool->cursor;

  pool->cursor += want;

  m->started = true;

  return want;
}

static u64 pool_take (fpga_pool_t *pool, pool_member_t *m, u64 *from)
{
  hc_thread_mutex_lock (pool->mux);

  const u64 cnt = pool_take_locked (pool, m, from);

  hc_thread_mutex_unlock (pool->mux);

  return cnt;
}

static void pool_credit (fpga_pool_t *pool, pool_member_t *m, const u64 cnt, const u64 ns)
{
  hc_thread_mutex_lock (pool->mux);

  m->done += cnt;
  m->ns   += ns;

  const bool usable = (cnt >= ((u64) m->grain * 2)) ? true : false;

  if ((ns > 0) && (usable == true))
  {
    const double inst = ((double) cnt * 1.0e9) / (double) ns;

    m->rate = (m->rate > 0) ? ((m->rate * (1.0 - FPGA_POOL_RATE_ALPHA)) + (inst * FPGA_POOL_RATE_ALPHA)) : inst;
  }

  hc_thread_mutex_unlock (pool->mux);
}

static void pool_requeue (fpga_pool_t *pool, pool_member_t *m, const u64 from, const u64 cnt, const bool dead)
{
  hc_thread_mutex_lock (pool->mux);

  if (dead == true) m->alive = false;

  if (pool->redo_cnt < FPGA_POOL_REDO_MAX)
  {
    pool->redo[pool->redo_cnt].from  = from;
    pool->redo[pool->redo_cnt].cnt   = cnt;
    pool->redo[pool->redo_cnt].owner = m->idx;

    pool->redo_cnt++;
  }
  else
  {
    pool->lost = true;
  }

  hc_thread_mutex_unlock (pool->mux);
}

#if defined (_WIN)
static HC_API_CALL DWORD pool_worker (void *p)
#else
static HC_API_CALL void *pool_worker (void *p)
#endif
{
  pool_member_t *m = (pool_member_t *) p;

  fpga_pool_t *pool = m->pool;

  while (true)
  {
    hc_thread_sem_wait (m->go);

    if (pool->shutdown == true) break;

    u32 requeues = 0;

    while (true)
    {
      u64 from = 0;

      const u64 cnt = pool_take (pool, m, &from);

      if (cnt == 0) break;

      fpga_pool_verdict_t verdict = FPGA_POOL_RETRY;

      for (u32 attempt = 0; attempt <= FPGA_POOL_RETRIES; attempt++)
      {
        const u64 t0 = fpga_now_ns ();

        verdict = pool->fn (pool->arg, m->idx, from, cnt);

        if (verdict == FPGA_POOL_DONE)
        {
          pool_credit (pool, m, cnt, fpga_now_ns () - t0);

          break;
        }

        if (verdict == FPGA_POOL_DEAD) break;
      }

      if (verdict == FPGA_POOL_DEAD)
      {
        pool_requeue (pool, m, from, cnt, true);

        break;
      }

      if (verdict == FPGA_POOL_DONE)
      {
        requeues = 0;

        continue;
      }

      pool_requeue (pool, m, from, cnt, false);

      requeues++;

      if (requeues >= FPGA_POOL_REQUEUES_MAX) break;
    }

    hc_thread_sem_post (pool->done);
  }

  return 0;
}

fpga_pool_t *fpga_pool_create (const int members, const u32 *grain, const u32 *capacity, const u32 chunks)
{
  if (members <= 0) return NULL;
  if (members > FPGA_POOL_MAX) return NULL;

  fpga_pool_t *pool = (fpga_pool_t *) hccalloc (1, sizeof (fpga_pool_t));

  if (pool == NULL) return NULL;

  pool->members_cnt = members;
  pool->chunks      = MAX (chunks, 1u);

  hc_thread_mutex_init (pool->mux);

  hc_thread_sem_init (pool->done);

  for (int i = 0; i < members; i++)
  {
    pool_member_t *m = &pool->members[i];

    m->pool     = pool;
    m->idx      = i;
    m->grain    = (grain[i]    > 0) ? grain[i]    : 1;
    m->capacity = (capacity[i] > 0) ? capacity[i] : 1;
    m->alive    = true;

    hc_thread_sem_init (m->go);

    if (hc_thread_create_ok (m->tid, pool_worker, m) == false)
    {
      hc_thread_sem_close (m->go);

      pool->members_cnt = i;

      fpga_pool_destroy (pool);

      return NULL;
    }
  }

  return pool;
}

void fpga_pool_destroy (fpga_pool_t *pool)
{
  if (pool == NULL) return;

  pool->shutdown = true;

  for (int i = 0; i < pool->members_cnt; i++) hc_thread_sem_post (pool->members[i].go);

  hc_thread_t tids[FPGA_POOL_MAX];

  for (int i = 0; i < pool->members_cnt; i++) tids[i] = pool->members[i].tid;

  hc_thread_wait (pool->members_cnt, tids);

  for (int i = 0; i < pool->members_cnt; i++) hc_thread_sem_close (pool->members[i].go);

  hc_thread_sem_close (pool->done);

  hc_thread_mutex_delete (pool->mux);

  hcfree (pool);
}

bool fpga_pool_run (fpga_pool_t *pool, const u64 total, fpga_pool_work_fn fn, void *arg)
{
  if (pool == NULL) return false;

  if (total == 0) return true;

  pool->total    = total;
  pool->cursor   = 0;
  pool->redo_cnt = 0;
  pool->lost     = false;
  pool->fn       = fn;
  pool->arg      = arg;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    pool->members[i].done    = 0;
    pool->members[i].ns      = 0;
    pool->members[i].started = false;
  }

  const int rounds_max = (pool->members_cnt * 8) + 8;

  for (int round = 0; round < rounds_max; round++)
  {
    for (int i = 0; i < pool->members_cnt; i++) hc_thread_sem_post (pool->members[i].go);

    for (int i = 0; i < pool->members_cnt; i++) hc_thread_sem_wait (pool->done);

    const bool drained = ((pool->redo_cnt == 0) && (pool->cursor == total)) ? true : false;

    if (drained == true) break;

    if (pool->lost == true) break;

    if (fpga_pool_alive_cnt (pool) == 0) break;
  }

  const bool ok = ((pool->lost == false) && (pool->redo_cnt == 0) && (pool->cursor == total)) ? true : false;

  return ok;
}

bool fpga_pool_alive (const fpga_pool_t *pool, const int member)
{
  if (pool == NULL) return false;

  if (member >= pool->members_cnt) return false;

  const bool result = pool->members[member].alive;

  return result;
}

int fpga_pool_alive_cnt (const fpga_pool_t *pool)
{
  if (pool == NULL) return 0;

  int cnt = 0;

  for (int i = 0; i < pool->members_cnt; i++)
  {
    if (pool->members[i].alive == true) cnt++;
  }

  return cnt;
}

double fpga_pool_rate (const fpga_pool_t *pool, const int member)
{
  if (pool == NULL) return 0;

  if (member >= pool->members_cnt) return 0;

  const double result = pool->members[member].rate;

  return result;
}

u64 fpga_pool_done (const fpga_pool_t *pool, const int member)
{
  if (pool == NULL) return 0;

  if (member >= pool->members_cnt) return 0;

  const u64 result = pool->members[member].done;

  return result;
}
