/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "shared.h"
#include "wordlist.h"
#include "pwpipe.h"
#include "feed_ctx.h"

// The producer. It owns one slot at a time and never touches the one being launched, so the only
// thing the two sides share is the pair of counting semaphores.

#if defined (_WIN)
static HC_API_CALL DWORD pw_pipe_thread (void *p)
#else
static HC_API_CALL void *pw_pipe_thread (void *p)
#endif
{
  pw_pipe_t *pipe = (pw_pipe_t *) p;

  status_ctx_t *status_ctx = pipe->hashcat_ctx->status_ctx;

  // The device this producer is filling for is made current here, once, for the same reason
  // thread_calc () does it at src/dispatch.c:1123: a feed's thread_next () runs on this thread and
  // may want to talk to that device. Once for the thread rather than once per call, because fill ()
  // asks a feed for one candidate at a time and a driver call per candidate would be a real cost on
  // a path that is already the limit.
  //
  // The serial arrangement has no thread of its own: fill () is called from pw_pipe_take () on the
  // caller's thread, which is thread_calc (), which has already made the same device current. So
  // there is nothing to do there and nothing here to do it in.

  const bool bound = feed_device_bind (pipe->hashcat_ctx, pipe->device_param);

  if (bound == false) pipe->failed = true;

  while (true)
  {
    hc_thread_sem_wait (pipe->sem_free);

    if (pipe->stop == true) break;

    pw_batch_t *batch = &pipe->device_param->pws_slot[pipe->head];

    pw_batch_reset (batch);

    bool last = false;

    if ((status_ctx->run_thread_level1 == false) || (pipe->failed == true))
    {
      last = true;
    }
    else
    {
      if (pipe->fill (pipe->hashcat_ctx, pipe->device_param, batch, pipe->state) == -1)
      {
        pipe->failed = true;

        batch->pws_cnt   = 0;
        batch->words_fin = 0;

        last = true;
      }
      else
      {
        if ((batch->pws_cnt == 0) && (batch->words_fin == 0)) last = true;
      }
    }

    pipe->head = (pipe->head + 1) % PW_PIPE_SLOTS;

    hc_thread_sem_post (pipe->sem_filled);

    if (last == true) break;
  }

  if (bound == true) feed_device_unbind (pipe->hashcat_ctx, pipe->device_param);

  return 0;
}

// HASHCAT_PIPE_SYNC turns the producer back into a plain call on the caller's own thread, which is
// exactly what the code did before the pipeline existed. It is the A/B for measuring what the overlap
// is worth, and it is the switch to reach for if a producer thread ever has to be ruled out.

static bool pw_pipe_sync (void)
{
  static int cache = -1;

  return hc_env_flag ("HASHCAT_PIPE_SYNC", &cache);
}

int pw_pipe_start (pw_pipe_t *pipe, hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_fill_t fill, void *state, const bool serial)
{
  memset (pipe, 0, sizeof (pw_pipe_t));

  pipe->hashcat_ctx  = hashcat_ctx;
  pipe->device_param = device_param;
  pipe->fill         = fill;
  pipe->state        = state;

  // Some producers cannot be run ahead. A brain client reserves, looks up and commits one batch at a
  // time over a single connection, so preparing the next batch early would interleave two batches
  // into one conversation.

  pipe->serial = (serial == true) || (pw_pipe_sync () == true);

  if (pipe->serial == true) return 0;

  hc_thread_sem_init (pipe->sem_free);
  hc_thread_sem_init (pipe->sem_filled);

  for (int i = 0; i < PW_PIPE_SLOTS; i++) hc_thread_sem_post (pipe->sem_free);

  hc_thread_create (pipe->thread, pw_pipe_thread, pipe);

  pipe->thread_live = true;

  return 0;
}

// Blocks until the next batch is ready. Returns NULL once the source is exhausted, which is also
// what a fill error looks like from here: pw_pipe_failed () tells the two apart.

pw_batch_t *pw_pipe_take (pw_pipe_t *pipe)
{
  if (pipe->serial == true)
  {
    pw_batch_t *batch = &pipe->device_param->pws_slot[0];

    pw_batch_reset (batch);

    if (pipe->fill (pipe->hashcat_ctx, pipe->device_param, batch, pipe->state) == -1)
    {
      pipe->failed = true;

      return NULL;
    }

    if ((batch->pws_cnt == 0) && (batch->words_fin == 0)) return NULL;

    return batch;
  }

  hc_thread_sem_wait (pipe->sem_filled);

  pw_batch_t *batch = &pipe->device_param->pws_slot[pipe->tail];

  pipe->tail = (pipe->tail + 1) % PW_PIPE_SLOTS;

  // the terminal batch carries no work and its slot is never handed back, because by the time it is
  // posted the producer has already left

  if ((batch->pws_cnt == 0) && (batch->words_fin == 0)) return NULL;

  return batch;
}

void pw_pipe_release (pw_pipe_t *pipe, MAYBE_UNUSED pw_batch_t *batch)
{
  if (pipe->serial == true) return;

  hc_thread_sem_post (pipe->sem_free);
}

// Winds the producer up and joins it. Safe to call whether the source ran dry on its own or the
// caller walked away from a full pipeline, and safe to call twice.

void pw_pipe_stop (pw_pipe_t *pipe)
{
  if (pipe->thread_live == false) return;

  pipe->stop = true;

  // a producer parked on an empty free count has to be let go, and one slot per depth is enough
  // whatever state the ring is in

  for (int i = 0; i < PW_PIPE_SLOTS; i++) hc_thread_sem_post (pipe->sem_free);

  hc_thread_t threads[1];

  threads[0] = pipe->thread;

  hc_thread_wait (1, threads);

  pipe->thread_live = false;

  hc_thread_sem_close (pipe->sem_free);
  hc_thread_sem_close (pipe->sem_filled);
}

bool pw_pipe_failed (const pw_pipe_t *pipe)
{
  const bool result = pipe->failed;

  return result;
}
