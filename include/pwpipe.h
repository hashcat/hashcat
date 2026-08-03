/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PWPIPE_H
#define HC_PWPIPE_H

#include <stdbool.h>

#include "thread.h"

// Building a batch of candidates is host work and running it is device work, and until now they took
// turns: the device sat idle while the host read the next words, and the host sat idle while the
// device worked. The pipeline runs the two at the same time. A producer thread fills one slot while
// the caller launches the batch in the other.
//
// A launch is still finished completely before the caller moves on. Nothing about a launch is
// deferred, so a result cannot arrive after the batch it belongs to has been let go. Only the
// PREPARATION of the next batch is moved off the critical path.
//
// The producer is whatever fills a batch: a wordlist reader, a mask generator, stdin. It is handed in
// as a callback, so the same pipeline serves every attack mode.

// Fill one batch. Return 0 on success and -1 on a hard error. A batch that comes back with pws_cnt
// and words_fin both zero means the source is exhausted, which ends the pipeline.

typedef int (*pw_fill_t) (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_batch_t *batch, void *state);

typedef struct pw_pipe
{
  hashcat_ctx_t     *hashcat_ctx;
  hc_device_param_t *device_param;

  pw_fill_t fill;
  void     *state;

  hc_thread_t thread;
  bool        thread_live;

  // A bounded buffer of PW_PIPE_SLOTS batches. free counts slots the producer may write, filled
  // counts batches the caller may take, and the two indices never need a lock because a slot is
  // owned by exactly one side at a time.

  hc_thread_semaphore_t sem_free;
  hc_thread_semaphore_t sem_filled;

  int head;
  int tail;

  bool serial;  // fill on the caller's own thread, with no producer at all
  bool stop;    // the caller is done and the producer should wind up
  bool failed;  // the producer hit a hard error

} pw_pipe_t;

int  pw_pipe_start   (pw_pipe_t *pipe, hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, pw_fill_t fill, void *state, const bool serial);
pw_batch_t *pw_pipe_take (pw_pipe_t *pipe);
void pw_pipe_release (pw_pipe_t *pipe, pw_batch_t *batch);
void pw_pipe_stop    (pw_pipe_t *pipe);
bool pw_pipe_failed  (const pw_pipe_t *pipe);

#endif // HC_PWPIPE_H
