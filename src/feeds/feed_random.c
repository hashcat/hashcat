/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A random password generator, and the smallest feed that is still correct.
//
// It produces words from a deterministic pseudo random sequence, which makes it the simplest kind of
// feed that cannot seek: word number N only exists once the generator has produced the N words before
// it. seek () therefore reseeds and replays, which is what any probabilistic generator has to do, and
// it is the reason a feed does not have to be a file to work under -a 8.
//
// Because the sequence is a pure function of the seed, every device produces the same word for the
// same offset, so hashcat can hand different ranges to different devices and a --restore lands on
// the word it left off at. A generator seeded from the clock or from a thread id cannot do either.
//
// The keyspace is unknown. Returning GENERIC_KEYSPACE_UNKNOWN is how a feed says it will keep going
// until it is stopped, and hashcat then shows a progress count with no denominator.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "feed.h"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;
const int GENERIC_PLUGIN_OPTIONS = 0;

// Any fixed value works. What matters is that it never changes between runs, because it is what
// makes --restore and multi device splitting land on the same words.

static const u64 RANDOM_SEED = 0x2545f4914f6cdd1dULL;

static const char RANDOM_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz0123456789";

typedef struct random_thread
{
  u64 state;
  u64 pos;

} random_thread_t;

// xorshift64*. Small, has no state to allocate and repeats after 2^64 - 1 words, which is more than
// a feed will ever be asked for.

static u64 random_rand (random_thread_t *random_thread)
{
  u64 x = random_thread->state;

  x ^= x >> 12;
  x ^= x << 25;
  x ^= x >> 27;

  random_thread->state = x;

  const u64 result = x * 0x2545f4914f6cdd1dULL;

  return result;
}

static void random_error (generic_thread_ctx_t *thread_ctx, const char *msg)
{
  thread_ctx->error = true;

  snprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), "%s", msg);
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  return GENERIC_KEYSPACE_UNKNOWN;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  random_thread_t *random_thread = hcmalloc (sizeof (random_thread_t));

  if (random_thread == NULL)
  {
    random_error (thread_ctx, "hcmalloc failed");

    return false;
  }

  random_thread->state = RANDOM_SEED;
  random_thread->pos   = 0;

  thread_ctx->thrdata = random_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  hcfree (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  random_thread_t *random_thread = thread_ctx->thrdata;

  // Never write more than out_size. hashcat hands out a pointer into the buffer it uploads, so a
  // long word does not get truncated, it lands on top of something else.

  const u64 r = random_rand (random_thread);

  const int alphabet_len = (int) (sizeof (RANDOM_ALPHABET) - 1);

  int out_len = 6 + (int) (r % 8);

  if (out_len > out_size) out_len = out_size;

  for (int i = 0; i < out_len; i++)
  {
    const u64 c = random_rand (random_thread);

    out_buf[i] = RANDOM_ALPHABET[c % alphabet_len];
  }

  random_thread->pos++;

  return out_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  random_thread_t *random_thread = thread_ctx->thrdata;

  // Seeking forward only has to keep generating. Seeking back has to start over, because a
  // pseudo random sequence has no way to run in reverse.

  if (offset < random_thread->pos)
  {
    random_thread->state = RANDOM_SEED;
    random_thread->pos   = 0;
  }

  u8 scratch[PW_MAX];

  while (random_thread->pos < offset)
  {
    if (thread_next (global_ctx, thread_ctx, scratch, PW_MAX) < 0) return false;
  }

  return true;
}
