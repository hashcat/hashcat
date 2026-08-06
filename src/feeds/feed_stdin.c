/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Candidates read from standard input.
//
// This is the feed that cannot seek and cannot be counted, and it is the reason both of those are
// part of the plugin interface rather than assumptions hashcat makes. A pipe has no length, so
// keyspace () says GENERIC_KEYSPACE_UNKNOWN and hashcat runs it with no denominator. A pipe has no
// position either, so seek () accepts whatever it is told and reads on from where it is.
//
// WHY seek () CAN SAY YES TO A POSITION IT DID NOT TAKE
//
// Every other feed answers offset N with the same word every time, which is what makes --restore and
// splitting the keyspace across devices work. A pipe cannot: the word at offset N is whichever word
// arrives next. So the offsets hashcat hands out are an accounting fiction here, and the only thing
// that has to hold is that every line is handed out exactly once. The mutex below is what guarantees
// that, and it is the same guarantee the old stdin producer got by holding mux_dispatcher for a whole
// batch.
//
// Refusing the seek instead would be worse than useless. hashcat treats a refused seek as a hard
// error and ends the session, so a second device joining the attack would kill the run.
//
// THE ONE SEEK THAT IS NOT A FICTION, AND WHY THE LAST LINE IS KEPT
//
// hashcat re-reads a candidate when a transform could make it shorter: a 512 byte hex line is a 256
// byte password, so a line too long for the upload buffer is read a second time into a bigger one.
// That second read is a seek back to the offset just read followed by another next (), and a seek
// that did nothing would make it swallow the FOLLOWING line and put it in the over-long line's place.
//
// So the offset is tracked. hashcat's offsets are contiguous once it has seeked, so a seek to the
// offset this thread last returned is the re-read and nothing else is, and the line is handed back out
// of the buffer it is still sitting in. Every other seek moves to a range this thread has not read and
// simply carries on.
//
// The line is handed back exactly as it arrived, minus its line ending. Every transform belongs to
// hashcat, which applies the hash mode's own and the user's to whatever a feed produces.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "shared.h"
#include "thread.h"
#include "generic.h"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// A pipe carries text lines, so everything hashcat can do to a wordlist line applies here too. The
// old stdin producer did the hex decode, the encoding change and the -j rule itself, and these three
// are how a feed asks hashcat to do them instead.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

// How long to wait for a line before looking at whether the session is still running. An interactive
// user typing candidates leaves stdin idle for as long as they like, and a blocking read would make
// hashcat ignore its own quit key for exactly that long.

#define STDIN_SELECT_SEC 1

// After this many successful reads the stream is taken to be a pipe rather than a keyboard, and the
// timeout is dropped. The number is the old producer's and the reason is the same: select () per line
// is a real cost on a fast pipe and it buys nothing once something is clearly feeding it.

#define STDIN_DISABLE_READ_TIMEOUT_AFTER 1000

typedef struct stdin_global
{
  hashcat_ctx_t *hashcat_ctx;

  // One pipe, one cursor, however many devices. A device asks for a range of offsets and gets that
  // many lines, and which lines they are is whatever had arrived by then.

  hc_thread_mutex_t mux;

  bool mux_live;
  bool eof;

  u64 selects_returned;

} stdin_global_t;

typedef struct stdin_thread
{
  char  *buf;
  size_t buf_len;

  // Where the next line this thread hands out sits in hashcat's numbering, and whether buf still
  // holds the one before it. Together they are what tells the re-read seek apart from every other.

  u64  pos;
  bool have;
  bool replay;

} stdin_thread_t;

static void stdin_error (generic_thread_ctx_t *thread_ctx, const char *msg)
{
  thread_ctx->error = true;

  snprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), "%s", msg);
}

bool global_init (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  stdin_global_t *stdin_global = hcmalloc (sizeof (stdin_global_t));

  if (stdin_global == NULL) return false;

  stdin_global->hashcat_ctx      = hashcat_ctx;
  stdin_global->eof              = false;
  stdin_global->selects_returned = 0;

  hc_thread_mutex_init (stdin_global->mux);

  stdin_global->mux_live = true;

  global_ctx->gbldata = stdin_global;

  return true;
}

void global_term (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  stdin_global_t *stdin_global = global_ctx->gbldata;

  if (stdin_global == NULL) return;

  if (stdin_global->mux_live == true)
  {
    hc_thread_mutex_delete (stdin_global->mux);

    stdin_global->mux_live = false;
  }

  hcfree (stdin_global);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  return GENERIC_KEYSPACE_UNKNOWN;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  stdin_thread_t *stdin_thread = hcmalloc (sizeof (stdin_thread_t));

  if (stdin_thread == NULL)
  {
    stdin_error (thread_ctx, "hcmalloc failed");

    return false;
  }

  // A line is read whole and then copied out, because hashcat asks for at most PW_MAX bytes and still
  // wants to be told the true length of anything longer so it can reject it.

  stdin_thread->buf = hcmalloc (HCBUFSIZ_LARGE);

  if (stdin_thread->buf == NULL)
  {
    hcfree (stdin_thread);

    stdin_error (thread_ctx, "hcmalloc failed");

    return false;
  }

  stdin_thread->buf_len = 0;
  stdin_thread->pos     = 0;
  stdin_thread->have    = false;
  stdin_thread->replay  = false;

  thread_ctx->thrdata = stdin_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  stdin_thread_t *stdin_thread = thread_ctx->thrdata;

  if (stdin_thread == NULL) return;

  hcfree (stdin_thread->buf);
  hcfree (stdin_thread);

  thread_ctx->thrdata = NULL;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  stdin_global_t *stdin_global = global_ctx->gbldata;
  stdin_thread_t *stdin_thread = thread_ctx->thrdata;

  status_ctx_t *status_ctx = stdin_global->hashcat_ctx->status_ctx;

  // The re-read. The line is still in this thread's buffer and no other thread has been offered it,
  // so nothing has to be locked to hand it back.

  if (stdin_thread->replay == true)
  {
    stdin_thread->replay = false;

    stdin_thread->pos++;

    size_t replay_len = stdin_thread->buf_len;

    if (replay_len > (size_t) out_size) replay_len = (size_t) out_size;

    memcpy (out_buf, stdin_thread->buf, replay_len);

    return (int) stdin_thread->buf_len;
  }

  hc_thread_mutex_lock (stdin_global->mux);

  if (stdin_global->eof == true)
  {
    hc_thread_mutex_unlock (stdin_global->mux);

    return GENERIC_RC_EOF;
  }

  char *line_buf = NULL;

  while (line_buf == NULL)
  {
    if (stdin_global->selects_returned < STDIN_DISABLE_READ_TIMEOUT_AFTER)
    {
      const int rc_select = select_read_timeout_console (STDIN_SELECT_SEC);

      if (rc_select == -1)
      {
        stdin_global->eof = true;

        hc_thread_mutex_unlock (stdin_global->mux);

        return GENERIC_RC_EOF;
      }

      if (rc_select == 0)
      {
        // Nothing has arrived yet. A session that has been asked to stop must not be held here, and a
        // session that is still running goes back round and waits again.

        if (status_ctx->run_thread_level1 == false)
        {
          hc_thread_mutex_unlock (stdin_global->mux);

          return GENERIC_RC_EOF;
        }

        status_ctx->stdin_read_timeout_cnt++;

        continue;
      }

      status_ctx->stdin_read_timeout_cnt = 0;

      stdin_global->selects_returned++;
    }

    line_buf = fgets (stdin_thread->buf, HCBUFSIZ_LARGE - 1, stdin);

    if (line_buf == NULL)
    {
      stdin_global->eof = true;

      hc_thread_mutex_unlock (stdin_global->mux);

      return GENERIC_RC_EOF;
    }
  }

  const size_t line_len = in_superchop (line_buf);

  hc_thread_mutex_unlock (stdin_global->mux);

  stdin_thread->buf_len = line_len;
  stdin_thread->have    = true;

  stdin_thread->pos++;

  // Never write past out_size. hashcat hands out a pointer into the buffer it uploads, so a long line
  // written whole would land on top of the candidate after it. The true length is returned either way
  // and hashcat rejects what will not fit.

  size_t copy_len = line_len;

  if (copy_len > (size_t) out_size) copy_len = (size_t) out_size;

  memcpy (out_buf, line_buf, copy_len);

  return (int) line_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  stdin_thread_t *stdin_thread = thread_ctx->thrdata;

  stdin_thread->replay = false;

  // Going back exactly one line is hashcat re-reading a candidate it could not fit, and that line is
  // still here. Anything else is a move to a range this thread has not read, and a pipe answers that
  // by carrying on: see the note at the top of this file.

  if ((stdin_thread->have == true) && (stdin_thread->pos > 0))
  {
    if (offset == (stdin_thread->pos - 1)) stdin_thread->replay = true;
  }

  stdin_thread->pos = offset;

  return true;
}
