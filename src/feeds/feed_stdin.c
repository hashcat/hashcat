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
// ONE READER, MANY DRAINERS
//
// A pipe has one file descriptor, so it has one reader. That is not a limitation to work around, it is
// the shape of the thing: bytes arrive in one order and somebody has to take them in that order.
//
// So a thread of this feed's own does the reading, in blocks, and it keeps reading for as long as it
// has anywhere to put what it reads. Devices never touch the descriptor. A device that wants
// candidates takes a whole block that has already arrived and then works through it alone, with
// nothing locked, until it is empty.
//
// The cost of a lock is paid once per block instead of once per candidate. A block holds on the order
// of a hundred thousand lines, so the difference is that many times over, and it is the difference
// between a feed that gets slower as devices are added and one that does not. Handing out one line per
// lock, which is what this did before, measured 34.8 M candidates/s with one device and 4.6 M/s with
// sixteen. Every device was spending its time waiting for the same mutex, and the more of them there
// were the less each one got.
//
// WHY seek () CAN SAY YES TO A POSITION IT DID NOT TAKE
//
// Every other feed answers offset N with the same word every time, which is what makes --restore and
// splitting the keyspace across devices work. A pipe cannot: the word at offset N is whichever word
// arrives next. So the offsets hashcat hands out are an accounting fiction here, and the only thing
// that has to hold is that every line is handed out exactly once. A block belongs to one device at a
// time, and that is what guarantees it.
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
// of the block it is still sitting in. A block is only given up when the next one is fetched, never as
// soon as it runs empty, so the line is still there to hand back.
//
// The line is handed back exactly as it arrived, minus its line ending. Every transform belongs to
// hashcat, which applies the hash mode's own and the user's to whatever a feed produces.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "shared.h"
#include "system.h"
#include "memchr.h"
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
// timeout is dropped. The number is the old producer's and the reason is the same: select () per read
// is a real cost on a fast pipe and it buys nothing once something is clearly feeding it.

#define STDIN_DISABLE_READ_TIMEOUT_AFTER 1000

// How much is read at once, and how much of it may be waiting to be worked through. The reader fills
// blocks as fast as the pipe gives them and only stops when every block is full, so this is how far
// ahead of the devices it is allowed to get.
//
// One block is one lock for whoever takes it. At ten bytes a line a block is around a hundred thousand
// candidates, which is what makes the lock too cheap to matter. There have to be more blocks than
// devices, or a device would find nothing waiting every time it came back.

#ifndef STDIN_BLOCK_SIZE
#define STDIN_BLOCK_SIZE (1024 * 1024)
#endif

#ifndef STDIN_BLOCK_CNT
#define STDIN_BLOCK_CNT  32
#endif

// A line longer than a block cannot be assembled, and something is wrong with the input rather than
// with the reader. It is cut here, which is what a fixed size read into a fixed size buffer did before.

typedef struct stdin_block
{
  char *buf;

  // How many bytes of buf are whole lines. A read stops wherever it stops, so the bytes after the last
  // line ending belong to a line that is not finished, and they are carried into the next block.

  size_t len;

} stdin_block_t;

typedef struct stdin_global
{
  hashcat_ctx_t *hashcat_ctx;

  hc_thread_mutex_t mux;

  // Signalled when a block is filled, and when one is given back. The reader waits on the second and
  // the devices wait on the first, so neither spins.

  hc_thread_cond_t cond_filled;
  hc_thread_cond_t cond_free;

  bool sync_live;

  stdin_block_t blocks[STDIN_BLOCK_CNT];

  // Which blocks are free, and which are full and waiting for a device. Both name the blocks rather
  // than counting them, because devices give blocks back in whatever order they finish them and a
  // count cannot say WHICH block that leaves free. Counting was wrong here: the reader would work its
  // way round the ring and refill a block a slower device was still reading out of.
  //
  // Free is a stack, because one free block is as good as another and the most recently freed is the
  // one most likely to still be in cache. Filled is a queue, so devices get the input roughly in the
  // order it arrived.

  int free_list[STDIN_BLOCK_CNT];
  int free_cnt;

  int filled_q[STDIN_BLOCK_CNT];
  int filled_head;
  int filled_tail;
  int filled_cnt;

  bool eof;      // the reader has seen the end of the input
  bool stop;     // the session is over and the reader should wind up

  hc_thread_t reader;
  bool        reader_live;

  u64 selects_returned;


} stdin_global_t;


// Padded and aligned to a cache line, because every candidate writes to this and there is one of these
// per device. Two of them in the same cache line is two cores taking turns to own that line, tens of
// millions of times a second, and it costs more than everything else this feed does put together.
//
// Measured, with one megabyte blocks and a hot page cache: one device 120 M candidates/s, and two
// devices 44 M/s BETWEEN them. The reader was idle and no device ever waited for a block. It was two
// eighty byte allocations landing next to each other. Aligning them takes two devices to 240 M/s.

#define STDIN_CACHELINE 128

typedef struct stdin_thread
{
  // The block this device is working through, and how far into it. It is not given back when it runs
  // empty, only when the next one is fetched, so that a re-read can still find the line it just had.

  int    blk;
  char  *buf;
  size_t len;
  size_t off;

  // Where the line this thread last handed out sits in that block, so a re-read can hand it back
  // without touching the stream.

  size_t last_off;
  size_t last_len;

  u64  pos;
  bool have;
  bool replay;

  char pad[STDIN_CACHELINE - (((sizeof (int) + sizeof (char *) + (5 * sizeof (size_t)) + sizeof (u64) + 2) % STDIN_CACHELINE))];

} stdin_thread_t;

static void stdin_error (generic_thread_ctx_t *thread_ctx, const char *msg)
{
  thread_ctx->error = true;

  snprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), "%s", msg);
}

// The reader. It owns the descriptor and nothing else reads from it.
//
// A block is filled from what is left of the line before it plus whatever the next read returns, and
// only the whole lines in it are published. The remainder is held back and becomes the front of the
// next block, which is what keeps a line from being cut in half between two devices.

#if defined (_WIN)
static HC_API_CALL DWORD stdin_reader (void *p)
#else
static HC_API_CALL void *stdin_reader (void *p)
#endif
{
  stdin_global_t *stdin_global = (stdin_global_t *) p;

  status_ctx_t *status_ctx = stdin_global->hashcat_ctx->status_ctx;

  // What is left of a line that the last read stopped in the middle of

  char  *carry     = (char *) hcmalloc (STDIN_BLOCK_SIZE);
  size_t carry_len = 0;

  while (1)
  {
    hc_thread_mutex_lock (stdin_global->mux);

    while ((stdin_global->free_cnt == 0) && (stdin_global->stop == false))
    {
      hc_thread_cond_wait (stdin_global->cond_free, stdin_global->mux);
    }

    const bool stop = stdin_global->stop;

    int blk = -1;

    if (stop == false)
    {
      stdin_global->free_cnt--;

      blk = stdin_global->free_list[stdin_global->free_cnt];
    }

    hc_thread_mutex_unlock (stdin_global->mux);

    if (stop == true) break;

    char *buf = stdin_global->blocks[blk].buf;

    memcpy (buf, carry, carry_len);

    size_t have = carry_len;

    carry_len = 0;

    // Wait for something to arrive, but not so long that a session being stopped goes unnoticed. Once
    // the stream has proved itself this is dropped, because it costs a syscall per read and an
    // interactive user is long gone by then.

    if (stdin_global->selects_returned < STDIN_DISABLE_READ_TIMEOUT_AFTER)
    {
      int rc_select = 0;

      while (rc_select == 0)
      {
        rc_select = select_read_timeout_console (STDIN_SELECT_SEC);

        if (rc_select == -1) break;

        if (rc_select == 0)
        {
          if (status_ctx->run_thread_level1 == false) break;

          status_ctx->stdin_read_timeout_cnt++;
        }
      }

      if (rc_select <= 0)
      {
        hc_thread_mutex_lock (stdin_global->mux);

        stdin_global->eof = true;

        hc_thread_cond_broadcast (stdin_global->cond_filled);

        hc_thread_mutex_unlock (stdin_global->mux);

        break;
      }

      status_ctx->stdin_read_timeout_cnt = 0;

      stdin_global->selects_returned++;
    }


    const size_t rc_read = fread (buf + have, 1, STDIN_BLOCK_SIZE - have, stdin);


    have += rc_read;

    if (rc_read == 0)
    {
      // The end of the input. Anything held back is a last line with no line ending, and it is a
      // candidate like any other.

      hc_thread_mutex_lock (stdin_global->mux);

      if (have > 0)
      {
        stdin_global->blocks[blk].len = have;

        stdin_global->filled_q[stdin_global->filled_head] = blk;

        stdin_global->filled_head = (stdin_global->filled_head + 1) % STDIN_BLOCK_CNT;

        stdin_global->filled_cnt++;
      }
      else
      {
        stdin_global->free_list[stdin_global->free_cnt] = blk;

        stdin_global->free_cnt++;
      }

      stdin_global->eof = true;

      hc_thread_cond_broadcast (stdin_global->cond_filled);

      hc_thread_mutex_unlock (stdin_global->mux);

      break;
    }

    // Publish the whole lines and keep the rest. A block with no line ending anywhere in it holds a
    // line longer than a block, which is cut here rather than grown into.

    size_t whole = have;

    while ((whole > 0) && (buf[whole - 1] != '\n')) whole--;

    if (whole == 0)
    {
      whole = have;
    }
    else
    {
      carry_len = have - whole;

      memcpy (carry, buf + whole, carry_len);
    }

    hc_thread_mutex_lock (stdin_global->mux);

    stdin_global->blocks[blk].len = whole;

    stdin_global->filled_q[stdin_global->filled_head] = blk;

    stdin_global->filled_head = (stdin_global->filled_head + 1) % STDIN_BLOCK_CNT;

    stdin_global->filled_cnt++;

    hc_thread_cond_signal (stdin_global->cond_filled);

    hc_thread_mutex_unlock (stdin_global->mux);
  }

  hcfree (carry);

  #if defined (_WIN)
  return 0;
  #else
  return NULL;
  #endif
}

bool global_init (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  stdin_global_t *stdin_global = hcmalloc (sizeof (stdin_global_t));

  if (stdin_global == NULL) return false;

  stdin_global->hashcat_ctx      = hashcat_ctx;
  stdin_global->eof              = false;
  stdin_global->stop             = false;
  stdin_global->filled_head      = 0;
  stdin_global->filled_tail      = 0;
  stdin_global->filled_cnt       = 0;
  stdin_global->free_cnt         = 0;
  stdin_global->selects_returned = 0;

  for (int i = 0; i < STDIN_BLOCK_CNT; i++)
  {
    stdin_global->blocks[i].buf = hcmalloc (STDIN_BLOCK_SIZE);
    stdin_global->blocks[i].len = 0;

    if (stdin_global->blocks[i].buf == NULL)
    {
      global_ctx->gbldata = stdin_global;

      return false;
    }

    stdin_global->free_list[i] = i;

    stdin_global->free_cnt++;
  }

  hc_thread_mutex_init (stdin_global->mux);
  hc_thread_cond_init  (stdin_global->cond_filled);
  hc_thread_cond_init  (stdin_global->cond_free);

  stdin_global->sync_live = true;

  global_ctx->gbldata = stdin_global;

  hc_thread_create (stdin_global->reader, stdin_reader, stdin_global);

  stdin_global->reader_live = true;

  return true;
}

void global_term (generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  stdin_global_t *stdin_global = global_ctx->gbldata;

  if (stdin_global == NULL) return;

  if (stdin_global->reader_live == true)
  {
    // The reader may be waiting for a block to come back, and nothing is going to give it one now.

    hc_thread_mutex_lock (stdin_global->mux);

    stdin_global->stop = true;

    hc_thread_cond_broadcast (stdin_global->cond_free);

    hc_thread_mutex_unlock (stdin_global->mux);

    hc_thread_wait (1, &stdin_global->reader);

    stdin_global->reader_live = false;
  }

  if (stdin_global->sync_live == true)
  {
    hc_thread_cond_delete  (stdin_global->cond_filled);
    hc_thread_cond_delete  (stdin_global->cond_free);
    hc_thread_mutex_delete (stdin_global->mux);

    stdin_global->sync_live = false;
  }


  for (int i = 0; i < STDIN_BLOCK_CNT; i++)
  {
    hcfree (stdin_global->blocks[i].buf);
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
  stdin_thread_t *stdin_thread = hc_alloc_aligned (STDIN_CACHELINE, sizeof (stdin_thread_t));

  if (stdin_thread == NULL)
  {
    stdin_error (thread_ctx, "hc_alloc_aligned failed");

    return false;
  }

  memset (stdin_thread, 0, sizeof (stdin_thread_t));

  stdin_thread->blk    = -1;
  stdin_thread->buf    = NULL;
  stdin_thread->len    = 0;
  stdin_thread->off    = 0;
  stdin_thread->pos    = 0;
  stdin_thread->have   = false;
  stdin_thread->replay = false;

  thread_ctx->thrdata = stdin_thread;

  return true;
}

void thread_term (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  stdin_thread_t *stdin_thread = thread_ctx->thrdata;

  if (stdin_thread == NULL) return;

  stdin_global_t *stdin_global = global_ctx->gbldata;

  // Give back whatever this thread was still holding, or the reader would wait for a block that is
  // never coming.

  if ((stdin_global) && (stdin_thread->blk != -1))
  {
    hc_thread_mutex_lock (stdin_global->mux);

    stdin_global->free_list[stdin_global->free_cnt] = stdin_thread->blk;

    stdin_global->free_cnt++;

    hc_thread_cond_signal (stdin_global->cond_free);

    hc_thread_mutex_unlock (stdin_global->mux);
  }

  hc_free_aligned ((void **) &stdin_thread);

  thread_ctx->thrdata = NULL;
}

// Give back the block this thread has finished with and take the next one that has arrived. This is
// the only part of reading a candidate that touches anything shared.

static bool stdin_block_next (stdin_global_t *stdin_global, stdin_thread_t *stdin_thread)
{
  hc_thread_mutex_lock (stdin_global->mux);

  if (stdin_thread->blk != -1)
  {
    stdin_global->free_list[stdin_global->free_cnt] = stdin_thread->blk;

    stdin_global->free_cnt++;

    hc_thread_cond_signal (stdin_global->cond_free);

    stdin_thread->blk = -1;
  }

  while ((stdin_global->filled_cnt == 0) && (stdin_global->eof == false))
  {
    hc_thread_cond_wait (stdin_global->cond_filled, stdin_global->mux);
  }

  if (stdin_global->filled_cnt == 0)
  {
    hc_thread_mutex_unlock (stdin_global->mux);

    return false;
  }

  const int blk = stdin_global->filled_q[stdin_global->filled_tail];

  stdin_global->filled_tail = (stdin_global->filled_tail + 1) % STDIN_BLOCK_CNT;

  stdin_global->filled_cnt--;

  hc_thread_mutex_unlock (stdin_global->mux);

  stdin_thread->blk = blk;
  stdin_thread->buf = stdin_global->blocks[blk].buf;
  stdin_thread->len = stdin_global->blocks[blk].len;
  stdin_thread->off = 0;

  return true;
}

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  stdin_global_t *stdin_global = global_ctx->gbldata;
  stdin_thread_t *stdin_thread = thread_ctx->thrdata;

  // The re-read. The line is still in the block this thread holds and no other thread has been offered
  // it, so nothing has to be locked to hand it back.

  if (stdin_thread->replay == true)
  {
    stdin_thread->replay = false;

    stdin_thread->pos++;

    size_t replay_len = stdin_thread->last_len;

    if (replay_len > (size_t) out_size) replay_len = (size_t) out_size;

    memcpy (out_buf, stdin_thread->buf + stdin_thread->last_off, replay_len);

    return (int) stdin_thread->last_len;
  }

  while (stdin_thread->off >= stdin_thread->len)
  {
    if (stdin_block_next (stdin_global, stdin_thread) == false) return GENERIC_RC_EOF;
  }

  const char *line = stdin_thread->buf + stdin_thread->off;

  const size_t remaining = stdin_thread->len - stdin_thread->off;

  size_t line_len = 0;

  const size_t step = hc_line_next ((const u8 *) line, remaining, &line_len);

  // A block ends on a line ending unless it is the last one, so a line with no ending is the end of the
  // input and runs to the end of the block.

  stdin_thread->off += (step < remaining) ? (step + 1) : remaining;

  stdin_thread->last_off = (size_t) (line - stdin_thread->buf);
  stdin_thread->last_len = line_len;

  stdin_thread->have = true;

  stdin_thread->pos++;

  // Never write past out_size. hashcat hands out a pointer into the buffer it uploads, so a long line
  // written whole would land on top of the candidate after it. The true length is returned either way
  // and hashcat rejects what will not fit.

  size_t copy_len = line_len;

  if (copy_len > (size_t) out_size) copy_len = (size_t) out_size;

  memcpy (out_buf, line, copy_len);

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
