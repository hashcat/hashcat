/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef FEED_WORDLIST_H
#define FEED_WORDLIST_H

#ifndef O_BINARY
#define O_BINARY 0
#endif

// One wordlist. Several of them are laid end to end into a single keyspace, so line 0 of the second
// file is offset line_count-of-the-first. first_line is where that source starts in the global
// numbering, which is what turns a global offset back into a file and a line inside it.

typedef struct feed_source
{
  char *path;

  u64  *seek_db;
  u64   seek_count;
  u64   seek_step;
  u64   line_count;
  u64   size;

  u64   first_line;

} feed_source_t;

typedef struct feed_global
{
  feed_source_t *sources;
  u64            sources_cnt;

  u64            line_count;

} feed_global_t;

// A thread has one source open at a time and moves between them as the offsets it is given move.
// Opening all of them at once would cost a mapping per file per device for no gain, because a
// thread only ever reads one place at a time.

typedef struct feed_thread
{
  HCFILE hcfile;

  size_t fd_off;
  size_t fd_len;
  void  *fd_mem;
  u64    fd_line;

  u64    source_idx;
  bool   source_open;

} feed_thread_t;

bool global_init      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);
void global_term      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);
u64  global_keyspace  (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx);

bool thread_init      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx);
void thread_term      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx);
int  thread_next      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size);
bool thread_seek      (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset);

#endif // FEED_WORDLIST_H
