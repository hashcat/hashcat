/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef WORDLIST_H
#define WORDLIST_H

#ifndef O_BINARY
#define O_BINARY 0
#endif

// One wordlist. Several of them are laid end to end into a single keyspace, so line 0 of the second
// file is offset line_count-of-the-first. first_line is where that source starts in the global
// numbering, which is what turns a global offset back into a file and a line inside it.

// frame_db is what makes a compressed source seekable, and it is empty for every other kind. Each
// frame of the file gets one entry of SEEKDB_FRAME_WORDS numbers, which say where that frame starts
// in the file on disk, how many decompressed bytes came before it, how far into it the first whole
// line starts, and which line that is. A seek reads the entry, restarts the decoder there and walks
// forward from that line, instead of decoding the whole file up to the line it wants.

typedef struct feed_source
{
  char *path;

  u64  *seek_db;
  u64   seek_count;
  u64   seek_step;
  u64   line_count;
  u64   size;

  u64  *frame_db;
  u64   frame_count;

  u64   first_line;

} feed_source_t;

typedef struct feed_global
{
  feed_source_t *sources;
  u64            sources_cnt;

  u64            line_count;

  // What the sources are, as one number, folded in the order they were given. It is the same value
  // that goes into global_ctx->source_ident, kept here as well because that one carries marks the
  // core puts on it afterwards: a feed offered a device engine and given the host one has its
  // source_ident altered, so a cache keyed on it is a different cache for the same wordlist. A feed
  // caching something per wordlist wants this one.

  u64            ident;

} feed_global_t;

// A thread has one source open at a time and moves between them as the offsets it is given move.
// Opening all of them at once would cost a mapping per file per device for no gain, because a
// thread only ever reads one place at a time.

// A source is read one of two ways. An ordinary wordlist is mapped, and fd_mem is the mapping with
// fd_off an offset into the whole file. A compressed one cannot be mapped, so fd_mem is a window of
// decompressed bytes instead and fd_off is an offset into that window: the same three fields, read
// the same way, refilled underneath when the window runs low.
//
// win_pos is how many uncompressed bytes came before the window, so win_pos + fd_off is the
// position in the decompressed stream, which is what an offset means for a compressed source.

typedef struct feed_thread
{
  HCFILE hcfile;

  size_t fd_off;
  size_t fd_len;
  void  *fd_mem;
  u64    fd_line;

  bool   compressed;

  u8    *win;
  size_t win_cap;
  u64    win_pos;
  bool   win_eof;

  u64    file_size;

  u64    source_idx;
  bool   source_open;

} feed_thread_t;

#endif // WORDLIST_H
