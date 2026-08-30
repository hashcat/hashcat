/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A feed hashes a wordlist to name the seek database that belongs to it. That is the feed's own
// business and not something the core promises, so xxHash is compiled into this plugin rather than
// resolved out of the library.

#define XXH_INLINE_ALL

#include "xxhash.h"

#include "common.h"
#include "types.h"
#include "memory.h"
#include "convert.h"
#include "filehandling.h"
#include "folder.h"
#include "shared.h"
#include "path.h"
#include "memchr.h"
#include "timer.h"
#include "event.h"
#include "feed.h"
#include "feed_wordlist.h"

#include <fcntl.h>

#if defined (_WIN)
#include "mmap_windows.c"
#else
#include <sys/mman.h>
#endif

// seekdb.c walks a source to count its lines, and a compressed one is walked a window at a time,
// so it needs the refill that source_open () below sets up.

static bool source_fill (feed_thread_t *feed_thread);
static bool source_is_compressed (const char *path);

#include "seekdb.c"

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

static void error_set (generic_global_ctx_t *global_ctx, const char *fmt, ...)
{
  global_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (global_ctx->error_msg, sizeof (global_ctx->error_msg), fmt, ap);

  va_end (ap);
}

// The four per device entry points report here instead, so that one device's failure does not speak
// for the others and does not stay set for the rest of the run.

static void thread_error_set (generic_thread_ctx_t *thread_ctx, const char *fmt, ...)
{
  thread_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);

  vsnprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), fmt, ap);

  va_end (ap);
}

// Hand out the word that starts here, and say where the next one starts. Finding the end of it and
// taking the line ending off is hc_line_next () in memchr.h, which is the same code the stdin feed and
// the line counter use.

static size_t process_word (const u8 *buf, const size_t max_len, u8 *out_buf, const size_t out_size, size_t *out_len)
{
  size_t word_len = 0;

  const size_t step = hc_line_next (buf, max_len, &word_len);

  // hashcat hands out a pointer straight into the buffer it uploads, so there is no room past
  // out_size. Write no more than that, and still report the real length: hashcat rejects an
  // over-length word, and reporting the clipped length instead would hand it a candidate that is
  // not in the wordlist.

  const size_t copy_len = MIN (word_len, out_size);

  memcpy ((char *) out_buf, buf, copy_len);

  *out_len = word_len;

  return step;
}

static int thread_next_source (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size);

/**
 * sources
 */

static bool source_add (generic_global_ctx_t *global_ctx, const char *path)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  struct stat s;

  if (stat (path, &s) == -1)
  {
    error_set (global_ctx, "%s: %s", path, strerror (errno));

    return false;
  }

  // An empty wordlist contributes nothing and is not an error, the same way -a 0 treats one.

  if (s.st_size == 0) return true;

  feed_global->sources = hcrealloc (feed_global->sources, feed_global->sources_cnt * sizeof (feed_source_t), sizeof (feed_source_t));

  feed_source_t *source = &feed_global->sources[feed_global->sources_cnt];

  source->path       = hcstrdup (path);
  source->seek_db    = NULL;
  source->seek_count = 0;
  source->line_count = 0;
  source->size       = 0;
  source->first_line = 0;

  feed_global->sources_cnt++;

  return true;
}

// A directory expands to the files directly inside it, in name order, which is what -a 0 does. The
// order has to be stable, because it is what an offset means.

static bool source_add_path (generic_global_ctx_t *global_ctx, const char *path)
{
  if (hc_path_is_directory (path) == false)
  {
    const bool rc = source_add (global_ctx, path);

    return rc;
  }

  char **files = scan_directory (path);

  if (files == NULL)
  {
    error_set (global_ctx, "%s: %s", path, strerror (errno));

    return false;
  }

  qsort (files, (size_t) count_dictionaries (files), sizeof (char *), sort_by_stringptr);

  for (int i = 0; files[i] != NULL; i++)
  {
    if (hc_path_is_file (files[i]) == false) continue;

    if (source_add (global_ctx, files[i]) == false)
    {
      hcfree (files);

      return false;
    }
  }

  hcfree (files);

  return true;
}

// How big a window of decompressed bytes a compressed source is read through, and how little may
// be left in it before it is refilled. The low mark is what bounds a line: a line longer than it is
// handed over cut short, which hashcat rejects for length anyway, and no wordlist line is near it.

#define FEED_WIN_CAP (1024 * 1024)
#define FEED_WIN_LOW (64 * 1024)

// Whether a path is one of the compressed formats the file layer knows. The file layer decides this
// by the same magic bytes when it opens the file, and this only has to decide it one step earlier,
// because a compressed source is opened and read a different way from a mapped one.

static bool source_is_compressed (const char *path)
{
  int fd = open (path, O_RDONLY);

  if (fd == -1) return false;

  u8 check[6];

  const ssize_t nread = read (fd, check, sizeof (check));

  close (fd);

  if (nread < 4) return false;

  if ((check[0] == 0x1f) && (check[1] == 0x8b) && (check[2] == 0x08)) return true;
  if ((check[0] == 0x28) && (check[1] == 0xb5) && (check[2] == 0x2f) && (check[3] == 0xfd)) return true;

  if (nread < 6) return false;

  if ((check[0] == 0xfd) && (check[1] == 0x37) && (check[2] == 0x7a) && (check[3] == 0x58) && (check[4] == 0x5a) && (check[5] == 0x00)) return true;

  return false;
}

static void source_close (feed_thread_t *feed_thread)
{
  if (feed_thread->source_open == false) return;

  if (feed_thread->compressed == true)
  {
    hcfree (feed_thread->win);

    feed_thread->win = NULL;
  }
  else
  {
    munmap (feed_thread->fd_mem, feed_thread->fd_len);
  }

  hc_fclose (&feed_thread->hcfile);

  feed_thread->source_open = false;
  feed_thread->compressed  = false;
  feed_thread->fd_mem      = NULL;
  feed_thread->fd_len      = 0;
  feed_thread->fd_off      = 0;
}

// Top the window up when it is running low, moving whatever is left of the current line to the
// front first. Answers false only when the source could not be read at all.

static bool source_fill (feed_thread_t *feed_thread)
{
  if (feed_thread->compressed == false) return true;

  const size_t left = feed_thread->fd_len - feed_thread->fd_off;

  if (left >= FEED_WIN_LOW) return true;
  if (feed_thread->win_eof == true) return true;

  if (left > 0) memmove (feed_thread->win, feed_thread->win + feed_thread->fd_off, left);

  feed_thread->win_pos += feed_thread->fd_off;
  feed_thread->fd_off   = 0;
  feed_thread->fd_len   = left;

  const size_t want = feed_thread->win_cap - left;

  const size_t got = hc_fread (feed_thread->win + left, 1, want, &feed_thread->hcfile);

  // A decode error is reported as (size_t) -1, which is not a length. Added to fd_len it makes the
  // window claim to hold SIZE_MAX bytes, and the next reader walks the whole address space looking
  // for a line ending. A corrupt .gz is enough to get here. The window keeps what it already had and
  // the source is finished.

  if (got == (size_t) -1)
  {
    feed_thread->win_eof = true;

    return false;
  }

  feed_thread->fd_len += got;

  if (got < want) feed_thread->win_eof = true;

  return true;
}

// Back to the first byte of the source, which for a compressed one means decoding it again from the
// start. Only a seek backwards needs this, and a seek forwards never does.

static bool source_restart (feed_thread_t *feed_thread)
{
  if (feed_thread->compressed == false)
  {
    feed_thread->fd_off  = 0;
    feed_thread->fd_line = 0;

    return true;
  }

  hc_rewind (&feed_thread->hcfile);

  feed_thread->fd_off  = 0;
  feed_thread->fd_len  = 0;
  feed_thread->fd_line = 0;
  feed_thread->win_pos = 0;
  feed_thread->win_eof = false;

  const bool rc = source_fill (feed_thread);

  return rc;
}

static bool source_open (generic_thread_ctx_t *thread_ctx, feed_global_t *feed_global, const u64 idx)
{
  feed_thread_t *feed_thread = thread_ctx->thrdata;

  if ((feed_thread->source_open == true) && (feed_thread->source_idx == idx)) return true;

  source_close (feed_thread);

  feed_source_t *source = &feed_global->sources[idx];

  const bool compressed = source_is_compressed (source->path);

  // A compressed source goes through hc_fopen (), which decompresses as it is read. An ordinary one
  // goes through hc_fopen_raw () and is mapped, which is what it has always done and what keeps a
  // read down to a pointer and an offset.

  const bool opened = (compressed == true)
                    ? hc_fopen     (&feed_thread->hcfile, source->path, "rb")
                    : hc_fopen_raw (&feed_thread->hcfile, source->path, "rb");

  if (opened == false)
  {
    thread_error_set (thread_ctx, "%s: %s", source->path, hc_fopen_strerror ());

    return false;
  }

  struct stat s;

  if (fstat (feed_thread->hcfile.fd, &s) == -1)
  {
    thread_error_set (thread_ctx, "%s: %s", source->path, strerror (errno));

    hc_fclose (&feed_thread->hcfile);

    return false;
  }

  feed_thread->compressed = compressed;
  feed_thread->file_size  = (u64) s.st_size;

  if (compressed == true)
  {
    feed_thread->win = (u8 *) hcmalloc (FEED_WIN_CAP);

    if (feed_thread->win == NULL)
    {
      thread_error_set (thread_ctx, "%s: out of memory", source->path);

      hc_fclose (&feed_thread->hcfile);

      return false;
    }

    feed_thread->win_cap = FEED_WIN_CAP;
    feed_thread->win_pos = 0;
    feed_thread->win_eof = false;

    feed_thread->fd_mem = feed_thread->win;
    feed_thread->fd_len = 0;
    feed_thread->fd_off = 0;

    source_fill (feed_thread);
  }
  else
  {
    void *fd_mem = mmap (NULL, s.st_size, PROT_READ, MAP_PRIVATE, feed_thread->hcfile.fd, 0);

    if (fd_mem == MAP_FAILED)
    {
      thread_error_set (thread_ctx, "%s: mmap failed", source->path);

      hc_fclose (&feed_thread->hcfile);

      return false;
    }

    feed_thread->fd_mem = fd_mem;
    feed_thread->fd_len = s.st_size;
    feed_thread->fd_off = 0;

    #if !defined (_WIN)
    #ifdef POSIX_MADV_SEQUENTIAL
    posix_madvise (feed_thread->fd_mem, feed_thread->fd_len, POSIX_MADV_SEQUENTIAL);
    #endif
    #endif
  }

  feed_thread->fd_line     = 0;
  feed_thread->source_idx  = idx;
  feed_thread->source_open = true;

  return true;
}

// Which source holds a global line offset. The sources are laid end to end and first_line only
// increases, so this is a plain binary search.

static u64 source_of_offset (const feed_global_t *feed_global, const u64 offset)
{
  u64 lo = 0;
  u64 hi = feed_global->sources_cnt - 1;

  while (lo < hi)
  {
    const u64 mid = lo + ((hi - lo + 1) / 2);

    if (feed_global->sources[mid].first_line > offset)
    {
      hi = mid - 1;
    }
    else
    {
      lo = mid;
    }
  }

  return lo;
}

/**
 * interface
 */

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  // create our own context

  feed_global_t *feed_global = hcmalloc (sizeof (feed_global_t));

  global_ctx->gbldata = feed_global;

  // check user command line arguments

  if (global_ctx->workc < 2)
  {
    error_set (global_ctx, "Invalid parameter count: %d. Count must be at least 2.", global_ctx->workc);

    return false;
  }

  // Every argument after the plugin name is a wordlist or a directory of them, and they are laid end
  // to end into one keyspace. -a 0 runs several dictionaries as several attacks instead, which is why
  // it has to refuse --skip and --limit when there is more than one. Here they keep working.

  for (int i = 1; i < global_ctx->workc; i++)
  {
    if (source_add_path (global_ctx, global_ctx->workv[i]) == false) return false;
  }

  if (feed_global->sources_cnt == 0)
  {
    error_set (global_ctx, "No usable dictionary file found.");

    return false;
  }

  // name the status line after the wordlist rather than after this plugin, because with several
  // sessions running the file is the thing that tells them apart. With more than one source the status
  // line replaces this with the source the run has reached, which needs the line counts and so cannot
  // happen before global_keyspace ().

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", feed_global->sources[0].path);

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  if (feed_global == NULL) return;

  // the segment arrays point at the source paths, so they go first and the paths go with the sources

  hcfree ((void *) global_ctx->segment_names);
  hcfree ((void *) global_ctx->segment_first);

  global_ctx->segments_cnt  = 0;
  global_ctx->segment_names = NULL;
  global_ctx->segment_first = NULL;

  for (u64 i = 0; i < feed_global->sources_cnt; i++)
  {
    hcfree (feed_global->sources[i].path);
    hcfree (feed_global->sources[i].seek_db);
  }

  hcfree (feed_global->sources);

  hcfree (feed_global);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  // The seek database is built by reading a file once, so it borrows the first device's thread
  // context to do it. If that context cannot be set up there is nothing to count, and going on would
  // walk a mapping that was never made.

  if (thread_init (global_ctx, thread_ctx[0]) == false)
  {
    error_set (global_ctx, "%s", thread_ctx[0]->error_msg);

    thread_ctx[0]->error = false;

    return GENERIC_KEYSPACE_UNKNOWN;
  }

  feed_thread_t *feed_thread = thread_ctx[0]->thrdata;

  for (u64 i = 0; i < feed_global->sources_cnt; i++)
  {
    feed_source_t *source = &feed_global->sources[i];

    source->first_line = feed_global->line_count;

    u64 source_ident = 0;
    u64 source_size  = 0;

    char *seekdb_file = seekdb_path (global_ctx, source->path, &source_ident, &source_size);

    if (seekdb_file == NULL)
    {
      error_set (global_ctx, "%s: %s", source->path, strerror (errno));

      thread_term (global_ctx, thread_ctx[0]);

      return GENERIC_KEYSPACE_UNKNOWN;
    }

    // Fold each source into what the feed as a whole reads from, in the order they were given, so that
    // the same files in a different order come out different. They are different: a keyspace position
    // means a different word.

    global_ctx->source_ident = XXH64 (&source_ident, sizeof (source_ident), global_ctx->source_ident);

    source->seek_db = seekdb_load (seekdb_file, &source->seek_count, &source->line_count, &source->size, &source->seek_step, source_ident, source_size);

    if (source->seek_db)
    {
      cache_hit_t cache_hit;

      cache_hit.dictfile      = source->path;
      cache_hit.stat.st_size  = source->size;
      cache_hit.cached_cnt    = source->line_count;
      cache_hit.keyspace      = source->line_count;

      EVENT_DATA (EVENT_WORDLIST_CACHE_HIT, &cache_hit, sizeof (cache_hit));

      hcfree (seekdb_file);

      feed_global->line_count += source->line_count;

      continue;
    }

    if (source_open (thread_ctx[0], feed_global, i) == false)
    {
      error_set (global_ctx, "%s", thread_ctx[0]->error_msg);

      thread_ctx[0]->error = false;

      hcfree (seekdb_file);

      thread_term (global_ctx, thread_ctx[0]);

      return GENERIC_KEYSPACE_UNKNOWN;
    }

    hc_timer_t start;

    hc_timer_set (&start);

    source->seek_db = seekdb_build (feed_thread, seekdb_file, source->path, &source->seek_count, &source->line_count, &source->size, &source->seek_step, source_ident, hashcat_ctx);

    cache_generate_t cache_generate;

    cache_generate.dictfile    = source->path;
    cache_generate.comp        = source->size;
    cache_generate.percent     = 100;
    cache_generate.cnt         = source->line_count;
    cache_generate.cnt2        = source->line_count;
    cache_generate.runtime     = hc_timer_get (start);

    EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));

    hcfree (seekdb_file);

    feed_global->line_count += source->line_count;
  }

  thread_term (global_ctx, thread_ctx[0]);

  // Publish where each source begins so the status line can say which one the run has reached. It has
  // to be here rather than in global_init (), because first_line is only known once every source has
  // been counted. Two flat arrays because that is what the interface hands over, rather than this
  // plugin's own struct.

  const char **segment_names = hcmalloc (feed_global->sources_cnt * sizeof (char *));

  u64 *segment_first = hcmalloc (feed_global->sources_cnt * sizeof (u64));

  for (u64 i = 0; i < feed_global->sources_cnt; i++)
  {
    segment_names[i] = feed_global->sources[i].path;
    segment_first[i] = feed_global->sources[i].first_line;
  }

  global_ctx->segments_cnt  = feed_global->sources_cnt;
  global_ctx->segment_names = segment_names;
  global_ctx->segment_first = segment_first;

  return feed_global->line_count;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  feed_thread_t *feed_thread = hcmalloc (sizeof (feed_thread_t));

  if (feed_thread == NULL)
  {
    thread_error_set (thread_ctx, "hcmalloc failed");

    return false;
  }

  // Nothing is opened here. Which file a device reads depends on the offset it is given, and hashcat
  // always seeks before it asks for the first candidate.

  feed_thread->source_idx  = 0;
  feed_thread->source_open = false;
  feed_thread->compressed  = false;
  feed_thread->win         = NULL;
  feed_thread->win_cap     = 0;
  feed_thread->win_pos     = 0;
  feed_thread->win_eof     = false;
  feed_thread->fd_mem      = NULL;
  feed_thread->fd_len      = 0;
  feed_thread->fd_off      = 0;
  feed_thread->fd_line     = 0;

  thread_ctx->thrdata = feed_thread;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  feed_thread_t *feed_thread = thread_ctx->thrdata;

  if (feed_thread == NULL) return;

  source_close (feed_thread);

  hcfree (feed_thread);

  thread_ctx->thrdata = NULL;
}

// Moving to the next source, and the end of the feed. Kept out of thread_next () so that the common
// case stays a straight read with everything it needs already in registers.

static int thread_next_source (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  feed_thread_t *feed_thread = thread_ctx->thrdata;
  feed_global_t *feed_global = global_ctx->gbldata;

  // hashcat seeks before it asks for the first candidate, so a source is normally already open.
  // Opening the first one here too means the feed still works for anything that does not.

  if (feed_thread->source_open == false)
  {
    if (source_open (thread_ctx, feed_global, 0) == false) return GENERIC_RC_ERROR;
  }

  while (feed_thread->fd_off >= feed_thread->fd_len)
  {
    const u64 next_idx = feed_thread->source_idx + 1;

    if (next_idx >= feed_global->sources_cnt) return GENERIC_RC_EOF;

    if (source_open (thread_ctx, feed_global, next_idx) == false) return GENERIC_RC_ERROR;
  }

  const int word_len = thread_next (global_ctx, thread_ctx, out_buf, out_size);

  return word_len;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  feed_thread_t *feed_thread = thread_ctx->thrdata;

  // A mapped source always has the whole file in front of it. A compressed one has a window, and
  // this is where it is topped up, so that running out of window is not mistaken for running out of
  // source below.

  if (feed_thread->compressed == true) source_fill (feed_thread);

  const u8      *fd_mem = feed_thread->fd_mem;
  const size_t   fd_len = feed_thread->fd_len;
  const size_t   fd_off = feed_thread->fd_off;

  // Out of the current source, or none open yet. Both are rare and both are handled elsewhere.

  if (fd_off >= fd_len)
  {
    const int word_len = thread_next_source (global_ctx, thread_ctx, out_buf, out_size);

    return word_len;
  }

  const size_t remaining = fd_len - fd_off;

  size_t word_len = 0;

  const size_t step = process_word (fd_mem + fd_off, remaining, out_buf, out_size, &word_len);

  // a word with no line ending after it is the last one in the file, and it runs to the end

  feed_thread->fd_off += (step < remaining) ? (step + 1) : remaining;
  feed_thread->fd_line++;

  return (int) word_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  feed_global_t *feed_global = global_ctx->gbldata;

  if (offset >= feed_global->line_count)
  {
    thread_error_set (thread_ctx, "seek target past EOF: %zu", (size_t) offset);

    return false;
  }

  const u64 idx = source_of_offset (feed_global, offset);

  if (source_open (thread_ctx, feed_global, idx) == false) return false;

  feed_thread_t *feed_thread = thread_ctx->thrdata;
  feed_source_t *source      = &feed_global->sources[idx];

  // the offset within this source, now that the source is known

  const u64 local = offset - source->first_line;

  // A compressed source has no byte to jump to. Going forwards is decoding and discarding, which
  // costs what it would have cost to read those lines anyway. Going backwards means starting the
  // file again, so the checkpoints below are of no use here and are not consulted.

  if (feed_thread->compressed == true)
  {
    if (feed_thread->fd_line > local)
    {
      if (source_restart (feed_thread) == false)
      {
        thread_error_set (thread_ctx, "%s: could not restart source", feed_global->sources[idx].path);

        return false;
      }
    }

    while (feed_thread->fd_line < local)
    {
      source_fill (feed_thread);

      const size_t avail = feed_thread->fd_len - feed_thread->fd_off;

      if (avail == 0)
      {
        thread_error_set (thread_ctx, "Seek past EOF");

        return false;
      }

      const u8 *pos = (const u8 *) feed_thread->fd_mem + feed_thread->fd_off;

      const u8 *next = memchr (pos, '\n', avail);

      if (next == NULL)
      {
        // no line ending in what is in hand, so the line runs on into the next window

        feed_thread->fd_off += avail;

        continue;
      }

      feed_thread->fd_off += (size_t) (next - pos) + 1;
      feed_thread->fd_line++;
    }

    return true;
  }

  const u8      *fd_mem = feed_thread->fd_mem;
  const size_t   fd_len = feed_thread->fd_len;

  // The checkpoints land on every seek_step'th line, so the nearest one at or before the target gets
  // the scan down to at most that many lines. The step comes from the database rather than from
  // SEEKDB_STEP, because a database built by an older hashcat may have used a different one.

  bool checkpoint_used = false;

  if ((source->seek_db) && (source->seek_step > 0))
  {
    const u64 db_idx = local / source->seek_step;

    if (db_idx < source->seek_count)
    {
      const u64 db_off = source->seek_db[db_idx];

      // A checkpoint is the first byte of a line, so the byte in front of it is the line ending that
      // closed the one before. Where it is not, this database does not describe this file: the size
      // matched, so a boundary moved without the length changing and the identity hash cannot see
      // that. Ignoring the checkpoint and scanning instead is slow, and it is right.

      if ((db_off == 0) || ((db_off < fd_len) && (fd_mem[db_off - 1] == '\n')))
      {
        feed_thread->fd_off  = db_off;
        feed_thread->fd_line = db_idx * source->seek_step;

        checkpoint_used = true;
      }
    }
  }

  if ((checkpoint_used == false) && (feed_thread->fd_line > local))
  {
    // No checkpoint was usable and the file is already read past the target. The scan below only
    // moves forward, so without this the seek would quietly leave the reader where it was.

    feed_thread->fd_off  = 0;
    feed_thread->fd_line = 0;
  }

  hc_memchr_t hc_memchr = hc_memchr_get ();

  while (feed_thread->fd_line < local)
  {
    if (feed_thread->fd_off >= fd_len)
    {
      thread_error_set (thread_ctx, "Seek past EOF");

      return false;
    }

    const size_t remaining = fd_len - feed_thread->fd_off;

    const size_t step = hc_memchr (fd_mem + feed_thread->fd_off, '\n', remaining);

    // hc_memchr answers with the length it was given when there is no line ending left, so the file
    // holds no further line to move to. The line count a seek database carries is never checked
    // against the file it describes, and one that claims more lines than the file has walked past
    // the end of the mapping here: fd_off went one byte past fd_len and the subtraction above
    // wrapped to an enormous length, which the old empty check could not see.

    if (step == remaining)
    {
      thread_error_set (thread_ctx, "Seek past EOF");

      return false;
    }

    feed_thread->fd_off += step + 1; // +1 for '\n'
    feed_thread->fd_line++;
  }

  return true;
}
