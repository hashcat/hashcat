/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A generic (attack-mode 8) feed that reads a SEEKABLE zstd wordlist: a file of independent,
// line-aligned zstd frames plus a sidecar index (<path>.idx) mapping each frame to its compressed
// offset and the line number it starts at. Because every frame decodes on its own, reaching word N
// decompresses exactly one frame rather than the whole file, so --skip stays O(1) and the wordlist
// stays compressed. This is the seekdb idea (a checkpoint -> position map) applied to frames instead
// of raw byte offsets.
//
// The .zsf / .zsf.idx pair is produced offline by the `zsf` tool (hashcat-seekable repo). A plain
// single-frame .zst also works, but is one frame, i.e. seeking still decodes from the start.
//
//   hashcat -a 8 -m 0 hash.txt feeds/feed_zstd.so wordlist.zsf -r rules/best64.rule

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "memchr.h"
#include "feed.h"

#include <zstd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <inttypes.h>

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

// index sidecar format, identical to prototype/zsf.c
#define ZSF_IDX_MAGIC 0x315A53464B434821ULL

typedef struct
{
  u64 comp_off;
  u64 first_line;
  u64 uncomp_size;
} zsf_entry_t;

typedef struct
{
  char   *path;

  u64    *comp_off;    // [nframes + 1], comp_off[nframes] = filesize
  u64    *first_line;  // [nframes]
  u64    *uncomp_size; // [nframes]

  u64     nframes;
  u64     total_lines;
  u64     filesize;

  size_t  max_comp;    // largest compressed frame, sizes the thread read buffer
  size_t  max_uncomp;  // largest decompressed frame, sizes the thread frame buffer

} zsf_global_t;

typedef struct
{
  int             fd;

  unsigned char  *cbuf;   // one compressed frame
  unsigned char  *dbuf;   // one decompressed frame

  size_t          dlen;   // valid bytes in dbuf
  size_t          doff;   // read cursor in dbuf

  u64             frame;  // frame currently in dbuf, or (u64) -1 when none is loaded
  u64             line;   // global line number of the next candidate

} zsf_thread_t;

static void error_set (generic_global_ctx_t *global_ctx, const char *fmt, ...)
{
  global_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);
  vsnprintf (global_ctx->error_msg, sizeof (global_ctx->error_msg), fmt, ap);
  va_end (ap);
}

static void thread_error_set (generic_thread_ctx_t *thread_ctx, const char *fmt, ...)
{
  thread_ctx->error = true;

  va_list ap;
  va_start (ap, fmt);
  vsnprintf (thread_ctx->error_msg, sizeof (thread_ctx->error_msg), fmt, ap);
  va_end (ap);
}

// Hand out the word that starts here and say where the next one starts. Same contract as the
// wordlist feed: write at most out_size bytes but report the real length, so hashcat rejects an
// over-long word rather than being handed a truncated candidate that is not in the list.

static size_t process_word (const u8 *buf, const size_t max_len, u8 *out_buf, const size_t out_size, size_t *out_len)
{
  size_t word_len = 0;

  const size_t step = hc_line_next (buf, max_len, &word_len);

  const size_t copy_len = MIN (word_len, out_size);

  memcpy ((char *) out_buf, buf, copy_len);

  *out_len = word_len;

  return step;
}

// largest frame with first_line <= offset
static u64 frame_of_line (const zsf_global_t *g, const u64 offset)
{
  u64 lo = 0;
  u64 hi = g->nframes - 1;
  u64 k  = 0;

  while (lo <= hi)
  {
    const u64 mid = lo + (hi - lo) / 2;

    if (g->first_line[mid] <= offset)
    {
      k = mid;
      lo = mid + 1;
    }
    else
    {
      if (mid == 0) break;
      hi = mid - 1;
    }
  }

  return k;
}

// read and decompress frame k into the thread's dbuf
static bool load_frame (generic_thread_ctx_t *thread_ctx, zsf_global_t *g, zsf_thread_t *t, const u64 k)
{
  const u64 comp_start = g->comp_off[k];
  const u64 comp_end   = g->comp_off[k + 1];
  const size_t csize   = (size_t) (comp_end - comp_start);
  const size_t dsize   = (size_t) g->uncomp_size[k];

  ssize_t rd = pread (t->fd, t->cbuf, csize, (off_t) comp_start);

  if (rd < 0 || (size_t) rd != csize)
  {
    thread_error_set (thread_ctx, "%s: short read of frame %" PRIu64, g->path, k);
    return false;
  }

  const size_t ds = ZSTD_decompress (t->dbuf, dsize, t->cbuf, csize);

  if (ZSTD_isError (ds) || ds != dsize)
  {
    thread_error_set (thread_ctx, "%s: frame %" PRIu64 " decode failed", g->path, k);
    return false;
  }

  t->dlen  = ds;
  t->doff  = 0;
  t->frame = k;

  return true;
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zsf_global_t *g = (zsf_global_t *) hccalloc (1, sizeof (zsf_global_t));

  global_ctx->gbldata = g;

  if (global_ctx->workc < 2)
  {
    error_set (global_ctx, "usage: feed_zstd.so <wordlist.zsf> (built by the zsf tool)");
    return false;
  }

  g->path = hcstrdup (global_ctx->workv[1]);

  // file size (end offset of the last frame)

  struct stat st;

  if (stat (g->path, &st) != 0)
  {
    error_set (global_ctx, "%s: cannot stat", g->path);
    return false;
  }

  g->filesize = (u64) st.st_size;

  // read the sidecar index: <path>.idx

  char idxpath[4352];
  snprintf (idxpath, sizeof (idxpath), "%s.idx", g->path);

  FILE *fx = fopen (idxpath, "rb");

  if (fx == NULL)
  {
    error_set (global_ctx, "%s: missing seek index (build it with: zsf build <in> %s)", idxpath, g->path);
    return false;
  }

  u64 hdr[5];

  if (fread (hdr, sizeof (hdr), 1, fx) != 1 || hdr[0] != ZSF_IDX_MAGIC)
  {
    fclose (fx);
    error_set (global_ctx, "%s: not a valid zsf index", idxpath);
    return false;
  }

  g->nframes     = hdr[3];
  g->total_lines = hdr[4];

  if (g->nframes == 0)
  {
    fclose (fx);
    error_set (global_ctx, "%s: empty index", idxpath);
    return false;
  }

  zsf_entry_t *ent = (zsf_entry_t *) hcmalloc (g->nframes * sizeof (zsf_entry_t));

  if (fread (ent, sizeof (zsf_entry_t), g->nframes, fx) != g->nframes)
  {
    hcfree (ent);
    fclose (fx);
    error_set (global_ctx, "%s: truncated index", idxpath);
    return false;
  }

  fclose (fx);

  g->comp_off    = (u64 *) hcmalloc ((g->nframes + 1) * sizeof (u64));
  g->first_line  = (u64 *) hcmalloc (g->nframes * sizeof (u64));
  g->uncomp_size = (u64 *) hcmalloc (g->nframes * sizeof (u64));

  for (u64 i = 0; i < g->nframes; i++)
  {
    g->comp_off[i]    = ent[i].comp_off;
    g->first_line[i]  = ent[i].first_line;
    g->uncomp_size[i] = ent[i].uncomp_size;

    if (ent[i].uncomp_size > g->max_uncomp) g->max_uncomp = (size_t) ent[i].uncomp_size;
  }

  g->comp_off[g->nframes] = g->filesize;

  for (u64 i = 0; i < g->nframes; i++)
  {
    const size_t csize = (size_t) (g->comp_off[i + 1] - g->comp_off[i]);
    if (csize > g->max_comp) g->max_comp = csize;
  }

  hcfree (ent);

  // brain / restore identity: two files with the same size and line count over the same frames are
  // the same attack.

  global_ctx->source_ident = (g->filesize * 1000003ULL) ^ (g->total_lines * 2654435761ULL) ^ g->nframes;

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", g->path);

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zsf_global_t *g = global_ctx->gbldata;

  if (g == NULL) return;

  hcfree (g->comp_off);
  hcfree (g->first_line);
  hcfree (g->uncomp_size);
  hcfree (g->path);
  hcfree (g);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zsf_global_t *g = global_ctx->gbldata;

  return g->total_lines;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  zsf_global_t *g = global_ctx->gbldata;

  zsf_thread_t *t = (zsf_thread_t *) hccalloc (1, sizeof (zsf_thread_t));

  t->fd = open (g->path, O_RDONLY);

  if (t->fd == -1)
  {
    thread_error_set (thread_ctx, "%s: %s", g->path, strerror (errno));
    hcfree (t);
    return false;
  }

  t->cbuf  = (unsigned char *) hcmalloc (g->max_comp);
  t->dbuf  = (unsigned char *) hcmalloc (g->max_uncomp);
  t->frame = (u64) -1;
  t->line  = 0;

  thread_ctx->thrdata = t;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  zsf_thread_t *t = thread_ctx->thrdata;

  if (t == NULL) return;

  if (t->fd != -1) close (t->fd);
  hcfree (t->cbuf);
  hcfree (t->dbuf);
  hcfree (t);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  zsf_global_t *g = global_ctx->gbldata;
  zsf_thread_t *t = thread_ctx->thrdata;

  // hashcat normally seeks before the first candidate; if it did not, start at frame 0

  if (t->frame == (u64) -1)
  {
    if (load_frame (thread_ctx, g, t, 0) == false) return GENERIC_RC_ERROR;
    t->line = 0;
  }

  // advance across empty tails / frame boundaries

  while (t->doff >= t->dlen)
  {
    const u64 next = t->frame + 1;

    if (next >= g->nframes) return GENERIC_RC_EOF;

    if (load_frame (thread_ctx, g, t, next) == false) return GENERIC_RC_ERROR;
  }

  const size_t remaining = t->dlen - t->doff;

  size_t word_len = 0;

  const size_t step = process_word (t->dbuf + t->doff, remaining, out_buf, out_size, &word_len);

  t->doff += (step < remaining) ? (step + 1) : remaining;
  t->line++;

  return (int) word_len;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  zsf_global_t *g = global_ctx->gbldata;
  zsf_thread_t *t = thread_ctx->thrdata;

  if (offset >= g->total_lines)
  {
    thread_error_set (thread_ctx, "seek target past EOF: %" PRIu64, offset);
    return false;
  }

  const u64 k = frame_of_line (g, offset);

  if (load_frame (thread_ctx, g, t, k) == false) return false;

  // walk forward to the exact line inside the one decoded frame

  u64 skip = offset - g->first_line[k];

  while (skip && t->doff < t->dlen)
  {
    const u8 *nl = (const u8 *) memchr (t->dbuf + t->doff, '\n', t->dlen - t->doff);

    if (nl == NULL) break;

    t->doff = (size_t) (nl - t->dbuf) + 1;
    skip--;
  }

  t->line = offset;

  return true;
}
