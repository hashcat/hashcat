/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A generic (attack-mode 8) feed that reads a zstd-compressed wordlist and seeks within it without
// decompressing the whole file. A zstd stream is a sequence of independently decodable frames, so a
// small index -- frame k starts at compressed offset X and at line L -- turns "reach word N" into
// "decode the one frame that holds it". That is the seekdb idea (a checkpoint -> position map) moved
// from raw byte offsets, which need a plaintext file, onto frame offsets, which do not. The stock
// mmap wordlist feed cannot seek a compressed file at all.
//
// The index is built on first use by one streaming pass over the file and then cached, named by a
// hash of the file the same way the plaintext seek database is, so a second run and every other
// machine sharing the file (see --seekdb-path) reuse it. A sidecar written by the `zsf` tool
// (<path>.idx) is used directly when present.
//
// A file compressed as a single frame still works but is one frame, so a seek decodes from the
// start: to get fast --skip the wordlist must be compressed in frames (the `zsf` tool, or zstd's
// seekable format). Lines that cross a frame boundary are handled, so any multi-frame zstd works.
//
//   hashcat -a 8 -m 0 hash.txt feeds/feed_zstd.so wordlist.zst -r rules/best64.rule

#define XXH_INLINE_ALL
#include "xxhash.h"

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "path.h"
#include "folder.h"
#include "memchr.h"
#include "feed.h"

#include <zstd.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include <stdarg.h>
#include <inttypes.h>

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

#define ZFIDX_CACHE_MAGIC  0x315844495A465A46ULL // cache file this feed writes
#define ZFIDX_CACHE_VER    1ULL
#define ZSF_SIDECAR_MAGIC  0x315A53464B434821ULL // sidecar written by prototype/zsf.c

#define ZFIDX_SAMPLE       65536
#define BUILD_OUTBUF       (4 * 1024 * 1024)

// One frame: where it starts in the compressed file, the line number of the first line that begins
// inside it, how many bytes it decodes to, and where in those bytes that first line begins (nonzero
// only when the frame opens in the middle of a line carried over from the frame before).
typedef struct
{
  u64 comp_off;
  u64 first_line;
  u64 uncomp_size;
  u64 line_off;
} zf_frame_t;

typedef struct
{
  char       *path;

  u64        *comp_off;    // [nframes + 1], comp_off[nframes] = filesize
  u64        *first_line;  // [nframes]
  u64        *uncomp_size; // [nframes]
  u64        *line_off;    // [nframes]

  u64         nframes;
  u64         total_lines;
  u64         filesize;

  size_t      max_comp;    // largest compressed frame  -> thread read buffer
  size_t      max_uncomp;  // largest decompressed frame -> thread frame buffer

} zf_global_t;

typedef struct
{
  int             fd;

  unsigned char  *cbuf;   // one compressed frame
  unsigned char  *dbuf;   // one decompressed frame

  size_t          dlen;   // valid bytes in dbuf
  size_t          doff;   // read cursor in dbuf

  u64             frame;  // frame currently in dbuf, or (u64) -1 when none is loaded
  u64             line;   // global line number of the next candidate

  unsigned char  *carry;  // a line that spans frames is assembled here
  size_t          carry_cap;

} zf_thread_t;

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

// ----------------------------------------------------------------------------------------------
// file identity, mirrored on the plaintext seek database: the size plus a sample of each end, so a
// file that changed under the same path builds a fresh index rather than trusting a stale one.
// ----------------------------------------------------------------------------------------------

static u64 file_ident (const char *path, u64 *filesize)
{
  struct stat st;

  if (stat (path, &st) != 0) return 0;

  *filesize = (u64) st.st_size;

  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return 0;

  XXH64_state_t *state = XXH64_createState ();
  XXH64_reset (state, 0);
  XXH64_update (state, &st.st_size, sizeof (st.st_size));

  u8 *buf = (u8 *) hcmalloc (ZFIDX_SAMPLE);

  const size_t n1 = fread (buf, 1, ZFIDX_SAMPLE, fp);
  XXH64_update (state, buf, n1);

  if ((u64) st.st_size > ZFIDX_SAMPLE)
  {
    fseeko (fp, (off_t) st.st_size - ZFIDX_SAMPLE, SEEK_SET);
    const size_t n2 = fread (buf, 1, ZFIDX_SAMPLE, fp);
    XXH64_update (state, buf, n2);
  }

  hcfree (buf);
  fclose (fp);

  const u64 h = XXH64_digest (state);
  XXH64_freeState (state);

  return h;
}

static char *cache_path (generic_global_ctx_t *global_ctx, const u64 ident)
{
  char *dir = NULL;

  if (global_ctx->seekdb_dir != NULL)
  {
    dir = hcstrdup (global_ctx->seekdb_dir);
  }
  else
  {
    hc_asprintf (&dir, "%s/seekdbs", global_ctx->cache_dir);
    hc_mkdir (dir, 0700);
  }

  char *path = NULL;
  hc_asprintf (&path, "%s/%016" PRIx64 ".zfidx", dir, ident);
  hcfree (dir);

  return path;
}

// ----------------------------------------------------------------------------------------------
// populate the in-memory index from a flat frame array
// ----------------------------------------------------------------------------------------------

static void index_adopt (zf_global_t *g, zf_frame_t *frames, const u64 nframes, const u64 total_lines)
{
  g->nframes     = nframes;
  g->total_lines = total_lines;

  g->comp_off    = (u64 *) hcmalloc ((nframes + 1) * sizeof (u64));
  g->first_line  = (u64 *) hcmalloc (nframes * sizeof (u64));
  g->uncomp_size = (u64 *) hcmalloc (nframes * sizeof (u64));
  g->line_off    = (u64 *) hcmalloc (nframes * sizeof (u64));

  for (u64 i = 0; i < nframes; i++)
  {
    g->comp_off[i]    = frames[i].comp_off;
    g->first_line[i]  = frames[i].first_line;
    g->uncomp_size[i] = frames[i].uncomp_size;
    g->line_off[i]    = frames[i].line_off;

    if (frames[i].uncomp_size > g->max_uncomp) g->max_uncomp = (size_t) frames[i].uncomp_size;
  }

  g->comp_off[nframes] = g->filesize;

  for (u64 i = 0; i < nframes; i++)
  {
    const size_t csize = (size_t) (g->comp_off[i + 1] - g->comp_off[i]);
    if (csize > g->max_comp) g->max_comp = csize;
  }
}

// ----------------------------------------------------------------------------------------------
// index sources: the zsf sidecar, the cache, or a fresh scan
// ----------------------------------------------------------------------------------------------

// prototype/zsf.c sidecar: header {magic, level, chunk, nframes, total_lines} then
// {comp_off, first_line, uncomp_size} per frame. Its frames are line-aligned, so line_off is 0.
static bool index_from_sidecar (zf_global_t *g, const char *path)
{
  char idxpath[4352];
  snprintf (idxpath, sizeof (idxpath), "%s.idx", path);

  FILE *fx = fopen (idxpath, "rb");
  if (fx == NULL) return false;

  u64 hdr[5];
  if (fread (hdr, sizeof (hdr), 1, fx) != 1 || hdr[0] != ZSF_SIDECAR_MAGIC)
  {
    fclose (fx);
    return false;
  }

  const u64 nframes = hdr[3];
  const u64 total   = hdr[4];

  if (nframes == 0) { fclose (fx); return false; }

  zf_frame_t *frames = (zf_frame_t *) hcmalloc (nframes * sizeof (zf_frame_t));

  bool ok = true;

  for (u64 i = 0; i < nframes; i++)
  {
    u64 e[3];
    if (fread (e, sizeof (e), 1, fx) != 1) { ok = false; break; }
    frames[i].comp_off    = e[0];
    frames[i].first_line  = e[1];
    frames[i].uncomp_size = e[2];
    frames[i].line_off    = 0;
  }

  fclose (fx);

  if (ok) index_adopt (g, frames, nframes, total);

  hcfree (frames);

  return ok;
}

static bool index_from_cache (zf_global_t *g, const char *cpath, const u64 ident)
{
  FILE *fx = fopen (cpath, "rb");
  if (fx == NULL) return false;

  u64 hdr[6];
  if (fread (hdr, sizeof (hdr), 1, fx) != 1
   || hdr[0] != ZFIDX_CACHE_MAGIC
   || hdr[1] != ZFIDX_CACHE_VER
   || hdr[4] != g->filesize
   || hdr[5] != ident)
  {
    fclose (fx);
    return false;
  }

  const u64 nframes = hdr[2];
  const u64 total   = hdr[3];

  if (nframes == 0) { fclose (fx); return false; }

  zf_frame_t *frames = (zf_frame_t *) hcmalloc (nframes * sizeof (zf_frame_t));

  const bool ok = (fread (frames, sizeof (zf_frame_t), nframes, fx) == nframes);

  fclose (fx);

  if (ok) index_adopt (g, frames, nframes, total);

  hcfree (frames);

  return ok;
}

static void index_save_cache (const zf_global_t *g, const char *cpath, const u64 ident)
{
  // A failed write is not fatal: the run uses the index it just built in memory, and the next run
  // rebuilds. Write to a temp beside the target and rename, so a reader never sees a half file.

  char *tmp = NULL;
  hc_asprintf (&tmp, "%s.tmp.%d", cpath, (int) getpid ());

  FILE *fx = fopen (tmp, "wb");
  if (fx == NULL) { hcfree (tmp); return; }

  u64 hdr[6] = { ZFIDX_CACHE_MAGIC, ZFIDX_CACHE_VER, g->nframes, g->total_lines, g->filesize, ident };

  bool ok = (fwrite (hdr, sizeof (hdr), 1, fx) == 1);

  for (u64 i = 0; ok && i < g->nframes; i++)
  {
    zf_frame_t e = { g->comp_off[i], g->first_line[i], g->uncomp_size[i], g->line_off[i] };
    ok = (fwrite (&e, sizeof (e), 1, fx) == 1);
  }

  fclose (fx);

  if (ok) rename (tmp, cpath);
  else    unlink (tmp);

  hcfree (tmp);
}

// One streaming pass: decode the whole file, and at each frame boundary record where the frame
// started and the line it opened on. Bounded memory (one input and one output block), decode only.
// The fallback: correct for anything (unknown content sizes, skippable frames), just single-threaded.
static bool index_build_serial (zf_global_t *g, const char *path)
{
  int fd = open (path, O_RDONLY);
  if (fd == -1) return false;

  ZSTD_DStream *ds = ZSTD_createDStream ();
  if (ds == NULL) { close (fd); return false; }

  ZSTD_bounds const wb = ZSTD_dParam_getBounds (ZSTD_d_windowLogMax);
  if (!ZSTD_isError (wb.error)) ZSTD_DCtx_setParameter (ds, ZSTD_d_windowLogMax, wb.upperBound);

  const size_t incap = ZSTD_DStreamInSize ();
  unsigned char *inbuf  = (unsigned char *) hcmalloc (incap);
  unsigned char *outbuf = (unsigned char *) hcmalloc (BUILD_OUTBUF);

  zf_frame_t *frames = NULL;
  u64 nframes = 0, aframes = 0;

  u64 comp_base   = 0;      // file offset of the current inbuf
  u64 line_count  = 0;      // line-starts seen
  bool prev_nl    = true;   // the file begins a line
  bool ok         = true;
  bool have_frame = false;

  zf_frame_t cur = { 0, 0, 0, (u64) -1 };  // line_off = -1 means "no line has started in this frame yet"

  for (;;)
  {
    ssize_t rd = read (fd, inbuf, incap);
    if (rd < 0) { ok = false; break; }
    if (rd == 0) break; // EOF

    ZSTD_inBuffer ib = { inbuf, (size_t) rd, 0 };

    while (ib.pos < ib.size)
    {
      ZSTD_outBuffer ob = { outbuf, BUILD_OUTBUF, 0 };

      const size_t ret = ZSTD_decompressStream (ds, &ob, &ib);
      if (ZSTD_isError (ret)) { ok = false; break; }

      const u64 base = cur.uncomp_size; // frame bytes before this output block

      for (size_t o = 0; o < ob.pos; o++)
      {
        if (prev_nl)
        {
          if (cur.line_off == (u64) -1) cur.line_off = base + o;
          line_count++;
        }
        prev_nl = (outbuf[o] == '\n');
      }

      cur.uncomp_size += ob.pos;
      have_frame = true;

      if (ret == 0)
      {
        // frame complete; if it never opened a line, leave line_off as 0 so seek code is simple
        if (cur.line_off == (u64) -1) cur.line_off = 0;

        if (nframes == aframes)
        {
          const u64 olda = aframes;
          aframes = aframes ? aframes * 2 : 256;
          frames = (zf_frame_t *) hcrealloc (frames, olda * sizeof (zf_frame_t), (aframes - olda) * sizeof (zf_frame_t));
        }
        frames[nframes++] = cur;

        // next frame starts where this one ended
        cur.comp_off    = comp_base + ib.pos;
        cur.first_line  = line_count;
        cur.uncomp_size = 0;
        cur.line_off    = (u64) -1;
        have_frame      = false;
      }
    }

    if (ok == false) break;

    comp_base += (u64) rd;
  }

  // a trailing partial frame (truncated stream) is still usable up to where it decoded
  if (ok && have_frame && cur.uncomp_size > 0)
  {
    if (cur.line_off == (u64) -1) cur.line_off = 0;
    if (nframes == aframes)
    {
      const u64 olda = aframes;
      aframes = aframes ? aframes * 2 : 1;
      frames = (zf_frame_t *) hcrealloc (frames, olda * sizeof (zf_frame_t), (aframes - olda) * sizeof (zf_frame_t));
    }
    frames[nframes++] = cur;
  }

  hcfree (inbuf);
  hcfree (outbuf);
  ZSTD_freeDStream (ds);
  close (fd);

  if (ok && nframes > 0) index_adopt (g, frames, nframes, line_count);

  hcfree (frames);

  return ok && nframes > 0;
}

// When every frame carries its content size in its header (one-shot compressed frames -- what the
// zsf tool and per-chunk `zstd -c` produce), the whole frame layout is known from the headers alone,
// so each frame can be decoded and line-scanned independently. That turns the first-run count from
// one serial decode of the entire file into an embarrassingly parallel decode across frames.

typedef struct
{
  const unsigned char *map;
  const u64 *comp_off;     // [nframes + 1]
  const u64 *uncomp_size;  // [nframes]
  u64        nframes;

  u64       *nl;           // out: newline count per frame
  uint8_t   *last_nl;      // out: 1 if the frame's last byte is '\n'
  int64_t   *first_nl;     // out: offset of first '\n' in the frame, or -1
  size_t     bufcap;       // per-thread decode buffer (>= largest frame)

  u64        next;         // atomic frame dispenser
  int        error;
} zf_build_ctx_t;

static void *zf_build_worker (void *arg)
{
  zf_build_ctx_t *b = (zf_build_ctx_t *) arg;

  unsigned char *out = (unsigned char *) malloc (b->bufcap);
  if (out == NULL) { b->error = 1; return NULL; }

  for (;;)
  {
    if (b->error) break;

    const u64 k = __atomic_fetch_add (&b->next, 1, __ATOMIC_RELAXED);
    if (k >= b->nframes) break;

    const size_t csize = (size_t) (b->comp_off[k + 1] - b->comp_off[k]);
    const size_t dsize = (size_t) b->uncomp_size[k];

    const size_t ds = ZSTD_decompress (out, b->bufcap, b->map + b->comp_off[k], csize);
    if (ZSTD_isError (ds) || ds != dsize) { b->error = 1; break; }

    u64 nl = 0;
    int64_t first = -1;

    for (size_t o = 0; o < ds; o++)
    {
      if (out[o] == '\n') { nl++; if (first < 0) first = (int64_t) o; }
    }

    b->nl[k]       = nl;
    b->last_nl[k]  = (ds > 0 && out[ds - 1] == '\n') ? 1 : 0;
    b->first_nl[k] = first;
  }

  free (out);
  return NULL;
}

static bool index_build_parallel (zf_global_t *g, const char *path)
{
  int fd = open (path, O_RDONLY);
  if (fd == -1) return false;

  struct stat st;
  if (fstat (fd, &st) != 0) { close (fd); return false; }

  const size_t fsz = (size_t) st.st_size;
  if (fsz == 0) { close (fd); return false; }

  unsigned char *map = (unsigned char *) mmap (NULL, fsz, PROT_READ, MAP_PRIVATE, fd, 0);
  close (fd);
  if (map == MAP_FAILED) return false;

  // 1) walk frame headers only (no decode); bail to serial on anything unusual
  //    (unknown content size, a skippable frame, a truncated tail)

  u64 *comp_off = NULL, *ucs = NULL;
  u64 nframes = 0, acap = 0;
  size_t off = 0;
  bool ok = true;

  while (off < fsz)
  {
    const size_t fcs = ZSTD_findFrameCompressedSize (map + off, fsz - off);
    if (ZSTD_isError (fcs)) { ok = false; break; }

    u32 magic;
    memcpy (&magic, map + off, sizeof (magic));
    if ((magic & 0xFFFFFFF0u) == 0x184D2A50u) { ok = false; break; } // skippable frame

    const unsigned long long content = ZSTD_getFrameContentSize (map + off, fcs);
    if (content == ZSTD_CONTENTSIZE_UNKNOWN || content == ZSTD_CONTENTSIZE_ERROR) { ok = false; break; }

    if (nframes == acap)
    {
      const u64 olda = acap;
      acap = acap ? acap * 2 : 256;
      comp_off = (u64 *) hcrealloc (comp_off, olda * sizeof (u64), (acap - olda) * sizeof (u64));
      ucs      = (u64 *) hcrealloc (ucs,      olda * sizeof (u64), (acap - olda) * sizeof (u64));
    }

    comp_off[nframes] = off;
    ucs[nframes]      = (u64) content;
    nframes++;
    off += fcs;
  }

  if (ok == false || off != fsz || nframes == 0)
  {
    munmap (map, fsz);
    hcfree (comp_off);
    hcfree (ucs);
    return false;
  }

  comp_off = (u64 *) hcrealloc (comp_off, acap * sizeof (u64), sizeof (u64)); // room for the sentinel
  comp_off[nframes] = fsz;

  size_t max_ucs = 1;
  for (u64 i = 0; i < nframes; i++) if (ucs[i] > max_ucs) max_ucs = (size_t) ucs[i];

  // 2) decode + line-scan every frame in parallel, bounded so threads * largest_frame stays modest

  const long ncpu = sysconf (_SC_NPROCESSORS_ONLN);
  u64 nthreads = (ncpu > 0) ? (u64) ncpu : 1;
  const u64 by_mem = ((u64) 8 * 1024 * 1024 * 1024) / max_ucs;
  if (by_mem < 1) nthreads = 1; else if (nthreads > by_mem) nthreads = by_mem;
  if (nthreads > nframes) nthreads = nframes;
  if (nthreads < 1) nthreads = 1;

  zf_build_ctx_t b;
  b.map = map; b.comp_off = comp_off; b.uncomp_size = ucs; b.nframes = nframes;
  b.nl       = (u64 *)     hcmalloc (nframes * sizeof (u64));
  b.last_nl  = (uint8_t *) hcmalloc (nframes * sizeof (uint8_t));
  b.first_nl = (int64_t *) hcmalloc (nframes * sizeof (int64_t));
  b.bufcap   = max_ucs;
  b.next     = 0;
  b.error    = 0;

  pthread_t *tids = (pthread_t *) hcmalloc (nthreads * sizeof (pthread_t));
  u64 spawned = 0;
  for (u64 i = 0; i < nthreads; i++)
  {
    if (pthread_create (&tids[i], NULL, zf_build_worker, &b) != 0) break;
    spawned++;
  }
  if (spawned == 0) zf_build_worker (&b);
  for (u64 i = 0; i < spawned; i++) pthread_join (tids[i], NULL);
  hcfree (tids);

  bool bad = (b.error != 0);

  // 3) combine per-frame summaries: line-starts before frame k = 1 + (newlines in frames < k)
  //    - (frame k-1 ended on '\n'); line_off[k] skips a leading carried-over partial line.

  zf_frame_t *frames = NULL;
  u64 total_lines = 0;

  if (bad == false)
  {
    frames = (zf_frame_t *) hcmalloc (nframes * sizeof (zf_frame_t));
    u64 prefix_nl = 0;

    for (u64 k = 0; k < nframes; k++)
    {
      frames[k].comp_off    = comp_off[k];
      frames[k].uncomp_size = ucs[k];

      if (k == 0)
      {
        frames[k].first_line = 0;
        frames[k].line_off   = 0;
      }
      else
      {
        frames[k].first_line = 1 + prefix_nl - b.last_nl[k - 1];
        frames[k].line_off   = b.last_nl[k - 1] ? 0 : ((b.first_nl[k] < 0) ? ucs[k] : (u64) (b.first_nl[k] + 1));
      }

      prefix_nl += b.nl[k];
    }

    total_lines = prefix_nl + (b.last_nl[nframes - 1] ? 0 : 1);
  }

  munmap (map, fsz);
  hcfree (b.nl); hcfree (b.last_nl); hcfree (b.first_nl);
  hcfree (comp_off); hcfree (ucs);

  if (bad) { hcfree (frames); return false; }

  index_adopt (g, frames, nframes, total_lines);
  hcfree (frames);

  return true;
}

// parallel when the frame layout is header-derivable, else the always-correct serial pass
static bool index_build (zf_global_t *g, const char *path)
{
  if (index_build_parallel (g, path)) return true;

  return index_build_serial (g, path);
}

// ----------------------------------------------------------------------------------------------

// largest frame with first_line <= offset
static u64 frame_of_line (const zf_global_t *g, const u64 offset)
{
  u64 lo = 0;
  u64 hi = g->nframes - 1;
  u64 k  = 0;

  while (lo <= hi)
  {
    const u64 mid = lo + (hi - lo) / 2;

    if (g->first_line[mid] <= offset) { k = mid; lo = mid + 1; }
    else { if (mid == 0) break; hi = mid - 1; }
  }

  return k;
}

static bool load_frame (generic_thread_ctx_t *thread_ctx, zf_global_t *g, zf_thread_t *t, const u64 k)
{
  const size_t csize = (size_t) (g->comp_off[k + 1] - g->comp_off[k]);
  const size_t dsize = (size_t) g->uncomp_size[k];

  ssize_t rd = pread (t->fd, t->cbuf, csize, (off_t) g->comp_off[k]);
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

static void carry_reserve (zf_thread_t *t, const size_t need)
{
  if (need <= t->carry_cap) return;

  const size_t oldcap = t->carry_cap;
  size_t cap = oldcap ? oldcap : 4096;
  while (cap < need) cap *= 2;

  t->carry = (unsigned char *) hcrealloc (t->carry, oldcap, cap - oldcap);
  t->carry_cap = cap;
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zf_global_t *g = (zf_global_t *) hccalloc (1, sizeof (zf_global_t));

  global_ctx->gbldata = g;

  if (global_ctx->workc < 2)
  {
    error_set (global_ctx, "usage: feed_zstd.so <wordlist.zst> (multi-frame for fast --skip)");
    return false;
  }

  g->path = hcstrdup (global_ctx->workv[1]);

  u64 ident = file_ident (g->path, &g->filesize);

  if (ident == 0)
  {
    error_set (global_ctx, "%s: cannot open", g->path);
    return false;
  }

  // 1) a zsf sidecar sits next to the file and is already the index
  // 2) a cached index for this exact file
  // 3) build it now, one streaming pass, and cache it

  if (index_from_sidecar (g, g->path) == false)
  {
    char *cpath = cache_path (global_ctx, ident);

    if (index_from_cache (g, cpath, ident) == false)
    {
      if (index_build (g, g->path) == false)
      {
        hcfree (cpath);
        error_set (global_ctx, "%s: not a valid zstd stream", g->path);
        return false;
      }

      index_save_cache (g, cpath, ident);
    }

    hcfree (cpath);
  }

  global_ctx->source_ident = (g->filesize * 1000003ULL) ^ (g->total_lines * 2654435761ULL) ^ ident;

  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", g->path);

  if (g->nframes < 2)
  {
    feed_say (hashcat_ctx, "feed_zstd: %s is a single frame, so --skip decodes from the start. Recompress in frames (e.g. the zsf tool) for O(1) skip.", g->path);
  }

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zf_global_t *g = global_ctx->gbldata;

  if (g == NULL) return;

  hcfree (g->comp_off);
  hcfree (g->first_line);
  hcfree (g->uncomp_size);
  hcfree (g->line_off);
  hcfree (g->path);
  hcfree (g);

  global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  zf_global_t *g = global_ctx->gbldata;

  return g->total_lines;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  zf_global_t *g = global_ctx->gbldata;

  zf_thread_t *t = (zf_thread_t *) hccalloc (1, sizeof (zf_thread_t));

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
  zf_thread_t *t = thread_ctx->thrdata;

  if (t == NULL) return;

  if (t->fd != -1) close (t->fd);
  hcfree (t->cbuf);
  hcfree (t->dbuf);
  hcfree (t->carry);
  hcfree (t);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  zf_global_t *g = global_ctx->gbldata;
  zf_thread_t *t = thread_ctx->thrdata;

  if (t->frame == (u64) -1)
  {
    if (load_frame (thread_ctx, g, t, 0) == false) return GENERIC_RC_ERROR;
    t->doff = g->line_off[0];
    t->line = 0;
  }

  while (t->doff >= t->dlen)
  {
    const u64 next = t->frame + 1;
    if (next >= g->nframes) return GENERIC_RC_EOF;
    if (load_frame (thread_ctx, g, t, next) == false) return GENERIC_RC_ERROR;
  }

  const size_t remaining = t->dlen - t->doff;

  size_t word_len = 0;
  const size_t step = hc_line_next (t->dbuf + t->doff, remaining, &word_len);

  if (step < remaining)
  {
    // whole line inside this frame
    const size_t copy_len = MIN (word_len, (size_t) out_size);
    memcpy (out_buf, t->dbuf + t->doff, copy_len);
    t->doff += step + 1;
    t->line++;
    return (int) word_len;
  }

  // no newline to the end of the frame
  const bool last_frame = (t->frame + 1 >= g->nframes);

  if (last_frame)
  {
    const size_t copy_len = MIN (word_len, (size_t) out_size);
    memcpy (out_buf, t->dbuf + t->doff, copy_len);
    t->doff = t->dlen;
    t->line++;
    return (int) word_len;
  }

  // the line spans into the next frame(s): assemble it in the carry buffer
  size_t clen = remaining;
  carry_reserve (t, clen);
  memcpy (t->carry, t->dbuf + t->doff, clen);
  t->doff = t->dlen;

  for (;;)
  {
    if (load_frame (thread_ctx, g, t, t->frame + 1) == false) return GENERIC_RC_ERROR;

    const size_t nl = hc_memchr_get () (t->dbuf, '\n', t->dlen);

    if (nl < t->dlen)
    {
      carry_reserve (t, clen + nl);
      memcpy (t->carry + clen, t->dbuf, nl);
      clen += nl;
      t->doff = nl + 1;
      break;
    }

    carry_reserve (t, clen + t->dlen);
    memcpy (t->carry + clen, t->dbuf, t->dlen);
    clen += t->dlen;
    t->doff = t->dlen;

    if (t->frame + 1 >= g->nframes) break; // line ends at EOF
  }

  while (clen > 0 && t->carry[clen - 1] == '\r') clen--;

  const size_t copy_len = MIN (clen, (size_t) out_size);
  memcpy (out_buf, t->carry, copy_len);
  t->line++;

  return (int) clen;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  zf_global_t *g = global_ctx->gbldata;
  zf_thread_t *t = thread_ctx->thrdata;

  if (offset >= g->total_lines)
  {
    thread_error_set (thread_ctx, "seek target past EOF: %" PRIu64, offset);
    return false;
  }

  const u64 k = frame_of_line (g, offset);

  if (load_frame (thread_ctx, g, t, k) == false) return false;

  t->doff = g->line_off[k];

  // walk forward to the exact line; a line that spans frames is followed across the boundary
  u64 skip = offset - g->first_line[k];

  hc_memchr_t memchr_fn = hc_memchr_get ();

  while (skip)
  {
    const size_t nl = memchr_fn (t->dbuf + t->doff, '\n', t->dlen - t->doff);

    if (t->doff + nl < t->dlen)
    {
      t->doff += nl + 1;
      skip--;
    }
    else
    {
      if (t->frame + 1 >= g->nframes) break;
      if (load_frame (thread_ctx, g, t, t->frame + 1) == false) return false;
      // no decrement: this line's newline is in the next frame
    }
  }

  t->line = offset;

  return true;
}
