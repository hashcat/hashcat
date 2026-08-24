/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// A generic (attack-mode 8) feed that reads an xz-compressed wordlist and seeks inside it, the same
// way feed_zstd does for zstd. The one difference is where the frame boundaries come from: an .xz
// stream carries a native block Index (compressed and uncompressed offset per block) in its footer,
// so there is nothing to reframe -- the standard `xz --block-size=16MiB -T0 wordlist` produces a
// multi-block, seekable file directly. This feed reads that index, records the line each block opens
// on (one parallel decode pass, cached), and reaches word N by decoding only its block.
//
//   xz --block-size=16MiB -T0 -k wordlist          # once, with the stock xz tool
//   hashcat -a 8 -m 0 hash.txt feeds/feed_xz.so wordlist.xz -r rules/best64.rule
//
// A single-block .xz (xz's default) still works but is one block, so a seek decodes from the start;
// use --block-size for O(1) skip. Multi-stream .xz (manually concatenated) is not handled yet.

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

#include <lzma.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <inttypes.h>

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_AUTOHEX
                                 | GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES;

#define XFIDX_CACHE_MAGIC  0x315844495A465831ULL // "1XFZIDX1"-ish; distinct from feed_zstd's
#define XFIDX_CACHE_VER    1ULL
#define XFIDX_SAMPLE       65536

typedef struct { u64 comp_off, first_line, uncomp_size, line_off; } xf_frame_t;

typedef struct
{
  char        *path;

  u64         *comp_off;    // [nblocks + 1], comp_off[nblocks] = filesize
  u64         *total_size;  // [nblocks] compressed block size incl header+padding
  u64         *first_line;  // [nblocks]
  u64         *uncomp_size; // [nblocks]
  u64         *line_off;    // [nblocks]

  u64          nblocks;
  u64          total_lines;
  u64          filesize;

  size_t       max_comp;
  size_t       max_uncomp;

  u64          build_threads;
  lzma_check   check;       // stream check type, needed to decode a block

} xf_global_t;

typedef struct
{
  int             fd;
  unsigned char  *cbuf;
  unsigned char  *dbuf;
  size_t          dlen, doff;
  u64             block;    // (u64) -1 when none loaded
  u64             line;
  unsigned char  *carry;
  size_t          carry_cap;
} xf_thread_t;

static void error_set (generic_global_ctx_t *g, const char *fmt, ...)
{
  g->error = true; va_list ap; va_start (ap, fmt);
  vsnprintf (g->error_msg, sizeof (g->error_msg), fmt, ap); va_end (ap);
}
static void thread_error_set (generic_thread_ctx_t *t, const char *fmt, ...)
{
  t->error = true; va_list ap; va_start (ap, fmt);
  vsnprintf (t->error_msg, sizeof (t->error_msg), fmt, ap); va_end (ap);
}

// ---- file identity + cache dir (same convention as the plaintext seekdb / feed_zstd) ----

static u64 file_ident (const char *path, u64 *filesize)
{
  struct stat st; if (stat (path, &st) != 0) return 0;
  *filesize = (u64) st.st_size;
  FILE *fp = fopen (path, "rb"); if (fp == NULL) return 0;
  XXH64_state_t *s = XXH64_createState (); XXH64_reset (s, 0);
  XXH64_update (s, &st.st_size, sizeof (st.st_size));
  u8 *b = (u8 *) hcmalloc (XFIDX_SAMPLE);
  size_t n1 = fread (b, 1, XFIDX_SAMPLE, fp); XXH64_update (s, b, n1);
  if ((u64) st.st_size > XFIDX_SAMPLE) { fseeko (fp, (off_t) st.st_size - XFIDX_SAMPLE, SEEK_SET); size_t n2 = fread (b, 1, XFIDX_SAMPLE, fp); XXH64_update (s, b, n2); }
  hcfree (b); fclose (fp);
  u64 h = XXH64_digest (s); XXH64_freeState (s); return h;
}

static char *cache_path (generic_global_ctx_t *global_ctx, const u64 ident)
{
  char *dir = NULL;
  if (global_ctx->seekdb_dir != NULL) dir = hcstrdup (global_ctx->seekdb_dir);
  else { hc_asprintf (&dir, "%s/seekdbs", global_ctx->cache_dir); hc_mkdir (dir, 0700); }
  char *path = NULL; hc_asprintf (&path, "%s/%016" PRIx64 ".xfidx", dir, ident); hcfree (dir); return path;
}

static u64 block_of_line (const xf_global_t *g, const u64 offset)
{
  u64 lo = 0, hi = g->nblocks - 1, k = 0;
  while (lo <= hi) { u64 m = lo + (hi - lo) / 2; if (g->first_line[m] <= offset) { k = m; lo = m + 1; } else { if (m == 0) break; hi = m - 1; } }
  return k;
}

// decode one xz block (its compressed bytes are already in cbuf) into dbuf
static bool decode_block (const xf_global_t *g, const unsigned char *cbuf, size_t csize, unsigned char *dbuf, size_t dsize)
{
  lzma_block blk; memset (&blk, 0, sizeof (blk));
  lzma_filter filt[LZMA_FILTERS_MAX + 1];
  blk.filters = filt; blk.check = g->check; blk.version = 0;
  blk.header_size = lzma_block_header_size_decode (cbuf[0]);
  if (lzma_block_header_decode (&blk, NULL, cbuf) != LZMA_OK) return false;

  lzma_stream s = LZMA_STREAM_INIT;
  if (lzma_block_decoder (&s, &blk) != LZMA_OK) { for (int i = 0; filt[i].id != LZMA_VLI_UNKNOWN; i++) free (filt[i].options); return false; }
  s.next_in = cbuf + blk.header_size; s.avail_in = csize - blk.header_size;
  s.next_out = dbuf; s.avail_out = dsize;
  lzma_ret r = lzma_code (&s, LZMA_FINISH);
  size_t got = dsize - s.avail_out;
  lzma_end (&s);
  for (int i = 0; filt[i].id != LZMA_VLI_UNKNOWN; i++) free (filt[i].options);
  return (r == LZMA_STREAM_END || r == LZMA_OK) && got == dsize;
}

// ---- read the native xz block index: fills comp_off/total_size/uncomp_size/nblocks + check ----

static bool xz_read_index (xf_global_t *g)
{
  int fd = open (g->path, O_RDONLY); if (fd == -1) return false;
  struct stat st; if (fstat (fd, &st) != 0) { close (fd); return false; }
  g->filesize = (u64) st.st_size;
  if (g->filesize < 24) { close (fd); return false; }

  unsigned char hdr[12], ftr[12];
  if (pread (fd, hdr, 12, 0) != 12) { close (fd); return false; }
  if (pread (fd, ftr, 12, (off_t) g->filesize - 12) != 12) { close (fd); return false; }

  lzma_stream_flags sh, sf;
  if (lzma_stream_header_decode (&sh, hdr) != LZMA_OK) { close (fd); return false; }
  if (lzma_stream_footer_decode (&sf, ftr) != LZMA_OK) { close (fd); return false; }
  g->check = sh.check;

  const size_t idx_size = (size_t) sf.backward_size;
  const off_t  idx_off  = (off_t) g->filesize - 12 - (off_t) idx_size;
  if (idx_off < 12) { close (fd); return false; }

  unsigned char *ibuf = (unsigned char *) hcmalloc (idx_size);
  if (pread (fd, ibuf, idx_size, idx_off) != (ssize_t) idx_size) { hcfree (ibuf); close (fd); return false; }
  close (fd);

  uint64_t memlimit = UINT64_MAX; size_t inpos = 0; lzma_index *idx = NULL;
  lzma_ret r = lzma_index_buffer_decode (&idx, &memlimit, NULL, ibuf, &inpos, idx_size);
  hcfree (ibuf);
  if (r != LZMA_OK) { if (idx) lzma_index_end (idx, NULL); return false; }

  // single-stream only: the index must cover the whole file
  if (lzma_index_stream_size (idx) != g->filesize)
  {
    // more than one stream present; not handled yet
    lzma_index_end (idx, NULL); return false;
  }

  const u64 n = (u64) lzma_index_block_count (idx);
  if (n == 0) { lzma_index_end (idx, NULL); return false; }

  g->nblocks     = n;
  g->comp_off    = (u64 *) hcmalloc ((n + 1) * sizeof (u64));
  g->total_size  = (u64 *) hcmalloc (n * sizeof (u64));
  g->uncomp_size = (u64 *) hcmalloc (n * sizeof (u64));

  lzma_index_iter it; lzma_index_iter_init (&it, idx);
  u64 k = 0;
  while (!lzma_index_iter_next (&it, LZMA_INDEX_ITER_BLOCK) && k < n)
  {
    g->comp_off[k]    = (u64) it.block.compressed_file_offset;
    g->total_size[k]  = (u64) it.block.total_size;
    g->uncomp_size[k] = (u64) it.block.uncompressed_size;
    if (g->uncomp_size[k] > g->max_uncomp) g->max_uncomp = (size_t) g->uncomp_size[k];
    if (g->total_size[k] > g->max_comp)    g->max_comp   = (size_t) g->total_size[k];
    k++;
  }
  g->comp_off[n] = g->filesize;
  lzma_index_end (idx, NULL);
  return k == n;
}

// ---- parallel line-count over the blocks -> first_line[] / line_off[] ----

typedef struct
{
  xf_global_t   *g;
  u64           *nl; uint8_t *last_nl; int64_t *first_nl;
  u64            next; int error;
} xf_build_ctx_t;

static void *xf_build_worker (void *arg)
{
  xf_build_ctx_t *b = (xf_build_ctx_t *) arg; xf_global_t *g = b->g;
  unsigned char *cbuf = (unsigned char *) malloc (g->max_comp);
  unsigned char *dbuf = (unsigned char *) malloc (g->max_uncomp ? g->max_uncomp : 1);
  int fd = open (g->path, O_RDONLY);
  if (cbuf == NULL || dbuf == NULL || fd == -1) { b->error = 1; free (cbuf); free (dbuf); if (fd!=-1) close (fd); return NULL; }

  for (;;)
  {
    if (b->error) break;
    u64 k = __atomic_fetch_add (&b->next, 1, __ATOMIC_RELAXED);
    if (k >= g->nblocks) break;
    size_t csize = (size_t) g->total_size[k], dsize = (size_t) g->uncomp_size[k];
    if (pread (fd, cbuf, csize, (off_t) g->comp_off[k]) != (ssize_t) csize) { b->error = 1; break; }
    if (decode_block (g, cbuf, csize, dbuf, dsize) == false) { b->error = 1; break; }
    u64 nl = 0; int64_t first = -1;
    for (size_t o = 0; o < dsize; o++) if (dbuf[o] == '\n') { nl++; if (first < 0) first = (int64_t) o; }
    b->nl[k] = nl; b->last_nl[k] = (dsize > 0 && dbuf[dsize - 1] == '\n') ? 1 : 0; b->first_nl[k] = first;
  }
  free (cbuf); free (dbuf); close (fd); return NULL;
}

static void index_finish (xf_global_t *g, const u64 *nl, const uint8_t *last_nl, const int64_t *first_nl)
{
  g->first_line = (u64 *) hcmalloc (g->nblocks * sizeof (u64));
  g->line_off   = (u64 *) hcmalloc (g->nblocks * sizeof (u64));
  u64 prefix = 0;
  for (u64 k = 0; k < g->nblocks; k++)
  {
    if (k == 0) { g->first_line[0] = 0; g->line_off[0] = 0; }
    else
    {
      g->first_line[k] = 1 + prefix - last_nl[k - 1];
      g->line_off[k]   = last_nl[k - 1] ? 0 : ((first_nl[k] < 0) ? g->uncomp_size[k] : (u64) (first_nl[k] + 1));
    }
    prefix += nl[k];
  }
  g->total_lines = prefix + (last_nl[g->nblocks - 1] ? 0 : 1);
}

static bool index_build (xf_global_t *g)
{
  const long ncpu = sysconf (_SC_NPROCESSORS_ONLN);
  u64 nthreads = g->build_threads ? g->build_threads : ((ncpu > 0) ? (u64) ncpu : 1);
  const u64 by_mem = ((u64) 8 * 1024 * 1024 * 1024) / (g->max_uncomp ? g->max_uncomp : 1);
  if (by_mem < 1) nthreads = 1; else if (nthreads > by_mem) nthreads = by_mem;
  if (nthreads > g->nblocks) nthreads = g->nblocks;
  if (nthreads < 1) nthreads = 1;

  xf_build_ctx_t b; b.g = g; b.next = 0; b.error = 0;
  b.nl       = (u64 *)     hcmalloc (g->nblocks * sizeof (u64));
  b.last_nl  = (uint8_t *) hcmalloc (g->nblocks * sizeof (uint8_t));
  b.first_nl = (int64_t *) hcmalloc (g->nblocks * sizeof (int64_t));

  pthread_t *t = (pthread_t *) hcmalloc (nthreads * sizeof (pthread_t)); u64 sp = 0;
  for (u64 i = 0; i < nthreads; i++) { if (pthread_create (&t[i], NULL, xf_build_worker, &b) != 0) break; sp++; }
  if (sp == 0) xf_build_worker (&b);
  for (u64 i = 0; i < sp; i++) pthread_join (t[i], NULL);
  hcfree (t);

  bool ok = (b.error == 0);
  if (ok) index_finish (g, b.nl, b.last_nl, b.first_nl);
  hcfree (b.nl); hcfree (b.last_nl); hcfree (b.first_nl);
  return ok;
}

// ---- cache (block -> first_line/line_off), same shape as feed_zstd's .zfidx ----

static bool index_from_cache (xf_global_t *g, const char *cpath, const u64 ident)
{
  FILE *fx = fopen (cpath, "rb"); if (fx == NULL) return false;
  u64 hdr[6];
  if (fread (hdr, sizeof (hdr), 1, fx) != 1 || hdr[0] != XFIDX_CACHE_MAGIC || hdr[1] != XFIDX_CACHE_VER
   || hdr[2] != g->nblocks || hdr[4] != g->filesize || hdr[5] != ident) { fclose (fx); return false; }
  xf_frame_t *e = (xf_frame_t *) hcmalloc (g->nblocks * sizeof (xf_frame_t));
  bool ok = (fread (e, sizeof (xf_frame_t), g->nblocks, fx) == g->nblocks);
  fclose (fx);
  if (ok)
  {
    g->first_line = (u64 *) hcmalloc (g->nblocks * sizeof (u64));
    g->line_off   = (u64 *) hcmalloc (g->nblocks * sizeof (u64));
    g->total_lines = hdr[3];
    for (u64 i = 0; i < g->nblocks; i++) { g->first_line[i] = e[i].first_line; g->line_off[i] = e[i].line_off; }
  }
  hcfree (e); return ok;
}

static void index_save_cache (const xf_global_t *g, const char *cpath, const u64 ident)
{
  char *tmp = NULL; hc_asprintf (&tmp, "%s.tmp.%d", cpath, (int) getpid ());
  FILE *fx = fopen (tmp, "wb"); if (fx == NULL) { hcfree (tmp); return; }
  u64 hdr[6] = { XFIDX_CACHE_MAGIC, XFIDX_CACHE_VER, g->nblocks, g->total_lines, g->filesize, ident };
  bool ok = (fwrite (hdr, sizeof (hdr), 1, fx) == 1);
  for (u64 i = 0; ok && i < g->nblocks; i++)
  { xf_frame_t e = { g->comp_off[i], g->first_line[i], g->uncomp_size[i], g->line_off[i] }; ok = (fwrite (&e, sizeof (e), 1, fx) == 1); }
  fclose (fx);
  if (ok) rename (tmp, cpath); else unlink (tmp);
  hcfree (tmp);
}

static bool load_block (generic_thread_ctx_t *tc, xf_global_t *g, xf_thread_t *t, const u64 k)
{
  size_t csize = (size_t) g->total_size[k], dsize = (size_t) g->uncomp_size[k];
  if (pread (t->fd, t->cbuf, csize, (off_t) g->comp_off[k]) != (ssize_t) csize) { thread_error_set (tc, "%s: short read of block %" PRIu64, g->path, k); return false; }
  if (decode_block (g, t->cbuf, csize, t->dbuf, dsize) == false) { thread_error_set (tc, "%s: block %" PRIu64 " decode failed", g->path, k); return false; }
  t->dlen = dsize; t->doff = 0; t->block = k; return true;
}

static void carry_reserve (xf_thread_t *t, const size_t need)
{
  if (need <= t->carry_cap) return;
  size_t old = t->carry_cap, cap = old ? old : 4096; while (cap < need) cap *= 2;
  t->carry = (unsigned char *) hcrealloc (t->carry, old, cap - old); t->carry_cap = cap;
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  xf_global_t *g = (xf_global_t *) hccalloc (1, sizeof (xf_global_t));
  global_ctx->gbldata = g;

  u64 p_threads = 0;
  const feed_param_t params[] = {
    { "threads", FEED_PARAM_TYPE_U64, &p_threads, 0, 4096, "cores for the parallel index build (0 = all)" },
    { NULL, 0, NULL, 0, 0, NULL },
  };
  char perr[256];
  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, perr, sizeof (perr)) == false) { error_set (global_ctx, "%s", perr); return false; }
  g->build_threads = p_threads;

  const char *src = NULL;
  for (int i = 1; i < global_ctx->workc; i++) if (feed_param_is_setting (global_ctx->workv[i]) == false) { src = global_ctx->workv[i]; break; }
  if (src == NULL) { error_set (global_ctx, "usage: feed_xz.so <wordlist.xz> [threads=<n>]  (make it multi-block: xz --block-size=16MiB -T0)"); return false; }
  g->path = hcstrdup (src);

  u64 ident = file_ident (g->path, &g->filesize);
  if (ident == 0) { error_set (global_ctx, "%s: cannot open", g->path); return false; }

  if (xz_read_index (g) == false) { error_set (global_ctx, "%s: not a single-stream xz file (or unreadable index)", g->path); return false; }

  char *cpath = cache_path (global_ctx, ident);
  if (index_from_cache (g, cpath, ident) == false)
  {
    if (index_build (g) == false) { hcfree (cpath); error_set (global_ctx, "%s: block decode failed during index build", g->path); return false; }
    index_save_cache (g, cpath, ident);
  }
  hcfree (cpath);

  global_ctx->source_ident = (g->filesize * 1000003ULL) ^ (g->total_lines * 2654435761ULL) ^ g->nblocks;
  snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", g->path);
  if (g->nblocks < 2) feed_say (hashcat_ctx, "feed_xz: %s is a single block, so --skip decodes from the start. Recompress with: xz --block-size=16MiB -T0", g->path);
  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  xf_global_t *g = global_ctx->gbldata; if (g == NULL) return;
  hcfree (g->comp_off); hcfree (g->total_size); hcfree (g->first_line); hcfree (g->uncomp_size); hcfree (g->line_off);
  hcfree (g->path); hcfree (g); global_ctx->gbldata = NULL;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  xf_global_t *g = global_ctx->gbldata; return g->total_lines;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  xf_global_t *g = global_ctx->gbldata;
  xf_thread_t *t = (xf_thread_t *) hccalloc (1, sizeof (xf_thread_t));
  t->fd = open (g->path, O_RDONLY);
  if (t->fd == -1) { thread_error_set (thread_ctx, "%s: %s", g->path, strerror (errno)); hcfree (t); return false; }
  t->cbuf = (unsigned char *) hcmalloc (g->max_comp); t->dbuf = (unsigned char *) hcmalloc (g->max_uncomp);
  t->block = (u64) -1; t->line = 0; thread_ctx->thrdata = t; return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  xf_thread_t *t = thread_ctx->thrdata; if (t == NULL) return;
  if (t->fd != -1) close (t->fd);
  hcfree (t->cbuf); hcfree (t->dbuf); hcfree (t->carry); hcfree (t); thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  xf_global_t *g = global_ctx->gbldata; xf_thread_t *t = thread_ctx->thrdata;
  if (t->block == (u64) -1) { if (load_block (thread_ctx, g, t, 0) == false) return GENERIC_RC_ERROR; t->doff = g->line_off[0]; t->line = 0; }
  while (t->doff >= t->dlen) { u64 nx = t->block + 1; if (nx >= g->nblocks) return GENERIC_RC_EOF; if (load_block (thread_ctx, g, t, nx) == false) return GENERIC_RC_ERROR; }

  const size_t remaining = t->dlen - t->doff; size_t word_len = 0;
  const size_t step = hc_line_next (t->dbuf + t->doff, remaining, &word_len);
  if (step < remaining) { const size_t cl = MIN (word_len, (size_t) out_size); memcpy (out_buf, t->dbuf + t->doff, cl); t->doff += step + 1; t->line++; return (int) word_len; }

  const bool last = (t->block + 1 >= g->nblocks);
  if (last) { const size_t cl = MIN (word_len, (size_t) out_size); memcpy (out_buf, t->dbuf + t->doff, cl); t->doff = t->dlen; t->line++; return (int) word_len; }

  size_t clen = remaining; carry_reserve (t, clen); memcpy (t->carry, t->dbuf + t->doff, clen); t->doff = t->dlen;
  for (;;)
  {
    if (load_block (thread_ctx, g, t, t->block + 1) == false) return GENERIC_RC_ERROR;
    const size_t nl = hc_memchr_get () (t->dbuf, '\n', t->dlen);
    if (nl < t->dlen) { carry_reserve (t, clen + nl); memcpy (t->carry + clen, t->dbuf, nl); clen += nl; t->doff = nl + 1; break; }
    carry_reserve (t, clen + t->dlen); memcpy (t->carry + clen, t->dbuf, t->dlen); clen += t->dlen; t->doff = t->dlen;
    if (t->block + 1 >= g->nblocks) break;
  }
  while (clen > 0 && t->carry[clen - 1] == '\r') clen--;
  const size_t cl = MIN (clen, (size_t) out_size); memcpy (out_buf, t->carry, cl); t->line++; return (int) clen;
}

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  xf_global_t *g = global_ctx->gbldata; xf_thread_t *t = thread_ctx->thrdata;
  if (offset >= g->total_lines) { thread_error_set (thread_ctx, "seek target past EOF: %" PRIu64, offset); return false; }
  const u64 k = block_of_line (g, offset);
  if (load_block (thread_ctx, g, t, k) == false) return false;
  t->doff = g->line_off[k];
  u64 skip = offset - g->first_line[k]; hc_memchr_t mc = hc_memchr_get ();
  while (skip)
  {
    const size_t nl = mc (t->dbuf + t->doff, '\n', t->dlen - t->doff);
    if (t->doff + nl < t->dlen) { t->doff += nl + 1; skip--; }
    else { if (t->block + 1 >= g->nblocks) break; if (load_block (thread_ctx, g, t, t->block + 1) == false) return false; }
  }
  t->line = offset; return true;
}
