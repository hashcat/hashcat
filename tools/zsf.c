// zsf — seekable-zstd wordlist tool (companion to the feed_zstd generic attack-mode-8 feed).
//
// Frames a wordlist into independent, line-aligned zstd frames plus a sidecar index
// (<out>.idx: per frame -> compressed offset, first line, uncompressed size). feed_zstd reads that
// index (or rebuilds it) and reaches word N by decoding only the one frame that holds it. The
// compressed file is a standard multi-frame .zst (any zstd tool reads it); the .idx is a small side
// file.
//
// Standalone; not wired into the hashcat build. Compile with:
//   cc -O2 -std=gnu11 tools/zsf.c -lzstd -lpthread -o zsf
//
//   zsf build   [opts] <in.txt> <out.zst>    frame a PLAINTEXT wordlist
//   zsf reframe [opts] <in.zst> <out.zst>    re-frame an existing zstd wordlist (streaming, no temp)
//   zsf skip           <in.zst> <N> [count]  print `count` words from word N (0-based), one frame
//   zsf info           <in.zst>              show frame / line counts
//
// opts:  -f/--frame <MiB> (16)   -l/--level <1..22> (19)   -t/--threads <n> (all cores)   -h/--help

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <pthread.h>
#include <getopt.h>
#include <errno.h>
#include <zstd.h>

#define IDX_MAGIC 0x315A53464B434821ULL   // matches feed_zstd's sidecar reader

static void die (const char *m) { fprintf (stderr, "zsf: %s\n", m); exit (1); }

// ---------------------------------------------------------------- input source (plaintext or zstd)

typedef struct
{
  int            is_zstd;
  FILE          *fp;      // plaintext
  int            fd;      // zstd raw
  ZSTD_DStream  *ds;
  unsigned char *inbuf;
  size_t         incap, inlen, inpos;
  int            ineof, err;
} src_t;

static int src_open (src_t *s, const char *path, int is_zstd)
{
  memset (s, 0, sizeof (*s));
  s->is_zstd = is_zstd;

  if (!is_zstd)
  {
    s->fp = fopen (path, "rb");
    return s->fp ? 0 : -1;
  }

  s->fd = open (path, O_RDONLY);
  if (s->fd == -1) return -1;
  s->ds = ZSTD_createDStream ();
  if (!s->ds) { close (s->fd); return -1; }
  ZSTD_bounds b = ZSTD_dParam_getBounds (ZSTD_d_windowLogMax);
  if (!ZSTD_isError (b.error)) ZSTD_DCtx_setParameter (s->ds, ZSTD_d_windowLogMax, b.upperBound);
  s->incap = ZSTD_DStreamInSize ();
  s->inbuf = malloc (s->incap);
  if (!s->inbuf) { ZSTD_freeDStream (s->ds); close (s->fd); return -1; }
  return 0;
}

// fill up to cap decoded bytes; return count, 0 at EOF
static size_t src_read (src_t *s, unsigned char *out, size_t cap)
{
  if (!s->is_zstd) return fread (out, 1, cap, s->fp);

  ZSTD_outBuffer ob = { out, cap, 0 };
  while (ob.pos == 0)
  {
    if (s->inpos == s->inlen)
    {
      if (s->ineof) break;
      ssize_t r = read (s->fd, s->inbuf, s->incap);
      if (r < 0) { s->err = 1; break; }
      if (r == 0) { s->ineof = 1; break; }
      s->inlen = (size_t) r; s->inpos = 0;
    }
    ZSTD_inBuffer ib = { s->inbuf, s->inlen, s->inpos };
    size_t rc = ZSTD_decompressStream (s->ds, &ob, &ib);
    s->inpos = ib.pos;
    if (ZSTD_isError (rc)) { s->err = 1; break; }
  }
  return ob.pos;
}

static void src_close (src_t *s)
{
  if (s->is_zstd) { if (s->ds) ZSTD_freeDStream (s->ds); free (s->inbuf); if (s->fd != -1) close (s->fd); }
  else if (s->fp) fclose (s->fp);
}

// ---------------------------------------------------------------- parallel per-frame compression

typedef struct { unsigned char *plain; size_t plen; unsigned char *comp; size_t clen; uint64_t nl; int level; int err; } job_t;
typedef struct { job_t *j; size_t n, next; } pool_t;

static void *cworker (void *arg)
{
  pool_t *p = (pool_t *) arg;
  for (;;)
  {
    size_t i = __atomic_fetch_add (&p->next, 1, __ATOMIC_RELAXED);
    if (i >= p->n) break;
    job_t *j = &p->j[i];
    size_t bound = ZSTD_compressBound (j->plen);
    j->comp = malloc (bound);
    if (!j->comp) { j->err = 1; continue; }
    size_t c = ZSTD_compress (j->comp, bound, j->plain, j->plen, j->level);
    if (ZSTD_isError (c)) { j->err = 1; continue; }
    j->clen = c;
    uint64_t nl = 0;
    for (size_t o = 0; o < j->plen; o++) if (j->plain[o] == '\n') nl++;
    j->nl = nl;
  }
  return NULL;
}

// ---------------------------------------------------------------- frame + write (build & reframe)

typedef struct { uint64_t comp_off, first_line, uncomp_size; } ent_t;

static int frame_and_write (src_t *s, const char *outpath, size_t frame_bytes, int level, long threads)
{
  FILE *out = fopen (outpath, "wb");
  if (!out) return -1;

  char idxpath[8192];
  snprintf (idxpath, sizeof idxpath, "%s.idx", outpath);
  FILE *fx = fopen (idxpath, "wb");
  if (!fx) { fclose (out); return -1; }

  long ncpu = sysconf (_SC_NPROCESSORS_ONLN);
  size_t nthreads = threads > 0 ? (size_t) threads : (ncpu > 0 ? (size_t) ncpu : 1);
  size_t BATCH = nthreads * 4;

  job_t  *batch = calloc (BATCH, sizeof (job_t));
  ent_t  *ents  = NULL; size_t nents = 0, cents = 0;
  uint64_t comp_off = 0, first_line = 0, total_lines = 0;

  size_t cap = frame_bytes + 4 * 1024 * 1024 + 1;
  unsigned char *line = malloc (cap);
  size_t head = 0, len = 0;
  unsigned char *rd = malloc (4 * 1024 * 1024);
  size_t bn = 0;
  int ok = 1, last_nl = 1;

  // flush the current batch: compress in parallel, write in order, record index
  #define FLUSH() do {                                                                          \
    if (bn) {                                                                                    \
      pool_t p = { batch, bn, 0 };                                                               \
      size_t nt = nthreads > bn ? bn : nthreads;                                                 \
      pthread_t *t = malloc (nt * sizeof (pthread_t)); size_t sp = 0;                            \
      for (size_t i = 0; i < nt; i++) { if (pthread_create (&t[i], NULL, cworker, &p)) break; sp++; } \
      if (!sp) cworker (&p);                                                                     \
      for (size_t i = 0; i < sp; i++) pthread_join (t[i], NULL);                                 \
      free (t);                                                                                  \
      for (size_t i = 0; i < bn; i++) {                                                          \
        if (batch[i].err) ok = 0;                                                                \
        else if (fwrite (batch[i].comp, 1, batch[i].clen, out) != batch[i].clen) ok = 0;         \
        if (nents == cents) { cents = cents ? cents * 2 : 1024; ents = realloc (ents, cents * sizeof (ent_t)); } \
        ents[nents].comp_off = comp_off; ents[nents].first_line = first_line;                    \
        ents[nents].uncomp_size = batch[i].plen; nents++;                                        \
        comp_off += batch[i].clen; first_line += batch[i].nl; total_lines += batch[i].nl;        \
        free (batch[i].comp); free (batch[i].plain); batch[i].comp = batch[i].plain = NULL;      \
      }                                                                                          \
      bn = 0;                                                                                    \
    }                                                                                            \
  } while (0)

  #define EMIT(P,L) do {                                                                         \
    unsigned char *c = malloc (L); if (!c) { ok = 0; break; }                                    \
    memcpy (c, (P), (L)); if ((L) > 0) last_nl = ((P)[(L)-1] == '\n');                            \
    batch[bn].plain = c; batch[bn].plen = (L); batch[bn].comp = NULL; batch[bn].level = level; batch[bn].err = 0; bn++; \
    if (bn == BATCH) FLUSH ();                                                                    \
  } while (0)

  while (ok)
  {
    size_t n = src_read (s, rd, 4 * 1024 * 1024);
    if (s->err) { ok = 0; break; }
    if (n == 0) break;

    if (head > 0 && len + n > cap) { memmove (line, line + head, len - head); len -= head; head = 0; }
    while (len + n > cap) { cap *= 2; line = realloc (line, cap); }
    memcpy (line + len, rd, n); len += n;

    while (ok && (len - head) >= frame_bytes)
    {
      unsigned char *base = line + head;
      size_t avail = len - head;
      unsigned char *nl = memchr (base + frame_bytes - 1, '\n', avail - (frame_bytes - 1));
      if (!nl) break;                     // no newline yet; need more input
      size_t cut = (size_t) (nl - base) + 1;
      EMIT (base, cut);
      head += cut;
    }
    if (head == len) { head = len = 0; }
  }

  if (ok && (len - head) > 0) EMIT (line + head, len - head);
  FLUSH ();

  #undef EMIT
  #undef FLUSH

  // a final line with no trailing newline is still a line (matches feed_zstd's count)
  if (nents > 0 && last_nl == 0) total_lines++;

  // sidecar: header {magic, level, frame_bytes, nframes, total_lines} then entries
  uint64_t hdr[5] = { IDX_MAGIC, (uint64_t) level, (uint64_t) frame_bytes, nents, total_lines };
  if (fwrite (hdr, sizeof hdr, 1, fx) != 1) ok = 0;
  if (fwrite (ents, sizeof (ent_t), nents, fx) != nents) ok = 0;

  fclose (fx); fclose (out);
  free (batch); free (ents); free (line); free (rd);

  if (!ok) { unlink (outpath); unlink (idxpath); return -1; }

  fprintf (stderr, "zsf: %s: %" PRIu64 " lines, %zu frames, %" PRIu64 " B compressed, index %zu B\n",
           outpath, total_lines, nents, comp_off, (size_t) (sizeof hdr + nents * sizeof (ent_t)));
  return 0;
}

// ---------------------------------------------------------------- skip / info (read the sidecar)

static ent_t *load_idx (const char *path, uint64_t *nframes, uint64_t *total, uint64_t *frame_bytes, uint64_t *filesize)
{
  struct stat st; if (stat (path, &st) != 0) die ("cannot stat input"); *filesize = (uint64_t) st.st_size;
  char ip[8192]; snprintf (ip, sizeof ip, "%s.idx", path);
  FILE *fx = fopen (ip, "rb"); if (!fx) die ("missing <in>.idx (run: zsf build/reframe ...)");
  uint64_t h[5]; if (fread (h, sizeof h, 1, fx) != 1 || h[0] != IDX_MAGIC) die ("bad index");
  *frame_bytes = h[2]; *nframes = h[3]; *total = h[4];
  ent_t *e = malloc (*nframes * sizeof (ent_t));
  if (fread (e, sizeof (ent_t), *nframes, fx) != *nframes) die ("truncated index");
  fclose (fx); return e;
}

static int cmd_skip (const char *path, uint64_t N, uint64_t count)
{
  uint64_t nframes, total, fb, fsz; ent_t *idx = load_idx (path, &nframes, &total, &fb, &fsz);
  if (N >= total) { fprintf (stderr, "zsf: N=%" PRIu64 " >= %" PRIu64 " lines\n", N, total); return 1; }

  uint64_t lo = 0, hi = nframes - 1, k = 0;
  while (lo <= hi) { uint64_t m = lo + (hi - lo) / 2; if (idx[m].first_line <= N) { k = m; lo = m + 1; } else { if (!m) break; hi = m - 1; } }

  uint64_t cstart = idx[k].comp_off, cend = (k + 1 < nframes) ? idx[k + 1].comp_off : fsz;
  size_t csize = cend - cstart;
  unsigned char *cbuf = malloc (csize), *dbuf = malloc (idx[k].uncomp_size);
  int fd = open (path, O_RDONLY); if (fd == -1) die ("open");
  if (pread (fd, cbuf, csize, (off_t) cstart) != (ssize_t) csize) die ("read frame");
  close (fd);
  size_t ds = ZSTD_decompress (dbuf, idx[k].uncomp_size, cbuf, csize);
  if (ZSTD_isError (ds)) die ("decompress");

  uint64_t skip = N - idx[k].first_line; unsigned char *p = dbuf, *end = dbuf + ds;
  while (skip && p < end) { unsigned char *nl = memchr (p, '\n', end - p); if (!nl) break; p = nl + 1; skip--; }
  for (uint64_t c = 0; c < count && p < end; c++) { unsigned char *nl = memchr (p, '\n', end - p); size_t l = nl ? (size_t) (nl - p) + 1 : (size_t) (end - p); fwrite (p, 1, l, stdout); if (!nl) break; p = nl + 1; }
  fprintf (stderr, "zsf: word %" PRIu64 " -> frame %" PRIu64 "/%" PRIu64 ", decoded %" PRIu64 " B (1 frame)\n", N, k, nframes, idx[k].uncomp_size);
  free (cbuf); free (dbuf); free (idx); return 0;
}

static int cmd_info (const char *path)
{
  uint64_t nframes, total, fb, fsz; ent_t *idx = load_idx (path, &nframes, &total, &fb, &fsz);
  uint64_t maxu = 0; for (uint64_t i = 0; i < nframes; i++) if (idx[i].uncomp_size > maxu) maxu = idx[i].uncomp_size;
  printf ("file            : %s\n", path);
  printf ("compressed size : %" PRIu64 " B\n", fsz);
  printf ("frames          : %" PRIu64 " (target %.1f MiB each)\n", nframes, (double) fb / (1024*1024));
  printf ("lines           : %" PRIu64 "\n", total);
  printf ("largest frame   : %.2f MiB uncompressed (seek decodes <= this)\n", (double) maxu / (1024*1024));
  free (idx); return 0;
}

// ---------------------------------------------------------------- CLI

static void usage (FILE *o)
{
  fprintf (o,
    "zsf — seekable-zstd wordlist tool\n\n"
    "usage:\n"
    "  zsf build   [opts] <in.txt> <out.zst>    frame a plaintext wordlist\n"
    "  zsf reframe [opts] <in.zst> <out.zst>    re-frame an existing zstd wordlist (streaming)\n"
    "  zsf skip           <in.zst> <N> [count]  print `count` words from word N (0-based)\n"
    "  zsf info           <in.zst>              show frame / line counts\n\n"
    "opts (build, reframe):\n"
    "  -f, --frame <MiB>    frame size, the seek granularity (default 16)\n"
    "  -l, --level <1..22>  zstd level (default 19)\n"
    "  -t, --threads <n>    worker threads (default: all cores)\n"
    "  -h, --help           this help\n\n"
    "the output is a standard multi-frame .zst (any zstd tool reads it) plus <out>.zst.idx.\n"
    "to replace a single-frame file in place:  zsf reframe old.zst new.zst && mv new.zst old.zst\n");
}

int main (int argc, char **argv)
{
  if (argc < 2) { usage (stderr); return 2; }
  const char *cmd = argv[1];

  size_t frame_mib = 16; int level = 19; long threads = 0;
  static struct option lo[] = {
    { "frame", required_argument, 0, 'f' }, { "level", required_argument, 0, 'l' },
    { "threads", required_argument, 0, 't' }, { "help", no_argument, 0, 'h' }, { 0, 0, 0, 0 } };

  optind = 2;
  int c;
  while ((c = getopt_long (argc, argv, "f:l:t:h", lo, NULL)) != -1)
  {
    if (c == 'f') frame_mib = strtoull (optarg, NULL, 10);
    else if (c == 'l') level = atoi (optarg);
    else if (c == 't') threads = atol (optarg);
    else if (c == 'h') { usage (stdout); return 0; }
    else { usage (stderr); return 2; }
  }
  char **pos = argv + optind; int npos = argc - optind;

  if (frame_mib < 1) frame_mib = 1;
  if (level < 1) level = 1;
  if (level > 22) level = 22;
  size_t frame_bytes = frame_mib * 1024 * 1024;

  if (!strcmp (cmd, "build") || !strcmp (cmd, "reframe"))
  {
    if (npos < 2) { usage (stderr); return 2; }
    src_t s;
    if (src_open (&s, pos[0], !strcmp (cmd, "reframe")) != 0) die ("cannot open input");
    int rc = frame_and_write (&s, pos[1], frame_bytes, level, threads);
    src_close (&s);
    return rc == 0 ? 0 : 1;
  }
  if (!strcmp (cmd, "skip"))
  {
    if (npos < 2) { usage (stderr); return 2; }
    uint64_t N = strtoull (pos[1], NULL, 10);
    uint64_t count = (npos >= 3) ? strtoull (pos[2], NULL, 10) : 1;
    return cmd_skip (pos[0], N, count);
  }
  if (!strcmp (cmd, "info"))
  {
    if (npos < 1) { usage (stderr); return 2; }
    return cmd_info (pos[0]);
  }
  if (!strcmp (cmd, "-h") || !strcmp (cmd, "--help")) { usage (stdout); return 0; }

  usage (stderr);
  return 2;
}
