/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

static const size_t SEEKDB_STEP = 8192;
static const size_t SAMPLE_SIZE = 65536;

// How many numbers one frame of a compressed source takes in the database: where the frame starts in
// the file on disk, how many decompressed bytes came before it, how far into it the first whole line
// starts, and which line that is.

#define SEEKDB_FRAME_WORDS 4

// Which rules the frame index in a database was built under.
//
// A database is a cache that outlives the hashcat that wrote it, is shared between hosts, and is
// only ever thrown away when the wordlist changes. That leaves no way to retire an index built by
// code that chose its boundaries differently, and there is already one such change: the first
// version recorded frames for .zst alone, so an .xz indexed by it carries one useless entry and
// would keep it forever. A compressed source whose database was built under a different generation
// is rebuilt. Raise this whenever what goes into the index changes.

#define SEEKDB_FRAME_GEN 2

// Which process is writing, so that two of them sharing a seek database directory do not pick the
// same temporary name.

#if defined (_WIN)
#include <process.h>
#define SEEKDB_GETPID _getpid
#else
#include <unistd.h>
#define SEEKDB_GETPID getpid
#endif

// How many bytes a compressed wordlist has to decode to before hashcat says anything about it not
// being seekable. It is the decompressed size that decides, because that is what a seek has to walk
// through, and below this walking through all of it is quicker than reading the advice.

#define SEEKDB_ADVICE_SIZE (64 * 1024 * 1024)

// A macro rather than a const, because it sizes the header buffers and a const size_t would make
// those variable length arrays.

#define SEEKDB_HEADER_SIZE 512

#define SEEKDB_MAGIC       "HASHCAT-SEEKDB"
#define SEEKDB_VERSION     1

// Which byte order the offsets in the body are written in.
//
// It only started to matter once these files began to travel between machines. The body is written in
// host order, so a database copied to a machine of the other order would be read as offsets that mean
// nothing rather than refused, and the run would seek to nonsense.

static const char *seekdb_endian (void)
{
  const u32 probe = 1;

  const u8 *probe_ptr = (const u8 *) &probe;

  if (probe_ptr[0] == 1) return "little";

  return "big";
}

// The wordlist name as it goes into the header.
//
// Only the base name, because the header is there to tell a person which file a database belongs to
// and a full path would additionally say where that person keeps their wordlists. Any byte outside
// printable ASCII becomes '_', because a file name may hold a newline and that would otherwise add a
// line to a header that is parsed a line at a time.

static void seekdb_source_name (char *dst, const size_t dst_sz, const char *wordlist)
{
  const size_t wordlist_len = strlen (wordlist);

  size_t base = 0;

  for (size_t i = 0; i < wordlist_len; i++)
  {
    if ((wordlist[i] == '/') || (wordlist[i] == '\\')) base = i + 1;
  }

  size_t j = 0;

  for (size_t i = base; i < wordlist_len; i++)
  {
    if ((j + 1) >= dst_sz) break;

    const u8 c = (const u8) wordlist[i];

    dst[j] = ((c >= 0x20) && (c < 0x7f)) ? (char) c : '_';

    j++;
  }

  dst[j] = 0;
}

// What a wordlist is, as one number.
//
// A seek database is only valid for the exact file it was built from, so it is named after a hash of
// that file's size and both of its ends, and looking the name up is what decides whether a cached one
// can be reused. That same hash answers "is this still the same wordlist" for anyone else who has to
// know, so it is handed back rather than left inside the file name.
//
// The modification time is deliberately not part of it. It is the only thing here that is not a
// property of the contents, and no ordinary transport preserves it, so including it meant the same
// wordlist hashed differently after being copied and every machine had to build its own database.
//
// What that gives up is narrower than it looks. A database maps a line number to a byte offset, and a
// line boundary only moves when a line's length changes, so an edit that keeps every length is still
// described correctly by the database it was built from. Almost everything that does move a boundary
// changes the file size, which is hashed. What is left is an edit that keeps the total size and moves
// a boundary anyway, and thread_seek () checks for that directly when it uses a checkpoint.
//
// ident and file_size are where the answers go. Both are only written when a path could be built, so
// a caller that got NULL has nothing to read.
//
// The directory is global_ctx->seekdb_dir when --seekdb-path named one, and a seekdbs folder inside
// the cache directory otherwise. Nothing else changes: the name is still the hash, so a directory
// shared between machines holds one database per wordlist rather than one per machine, and the
// header checks below decide whether what is found there belongs to the file in hand.

static char *seekdb_path (generic_global_ctx_t *global_ctx, const char *wordlist, u64 *ident, u64 *file_size)
{
  char *seekdb_dir = NULL;

  if (global_ctx->seekdb_dir != NULL)
  {
    seekdb_dir = hcstrdup (global_ctx->seekdb_dir);
  }
  else
  {
    hc_asprintf (&seekdb_dir, "%s/seekdbs", global_ctx->cache_dir);

    // Only the directory hashcat owns is created. One the user named is checked at startup instead,
    // and creating it here would turn a typo into a directory rather than an error.

    hc_mkdir (seekdb_dir, 0700);
  }

  HCFILE fp;

  if (hc_fopen_raw (&fp, wordlist, "rb") == false)
  {
    hcfree (seekdb_dir);

    return NULL;
  }

  struct stat st;

  if (hc_fstat (&fp, &st) == -1)
  {
    hc_fclose (&fp);

    hcfree (seekdb_dir);

    return NULL;
  }

  paw64_ctx_t state;

  paw64_init (&state, 0);

  paw64_update (&state, &st.st_size, sizeof (st.st_size));

  u8 *buf = (u8 *) hcmalloc (SAMPLE_SIZE);

  hc_fseek (&fp, 0, SEEK_SET);

  // A compressed source is read whole rather than sampled at its ends.
  //
  // Sampling is sound for a plain wordlist, where a byte that changes without moving a line ending
  // leaves every offset in the database still correct. A compressed file has no such property: one
  // byte alters everything decoded after it, so two files with the same size and the same ends can
  // hold entirely different wordlists. Reading all of it is what that costs, and it is a smaller
  // read than the one it protects, because the whole point of the file is that it is smaller than
  // what it carries.

  if (hc_path_is_compressed (wordlist) == true)
  {
    while (true)
    {
      const size_t nread = hc_fread (buf, 1, SAMPLE_SIZE, &fp);

      if (nread == 0) break;
      if (nread == (size_t) -1) break;

      paw64_update (&state, buf, nread);
    }
  }
  else
  {
    const size_t nread1 = hc_fread (buf, 1, SAMPLE_SIZE, &fp);

    if (nread1 != (size_t) -1) paw64_update (&state, buf, nread1);

    const size_t file_len = (size_t) st.st_size;

    if (file_len > SAMPLE_SIZE)
    {
      hc_fseek (&fp, file_len - SAMPLE_SIZE, SEEK_SET);

      const size_t nread2 = hc_fread (buf, 1, SAMPLE_SIZE, &fp);

      if (nread2 != (size_t) -1) paw64_update (&state, buf, nread2);
    }
  }

  hcfree (buf);

  hc_fclose (&fp);

  const u64 hash = paw64_final (&state);

  char *seekdb_path = NULL;

  hc_asprintf (&seekdb_path, "%s/%016" PRIx64 ".seekdb", seekdb_dir, hash);

  hcfree (seekdb_dir);

  ident[0]     = hash;
  file_size[0] = (u64) st.st_size;

  return seekdb_path;
}

// One field out of the text header, as a pointer to whatever follows its name.
//
// The header is a fixed size block of lines, so this searches a buffer rather than a file, and a name
// only counts where it starts a line. That keeps a value from being mistaken for a field name.

static const char *seekdb_header_field (const char *header, const char *name)
{
  const size_t name_len = strlen (name);

  const char *pos = header;

  while (pos < (header + SEEKDB_HEADER_SIZE))
  {
    const size_t left = (size_t) SEEKDB_HEADER_SIZE - (size_t) (pos - header);

    if (left > name_len)
    {
      if (strncmp (pos, name, name_len) == 0)
      {
        if (pos[name_len] == ' ') return pos + name_len + 1;
      }
    }

    const char *next = (const char *) memchr (pos, '\n', left);

    if (next == NULL) break;

    pos = next + 1;
  }

  return NULL;
}

static bool seekdb_header_u64 (const char *header, const char *name, const char *fmt, u64 *value)
{
  const char *field = seekdb_header_field (header, name);

  if (field == NULL) return false;

  const int rc = sscanf (field, fmt, value);

  if (rc != 1) return false;

  return true;
}

// The frames of a compressed source, while they are still being collected.
//
// The file layer reports a boundary as soon as it reads past one, which is before the bytes of that
// frame have been walked for line endings, so an entry arrives knowing where it is and not yet which
// line it belongs to. resolved is how many of them the walk has caught up with. Everything from
// there on is waiting for the next line ending to say what it points at.

typedef struct seekdb_frames
{
  u64 *buf;
  u64  count;
  u64  alloc;
  u64  resolved;

} seekdb_frames_t;

static void seekdb_frame_seen (void *userdata, const u64 comp_off, const u64 uncomp_off)
{
  seekdb_frames_t *frames = (seekdb_frames_t *) userdata;

  // Two boundaries at the same decompressed offset are one place to a reader. A file that puts a
  // skippable frame in front of every compressed one, which is what pzstd writes, hands over such a
  // pair for every chunk it wrote. Keeping the later of the two leaves the reader less to walk past.

  if (frames->count > 0)
  {
    u64 *last = &frames->buf[(frames->count - 1) * SEEKDB_FRAME_WORDS];

    if (last[1] == uncomp_off)
    {
      last[0] = comp_off;

      return;
    }
  }

  if (frames->count == frames->alloc)
  {
    const size_t alloc_sz = (size_t) frames->alloc * SEEKDB_FRAME_WORDS * sizeof (u64);

    frames->buf = (u64 *) hcrealloc (frames->buf, alloc_sz, alloc_sz);

    frames->alloc *= 2;
  }

  u64 *entry = &frames->buf[frames->count * SEEKDB_FRAME_WORDS];

  entry[0] = comp_off;
  entry[1] = uncomp_off;
  entry[2] = 0;
  entry[3] = 0;

  frames->count++;
}

// A database is written under a name nobody looks for and renamed into place.
//
// The directory is shared on purpose: --seekdb-path points a whole cluster at one of them, and every
// host builds the same database for the same wordlist. Writing it in place means one host can read
// what another host is halfway through writing, and a half written database is worse than none: the
// header describes the wordlist correctly, so it passes every check, and the body it hands over is
// whatever had been flushed. A rename is atomic on every filesystem this runs on, so a reader sees
// either the old file or the whole new one. feed_gpu_cache_write () in src/feed.c avoids the same
// race the same way for the same reason.

static bool seekdb_save (const char *path, const char *wordlist, const u64 line_count, const u64 *db, const u64 count, const u64 *frame_db, const u64 frame_count, const u64 size, const u64 ident, const u64 content, const u64 step)
{
  char source[192];

  seekdb_source_name (source, sizeof (source), wordlist);

  char header[SEEKDB_HEADER_SIZE];

  const u64 built = (u64) time (NULL);

  const int header_len = snprintf (header, SEEKDB_HEADER_SIZE,
    SEEKDB_MAGIC " %d\n"
    "endian %s\n"
    "step %" PRIu64 "\n"
    "lines %" PRIu64 "\n"
    "bytes %" PRIu64 "\n"
    "ident %016" PRIx64 "\n"
    "content %016" PRIx64 "\n"
    "frames %" PRIu64 "\n"
    "framegen %d\n"
    "built %" PRIu64 "\n"
    "source %s\n",
    SEEKDB_VERSION, seekdb_endian (), step, line_count, size, ident, content, frame_count, SEEKDB_FRAME_GEN, built, source);

  if (header_len < 0) return false;

  // A truncated header would be read back as a database missing whichever fields fell off the end, so
  // it is better to write nothing and rebuild next time than to leave that behind.

  if (header_len >= (int) SEEKDB_HEADER_SIZE) return false;

  // Pad with line endings rather than zero bytes, so the whole header stays printable and `head -c 512`
  // on the file answers what it is without a tool.

  for (size_t i = (size_t) header_len; i < (size_t) SEEKDB_HEADER_SIZE; i++) header[i] = '\n';

  char tmp[1024];

  snprintf (tmp, sizeof (tmp), "%s.tmp.%d", path, (int) SEEKDB_GETPID ());

  HCFILE fp;

  if (hc_fopen (&fp, tmp, "wb") == false)
  {
    return false;
  }

  bool ok = true;

  if (hc_fwrite (header, sizeof (char), (size_t) SEEKDB_HEADER_SIZE, &fp) != (size_t) SEEKDB_HEADER_SIZE) ok = false;

  if ((ok == true) && (hc_fwrite (db, sizeof (u64), count, &fp) != count)) ok = false;

  const size_t frame_words = (size_t) frame_count * SEEKDB_FRAME_WORDS;

  if ((ok == true) && (frame_words > 0))
  {
    if (hc_fwrite (frame_db, sizeof (u64), frame_words, &fp) != frame_words) ok = false;
  }

  hc_fflush (&fp);
  hc_fclose (&fp);

  if (ok == false)
  {
    remove (tmp);

    return false;
  }

  // rename () refuses an existing target on Windows, where POSIX replaces it silently.

  #if defined (_WIN)
  remove (path);
  #endif

  if (rename (tmp, path) != 0)
  {
    remove (tmp);

    return false;
  }

  return true;
}

// Read a database back, and refuse it unless it describes the wordlist in hand.
//
// want_ident and want_size come from seekdb_path (), so they are what the file on disk is right now.
// Every check here is cheap on purpose: this runs before anything has been cracked and a wrong answer
// is worse than a rebuild.

// Whether a frame index could have come from the file it was loaded for.
//
// A database is stored under a hash of the wordlist, so one found at all is almost certainly the
// right one. What that does not cover is the database's own contents. A file damaged after it was
// written passes every check on the header and then hands thread_seek () offsets that point nowhere,
// and a seek to the wrong byte is a candidate never tried. These are the properties any real index
// has, and checking them costs one walk of the array.

static bool seekdb_frames_sane (const u64 *frames, const u64 count, const u64 file_size, const u64 line_count)
{
  u64 prev_comp   = 0;
  u64 prev_uncomp = 0;
  u64 prev_line   = 0;

  for (u64 i = 0; i < count; i++)
  {
    const u64 *entry = &frames[i * SEEKDB_FRAME_WORDS];

    // a frame begins inside the file it belongs to, and names a line that file has

    if (entry[0] >= file_size) return false;
    if (entry[3] >= line_count) return false;

    // and the frames are in file order, which is the order a search over them assumes. Two frames
    // may name the same line, because a frame need not hold a whole one.

    if (entry[0] < prev_comp) return false;
    if (entry[1] < prev_uncomp) return false;
    if (entry[3] < prev_line) return false;

    prev_comp   = entry[0];
    prev_uncomp = entry[1];
    prev_line   = entry[3];
  }

  return true;
}

static u64 *seekdb_load (const char *path, u64 *count, u64 *line_count, u64 *size, u64 *step, u64 **frame_db, u64 *frame_count, u64 *frame_gen, const u64 want_ident, const u64 want_size)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false)
  {
    return NULL;
  }

  struct stat st;

  if (hc_fstat (&fp, &st) == -1)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (st.st_size < (ssize_t) SEEKDB_HEADER_SIZE)
  {
    hc_fclose (&fp);

    return NULL;
  }

  char header[SEEKDB_HEADER_SIZE + 1];

  if (hc_fread (header, sizeof (char), (size_t) SEEKDB_HEADER_SIZE, &fp) != (size_t) SEEKDB_HEADER_SIZE)
  {
    hc_fclose (&fp);

    return NULL;
  }

  header[SEEKDB_HEADER_SIZE] = 0;

  // Anything that is not one of ours, or is a format from later than this build understands, is left
  // alone and rebuilt rather than guessed at.

  u64 version = 0;

  if (seekdb_header_u64 (header, SEEKDB_MAGIC, "%" SCNu64, &version) == false)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (version != SEEKDB_VERSION)
  {
    hc_fclose (&fp);

    return NULL;
  }

  const char *endian = seekdb_header_field (header, "endian");

  if (endian == NULL)
  {
    hc_fclose (&fp);

    return NULL;
  }

  const char *host_endian = seekdb_endian ();

  const size_t host_endian_len = strlen (host_endian);

  if (strncmp (endian, host_endian, host_endian_len) != 0)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (endian[host_endian_len] != '\n')
  {
    hc_fclose (&fp);

    return NULL;
  }

  u64 header_step = 0;

  if (seekdb_header_u64 (header, "step", "%" SCNu64, &header_step) == false)
  {
    hc_fclose (&fp);

    return NULL;
  }

  // The step is read from the file rather than taken from SEEKDB_STEP, so retuning that constant
  // leaves every database already on disk valid and merely coarser. A zero would divide by zero in
  // thread_seek ().

  if (header_step == 0)
  {
    hc_fclose (&fp);

    return NULL;
  }

  u64 header_lines = 0;

  if (seekdb_header_u64 (header, "lines", "%" SCNu64, &header_lines) == false)
  {
    hc_fclose (&fp);

    return NULL;
  }

  u64 header_bytes = 0;

  if (seekdb_header_u64 (header, "bytes", "%" SCNu64, &header_bytes) == false)
  {
    hc_fclose (&fp);

    return NULL;
  }

  u64 header_ident = 0;

  if (seekdb_header_u64 (header, "ident", "%" SCNx64, &header_ident) == false)
  {
    hc_fclose (&fp);

    return NULL;
  }

  // The name of the file already says which wordlist this is, but a database that was copied here can
  // arrive under a name that does not match what is inside it. This is what catches that.

  if (header_ident != want_ident)
  {
    hc_fclose (&fp);

    return NULL;
  }

  // The size is the check that carries the most weight, because almost every edit that moves a line
  // boundary also changes it.

  if (header_bytes != want_size)
  {
    hc_fclose (&fp);

    return NULL;
  }

  // How much of the body is the frame index, which is written after the line checkpoints.
  //
  // A database built before the frame index existed carries neither field, and its body cannot be
  // told apart from one that has frames in it. Such a file reads as generation 0, which is not the
  // generation this hashcat writes, and a compressed source rebuilds on that difference: the file it
  // has predates its being seekable at all. The same difference retires an index whose rules have
  // changed since, which is what the generation is really for.

  u64 header_frames = 0;

  const bool has_frames = seekdb_header_u64 (header, "frames", "%" SCNu64, &header_frames);

  u64 header_gen = 0;

  if (has_frames == false) header_frames = 0;

  if (seekdb_header_u64 (header, "framegen", "%" SCNu64, &header_gen) == false) header_gen = 0;

  const size_t rem = ((size_t) st.st_size - SEEKDB_HEADER_SIZE) / sizeof (u64);

  // The count came out of a file, and multiplying it by the width of an entry is where a large one
  // stops meaning anything. The product wraps, a bound written as a product passes, and the count
  // itself is kept and used to index an array of a few entries. Dividing the room by the width says
  // the same thing and cannot wrap.

  if (header_frames > (rem / SEEKDB_FRAME_WORDS))
  {
    hc_fclose (&fp);

    return NULL;
  }

  const size_t frame_words = (size_t) header_frames * SEEKDB_FRAME_WORDS;

  const size_t db_words = rem - frame_words;

  u64 *db = (u64 *) hcmalloc (db_words * sizeof (u64));

  if (db == NULL)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (hc_fread (db, sizeof (u64), db_words, &fp) != db_words)
  {
    hc_fclose (&fp);

    hcfree (db);

    return NULL;
  }

  u64 *frames = NULL;

  if (frame_words > 0)
  {
    frames = (u64 *) hcmalloc (frame_words * sizeof (u64));

    if (frames == NULL)
    {
      hc_fclose (&fp);

      hcfree (db);

      return NULL;
    }

    if (hc_fread (frames, sizeof (u64), frame_words, &fp) != frame_words)
    {
      hc_fclose (&fp);

      hcfree (frames);
      hcfree (db);

      return NULL;
    }

    if (seekdb_frames_sane (frames, header_frames, header_bytes, header_lines) == false)
    {
      hc_fclose (&fp);

      hcfree (frames);
      hcfree (db);

      return NULL;
    }
  }

  hc_fclose (&fp);

  *count        = db_words;
  *line_count   = header_lines;
  *size         = header_bytes;
  *step         = header_step;
  *frame_db     = frames;
  *frame_count  = header_frames;
  *frame_gen    = header_gen;

  return db;
}

// Count the lines of a source and record where every SEEKDB_STEP'th one starts.
//
// A mapped source is one run of bytes and is walked once. A compressed one arrives a window at a
// time, and the only difference that makes is that the walk goes round again: a line ending is
// counted wherever it turns up, so a line lying across two windows is still one line.
//
// The offsets recorded are into the decompressed bytes. For a compressed source nothing can seek to
// one of them, so they are written for the line count they come with rather than for themselves.
// What a compressed source is seeked with is the frame index built alongside them, which records
// the places in the file on disk that a decoder can be started at. The size written to the header is
// the size of the file on disk either way, because that is what the header is checked against when
// it is read back.

static u64 *seekdb_build (feed_thread_t *feed_thread, const char *seekdb_path, const char *wordlist, u64 *count, u64 *line_count, u64 *size, u64 *step, u64 **frame_db, u64 *frame_count, const u64 ident, hashcat_ctx_t *hashcat_ctx)
{
  u64 lines       = 0;
  u64 pos         = 0;
  u64 last_nl_end = 0;

  u64 alloc = (feed_thread->compressed == true) ? 4096 : (feed_thread->fd_len / SEEKDB_STEP) + 2;

  u64 *tmp = (u64 *) hcmalloc (alloc * sizeof (u64));

  u64 checkpoints = 0;

  tmp[checkpoints++] = 0;

  seekdb_frames_t frames;

  frames.buf      = NULL;
  frames.count    = 0;
  frames.alloc    = 0;
  frames.resolved = 0;

  if (feed_thread->compressed == true)
  {
    frames.alloc = 1024;
    frames.buf   = (u64 *) hcmalloc (frames.alloc * SEEKDB_FRAME_WORDS * sizeof (u64));

    // The first frame begins where the file does. Nothing reports that boundary, because a boundary
    // is only reported once the frame in front of it has been decoded, so it is put in by hand. It
    // needs no line to complete it either: there is nothing in front of the first line, so a reader
    // sent here drops no bytes and arrives at line zero.

    seekdb_frame_seen (&frames, 0, 0);

    frames.resolved = 1;

    // source_open () decoded the front of the file already, to fill the window it handed over, and
    // any boundary in there went past before there was anywhere to report it to. Reading that window
    // again with the callback in place costs one window of decoding and is the only way to see them.

    hc_frame_notify (&feed_thread->hcfile, seekdb_frame_seen, &frames);

    source_restart (feed_thread);
  }

  paw64_ctx_t xstate;

  paw64_init (&xstate, 0);

  hc_timer_t start;

  hc_timer_set (&start);

  double prev_percent = 0;

  bool done = false;

  while (done == false)
  {
    const u8 *buf = NULL;

    size_t n = 0;

    if (feed_thread->compressed == true)
    {
      source_fill (feed_thread);

      buf = (const u8 *) feed_thread->fd_mem + feed_thread->fd_off;
      n   = feed_thread->fd_len - feed_thread->fd_off;

      feed_thread->fd_off += n;
    }
    else
    {
      buf  = (const u8 *) feed_thread->fd_mem;
      n    = feed_thread->fd_len;
      done = true;
    }

    if (n == 0) break;

    paw64_update (&xstate, buf, n);

    size_t i = 0;

    while (i < n)
    {
      const u8 *next = (const u8 *) memchr (buf + i, '\n', n - i);

      if (next == NULL)
      {
        pos += (u64) (n - i);

        break;
      }

      const size_t step_size = (size_t) (next - (buf + i)) + 1;

      i   += step_size;
      pos += (u64) step_size;

      lines++;

      last_nl_end = pos;

      // A frame boundary lands wherever the compressor put it, which is almost never on a line
      // ending, so what a reader restarting there finds first is the tail of a line that began in
      // the frame before. A line ending has just gone past, which makes pos the start of a line and
      // lines its number, and that is the first whole line after every boundary still waiting. The
      // check has to be here rather than anywhere else in this loop, because this is the only point
      // where pos is known to be the start of a line: a window ends wherever it fills up, which is
      // usually in the middle of one. Nothing waits for the whole of a plain wordlist, so what this
      // costs there is one comparison per line.

      while (frames.resolved < frames.count)
      {
        u64 *entry = &frames.buf[frames.resolved * SEEKDB_FRAME_WORDS];

        if (entry[1] > pos) break;

        entry[2] = pos - entry[1];
        entry[3] = lines;

        frames.resolved++;
      }

      if ((lines % SEEKDB_STEP) == 0)
      {
        if (checkpoints == alloc)
        {
          tmp = (u64 *) hcrealloc (tmp, alloc * sizeof (u64), alloc * sizeof (u64));

          alloc *= 2;
        }

        tmp[checkpoints++] = pos;
      }
    }

    // What has been got through, measured against the file on disk. For a compressed source that is
    // how far into the compressed bytes the reader has reached, which is the only one of the two
    // that has a total to compare against.

    const u64 cur_pos = (feed_thread->compressed == true) ? (u64) lseek (feed_thread->hcfile.fd, 0, SEEK_CUR) : pos;

    const u64 den = feed_thread->file_size;

    double percent = (den > 0) ? (((double) cur_pos / (double) den) * 100) : 0;

    if (percent > 100) percent = 100;

    if ((prev_percent + 1.234) > percent) continue;

    prev_percent = percent;

    if (percent < 100)
    {
      cache_generate_t cache_generate;

      cache_generate.dictfile    = wordlist;
      cache_generate.comp        = cur_pos;
      cache_generate.percent     = percent;
      cache_generate.cnt         = lines;
      cache_generate.cnt2        = lines;
      cache_generate.runtime     = hc_timer_get (start);

      EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));
    }
  }

  hc_frame_notify (&feed_thread->hcfile, NULL, NULL);

  // A boundary with no whole line after it is the tail end of the file, and there is nothing there
  // to seek to.

  frames.count = frames.resolved;

  // bytes after the last line ending are a line with nothing after it

  if (pos > last_nl_end) lines++;

  // A file whose last line ends exactly where the file does leaves a boundary naming the line after
  // it, which is a line the file does not have. Nothing can seek there, so it goes rather than sit
  // in the search.

  while (frames.count > 0)
  {
    if (frames.buf[((frames.count - 1) * SEEKDB_FRAME_WORDS) + 3] < lines) break;

    frames.count--;
  }

  u64 *db = (u64 *) hccalloc (checkpoints, sizeof (u64));

  memcpy (db, tmp, checkpoints * sizeof (u64));

  u64 *frame_out = NULL;

  if (frames.count > 0)
  {
    frame_out = (u64 *) hccalloc (frames.count * SEEKDB_FRAME_WORDS, sizeof (u64));

    memcpy (frame_out, frames.buf, frames.count * SEEKDB_FRAME_WORDS * sizeof (u64));
  }

  *count       = checkpoints;
  *line_count  = lines;
  *size        = feed_thread->file_size;
  *step        = SEEKDB_STEP;
  *frame_db    = frame_out;
  *frame_count = frames.count;

  // A compressed wordlist that was written in one piece has no boundary to seek to but its own
  // start, so every seek backwards decodes it again from there and every device pays for that
  // separately. Saying so once, while the index is being built, is the only moment where the fact is
  // both known and still worth acting on. Small files are left alone: decoding one of those from the
  // start costs nothing worth a line of advice.

  if ((feed_thread->compressed == true) && (frames.count < 2) && (pos >= SEEKDB_ADVICE_SIZE))
  {
    // What to write it with instead depends on what it is. The stock xz already writes blocks when
    // it is asked to use every core, so an .xz needs one more switch and not another format. A .zst
    // needs pzstd, because zstd itself writes the whole file as one frame however it is called.

    const char *advice = "compressing it with pzstd instead gives hashcat frames it can seek to";

    if (strcmp (hc_container_name (&feed_thread->hcfile), "xz") == 0)
    {
      advice = "compressing it with xz -T0 instead gives hashcat blocks it can seek to";
    }

    feed_say (hashcat_ctx, "%s: compressed in one piece, so seeking into it means decoding it from the start.", wordlist);
    feed_say (hashcat_ctx, "%s: %s.", wordlist, advice);
  }

  const u64 content = paw64_final (&xstate);

  seekdb_save (seekdb_path, wordlist, *line_count, db, *count, frame_out, frames.count, feed_thread->file_size, ident, content, SEEKDB_STEP);

  hcfree (frames.buf);

  hcfree (tmp);

  return db;
}
