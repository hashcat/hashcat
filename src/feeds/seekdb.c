/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

static const size_t SEEKDB_STEP = 8192;
static const size_t SAMPLE_SIZE = 65536;

// Where this wordlist's seek database lives, and what the wordlist is.
//
// The two are the same question. A seek database is only valid for the exact file it was built from,
// so it is named after a hash of that file's size, modification time and both of its ends, and looking
// the name up is what decides whether the cached one can be reused. That same hash answers "is this
// still the same wordlist" for anyone else who has to know, so it is handed back rather than left
// inside the file name.
//
// ident is where it goes. It is only written when a path could be built, so a caller that got NULL
// has nothing to read.

static char *seekdb_path (generic_global_ctx_t *global_ctx, const char *wordlist, u64 *ident)
{
  char *seekdb_dir = NULL;

  hc_asprintf (&seekdb_dir, "%s/seekdbs", global_ctx->cache_dir);

  hc_mkdir (seekdb_dir, 0700);

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

  XXH64_state_t *state = XXH64_createState ();

  XXH64_reset (state, 0);

  //would work better with realpath(), but maybe overkill
  //XXH64_update (state, wordlist, strlen (wordlist));

  XXH64_update (state, &st.st_size,  sizeof (st.st_size));
  XXH64_update (state, &st.st_mtime, sizeof (st.st_mtime));

  u8 *buf = (u8 *) hcmalloc (SAMPLE_SIZE);

  hc_fseek (&fp, 0, SEEK_SET);

  const size_t nread1 = hc_fread (buf, 1, SAMPLE_SIZE, &fp);

  XXH64_update (state, buf, nread1);

  const size_t file_size = (size_t) st.st_size;

  if (file_size > SAMPLE_SIZE)
  {
    hc_fseek (&fp, file_size- SAMPLE_SIZE, SEEK_SET);

    const size_t nread2 = hc_fread (buf, 1, SAMPLE_SIZE, &fp);

    XXH64_update (state, buf, nread2);
  }

  hcfree (buf);

  hc_fclose (&fp);

  u64 hash = XXH64_digest (state);

  XXH64_freeState (state);

  char *seekdb_path = NULL;

  hc_asprintf (&seekdb_path, "%s/%016" PRIx64 ".seekdb", seekdb_dir, hash);

  hcfree (seekdb_dir);

  ident[0] = hash;

  return seekdb_path;
}

static bool seekdb_save (const char *path, u64 line_count, u64 *db, u64 count, const u64 size)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "wb") == false)
  {
    return false;
  }

  if (hc_fwrite (&line_count, sizeof (u64), 1, &fp) != 1)
  {
    hc_fclose (&fp);

    return false;
  }

  if (hc_fwrite (&size, sizeof (u64), 1, &fp) != 1)
  {
    hc_fclose (&fp);

    return false;
  }

  if (hc_fwrite (db, sizeof (u64), count, &fp) != count)
  {
    hc_fclose (&fp);

    return false;
  }

  hc_fclose (&fp);

  return true;
}

static u64 *seekdb_load (const char *path, u64 *count, u64 *line_count, u64 *size)
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

  if (st.st_size < (ssize_t) sizeof (u64))
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (hc_fread (line_count, sizeof (u64), 1, &fp) != 1)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (hc_fread (size, sizeof (u64), 1, &fp) != 1)
  {
    hc_fclose (&fp);

    return NULL;
  }

  size_t rem = (st.st_size - sizeof (u64) - sizeof (u64)) / sizeof (u64);

  u64 *db = (u64 *) hcmalloc (rem * sizeof (u64));

  if (db == NULL)
  {
    hc_fclose (&fp);

    return NULL;
  }

  if (hc_fread (db, sizeof (u64), rem, &fp) != rem)
  {
    hc_fclose (&fp);

    hcfree (db);

    return NULL;
  }

  hc_fclose (&fp);

  *count = rem;

  return db;
}

static u64 *seekdb_build (feed_thread_t *feed_thread, const char *seekdb_path, const char *wordlist, u64 *count, u64 *line_count, u64 *size, hashcat_ctx_t *hashcat_ctx)
{
  const u8 *fd_mem = feed_thread->fd_mem;

  size_t fd_len = feed_thread->fd_len;

  u64 lines = 0;

  u64 alloc = (fd_len / SEEKDB_STEP) + 2;

  u64 *tmp = (u64 *) hcmalloc (alloc * sizeof (u64));

  u64 checkpoints = 0;

  tmp[checkpoints++] = 0;

  hc_timer_t start;

  hc_timer_set (&start);

  double prev_percent = 0;

  while (fd_len)
  {
    const u8 *next = memchr (fd_mem, '\n', fd_len);

    if (next == NULL)
    {
      // this should be fine as meassurement to detect if there's a newline at the end of file or not,
      // because we limit ourself with fd_len and if there's a newline as last byte of the file, the while loop will break naturally

      lines++;

      break;
    }

    const size_t step_size = (size_t) (next - fd_mem) + 1;

    fd_mem += step_size;
    fd_len -= step_size;

    lines++;

    if ((lines % SEEKDB_STEP) == 0)
    {
      tmp[checkpoints++] = (size_t) ((const u8 *) fd_mem - (const u8 *) feed_thread->fd_mem);
    }

    // let's see if we update stats for the user

    const size_t cur_pos = feed_thread->fd_len - fd_len;

    double percent = ((double) (cur_pos) / (double) feed_thread->fd_len) * 100;

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

  u64 *db = (u64 *) hccalloc (checkpoints, sizeof (u64));

  memcpy (db, tmp, checkpoints * sizeof (u64));

  *count = checkpoints;

  *line_count = lines;

  *size = feed_thread->fd_len;

  seekdb_save (seekdb_path, *line_count, db, *count, feed_thread->fd_len);

  hcfree (tmp);

  return db;
}
