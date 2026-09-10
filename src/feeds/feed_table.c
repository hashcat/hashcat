/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The table attack. A wordlist plus a table file that maps a source token to a set of replacement
// tokens, where every token position of a word expands independently and the attack emits the cross
// product. hashcat-legacy ran this as attack mode 5 and it was dropped in 3.00 as something a GPU
// could not be given, because a word's candidate count is a product over its own characters and no
// two words agree on it.
//
// The wordlist half is wordlist.c, unchanged and shared with the wordlist feed. What is here is the
// table, the reading of it over a word, and the odometer that walks what that produced.

#include "wordlist.c"

// How long a source token may be. Longest match probes every length down from here at every position
// of every word, so this is a cost as well as a limit.

#define TABLE_SRC_MAX 32

// How long a replacement may be. The kernel writes a candidate of at most PCFG_DEV_MAXBYTE bytes, so
// nothing longer can appear in one, and the byte that carries an entry length in a slot descriptor
// stops at 255 either way.

#define TABLE_ENT_MAX 255

// A run of a word the table said nothing about. It is not a bucket, it is the word's own bytes.

#define TABLE_TOK_LITERAL 0xffffffff

// One replacement, as a span of the arena rather than a pointer, because the arena moves as it grows.

typedef struct table_ent
{
  u32 off;
  u32 len;

} table_ent_t;

typedef struct table_bucket
{
  u32 src_off;
  u32 src_len;

  table_ent_t *ent;
  u32          ent_cnt;
  u32          ent_alloc;

  // What the pool build settled. pool_off is what goes in a slot descriptor and it means two
  // different things depending on varlen: the byte offset of the first entry when every entry is the
  // same length, and the u32 index of the bucket's offset table when they are not.

  u32 pool_off;
  u32 ent_len;

  // the shortest and longest entries the bucket holds, which is what a candidate's length is bounded
  // with

  u32 ent_min;
  u32 ent_max;

} table_bucket_t;

typedef struct table
{
  u8 *arena;
  u64 arena_len;
  u64 arena_alloc;

  table_bucket_t *bucket;
  u32             bucket_cnt;
  u32             bucket_alloc;

  // Longest match, by first byte. Sources sharing a first byte are held together and sorted longest
  // first, so the first one that matches at a position is the one to take and there is nothing to
  // compare afterwards. A single byte table gives every list one member and the walk is a load.
  //
  // A bucket of one entry is left out of these lists. Its only entry is the identity, so it varies
  // not at all, and leaving it in would spend a slot of the cell on a token that never changes.

  u32 *first[256];
  u32  first_cnt[256];

  u32  src_max;

  // Whether any bucket holds entries of more than one length, which decides how the kernel reaches an
  // entry. It reaches the kernel as a build option, so it is a property of the whole run rather than
  // of a bucket. Multibyte alone does not set it: a bucket of ss, 55 and $$ is uniform.

  bool varlen;

  // whether a source is an alternative to itself, which is what tells a bucket of one entry from a
  // token that never changes

  bool identity;

  // What the merged table is, as one number. Everything that changes a candidate or its place in the
  // run goes into it: the sources and their replacements, in order, and whether a token is an
  // alternative to itself. It is what names the keyspace index on disk.

  u64 ident;

  u32 *pool;
  u64  pool_cnt;

} table_t;

// One stretch of a word: which bytes it covers, and the bucket that expands it. A literal run covers
// bytes the table had nothing to say about and carries TABLE_TOK_LITERAL.

typedef struct table_tok
{
  u32 off;
  u32 len;

  u32 bucket;

} table_tok_t;

void table_free (table_t *tb);

static void table_err (char *err_buf, const size_t err_size, const char *fmt, ...)
{
  if (err_buf == NULL) return;

  va_list ap;

  va_start (ap, fmt);

  vsnprintf (err_buf, err_size, fmt, ap);

  va_end (ap);
}

static u32 table_arena_add (table_t *tb, const u8 *buf, const u32 len)
{
  if ((tb->arena_len + len) > tb->arena_alloc)
  {
    u64 want = (tb->arena_alloc == 0) ? 4096 : (tb->arena_alloc * 2);

    want = MAX (want, tb->arena_len + len);

    tb->arena = (u8 *) hcrealloc (tb->arena, tb->arena_alloc, want - tb->arena_alloc);

    tb->arena_alloc = want;
  }

  const u32 off = (u32) tb->arena_len;

  for (u32 i = 0; i < len; i++) tb->arena[off + i] = buf[i];

  tb->arena_len += len;

  return off;
}

static bool table_span_eq (const table_t *tb, const u32 off, const u32 len, const u8 *buf, const u32 buf_len)
{
  if (len != buf_len) return false;

  for (u32 i = 0; i < len; i++)
  {
    if (tb->arena[off + i] != buf[i]) return false;
  }

  return true;
}

static u32 table_bucket_find (const table_t *tb, const u8 *src, const u32 src_len)
{
  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    const table_bucket_t *b = &tb->bucket[i];

    if (table_span_eq (tb, b->src_off, b->src_len, src, src_len) == true) return i;
  }

  return TABLE_TOK_LITERAL;
}

// An exact repeat of a replacement already in the bucket is dropped rather than kept, because the two
// would only produce the same candidate twice.

static void table_ent_add (table_t *tb, const u32 idx, const u8 *ent, const u32 ent_len)
{
  table_bucket_t *b = &tb->bucket[idx];

  for (u32 i = 0; i < b->ent_cnt; i++)
  {
    if (table_span_eq (tb, b->ent[i].off, b->ent[i].len, ent, ent_len) == true) return;
  }

  if (b->ent_cnt == b->ent_alloc)
  {
    const u32 want = (b->ent_alloc == 0) ? 8 : (b->ent_alloc * 2);

    b->ent = (table_ent_t *) hcrealloc (b->ent, b->ent_alloc * sizeof (table_ent_t), (want - b->ent_alloc) * sizeof (table_ent_t));

    b->ent_alloc = want;
  }

  const u32 off = table_arena_add (tb, ent, ent_len);

  b->ent[b->ent_cnt].off = off;
  b->ent[b->ent_cnt].len = ent_len;

  b->ent_cnt++;
}

// A bucket is seeded with its own source, so leaving a token alone is one of its choices. Digit zero of
// every slot is then the token the word already had, the all zero odometer reproduces the word, and the
// attack contains attack mode 0 at index 0 of each word.
//
// It is implicit because a table cannot be asked to spell it out for characters nobody thought of. A
// table covering one language's letters would otherwise force a conversion on every letter it happens
// to name and leave every other letter alone, and the two would not compose.
//
// identity=0 takes it away, for a table that converts rather than varies. A keyboard layout map is the
// case: it wants the whole word converted, and the choice at every position turns that into every
// mixture of converted and not.

static u32 table_bucket_add (table_t *tb, const u8 *src, const u32 src_len)
{
  if (tb->bucket_cnt == tb->bucket_alloc)
  {
    const u32 want = (tb->bucket_alloc == 0) ? 64 : (tb->bucket_alloc * 2);

    tb->bucket = (table_bucket_t *) hcrealloc (tb->bucket, tb->bucket_alloc * sizeof (table_bucket_t), (want - tb->bucket_alloc) * sizeof (table_bucket_t));

    tb->bucket_alloc = want;
  }

  const u32 idx = tb->bucket_cnt;

  table_bucket_t *b = &tb->bucket[idx];

  b->src_off = table_arena_add (tb, src, src_len);
  b->src_len = src_len;

  b->ent       = NULL;
  b->ent_cnt   = 0;
  b->ent_alloc = 0;

  b->pool_off = 0;
  b->ent_len  = 0;

  tb->bucket_cnt++;

  if (tb->identity == true) table_ent_add (tb, idx, src, src_len);

  return idx;
}

// $HEX[..] wrapping the whole side, and nothing else. It is what writes a # in the first column, a
// newline, and the empty replacement that deletes the token.

static int table_decode (const u8 *in, const u32 in_len, u8 *out, const u32 out_max)
{
  if (is_hexify (in, in_len) == true)
  {
    const u32 len = (in_len - 6) / 2;

    if (len > out_max) return -1;

    for (u32 i = 0; i < len; i++) out[i] = hex_to_u8 (&in[5 + (i * 2)]);

    return (int) len;
  }

  if (in_len > out_max) return -1;

  for (u32 i = 0; i < in_len; i++) out[i] = in[i];

  return (int) in_len;
}

static u8 *table_slurp (const char *path, u64 *out_len, char *err_buf, const size_t err_size)
{
  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false)
  {
    table_err (err_buf, err_size, "%s: %s", path, hc_fopen_strerror ());

    return NULL;
  }

  u8 *buf = NULL;

  u64 len   = 0;
  u64 alloc = 0;

  while (true)
  {
    if (len == alloc)
    {
      const u64 want = (alloc == 0) ? 65536 : (alloc * 2);

      buf = (u8 *) hcrealloc (buf, alloc, want - alloc);

      alloc = want;
    }

    const size_t got = hc_fread (&buf[len], 1, alloc - len, &fp);

    // A read error is (size_t) -1 rather than 0, and treating it as a short read would take len
    // backwards past the end of the buffer and never terminate.

    if (got == 0) break;
    if (got == (size_t) -1) break;

    len += got;
  }

  hc_fclose (&fp);

  out_len[0] = len;

  return buf;
}

// A bucket that leaves every word it matches exactly as it was, which is one holding nothing but the
// source itself. It costs a slot and reaches one candidate, so the tokenizer passes over it and the
// bytes fall into a literal run instead.

static bool table_bucket_idle (const table_t *tb, const u32 idx)
{
  const table_bucket_t *b = &tb->bucket[idx];

  if (b->ent_cnt == 0) return true;
  if (b->ent_cnt > 1) return false;

  const bool same = table_span_eq (tb, b->ent[0].off, b->ent[0].len, &tb->arena[b->src_off], b->src_len);

  return same;
}

// The lists longest match walks, one per first byte.

static void table_index_build (table_t *tb)
{
  for (u32 i = 0; i < 256; i++)
  {
    tb->first[i]     = NULL;
    tb->first_cnt[i] = 0;
  }

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    if (table_bucket_idle (tb, i) == true) continue;

    const u32 c = tb->arena[tb->bucket[i].src_off];

    tb->first_cnt[c]++;
  }

  for (u32 i = 0; i < 256; i++)
  {
    if (tb->first_cnt[i] == 0) continue;

    tb->first[i] = (u32 *) hcmalloc (tb->first_cnt[i] * sizeof (u32));

    tb->first_cnt[i] = 0;
  }

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    if (table_bucket_idle (tb, i) == true) continue;

    const u32 c = tb->arena[tb->bucket[i].src_off];

    tb->first[c][tb->first_cnt[c]] = i;

    tb->first_cnt[c]++;
  }

  // Longest first, so the first source that matches at a position is the one to take.

  for (u32 i = 0; i < 256; i++)
  {
    for (u32 j = 1; j < tb->first_cnt[i]; j++)
    {
      const u32 v   = tb->first[i][j];
      const u32 len = tb->bucket[v].src_len;

      u32 k = j;

      while ((k > 0) && (tb->bucket[tb->first[i][k - 1]].src_len < len))
      {
        tb->first[i][k] = tb->first[i][k - 1];

        k--;
      }

      tb->first[i][k] = v;
    }
  }
}

// The pool the device reads, in the two shapes the kernel is built for. With entries of one length a
// slot names the byte offset of its first entry and multiplies; with entries of several it names the
// u32 index of an offset table, and an entry's length is the difference to the next offset, which is
// what the sentinel at the end of each bucket is for.

// The pool is handed to the device rather than copied where the device can read the host's own bytes,
// and both Metal and OpenCL ask for a page aligned pointer a whole number of pages long before they
// will. It is zeroed here because the guard word and the padding are read as pool bytes.

static u32 *table_pool_alloc (u64 words)
{
  const u64 bytes = ((words * 4) + (PCFG_POOL_ALIGN - 1)) & ~((u64) (PCFG_POOL_ALIGN - 1));

  u32 *p = (u32 *) hc_alloc_aligned (PCFG_POOL_ALIGN, bytes);

  if (p == NULL) return NULL;

  memset (p, 0, bytes);

  return p;
}

// Every offset into the pool is a u32, in the cells the device reads and in the byte reads the kernel
// makes, while the pool is sized from a u64. A table whose entries sum past 4 GiB would have those
// offsets wrap, and the run would read the wrong bytes rather than fail, so it is refused instead. No
// table anyone writes by hand comes near it; a generated one could.

static bool table_pool_build (table_t *tb, char *err_buf, const size_t err_size)
{
  if (tb->varlen == true)
  {
    u64 idx_cnt = 1;

    for (u32 i = 0; i < tb->bucket_cnt; i++) idx_cnt += tb->bucket[i].ent_cnt + 1;

    u64 bytes = 0;

    for (u32 i = 0; i < tb->bucket_cnt; i++)
    {
      const table_bucket_t *b = &tb->bucket[i];

      for (u32 j = 0; j < b->ent_cnt; j++) bytes += b->ent[j].len;
    }

    if ((tb->pool_cnt = idx_cnt + ((bytes + 3) / 4)) > (0xffffffffULL / 4))
    {
      table_err (err_buf, err_size, "the table needs a pool of %" PRIu64 " bytes and an offset into it is a 32 bit number, so it cannot be addressed", tb->pool_cnt * 4);

      return false;
    }

    tb->pool = table_pool_alloc (tb->pool_cnt);

    if (tb->pool == NULL)
    {
      table_err (err_buf, err_size, "the table needs a pool of %" PRIu64 " bytes and the host has none to give", tb->pool_cnt * 4);

      return false;
    }

    u8 *pb = (u8 *) tb->pool;

    u64 at  = idx_cnt * 4;
    u64 idx = 1;

    for (u32 i = 0; i < tb->bucket_cnt; i++)
    {
      table_bucket_t *b = &tb->bucket[i];

      b->pool_off = (u32) idx;
      b->ent_len  = 0;

      for (u32 j = 0; j < b->ent_cnt; j++)
      {
        tb->pool[idx] = (u32) at;

        idx++;

        for (u32 k = 0; k < b->ent[j].len; k++) pb[at + k] = tb->arena[b->ent[j].off + k];

        at += b->ent[j].len;
      }

      tb->pool[idx] = (u32) at;

      idx++;
    }

    return true;
  }

  // Word zero is left out so that a pool_off of zero is never a real bucket.

  u64 at = 4;

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    table_bucket_t *b = &tb->bucket[i];

    b->ent_len  = b->ent[0].len;
    b->pool_off = (u32) at;

    at += (u64) b->ent_cnt * b->ent_len;
  }

  if (at > 0xffffffffULL)
  {
    table_err (err_buf, err_size, "the table needs a pool of %" PRIu64 " bytes and an offset into it is a 32 bit number, so it cannot be addressed", at);

    return false;
  }

  tb->pool_cnt = (at + 3) / 4;
  tb->pool     = table_pool_alloc (tb->pool_cnt);

  if (tb->pool == NULL)
  {
    table_err (err_buf, err_size, "the table needs a pool of %" PRIu64 " bytes and the host has none to give", tb->pool_cnt * 4);

    return false;
  }

  u8 *pb = (u8 *) tb->pool;

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    const table_bucket_t *b = &tb->bucket[i];

    for (u32 j = 0; j < b->ent_cnt; j++)
    {
      const u64 dst = b->pool_off + ((u64) j * b->ent_len);

      for (u32 k = 0; k < b->ent_len; k++) pb[dst + k] = tb->arena[b->ent[j].off + k];
    }
  }

  return true;
}

// A blank line is skipped and a # in the first column is a comment. Every other line is taken only
// when it holds exactly one tab, so a line of prose and a line whose trailing tab an editor stripped
// are both passed over rather than read as a rule.

// One table file read into the set. Several of them are read into the same one, so a source named by
// more than one table ends up with the union of what they say about it, in the order the tables were
// given and with exact repeats dropped. That is what lets a leetspeak table and a case table be
// combined on the command line rather than shipped pre-merged.

static bool table_read (table_t *tb, const char *path, char *err_buf, const size_t err_size)
{
  u64 len = 0;

  u8 *buf = table_slurp (path, &len, err_buf, err_size);

  if (buf == NULL) return false;

  u64 pos  = 0;
  u64 line = 0;

  while (pos < len)
  {
    line++;

    u64 end = pos;

    while ((end < len) && (buf[end] != '\n')) end++;

    u64 stop = end;

    if ((stop > pos) && (buf[stop - 1] == '\r')) stop--;

    const u64 next = end + 1;

    if (stop == pos)
    {
      pos = next;

      continue;
    }

    if (buf[pos] == '#')
    {
      pos = next;

      continue;
    }

    u64 tab = 0;
    u64 at  = 0;

    for (u64 i = pos; i < stop; i++)
    {
      if (buf[i] != '\t') continue;

      tab++;
      at = i;
    }

    if (tab != 1)
    {
      pos = next;

      continue;
    }

    u8 src[TABLE_SRC_MAX];
    u8 ent[TABLE_ENT_MAX];

    const int src_len = table_decode (&buf[pos],     (u32) (at - pos),      src, TABLE_SRC_MAX);
    const int ent_len = table_decode (&buf[at + 1],  (u32) (stop - at - 1), ent, TABLE_ENT_MAX);

    if (src_len < 0)
    {
      table_err (err_buf, err_size, "%s: line %" PRIu64 ": source longer than %d bytes", path, line, TABLE_SRC_MAX);

      hcfree (buf);

      return false;
    }

    if (ent_len < 0)
    {
      table_err (err_buf, err_size, "%s: line %" PRIu64 ": replacement longer than %d bytes", path, line, TABLE_ENT_MAX);

      hcfree (buf);

      return false;
    }

    // A source of no bytes matches nowhere, so the line says nothing.

    if (src_len == 0)
    {
      pos = next;

      continue;
    }

    u32 idx = table_bucket_find (tb, src, (u32) src_len);

    if (idx == TABLE_TOK_LITERAL) idx = table_bucket_add (tb, src, (u32) src_len);

    table_ent_add (tb, idx, ent, (u32) ent_len);

    pos = next;
  }

  hcfree (buf);
  return true;
}

// Order is part of it. Two tables holding the same rules in a different order are the same set of
// candidates in a different sequence, and a keyspace index describes a sequence.

static void table_ident (table_t *tb)
{
  paw64_ctx_t state;

  paw64_init (&state, 0);

  const u32 identity = (tb->identity == true) ? 1 : 0;

  paw64_update (&state, &identity, sizeof (identity));
  paw64_update (&state, &tb->bucket_cnt, sizeof (tb->bucket_cnt));

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    const table_bucket_t *b = &tb->bucket[i];

    paw64_update (&state, &b->src_len, sizeof (b->src_len));
    paw64_update (&state, &tb->arena[b->src_off], b->src_len);
    paw64_update (&state, &b->ent_cnt, sizeof (b->ent_cnt));

    for (u32 j = 0; j < b->ent_cnt; j++)
    {
      paw64_update (&state, &b->ent[j].len, sizeof (b->ent[j].len));
      paw64_update (&state, &tb->arena[b->ent[j].off], b->ent[j].len);
    }
  }

  tb->ident = paw64_final (&state);
}

bool table_load (table_t *tb, char * const *paths, const int paths_cnt, const bool identity, char *err_buf, const size_t err_size)
{
  memset (tb, 0, sizeof (table_t));

  tb->identity = identity;

  for (int i = 0; i < paths_cnt; i++)
  {
    if (table_read (tb, paths[i], err_buf, err_size) == false)
    {
      table_free (tb);

      return false;
    }
  }


  if (tb->bucket_cnt == 0)
  {
    table_err (err_buf, err_size, "no rules in any table given, and a table line is a source and a replacement with one tab between them");

    return false;
  }

  for (u32 i = 0; i < tb->bucket_cnt; i++)
  {
    const table_bucket_t *b = &tb->bucket[i];

    tb->src_max = MAX (tb->src_max, b->src_len);

    // Whether an entry is the length of what it replaces, which is what lets the candidate keep the
    // base word's layout and the literal runs stay where they are.
    //
    // Comparing entries against each other is not the same test and was wrong. It only looked right
    // because the source is normally an entry of its own bucket, so a bucket of one length was a
    // bucket of the source's length. With identity off it is not: a keyboard map gives every bucket a
    // single two byte entry against a one byte source, every bucket agrees with itself, and the
    // candidate is still not the base word's shape.

    tb->bucket[i].ent_min = 0xffffffff;

    for (u32 j = 0; j < b->ent_cnt; j++)
    {
      tb->bucket[i].ent_min = MIN (tb->bucket[i].ent_min, b->ent[j].len);
      tb->bucket[i].ent_max = MAX (tb->bucket[i].ent_max, b->ent[j].len);

      if (b->ent[j].len != b->src_len) tb->varlen = true;
    }

    if (b->ent_cnt == 0) tb->bucket[i].ent_min = 0;
  }

  table_index_build (tb);

  if (table_pool_build (tb, err_buf, err_size) == false)
  {
    table_free (tb);

    return false;
  }

  table_ident (tb);

  return true;
}

void table_free (table_t *tb)
{
  for (u32 i = 0; i < tb->bucket_cnt; i++) hcfree (tb->bucket[i].ent);

  for (u32 i = 0; i < 256; i++) hcfree (tb->first[i]);

  hcfree (tb->bucket);
  hcfree (tb->arena);

  hc_free_aligned ((void **) &tb->pool);

  memset (tb, 0, sizeof (table_t));
}

// Reading the table over a word. Every position takes the longest source that matches there, bytes no
// source matches gather into a literal run, and the run is closed as soon as a source does match.

int table_tokenize (const table_t *tb, const u8 *word, const u32 word_len, table_tok_t *tok, const u32 tok_max)
{
  u32 cnt = 0;
  u32 lit = 0;

  bool in_lit = false;

  u32 i = 0;

  while (i < word_len)
  {
    const u32 c = word[i];

    u32 hit = TABLE_TOK_LITERAL;

    for (u32 n = 0; n < tb->first_cnt[c]; n++)
    {
      const u32 idx = tb->first[c][n];
      const u32 len = tb->bucket[idx].src_len;

      if ((i + len) > word_len) continue;

      if (table_span_eq (tb, tb->bucket[idx].src_off, len, &word[i], len) == false) continue;

      hit = idx;

      break;
    }

    if (hit == TABLE_TOK_LITERAL)
    {
      if (in_lit == false)
      {
        lit    = i;
        in_lit = true;
      }

      i++;

      continue;
    }

    if (in_lit == true)
    {
      if (cnt == tok_max) return -1;

      tok[cnt].off    = lit;
      tok[cnt].len    = i - lit;
      tok[cnt].bucket = TABLE_TOK_LITERAL;

      cnt++;

      in_lit = false;
    }

    if (cnt == tok_max) return -1;

    tok[cnt].off    = i;
    tok[cnt].len    = tb->bucket[hit].src_len;
    tok[cnt].bucket = hit;

    cnt++;

    i += tb->bucket[hit].src_len;
  }

  if (in_lit == true)
  {
    if (cnt == tok_max) return -1;

    tok[cnt].off    = lit;
    tok[cnt].len    = word_len - lit;
    tok[cnt].bucket = TABLE_TOK_LITERAL;

    cnt++;
  }

  return (int) cnt;
}

// What a word is worth, which is the product of the radices the tokenizer found in it. Saturates
// rather than wrapping, because a word that reaches the top of a u64 is one the caller has to refuse
// and a wrapped product would look small.

u64 table_rect (const table_t *tb, const table_tok_t *tok, const u32 tok_cnt)
{
  u64 rect = 1;

  for (u32 i = 0; i < tok_cnt; i++)
  {
    if (tok[i].bucket == TABLE_TOK_LITERAL) continue;

    const u64 radix = tb->bucket[tok[i].bucket].ent_cnt;

    if (rect > (0xffffffffffffffffULL / radix)) return 0xffffffffffffffffULL;

    rect *= radix;
  }

  return rect;
}

/**
 * interface
 */

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// AUTOHEX is off on purpose. hashcat would apply it to what this feed returns, which is a candidate
// the table has already been read over, and a $HEX[] line of the wordlist has to be decoded before
// that rather than after. The feed decodes it itself, below.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_ICONV
                                 | GENERIC_PLUGIN_OPTIONS_RULES
                                 | GENERIC_PLUGIN_OPTIONS_DEVICE;

// How wide the inner loop may be, as a power of two. A cell never reaches further than this, and the
// host enumerates whatever is left over, so it trades base words the CPU must produce against work
// items the card must find room for.

#define TABLE_KBITS_DEF 20
#define TABLE_KBITS_MAX 31

// How much of the first wordlist is read to work out what a cell is worth on average. The answer
// only sizes launches and scales the status line, so a sample is enough and a pass over the file is
// not worth its seconds.

#define TABLE_SAMPLE_BYTES (64 * 1024)

// and how many places it is read from. A wordlist is very often ordered, by length or by how likely a
// word is, so reading only the front of one describes the front and not the file. Spreading the reads
// costs a seek each and is the difference between sizing a launch for the wordlist and sizing it for
// whatever happens to sort first.

#define TABLE_SAMPLE_CHUNKS 16

// How many lines one entry of the keyspace index stands for. A seek reads the entry in front of its
// target and walks from there, so this is how many words a seek may have to walk over, against eight
// bytes of memory for every step of it.

#define TABLE_INDEX_STEP 1024

// and how many entries it may come to before the step is widened, which holds the index to 8 MiB
// however long the wordlist is.

#define TABLE_INDEX_MAX (1024 * 1024)

// The most candidates one word of the wordlist may be worth.
//
// A word is worth the product of its radices, so what it costs grows exponentially with its length
// while what it is likely to be worth does not. On a million real passwords with a full leet and case
// table, the words of 16 characters and under come to 367 million base words and the whole file comes
// to 2.9e17: the 5.7 percent that are longer carry all but a billionth of the run, and the attack
// never leaves the first few of them it meets.
//
// So a word gets a budget. What the budget buys is described at table_front_plan ().

#define TABLE_MAXPERM_DEF (1024 * 1024)

// How many substitutions a candidate may make outside the part the graphics card enumerates. It is
// what the budget is spent on, and every step of it costs another row of the table below.

#define TABLE_WMAX 8

// Where the run is, in units, at every TABLE_INDEX_STEP'th line. What a word is worth depends on the
// word and on the table, so this cannot be worked out from a line number the way an ordinary wordlist
// attack can, and a seek would otherwise read the whole wordlist to find out.

typedef struct table_index
{
  u64 *cum;
  u64  cnt;
  u64  step;

  u64  units;
  u64  total;

} table_index_t;

typedef struct table_global
{
  feed_global_t wl;

  table_t tb;

  // kept for feed_say (), which is the only place a feed says anything and needs it

  hashcat_ctx_t *hcctx;

  u32 il_cnt;
  u32 maxword;

  u64 maxperm;

  // Whether a word the table had nothing to say about is a candidate. Off, it is: the word comes out
  // as it went in, which is what a table that varies a word wants. On, it is worth nothing and the
  // wordlist is read as a set of patterns rather than as a list of passwords, so only the words the
  // table reaches produce anything at all.

  bool template;

  // The lengths this hash mode accepts. A candidate outside them is built, copied over and thrown
  // away again, so a word that cannot land inside them is work with no possible outcome. pwmax 0
  // means the run never said, and then nothing is filtered.

  u32 pwmin;
  u32 pwmax;

  // how many words those bounds took out, and how many the table never reached, for the lines this
  // says on startup

  u64 outside;
  u64 unmatched;

  bool dev;

  // the widest a word wanted to be before the budget was applied, and how many were held back, both
  // for the line this says on startup

  u64 widest;
  u64 capped;

  // What global_dev_init () worked out, kept rather than said. It runs before the wordlist is counted
  // and the counting prints a block of its own, so saying it there splits what this feed has to say
  // in two and puts somebody else's lines between the halves.

  u32 dev_mean;

  table_index_t idx;

} table_global_t;

// A word in hand, what the tokenizer made of it, and where the odometer has got to inside it.
//
// var holds the tokens that actually vary, because those are the only ones that carry a digit and,
// on the device, the only ones that become a slot. A literal run never does either: with entries the
// same length as their sources the candidate has the base word's own layout, so a literal is already
// in place and the cell writes over the rest.
//
// nfront is how many of them this side enumerates. It is all of them for the host engine, and it is
// what the cell did not take for the device engine.

typedef struct table_thread
{
  feed_thread_t *wl;

  u8  word[PW_MAX];
  u32 word_len;

  table_tok_t tok[PW_MAX];
  u32         tok_cnt;

  u32 var[PW_MAX];
  u32 var_cnt;

  u32 digit[PW_MAX];

  // The first token the cell covers. Everything in front of it is written into the base word here,
  // and everything from it on is the cell's.

  u32 dev_tok;

  u32 nfront;
  u64 cell_rect;

  // How many substitutions the front may make, and how much each weight up to it is worth. dp[i][w] is
  // what the front positions from i on are worth at exactly w substitutions, which is what turns a
  // position in the run into a set of positions to change.

  u32 wmax;

  // How many base words the front comes to. On the device engine that is what a unit is; on the host
  // engine a unit is a candidate and there are cell_rect of them to each.

  u64 front_units;

  // what the front wanted before the budget, which is what the startup line reports

  u64 front_full;

  // Why this word is worth nothing, when it is. The two reasons are counted apart because they are
  // different things to tell somebody: one is a table that never reached the word, the other is a
  // hash mode that would not take any candidate the word makes.

  bool unmatched;

  u64 dp[PW_MAX + 1][TABLE_WMAX + 1];

  u64 rect;
  u64 at;

  // Where the next unit sits in the whole run, which is what makes a seek forward able to carry on
  // from here instead of counting from the first word again. A unit is a candidate for the host
  // engine and a base word for the device engine.

  u64 pos;

} table_thread_t;

static u32 table_radix (const table_t *tb, const table_tok_t *tok)
{
  const u32 radix = tb->bucket[tok->bucket].ent_cnt;

  return radix;
}

// Reading an entry out of the pool with the arithmetic the kernel uses, so that the host engine and
// the device engine cannot drift apart on what an entry is. Both shapes are here: pool_off is the
// byte offset of the first entry when every entry of the bucket is the same length, and the index of
// the bucket's offset table when they are not. A length changing table reaches the device too, which
// is what the copy slot kind is for.

static const u8 *table_ent (const table_t *tb, const u32 bucket, const u32 d, u32 *ent_len)
{
  const u8 *pb = (const u8 *) tb->pool;

  const table_bucket_t *b = &tb->bucket[bucket];

  if (tb->varlen == true)
  {
    const u32 off = tb->pool[b->pool_off + d];

    ent_len[0] = tb->pool[b->pool_off + d + 1] - off;

    return &pb[off];
  }

  ent_len[0] = b->ent_len;

  return &pb[b->pool_off + (d * b->ent_len)];
}

// The whole candidate, which is what the host engine hands over.

// A table that lengthens can make a candidate longer than hashcat takes, and only the host engine can
// reach one: the device split refuses a word whose widest form passes the kernel's buffer. What is
// written stops at the buffer, and what is returned is the length the candidate really has, because
// hashcat rejects an over-length candidate and handing it a clipped one would hash a password the
// table never described. It is the same contract process_word () keeps for an over-length line.

static u32 table_write (const table_t *tb, const table_thread_t *tt, u8 *out_buf, const u32 out_size)
{
  u32 len = 0;
  u32 v   = 0;

  for (u32 i = 0; i < tt->tok_cnt; i++)
  {
    if (tt->tok[i].bucket == TABLE_TOK_LITERAL)
    {
      for (u32 k = 0; k < tt->tok[i].len; k++)
      {
        if (len < out_size) out_buf[len] = tt->word[tt->tok[i].off + k];

        len++;
      }

      continue;
    }

    u32 ent_len = 0;

    const u8 *ent = table_ent (tb, tt->tok[i].bucket, tt->digit[v], &ent_len);

    v++;

    for (u32 k = 0; k < ent_len; k++)
    {
      if (len < out_size) out_buf[len] = ent[k];

      len++;
    }
  }

  return len;
}

// The base word the device engine starts from: the word with the substitutions this side enumerates
// already written into it, and everything the cell has not been given left as it was.
//
// With entries the length of what they replace this is the word's own bytes with some overwritten in
// place. Otherwise it is built token by token, because a substitution in front moves everything behind
// it, and the tail is copied over unchanged for the cell's copy slots to read back out.

static u32 table_write_base (const table_t *tb, const table_thread_t *tt, u8 *out_buf, const u32 out_size)
{
  if (tb->varlen == false)
  {
    // What is written stops at the buffer and what is returned is the length the base word really
    // has, the same contract table_write () keeps. hashcat rejects a base word past PW_MAX, and
    // reporting the clipped length instead would have it hash a truncation of a candidate the table
    // never described.

    const u32 len = tt->word_len;

    const u32 fit = MIN (len, out_size);

    for (u32 k = 0; k < fit; k++) out_buf[k] = tt->word[k];

    for (u32 v = 0; v < tt->nfront; v++)
    {
      const table_tok_t *tok = &tt->tok[tt->var[v]];

      u32 ent_len = 0;

      const u8 *ent = table_ent (tb, tok->bucket, tt->digit[v], &ent_len);

      for (u32 k = 0; k < ent_len; k++)
      {
        if ((tok->off + k) >= fit) break;

        out_buf[tok->off + k] = ent[k];
      }
    }

    return len;
  }

  u32 len = 0;
  u32 v   = 0;

  for (u32 i = 0; i < tt->tok_cnt; i++)
  {
    const table_tok_t *tok = &tt->tok[i];

    const bool lit = (tok->bucket == TABLE_TOK_LITERAL);

    // In front of the cell a substitution is written out. From the cell on the word's own bytes are,
    // because that is what a copy slot reads back and what a substitution slot writes over.

    if ((lit == false) && (i < tt->dev_tok))
    {
      u32 ent_len = 0;

      const u8 *ent = table_ent (tb, tok->bucket, tt->digit[v], &ent_len);

      v++;

      for (u32 k = 0; k < ent_len; k++)
      {
        if (len < out_size) out_buf[len] = ent[k];

        len++;
      }

      continue;
    }

    if (lit == false) v++;

    for (u32 k = 0; k < tok->len; k++)
    {
      if (len < out_size) out_buf[len] = tt->word[tok->off + k];

      len++;
    }
  }

  return len;
}

// Where the cell starts writing, in the base word this side has just built.

static u32 table_base_head (const table_t *tb, const table_thread_t *tt)
{
  if (tb->varlen == false)
  {
    const u32 off = (tt->dev_tok < tt->tok_cnt) ? tt->tok[tt->dev_tok].off : tt->word_len;

    return off;
  }

  u32 len = 0;
  u32 v   = 0;

  for (u32 i = 0; i < tt->dev_tok; i++)
  {
    const table_tok_t *tok = &tt->tok[i];

    if (tok->bucket == TABLE_TOK_LITERAL)
    {
      len += tok->len;

      continue;
    }

    u32 ent_len = 0;

    table_ent (tb, tok->bucket, tt->digit[v], &ent_len);

    v++;

    len += ent_len;
  }

  return len;
}

// The cell. With entries the length of what they replace it is the variable tokens the host did not
// take, each writing over the bytes its own token had in the base word. Otherwise it is every token
// from the cut on, a substitution reading the pool and a literal run copying itself back out of the
// base word, with the write offsets a running sum the odometer keeps.

static void table_cell (const table_t *tb, const table_thread_t *tt, pcfg_cell_t *cell)
{
  memset (cell, 0, sizeof (pcfg_cell_t));

  cell->rect = (u32) tt->cell_rect;

  if (tb->varlen == false)
  {
    cell->slot_cnt = tt->var_cnt - tt->nfront;
    cell->flags    = 0;

    for (u32 j = 0; j < cell->slot_cnt; j++)
    {
      const table_tok_t *tok = &tt->tok[tt->var[tt->nfront + j]];

      const table_bucket_t *b = &tb->bucket[tok->bucket];

      cell->slots[j].pool_off = b->pool_off;
      cell->slots[j].radix    = b->ent_cnt;
      cell->slots[j].digit    = 0;
      cell->slots[j].packed   = (b->ent_len & 0xff) | ((tok->off & 0xff) << 8) | (PCFG_SLOT_KIND_BYTES << 16) | ((j & 0xff) << 24);
    }

    return;
  }

  cell->slot_cnt = tt->tok_cnt - tt->dev_tok;
  cell->flags    = PCFG_CELL_VARLEN;

  u32 at = table_base_head (tb, tt);

  for (u32 j = 0; j < cell->slot_cnt; j++)
  {
    const table_tok_t *tok = &tt->tok[tt->dev_tok + j];

    // Only the first slot's offset is read, because every other one is the running sum.

    const u32 off = (j == 0) ? at : 0;

    if (tok->bucket == TABLE_TOK_LITERAL)
    {
      cell->slots[j].pool_off = at;
      cell->slots[j].radix    = 1;
      cell->slots[j].digit    = 0;
      cell->slots[j].packed   = (tok->len & 0xff) | ((off & 0xff) << 8) | (PCFG_SLOT_KIND_COPY << 16) | ((j & 0xff) << 24);
    }
    else
    {
      const table_bucket_t *b = &tb->bucket[tok->bucket];

      cell->slots[j].pool_off = b->pool_off;
      cell->slots[j].radix    = b->ent_cnt;
      cell->slots[j].digit    = 0;
      cell->slots[j].packed   = ((off & 0xff) << 8) | (PCFG_SLOT_KIND_BYTES << 16) | ((j & 0xff) << 24);
    }

    at += tok->len;
  }
}

#define TABLE_WFULL 0xffffffff

static u64 table_sat_mul (const u64 a, const u64 b)
{
  if (a == 0) return 0;
  if (a > (0xffffffffffffffffULL / b)) return 0xffffffffffffffffULL;

  const u64 r = a * b;

  return r;
}

static u64 table_sat_add (const u64 a, const u64 b)
{
  if ((0xffffffffffffffffULL - a) < b) return 0xffffffffffffffffULL;

  const u64 r = a + b;

  return r;
}

// What the front of a word is allowed to do.
//
// The card enumerates the last few substitutable positions in full and the host enumerates everything
// in front of them, and that front is where a long word explodes: another letter is another factor,
// without end. A budget stops it, and the whole question is what the budget buys.
//
// Taking the first so many base words of the front's own odometer is the obvious answer and the wrong
// one. That odometer turns its last digit fastest, so what it gives up is the beginning of the word:
// truncate it and administrator1234 is never spelled with a 4 at the front, however much budget is
// left. It is not that too little is kept, it is that the wrong part is.
//
// So the budget is spent on how many substitutions the front makes rather than on where they are. The
// word itself first, then every candidate that changes one letter of the front, then every one that
// changes two, as far as the budget reaches. Every position is reachable at every weight, and the
// candidates dropped are the ones that change a great many letters at once, which is not what people
// type.
//
// A word whose front fits the budget outright keeps its full cross product and none of this applies.
//
// dp[i][w] is what the positions from i on are worth at exactly w substitutions. It is what makes the
// count exact and what a seek walks to turn a position back into a set of letters to change.

static void table_front_plan (const table_global_t *tg, table_thread_t *tt)
{
  u64 full = 1;

  for (u32 v = 0; v < tt->nfront; v++)
  {
    full = table_sat_mul (full, table_radix (&tg->tb, &tt->tok[tt->var[v]]));
  }

  tt->front_full = full;

  const u64 cell = (tt->cell_rect > 0) ? tt->cell_rect : 1;

  if (tg->maxperm == 0)
  {
    tt->wmax        = TABLE_WFULL;
    tt->front_units = full;

    return;
  }

  u64 budget = tg->maxperm / cell;

  if (budget == 0) budget = 1;

  if (full <= budget)
  {
    tt->wmax        = TABLE_WFULL;
    tt->front_units = full;

    return;
  }

  const u32 nf = tt->nfront;

  for (u32 w = 0; w <= TABLE_WMAX; w++) tt->dp[nf][w] = 0;

  tt->dp[nf][0] = 1;

  for (int i = (int) nf - 1; i >= 0; i--)
  {
    const u64 less = table_radix (&tg->tb, &tt->tok[tt->var[i]]) - 1;

    tt->dp[i][0] = 1;

    for (u32 w = 1; w <= TABLE_WMAX; w++)
    {
      tt->dp[i][w] = table_sat_add (tt->dp[i + 1][w], table_sat_mul (less, tt->dp[i + 1][w - 1]));
    }
  }

  u64 sum = 1;

  u32 wmax = 0;

  for (u32 w = 1; w <= TABLE_WMAX; w++)
  {
    const u64 next = table_sat_add (sum, tt->dp[0][w]);

    if (next > budget) break;

    sum  = next;
    wmax = w;
  }

  tt->wmax        = wmax;
  tt->front_units = sum;
}

// Turning a position in the front back into the letters it changes.

static void table_front_unrank (const table_global_t *tg, table_thread_t *tt, const u64 pos)
{
  tt->at = pos;

  if (tt->wmax == TABLE_WFULL)
  {
    u64 carry = pos;

    for (int v = (int) tt->nfront - 1; v >= 0; v--)
    {
      const u64 radix = table_radix (&tg->tb, &tt->tok[tt->var[v]]);

      tt->digit[v] = (u32) (carry % radix);

      carry /= radix;
    }

    return;
  }

  for (u32 v = 0; v < tt->nfront; v++) tt->digit[v] = 0;

  u64 rem = pos;

  u32 need = 0;

  while (need <= tt->wmax)
  {
    if (rem < tt->dp[0][need]) break;

    rem -= tt->dp[0][need];

    need++;
  }

  // Past the end of the plan, which a caller that respects rect never asks for.

  if (need > tt->wmax) return;

  u32 i = 0;

  while ((need > 0) && (i < tt->nfront))
  {
    const u64 per  = tt->dp[i + 1][need - 1];
    const u64 less = table_radix (&tg->tb, &tt->tok[tt->var[i]]) - 1;
    const u64 with = table_sat_mul (less, per);

    if ((per > 0) && (rem < with))
    {
      tt->digit[i] = 1 + (u32) (rem / per);

      rem = rem % per;

      need--;
    }
    else
    {
      rem -= with;
    }

    i++;
  }
}

// How the word is divided between the two engines.
//
// With entries the length of what they replace, the candidate keeps the base word's layout: a literal
// run is already in place and only the substitutions need a slot. With entries of any length every
// byte behind a substitution moves, so the cell writes the whole tail and a literal run costs a slot
// of its own.
//
// Either way the cell takes the longest suffix it can: no more than a cell has slots, no further than
// the inner loop reaches, and no longer than the kernel's candidate buffer.

// The shortest and longest this word can come out, which is every token at its shortest and at its
// longest. For a table whose entries are the length of what they replace the two are the same number
// and the test below is exact, so such a run rejects nothing at all.

static void table_span (const table_global_t *tg, const table_thread_t *tt, u32 *lo, u32 *hi)
{
  u32 a = 0;
  u32 b = 0;

  for (u32 i = 0; i < tt->tok_cnt; i++)
  {
    const table_tok_t *tok = &tt->tok[i];

    if (tok->bucket == TABLE_TOK_LITERAL)
    {
      a += tok->len;
      b += tok->len;

      continue;
    }

    a += tg->tb.bucket[tok->bucket].ent_min;
    b += tg->tb.bucket[tok->bucket].ent_max;
  }

  lo[0] = a;
  hi[0] = b;
}

static void table_split (const table_global_t *tg, table_thread_t *tt)
{
  const u32 maxbyte = (tg->maxword * 4) - 1;

  // The longest this word could ever come out. Past the kernel's candidate buffer it stops expanding
  // a cell and hashes the base word alone, so a word that could reach there is enumerated here in
  // full instead and every base word it makes is a finished candidate. That is the one case where the
  // card is handed no work, and it is a word longer than a password.

  u64 wide = 0;

  // And the longest the base word could come out, which is not the same number. A cell that copies
  // runs of the base word reads the word's own bytes from the cell onward, so the base word carries
  // the source text of every token the card handles rather than its replacement. Where a replacement
  // is shorter than what it replaces, and identity=0 with a keyboard layout is exactly that, the base
  // word is longer than any candidate built from it. Bounding only the candidate would let a base
  // word past the kernel's buffer, and the kernel answers that by dropping the cell and hashing the
  // base word, which is not a candidate of this attack.
  //
  // Each token contributes its replacement or its source depending on which side of the split it
  // lands, and the split is not chosen yet, so the larger of the two is counted for each.

  u64 basewide = 0;
  u64 basemin  = 0;

  for (u32 i = 0; i < tt->tok_cnt; i++)
  {
    const table_tok_t *tok = &tt->tok[i];

    if (tok->bucket == TABLE_TOK_LITERAL)
    {
      wide     += tok->len;
      basewide += tok->len;
      basemin  += tok->len;

      continue;
    }

    const u32 ent_max = tg->tb.bucket[tok->bucket].ent_max;
    const u32 ent_min = tg->tb.bucket[tok->bucket].ent_min;

    wide     += ent_max;
    basewide += MAX (ent_max, tok->len);
    basemin  += MIN (ent_min, tok->len);
  }

  // The card is handed the base word and hashcat judges that against the hash mode's shortest
  // password before the cell is ever expanded, so a base word under it takes every candidate of its
  // cell with it however long those candidates are. A table that shortens what it replaces can do
  // that: the base word carries the source text and the candidates are longer than it. Such a word is
  // enumerated in full on the host instead, where each candidate is judged on its own length.

  u64 rect = 1;

  if ((wide > maxbyte) || (basewide > maxbyte) || (basemin < tg->pwmin))
  {
    tt->nfront  = tt->var_cnt;
    tt->dev_tok = tt->tok_cnt;
  }
  else if (tg->tb.varlen == false)
  {
    u32 seen = 0;

    while (seen < tt->var_cnt)
    {
      if (seen == PCFG_DEV_MAXSLOT) break;

      const u64 radix = table_radix (&tg->tb, &tt->tok[tt->var[tt->var_cnt - 1 - seen]]);

      if ((rect * radix) > tg->il_cnt) break;

      rect *= radix;

      seen++;
    }

    tt->nfront  = tt->var_cnt - seen;
    tt->dev_tok = (seen == 0) ? tt->tok_cnt : tt->var[tt->var_cnt - seen];
  }
  else
  {
    // How long the tail could get, counted back from the end. The kernel carries a slot's write offset
    // in a byte, so a tail that could outgrow that is not one this cell may take.

    u32 k     = 0;
    u32 grown = 0;

    while (k < tt->tok_cnt)
    {
      if (k == PCFG_DEV_MAXSLOT) break;

      const table_tok_t *tok = &tt->tok[tt->tok_cnt - 1 - k];

      const bool lit = (tok->bucket == TABLE_TOK_LITERAL);

      const u64 radix = (lit == true) ? 1 : table_radix (&tg->tb, tok);
      const u32 wide  = (lit == true) ? tok->len : tg->tb.bucket[tok->bucket].ent_max;

      if ((rect * radix) > tg->il_cnt) break;
      if ((grown + wide) > maxbyte) break;

      rect  *= radix;
      grown += wide;

      k++;
    }

    tt->dev_tok = tt->tok_cnt - k;

    tt->nfront = 0;

    for (u32 v = 0; v < tt->var_cnt; v++)
    {
      if (tt->var[v] >= tt->dev_tok) break;

      tt->nfront++;
    }

    // A cell of nothing but literal runs reaches one candidate and spends slots doing it, so the word
    // is better handed over whole.

    if (rect == 1)
    {
      tt->dev_tok = tt->tok_cnt;
      tt->nfront  = tt->var_cnt;
    }
  }

  tt->cell_rect = rect;

  table_front_plan (tg, tt);

  // A unit is a base word where the card expands one and a candidate where it does not, and the split
  // above is the same either way, so the two engines walk the same candidates in the same order.

  tt->rect = (tg->dev == true) ? tt->front_units : table_sat_mul (tt->front_units, tt->cell_rect);
  tt->at   = 0;

  // A word no rule in the table matched is worth nothing under template=1. Every token of it is a
  // literal run, so the only candidate it could make is the word itself, and somebody reading a
  // wordlist as a set of patterns wants the patterns the table fills in rather than the wordlist back.

  tt->unmatched = ((tg->template == true) && (tt->var_cnt == 0));

  if (tt->unmatched == true) tt->rect = 0;

  // A word none of whose candidates the hash mode would accept is worth nothing, and a word worth
  // nothing is stepped over by the same loop that steps over an exhausted one. The keyspace counts
  // what it counts here, so the run never builds them and never has them thrown back.

  if (tg->pwmax > 0)
  {
    u32 lo = 0;
    u32 hi = 0;

    table_span (tg, tt, &lo, &hi);

    if ((hi < tg->pwmin) || (lo > tg->pwmax)) tt->rect = 0;
  }

  for (u32 v = 0; v < tt->var_cnt; v++) tt->digit[v] = 0;
}

// One step of whichever odometer this engine is walking. On the host that is the cell's digits inside
// the front's, because a unit there is a candidate rather than a base word.

static void table_step (const table_global_t *tg, table_thread_t *tt)
{
  if (tg->dev == false)
  {
    bool carry = true;

    for (int v = (int) tt->var_cnt - 1; v >= (int) tt->nfront; v--)
    {
      tt->digit[v]++;

      if (tt->digit[v] < table_radix (&tg->tb, &tt->tok[tt->var[v]]))
      {
        carry = false;

        break;
      }

      tt->digit[v] = 0;
    }

    const u64 at = tt->at + 1;

    if (carry == true) table_front_unrank (tg, tt, at / tt->cell_rect);

    tt->at = at;

    return;
  }

  if (tt->wmax == TABLE_WFULL)
  {
    for (int v = (int) tt->nfront - 1; v >= 0; v--)
    {
      tt->digit[v]++;

      if (tt->digit[v] < table_radix (&tg->tb, &tt->tok[tt->var[v]])) break;

      tt->digit[v] = 0;
    }

    tt->at++;

    return;
  }

  table_front_unrank (tg, tt, tt->at + 1);
}

// Landing on one unit of a word without walking the ones in front of it.

static void table_unrank (const table_global_t *tg, table_thread_t *tt, const u64 pos)
{
  if (tg->dev == true)
  {
    table_front_unrank (tg, tt, pos);

    return;
  }

  table_front_unrank (tg, tt, pos / tt->cell_rect);

  u64 carry = pos % tt->cell_rect;

  for (int v = (int) tt->var_cnt - 1; v >= (int) tt->nfront; v--)
  {
    const u64 radix = table_radix (&tg->tb, &tt->tok[tt->var[v]]);

    tt->digit[v] = (u32) (carry % radix);

    carry /= radix;
  }

  tt->at = pos;
}

// Reading the table over one word. Everything a word is worth on either side follows from this, so
// the sampler below runs it too rather than estimating.

static bool table_take (const table_global_t *tg, table_thread_t *tt, const u8 *word, const u32 word_len)
{
  // A line longer than PW_MAX arrives as a length with nothing behind it. wordlist_next () writes at
  // most as many bytes as it was given room for and still reports what it read, deliberately, so that
  // hashcat can reject an over-length word rather than be handed a truncated one that is not in the
  // wordlist. Copying by that length would read past the caller's buffer and write past this one.
  //
  // Such a word is worth nothing here. Every candidate it could make is at least as long as the parts
  // of it the table leaves alone, so none of them fits either, which is the same answer the hash
  // mode's length window gives and is stepped over by the same loop.

  if (word_len > PW_MAX)
  {
    tt->word_len   = 0;
    tt->tok_cnt    = 0;
    tt->var_cnt    = 0;
    tt->nfront     = 0;
    tt->cell_rect  = 1;
    tt->front_units = 0;
    tt->front_full = 0;
    tt->wmax       = TABLE_WFULL;
    tt->rect       = 0;
    tt->at         = 0;

    return true;
  }

  u32 len = word_len;

  for (u32 i = 0; i < len; i++) tt->word[i] = word[i];

  // A $HEX[] line stands for bytes, and the table matches those bytes rather than the spelling.

  if (is_hexify (tt->word, len) == true)
  {
    u8 dec[PW_MAX];

    const int dec_len = table_decode (tt->word, len, dec, PW_MAX);

    if (dec_len >= 0)
    {
      for (int i = 0; i < dec_len; i++) tt->word[i] = dec[i];

      len = (u32) dec_len;
    }
  }

  tt->word_len = len;

  // A word is at most PW_MAX bytes and a token covers at least one, so the array cannot be too small
  // and this cannot fail. It is still read, because a change to either bound would make it able to.

  const int tok_cnt = table_tokenize (&tg->tb, tt->word, len, tt->tok, PW_MAX);

  if (tok_cnt < 0) return false;

  tt->tok_cnt = (u32) tok_cnt;
  tt->var_cnt = 0;

  for (u32 i = 0; i < tt->tok_cnt; i++)
  {
    if (tt->tok[i].bucket == TABLE_TOK_LITERAL) continue;

    tt->var[tt->var_cnt] = i;

    tt->var_cnt++;
  }

  table_split (tg, tt);

  return true;
}

static int table_word_load (generic_global_ctx_t *global_ctx, table_global_t *tg, generic_thread_ctx_t *thread_ctx, table_thread_t *tt)
{
  const int word_len = wordlist_next (global_ctx, &tg->wl, thread_ctx, tt->wl, tt->word, PW_MAX);

  if (word_len < 0)
  {
    tt->rect = 0;
    tt->at   = 0;

    return word_len;
  }

  // Same over-length line as table_take () guards against, caught before this copy rather than inside
  // it, because both of these buffers are PW_MAX and the length can exceed it.

  if (word_len > PW_MAX)
  {
    table_take (tg, tt, tt->word, (u32) word_len);

    return word_len;
  }

  u8 word[PW_MAX];

  for (int i = 0; i < word_len; i++) word[i] = tt->word[i];

  if (table_take (tg, tt, word, (u32) word_len) == false) return GENERIC_RC_ERROR;

  return word_len;
}

// Moving the reader on by units without building any of them. A word whose whole rectangle is passed
// over costs only the tokenizing, and the word the target lands in is entered by unranking rather
// than by stepping.

static int table_skip (generic_global_ctx_t *global_ctx, table_global_t *tg, generic_thread_ctx_t *thread_ctx, table_thread_t *tt, u64 n)
{
  while (n > 0)
  {
    if (tt->at >= tt->rect)
    {
      const int rc = table_word_load (global_ctx, tg, thread_ctx, tt);

      if (rc < 0) return rc;

      continue;
    }

    const u64 left = tt->rect - tt->at;

    if (n < left)
    {
      table_unrank (tg, tt, tt->at + n);

      tt->pos += n;

      return 0;
    }

    tt->at   = tt->rect;
    tt->pos += left;

    n -= left;
  }

  return 0;
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  table_global_t *tg = hccalloc (1, sizeof (table_global_t));

  global_ctx->gbldata = tg;

  tg->hcctx = hashcat_ctx;

  // The first argument is the wordlist and every one after it is a table. One wordlist rather than
  // several, because a directory already stands for as many as you like and the reader lays them end to
  // end, and because whatever follows it has to mean one thing. Several tables are read into one set,
  // so a leetspeak table and a case table are combined here rather than shipped pre-merged.
  //
  // The positional arguments run until the first key=value setting.

  int pos_end = global_ctx->workc;

  for (int i = 1; i < global_ctx->workc; i++)
  {
    if (feed_param_is_setting (global_ctx->workv[i]) == false) continue;

    pos_end = i;

    break;
  }

  const int tables_cnt = pos_end - 2;

  if (tables_cnt < 1)
  {
    error_set (global_ctx, "usage: table <wordlist|directory> <table ..> [maxperm=%d] [identity=0] [template=1]", TABLE_MAXPERM_DEF);

    return false;
  }

  u64 maxperm = TABLE_MAXPERM_DEF;

  bool identity = true;
  bool template = false;

  const feed_param_t params[] =
  {
    { "maxperm",  FEED_PARAM_TYPE_U64,  &maxperm,  0, 0xffffffffffffffffULL, "candidates one word may be worth, 0 for no limit" },
    { "identity", FEED_PARAM_TYPE_BOOL, &identity, 0, 0,                     "whether leaving a token alone is one of its choices, 0 for a table that converts rather than varies" },
    { "template", FEED_PARAM_TYPE_BOOL, &template, 0, 0,                     "whether a word no rule matched is dropped, 1 to read the wordlist as a template" },
    { NULL, 0, NULL, 0, 0, NULL }
  };

  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  tg->maxperm  = maxperm;
  tg->template = template;

  if (wordlist_init (global_ctx, &tg->wl, 1, 2) == false) return false;

  char err[256];

  if (table_load (&tg->tb, &global_ctx->workv[2], tables_cnt, identity, err, sizeof (err)) == false)
  {
    error_set (global_ctx, "%s", err);

    return false;
  }

  tg->il_cnt  = 1 << TABLE_KBITS_DEF;
  tg->maxword = PCFG_DEV_MAXWORD;

  // hashconfig_init () runs in outer_loop () before generic_ctx_init () gets here, so the hash mode's
  // own bounds are settled and a feed may read them.

  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig != NULL)
  {
    tg->pwmin = hashconfig->pw_min;
    tg->pwmax = hashconfig->pw_max;
  }

  // With several tables the list is longer than the status line has room for, so it says how many.

  if (tables_cnt == 1)
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s + %s", tg->wl.sources[0].path, global_ctx->workv[2]);
  }
  else
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s + %d tables", tg->wl.sources[0].path, tables_cnt);
  }

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  table_global_t *tg = global_ctx->gbldata;

  if (tg == NULL) return;

  wordlist_term (global_ctx, &tg->wl);

  hcfree (tg->idx.cum);

  table_free (&tg->tb);

  hcfree (tg);

  global_ctx->gbldata = NULL;
}

// What a cell is worth on this wordlist, and one real cell for the autotuner to search with. Both
// come from reading the front of the first source, because global_dev_init () runs before the
// keyspace pass and there is no reader open yet.

static u64 table_sample (table_global_t *tg, pcfg_cell_t *probe, u32 *step)
{
  step[0] = 1;

  if (tg->wl.sources_cnt == 0) return 1;

  const char *path = tg->wl.sources[0].path;

  HCFILE fp;

  if (hc_fopen (&fp, path, "rb") == false) return 1;

  // How big the file is, taken here rather than from the source. wordlist_keyspace () fills that in
  // and it runs after this does, so reading it would spread the sample over a size of zero and quietly
  // sample the front of the file instead.

  struct stat st;

  const u64 size = (stat (path, &st) == 0) ? (u64) st.st_size : 0;

  // A compressed source cannot be seeked into without decoding what is in front, so it is read from
  // the front alone and the estimate is worth whatever its first lines are worth.

  const bool spread = (hc_path_is_compressed (path) == false) && (size > (TABLE_SAMPLE_BYTES * TABLE_SAMPLE_CHUNKS));

  u8 *buf = (u8 *) hcmalloc (TABLE_SAMPLE_BYTES);

  table_thread_t *tt = (table_thread_t *) hccalloc (1, sizeof (table_thread_t));

  u64 seen = 0;
  u64 sum  = 0;
  u64 best = 0;

  const u32 chunks = (spread == true) ? TABLE_SAMPLE_CHUNKS : 1;

  for (u32 c = 0; c < chunks; c++)
  {
    if (spread == true)
    {
      const u64 at = (size / chunks) * c;

      if (hc_fseek (&fp, (off_t) at, SEEK_SET) != 0) break;
    }

    const size_t got = hc_fread (buf, 1, TABLE_SAMPLE_BYTES, &fp);

    if (got == 0) break;

    size_t pos = 0;

    // every chunk but the first begins in the middle of a line, so that line is dropped

    if (c > 0)
    {
      while ((pos < got) && (buf[pos] != 0x0a)) pos++;

      pos++;
    }

    while (pos < got)
    {
      size_t end = pos;

      while ((end < got) && (buf[end] != 0x0a)) end++;

      // the last line of a chunk is cut by the chunk rather than by the file, so it is dropped too

      if (end == got) break;

      size_t stop = end;

      if ((stop > pos) && (buf[stop - 1] == 0x0d)) stop--;

      const size_t len = stop - pos;

      const size_t at = pos;

      pos = end + 1;

      if (len == 0) continue;
      if (len > PW_MAX) continue;

      if (table_take (tg, tt, &buf[at], (u32) len) == false) continue;

      sum += tt->cell_rect;

      seen++;

      // A probe the autotuner searches with has to be one the feed really emits, and the widest of
      // the sample is the one whose launch is worth sizing for.

      if (tt->cell_rect <= best) continue;

      best = tt->cell_rect;

      table_cell (&tg->tb, tt, probe);

      step[0] = (tt->var_cnt > tt->nfront) ? tg->tb.bucket[tt->tok[tt->var[tt->nfront]].bucket].ent_len : 1;
    }
  }

  hc_fclose (&fp);

  hcfree (tt);
  hcfree (buf);

  if (seen == 0) return 1;

  const u64 avg = sum / seen;

  return (avg > 0) ? avg : 1;
}

bool global_dev_init (generic_global_ctx_t *global_ctx, const u32 **pool, u64 *pool_size, u32 *il_cnt, u32 *avg, u32 *maxword, u32 *front, u32 *step, u32 *varlen, pcfg_cell_t *probe)
{
  table_global_t *tg = global_ctx->gbldata;

  memset (probe, 0, sizeof (pcfg_cell_t));

  pool[0]      = tg->tb.pool;
  pool_size[0] = tg->tb.pool_cnt * sizeof (u32);
  maxword[0]   = tg->maxword;
  varlen[0]    = 0;
  step[0]      = 1;
  avg[0]       = 1;
  front[0]     = 1;

  tg->dev = true;

  varlen[0] = (tg->tb.varlen == true) ? 1 : 0;

  il_cnt[0] = tg->il_cnt;

  const u64 mean = table_sample (tg, probe, step);

  avg[0]   = (mean > 0xffffffffULL) ? 0xffffffff : (u32) mean;
  front[0] = avg[0];

  if (avg[0] == 0) avg[0] = 1;
  if (front[0] == 0) front[0] = 1;

  tg->dev_mean = avg[0];

  return true;
}

// Everything this feed has to say, in one block, once the wordlist has finished saying its own.

static void table_report (table_global_t *tg, const u64 lines, const double runtime)
{
  if (tg->dev == true)
  {
    feed_say (tg->hcctx, "table: device engine, %u buckets, %" PRIu64 " byte pool, mean cell %u%s", tg->tb.bucket_cnt, tg->tb.pool_cnt * 4, tg->dev_mean, (tg->tb.varlen == true) ? ", entries of several lengths" : "");
  }
  else
  {
    feed_say (tg->hcctx, "table: host engine, %u buckets, every candidate is built here and copied over", tg->tb.bucket_cnt);
  }

  // Only worth saying when it was turned off, which is the unusual case and the one that changes what
  // a table means.

  if (tg->tb.identity == false)
  {
    feed_say (tg->hcctx, "table: identity off, so every token the table matches is converted rather than offered the choice");
  }

  if (tg->template == true)
  {
    feed_say (tg->hcctx, "table: template on, %" PRIu64 " of %" PRIu64 " words matched no rule and were dropped", tg->unmatched, lines);
  }

  if (runtime > 1000) feed_say (tg->hcctx, "table: %" PRIu64 " words measured in %.1fs", lines, runtime / 1000);

  const u64 mean = (tg->idx.units > 0) ? (tg->idx.total / tg->idx.units) : 1;

  if (tg->dev == true)
  {
    feed_say (tg->hcctx, "table: %" PRIu64 " base words for %" PRIu64 " candidates (x%" PRIu64 ")", tg->idx.units, tg->idx.total, mean);
  }
  else
  {
    feed_say (tg->hcctx, "table: %" PRIu64 " candidates", tg->idx.units);
  }

  if (tg->outside > 0)
  {
    feed_say (tg->hcctx, "table: %" PRIu64 " words left out, no candidate of theirs is between the %u and %u bytes this hash mode accepts", tg->outside, tg->pwmin, tg->pwmax);
  }

  if (tg->maxperm == 0)
  {
    feed_say (tg->hcctx, "table: no limit per word, the widest is %" PRIu64 " candidates", tg->widest);

    return;
  }

  // A word wide enough to overflow the count is exactly the kind the budget is here for, so it says so
  // rather than printing the number it saturated at.

  if (tg->widest == 0xffffffffffffffffULL)
  {
    feed_say (tg->hcctx, "table: maxperm %" PRIu64 ", %" PRIu64 " words held to it, the widest wanting more than 2^64", tg->maxperm, tg->capped);

    return;
  }

  feed_say (tg->hcctx, "table: maxperm %" PRIu64 ", %" PRIu64 " words held to it, widest wanted %" PRIu64, tg->maxperm, tg->capped, tg->widest);
}

// The keyspace index, kept between runs.
//
// Building it reads the whole wordlist, which is the one unavoidable cost of the attack: a word is
// worth what the table makes of it, so the run's length cannot be worked out from a line count. That
// read is the same every time for the same wordlist and the same tables, so it is done once and the
// answer is written down.
//
// The file is raw u64 rather than packed. The index is one number per TABLE_INDEX_STEP lines and
// TABLE_INDEX_MAX caps it, so a wordlist of any size comes to at most 8 MiB and a realistic one to
// about a hundred kilobytes. Packing it would buy little and cost the reader something to get wrong.

#define TABLE_CACHE_MAGIC   0x584449454c424154ULL
#define TABLE_CACHE_VERSION 7

typedef struct table_cache_head
{
  u64 magic;
  u32 version;

  // Which engine the index counts for. A unit is a base word where the card expands one and a
  // candidate where it does not, so the two engines number the same run differently and an index
  // built for one says nothing about a position in the other. The split itself is the same, which is
  // why only this one field separates them.

  u32 dev;

  // What the index describes. The wordlist set as one number, from the seek databases, and the merged
  // table as another.

  u64 wl_ident;
  u64 tb_ident;

  // The wordlist ident is the seek database's, which is the file size plus its two ends rather than
  // all of it, because reading every byte to name a file defeats the point of not reading it. A seek
  // database survives an edit that keeps every line the same length, since no line offset moves. This
  // index does not: it counts what each block of words is worth, and that changes with the bytes. The
  // line count is cheap to carry and catches an edit that adds or removes a line, which is most of
  // them. An edit that changes neither the size nor the line count is not detected, the same blind
  // spot the seek database has and for the same reason.

  u64 lines;

  // What the pass was told. maxperm bounds what a word may be worth, and the hash mode's length
  // window decides which candidates count at all, so a word can be worth nothing under one mode and
  // something under another.

  u64 maxperm;
  u32 pwmin;
  u32 pwmax;

  // Compile time limits that shape the same numbers. A build with a different slot count or a
  // different step reads its own files rather than someone else's.

  u32 wmax;
  u32 slotcap;
  u32 maxword;
  u32 ilcnt;
  u32 template;
  u64 index_step;
  u64 index_max;

  // What the pass found

  u64 cnt;
  u64 step;
  u64 units;
  u64 total;
  u64 outside;
  u64 unmatched;
  u64 capped;
  u64 widest;

  // Last and on its own, because it can only be checked once the rows have been read

  u64 sum;

} table_cache_head_t;

static void table_cache_head_fill (const table_global_t *tg, table_cache_head_t *h, const u64 wl_ident)
{
  memset (h, 0, sizeof (table_cache_head_t));

  h->magic      = TABLE_CACHE_MAGIC;
  h->version    = TABLE_CACHE_VERSION;
  h->dev        = (tg->dev == true) ? 1 : 0;
  h->wl_ident   = wl_ident;
  h->lines      = tg->wl.line_count;
  h->tb_ident   = tg->tb.ident;
  h->maxperm    = tg->maxperm;
  h->pwmin      = tg->pwmin;
  h->pwmax      = tg->pwmax;
  h->wmax       = TABLE_WMAX;
  h->slotcap    = PCFG_DEV_MAXSLOT;
  h->maxword    = tg->maxword;
  h->ilcnt      = tg->il_cnt;
  h->template   = (tg->template == true) ? 1 : 0;
  h->index_step = TABLE_INDEX_STEP;
  h->index_max  = TABLE_INDEX_MAX;
  h->cnt        = tg->idx.cnt;
  h->step       = tg->idx.step;
  h->units      = tg->idx.units;
  h->total      = tg->idx.total;
  h->outside    = tg->outside;
  h->unmatched  = tg->unmatched;
  h->capped     = tg->capped;
  h->widest     = tg->widest;
}

// make says where a name goes: a load only reads, and creating the folder for it would leave an empty
// one behind on every run that never writes anything.

static char *table_cache_path (const generic_global_ctx_t *global_ctx, const table_global_t *tg, const bool make)
{
  if (global_ctx->cache_dir == NULL) return NULL;
  if (tg->wl.ident == 0) return NULL;
  if (tg->tb.ident == 0) return NULL;

  char *dir = NULL;

  // Named after the feed, the way the plugin beside it is: feeds/feed_table.so writes this.

  hc_asprintf (&dir, "%s/feeds/table", global_ctx->cache_dir);

  if (dir == NULL) return NULL;

  // Recursive because the feeds level above may not be there yet.

  if (make == true) hc_mkdir_rec (dir, 0700);

  // Every configuration of one wordlist and one table set is a file of its own, the engine included.
  // Keeping any of it out of the name and only in the header would leave two runs that differ in it
  // writing the same file over each other, so neither would ever find what it wrote.

  char *path = NULL;

  hc_asprintf (&path, "%s/%016" PRIx64 "-%016" PRIx64 "-%" PRIu64 "-%u-%u-%u.tabledb", dir, tg->wl.ident, tg->tb.ident, tg->maxperm, tg->pwmin, tg->pwmax, (tg->dev == true) ? 1 : 0);

  hcfree (dir);

  return path;
}

static bool table_cache_load (const generic_global_ctx_t *global_ctx, table_global_t *tg)
{
  char *path = table_cache_path (global_ctx, tg, false);

  if (path == NULL) return false;

  HCFILE fp;

  const bool open = hc_fopen_raw (&fp, path, "rb");

  hcfree (path);

  if (open == false) return false;

  table_cache_head_t want;
  table_cache_head_t have;

  table_cache_head_fill (tg, &want, tg->wl.ident);

  if (hc_fread (&have, sizeof (have), 1, &fp) != 1) { hc_fclose (&fp); return false; }

  // A file found under the right name is not yet the right file. Only the fields the caller knows
  // before the pass can be compared, so cnt and everything after it are what the file says.

  if (have.magic      != want.magic)      { hc_fclose (&fp); return false; }
  if (have.version    != want.version)    { hc_fclose (&fp); return false; }
  if (have.dev        != want.dev)        { hc_fclose (&fp); return false; }
  if (have.wl_ident   != want.wl_ident)   { hc_fclose (&fp); return false; }
  if (have.lines      != want.lines)     { hc_fclose (&fp); return false; }
  if (have.tb_ident   != want.tb_ident)   { hc_fclose (&fp); return false; }
  if (have.maxperm    != want.maxperm)    { hc_fclose (&fp); return false; }
  if (have.pwmin      != want.pwmin)      { hc_fclose (&fp); return false; }
  if (have.pwmax      != want.pwmax)      { hc_fclose (&fp); return false; }
  if (have.wmax       != want.wmax)       { hc_fclose (&fp); return false; }
  if (have.slotcap    != want.slotcap)    { hc_fclose (&fp); return false; }
  if (have.maxword    != want.maxword)   { hc_fclose (&fp); return false; }
  if (have.ilcnt      != want.ilcnt)     { hc_fclose (&fp); return false; }
  if (have.template   != want.template)  { hc_fclose (&fp); return false; }
  if (have.index_step != want.index_step) { hc_fclose (&fp); return false; }
  if (have.index_max  != want.index_max)  { hc_fclose (&fp); return false; }

  // A cnt the pass could never have produced is a corrupt file rather than a big wordlist

  if (have.cnt == 0)              { hc_fclose (&fp); return false; }
  if (have.cnt > TABLE_INDEX_MAX + 1) { hc_fclose (&fp); return false; }
  if (have.step == 0)             { hc_fclose (&fp); return false; }

  u64 *cum = (u64 *) hcmalloc (have.cnt * sizeof (u64));

  if (cum == NULL) { hc_fclose (&fp); return false; }

  const size_t got = hc_fread (cum, sizeof (u64), have.cnt, &fp);

  hc_fclose (&fp);

  if (got != have.cnt) { hcfree (cum); return false; }

  if (paw64 (cum, have.cnt * sizeof (u64), 0) != have.sum) { hcfree (cum); return false; }

  // The index only means anything if it climbs, because a seek finds its line by walking it

  for (u64 i = 1; i < have.cnt; i++)
  {
    if (cum[i] >= cum[i - 1]) continue;

    hcfree (cum);

    return false;
  }

  if (cum[have.cnt - 1] > have.units) { hcfree (cum); return false; }

  tg->idx.cum   = cum;
  tg->idx.cnt   = have.cnt;
  tg->idx.step  = have.step;
  tg->idx.units = have.units;
  tg->idx.total = have.total;

  tg->outside   = have.outside;
  tg->unmatched = have.unmatched;
  tg->capped  = have.capped;
  tg->widest  = have.widest;

  return true;
}

static void table_cache_save (const generic_global_ctx_t *global_ctx, const table_global_t *tg)
{
  char *path = table_cache_path (global_ctx, tg, true);

  if (path == NULL) return;

  // Written beside the name and moved onto it, so a run that dies leaves no file the next would
  // trust. The temporary carries the process, or two runs on one wordlist write the same one over
  // each other.

  char *tmp = NULL;

  hc_asprintf (&tmp, "%s.%d.tmp", path, (int) getpid ());

  if (tmp == NULL) { hcfree (path); return; }

  HCFILE fp;

  if (hc_fopen_raw (&fp, tmp, "wb") == false) { hcfree (tmp); hcfree (path); return; }

  table_cache_head_t h;

  table_cache_head_fill (tg, &h, tg->wl.ident);

  h.sum = paw64 (tg->idx.cum, tg->idx.cnt * sizeof (u64), 0);

  bool ok = (hc_fwrite (&h, sizeof (h), 1, &fp) == 1);

  if (ok == true) ok = (hc_fwrite (tg->idx.cum, sizeof (u64), tg->idx.cnt, &fp) == tg->idx.cnt);

  hc_fclose (&fp);

  // A directory that cannot be written to is a normal way to use this, so a failure here is not an
  // error: the run carries on from the index it just built in memory.

  // rename () refuses an existing target on Windows, where POSIX replaces it silently.

  #if defined (_WIN)
  if (ok == true) remove (path);
  #endif

  if (ok == true) ok = (rename (tmp, path) == 0);

  if (ok == false) unlink (tmp);

  hcfree (tmp);
  hcfree (path);
}

// One pass over the wordlist, which is what says how long the attack is and where a seek lands.
//
// A word is worth what the table makes of it, so unlike an ordinary wordlist attack the run's length
// is not the line count and a position in it does not follow from a line number. The pass reads every
// line once and records where the run has got to every so many lines. A seek then reads the entry in
// front of its target and walks the few lines from there, instead of reading the wordlist from the
// start.

static bool table_keyspace_build (generic_global_ctx_t *global_ctx, table_global_t *tg, generic_thread_ctx_t *thread_ctx)
{
  const u64 lines = tg->wl.line_count;

  if (lines == 0) return true;

  u64 step = TABLE_INDEX_STEP;

  while ((lines / step) > TABLE_INDEX_MAX) step *= 2;

  // One entry per block the fill loop below reaches, which is every step'th line from 0 up to the
  // last one. Sizing it lines / step + 1 leaves a trailing entry nothing ever writes whenever the
  // line count is an exact multiple of the step, and a zero there is smaller than the entry in front
  // of it, so the index stops being ascending and every reader of it is wrong.

  const u64 cnt = ((lines - 1) / step) + 1;

  feed_thread_t *ft = wordlist_thread_init (thread_ctx);

  if (ft == NULL) return false;

  if (wordlist_seek (&tg->wl, thread_ctx, ft, 0) == false)
  {
    wordlist_thread_term (ft);

    return false;
  }

  table_thread_t *tt = (table_thread_t *) hccalloc (1, sizeof (table_thread_t));

  u64 *cum = (u64 *) hcmalloc (cnt * sizeof (u64));

  u64 units = 0;
  u64 total = 0;

  bool ok = true;

  for (u64 i = 0; i < lines; i++)
  {
    if ((i % step) == 0) cum[i / step] = units;

    u8 word[PW_MAX];

    const int word_len = wordlist_next (global_ctx, &tg->wl, thread_ctx, ft, word, PW_MAX);

    if (word_len == GENERIC_RC_EOF) break;

    if (word_len < 0)
    {
      ok = false;

      break;
    }

    if (table_take (tg, tt, word, (u32) word_len) == false)
    {
      ok = false;

      break;
    }

    // Saturating, like total below and widest above. maxperm=0 lets one word be worth 2^64-1, and a
    // plain add would wrap the run length round to a small number or to zero.

    units = table_sat_add (units, tt->rect);

    if (tt->rect == 0)
    {
      if (tt->unmatched == true) tg->unmatched++; else tg->outside++;
    }

    if (tt->wmax != TABLE_WFULL) tg->capped++;

    const u64 wanted = table_sat_mul (tt->front_full, tt->cell_rect);

    if (wanted > tg->widest) tg->widest = wanted;

    // What the run comes to in candidates rather than in base words, which the status line would
    // otherwise reconstruct from a mean rounded down to an integer and always fall short of.

    // rect is base words on the card and candidates on the host, so the cell is what turns one into
    // the other only on the card. Multiplying by it on both would count the cell twice.

    const u64 full = (tg->dev == true) ? table_sat_mul (tt->rect, tt->cell_rect) : tt->rect;

    total = table_sat_add (total, full);
  }

  hcfree (tt);

  wordlist_thread_term (ft);

  if (ok == false)
  {
    hcfree (cum);

    return false;
  }

  tg->idx.cum   = cum;
  tg->idx.cnt   = cnt;
  tg->idx.step  = step;
  tg->idx.units = units;
  tg->idx.total = total;

  return true;
}

u64 global_keyspace (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  table_global_t *tg = global_ctx->gbldata;

  const u64 lines = wordlist_keyspace (global_ctx, thread_ctx[0], hashcat_ctx, &tg->wl);

  if (lines == GENERIC_KEYSPACE_ERROR) return GENERIC_KEYSPACE_ERROR;

  // The reader publishes where each wordlist starts as a line number, which is what a position means
  // to the wordlist feed. It is not what one means here: this feed counts base words or candidates,
  // and a word is worth as many of them as the table makes of it. Comparing a position against those
  // line numbers names the wrong file in the status display and moves the bypass key to the wrong
  // place, so the segments are dropped rather than left to be read in the wrong unit. Guess.Base
  // still names the wordlist and the tables, which global_init () sets.

  global_ctx->segments_cnt  = 0;
  global_ctx->segment_names = NULL;
  global_ctx->segment_first = NULL;

  hc_timer_t start;

  hc_timer_set (&start);

  // The pass is the same every time for the same wordlist and the same tables, so it runs once and
  // what it found is written down. A miss for any reason is a build, which is what happened before
  // there was a file to look for.

  const bool cache_hit = table_cache_load (global_ctx, tg);

  if (cache_hit == false)
  {
    if (table_keyspace_build (global_ctx, tg, thread_ctx[0]) == false)
    {
      error_set (global_ctx, "could not read the wordlist to measure the attack: %s", thread_ctx[0]->error_msg);

      return GENERIC_KEYSPACE_ERROR;
    }

    table_cache_save (global_ctx, tg);
  }

  table_report (tg, lines, (cache_hit == true) ? 0 : hc_timer_get (start));

  // The run's length in candidates, which is known exactly here. Without it the status line multiplies
  // the base word count by a mean rounded down to an integer and never quite reaches its own total.

  if (tg->dev == true) global_ctx->dev_total = tg->idx.total;

  return tg->idx.units;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  table_thread_t *tt = hccalloc (1, sizeof (table_thread_t));

  tt->wl = wordlist_thread_init (thread_ctx);

  if (tt->wl == NULL)
  {
    hcfree (tt);

    return false;
  }

  thread_ctx->thrdata = tt;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx)
{
  table_thread_t *tt = thread_ctx->thrdata;

  if (tt == NULL) return;

  wordlist_thread_term (tt->wl);

  hcfree (tt);

  thread_ctx->thrdata = NULL;
}

int thread_next (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  table_global_t *tg = global_ctx->gbldata;
  table_thread_t *tt = thread_ctx->thrdata;

  while (tt->at >= tt->rect)
  {
    const int rc = table_word_load (global_ctx, tg, thread_ctx, tt);

    if (rc < 0) return rc;
  }

  const u32 len = table_write (&tg->tb, tt, out_buf, (u32) out_size);

  table_step (tg, tt);

  tt->pos++;

  return (int) len;
}

// One base word and the cell that extends it. The base word carries the substitutions the host
// enumerates and every byte the table said nothing about, and the cell carries the rest.

int thread_next_dev (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  table_global_t *tg = global_ctx->gbldata;
  table_thread_t *tt = thread_ctx->thrdata;

  while (tt->at >= tt->rect)
  {
    const int rc = table_word_load (global_ctx, tg, thread_ctx, tt);

    if (rc < 0) return rc;
  }

  const u32 len = table_write_base (&tg->tb, tt, out_buf, (u32) out_size);

  table_cell (&tg->tb, tt, cell);

  table_step (tg, tt);

  tt->pos++;

  return (int) len;
}

// Walking to a unit. Seeking forward carries on from where the reader already is, which is what keeps
// a run whose dispatcher hands out one chunk after another from re-reading the wordlist for every one
// of them. Only a seek backwards starts over.
//
// It is still a walk. What it is not yet is an index, so a device handed a range deep in a large
// wordlist pays for every word in front of it once.

bool thread_seek (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t *thread_ctx, const u64 offset)
{
  table_global_t *tg = global_ctx->gbldata;
  table_thread_t *tt = thread_ctx->thrdata;

  // The entry in front of the target, which is where the walk starts unless the reader is already
  // between it and the target. Carrying on from where the reader is beats jumping backwards to an
  // index entry, and a dispatcher that hands out one chunk after another is doing exactly that.

  if (tg->idx.cum != NULL)
  {
    u64 lo = 0;
    u64 hi = tg->idx.cnt - 1;

    while (lo < hi)
    {
      const u64 mid = lo + ((hi - lo + 1) / 2);

      if (tg->idx.cum[mid] > offset) hi = mid - 1;
      else                           lo = mid;
    }

    if ((tt->pos > offset) || (tg->idx.cum[lo] > tt->pos))
    {
      if (wordlist_seek (&tg->wl, thread_ctx, tt->wl, lo * tg->idx.step) == false) return false;

      tt->rect = 0;
      tt->at   = 0;
      tt->pos  = tg->idx.cum[lo];
    }
  }
  else if (offset < tt->pos)
  {
    if (wordlist_seek (&tg->wl, thread_ctx, tt->wl, 0) == false) return false;

    tt->rect = 0;
    tt->at   = 0;
    tt->pos  = 0;
  }

  const int rc = table_skip (global_ctx, tg, thread_ctx, tt, offset - tt->pos);

  // Running out of words on the way to a target past the end is not a failure. The reader is left
  // saying it has nothing, and the next call for a unit reports the end of the feed.

  if (rc == GENERIC_RC_ERROR) return false;

  return true;
}
