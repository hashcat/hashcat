/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "shared.h"
#include "filehandling.h"
#include "wordlist_index.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>

// ---------------------------------------------------------------------------
// Minimal, self-contained SHA-256 (host side, only used for the optional
// integrity field). Kept local so the index module has no dependency on the
// GPU hash-emulation headers.
// ---------------------------------------------------------------------------

typedef struct
{
  u32 state[8];
  u64 bitlen;
  u8  buf[64];
  u32 buflen;

} hcidx_sha256_ctx_t;

static const u32 HCIDX_SHA256_K[64] =
{
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

#define HCIDX_ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))

static void hcidx_sha256_init (hcidx_sha256_ctx_t *c)
{
  c->state[0] = 0x6a09e667; c->state[1] = 0xbb67ae85;
  c->state[2] = 0x3c6ef372; c->state[3] = 0xa54ff53a;
  c->state[4] = 0x510e527f; c->state[5] = 0x9b05688c;
  c->state[6] = 0x1f83d9ab; c->state[7] = 0x5be0cd19;
  c->bitlen = 0;
  c->buflen = 0;
}

static void hcidx_sha256_block (hcidx_sha256_ctx_t *c, const u8 *p)
{
  u32 w[64];

  for (int i = 0; i < 16; i++)
  {
    w[i] = ((u32) p[i * 4] << 24) | ((u32) p[i * 4 + 1] << 16) | ((u32) p[i * 4 + 2] << 8) | ((u32) p[i * 4 + 3]);
  }

  for (int i = 16; i < 64; i++)
  {
    const u32 s0 = HCIDX_ROTR (w[i - 15], 7) ^ HCIDX_ROTR (w[i - 15], 18) ^ (w[i - 15] >> 3);
    const u32 s1 = HCIDX_ROTR (w[i - 2], 17) ^ HCIDX_ROTR (w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  u32 a = c->state[0], b = c->state[1], cc = c->state[2], d = c->state[3];
  u32 e = c->state[4], f = c->state[5], g = c->state[6], h = c->state[7];

  for (int i = 0; i < 64; i++)
  {
    const u32 S1 = HCIDX_ROTR (e, 6) ^ HCIDX_ROTR (e, 11) ^ HCIDX_ROTR (e, 25);
    const u32 ch = (e & f) ^ ((~e) & g);
    const u32 t1 = h + S1 + ch + HCIDX_SHA256_K[i] + w[i];
    const u32 S0 = HCIDX_ROTR (a, 2) ^ HCIDX_ROTR (a, 13) ^ HCIDX_ROTR (a, 22);
    const u32 maj = (a & b) ^ (a & cc) ^ (b & cc);
    const u32 t2 = S0 + maj;

    h = g; g = f; f = e; e = d + t1; d = cc; cc = b; b = a; a = t1 + t2;
  }

  c->state[0] += a; c->state[1] += b; c->state[2] += cc; c->state[3] += d;
  c->state[4] += e; c->state[5] += f; c->state[6] += g; c->state[7] += h;
}

static void hcidx_sha256_update (hcidx_sha256_ctx_t *c, const u8 *data, size_t len)
{
  c->bitlen += (u64) len * 8;

  while (len > 0)
  {
    const u32 space = 64 - c->buflen;
    const u32 take  = (len < space) ? (u32) len : space;

    memcpy (c->buf + c->buflen, data, take);

    c->buflen += take;
    data      += take;
    len       -= take;

    if (c->buflen == 64)
    {
      hcidx_sha256_block (c, c->buf);
      c->buflen = 0;
    }
  }
}

static void hcidx_sha256_final (hcidx_sha256_ctx_t *c, u8 out[32])
{
  const u64 bitlen = c->bitlen;

  u8 pad = 0x80;
  hcidx_sha256_update (c, &pad, 1);

  pad = 0x00;
  while (c->buflen != 56) hcidx_sha256_update (c, &pad, 1);

  u8 lenbuf[8];
  for (int i = 0; i < 8; i++) lenbuf[i] = (u8) (bitlen >> (56 - i * 8));
  hcidx_sha256_update (c, lenbuf, 8);

  for (int i = 0; i < 8; i++)
  {
    out[i * 4 + 0] = (u8) (c->state[i] >> 24);
    out[i * 4 + 1] = (u8) (c->state[i] >> 16);
    out[i * 4 + 2] = (u8) (c->state[i] >> 8);
    out[i * 4 + 3] = (u8) (c->state[i]);
  }
}

static int hcidx_sha256_file (const char *path, u8 out[32])
{
  FILE *fp = fopen (path, "rb");

  if (fp == NULL) return -1;

  hcidx_sha256_ctx_t ctx;
  hcidx_sha256_init (&ctx);

  u8 *buf = (u8 *) hcmalloc (1024 * 1024);

  size_t n;

  while ((n = fread (buf, 1, 1024 * 1024, fp)) > 0)
  {
    hcidx_sha256_update (&ctx, buf, n);
  }

  hcfree (buf);
  fclose (fp);

  hcidx_sha256_final (&ctx, out);

  return 0;
}

// ---------------------------------------------------------------------------
// path helpers
// ---------------------------------------------------------------------------

static char *hcidx_default_path (const char *dictfile)
{
  const size_t len = strlen (dictfile) + strlen (HCIDX_SUFFIX) + 1;

  char *p = (char *) hcmalloc (len);

  snprintf (p, len, "%s%s", dictfile, HCIDX_SUFFIX);

  return p;
}

static off_t hcidx_file_size (const char *path)
{
  struct stat st;

  if (stat (path, &st) != 0) return -1;

  return st.st_size;
}

// ---------------------------------------------------------------------------
// loading / lookup (JSON on-disk format)
// ---------------------------------------------------------------------------

// On-disk shape:
// {
//   "version": 1,
//   "flags": 0,
//   "interval": 1000000,
//   "word_count": 30000000,
//   "file_size": 350000000,
//   "sha256": null,
//   "entries": [
//     [0, 0],
//     [1000000, 13000000],
//     ...
//   ]
// }
//
// Parser is deliberately tiny: known shape, fixed keys, sscanf-based. It
// tolerates whitespace and comment-free JSON; it is NOT a general parser.

static int hcidx_hexval (char c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static const char *hcidx_skip_ws (const char *p)
{
  while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
  return p;
}

// Find `"key":` in `buf` and return a pointer to the first char of the value
// (with any whitespace skipped). Returns NULL if the key is not found.
static const char *hcidx_find_value (const char *buf, const char *key)
{
  char pattern[64];
  snprintf (pattern, sizeof (pattern), "\"%s\"", key);

  const char *p = strstr (buf, pattern);
  if (p == NULL) return NULL;

  p += strlen (pattern);
  p  = hcidx_skip_ws (p);
  if (*p != ':') return NULL;
  p++;
  p = hcidx_skip_ws (p);
  return p;
}

static int hcidx_read_u64 (const char *buf, const char *key, u64 *out)
{
  const char *p = hcidx_find_value (buf, key);
  if (p == NULL) return -1;

  char *endp;
  unsigned long long v = strtoull (p, &endp, 10);
  if (endp == p) return -1;

  *out = (u64) v;
  return 0;
}

int hcidx_load (hcidx_t *idx, const char *dictfile, const char *index_path)
{
  memset (idx, 0, sizeof (hcidx_t));

  char *path = (index_path != NULL) ? hcstrdup (index_path) : hcidx_default_path (dictfile);

  FILE *fp = fopen (path, "rb");

  if (fp == NULL)
  {
    // Not an error: silently fall back to a linear seek.
    hcfree (path);
    return 0;
  }

  // The index is small (KB-scale). Read it all at once for easy parsing.
  if (fseek (fp, 0, SEEK_END) != 0) { fclose (fp); hcfree (path); return 0; }
  long fsz = ftell (fp);
  if (fsz <= 0 || fsz > (long) (32 * 1024 * 1024)) { fclose (fp); hcfree (path); return 0; }
  rewind (fp);

  char *buf = (char *) hcmalloc ((size_t) fsz + 1);

  if (fread (buf, 1, (size_t) fsz, fp) != (size_t) fsz)
  {
    hcfree (buf);
    fclose (fp);
    hcfree (path);
    return 0;
  }

  buf[fsz] = 0;

  fclose (fp);
  hcfree (path);

  hcidx_header_t hdr;
  memset (&hdr, 0, sizeof (hdr));

  u64 v_version, v_flags, v_interval, v_word_count, v_file_size;

  if (hcidx_read_u64 (buf, "version",    &v_version)    != 0) { hcfree (buf); return 0; }
  if (hcidx_read_u64 (buf, "flags",      &v_flags)      != 0) { hcfree (buf); return 0; }
  if (hcidx_read_u64 (buf, "interval",   &v_interval)   != 0) { hcfree (buf); return 0; }
  if (hcidx_read_u64 (buf, "word_count", &v_word_count) != 0) { hcfree (buf); return 0; }
  if (hcidx_read_u64 (buf, "file_size",  &v_file_size)  != 0) { hcfree (buf); return 0; }

  if (v_version != HCIDX_VERSION) { hcfree (buf); return 0; }

  hdr.version    = (u32) v_version;
  hdr.flags      = (u32) v_flags;
  hdr.interval   = v_interval;
  hdr.word_count = v_word_count;
  hdr.file_size  = v_file_size;

  // Cheap validation: wordlist size only. mtime is deliberately NOT checked.
  const off_t cur_size = hcidx_file_size (dictfile);

  if (cur_size < 0 || (u64) cur_size != hdr.file_size)
  {
    hcfree (buf);
    return 0;
  }

  // Optional sha256: either "null" or a 64-char hex string.
  const char *psha = hcidx_find_value (buf, "sha256");
  if (psha != NULL)
  {
    if (*psha == '"')
    {
      psha++;
      for (int i = 0; i < 32; i++)
      {
        int hi = hcidx_hexval (psha[i * 2]);
        int lo = hcidx_hexval (psha[i * 2 + 1]);
        if (hi < 0 || lo < 0) { hcfree (buf); return 0; }
        hdr.sha256[i] = (u8) ((hi << 4) | lo);
      }
      hdr.flags |= HCIDX_FLAG_SHA256;
    }
    // else "null" -> leave sha256 zeroed, flag bit unset
  }

  // Parse entries array. Locate "entries" then the opening '['.
  const char *pe = hcidx_find_value (buf, "entries");
  if (pe == NULL || *pe != '[') { hcfree (buf); return 0; }
  pe++;

  // Count entries by walking the outer array, tracking bracket depth so the
  // inner ']' of each [idx, off] pair is not mistaken for the array terminator.
  u64 entry_count = 0;
  const char *q = pe;
  int depth = 0;
  while (*q)
  {
    if (*q == '[')
    {
      if (depth == 0) entry_count++;
      depth++;
    }
    else if (*q == ']')
    {
      if (depth == 0) break;
      depth--;
    }
    q++;
  }

  if (entry_count == 0) { hcfree (buf); return 0; }

  hcidx_entry_t *entries = (hcidx_entry_t *) hccalloc (entry_count, sizeof (hcidx_entry_t));

  u64 ei = 0;
  q = pe;
  while (ei < entry_count)
  {
    q = hcidx_skip_ws (q);
    if (*q == 0 || *q == ']') break;
    if (*q != '[') { q++; continue; }
    q++;
    q = hcidx_skip_ws (q);

    char *endp;
    unsigned long long widx = strtoull (q, &endp, 10);
    if (endp == q) { hcfree (entries); hcfree (buf); return 0; }
    q = hcidx_skip_ws (endp);
    if (*q != ',') { hcfree (entries); hcfree (buf); return 0; }
    q++;
    q = hcidx_skip_ws (q);

    unsigned long long boff = strtoull (q, &endp, 10);
    if (endp == q) { hcfree (entries); hcfree (buf); return 0; }
    q = hcidx_skip_ws (endp);
    if (*q != ']') { hcfree (entries); hcfree (buf); return 0; }
    q++;

    entries[ei].word_idx = (u64) widx;
    entries[ei].byte_off = (u64) boff;
    ei++;
  }

  hdr.entry_count = ei;

  hcfree (buf);

  if (ei == 0)
  {
    hcfree (entries);
    return 0;
  }

  idx->loaded  = true;
  idx->header  = hdr;
  idx->entries = entries;

  return 0;
}

bool hcidx_lookup (const hcidx_t *idx, const u64 target_word, u64 *byte_off, u64 *word_idx)
{
  if (idx == NULL || idx->loaded == false) return false;
  if (idx->header.entry_count == 0)        return false;

  // Binary search for the largest entry with word_idx <= target_word.

  u64 lo = 0;
  u64 hi = idx->header.entry_count - 1;
  bool found = false;
  u64 best = 0;

  if (idx->entries[0].word_idx > target_word) return false; // target before first checkpoint

  while (lo <= hi)
  {
    const u64 mid = lo + (hi - lo) / 2;

    if (idx->entries[mid].word_idx <= target_word)
    {
      best  = mid;
      found = true;
      if (mid == idx->header.entry_count - 1) break;
      lo = mid + 1;
    }
    else
    {
      if (mid == 0) break;
      hi = mid - 1;
    }
  }

  if (found == false) return false;

  *byte_off = idx->entries[best].byte_off;
  *word_idx = idx->entries[best].word_idx;

  return true;
}

void hcidx_free (hcidx_t *idx)
{
  if (idx == NULL) return;

  if (idx->entries != NULL) hcfree (idx->entries);

  memset (idx, 0, sizeof (hcidx_t));
}

bool hcidx_verify_sha256 (const hcidx_t *idx, const char *dictfile, bool *checked)
{
  if (checked != NULL) *checked = false;

  if (idx == NULL || idx->loaded == false) return true;

  if ((idx->header.flags & HCIDX_FLAG_SHA256) == 0)
  {
    // Nothing stored to verify against; size check is all we have.
    return true;
  }

  u8 digest[32];

  if (hcidx_sha256_file (dictfile, digest) != 0) return false;

  if (checked != NULL) *checked = true;

  return memcmp (digest, idx->header.sha256, 32) == 0;
}

// ---------------------------------------------------------------------------
// building
// ---------------------------------------------------------------------------

bool hcidx_should_build (const u64 file_size, const u64 skip, const u64 limit, const char *index_path)
{
  // "Use mode": an explicit index path means do not build.
  if (index_path != NULL) return false;

  // Only worth it for large files.
  if (file_size < HCIDX_MIN_FILE_SIZE) return false;

  // Only worth it when a skip/limit window is in effect (chunked run, the case
  // where future chunks/agents will reuse the index).
  if (skip == 0 && limit == 0) return false;

  return true;
}

int hcidx_builder_begin (hcidx_builder_t *b, const char *dictfile, const u64 file_size, const u64 interval, const bool want_sha256)
{
  memset (b, 0, sizeof (hcidx_builder_t));

  b->path = hcidx_default_path (dictfile);

  // Include PID in the tmp suffix so two concurrent hashcat instances
  // racing to build the same .hcidx (e.g. multiple hashtopolis agents on a
  // shared filesystem) cannot clobber each other's in-flight tmp file.
  const size_t tmplen = strlen (b->path) + 32;
  b->tmp_path = (char *) hcmalloc (tmplen);
  snprintf (b->tmp_path, tmplen, "%s.tmp.%d", b->path, (int) getpid ());

  b->interval        = (interval > 0) ? interval : HCIDX_DEFAULT_INTERVAL;
  b->next_checkpoint = 0;        // record a checkpoint at word 0
  b->entry_count     = 0;
  b->entry_avail     = 4096;
  b->entries         = (hcidx_entry_t *) hccalloc (b->entry_avail, sizeof (hcidx_entry_t));
  b->word_count      = 0;
  b->file_size       = file_size;
  b->want_sha256     = want_sha256;
  b->active          = true;

  return 0;
}

int hcidx_builder_offer (hcidx_builder_t *b, const u64 word_idx, const u64 byte_off)
{
  if (b == NULL || b->active == false) return 0;

  b->word_count = word_idx + 1;

  if (word_idx < b->next_checkpoint) return 0;

  if (b->entry_count == b->entry_avail)
  {
    const u64 old = b->entry_avail;
    b->entry_avail *= 2;
    b->entries = (hcidx_entry_t *) hcrealloc (b->entries, old * sizeof (hcidx_entry_t), (b->entry_avail - old) * sizeof (hcidx_entry_t));
  }

  b->entries[b->entry_count].word_idx = word_idx;
  b->entries[b->entry_count].byte_off = byte_off;

  b->entry_count++;
  b->next_checkpoint = word_idx + b->interval;

  return 0;
}

int hcidx_builder_finalize (hcidx_builder_t *b, const u64 total_words, const bool complete, const bool keep_partial)
{
  if (b == NULL || b->active == false) return 0;

  if (complete == false && keep_partial == false)
  {
    // Run ended before the whole file was scanned: discard rather than publish
    // a partial index labelled as whole-file.
    hcidx_builder_abort (b);
    return 0;
  }

  hcidx_header_t hdr;
  memset (&hdr, 0, sizeof (hdr));

  hdr.version     = HCIDX_VERSION;
  hdr.flags       = complete ? HCIDX_FLAG_WHOLE_FILE : 0;
  hdr.interval    = b->interval;
  hdr.word_count  = (total_words > 0) ? total_words : b->word_count;
  hdr.file_size   = b->file_size;
  hdr.entry_count = b->entry_count;

  if (b->want_sha256)
  {
    // Optional cross-host integrity. The wordlist path is the index path minus
    // the suffix. Costs a full read, so only done when explicitly requested.
    const size_t plen = strlen (b->path);
    const size_t slen = strlen (HCIDX_SUFFIX);

    if (plen > slen)
    {
      char *dictfile = hcstrdup (b->path);
      dictfile[plen - slen] = 0;

      u8 digest[32];

      if (hcidx_sha256_file (dictfile, digest) == 0)
      {
        memcpy (hdr.sha256, digest, 32);
        hdr.flags |= HCIDX_FLAG_SHA256;
      }

      hcfree (dictfile);
    }
  }

  // Write JSON to the tmp file, then atomically rename into place. A process
  // that dies before the rename leaves only the orphaned tmp, never a
  // half-written .hcidx that would validate.

  FILE *fp = fopen (b->tmp_path, "w");

  if (fp == NULL)
  {
    hcidx_builder_abort (b);
    return -1;
  }

  fprintf (fp, "{\n");
  fprintf (fp, "  \"version\": %u,\n",            hdr.version);
  fprintf (fp, "  \"flags\": %u,\n",              hdr.flags);
  fprintf (fp, "  \"interval\": %" PRIu64 ",\n",  hdr.interval);
  fprintf (fp, "  \"word_count\": %" PRIu64 ",\n",hdr.word_count);
  fprintf (fp, "  \"file_size\": %" PRIu64 ",\n", hdr.file_size);

  if (hdr.flags & HCIDX_FLAG_SHA256)
  {
    fprintf (fp, "  \"sha256\": \"");
    for (int i = 0; i < 32; i++) fprintf (fp, "%02x", hdr.sha256[i]);
    fprintf (fp, "\",\n");
  }
  else
  {
    fprintf (fp, "  \"sha256\": null,\n");
  }

  fprintf (fp, "  \"entries\": [");

  if (b->entry_count == 0)
  {
    fprintf (fp, "]\n");
  }
  else
  {
    fprintf (fp, "\n");
    for (u64 i = 0; i < b->entry_count; i++)
    {
      fprintf (fp, "    [%" PRIu64 ", %" PRIu64 "]%s\n",
               b->entries[i].word_idx,
               b->entries[i].byte_off,
               (i + 1 < b->entry_count) ? "," : "");
    }
    fprintf (fp, "  ]\n");
  }

  fprintf (fp, "}\n");

  if (ferror (fp))
  {
    fclose (fp);
    hcidx_builder_abort (b);
    return -1;
  }

  fflush (fp);
  fclose (fp);

  if (rename (b->tmp_path, b->path) != 0)
  {
    unlink (b->tmp_path);
    hcfree (b->entries);
    hcfree (b->path);
    hcfree (b->tmp_path);
    memset (b, 0, sizeof (hcidx_builder_t));
    return -1;
  }

  hcfree (b->entries);
  hcfree (b->path);
  hcfree (b->tmp_path);
  memset (b, 0, sizeof (hcidx_builder_t));

  return 0;
}

void hcidx_builder_abort (hcidx_builder_t *b)
{
  if (b == NULL || b->active == false) return;

  if (b->tmp_path != NULL) unlink (b->tmp_path);

  hcfree (b->entries);
  hcfree (b->path);
  hcfree (b->tmp_path);

  memset (b, 0, sizeof (hcidx_builder_t));
}
