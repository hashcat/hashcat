/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_WORDLIST_INDEX_H
#define HC_WORDLIST_INDEX_H

#include <stdio.h>
#include <stdbool.h>

// Wordlist seek index (.hcidx).
//
// Maps base-word positions to byte offsets in the wordlist so that a large
// --skip can fseek() close to the target instead of reading and counting
// every line from the start of the file. Entries are sparse: one checkpoint
// every HCIDX_DEFAULT_INTERVAL base words. A lookup binary-searches for the
// largest checkpoint <= the requested base-word, seeks there, and the caller
// walks forward at most (interval - 1) words to land exactly on the target.
//
// On-disk format is JSON (inspectable with cat/jq), shape:
//   { "version": 1, "flags": 0, "interval": 1000000, "word_count": N,
//     "file_size": B, "sha256": null | "<64-hex>",
//     "entries": [[idx, off], [idx, off], ...] }
//
// Validation is intentionally cheap: only the wordlist size is checked at load
// time (an O(1) stat), never mtime (unreliable across copies / clock skew).
// An optional SHA-256 of the wordlist may be stored for callers that cross a
// trust boundary (e.g. an index built on one host and shipped to another by a
// distribution layer such as hashtopolis); it is verified only on request, not
// on every run, because hashing the whole file would reintroduce the very scan
// this index removes.

#define HCIDX_VERSION           1
#define HCIDX_SUFFIX            ".hcidx"

#define HCIDX_FLAG_SHA256       (1u << 0)         // sha256 field is populated
#define HCIDX_FLAG_WHOLE_FILE   (1u << 1)         // index covers the entire file

// One checkpoint every this many *base words*. Keeps the index tiny: a 1e9-word
// list produces ~1000 entries.
#define HCIDX_DEFAULT_INTERVAL  1000000

// Do not bother building an index for files smaller than this; the linear seek
// is already cheap and the .hcidx write would just be overhead.
#define HCIDX_MIN_FILE_SIZE     (256 * 1024 * 1024)   // 256 MiB

typedef struct hcidx_header
{
  u32 version;
  u32 flags;
  u64 interval;       // base words between checkpoints
  u64 word_count;     // total base words (whole-file) or covered (partial)
  u64 file_size;      // wordlist size in bytes - cheap validation
  u8  sha256[32];     // optional (flags & HCIDX_FLAG_SHA256); else zeroed
  u64 entry_count;

} hcidx_header_t;

typedef struct hcidx_entry
{
  u64 word_idx;       // base-word position of this checkpoint
  u64 byte_off;       // byte offset in the wordlist of that word

} hcidx_entry_t;

typedef struct hcidx
{
  bool             loaded;
  hcidx_header_t   header;
  hcidx_entry_t   *entries;

} hcidx_t;

// Builder: accumulates checkpoints while the caller walks the file, then writes
// the .hcidx atomically (tmp + rename) on finalize. The builder records a
// checkpoint only at the start of a line, i.e. immediately after a base word
// boundary, so the stored byte offset is safe to fseek() to.
typedef struct hcidx_builder
{
  bool             active;
  char            *path;          // final .hcidx path
  char            *tmp_path;      // path + ".tmp"
  u64              interval;
  u64              next_checkpoint; // next base-word idx to record at
  u64              entry_count;
  u64              entry_avail;    // allocated capacity
  hcidx_entry_t   *entries;       // buffered in memory; sparse, so tiny
  u64              word_count;     // base words seen so far
  u64              file_size;
  bool             want_sha256;

} hcidx_builder_t;

// --- loading / lookup -------------------------------------------------------

// Load and validate an index for `dictfile`. `index_path` may be NULL, in which
// case `dictfile` + ".hcidx" is used. Returns 0 on success with idx->loaded set,
// or a negative value on hard error. A missing or size-mismatched index is NOT
// an error: idx->loaded stays false and 0 is returned so the caller silently
// falls back to a linear seek.
int  hcidx_load (hcidx_t *idx, const char *dictfile, const char *index_path);

// Find the best checkpoint at or before `target_word`. On success sets
// *byte_off and *word_idx to that checkpoint and returns true; the caller seeks
// to *byte_off and walks forward (target_word - *word_idx) base words. Returns
// false if no usable checkpoint exists (target before the first one).
bool hcidx_lookup (const hcidx_t *idx, const u64 target_word, u64 *byte_off, u64 *word_idx);

void hcidx_free (hcidx_t *idx);

// Optional integrity check across a trust boundary. Reads the whole wordlist,
// so callers must opt in explicitly. Returns true if the stored SHA-256 matches
// (or if no SHA-256 is stored, in which case nothing can be verified and the
// caller should rely on the size check alone -> returns true with *checked=false).
bool hcidx_verify_sha256 (const hcidx_t *idx, const char *dictfile, bool *checked);

// --- building ---------------------------------------------------------------

// Decide whether building makes sense for this run. True only when the file is
// large enough and a skip/limit window is in effect (the chunked case where the
// index actually pays off). `index_path` non-NULL ("use mode") disables build.
bool hcidx_should_build (const u64 file_size, const u64 skip, const u64 limit, const char *index_path);

int  hcidx_builder_begin (hcidx_builder_t *b, const char *dictfile, const u64 file_size, const u64 interval, const bool want_sha256);

// Offer the byte offset at the start of base word `word_idx`. Cheap no-op unless
// `word_idx` has reached the next checkpoint boundary. `byte_off` must be the
// offset of the *start of the line* for that word.
int  hcidx_builder_offer (hcidx_builder_t *b, const u64 word_idx, const u64 byte_off);

// Finalize: write header (entry_count now known) and rename into place. If
// `complete` is false (run ended before the whole file was scanned) the partial
// tmp file is discarded rather than published, unless `keep_partial` is set.
int  hcidx_builder_finalize (hcidx_builder_t *b, const u64 total_words, const bool complete, const bool keep_partial);

void hcidx_builder_abort (hcidx_builder_t *b);

#endif // HC_WORDLIST_INDEX_H
