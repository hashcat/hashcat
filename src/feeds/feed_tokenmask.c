/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// The token mask feed. It reads a mask the way a brute force attack does, one position per token of
// the mask, but a position's charset is a set of STRINGS rather than a set of bytes. A built-in like
// ?l is still the 26 lowercase letters, each a one byte token. A custom charset ?1 to ?8 is a file
// whose lines are the tokens, so ?1?1 over a file holding "test" spells "testtest". That is what lets
// a position carry a multibyte character, a whole word, or any other string a byte charset cannot.
//
// A mask value is therefore no longer a fixed length: two tokens of one position can differ in length,
// so the candidate a position index spells can be longer or shorter than its neighbour. Everything a
// byte mask takes for granted about length is handled here instead, in the one place the length is
// known: a candidate that falls outside the hash mode's pw_min and pw_max is a position the feed holds
// but rejects, which is GENERIC_RC_SKIP, so the position stays the same candidate on every run and
// --skip, --limit and a restore keep working.
//
// THE KEYSPACE IS AN ODOMETER. Candidate number N is a pure function of N: the rightmost position runs
// fastest, each position a digit over its own token count, exactly as a byte mask counts. So the
// keyspace is the product of the per position token counts, counted in 128 bits because a mask of
// several large token files passes 2^64 easily, and a seek is an assignment with no replay.
//
// A CHARSET IS LOADED ONCE. ?1?1 names one charset twice, so the file behind it is read once and both
// positions share it, which is what keeps a mask over a large token file from loading it per position.
// A built-in and a literal are shared the same way.
//
// WHAT A CUSTOM CHARSET MAY BE. A value that names a file is that file, its lines the tokens. A value
// that does not is an inline charset read the way hashcat's own -1 to -8 are: ?l through ?H and ?1
// through ?8 expand, ?? is a literal question mark, and every other run is bytes, two hex digits to a
// byte under --hex-charset and one byte each without it. A ?N inside an inline charset pulls in that
// charset's tokens, so an inline set may name a file's multibyte tokens as well as its own bytes.
//
// A fast hash runs on the card through the PCFG device engine, the same infrastructure the PCFG and
// table attacks use: the mask's trailing positions are walked in the kernel and only its leading ones
// are produced on the host. A slow hash, --stdout and --slow-candidates run the host engine instead.

#include "common.h"
#include "types.h"
#include "memory.h"
#include "convert.h"
#include "filehandling.h"
#include "paw64.h"
#include "feed.h"

#include "feed_error.h"

// The most positions a mask may have. A candidate is at least one byte per position, so a mask longer
// than PW_MAX could never produce a candidate the hash mode accepts anyway.

#define TM_POS_MAX PW_MAX

// The longest one token may be. A token longer than a candidate can be is a token no candidate can
// hold, so it is refused when the charset is read rather than skipped on every position it reaches.

#define TM_TOKEN_MAX PW_MAX

// How many distinct charsets a run may hold. Every position names one, and an inline charset may name
// up to the eight custom charsets on top of that, so the mask's positions plus the eight is the bound.

#define TM_CS_MAX (TM_POS_MAX + 8)

// How deep an inline charset's ?N references may nest before it is called a cycle. A reference that
// comes back to a charset still being read is caught directly. This is the backstop for a chain that
// never does but is absurd anyway.

#define TM_DEPTH_MAX 8

typedef enum tm_cs_kind
{
  TM_CS_BUILTIN = 0, // ?l ?u ?d ?s ?a ?b ?h ?H, keyed by the letter
  TM_CS_LITERAL = 1, // one byte of the mask, keyed by the byte
  TM_CS_CUSTOM  = 2, // -1 to -8 or c1= to c8=, keyed by the value string

} tm_cs_kind_t;

// One charset: a bucket of tokens kept as bytes in an arena, with an offset table so a token is a span
// of it rather than a pointer, because the arena moves as it grows. off has cnt + 1 entries and
// off[cnt] is the arena length, so token i is the bytes from off[i] to off[i + 1]. The kind and its key
// are what two positions are matched on so that one charset is read once.

typedef struct tm_charset
{
  u8  *arena;
  u64  arena_len;
  u64  arena_alloc;

  u32 *off;
  u32  cnt;
  u32  alloc;

  u32  min_len;
  u32  max_len;

  tm_cs_kind_t  kind;
  u32           ival; // TM_CS_BUILTIN letter, TM_CS_LITERAL byte
  const char   *sval; // TM_CS_CUSTOM value, borrowed from the arguments

  // Set while this charset is being read, so an inline ?N that comes back to it is a cycle rather than
  // an endless recursion.

  bool resolving;

  // Where this charset's tokens sit in the device pool, for a position that draws from it on the device
  // engine. Set only for a charset a cell slot reaches: a charset only the host front reads stays in
  // the arena and never enters the pool, so a large token file named by a front position costs no pool.
  // It is the u32 index of the charset's offset table in the pool, as a pcfg_slot_t's pool_off is.

  u32  pool_off;
  bool in_pool;

} tm_charset_t;

// One mask of the run. --increment runs a mask at every length, so a run is a list of these laid end
// to end. Candidate number N and base word number N both fall in whichever mask's range holds them.
// cand_base and unit_base are where each mask's range begins, so a position is routed to a mask by
// where it lands.

typedef struct tm_mask
{
  // Position i draws from charset pos_cs[i]. The charsets themselves live once in the global store and
  // are shared by every mask that names them.

  u32 pos_cs[TM_POS_MAX];
  u32 pos_cnt;

  // The product of the per position token counts, the candidates this mask spells, and where this
  // mask's candidates begin in the whole run.

  u128 keyspace;
  u128 cand_base;

  // The mask as text, for the status line.

  char text[256];

  // ---- device engine, per mask ----

  // Every candidate is a finished word the card only hashes, because this mask's candidates are too
  // long for the cell buffer or could be shorter than the hash mode's minimum.

  bool dev_hostonly;

  // The split: the first front_cnt positions are written into the base word on the host, the last
  // cell_cnt are the device cell. units is the product of the front radices, cell_rect the product of
  // the cell radices, and unit_base where this mask's base words begin in the whole run.

  u32  front_cnt;
  u32  cell_cnt;
  u32  cell_rect;
  u128 units;
  u128 unit_base;

  pcfg_cell_t cell_tmpl;
  u32         front_minlen;

} tm_mask_t;

typedef struct tm_global
{
  // kept for feed_say (), which is the only place a feed says anything and needs it

  hashcat_ctx_t *hcctx;

  // Everything an inline charset's ?N reference needs to resolve another charset, so the resolver does
  // not carry them through every call.

  const user_options_t *user_options;
  const char           *cparam[8];
  bool                  hex;

  tm_charset_t cs[TM_CS_MAX];
  u32          cs_cnt;

  // The masks, laid end to end, and what they come to together. keyspace is every candidate, units
  // every base word on the device engine.

  tm_mask_t *masks;
  u32        mask_cnt;
  u32        mask_alloc;

  u128 keyspace;
  u128 units;

  // The lengths this hash mode accepts. A candidate outside them is spelled, measured and rejected, so
  // the position is spent as a skip rather than emitted. pwmax 0 means the run never said and then only
  // the candidate buffer bounds the length.

  u32 pwmin;
  u32 pwmax;

  // ---------------------------------------------------------------------------------------------
  // device engine (the PCFG infra, reused), the parts shared by every mask
  // ---------------------------------------------------------------------------------------------

  // Whether hashcat drives this feed through the device engine, settled before global_init () runs. When
  // it does, the feed counts base words rather than candidates and hands each one to the card as a cell,
  // so no candidate crosses the host boundary and a fast hash is not starved by the PCIe bus.

  bool dev;

  u32 *pool;
  u64  pool_cnt; // in u32
  bool varlen;

  u32  il_cnt;
  u32  maxword;
  u32  maxbyte;

  // the mean cell over the whole run, which is what the status line scales base words into candidates by

  u32  dev_mean;

} tm_global_t;

// One position in the run, which is all a thread carries because a token mask has no state to rebuild:
// the candidate is a function of the position alone.

typedef struct tm_thread
{
  u128 pos;

} tm_thread_t;

// Append one token to a charset, growing the arena and the offset table as needed. The offset table is
// sized to hold the sentinel off[cnt] as well, which tm_cs_finish () writes.

static void tm_cs_add (tm_charset_t *cs, const u8 *buf, const u32 len)
{
  if ((cs->arena_len + len) > cs->arena_alloc)
  {
    u64 want = (cs->arena_alloc == 0) ? 4096 : (cs->arena_alloc * 2);

    want = MAX (want, cs->arena_len + len);

    cs->arena = (u8 *) hcrealloc (cs->arena, cs->arena_alloc, want - cs->arena_alloc);

    cs->arena_alloc = want;
  }

  if ((cs->cnt + 2) > cs->alloc)
  {
    const u32 want = (cs->alloc == 0) ? 64 : (cs->alloc * 2);

    cs->off = (u32 *) hcrealloc (cs->off, cs->alloc * sizeof (u32), (want - cs->alloc) * sizeof (u32));

    cs->alloc = want;
  }

  cs->off[cs->cnt] = (u32) cs->arena_len;

  for (u32 i = 0; i < len; i++) cs->arena[cs->arena_len + i] = buf[i];

  cs->arena_len += len;

  cs->cnt++;

  cs->min_len = MIN (cs->min_len, len);
  cs->max_len = MAX (cs->max_len, len);
}

// The sentinel, written once the bucket is complete, so every token including the last is a span to the
// next offset.

static void tm_cs_finish (tm_charset_t *cs)
{
  if ((cs->cnt + 1) > cs->alloc)
  {
    const u32 want = cs->alloc + 1;

    cs->off = (u32 *) hcrealloc (cs->off, cs->alloc * sizeof (u32), (want - cs->alloc) * sizeof (u32));

    cs->alloc = want;
  }

  cs->off[cs->cnt] = (u32) cs->arena_len;
}

static const u8 *tm_cs_tok (const tm_charset_t *cs, const u32 d, u32 *len)
{
  len[0] = cs->off[d + 1] - cs->off[d];

  return &cs->arena[cs->off[d]];
}

// Copy another charset's tokens onto the end of this one, which is how an inline ?N pulls in the tokens
// of the charset it names. src is a different charset and nothing writes to it here, so the pointers a
// walk of it hands back stay good for the length of the copy.

static void tm_cs_copy (tm_charset_t *dst, const tm_charset_t *src)
{
  for (u32 d = 0; d < src->cnt; d++)
  {
    u32 len = 0;

    const u8 *tok = tm_cs_tok (src, d, &len);

    tm_cs_add (dst, tok, len);
  }
}

// Append a built-in charset's bytes as one byte tokens, byte for byte what hashcat's own mask processor
// builds in mp_setup_sys (). The order matters: it is the order a digit of this position counts
// through, so it has to be the order the byte mask would have used. Returns false for a letter that is
// not a built-in, which is how the parser tells ?z from ?l.

static bool tm_cs_builtin (tm_charset_t *cs, const char key)
{
  u8 c;

  switch (key)
  {
    case 'l':

      for (c = 'a'; c <= 'z'; c++) tm_cs_add (cs, &c, 1);

      return true;

    case 'u':

      for (c = 'A'; c <= 'Z'; c++) tm_cs_add (cs, &c, 1);

      return true;

    case 'd':

      for (c = '0'; c <= '9'; c++) tm_cs_add (cs, &c, 1);

      return true;

    case 'h':

      for (c = '0'; c <= '9'; c++) tm_cs_add (cs, &c, 1);
      for (c = 'a'; c <= 'f'; c++) tm_cs_add (cs, &c, 1);

      return true;

    case 'H':

      for (c = '0'; c <= '9'; c++) tm_cs_add (cs, &c, 1);
      for (c = 'A'; c <= 'F'; c++) tm_cs_add (cs, &c, 1);

      return true;

    // ?s is every printable byte that ?l, ?u and ?d do not already cover, in ascending byte order,
    // which is the gap mp_setup_sys () walks with its donec table.

    case 's':

      for (c = 0x20; c <= 0x7e; c++)
      {
        if ((c >= 'a') && (c <= 'z')) continue;
        if ((c >= 'A') && (c <= 'Z')) continue;
        if ((c >= '0') && (c <= '9')) continue;

        tm_cs_add (cs, &c, 1);
      }

      return true;

    // ?a is every printable byte, ascending.

    case 'a':

      for (c = 0x20; c <= 0x7e; c++) tm_cs_add (cs, &c, 1);

      return true;

    // ?b is every byte there is. c <= 0xff would never end, so it counts a u32.

    case 'b':

      for (u32 b = 0x00; b <= 0xff; b++)
      {
        const u8 one = (u8) b;

        tm_cs_add (cs, &one, 1);
      }

      return true;
  }

  return false;
}

// Whether a letter names a built-in charset, without building one. The parser asks before it decides a
// ?x is an error, and tm_cs_builtin () cannot answer because it writes as it goes.

static bool tm_is_builtin (const char key)
{
  switch (key)
  {
    case 'l':
    case 'u':
    case 'd':
    case 's':
    case 'a':
    case 'b':
    case 'h':
    case 'H': return true;
  }

  return false;
}

// Decode a run of hex into bytes, two hex digits to a byte, the same conversion mp_expand () does under
// --hex-charset. Returns the byte count, or -1 for an odd length or a non hex digit.

static int tm_hex_decode (const u8 *in, const u32 in_len, u8 *out, const u32 out_max)
{
  if ((in_len % 2) != 0) return -1;

  const u32 n = in_len / 2;

  if (n > out_max) return -1;

  for (u32 i = 0; i < n; i++)
  {
    const u8 hi = in[(i * 2) + 0];
    const u8 lo = in[(i * 2) + 1];

    if ((is_valid_hex_char (hi) == false) || (is_valid_hex_char (lo) == false)) return -1;

    out[i] = (u8) ((hex_convert (hi) << 4) | hex_convert (lo));
  }

  return (int) n;
}

// Which custom charset ?1 through ?8 resolves to: the c1= through c8= setting when one was given, and
// the -1 through -8 option otherwise, so a setting overrides the option the way a feed's own settings
// are meant to.

static const char *tm_charset_value (const tm_global_t *tg, const u32 n)
{
  if (tg->cparam[n] != NULL) return tg->cparam[n];

  switch (n)
  {
    case 0: return tg->user_options->custom_charset_1;
    case 1: return tg->user_options->custom_charset_2;
    case 2: return tg->user_options->custom_charset_3;
    case 3: return tg->user_options->custom_charset_4;
    case 4: return tg->user_options->custom_charset_5;
    case 5: return tg->user_options->custom_charset_6;
    case 6: return tg->user_options->custom_charset_7;
    case 7: return tg->user_options->custom_charset_8;
  }

  return NULL;
}

static int tm_charset_get (tm_global_t *tg, const tm_cs_kind_t kind, const u32 ival, const char *sval, const u32 depth, char *err_buf, const size_t err_size);

// Read a token file: every line is one token, its trailing \r dropped and a blank line skipped. Under
// --hex-charset the line is a hex string and the token is what it decodes to, which is how a token
// carries a byte a line cannot, a newline or a null among them.

static bool tm_cs_load_file (tm_global_t *tg, tm_charset_t *cs, HCFILE *fp, const char *path, char *err_buf, const size_t err_size)
{
  u8  *buf   = NULL;
  u64  len   = 0;
  u64  alloc = 0;

  while (true)
  {
    if (len == alloc)
    {
      const u64 want = (alloc == 0) ? 65536 : (alloc * 2);

      buf = (u8 *) hcrealloc (buf, alloc, want - alloc);

      alloc = want;
    }

    const size_t got = hc_fread (&buf[len], 1, alloc - len, fp);

    if (got == 0) break;
    if (got == (size_t) -1) break;

    len += got;
  }

  u64 off = 0;

  while (off < len)
  {
    u64 end = off;

    while ((end < len) && (buf[end] != '\n')) end++;

    u64 stop = end;

    if ((stop > off) && (buf[stop - 1] == '\r')) stop--;

    const u32 line_len = (u32) (stop - off);

    if (line_len == 0)
    {
      off = end + 1;

      continue;
    }

    u8 tok[TM_TOKEN_MAX];

    u32 tok_len = 0;

    if (tg->hex == true)
    {
      const int rc = tm_hex_decode (&buf[off], line_len, tok, TM_TOKEN_MAX);

      if (rc < 0)
      {
        snprintf (err_buf, err_size, "tokenmask: a line in '%s' is not an even run of hex digits, which --hex-charset wants", path);

        hcfree (buf);

        return false;
      }

      tok_len = (u32) rc;
    }
    else
    {
      if (line_len > TM_TOKEN_MAX)
      {
        snprintf (err_buf, err_size, "tokenmask: a token in '%s' is longer than %d bytes", path, TM_TOKEN_MAX);

        hcfree (buf);

        return false;
      }

      for (u32 i = 0; i < line_len; i++) tok[i] = buf[off + i];

      tok_len = line_len;
    }

    tm_cs_add (cs, tok, tok_len);

    off = end + 1;
  }

  hcfree (buf);

  return true;
}

// Read an inline charset, the same grammar hashcat's own -1 to -8 use. ?l through ?H and ?1 through ?8
// expand, ?? is a literal question mark, and every other run is bytes, two hex digits to a byte under
// --hex-charset. A ?N copies in the tokens of that charset, which is resolved through the cache so it
// too is read once however many inline sets name it.

static bool tm_cs_expand_inline (tm_global_t *tg, tm_charset_t *cs, const char *spec, const u32 depth, char *err_buf, const size_t err_size)
{
  const u32 spec_len = (u32) strlen (spec);

  u32 i = 0;

  while (i < spec_len)
  {
    if (spec[i] == '?')
    {
      if ((i + 1) >= spec_len)
      {
        snprintf (err_buf, err_size, "tokenmask: the charset '%s' ends with a lone '?'", spec);

        return false;
      }

      const char key = spec[i + 1];

      if (key == '?')
      {
        const u8 q = '?';

        tm_cs_add (cs, &q, 1);
      }
      else if ((key >= '1') && (key <= '8'))
      {
        const u32 n = (u32) (key - '1');

        const char *val = tm_charset_value (tg, n);

        if (val == NULL)
        {
          snprintf (err_buf, err_size, "tokenmask: the charset '%s' names ?%c but no -%c or c%c= charset was given", spec, key, key, key);

          return false;
        }

        const int ref = tm_charset_get (tg, TM_CS_CUSTOM, 0, val, depth + 1, err_buf, err_size);

        if (ref < 0) return false;

        tm_cs_copy (cs, &tg->cs[ref]);
      }
      else if (tm_cs_builtin (cs, key) == false)
      {
        snprintf (err_buf, err_size, "tokenmask: unknown token '?%c' in the charset '%s'", key, spec);

        return false;
      }

      i += 2;
    }
    else if (tg->hex == true)
    {
      if (((i + 2) > spec_len) || (is_valid_hex_char ((u8) spec[i]) == false) || (is_valid_hex_char ((u8) spec[i + 1]) == false))
      {
        snprintf (err_buf, err_size, "tokenmask: the charset '%s' is not an even run of hex digits, which --hex-charset wants", spec);

        return false;
      }

      const u8 byte = (u8) ((hex_convert ((u8) spec[i]) << 4) | hex_convert ((u8) spec[i + 1]));

      tm_cs_add (cs, &byte, 1);

      i += 2;
    }
    else
    {
      const u8 byte = (u8) spec[i];

      tm_cs_add (cs, &byte, 1);

      i++;
    }
  }

  return true;
}

// A custom charset is a file when one of that name opens, its lines the tokens. Otherwise it is an
// inline set. The feed decides between them the same either-or hashcat's own -1 to -8 use.

static bool tm_cs_build_custom (tm_global_t *tg, tm_charset_t *cs, const char *val, const u32 depth, char *err_buf, const size_t err_size)
{
  HCFILE fp;

  if (hc_fopen (&fp, val, "rb") == true)
  {
    const bool rc = tm_cs_load_file (tg, cs, &fp, val, err_buf, err_size);

    hc_fclose (&fp);

    return rc;
  }

  return tm_cs_expand_inline (tg, cs, val, depth, err_buf, err_size);
}

// A charset a position names, read once and shared. A built-in is matched on its letter, a literal on
// its byte, and a custom on its value string, so ?1?1 and two literals of the same byte each share one
// charset. A match found while it is still being read is a cycle an inline ?N walked back into.

static int tm_charset_get (tm_global_t *tg, const tm_cs_kind_t kind, const u32 ival, const char *sval, const u32 depth, char *err_buf, const size_t err_size)
{
  if (depth > TM_DEPTH_MAX)
  {
    snprintf (err_buf, err_size, "tokenmask: a custom charset's ?N references nest more than %d deep", TM_DEPTH_MAX);

    return -1;
  }

  for (u32 i = 0; i < tg->cs_cnt; i++)
  {
    tm_charset_t *cs = &tg->cs[i];

    if (cs->kind != kind) continue;

    bool same = false;

    if (kind == TM_CS_CUSTOM) same = (strcmp (cs->sval, sval) == 0);
    else                      same = (cs->ival == ival);

    if (same == false) continue;

    if (cs->resolving == true)
    {
      snprintf (err_buf, err_size, "tokenmask: the custom charset '%s' references itself", sval);

      return -1;
    }

    return (int) i;
  }

  if (tg->cs_cnt >= TM_CS_MAX)
  {
    snprintf (err_buf, err_size, "tokenmask: the mask names more than %d distinct charsets", TM_CS_MAX);

    return -1;
  }

  const u32 idx = tg->cs_cnt;

  tm_charset_t *cs = &tg->cs[idx];

  cs->kind      = kind;
  cs->ival      = ival;
  cs->sval      = sval;
  cs->min_len   = 0xffffffff;
  cs->max_len   = 0;
  cs->resolving = true;

  tg->cs_cnt++;

  bool rc = true;

  if (kind == TM_CS_BUILTIN)
  {
    rc = tm_cs_builtin (cs, (char) ival);
  }
  else if (kind == TM_CS_LITERAL)
  {
    const u8 byte = (u8) ival;

    tm_cs_add (cs, &byte, 1);
  }
  else
  {
    rc = tm_cs_build_custom (tg, cs, sval, depth, err_buf, err_size);
  }

  if (rc == false) return -1;

  tm_cs_finish (cs);

  if (cs->cnt == 0)
  {
    snprintf (err_buf, err_size, "tokenmask: the charset '%s' is empty", (kind == TM_CS_CUSTOM) ? sval : "");

    return -1;
  }

  cs->resolving = false;

  return (int) idx;
}

// Read the mask into positions. A ? begins a token: ?? is a literal question mark, ?l through ?H are
// the built-ins, ?1 through ?8 are the custom charsets, and anything else is an error. Every other byte
// of the mask is a literal of its own. Each position is resolved to a charset through the cache, so the
// charset behind it is read once.

static bool tm_parse (tm_global_t *tg, tm_mask_t *m, const char *mask, char *err_buf, const size_t err_size)
{
  const u32 mask_len = (u32) strlen (mask);

  m->pos_cnt = 0;

  snprintf (m->text, sizeof (m->text), "%s", mask);

  u32 i = 0;

  while (i < mask_len)
  {
    if (m->pos_cnt >= TM_POS_MAX)
    {
      snprintf (err_buf, err_size, "tokenmask: the mask has more than %d positions", TM_POS_MAX);

      return false;
    }

    int cs = -1;

    if (mask[i] != '?')
    {
      cs = tm_charset_get (tg, TM_CS_LITERAL, (u8) mask[i], NULL, 0, err_buf, err_size);

      i++;
    }
    else
    {
      if ((i + 1) >= mask_len)
      {
        snprintf (err_buf, err_size, "tokenmask: the mask ends with a lone '?'");

        return false;
      }

      const char key = mask[i + 1];

      if (key == '?')
      {
        cs = tm_charset_get (tg, TM_CS_LITERAL, (u8) '?', NULL, 0, err_buf, err_size);
      }
      else if ((key >= '1') && (key <= '8'))
      {
        const u32 n = (u32) (key - '1');

        const char *val = tm_charset_value (tg, n);

        if (val == NULL)
        {
          snprintf (err_buf, err_size, "tokenmask: the mask names ?%c but no -%c or c%c= charset was given", key, key, key);

          return false;
        }

        cs = tm_charset_get (tg, TM_CS_CUSTOM, 0, val, 0, err_buf, err_size);
      }
      else if (tm_is_builtin (key) == true)
      {
        cs = tm_charset_get (tg, TM_CS_BUILTIN, (u8) key, NULL, 0, err_buf, err_size);
      }
      else
      {
        snprintf (err_buf, err_size, "tokenmask: unknown mask token '?%c'", key);

        return false;
      }

      i += 2;
    }

    if (cs < 0) return false;

    m->pos_cs[m->pos_cnt] = (u32) cs;

    m->pos_cnt++;
  }

  if (m->pos_cnt == 0)
  {
    snprintf (err_buf, err_size, "tokenmask: the mask is empty");

    return false;
  }

  return true;
}

// The product of a mask's per position token counts, saturating to GENERIC_KEYSPACE_UNKNOWN_U128 where
// it passes a u128, which hashcat runs without a denominator rather than on a wrapped one.

static void tm_keyspace (const tm_global_t *tg, tm_mask_t *m)
{
  u128 ks = 1;

  for (u32 i = 0; i < m->pos_cnt; i++)
  {
    const u32 radix = tg->cs[m->pos_cs[i]].cnt;

    if (overflow_check_u128_mul (ks, radix) == true)
    {
      m->keyspace = GENERIC_KEYSPACE_UNKNOWN_U128;

      return;
    }

    ks = ks * radix;
  }

  m->keyspace = ks;
}

// What the whole run is, as one number, so the brain tells two runs apart when their inputs differ.
// Every mask, its positions, the charset each draws from and every token byte go into it, in order,
// because any of them changing is a different set of candidates in a different sequence.

static u64 tm_source_ident (const tm_global_t *tg)
{
  paw64_ctx_t state;

  paw64_init (&state, 0);

  paw64_update (&state, &tg->mask_cnt, sizeof (tg->mask_cnt));

  for (u32 mi = 0; mi < tg->mask_cnt; mi++)
  {
    const tm_mask_t *m = &tg->masks[mi];

    paw64_update (&state, &m->pos_cnt, sizeof (m->pos_cnt));

    for (u32 i = 0; i < m->pos_cnt; i++)
    {
      const tm_charset_t *cs = &tg->cs[m->pos_cs[i]];

      paw64_update (&state, &cs->cnt, sizeof (cs->cnt));
      paw64_update (&state, cs->arena, cs->arena_len);
    }
  }

  return paw64_final (&state);
}

// Find the mask a candidate or base word falls in, by its cumulative base. A linear scan, because a run
// has a handful of masks and the position asked for usually sits in the same one as the last.

static const tm_mask_t *tm_mask_at (const tm_global_t *tg, const u128 pos, const bool dev, u128 *local)
{
  for (u32 mi = tg->mask_cnt; mi > 0; mi--)
  {
    const tm_mask_t *m = &tg->masks[mi - 1];

    const u128 base = (dev == true) ? m->unit_base : m->cand_base;

    if (pos >= base)
    {
      local[0] = pos - base;

      return m;
    }
  }

  return NULL;
}

// ---------------------------------------------------------------------------------------------
// device engine (the PCFG infra, reused)
// ---------------------------------------------------------------------------------------------

// The pool the card reads, page aligned and zeroed because Metal and OpenCL want a whole number of
// pages and the padding is read as pool bytes. The same shape table_pool_alloc () uses.

static u32 *tm_pool_alloc (const u64 words)
{
  const u64 bytes = ((words * 4) + (PCFG_POOL_ALIGN - 1)) & ~((u64) (PCFG_POOL_ALIGN - 1));

  u32 *p = (u32 *) hc_alloc_aligned (PCFG_POOL_ALIGN, bytes);

  if (p == NULL) return NULL;

  memset (p, 0, bytes);

  return p;
}

// Lay the cell charsets into the pool, in the one of two shapes the kernel was built for. With tokens
// of one length a slot names the byte offset of its first token and multiplies. With tokens of several
// it names the u32 index of an offset table and a token's length is the difference to the next offset,
// which is what the sentinel after each charset is for. Only a charset a cell slot reaches is laid
// down, because the front charsets are written on the host and never read by the card, so a large token
// file named by a front position costs no device memory.

static bool tm_pool_build (tm_global_t *tg, char *err_buf, const size_t err_size)
{
  u64 idx_cnt = 1; // word 0 is left out so that a pool_off of zero is never a real charset
  u64 bytes   = 0;

  for (u32 i = 0; i < tg->cs_cnt; i++)
  {
    if (tg->cs[i].in_pool == false) continue;

    idx_cnt += tg->cs[i].cnt + 1;
    bytes   += tg->cs[i].arena_len;
  }

  tg->pool_cnt = idx_cnt + ((bytes + 3) / 4);

  if (tg->pool_cnt > (0xffffffffULL / 4))
  {
    snprintf (err_buf, err_size, "tokenmask: the token pool needs %" PRIu64 " bytes and an offset into it is a 32 bit number", tg->pool_cnt * 4);

    return false;
  }

  tg->pool = tm_pool_alloc (tg->pool_cnt);

  if (tg->pool == NULL)
  {
    snprintf (err_buf, err_size, "tokenmask: the host has no memory for a %" PRIu64 " byte token pool", tg->pool_cnt * 4);

    return false;
  }

  u8 *pb = (u8 *) tg->pool;

  u64 at  = idx_cnt * 4;
  u64 idx = 1;

  for (u32 i = 0; i < tg->cs_cnt; i++)
  {
    tm_charset_t *cs = &tg->cs[i];

    if (cs->in_pool == false) continue;

    cs->pool_off = (u32) idx;

    for (u32 d = 0; d < cs->cnt; d++)
    {
      tg->pool[idx] = (u32) at;

      idx++;

      u32 len = 0;

      const u8 *tok = tm_cs_tok (cs, d, &len);

      for (u32 k = 0; k < len; k++) pb[at + k] = tok[k];

      at += len;
    }

    tg->pool[idx] = (u32) at;

    idx++;
  }

  return true;
}

// The shortest and longest candidate a mask can spell, the sums of its positions' shortest and longest
// tokens. The candidate buffer is sized against the longest and a mask that can make nothing against the
// shortest.

static void tm_mask_minmax (const tm_global_t *tg, const tm_mask_t *m, u64 *min_cand, u64 *max_cand)
{
  u64 lo = 0;
  u64 hi = 0;

  for (u32 i = 0; i < m->pos_cnt; i++)
  {
    lo += tg->cs[m->pos_cs[i]].min_len;
    hi += tg->cs[m->pos_cs[i]].max_len;
  }

  min_cand[0] = lo;
  max_cand[0] = hi;
}

// The cell a base word of this mask hands the card: one slot per cell position, each a byte bucket the
// odometer reads an entry of. The cell writes its positions after the base word, so slots[0] carries
// where that writing begins, which is the base word length. The kernel runs the running write offset
// from there, and FROM in each slot's packed word is the slot itself, so a carry rewrites from the slot
// that moved on. slots[0]'s offset here is the shortest base word, a real one, for the probe.
// thread_next_dev () patches it to the true length per base word.

static void tm_mask_cell (const tm_global_t *tg, tm_mask_t *m)
{
  pcfg_cell_t *cell = &m->cell_tmpl;

  memset (cell, 0, sizeof (pcfg_cell_t));

  if (m->dev_hostonly == true)
  {
    cell->rect     = 1;
    cell->slot_cnt = 0;

    return;
  }

  cell->rect     = m->cell_rect;
  cell->slot_cnt = m->cell_cnt;
  cell->flags    = PCFG_CELL_VARLEN;

  for (u32 j = 0; j < m->cell_cnt; j++)
  {
    const tm_charset_t *cs = &tg->cs[m->pos_cs[m->front_cnt + j]];

    const u32 dst_off = (j == 0) ? m->front_minlen : 0;

    cell->slots[j].pool_off = cs->pool_off;
    cell->slots[j].radix    = cs->cnt;
    cell->slots[j].digit    = 0;
    cell->slots[j].packed   = ((dst_off & 0xff) << 8) | (PCFG_SLOT_KIND_BYTES << 16) | ((j & 0xff) << 24);
  }
}

// Split one mask into the base word the host writes and the cell the card walks, using the candidate
// buffer width and inner loop tm_dev_build () settled for the whole run. A mask whose candidates are
// too long for the buffer, or could be shorter than the hash mode's minimum, cannot use the cell at
// all: the card is given the base word and hashcat judges that against the mode's bounds before the
// cell runs, so such a mask is enumerated in full on the host, each candidate a finished word the card
// only hashes. Marks the cell charsets so the pool holds them.

static void tm_mask_split (tm_global_t *tg, tm_mask_t *m)
{
  u64 min_cand = 0;
  u64 max_cand = 0;

  tm_mask_minmax (tg, m, &min_cand, &max_cand);

  m->dev_hostonly = ((max_cand > (u64) tg->maxbyte) || (min_cand < (u64) tg->pwmin));

  if (m->dev_hostonly == true)
  {
    m->front_cnt = m->pos_cnt;
    m->cell_cnt  = 0;
    m->cell_rect = 1;
    m->units     = m->keyspace;

    return;
  }

  // The cell is the longest suffix of positions whose product fits both the inner loop and the slot
  // count. The suffix is what keeps the device odometer in step with the host one: the full position is
  // unit * cell_rect + il_pos, and decomposing it names the same candidate either side.

  u32 cell_cnt  = 0;
  u64 cell_rect = 1;

  for (int i = (int) m->pos_cnt - 1; (i >= 0) && (cell_cnt < PCFG_DEV_MAXSLOT); i--)
  {
    const u32 radix = tg->cs[m->pos_cs[i]].cnt;

    if ((cell_rect * radix) > (u64) tg->il_cnt) break;

    cell_rect *= radix;
    cell_cnt++;
  }

  m->cell_cnt  = cell_cnt;
  m->cell_rect = (u32) cell_rect;
  m->front_cnt = m->pos_cnt - cell_cnt;
  m->units     = m->keyspace / cell_rect;

  m->front_minlen = 0;

  for (u32 i = 0; i < m->front_cnt; i++) m->front_minlen += tg->cs[m->pos_cs[i]].min_len;

  for (u32 i = m->front_cnt; i < m->pos_cnt; i++) tg->cs[m->pos_cs[i]].in_pool = true;
}

// Settle the whole run on the card. Every mask's kernel is one kernel, so the candidate buffer width,
// the inner loop and the pool shape are picked once for all of them: the pool is always the varlen
// shape, because a token mask's cell writes its positions after the base word rather than over it, so
// the candidate is longer than the base word and only the varlen path returns that longer length. The
// buffer is as wide as the widest candidate a mask that can use the cell makes. Then each mask is
// split, the one shared pool is built from every cell charset, and the masks are laid end to end in base
// words so a base word number routes to a mask.

static bool tm_dev_build (tm_global_t *tg, char *err_buf, const size_t err_size)
{
  tg->varlen = true;

  // The inner loop width, the table feed's proven value. One base word's launch walks up to this many
  // candidates, and a wider loop makes that launch run longer. Past a point it trips the device's
  // watchdog and the autotuner gives up. A position whose radix passes this cannot be a cell slot and
  // stays in the front, so a mask ending in a very large charset loses its device cell. That is rare,
  // and the alternative is a launch the card will not run.

  tg->il_cnt = 1u << 20;

  // The candidate buffer width, from the widest candidate a mask that can use the cell makes. The two
  // the engine offers hold 63 and 127 bytes, and the narrower kernel is the faster of the two. A mask
  // whose candidates pass the wider buffer runs host only and does not force it wider still.

  bool need_hi = false;

  for (u32 mi = 0; mi < tg->mask_cnt; mi++)
  {
    u64 lo = 0;
    u64 hi = 0;

    tm_mask_minmax (tg, &tg->masks[mi], &lo, &hi);

    if ((hi > (u64) ((PCFG_DEV_MAXWORD_LO * 4) - 1)) && (hi <= (u64) ((PCFG_DEV_MAXWORD_HI * 4) - 1))) need_hi = true;
  }

  tg->maxword = (need_hi == true) ? PCFG_DEV_MAXWORD_HI : PCFG_DEV_MAXWORD_LO;
  tg->maxbyte = (tg->maxword * 4) - 1;

  for (u32 i = 0; i < tg->cs_cnt; i++) tg->cs[i].in_pool = false;

  for (u32 mi = 0; mi < tg->mask_cnt; mi++) tm_mask_split (tg, &tg->masks[mi]);

  if (tm_pool_build (tg, err_buf, err_size) == false) return false;

  u128 unit_base = 0;

  for (u32 mi = 0; mi < tg->mask_cnt; mi++)
  {
    tm_mask_t *m = &tg->masks[mi];

    tm_mask_cell (tg, m);

    m->unit_base = unit_base;

    if (overflow_check_u128_add (unit_base, m->units) == true)
    {
      unit_base = GENERIC_KEYSPACE_UNKNOWN_U128;
    }
    else
    {
      unit_base = unit_base + m->units;
    }
  }

  tg->units = unit_base;

  // The mean cell over the whole run, which is what the status line scales base words into candidates by.

  tg->dev_mean = (unit_base > 0) ? (u32) u128_lo (tg->keyspace / unit_base) : 1;

  if (tg->dev_mean == 0) tg->dev_mean = 1;

  return true;
}

/**
 * interface
 */

const int GENERIC_PLUGIN_VERSION = FEEDS_INTERFACE_VERSION_CURRENT;

// MASK is set because the feed reads the custom charsets -1 through -8. Without it a run that names one
// is refused. DEVICE is set because the feed can amplify on the card through the PCFG device engine,
// which is what keeps a fast hash fed. EXPLAIN is set because the feed can say which tokens made a
// candidate, which is what --debug-mode writes. ICONV and AUTOHEX are for a feed that reads lines
// someone else wrote, and this feed produces its own bytes from tokens it has already decoded.

const int GENERIC_PLUGIN_OPTIONS = GENERIC_PLUGIN_OPTIONS_MASK
                                 | GENERIC_PLUGIN_OPTIONS_DEVICE
                                 | GENERIC_PLUGIN_OPTIONS_EXPLAIN;

// A fresh mask at the end of the list, the list grown if it was full. The returned pointer is good
// until the next call, which may move the list, so it is filled before another mask is added.

static tm_mask_t *tm_mask_add (tm_global_t *tg)
{
  if (tg->mask_cnt >= tg->mask_alloc)
  {
    const u32 want = (tg->mask_alloc == 0) ? 8 : (tg->mask_alloc * 2);

    tg->masks = (tm_mask_t *) hcrealloc (tg->masks, (u64) tg->mask_alloc * sizeof (tm_mask_t), (u64) (want - tg->mask_alloc) * sizeof (tm_mask_t));

    tg->mask_alloc = want;
  }

  tm_mask_t *m = &tg->masks[tg->mask_cnt];

  memset (m, 0, sizeof (tm_mask_t));

  tg->mask_cnt++;

  return m;
}

bool global_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, hashcat_ctx_t *hashcat_ctx)
{
  tm_global_t *tg = hccalloc (1, sizeof (tm_global_t));

  global_ctx->gbldata = tg;

  tg->hcctx        = hashcat_ctx;
  tg->user_options = hashcat_ctx->user_options;
  tg->hex          = hashcat_ctx->user_options->hex_charset;

  // The masks come first and the settings after. The positional arguments run until the first key=value,
  // the same shape the other feeds take, and there may be several masks rather than one.

  int pos_end = global_ctx->workc;

  for (int i = 1; i < global_ctx->workc; i++)
  {
    if (feed_param_is_setting (global_ctx->workv[i]) == false) continue;

    pos_end = i;

    break;
  }

  if ((pos_end - 1) < 1)
  {
    error_set (global_ctx, "usage: tokenmask <mask> [pw-min=N] [pw-max=N] [c1=charset .. c8=charset]");

    return false;
  }

  // One mask is taken from the command line. The feed holds a list internally, which is what
  // --increment fills with a mask at every length.

  if ((pos_end - 1) > 1)
  {
    error_set (global_ctx, "tokenmask: only one mask is supported");

    return false;
  }

  u64 pwmin_p = 0;
  u64 pwmax_p = 0;

  const feed_param_t params[] =
  {
    { "pw-min", FEED_PARAM_TYPE_U64, &pwmin_p,       0, PW_MAX, "shortest candidate to keep, 0 for the hash mode's own minimum" },
    { "pw-max", FEED_PARAM_TYPE_U64, &pwmax_p,       0, PW_MAX, "longest candidate to keep, 0 for the hash mode's own maximum" },
    { "c1",     FEED_PARAM_TYPE_STR, &tg->cparam[0], 0, 0,      "token charset for ?1, a file of tokens or an inline set, overriding -1" },
    { "c2",     FEED_PARAM_TYPE_STR, &tg->cparam[1], 0, 0,      "token charset for ?2, overriding -2" },
    { "c3",     FEED_PARAM_TYPE_STR, &tg->cparam[2], 0, 0,      "token charset for ?3, overriding -3" },
    { "c4",     FEED_PARAM_TYPE_STR, &tg->cparam[3], 0, 0,      "token charset for ?4, overriding -4" },
    { "c5",     FEED_PARAM_TYPE_STR, &tg->cparam[4], 0, 0,      "token charset for ?5, overriding -5" },
    { "c6",     FEED_PARAM_TYPE_STR, &tg->cparam[5], 0, 0,      "token charset for ?6, overriding -6" },
    { "c7",     FEED_PARAM_TYPE_STR, &tg->cparam[6], 0, 0,      "token charset for ?7, overriding -7" },
    { "c8",     FEED_PARAM_TYPE_STR, &tg->cparam[7], 0, 0,      "token charset for ?8, overriding -8" },
    { NULL, 0, NULL, 0, 0, NULL }
  };

  if (feed_param_parse (global_ctx->workc, global_ctx->workv, params, global_ctx->error_msg, sizeof (global_ctx->error_msg)) == false)
  {
    global_ctx->error = true;

    return false;
  }

  // hashconfig_init () runs in outer_loop () before generic_ctx_init () gets here, so the hash mode's
  // own bounds are settled and a feed may read them. A pw-min or pw-max setting overrides them, for a
  // run that wants a narrower band than the hash mode allows.

  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig != NULL)
  {
    tg->pwmin = hashconfig->pw_min;
    tg->pwmax = hashconfig->pw_max;
  }

  if (pwmin_p > 0) tg->pwmin = (u32) pwmin_p;
  if (pwmax_p > 0) tg->pwmax = (u32) pwmax_p;

  // --increment runs a mask at every length rather than only its own, where a length is a number of
  // token positions and not a number of bytes, because a token mask's positions are not one byte each.
  // So ?1?1?1 under --increment is ?1, then ?1?1, then ?1?1?1. --increment-min and --increment-max bound
  // the position count. hashcat's own increment shortens a mask it holds in the mask processor, which a
  // feed does not use, so the feed reads the options and lengthens its own list here instead.

  const user_options_t *uo = hashcat_ctx->user_options;

  const bool increment = (uo->increment > 0);

  const bool inverse = (uo->increment == INCREMENT_INVERSED);

  char err[256];

  tm_mask_t base;

  u64 run_min = (u64) -1;
  u64 run_max = 0;
  u64 skipped = 0;

  const char *mask_str = global_ctx->workv[1];

  // A mask file would need a format of its own, because the one hashcat reads carries inline byte
  // charsets a token mask cannot use, so one is refused rather than read as a mask of literal bytes.

  HCFILE fp;

  if (hc_fopen (&fp, mask_str, "rb") == true)
  {
    hc_fclose (&fp);

    error_set (global_ctx, "tokenmask: '%s' is a file, and mask files are not supported; give the mask itself", mask_str);

    return false;
  }

  if (tm_parse (tg, &base, mask_str, err, sizeof (err)) == false)
  {
    error_set (global_ctx, "%s", err);

    return false;
  }

  u32 kmin = base.pos_cnt;
  u32 kmax = base.pos_cnt;

  if (increment == true)
  {
    kmin = (uo->increment_min < 1) ? 1 : uo->increment_min;
    kmax = (uo->increment_max < base.pos_cnt) ? uo->increment_max : base.pos_cnt;
  }

  for (u32 k = kmin; k <= kmax; k++)
  {
    tm_mask_t *m = tm_mask_add (tg);

    m->pos_cnt = k;

    // --increment-inverse shortens from the left rather than the right, so a length of k keeps the last k
    // positions of the mask instead of the first k. hashcat's own increment does the same for -a 3.

    const u32 off = (inverse == true) ? (base.pos_cnt - k) : 0;

    for (u32 i = 0; i < k; i++) m->pos_cs[i] = base.pos_cs[off + i];

    snprintf (m->text, sizeof (m->text), "%s", base.text);

    tm_keyspace (tg, m);

    // A token is capped at the length of one candidate when it is read, but several in a row can add up
    // past it, so a mask whose shortest candidate is already longer than a candidate may be can make
    // nothing on any hash mode and is dropped rather than left to skip every position in silence.

    u64 lo = 0;
    u64 hi = 0;

    tm_mask_minmax (tg, m, &lo, &hi);

    if (lo > PW_MAX)
    {
      tg->mask_cnt--;

      skipped++;

      continue;
    }

    m->cand_base = tg->keyspace;

    // Saturate the running total the way tm_keyspace () saturates a single mask. A sum past 128 bits is
    // reported as unknown rather than wrapped. This keeps --increment over a mask with more candidates
    // than fit from turning a real total into a small wrong one.

    if (overflow_check_u128_add (tg->keyspace, m->keyspace) == true)
    {
      tg->keyspace = GENERIC_KEYSPACE_UNKNOWN_U128;
    }
    else
    {
      tg->keyspace = tg->keyspace + m->keyspace;
    }

    if (lo < run_min) run_min = lo;
    if (hi > run_max) run_max = hi;
  }

  if (tg->mask_cnt == 0)
  {
    error_set (global_ctx, "tokenmask: no mask can make a candidate within the %d bytes a candidate may be", PW_MAX);

    return false;
  }

  if (skipped > 0)
  {
    feed_say (tg->hcctx, "tokenmask: %" PRIu64 " mask(s) dropped, their shortest candidate is longer than the %d bytes a candidate may be", skipped, PW_MAX);
  }

  // The band the whole run can spell against the band the hash mode accepts. A run that falls entirely
  // outside it is a warning rather than an error, because the same masks on another mode are fine.

  const u32 hi_b = ((tg->pwmax > 0) && (tg->pwmax < PW_MAX)) ? tg->pwmax : PW_MAX;
  const u32 lo_b = tg->pwmin;

  if ((run_min > hi_b) || (run_max < lo_b))
  {
    const u32 lo_show = (lo_b == 0) ? 1 : lo_b;

    feed_say (tg->hcctx, "tokenmask: every candidate is outside the %u to %u bytes this hash mode accepts, so all will be rejected", lo_show, hi_b);
  }

  // Whether this run amplifies on the card, settled by hashcat before global_init () from the hash mode:
  // a fast hash that would starve on host generation gets the device engine, a slow one or --stdout does
  // not. When it does, the feed counts base words and hands each one over as a cell.

  tg->dev = global_ctx->dev_enable;

  if (tg->dev == true)
  {
    if (tm_dev_build (tg, err, sizeof (err)) == false)
    {
      error_set (global_ctx, "%s", err);

      return false;
    }

    u32 host_masks = 0;

    for (u32 mi = 0; mi < tg->mask_cnt; mi++)
    {
      if (tg->masks[mi].dev_hostonly == true) host_masks++;
    }

    if (host_masks == tg->mask_cnt)
    {
      feed_say (tg->hcctx, "tokenmask: device engine, but no mask's candidates fit the cell, so each is hashed whole at host speed");
    }
    else
    {
      feed_say (tg->hcctx, "tokenmask: device engine, %u mask(s), about %u candidates per base word", tg->mask_cnt, tg->dev_mean);
    }
  }
  else
  {
    if (tg->keyspace >= GENERIC_KEYSPACE_UNKNOWN_U128)
    {
      feed_say (tg->hcctx, "tokenmask: host engine, more candidates than fit 128 bits, so the run goes without a total");
    }
    else
    {
      char cand_buf[U128_DEC_SIZE];

      feed_say (tg->hcctx, "tokenmask: host engine, %s candidates", u128_to_dec (cand_buf, tg->keyspace));
    }
  }

  global_ctx->source_ident = tm_source_ident (tg);

  if (tg->mask_cnt == 1)
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%s", tg->masks[0].text);
  }
  else
  {
    snprintf (global_ctx->guess_base, sizeof (global_ctx->guess_base), "%u masks", tg->mask_cnt);
  }

  return true;
}

void global_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  tm_global_t *tg = global_ctx->gbldata;

  if (tg == NULL) return;

  for (u32 i = 0; i < tg->cs_cnt; i++)
  {
    hcfree (tg->cs[i].arena);
    hcfree (tg->cs[i].off);
  }

  hc_free_aligned ((void **) &tg->pool);

  hcfree (tg->masks);

  hcfree (tg);

  global_ctx->gbldata = NULL;
}

// The keyspace hashcat runs against. On the device engine it is base words, because that is what a
// position is there, and the run's true length in candidates goes in dev_total_u128 so the status line
// reaches its own total exactly. On the host engine a position is a candidate, so it is the candidate
// count.

u128 global_keyspace_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, MAYBE_UNUSED generic_thread_ctx_t **thread_ctx, MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  tm_global_t *tg = global_ctx->gbldata;

  if (tg->dev == true)
  {
    global_ctx->dev_total_u128 = tg->keyspace;

    return tg->units;
  }

  return tg->keyspace;
}

bool thread_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  tm_thread_t *tt = hcmalloc (sizeof (tm_thread_t));

  if (tt == NULL)
  {
    thread_error_set (thread_ctx, "hcmalloc failed");

    return false;
  }

  tt->pos = 0;

  thread_ctx->thrdata = tt;

  return true;
}

void thread_term (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx)
{
  hcfree (thread_ctx->thrdata);

  thread_ctx->thrdata = NULL;
}

// One candidate. The position decomposes into one digit per mask position, rightmost fastest, and the
// tokens those digits name are written left to right. A candidate whose length falls outside the hash
// mode's band is a position the feed holds but rejects, GENERIC_RC_SKIP, so it stays the same candidate
// on every run and the position is still spent.

int thread_next (generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size)
{
  const tm_global_t *tg = global_ctx->gbldata;

  tm_thread_t *tt = thread_ctx->thrdata;

  if (tt->pos >= tg->keyspace) return GENERIC_RC_EOF;

  // Which mask the candidate falls in, and where in that mask. The masks are laid end to end, so a
  // candidate past the first one's keyspace is the second one's, and so on.

  u128 local = 0;

  const tm_mask_t *m = tm_mask_at (tg, tt->pos, false, &local);

  if (m == NULL) return GENERIC_RC_ERROR;

  u32 digit[TM_POS_MAX];

  u128 p = local;

  for (int i = (int) m->pos_cnt - 1; i >= 0; i--)
  {
    const u32 radix = tg->cs[m->pos_cs[i]].cnt;

    digit[i] = (u32) (p % radix);

    p = p / radix;
  }

  // The length is summed before anything is written, so a candidate that cannot land inside the band is
  // skipped without touching the buffer.

  u32 len = 0;

  for (u32 i = 0; i < m->pos_cnt; i++)
  {
    u32 tok_len = 0;

    tm_cs_tok (&tg->cs[m->pos_cs[i]], digit[i], &tok_len);

    len += tok_len;
  }

  const u32 hardcap = (u32) out_size;
  const u32 maxlen  = ((tg->pwmax > 0) && (tg->pwmax < hardcap)) ? tg->pwmax : hardcap;

  if ((len > maxlen) || (len < tg->pwmin))
  {
    tt->pos = tt->pos + 1;

    return GENERIC_RC_SKIP;
  }

  u32 w = 0;

  for (u32 i = 0; i < m->pos_cnt; i++)
  {
    u32 tok_len = 0;

    const u8 *tok = tm_cs_tok (&tg->cs[m->pos_cs[i]], digit[i], &tok_len);

    for (u32 k = 0; k < tok_len; k++) out_buf[w + k] = tok[k];

    w += tok_len;
  }

  tt->pos = tt->pos + 1;

  return (int) len;
}

bool thread_seek_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, const u128 offset)
{
  tm_thread_t *tt = thread_ctx->thrdata;

  tt->pos = offset;

  return true;
}

// What global_dev_init () worked out, handed over. Everything was settled in global_init (), where the
// hash mode's bounds and the dev_enable flag are both in hand, so this only passes the stored answers
// to hashcat and to the backend that builds the kernel.

bool global_dev_init (MAYBE_UNUSED generic_global_ctx_t *global_ctx, const u32 **pool, u64 *pool_size, u32 *il_cnt, u32 *avg, u32 *maxword, u32 *front, u32 *step, u32 *varlen, pcfg_cell_t *probe)
{
  tm_global_t *tg = global_ctx->gbldata;

  pool[0]      = tg->pool;
  pool_size[0] = tg->pool_cnt * sizeof (u32);
  il_cnt[0]    = tg->il_cnt;
  maxword[0]   = tg->maxword;
  varlen[0]    = (tg->varlen == true) ? 1 : 0;
  step[0]      = 1;

  // The mean cell over the whole run. dev_total_u128 carries the exact candidate count, so this only
  // scales the status line and need not be exact.

  avg[0]   = tg->dev_mean;
  front[0] = tg->dev_mean;

  // The autotuner searches the accel with a cell the run really emits, so it is the first mask's that
  // actually walks the pool. Where every mask is host only there is none, and the first mask's empty
  // cell stands in.

  probe[0] = tg->masks[0].cell_tmpl;

  for (u32 mi = 0; mi < tg->mask_cnt; mi++)
  {
    if (tg->masks[mi].dev_hostonly == false)
    {
      probe[0] = tg->masks[mi].cell_tmpl;

      break;
    }
  }

  return true;
}

// One base word and the cell it hands the card. The base word is the front positions written out, its
// position decomposing into one digit per front position, rightmost of them fastest, the same walk the
// host engine makes over the whole mask. The cell is the fixed one built in global_init (). Only slot
// 0's write offset depends on this base word, and only when the pool is varlen, so only then is it
// patched. One call stands for cell_rect candidates and the feed's position advances by one base word.

int thread_next_dev (MAYBE_UNUSED generic_global_ctx_t *global_ctx, generic_thread_ctx_t *thread_ctx, u8 *out_buf, const int out_size, pcfg_cell_t *cell)
{
  const tm_global_t *tg = global_ctx->gbldata;

  tm_thread_t *tt = thread_ctx->thrdata;

  if (tt->pos >= tg->units) return GENERIC_RC_EOF;

  // Which mask the base word belongs to, and where in that mask's base words. The masks are laid end to
  // end in base words the same way they are in candidates.

  u128 local = 0;

  const tm_mask_t *m = tm_mask_at (tg, tt->pos, true, &local);

  if (m == NULL) return GENERIC_RC_ERROR;

  u32 digit[TM_POS_MAX];

  u128 p = local;

  for (int i = (int) m->front_cnt - 1; i >= 0; i--)
  {
    const u32 radix = tg->cs[m->pos_cs[i]].cnt;

    digit[i] = (u32) (p % radix);

    p = p / radix;
  }

  u32 len = 0;

  for (u32 i = 0; i < m->front_cnt; i++)
  {
    u32 tok_len = 0;

    const u8 *tok = tm_cs_tok (&tg->cs[m->pos_cs[i]], digit[i], &tok_len);

    for (u32 k = 0; k < tok_len; k++)
    {
      if ((len + k) < (u32) out_size) out_buf[len + k] = tok[k];
    }

    len += tok_len;
  }

  cell[0] = m->cell_tmpl;

  // The varlen cell writes from the base word's end, which only this base word knows. slot 0 carries
  // that offset and the kernel runs the running sum from it.

  if (m->cell_cnt > 0)
  {
    const u32 packed = cell->slots[0].packed;

    cell->slots[0].packed = (packed & ~(0xffu << 8)) | ((len & 0xff) << 8);
  }

  tt->pos = tt->pos + 1;

  return (int) len;
}

// How this candidate was made, as text, for --debug-mode: the tokens that compose it, separated by a
// space so their boundaries show. On the host engine the candidate's position names the mask and the
// digits, so the whole of it is rebuilt. On the device engine the base word is handed over as bytes and
// only the cell's positions carry a digit, so the base word is written as it stands and the cell's
// tokens follow it.

int global_explain_u128 (MAYBE_UNUSED generic_global_ctx_t *global_ctx, const pcfg_cell_t *cell, MAYBE_UNUSED const u32 *pool, const u8 *base, const int base_len, const u32 il_pos, const u128 pos, char *out_buf, const int out_size)
{
  const tm_global_t *tg = global_ctx->gbldata;

  if (tg == NULL) return -1;

  int len = 0;

  if (cell == NULL)
  {
    // host engine: the position names the mask and decomposes into one digit per position.

    u128 local = 0;

    const tm_mask_t *m = tm_mask_at (tg, pos, false, &local);

    if (m == NULL) return -1;

    u32 digit[TM_POS_MAX];

    u128 p = local;

    for (int i = (int) m->pos_cnt - 1; i >= 0; i--)
    {
      const u32 radix = tg->cs[m->pos_cs[i]].cnt;

      digit[i] = (u32) (p % radix);

      p = p / radix;
    }

    for (u32 i = 0; i < m->pos_cnt; i++)
    {
      if ((i > 0) && (len < out_size)) out_buf[len++] = ' ';

      u32 tok_len = 0;

      const u8 *tok = tm_cs_tok (&tg->cs[m->pos_cs[i]], digit[i], &tok_len);

      for (u32 k = 0; (k < tok_len) && (len < out_size); k++) out_buf[len++] = tok[k];
    }

    return len;
  }

  // device engine: the base word as it stands, then the cell's tokens, read from the pool the kernel
  // read them from so the two agree.

  for (int k = 0; (k < base_len) && (len < out_size); k++) out_buf[len++] = base[k];

  const u32 slot_cnt = (cell->slot_cnt < PCFG_DEV_MAXSLOT) ? cell->slot_cnt : PCFG_DEV_MAXSLOT;

  u32 digit[PCFG_DEV_MAXSLOT];

  u32 carry = il_pos;

  for (int j = (int) slot_cnt - 1; j >= 0; j--)
  {
    const u32 radix = cell->slots[j].radix;

    if (radix == 0) return -1;

    digit[j] = carry % radix;

    carry = carry / radix;
  }

  for (u32 j = 0; j < slot_cnt; j++)
  {
    if ((len > 0) && (len < out_size)) out_buf[len++] = ' ';

    const u32 po  = cell->slots[j].pool_off;
    const u32 off = pool[po + digit[j]];
    const u32 nxt = pool[po + digit[j] + 1];

    const u8 *tok = ((const u8 *) pool) + off;

    for (u32 k = 0; (k < (nxt - off)) && (len < out_size); k++) out_buf[len++] = tok[k];
  }

  return len;
}
