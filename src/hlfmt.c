/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "filehandling.h"
#include "hlfmt.h"
#include "shared.h"
#include "parser.h"

static const char *const HLFMT_TEXT_HASHCAT  = "native hashcat";
static const char *const HLFMT_TEXT_PWDUMP   = "pwdump";
static const char *const HLFMT_TEXT_PASSWD   = "passwd";
static const char *const HLFMT_TEXT_SHADOW   = "shadow";
static const char *const HLFMT_TEXT_DCC      = "DCC";
static const char *const HLFMT_TEXT_DCC2     = "DCC 2";
static const char *const HLFMT_TEXT_NETNTLM1 = "NetNTLMv1";
static const char *const HLFMT_TEXT_NETNTLM2 = "NetNTLMv2";
static const char *const HLFMT_TEXT_NSLDAP   = "nsldap";
static const char *const HLFMT_TEXT_NSLDAPS  = "nsldaps";

// Turning one account name into the words an association attack can try for that account.
//
// "j.smith" is three tries and not one, because the account name is a hint rather than a password and
// the parts of it are hints in their own right. Only the name is available here, and what a mode
// carries beyond it comes from the module instead: see module_hash_hints ().
//
// Every word here is a substring of the name, so no bytes are copied and the words point into the
// caller's buffer.

static bool association_word_add (hlfmt_word_t *out_words, u32 *out_cnt, const u32 out_max, const char *buf, const u32 len)
{
  if (len == 0) return true;

  // Too short to be a password on its own. Returns true rather than false because false means "the
  // collection is full, stop", which would abandon the rest of the name over one useless piece.
  //
  // This is the collector the case splitter fills, so the floor is applied on the way in as well as on
  // the way out in hlfmt_hint_take (). Whatever was collected first is exempt, which matters only when
  // a caller starts from an empty collection.

  if ((*out_cnt > 0) && (len < ASSOCIATION_WORD_MIN_LEN)) return true;

  if (*out_cnt == out_max) return false;

  // A name whose parts repeat, and a name with no separator in it at all, would otherwise be tried
  // twice. Every account is tried as often as the widest account in the file, so a duplicate here is
  // paid for by every other account too.

  for (u32 i = 0; i < *out_cnt; i++)
  {
    if (out_words[i].len != len) continue;

    if (memcmp (out_words[i].buf, buf, len) == 0) return true;
  }

  out_words[*out_cnt].buf = buf;
  out_words[*out_cnt].len = len;

  *out_cnt = *out_cnt + 1;

  return true;
}

// Split again on case and digit boundaries, so that "JEdgarHoover" is also J, Edgar and Hoover.
//
// A capital starts a new word when it begins a capitalised one, which is a capital with a small letter
// either side of it. Cutting before every capital instead, which is what john does, turns "HTTPServer"
// into H, T, T, P and Server. Those single letters are not candidates on their own, and each one costs a
// round for every account in the file, so the rule here is the narrower one and "HTTPServer" stays
// HTTP and Server.

static void association_words_split_more (hlfmt_word_t *out_words, u32 *out_cnt, const u32 out_max, const char *buf, const u32 len)
{
  u32 start = 0;

  for (u32 i = 1; i < len; i++)
  {
    const char prev = buf[i - 1];
    const char cur  = buf[i];

    const bool prev_digit = ((prev >= '0') && (prev <= '9'));
    const bool cur_digit  = ((cur  >= '0') && (cur  <= '9'));

    const bool prev_lower = ((prev >= 'a') && (prev <= 'z'));
    const bool cur_upper  = ((cur  >= 'A') && (cur  <= 'Z'));

    bool next_lower = false;

    if ((i + 1) < len) next_lower = ((buf[i + 1] >= 'a') && (buf[i + 1] <= 'z'));

    bool boundary = false;

    if (prev_digit != cur_digit) boundary = true;

    if (cur_upper == true)
    {
      if (prev_lower == true) boundary = true;
      if (next_lower == true) boundary = true;
    }

    if (boundary == false) continue;

    if (association_word_add (out_words, out_cnt, out_max, buf + start, i - start) == false) return;

    start = i;
  }

  // Only worth adding when something was split off before it, otherwise this is the whole word again

  if (start == 0) return;

  association_word_add (out_words, out_cnt, out_max, buf + start, len - start);
}

// The words an attack guesses from, cut out of an account name. Both phases of -a 9 read this one list,
// the rules phase to try each word as a candidate and the grammar phase to put something around it.
//
// The list is ranked by how likely a word is to be the STEM of a password rather than to be one. That
// is what a grammar needs, and it is close enough for a rule list: the first rule of a rule list
// ordered by yield is the do-nothing rule, so a word the ranking puts first is tried as itself
// first anyway. "j.smith" is a fine guess and a poor stem, because the full stop survives into every
// candidate built on it, and it is still in the list, further down.
//
// What a grammar has no list of is names, so names come first and the rest follows them. A grammar
// reaches "smith42" from "smith" and its own digit lists, so a digit run is worth less as a hint than a
// name is. It is still worth having, because a rule applied to "2024" out of "user2024" reaches a
// password somebody chose.
//
// The order, best first:
//
//   1. the longest run of letters, which for a login is usually the surname
//   2. every run of letters laid end to end, which is a stem in its own right and is not a substring of
//      the name, so it is the one hint that has to be built rather than pointed at
//   3. the other runs of letters, longest first
//   4. the runs of digits, longest first
//   5. the account name as it was written, when that is not already one of the above
//
// That order is a judgement and not a measurement. Measuring it needs a corpus of account names beside
// the passwords those people chose, and the one to hand, a password contest, has none: 0.1 per cent of
// its 2645 pairs have any word of the account name in the password, because contest passwords are
// generated rather than chosen. Whoever does have such a corpus should try 1 and 2 the other way round
// before anything else.
//
// The last entry has a slot kept for it while 3 and 4 are collected, because a name that falls into
// enough pieces would otherwise fill the list with them and leave no room for the name itself. If the
// name turns out to be one of the pieces, the slot goes back to them.
//
// scratch holds the joined form, which is the only hint that is not a substring of the name.
//
// Every piece a split produces is held to ASSOCIATION_WORD_MIN_LEN, at a separator and at a case or
// digit boundary alike, and so is the joined form. The name as it was written is the one exemption, and
// it is added last and unconditionally, so an account too short to survive the floor still has itself
// to try.

static bool hlfmt_hint_add (hlfmt_word_t *out_words, u32 *out_cnt, const u32 out_max, const char *buf, const u32 len)
{
  if (len == 0) return true;

  if (*out_cnt == out_max) return false;

  // Compared without case because the grammar lowers a hint before it uses it, so two hints that differ
  // only in case are one hint that costs two slots.

  for (u32 i = 0; i < *out_cnt; i++)
  {
    if (out_words[i].len != len) continue;

    u32 k = 0;

    while (k < len)
    {
      const char a = out_words[i].buf[k];
      const char b = buf[k];

      const char la = ((a >= 'A') && (a <= 'Z')) ? (char) (a + 32) : a;
      const char lb = ((b >= 'A') && (b <= 'Z')) ? (char) (b + 32) : b;

      if (la != lb) break;

      k++;
    }

    if (k == len) return true;
  }

  out_words[*out_cnt].buf = buf;
  out_words[*out_cnt].len = len;

  *out_cnt = *out_cnt + 1;

  return true;
}

static bool hlfmt_is_letter (const char c)
{
  if ((c >= 'a') && (c <= 'z')) return true;
  if ((c >= 'A') && (c <= 'Z')) return true;

  // Anything above ASCII is a letter as far as this is concerned, the same as it is to the splitter
  // above, so a name in a non-latin script is one run rather than none.

  if ((u8) c >= 0x80) return true;

  return false;
}

// Take the longest word left in a pool, then the next longest, until the collection is full or the pool
// is spent. A word that is taken is emptied out of the pool, so the walk can be resumed where it
// stopped and never offers the same word twice.

// Longest first out of a pool, and never a piece below the floor. A pool holds what a split produced,
// so everything in it is subject to ASSOCIATION_WORD_MIN_LEN. The name itself never comes through here.

static void hlfmt_hint_take (hlfmt_word_t *out_words, u32 *out_cnt, const u32 out_max, hlfmt_word_t *pool, const u32 pool_cnt)
{
  while (*out_cnt < out_max)
  {
    u32 best = pool_cnt;

    for (u32 i = 0; i < pool_cnt; i++)
    {
      if (pool[i].len == 0) continue;

      if (pool[i].len < ASSOCIATION_WORD_MIN_LEN) continue;

      if ((best == pool_cnt) || (pool[i].len > pool[best].len)) best = i;
    }

    if (best == pool_cnt) break;

    hlfmt_hint_add (out_words, out_cnt, out_max, pool[best].buf, pool[best].len);

    pool[best].len = 0;
  }
}

// Cutting one field into words and adding them to a list that may already hold some.
//
// Three fields are cut this way and they share one list, so the count is carried in and out rather than
// started from zero. That is what lets the duplicate test see the words an earlier field contributed: a
// home directory ending in the login, which is nearly every home directory, adds nothing twice.
//
// The joined form is the one word that is not a substring of the field, so it is built in scratch, and
// each field therefore needs a slice of its own. It can never be longer than the field, so the caller
// advances scratch by the field length and the slices cannot overlap.

static void hlfmt_user_hints_append (const char *user_buf, const u32 user_len, hlfmt_word_t *out_words, u32 *io_cnt, const u32 out_max, char *scratch, const u32 scratch_size)
{
  if (user_len == 0) return;
  if (out_max  == 0) return;

  // The runs of letters, cut again on the case boundaries inside them so that "JEdgarHoover" is J,
  // Edgar and Hoover rather than one run.

  hlfmt_word_t runs[ASSOCIATION_WORDS_COLLECT];

  u32 runs_cnt = 0;

  u32 at = 0;

  while (at < user_len)
  {
    if (hlfmt_is_letter (user_buf[at]) == false) { at++; continue; }

    const u32 start = at;

    while ((at < user_len) && (hlfmt_is_letter (user_buf[at]) == true)) at++;

    if (runs_cnt == ASSOCIATION_WORDS_COLLECT) break;

    runs[runs_cnt].buf = user_buf + start;
    runs[runs_cnt].len = at - start;

    runs_cnt++;
  }

  const u32 whole_cnt = runs_cnt;

  for (u32 i = 0; i < whole_cnt; i++)
  {
    association_words_split_more (runs, &runs_cnt, ASSOCIATION_WORDS_COLLECT, runs[i].buf, runs[i].len);
  }

  // The joined form, which is every run of letters end to end. It is built here because it is the one
  // hint that is not a substring of the name.

  u32 joined_len = 0;

  for (u32 i = 0; i < whole_cnt; i++)
  {
    if ((joined_len + runs[i].len) > scratch_size) break;

    memcpy (scratch + joined_len, runs[i].buf, runs[i].len);

    joined_len += runs[i].len;
  }

    // 1. the longest run. A later one wins a tie, because a login is usually given name then surname and
  // the surname is the better stem.

  if (runs_cnt > 0)
  {
    u32 best = 0;

    for (u32 i = 1; i < runs_cnt; i++)
    {
      if (runs[i].len >= runs[best].len) best = i;
    }

    if (runs[best].len >= ASSOCIATION_WORD_MIN_LEN)
    {
      hlfmt_hint_add (out_words, io_cnt, out_max, runs[best].buf, runs[best].len);
    }
  }

  // 2. the joined form, which is built out of the pieces and is held to the same floor

  if (joined_len >= ASSOCIATION_WORD_MIN_LEN)
  {
    hlfmt_hint_add (out_words, io_cnt, out_max, scratch, joined_len);
  }

  // The runs of digits, collected before anything is taken from either pool so that both are ready.

  u32 digs_cnt = 0;

  hlfmt_word_t digs[ASSOCIATION_WORDS_COLLECT];

  at = 0;

  while (at < user_len)
  {
    const char c = user_buf[at];

    if ((c < '0') || (c > '9')) { at++; continue; }

    const u32 start = at;

    while ((at < user_len) && (user_buf[at] >= '0') && (user_buf[at] <= '9')) at++;

    if (digs_cnt == ASSOCIATION_WORDS_COLLECT) break;

    digs[digs_cnt].buf = user_buf + start;
    digs[digs_cnt].len = at - start;

    digs_cnt++;
  }

  // One slot short of the cap, so that the name as it was written has somewhere to go. A name that
  // falls into as many pieces as the cap allows would otherwise fill the list with them, one letter
  // pieces included, and be refused itself: john.q.public@mail.corp.example.com used all eight slots on
  // its parts and never tried the address.

  const u32 keep = (out_max > 1) ? (out_max - 1) : out_max;

  // 3. the rest of the runs, longest first

  hlfmt_hint_take (out_words, io_cnt, keep, runs, runs_cnt);

  // 4. the runs of digits, longest first

  hlfmt_hint_take (out_words, io_cnt, keep, digs, digs_cnt);

  // 5. the name as it was written

  hlfmt_hint_add (out_words, io_cnt, out_max, user_buf, user_len);

  // The name was already in the list under another guise, so the slot kept for it goes back to the
  // pieces.

  hlfmt_hint_take (out_words, io_cnt, out_max, runs, runs_cnt);

  hlfmt_hint_take (out_words, io_cnt, out_max, digs, digs_cnt);
}

u32 hlfmt_user_hints (const char *user_buf, const u32 user_len, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  u32 out_cnt = 0;

  hlfmt_user_hints_append (user_buf, user_len, out_words, &out_cnt, out_max, scratch, scratch_size);

  return out_cnt;
}

// Every field of an account, cut into one list.
//
// The login comes first, because it is the field every hash list format carries and the one a password
// is most often built from. The gecos field is next, since a real name is worth more than a path, and
// the home directory last. A field that is empty costs nothing.
//
// The first two are given a smaller list than they could fill, so that a login falling into many pieces
// cannot crowd the real name out. Then the login is offered the rest, which it takes only if the fields
// behind it left anything, and the duplicate test in hlfmt_hint_add () makes that second pass free.
//
// scratch is cut into a slice per field, because each one builds its joined form there and that word
// has to outlive the call.

u32 hlfmt_account_hints (const char *user_buf, const u32 user_len, const char *gecos_buf, const u32 gecos_len, const char *home_buf, const u32 home_len, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  u32 out_cnt = 0;

  if (out_max == 0) return 0;

  u32 at = 0;

  const u32 keep_user  = (out_max > 2) ? (out_max - 2) : out_max;
  const u32 keep_gecos = (out_max > 1) ? (out_max - 1) : out_max;

  if ((user_len > 0) && ((at + user_len) <= scratch_size))
  {
    hlfmt_user_hints_append (user_buf, user_len, out_words, &out_cnt, keep_user, scratch + at, user_len);

    at += user_len;
  }

  if ((gecos_len > 0) && ((at + gecos_len) <= scratch_size))
  {
    hlfmt_user_hints_append (gecos_buf, gecos_len, out_words, &out_cnt, keep_gecos, scratch + at, gecos_len);

    at += gecos_len;
  }

  if ((home_len > 0) && ((at + home_len) <= scratch_size))
  {
    hlfmt_user_hints_append (home_buf, home_len, out_words, &out_cnt, out_max, scratch + at, home_len);

    at += home_len;
  }

  // Whatever the fields behind the login did not use goes back to it.

  if ((user_len > 0) && ((at + user_len) <= scratch_size))
  {
    hlfmt_user_hints_append (user_buf, user_len, out_words, &out_cnt, out_max, scratch + at, user_len);
  }

  return out_cnt;
}

// What one hash carries about its owner, as words an attack may guess from.
//
// The module supplies them, because only the module can interpret its own salt and esalt. A module that
// leaves the hook at MODULE_DEFAULT was given default_hash_hints () when it was loaded, so the pointer
// is always valid and no caller has to test for it.
//
// hash_pos is a digest position. hash_info and the esalt array are indexed that way; the salt array is
// not, and a digest position is only a salt position where every hash has a salt of its own. That is
// what -a 9 requires and checks before it runs, and -a 9 is what asks this. Any other caller is handed
// no salt rather than the wrong one.

u32 hlfmt_hash_hints (hashcat_ctx_t *hashcat_ctx, const u64 hash_pos, hlfmt_word_t *out_words, const u32 out_max, char *scratch, const u32 scratch_size)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const module_ctx_t *module_ctx = hashcat_ctx->module_ctx;

  if (hashes == NULL) return 0;

  if (hash_pos >= hashes->digests_cnt) return 0;

  const hashinfo_t *hash_info = (hashes->hash_info != NULL) ? hashes->hash_info[hash_pos] : NULL;

  const void *esalt = NULL;

  if ((hashes->esalts_buf != NULL) && (hashconfig->esalt_size > 0))
  {
    esalt = (const u8 *) hashes->esalts_buf + (hash_pos * hashconfig->esalt_size);
  }

  const salt_t *salt = NULL;

  if ((hashes->salts_buf != NULL) && (hashes->salts_cnt == hashes->digests_cnt))
  {
    salt = &hashes->salts_buf[hash_pos];
  }

  const u32 cnt = module_ctx->module_hash_hints (hashconfig, salt, esalt, hash_info, out_words, out_max, scratch, scratch_size);

  return cnt;
}

// hlfmt hashcat

static void hlfmt_hash_hashcat (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;

  *hashbuf_pos = line_buf;
  *hashbuf_len = line_len;

  if (user_options->username == true)
  {
    char  *pos = *hashbuf_pos;
    size_t len = *hashbuf_len;

    for (int i = 0; i < line_len; i++, pos++, len--)
    {
      if (line_buf[i] == hashconfig->separator)
      {
        pos++;

        len--;

        break;
      }
    }

    *hashbuf_pos = pos;
    *hashbuf_len = len;
  }

  if (user_options->dynamic_x == true)
  {
    char *pos = NULL;
    int   len = 0;

    // the line arrives already translated into hashcat's spelling, all that is left is the tag

    if (extract_dynamicx_hash ((const u8 *) line_buf, line_len, (u8 **) &pos, &len) != -1)
    {
      *hashbuf_pos = pos;
      *hashbuf_len = len;
    }
  }
}

static void hlfmt_user_hashcat (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  char  *pos = NULL;
  size_t len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == hashconfig->separator)
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt pwdump

static int hlfmt_detect_pwdump (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, const char *line_buf, const int line_len)
{
  int sep_cnt = 0;

  int sep2_len = 0;
  int sep3_len = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 2) sep2_len++;
    if (sep_cnt == 3) sep3_len++;
  }

  if ((sep_cnt == 6) && ((sep2_len == 32) || (sep3_len == 32))) return 1;

  return 0;
}

static void hlfmt_hash_pwdump (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  char  *pos = NULL;
  size_t len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (hashconfig->pwdump_column == PWDUMP_COLUMN_LM_HASH)
    {
      if (sep_cnt == 2)
      {
        if (pos == NULL) pos = line_buf + i;

        len++;
      }
    }
    else if (hashconfig->pwdump_column == PWDUMP_COLUMN_NTLM_HASH)
    {
      if (sep_cnt == 3)
      {
        if (pos == NULL) pos = line_buf + i;

        len++;
      }
    }
  }

  *hashbuf_pos = pos;
  *hashbuf_len = len;
}

static void hlfmt_user_pwdump (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len)
{
  char  *pos = NULL;
  size_t len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt passwd

static int hlfmt_detect_passwd (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, const char *line_buf, const int line_len)
{
  int sep_cnt = 0;

  char sep5_first = 0;
  char sep6_first = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 5) if (sep5_first == 0) sep5_first = line_buf[i];
    if (sep_cnt == 6) if (sep6_first == 0) sep6_first = line_buf[i];
  }

  if ((sep_cnt == 6) && ((sep5_first == '/') || (sep6_first == '/'))) return 1;

  return 0;
}

static void hlfmt_hash_passwd (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  char  *pos = NULL;
  size_t len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 1)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *hashbuf_pos = pos;
  *hashbuf_len = len;
}

static void hlfmt_user_passwd (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len)
{
  char  *pos = NULL;
  size_t len = 0;

  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':')
    {
      sep_cnt++;

      continue;
    }

    if (sep_cnt == 0)
    {
      if (pos == NULL) pos = line_buf + i;

      len++;
    }
  }

  *userbuf_pos = pos;
  *userbuf_len = len;
}

// hlfmt shadow

static int hlfmt_detect_shadow (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, const char *line_buf, const int line_len)
{
  int sep_cnt = 0;

  for (int i = 0; i < line_len; i++)
  {
    if (line_buf[i] == ':') sep_cnt++;
  }

  if (sep_cnt == 8) return 1;

  return 0;
}

static void hlfmt_hash_shadow (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  hlfmt_hash_passwd (hashcat_ctx, line_buf, line_len, hashbuf_pos, hashbuf_len);
}

static void hlfmt_user_shadow (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len)
{
  hlfmt_user_passwd (hashcat_ctx, line_buf, line_len, userbuf_pos, userbuf_len);
}

// hlfmt main

const char *strhlfmt (const u32 hashfile_format)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT:  return HLFMT_TEXT_HASHCAT;
    case HLFMT_PWDUMP:   return HLFMT_TEXT_PWDUMP;
    case HLFMT_PASSWD:   return HLFMT_TEXT_PASSWD;
    case HLFMT_SHADOW:   return HLFMT_TEXT_SHADOW;
    case HLFMT_DCC:      return HLFMT_TEXT_DCC;
    case HLFMT_DCC2:     return HLFMT_TEXT_DCC2;
    case HLFMT_NETNTLM1: return HLFMT_TEXT_NETNTLM1;
    case HLFMT_NETNTLM2: return HLFMT_TEXT_NETNTLM2;
    case HLFMT_NSLDAP:   return HLFMT_TEXT_NSLDAP;
    case HLFMT_NSLDAPS:  return HLFMT_TEXT_NSLDAPS;
  }

  return "Unknown";
}

void hlfmt_hash (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **hashbuf_pos, int *hashbuf_len)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT: hlfmt_hash_hashcat (hashcat_ctx, line_buf, line_len, hashbuf_pos, hashbuf_len); break;
    case HLFMT_PWDUMP:  hlfmt_hash_pwdump  (hashcat_ctx, line_buf, line_len, hashbuf_pos, hashbuf_len); break;
    case HLFMT_PASSWD:  hlfmt_hash_passwd  (hashcat_ctx, line_buf, line_len, hashbuf_pos, hashbuf_len); break;
    case HLFMT_SHADOW:  hlfmt_hash_shadow  (hashcat_ctx, line_buf, line_len, hashbuf_pos, hashbuf_len); break;
  }
}

// The two fields of a passwd line that describe the person rather than the account.
//
// Field 4 is the gecos field and its first comma separated part is the real name, where the parts behind
// it are an office, a phone number and whatever else the site puts there. Field 5 is the home directory,
// and only its last component is worth anything: the ones in front are "home", "export" and "users",
// which are the same for every account in the file and would cost a round each for all of them.
//
// Both point into line_buf, the same as the login does. A format that has neither is handed two empty
// fields rather than an error, because most of them have neither.

static void hlfmt_user_extra_passwd (char *line_buf, const int line_len, char **gecos_pos, int *gecos_len, char **home_pos, int *home_len)
{
  int sep_cnt = 0;

  int field_start = 0;

  for (int i = 0; i <= line_len; i++)
  {
    const bool end = (i == line_len) || (line_buf[i] == ':');

    if (end == false) continue;

    if (sep_cnt == 4)
    {
      // The real name only, which is everything before the first comma.

      int len = i - field_start;

      for (int k = 0; k < len; k++)
      {
        if (line_buf[field_start + k] != ',') continue;

        len = k;

        break;
      }

      if (len > 0)
      {
        *gecos_pos = line_buf + field_start;
        *gecos_len = len;
      }
    }

    if (sep_cnt == 5)
    {
      // The last component, which is the one that names the person rather than the file system.

      int start = field_start;

      for (int k = field_start; k < i; k++)
      {
        if (line_buf[k] != '/') continue;

        start = k + 1;
      }

      if (i > start)
      {
        *home_pos = line_buf + start;
        *home_len = i - start;
      }
    }

    sep_cnt++;

    field_start = i + 1;
  }
}

void hlfmt_user_extra (u32 hashfile_format, char *line_buf, const int line_len, char **gecos_pos, int *gecos_len, char **home_pos, int *home_len)
{
  *gecos_pos = NULL;
  *gecos_len = 0;
  *home_pos  = NULL;
  *home_len  = 0;

  // Only a passwd line carries them. A shadow line has the login and the hash and then ageing counters,
  // and every other format has the login alone.

  if (hashfile_format != HLFMT_PASSWD) return;

  hlfmt_user_extra_passwd (line_buf, line_len, gecos_pos, gecos_len, home_pos, home_len);
}

void hlfmt_user (hashcat_ctx_t *hashcat_ctx, u32 hashfile_format, char *line_buf, const int line_len, char **userbuf_pos, int *userbuf_len)
{
  switch (hashfile_format)
  {
    case HLFMT_HASHCAT: hlfmt_user_hashcat (hashcat_ctx, line_buf, line_len, userbuf_pos, userbuf_len); break;
    case HLFMT_PWDUMP:  hlfmt_user_pwdump  (hashcat_ctx, line_buf, line_len, userbuf_pos, userbuf_len); break;
    case HLFMT_PASSWD:  hlfmt_user_passwd  (hashcat_ctx, line_buf, line_len, userbuf_pos, userbuf_len); break;
    case HLFMT_SHADOW:  hlfmt_user_shadow  (hashcat_ctx, line_buf, line_len, userbuf_pos, userbuf_len); break;
  }
}

u32 hlfmt_detect (hashcat_ctx_t *hashcat_ctx, HCFILE *fp, u32 max_check)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  // Exception: those formats are wrongly detected as HLFMT_SHADOW, prevent it

  if (hashconfig->hlfmt_disable == true) return HLFMT_HASHCAT;

  u32 *formats_cnt = (u32 *) hccalloc (HLFMTS_CNT, sizeof (u32));

  u32 num_check = 0;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  while (!hc_feof (fp))
  {
    const size_t line_len = fgetl (fp, line_buf, HCBUFSIZ_LARGE);

    if (line_len == 0) continue;

    if (hlfmt_detect_pwdump (hashcat_ctx, line_buf, line_len)) formats_cnt[HLFMT_PWDUMP]++;
    if (hlfmt_detect_passwd (hashcat_ctx, line_buf, line_len)) formats_cnt[HLFMT_PASSWD]++;
    if (hlfmt_detect_shadow (hashcat_ctx, line_buf, line_len)) formats_cnt[HLFMT_SHADOW]++;

    if (num_check == max_check) break;

    num_check++;
  }

  hcfree (line_buf);

  u32 hashlist_format = HLFMT_HASHCAT;

  for (u32 i = 1; i < HLFMTS_CNT; i++)
  {
    if (formats_cnt[i - 1] >= formats_cnt[i]) continue;

    hashlist_format = i;
  }

  hcfree (formats_cnt);

  return hashlist_format;
}
