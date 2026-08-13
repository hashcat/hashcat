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
// the parts of it are hints in their own right. john's single mode does the same thing, and it takes
// the parts from the gecos field and the home directory too. Here there is only the name.
//
// Every word is a substring of the name, so nothing is copied and the words point into the caller's
// buffer. The whole name is always first, which is what makes the first round of an attack identical to
// what a one word per account run has always done.

static bool association_word_is_separator (const char c)
{
  if ((c >= 'a') && (c <= 'z')) return false;
  if ((c >= 'A') && (c <= 'Z')) return false;
  if ((c >= '0') && (c <= '9')) return false;

  // Anything above ASCII is a letter as far as this is concerned. Splitting inside a UTF-8 sequence
  // would produce words that are not words, and a name in a non-latin script would be split to pieces.

  if ((u8) c >= 0x80) return false;

  return true;
}

static bool association_word_add (hlfmt_word_t *out_words, u32 *out_cnt, const u32 out_max, const char *buf, const u32 len)
{
  if (len == 0) return true;

  // Too short to be a password on its own. Returns true rather than false because false means "the
  // collection is full, stop", which would abandon the rest of the name over one useless piece.
  //
  // The first word is the whole account name and is exempt. It is added before any split, so an empty
  // collection is the test for it, and a short name is still tried as itself.

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

u32 hlfmt_user_words (const char *user_buf, const u32 user_len, hlfmt_word_t *out_words, const u32 out_max)
{
  if (user_len == 0) return 0;
  if (out_max  == 0) return 0;

  hlfmt_word_t all[ASSOCIATION_WORDS_COLLECT];

  u32 all_cnt = 0;

  // The whole name first, so that round zero of an attack is exactly the one word per account run

  association_word_add (all, &all_cnt, ASSOCIATION_WORDS_COLLECT, user_buf, user_len);

  // Then the parts between the separators, "j.smith" giving j and smith

  u32 start = 0;

  for (u32 i = 0; i <= user_len; i++)
  {
    const bool end = (i == user_len) ? true : association_word_is_separator (user_buf[i]);

    if (end == false) continue;

    if (association_word_add (all, &all_cnt, ASSOCIATION_WORDS_COLLECT, user_buf + start, i - start) == false) break;

    start = i + 1;
  }

  // Then the case and digit boundaries inside each of those parts. Walked over what has been collected
  // so far rather than over the name again, because "JEdgarHoover.2024" wants splitting on both.

  const u32 split_cnt = all_cnt;

  for (u32 i = 0; i < split_cnt; i++)
  {
    association_words_split_more (all, &all_cnt, ASSOCIATION_WORDS_COLLECT, all[i].buf, all[i].len);
  }

  // Over the cap, drop the shortest. A name that falls apart into a dozen pieces would otherwise make
  // every other account in the file run a dozen times, and the pieces it would spend that on are its
  // initials. The whole name is the longest of its own parts, so it is never the one dropped.

  while (all_cnt > out_max)
  {
    u32 worst = 1;

    for (u32 i = 2; i < all_cnt; i++)
    {
      if (all[i].len <= all[worst].len) worst = i;
    }

    for (u32 i = worst; i < (all_cnt - 1); i++)
    {
      all[i] = all[i + 1];
    }

    all_cnt--;
  }

  for (u32 i = 0; i < all_cnt; i++)
  {
    out_words[i] = all[i];
  }

  return all_cnt;
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
