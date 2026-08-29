/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "bitops.h"
#include "logfile.h"
#include "convert.h"
#include "filehandling.h"
#include "backend.h"
#include "shared.h"
#include "path.h"
#include "feed_ctx.h"
#include "ext_lzma.h"
#include "mpsp.h"

static const char *const DEF_MASK = "?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d";

#define MAX_MFS 9 // 8*charset, 1*mask

static int sp_comp_val (const void *p1, const void *p2)
{
  const hcstat_table_t *b1 = (const hcstat_table_t *) p1;
  const hcstat_table_t *b2 = (const hcstat_table_t *) p2;

  const u64 v1 = b1->val;
  const u64 v2 = b2->val;

  if (v1 < v2) return  1;
  if (v1 > v2) return -1;

  return 0;
}

static void mp_css_split_cnt (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_orig, u32 css_cnt_lr[2])
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  u32 css_cnt_l = mask_ctx->css_cnt;
  u32 css_cnt_r;

  if (user_options->slow_candidates == true)
  {
    css_cnt_r = 0;
  }
  else
  {
    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (css_cnt_orig < 6)
      {
        css_cnt_r = 1;
      }
      else if (css_cnt_orig == 6)
      {
        css_cnt_r = 2;
      }
      else
      {
        if ((hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE) || (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE))
        {
          if (css_cnt_orig == 8 || css_cnt_orig == 10)
          {
            css_cnt_r = 2;
          }
          else
          {
            css_cnt_r = 4;
          }
        }
        else
        {
          if ((mask_ctx->css_buf[0].cs_len * mask_ctx->css_buf[1].cs_len * mask_ctx->css_buf[2].cs_len) > 256)
          {
            css_cnt_r = 3;
          }
          else
          {
            css_cnt_r = 4;
          }
        }
      }
    }
    else
    {
      css_cnt_r = 1;

      /* unfinished code?
      int sum = css_buf[css_cnt_r - 1].cs_len;

      for (u32 i = 1; i < 4 && i < css_cnt; i++)
      {
        if (sum > 1) break; // we really don't need alot of amplifier them for slow hashes

        css_cnt_r++;

        sum *= css_buf[css_cnt_r - 1].cs_len;
      }
      */
    }
  }

  css_cnt_l -= css_cnt_r;

  css_cnt_lr[0] = css_cnt_l;
  css_cnt_lr[1] = css_cnt_r;
}

static int mp_css_append_salt (hashcat_ctx_t *hashcat_ctx, salt_t *salt_buf)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u32  salt_len     =        salt_buf->salt_len;
  u8  *salt_buf_ptr = (u8 *) salt_buf->salt_buf;

  if ((mask_ctx->css_cnt + salt_len) > 256) return -1;

  for (u32 i = 0, j = mask_ctx->css_cnt; i < salt_len; i++, j++)
  {
    mask_ctx->css_buf[j].cs_buf[0] = salt_buf_ptr[i];
    mask_ctx->css_buf[j].cs_len    = 1;

    mask_ctx->css_cnt++;
  }

  return 0;
}

static int mp_css_utf16le_expand (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u32 css_cnt_utf16le = mask_ctx->css_cnt * 2;

  if (css_cnt_utf16le > 256) return -1;

  cs_t *css_buf_utf16le = (cs_t *) hccalloc (css_cnt_utf16le, sizeof (cs_t));

  for (u32 i = 0, j = 0; i < mask_ctx->css_cnt; i += 1, j += 2)
  {
    memcpy (&css_buf_utf16le[j + 0], &mask_ctx->css_buf[i], sizeof (cs_t));

    css_buf_utf16le[j + 1].cs_buf[0] = 0;
    css_buf_utf16le[j + 1].cs_len    = 1;
  }

  memcpy (mask_ctx->css_buf, css_buf_utf16le, css_cnt_utf16le * sizeof (cs_t));

  mask_ctx->css_cnt = css_cnt_utf16le;

  hcfree (css_buf_utf16le);

  return 0;
}

static int mp_css_utf16be_expand (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u32 css_cnt_utf16be = mask_ctx->css_cnt * 2;

  if (css_cnt_utf16be > 256) return -1;

  cs_t *css_buf_utf16be = (cs_t *) hccalloc (css_cnt_utf16be, sizeof (cs_t));

  for (u32 i = 0, j = 0; i < mask_ctx->css_cnt; i += 1, j += 2)
  {
    css_buf_utf16be[j + 0].cs_buf[0] = 0;
    css_buf_utf16be[j + 0].cs_len    = 1;

    memcpy (&css_buf_utf16be[j + 1], &mask_ctx->css_buf[i], sizeof (cs_t));
  }

  memcpy (mask_ctx->css_buf, css_buf_utf16be, css_cnt_utf16be * sizeof (cs_t));

  mask_ctx->css_cnt = css_cnt_utf16be;

  hcfree (css_buf_utf16be);

  return 0;
}

static int mp_css_to_uniq_tbl (hashcat_ctx_t *hashcat_ctx, u32 css_cnt, cs_t *css, u32 **uniq_tbls)
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    event_log_error (hashcat_ctx, "Mask length is too long.");

    return -1;
  }

  for (u32 css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    u32 *uniq_tbl = uniq_tbls[css_pos];

    u32 *cs_buf = css[css_pos].cs_buf;
    u32  cs_len = css[css_pos].cs_len;

    for (u32 cs_pos = 0; cs_pos < cs_len; cs_pos++)
    {
      u32 c = cs_buf[cs_pos] & 0xff;

      uniq_tbl[c] = 1;
    }
  }

  return 0;
}

static int mp_add_cs_buf (hashcat_ctx_t *hashcat_ctx, const u32 *in_buf, size_t in_len, cs_t *css, u32 css_cnt)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (css_cnt == 256)
  {
    event_log_error (hashcat_ctx, "Invalid mask length.");

    return -1;
  }

  cs_t *cs = &css[css_cnt];

  size_t css_uniq_sz = CHARSIZ * sizeof (u32);

  u32 *css_uniq = (u32 *) hcmalloc (css_uniq_sz);

  size_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    const u32 u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    u32 u = in_buf[i] & 0xff;

    if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER) u = (u32) toupper (u);

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  hcfree (css_uniq);

  return 0;
}

static int mp_expand (hashcat_ctx_t *hashcat_ctx, const char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, u32 mp_usr_offset, int interpret)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    u32 p0 = in_buf[in_pos] & 0xff;

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len)
      {
        event_log_error (hashcat_ctx, "Syntax error in mask: %s", in_buf);

        return -1;
      }

      u32 p1 = in_buf[in_pos] & 0xff;

      int rc = 0;

      switch (p1)
      {
        case 'l': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[0].cs_buf, mp_sys[0].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'u': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[1].cs_buf, mp_sys[1].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'd': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[2].cs_buf, mp_sys[2].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 's': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[3].cs_buf, mp_sys[3].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'a': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[4].cs_buf, mp_sys[4].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'b': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[5].cs_buf, mp_sys[5].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'h': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[6].cs_buf, mp_sys[6].cs_len, mp_usr, mp_usr_offset);
                  break;
        case 'H': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[7].cs_buf, mp_sys[7].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 1 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[0].cs_buf, mp_usr[0].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 2 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[1].cs_buf, mp_usr[1].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 3 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[2].cs_buf, mp_usr[2].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 4 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[3].cs_buf, mp_usr[3].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '5': if (mp_usr[4].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 5 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[4].cs_buf, mp_usr[4].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '6': if (mp_usr[5].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 6 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[5].cs_buf, mp_usr[5].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '7': if (mp_usr[6].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 7 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[6].cs_buf, mp_usr[6].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '8': if (mp_usr[7].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 8 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[7].cs_buf, mp_usr[7].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '?': rc = mp_add_cs_buf (hashcat_ctx, &p0, 1, mp_usr, mp_usr_offset);
                  break;
        default:  event_log_error (hashcat_ctx, "Syntax error in mask: %s", in_buf);
                  return -1;
      }

      if (rc == -1) return -1;
    }
    else
    {
      if (hashconfig->opts_type & OPTS_TYPE_MT_HEX)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          event_log_error (hashcat_ctx, "The hex-charset option expects exactly 2 hexadecimal chars. Failed mask: %s", in_buf);

          return -1;
        }

        u32 p1 = in_buf[in_pos] & 0xff;

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          event_log_error (hashcat_ctx, "Invalid hex character detected in mask %s", in_buf);

          return -1;
        }

        u32 chr = 0;

        chr  = (u32) hex_convert ((u8) p1) << 0;
        chr |= (u32) hex_convert ((u8) p0) << 4;

        const int rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, mp_usr, mp_usr_offset);

        if (rc == -1) return -1;
      }
      else
      {
        u32 chr = p0;

        const int rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, mp_usr, mp_usr_offset);

        if (rc == -1) return -1;
      }
    }
  }

  return 0;
}

// ?w marks where the base word goes. It is a position and not a charset, so it contributes no css
// entry and the caller has to put the css index back after it is seen.

static int mp_set_w_marker (hashcat_ctx_t *hashcat_ctx, const char *mask_buf, const size_t css_pos)
{
  mask_ctx_t           *mask_ctx     = hashcat_ctx->mask_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  // The attack mode the run uses, not the one the user typed, because the masks of the three modes
  // that are rewritten into attack-mode 12 carry a ?w this put there. A user who writes their own ?w
  // into an aliased mode's mask ends up with two of them and the check below says so.

  if (user_options->attack_mode != ATTACK_MODE_HYBRID)
  {
    event_log_error (hashcat_ctx, "?w is supported in attack-mode 12 only. Failed mask: %s", mask_buf);

    return -1;
  }

  if (mask_ctx->has_w == true)
  {
    event_log_error (hashcat_ctx, "A mask can hold only one ?w. Failed mask: %s", mask_buf);

    return -1;
  }

  mask_ctx->has_w   = true;
  mask_ctx->pre_len = (u32) css_pos;

  return 0;
}

// ?q marks a word from a second wordlist. It is optional, it may only follow ?w, and like ?w it is a
// position rather than a charset.

static int mp_set_q_marker (hashcat_ctx_t *hashcat_ctx, const char *mask_buf, const size_t css_pos)
{
  mask_ctx_t           *mask_ctx     = hashcat_ctx->mask_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->attack_mode != ATTACK_MODE_HYBRID)
  {
    event_log_error (hashcat_ctx, "?q is supported in attack-mode 12 only. Failed mask: %s", mask_buf);

    return -1;
  }

  if (mask_ctx->has_w == false)
  {
    event_log_error (hashcat_ctx, "?q names the second word, so it has to come after ?w. Failed mask: %s", mask_buf);

    return -1;
  }

  if (mask_ctx->has_q == true)
  {
    event_log_error (hashcat_ctx, "A mask can hold only one ?q. Failed mask: %s", mask_buf);

    return -1;
  }

  mask_ctx->has_q   = true;
  mask_ctx->mid_len = (u32) css_pos - mask_ctx->pre_len;

  return 0;
}

// Does a mask carry the given marker? Asked before the mask is parsed into a css, because which of the
// work arguments are wordlists depends on whether ?q is there and generic_ctx_init runs first.
//
// A '?' escapes itself, so "??q" is a literal question mark followed by a literal q and not a marker.

bool mask_has_marker (const char *mask, const char marker)
{
  if (mask == NULL) return false;

  const size_t mask_len = strlen (mask);

  for (size_t i = 0; i < mask_len; i++)
  {
    if (mask[i] != '?') continue;

    i++;

    if (i == mask_len) break;

    if (mask[i] == marker) return true;
  }

  return false;
}

// Is the given marker the last thing in the mask? Asked of a -a 12 mask about its ?w, because a mask
// that ends in the base word is the one shape whose base words the mask processor can produce: the
// word goes behind them and the mask in front of it never has to be fed again.
//
// The same escaping applies, so "??w" ends in a literal w and not in a marker. Walking the whole mask
// rather than looking at the last two bytes is what tells those apart.

bool mask_ends_with_marker (const char *mask, const char marker)
{
  if (mask == NULL) return false;

  const size_t mask_len = strlen (mask);

  bool ends = false;

  for (size_t i = 0; i < mask_len; i++)
  {
    ends = false;

    if (mask[i] != '?') continue;

    i++;

    if (i == mask_len) break;

    if (mask[i] != marker) continue;

    ends = (i == (mask_len - 1));
  }

  return ends;
}

static int mp_gen_css (hashcat_ctx_t *hashcat_ctx, char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, cs_t *css_buf, u32 *css_cnt)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  memset (css_buf, 0, 256 * sizeof (cs_t));

  // Every mask is parsed from scratch, so the markers found in the previous one must not survive into
  // this one. With a mask file the masks differ and only some of them may carry a ?w.

  mask_ctx->has_w   = false;
  mask_ctx->has_q   = false;
  mask_ctx->pre_len = 0;
  mask_ctx->mid_len = 0;

  size_t mask_pos;
  size_t css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    char p0 = mask_buf[mask_pos];

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len)
      {
        event_log_error (hashcat_ctx, "Syntax error in mask: %s", mask_buf);

        return -1;
      }

      char p1 = mask_buf[mask_pos];

      u32 chr = (u32) p1;

      int rc = 0;

      switch (p1)
      {
        case 'l': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[0].cs_buf, mp_sys[0].cs_len, css_buf, css_pos);
                  break;
        case 'u': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[1].cs_buf, mp_sys[1].cs_len, css_buf, css_pos);
                  break;
        case 'd': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[2].cs_buf, mp_sys[2].cs_len, css_buf, css_pos);
                  break;
        case 's': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[3].cs_buf, mp_sys[3].cs_len, css_buf, css_pos);
                  break;
        case 'a': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[4].cs_buf, mp_sys[4].cs_len, css_buf, css_pos);
                  break;
        case 'b': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[5].cs_buf, mp_sys[5].cs_len, css_buf, css_pos);
                  break;
        case 'h': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[6].cs_buf, mp_sys[6].cs_len, css_buf, css_pos);
                  break;
        case 'H': rc = mp_add_cs_buf (hashcat_ctx, mp_sys[7].cs_buf, mp_sys[7].cs_len, css_buf, css_pos);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 1 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[0].cs_buf, mp_usr[0].cs_len, css_buf, css_pos);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 2 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[1].cs_buf, mp_usr[1].cs_len, css_buf, css_pos);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 3 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[2].cs_buf, mp_usr[2].cs_len, css_buf, css_pos);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 4 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[3].cs_buf, mp_usr[3].cs_len, css_buf, css_pos);
                  break;
        case '5': if (mp_usr[4].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 5 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[4].cs_buf, mp_usr[4].cs_len, css_buf, css_pos);
                  break;
        case '6': if (mp_usr[5].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 6 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[5].cs_buf, mp_usr[5].cs_len, css_buf, css_pos);
                  break;
        case '7': if (mp_usr[6].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 7 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[6].cs_buf, mp_usr[6].cs_len, css_buf, css_pos);
                  break;
        case '8': if (mp_usr[7].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 8 is undefined."); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[7].cs_buf, mp_usr[7].cs_len, css_buf, css_pos);
                  break;
        case '?': rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, css_buf, css_pos);
                  break;
        case 'w': rc = mp_set_w_marker (hashcat_ctx, mask_buf, css_pos);
                  css_pos--; // no css entry was added, and the loop is about to step css_pos on
                  break;
        case 'q': rc = mp_set_q_marker (hashcat_ctx, mask_buf, css_pos);
                  css_pos--; // same, ?q is a position and not a charset
                  break;
        default:  event_log_error (hashcat_ctx, "Syntax error in mask: %s", mask_buf);
                  return -1;
      }

      if (rc == -1) return -1;
    }
    else
    {
      if (hashconfig->opts_type & OPTS_TYPE_MT_HEX)
      {
        mask_pos++;

        // if there is no 2nd hex character, show an error:

        if (mask_pos == mask_len)
        {
          event_log_error (hashcat_ctx, "The hex-charset option expects exactly 2 hexadecimal chars. Failed mask: %s", mask_buf);

          return -1;
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          event_log_error (hashcat_ctx, "Invalid hex character detected in mask %s", mask_buf);

          return -1;
        }

        u32 chr = 0;

        chr |= (u32) hex_convert ((u8) p1) << 0;
        chr |= (u32) hex_convert ((u8) p0) << 4;

        const int rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, css_buf, css_pos);

        if (rc == -1) return -1;
      }
      else
      {
        u32 chr = (u32) p0;

        const int rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, css_buf, css_pos);

        if (rc == -1) return -1;
      }
    }
  }

  // -a 12 is defined by where the word sits, so a mask that does not say where that is has no meaning
  // in this mode. Checked here rather than at option parsing time because a mask file supplies masks
  // one at a time and every one of them has to carry the marker.

  if ((hashcat_ctx->user_options->attack_mode == ATTACK_MODE_HYBRID) && (mask_ctx->has_w == false))
  {
    event_log_error (hashcat_ctx, "Attack-mode 12 needs a ?w in the mask to say where the word goes. Failed mask: %s", mask_buf);

    return -1;
  }

  // A mask of ?w alone is a plain wordlist run with extra steps, but it is not a syntax error and the
  // length check below would reject it for the wrong reason.

  if ((css_pos == 0) && (mask_ctx->has_w == false))
  {
    event_log_error (hashcat_ctx, "Invalid mask length (0).");

    return -1;
  }

  *css_cnt = css_pos;

  return 0;
}

static int mp_get_truncated_mask (hashcat_ctx_t *hashcat_ctx, const char *mask_buf, const size_t mask_len, const u32 len, char *new_mask_buf)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  u32 mask_pos;

  u32 css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    if (css_pos == len) break;

    char p0 = mask_buf[mask_pos];

    new_mask_buf[mask_pos] = p0;

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      new_mask_buf[mask_pos] = mask_buf[mask_pos];
    }
    else
    {
      if (hashconfig->opts_type & OPTS_TYPE_MT_HEX)
      {
        mask_pos++;

        if (mask_pos == mask_len)
        {
          event_log_error (hashcat_ctx, "The hex-charset option expects exactly 2 hexadecimal chars. Failed mask: %s", mask_buf);

          return -1;
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          event_log_error (hashcat_ctx, "Invalid hex character detected in mask: %s", mask_buf);

          return -1;
        }

        new_mask_buf[mask_pos] = p1;
      }
    }
  }

  return 0;
}

static void mp_setup_sys (cs_t *mp_sys)
{
  u32 pos;
  u32 chr;
  u32 donec[CHARSIZ] = { 0 };

  for (pos =  0, chr =  'a'; chr <=  'z'; chr++) { donec[chr] = 1;
                                                   mp_sys[0].cs_buf[pos++] = chr;
                                                   mp_sys[0].cs_len = pos; }

  for (pos =  0, chr =  'A'; chr <=  'Z'; chr++) { donec[chr] = 1;
                                                   mp_sys[1].cs_buf[pos++] = chr;
                                                   mp_sys[1].cs_len = pos; }

  for (pos =  0, chr =  '0'; chr <=  '9'; chr++) { donec[chr] = 1;
                                                   mp_sys[2].cs_buf[pos++] = chr;
                                                   mp_sys[2].cs_len = pos; }

  for (pos =  0, chr = 0x20; chr <= 0x7e; chr++) { if (donec[chr]) continue;
                                                   mp_sys[3].cs_buf[pos++] = chr;
                                                   mp_sys[3].cs_len = pos; }

  for (pos =  0, chr = 0x20; chr <= 0x7e; chr++) { mp_sys[4].cs_buf[pos++] = chr;
                                                   mp_sys[4].cs_len = pos; }

  for (pos =  0, chr = 0x00; chr <= 0xff; chr++) { mp_sys[5].cs_buf[pos++] = chr;
                                                   mp_sys[5].cs_len = pos; }

  for (pos =  0, chr = 0x30; chr <= 0x39; chr++) { mp_sys[6].cs_buf[pos++] = chr;
                                                   mp_sys[6].cs_len = pos; }
  for (pos = 10, chr = 0x61; chr <= 0x66; chr++) { mp_sys[6].cs_buf[pos++] = chr;
                                                   mp_sys[6].cs_len = pos; }

  for (pos =  0, chr = 0x30; chr <= 0x39; chr++) { mp_sys[7].cs_buf[pos++] = chr;
                                                   mp_sys[7].cs_len = pos; }
  for (pos = 10, chr = 0x41; chr <= 0x46; chr++) { mp_sys[7].cs_buf[pos++] = chr;
                                                   mp_sys[7].cs_len = pos; }
}

static int mp_setup_usr (hashcat_ctx_t *hashcat_ctx, cs_t *mp_sys, cs_t *mp_usr, const char *buf, const u32 userindex)
{
  HCFILE fp;

  if (hc_fopen (&fp, buf, "rb") == false)
  {
    const int rc = mp_expand (hashcat_ctx, buf, strlen (buf), mp_sys, mp_usr, userindex, 1);

    if (rc == -1) return -1;
  }
  else
  {
    char mp_file[1024];

    const size_t nread = hc_fread (mp_file, 1, sizeof (mp_file) - 1, &fp);

    if (!hc_feof (&fp))
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is too large.", buf);

      hc_fclose (&fp);

      return -1;
    }

    hc_fclose (&fp);

    if (nread == 0)
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is empty.", buf);

      return -1;
    }

    mp_file[nread] = 0;

    const size_t len = superchop_with_length (mp_file, nread);

    if (len == 0)
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is corrupted.", buf);

      return -1;
    }

    const int rc = mp_expand (hashcat_ctx, mp_file, len, mp_sys, mp_usr, userindex, 0);

    if (rc == -1) return -1;
  }

  return 0;
}

static void mp_reset_usr (cs_t *mp_usr, const u32 userindex)
{
  mp_usr[userindex].cs_len = 0;

  memset (mp_usr[userindex].cs_buf, 0, sizeof (mp_usr[userindex].cs_buf));
}

static int sp_setup_tbl (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  mask_ctx_t      *mask_ctx      = hashcat_ctx->mask_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  char *shared_dir = folder_config->shared_dir;

  char *hcstat  = user_options->markov_hcstat2;
  u32   markov  = user_options->markov;
  u32   classic = user_options->markov_classic;
  bool  inverse = user_options->markov_inverse;

  hcstat_table_t *root_table_buf   = mask_ctx->root_table_buf;
  hcstat_table_t *markov_table_buf = mask_ctx->markov_table_buf;

  /**
   * Initialize hcstats
   */

  u64 *root_stats_buf = (u64 *) hccalloc (SP_ROOT_CNT, sizeof (u64));

  u64 *root_stats_ptr = root_stats_buf;

  u64 *root_stats_buf_by_pos[SP_PW_MAX];

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  u64 *markov_stats_buf = (u64 *) hccalloc (SP_MARKOV_CNT, sizeof (u64));

  u64 *markov_stats_ptr = markov_stats_buf;

  u64 *(*markov_stats_buf_by_key)[CHARSIZ] = (u64 *(*)[CHARSIZ]) hcmalloc (SP_PW_MAX * sizeof (*markov_stats_buf_by_key));

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    for (int j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /**
   * Load hcstats File
   */

  char hcstat_tmp[256];

  if (hcstat == NULL)
  {
    snprintf (hcstat_tmp, sizeof (hcstat_tmp), "%s/%s", shared_dir, SP_HCSTAT);

    hcstat = hcstat_tmp;
  }

  struct stat s;

  if (stat (hcstat, &s) == -1)
  {
    event_log_error (hashcat_ctx, "%s: %s", hcstat, strerror (errno));

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  HCFILE fp;

  if (hc_fopen_raw (&fp, hcstat, "rb") == false)
  {
    event_log_error (hashcat_ctx, "%s: %s", hcstat, strerror (errno));

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  u8 *inbuf = (u8 *) hcmalloc (s.st_size);

  size_t inlen = hc_fread (inbuf, 1, s.st_size, &fp);

  if (inlen != (size_t) s.st_size)
  {
    event_log_error (hashcat_ctx, "%s: Could not read data.", hcstat);

    hc_fclose (&fp);

    hcfree (inbuf);

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  hc_fclose (&fp);

  u8 *outbuf = (u8 *) hcmalloc (SP_FILESZ);

  size_t outlen = SP_FILESZ;

  const char props = 0x1c; // lzma properties constant, retrieved with 7z2hashcat

  const bool res = hc_lzma2_decompress (inbuf, &inlen, outbuf, &outlen, &props);

  if (res == false)
  {
    event_log_error (hashcat_ctx, "%s: Could not uncompress data.", hcstat);

    hcfree (inbuf);
    hcfree (outbuf);

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  if (outlen != SP_FILESZ)
  {
    event_log_error (hashcat_ctx, "%s: Could not uncompress data.", hcstat);

    hcfree (inbuf);
    hcfree (outbuf);

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  u64 *ptr = (u64 *) outbuf;

  u64 v = *ptr++;
  u64 z = *ptr++;

  memcpy (root_stats_buf,   ptr, sizeof (u64) * SP_ROOT_CNT);   ptr += SP_ROOT_CNT;
  memcpy (markov_stats_buf, ptr, sizeof (u64) * SP_MARKOV_CNT); // ptr += SP_MARKOV_CNT;

  hcfree (inbuf);
  hcfree (outbuf);

  /**
   * switch endianess
   */

  v = byte_swap_64 (v);
  z = byte_swap_64 (z);

  for (int i = 0; i < SP_ROOT_CNT; i++)   root_stats_buf[i]   = byte_swap_64 (root_stats_buf[i]);
  for (int i = 0; i < SP_MARKOV_CNT; i++) markov_stats_buf[i] = byte_swap_64 (markov_stats_buf[i]);

  /**
   * markov inverse: https://github.com/hashcat/hashcat/issues/1058
   */

  if (inverse == true)
  {
    for (int i = 0; i < SP_ROOT_CNT; i++)   root_stats_buf[i]   = 0 - (1 + root_stats_buf[i]);
    for (int i = 0; i < SP_MARKOV_CNT; i++) markov_stats_buf[i] = 0 - (1 + markov_stats_buf[i]);
  }

  /**
   * verify header
   */

  if (v != SP_VERSION)
  {
    event_log_error (hashcat_ctx, "%s: Invalid header", hcstat);

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  if (z != 0)
  {
    event_log_error (hashcat_ctx, "%s: Invalid header", hcstat);

    hcfree (root_stats_buf);
    hcfree (markov_stats_buf);
    hcfree (markov_stats_buf_by_key);

    return -1;
  }

  /**
   * Markov modifier of hcstat_table on user request
   */

  if (markov == false)
  {
    memset (root_stats_buf,   0, SP_ROOT_CNT   * sizeof (u64));
    memset (markov_stats_buf, 0, SP_MARKOV_CNT * sizeof (u64));
  }

  if (classic)
  {
    /* Add all stats to first position */

    for (int i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = root_stats_buf_by_pos[0];
      u64 *in  = root_stats_buf_by_pos[i];

      for (int j = 0; j < CHARSIZ; j++)
      {
        *out++ += *in++;
      }
    }

    for (int i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = markov_stats_buf_by_key[0][0];
      u64 *in  = markov_stats_buf_by_key[i][0];

      for (int j = 0; j < CHARSIZ; j++)
      {
        for (int k = 0; k < CHARSIZ; k++)
        {
          *out++ += *in++;
        }
      }
    }

    /* copy them to all pw_positions */

    for (int i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (root_stats_buf_by_pos[i], root_stats_buf_by_pos[0], CHARSIZ * sizeof (u64));
    }

    for (int i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (markov_stats_buf_by_key[i][0], markov_stats_buf_by_key[0][0], CHARSIZ * CHARSIZ * sizeof (u64));
    }
  }

  /**
   * Initialize tables
   */

  hcstat_table_t *root_table_ptr = root_table_buf;

  hcstat_table_t *root_table_buf_by_pos[SP_PW_MAX];

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    root_table_buf_by_pos[i] = root_table_ptr;

    root_table_ptr += CHARSIZ;
  }

  hcstat_table_t *markov_table_ptr = markov_table_buf;

  hcstat_table_t *(*markov_table_buf_by_key)[CHARSIZ] = (hcstat_table_t *(*)[CHARSIZ]) hcmalloc (SP_PW_MAX * sizeof (*markov_table_buf_by_key));

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    for (int j = 0; j < CHARSIZ; j++)
    {
      markov_table_buf_by_key[i][j] = markov_table_ptr;

      markov_table_ptr += CHARSIZ;
    }
  }

  /**
   * Convert hcstat to tables
   */

  for (int i = 0; i < SP_ROOT_CNT; i++)
  {
    u32 key = i % CHARSIZ;

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (int i = 0; i < SP_MARKOV_CNT; i++)
  {
    u32 key = i % CHARSIZ;

    markov_table_buf[i].key = key;
    markov_table_buf[i].val = markov_stats_buf[i];
  }

  hcfree (root_stats_buf);
  hcfree (markov_stats_buf);
  hcfree (markov_stats_buf_by_key);


  /**
   * Finally sort them
   */

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    qsort (root_table_buf_by_pos[i], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
  }

  for (int i = 0; i < SP_PW_MAX; i++)
  {
    for (int j = 0; j < CHARSIZ; j++)
    {
      qsort (markov_table_buf_by_key[i][j], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
    }
  }

  hcfree (markov_table_buf_by_key);

  return 0;
}

static int sp_get_sum (u32 start, u32 stop, cs_t *root_css_buf, u64 *result)
{
  u64 sum = 1;

  u32 i;

  for (i = start; i < stop; i++)
  {
    if (overflow_check_u64_mul (sum, root_css_buf[i].cs_len) == true) return -1;

    sum *= root_css_buf[i].cs_len;
  }

  *result = sum;

  return 0;
}

static void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 threshold, u32 **uniq_tbls)
{
  memset (root_css_buf,   0, SP_PW_MAX *           sizeof (cs_t));
  memset (markov_css_buf, 0, SP_PW_MAX * CHARSIZ * sizeof (cs_t));

  /**
   * Convert tables to css
   */

  for (u32 i = 0; i < SP_ROOT_CNT; i++)
  {
    u32 pw_pos = i / CHARSIZ;

    cs_t *cs = &root_css_buf[pw_pos];

    if (cs->cs_len == threshold) continue;

    u32 key = root_table_buf[i].key;

    if (uniq_tbls[pw_pos][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /**
   * Convert table to css
   */

  for (u32 i = 0; i < SP_MARKOV_CNT; i++)
  {
    u32 c = i / CHARSIZ;

    cs_t *cs = &markov_css_buf[c];

    if (cs->cs_len == threshold) continue;

    u32 pw_pos = c / CHARSIZ;

    u32 key = markov_table_buf[i].key;

    if ((pw_pos + 1) < SP_PW_MAX) if (uniq_tbls[pw_pos + 1][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /*
  for (u32 i = 0; i < 8; i++)
  {
    for (u32 j = 0x20; j < 0x80; j++)
    {
      cs_t *ptr = &markov_css_buf[(i * CHARSIZ) + j];

      printf ("pos:%u key:%u len:%u" EOL, i, j, ptr->cs_len);

      for (u32 k = 0; k < 10; k++)
      {
        printf ("  %u" EOL,  ptr->cs_buf[k]);
      }
    }
  }
  */
}

void sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 start, u32 stop)
{
  u64 v = ctx;

  cs_t *cs = &root_css_buf[start];

  u32 i;

  for (i = start; i < stop; i++)
  {
    const u64 m = v % cs->cs_len;
    const u64 d = v / cs->cs_len;

    v = d;

    const u32 k = cs->cs_buf[m];

    pw_buf[i - start] = (char) k;

    cs = &markov_css_buf[(i * CHARSIZ) + k];
  }
}

// sp_exec () read backwards: the offset that produces a given stretch of a candidate.
//
// Going forward, each position takes one digit off the offset, lowest position first, writes the
// character that digit selects, and lets that character choose the next position's charset. Every
// position has a fixed radix, which is what lets sp_get_sum () call the keyspace a plain product, so
// coming back is a Horner accumulation: find the character in the charset the walk has arrived at and
// that is the digit.
//
// The walk starts from root_css_buf[start] and not from a markov charset, exactly as sp_exec () does,
// which is what makes the two halves of a split mask invertible one at a time.
//
// A character the arrived-at charset does not hold is a real refusal and the position is reported, so
// the caller can say whether the mask never allowed it there or --markov-threshold dropped it.

static bool sp_rank (const cs_t *root_css_buf, const cs_t *markov_css_buf, const u8 *pw_buf, const u32 start, const u32 stop, u64 *result, u32 *fail_pos)
{
  u64 off = 0;
  u64 mul = 1;

  const cs_t *cs = &root_css_buf[start];

  for (u32 i = start; i < stop; i++)
  {
    const u32 k = pw_buf[i];

    u32 m;

    for (m = 0; m < cs->cs_len; m++)
    {
      if (cs->cs_buf[m] == k) break;
    }

    if (m == cs->cs_len)
    {
      *fail_pos = i;

      return false;
    }

    off += (u64) m * mul;
    mul *= cs->cs_len;

    cs = &markov_css_buf[(i * CHARSIZ) + k];
  }

  *result = off;

  return true;
}

// Whether the mask itself allows a character at a position, as opposed to whether the tables built
// from it still hold that character. The two differ only under --markov-threshold, and telling them
// apart is the difference between "this mask cannot spell it" and "raise -t and it can".

static bool mp_css_allows (const cs_t *css_buf, const u32 css_pos, const u32 chr)
{
  const cs_t *cs = &css_buf[css_pos];

  for (u32 i = 0; i < cs->cs_len; i++)
  {
    if (cs->cs_buf[i] == chr) return true;
  }

  return false;
}

// Whether -S would reach the candidate, which is the same mask walked in one piece rather than in
// the two the devices need. Asked on both the hit and the miss path, because the two engines can
// each hold a candidate the other does not.

static bool mask_ctx_lookup_whole (const mask_ctx_t *mask_ctx, const u8 *pw_buf, const u32 css_cnt_orig)
{
  u64 whole = 0;

  u32 whole_fail = 0;

  return sp_rank (mask_ctx->root_css_buf, mask_ctx->markov_css_buf, pw_buf, 0, css_cnt_orig, &whole, &whole_fail);
}

// Where this round's mask reaches the candidate --lookup asked about.
//
// The run does not walk a mask in one piece. mp_css_split_cnt () cuts it into the amplifier, the
// css_cnt_r lowest positions, and the base word, everything above them, and the two are enumerated
// separately: the base word walk starts from root_css_buf[css_cnt_r] rather than from the markov
// charset the character below it would have chosen. So the cut is walked back the same way, in two
// pieces, or the answer would be the offset of a candidate this run never produces.
//
// css_cnt_orig is the mask's own length. mask_ctx->css_cnt can be longer, because an appended salt
// adds fixed positions to it, and those are not the user's to spell. They cost nothing to leave out:
// a fixed position has radix 1, so it contributes no digit and multiplies the offset by nothing.

static void mask_ctx_lookup (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_orig, const u32 css_cnt_r)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const user_options_t *user_options = hashcat_ctx->user_options;

  mask_ctx_t    *mask_ctx = hashcat_ctx->mask_ctx;
  mask_lookup_t *lookup   = &mask_ctx->lookup;

  if (user_options->lookup == NULL) return;

  // The queue is walked in the order the run walks it, so the first round that reaches the candidate
  // is where the run reaches it and no later round can be nearer.

  if (lookup->hit == true) return;

  const u8 *arg     = (const u8 *) user_options->lookup;
  const u32 arg_len = (u32) strlen (user_options->lookup);

  u8 cand[PW_MAX];

  u32 cand_len = 0;

  // A ?b mask produces candidates that no command line can carry, and a shell cannot pass a NUL byte
  // at all. $HEX[...] is how the rest of hashcat writes such a word, in the potfile and in --show,
  // so a candidate is accepted in it here for the same reason.

  if (is_hexify (arg, arg_len) == true)
  {
    cand_len = (u32) exec_unhexify (arg, arg_len, cand, sizeof (cand));
  }
  else
  {
    if (arg_len > sizeof (cand)) return;

    memcpy (cand, arg, arg_len);

    cand_len = arg_len;
  }

  // A mode that hashes in upper case has had every charset folded by mp_add_cs_buf (), so a lower
  // case candidate would be refused by a run that does reach it, spelled the mode's way.

  if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
  {
    for (u32 i = 0; i < cand_len; i++) cand[i] = (u8) toupper (cand[i]);

    lookup->uppered = true;
  }

  // The candidate as the mask spells it. A mode that hashes UTF-16 has had its css expanded to two
  // entries per character, one of them a fixed zero, and the run compares against that rather than
  // against what the user typed.

  u8 pw_buf[PW_MAX * 2];

  u32 pw_len = 0;

  // How many css entries one character of the candidate occupies, which is two for a UTF-16 mode and
  // one for everything else. Every position the user is told about is divided back down by it, so a
  // refusal is reported at the character they typed and not at the byte the mask counts.

  u32 stride = 1;

  if ((user_options->slow_candidates == false) && (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE))
  {
    for (u32 i = 0; i < cand_len; i++)
    {
      pw_buf[(i * 2) + 0] = cand[i];
      pw_buf[(i * 2) + 1] = 0;
    }

    pw_len = cand_len * 2;
    stride = 2;
  }
  else if ((user_options->slow_candidates == false) && (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE))
  {
    for (u32 i = 0; i < cand_len; i++)
    {
      pw_buf[(i * 2) + 0] = 0;
      pw_buf[(i * 2) + 1] = cand[i];
    }

    pw_len = cand_len * 2;
    stride = 2;
  }
  else
  {
    memcpy (pw_buf, cand, cand_len);

    pw_len = cand_len;
  }

  // A mask of the wrong length holds no offset at all. It is still worth recording, because a queue
  // in which no mask is the right length is a different answer from one where the lengths are there
  // and the characters are not.

  if (pw_len != css_cnt_orig)
  {
    if (lookup->miss == MASK_LOOKUP_MISS_NONE)
    {
      lookup->miss       = MASK_LOOKUP_MISS_LENGTH;
      lookup->round_miss = mask_ctx->masks_pos;
      lookup->miss_pos   = 0;
      lookup->miss_chr   = 0;

      snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
    }

    return;
  }

  u64 amp  = 0;
  u64 word = 0;

  u32 fail_pos = 0;

  const bool got = sp_rank (mask_ctx->root_css_buf, mask_ctx->markov_css_buf, pw_buf, 0, css_cnt_r, &amp, &fail_pos)
                && sp_rank (mask_ctx->root_css_buf, mask_ctx->markov_css_buf, pw_buf, css_cnt_r, css_cnt_orig, &word, &fail_pos);

  if (got == false)
  {
    // The other engine, asked the same question. -S walks the mask in one piece, so a character the
    // split refused at the boundary can still be there, and saying so is the difference between
    // "change the mask" and "add -S". Only the direction that costs one walk is answered: a run that
    // already has -S has no second engine to offer, because the split is what the devices need.

    // Sticky across the queue, because the claim it backs is about the queue: some mask in it is one
    // -S would reach. A plain assignment would leave the last round's answer rather than the queue's.

    if (css_cnt_r > 0)
    {
      lookup->other_probed = true;

      if (mask_ctx_lookup_whole (mask_ctx, pw_buf, css_cnt_orig) == true) lookup->other = true;
    }

    // A miss from a mask of the right length always beats one from a mask of the wrong length, and
    // among those the one that got furthest along the candidate is the one worth naming.

    if ((lookup->miss == MASK_LOOKUP_MISS_NONE) || (lookup->miss == MASK_LOOKUP_MISS_LENGTH) || (((fail_pos / stride) + 1) > lookup->miss_pos))
    {
      const u32 chr = pw_buf[fail_pos];

      lookup->miss       = (mp_css_allows (mask_ctx->css_buf, fail_pos, chr) == true) ? MASK_LOOKUP_MISS_MARKOV : MASK_LOOKUP_MISS_CHARSET;
      lookup->round_miss = mask_ctx->masks_pos;
      lookup->miss_pos   = (fail_pos / stride) + 1;
      lookup->miss_chr   = chr;

      snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
    }

    return;
  }

  // The same question of the other engine, now that this one has answered. A candidate the split
  // reaches can be one -S does not: the split walk restarts from root_css_buf[css_cnt_r], and under
  // --markov-threshold root holds characters the markov table at that position does not. Handing out
  // an offset without saying that would send a user who later adds -S past their own password.

  if (css_cnt_r > 0)
  {
    lookup->other_probed = true;
    lookup->other        = mask_ctx_lookup_whole (mask_ctx, pw_buf, css_cnt_orig);
  }

  lookup->hit     = true;
  lookup->round   = mask_ctx->masks_pos;
  lookup->word    = word;
  lookup->amp     = amp;
  lookup->amp_cnt = mask_ctx->bfs_cnt;

  snprintf (lookup->mask, sizeof (lookup->mask), "%s", mask_ctx->mask);
}

// Copy one piece of a -a 12 candidate without running past the end of the buffer, and report how much
// was taken.

static u32 hybrid_append (u8 *out_buf, const u32 out_len, const u8 *src, const u32 src_len)
{
  if (out_len >= PW_MAX) return 0;

  const u32 copy_len = MIN (src_len, PW_MAX - out_len);

  memcpy (out_buf + out_len, src, copy_len);

  return copy_len;
}

// The mask value at an amplifier position, produced whole. With a ?q an amplifier position covers a
// mask value and a word from the second wordlist together, and the word index runs fastest so that one
// pass of the mask is one pass of that wordlist.

u32 hybrid_amp_mask (hashcat_ctx_t *hashcat_ctx, const u64 off, char *mask_buf)
{
  const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u64 mask_pos = off;

  if (mask_ctx->has_q == true)
  {
    const u64 words_cnt = hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP].keyspace;

    mask_pos = off / words_cnt;
  }

  sp_exec (mask_pos, mask_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, 0, mask_ctx->css_cnt);

  return mask_ctx->css_cnt;
}

// Put one -a 12 candidate together out of the amplifier the fill already built, rather than out of
// the amplifier position. Two reasons it has to come from the buffer.
//
// The bytes in it are the bytes the kernel was given. The second word has been through the -k rule
// and the encoding options, and reading the feed again here would report the word before any of that.
// It would also be a second reader of a feed the device thread is in the middle of: the fill seeks
// once per chunk and then reads forward through it, so a status refresh landing mid chunk would move
// the shared position and the rest of that chunk would get the wrong words.
//
// And the item is no longer at the position it belongs to. A ?q word the transform refuses gives up
// its item, so everything the fill accepted after it has moved up, and only the fill knows by how
// much. The buffer is the record of what it decided.

u32 hybrid_amp_rebuild (hashcat_ctx_t *hashcat_ctx, const hc_device_param_t *device_param, const u32 il_pos, u8 *out_buf, const u8 *base_buf, const u32 base_len)
{
  const combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;

  u32 out_len = 0;

  if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_MIDDLE)
  {
    const pw_t *pre_ptr  = &device_param->combs_buf[((u64) il_pos * COMBS_PIECE_CNT) + COMBS_PIECE_PRE];
    const pw_t *mid_ptr  = &device_param->combs_buf[((u64) il_pos * COMBS_PIECE_CNT) + COMBS_PIECE_MID];
    const pw_t *word_ptr = &device_param->combs_buf[((u64) il_pos * COMBS_PIECE_CNT) + COMBS_PIECE_WORD];
    const pw_t *post_ptr = &device_param->combs_buf[((u64) il_pos * COMBS_PIECE_CNT) + COMBS_PIECE_POST];

    out_len += hybrid_append (out_buf, out_len, (const u8 *) pre_ptr->i,  pre_ptr->pw_len);
    out_len += hybrid_append (out_buf, out_len, base_buf,                 base_len);
    out_len += hybrid_append (out_buf, out_len, (const u8 *) mid_ptr->i,  mid_ptr->pw_len);
    out_len += hybrid_append (out_buf, out_len, (const u8 *) word_ptr->i, word_ptr->pw_len);
    out_len += hybrid_append (out_buf, out_len, (const u8 *) post_ptr->i, post_ptr->pw_len);

    return out_len;
  }

  // One buffer, and which side of the base word it goes on is the whole difference between the two
  // layouts that use one.

  const pw_t *one_ptr = &device_param->combs_buf[il_pos];

  if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_RIGHT)
  {
    out_len += hybrid_append (out_buf, out_len, (const u8 *) one_ptr->i, one_ptr->pw_len);
    out_len += hybrid_append (out_buf, out_len, base_buf,                base_len);

    return out_len;
  }

  out_len += hybrid_append (out_buf, out_len, base_buf,                base_len);
  out_len += hybrid_append (out_buf, out_len, (const u8 *) one_ptr->i, one_ptr->pw_len);

  return out_len;
}

// Put one -a 12 candidate together from its pieces, in the one order the amplifier kernel also uses:
// mask, base word, mask, second word, mask. Any of the five may be empty.

u32 hybrid_assemble (hashcat_ctx_t *hashcat_ctx, u8 *out_buf, const char *mask_buf, const u8 *base_buf, const u32 base_len, const u8 *word_buf, const u32 word_len)
{
  const mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  const u32 pre_len  = mask_ctx->pre_len;
  const u32 mid_len  = mask_ctx->mid_len;
  const u32 post_len = mask_ctx->css_cnt - pre_len - mid_len;

  const u8 *mask_ptr = (const u8 *) mask_buf;

  u32 out_len = 0;

  out_len += hybrid_append (out_buf, out_len, mask_ptr,                     pre_len);
  out_len += hybrid_append (out_buf, out_len, base_buf,                     base_len);
  out_len += hybrid_append (out_buf, out_len, mask_ptr + pre_len,           mid_len);
  out_len += hybrid_append (out_buf, out_len, word_buf,                     word_len);
  out_len += hybrid_append (out_buf, out_len, mask_ptr + pre_len + mid_len, post_len);

  return out_len;
}

static int mask_append_final (hashcat_ctx_t *hashcat_ctx, const char *mask)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  const user_options_t *user_options = hashcat_ctx->user_options;

  if (mask_ctx->masks_avail == mask_ctx->masks_cnt)
  {
    char **tmp = (char **) hcrealloc (mask_ctx->masks, mask_ctx->masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

    if (tmp == NULL) return -1;

    mask_ctx->masks = tmp;

    mask_ctx->masks_avail += INCR_MASKS;
  }

  // -a 6 and -a 7 are -a 12 masks with the ?w at one end, and this is where it goes on. Here rather
  // than on the argument, because every mask arrives here and this is the last thing that happens to
  // one: a mask file line arrives with its own charsets already split off, and an --increment mask
  // arrives already truncated and already mirrored. So -i keeps working for both of them with no
  // change to the increment machinery at all.

  char mask_buf[256];

  if (user_options->marker_policy != MARKER_POLICY_NONE)
  {
    const char *fmt = (user_options->marker_policy == MARKER_POLICY_PREFIX_W) ? "?w%s" : "%s?w";

    if (snprintf (mask_buf, sizeof (mask_buf), fmt, mask) >= (int) sizeof (mask_buf))
    {
      event_log_error (hashcat_ctx, "%s: mask is too long.", mask);

      return -1;
    }

    mask = mask_buf;
  }

  mask_ctx->masks[mask_ctx->masks_cnt] = hcstrdup (mask);

  mask_ctx->masks_cnt++;

  return 0;
}

// ?l?u?d -> ?d?u?l
static char* reverseMask (const char *mask, const char *prepend)
{
  u32 maskLength = strlen (mask);
  u32 prependLength = strlen (prepend);

  char *tmp_buf = (char *) hcmalloc (256);

  u32 i = 0;

  // Add prepend section to tmp_buf, avoiding reversal
  if (prependLength != 0)
  {
    for (i = 0; i < prependLength ; i++)
    {
      tmp_buf[i] = prepend[i];
    }
    tmp_buf[i++] = ',';
  }

  for (u32 j = maskLength - 1; i <= maskLength - 1 ; i++)
  {
    if (mask[i] == '?' && mask[i + 1] != '\0')
    {
        tmp_buf[j--] = mask[i + 1];
        tmp_buf[j--] = mask[i];
        i++;
    }
    else
    {
        tmp_buf[j--] = mask[i];
    }
  }

  return tmp_buf;
}

static int mask_append (hashcat_ctx_t *hashcat_ctx, const char *mask, const char *prepend)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->increment != INCREMENT_NONE)
  {
    const u32 mask_length = mp_get_length (mask, hashconfig->opts_type);

    u32 increment_min = user_options->increment_min;
    u32 increment_max = user_options->increment_max;

    increment_max = MIN (increment_max, mask_length);

    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      const u32 pw_min = hashconfig->pw_min;
      const u32 pw_max = hashconfig->pw_max;

      increment_min = MAX (increment_min, pw_min);
      increment_max = MIN (increment_max, pw_max);
    }

    for (u32 increment_len = increment_min; increment_len <= increment_max; increment_len++)
    {
      char *mask_truncated = (char *) hcmalloc (256);

      char *mask_truncated_next = mask_truncated;

      if (prepend)
      {
        // this happens with maskfiles only

        mask_truncated_next += snprintf (mask_truncated, 256, "%s,", prepend);
      }

      if (user_options->increment == INCREMENT_INVERSED)
      {
        if (mp_get_truncated_mask (hashcat_ctx, reverseMask (mask, ""), strlen (mask), increment_len, mask_truncated_next) == -1)
        {
          hcfree (mask_truncated);

          break;
        }

        if (prepend)
        {
          mask_truncated = reverseMask (mask_truncated, prepend);
        }
        else
        {
         mask_truncated = reverseMask (mask_truncated, "");
        }
      }
      else
      {
        if (mp_get_truncated_mask (hashcat_ctx, mask, strlen (mask), increment_len, mask_truncated_next) == -1)
        {
          hcfree (mask_truncated);

          break;
        }
      }

      const int rc = mask_append_final (hashcat_ctx, mask_truncated);

      hcfree (mask_truncated);

      if (rc == -1) return -1;
    }
  }
  else
  {
    if (prepend)
    {
      // this happens with maskfiles only

      char *prepend_mask = NULL;

      hc_asprintf (&prepend_mask, "%s,%s", prepend, mask);

      const int rc = mask_append_final (hashcat_ctx, prepend_mask);

      hcfree (prepend_mask);

      if (rc == -1) return -1;
    }
    else
    {
      if (mask_append_final (hashcat_ctx, mask) == -1) return -1;
    }
  }

  return 0;
}

u32 mp_get_length (const char *mask, const u32 opts_type)
{
  bool ignore_next = false;

  u32 len = 0;

  const size_t mask_len = strlen (mask);

  for (size_t i = 0; i < mask_len; i++)
  {
    if (ignore_next == true)
    {
      ignore_next = false;
    }
    else
    {
      if (mask[i] == '?')
      {
        ignore_next = true;
      }

      if (opts_type & OPTS_TYPE_MT_HEX)
      {
        ignore_next = true;
      }

      len++;
    }
  }

  return len;
}

static char *mask_ctx_parse_maskfile_find_mask (char *line_buf, const size_t line_len)
{
  char *mask_buf = line_buf;

  bool escaped = false;

  for (size_t i = 0; i < line_len; i++)
  {
    if (escaped == true)
    {
      escaped = false;
    }
    else
    {
      if (line_buf[i] == '\\')
      {
        escaped = true;
      }
      else if (line_buf[i] == ',')
      {
        mask_buf = line_buf + i + 1;
      }
    }
  }

  return mask_buf;
}

// Does the mask start with the given marker? That is the first token and nothing before it, so the
// test is the first two bytes and no walk is needed. "??w" starts with a literal question mark.

bool mask_starts_with_marker (const char *mask, const char marker)
{
  if (mask == NULL) return false;

  if (mask[0] != '?') return false;

  if (mask[1] != marker) return false;

  return true;
}

// Does every mask a work argument names end in the given marker? Every one of them, because the base
// word source is chosen once for the whole session and a mask file cannot change it halfway through.
// A file whose lines disagree answers false and the run keeps the wordlist as its base, which
// produces the same candidates in a different order.

bool mask_arg_ends_with_marker (const char *arg, const char marker)
{
  if (arg == NULL) return false;

  if (hc_path_exist (arg) == false) return mask_ends_with_marker (arg, marker);

  if (hc_path_is_file (arg) == false) return false;

  HCFILE mask_fp;

  if (hc_fopen (&mask_fp, arg, "r") == false) return false;

  char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

  bool all = false;

  while (hc_feof (&mask_fp) == 0)
  {
    const size_t line_len = fgetl (&mask_fp, line_buf, HCBUFSIZ_LARGE);

    if (line_len == 0) continue;

    if (line_buf[0] == '#') continue;

    const char *mask_buf = mask_ctx_parse_maskfile_find_mask (line_buf, line_len);

    if (mask_ends_with_marker (mask_buf, marker) == false)
    {
      all = false;

      break;
    }

    all = true;
  }

  hcfree (line_buf);

  hc_fclose (&mask_fp);

  return all;
}

// Defined below, next to the report that reads what it finds, and called from the hybrid branch of
// the loop below.

static void mask_ctx_lookup_combi (hashcat_ctx_t *hashcat_ctx);

int mask_ctx_update_loop (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  logfile_ctx_t        *logfile_ctx        = hashcat_ctx->logfile_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
  {
  // The mask is the base word source, so its size is the base word count and the amplifier count
    // belongs to the wordlist. That is -a 7 under a pure kernel, and -a 12 under a pure kernel
    // whenever its mask ends in ?w.

    if (user_options_extra->base_source == BASE_SOURCE_MASK)
    {
      mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

      if (mask_ctx_parse_maskfile (hashcat_ctx) == -1) return -1;

      if (mp_gen_css (hashcat_ctx, mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, mask_ctx->css_buf, &mask_ctx->css_cnt) == -1) return -1;

      u32 **uniq_tbls = (u32 **) hcmalloc (SP_PW_MAX * sizeof(u32 *));

      for (int i = 0; i < SP_PW_MAX; i++) uniq_tbls[i] = (u32 *) hcmalloc(CHARSIZ * sizeof(u32));

      mp_css_to_uniq_tbl (hashcat_ctx, mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      for (int i = 0; i < SP_PW_MAX; i++) hcfree (uniq_tbls[i]);

      hcfree (uniq_tbls);

      if (sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf, &mask_ctx->bfs_cnt) == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

        return -1;
      }

      if (backend_session_update_mp (hashcat_ctx) == -1) return -1;
    }
    else
    {
      mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

      if (mask_ctx_parse_maskfile (hashcat_ctx) == -1) return -1;

      if (mp_gen_css (hashcat_ctx, mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, mask_ctx->css_buf, &mask_ctx->css_cnt) == -1) return -1;

      u32 **uniq_tbls = (u32 **) hcmalloc (SP_PW_MAX * sizeof(u32 *));

      for (int i = 0; i < SP_PW_MAX; i++) uniq_tbls[i] = (u32 *) hcmalloc(CHARSIZ * sizeof(u32));

      mp_css_to_uniq_tbl (hashcat_ctx, mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      for (int i = 0; i < SP_PW_MAX; i++) hcfree (uniq_tbls[i]);

      hcfree (uniq_tbls);

      if (sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf, &combinator_ctx->combs_cnt) == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

        return -1;
      }

      // A ?q puts a second word in every candidate, and that word amplifies the base word the same
      // way the mask does. Both live in the one amplifier rather than in two, so the amplifier count
      // is the product and an amplifier position divides back into a mask index and a word index.
      // With no mask left at all, ?w?q, the product is just the second wordlist, which is -a 1.

      if (mask_ctx->has_q == true)
      {
        const u64 words_cnt = hashcat_ctx->generic_ctx[GENERIC_ROLE_AMP].keyspace;

        if (words_cnt == GENERIC_KEYSPACE_UNKNOWN)
        {
          event_log_error (hashcat_ctx, "?q: feed cannot report a keyspace.");

          return -1;
        }

        // No instance was opened, so the amplifier count would be multiplied by nothing and the
        // round would compute an empty keyspace without saying so.

        if (words_cnt == 0)
        {
          event_log_error (hashcat_ctx, "%s: has a ?q, but no wordlist was given for it.", mask_ctx->mask);

          return -1;
        }

        if (overflow_check_u64_mul (combinator_ctx->combs_cnt, words_cnt) == true)
        {
          event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

          return -1;
        }

        combinator_ctx->combs_cnt *= words_cnt;
      }

      // Nothing in front of the base word means everything else is behind it, and everything behind
      // it is contiguous: the mask between the words, the second word, the mask after it. So the
      // host can hand the kernel one buffer instead of four, which is the layout every other attack
      // mode already uses and a quarter of the upload.
      //
      // That covers ?w?d?d and ?w?q, and also ?w?d?q, ?w?q?d and ?w?d?q?d, which are only five
      // pieces on paper.
      //
      // The mirror image is one buffer as well. Nothing behind the word and no ?q leaves the whole
      // mask in front of it, which is the layout -a 7 uses. Only an optimized kernel can be given
      // it: a pure kernel appends its amplifier to a context that has already absorbed the base
      // word, so it has no way to put anything in front.
      //
      // Anything else really is five pieces, because the base word splits the amplifier in two.
      //
      // The mask is parsed per mask, so this is decided per mask as well, and
      // backend_session_update_combinator () carries it to the devices.

      if (user_options->attack_mode == ATTACK_MODE_HYBRID)
      {
        const u32 post_len = mask_ctx->css_cnt - mask_ctx->pre_len - mask_ctx->mid_len;

        const bool mask_in_front = (post_len == 0) && (mask_ctx->has_q == false);

        const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;

        if (combinator_ctx->roles_swapped == true)
        {
          // The two wordlists were swapped so that the bigger one is the base word source, so the
          // smaller one goes in front of it and the candidate still comes out in the order it was
          // typed.

          combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;
        }
        else if (mask_ctx->pre_len == 0)
        {
          combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_LEFT;
        }
        else if ((mask_in_front == true) && (optimized_kernel == true))
        {
          combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_RIGHT;
        }
        else
        {
          combinator_ctx->combs_mode = COMBINATOR_MODE_BASE_MIDDLE;
        }
      }

      // do not allow modifier count > 32 bit
      // https://github.com/hashcat/hashcat/issues/2482

      // if (combinator_ctx->combs_cnt > 0xffffffff)
      // {
      //   event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

      //   return -1;
      // }

      if (backend_session_update_mp (hashcat_ctx) == -1) return -1;
    }

    // Everything a hybrid lookup needs is settled by here and nowhere earlier: the mask tables, the
    // three mask piece lengths, and combs_cnt, which the ?q multiplication above is part of.

    mask_ctx_lookup_combi (hashcat_ctx);

    if (backend_session_update_combinator (hashcat_ctx) == -1) return -1;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

    if (mask_ctx_parse_maskfile (hashcat_ctx) == -1) return -1;

    if (user_options->attack_mode == ATTACK_MODE_BF) // always true
    {
      if (mp_gen_css (hashcat_ctx, mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, mask_ctx->css_buf, &mask_ctx->css_cnt) == -1) return -1;

      // special case for benchmark

      u32 pw_min = hashconfig->pw_min;
      u32 pw_max = hashconfig->pw_max;

      if (user_options->benchmark == true)
      {
        pw_min = mp_get_length (mask_ctx->mask, hashconfig->opts_type);
        pw_max = pw_min;
      }

      hashconfig->pw_min = pw_min;
      hashconfig->pw_max = pw_max;

      // check if mask is not too large or too small for pw_min/pw_max

      u32 mask_min = hashconfig->pw_min;
      u32 mask_max = hashconfig->pw_max;

      if ((mask_ctx->css_cnt < mask_min) || (mask_ctx->css_cnt > mask_max))
      {
        if (mask_ctx->css_cnt < mask_min)
        {
          event_log_warning (hashcat_ctx, "Skipping mask '%s' because it is smaller than the minimum password length.", mask_ctx->mask);
          event_log_warning (hashcat_ctx, NULL);
        }

        if (mask_ctx->css_cnt > mask_max)
        {
          event_log_warning (hashcat_ctx, "Skipping mask '%s' because it is larger than the maximum password length.", mask_ctx->mask);
          event_log_warning (hashcat_ctx, NULL);
        }

        // Counted because --lookup has to be able to say the run passed over a mask, rather than
        // report the queue it was left with as though that were the queue the user asked for.

        mask_ctx->lookup.skipped++;

        // skip to next mask

        logfile_sub_msg ("STOP");

        return -1;
      }

      if (user_options->slow_candidates == false)
      {
        if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16LE)
        {
          if (mp_css_utf16le_expand (hashcat_ctx) == -1) return -1;
        }
        else if (hashconfig->opts_type & OPTS_TYPE_PT_UTF16BE)
        {
          if (mp_css_utf16be_expand (hashcat_ctx) == -1) return -1;
        }
      }

      u32 css_cnt_orig = mask_ctx->css_cnt;

      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          if (mp_css_append_salt (hashcat_ctx, &hashes->salts_buf[0]) == -1) return -1;
        }
      }

      u32 **uniq_tbls = (u32 **) hcmalloc (SP_PW_MAX * sizeof(u32 *));

      for (int i = 0; i < SP_PW_MAX; i++) uniq_tbls[i] = (u32 *) hcmalloc(CHARSIZ * sizeof(u32));

      mp_css_to_uniq_tbl (hashcat_ctx, mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      for (int i = 0; i < SP_PW_MAX; i++) hcfree (uniq_tbls[i]);

      hcfree (uniq_tbls);

      if (sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf, &status_ctx->words_cnt) == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

        return -1;
      }

      // copy + args

      u32 css_cnt_lr[2];

      mp_css_split_cnt (hashcat_ctx, css_cnt_orig, css_cnt_lr);

      if (sp_get_sum (0, css_cnt_lr[1], mask_ctx->root_css_buf, &mask_ctx->bfs_cnt) == -1)
      {
        event_log_error (hashcat_ctx, "Integer overflow detected in keyspace of mask: %s", mask_ctx->mask);

        return -1;
      }

      // Everything a lookup needs is here and nowhere else: the tables the run will enumerate, the
      // cut it will enumerate them in two halves at, and the mask's own length before an appended
      // salt was added to it. The next round overwrites all three.

      mask_ctx_lookup (hashcat_ctx, css_cnt_orig, css_cnt_lr[1]);

      if (backend_session_update_mp_rl (hashcat_ctx, css_cnt_lr[0], css_cnt_lr[1]) == -1) return -1;
    }
  }

  return 0;
}

// Where a hybrid attack reaches the candidate --lookup asked about.
//
// -a 1, -a 6, -a 7 and -a 12 are one attack below the option parser, and hybrid_assemble () is the
// definition of what it produces:
//
//   mask[0, pre_len)  base word  mask[pre_len, pre_len + mid_len)  ?q word  mask[.., css_cnt)
//
// Only the two word lengths are free, so the inversion is: for each way of splitting the candidate,
// look the base word up in its feed, the ?q word up in its own, and rank what is left as a mask.
//
// The splits are not searched one at a time. Wherever the cut falls, the base word is a prefix of
// whatever follows the mask in front of it and the ?q word is a suffix of whatever precedes the mask
// behind it, so one pass of each feed answers every length at once.
//
// The mask is walked in ONE piece here, unlike -a 3. mp_css_split_cnt () is called only in the
// brute force branch; a hybrid run enumerates its mask with a single sp_exec () over the whole of it,
// so a single sp_rank () over the whole of it is the inverse. It also applies neither the UTF-16
// expansion nor the appended salt, so there is no stride and no css_cnt_orig to keep apart.

static void mask_ctx_lookup_combi (hashcat_ctx_t *hashcat_ctx)
{
  const combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

  mask_ctx_t     *mask_ctx = hashcat_ctx->mask_ctx;
  combi_lookup_t *lookup   = &mask_ctx->lookup_combi;

  if (user_options->lookup == NULL) return;

  if (lookup->hit == true) return;

  const u8 *arg     = (const u8 *) user_options->lookup;
  const u32 arg_len = (u32) strlen (user_options->lookup);

  u8 cand[PW_MAX];

  u32 cand_len = 0;

  if (is_hexify (arg, arg_len) == true)
  {
    cand_len = (u32) exec_unhexify (arg, arg_len, cand, sizeof (cand));
  }
  else
  {
    if (arg_len > sizeof (cand)) return;

    memcpy (cand, arg, arg_len);

    cand_len = arg_len;
  }

  const u32 css_cnt  = mask_ctx->css_cnt;
  const u32 pre_len  = mask_ctx->pre_len;
  const u32 mid_len  = mask_ctx->mid_len;
  const u32 post_len = css_cnt - pre_len - mid_len;

  const bool has_q = mask_ctx->has_q;

  // The mirror shape: the mask is the base word and the dictionary amplifies it, which is -a 7 under
  // a pure kernel and -a 12 under one when its mask ends in ?w. The rewrite puts the ?w last, so the
  // mask spells the front of the candidate and one word follows it, and there is nothing to split:
  // the mask's length is known, so the word's is what is left.
  //
  // The two halves swap jobs with it. The mask offset is the base word, which is what -s counts, and
  // the word index is the position inside its cell.

  if (user_options_extra->base_source == BASE_SOURCE_MASK)
  {
    if ((has_q == true) || (pre_len != css_cnt))
    {
      lookup->unsupported = true;

      return;
    }

    if (cand_len < (css_cnt + 1))
    {
      if (lookup->miss == MASK_LOOKUP_MISS_NONE)
      {
        lookup->miss = MASK_LOOKUP_MISS_LENGTH;

        snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
      }

      return;
    }

    const u32 word_len = cand_len - css_cnt;

    u64 word_at  = 0;
    u64 amp_word = 0;

    if (generic_ctx_word_family (hashcat_ctx, GENERIC_ROLE_AMP, cand + cand_len, word_len, word_len, true, &word_at, &amp_word) == -1) return;

    if (word_at == GENERIC_KEYSPACE_UNKNOWN)
    {
      if (lookup->miss == MASK_LOOKUP_MISS_NONE) snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);

      return;
    }

    u64 mask_off = 0;

    u32 fail_pos = 0;

    if (sp_rank (mask_ctx->root_css_buf, mask_ctx->markov_css_buf, cand, 0, css_cnt, &mask_off, &fail_pos) == false)
    {
      const u32 chr = cand[fail_pos];

      if ((lookup->miss == MASK_LOOKUP_MISS_NONE) || (lookup->miss == MASK_LOOKUP_MISS_LENGTH))
      {
        lookup->miss     = (mp_css_allows (mask_ctx->css_buf, fail_pos, chr) == true) ? MASK_LOOKUP_MISS_MARKOV : MASK_LOOKUP_MISS_CHARSET;
        lookup->miss_pos = fail_pos + 1;
        lookup->miss_chr = chr;

        snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
      }

      return;
    }

    lookup->hit       = true;
    lookup->round     = mask_ctx->masks_pos;
    lookup->word      = mask_off;
    lookup->amp       = word_at;
    lookup->amp_cnt   = combinator_ctx->combs_cnt;
    lookup->base_len  = css_cnt;
    lookup->q_len     = word_len;
    lookup->has_q     = false;
    lookup->mask_base = true;

    snprintf (lookup->mask, sizeof (lookup->mask), "%s", mask_ctx->mask);

    return;
  }

  // Every mask byte is spelled out in the candidate, and so is at least one byte of a base word.
  // Anything shorter than that cannot be this round's.

  const u32 words_min = (has_q == true) ? 2 : 1;

  if (cand_len < (css_cnt + words_min))
  {
    if (lookup->miss == MASK_LOOKUP_MISS_NONE)
    {
      lookup->miss = MASK_LOOKUP_MISS_LENGTH;

      snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
    }

    return;
  }

  const u32 words_len = cand_len - css_cnt;

  // How much of the candidate the base word can be. With a ?q the two words share what the mask does
  // not spell and the cut between them is free, so every split is tried. Without one there is only
  // one word and it is all of it: a shorter base word would leave bytes belonging to nothing, and
  // taking the mask from the far end regardless would match a decomposition the run never builds.

  const u32 base_min = (has_q == true) ? 1                : words_len;
  const u32 base_max = (has_q == true) ? (words_len - 1)  : words_len;

  // Which feed each half of the candidate came out of. -a 1 under an optimized kernel makes the
  // larger wordlist the base so that the smaller one amplifies it, and the candidate still comes out
  // in the order it was typed. The word in front is then the amplifier and the word behind is the
  // base word, which is the opposite of every other shape here. Reading the two roles the wrong way
  // round finds nothing, and reports a password that is in the run as absent from it.

  const bool swapped = combinator_ctx->roles_swapped;

  const generic_role_t role_pre = (swapped == true) ? GENERIC_ROLE_AMP  : GENERIC_ROLE_BASE;
  const generic_role_t role_suf = (swapped == true) ? GENERIC_ROLE_BASE : GENERIC_ROLE_AMP;

  u64 pre_idx[PW_MAX];
  u64 suf_idx[PW_MAX];

  u64 pre_words = 0;
  u64 suf_words = 0;

  if (generic_ctx_word_family (hashcat_ctx, role_pre, cand + pre_len, base_min, base_max, false, pre_idx, &pre_words) == -1) return;

  if (has_q == true)
  {
    const u32 q_min = 1;
    const u32 q_max = words_len - 1;

    if (generic_ctx_word_family (hashcat_ctx, role_suf, cand + (cand_len - post_len), q_min, q_max, true, suf_idx, &suf_words) == -1) return;
  }

  bool found = false;

  u64 best_word = 0;
  u64 best_amp  = 0;
  u32 best_base = 0;

  for (u32 base_len = base_min; base_len <= base_max; base_len++)
  {
    if (pre_idx[base_len - base_min] == GENERIC_KEYSPACE_UNKNOWN) continue;

    const u64 pre_at = pre_idx[base_len - base_min];

    const u32 q_len = words_len - base_len;

    u64 suf_at = 0;

    if (has_q == true)
    {
      if (suf_idx[q_len - 1] == GENERIC_KEYSPACE_UNKNOWN) continue;

      suf_at = suf_idx[q_len - 1];
    }

    // The mask, back in mask order: the piece in front of the base word, the piece between the two
    // words, and the piece behind the second one, with the words themselves taken out.

    u8 pw_buf[PW_MAX];

    u32 pw_len = 0;

    memcpy (pw_buf + pw_len, cand, pre_len);                                   pw_len += pre_len;
    memcpy (pw_buf + pw_len, cand + pre_len + base_len, mid_len);              pw_len += mid_len;
    memcpy (pw_buf + pw_len, cand + (cand_len - post_len), post_len);          pw_len += post_len;

    u64 mask_off = 0;

    u32 fail_pos = 0;

    if (css_cnt > 0)
    {
      if (sp_rank (mask_ctx->root_css_buf, mask_ctx->markov_css_buf, pw_buf, 0, css_cnt, &mask_off, &fail_pos) == false)
      {
        const u32 chr = pw_buf[fail_pos];

        if ((lookup->miss == MASK_LOOKUP_MISS_NONE) || (lookup->miss == MASK_LOOKUP_MISS_LENGTH))
        {
          lookup->miss     = (mp_css_allows (mask_ctx->css_buf, fail_pos, chr) == true) ? MASK_LOOKUP_MISS_MARKOV : MASK_LOOKUP_MISS_CHARSET;
          lookup->miss_pos = fail_pos + 1;
          lookup->miss_chr = chr;

          snprintf (lookup->mask_miss, sizeof (lookup->mask_miss), "%s", mask_ctx->mask);
        }

        continue;
      }
    }

    // A ?q puts a second word in every candidate and it amplifies the base word alongside the mask,
    // so one amplifier position holds both, with the word index running fastest.

    // A ?q word and a mask value live in one amplifier position together, with the word running
    // fastest. Which word that is follows the roles: the amplifier is the half of the candidate the
    // base word is not.

    const u64 amp = (swapped == true)
                  ? ((mask_off * pre_words) + pre_at)
                  : ((has_q == true) ? ((mask_off * suf_words) + suf_at) : mask_off);

    const u64 word = (swapped == true) ? suf_at : pre_at;

    // Several splits can be real at once, and the run reaches the earliest of them first.

    if ((found == false) || (word < best_word) || ((word == best_word) && (amp < best_amp)))
    {
      found     = true;
      best_word = word;
      best_amp  = amp;
      best_base = base_len;
    }
  }

  if (found == false) return;

  lookup->hit      = true;
  lookup->round    = mask_ctx->masks_pos;
  lookup->word     = best_word;
  lookup->amp      = best_amp;
  lookup->amp_cnt  = combinator_ctx->combs_cnt;
  lookup->base_len = best_base;
  lookup->q_len    = words_len - best_base;
  lookup->has_q    = has_q;

  snprintf (lookup->mask, sizeof (lookup->mask), "%s", mask_ctx->mask);
}

// One byte of a candidate, written so that a ?b mask's answer is readable. The same two spellings
// the potfile uses, and for the same reason: a byte that is not a character has to be shown as one
// or the line says nothing.

static const char *mask_lookup_chr (const u32 chr, char *buf, const size_t buf_sz)
{
  if ((chr >= 0x20) && (chr <= 0x7e))
  {
    snprintf (buf, buf_sz, "'%c'", (char) chr);
  }
  else
  {
    snprintf (buf, buf_sz, "0x%02x", chr);
  }

  return buf;
}

// What --lookup found, said once the queue of rounds has been walked and sized.
//
// The numbers are in the units the run counts, which is the reason for answering from inside hashcat
// rather than from a program alongside it. -a 3 counts -s in base words, and a base word is a cell
// the devices expand into bfs_cnt candidates, so the offset that reaches a candidate is not the
// candidate's own ordinal. Under -S there is no cell: the mask is walked in one piece on the host and
// -s counts candidates. The same question has two answers and only the run knows which one it wants.

// What --lookup found for a hybrid attack. The unit is the base word, as everywhere else, and the
// split of the candidate is named because it is the part of the answer the user cannot see for
// themselves: two wordlists and a mask can cut one password in more than one place, and the run
// reaches whichever cut comes first.

void combi_ctx_lookup_report (hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->lookup == NULL) return;

  if (user_options->attack_mode != ATTACK_MODE_HYBRID) return;

  const combi_lookup_t *lookup = &mask_ctx->lookup_combi;

  event_log_info (hashcat_ctx, "lookup: '%s'", user_options->lookup);

  if ((lookup->hit == false) && (lookup->unsupported == true))
  {
    event_log_info (hashcat_ctx, "lookup: this run takes its base words from the mask and amplifies them with the wordlist");

    event_log_info (hashcat_ctx, "lookup: that shape is not inverted yet, so there is no offset to give rather than a wrong one");

    event_log_info (hashcat_ctx, "lookup: -O runs the same attack with the wordlist as the base word, which is answered. ask again with it");

    return;
  }

  if (status_ctx->words_walk_base == 0)
  {
    event_log_info (hashcat_ctx, "lookup: this run has no rounds in it to search");

    return;
  }

  if (lookup->hit == false)
  {
    event_log_info (hashcat_ctx, "lookup: nothing in this run produces it");

    if (lookup->miss == MASK_LOOKUP_MISS_LENGTH)
    {
      event_log_info (hashcat_ctx, "lookup: it is too short for the mask %s and a word on top of it", lookup->mask_miss);
    }
    else if (lookup->miss == MASK_LOOKUP_MISS_MARKOV)
    {
      char chr[8];

      event_log_info (hashcat_ctx, "lookup: mask %s gets furthest: position %u wants %s, which the mask allows and --markov-threshold %u dropped from the table",
        lookup->mask_miss, lookup->miss_pos, mask_lookup_chr (lookup->miss_chr, chr, sizeof (chr)), user_options->markov_threshold);
    }
    else if (lookup->miss == MASK_LOOKUP_MISS_CHARSET)
    {
      char chr[8];

      event_log_info (hashcat_ctx, "lookup: mask %s gets furthest: position %u wants %s and that mask does not allow it there",
        lookup->mask_miss, lookup->miss_pos, mask_lookup_chr (lookup->miss_chr, chr, sizeof (chr)));
    }
    else if (lookup->has_q == true)
    {
      event_log_info (hashcat_ctx, "lookup: no way of cutting it in two leaves a word in each wordlist");
    }
    else
    {
      event_log_info (hashcat_ctx, "lookup: no way of cutting it leaves a word this wordlist holds and a mask value beside it");
    }

    return;
  }

  if (mask_ctx->masks_cnt > 1)
  {
    // The ?w the rewrite glued on is not part of the mask the user typed, so it comes off again
    // before the mask is named back to them.

    char shown[0x400];

    snprintf (shown, sizeof (shown), "%s", lookup->mask);

    const size_t shown_len = strlen (shown);

    if (shown_len >= 2)
    {
      if (user_options->marker_policy == MARKER_POLICY_PREFIX_W)
      {
        memmove (shown, shown + 2, shown_len - 1);
      }
      else if (user_options->marker_policy == MARKER_POLICY_SUFFIX_W)
      {
        shown[shown_len - 2] = 0;
      }
    }

    event_log_info (hashcat_ctx, "lookup: round %u of %u, mask %s, reaches it", lookup->round + 1, mask_ctx->masks_cnt, shown);
  }

  if (lookup->mask_base == true)
  {
    event_log_info (hashcat_ctx, "lookup: cut as %u bytes of the mask and %u of the wordlist, and the mask is the base word here", lookup->base_len, lookup->q_len);
  }
  else if (lookup->has_q == true)
  {
    event_log_info (hashcat_ctx, "lookup: cut as %u bytes of the first wordlist and %u of the second", lookup->base_len, lookup->q_len);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: cut as %u bytes of the wordlist and the rest from the mask", lookup->base_len);
  }

  const char *segment = (lookup->mask_base == true) ? NULL : generic_ctx_segment_of (hashcat_ctx, GENERIC_ROLE_BASE, lookup->word);

  const double pct = (double) lookup->word * 100.0 / (double) status_ctx->words_walk_base;

  if (segment != NULL)
  {
    event_log_info (hashcat_ctx, "lookup: base word %" PRIu64 " of %" PRIu64 ", in %s, %.4f%% into the run", lookup->word, status_ctx->words_walk_base, segment, pct);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: base word %" PRIu64 " of %" PRIu64 ", %.4f%% into the run", lookup->word, status_ctx->words_walk_base, pct);
  }

  event_log_info (hashcat_ctx, "lookup: this run reaches it at -s %" PRIu64 ", because it counts -s in base words", lookup->word);

  event_log_info (hashcat_ctx, "lookup: -s %" PRIu64 " -l 1 runs the one cell of %" PRIu64 " candidates that holds it, where it is number %" PRIu64,
    lookup->word, lookup->amp_cnt, lookup->amp + 1);

  if ((user_options->skip != 0) || (user_options->limit != 0))
  {
    const u64 from = user_options->skip;
    const u64 upto = (user_options->limit > 0) ? user_options->limit : status_ctx->words_walk_base;

    if ((lookup->word >= from) && (lookup->word < upto))
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here covers it", from, upto - from);
    }
    else
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here does not cover it", from, upto - from);
    }
  }
}

void mask_ctx_lookup_report (hashcat_ctx_t *hashcat_ctx)
{
  const mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->lookup == NULL) return;

  // Two report functions are called one after the other and each answers for one attack mode, so the
  // one this is not for says nothing at all rather than reporting an empty search.

  if (user_options->attack_mode != ATTACK_MODE_BF) return;

  const mask_lookup_t *lookup = &mask_ctx->lookup;

  event_log_info (hashcat_ctx, "lookup: '%s'", user_options->lookup);

  if (lookup->uppered == true)
  {
    event_log_info (hashcat_ctx, "lookup: this mode hashes in upper case, so every candidate in the run is, and this one was folded to match");
  }

  // No round was sized at all, so there was nothing to search. A mask outside the mode's password
  // length is skipped before its tables are built, and a queue of nothing but those leaves this.

  // A mask the run declined is not one the answer may be silent about, whether or not anything was
  // left to search afterwards.

  if (lookup->skipped > 0)
  {
    event_log_info (hashcat_ctx, "lookup: %u mask(s) were passed over for being outside this mode's password length, and are not part of the run",
      lookup->skipped);
  }

  if (status_ctx->words_walk_base == 0)
  {
    event_log_info (hashcat_ctx, "lookup: this run has no rounds in it to search");

    return;
  }

  const bool queue = (mask_ctx->masks_cnt > 1);

  if (lookup->hit == false)
  {
    event_log_info (hashcat_ctx, "lookup: nothing in this run produces it");

    if (lookup->miss == MASK_LOOKUP_MISS_LENGTH)
    {
      event_log_info (hashcat_ctx, "lookup: no mask in this run is that many characters long, and a mask only ever produces its own length");
    }
    else if (lookup->miss == MASK_LOOKUP_MISS_MARKOV)
    {
      char chr[8];

      event_log_info (hashcat_ctx, "lookup: mask %s gets furthest: position %u wants %s, which the mask allows and --markov-threshold %u dropped from the table",
        lookup->mask_miss, lookup->miss_pos, mask_lookup_chr (lookup->miss_chr, chr, sizeof (chr)), user_options->markov_threshold);

      event_log_info (hashcat_ctx, "lookup: raise -t, or drop it, and that mask reaches it");
    }
    else if (lookup->miss == MASK_LOOKUP_MISS_CHARSET)
    {
      char chr[8];

      event_log_info (hashcat_ctx, "lookup: mask %s gets furthest: position %u wants %s and that mask does not allow it there",
        lookup->mask_miss, lookup->miss_pos, mask_lookup_chr (lookup->miss_chr, chr, sizeof (chr)));
    }

    // The run walks a mask in two pieces and -S walks it in one. Under --markov-threshold that is not
    // a reordering of the same candidates but a different set of them, so an engine this run did not
    // get can hold a candidate this one does not.

    if (lookup->other == true)
    {
      event_log_info (hashcat_ctx, "lookup: -S does reach it, because the host engine walks a mask in one piece where the devices need it in two");
      event_log_info (hashcat_ctx, "lookup: ask again with -S for the offset, which is a different number in a differently ordered run");
    }

    return;
  }

  if (queue == true)
  {
    event_log_info (hashcat_ctx, "lookup: round %u of %u, mask %s, reaches it", lookup->round + 1, mask_ctx->masks_cnt, lookup->mask);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: mask %s reaches it", lookup->mask);
  }

  const double pct = (double) lookup->word * 100.0 / (double) status_ctx->words_walk_base;

  if (lookup->amp_cnt > 1)
  {
    event_log_info (hashcat_ctx, "lookup: base word %" PRIu64 " of %" PRIu64 ", %.4f%% into the run", lookup->word, status_ctx->words_walk_base, pct);

    event_log_info (hashcat_ctx, "lookup: this run reaches it at -s %" PRIu64 ", because -a 3 counts -s in base words", lookup->word);

    event_log_info (hashcat_ctx, "lookup: -s %" PRIu64 " -l 1 runs the one cell of %" PRIu64 " candidates that holds it, where it is number %" PRIu64,
      lookup->word, lookup->amp_cnt, lookup->amp + 1);
  }
  else
  {
    event_log_info (hashcat_ctx, "lookup: candidate %" PRIu64 " of %" PRIu64 ", %.4f%% into the run", lookup->word, status_ctx->words_walk_base, pct);

    event_log_info (hashcat_ctx, "lookup: this run reaches it at -s %" PRIu64 ", because -S counts -s in candidates", lookup->word);

    event_log_info (hashcat_ctx, "lookup: -s %" PRIu64 " -l 1 runs the one candidate", lookup->word);
  }

  // The other engine holds a different set of candidates whenever --markov-threshold prunes, so an
  // offset handed out without this can send a user who later adds -S past their own password.

  if ((lookup->other_probed == true) && (lookup->other == false))
  {
    event_log_info (hashcat_ctx, "lookup: -S would NOT reach it, because the host engine walks a mask in one piece and --markov-threshold %u makes that a different set of candidates",
      user_options->markov_threshold);
  }

  // A --skip or --limit on the command line is a chunk somebody was handed, and whether it held the
  // password is a different question from whether the attack did. The offset above answers the
  // attack, because the window is not applied to a run that only sizes its rounds, so the window is
  // answered here instead of being silently ignored.
  //
  // --limit had --skip added to it in user_options_preprocess (), so the two are the ends of one
  // window and not an offset and a length.

  if ((user_options->skip != 0) || (user_options->limit != 0))
  {
    const u64 from = user_options->skip;
    const u64 upto = (user_options->limit > 0) ? user_options->limit : status_ctx->words_walk_base;

    if ((lookup->word >= from) && (lookup->word < upto))
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here covers it", from, upto - from);
    }
    else
    {
      event_log_info (hashcat_ctx, "lookup: the -s %" PRIu64 " -l %" PRIu64 " window given here does not cover it", from, upto - from);
    }
  }
}

int mask_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  const hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  const user_options_t       *user_options       = hashcat_ctx->user_options;
  mask_ctx_t                 *mask_ctx           = hashcat_ctx->mask_ctx;

  mask_ctx->enabled = false;

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;

  if (user_options->attack_mode  == ATTACK_MODE_STRAIGHT)    return 0;
  if (user_options->attack_mode  == ATTACK_MODE_GENERIC)     return 0;
  if (user_options->attack_mode  == ATTACK_MODE_ASSOCIATION) return 0;

  mask_ctx->enabled = true;

  mask_ctx->mp_sys  = (cs_t *) hccalloc (8, sizeof (cs_t));
  mask_ctx->mp_usr  = (cs_t *) hccalloc (8, sizeof (cs_t));

  mask_ctx->css_buf = (cs_t *) hccalloc (256, sizeof (cs_t));
  mask_ctx->css_cnt = 0;

  mask_ctx->root_table_buf   = (hcstat_table_t *) hccalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
  mask_ctx->markov_table_buf = (hcstat_table_t *) hccalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

  if (sp_setup_tbl (hashcat_ctx) == -1) return -1;

  mask_ctx->root_css_buf   = (cs_t *) hccalloc (SP_PW_MAX,           sizeof (cs_t));
  mask_ctx->markov_css_buf = (cs_t *) hccalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

  mask_ctx->mask_from_file = false;

  // Cleared here rather than relied on, because outer_loop () runs mask_ctx_init () once per hash
  // mode and the answer belongs to the queue this one is about to build.

  memset (&mask_ctx->lookup, 0, sizeof (mask_ctx->lookup));
  memset (&mask_ctx->lookup_combi, 0, sizeof (mask_ctx->lookup_combi));

  mask_ctx->masks     = NULL;
  mask_ctx->masks_pos = 0;
  mask_ctx->masks_cnt = 0;

  mask_ctx->mfs = (mf_t *) hccalloc (MAX_MFS, sizeof (mf_t));

  mp_setup_sys (mask_ctx->mp_sys);

  if (user_options->custom_charset_1) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0) == -1) return -1; }
  if (user_options->custom_charset_2) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1) == -1) return -1; }
  if (user_options->custom_charset_3) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2) == -1) return -1; }
  if (user_options->custom_charset_4) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3) == -1) return -1; }
  if (user_options->custom_charset_5) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_5, 4) == -1) return -1; }
  if (user_options->custom_charset_6) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_6, 5) == -1) return -1; }
  if (user_options->custom_charset_7) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_7, 6) == -1) return -1; }
  if (user_options->custom_charset_8) { if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_8, 7) == -1) return -1; }

  if (user_options->benchmark == true)
  {
    if (hashconfig->benchmark_charset != NULL)
    {
      if (mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, hashconfig->benchmark_charset, 0) == -1) return -1;
    }
  }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->benchmark == false)
    {
      if (user_options_extra->hc_workc)
      {
        char *arg = user_options_extra->hc_workv[0];

        if (hc_path_exist (arg) == false)
        {
          if (mask_append (hashcat_ctx, arg, NULL) == -1) return -1;
        }
        else
        {
          mask_ctx->mask_from_file = true;

          for (int i = 0; i < user_options_extra->hc_workc; i++)
          {
            arg = user_options_extra->hc_workv[i];

            if (hc_path_is_file (arg) == true)
            {
              HCFILE mask_fp;

              if (hc_fopen (&mask_fp, arg, "r") == false)
              {
                event_log_error (hashcat_ctx, "%s: %s", arg, hc_fopen_strerror ());

                return -1;
              }

              char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

              while (!hc_feof (&mask_fp))
              {
                const size_t line_len = fgetl (&mask_fp, line_buf, HCBUFSIZ_LARGE);

                if (line_len == 0) continue;

                if (line_buf[0] == '#') continue;

                char *mask_buf = mask_ctx_parse_maskfile_find_mask (line_buf, line_len);

                char *prepend_buf = NULL;

                if (line_buf != mask_buf)
                {
                  // if we have custom charsets

                  prepend_buf = line_buf;

                  mask_buf[-1] = 0;
                }

                if (mask_append (hashcat_ctx, mask_buf, prepend_buf) == -1)
                {
                  hc_fclose (&mask_fp);

                  return -1;
                }
              }

              hcfree (line_buf);

              hc_fclose (&mask_fp);
            }
            else
            {
              event_log_error (hashcat_ctx, "%s: unsupported file type.", arg);

              return -1;
            }
          }
        }
      }
      else
      {
        const char *mask = DEF_MASK;

        if (mask_append (hashcat_ctx, mask, NULL) == -1) return -1;
      }
    }
    else
    {
      const char *mask = hashconfig->benchmark_mask;

      if (mask_append (hashcat_ctx, mask, NULL) == -1) return -1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    // display

    // -a 6 writes the mask last and -a 12 writes it first, and either way it can be a mask file

    char *arg = user_options_extra->hc_workv[(user_options->attack_mode == ATTACK_MODE_HYBRID) ? 0 : (user_options_extra->hc_workc - 1)];

    // mod

    if (hc_path_exist (arg) == false)
    {
      if (mask_append (hashcat_ctx, arg, NULL) == -1) return -1;
    }
    else
    {
      if (hc_path_is_file (arg) == true)
      {
        mask_ctx->mask_from_file = true;

        HCFILE mask_fp;

        if (hc_fopen (&mask_fp, arg, "r") == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", arg, hc_fopen_strerror ());

          return -1;
        }

        char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

        while (!hc_feof (&mask_fp))
        {
          const size_t line_len = fgetl (&mask_fp, line_buf, HCBUFSIZ_LARGE);

          if (line_len == 0) continue;

          if (line_buf[0] == '#') continue;

          char *mask_buf = mask_ctx_parse_maskfile_find_mask (line_buf, line_len);

          char *prepend_buf = NULL;

          if (line_buf != mask_buf)
          {
            // if we have custom charsets

            prepend_buf = line_buf;

            mask_buf[-1] = 0;
          }

          if (mask_append (hashcat_ctx, mask_buf, prepend_buf) == -1)
          {
            hc_fclose (&mask_fp);

            return -1;
          }
        }

        hcfree (line_buf);

        hc_fclose (&mask_fp);
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: unsupported file type.", arg);

        return -1;
      }
    }
  }
  if (mask_ctx->masks_cnt == 0)
  {
    event_log_error (hashcat_ctx, "Invalid mask.");

    return -1;
  }

  mask_ctx->mask = mask_ctx->masks[0];

  // Does any mask in this run put the base word inside the amplifier rather than at one end of it?
  // Only such a mask reaches the five piece assembly, and the kernels compile that block in only when
  // the answer is yes, so a mask with the word at one end builds the kernel every other attack mode
  // builds. The three modes rewritten into this one are all word at one end.
  //
  // A mask that starts with ?w has everything behind the word, which is one buffer. A mask that ends
  // with ?w has everything in front of it, which is one buffer too, but only an optimized kernel can
  // be handed it that way round, or a pure kernel that took its base words from the mask instead.
  //
  // Read off the mask strings rather than off a parse, because the parse happens per round and this
  // has to be settled before the kernels are built.

  mask_ctx->needs_middle = false;

  const bool optimized_kernel = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) != 0;

  const bool mask_is_base = (user_options_extra->base_source == BASE_SOURCE_MASK);

  if (user_options->attack_mode == ATTACK_MODE_HYBRID)
  {
    for (u32 mask_pos = 0; mask_pos < mask_ctx->masks_cnt; mask_pos++)
    {
      const char *mask = mask_ctx->masks[mask_pos];

      if (mask_starts_with_marker (mask, 'w') == true) continue;

      if ((mask_ends_with_marker (mask, 'w') == true) && ((optimized_kernel == true) || (mask_is_base == true))) continue;

      mask_ctx->needs_middle = true;

      break;
    }
  }

  // The last work argument is the wordlist a ?q names, so there has to be a ?q somewhere to name it.
  // Every mask is in memory by now, so this reads them rather than the file they may have come from.

  if (user_options_extra->hybrid_q == true)
  {
    bool has_q = false;

    for (u32 mask_pos = 0; mask_pos < mask_ctx->masks_cnt; mask_pos++)
    {
      if (mask_has_marker (mask_ctx->masks[mask_pos], 'q') == false) continue;

      has_q = true;

      break;
    }

    if (has_q == false)
    {
      event_log_error (hashcat_ctx, "%s: given as the wordlist a ?q names, but no mask has a ?q.", user_options_extra->hc_workv[user_options_extra->hc_workc - 1]);

      return -1;
    }
  }

  return 0;
}

void mask_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  if (mask_ctx->enabled == false) return;

  hcfree (mask_ctx->mp_sys);
  hcfree (mask_ctx->mp_usr);

  hcfree (mask_ctx->css_buf);

  hcfree (mask_ctx->root_css_buf);
  hcfree (mask_ctx->markov_css_buf);

  hcfree (mask_ctx->root_table_buf);
  hcfree (mask_ctx->markov_table_buf);

  for (u32 mask_pos = 0; mask_pos < mask_ctx->masks_cnt; mask_pos++)
  {
    hcfree (mask_ctx->masks[mask_pos]);
  }

  hcfree (mask_ctx->masks);

  hcfree (mask_ctx->mfs);

  memset (mask_ctx, 0, sizeof (mask_ctx_t));
}

int mask_ctx_parse_maskfile (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (mask_ctx->enabled == false) return 0;

  if (mask_ctx->mask_from_file == false) return 0;

  mf_t *mfs_buf = mask_ctx->mfs;

  mfs_buf[0].mf_len = 0;
  mfs_buf[1].mf_len = 0;
  mfs_buf[2].mf_len = 0;
  mfs_buf[3].mf_len = 0;
  mfs_buf[4].mf_len = 0;
  mfs_buf[5].mf_len = 0;
  mfs_buf[6].mf_len = 0;
  mfs_buf[7].mf_len = 0;
  mfs_buf[8].mf_len = 0;

  size_t mfs_cnt = 0;

  char *mask_buf = mask_ctx->mask;

  const size_t mask_len = strlen (mask_buf);

  bool escaped = false;

  for (size_t i = 0; i < mask_len; i++)
  {
    mf_t *mf = mfs_buf + mfs_cnt;

    if (escaped == true)
    {
      escaped = false;

      mf->mf_buf[mf->mf_len] = mask_buf[i];

      mf->mf_len++;
    }
    else
    {
      if (mask_buf[i] == '\\')
      {
        escaped = true;
      }
      else if (mask_buf[i] == ',')
      {
        mf->mf_buf[mf->mf_len] = 0;

        mfs_cnt++;

        if (mfs_cnt == MAX_MFS)
        {
          event_log_error (hashcat_ctx, "Invalid line '%s' in maskfile.", mask_buf);

          return -1;
        }
      }
      else
      {
        mf->mf_buf[mf->mf_len] = mask_buf[i];

        mf->mf_len++;
      }
    }
  }

  mf_t *mf = mfs_buf + mfs_cnt;

  mf->mf_buf[mf->mf_len] = 0;

  user_options->custom_charset_1 = NULL;
  user_options->custom_charset_2 = NULL;
  user_options->custom_charset_3 = NULL;
  user_options->custom_charset_4 = NULL;
  user_options->custom_charset_5 = NULL;
  user_options->custom_charset_6 = NULL;
  user_options->custom_charset_7 = NULL;
  user_options->custom_charset_8 = NULL;

  mp_reset_usr (mask_ctx->mp_usr, 0);
  mp_reset_usr (mask_ctx->mp_usr, 1);
  mp_reset_usr (mask_ctx->mp_usr, 2);
  mp_reset_usr (mask_ctx->mp_usr, 3);
  mp_reset_usr (mask_ctx->mp_usr, 4);
  mp_reset_usr (mask_ctx->mp_usr, 5);
  mp_reset_usr (mask_ctx->mp_usr, 6);
  mp_reset_usr (mask_ctx->mp_usr, 7);

  for (size_t i = 0; i < mfs_cnt; i++)
  {
    switch (i)
    {
      case 0:
        user_options->custom_charset_1 = mfs_buf[0].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0);
        break;

      case 1:
        user_options->custom_charset_2 = mfs_buf[1].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1);
        break;

      case 2:
        user_options->custom_charset_3 = mfs_buf[2].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2);
        break;

      case 3:
        user_options->custom_charset_4 = mfs_buf[3].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3);
        break;

      case 4:
        user_options->custom_charset_5 = mfs_buf[4].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_5, 4);
        break;

      case 5:
        user_options->custom_charset_6 = mfs_buf[5].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_6, 5);
        break;

      case 6:
        user_options->custom_charset_7 = mfs_buf[6].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_7, 6);
        break;

      case 7:
        user_options->custom_charset_8 = mfs_buf[7].mf_buf;
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_8, 7);
        break;
    }
  }

  mask_ctx->mask = mfs_buf[mfs_cnt].mf_buf;

  return 0;
}
