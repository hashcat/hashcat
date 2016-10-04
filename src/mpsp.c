/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "convert.h"
#include "filehandling.h"
#include "interface.h"
#include "mpsp.h"

static const char DEF_MASK[] = "?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d";

#define MAX_MFS 5 // 4*charset, 1*mask

void mp_css_split_cnt (const mask_ctx_t *mask_ctx, const hashconfig_t *hashconfig, const u32 css_cnt_orig, u32 css_cnt_lr[2])
{
  u32 css_cnt_l = mask_ctx->css_cnt;
  u32 css_cnt_r;

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
      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
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

  css_cnt_l -= css_cnt_r;

  css_cnt_lr[0] = css_cnt_l;
  css_cnt_lr[1] = css_cnt_r;
}

void mp_css_append_salt (mask_ctx_t *mask_ctx, salt_t *salt_buf)
{
  u32  salt_len     = (u32)  salt_buf->salt_len;
  u8  *salt_buf_ptr = (u8 *) salt_buf->salt_buf;

  u32 css_cnt_salt = mask_ctx->css_cnt + salt_len;

  cs_t *css_buf_salt = (cs_t *) mycalloc (css_cnt_salt, sizeof (cs_t));

  memcpy (css_buf_salt, mask_ctx->css_buf, mask_ctx->css_cnt * sizeof (cs_t));

  for (u32 i = 0, j = mask_ctx->css_cnt; i < salt_len; i++, j++)
  {
    css_buf_salt[j].cs_buf[0] = salt_buf_ptr[i];
    css_buf_salt[j].cs_len    = 1;
  }

  myfree (mask_ctx->css_buf);

  mask_ctx->css_buf = css_buf_salt;
  mask_ctx->css_cnt = css_cnt_salt;
}

void mp_css_unicode_expand (mask_ctx_t *mask_ctx)
{
  u32 css_cnt_unicode = mask_ctx->css_cnt * 2;

  cs_t *css_buf_unicode = (cs_t *) mycalloc (css_cnt_unicode, sizeof (cs_t));

  for (u32 i = 0, j = 0; i < mask_ctx->css_cnt; i += 1, j += 2)
  {
    memcpy (&css_buf_unicode[j + 0], &mask_ctx->css_buf[i], sizeof (cs_t));

    css_buf_unicode[j + 1].cs_buf[0] = 0;
    css_buf_unicode[j + 1].cs_len    = 1;
  }

  myfree (mask_ctx->css_buf);

  mask_ctx->css_buf = css_buf_unicode;
  mask_ctx->css_cnt = css_cnt_unicode;
}

void mp_css_to_uniq_tbl (u32 css_cnt, cs_t *css, u32 uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    log_error ("ERROR: Mask length is too long");

    exit (-1);
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
}

static void mp_add_cs_buf (u32 *in_buf, size_t in_len, cs_t *css, u32 css_cnt, const hashconfig_t *hashconfig)
{
  cs_t *cs = &css[css_cnt];

  size_t css_uniq_sz = CHARSIZ * sizeof (u32);

  u32 *css_uniq = (u32 *) mymalloc (css_uniq_sz);

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

  myfree (css_uniq);
}

static void mp_expand (char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, u32 mp_usr_offset, int interpret, const hashconfig_t *hashconfig, const user_options_t *user_options)
{
  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    u32 p0 = in_buf[in_pos] & 0xff;

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      u32 p1 = in_buf[in_pos] & 0xff;

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { log_error ("ERROR: Custom-charset 1 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[0].cs_buf, mp_usr[0].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { log_error ("ERROR: Custom-charset 2 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[1].cs_buf, mp_usr[1].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { log_error ("ERROR: Custom-charset 3 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[2].cs_buf, mp_usr[2].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { log_error ("ERROR: Custom-charset 4 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[3].cs_buf, mp_usr[3].cs_len, mp_usr, mp_usr_offset, hashconfig);
                  break;
        case '?': mp_add_cs_buf (&p0, 1, mp_usr, mp_usr_offset, hashconfig);
                  break;
        default:  log_error ("Syntax error: %s", in_buf);
                  exit (-1);
      }
    }
    else
    {
      if (user_options->hex_charset == true)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

          exit (-1);
        }

        u32 p1 = in_buf[in_pos] & 0xff;

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", in_buf);

          exit (-1);
        }

        u32 chr = 0;

        chr  = (u32) hex_convert ((u8) p1) << 0;
        chr |= (u32) hex_convert ((u8) p0) << 4;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset, hashconfig);
      }
      else
      {
        u32 chr = p0;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset, hashconfig);
      }
    }
  }
}

u64 mp_get_sum (u32 css_cnt, cs_t *css)
{
  u64 sum = 1;

  for (u32 css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    sum *= css[css_pos].cs_len;
  }

  return (sum);
}

cs_t *mp_gen_css (char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, u32 *css_cnt, const hashconfig_t *hashconfig, const user_options_t *user_options)
{
  cs_t *css = (cs_t *) mycalloc (256, sizeof (cs_t));

  u32 mask_pos;
  u32 css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    char p0 = mask_buf[mask_pos];

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      char p1 = mask_buf[mask_pos];

      u32 chr = (u32) p1;

      switch (p1)
      {
        case 'l': mp_add_cs_buf (mp_sys[0].cs_buf, mp_sys[0].cs_len, css, css_pos, hashconfig);
                  break;
        case 'u': mp_add_cs_buf (mp_sys[1].cs_buf, mp_sys[1].cs_len, css, css_pos, hashconfig);
                  break;
        case 'd': mp_add_cs_buf (mp_sys[2].cs_buf, mp_sys[2].cs_len, css, css_pos, hashconfig);
                  break;
        case 's': mp_add_cs_buf (mp_sys[3].cs_buf, mp_sys[3].cs_len, css, css_pos, hashconfig);
                  break;
        case 'a': mp_add_cs_buf (mp_sys[4].cs_buf, mp_sys[4].cs_len, css, css_pos, hashconfig);
                  break;
        case 'b': mp_add_cs_buf (mp_sys[5].cs_buf, mp_sys[5].cs_len, css, css_pos, hashconfig);
                  break;
        case '1': if (mp_usr[0].cs_len == 0) { log_error ("ERROR: Custom-charset 1 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[0].cs_buf, mp_usr[0].cs_len, css, css_pos, hashconfig);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { log_error ("ERROR: Custom-charset 2 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[1].cs_buf, mp_usr[1].cs_len, css, css_pos, hashconfig);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { log_error ("ERROR: Custom-charset 3 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[2].cs_buf, mp_usr[2].cs_len, css, css_pos, hashconfig);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { log_error ("ERROR: Custom-charset 4 is undefined\n"); exit (-1); }
                  mp_add_cs_buf (mp_usr[3].cs_buf, mp_usr[3].cs_len, css, css_pos, hashconfig);
                  break;
        case '?': mp_add_cs_buf (&chr, 1, css, css_pos, hashconfig);
                  break;
        default:  log_error ("ERROR: Syntax error: %s", mask_buf);
                  exit (-1);
      }
    }
    else
    {
      if (user_options->hex_charset == true)
      {
        mask_pos++;

        // if there is no 2nd hex character, show an error:

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", mask_buf);

          exit (-1);
        }

        u32 chr = 0;

        chr |= (u32) hex_convert ((u8) p1) << 0;
        chr |= (u32) hex_convert ((u8) p0) << 4;

        mp_add_cs_buf (&chr, 1, css, css_pos, hashconfig);
      }
      else
      {
        u32 chr = (u32) p0;

        mp_add_cs_buf (&chr, 1, css, css_pos, hashconfig);
      }
    }
  }

  if (css_pos == 0)
  {
    log_error ("ERROR: Invalid mask length (0)");

    exit (-1);
  }

  *css_cnt = css_pos;

  return (css);
}

void mp_exec (u64 val, char *buf, cs_t *css, int css_cnt)
{
  for (int i = 0; i < css_cnt; i++)
  {
    u32 len  = css[i].cs_len;
    u64 next = val / len;
    u32 pos  = val % len;
    buf[i] = (char) (css[i].cs_buf[pos] & 0xff);
    val = next;
  }
}

u32 mp_get_length (char *mask)
{
  u32 len = 0;

  u32 mask_len = strlen (mask);

  for (u32 i = 0; i < mask_len; i++)
  {
    if (mask[i] == '?') i++;

    len++;
  }

  return len;
}

void mp_cut_at (char *mask, u32 max)
{
  u32 i;
  u32 j;
  u32 mask_len = strlen (mask);

  for (i = 0, j = 0; i < mask_len && j < max; i++, j++)
  {
    if (mask[i] == '?') i++;
  }

  mask[i] = 0;
}

void mp_setup_sys (cs_t *mp_sys)
{
  u32 pos;
  u32 chr;
  u32 donec[CHARSIZ] = { 0 };

  for (pos = 0, chr =  'a'; chr <=  'z'; chr++) { donec[chr] = 1;
                                                  mp_sys[0].cs_buf[pos++] = chr;
                                                  mp_sys[0].cs_len = pos; }

  for (pos = 0, chr =  'A'; chr <=  'Z'; chr++) { donec[chr] = 1;
                                                  mp_sys[1].cs_buf[pos++] = chr;
                                                  mp_sys[1].cs_len = pos; }

  for (pos = 0, chr =  '0'; chr <=  '9'; chr++) { donec[chr] = 1;
                                                  mp_sys[2].cs_buf[pos++] = chr;
                                                  mp_sys[2].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { if (donec[chr]) continue;
                                                  mp_sys[3].cs_buf[pos++] = chr;
                                                  mp_sys[3].cs_len = pos; }

  for (pos = 0, chr = 0x20; chr <= 0x7e; chr++) { mp_sys[4].cs_buf[pos++] = chr;
                                                  mp_sys[4].cs_len = pos; }

  for (pos = 0, chr = 0x00; chr <= 0xff; chr++) { mp_sys[5].cs_buf[pos++] = chr;
                                                  mp_sys[5].cs_len = pos; }
}

void mp_setup_usr (cs_t *mp_sys, cs_t *mp_usr, char *buf, u32 index, const hashconfig_t *hashconfig, const user_options_t *user_options)
{
  FILE *fp = fopen (buf, "rb");

  if (fp == NULL || feof (fp)) // feof() in case if file is empty
  {
    mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1, hashconfig, user_options);
  }
  else
  {
    char mp_file[1024] = { 0 };

    int len = (int) fread (mp_file, 1, sizeof (mp_file) - 1, fp);

    fclose (fp);

    len = in_superchop (mp_file);

    if (len == 0)
    {
      log_info ("WARNING: Charset file corrupted");

      mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1, hashconfig, user_options);
    }
    else
    {
      mp_expand (mp_file, (size_t) len, mp_sys, mp_usr, index, 0, hashconfig, user_options);
    }
  }
}

void mp_reset_usr (cs_t *mp_usr, u32 index)
{
  mp_usr[index].cs_len = 0;

  memset (mp_usr[index].cs_buf, 0, sizeof (mp_usr[index].cs_buf));
}

static char *mp_get_truncated_mask (const char *mask_buf, const size_t mask_len, const u32 len, const user_options_t *user_options)
{
  char *new_mask_buf = (char *) mymalloc (256);

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
      if (user_options->hex_charset == true)
      {
        mask_pos++;

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char ((u8) p0) == false) || (is_valid_hex_char ((u8) p1) == false))
        {
          log_error ("ERROR: Invalid hex character detected in mask: %s", mask_buf);

          exit (-1);
        }

        new_mask_buf[mask_pos] = p1;
      }
    }
  }

  if (css_pos == len) return (new_mask_buf);

  myfree (new_mask_buf);

  return (NULL);
}

u64 sp_get_sum (u32 start, u32 stop, cs_t *root_css_buf)
{
  u64 sum = 1;

  u32 i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
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

int sp_comp_val (const void *p1, const void *p2)
{
  hcstat_table_t *b1 = (hcstat_table_t *) p1;
  hcstat_table_t *b2 = (hcstat_table_t *) p2;

  return b2->val - b1->val;
}

void sp_setup_tbl (const char *shared_dir, char *hcstat, u32 disable, u32 classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf)
{
  u32 i;
  u32 j;
  u32 k;

  /**
   * Initialize hcstats
   */

  u64 *root_stats_buf = (u64 *) mycalloc (SP_ROOT_CNT, sizeof (u64));

  u64 *root_stats_ptr = root_stats_buf;

  u64 *root_stats_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_stats_buf_by_pos[i] = root_stats_ptr;

    root_stats_ptr += CHARSIZ;
  }

  u64 *markov_stats_buf = (u64 *) mycalloc (SP_MARKOV_CNT, sizeof (u64));

  u64 *markov_stats_ptr = markov_stats_buf;

  u64 *markov_stats_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_stats_buf_by_key[i][j] = markov_stats_ptr;

      markov_stats_ptr += CHARSIZ;
    }
  }

  /**
   * Load hcstats File
   */

  if (hcstat == NULL)
  {
    char hcstat_tmp[256] = { 0 };

    snprintf (hcstat_tmp, sizeof (hcstat_tmp) - 1, "%s/%s", shared_dir, SP_HCSTAT);

    hcstat = hcstat_tmp;
  }

  FILE *fd = fopen (hcstat, "rb");

  if (fd == NULL)
  {
    log_error ("%s: %s", hcstat, strerror (errno));

    exit (-1);
  }

  if (fread (root_stats_buf, sizeof (u64), SP_ROOT_CNT, fd) != SP_ROOT_CNT)
  {
    log_error ("%s: Could not load data", hcstat);

    fclose (fd);

    exit (-1);
  }

  if (fread (markov_stats_buf, sizeof (u64), SP_MARKOV_CNT, fd) != SP_MARKOV_CNT)
  {
    log_error ("%s: Could not load data", hcstat);

    fclose (fd);

    exit (-1);
  }

  fclose (fd);

  /**
   * Markov modifier of hcstat_table on user request
   */

  if (disable)
  {
    memset (root_stats_buf,   0, SP_ROOT_CNT   * sizeof (u64));
    memset (markov_stats_buf, 0, SP_MARKOV_CNT * sizeof (u64));
  }

  if (classic)
  {
    /* Add all stats to first position */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = root_stats_buf_by_pos[0];
      u64 *in  = root_stats_buf_by_pos[i];

      for (j = 0; j < CHARSIZ; j++)
      {
        *out++ += *in++;
      }
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      u64 *out = markov_stats_buf_by_key[0][0];
      u64 *in  = markov_stats_buf_by_key[i][0];

      for (j = 0; j < CHARSIZ; j++)
      {
        for (k = 0; k < CHARSIZ; k++)
        {
          *out++ += *in++;
        }
      }
    }

    /* copy them to all pw_positions */

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (root_stats_buf_by_pos[i], root_stats_buf_by_pos[0], CHARSIZ * sizeof (u64));
    }

    for (i = 1; i < SP_PW_MAX; i++)
    {
      memcpy (markov_stats_buf_by_key[i][0], markov_stats_buf_by_key[0][0], CHARSIZ * CHARSIZ * sizeof (u64));
    }
  }

  /**
   * Initialize tables
   */

  hcstat_table_t *root_table_ptr = root_table_buf;

  hcstat_table_t *root_table_buf_by_pos[SP_PW_MAX];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    root_table_buf_by_pos[i] = root_table_ptr;

    root_table_ptr += CHARSIZ;
  }

  hcstat_table_t *markov_table_ptr = markov_table_buf;

  hcstat_table_t *markov_table_buf_by_key[SP_PW_MAX][CHARSIZ];

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      markov_table_buf_by_key[i][j] = markov_table_ptr;

      markov_table_ptr += CHARSIZ;
    }
  }

  /**
   * Convert hcstat to tables
   */

  for (i = 0; i < SP_ROOT_CNT; i++)
  {
    u32 key = i % CHARSIZ;

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    u32 key = i % CHARSIZ;

    markov_table_buf[i].key = key;
    markov_table_buf[i].val = markov_stats_buf[i];
  }

  myfree (root_stats_buf);
  myfree (markov_stats_buf);

  /**
   * Finally sort them
   */

  for (i = 0; i < SP_PW_MAX; i++)
  {
    qsort (root_table_buf_by_pos[i], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
  }

  for (i = 0; i < SP_PW_MAX; i++)
  {
    for (j = 0; j < CHARSIZ; j++)
    {
      qsort (markov_table_buf_by_key[i][j], CHARSIZ, sizeof (hcstat_table_t), sp_comp_val);
    }
  }
}

void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 threshold, u32 uniq_tbls[SP_PW_MAX][CHARSIZ])
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

      printf ("pos:%u key:%u len:%u\n", i, j, ptr->cs_len);

      for (u32 k = 0; k < 10; k++)
      {
        printf ("  %u\n",  ptr->cs_buf[k]);
      }
    }
  }
  */
}

void sp_stretch_root (hcstat_table_t *in, hcstat_table_t *out)
{
  for (u32 i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ;
    in  += CHARSIZ;

    out->key = 0;
    out->val = 1;

    out++;

    for (u32 j = 1; j < CHARSIZ; j++)
    {
      out->key = j;
      out->val = 0;

      out++;
    }
  }
}

void sp_stretch_markov (hcstat_table_t *in, hcstat_table_t *out)
{
  for (u32 i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ * CHARSIZ;
    in  += CHARSIZ * CHARSIZ;

    for (u32 j = 0; j < CHARSIZ; j++)
    {
      out->key = 0;
      out->val = 1;

      out++;

      for (u32 k = 1; k < CHARSIZ; k++)
      {
        out->key = k;
        out->val = 0;

        out++;
      }
    }
  }
}

static void mask_append_final (mask_ctx_t *mask_ctx, const char *mask)
{
  if (mask_ctx->masks_avail == mask_ctx->masks_cnt)
  {
    mask_ctx->masks = (char **) myrealloc (mask_ctx->masks, mask_ctx->masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

    mask_ctx->masks_avail += INCR_MASKS;
  }

  mask_ctx->masks[mask_ctx->masks_cnt] = mystrdup (mask);

  mask_ctx->masks_cnt++;
}

static void mask_append (mask_ctx_t *mask_ctx, const user_options_t *user_options, const char *mask)
{
  if (user_options->increment == true)
  {
    for (u32 mask_len = user_options->increment_min; mask_len <= user_options->increment_max; mask_len++)
    {
      char *mask_truncated = mp_get_truncated_mask (mask, strlen (mask), mask_len, user_options);

      if (mask_truncated == NULL) break;

      mask_append_final (mask_ctx, mask_truncated);
    }
  }
  else
  {
    mask_append_final (mask_ctx, mask);
  }
}

int mask_ctx_init (mask_ctx_t *mask_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const folder_config_t *folder_config, const hashconfig_t *hashconfig)
{
  mask_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT) return 0;
  if (user_options->attack_mode == ATTACK_MODE_COMBI)    return 0;

  mask_ctx->enabled = true;

  mask_ctx->root_table_buf   = (hcstat_table_t *) mycalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
  mask_ctx->markov_table_buf = (hcstat_table_t *) mycalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

  sp_setup_tbl (folder_config->shared_dir, user_options->markov_hcstat, user_options->markov_disable, user_options->markov_classic, mask_ctx->root_table_buf, mask_ctx->markov_table_buf);

  mask_ctx->root_css_buf   = (cs_t *) mycalloc (SP_PW_MAX,           sizeof (cs_t));
  mask_ctx->markov_css_buf = (cs_t *) mycalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

  mask_ctx->css_cnt = 0;
  mask_ctx->css_buf = NULL;

  mask_ctx->mask_from_file = false;

  mask_ctx->masks     = NULL;
  mask_ctx->masks_pos = 0;
  mask_ctx->masks_cnt = 0;

  mask_ctx->mfs = (mf_t *) mycalloc (MAX_MFS, sizeof (mf_t));

  mp_setup_sys (mask_ctx->mp_sys);

  if (user_options->custom_charset_1) mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0, hashconfig, user_options);
  if (user_options->custom_charset_2) mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1, hashconfig, user_options);
  if (user_options->custom_charset_3) mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2, hashconfig, user_options);
  if (user_options->custom_charset_4) mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3, hashconfig, user_options);

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->benchmark == false)
    {
      if (user_options_extra->hc_workc)
      {
        char *arg = user_options_extra->hc_workv[0];

        struct stat file_stat;

        if (stat (arg, &file_stat) == -1)
        {
          mask_append (mask_ctx, user_options, arg);
        }
        else
        {
          mask_ctx->mask_from_file = true;

          for (int i = 0; i < user_options_extra->hc_workc; i++)
          {
            arg = user_options_extra->hc_workv[i];

            if (stat (arg, &file_stat) == -1)
            {
              log_error ("ERROR: %s: %s", arg, strerror (errno));

              return -1;
            }

            if (S_ISREG (file_stat.st_mode))
            {
              FILE *mask_fp = fopen (arg, "r");

              if (mask_fp == NULL)
              {
                log_error ("ERROR: %s: %s", arg, strerror (errno));

                return -1;
              }

              char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

              while (!feof (mask_fp))
              {
                const int line_len = fgetl (mask_fp, line_buf);

                if (line_len == 0) continue;

                if (line_buf[0] == '#') continue;

                mask_append (mask_ctx, user_options, line_buf);
              }

              myfree (line_buf);

              fclose (mask_fp);
            }
            else
            {
              log_error ("ERROR: %s: unsupported file-type", arg);

              return -1;
            }
          }
        }
      }
      else
      {
        const char *mask = DEF_MASK;

        mask_append (mask_ctx, user_options, mask);
      }
    }
    else
    {
      const char *mask = hashconfig_benchmark_mask (hashconfig);

      mask_append (mask_ctx, user_options, mask);
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    // display

    char *arg = user_options_extra->hc_workv[user_options_extra->hc_workc - 1];

    // mod

    struct stat file_stat;

    if (stat (arg, &file_stat) == -1)
    {
      mask_append (mask_ctx, user_options, arg);
    }
    else
    {
      if (S_ISREG (file_stat.st_mode))
      {
        mask_ctx->mask_from_file = true;

        FILE *mask_fp = fopen (arg, "r");

        if (mask_fp == NULL)
        {
          log_error ("ERROR: %s: %s", arg, strerror (errno));

          return -1;
        }

        char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

        while (!feof (mask_fp))
        {
          const int line_len = fgetl (mask_fp, line_buf);

          if (line_len == 0) continue;

          if (line_buf[0] == '#') continue;

          mask_append (mask_ctx, user_options, line_buf);
        }

        myfree (line_buf);

        fclose (mask_fp);
      }
      else
      {
        log_error ("ERROR: %s: unsupported file-type", arg);

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    // display

    char *arg = user_options_extra->hc_workv[0];

    // mod

    struct stat file_stat;

    if (stat (arg, &file_stat) == -1)
    {
      mask_append (mask_ctx, user_options, arg);
    }
    else
    {
      if (S_ISREG (file_stat.st_mode))
      {
        mask_ctx->mask_from_file = true;

        FILE *mask_fp = fopen (arg, "r");

        if (mask_fp == NULL)
        {
          log_error ("ERROR: %s: %s", arg, strerror (errno));

          return -1;
        }

        char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

        while (!feof (mask_fp))
        {
          const int line_len = fgetl (mask_fp, line_buf);

          if (line_len == 0) continue;

          if (line_buf[0] == '#') continue;

          mask_append (mask_ctx, user_options, line_buf);
        }

        myfree (line_buf);

        fclose (mask_fp);
      }
      else
      {
        log_error ("ERROR: %s: unsupported file-type", arg);

        return -1;
      }
    }
  }

  if (mask_ctx->masks_cnt == 0)
  {
    log_error ("ERROR: Invalid mask");

    return -1;
  }

  mask_ctx->mask = mask_ctx->masks[0];

  return 0;
}

void mask_ctx_destroy (mask_ctx_t *mask_ctx)
{
  if (mask_ctx->enabled == false) return;

  myfree (mask_ctx->css_buf);

  myfree (mask_ctx->root_css_buf);
  myfree (mask_ctx->markov_css_buf);

  myfree (mask_ctx->root_table_buf);
  myfree (mask_ctx->markov_table_buf);

  for (u32 mask_pos = 0; mask_pos < mask_ctx->masks_cnt; mask_pos++)
  {
    myfree (mask_ctx->masks[mask_pos]);
  }

  myfree (mask_ctx->masks);

  myfree (mask_ctx->mfs);

  memset (mask_ctx, 0, sizeof (mask_ctx_t));
}

int mask_ctx_parse_maskfile (mask_ctx_t *mask_ctx, user_options_t *user_options, const hashconfig_t *hashconfig)
{
  if (mask_ctx->enabled == false) return 0;

  if (mask_ctx->mask_from_file == false) return 0;

  mf_t *mfs = mask_ctx->mfs;

  mfs[0].mf_len = 0;
  mfs[1].mf_len = 0;
  mfs[2].mf_len = 0;
  mfs[3].mf_len = 0;
  mfs[4].mf_len = 0;

  char *mask_buf = mask_ctx->mask;

  const int mask_len = strlen (mask_buf);

  bool escaped = false;

  int mf_cnt = 0;

  for (int i = 0; i < mask_len; i++)
  {
    mf_t *mf = mfs + mf_cnt;

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

        mf_cnt++;

        if (mf_cnt >= MAX_MFS)
        {
          log_error ("ERROR: Invalid line '%s' in maskfile", mask_buf);

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

  mf_t *mf = mfs + mf_cnt;

  mf->mf_buf[mf->mf_len] = 0;

  for (int i = 0; i < mf_cnt; i++)
  {
    switch (i)
    {
      case 0:
        user_options->custom_charset_1 = mfs[0].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 0);
        mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0, hashconfig, user_options);
        break;

      case 1:
        user_options->custom_charset_2 = mfs[1].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 1);
        mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1, hashconfig, user_options);
        break;

      case 2:
        user_options->custom_charset_3 = mfs[2].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 2);
        mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2, hashconfig, user_options);
        break;

      case 3:
        user_options->custom_charset_4 = mfs[3].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 3);
        mp_setup_usr (mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3, hashconfig, user_options);
        break;
    }
  }

  mask_ctx->mask = mfs[mf_cnt].mf_buf;

  return 0;
}
