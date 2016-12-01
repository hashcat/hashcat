/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "logfile.h"
#include "convert.h"
#include "filehandling.h"
#include "interface.h"
#include "opencl.h"
#include "shared.h"
#include "mpsp.h"

static const char DEF_MASK[] = "?1?2?2?2?2?2?2?3?3?3?3?d?d?d?d";

#define MAX_MFS 5 // 4*charset, 1*mask

static int sp_comp_val (const void *p1, const void *p2)
{
  hcstat_table_t *b1 = (hcstat_table_t *) p1;
  hcstat_table_t *b2 = (hcstat_table_t *) p2;

  return b2->val - b1->val;
}

static void mp_css_split_cnt (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_orig, u32 css_cnt_lr[2])
{
  const mask_ctx_t   *mask_ctx   = hashcat_ctx->mask_ctx;
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

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

static int mp_css_append_salt (hashcat_ctx_t *hashcat_ctx, salt_t *salt_buf)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u32  salt_len     = (u32)  salt_buf->salt_len;
  u8  *salt_buf_ptr = (u8 *) salt_buf->salt_buf;

  u32 css_cnt_salt = mask_ctx->css_cnt + salt_len;

  cs_t *css_buf_salt = (cs_t *) hccalloc (css_cnt_salt, sizeof (cs_t));

  memcpy (css_buf_salt, mask_ctx->css_buf, mask_ctx->css_cnt * sizeof (cs_t));

  for (u32 i = 0, j = mask_ctx->css_cnt; i < salt_len; i++, j++)
  {
    css_buf_salt[j].cs_buf[0] = salt_buf_ptr[i];
    css_buf_salt[j].cs_len    = 1;
  }

  hcfree (mask_ctx->css_buf);

  mask_ctx->css_buf = css_buf_salt;
  mask_ctx->css_cnt = css_cnt_salt;

  return 0;
}

static int mp_css_unicode_expand (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  u32 css_cnt_unicode = mask_ctx->css_cnt * 2;

  cs_t *css_buf_unicode = (cs_t *) hccalloc (css_cnt_unicode, sizeof (cs_t));

  for (u32 i = 0, j = 0; i < mask_ctx->css_cnt; i += 1, j += 2)
  {
    memcpy (&css_buf_unicode[j + 0], &mask_ctx->css_buf[i], sizeof (cs_t));

    css_buf_unicode[j + 1].cs_buf[0] = 0;
    css_buf_unicode[j + 1].cs_len    = 1;
  }

  hcfree (mask_ctx->css_buf);

  mask_ctx->css_buf = css_buf_unicode;
  mask_ctx->css_cnt = css_cnt_unicode;

  return 0;
}

static int mp_css_to_uniq_tbl (hashcat_ctx_t *hashcat_ctx, u32 css_cnt, cs_t *css, u32 uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    event_log_error (hashcat_ctx, "Mask length is too long");

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

static int mp_add_cs_buf (hashcat_ctx_t *hashcat_ctx, u32 *in_buf, size_t in_len, cs_t *css, u32 css_cnt)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

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

static int mp_expand (hashcat_ctx_t *hashcat_ctx, char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, u32 mp_usr_offset, int interpret)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    u32 p0 = in_buf[in_pos] & 0xff;

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

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
        case '1': if (mp_usr[0].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 1 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[0].cs_buf, mp_usr[0].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 2 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[1].cs_buf, mp_usr[1].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 3 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[2].cs_buf, mp_usr[2].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 4 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[3].cs_buf, mp_usr[3].cs_len, mp_usr, mp_usr_offset);
                  break;
        case '?': rc = mp_add_cs_buf (hashcat_ctx, &p0, 1, mp_usr, mp_usr_offset);
                  break;
        default:  event_log_error (hashcat_ctx, "Syntax error: %s", in_buf);
                  return -1;
      }

      if (rc == -1) return -1;
    }
    else
    {
      if (user_options->hex_charset == true)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          event_log_error (hashcat_ctx, "The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

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

static int mp_gen_css (hashcat_ctx_t *hashcat_ctx, char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, cs_t *css_buf, u32 *css_cnt)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

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
        case '1': if (mp_usr[0].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 1 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[0].cs_buf, mp_usr[0].cs_len, css_buf, css_pos);
                  break;
        case '2': if (mp_usr[1].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 2 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[1].cs_buf, mp_usr[1].cs_len, css_buf, css_pos);
                  break;
        case '3': if (mp_usr[2].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 3 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[2].cs_buf, mp_usr[2].cs_len, css_buf, css_pos);
                  break;
        case '4': if (mp_usr[3].cs_len == 0) { event_log_error (hashcat_ctx, "Custom-charset 4 is undefined"); return -1; }
                  rc = mp_add_cs_buf (hashcat_ctx, mp_usr[3].cs_buf, mp_usr[3].cs_len, css_buf, css_pos);
                  break;
        case '?': rc = mp_add_cs_buf (hashcat_ctx, &chr, 1, css_buf, css_pos);
                  break;
        default:  event_log_error (hashcat_ctx, "Syntax error: %s", mask_buf);
                  return -1;
      }

      if (rc == -1) return -1;
    }
    else
    {
      if (user_options->hex_charset == true)
      {
        mask_pos++;

        // if there is no 2nd hex character, show an error:

        if (mask_pos == mask_len)
        {
          event_log_error (hashcat_ctx, "The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

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

  if (css_pos == 0)
  {
    event_log_error (hashcat_ctx, "Invalid mask length (0)");

    return -1;
  }

  *css_cnt = css_pos;

  return 0;
}

static int mp_get_truncated_mask (hashcat_ctx_t *hashcat_ctx, const char *mask_buf, const size_t mask_len, const u32 len, char *new_mask_buf)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

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
          event_log_error (hashcat_ctx, "The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

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

static int mp_setup_usr (hashcat_ctx_t *hashcat_ctx, cs_t *mp_sys, cs_t *mp_usr, char *buf, u32 index)
{
  FILE *fp = fopen (buf, "rb");

  if (fp == NULL) // feof() in case if file is empty
  {
    const int rc = mp_expand (hashcat_ctx, buf, strlen (buf), mp_sys, mp_usr, index, 1);

    if (rc == -1) return -1;
  }
  else
  {
    char mp_file[1024] = { 0 };

    const size_t nread = fread (mp_file, 1, sizeof (mp_file) - 1, fp);

    if (!feof (fp))
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is too large", buf);

      fclose (fp);

      return -1;
    }
    else
    {
      fclose (fp);
    }

    if (nread == 0)
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is empty", buf);

      return -1;
    }

    const size_t len = in_superchop (mp_file);

    if (len == 0)
    {
      event_log_error (hashcat_ctx, "%s: Custom charset file is corrupted", buf);

      return -1;
    }

    const int rc = mp_expand (hashcat_ctx, mp_file, len, mp_sys, mp_usr, index, 0);

    if (rc == -1) return -1;
  }

  return 0;
}

static void mp_reset_usr (cs_t *mp_usr, u32 index)
{
  mp_usr[index].cs_len = 0;

  memset (mp_usr[index].cs_buf, 0, sizeof (mp_usr[index].cs_buf));
}

static int sp_setup_tbl (hashcat_ctx_t *hashcat_ctx)
{
  folder_config_t *folder_config = hashcat_ctx->folder_config;
  mask_ctx_t      *mask_ctx      = hashcat_ctx->mask_ctx;
  user_options_t  *user_options  = hashcat_ctx->user_options;

  char *shared_dir = folder_config->shared_dir;

  char *hcstat  = user_options->markov_hcstat;
  u32   disable = user_options->markov_disable;
  u32   classic = user_options->markov_classic;

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

  u64 *markov_stats_buf_by_key[SP_PW_MAX][CHARSIZ];

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

  if (hcstat == NULL)
  {
    char hcstat_tmp[256] = { 0 };

    snprintf (hcstat_tmp, sizeof (hcstat_tmp) - 1, "%s/%s", shared_dir, SP_HCSTAT);

    hcstat = hcstat_tmp;
  }

  FILE *fd = fopen (hcstat, "rb");

  if (fd == NULL)
  {
    event_log_error (hashcat_ctx, "%s: %s", hcstat, strerror (errno));

    return -1;
  }

  if (fread (root_stats_buf, sizeof (u64), SP_ROOT_CNT, fd) != SP_ROOT_CNT)
  {
    event_log_error (hashcat_ctx, "%s: Could not load data", hcstat);

    fclose (fd);

    return -1;
  }

  if (fread (markov_stats_buf, sizeof (u64), SP_MARKOV_CNT, fd) != SP_MARKOV_CNT)
  {
    event_log_error (hashcat_ctx, "%s: Could not load data", hcstat);

    fclose (fd);

    return -1;
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

  hcstat_table_t *markov_table_buf_by_key[SP_PW_MAX][CHARSIZ];

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

  return 0;
}

static u64 sp_get_sum (u32 start, u32 stop, cs_t *root_css_buf)
{
  u64 sum = 1;

  u32 i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
}

static void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, u32 threshold, u32 uniq_tbls[SP_PW_MAX][CHARSIZ])
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

static int mask_append_final (hashcat_ctx_t *hashcat_ctx, const char *mask)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  if (mask_ctx->masks_avail == mask_ctx->masks_cnt)
  {
    mask_ctx->masks = (char **) hcrealloc (mask_ctx->masks, mask_ctx->masks_avail * sizeof (char *), INCR_MASKS * sizeof (char *));

    mask_ctx->masks_avail += INCR_MASKS;
  }

  mask_ctx->masks[mask_ctx->masks_cnt] = hcstrdup (mask);

  mask_ctx->masks_cnt++;

  return 0;
}

static int mask_append (hashcat_ctx_t *hashcat_ctx, const char *mask)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->increment == true)
  {
    const u32 mask_length = mp_get_length (mask);

    const u32 pw_min = hashconfig->pw_min;
    const u32 pw_max = hashconfig->pw_max;

    u32 increment_min = user_options->increment_min;
    u32 increment_max = user_options->increment_max;

    increment_min = MAX (increment_min, pw_min);
    increment_max = MIN (increment_max, pw_max);
    increment_max = MIN (increment_max, mask_length);

    for (u32 increment_len = increment_min; increment_len <= increment_max; increment_len++)
    {
      char *mask_truncated = (char *) hcmalloc (256);

      const int rc_truncated_mask = mp_get_truncated_mask (hashcat_ctx, mask, strlen (mask), increment_len, mask_truncated);

      if (rc_truncated_mask == -1) break;

      const int rc = mask_append_final (hashcat_ctx, mask_truncated);

      if (rc == -1) return -1;
    }
  }
  else
  {
    const int rc = mask_append_final (hashcat_ctx, mask);

    if (rc == -1) return -1;
  }

  return 0;
}

u32 mp_get_length (const char *mask)
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
    if (user_options->attack_mode == ATTACK_MODE_COMBI)
    {

    }
    else if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
    {
      mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

      const int rc_mask_file = mask_ctx_parse_maskfile (hashcat_ctx);

      if (rc_mask_file == -1) return -1;

      mask_ctx->css_buf = (cs_t *) hccalloc (256, sizeof (cs_t));

      const int rc_gen_css = mp_gen_css (hashcat_ctx, mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, mask_ctx->css_buf, &mask_ctx->css_cnt);

      if (rc_gen_css == -1) return -1;

      u32 uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

      mp_css_to_uniq_tbl (hashcat_ctx, mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      combinator_ctx->combs_cnt = sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf);

      const int rc_update_mp = opencl_session_update_mp (hashcat_ctx);

      if (rc_update_mp == -1) return -1;
    }

    const int rc_update_combinator = opencl_session_update_combinator (hashcat_ctx);

    if (rc_update_combinator == -1) return -1;
  }
  else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
  {
    mask_ctx->mask = mask_ctx->masks[mask_ctx->masks_pos];

    const int rc_mask_file = mask_ctx_parse_maskfile (hashcat_ctx);

    if (rc_mask_file == -1) return -1;

    if (user_options->attack_mode == ATTACK_MODE_BF) // always true
    {
      mask_ctx->css_buf = (cs_t *) hccalloc (256, sizeof (cs_t));

      const int rc_gen_css = mp_gen_css (hashcat_ctx, mask_ctx->mask, strlen (mask_ctx->mask), mask_ctx->mp_sys, mask_ctx->mp_usr, mask_ctx->css_buf, &mask_ctx->css_cnt);

      if (rc_gen_css == -1) return -1;

      // special case for benchmark

      u32 pw_min = hashconfig->pw_min;
      u32 pw_max = hashconfig->pw_max;

      if (user_options->benchmark == true)
      {
        pw_min = mp_get_length (mask_ctx->mask);
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
          event_log_warning (hashcat_ctx, "Skipping mask '%s' because it is smaller than the minimum password length", mask_ctx->mask);
        }

        if (mask_ctx->css_cnt > mask_max)
        {
          event_log_warning (hashcat_ctx, "Skipping mask '%s' because it is larger than the maximum password length", mask_ctx->mask);
        }

        // skip to next mask

        logfile_sub_msg ("STOP");

        return 0;
      }

      if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE)
      {
        const int rc = mp_css_unicode_expand (hashcat_ctx);

        if (rc == -1) return -1;
      }

      u32 css_cnt_orig = mask_ctx->css_cnt;

      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
        {
          const int rc = mp_css_append_salt (hashcat_ctx, &hashes->salts_buf[0]);

          if (rc == -1) return -1;
        }
      }

      u32 uniq_tbls[SP_PW_MAX][CHARSIZ] = { { 0 } };

      mp_css_to_uniq_tbl (hashcat_ctx, mask_ctx->css_cnt, mask_ctx->css_buf, uniq_tbls);

      sp_tbl_to_css (mask_ctx->root_table_buf, mask_ctx->markov_table_buf, mask_ctx->root_css_buf, mask_ctx->markov_css_buf, user_options->markov_threshold, uniq_tbls);

      status_ctx->words_cnt = sp_get_sum (0, mask_ctx->css_cnt, mask_ctx->root_css_buf);

      // copy + args

      u32 css_cnt_lr[2];

      mp_css_split_cnt (hashcat_ctx, css_cnt_orig, css_cnt_lr);

      mask_ctx->bfs_cnt = sp_get_sum (0, css_cnt_lr[1], mask_ctx->root_css_buf);

      const int rc_update_mp_rl = opencl_session_update_mp_rl (hashcat_ctx, css_cnt_lr[0], css_cnt_lr[1]);

      if (rc_update_mp_rl == -1) return -1;
    }
  }

  return 0;
}

int mask_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  mask_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT) return 0;
  if (user_options->attack_mode == ATTACK_MODE_COMBI)    return 0;

  mask_ctx->enabled = true;

  mask_ctx->root_table_buf   = (hcstat_table_t *) hccalloc (SP_ROOT_CNT,   sizeof (hcstat_table_t));
  mask_ctx->markov_table_buf = (hcstat_table_t *) hccalloc (SP_MARKOV_CNT, sizeof (hcstat_table_t));

  sp_setup_tbl (hashcat_ctx);

  mask_ctx->root_css_buf   = (cs_t *) hccalloc (SP_PW_MAX,           sizeof (cs_t));
  mask_ctx->markov_css_buf = (cs_t *) hccalloc (SP_PW_MAX * CHARSIZ, sizeof (cs_t));

  mask_ctx->css_cnt = 0;
  mask_ctx->css_buf = NULL;

  mask_ctx->mask_from_file = false;

  mask_ctx->masks     = NULL;
  mask_ctx->masks_pos = 0;
  mask_ctx->masks_cnt = 0;

  mask_ctx->mfs = (mf_t *) hccalloc (MAX_MFS, sizeof (mf_t));

  mp_setup_sys (mask_ctx->mp_sys);

  if (user_options->custom_charset_1) { const int rc = mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0); if (rc == -1) return -1; }
  if (user_options->custom_charset_2) { const int rc = mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1); if (rc == -1) return -1; }
  if (user_options->custom_charset_3) { const int rc = mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2); if (rc == -1) return -1; }
  if (user_options->custom_charset_4) { const int rc = mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3); if (rc == -1) return -1; }

  if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    if (user_options->benchmark == false)
    {
      if (user_options_extra->hc_workc)
      {
        char *arg = user_options_extra->hc_workv[0];

        hc_stat_t file_stat;

        if (hc_stat (arg, &file_stat) == -1)
        {
          const int rc = mask_append (hashcat_ctx, arg);

          if (rc == -1) return -1;
        }
        else
        {
          mask_ctx->mask_from_file = true;

          for (int i = 0; i < user_options_extra->hc_workc; i++)
          {
            arg = user_options_extra->hc_workv[i];

            if (hc_stat (arg, &file_stat) == -1)
            {
              event_log_error (hashcat_ctx, "%s: %s", arg, strerror (errno));

              return -1;
            }

            if (S_ISREG (file_stat.st_mode))
            {
              FILE *mask_fp = fopen (arg, "r");

              if (mask_fp == NULL)
              {
                event_log_error (hashcat_ctx, "%s: %s", arg, strerror (errno));

                return -1;
              }

              char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

              while (!feof (mask_fp))
              {
                const int line_len = fgetl (mask_fp, line_buf);

                if (line_len == 0) continue;

                if (line_buf[0] == '#') continue;

                const int rc = mask_append (hashcat_ctx, line_buf);

                if (rc == -1)
                {
                  fclose (mask_fp);

                  return -1;
                }
              }

              hcfree (line_buf);

              fclose (mask_fp);
            }
            else
            {
              event_log_error (hashcat_ctx, "%s: unsupported file-type", arg);

              return -1;
            }
          }
        }
      }
      else
      {
        const char *mask = DEF_MASK;

        const int rc = mask_append (hashcat_ctx, mask);

        if (rc == -1) return -1;
      }
    }
    else
    {
      const char *mask = hashconfig_benchmark_mask (hashcat_ctx);

      const int rc = mask_append (hashcat_ctx, mask);

      if (rc == -1) return -1;
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    // display

    char *arg = user_options_extra->hc_workv[user_options_extra->hc_workc - 1];

    // mod

    hc_stat_t file_stat;

    if (hc_stat (arg, &file_stat) == -1)
    {
      const int rc = mask_append (hashcat_ctx, arg);

      if (rc == -1) return -1;
    }
    else
    {
      if (S_ISREG (file_stat.st_mode))
      {
        mask_ctx->mask_from_file = true;

        FILE *mask_fp = fopen (arg, "r");

        if (mask_fp == NULL)
        {
          event_log_error (hashcat_ctx, "%s: %s", arg, strerror (errno));

          return -1;
        }

        char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

        while (!feof (mask_fp))
        {
          const int line_len = fgetl (mask_fp, line_buf);

          if (line_len == 0) continue;

          if (line_buf[0] == '#') continue;

          const int rc = mask_append (hashcat_ctx, line_buf);

          if (rc == -1)
          {
            fclose (mask_fp);

            return -1;
          }
        }

        hcfree (line_buf);

        fclose (mask_fp);
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: unsupported file-type", arg);

        return -1;
      }
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    // display

    char *arg = user_options_extra->hc_workv[0];

    // mod

    hc_stat_t file_stat;

    if (hc_stat (arg, &file_stat) == -1)
    {
      const int rc = mask_append (hashcat_ctx, arg);

      if (rc == -1) return -1;
    }
    else
    {
      if (S_ISREG (file_stat.st_mode))
      {
        mask_ctx->mask_from_file = true;

        FILE *mask_fp = fopen (arg, "r");

        if (mask_fp == NULL)
        {
          event_log_error (hashcat_ctx, "%s: %s", arg, strerror (errno));

          return -1;
        }

        char *line_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

        while (!feof (mask_fp))
        {
          const int line_len = fgetl (mask_fp, line_buf);

          if (line_len == 0) continue;

          if (line_buf[0] == '#') continue;

          const int rc = mask_append (hashcat_ctx, line_buf);

          if (rc == -1)
          {
            fclose (mask_fp);

            return -1;
          }
        }

        hcfree (line_buf);

        fclose (mask_fp);
      }
      else
      {
        event_log_error (hashcat_ctx, "%s: unsupported file-type", arg);

        return -1;
      }
    }
  }

  if (mask_ctx->masks_cnt == 0)
  {
    event_log_error (hashcat_ctx, "Invalid mask");

    return -1;
  }

  mask_ctx->mask = mask_ctx->masks[0];

  return 0;
}

void mask_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t *mask_ctx = hashcat_ctx->mask_ctx;

  if (mask_ctx->enabled == false) return;

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
          event_log_error (hashcat_ctx, "Invalid line '%s' in maskfile", mask_buf);

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
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_1, 0);
        break;

      case 1:
        user_options->custom_charset_2 = mfs[1].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 1);
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_2, 1);
        break;

      case 2:
        user_options->custom_charset_3 = mfs[2].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 2);
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_3, 2);
        break;

      case 3:
        user_options->custom_charset_4 = mfs[3].mf_buf;
        mp_reset_usr (mask_ctx->mp_usr, 3);
        mp_setup_usr (hashcat_ctx, mask_ctx->mp_sys, mask_ctx->mp_usr, user_options->custom_charset_4, 3);
        break;
    }
  }

  mask_ctx->mask = mfs[mf_cnt].mf_buf;

  return 0;
}
