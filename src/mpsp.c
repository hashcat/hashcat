/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "convert.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "filehandling.h"
#include "tuningdb.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "thread.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"

extern hc_global_data_t data;

const unsigned int full01 = 0x01010101;
const unsigned int full80 = 0x80808080;


void mp_css_to_uniq_tbl (uint css_cnt, cs_t *css, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /* generates a lookup table where key is the char itself for fastest possible lookup performance */

  if (css_cnt > SP_PW_MAX)
  {
    log_error ("ERROR: Mask length is too long");

    exit (-1);
  }

  for (uint css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    uint *uniq_tbl = uniq_tbls[css_pos];

    uint *cs_buf = css[css_pos].cs_buf;
    uint  cs_len = css[css_pos].cs_len;

    for (uint cs_pos = 0; cs_pos < cs_len; cs_pos++)
    {
      uint c = cs_buf[cs_pos] & 0xff;

      uniq_tbl[c] = 1;
    }
  }
}

static void mp_add_cs_buf (uint *in_buf, size_t in_len, cs_t *css, int css_cnt, hashconfig_t *hashconfig)
{
  cs_t *cs = &css[css_cnt];

  size_t css_uniq_sz = CHARSIZ * sizeof (uint);

  uint *css_uniq = (uint *) mymalloc (css_uniq_sz);

  size_t i;

  for (i = 0; i < cs->cs_len; i++)
  {
    const uint u = cs->cs_buf[i];

    css_uniq[u] = 1;
  }

  for (i = 0; i < in_len; i++)
  {
    uint u = in_buf[i] & 0xff;

    if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER) u = (uint) toupper (u);

    if (css_uniq[u] == 1) continue;

    css_uniq[u] = 1;

    cs->cs_buf[cs->cs_len] = u;

    cs->cs_len++;
  }

  myfree (css_uniq);
}

static void mp_expand (char *in_buf, size_t in_len, cs_t *mp_sys, cs_t *mp_usr, int mp_usr_offset, int interpret, hashconfig_t *hashconfig)
{
  size_t in_pos;

  for (in_pos = 0; in_pos < in_len; in_pos++)
  {
    uint p0 = in_buf[in_pos] & 0xff;

    if (interpret == 1 && p0 == '?')
    {
      in_pos++;

      if (in_pos == in_len) break;

      uint p1 = in_buf[in_pos] & 0xff;

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
      if (data.hex_charset)
      {
        in_pos++;

        if (in_pos == in_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", in_buf);

          exit (-1);
        }

        uint p1 = in_buf[in_pos] & 0xff;

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", in_buf);

          exit (-1);
        }

        uint chr = 0;

        chr  = hex_convert (p1) << 0;
        chr |= hex_convert (p0) << 4;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset, hashconfig);
      }
      else
      {
        uint chr = p0;

        mp_add_cs_buf (&chr, 1, mp_usr, mp_usr_offset, hashconfig);
      }
    }
  }
}

u64 mp_get_sum (uint css_cnt, cs_t *css)
{
  u64 sum = 1;

  for (uint css_pos = 0; css_pos < css_cnt; css_pos++)
  {
    sum *= css[css_pos].cs_len;
  }

  return (sum);
}

cs_t *mp_gen_css (char *mask_buf, size_t mask_len, cs_t *mp_sys, cs_t *mp_usr, uint *css_cnt, hashconfig_t *hashconfig)
{
  cs_t *css = (cs_t *) mycalloc (256, sizeof (cs_t));

  uint mask_pos;
  uint css_pos;

  for (mask_pos = 0, css_pos = 0; mask_pos < mask_len; mask_pos++, css_pos++)
  {
    char p0 = mask_buf[mask_pos];

    if (p0 == '?')
    {
      mask_pos++;

      if (mask_pos == mask_len) break;

      char p1 = mask_buf[mask_pos];

      uint chr = p1;

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
      if (data.hex_charset)
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

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
        {
          log_error ("ERROR: Invalid hex character detected in mask %s", mask_buf);

          exit (-1);
        }

        uint chr = 0;

        chr |= hex_convert (p1) << 0;
        chr |= hex_convert (p0) << 4;

        mp_add_cs_buf (&chr, 1, css, css_pos, hashconfig);
      }
      else
      {
        uint chr = p0;

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
    uint len  = css[i].cs_len;
    u64 next = val / len;
    uint pos  = val % len;
    buf[i] = (char) css[i].cs_buf[pos] & 0xff;
    val = next;
  }
}

uint mp_get_length (char *mask)
{
  uint len = 0;

  uint mask_len = strlen (mask);

  for (uint i = 0; i < mask_len; i++)
  {
    if (mask[i] == '?') i++;

    len++;
  }

  return len;
}

void mp_cut_at (char *mask, uint max)
{
  uint i;
  uint j;
  uint mask_len = strlen (mask);

  for (i = 0, j = 0; i < mask_len && j < max; i++, j++)
  {
    if (mask[i] == '?') i++;
  }

  mask[i] = 0;
}

void mp_setup_sys (cs_t *mp_sys)
{
  uint pos;
  uint chr;
  uint donec[CHARSIZ] = { 0 };

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

void mp_setup_usr (cs_t *mp_sys, cs_t *mp_usr, char *buf, uint index, hashconfig_t *hashconfig)
{
  FILE *fp = fopen (buf, "rb");

  if (fp == NULL || feof (fp)) // feof() in case if file is empty
  {
    mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1, hashconfig);
  }
  else
  {
    char mp_file[1024] = { 0 };

    size_t len = fread (mp_file, 1, sizeof (mp_file) - 1, fp);

    fclose (fp);

    len = in_superchop (mp_file);

    if (len == 0)
    {
      log_info ("WARNING: Charset file corrupted");

      mp_expand (buf, strlen (buf), mp_sys, mp_usr, index, 1, hashconfig);
    }
    else
    {
      mp_expand (mp_file, len, mp_sys, mp_usr, index, 0, hashconfig);
    }
  }
}

void mp_reset_usr (cs_t *mp_usr, uint index)
{
  mp_usr[index].cs_len = 0;

  memset (mp_usr[index].cs_buf, 0, sizeof (mp_usr[index].cs_buf));
}

char *mp_get_truncated_mask (char *mask_buf, size_t mask_len, uint len)
{
  char *new_mask_buf = (char *) mymalloc (256);

  uint mask_pos;

  uint css_pos;

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
      if (data.hex_charset)
      {
        mask_pos++;

        if (mask_pos == mask_len)
        {
          log_error ("ERROR: The hex-charset option always expects couples of exactly 2 hexadecimal chars, failed mask: %s", mask_buf);

          exit (-1);
        }

        char p1 = mask_buf[mask_pos];

        // if they are not valid hex character, show an error:

        if ((is_valid_hex_char (p0) == 0) || (is_valid_hex_char (p1) == 0))
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

u64 sp_get_sum (uint start, uint stop, cs_t *root_css_buf)
{
  u64 sum = 1;

  uint i;

  for (i = start; i < stop; i++)
  {
    sum *= root_css_buf[i].cs_len;
  }

  return (sum);
}

void sp_exec (u64 ctx, char *pw_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint start, uint stop)
{
  u64 v = ctx;

  cs_t *cs = &root_css_buf[start];

  uint i;

  for (i = start; i < stop; i++)
  {
    const u64 m = v % cs->cs_len;
    const u64 d = v / cs->cs_len;

    v = d;

    const uint k = cs->cs_buf[m];

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

void sp_setup_tbl (const char *shared_dir, char *hcstat, uint disable, uint classic, hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf)
{
  uint i;
  uint j;
  uint k;

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
    uint key = i % CHARSIZ;

    root_table_buf[i].key = key;
    root_table_buf[i].val = root_stats_buf[i];
  }

  for (i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint key = i % CHARSIZ;

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

void sp_tbl_to_css (hcstat_table_t *root_table_buf, hcstat_table_t *markov_table_buf, cs_t *root_css_buf, cs_t *markov_css_buf, uint threshold, uint uniq_tbls[SP_PW_MAX][CHARSIZ])
{
  /**
   * Convert tables to css
   */

  for (uint i = 0; i < SP_ROOT_CNT; i++)
  {
    uint pw_pos = i / CHARSIZ;

    cs_t *cs = &root_css_buf[pw_pos];

    if (cs->cs_len == threshold) continue;

    uint key = root_table_buf[i].key;

    if (uniq_tbls[pw_pos][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /**
   * Convert table to css
   */

  for (uint i = 0; i < SP_MARKOV_CNT; i++)
  {
    uint c = i / CHARSIZ;

    cs_t *cs = &markov_css_buf[c];

    if (cs->cs_len == threshold) continue;

    uint pw_pos = c / CHARSIZ;

    uint key = markov_table_buf[i].key;

    if ((pw_pos + 1) < SP_PW_MAX) if (uniq_tbls[pw_pos + 1][key] == 0) continue;

    cs->cs_buf[cs->cs_len] = key;

    cs->cs_len++;
  }

  /*
  for (uint i = 0; i < 8; i++)
  {
    for (uint j = 0x20; j < 0x80; j++)
    {
      cs_t *ptr = &markov_css_buf[(i * CHARSIZ) + j];

      printf ("pos:%u key:%u len:%u\n", i, j, ptr->cs_len);

      for (uint k = 0; k < 10; k++)
      {
        printf ("  %u\n",  ptr->cs_buf[k]);
      }
    }
  }
  */
}

void sp_stretch_root (hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ;
    in  += CHARSIZ;

    out->key = 0;
    out->val = 1;

    out++;

    for (uint j = 1; j < CHARSIZ; j++)
    {
      out->key = j;
      out->val = 0;

      out++;
    }
  }
}

void sp_stretch_markov (hcstat_table_t *in, hcstat_table_t *out)
{
  for (uint i = 0; i < SP_PW_MAX; i += 2)
  {
    memcpy (out, in, CHARSIZ * CHARSIZ * sizeof (hcstat_table_t));

    out += CHARSIZ * CHARSIZ;
    in  += CHARSIZ * CHARSIZ;

    for (uint j = 0; j < CHARSIZ; j++)
    {
      out->key = 0;
      out->val = 1;

      out++;

      for (uint k = 1; k < CHARSIZ; k++)
      {
        out->key = k;
        out->val = 0;

        out++;
      }
    }
  }
}
