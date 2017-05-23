/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "convert.h"
#include "dictstat.h"
#include "thread.h"
#include "rp_cpu.h"
#include "shared.h"
#include "wordlist.h"

u32 convert_from_hex (hashcat_ctx_t *hashcat_ctx, char *line_buf, const u32 line_len)
{
  const user_options_t *user_options = hashcat_ctx->user_options;

  if (line_len & 1) return (line_len); // not in hex

  if (user_options->hex_wordlist == true)
  {
    size_t i, j;

    for (i = 0, j = 0; j < line_len; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }

    memset (line_buf + i, 0, line_len - i);

    return (i);
  }

  if (is_hexify ((const u8 *) line_buf, (const int) line_len) == true)
  {
    const int new_len = exec_unhexify ((const u8 *) line_buf, (const int) line_len, (u8 *) line_buf, (const int) line_len);

    return (u32) new_len;
  }

  return (line_len);
}

int load_segment (hashcat_ctx_t *hashcat_ctx, FILE *fd)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  // NOTE: use (never changing) ->incr here instead of ->avail otherwise the buffer gets bigger and bigger

  wl_data->pos = 0;

  wl_data->cnt = fread (wl_data->buf, 1, wl_data->incr - 1000, fd);

  wl_data->buf[wl_data->cnt] = 0;

  if (wl_data->cnt == 0) return 0;

  if (wl_data->buf[wl_data->cnt - 1] == '\n') return 0;

  while (!feof (fd))
  {
    if (wl_data->cnt == wl_data->avail)
    {
      wl_data->buf = (char *) hcrealloc (wl_data->buf, wl_data->avail, wl_data->incr);

      wl_data->avail += wl_data->incr;
    }

    const int c = fgetc (fd);

    if (c == EOF) break;

    wl_data->buf[wl_data->cnt] = (char) c;

    wl_data->cnt++;

    if (c == '\n') break;
  }

  // ensure stream ends with a newline

  if (wl_data->buf[wl_data->cnt - 1] != '\n')
  {
    wl_data->cnt++;

    wl_data->buf[wl_data->cnt - 1] = '\n';
  }

  return 0;
}

void get_next_word_lm (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (i == 7)
    {
      *off = i;
      *len = i;

      return;
    }

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word_uc (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr >= 'a' && *ptr <= 'z') *ptr -= 0x20;

    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word_std (char *buf, u64 sz, u64 *len, u64 *off)
{
  char *ptr = buf;

  for (u64 i = 0; i < sz; i++, ptr++)
  {
    if (*ptr != '\n') continue;

    *off = i + 1;

    if ((i > 0) && (buf[i - 1] == '\r')) i--;

    *len = i;

    return;
  }

  *off = sz;
  *len = sz;
}

void get_next_word (hashcat_ctx_t *hashcat_ctx, FILE *fd, char **out_buf, u32 *out_len)
{
  user_options_t       *user_options       = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  while (wl_data->pos < wl_data->cnt)
  {
    u64 off;
    u64 len;

    char *ptr = wl_data->buf + wl_data->pos;

    wl_data->func (ptr, wl_data->cnt - wl_data->pos, &len, &off);

    wl_data->pos += off;

    // do the on-the-fly encoding

    if (wl_data->iconv_enabled == true)
    {
      char  *iconv_ptr = wl_data->iconv_tmp;
      size_t iconv_sz  = HCBUFSIZ_TINY;

      size_t ptr_len = len;

      const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

      if (iconv_rc == (size_t) -1)
      {
        len = PW_MAX1;
      }
      else
      {
        ptr = wl_data->iconv_tmp;
        len = HCBUFSIZ_TINY - iconv_sz;
      }
    }

    if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
    {
      int rule_len_out = -1;

      if (len < BLOCK_SIZE)
      {
        char unused[BLOCK_SIZE] = { 0 };

        rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, len, unused);
      }

      if (rule_len_out < 0)
      {
        continue;
      }

      if (rule_len_out > PW_MAX)
      {
        continue;
      }
    }
    else
    {
      if (len > PW_MAX)
      {
        continue;
      }
    }

    *out_buf = ptr;
    *out_len = len;

    return;
  }

  if (feof (fd))
  {
    fprintf (stderr, "BUG feof()!!\n");

    return;
  }

  load_segment (hashcat_ctx, fd);

  get_next_word (hashcat_ctx, fd, out_buf, out_len);
}

void pw_add (hc_device_param_t *device_param, const u8 *pw_buf, const int pw_len)
{
  //if (device_param->pws_cnt < device_param->kernel_power)
  //{
    pw_t *pw = (pw_t *) device_param->pws_buf + device_param->pws_cnt;

    u8 *ptr = (u8 *) pw->i;

    memcpy (ptr, pw_buf, pw_len);

    memset (ptr + pw_len, 0, sizeof (pw->i) - pw_len);

    pw->pw_len = pw_len;

    device_param->pws_cnt++;
  //}
  //else
  //{
  //  fprintf (stderr, "BUG pw_add()!!\n");
  //
  //  return;
  //}
}

int count_words (hashcat_ctx_t *hashcat_ctx, FILE *fd, const char *dictfile, u64 *result)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;
  wl_data_t            *wl_data            = hashcat_ctx->wl_data;

  //hc_signal (NULL);

  dictstat_t d;

  d.cnt = 0;

  if (hc_fstat (fileno (fd), &d.stat))
  {
    *result = 0;

    return 0;
  }

  d.stat.st_mode    = 0;
  d.stat.st_nlink   = 0;
  d.stat.st_uid     = 0;
  d.stat.st_gid     = 0;
  d.stat.st_rdev    = 0;
  d.stat.st_atime   = 0;

  #if defined (_POSIX)
  d.stat.st_blksize = 0;
  d.stat.st_blocks  = 0;
  #endif

  memset (d.encoding_from, 0, sizeof (d.encoding_from));
  memset (d.encoding_to,   0, sizeof (d.encoding_to));

  strncpy (d.encoding_from, user_options->encoding_from, sizeof (d.encoding_from));
  strncpy (d.encoding_to,   user_options->encoding_to,   sizeof (d.encoding_to));

  if (d.stat.st_size == 0)
  {
    *result = 0;

    return 0;
  }

  const u64 cached_cnt = dictstat_find (hashcat_ctx, &d);

  if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l) == 0)
  {
    if (cached_cnt)
    {
      u64 keyspace = cached_cnt;

      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        if (overflow_check_u64_mul (keyspace, straight_ctx->kernel_rules_cnt) == false) return -1;

        keyspace *= straight_ctx->kernel_rules_cnt;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if (overflow_check_u64_mul (keyspace, combinator_ctx->combs_cnt) == false) return -1;

        keyspace *= combinator_ctx->combs_cnt;
      }

      cache_hit_t cache_hit;

      cache_hit.dictfile      = (char *) dictfile;
      cache_hit.stat.st_size  = d.stat.st_size;
      cache_hit.cached_cnt    = cached_cnt;
      cache_hit.keyspace      = keyspace;

      EVENT_DATA (EVENT_WORDLIST_CACHE_HIT, &cache_hit, sizeof (cache_hit));

      *result = keyspace;

      return 0;
    }
  }

  time_t rt_start;

  time (&rt_start);

  time_t now  = 0;
  time_t prev = 0;

  u64 comp = 0;
  u64 cnt  = 0;
  u64 cnt2 = 0;

  while (!feof (fd))
  {
    load_segment (hashcat_ctx, fd);

    comp += wl_data->cnt;

    u64 i = 0;

    while (i < wl_data->cnt)
    {
      u64 len;
      u64 off;

      char *ptr = wl_data->buf + i;

      wl_data->func (ptr, wl_data->cnt - i, &len, &off);

      // do the on-the-fly encoding

      if (wl_data->iconv_enabled == true)
      {
        char  *iconv_ptr = wl_data->iconv_tmp;
        size_t iconv_sz  = HCBUFSIZ_TINY;

        size_t ptr_len = len;

        const size_t iconv_rc = iconv (wl_data->iconv_ctx, &ptr, &ptr_len, &iconv_ptr, &iconv_sz);

        if (iconv_rc == (size_t) -1)
        {
          len = PW_MAX1;
        }
        else
        {
          ptr = wl_data->iconv_tmp;
          len = HCBUFSIZ_TINY - iconv_sz;
        }
      }

      if (run_rule_engine (user_options_extra->rule_len_l, user_options->rule_buf_l))
      {
        int rule_len_out = -1;

        if (len < BLOCK_SIZE)
        {
          char unused[BLOCK_SIZE] = { 0 };

          rule_len_out = _old_apply_rule (user_options->rule_buf_l, user_options_extra->rule_len_l, ptr, len, unused);
        }

        if (rule_len_out < 0)
        {
          len = PW_MAX1;
        }
        else
        {
          len = rule_len_out;
        }
      }

      if (len < PW_MAX1)
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (overflow_check_u64_add (cnt, straight_ctx->kernel_rules_cnt) == false) return -1;

          cnt += straight_ctx->kernel_rules_cnt;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (overflow_check_u64_add (cnt, combinator_ctx->combs_cnt) == false) return -1;

          cnt += combinator_ctx->combs_cnt;
        }

        d.cnt++;
      }

      i += off;

      cnt2++;
    }

    time (&now);

    if ((now - prev) == 0) continue;

    time (&prev);

    double percent = ((double) comp / (double) d.stat.st_size) * 100;

    if (percent < 100)
    {
      cache_generate_t cache_generate;

      cache_generate.dictfile    = (char *) dictfile;
      cache_generate.comp        = comp;
      cache_generate.percent     = percent;
      cache_generate.cnt         = cnt;
      cache_generate.cnt2        = cnt2;

      EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));
    }
  }

  time_t rt_stop;

  time (&rt_stop);

  cache_generate_t cache_generate;

  cache_generate.dictfile    = (char *) dictfile;
  cache_generate.comp        = comp;
  cache_generate.percent     = 100;
  cache_generate.cnt         = cnt;
  cache_generate.cnt2        = cnt2;
  cache_generate.runtime     = rt_stop - rt_start;

  EVENT_DATA (EVENT_WORDLIST_CACHE_GENERATE, &cache_generate, sizeof (cache_generate));

  dictstat_append (hashcat_ctx, &d);

  //hc_signal (sigHandler_default);

  *result = cnt;

  return 0;
}

int wl_data_init (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;
  wl_data_t      *wl_data      = hashcat_ctx->wl_data;

  wl_data->enabled = false;

  if (user_options->benchmark   == true) return 0;
  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  wl_data->enabled = true;

  wl_data->buf   = (char *) hcmalloc (user_options->segment_size);
  wl_data->avail = user_options->segment_size;
  wl_data->incr  = user_options->segment_size;
  wl_data->cnt   = 0;
  wl_data->pos   = 0;

  /**
   * choose dictionary parser
   */

  wl_data->func = get_next_word_std;

  if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
  {
    wl_data->func = get_next_word_uc;
  }

  if (hashconfig->hash_mode == 3000) // yes that's fine that way
  {
    wl_data->func = get_next_word_lm;
  }

  /**
   * iconv
   */

  if (strcmp (user_options->encoding_from, user_options->encoding_to))
  {
    wl_data->iconv_enabled = true;

    wl_data->iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (wl_data->iconv_ctx == (iconv_t) -1) return -1;

    wl_data->iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  return 0;
}

void wl_data_destroy (hashcat_ctx_t *hashcat_ctx)
{
  wl_data_t *wl_data = hashcat_ctx->wl_data;

  if (wl_data->enabled == false) return;

  hcfree (wl_data->buf);

  if (wl_data->iconv_enabled == true)
  {
    iconv_close (wl_data->iconv_ctx);

    wl_data->iconv_enabled = false;

    hcfree (wl_data->iconv_tmp);
  }

  memset (wl_data, 0, sizeof (wl_data_t));
}
