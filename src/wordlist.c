/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "memory.h"
#include "convert.h"
#include "logging.h"
#include "logfile.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "opencl.h"
#include "thread.h"
#include "locking.h"
#include "rp_cpu.h"
#include "rp_kernel_on_cpu.h"
#include "shared.h"
#include "hwmon.h"
#include "thread.h"
#include "dictstat.h"
#include "mpsp.h"
#include "restore.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "wordlist.h"

extern hc_global_data_t data;

void (*get_next_word_func) (char *, u32, u32 *, u32 *);

uint convert_from_hex (char *line_buf, const uint line_len)
{
  if (line_len & 1) return (line_len); // not in hex

  if (data.hex_wordlist == 1)
  {
    uint i;
    uint j;

    for (i = 0, j = 0; j < line_len; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }

    memset (line_buf + i, 0, line_len - i);

    return (i);
  }
  else if (line_len >= 6) // $HEX[] = 6
  {
    if (line_buf[0]            != '$') return (line_len);
    if (line_buf[1]            != 'H') return (line_len);
    if (line_buf[2]            != 'E') return (line_len);
    if (line_buf[3]            != 'X') return (line_len);
    if (line_buf[4]            != '[') return (line_len);
    if (line_buf[line_len - 1] != ']') return (line_len);

    uint i;
    uint j;

    for (i = 0, j = 5; j < line_len - 1; i += 1, j += 2)
    {
      line_buf[i] = hex_to_u8 ((const u8 *) &line_buf[j]);
    }

    memset (line_buf + i, 0, line_len - i);

    return (i);
  }

  return (line_len);
}

void load_segment (wl_data_t *wl_data, FILE *fd)
{
  // NOTE: use (never changing) ->incr here instead of ->avail otherwise the buffer gets bigger and bigger

  wl_data->pos = 0;

  wl_data->cnt = fread (wl_data->buf, 1, wl_data->incr - 1000, fd);

  wl_data->buf[wl_data->cnt] = 0;

  if (wl_data->cnt == 0) return;

  if (wl_data->buf[wl_data->cnt - 1] == '\n') return;

  while (!feof (fd))
  {
    if (wl_data->cnt == wl_data->avail)
    {
      wl_data->buf = (char *) myrealloc (wl_data->buf, wl_data->avail, wl_data->incr);

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

  return;
}

void get_next_word_lm (char *buf, u32 sz, u32 *len, u32 *off)
{
  char *ptr = buf;

  for (u32 i = 0; i < sz; i++, ptr++)
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

void get_next_word_uc (char *buf, u32 sz, u32 *len, u32 *off)
{
  char *ptr = buf;

  for (u32 i = 0; i < sz; i++, ptr++)
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

void get_next_word_std (char *buf, u32 sz, u32 *len, u32 *off)
{
  char *ptr = buf;

  for (u32 i = 0; i < sz; i++, ptr++)
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

void get_next_word (wl_data_t *wl_data, FILE *fd, char **out_buf, uint *out_len)
{
  while (wl_data->pos < wl_data->cnt)
  {
    uint off;
    uint len;

    char *ptr = wl_data->buf + wl_data->pos;

    get_next_word_func (ptr, wl_data->cnt - wl_data->pos, &len, &off);

    wl_data->pos += off;

    if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
    {
      char rule_buf_out[BLOCK_SIZE] = { 0 };

      int rule_len_out = -1;

      if (len < BLOCK_SIZE)
      {
        rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, ptr, len, rule_buf_out);
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

  load_segment (wl_data, fd);

  get_next_word (wl_data, fd, out_buf, out_len);
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

u64 count_words (wl_data_t *wl_data, FILE *fd, const char *dictfile, dictstat_ctx_t *dictstat_ctx)
{
  hc_signal (NULL);

  dictstat_t d;

  d.cnt = 0;

  #if defined (_POSIX)
  fstat (fileno (fd), &d.stat);
  #endif

  #if defined (_WIN)
  _fstat64 (fileno (fd), &d.stat);
  #endif

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

  if (d.stat.st_size == 0) return 0;

  const u64 cached_cnt = dictstat_find (dictstat_ctx, &d);

  if (run_rule_engine (data.rule_len_l, data.rule_buf_l) == 0)
  {
    if (cached_cnt)
    {
      u64 keyspace = cached_cnt;

      if (data.attack_kern == ATTACK_KERN_STRAIGHT)
      {
        keyspace *= data.kernel_rules_cnt;
      }
      else if (data.attack_kern == ATTACK_KERN_COMBI)
      {
        keyspace *= data.combs_cnt;
      }

      if (data.quiet == 0) log_info ("Cache-hit dictionary stats %s: %" PRIu64 " bytes, %" PRIu64 " words, %" PRIu64 " keyspace", dictfile, d.stat.st_size, cached_cnt, keyspace);
      if (data.quiet == 0) log_info ("");

      hc_signal (sigHandler_default);

      return (keyspace);
    }
  }

  time_t now  = 0;
  time_t prev = 0;

  u64 comp = 0;
  u64 cnt  = 0;
  u64 cnt2 = 0;

  while (!feof (fd))
  {
    load_segment (wl_data, fd);

    comp += wl_data->cnt;

    u32 i = 0;

    while (i < wl_data->cnt)
    {
      u32 len;
      u32 off;

      get_next_word_func (wl_data->buf + i, wl_data->cnt - i, &len, &off);

      if (run_rule_engine (data.rule_len_l, data.rule_buf_l))
      {
        char rule_buf_out[BLOCK_SIZE] = { 0 };

        int rule_len_out = -1;

        if (len < BLOCK_SIZE)
        {
          rule_len_out = _old_apply_rule (data.rule_buf_l, data.rule_len_l, wl_data->buf + i, len, rule_buf_out);
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
        if (data.attack_kern == ATTACK_KERN_STRAIGHT)
        {
          cnt += data.kernel_rules_cnt;
        }
        else if (data.attack_kern == ATTACK_KERN_COMBI)
        {
          cnt += data.combs_cnt;
        }

        d.cnt++;
      }

      i += off;

      cnt2++;
    }

    time (&now);

    if ((now - prev) == 0) continue;

    double percent = (double) comp / (double) d.stat.st_size;

    if (data.quiet == 0) log_info_nn ("Generating dictionary stats for %s: %" PRIu64 " bytes (%.2f%%), %" PRIu64 " words, %" PRIu64 " keyspace", dictfile, comp, percent * 100, cnt2, cnt);

    time (&prev);
  }

  if (data.quiet == 0) log_info ("Generated dictionary stats for %s: %" PRIu64 " bytes, %" PRIu64 " words, %" PRIu64 " keyspace", dictfile, comp, cnt2, cnt);
  if (data.quiet == 0) log_info ("");

  dictstat_append (dictstat_ctx, &d);

  hc_signal (sigHandler_default);

  return (cnt);
}
