/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "thread.h"
#include "rp_cpu.h"
#include "terminal.h"
#include "hwmon.h"
#include "mpsp.h"
#include "opencl.h"
#include "restore.h"
#include "data.h"
#include "shared.h"
#include "interface.h"
#include "status.h"

static const char ST_0000[] = "Initializing";
static const char ST_0001[] = "Starting";
static const char ST_0002[] = "Running";
static const char ST_0003[] = "Paused";
static const char ST_0004[] = "Exhausted";
static const char ST_0005[] = "Cracked";
static const char ST_0006[] = "Aborted";
static const char ST_0007[] = "Quit";
static const char ST_0008[] = "Bypass";
static const char ST_0009[] = "Running (stop at checkpoint)";
static const char ST_0010[] = "Autotuning";

extern hc_global_data_t  data;
extern hc_thread_mutex_t mux_hwmon;

hc_thread_mutex_t mux_display;

static void format_timer_display (struct tm *tm, char *buf, size_t len)
{
  const char *time_entities_s[] = { "year",  "day",  "hour",  "min",  "sec"  };
  const char *time_entities_m[] = { "years", "days", "hours", "mins", "secs" };

  if (tm->tm_year - 70)
  {
    char *time_entity1 = ((tm->tm_year - 70) == 1) ? (char *) time_entities_s[0] : (char *) time_entities_m[0];
    char *time_entity2 = ( tm->tm_yday       == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_year - 70, time_entity1, tm->tm_yday, time_entity2);
  }
  else if (tm->tm_yday)
  {
    char *time_entity1 = (tm->tm_yday == 1) ? (char *) time_entities_s[1] : (char *) time_entities_m[1];
    char *time_entity2 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_yday, time_entity1, tm->tm_hour, time_entity2);
  }
  else if (tm->tm_hour)
  {
    char *time_entity1 = (tm->tm_hour == 1) ? (char *) time_entities_s[2] : (char *) time_entities_m[2];
    char *time_entity2 = (tm->tm_min  == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_hour, time_entity1, tm->tm_min, time_entity2);
  }
  else if (tm->tm_min)
  {
    char *time_entity1 = (tm->tm_min == 1) ? (char *) time_entities_s[3] : (char *) time_entities_m[3];
    char *time_entity2 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s, %d %s", tm->tm_min, time_entity1, tm->tm_sec, time_entity2);
  }
  else
  {
    char *time_entity1 = (tm->tm_sec == 1) ? (char *) time_entities_s[4] : (char *) time_entities_m[4];

    snprintf (buf, len - 1, "%d %s", tm->tm_sec, time_entity1);
  }
}

static void format_speed_display (double val, char *buf, size_t len)
{
  if (val <= 0)
  {
    buf[0] = '0';
    buf[1] = ' ';
    buf[2] = 0;

    return;
  }

  char units[7] = { ' ', 'k', 'M', 'G', 'T', 'P', 'E' };

  uint level = 0;

  while (val > 99999)
  {
    val /= 1000;

    level++;
  }

  /* generate output */

  if (level == 0)
  {
    snprintf (buf, len - 1, "%.0f ", val);
  }
  else
  {
    snprintf (buf, len - 1, "%.1f %c", val, units[level]);
  }
}

static char *strstatus (const uint devices_status)
{
  switch (devices_status)
  {
    case  STATUS_INIT:               return ((char *) ST_0000);
    case  STATUS_STARTING:           return ((char *) ST_0001);
    case  STATUS_RUNNING:            return ((char *) ST_0002);
    case  STATUS_PAUSED:             return ((char *) ST_0003);
    case  STATUS_EXHAUSTED:          return ((char *) ST_0004);
    case  STATUS_CRACKED:            return ((char *) ST_0005);
    case  STATUS_ABORTED:            return ((char *) ST_0006);
    case  STATUS_QUIT:               return ((char *) ST_0007);
    case  STATUS_BYPASS:             return ((char *) ST_0008);
    case  STATUS_STOP_AT_CHECKPOINT: return ((char *) ST_0009);
    case  STATUS_AUTOTUNE:           return ((char *) ST_0010);
  }

  return ((char *) "Unknown");
}

void status_display_machine_readable ()
{
  FILE *out = stdout;

  fprintf (out, "STATUS\t%u\t", data.devices_status);

  /**
   * speed new
   */

  fprintf (out, "SPEED\t");

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    u64    speed_cnt  = 0;
    double speed_ms   = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      speed_cnt  += device_param->speed_cnt[i];
      speed_ms   += device_param->speed_ms[i];
    }

    speed_cnt  /= SPEED_CACHE;
    speed_ms   /= SPEED_CACHE;

    fprintf (out, "%" PRIu64 "\t%f\t", speed_cnt, speed_ms);
  }

  /**
   * exec time
   */

  fprintf (out, "EXEC_RUNTIME\t");

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    fprintf (out, "%f\t", exec_ms_avg);
  }

  /**
   * words_cur
   */

  u64 words_cur = get_lowest_words_done ();

  fprintf (out, "CURKU\t%" PRIu64 "\t", words_cur);

  /**
   * counter
   */

  u64 progress_total = data.words_cnt * data.salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    all_done     += data.words_progress_done[salt_pos];
    all_rejected += data.words_progress_rejected[salt_pos];
    all_restored += data.words_progress_restored[salt_pos];
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (data.skip)
  {
    progress_skip = MIN (data.skip, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_skip *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_skip *= data.bfs_cnt;
  }

  if (data.limit)
  {
    progress_end = MIN (data.limit, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_end  *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_end  *= data.bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  fprintf (out, "PROGRESS\t%" PRIu64 "\t%" PRIu64 "\t", progress_cur_relative_skip, progress_end_relative_skip);

  /**
   * cracks
   */

  fprintf (out, "RECHASH\t%u\t%u\t", data.digests_done, data.digests_cnt);
  fprintf (out, "RECSALT\t%u\t%u\t", data.salts_done,   data.salts_cnt);

  /**
   * temperature
   */

  #if defined (HAVE_HWMON)
  if (data.gpu_temp_disable == 0)
  {
    fprintf (out, "TEMP\t");

    hc_thread_mutex_lock (mux_hwmon);

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      int temp = hm_get_temperature_with_device_id (device_id);

      fprintf (out, "%d\t", temp);
    }

    hc_thread_mutex_unlock (mux_hwmon);
  }
  #endif // HAVE_HWMON

  /**
   * flush
   */

  fputs (EOL, out);
  fflush (out);
}

void status_display ()
{
  if (data.devices_status == STATUS_INIT)     return;
  if (data.devices_status == STATUS_STARTING) return;

  // in this case some required buffers are free'd, ascii_digest() would run into segfault
  if (data.shutdown_inner == 1) return;

  if (data.machine_readable == 1)
  {
    status_display_machine_readable ();

    return;
  }

  char tmp_buf[1000] = { 0 };

  uint tmp_len = 0;

  log_info ("Session.Name...: %s", data.session);

  char *status_type = strstatus (data.devices_status);

  uint hash_mode = data.hash_mode;

  char *hash_type = strhashtype (hash_mode); // not a bug

  log_info ("Status.........: %s", status_type);

  /**
   * show rules
   */

  if (data.rp_files_cnt)
  {
    uint i;

    for (i = 0, tmp_len = 0; i < data.rp_files_cnt - 1 && tmp_len < sizeof (tmp_buf); i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s), ", data.rp_files[i]);
    }

    snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s)", data.rp_files[i]);

    log_info ("Rules.Type.....: %s", tmp_buf);

    tmp_len = 0;
  }

  if (data.rp_gen)
  {
    log_info ("Rules.Type.....: Generated (%u)", data.rp_gen);

    if (data.rp_gen_seed)
    {
      log_info ("Rules.Seed.....: %u", data.rp_gen_seed);
    }
  }

  /**
   * show input
   */

  if (data.attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (data.wordlist_mode == WL_MODE_FILE)
    {
      if (data.dictfile != NULL) log_info ("Input.Mode.....: File (%s)", data.dictfile);
    }
    else if (data.wordlist_mode == WL_MODE_STDIN)
    {
      log_info ("Input.Mode.....: Pipe");
    }
  }
  else if (data.attack_mode == ATTACK_MODE_COMBI)
  {
    if (data.dictfile  != NULL) log_info ("Input.Left.....: File (%s)", data.dictfile);
    if (data.dictfile2 != NULL) log_info ("Input.Right....: File (%s)", data.dictfile2);
  }
  else if (data.attack_mode == ATTACK_MODE_BF)
  {
    char *mask = data.mask;

    if (mask != NULL)
    {
      uint mask_len = data.css_cnt;

      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "Mask (%s)", mask);

      if (mask_len > 0)
      {
        if (data.opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (data.opti_type & OPTI_TYPE_APPENDED_SALT)
          {
            mask_len -= data.salts_buf[0].salt_len;
          }
        }

        if (data.opts_type & OPTS_TYPE_PT_UNICODE) mask_len /= 2;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " [%i]", mask_len);
      }

      if (data.maskcnt > 1)
      {
        double mask_percentage = (double) data.maskpos / (double) data.maskcnt;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " (%.02f%%)", mask_percentage * 100);
      }

      log_info ("Input.Mode.....: %s", tmp_buf);

      if (data.custom_charset_1 || data.custom_charset_2 || data.custom_charset_3 || data.custom_charset_4)
      {
        char *custom_charset_1 = data.custom_charset_1;
        char *custom_charset_2 = data.custom_charset_2;
        char *custom_charset_3 = data.custom_charset_3;
        char *custom_charset_4 = data.custom_charset_4;

        if (custom_charset_1 == NULL)
        {
          custom_charset_1 = "Undefined";
        }
        if (custom_charset_2 == NULL)
        {
          custom_charset_2 = "Undefined";
        }
        if (custom_charset_3 == NULL)
        {
          custom_charset_3 = "Undefined";
        }
        if (custom_charset_4 == NULL)
        {
          custom_charset_4 = "Undefined";
        }

        log_info ("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
      }
    }

    tmp_len = 0;
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID1)
  {
    if (data.dictfile != NULL) log_info ("Input.Left.....: File (%s)", data.dictfile);
    if (data.mask     != NULL) log_info ("Input.Right....: Mask (%s) [%i]", data.mask, data.css_cnt);
    if (data.custom_charset_1 || data.custom_charset_2 || data.custom_charset_3 || data.custom_charset_4)
    {
      char *custom_charset_1 = data.custom_charset_1;
      char *custom_charset_2 = data.custom_charset_2;
      char *custom_charset_3 = data.custom_charset_3;
      char *custom_charset_4 = data.custom_charset_4;

      if (custom_charset_1 == NULL)
      {
        custom_charset_1 = "Undefined";
      }
      if (custom_charset_2 == NULL)
      {
        custom_charset_2 = "Undefined";
      }
      if (custom_charset_3 == NULL)
      {
        custom_charset_3 = "Undefined";
      }
      if (custom_charset_4 == NULL)
      {
        custom_charset_4 = "Undefined";
      }

      log_info ("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }
  else if (data.attack_mode == ATTACK_MODE_HYBRID2)
  {
    if (data.mask     != NULL) log_info ("Input.Left.....: Mask (%s) [%i]", data.mask, data.css_cnt);
    if (data.dictfile != NULL) log_info ("Input.Right....: File (%s)", data.dictfile);
    if (data.custom_charset_1 || data.custom_charset_2 || data.custom_charset_3 || data.custom_charset_4)
    {
      char *custom_charset_1 = data.custom_charset_1;
      char *custom_charset_2 = data.custom_charset_2;
      char *custom_charset_3 = data.custom_charset_3;
      char *custom_charset_4 = data.custom_charset_4;

      if (custom_charset_1 == NULL)
      {
        custom_charset_1 = "Undefined";
      }
      if (custom_charset_2 == NULL)
      {
        custom_charset_2 = "Undefined";
      }
      if (custom_charset_3 == NULL)
      {
        custom_charset_3 = "Undefined";
      }
      if (custom_charset_4 == NULL)
      {
        custom_charset_4 = "Undefined";
      }

      log_info ("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }

  if (data.digests_cnt == 1)
  {
    if (data.hash_mode == 2500)
    {
      wpa_t *wpa = (wpa_t *) data.esalts_buf;

      log_info ("Hash.Target....: %s (%02x:%02x:%02x:%02x:%02x:%02x <-> %02x:%02x:%02x:%02x:%02x:%02x)",
                (char *) data.salts_buf[0].salt_buf,
                wpa->orig_mac1[0],
                wpa->orig_mac1[1],
                wpa->orig_mac1[2],
                wpa->orig_mac1[3],
                wpa->orig_mac1[4],
                wpa->orig_mac1[5],
                wpa->orig_mac2[0],
                wpa->orig_mac2[1],
                wpa->orig_mac2[2],
                wpa->orig_mac2[3],
                wpa->orig_mac2[4],
                wpa->orig_mac2[5]);
    }
    else if (data.hash_mode == 5200)
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else if (data.hash_mode == 9000)
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else if ((data.hash_mode >= 6200) && (data.hash_mode <= 6299))
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else if ((data.hash_mode >= 13700) && (data.hash_mode <= 13799))
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
    else
    {
      char out_buf[HCBUFSIZ_LARGE] = { 0 };

      ascii_digest (out_buf, 0, 0);

      // limit length
      if (strlen (out_buf) > 40)
      {
        out_buf[41] = '.';
        out_buf[42] = '.';
        out_buf[43] = '.';
        out_buf[44] = 0;
      }

      log_info ("Hash.Target....: %s", out_buf);
    }
  }
  else
  {
    if (data.hash_mode == 3000)
    {
      char out_buf1[32] = { 0 };
      char out_buf2[32] = { 0 };

      ascii_digest (out_buf1, 0, 0);
      ascii_digest (out_buf2, 0, 1);

      log_info ("Hash.Target....: %s, %s", out_buf1, out_buf2);
    }
    else
    {
      log_info ("Hash.Target....: File (%s)", data.hashfile);
    }
  }

  log_info ("Hash.Type......: %s", hash_type);

  /**
   * speed new
   */

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = 0;
    speed_ms[device_id]  = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      speed_cnt[device_id] += device_param->speed_cnt[i];
      speed_ms[device_id]  += device_param->speed_ms[i];
    }

    speed_cnt[device_id] /= SPEED_CACHE;
    speed_ms[device_id]  /= SPEED_CACHE;
  }

  double hashes_all_ms = 0;

  double hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id] > 0)
    {
      hashes_dev_ms[device_id] = (double) speed_cnt[device_id] / speed_ms[device_id];

      hashes_all_ms += hashes_dev_ms[device_id];
    }
  }

  /**
   * exec time
   */

  double exec_all_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  /**
   * timers
   */

  double ms_running = 0;

  hc_timer_get (data.timer_running, ms_running);

  double ms_paused = data.ms_paused;

  if (data.devices_status == STATUS_PAUSED)
  {
    double ms_paused_tmp = 0;

    hc_timer_get (data.timer_paused, ms_paused_tmp);

    ms_paused += ms_paused_tmp;
  }

  #if defined (_WIN)

  __time64_t sec_run = (__time64_t) ms_running / 1000;

  #else

  time_t sec_run = (time_t) ms_running / 1000;

  #endif

  if (sec_run)
  {
    char display_run[32] = { 0 };

    struct tm tm_run;

    struct tm *tmp = NULL;

    #if defined (_WIN)

    tmp = _gmtime64 (&sec_run);

    #else

    tmp = gmtime (&sec_run);

    #endif

    if (tmp != NULL)
    {
      memset (&tm_run, 0, sizeof (tm_run));

      memcpy (&tm_run, tmp, sizeof (tm_run));

      format_timer_display (&tm_run, display_run, sizeof (tm_run));

      char *start = ctime (&data.proc_start);

      size_t start_len = strlen (start);

      if (start[start_len - 1] == '\n') start[start_len - 1] = 0;
      if (start[start_len - 2] == '\r') start[start_len - 2] = 0;

      log_info ("Time.Started...: %s (%s)", start, display_run);
    }
  }
  else
  {
    log_info ("Time.Started...: 0 secs");
  }

  /**
   * counters
   */

  u64 progress_total = data.words_cnt * data.salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  u64 progress_noneed = 0;

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    all_done     += data.words_progress_done[salt_pos];
    all_rejected += data.words_progress_rejected[salt_pos];
    all_restored += data.words_progress_restored[salt_pos];

    // Important for ETA only

    if (data.salts_shown[salt_pos] == 1)
    {
      const u64 all = data.words_progress_done[salt_pos]
                    + data.words_progress_rejected[salt_pos]
                    + data.words_progress_restored[salt_pos];

      const u64 left = data.words_cnt - all;

      progress_noneed += left;
    }
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (data.skip)
  {
    progress_skip = MIN (data.skip, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_skip *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_skip *= data.bfs_cnt;
  }

  if (data.limit)
  {
    progress_end = MIN (data.limit, data.words_base) * data.salts_cnt;

    if      (data.attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= data.kernel_rules_cnt;
    else if (data.attack_kern == ATTACK_KERN_COMBI)    progress_end  *= data.combs_cnt;
    else if (data.attack_kern == ATTACK_KERN_BF)       progress_end  *= data.bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
  {
    if (data.devices_status != STATUS_CRACKED)
    {
      #if defined (_WIN)
      __time64_t sec_etc = 0;
      #else
      time_t sec_etc = 0;
      #endif

      if (hashes_all_ms > 0)
      {
        u64 progress_left_relative_skip = progress_end_relative_skip - progress_cur_relative_skip;

        u64 ms_left = (u64) ((progress_left_relative_skip - progress_noneed) / hashes_all_ms);

        sec_etc = ms_left / 1000;
      }

      if (sec_etc == 0)
      {
        //log_info ("Time.Estimated.: 0 secs");
      }
      else if ((u64) sec_etc > ETC_MAX)
      {
        log_info ("Time.Estimated.: > 10 Years");
      }
      else
      {
        char display_etc[32]     = { 0 };
        char display_runtime[32] = { 0 };

        struct tm tm_etc;
        struct tm tm_runtime;

        struct tm *tmp = NULL;

        #if defined (_WIN)
        tmp = _gmtime64 (&sec_etc);
        #else
        tmp = gmtime (&sec_etc);
        #endif

        if (tmp != NULL)
        {
          memcpy (&tm_etc, tmp, sizeof (tm_etc));

          format_timer_display (&tm_etc, display_etc, sizeof (display_etc));

          time_t now;

          time (&now);

          now += sec_etc;

          char *etc = ctime (&now);

          size_t etc_len = strlen (etc);

          if (etc[etc_len - 1] == '\n') etc[etc_len - 1] = 0;
          if (etc[etc_len - 2] == '\r') etc[etc_len - 2] = 0;

          if (data.runtime)
          {
            time_t runtime_cur;

            time (&runtime_cur);

            #if defined (_WIN)

            __time64_t runtime_left = data.proc_start + data.runtime + data.prepare_time + (ms_paused / 1000) - runtime_cur;

            tmp = _gmtime64 (&runtime_left);

            #else

            time_t runtime_left = data.proc_start + data.runtime + data.prepare_time  + (ms_paused / 1000) - runtime_cur;

            tmp = gmtime (&runtime_left);

            #endif

            if ((tmp != NULL) && (runtime_left > 0) && (runtime_left < sec_etc))
            {
              memcpy (&tm_runtime, tmp, sizeof (tm_runtime));

              format_timer_display (&tm_runtime, display_runtime, sizeof (display_runtime));

              log_info ("Time.Estimated.: %s (%s), but limited (%s)", etc, display_etc, display_runtime);
            }
            else
            {
              log_info ("Time.Estimated.: %s (%s), but limit exceeded", etc, display_etc);
            }
          }
          else
          {
            log_info ("Time.Estimated.: %s (%s)", etc, display_etc);
          }
        }
      }
    }
  }

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display (hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    log_info ("Speed.Dev.#%d...: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
  }

  char display_all_cur[16] = { 0 };

  strncpy (display_all_cur, "0.00", 4);

  format_speed_display (hashes_all_ms * 1000, display_all_cur, sizeof (display_all_cur));

  if (data.devices_active > 1) log_info ("Speed.Dev.#*...: %9sH/s", display_all_cur);

  const double digests_percent = (double) data.digests_done / data.digests_cnt;
  const double salts_percent   = (double) data.salts_done   / data.salts_cnt;

  log_info ("Recovered......: %u/%u (%.2f%%) Digests, %u/%u (%.2f%%) Salts", data.digests_done, data.digests_cnt, digests_percent * 100, data.salts_done, data.salts_cnt, salts_percent * 100);

  // crack-per-time

  if (data.digests_cnt > 100)
  {
    time_t now = time (NULL);

    int cpt_cur_min  = 0;
    int cpt_cur_hour = 0;
    int cpt_cur_day  = 0;

    for (int i = 0; i < CPT_BUF; i++)
    {
      const uint   cracked   = data.cpt_buf[i].cracked;
      const time_t timestamp = data.cpt_buf[i].timestamp;

      if ((timestamp + 60) > now)
      {
        cpt_cur_min  += cracked;
      }

      if ((timestamp + 3600) > now)
      {
        cpt_cur_hour += cracked;
      }

      if ((timestamp + 86400) > now)
      {
        cpt_cur_day  += cracked;
      }
    }

    double ms_real = ms_running - ms_paused;

    double cpt_avg_min  = (double) data.cpt_total / ((ms_real / 1000) / 60);
    double cpt_avg_hour = (double) data.cpt_total / ((ms_real / 1000) / 3600);
    double cpt_avg_day  = (double) data.cpt_total / ((ms_real / 1000) / 86400);

    if ((data.cpt_start + 86400) < now)
    {
      log_info ("Recovered/Time.: CUR:%" PRIu64 ",%" PRIu64 ",%" PRIu64 " AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_cur_day,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 3600) < now)
    {
      log_info ("Recovered/Time.: CUR:%" PRIu64 ",%" PRIu64 ",N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 60) < now)
    {
      log_info ("Recovered/Time.: CUR:%" PRIu64 ",N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else
    {
      log_info ("Recovered/Time.: CUR:N/A,N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
  }

  // Restore point

  u64 restore_point = get_lowest_words_done ();

  u64 restore_total = data.words_base;

  double percent_restore = 0;

  if (restore_total != 0) percent_restore = (double) restore_point / (double) restore_total;

  if (progress_end_relative_skip)
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      double percent_finished = (double) progress_cur_relative_skip / (double) progress_end_relative_skip;
      double percent_rejected = 0.0;

      if (progress_cur)
      {
        percent_rejected = (double) (all_rejected) / (double) progress_cur;
      }

      log_info ("Progress.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", progress_cur_relative_skip, progress_end_relative_skip, percent_finished * 100);
      log_info ("Rejected.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", all_rejected,               progress_cur_relative_skip, percent_rejected * 100);

      if (data.restore_disable == 0)
      {
        if (percent_finished != 1)
        {
          log_info ("Restore.Point..: %" PRIu64 "/%" PRIu64 " (%.02f%%)", restore_point, restore_total, percent_restore * 100);
        }
      }
    }
  }
  else
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      log_info ("Progress.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);
      log_info ("Rejected.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);

      if (data.restore_disable == 0)
      {
        log_info ("Restore.Point..: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);
      }
    }
    else
    {
      log_info ("Progress.......: %" PRIu64 "", progress_cur_relative_skip);
      log_info ("Rejected.......: %" PRIu64 "", all_rejected);

      // --restore not allowed if stdin is used -- really? why?

      //if (data.restore_disable == 0)
      //{
      //  log_info ("Restore.Point..: %" PRIu64 "", restore_point);
      //}
    }
  }

  #if defined (HAVE_HWMON)

  if (data.devices_status == STATUS_EXHAUSTED)  return;
  if (data.devices_status == STATUS_CRACKED)    return;
  if (data.devices_status == STATUS_ABORTED)    return;
  if (data.devices_status == STATUS_QUIT)       return;

  if (data.gpu_temp_disable == 0)
  {
    hc_thread_mutex_lock (mux_hwmon);

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      const int num_temperature = hm_get_temperature_with_device_id (device_id);
      const int num_fanspeed    = hm_get_fanspeed_with_device_id    (device_id);
      const int num_utilization = hm_get_utilization_with_device_id (device_id);
      const int num_corespeed   = hm_get_corespeed_with_device_id   (device_id);
      const int num_memoryspeed = hm_get_memoryspeed_with_device_id (device_id);
      const int num_buslanes    = hm_get_buslanes_with_device_id    (device_id);
      const int num_throttle    = hm_get_throttle_with_device_id    (device_id);

      char output_buf[256] = { 0 };

      int output_len = 0;

      if (num_temperature >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Temp:%3uc", num_temperature);

        output_len = strlen (output_buf);
      }

      if (num_fanspeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Fan:%3u%%", num_fanspeed);

        output_len = strlen (output_buf);
      }

      if (num_utilization >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Util:%3u%%", num_utilization);

        output_len = strlen (output_buf);
      }

      if (num_corespeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Core:%4uMhz", num_corespeed);

        output_len = strlen (output_buf);
      }

      if (num_memoryspeed >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Mem:%4uMhz", num_memoryspeed);

        output_len = strlen (output_buf);
      }

      if (num_buslanes >= 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " Lanes:%u", num_buslanes);

        output_len = strlen (output_buf);
      }

      if (num_throttle == 1)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " *Throttled*");

        output_len = strlen (output_buf);
      }

      if (output_len == 0)
      {
        snprintf (output_buf + output_len, sizeof (output_buf) - output_len, " N/A");

        output_len = strlen (output_buf);
      }

      log_info ("HWMon.Dev.#%d...:%s", device_id + 1, output_buf);
    }

    hc_thread_mutex_unlock (mux_hwmon);
  }

  #endif // HAVE_HWMON
}

void status_benchmark_automate ()
{
  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = device_param->speed_cnt[0];
    speed_ms[device_id]  = device_param->speed_ms[0];
  }

  double hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id] > 0)
    {
      hashes_dev_ms[device_id] = (double) speed_cnt[device_id] / speed_ms[device_id];
    }
  }

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    log_info ("%u:%u:%" PRIu64 "", device_id + 1, data.hash_mode, (hashes_dev_ms[device_id] * 1000));
  }
}

void status_benchmark ()
{
  if (data.devices_status == STATUS_INIT)     return;
  if (data.devices_status == STATUS_STARTING) return;

  if (data.shutdown_inner == 1) return;

  if (data.machine_readable == 1)
  {
    status_benchmark_automate ();

    return;
  }

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = device_param->speed_cnt[0];
    speed_ms[device_id]  = device_param->speed_ms[0];
  }

  double hashes_all_ms = 0;

  double hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id] > 0)
    {
      hashes_dev_ms[device_id] = (double) speed_cnt[device_id] / speed_ms[device_id];

      hashes_all_ms += hashes_dev_ms[device_id];
    }
  }

  /**
   * exec time
   */

  double exec_all_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display (hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    if (data.devices_active >= 10)
    {
      log_info ("Speed.Dev.#%d: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
    }
    else
    {
      log_info ("Speed.Dev.#%d.: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
    }
  }

  char display_all_cur[16] = { 0 };

  strncpy (display_all_cur, "0.00", 4);

  format_speed_display (hashes_all_ms * 1000, display_all_cur, sizeof (display_all_cur));

  if (data.devices_active > 1) log_info ("Speed.Dev.#*.: %9sH/s", display_all_cur);
}
