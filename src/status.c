/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "convert.h"
#include "restore.h"
#include "thread.h"
#include "timer.h"
#include "interface.h"
#include "hwmon.h"
#include "outfile.h"
#include "status.h"

static const char ST_0000[] = "Initializing";
static const char ST_0001[] = "Autotuning";
static const char ST_0002[] = "Running";
static const char ST_0003[] = "Paused";
static const char ST_0004[] = "Exhausted";
static const char ST_0005[] = "Cracked";
static const char ST_0006[] = "Aborted";
static const char ST_0007[] = "Quit";
static const char ST_0008[] = "Bypass";

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

  u32 level = 0;

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

static char *strstatus (const u32 devices_status)
{
  switch (devices_status)
  {
    case  STATUS_INIT:      return ((char *) ST_0000);
    case  STATUS_AUTOTUNE:  return ((char *) ST_0001);
    case  STATUS_RUNNING:   return ((char *) ST_0002);
    case  STATUS_PAUSED:    return ((char *) ST_0003);
    case  STATUS_EXHAUSTED: return ((char *) ST_0004);
    case  STATUS_CRACKED:   return ((char *) ST_0005);
    case  STATUS_ABORTED:   return ((char *) ST_0006);
    case  STATUS_QUIT:      return ((char *) ST_0007);
    case  STATUS_BYPASS:    return ((char *) ST_0008);
  }

  return ((char *) "Uninitialized! Bug!");
}

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries)
{
  int exec_pos = (int) device_param->exec_pos - last_num_entries;

  if (exec_pos < 0) exec_pos += EXEC_CACHE;

  double exec_ms_sum = 0;

  int exec_ms_cnt = 0;

  for (int i = 0; i < last_num_entries; i++)
  {
    double exec_ms = device_param->exec_ms[(exec_pos + i) % EXEC_CACHE];

    if (exec_ms > 0)
    {
      exec_ms_sum += exec_ms;

      exec_ms_cnt++;
    }
  }

  if (exec_ms_cnt == 0) return 0;

  return exec_ms_sum / exec_ms_cnt;
}

void status_display_machine_readable (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  hwmon_ctx_t          *hwmon_ctx          = hashcat_ctx->hwmon_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  restore_ctx_t        *restore_ctx        = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    log_error ("ERROR: status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    log_error ("ERROR: status view is not available during autotune phase");

    return;
  }

  FILE *out = stdout;

  fprintf (out, "STATUS\t%u\t", status_ctx->devices_status);

  /**
   * speed new
   */

  fprintf (out, "SPEED\t");

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

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

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    fprintf (out, "%f\t", exec_ms_avg);
  }

  /**
   * words_cur
   */

  u64 words_cur = get_lowest_words_done (restore_ctx, opencl_ctx);

  fprintf (out, "CURKU\t%" PRIu64 "\t", words_cur);

  /**
   * counter
   */

  u64 progress_total = status_ctx->words_cnt * hashes->salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    all_done     += status_ctx->words_progress_done[salt_pos];
    all_rejected += status_ctx->words_progress_rejected[salt_pos];
    all_restored += status_ctx->words_progress_restored[salt_pos];
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (user_options->skip)
  {
    progress_skip = MIN (user_options->skip, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_skip *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_skip *= mask_ctx->bfs_cnt;
  }

  if (user_options->limit)
  {
    progress_end = MIN (user_options->limit, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_end  *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_end  *= mask_ctx->bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  fprintf (out, "PROGRESS\t%" PRIu64 "\t%" PRIu64 "\t", progress_cur_relative_skip, progress_end_relative_skip);

  /**
   * cracks
   */

  fprintf (out, "RECHASH\t%u\t%u\t", hashes->digests_done, hashes->digests_cnt);
  fprintf (out, "RECSALT\t%u\t%u\t", hashes->salts_done,   hashes->salts_cnt);

  /**
   * temperature
   */

  if (user_options->gpu_temp_disable == false)
  {
    fprintf (out, "TEMP\t");

    hc_thread_mutex_lock (status_ctx->mux_hwmon);

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      int temp = hm_get_temperature_with_device_id (hwmon_ctx, opencl_ctx, device_id);

      fprintf (out, "%d\t", temp);
    }

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);
  }

  /**
   * flush
   */

  fputs (EOL, out);
  fflush (out);
}

void status_display (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx     = hashcat_ctx->combinator_ctx;
  cpt_ctx_t            *cpt_ctx            = hashcat_ctx->cpt_ctx;
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  hwmon_ctx_t          *hwmon_ctx          = hashcat_ctx->hwmon_ctx;
  mask_ctx_t           *mask_ctx           = hashcat_ctx->mask_ctx;
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  restore_ctx_t        *restore_ctx        = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t       *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    log_error ("ERROR: status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    log_error ("ERROR: status view is not available during autotune phase");

    return;
  }

  // in this case some required buffers are free'd, ascii_digest() would run into segfault
  if (status_ctx->shutdown_inner == 1) return;

  if (user_options->machine_readable == true)
  {
    status_display_machine_readable (hashcat_ctx);

    return;
  }

  char tmp_buf[1000] = { 0 };

  u32 tmp_len = 0;

  log_info ("Session.Name...: %s", user_options->session);

  char *status_type = strstatus (status_ctx->devices_status);

  u32 hash_mode = hashconfig->hash_mode;

  char *hash_type = strhashtype (hash_mode); // not a bug

  log_info ("Status.........: %s", status_type);

  /**
   * show rules
   */

  if (user_options->rp_files_cnt)
  {
    u32 i;

    for (i = 0, tmp_len = 0; i < user_options->rp_files_cnt - 1 && tmp_len < sizeof (tmp_buf); i++)
    {
      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s), ", user_options->rp_files[i]);
    }

    snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "File (%s)", user_options->rp_files[i]);

    log_info ("Rules.Type.....: %s", tmp_buf);

    tmp_len = 0;
  }

  if (user_options->rp_gen)
  {
    log_info ("Rules.Type.....: Generated (%u)", user_options->rp_gen);

    if (user_options->rp_gen_seed)
    {
      log_info ("Rules.Seed.....: %u", user_options->rp_gen_seed);
    }
  }

  /**
   * show input
   */

  char *custom_charset_1 = user_options->custom_charset_1;
  char *custom_charset_2 = user_options->custom_charset_2;
  char *custom_charset_3 = user_options->custom_charset_3;
  char *custom_charset_4 = user_options->custom_charset_4;

  if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
  {
    if (user_options_extra->wordlist_mode == WL_MODE_FILE)
    {
      log_info ("Input.Mode.....: File (%s)", straight_ctx->dict);
    }
    else if (user_options_extra->wordlist_mode == WL_MODE_STDIN)
    {
      log_info ("Input.Mode.....: Pipe");
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_COMBI)
  {
    log_info ("Input.Left.....: File (%s)", combinator_ctx->dict1);
    log_info ("Input.Right....: File (%s)", combinator_ctx->dict2);
  }
  else if (user_options->attack_mode == ATTACK_MODE_BF)
  {
    char *mask = mask_ctx->mask;

    if (mask != NULL)
    {
      u32 mask_len = mask_ctx->css_cnt;

      tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, "Mask (%s)", mask);

      if (mask_len > 0)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (hashconfig->opti_type & OPTI_TYPE_APPENDED_SALT)
          {
            mask_len -= hashes->salts_buf[0].salt_len;
          }
        }

        if (hashconfig->opts_type & OPTS_TYPE_PT_UNICODE) mask_len /= 2;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " [%i]", mask_len);
      }

      if (mask_ctx->masks_cnt > 1)
      {
        const int maks_pos_done = ((status_ctx->devices_status == STATUS_EXHAUSTED) && (status_ctx->run_main_level1 == true)) ? 1 : 0;

        double mask_percentage = (double) (mask_ctx->masks_pos + maks_pos_done) / (double) mask_ctx->masks_cnt;

        tmp_len += snprintf (tmp_buf + tmp_len, sizeof (tmp_buf) - tmp_len, " (%.02f%%)", mask_percentage * 100);
      }

      log_info ("Input.Mode.....: %s", tmp_buf);

      if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL))
      {
        if (custom_charset_1 == NULL) custom_charset_1 = "Undefined";
        if (custom_charset_2 == NULL) custom_charset_2 = "Undefined";
        if (custom_charset_3 == NULL) custom_charset_3 = "Undefined";
        if (custom_charset_4 == NULL) custom_charset_4 = "Undefined";

        log_info ("Custom.Charset.: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
      }
    }

    tmp_len = 0;
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
  {
    log_info ("Input.Left.....: File (%s)", straight_ctx->dict);
    log_info ("Input.Right....: Mask (%s) [%i]", mask_ctx->mask, mask_ctx->css_cnt);

    if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL))
    {
      if (custom_charset_1 == NULL) custom_charset_1 = "Undefined";
      if (custom_charset_2 == NULL) custom_charset_2 = "Undefined";
      if (custom_charset_3 == NULL) custom_charset_3 = "Undefined";
      if (custom_charset_4 == NULL) custom_charset_4 = "Undefined";

      log_info ("Custom.Charset.: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }
  else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
  {
    log_info ("Input.Left.....: Mask (%s) [%i]", mask_ctx->mask, mask_ctx->css_cnt);
    log_info ("Input.Right....: File (%s)", straight_ctx->dict);

    if ((custom_charset_1 != NULL) || (custom_charset_2 != NULL) || (custom_charset_3 != NULL) || (custom_charset_4 != NULL))
    {
      if (custom_charset_1 == NULL) custom_charset_1 = "Undefined";
      if (custom_charset_2 == NULL) custom_charset_2 = "Undefined";
      if (custom_charset_3 == NULL) custom_charset_3 = "Undefined";
      if (custom_charset_4 == NULL) custom_charset_4 = "Undefined";

      log_info ("Custom.Charset.: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }

  if (hashes->digests_cnt == 1)
  {
    if (hashconfig->hash_mode == 2500)
    {
      wpa_t *wpa = (wpa_t *) hashes->esalts_buf;

      log_info ("Hash.Target....: %s (%02x:%02x:%02x:%02x:%02x:%02x <-> %02x:%02x:%02x:%02x:%02x:%02x)",
                (char *) hashes->salts_buf[0].salt_buf,
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
    else if (hashconfig->hash_mode == 5200)
    {
      log_info ("Hash.Target....: File (%s)", hashes->hashfile);
    }
    else if (hashconfig->hash_mode == 9000)
    {
      log_info ("Hash.Target....: File (%s)", hashes->hashfile);
    }
    else if ((hashconfig->hash_mode >= 6200) && (hashconfig->hash_mode <= 6299))
    {
      log_info ("Hash.Target....: File (%s)", hashes->hashfile);
    }
    else if ((hashconfig->hash_mode >= 13700) && (hashconfig->hash_mode <= 13799))
    {
      log_info ("Hash.Target....: File (%s)", hashes->hashfile);
    }
    else
    {
      char out_buf[HCBUFSIZ_LARGE] = { 0 };

      ascii_digest (out_buf, 0, 0, hashconfig, hashes);

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
    if (hashconfig->hash_mode == 3000)
    {
      char out_buf1[32] = { 0 };
      char out_buf2[32] = { 0 };

      ascii_digest (out_buf1, 0, 0, hashconfig, hashes);
      ascii_digest (out_buf2, 0, 1, hashconfig, hashes);

      log_info ("Hash.Target....: %s, %s", out_buf1, out_buf2);
    }
    else
    {
      log_info ("Hash.Target....: File (%s)", hashes->hashfile);
    }
  }

  log_info ("Hash.Type......: %s", hash_type);

  /**
   * speed new
   */

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

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

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

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

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  /**
   * timers
   */

  double ms_running = hc_timer_get (status_ctx->timer_running);

  double ms_paused = status_ctx->ms_paused;

  if (status_ctx->devices_status == STATUS_PAUSED)
  {
    double ms_paused_tmp = hc_timer_get (status_ctx->timer_paused);

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

      char *start = ctime (&status_ctx->proc_start);

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

  u64 progress_total = status_ctx->words_cnt * hashes->salts_cnt;

  u64 all_done     = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  u64 progress_noneed = 0;

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    all_done     += status_ctx->words_progress_done[salt_pos];
    all_rejected += status_ctx->words_progress_rejected[salt_pos];
    all_restored += status_ctx->words_progress_restored[salt_pos];

    // Important for ETA only

    if (hashes->salts_shown[salt_pos] == 1)
    {
      const u64 all = status_ctx->words_progress_done[salt_pos]
                    + status_ctx->words_progress_rejected[salt_pos]
                    + status_ctx->words_progress_restored[salt_pos];

      const u64 left = status_ctx->words_cnt - all;

      progress_noneed += left;
    }
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (user_options->skip)
  {
    progress_skip = MIN (user_options->skip, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_skip *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_skip *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_skip *= mask_ctx->bfs_cnt;
  }

  if (user_options->limit)
  {
    progress_end = MIN (user_options->limit, status_ctx->words_base) * hashes->salts_cnt;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) progress_end  *= straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    progress_end  *= combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       progress_end  *= mask_ctx->bfs_cnt;
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (status_ctx->devices_status != STATUS_CRACKED)
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

      #define SEC10YEARS (60 * 60 * 24 * 365 * 10)

      if (sec_etc == 0)
      {
        //log_info ("Time.Estimated.: 0 secs");
      }
      else if ((u64) sec_etc > SEC10YEARS)
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

          if (user_options->runtime)
          {
            time_t runtime_cur;

            time (&runtime_cur);

            #if defined (_WIN)

            __time64_t runtime_left = status_ctx->proc_start + user_options->runtime + status_ctx->prepare_time + (ms_paused / 1000) - runtime_cur;

            tmp = _gmtime64 (&runtime_left);

            #else

            time_t runtime_left = status_ctx->proc_start + user_options->runtime + status_ctx->prepare_time  + (ms_paused / 1000) - runtime_cur;

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

  if (status_ctx->run_main_level1 == true)
  {
    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      if ((device_param->outerloop_left == 0) || (device_param->innerloop_left == 0))
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          log_info ("Candidates.#%d..: [Generating]", device_id + 1);
        }
        else
        {
          log_info ("Candidates.#%d..: [Copying]", device_id + 1);
        }

        continue;
      }

      const u32 outerloop_first = 0;
      const u32 outerloop_last  = device_param->outerloop_left - 1;

      const u32 innerloop_first = 0;
      const u32 innerloop_last  = device_param->innerloop_left - 1;

      plain_t plain1 = { 0, 0, 0, outerloop_first, innerloop_first };
      plain_t plain2 = { 0, 0, 0, outerloop_last,  innerloop_last  };

      u32 plain_buf1[16] = { 0 };
      u32 plain_buf2[16] = { 0 };

      u8 *plain_ptr1 = (u8 *) plain_buf1;
      u8 *plain_ptr2 = (u8 *) plain_buf2;

      int plain_len1 = 0;
      int plain_len2 = 0;

      build_plain (hashcat_ctx, device_param, &plain1, plain_buf1, &plain_len1);
      build_plain (hashcat_ctx, device_param, &plain2, plain_buf2, &plain_len2);

      bool need_hex1 = need_hexify (plain_ptr1, plain_len1);
      bool need_hex2 = need_hexify (plain_ptr2, plain_len2);

      if ((need_hex1 == true) || (need_hex2 == true))
      {
        exec_hexify (plain_ptr1, plain_len1, plain_ptr1);
        exec_hexify (plain_ptr2, plain_len2, plain_ptr2);

        plain_ptr1[plain_len1 * 2] = 0;
        plain_ptr2[plain_len2 * 2] = 0;

        log_info ("Candidates.#%d..: $HEX[%s] -> $HEX[%s]", device_id + 1, plain_ptr1, plain_ptr2);
      }
      else
      {
        log_info ("Candidates.#%d..: %s -> %s", device_id + 1, plain_ptr1, plain_ptr2);
      }
    }
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display ((double) hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    log_info ("Speed.Dev.#%d...: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
  }

  char display_all_cur[16] = { 0 };

  strncpy (display_all_cur, "0.00", 4);

  format_speed_display ((double) hashes_all_ms * 1000, display_all_cur, sizeof (display_all_cur));

  if (opencl_ctx->devices_active > 1) log_info ("Speed.Dev.#*...: %9sH/s", display_all_cur);

  const double digests_percent = (double) hashes->digests_done / hashes->digests_cnt;
  const double salts_percent   = (double) hashes->salts_done   / hashes->salts_cnt;

  log_info ("Recovered......: %u/%u (%.2f%%) Digests, %u/%u (%.2f%%) Salts", hashes->digests_done, hashes->digests_cnt, digests_percent * 100, hashes->salts_done, hashes->salts_cnt, salts_percent * 100);

  // crack-per-time

  if (hashes->digests_cnt > 100)
  {
    time_t now = time (NULL);

    int cpt_cur_min  = 0;
    int cpt_cur_hour = 0;
    int cpt_cur_day  = 0;

    for (int i = 0; i < CPT_BUF; i++)
    {
      const u32    cracked   = cpt_ctx->cpt_buf[i].cracked;
      const time_t timestamp = cpt_ctx->cpt_buf[i].timestamp;

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

    double cpt_avg_min  = (double) cpt_ctx->cpt_total / ((ms_real / 1000) / 60);
    double cpt_avg_hour = (double) cpt_ctx->cpt_total / ((ms_real / 1000) / 3600);
    double cpt_avg_day  = (double) cpt_ctx->cpt_total / ((ms_real / 1000) / 86400);

    if ((cpt_ctx->cpt_start + 86400) < now)
    {
      log_info ("Recovered/Time.: CUR:%" PRIu64 ",%" PRIu64 ",%" PRIu64 " AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_cur_day,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((cpt_ctx->cpt_start + 3600) < now)
    {
      log_info ("Recovered/Time.: CUR:%" PRIu64 ",%" PRIu64 ",N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((cpt_ctx->cpt_start + 60) < now)
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

  u64 restore_point = get_lowest_words_done (restore_ctx, opencl_ctx);

  u64 restore_total = status_ctx->words_base;

  double percent_restore = 0;

  if (restore_total != 0) percent_restore = (double) restore_point / (double) restore_total;

  if (progress_end_relative_skip)
  {
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      double percent_finished = (double) progress_cur_relative_skip / (double) progress_end_relative_skip;
      double percent_rejected = 0.0;

      if (progress_cur)
      {
        percent_rejected = (double) (all_rejected) / (double) progress_cur;
      }

      log_info ("Progress.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", progress_cur_relative_skip, progress_end_relative_skip, percent_finished * 100);
      log_info ("Rejected.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", all_rejected,               progress_cur_relative_skip, percent_rejected * 100);

      if (user_options->restore_disable == false)
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
    if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
    {
      log_info ("Progress.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);
      log_info ("Rejected.......: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);

      if (user_options->restore_disable == false)
      {
        log_info ("Restore.Point..: %" PRIu64 "/%" PRIu64 " (%.02f%%)", 0ull, 0ull, 100);
      }
    }
    else
    {
      log_info ("Progress.......: %" PRIu64 "", progress_cur_relative_skip);
      log_info ("Rejected.......: %" PRIu64 "", all_rejected);

      // --restore not allowed if stdin is used -- really? why?

      //if (user_options->restore_disable == false)
      //{
      //  log_info ("Restore.Point..: %" PRIu64 "", restore_point);
      //}
    }
  }

  if (status_ctx->run_main_level1 == false) return;

  if (user_options->gpu_temp_disable == false)
  {
    hc_thread_mutex_lock (status_ctx->mux_hwmon);

    for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

      if (device_param->skipped) continue;

      const int num_temperature = hm_get_temperature_with_device_id (hwmon_ctx, opencl_ctx, device_id);
      const int num_fanspeed    = hm_get_fanspeed_with_device_id    (hwmon_ctx, opencl_ctx, device_id);
      const int num_utilization = hm_get_utilization_with_device_id (hwmon_ctx, opencl_ctx, device_id);
      const int num_corespeed   = hm_get_corespeed_with_device_id   (hwmon_ctx, opencl_ctx, device_id);
      const int num_memoryspeed = hm_get_memoryspeed_with_device_id (hwmon_ctx, opencl_ctx, device_id);
      const int num_buslanes    = hm_get_buslanes_with_device_id    (hwmon_ctx, opencl_ctx, device_id);
      const int num_throttle    = hm_get_throttle_with_device_id    (hwmon_ctx, opencl_ctx, device_id);

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

    hc_thread_mutex_unlock (status_ctx->mux_hwmon);
  }
}

void status_benchmark_automate (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    log_error ("ERROR: status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    log_error ("ERROR: status view is not available during autotune phase");

    return;
  }

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = device_param->speed_cnt[0];
    speed_ms[device_id]  = device_param->speed_ms[0];
  }

  u64 hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id] > 0)
    {
      hashes_dev_ms[device_id] = (double) speed_cnt[device_id] / speed_ms[device_id];
    }
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    log_info ("%u:%u:%" PRIu64 "", device_id + 1, hashconfig->hash_mode, (hashes_dev_ms[device_id] * 1000));
  }
}

void status_benchmark (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  if (status_ctx->devices_status == STATUS_INIT)
  {
    log_error ("ERROR: status view is not available during initialization phase");

    return;
  }

  if (status_ctx->devices_status == STATUS_AUTOTUNE)
  {
    log_error ("ERROR: status view is not available during autotune phase");

    return;
  }

  if (status_ctx->shutdown_inner == 1) return;

  if (user_options->machine_readable == true)
  {
    status_benchmark_automate (hashcat_ctx);

    return;
  }

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX]  = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = device_param->speed_cnt[0];
    speed_ms[device_id]  = device_param->speed_ms[0];
  }

  double hashes_all_ms = 0;

  double hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

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

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time (device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped) continue;

    char display_dev_cur[16] = { 0 };

    strncpy (display_dev_cur, "0.00", 4);

    format_speed_display ((double) hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof (display_dev_cur));

    if (opencl_ctx->devices_active >= 10)
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

  format_speed_display ((double) hashes_all_ms * 1000, display_all_cur, sizeof (display_all_cur));

  if (opencl_ctx->devices_active > 1) log_info ("Speed.Dev.#*.: %9sH/s", display_all_cur);
}

int status_progress_init (status_ctx_t *status_ctx, const hashes_t *hashes)
{
  status_ctx->words_progress_done     = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
  status_ctx->words_progress_rejected = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));
  status_ctx->words_progress_restored = (u64 *) mycalloc (hashes->salts_cnt, sizeof (u64));

  return 0;
}

void status_progress_destroy (status_ctx_t *status_ctx)
{
  myfree (status_ctx->words_progress_done);
  myfree (status_ctx->words_progress_rejected);
  myfree (status_ctx->words_progress_restored);

  status_ctx->words_progress_done     = NULL;
  status_ctx->words_progress_rejected = NULL;
  status_ctx->words_progress_restored = NULL;
}

void status_progress_reset (status_ctx_t *status_ctx, const hashes_t *hashes)
{
  memset (status_ctx->words_progress_done,     0, hashes->salts_cnt * sizeof (u64));
  memset (status_ctx->words_progress_rejected, 0, hashes->salts_cnt * sizeof (u64));
  memset (status_ctx->words_progress_restored, 0, hashes->salts_cnt * sizeof (u64));
}

int status_ctx_init (status_ctx_t *status_ctx)
{
  status_ctx->devices_status = STATUS_INIT;

  status_ctx->run_main_level1   = true;
  status_ctx->run_main_level2   = true;
  status_ctx->run_main_level3   = true;
  status_ctx->run_thread_level1 = true;
  status_ctx->run_thread_level2 = true;

  hc_thread_mutex_init (status_ctx->mux_dispatcher);
  hc_thread_mutex_init (status_ctx->mux_counter);
  hc_thread_mutex_init (status_ctx->mux_display);
  hc_thread_mutex_init (status_ctx->mux_hwmon);

  time (&status_ctx->proc_start);

  return 0;
}

void status_ctx_destroy (status_ctx_t *status_ctx)
{
  hc_thread_mutex_delete (status_ctx->mux_dispatcher);
  hc_thread_mutex_delete (status_ctx->mux_counter);
  hc_thread_mutex_delete (status_ctx->mux_display);
  hc_thread_mutex_delete (status_ctx->mux_hwmon);

  memset (status_ctx, 0, sizeof (status_ctx_t));
}
