
#include <common.h>
#include <shared.h>
#include <bit_ops.h>
#include <rp_kernel_on_cpu.h>
#include <getopt.h>
#include <consts/hash_types.h>
#include <consts/kernel_types.h>
#include <consts/digest_sizes.h>
#include <consts/hash_options.h>
#include <consts/salt_types.h>
#include <consts/outfile_formats.h>
#include <consts/parser.h>
#include <consts/rounds_count.h>
#include <consts/optimizer_options.h>
#include <consts/devices_vendors.h>
#include <consts/hashcat_modes.h>
#include <cpu/cpu-md5.h>
#include <converter.h>
#include <cpu_rules.h>
#include <logfile.h>
#include <sort_by.h>
#include <parse_hash.h>
#include <mask_processor.h>
#include <stat_processor.h>
#include <logging.h>
#include <hc_global_data_t.h>
#include <hc_global.h>
#include <hc_device_param_t.h>
#include <status_display.h>

void status_display_machine_readable()
{
  FILE *out = stdout;

  fprintf(out, "STATUS\t%u\t", data.devices_status);

  /**
  * speed new
  */

  fprintf(out, "SPEED\t");

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    u64    speed_cnt = 0;
    double speed_ms = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      speed_cnt += device_param->speed_cnt[i];
      speed_ms += device_param->speed_ms[i];
    }

    speed_cnt /= SPEED_CACHE;
    speed_ms /= SPEED_CACHE;

    fprintf(out, "%llu\t%f\t", (unsigned long long int) speed_cnt, speed_ms);
  }

  /**
  * exec time
  */

  fprintf(out, "EXEC_RUNTIME\t");

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    double exec_ms_avg = get_avg_exec_time(device_param, EXEC_CACHE);

    fprintf(out, "%f\t", exec_ms_avg);
  }

  /**
  * words_cur
  */

  u64 words_cur = get_lowest_words_done();

  fprintf(out, "CURKU\t%llu\t", (unsigned long long int) words_cur);

  /**
  * counter
  */

  u64 progress_total = data.words_cnt * data.salts_cnt;

  u64 all_done = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    all_done += data.words_progress_done[salt_pos];
    all_rejected += data.words_progress_rejected[salt_pos];
    all_restored += data.words_progress_restored[salt_pos];
  }

  u64 progress_cur = all_restored + all_done + all_rejected;
  u64 progress_end = progress_total;

  u64 progress_skip = 0;

  if (data.skip)
  {
    progress_skip = MIN(data.skip, data.words_base) * data.salts_cnt;

    switch (data.attack_kern) {
    case ATTACK_KERN_STRAIGHT: progress_skip *= data.kernel_rules_cnt; break;
    case ATTACK_KERN_COMBI: progress_skip *= data.combs_cnt; break;
    case ATTACK_KERN_BF: progress_skip *= data.bfs_cnt; break;
    }
  }

  if (data.limit)
  {
    progress_end = MIN(data.limit, data.words_base) * data.salts_cnt;

    switch (data.attack_kern) {
    case ATTACK_KERN_STRAIGHT: progress_end *= data.kernel_rules_cnt; break;
    case ATTACK_KERN_COMBI: progress_end *= data.combs_cnt; break;
    case ATTACK_KERN_BF: progress_end *= data.bfs_cnt; break;
    }
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  fprintf(out, "PROGRESS\t%llu\t%llu\t", (unsigned long long int) progress_cur_relative_skip, (unsigned long long int) progress_end_relative_skip);

  /**
  * cracks
  */

  fprintf(out, "RECHASH\t%u\t%u\t", data.digests_done, data.digests_cnt);
  fprintf(out, "RECSALT\t%u\t%u\t", data.salts_done, data.salts_cnt);

  /**
  * temperature
  */

#ifdef HAVE_HWMON
  if (data.gpu_temp_disable == 0)
  {
    fprintf(out, "TEMP\t");

    hc_thread_mutex_lock(mux_adl);

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      int temp = hm_get_temperature_with_device_id(device_id);

      fprintf(out, "%d\t", temp);
    }

    hc_thread_mutex_unlock(mux_adl);
  }
#endif // HAVE_HWMON

  /**
  * flush
  */

  fputs(EOL, out);
  fflush(out);
}

void status_display()
{
  if (data.devices_status == STATUS_INIT ||
    data.devices_status == STATUS_STARTING)return;

  // in this case some required buffers are free'd, ascii_digest() would run into segfault
  if (data.shutdown_inner == 1) return;

  if (data.machine_readable == 1)
  {
    status_display_machine_readable();

    return;
  }

  char tmp_buf[1000] = { 0 };

  uint tmp_len = 0;

  log_info("Session.Name...: %s", data.session);

  char *status_type = strstatus(data.devices_status);

  uint hash_mode = data.hash_mode;

  char *hash_type = strhashtype(hash_mode); // not a bug

  log_info("Status.........: %s", status_type);

  /**
  * show rules
  */

  if (data.rp_files_cnt)
  {
    uint i;

    for (i = 0, tmp_len = 0; i < data.rp_files_cnt - 1 && tmp_len < sizeof(tmp_buf); i++)
    {
      tmp_len += snprintf(tmp_buf + tmp_len, sizeof(tmp_buf) - tmp_len, "File (%s), ", data.rp_files[i]);
    }

    snprintf(tmp_buf + tmp_len, sizeof(tmp_buf) - tmp_len, "File (%s)", data.rp_files[i]);

    log_info("Rules.Type.....: %s", tmp_buf);

    tmp_len = 0;
  }

  if (data.rp_gen)
  {
    log_info("Rules.Type.....: Generated (%u)", data.rp_gen);

    if (data.rp_gen_seed)
    {
      log_info("Rules.Seed.....: %u", data.rp_gen_seed);
    }
  }

  /**
  * show input
  */

  switch (data.attack_mode) {
  case ATTACK_MODE_STRAIGHT:
    switch (data.wordlist_mode) {
    case WL_MODE_FILE:
      if (data.dictfile != NULL) log_info("Input.Mode.....: File (%s)", data.dictfile);
      break;
    case WL_MODE_STDIN:
      log_info("Input.Mode.....: Pipe");
      break;
    }
    break;
  case ATTACK_MODE_COMBI:
    if (data.dictfile != NULL) log_info("Input.Left.....: File (%s)", data.dictfile);
    if (data.dictfile2 != NULL) log_info("Input.Right....: File (%s)", data.dictfile2);
    break;
  case ATTACK_MODE_BF:
  {
    char *mask = data.mask;

    if (mask != NULL)
    {
      uint mask_len = data.css_cnt;

      tmp_len += snprintf(tmp_buf + tmp_len, sizeof(tmp_buf) - tmp_len, "Mask (%s)", mask);

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

        tmp_len += snprintf(tmp_buf + tmp_len, sizeof(tmp_buf) - tmp_len, " [%i]", mask_len);
      }

      if (data.maskcnt > 1)
      {
        float mask_percentage = (float)data.maskpos / (float)data.maskcnt;

        tmp_len += snprintf(tmp_buf + tmp_len, sizeof(tmp_buf) - tmp_len, " (%.02f%%)", mask_percentage * 100);
      }

      log_info("Input.Mode.....: %s", tmp_buf);

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

        log_info("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
      }
    }

    tmp_len = 0;
  }
  break;
  case ATTACK_MODE_HYBRID1:
  {
    if (data.dictfile != NULL) log_info("Input.Left.....: File (%s)", data.dictfile);
    if (data.mask != NULL) log_info("Input.Right....: Mask (%s) [%i]", data.mask, data.css_cnt);
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

      log_info("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }
  break;
  case ATTACK_MODE_HYBRID2:
  {
    if (data.mask != NULL) log_info("Input.Left.....: Mask (%s) [%i]", data.mask, data.css_cnt);
    if (data.dictfile != NULL) log_info("Input.Right....: File (%s)", data.dictfile);
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

      log_info("Custom.Chars...: -1 %s, -2 %s, -3 %s, -4 %s", custom_charset_1, custom_charset_2, custom_charset_3, custom_charset_4);
    }
  }
  break;
  }

  if (data.digests_cnt == 1)
  {
    switch (data.hash_mode) {
    case 2500:
    {
      wpa_t *wpa = (wpa_t *)data.esalts_buf;

      log_info("Hash.Target....: %s (%02x:%02x:%02x:%02x:%02x:%02x <-> %02x:%02x:%02x:%02x:%02x:%02x)",
        (char *)data.salts_buf[0].salt_buf,
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
    break;
    case 5200:
    {
      log_info("Hash.Target....: File (%s)", data.hashfile);
    }
    break;
    case 9000:
    {
      log_info("Hash.Target....: File (%s)", data.hashfile);
    }
    default:
    {
      if ((data.hash_mode >= 6200) && (data.hash_mode <= 6299))
      {
        log_info("Hash.Target....: File (%s)", data.hashfile);
      }
      else if ((data.hash_mode >= 13700) && (data.hash_mode <= 13799))
      {
        log_info("Hash.Target....: File (%s)", data.hashfile);
      }
      else
      {
        char out_buf[HCBUFSIZ] = { 0 };

        ascii_digest(out_buf, 0, 0);

        // limit length
        if (strlen(out_buf) > 40)
        {
          out_buf[41] = '.';
          out_buf[42] = '.';
          out_buf[43] = '.';
          out_buf[44] = 0;
        }

        log_info("Hash.Target....: %s", out_buf);
      }
    }
    break;
    }
  }
  else
  {
    if (data.hash_mode == 3000)
    {
      char out_buf1[32] = { 0 };
      char out_buf2[32] = { 0 };

      ascii_digest(out_buf1, 0, 0);
      ascii_digest(out_buf2, 0, 1);

      log_info("Hash.Target....: %s, %s", out_buf1, out_buf2);
    }
    else
    {
      log_info("Hash.Target....: File (%s)", data.hashfile);
    }
  }

  log_info("Hash.Type......: %s", hash_type);

  /**
  * speed new
  */

  u64    speed_cnt[DEVICES_MAX] = { 0 };
  double speed_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    speed_cnt[device_id] = 0;
    speed_ms[device_id] = 0;

    for (int i = 0; i < SPEED_CACHE; i++)
    {
      speed_cnt[device_id] += device_param->speed_cnt[i];
      speed_ms[device_id] += device_param->speed_ms[i];
    }

    speed_cnt[device_id] /= SPEED_CACHE;
    speed_ms[device_id] /= SPEED_CACHE;
  }

  double hashes_all_ms = 0;

  double hashes_dev_ms[DEVICES_MAX] = { 0 };

  for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &data.devices_param[device_id];

    if (device_param->skipped) continue;

    hashes_dev_ms[device_id] = 0;

    if (speed_ms[device_id])
    {
      hashes_dev_ms[device_id] = (double)speed_cnt[device_id] / speed_ms[device_id];

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

    double exec_ms_avg = get_avg_exec_time(device_param, EXEC_CACHE);

    exec_all_ms[device_id] = exec_ms_avg;
  }

  /**
  * timers
  */

  double ms_running = 0;

  ms_running = hc_timer_get(data.timer_running);

  double ms_paused = data.ms_paused;

  if (data.devices_status == STATUS_PAUSED)
  {
    double ms_paused_tmp = 0;

    ms_paused_tmp = hc_timer_get(data.timer_paused);

    ms_paused += ms_paused_tmp;
  }

#ifdef WIN

  __time64_t sec_run = (__time64_t)(ms_running / 1000);

#else

  time_t sec_run = ms_running / 1000;

#endif

  if (sec_run)
  {
    char display_run[32] = { 0 };

    struct tm tm_run;

    struct tm *tmp = NULL;

#ifdef WIN

    tmp = _gmtime64(&sec_run);

#else

    tmp = gmtime(&sec_run);

#endif

    if (tmp != NULL)
    {
      memset(&tm_run, 0, sizeof(tm_run));

      memcpy(&tm_run, tmp, sizeof(tm_run));

      format_timer_display(&tm_run, display_run, sizeof(tm_run));

      char *start = ctime(&data.proc_start);

      size_t start_len = strlen(start);

      if (start[start_len - 1] == '\n') start[start_len - 1] = 0;
      if (start[start_len - 2] == '\r') start[start_len - 2] = 0;

      log_info("Time.Started...: %s (%s)", start, display_run);
    }
  }
  else
  {
    log_info("Time.Started...: 0 secs");
  }

  /**
  * counters
  */

  u64 progress_total = data.words_cnt * data.salts_cnt;

  u64 all_done = 0;
  u64 all_rejected = 0;
  u64 all_restored = 0;

  u64 progress_noneed = 0;

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    all_done += data.words_progress_done[salt_pos];
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
    progress_skip = MIN(data.skip, data.words_base) * data.salts_cnt;

    switch (data.attack_kern) {
    case ATTACK_KERN_STRAIGHT:
      progress_skip *= data.kernel_rules_cnt;
      break;
    case ATTACK_KERN_COMBI:
      progress_skip *= data.combs_cnt;
      break;
    case ATTACK_KERN_BF:
      progress_skip *= data.bfs_cnt;
      break;
    }
  }

  if (data.limit)
  {
    progress_end = MIN(data.limit, data.words_base) * data.salts_cnt;

    switch (data.attack_kern) {
    case ATTACK_KERN_STRAIGHT:
      progress_end *= data.kernel_rules_cnt;
      break;
    case ATTACK_KERN_COMBI:
      progress_end *= data.combs_cnt;
      break;
    case ATTACK_KERN_BF:
      progress_end *= data.bfs_cnt;
      break;
    }
  }

  u64 progress_cur_relative_skip = progress_cur - progress_skip;
  u64 progress_end_relative_skip = progress_end - progress_skip;

  if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
  {
    if (data.devices_status != STATUS_CRACKED)
    {
#ifdef WIN
      __time64_t sec_etc = 0;
#else
      time_t sec_etc = 0;
#endif

      if (hashes_all_ms)
      {
        u64 progress_left_relative_skip = progress_end_relative_skip - progress_cur_relative_skip;

        u64 ms_left = (u64)((progress_left_relative_skip - progress_noneed) / hashes_all_ms);

        sec_etc = ms_left / 1000;
      }

      if (sec_etc == 0)
      {
        //log_info ("Time.Estimated.: 0 secs");
      }
      else if ((u64)sec_etc > ETC_MAX)
      {
        log_info("Time.Estimated.: > 10 Years");
      }
      else
      {
        char display_etc[32] = { 0 };
        char display_runtime[32] = { 0 };

        struct tm tm_etc;
        struct tm tm_runtime;

        struct tm *tmp = NULL;

#ifdef WIN
        tmp = _gmtime64(&sec_etc);
#else
        tmp = gmtime(&sec_etc);
#endif

        if (tmp != NULL)
        {
          memcpy(&tm_etc, tmp, sizeof(tm_etc));

          format_timer_display(&tm_etc, display_etc, sizeof(display_etc));

          time_t now;

          time(&now);

          now += sec_etc;

          char *etc = ctime(&now);

          size_t etc_len = strlen(etc);

          if (etc[etc_len - 1] == '\n') etc[etc_len - 1] = 0;
          if (etc[etc_len - 2] == '\r') etc[etc_len - 2] = 0;

          if (data.runtime)
          {
            time_t runtime_cur;

            time(&runtime_cur);

#ifdef WIN

            __time64_t runtime_left = data.proc_start + data.runtime + data.prepare_time - runtime_cur;

            tmp = _gmtime64(&runtime_left);

#else

            time_t runtime_left = data.proc_start + data.runtime + data.prepare_time - runtime_cur;

            tmp = gmtime(&runtime_left);

#endif

            if ((tmp != NULL) && (runtime_left > 0) && (runtime_left < sec_etc))
            {
              memcpy(&tm_runtime, tmp, sizeof(tm_runtime));

              format_timer_display(&tm_runtime, display_runtime, sizeof(display_runtime));

              log_info("Time.Estimated.: %s (%s), but limited (%s)", etc, display_etc, display_runtime);
            }
            else
            {
              log_info("Time.Estimated.: %s (%s), but limit exceeded", etc, display_etc);
            }
          }
          else
          {
            log_info("Time.Estimated.: %s (%s)", etc, display_etc);
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

    strncpy(display_dev_cur, "0.00", 4);

    format_speed_display((float)hashes_dev_ms[device_id] * 1000, display_dev_cur, sizeof(display_dev_cur));

    log_info("Speed.Dev.#%d...: %9sH/s (%0.2fms)", device_id + 1, display_dev_cur, exec_all_ms[device_id]);
  }

  char display_all_cur[16] = { 0 };

  strncpy(display_all_cur, "0.00", 4);

  format_speed_display((float)hashes_all_ms * 1000, display_all_cur, sizeof(display_all_cur));

  if (data.devices_active > 1) log_info("Speed.Dev.#*...: %9sH/s", display_all_cur);

  const float digests_percent = (float)data.digests_done / data.digests_cnt;
  const float salts_percent = (float)data.salts_done / data.salts_cnt;

  log_info("Recovered......: %u/%u (%.2f%%) Digests, %u/%u (%.2f%%) Salts", data.digests_done, data.digests_cnt, digests_percent * 100, data.salts_done, data.salts_cnt, salts_percent * 100);

  // crack-per-time

  if (data.digests_cnt > 100)
  {
    time_t now = time(NULL);

    int cpt_cur_min = 0;
    int cpt_cur_hour = 0;
    int cpt_cur_day = 0;

    for (int i = 0; i < CPT_BUF; i++)
    {
      const uint   cracked = data.cpt_buf[i].cracked;
      const time_t timestamp = data.cpt_buf[i].timestamp;

      if ((timestamp + 60) > now)
      {
        cpt_cur_min += cracked;
      }

      if ((timestamp + 3600) > now)
      {
        cpt_cur_hour += cracked;
      }

      if ((timestamp + 86400) > now)
      {
        cpt_cur_day += cracked;
      }
    }

    double ms_real = ms_running - ms_paused;
    float cpt = (float)(data.cpt_total / (ms_real / 1000));

    float cpt_avg_min = cpt / 60;
    float cpt_avg_hour = cpt_avg_min / 60;
    float cpt_avg_day = cpt_avg_hour / 24;

    if ((data.cpt_start + 86400) < now)
    {
      log_info("Recovered/Time.: CUR:%llu,%llu,%llu AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_cur_day,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 3600) < now)
    {
      log_info("Recovered/Time.: CUR:%llu,%llu,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_cur_hour,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else if ((data.cpt_start + 60) < now)
    {
      log_info("Recovered/Time.: CUR:%llu,N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_cur_min,
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
    else
    {
      log_info("Recovered/Time.: CUR:N/A,N/A,N/A AVG:%0.2f,%0.2f,%0.2f (Min,Hour,Day)",
        cpt_avg_min,
        cpt_avg_hour,
        cpt_avg_day);
    }
  }

  // Restore point

  u64 restore_point = get_lowest_words_done();

  u64 restore_total = data.words_base;

  float percent_restore = 0;

  if (restore_total != 0) percent_restore = (float)restore_point / (float)restore_total;

  if (progress_end_relative_skip)
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      float percent_finished = (float)progress_cur_relative_skip / (float)progress_end_relative_skip;
      float percent_rejected = 0.0;

      if (progress_cur)
      {
        percent_rejected = (float)(all_rejected) / (float)progress_cur;
      }

      log_info("Progress.......: %llu/%llu (%.02f%%)", (unsigned long long int) progress_cur_relative_skip, (unsigned long long int) progress_end_relative_skip, percent_finished * 100);
      log_info("Rejected.......: %llu/%llu (%.02f%%)", (unsigned long long int) all_rejected, (unsigned long long int) progress_cur_relative_skip, percent_rejected * 100);

      if (data.restore_disable == 0)
      {
        if (percent_finished != 1)
        {
          log_info("Restore.Point..: %llu/%llu (%.02f%%)", (unsigned long long int) restore_point, (unsigned long long int) restore_total, percent_restore * 100);
        }
      }
    }
  }
  else
  {
    if ((data.wordlist_mode == WL_MODE_FILE) || (data.wordlist_mode == WL_MODE_MASK))
    {
      log_info("Progress.......: %llu/%llu (%.02f%%)", (u64)0, (u64)0, (float)100);
      log_info("Rejected.......: %llu/%llu (%.02f%%)", (u64)0, (u64)0, (float)100);

      if (data.restore_disable == 0)
      {
        log_info("Restore.Point..: %llu/%llu (%.02f%%)", (u64)0, (u64)0, (float)100);
      }
    }
    else
    {
      log_info("Progress.......: %llu", (unsigned long long int) progress_cur_relative_skip);
      log_info("Rejected.......: %llu", (unsigned long long int) all_rejected);

      // --restore not allowed if stdin is used -- really? why?

      //if (data.restore_disable == 0)
      //{
      //  log_info ("Restore.Point..: %llu", (unsigned long long int) restore_point);
      //}
    }
  }

#ifdef HAVE_HWMON

  if (
    data.devices_status == STATUS_EXHAUSTED ||
    data.devices_status == STATUS_CRACKED ||
    data.devices_status == STATUS_ABORTED ||
    data.devices_status == STATUS_QUIT
    )return;

  if (data.gpu_temp_disable == 0)
  {
    hc_thread_mutex_lock(mux_adl);

    for (uint device_id = 0; device_id < data.devices_cnt; device_id++)
    {
      hc_device_param_t *device_param = &data.devices_param[device_id];

      if (device_param->skipped) continue;

      const int num_temperature = hm_get_temperature_with_device_id(device_id);
      const int num_fanspeed = hm_get_fanspeed_with_device_id(device_id);
      const int num_utilization = hm_get_utilization_with_device_id(device_id);
      const int num_corespeed = hm_get_corespeed_with_device_id(device_id);
      const int num_memoryspeed = hm_get_memoryspeed_with_device_id(device_id);
      const int num_buslanes = hm_get_buslanes_with_device_id(device_id);
      const int num_throttle = hm_get_throttle_with_device_id(device_id);

      char output_buf[256] = { 0 };

      int output_len = 0;

      if (num_temperature >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Temp:%3uc", num_temperature);

        output_len = strlen(output_buf);
      }

      if (num_fanspeed >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Fan:%3u%%", num_fanspeed);

        output_len = strlen(output_buf);
      }

      if (num_utilization >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Util:%3u%%", num_utilization);

        output_len = strlen(output_buf);
      }

      if (num_corespeed >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Core:%4uMhz", num_corespeed);

        output_len = strlen(output_buf);
      }

      if (num_memoryspeed >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Mem:%4uMhz", num_memoryspeed);

        output_len = strlen(output_buf);
      }

      if (num_buslanes >= 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " Lanes:%u", num_buslanes);

        output_len = strlen(output_buf);
      }

      if (num_throttle == 1)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " *Throttled*");

        output_len = strlen(output_buf);
      }

      if (output_len == 0)
      {
        snprintf(output_buf + output_len, sizeof(output_buf) - output_len, " N/A");

        output_len = strlen(output_buf);
      }

      log_info("HWMon.Dev.#%d...:%s", device_id + 1, output_buf);
    }

    hc_thread_mutex_unlock(mux_adl);
  }

#endif // HAVE_HWMON
}
