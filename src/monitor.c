/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "memory.h"
#include "hwmon.h"
#include "timer.h"
#include "hashes.h"
#include "thread.h"
#include "restore.h"
#include "shared.h"
#include "status.h"
#include "monitor.h"

int get_runtime_left (const hashcat_ctx_t *hashcat_ctx)
{
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  double msec_paused = status_ctx->msec_paused;

  if (status_ctx->devices_status == STATUS_PAUSED)
  {
    double msec_paused_tmp = hc_timer_get (status_ctx->timer_paused);

    msec_paused += msec_paused_tmp;
  }

  time_t runtime_cur;

  time (&runtime_cur);

  const int runtime_left = (int) (status_ctx->runtime_start
                                + status_ctx->prepare_time
                                + user_options->runtime
                                + (msec_paused / 1000)
                                - runtime_cur);

  return runtime_left;
}

static int monitor (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes        = hashcat_ctx->hashes;
  hwmon_ctx_t    *hwmon_ctx     = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t   *opencl_ctx    = hashcat_ctx->opencl_ctx;
  restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;
  user_options_t *user_options  = hashcat_ctx->user_options;

  bool runtime_check      = false;
  bool remove_check       = false;
  bool status_check       = false;
  bool restore_check      = false;
  bool hwmon_check        = false;
  bool performance_check  = false;

  const int   sleep_time      = 1;
  const int   temp_threshold  = 1;      // degrees celcius
  const int   fan_speed_min   = 33;     // in percentage
  const int   fan_speed_max   = 100;
  const float exec_low        = 50.0f;  // in ms
  const float util_low        = 90.0f;  // in percent

  if (user_options->runtime)
  {
    runtime_check = true;
  }

  if (restore_ctx->enabled == true)
  {
    restore_check = true;
  }

  if ((user_options->remove == true) && (hashes->hashlist_mode == HL_MODE_FILE))
  {
    remove_check = true;
  }

  if (user_options->status == true)
  {
    status_check = true;
  }

  if (hwmon_ctx->enabled == true)
  {
    hwmon_check = true;
  }

  if (hwmon_ctx->enabled == true)
  {
    performance_check = true; // this check simply requires hwmon to work
  }

  if ((runtime_check == false) && (remove_check == false) && (status_check == false) && (restore_check == false) && (hwmon_check == false) && (performance_check == false))
  {
    return 0;
  }

  // these variables are mainly used for fan control

  int *fan_speed_chgd = (int *) hccalloc (opencl_ctx->devices_cnt, sizeof (int));

  // temperature controller "loopback" values

  int *temp_diff_old = (int *) hccalloc (opencl_ctx->devices_cnt, sizeof (int));
  int *temp_diff_sum = (int *) hccalloc (opencl_ctx->devices_cnt, sizeof (int));

  time_t last_temp_check_time;

  time (&last_temp_check_time);

  u32 slowdown_warnings    = 0;
  u32 performance_warnings = 0;

  u32 restore_left  = user_options->restore_timer;
  u32 remove_left   = user_options->remove_timer;
  u32 status_left   = user_options->status_timer;

  while (status_ctx->shutdown_inner == false)
  {
    hc_sleep (sleep_time);

    if (status_ctx->devices_status == STATUS_INIT) continue;

    if (hwmon_check == true)
    {
      hc_thread_mutex_lock (status_ctx->mux_hwmon);

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        const int rc_throttle = hm_get_throttle_with_device_id (hashcat_ctx, device_id);

        if (rc_throttle == -1) continue;

        if (rc_throttle > 0)
        {
          slowdown_warnings++;

          if (slowdown_warnings == 1) EVENT_DATA (EVENT_MONITOR_THROTTLE1, &device_id, sizeof (u32));
          if (slowdown_warnings == 2) EVENT_DATA (EVENT_MONITOR_THROTTLE2, &device_id, sizeof (u32));
          if (slowdown_warnings == 3) EVENT_DATA (EVENT_MONITOR_THROTTLE3, &device_id, sizeof (u32));
        }
        else
        {
          slowdown_warnings = 0;
        }
      }

      hc_thread_mutex_unlock (status_ctx->mux_hwmon);
    }

    if (hwmon_check == true)
    {
      hc_thread_mutex_lock (status_ctx->mux_hwmon);

      time_t temp_check_time;

      time (&temp_check_time);

      u32 Ta = temp_check_time - last_temp_check_time; // set Ta = sleep_time; is not good enough (see --remove etc)

      if (Ta == 0) Ta = 1;

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        const int temperature = hm_get_temperature_with_device_id (hashcat_ctx, device_id);

        if (temperature > (int) user_options->gpu_temp_abort)
        {
          EVENT_DATA (EVENT_MONITOR_TEMP_ABORT, &device_id, sizeof (u32));

          myabort (hashcat_ctx);
        }

        if (hwmon_ctx->hm_device[device_id].fanspeed_get_supported == false) continue;
        if (hwmon_ctx->hm_device[device_id].fanspeed_set_supported == false) continue;

        const u32 gpu_temp_retain = user_options->gpu_temp_retain;

        if (gpu_temp_retain > 0)
        {
          int temp_cur = temperature;

          int temp_diff_new = (int) gpu_temp_retain - temp_cur;

          temp_diff_sum[device_id] = temp_diff_sum[device_id] + temp_diff_new;

          // calculate Ta value (time difference in seconds between the last check and this check)

          last_temp_check_time = temp_check_time;

          float Kp = 1.8f;
          float Ki = 0.005f;
          float Kd = 6.0f;

          // PID controller (3-term controller: proportional - Kp, integral - Ki, derivative - Kd)

          int fan_diff_required = (int) (Kp * (float)temp_diff_new + Ki * Ta * (float)temp_diff_sum[device_id] + Kd * ((float)(temp_diff_new - temp_diff_old[device_id])) / Ta);

          if (abs (fan_diff_required) >= temp_threshold)
          {
            const int fan_speed_cur = hm_get_fanspeed_with_device_id (hashcat_ctx, device_id);

            int fan_speed_level = fan_speed_cur;

            if (fan_speed_chgd[device_id] == 0) fan_speed_level = temp_cur;

            int fan_speed_new = fan_speed_level - fan_diff_required;

            if (fan_speed_new > fan_speed_max) fan_speed_new = fan_speed_max;
            if (fan_speed_new < fan_speed_min) fan_speed_new = fan_speed_min;

            if (fan_speed_new != fan_speed_cur)
            {
              int freely_change_fan_speed = (fan_speed_chgd[device_id] == 1);
              int fan_speed_must_change = (fan_speed_new > fan_speed_cur);

              if ((freely_change_fan_speed == 1) || (fan_speed_must_change == 1))
              {
                if (device_param->device_vendor_id == VENDOR_ID_AMD)
                {
                  if (hwmon_ctx->hm_adl)
                  {
                    hm_set_fanspeed_with_device_id_adl (hashcat_ctx, device_id, fan_speed_new, 1);
                  }

                  if (hwmon_ctx->hm_sysfs)
                  {
                    hm_set_fanspeed_with_device_id_sysfs (hashcat_ctx, device_id, fan_speed_new);
                  }
                }
                else if (device_param->device_vendor_id == VENDOR_ID_NV)
                {
                  if (hwmon_ctx->hm_nvapi)
                  {
                    hm_set_fanspeed_with_device_id_nvapi (hashcat_ctx, device_id, fan_speed_new, 1);
                  }

                  if (hwmon_ctx->hm_xnvctrl)
                  {
                    hm_set_fanspeed_with_device_id_xnvctrl (hashcat_ctx, device_id, fan_speed_new);
                  }
                }

                fan_speed_chgd[device_id] = 1;
              }

              temp_diff_old[device_id] = temp_diff_new;
            }
          }
        }
      }

      hc_thread_mutex_unlock (status_ctx->mux_hwmon);
    }

    if (restore_check == true)
    {
      restore_left--;

      if (restore_left == 0)
      {
        const int rc = cycle_restore (hashcat_ctx);

        if (rc == -1) return -1;

        restore_left = user_options->restore_timer;
      }
    }

    if ((runtime_check == true) && (status_ctx->runtime_start > 0))
    {
      const int runtime_left = get_runtime_left (hashcat_ctx);

      if (runtime_left <= 0)
      {
        EVENT_DATA (EVENT_MONITOR_RUNTIME_LIMIT, NULL, 0);

        myabort (hashcat_ctx);
      }
    }

    if (remove_check == true)
    {
      remove_left--;

      if (remove_left == 0)
      {
        if (hashes->digests_saved != hashes->digests_done)
        {
          hashes->digests_saved = hashes->digests_done;

          const int rc = save_hash (hashcat_ctx);

          if (rc == -1) return -1;
        }

        remove_left = user_options->remove_timer;
      }
    }

    if (status_check == true)
    {
      status_left--;

      if (status_left == 0)
      {
        hc_thread_mutex_lock (status_ctx->mux_display);

        EVENT_DATA (EVENT_MONITOR_STATUS_REFRESH, NULL, 0);

        hc_thread_mutex_unlock (status_ctx->mux_display);

        status_left = user_options->status_timer;
      }
    }

    if (performance_check == true)
    {
      int exec_cnt = 0;
      int util_cnt = 0;

      double exec_total = 0;
      double util_total = 0;

      hc_thread_mutex_lock (status_ctx->mux_hwmon);

      for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
      {
        hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

        if (device_param->skipped == true) continue;

        exec_cnt++;

        const double exec = status_get_exec_msec_dev (hashcat_ctx, device_id);

        exec_total += exec;

        const int util = hm_get_utilization_with_device_id (hashcat_ctx, device_id);

        if (util == -1) continue;

        util_total += (double) util;

        util_cnt++;
      }

      hc_thread_mutex_unlock (status_ctx->mux_hwmon);

      double exec_avg = 0;
      double util_avg = 0;

      if (exec_cnt > 0) exec_avg = exec_total / exec_cnt;
      if (util_cnt > 0) util_avg = util_total / util_cnt;

      if ((exec_avg > 0) && (exec_avg < exec_low))
      {
        performance_warnings++;

        if (performance_warnings == 10) EVENT_DATA (EVENT_MONITOR_PERFORMANCE_HINT, NULL, 0);
      }

      if ((util_avg > 0) && (util_avg < util_low))
      {
        performance_warnings++;

        if (performance_warnings == 10) EVENT_DATA (EVENT_MONITOR_PERFORMANCE_HINT, NULL, 0);
      }
    }
  }

  // final round of save_hash

  if (remove_check == true)
  {
    if (hashes->digests_saved != hashes->digests_done)
    {
      const int rc = save_hash (hashcat_ctx);

      if (rc == -1) return -1;
    }
  }

  // final round of cycle_restore

  if (restore_check == true)
  {
    const int rc = cycle_restore (hashcat_ctx);

    if (rc == -1) return -1;
  }

  hcfree (fan_speed_chgd);

  hcfree (temp_diff_old);
  hcfree (temp_diff_sum);

  return 0;
}

void *thread_monitor (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  monitor (hashcat_ctx); // we should give back some useful returncode

  return NULL;
}
