/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "hwmon.h"
#include "timer.h"
#include "hashes.h"
#include "thread.h"
#include "restore.h"
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
                                + user_options->runtime
                                + (msec_paused / 1000)
                                - runtime_cur);

  return runtime_left;
}

static int monitor (hashcat_ctx_t *hashcat_ctx)
{
  hashes_t       *hashes        = hashcat_ctx->hashes;
  hwmon_ctx_t    *hwmon_ctx     = hashcat_ctx->hwmon_ctx;
  backend_ctx_t  *backend_ctx   = hashcat_ctx->backend_ctx;
  restore_ctx_t  *restore_ctx   = hashcat_ctx->restore_ctx;
  status_ctx_t   *status_ctx    = hashcat_ctx->status_ctx;
  user_options_t *user_options  = hashcat_ctx->user_options;

  bool runtime_check      = false;
  bool remove_check       = false;
  bool status_check       = false;
  bool restore_check      = false;
  bool hwmon_check        = false;
  bool performance_check  = false;

  const int    sleep_time = 1;
  const double exec_low   = 50.0;  // in ms
  const double util_low   = 90.0;  // in percent

  if (user_options->runtime)
  {
    runtime_check = true;
  }

  if (restore_ctx->enabled == true)
  {
    restore_check = true;
  }

  if ((user_options->remove == true) && ((hashes->hashlist_mode == HL_MODE_FILE_PLAIN) || (hashes->hashlist_mode == HL_MODE_FILE_BINARY)))
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

  // timer

  u32 slowdown_warnings    = 0;
  u32 performance_warnings = 0;

  u32 restore_left  = user_options->restore_timer;
  u32 remove_left   = user_options->remove_timer;
  u32 status_left   = user_options->status_timer;

  while (status_ctx->shutdown_inner == false)
  {
    sleep (sleep_time);

    if (status_ctx->devices_status == STATUS_INIT) continue;

    if (hwmon_ctx->enabled == true)
    {
      hc_thread_mutex_lock (status_ctx->mux_hwmon);

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if ((backend_ctx->devices_param[backend_devices_idx].opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        const int temperature = hm_get_temperature_with_devices_idx (hashcat_ctx, backend_devices_idx);

        if (temperature > (int) user_options->hwmon_temp_abort)
        {
          EVENT_DATA (EVENT_MONITOR_TEMP_ABORT, &backend_devices_idx, sizeof (int));

          myabort (hashcat_ctx);
        }
      }

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->skipped_warning == true) continue;

        const int rc_throttle = hm_get_throttle_with_devices_idx (hashcat_ctx, backend_devices_idx);

        if (rc_throttle == -1) continue;

        if (rc_throttle > 0)
        {
          slowdown_warnings++;

          if (slowdown_warnings == 1) EVENT_DATA (EVENT_MONITOR_THROTTLE1, &backend_devices_idx, sizeof (int));
          if (slowdown_warnings == 2) EVENT_DATA (EVENT_MONITOR_THROTTLE2, &backend_devices_idx, sizeof (int));
          if (slowdown_warnings == 3) EVENT_DATA (EVENT_MONITOR_THROTTLE3, &backend_devices_idx, sizeof (int));
        }
        else
        {
          if (slowdown_warnings > 0) slowdown_warnings--;
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

        myabort_runtime (hashcat_ctx);
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

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        if (device_param->skipped_warning == true) continue;

        exec_cnt++;

        const double exec = status_get_exec_msec_dev (hashcat_ctx, backend_devices_idx);

        exec_total += exec;

        const int util = hm_get_utilization_with_devices_idx (hashcat_ctx, backend_devices_idx);

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

    // stdin read timeout check
    // note: we skip the stdin timeout check if it was disabled with stdin_timeout_abort set to 0

    if (user_options->stdin_timeout_abort != 0)
    {
      if (status_get_progress_done (hashcat_ctx) == 0)
      {
        if (status_ctx->stdin_read_timeout_cnt > 0)
        {
          if (status_ctx->stdin_read_timeout_cnt >= user_options->stdin_timeout_abort)
          {
            EVENT_DATA (EVENT_MONITOR_NOINPUT_ABORT, NULL, 0);

            myabort (hashcat_ctx);

            status_ctx->shutdown_inner = true;

            break;
          }

          if ((status_ctx->stdin_read_timeout_cnt % STDIN_TIMEOUT_WARN) == 0)
          {
            EVENT_DATA (EVENT_MONITOR_NOINPUT_HINT, NULL, 0);
          }
        }
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

  return 0;
}

HC_API_CALL void *thread_monitor (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  monitor (hashcat_ctx); // we should give back some useful returncode

  return NULL;
}
