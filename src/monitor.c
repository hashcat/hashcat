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
                                + status_ctx->runtime_adjust_sec
                                - runtime_cur);

  return runtime_left;
}

static int monitor (hashcat_ctx_t *hashcat_ctx)
{
  bridge_ctx_t   *bridge_ctx    = hashcat_ctx->bridge_ctx;
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
  bool performance_warned = false;

  const int    sleep_time = 1;
  const double exec_low   = 25.0;  // in ms
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
  else
  {
    // hwmon_ctx->enabled says a GPU vendor library loaded. A bridge reports its units' sensors
    // without one, and a machine whose real compute is a bridge device may well have none, so the
    // watchdog would never run on exactly the hardware that needs watching.

    for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
    {
      if (hm_bridge_owns_device (hashcat_ctx, backend_devices_idx) == false) continue;

      hwmon_check = true;

      break;
    }
  }

  if (hwmon_ctx->enabled == true)
  {
    if (bridge_ctx->enabled == false)
    {
      performance_check = true; // this check simply requires hwmon to work
    }
  }

  if ((runtime_check == false) && (remove_check == false) && (status_check == false) && (restore_check == false) && (hwmon_check == false) && (performance_check == false))
  {
    return 0;
  }

  // timer

  u32 slowdown_warnings    = 0;
  u32 performance_warnings = 0;

  // The feeder abort is one shot. Aborting does not stop the monitor, it asks the session to wind
  // down, and a bridge batch can run for seconds after that, which is long enough for another tick to
  // measure the same still-hot GPU and say so again. The per device aborts below get away without
  // this only because their kernels finish sooner.

  bool feeder_aborted = false;

  u32 restore_left  = user_options->restore_timer;
  u32 remove_left   = user_options->remove_timer;
  u32 status_left   = user_options->status_timer;

  while (status_ctx->shutdown_inner == false)
  {
    // the loop body below counts iterations as seconds, so the cadence stays one second. Only the
    // waiting is broken up, so a quit is noticed in 100ms instead of up to a full second.

    for (u32 slice = 0; slice < sleep_time * 10; slice++)
    {
      if (status_ctx->shutdown_inner == true) break;

      usleep (100000);
    }

    if (status_ctx->shutdown_inner == true) break;

    if (status_ctx->devices_status == STATUS_INIT) continue;

    if (hwmon_check == true)
    {
      hc_thread_mutex_lock (status_ctx->mux_hwmon);

      // The candidate generator, found during the sweep below and measured once after it.

      int feeder_idx = -1;

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == true) continue;

        // The GPU test guards the vendor sensor path, where a CPU's reading is not something to end
        // a run over. A bridge unit is a different case: it is the hardware doing the work, and its
        // reading comes from the bridge, so it is watched whatever the backend feeder device is.

        const bool bridge_owns = hm_bridge_owns_device (hashcat_ctx, backend_devices_idx);
        const bool is_gpu      = ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) != 0);

        if ((bridge_owns == false) && (is_gpu == false)) continue;

        // Zero means the user asked for no temperature abort at all, and it arrives here from three
        // places: --hwmon-temp-abort 0, --hwmon-disable, and benchmark mode. A bridge unit's own
        // limit REFINES that setting, it does not outrank it, so no unit is consulted while the
        // abort is off. Checked before the sensor is read, because that reading has no other use and
        // on some hardware it is a USB round trip every second.

        if (user_options->hwmon_temp_abort == 0) continue;

        const int temperature = hm_get_temperature_with_devices_idx (hashcat_ctx, backend_devices_idx);

        // A bridge unit may carry its own limit. The default is a GPU number, and a unit that is not
        // a GPU has no reason to inherit it.
        //
        // The STRICTER of the two wins, which needs no way of telling a typed 90 from the default 90.
        // Letting the unit limit win outright was wrong in one direction: a user asking for 60 on a
        // box with a unit rated 75 was given 75, so a deliberately cautious setting was ignored on
        // exactly the hardware doing the work. It stays right in the other direction, where a user
        // asking for 100 still does not get to run a part past what it survives.

        const u32 temp_abort_unit = hm_get_bridge_temperature_abort (hashcat_ctx, backend_devices_idx);

        const u32 temp_abort = (temp_abort_unit > 0) ? MIN (temp_abort_unit, user_options->hwmon_temp_abort) : user_options->hwmon_temp_abort;

        if (temperature > (int) temp_abort)
        {
          EVENT_DATA (EVENT_MONITOR_TEMP_ABORT, &backend_devices_idx, sizeof (int));

          myabort (hashcat_ctx);
        }

        // Under a bridge the reading above describes the UNIT, so the device that generated the
        // candidates for it has been measured by nobody. Remember one of them and measure it AFTER
        // this loop: every bridge unit is a virtual clone of the same physical device, so checking it
        // here would test one GPU once per unit and abort once per unit for a single overheating card.

        if ((bridge_owns == true) && (feeder_idx == -1)) feeder_idx = backend_devices_idx;
        #if defined (__APPLE__)
        // experimental feature, check the "Sensor Graphic Hot" sensor through IOKIT/SMC to catch a GPU overtemp alarm
        else if (temperature > (int) (temp_abort - 10))
        {
          if (hm_IOKIT_SMCGetSensorGraphicHot (hashcat_ctx) == 1)
          {
            event_log_error (hashcat_ctx, "hm_IOKIT_SMCGetSensorGraphicHot(): Sensor Graphics HoT, GPU Overtemp");

            EVENT_DATA (EVENT_MONITOR_TEMP_ABORT, &backend_devices_idx, sizeof (int));

            myabort (hashcat_ctx);
          }
        }
        #endif
      }

      // The candidate generator, once per tick and not once per unit. It is a GPU running flat out,
      // and under a bridge nothing else measures it: every reading taken through a bridge unit
      // describes the unit. The user's own limit applies, because this really is a GPU and that is
      // the number the default was chosen for.

      if ((feeder_idx >= 0) && (user_options->hwmon_temp_abort > 0) && (feeder_aborted == false))
      {
        const int feeder_temperature = hm_get_device_temperature (hashcat_ctx, feeder_idx);

        if (feeder_temperature > (int) user_options->hwmon_temp_abort)
        {
          feeder_aborted = true;

          EVENT_DATA (EVENT_MONITOR_TEMP_ABORT_FEEDER, &feeder_idx, sizeof (int));

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
        // Can't return from monitor for that reasons, see:
        // https://github.com/hashcat/hashcat/issues/2704
        //
        //const int rc = cycle_restore (hashcat_ctx);
        //
        //if (rc == -1) return -1;

        cycle_restore (hashcat_ctx);

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

          // Can't return from monitor for that reasons, see:
          // https://github.com/hashcat/hashcat/issues/2704
          //
          // const int rc = save_hash (hashcat_ctx);
          //
          // if (rc == -1) return -1;

          save_hash (hashcat_ctx);
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

    if (performance_check == true && status_ctx->devices_status == STATUS_RUNNING && performance_warned == false)
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

      if (((exec_avg > 0) && (exec_avg < exec_low)) || ((util_avg > 0) && (util_avg < util_low)))
      {
        performance_warnings++;
      }
      else
      {
        if (performance_warnings > 0)
        {
          performance_warnings--;
        }
      }

      if (performance_warnings == 10)
      {
        performance_warned = true;
        EVENT_DATA (EVENT_MONITOR_PERFORMANCE_HINT, NULL, 0);
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

    if (user_options->bypass_delay_chgd == true)
    {
      time (&status_ctx->timer_bypass_cur);

      if (status_ctx->devices_status == STATUS_RUNNING)
      {
        // --bypass-delay check
        if ((status_ctx->timer_bypass_cur - status_ctx->timer_bypass_start) >= user_options->bypass_delay)
        {
          time (&status_ctx->timer_bypass_start);

          // --bypass-threshold check
          if ((u32)(hashcat_ctx->hashes->digests_done_new - status_ctx->bypass_digests_done_new) < user_options->bypass_threshold)
          {
            event_log_info (hashcat_ctx, NULL);
            event_log_info (hashcat_ctx, NULL);

            bypass (hashcat_ctx);

            event_log_info (hashcat_ctx, "Bypass threshold reached! Next dictionary / mask in queue selected. Bypassing current one.");

            event_log_info (hashcat_ctx, NULL);
            status_ctx->bypass_digests_done_new = 0;
          }
          else
          {
              // enough recovered to continue the session
              status_ctx->bypass_digests_done_new = hashcat_ctx->hashes->digests_done_new;
          }
        }
      }
      else if (status_ctx->devices_status == STATUS_PAUSED)
      {
        status_ctx->timer_bypass_start += 1;
      }
    }
  }

  // final round of save_hash

  if (remove_check == true)
  {
    if (hashes->digests_saved != hashes->digests_done)
    {
      // Can't return from monitor for that reasons, see:
      // https://github.com/hashcat/hashcat/issues/2704
      //
      // const int rc = save_hash (hashcat_ctx);
      //
      // if (rc == -1) return -1;

      save_hash (hashcat_ctx);
    }
  }

  // final round of cycle_restore

  if (restore_check == true)
  {
    // Can't return from monitor for that reasons, see:
    // https://github.com/hashcat/hashcat/issues/2704
    //
    // const int rc = cycle_restore (hashcat_ctx);
    //
    // if (rc == -1) return -1;

    cycle_restore (hashcat_ctx);
  }

  return 0;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_monitor (void *p)
#else
HC_API_CALL void *thread_monitor (void *p)
#endif
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  monitor (hashcat_ctx); // we should give back some useful returncode

  return 0;
}
