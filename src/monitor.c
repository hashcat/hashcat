/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "logging.h"
#include "memory.h"
#include "hwmon.h"
#include "timer.h"
#include "hashes.h"
#include "thread.h"
#include "restore.h"
#include "terminal.h"
#include "status.h"
#include "shared.h"
#include "monitor.h"

static void monitor (hashcat_ctx_t *hashcat_ctx)
{
  hashconfig_t         *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t             *hashes             = hashcat_ctx->hashes;
  hwmon_ctx_t          *hwmon_ctx          = hashcat_ctx->hwmon_ctx;
  opencl_ctx_t         *opencl_ctx         = hashcat_ctx->opencl_ctx;
  restore_ctx_t        *restore_ctx        = hashcat_ctx->restore_ctx;
  status_ctx_t         *status_ctx         = hashcat_ctx->status_ctx;
  user_options_t       *user_options       = hashcat_ctx->user_options;

  bool runtime_check = false;
  bool remove_check  = false;
  bool status_check  = false;
  bool restore_check = false;
  bool hwmon_check   = false;

  const int sleep_time        = 1;
  const int temp_threshold    = 1;  // degrees celcius
  const int fan_speed_min     = 15; // in percentage
  const int fan_speed_max     = 100;

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

  if ((runtime_check == false) && (remove_check == false) && (status_check == false) && (restore_check == false) && (hwmon_check == false))
  {
    return;
  }

  // these variables are mainly used for fan control

  int *fan_speed_chgd = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));

  // temperature controller "loopback" values

  int *temp_diff_old = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));
  int *temp_diff_sum = (int *) mycalloc (opencl_ctx->devices_cnt, sizeof (int));

  time_t last_temp_check_time;

  time (&last_temp_check_time);

  u32 slowdown_warnings = 0;

  u32 restore_left = user_options->restore_timer;
  u32 remove_left  = user_options->remove_timer;
  u32 status_left  = user_options->status_timer;

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

        if (device_param->skipped) continue;

        if (device_param->device_vendor_id == VENDOR_ID_NV)
        {
          if (hwmon_ctx->hm_nvapi)
          {
            NV_GPU_PERF_POLICIES_INFO_PARAMS_V1   perfPolicies_info;
            NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1 perfPolicies_status;

            memset (&perfPolicies_info,   0, sizeof (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1));
            memset (&perfPolicies_status, 0, sizeof (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1));

            perfPolicies_info.version   = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_INFO_PARAMS_V1, 1);
            perfPolicies_status.version = MAKE_NVAPI_VERSION (NV_GPU_PERF_POLICIES_STATUS_PARAMS_V1, 1);

            hm_NvAPI_GPU_GetPerfPoliciesInfo (hwmon_ctx->hm_nvapi, hwmon_ctx->hm_device[device_id].nvapi, &perfPolicies_info);

            perfPolicies_status.info_value = perfPolicies_info.info_value;

            hm_NvAPI_GPU_GetPerfPoliciesStatus (hwmon_ctx->hm_nvapi, hwmon_ctx->hm_device[device_id].nvapi, &perfPolicies_status);

            if (perfPolicies_status.throttle & 2)
            {
              if (slowdown_warnings < 3)
              {
                if (user_options->quiet == false) clear_prompt ();

                log_info ("WARNING: Drivers temperature threshold hit on GPU #%d, expect performance to drop...", device_id + 1);

                if (slowdown_warnings == 2)
                {
                  log_info ("");
                }

                if (user_options->quiet == false) send_prompt ();

                slowdown_warnings++;
              }
            }
            else
            {
              slowdown_warnings = 0;
            }
          }
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

        if (device_param->skipped) continue;

        if ((opencl_ctx->devices_param[device_id].device_type & CL_DEVICE_TYPE_GPU) == 0) continue;

        const int temperature = hm_get_temperature_with_device_id (hwmon_ctx, opencl_ctx, device_id);

        if (temperature > (int) user_options->gpu_temp_abort)
        {
          log_error ("ERROR: Temperature limit on GPU %d reached, aborting...", device_id + 1);

          myabort (status_ctx);

          break;
        }

        const u32 gpu_temp_retain = user_options->gpu_temp_retain;

        if (gpu_temp_retain)
        {
          if (hwmon_ctx->hm_device[device_id].fan_set_supported == 1)
          {
            int temp_cur = temperature;

            int temp_diff_new = (int) gpu_temp_retain - temp_cur;

            temp_diff_sum[device_id] = temp_diff_sum[device_id] + temp_diff_new;

            // calculate Ta value (time difference in seconds between the last check and this check)

            last_temp_check_time = temp_check_time;

            float Kp = 1.8f;
            float Ki = 0.005f;
            float Kd = 6;

            // PID controller (3-term controller: proportional - Kp, integral - Ki, derivative - Kd)

            int fan_diff_required = (int) (Kp * (float)temp_diff_new + Ki * Ta * (float)temp_diff_sum[device_id] + Kd * ((float)(temp_diff_new - temp_diff_old[device_id])) / Ta);

            if (abs (fan_diff_required) >= temp_threshold)
            {
              const int fan_speed_cur = hm_get_fanspeed_with_device_id (hwmon_ctx, opencl_ctx, device_id);

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
                    hm_set_fanspeed_with_device_id_adl (hwmon_ctx, device_id, fan_speed_new, 1);
                  }
                  else if (device_param->device_vendor_id == VENDOR_ID_NV)
                  {
                    #if defined (_WIN)
                    hm_set_fanspeed_with_device_id_nvapi (hwmon_ctx, device_id, fan_speed_new, 1);
                    #endif

                    #if defined (__linux__)
                    hm_set_fanspeed_with_device_id_xnvctrl (hwmon_ctx, device_id, fan_speed_new);
                    #endif
                  }

                  fan_speed_chgd[device_id] = 1;
                }

                temp_diff_old[device_id] = temp_diff_new;
              }
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
        cycle_restore (restore_ctx, opencl_ctx);

        restore_left = user_options->restore_timer;
      }
    }

    if ((runtime_check == true) && (status_ctx->runtime_start > 0))
    {
      double ms_paused = status_ctx->ms_paused;

      if (status_ctx->devices_status == STATUS_PAUSED)
      {
        double ms_paused_tmp = hc_timer_get (status_ctx->timer_paused);

        ms_paused += ms_paused_tmp;
      }

      time_t runtime_cur;

      time (&runtime_cur);

      int runtime_left = status_ctx->proc_start + user_options->runtime + status_ctx->prepare_time + (ms_paused / 1000) - runtime_cur;

      if (runtime_left <= 0)
      {
        if (user_options->benchmark == false)
        {
          if (user_options->quiet == false) log_info ("\nNOTE: Runtime limit reached, aborting...\n");
        }

        myabort (status_ctx);
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

          save_hash (user_options, hashconfig, hashes);
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

        if (user_options->quiet == false) clear_prompt ();

        if (user_options->quiet == false) log_info ("");

        status_display (hashcat_ctx);

        if (user_options->quiet == false) log_info ("");

        hc_thread_mutex_unlock (status_ctx->mux_display);

        status_left = user_options->status_timer;
      }
    }
  }

  // final round of save_hash

  if (remove_check == true)
  {
    if (hashes->digests_saved != hashes->digests_done)
    {
      save_hash (user_options, hashconfig, hashes);
    }
  }

  // final round of cycle_restore

  if (restore_check == true)
  {
    cycle_restore (restore_ctx, opencl_ctx);
  }

  myfree (fan_speed_chgd);

  myfree (temp_diff_old);
  myfree (temp_diff_sum);
}

void *thread_monitor (void *p)
{
  hashcat_ctx_t *hashcat_ctx = (hashcat_ctx_t *) p;

  monitor (hashcat_ctx);

  return NULL;
}
