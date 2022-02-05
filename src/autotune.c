/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "backend.h"
#include "status.h"
#include "autotune.h"

static double try_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kernel_accel, const u32 kernel_loops, const u32 kernel_threads)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  user_options_t *user_options = hashcat_ctx->user_options;

  device_param->kernel_param.loop_pos = 0;
  device_param->kernel_param.loop_cnt = kernel_loops; // not a bug, both need to be set
  device_param->kernel_param.il_cnt   = kernel_loops; // because there's two variables for inner iters for slow and fast hashes

  const u32 hardware_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * kernel_threads;

  u32 kernel_power_try = hardware_power * kernel_accel;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    hashes_t *hashes = hashcat_ctx->hashes;

    const u32 salts_cnt = hashes->salts_cnt;

    if (kernel_power_try > salts_cnt)
    {
      kernel_power_try = salts_cnt;
    }
  }

  const u32 kernel_threads_sav = device_param->kernel_threads;

  device_param->kernel_threads = kernel_threads;

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, kernel_power_try, true, 0);
    }
    else
    {
      run_kernel (hashcat_ctx, device_param, KERN_RUN_4, 0, kernel_power_try, true, 0);
    }
  }
  else
  {
    run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 0, kernel_power_try, true, 0);
  }

  device_param->spin_damp = spin_damp_sav;

  device_param->kernel_threads = kernel_threads_sav;

  const double exec_msec_prev = get_avg_exec_time (device_param, 1);

  return exec_msec_prev;
}

static double try_run_times (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kernel_accel, const u32 kernel_loops, const u32 kernel_threads, const int times)
{
  double exec_msec_best = try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);

  for (int i = 1; i < times; i++)
  {
    double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);

    if (exec_msec > exec_msec_best) continue;

    exec_msec_best = exec_msec;
  }

  return exec_msec_best;
}

static u32 previous_power_of_two (const u32 x)
{
  // https://stackoverflow.com/questions/2679815/previous-power-of-2
  // really cool!

  if (x == 0) return 0;

  u32 r = x;

  r |= (r >>  1);
  r |= (r >>  2);
  r |= (r >>  4);
  r |= (r >>  8);
  r |= (r >> 16);

  return r - (r >> 1);
}

static int autotune (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  const double target_msec = backend_ctx->target_msec;

  const u32 kernel_accel_min = device_param->kernel_accel_min;
  const u32 kernel_accel_max = device_param->kernel_accel_max;

  const u32 kernel_loops_min = device_param->kernel_loops_min;
  const u32 kernel_loops_max = device_param->kernel_loops_max;

  const u32 kernel_threads_min = device_param->kernel_threads_min;
  const u32 kernel_threads_max = device_param->kernel_threads_max;

  // stores the minimum values
  // they could be used if the autotune fails and user specify --force

  if (user_options->force == true)
  {
    device_param->kernel_accel   = kernel_accel_min;
    device_param->kernel_loops   = kernel_loops_min;
    device_param->kernel_threads = kernel_threads_min;
    device_param->hardware_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * kernel_threads_min;
    device_param->kernel_power   = device_param->hardware_power * kernel_accel_min;
  }

  // start engine

  u32 kernel_accel = kernel_accel_min;
  u32 kernel_loops = kernel_loops_min;

  // for the threads we take as initial value what we receive from the runtime
  // but is only to start with something, we will fine tune this value as soon as we have our workload specified
  // this thread limiting is also performed insinde run_kernel() so we need to redo it here, too

  u32 kernel_wgs = 0;
  u32 kernel_wgs_multiple = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      kernel_wgs = device_param->kernel_wgs1;

      kernel_wgs_multiple = device_param->kernel_preferred_wgs_multiple1;
    }
    else
    {
      kernel_wgs = device_param->kernel_wgs4;

      kernel_wgs_multiple = device_param->kernel_preferred_wgs_multiple4;
    }
  }
  else
  {
    kernel_wgs = device_param->kernel_wgs2;

    kernel_wgs_multiple = device_param->kernel_preferred_wgs_multiple2;
  }

  u32 kernel_threads = kernel_threads_max;

  if ((kernel_wgs >= kernel_threads_min) && (kernel_wgs <= kernel_threads_max))
  {
    kernel_threads = kernel_wgs;
  }

  // having a value power of 2 makes it easier to divide

  const u32 kernel_threads_p2 = previous_power_of_two (kernel_threads);

  if ((kernel_threads_p2 >= kernel_threads_min) && (kernel_threads_p2 <= kernel_threads_max))
  {
    kernel_threads = kernel_threads_p2;
  }

  // in this case the user specified a fixed -n and -u on the commandline
  // no way to tune anything
  // but we need to run a few caching rounds

  if ((kernel_accel_min == kernel_accel_max) && (kernel_loops_min == kernel_loops_max))
  {
    #if defined (DEBUG)

    // don't do any autotune in debug mode in this case
    // we're propably during kernel development

    #else

    if (hashconfig->warmup_disable == false)
    {
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads);
    }

    #endif
  }
  else
  {
    // from here it's clear we are allowed to autotune
    // so let's init some fake words

    const u32 hardware_power_max = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * kernel_threads_max;

    u32 kernel_power_max = hardware_power_max * kernel_accel_max;

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      hashes_t *hashes = hashcat_ctx->hashes;

      const u32 salts_cnt = hashes->salts_cnt;

      if (kernel_power_max > salts_cnt)
      {
        kernel_power_max = salts_cnt;
      }
    }

    device_param->at_rc = -2;

    if (device_param->is_cuda == true)
    {
      if (run_cuda_kernel_atinit (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, kernel_power_max) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (run_hip_kernel_atinit (hashcat_ctx, device_param, device_param->hip_d_pws_buf, kernel_power_max) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (run_metal_kernel_atinit (hashcat_ctx, device_param, device_param->metal_d_pws_buf, kernel_power_max) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (run_opencl_kernel_atinit (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, kernel_power_max) == -1) return -1;
    }

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (straight_ctx->kernel_rules_cnt > 1)
        {
          device_param->at_rc = -3;

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_rules_c, device_param->cuda_d_rules, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_rules_c, device_param->hip_d_rules, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_rules_c, 0, device_param->metal_d_rules, 0, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_rules, device_param->opencl_d_rules_c, 0, 0, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t), 0, NULL, NULL) == -1) return -1;
          }
        }
      }
    }

    // we also need to initialize some values using kernels

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      // nothing to do
    }
    else
    {
      const u32 kernel_threads_sav = device_param->kernel_threads;

      device_param->kernel_threads = device_param->kernel_wgs1;

      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, kernel_power_max, false, 0);

      if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
      {
        device_param->kernel_threads = device_param->kernel_wgs2p;

        run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, 0, kernel_power_max, false, 0);
      }

      device_param->kernel_threads = kernel_threads_sav;
    }

    // Do a pre-autotune test run to find out if kernel runtime is above some TDR limit

    u32 kernel_loops_max_reduced = kernel_loops_max;

    if (true)
    {
      double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min, kernel_threads);

      if (exec_msec > 2000)
      {
        event_log_error (hashcat_ctx, "Kernel minimum runtime larger than default TDR");

        device_param->at_rc = -4;

        return -1;
      }

      exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min, kernel_threads);

      const u32 mm = kernel_loops_max / kernel_loops_min;

      if ((exec_msec * mm) > target_msec)
      {
        const u32 loops_valid = (const u32) (target_msec / exec_msec);

        kernel_loops_max_reduced = kernel_loops_min * loops_valid;
      }
    }

    // first find out highest kernel-loops that stays below target_msec

    if (kernel_loops_min < kernel_loops_max)
    {
      for (kernel_loops = kernel_loops_max; kernel_loops > kernel_loops_min; kernel_loops >>= 1)
      {
        if (kernel_loops > kernel_loops_max_reduced) continue;

        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_min, kernel_loops, kernel_threads, 1);

        if (exec_msec < target_msec) break;
      }
    }

    #define STEPS_CNT 16

    // now the same for kernel-accel but with the new kernel-loops from previous loop set

    if (kernel_accel_min < kernel_accel_max)
    {
      for (int i = 0; i < STEPS_CNT; i++)
      {
        const u32 kernel_accel_try = 1U << i;

        if (kernel_accel_try < kernel_accel_min) continue;
        if (kernel_accel_try > kernel_accel_max) break;

        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_try, kernel_loops, kernel_threads, 1);

        if (exec_msec > target_msec) break;

        kernel_accel = kernel_accel_try;
      }
    }

    // now find the middle balance between kernel_accel and kernel_loops
    // while respecting allowed ranges at the same time

    if (kernel_accel < kernel_loops)
    {
      const u32 kernel_accel_orig = kernel_accel;
      const u32 kernel_loops_orig = kernel_loops;

      double exec_msec_prev = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 1);

      for (int i = 1; i < STEPS_CNT; i++)
      {
        const u32 kernel_accel_try = kernel_accel_orig * (1U << i);
        const u32 kernel_loops_try = kernel_loops_orig / (1U << i);

        if (kernel_accel_try < kernel_accel_min) continue;
        if (kernel_accel_try > kernel_accel_max) break;

        if (kernel_loops_try > kernel_loops_max) continue;
        if (kernel_loops_try < kernel_loops_min) break;

        // do a real test

        const double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_try, kernel_loops_try, kernel_threads, 1);

        if (exec_msec_prev < exec_msec) break;

        exec_msec_prev = exec_msec;

        // so far, so good! save

        kernel_accel = kernel_accel_try;
        kernel_loops = kernel_loops_try;

        // too much if the next test is true

        if (kernel_loops_try < kernel_accel_try) break;
      }
    }

    double exec_msec_pre_final = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 1);

    const u32 exec_left = (const u32) (target_msec / exec_msec_pre_final);

    const u32 accel_left = kernel_accel_max / kernel_accel;

    const u32 exec_accel_min = MIN (exec_left, accel_left); // we want that to be int

    if (exec_accel_min >= 1)
    {
      // this is safe to not overflow kernel_accel_max because of accel_left

      kernel_accel *= exec_accel_min;
    }

    // v6.2.4 new section: find thread count
    // This is not as effective as it could be because of inaccurate kernel return timers
    // But is better than fixed values
    // Timers in this section are critical, so we rerun meassurements 3 times

    if (kernel_threads_max > kernel_threads_min)
    {
      const u32 kernel_accel_orig   = kernel_accel;
      const u32 kernel_threads_orig = kernel_threads;

      double exec_msec_prev = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 3);

      for (int i = 1; i < STEPS_CNT; i++)
      {
        const u32 kernel_accel_try   = kernel_accel_orig   * (1U << i);
        const u32 kernel_threads_try = kernel_threads_orig / (1U << i);

        // since we do not modify total amount of workitems, we can (and need) to do increase kernel_accel_max

        const u32 kernel_accel_max_try = kernel_accel_max * (1U << i);

        if (kernel_accel_try > kernel_accel_max_try) break;

        if (kernel_threads_try < kernel_threads_min) break;

        if (kernel_threads_try % kernel_wgs_multiple) break; // this would just be waste of time

        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_try, kernel_loops, kernel_threads_try, 3);

        if (exec_msec > exec_msec_prev) continue;

        exec_msec_prev = exec_msec;

        kernel_accel   = kernel_accel_try;
        kernel_threads = kernel_threads_try;
      }
    }
  }

  // reset them fake words
  // reset other buffers in case autotune cracked something

  device_param->at_rc = -5;

  if (device_param->is_cuda == true)
  {
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, device_param->size_pws) == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_plain_bufs, device_param->size_plains) == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_digests_shown, device_param->size_shown) == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_result, device_param->size_results) == -1) return -1;
    if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tmps, device_param->size_tmps) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_buf, device_param->size_pws) == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_plain_bufs, device_param->size_plains) == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_digests_shown, device_param->size_shown) == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_result, device_param->size_results) == -1) return -1;
    if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tmps, device_param->size_tmps) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_buf, device_param->size_pws) == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_plain_bufs, device_param->size_plains) == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_digests_shown, device_param->size_shown) == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_result, device_param->size_results) == -1) return -1;
    if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_tmps, device_param->size_tmps) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, device_param->size_pws) == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_plain_bufs, device_param->size_plains) == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, device_param->size_shown) == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_result, device_param->size_results) == -1) return -1;
    if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tmps, device_param->size_tmps) == -1) return -1;

    device_param->at_rc = -6;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  // reset timer

  device_param->exec_pos = 0;

  memset (device_param->exec_msec,          0,          EXEC_CACHE * sizeof (double));
  memset (device_param->exec_us_prev1,      0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev2,      0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev3,      0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev4,      0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_init2, 0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_loop2, 0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_aux1,  0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_aux2,  0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_aux3,  0, EXPECTED_ITERATIONS * sizeof (double));
  memset (device_param->exec_us_prev_aux4,  0, EXPECTED_ITERATIONS * sizeof (double));

  // store

  device_param->kernel_accel   = kernel_accel;
  device_param->kernel_loops   = kernel_loops;
  device_param->kernel_threads = kernel_threads;

  const u32 hardware_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * device_param->kernel_threads;

  device_param->hardware_power = hardware_power;

  const u32 kernel_power = device_param->hardware_power * device_param->kernel_accel;

  device_param->kernel_power = kernel_power;

  return 0;
}

HC_API_CALL void *thread_autotune (void *p)
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return NULL;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped == true) return NULL;
  if (device_param->skipped_warning == true) return NULL;

  // init autotunes status and rc

  device_param->at_status = AT_STATUS_FAILED;
  device_param->at_rc = -1; // generic error

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1) return NULL;
  }

  // check for autotune failure

  if (autotune (hashcat_ctx, device_param) == 0)
  {
    device_param->at_status = AT_STATUS_PASSED;
    device_param->at_rc = 0;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return NULL;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1) return NULL;
  }

  return NULL;
}
