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

int find_tuning_function (hashcat_ctx_t *hashcat_ctx, MAYBE_UNUSED hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      return KERN_RUN_1;
    }
    else
    {
      return KERN_RUN_4;
    }
  }
  else
  {
    return KERN_RUN_2;
  }

  return -1;
}

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

  const u32 kern_run = find_tuning_function (hashcat_ctx, device_param);

  run_kernel (hashcat_ctx, device_param, kern_run, 0, kernel_power_try, true, 0, true);

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

/*
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
*/

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

  /*
  printf ("starting autotune with: %d %d %d %d %d %d\n",
  kernel_accel_min,
  kernel_accel_max,
  kernel_loops_min,
  kernel_loops_max,
  kernel_threads_min,
  kernel_threads_max);
  */

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
  u32 kernel_threads = kernel_threads_min;

  // for the threads we take as initial value what we receive from the runtime
  // but is only to start with something, we will fine tune this value as soon as we have our workload specified
  // this thread limiting is also performed inside run_kernel() so we need to redo it here, too

  /*
  u32 kernel_wgs = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      kernel_wgs = device_param->kernel_wgs1;
    }
    else
    {
      kernel_wgs = device_param->kernel_wgs4;
    }
  }
  else
  {
    kernel_wgs = device_param->kernel_wgs2;
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
  */

  // in this case the user specified a fixed -n and -u on the commandline
  // no way to tune anything
  // but we need to run a few caching rounds

  if ((kernel_threads_min == kernel_threads_max) && (kernel_accel_min == kernel_accel_max) && (kernel_loops_min == kernel_loops_max))
  {
    #if defined (DEBUG)

    // don't do any autotune in debug mode in this case
    // we're probably during kernel development

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

      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, kernel_power_max, false, 0, true);

      if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
      {
        device_param->kernel_threads = device_param->kernel_wgs2p;

        run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, 0, kernel_power_max, false, 0, true);
      }

      device_param->kernel_threads = kernel_threads_sav;
    }

    // Do a pre-autotune test run to find out if kernel runtime is above some TDR limit

    if (true)
    {
      double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min, kernel_threads);

      if (exec_msec > 2000)
      {
        event_log_error (hashcat_ctx, "Kernel minimum runtime larger than default TDR");

        device_param->at_rc = -4;

        return -1;
      }
    }

    // v7 autotuner is a lot more straight forward

    for (u32 kernel_loops_test = kernel_loops_min; kernel_loops_test <= kernel_loops_max; kernel_loops_test <<= 1)
    {
      double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_test, kernel_threads_min, 2);

      //printf ("loop %f %u %u %u\n", exec_msec, kernel_accel_min, kernel_loops_test, kernel_threads_min);
      if (exec_msec > target_msec) break;

      if (kernel_loops >= 32)
      {
        // we want a little room for threads to play with so not full target_msec

        if (exec_msec > target_msec / 8) break;
      }

      kernel_loops = kernel_loops_test;
    }

    for (u32 kernel_threads_test = kernel_threads_min; kernel_threads_test <= kernel_threads_max; kernel_threads_test <<= 1)
    {
      double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_min, kernel_loops, kernel_threads_test, 2);

      //printf ("threads %f %u %u %u\n", exec_msec, kernel_accel_min, kernel_loops, kernel_threads_test);
      if (exec_msec > target_msec) break;

      if (kernel_threads >= 32)
      {
        // we want a little room for accel to play with so not full target_msec

        if (exec_msec > target_msec / 8) break;
      }

      kernel_threads = kernel_threads_test;
    }

    #define STEPS_CNT 12

    // now we tune for kernel-accel but with the new kernel-loops from previous loop set

    if (kernel_accel_min < kernel_accel_max)
    {
      for (int i = 0; i < STEPS_CNT; i++)
      {
        const u32 kernel_accel_try = kernel_accel;

        if (kernel_accel_try < kernel_accel_min) continue;
        if (kernel_accel_try > kernel_accel_max) break;

        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel_try, kernel_loops, kernel_threads, 2);

        //printf ("accel %f %u %u %u\n", exec_msec, kernel_accel_try, kernel_loops, kernel_threads);
        if (exec_msec > target_msec) break;

        float multi = target_msec / exec_msec;

        // we cap that multiplier, because on low accel numbers we do not run into spilling
        multi = (multi > 4) ? 4 : multi;

        kernel_accel = (float) kernel_accel_try * multi;

        if (kernel_accel == kernel_accel_try) break; // too close
      }

      if (kernel_accel > kernel_accel_max) kernel_accel = kernel_accel_max;
    }

    if (kernel_accel > 64) kernel_accel -= kernel_accel % 32;
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

  //printf ("Final: %d %d %d %d %d\n", kernel_accel, kernel_loops, kernel_threads, hardware_power, kernel_power);

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
