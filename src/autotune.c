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

static double try_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kernel_accel, const u32 kernel_loops)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = kernel_loops; // not a bug, both need to be set
  device_param->kernel_params_buf32[30] = kernel_loops; // because there's two variables for inner iters for slow and fast hashes

  const u32 kernel_power_try = device_param->hardware_power * kernel_accel;

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, kernel_power_try, true, 0);
    }
    else
    {
      run_kernel (hashcat_ctx, device_param, KERN_RUN_4, kernel_power_try, true, 0);
    }
  }
  else
  {
    run_kernel (hashcat_ctx, device_param, KERN_RUN_2, kernel_power_try, true, 0);
  }

  device_param->spin_damp = spin_damp_sav;

  const double exec_msec_prev = get_avg_exec_time (device_param, 1);

  return exec_msec_prev;
}

/*
static double try_run_preferred (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kernel_accel, const u32 kernel_loops)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = kernel_loops; // not a bug, both need to be set
  device_param->kernel_params_buf32[30] = kernel_loops; // because there's two variables for inner iters for slow and fast hashes

  const u32 kernel_power_try = device_param->hardware_power * kernel_accel;

  const u32 kernel_threads_sav = device_param->kernel_threads;

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      device_param->kernel_threads = device_param->kernel_preferred_wgs_multiple1;

      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, kernel_power_try, true, 0);
    }
    else
    {
      device_param->kernel_threads = device_param->kernel_preferred_wgs_multiple4;

      run_kernel (hashcat_ctx, device_param, KERN_RUN_4, kernel_power_try, true, 0);
    }
  }
  else
  {
    device_param->kernel_threads = device_param->kernel_preferred_wgs_multiple2;

    run_kernel (hashcat_ctx, device_param, KERN_RUN_2, kernel_power_try, true, 0);
  }

  device_param->kernel_threads = kernel_threads_sav;

  device_param->spin_damp = spin_damp_sav;

  const double exec_msec_prev = get_avg_exec_time (device_param, 1);

  return exec_msec_prev;
}
*/

static int autotune (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const hashconfig_t    *hashconfig   = hashcat_ctx->hashconfig;
  const backend_ctx_t   *backend_ctx  = hashcat_ctx->backend_ctx;
  const straight_ctx_t  *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t  *user_options = hashcat_ctx->user_options;

  const double target_msec = backend_ctx->target_msec;

  const u32 kernel_accel_min = device_param->kernel_accel_min;
  const u32 kernel_accel_max = device_param->kernel_accel_max;

  const u32 kernel_loops_min = device_param->kernel_loops_min;
  const u32 kernel_loops_max = device_param->kernel_loops_max;

  u32 kernel_accel = kernel_accel_min;
  u32 kernel_loops = kernel_loops_min;

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
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);
      try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);
    }

    #endif

    device_param->kernel_accel = kernel_accel;
    device_param->kernel_loops = kernel_loops;

    const u32 kernel_power = device_param->hardware_power * device_param->kernel_accel;

    device_param->kernel_power = kernel_power;

    return 0;
  }

  // from here it's clear we are allowed to autotune
  // so let's init some fake words

  const u32 kernel_power_max = device_param->hardware_power * kernel_accel_max;

  int CL_rc;
  int CU_rc;

  if (device_param->is_cuda == true)
  {
    CU_rc = run_cuda_kernel_atinit (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, kernel_power_max);

    if (CU_rc == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    CL_rc = run_opencl_kernel_atinit (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, kernel_power_max);

    if (CL_rc == -1) return -1;
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
        if (device_param->is_cuda == true)
        {
          CU_rc = hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_rules_c, device_param->cuda_d_rules, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t));

          if (CU_rc == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_rules, device_param->opencl_d_rules_c, 0, 0, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t), 0, NULL, NULL);

          if (CL_rc == -1) return -1;
        }
      }
    }
  }

  // Do a pre-autotune test run to find out if kernel runtime is above some TDR limit

  u32 kernel_loops_max_reduced = kernel_loops_max;

  if (1)
  {
    double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min);

    if (exec_msec > 2000)
    {
      event_log_error (hashcat_ctx, "Kernel minimum runtime larger than default TDR");

      return -1;
    }

    exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min);

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

      double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops);

      if (exec_msec < target_msec) break;
    }
  }

  // now the same for kernel-accel but with the new kernel-loops from previous loop set

  #define STEPS_CNT 16

  if (kernel_accel_min < kernel_accel_max)
  {
    for (int i = 0; i < STEPS_CNT; i++)
    {
      const u32 kernel_accel_try = 1U << i;

      if (kernel_accel_try < kernel_accel_min) continue;
      if (kernel_accel_try > kernel_accel_max) break;

      double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_try, kernel_loops);

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

    double exec_msec_prev = try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);

    for (int i = 1; i < STEPS_CNT; i++)
    {
      const u32 kernel_accel_try = kernel_accel_orig * (1U << i);
      const u32 kernel_loops_try = kernel_loops_orig / (1U << i);

      if (kernel_accel_try < kernel_accel_min) continue;
      if (kernel_accel_try > kernel_accel_max) break;

      if (kernel_loops_try > kernel_loops_max) continue;
      if (kernel_loops_try < kernel_loops_min) break;

      // do a real test

      const double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_try, kernel_loops_try);

      if (exec_msec_prev < exec_msec) break;

      exec_msec_prev = exec_msec;

      // so far, so good! save

      kernel_accel = kernel_accel_try;
      kernel_loops = kernel_loops_try;

      // too much if the next test is true

      if (kernel_loops_try < kernel_accel_try) break;
    }
  }

  double exec_msec_pre_final = try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);

  const u32 exec_left = (const u32) (target_msec / exec_msec_pre_final);

  const u32 accel_left = kernel_accel_max / kernel_accel;

  const u32 exec_accel_min = MIN (exec_left, accel_left); // we want that to be int

  if (exec_accel_min >= 1)
  {
    // this is safe to not overflow kernel_accel_max because of accel_left

    kernel_accel *= exec_accel_min;
  }

  // start finding best thread count is easier.
  // it's either the preferred or the maximum thread count

  /*
  const u32 kernel_threads_min = device_param->kernel_threads_min;
  const u32 kernel_threads_max = device_param->kernel_threads_max;

  if (kernel_threads_min < kernel_threads_max)
  {
    const double exec_msec_max = try_run (hashcat_ctx, device_param, kernel_accel, kernel_loops);

    u32 preferred_threads = 0;

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        preferred_threads = device_param->kernel_preferred_wgs_multiple1;
      }
      else
      {
        preferred_threads = device_param->kernel_preferred_wgs_multiple4;
      }
    }
    else
    {
      preferred_threads = device_param->kernel_preferred_wgs_multiple2;
    }

    if ((preferred_threads >= kernel_threads_min) && (preferred_threads <= kernel_threads_max))
    {
      const double exec_msec_preferred = try_run_preferred (hashcat_ctx, device_param, kernel_accel, kernel_loops);

      if (exec_msec_preferred < exec_msec_max)
      {
        device_param->kernel_threads = preferred_threads;
      }
    }
  }
  */

  if (device_param->is_cuda == true)
  {
    // reset them fake words

    CU_rc = run_cuda_kernel_memset (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, 0, device_param->size_pws);

    if (CU_rc == -1) return -1;

    // reset other buffers in case autotune cracked something

    CU_rc = run_cuda_kernel_memset (hashcat_ctx, device_param, device_param->cuda_d_plain_bufs, 0, device_param->size_plains);

    if (CU_rc == -1) return -1;

    CU_rc = run_cuda_kernel_memset (hashcat_ctx, device_param, device_param->cuda_d_digests_shown, 0, device_param->size_shown);

    if (CU_rc == -1) return -1;

    CU_rc = run_cuda_kernel_memset (hashcat_ctx, device_param, device_param->cuda_d_result, 0, device_param->size_results);

    if (CU_rc == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    // reset them fake words

    CL_rc = run_opencl_kernel_memset (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, 0, device_param->size_pws);

    if (CL_rc == -1) return -1;

    // reset other buffers in case autotune cracked something

    CL_rc = run_opencl_kernel_memset (hashcat_ctx, device_param, device_param->opencl_d_plain_bufs, 0, device_param->size_plains);

    if (CL_rc == -1) return -1;

    CL_rc = run_opencl_kernel_memset (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, 0, device_param->size_shown);

    if (CL_rc == -1) return -1;

    CL_rc = run_opencl_kernel_memset (hashcat_ctx, device_param, device_param->opencl_d_result, 0, device_param->size_results);

    if (CL_rc == -1) return -1;
  }

  // reset timer

  device_param->exec_pos = 0;

  memset (device_param->exec_msec, 0, EXEC_CACHE * sizeof (double));

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

  device_param->kernel_accel = kernel_accel;
  device_param->kernel_loops = kernel_loops;

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

  if (device_param->is_cuda == true)
  {
    const int rc_cuCtxSetCurrent = hc_cuCtxSetCurrent (hashcat_ctx, device_param->cuda_context);

    if (rc_cuCtxSetCurrent == -1) return NULL;
  }

  const int rc_autotune = autotune (hashcat_ctx, device_param);

  if (rc_autotune == -1)
  {
    // we should do something here, tell hashcat main that autotune failed to abort
  }

  return NULL;
}
