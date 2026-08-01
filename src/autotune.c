/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "backend.h"
#include "bridges.h"
#include "status.h"
#include "shared.h"
#include "autotune.h"

// How much longer a bridge is allowed to run per launch than a compute kernel is, per workload profile.
//
// TARGET_MSEC_PROFILE in backend.c is picked for a kernel on a GPU, where a short launch is what keeps a
// display drawing. A bridge that replaced the loop kernel never enters that queue, which is the same
// reason the TDR limit is waived for it further down in this file.
//
// It also pays far more for a short launch than a GPU does. A bridge unit that is wide internally runs
// a launch's candidates through its whole compute array and then drains it, so the waste is one
// array-fill per launch rather than a fixed overhead, and it grows as the launch gets shorter. On such
// a unit the 96 ms that -w 3 asks for has been measured costing five to eleven percent of throughput,
// against about 1.2 percent for a GPU running -m 1000.
//
// Scaling the whole ladder rather than moving one rung keeps -w meaning what it means: 1 and 2 stay the
// responsive settings, 3 stays the default that should sit near peak, 4 stays maximum throughput.

#define BRIDGE_TARGET_MSEC_SCALE 4

// How many of a wide unit's own waves a launch should hold, and how far past the time budget the
// floor may push to get them. See the measured curve where these are used.

#define BRIDGE_WAVES_MIN        32
#define BRIDGE_WAVES_MSEC_SCALE 16

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

  const u32 hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? 1
                           : ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE)     ? 1 : device_param->device_processors)
                           * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : kernel_threads);

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

  // the count a bridge advertises is a maximum it cannot be asked to exceed, so a probe has to
  // respect it the same way the production launch does. the accel is derived by rounding that
  // count up to a whole hardware_power step, so kernel_power_try lands above it whenever the two
  // are not multiples of each other. that is the case this trims.

  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)
  {
    bridge_ctx_t *bridge_ctx = hashcat_ctx->bridge_ctx;

    const u32 workitem_count = bridge_ctx->get_workitem_count (bridge_ctx->platform_context, device_param->bridge_link_device);

    if (kernel_power_try > workitem_count)
    {
      kernel_power_try = workitem_count;
    }
  }

  const u32 kernel_threads_sav = device_param->kernel_threads;

  device_param->kernel_threads = kernel_threads;

  const double spin_damp_sav = device_param->spin_damp;

  device_param->spin_damp = 0;

  // when a bridge replaced the loop kernel, that kernel is empty and timing it measures
  // nothing. time the bridge instead, which is the unit that actually does the work.

  if (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)
  {
    run_bridge_loop (hashcat_ctx, device_param, 0, kernel_power_try, 0, kernel_loops, true);
  }
  else
  {
    const u32 kern_run = find_tuning_function (hashcat_ctx, device_param);

    run_kernel (hashcat_ctx, device_param, kern_run, 0, kernel_power_try, true, 0, true);
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

// A wide bridge unit does not need its launch size searched for. Throughput is monotonic in waves per
// launch, and the cost of a launch has a known shape: one fill and drain of the whole array, plus the
// waves themselves. Two measurements pin that line down and the size follows from it.
//
// Searching is expensive here in a way it is not for a kernel, because every trial IS a real launch.
// On a slow salt that is seconds per trial, and the search ran a dozen of them before the first real
// candidate was ever tried.
//
// Sizing in TIME is also the wrong axis. The efficiency of a launch is about W/(W+1) for W waves, and
// holding a launch at a fixed number of milliseconds means W falls as the hash gets more iterations,
// so the launch collapses exactly where the hash is slowest. Measured against a 32 wave launch, and
// the same curve came out at two different iteration counts because it depends on waves and not on the
// hash:
//
//   2 waves 58 %   4 waves 76 %   8 waves 89 %   16 waves 96 %   32 waves 100 %
//
// So the target is a number of WAVES, and the time budget only caps how far the floor may stretch to
// reach it. Without that cap a high iteration count would produce a launch of tens of seconds, and the
// status line, an abort and --runtime all wait for one launch.

static u32 autotune_wide_accel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kernel_loops, const u32 kernel_threads, const u32 workitem_multiple, const u32 kernel_accel_min, const u32 kernel_accel_max, const double target_msec)
{
  const u32 accel_1 = MAX (kernel_accel_min, workitem_multiple);
  const u32 accel_2 = MIN (accel_1 * 2, kernel_accel_max);

  const double msec_1 = try_run_times (hashcat_ctx, device_param, accel_1, kernel_loops, kernel_threads, 1);

  const double waves_1 = (double) accel_1 / (double) workitem_multiple;

  double per_wave = msec_1 / waves_1;

  if (accel_2 > accel_1)
  {
    const double msec_2 = try_run_times (hashcat_ctx, device_param, accel_2, kernel_loops, kernel_threads, 1);

    const double waves_2 = (double) accel_2 / (double) workitem_multiple;

    const double slope = (msec_2 - msec_1) / (waves_2 - waves_1);

    if (slope > 0) per_wave = slope;
  }

  // whatever the line does not explain is the fill and drain, and it is paid once per launch

  const double fixed_msec = msec_1 - (per_wave * waves_1);

  const double waves_budget  = (target_msec - fixed_msec) / per_wave;
  const double waves_stretch = ((target_msec * BRIDGE_WAVES_MSEC_SCALE) - fixed_msec) / per_wave;

  double waves = MAX (waves_budget, MIN ((double) BRIDGE_WAVES_MIN, waves_stretch));

  if (waves < 1) waves = 1;

  u64 accel = (u64) (waves * (double) workitem_multiple);

  accel = MAX (accel, kernel_accel_min);
  accel = MIN (accel, kernel_accel_max);

  // a launch the device cannot use is not an answer, so snap to a whole wave

  accel = MAX ((accel / workitem_multiple) * workitem_multiple, kernel_accel_min);

  const u32 result = (u32) accel;

  return result;
}

static int autotune (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const hashes_t       *hashes       = hashcat_ctx->hashes;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  // see BRIDGE_TARGET_MSEC_SCALE above
  const double target_msec = (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)
                           ? backend_ctx->target_msec * BRIDGE_TARGET_MSEC_SCALE
                           : backend_ctx->target_msec;

  const bool is_bridge = bridge_active (hashcat_ctx, device_param->bridge_link_device);

  // Does one bridge unit have width inside it? An accelerator computes in waves and has to fill and
  // drain its array for every call, so chunking costs it real work. A unit that is one CPU thread
  // reports a multiple of 1 and pays almost nothing to be called more often, so the two want opposite
  // things from kernel_loops and are told apart here rather than lumped together as "a bridge".

  const u32 workitem_multiple = (is_bridge == true) ? bridge_workitem_multiple (hashcat_ctx, device_param->bridge_link_device) : 1;

  const bool wide_unit = (is_bridge == true) && (workitem_multiple > 1);

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
    device_param->hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? 1
                                 : ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE)     ? 1 : device_param->device_processors)
                                 * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : kernel_threads_min);
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

    const u32 hardware_power_max = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? 1
                                 : ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE)     ? 1 : device_param->device_processors)
                                 * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : kernel_threads_max);

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
            if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_rules_c, device_param->cuda_d_rules, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t)) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyDtoD (hashcat_ctx, device_param->hip_d_rules_c, device_param->hip_d_rules, MIN (kernel_loops_max, KERNEL_RULES) * sizeof (kernel_rule_t)) == -1) return -1;
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

      device_param->kernel_threads = MIN (device_param->kernel_wgs1, kernel_threads_max);

      run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, kernel_power_max, false, 0, true);

      if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
      {
        device_param->kernel_threads = MIN (device_param->kernel_wgs2p, kernel_threads_max);

        run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, 0, kernel_power_max, false, 0, true);
      }

      device_param->kernel_threads = kernel_threads_sav;
    }

    // Do a pre-autotune test run to find out if kernel runtime is above some TDR limit

    if (true)
    {
      const double exec_msec = try_run (hashcat_ctx, device_param, kernel_accel_min, kernel_loops_min, kernel_threads);

      // the TDR limit only applies when the timed unit is a compute kernel, because it is
      // the driver watchdog that reloads the driver when one runs too long. a bridge that
      // replaced the loop kernel never enters that queue, so the watchdog cannot fire and
      // a runtime above the limit is legitimate.

      const bool tdr_applies = (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP) ? false : true;

      if ((exec_msec > 2000) && (tdr_applies == true))
      {
        event_log_error (hashcat_ctx, "Kernel minimum runtime larger than default TDR");

        device_param->at_rc = -4;

        return -1;
      }
    }

    // v7 autotuner is a lot more straight forward
    // we start with some purely theoretical values as a base, then move on to some meassured tests

    /* This causes more problems than it solves.
     * In theory, it's fine to boost accel early to improve accuracy, and it does,
     * but on the other hand, it prevents increasing the thread count due to high runtime.
     * For longer runtimes, we want to prioritize more threads over higher accel.
     * This change also has some downsides for algorithms that actually benefit
     * from higher accel and fewer threads (e.g., 7800, 14900). But those are easy to manage
     * by limiting thread count, or better, by setting them to OPTS_TYPE_NATIVE_THREADS.

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (kernel_accel_min < kernel_accel_max)
      {
        // let's also do some minimal accel, this is only to improve early meassurements taken with try_run()

        const u32 kernel_accel_start = previous_power_of_two (kernel_accel_max / 8);

        if ((kernel_accel_start >= kernel_accel_min) && (kernel_accel_start <= kernel_accel_max))
        {
          kernel_accel = kernel_accel_start;
        }
      }
    }
    */

    if (kernel_threads_min < kernel_threads_max)
    {
      // there could be a situation, like in 18600, where we have a thread_min which is not a multiple of
      // kernel_preferred_wgs_multiple. As long as it's only a threads_min, but not a threads_max, we
      // should stick to at least kernel_preferred_wgs_multiple

      if (kernel_threads_min % device_param->kernel_preferred_wgs_multiple)
      {
        if ((device_param->kernel_preferred_wgs_multiple >= kernel_threads_min) && (device_param->kernel_preferred_wgs_multiple <= kernel_threads_max))
        {
          kernel_threads = device_param->kernel_preferred_wgs_multiple;
        }
      }
    }

    // A bridge is tuned by the SIZE OF THE LAUNCH, not by how finely the iteration space is cut.
    //
    // Chunking is not free for a bridge the way it is for a loop kernel. A unit that is wide
    // internally has to fill and drain its whole array for every call, so each extra chunk pays that
    // again, and a bridge that cannot resume a candidate part way through has to emulate chunking by
    // splitting the CANDIDATES instead. Once a chunk falls below the unit's own width the array is
    // running half empty, which is where the cost goes.
    //
    // The iteration space is therefore taken in one call and the launch is sized with kernel_accel,
    // which the accel search below already drives towards target_msec and which is floored at one
    // workitem multiple. Where that floor is reached the launch simply runs longer than the profile
    // asks for, because a unit cannot compute less than one wave.
    //
    // This was found on an accelerator bridge whose salt had a few hundred iterations. The loops
    // search settled on 2 of them, so the work was cut into 128 chunks and each one handed the unit
    // less than half of one wave. Taking the space in a single call instead measured three to five
    // times faster across the higher iteration counts, and restored the property that doubling the
    // iteration count should roughly halve the rate.

    if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
    {
      if ((hashes != NULL) && (hashes->salts_buf != NULL))
      {
        const u32 salt_iter = hashes->salts_buf->salt_iter; // we use the first salt as reference

        if (wide_unit == true)
        {
          if (salt_iter)
          {
            u32 start = MIN (kernel_loops_max, salt_iter);

            start = MAX (start, kernel_loops_min);

            kernel_loops = start;
          }
        }
        else
        {
          u32 start = kernel_loops_max;

          if (salt_iter)
          {
            start = MIN (start, smallest_repeat_double (salt_iter));
            start = MIN (start, smallest_repeat_double (salt_iter + 1));

            if (((salt_iter + 0) % 125) == 0) start = MIN (start, 125);
            if (((salt_iter + 1) % 125) == 0) start = MIN (start, 125);

            if ((start >= kernel_loops_min) && (start <= kernel_loops_max))
            {
              kernel_loops = start;
            }
          }
          else
          {
            // how can there be a slow hash with no iterations?
          }
        }
      }
    }
    else
    {
      // let's also do some minimal loops, this is only to improve early meassurements taken with try_run()

      const u32 kernel_loops_start = previous_power_of_two (kernel_loops_max / 4);

      if ((kernel_loops_start >= kernel_loops_min) && (kernel_loops_start <= kernel_loops_max))
      {
        kernel_loops = kernel_loops_start;
      }
    }

    // A wide unit is sized below from a model rather than by searching, so none of the trial launches
    // between here and the accel search buy it anything, and on a bridge every trial is a real launch.

    if (wide_unit == false)
    {
      // some algorithm start ways to high with these theoretical preset (for instance, 8700)
      // so much that they can't be tuned anymore

      while ((kernel_accel > kernel_accel_min) || (kernel_threads > kernel_threads_min) || (kernel_loops > kernel_loops_min))
      {
        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 2);

        if (exec_msec < target_msec / 16) break;

        if (kernel_accel > kernel_accel_min)
        {
          kernel_accel = MAX (kernel_accel / 2, kernel_accel_min);

          continue;
        }

        if (kernel_threads > kernel_threads_min)
        {
          kernel_threads = MAX (kernel_threads / 2, kernel_threads_min);

          continue;
        }

        // a wide unit's loops were set to the whole iteration space on purpose, see above. Halving it
        // here would put the chunking back, so accel is the only thing left for it to give.

        if (wide_unit == true) break;

        if (kernel_loops > kernel_loops_min)
        {
          kernel_loops = MAX (kernel_loops / 2, kernel_loops_min);

          continue;
        }

        break;
      }
    }

    // the search below hunts for the largest loop count that still fits the time budget. A wide unit
    // has already been given the whole iteration space, and going past it means asking for iterations
    // the salt does not have, so there is nothing left to search for.

    if (wide_unit == false)
    {
      for (u32 kernel_loops_test = kernel_loops; kernel_loops_test <= kernel_loops_max; kernel_loops_test <<= 1)
      {
        double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops_test, kernel_threads, 2);

        //printf ("loop %f %u %u %u\n", exec_msec, kernel_accel, kernel_loops_test, kernel_threads);
        if (exec_msec > target_msec) break;

        // we want a little room for threads to play with so not full target_msec
        // but of course only if we are going to make use of that :)

        if ((kernel_accel < kernel_accel_max) || (kernel_threads < kernel_threads_max))
        {
          if (exec_msec > target_msec / 8) break;

          // in general, an unparallelized kernel should not run that long.
          // if the kernel uses barriers it will have a bad impact on performance.
          // streebog is a good testing example
          //
          // a bridge is not a kernel. it does not queue behind one and it has no barriers, so the 4 ms
          // figure describes nothing about it. a bridge launch is tens to hundreds of milliseconds by
          // design, which is the same reason the TDR limit is waived for it above. left in place this
          // test ends the loops search at its first rung, whatever the workload profile asks for.

          if ((exec_msec > 4) && (is_bridge == false)) break;
        }

        kernel_loops = kernel_loops_test;
      }
    }

    if (wide_unit == false)
    {
    double exec_msec_init = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 2);

    float threads_eff_best = exec_msec_init / kernel_threads;
    u32   threads_cnt_best = kernel_threads;

    float threads_eff_prev = 0;
    u32   threads_cnt_prev = 0;

    for (u32 kernel_threads_test = kernel_threads; kernel_threads_test <= kernel_threads_max; kernel_threads_test = (kernel_threads_test < device_param->kernel_preferred_wgs_multiple) ? kernel_threads_test << 1 : kernel_threads_test + device_param->kernel_preferred_wgs_multiple)
    {
      double exec_msec = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads_test, 2);

      //printf ("thread %f %u %u %u\n", exec_msec, kernel_accel, kernel_loops, kernel_threads_test);
      if (exec_msec > target_msec) break;

      if (kernel_threads >= 32)
      {
        // we want a little room for accel to play with so not full target_msec

        if (exec_msec > target_msec / 4) break;
      }

      kernel_threads = kernel_threads_test;

      threads_eff_prev = exec_msec / kernel_threads_test;
      threads_cnt_prev = kernel_threads_test;

      //printf ("%f\n", threads_eff_prev);

      if (threads_eff_prev < threads_eff_best)
      {
        threads_eff_best = threads_eff_prev;
        threads_cnt_best = threads_cnt_prev;
      }
    }

    // now we decide to choose either maximum or in some extreme cases prefer more efficient ones
    if ((threads_eff_best * 1.06) < threads_eff_prev)
    {
      kernel_threads = threads_cnt_best;
    }
    }

    #define STEPS_CNT 12

    // now we tune for kernel-accel but with the new kernel-loops from previous loop set

    if (wide_unit == true)
    {
      kernel_accel = autotune_wide_accel (hashcat_ctx, device_param, kernel_loops, kernel_threads, workitem_multiple, kernel_accel_min, kernel_accel_max, target_msec);
    }
    else if (kernel_accel_min < kernel_accel_max)
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

    // overtune section. relevant if we have strange numbers from the APIs, namely 96, 384, and such
    // this is a dangerous action, and we set conditions somewhere in the code to disable this

    if ((wide_unit == true) || (kernel_accel_min == kernel_accel_max) || (kernel_threads_min == kernel_threads_max) || (device_param->overtune_unfriendly == true))
    {
    }
    else
    {
      if (kernel_accel > 64) kernel_accel -= kernel_accel % 32;

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
      {
        if (kernel_accel > device_param->device_processors) kernel_accel -= kernel_accel % device_param->device_processors;
      }

      u32 fun[2];

      if (is_power_of_2 (kernel_threads) == false)
      {
        fun[0] = previous_power_of_two (kernel_threads);
        fun[1] = next_power_of_two (kernel_threads);
      }
      else
      {
        fun[0] = kernel_threads >> 1;
        fun[1] = kernel_threads << 1;
      }

      float fact[2];

      fact[0] = (float) kernel_threads / fun[0];
      fact[1] = (float) kernel_threads / fun[1];

      float ms_prev = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 2);

      float res[2] = { 0 };

      for (int i = 0; i < 2; i++)
      {
        const u32 kernel_threads_test = fun[i];
        const u32 kernel_accel_test =  kernel_accel * fact[i];

        if (kernel_accel_test == 0) continue;
        if (kernel_threads_test == 0) continue;

        if (kernel_threads_test > device_param->device_maxworkgroup_size) continue;

        const float ms = try_run_times (hashcat_ctx, device_param, kernel_accel_test, kernel_loops, kernel_threads_test, 2);

        res[i] = ms_prev / ms;
      }

      const int sel = (res[0] > res[1]) ? 0 : 1;

      if (res[sel] > 1.01)
      {
        const u32 kernel_accel_new = kernel_accel * fact[sel];
        const u32 kernel_threads_new = fun[sel];

        if ((kernel_accel_new >= kernel_accel_min) && (kernel_accel_new <= kernel_accel_max))
        {
          // we can't check kernel_threads because that is for sure outside the range

          kernel_accel = kernel_accel_new;
          kernel_threads = kernel_threads_new;
        }
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

  const u32 hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? 1
                           : ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE)     ? 1 : device_param->device_processors)
                           * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : device_param->kernel_threads);

  device_param->hardware_power = hardware_power;

  const u32 kernel_power = device_param->hardware_power * device_param->kernel_accel;

  device_param->kernel_power = kernel_power;

  //printf ("Final: %d %d %d %d %d\n", kernel_accel, kernel_loops, kernel_threads, hardware_power, kernel_power);

  return 0;
}

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD thread_autotune (void *p)
#else
HC_API_CALL void *thread_autotune (void *p)
#endif
{
  thread_param_t *thread_param = (thread_param_t *) p;

  hashcat_ctx_t *hashcat_ctx = thread_param->hashcat_ctx;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *device_param = backend_ctx->devices_param + thread_param->tid;

  if (device_param->skipped == true) return 0;
  if (device_param->skipped_warning == true) return 0;

  // init autotunes status and rc

  device_param->at_status = AT_STATUS_FAILED;
  device_param->at_rc = -1; // generic error

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return 0;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return 0;
  }

  // check for autotune failure

  if (autotune (hashcat_ctx, device_param) == 0)
  {
    device_param->at_status = AT_STATUS_PASSED;
    device_param->at_rc = 0;
  }

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return 0;
  }

  return 0;
}

