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

  const u32 hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? bridge_workitem_multiple (hashcat_ctx, device_param->bridge_link_device)
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

    const u32 workitem_count = bridge_ctx->get_workitem_count (hashcat_ctx, bridge_ctx->platform_context, device_param->bridge_link_device);

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

// The workgroup size, taken from what the runtime already knows and without launching anything.
//
// kernel_wgs is the register limit the runtime has already resolved for this kernel, so register
// pressure is accounted for without asking for a register count, which OpenCL cannot portably
// answer. Where a kernel uses local memory, that caps how many groups a compute unit holds at once.
//
// The size is rounded down to a whole wave, and no further.
//
// Rounding to a whole group of SIMD units as well was tried, because on an RX 7900 XTX running -m 0
// every multiple of 4 waves lands within 0.8 percent of the best result while 192, 320 and 448
// threads lose 6 to 10 percent. That plateau is real, but it never reaches this function. Over 375
// modes on seven devices spanning CUDA, HIP, Metal, OpenCL and a CPU, the extra rounding did not
// change one answer: the caps kernel_wgs hands out are either already whole multiples of 4 waves, or
// small enough that rounding to them leaves nothing and the wave rounding below is what runs anyway.
//
// Not asking for the SIMD count is worth more than the rounding would have been. Only AMD's OpenCL
// runtime reports it, as CL_DEVICE_SIMD_PER_COMPUTE_UNIT_AMD. CUDA has no attribute for it and
// NVIDIA's own answer is a compute capability table inside cuda_occupancy.h. HIP has none either,
// and reaching the value through HSA gives a per-CU count that reads 2 on RDNA where OpenCL reads 4.
// Metal does not expose it at all. A constant that changes nothing is not worth that.

// The largest workgroup the runtime will accept, rounded down to a whole wave. This is where the
// search starts, not where it ends. Taking it as the answer costs 11 to 14 percent on an Arc A770,
// where a kernel compiled to SIMD8 puts 128 hardware threads in a 1024 wide group and fills a whole
// Xe core with one group.

static u32 autotune2_threads_max (const hc_device_param_t *device_param, const u32 kernel_threads_min, const u32 kernel_threads_max)
{
  const u32 wave = (device_param->kernel_preferred_wgs_multiple > 0) ? device_param->kernel_preferred_wgs_multiple : 32;

  u32 cap = kernel_threads_max;

  if (device_param->device_maxworkgroup_size > 0) cap = MIN (cap, (u32) device_param->device_maxworkgroup_size);

  u32 threads = cap - (cap % wave);

  if (threads < kernel_threads_min) threads = kernel_threads_min;
  if (threads > kernel_threads_max) threads = kernel_threads_max;
  if (threads < 1) threads = 1;

  return threads;
}

// How close two thread counts have to be before the smaller one is not worth another launch.

#define AUTOTUNE2_THREADS_TIE 0.02

// The most candidates the walk will pay for.

#define AUTOTUNE2_THREADS_STEPS 5

// Measure the workgroup size rather than compute it.
//
// Nothing a runtime reports predicts this. On an A770 the maximum is 11 to 14 percent slower than
// half of it on some kernels and identical on others, and the kernels cannot be told apart by
// CL_KERNEL_WORK_GROUP_SIZE, local memory, spill size, or the preferred multiple. Measured across
// four devices the axis is worth nothing on an RX 7900 XTX, worth 19 percent once on an RTX 4090,
// and worth 11 to 14 percent repeatedly on an Arc. So it is searched, not derived.
//
// The walk holds kernel_power constant, halving threads and doubling accel, so every candidate does
// the same work and only the shape of the launch changes. Comparing at a fixed accel instead would
// shrink the launch as threads fall and measure saturation rather than the workgroup size, which is
// the mistake that made an early experiment of ours read 42 times below the real operating point.
//
// Candidates are walked downward from the ceiling and the walk stops as soon as two in a row agree,
// because past the point where a device stops caring, every smaller size ties.

static u32 autotune2_threads_walk (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 threads_hi, const u32 kernel_threads_min, const u32 accel_hi, const u32 accel_min, const u32 accel_max, const u32 loops)
{
  const u32 wave = (device_param->kernel_preferred_wgs_multiple > 0) ? device_param->kernel_preferred_wgs_multiple : 32;

  const u32 threads_lo = MAX (kernel_threads_min, wave);

  if (threads_hi <= threads_lo) return threads_hi;

  const u64 work_unit = (u64) threads_hi * (u64) accel_hi;

  double best_rate = 0;
  u32    best_threads = threads_hi;

  u32 ties = 0;

  u32 threads = threads_hi;

  for (u32 step = 0; step < AUTOTUNE2_THREADS_STEPS; step++)
  {
    u64 accel64 = work_unit / (u64) threads;

    if (accel64 < (u64) accel_min) accel64 = accel_min;
    if (accel64 > (u64) accel_max) accel64 = accel_max;

    const u32 accel = (u32) accel64;

    const double msec = try_run_times (hashcat_ctx, device_param, accel, loops, threads, 2);

    if (msec > 0)
    {
      // Candidates per millisecond, not milliseconds per thread. The clamp above can leave two
      // candidates carrying different amounts of work, and only a rate compares those honestly.

      const double rate = ((double) threads * (double) accel) / msec;

      if (rate > (best_rate * (1.0 + AUTOTUNE2_THREADS_TIE)))
      {
        best_rate    = rate;
        best_threads = threads;

        ties = 0;
      }
      else
      {
        if (rate > best_rate) best_rate = rate;

        ties++;

        if (ties >= 2) break;
      }
    }

    u32 next = threads / 2;

    next = next - (next % wave);

    if (next < threads_lo) break;
    if (next == threads) break;

    threads = next;
  }

  // Halving can only land on threads_hi / 2^n and the answer is not always there. The stock tuner
  // picks 896 threads for -m 1000 on an RTX 4090, which is 28 waves and no power of two, because
  // its ladder steps by a wave rather than by halving. Two bisections between the winner and the
  // candidate above it reach exactly that, for two more launches.

  u32 lo = best_threads;
  u32 hi = (best_threads <= (threads_hi / 2)) ? best_threads * 2 : threads_hi;

  for (u32 refine = 0; refine < 2; refine++)
  {
    if (hi <= lo) break;

    u32 mid = lo + ((hi - lo) / 2);

    mid = mid - (mid % wave);

    if (mid <= lo) break;
    if (mid >= hi) break;

    u64 accel64 = work_unit / (u64) mid;

    if (accel64 < (u64) accel_min) accel64 = accel_min;
    if (accel64 > (u64) accel_max) accel64 = accel_max;

    const u32 accel = (u32) accel64;

    const double msec = try_run_times (hashcat_ctx, device_param, accel, loops, mid, 2);

    if (msec <= 0) break;

    const double rate = ((double) mid * (double) accel) / msec;

    if (rate > best_rate)
    {
      best_rate    = rate;
      best_threads = mid;

      lo = mid;
    }
    else
    {
      hi = mid;
    }
  }

  return best_threads;
}

// Fit the launch to the target time instead of walking towards it.
//
//   msec = accel * (F + loops * P)
//
// P is what one loop iteration costs for one unit of accel, F what a unit of accel costs whatever
// the loop count. Two runs at one accel and two loop counts give both. The two are not
// interchangeable: an iteration is cheaper than the same work added through accel, because the loop
// kernel loads its state once and iterates, where accel pays that load again for every work item.
// Measured, an iteration is 2.2 times cheaper on -m 1800 and 9.4 times on -m 0. So loops are taken
// as high as the target allows and accel is given what is left.

// Fit the launch to the time budget, then choose how to spend it.
//
//   msec = accel * (F + loops * P)
//
// P is what one loop iteration costs for one unit of accel, F what a unit of accel costs whatever
// the loop count. Two runs at one accel and two loop counts give both, and from them any accel can
// be paired with the loop count that lands on the budget.
//
// Which pairing is best is not something the line can answer. Throughput under the line works out
// proportional to loops / (F + loops * P), which always rises with loops, so the line says take
// loops as high as they go. Measured on -m 1800 that is wrong by 9 percent: at a fixed 9.4 ms,
// accel 1 with loops 286 reaches 422 kH/s where accel 5 with loops 62 reaches 461. Below a few
// workgroups per compute unit nothing overlaps a group's tail, and the cost per unit of work is
// higher than the line assumes. Where that turns over is a property of the kernel, not the device:
// -m 0 on the same card has not turned over by accel 128.
//
// So the candidates are built by arithmetic and a few of them are measured. All of them cost the
// same time by construction, so the comparison is fair, and the lowest accel within a small margin
// of the best is taken. Fewer candidates in flight means less work thrown away when a slow hash
// finishes, and it costs nothing when the margin is respected.

#define AUTOTUNE2_MARGIN 0.98

// Greed is how much of a gain a bigger launch has to show before the tuner takes it. Below 1 it keeps
// the smaller launch unless the bigger one clearly wins, and that is what makes the batch short. At 1
// it takes every gain there is and the batch grows to whatever the budget allows.
//
// Greed rides -w because -w already means responsiveness against throughput, and hashcat already
// documents it that way. The two lower profiles stay frugal, so an interactive run and a distributed
// agent both get the short batch. The two upper profiles chase the last percent, so a dedicated rig
// gives up nothing, and benchmark figures stay comparable across the change because --benchmark
// forces profile 3.

static const double AUTOTUNE2_GREED[4] = { AUTOTUNE2_MARGIN, AUTOTUNE2_MARGIN, 1.00, 1.00 };

// How long a calibration probe has to run before its result is a measurement rather than timer noise.
// The launches that defeated the fit came back at 0.002 ms to 0.34 ms, and two of them were identical
// to the last digit, so anything below about a millisecond carries no slope worth fitting.

#define AUTOTUNE2_PROBE_MSEC 1.0

// What one launch costs outside the kernel try_run times.
//
// try_run times a single kernel: the loop kernel for a slow hash, and the one kernel a fast hash
// computes inside. A real launch also runs init and comp once for the whole set of candidates, and
// that cost is spread over accel * hardware_power of them. It is the reason a low accel is slower
// than the loop kernel timings alone suggest, and the reason the search finds a knee it cannot
// explain. A fast hash has no separate init and comp, so this is zero there and the knee is absent,
// which is what -m 0 measures.

static double autotune2_fixed_msec (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 accel, const u32 threads)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) return 0;

  const u32 threads_sav = device_param->kernel_threads;

  const u32 kernel_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors)
                         * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : threads) * accel;

  device_param->kernel_threads = threads;

  double msec = 0;

  run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 0, kernel_power, true, 0, true);

  msec += get_avg_exec_time (device_param, 1);

  run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 0, kernel_power, true, 0, true);

  msec += get_avg_exec_time (device_param, 1);

  device_param->kernel_threads = threads_sav;

  return msec;
}

// Cut the iterations into equal chunks where that is free.
//
// The loop count is a chunk size: the iterations are cut into ceil(W / loops) launches, and any
// launch that is short still pays a full load and save of the tmps. A chunk size that divides W
// exactly avoids the short one, and it is worth taking only when it does not buy that with an extra
// launch. Snapping down to the nearest divisor without that check is a loss, not a gain: on 5000
// iterations a budget of 971 needs 6 launches, and the nearest divisor of 625 needs 8.
//
// The divisors that matter are the odd part of W times a power of two. W a power of two gives an
// odd part of 1, so every power-of-two chunk already divides it. The crypt family, where W is 1000
// or 5000, gives 125, and chunking on 125, 250, 500 or 1000 keeps every launch the same length
// where a power of two leaves a ragged tail.
//
// Among the divisors that keep the launch count, the smallest is taken. All of them cost the same
// number of launches, and the shortest one holds the device for the least time per launch.

static u32 autotune2_align_loops (const u32 loops, const u32 work, const u32 loops_min)
{
  if (work == 0) return loops;
  if (loops == 0) return loops;

  const u32 launches = (work + loops - 1) / loops;

  if (launches == 0) return loops;

  // the shortest chunk that still fits in the same number of launches

  const u32 floor_loops = (work + launches - 1) / launches;

  const u32 odd = smallest_repeat_double (work);

  for (u32 c = odd; c <= loops; c *= 2)
  {
    if (c < loops_min) continue;
    if (c < floor_loops) continue;
    if ((work % c) != 0) continue;

    return c;
  }

  return loops;
}

// Put the second loop's input into the state an attack leaves it in.
//
// backend.c runs INIT2 once after the first loop finishes and before the second one starts, and
// LOOP2 reads what INIT2 wrote. Autotune has never run INIT2, so timing LOOP2 without it would
// measure a kernel reading whatever the first loop happened to leave in tmps. That is the same
// reason the pws buffer is filled with varying lengths before any of this begins: a probe has to
// run on the data the real launch sees, or it is not measuring the launch.

static void autotune2_run_init2 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 accel, const u32 threads)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  if ((hashconfig->opts_type & OPTS_TYPE_INIT2) == 0) return;

  const u32 threads_sav = device_param->kernel_threads;

  const u32 kernel_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors)
                         * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : threads) * accel;

  device_param->kernel_threads = threads;

  run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, 0, kernel_power, false, 0, true);

  if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
  {
    run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2P, 0, kernel_power, false, 0, true);
  }

  device_param->kernel_threads = threads_sav;
}

// Time one launch of the second loop. Same shape as try_run, but naming the kernel rather than
// asking find_tuning_function, which only ever answers with the first loop.

static double autotune2_loop2_msec (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 accel, const u32 loops, const u32 threads)
{
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  device_param->kernel_param.loop_pos = 0;
  device_param->kernel_param.loop_cnt = loops;
  device_param->kernel_param.il_cnt   = loops;

  const u32 kernel_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors)
                         * ((hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) ? 1 : threads) * accel;

  const u32    threads_sav   = device_param->kernel_threads;
  const double spin_damp_sav = device_param->spin_damp;

  device_param->kernel_threads = threads;
  device_param->spin_damp      = 0;

  run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, 0, kernel_power, true, 0, true);

  device_param->spin_damp      = spin_damp_sav;
  device_param->kernel_threads = threads_sav;

  const double msec = get_avg_exec_time (device_param, 1);

  return msec;
}

// Choose accel and loops from a model rather than by walking towards the answer.
//
//   msec_loop  = A + accel * (F + loops * P)
//   throughput = accel / (I + (W / loops) * msec_loop)
//
// F and P come from two runs of the loop kernel at one accel and two loop counts. W is how many
// iterations one candidate needs, which the hash states. I is measured above. Everything after that
// is arithmetic, so the split is chosen without launching anything more.
//
// Fitted against nine configurations of -m 1800 that all cost the same time, the expression is
// within 0.4 percent through accel 5 and drifts to 6 percent by accel 16, so it is trusted where
// the frugal answers live and the margin below keeps it away from the far end.

static void autotune2_solve (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 accel_min, const u32 accel_max, const u32 loops_min, const u32 loops_max, const u32 threads, const double target_msec, u32 *out_accel, u32 *out_loops)
{
  const hashes_t     *hashes     = hashcat_ctx->hashes;
  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const bool verbose = (getenv ("HASHCAT_AUTOTUNE2_VERBOSE") != NULL);

  *out_accel = accel_min;
  *out_loops = loops_min;

  if ((accel_min == accel_max) && (loops_min == loops_max)) return;

  // Cost of one launch, as three numbers rather than two.
  //
  //   msec = A + accel * (F + loops * P)
  //
  // P is what one loop iteration costs a unit of accel and F what a unit of accel costs whatever the
  // loop count, and those two were all the model used to carry. A is the part that does not shrink
  // when accel does: a launch too small to fill the device pays for the fill whatever it carries.
  //
  // Leaving A out is not a small error, it is the one that decided the answer. Without it the cost is
  // a line through the origin, so throughput works out as accel / (I + c * accel), which flattens as
  // soon as c * accel passes I. Every accel then scores the same to within the margin below, the
  // margin hands the tie to the smallest, and a starved launch is reported as the best one. Measured
  // on m33400 that is 14397 H/s read as 278.
  //
  // Three points give all three numbers. Two loop counts at one accel give P, and a second accel at
  // the lower loop count gives F and A. The low point has to be genuinely low: fitted from accel 4
  // and accel 16, both already wide enough to fill the card, A came back as 0.348 ms when the real
  // penalty was far larger. So the low point is accel_min and the high one is four times it.

  const u32 a_lo = accel_min;

  u32 a_cal = MIN (MAX (a_lo * 4, 4), accel_max);

  // How long a probe has to run before it is a measurement. The floor is what a timer can resolve at
  // all, but the scale that decides whether a fit is useful is the budget it is fitted against: one
  // millisecond carries a slope on a CPU, while against a 96 ms target it reads a corner of the curve
  // that the answer never visits, and the loop cost fitted there comes out too low to hold the launch
  // inside the budget.

  const double probe_msec = MAX (AUTOTUNE2_PROBE_MSEC, target_msec / 16.0);

  u32 l_cal = loops_min * 8;

  if (l_cal > loops_max) l_cal = loops_max;

  // Both loop counts are measured at the calibration accel, and the accel axis is then measured at
  // the HIGHER of the two. Sampling the accel axis at loops_min instead reads nothing: at the lowest
  // loop count the kernel barely runs and the launch is all overhead, so accel 1 and accel 4 came back
  // 0.052 ms and 0.054 ms apart on m33400, which is noise and not a slope. Fitted from those the
  // intercept is meaningless and the loop cost comes out negative. At the higher loop count the kernel
  // is doing the work it will do in the attack, and the two accels separate properly.
  //
  // Eight times loops_min is not always that point. A mode whose loops_min is 1 calibrates at 8 loops
  // while its answer runs at 999 or more, and there the two accels land inside the timer's resolution:
  // 0.207 ms against 0.207 ms on m14800, 0.331 against 0.342 on m33400, 0.002 against 0.004 on a CPU
  // device. Every one of those fits the per-accel cost negative, which throws the intercept away and
  // leaves the origin form that scores every accel alike, so the margin returns accel_min and the
  // launch is starved. So climb the calibration loop count until the probe is long enough to carry a
  // slope, stopping at loops_max or once the probe is already worth a launch of its own.

  double t_cal = try_run_times (hashcat_ctx, device_param, a_cal, l_cal, threads, 2);

  while ((t_cal < probe_msec) && (l_cal < loops_max) && (t_cal < target_msec))
  {
    l_cal = MIN (l_cal * 4, loops_max);

    t_cal = try_run_times (hashcat_ctx, device_param, a_cal, l_cal, threads, 2);
  }

  // The accel axis needs the same treatment and for the same reason. Four units of accel does not
  // load a large GPU: m33400 on an RTX 2080 Ti reads 1.323 ms at accel 1 against 1.339 ms at accel 4,
  // because neither launch has filled the card, while the accel that mode actually wants is in the
  // hundreds. A slope fitted across two points that both sit in the latency bound region is noise, so
  // climb the high point until the two separate by something a timer can see.

  double t_acc = try_run_times (hashcat_ctx, device_param, a_lo, l_cal, threads, 2);

  while (((t_cal - t_acc) < probe_msec) && (a_cal < accel_max) && (t_cal < target_msec))
  {
    a_cal = MIN (a_cal * 4, accel_max);

    t_cal = try_run_times (hashcat_ctx, device_param, a_cal, l_cal, threads, 2);
  }

  const double t_lo_min = try_run_times (hashcat_ctx, device_param, a_cal, loops_min, threads, 2);

  double per_loop = 0;

  if (l_cal > loops_min)
  {
    const double slope = (t_cal - t_lo_min) / ((double) a_cal * (double) (l_cal - loops_min));

    if (slope > 0) per_loop = slope;
  }

  double per_accel = 0;
  double base_msec = 0;

  // Whether the axis separated is decided by per_unit, not by the sign of what the split leaves in F.
  // per_unit is the whole cost of one unit of accel and is what the two probes actually measured. F is
  // only that cost with the loop part taken back out, so when the loop part accounts for nearly all of
  // it, F lands a rounding error below zero while the fit itself is sound. Treating that as a failure
  // threw away a measured intercept of 1.293 ms on m33400 and left the origin form in its place.

  bool accel_fit = false;

  if (a_cal > a_lo)
  {
    const double per_unit = (t_cal - t_acc) / (double) (a_cal - a_lo);

    if (per_unit > 0)
    {
      per_accel = per_unit - ((double) l_cal * per_loop);
      base_msec = t_cal - ((double) a_cal * per_unit);

      accel_fit = true;
    }

    if (verbose == true) event_log_info (hashcat_ctx, "AT2 fit L=%u A=%u t(%u)=%.3f t(%u)=%.3f -> A=%.3f F=%.5f P=%.5f", l_cal, a_cal, a_lo, t_acc, a_cal, t_cal, base_msec, per_accel, per_loop);
  }

  // The accel axis gave nothing usable, so the origin form is all there is to fall back to. That form
  // scores every accel within a couple of percent of every other one, and the margin below would then
  // hand the answer to the smallest and starve the launch. A fit that cannot separate one accel from
  // another has not earned the right to choose the frugal end, so the margin is dropped here and the
  // best rate is taken outright.

  if (accel_fit == false)
  {
    per_accel = (t_cal / (double) a_cal) - ((double) l_cal * per_loop);
    base_msec = 0;
  }

  if (per_accel < 0) per_accel = 0;
  if (base_msec < 0) base_msec = 0;

  const double fixed_msec = autotune2_fixed_msec (hashcat_ctx, device_param, a_cal, threads);

  // How much work one launch of the loop kernel is a chunk of. A hash that states none runs once.
  //
  // For a slow hash that is the iteration count, and the batch runs ceil(salt_iter / loops) times.
  // A fast hash has no iteration count and salt_iter is left at zero by every fast module, so
  // reading it here put work at 1 for all of them and the launch count came out as 1 whatever the
  // loop count was. What divides into chunks for a fast hash is the amplifier: innerloop_step is
  // kernel_loops and innerloop_cnt is the rule, combinator or mask count, so the launch runs
  // ceil(innerloop_cnt / loops) times over one resident candidate buffer. Same shape, different
  // numerator.

  double work = 1;

  if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
  {
    if (hashes->salts_buf != NULL)
    {
      const u32 salt_iter = hashes->salts_buf[0].salt_iter;

      if (salt_iter > 0) work = (double) salt_iter;
    }
  }
  else
  {
    const user_options_extra_t *user_options_extra = hashcat_ctx->user_options_extra;

    u64 innerloop_cnt = 0;

    if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT) innerloop_cnt = hashcat_ctx->straight_ctx->kernel_rules_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)    innerloop_cnt = hashcat_ctx->combinator_ctx->combs_cnt;
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)       innerloop_cnt = hashcat_ctx->mask_ctx->bfs_cnt;

    if (innerloop_cnt > 0) work = (double) innerloop_cnt;
  }

  // The second loop takes its chunk from the same kernel_loops as the first, so the budget has to
  // hold for whichever of the two is slower, and the total has to count both. Only the first loop
  // was ever measured, which is why a mode whose work sits in the second one was sized from a
  // kernel that is not the one doing the work.

  double work2      = 0;
  double per_accel2 = 0;
  double per_loop2  = 0;
  double base_msec2 = 0;

  if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
  {
    if (hashes->salts_buf != NULL) work2 = (double) hashes->salts_buf[0].salt_iter2;

    if (work2 > 0)
    {
      autotune2_run_init2 (hashcat_ctx, device_param, a_cal, threads);

      const double u_lo_min = autotune2_loop2_msec (hashcat_ctx, device_param, a_cal, loops_min, threads);

      double u_cal = u_lo_min;

      if (l_cal > loops_min)
      {
        u_cal = autotune2_loop2_msec (hashcat_ctx, device_param, a_cal, l_cal, threads);

        const double slope2 = (u_cal - u_lo_min) / ((double) a_cal * (double) (l_cal - loops_min));

        if (slope2 > 0) per_loop2 = slope2;
      }

      // The second loop is a launch like any other and pays the same fill cost, so it is fitted the
      // same way rather than being assumed to pass through the origin.

      if (a_cal > a_lo)
      {
        const double u_acc = autotune2_loop2_msec (hashcat_ctx, device_param, a_lo, l_cal, threads);

        const double per_unit2 = (u_cal - u_acc) / (double) (a_cal - a_lo);

        if (per_unit2 > 0)
        {
          per_accel2 = per_unit2 - ((double) l_cal * per_loop2);
          base_msec2 = u_cal - ((double) a_cal * per_unit2);
        }
      }

      if (per_accel2 <= 0)
      {
        per_accel2 = (u_cal / (double) a_cal) - ((double) l_cal * per_loop2);
        base_msec2 = 0;
      }

      if (per_accel2 < 0) per_accel2 = 0;
      if (base_msec2 < 0) base_msec2 = 0;

      if (verbose == true) event_log_info (hashcat_ctx, "AT2 loop2 A=%.3f F=%.5f P=%.5f W2=%.0f", base_msec2, per_accel2, per_loop2, work2);
    }
  }

  const user_options_t *user_options = hashcat_ctx->user_options;

  const double greed = AUTOTUNE2_GREED[user_options->workload_profile - 1];

  // A fit that could not separate the accel axis scores every accel alike, so greed below 1 would hand
  // the answer to the smallest and starve the launch whatever the profile asked for.

  const double margin = (accel_fit == true) ? greed : 1.0;

  double best_rate  = 0;
  u32    best_accel = accel_min;
  u32    best_loops = loops_min;

  for (u32 accel = MAX (accel_min, 1); accel <= accel_max; accel = (accel < 4) ? accel + 1 : accel + (accel / 2))
  {
    u32 loops = loops_max;

    if (per_loop > 0)
    {
      const double room = ((target_msec - base_msec) / (double) accel) - per_accel;

      if (room <= 0) break;

      double fit = room / per_loop;

      if (fit < (double) loops_min) break;
      if (fit > (double) loops_max) fit = (double) loops_max;

      if (per_loop2 > 0)
      {
        const double room2 = ((target_msec - base_msec2) / (double) accel) - per_accel2;

        if (room2 <= 0) break;

        const double fit2 = room2 / per_loop2;

        if (fit2 < fit) fit = fit2;

        if (fit < (double) loops_min) break;
      }

      loops = (u32) fit;

      loops = autotune2_align_loops (loops, (u32) work, loops_min);
    }

    const double msec_loop = base_msec + ((double) accel * (per_accel + ((double) loops * per_loop)));

    if (msec_loop > target_msec) continue;

    const double msec_loop2 = (work2 > 0) ? (base_msec2 + ((double) accel * (per_accel2 + ((double) loops * per_loop2)))) : 0;

    if (msec_loop2 > target_msec) continue;

    double total = fixed_msec + ((work / (double) loops) * msec_loop);

    if (work2 > 0) total += (work2 / (double) loops) * msec_loop2;

    if (total <= 0) continue;

    const double rate = (double) accel / total;

    if (verbose == true)
    {
      event_log_info (hashcat_ctx, "AT2 accel=%u loops=%u loop_msec=%.3f total=%.3f rate=%.5f", accel, loops, msec_loop, total, rate);
    }

    // Frugality wins ties. A candidate has to beat the incumbent by more than the margin to take
    // its place, and candidates are walked from the smallest accel upward, so the cheapest one that
    // is good enough is the one that survives.

    if (rate > (best_rate / margin))
    {
      best_rate  = rate;
      best_accel = accel;
      best_loops = loops;
    }
    else if (rate > best_rate)
    {
      best_rate = rate;
    }
  }

  *out_accel = best_accel;
  *out_loops = best_loops;

  if (verbose == true)
  {
    event_log_info (hashcat_ctx, "AT2 A=%.3f F=%.5f P=%.5f I=%.3f W=%.0f -> accel=%u loops=%u threads=%u", base_msec, per_accel, per_loop, fixed_msec, work, *out_accel, *out_loops, threads);
  }
}

static int autotune (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  const straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  // see BRIDGE_TARGET_MSEC_SCALE above
  const double target_msec = (hashconfig->bridge_type & BRIDGE_TYPE_REPLACE_LOOP)
                           ? backend_ctx->target_msec * BRIDGE_TARGET_MSEC_SCALE
                           : backend_ctx->target_msec;

  const u32 kernel_accel_min = device_param->kernel_accel_min;
  const u32 kernel_accel_max = device_param->kernel_accel_max;

  const u32 kernel_loops_min = device_param->kernel_loops_min;
  const u32 kernel_loops_max = device_param->kernel_loops_max;

  u32 kernel_threads_max = device_param->kernel_threads_max;

  u32 kernel_threads_min = device_param->kernel_threads_min;

  // The device engine's lanes own positions inside one cell's rectangle, so the work per work item does not
  // change with the group size and the search's efficiency measure, exec time over thread count, has
  // nothing to reward. It settles on one wave per group, and one wave per group measures a third
  // slower than two.

  if (hashcat_ctx->user_options_extra->attack_kern == ATTACK_KERN_PCFG)
  {
    const u32 two_waves = device_param->kernel_preferred_wgs_multiple * 2;

    if ((two_waves > kernel_threads_min) && (two_waves <= kernel_threads_max)) kernel_threads_min = two_waves;

    // The kernel keeps one odometer per work item in shared memory, sized for a group of this many.
    // A larger group would walk off the end of it.

    if (kernel_threads_max > PCFG_DEV_GROUP) kernel_threads_max = PCFG_DEV_GROUP;

    // A cell's work items are handed out in whole waves and one descriptor is shared by a wave, so a
    // group has to be a whole number of waves or two of its threads land in different cells holding
    // the same descriptor. Every device measured picks 32 or 64 here anyway; this is what says so.

    if (kernel_threads_max > PCFG_DEV_WARP) kernel_threads_max -= (kernel_threads_max % PCFG_DEV_WARP);
    if (kernel_threads_min > PCFG_DEV_WARP) kernel_threads_min -= (kernel_threads_min % PCFG_DEV_WARP);

    if (kernel_threads_min > kernel_threads_max) kernel_threads_min = kernel_threads_max;

    // And the probe has to be given cells, or it measures one candidate per base word where the real
    // launch walks thousands, maxes the accel out and leaves every launch after it far past the
    // target. pcfg_seed_cells () explains what that costs.

    if (pcfg_seed_cells (hashcat_ctx, device_param) == -1) return -1;
  }

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
    device_param->hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? bridge_workitem_multiple (hashcat_ctx, device_param->bridge_link_device)
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

    const u32 hardware_power_max = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? bridge_workitem_multiple (hashcat_ctx, device_param->bridge_link_device)
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

    if (getenv ("PROBE_POINT") != NULL)
    {
      const u32 pa = (u32) atoi (getenv ("PROBE_A"));
      const u32 pl = (u32) atoi (getenv ("PROBE_L"));
      const u32 pt = (u32) atoi (getenv ("PROBE_T"));

      const double ms = try_run_times (hashcat_ctx, device_param, pa, pl, pt, 3);

      event_log_info (hashcat_ctx, "POINT accel=%u loops=%u threads=%u ms=%.4f", pa, pl, pt, ms);

      device_param->skipped = true;

      return 0;
    }

    // The model applies where the work is spread across init, loop and comp kernels, because there
    // the cost that decides the split is device side and try_run can see all of it. A hash that
    // computes inside a single kernel is fed by the host instead, and how many candidates a launch
    // should carry is then decided by work try_run cannot observe: it reuses a buffer that is
    // already resident, so the produce and transfer cost never appears. Measured, choosing accel
    // from device timings alone costs up to 83 percent on those, so they keep the search.

    // The thread count is the part of the model that stands on its own. It needs no launch at all:
    // it goes straight to the largest whole wave the kernel's register limit allows, where a search
    // walks up to that one wave at a time and spends a launch on every rung.

    kernel_threads = autotune2_threads_max (device_param, kernel_threads_min, kernel_threads_max);

    // Solve once at the ceiling. That answer is not kept, it only fixes a launch size worth
    // comparing thread counts at: the walk below is meaningless at a launch the device never runs.

    autotune2_solve (hashcat_ctx, device_param, kernel_accel_min, kernel_accel_max, kernel_loops_min, kernel_loops_max, kernel_threads, target_msec, &kernel_accel, &kernel_loops);

    const u32 threads_walked = autotune2_threads_walk (hashcat_ctx, device_param, kernel_threads, kernel_threads_min, kernel_accel, kernel_accel_min, kernel_accel_max, kernel_loops);

    if (threads_walked != kernel_threads)
    {
      // A different workgroup size changes what a unit of accel and a loop iteration cost, so the
      // fit is redone rather than rescaled.

      u32 accel_walked = 0;
      u32 loops_walked = 0;

      autotune2_solve (hashcat_ctx, device_param, kernel_accel_min, kernel_accel_max, kernel_loops_min, kernel_loops_max, threads_walked, target_msec, &accel_walked, &loops_walked);

      // The walk compared thread counts at one launch size, and the fit above does not have to
      // land back on it. Measured on -m 29421, the walk correctly preferred 256 threads over 512
      // at equal kernel_power, and the fit then chose a launch a third the size and lost 7 percent
      // against the stock tuner. So the two finished answers are raced against each other and the
      // proxy only decides which challenger gets a run, never what ships.

      const double msec_hi = try_run_times (hashcat_ctx, device_param, kernel_accel, kernel_loops, kernel_threads, 2);
      const double msec_lo = try_run_times (hashcat_ctx, device_param, accel_walked, loops_walked, threads_walked, 2);

      const double work_hi = (double) kernel_threads * (double) kernel_accel * (double) kernel_loops;
      const double work_lo = (double) threads_walked * (double) accel_walked * (double) loops_walked;

      const double rate_hi = (msec_hi > 0) ? (work_hi / msec_hi) : 0;
      const double rate_lo = (msec_lo > 0) ? (work_lo / msec_lo) : 0;

      if (rate_lo > rate_hi)
      {
        kernel_threads = threads_walked;
        kernel_accel   = accel_walked;
        kernel_loops   = loops_walked;
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

  const u32 hardware_power = bridge_active (hashcat_ctx, device_param->bridge_link_device) ? bridge_workitem_multiple (hashcat_ctx, device_param->bridge_link_device)
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
    CUcontext cuda_context_popped;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &cuda_context_popped) == -1) return 0;
  }

  return 0;
}

