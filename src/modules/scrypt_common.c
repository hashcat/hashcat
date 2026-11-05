
/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"
#include "module_options.h"

u32 scrypt_module_kernel_loops_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_min = 2048;

  return kernel_loops_min;
}

u32 scrypt_module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 2048;

  return kernel_loops_max;
}

u32 scrypt_module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : SCRYPT_THREADS;

  return kernel_threads_max;
}

// --scrypt-tmto overrides the TMTO the tuning below would pick. Every module that includes this file
// registers it with scrypt_module_register_options (). It has no brain slot, because TMTO only trades
// memory for time and two runs that differ in it test the same candidates.

#define OPTION_SCRYPT_TMTO "scrypt-tmto"

const module_option_t *scrypt_module_register_options (void)
{
  static const module_option_t options[] =
  {
    {
      .name         = OPTION_SCRYPT_TMTO,
      .type         = MODULE_OPTION_TYPE_U32,
      .help_type    = "Num",
      .help         = "Manually override TMTO value for scrypt to X",
      .help_example = "--scrypt-tmto=3",
    },
    { .name = NULL },
  };

  return options;
}

// The highest TMTO the search will propose. Past this the recomputation dominates on every
// device measured, and the stored element count gets small enough that the walk is pointless.

#define SCRYPT_TMTO_CEILING 6

// The TMTO the search always reaches, even where the memory holds every candidate at a lower one.
// A higher TMTO adds replay work, but the first loop then writes less of V, and where V is small
// those writes bound the run: at N=1024 r=1 an RTX 4090 ran 2.9 MH/s at TMTO 0 and 4.7 MH/s at
// TMTO 2.

#define SCRYPT_TMTO_REACH 2

u32 tmto = 0;

// module_tune as the kernel reads it, see SCRYPT_TUNE_TMTO and SCRYPT_TUNE_LANES4 in
// inc_hash_scrypt.h: the TMTO in the low byte, and whether the four-lane kernel runs.

#define SCRYPT_TUNE_LANES4 (1u << 8)

// A module sets OPTS_TYPE_THREAD_MULTI_DISABLE to take what follows: kernel_accel counts candidates,
// the kernel takes its TMTO and its lane count from module_tune at run time, and autotune times the
// variants of scrypt_module_tune_variants () to pick them. A module without it keeps the tuning
// further down, which builds one TMTO into the kernel.

static bool scrypt_per_candidate (const hashconfig_t *hashconfig)
{
  const bool per_candidate = (hashconfig->opts_type & OPTS_TYPE_THREAD_MULTI_DISABLE) != 0;

  return per_candidate;
}

// Four lanes per candidate need a lane exchange in the kernel, see SCRYPT_COOP in inc_hash_scrypt.h.
// They are asked for on CUDA, HIP and NVIDIA's OpenCL. The kernel has an exchange for AMD's OpenCL
// as well, but it is untested there, so AMD's OpenCL keeps to the single-lane kernel.

bool scrypt_coop_device (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if (scrypt_per_candidate (hashconfig) == false) return false;

  if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) == 0) return false;

  if (device_param->is_cuda == true) return true;
  if (device_param->is_hip  == true) return true;

  if ((device_param->is_opencl == true) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV)) return true;

  return false;
}

// The four-lane kernel holds 8 candidates in a work group of 32 lanes, whatever thread count the mode
// picked for the single-lane kernel. That count stays where the four-lane kernel does not run, since a
// mode with a large N picked a small one to keep a work group's memory small.

u32 scrypt_exptected_threads (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  u32 threads = scrypt_module_kernel_threads_max (hashconfig, user_options, user_options_extra);

  if (hashconfig->opts_type & OPTS_TYPE_NATIVE_THREADS)
  {
    if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      threads = 1;
    }
  }

  if ((user_options->kernel_threads_chgd == false) && (scrypt_coop_device (hashconfig, device_param) == true))
  {
    threads = 32;
  }

  return threads;
}

bool scrypt_coop (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  if (scrypt_coop_device (hashconfig, device_param) == false) return false;

  if (scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param) != 32) return false;

  return true;
}

// Under OPTS_TYPE_THREAD_MULTI_DISABLE kernel_accel counts candidates, and the usual ceiling of 1024
// would hold a large card well below what its memory takes. At r=1 an RTX 4090 ran 32768 candidates
// before, 1024 work groups of 32.

u32 scrypt_module_kernel_accel_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_accel_max = (scrypt_per_candidate (hashconfig) == true) ? KERNEL_ACCEL_MAX_CANDIDATES : KERNEL_ACCEL_MAX;

  return kernel_accel_max;
}

// The memory the V buffers of a device may take. See the comment on spill_mem in
// scrypt_module_extra_tuningdb_block (), which computes the same thing for a module without
// OPTS_TYPE_THREAD_MULTI_DISABLE.

static u64 scrypt_available_mem (const u32 scrypt_r, const hc_device_param_t *device_param)
{
  const u64 fixed_mem = (128 * 1024 * 1024);

  const u64 spill_mem = 3 * ((128ULL * scrypt_r) * device_param->device_processors * device_param->device_maxworkgroup_size);

  // The runtime needs room of its own beside the buffers hashcat sizes. Left with 156 MiB of its
  // reported free memory, an RX 7900 XTX under HIP failed hipMemAlloc () at N=16384 r=1, and left
  // with 524 MiB it ran. The spill term alone covered r=8, where it is 8 times larger.

  const u64 runtime_mem = MAX ((u64) 256 * 1024 * 1024, device_param->device_global_mem / 48);

  const u64 reserve_mem = fixed_mem + spill_mem + runtime_mem;

  const u64 usable_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4));

  const u64 available_mem = (usable_mem > reserve_mem) ? usable_mem - reserve_mem : 0;

  return available_mem;
}

// The bytes of V one candidate takes in the per-candidate kernels: N >> tmto elements of 128 * r
// bytes, and one element where the TMTO reaches past log2 (N), see scrypt_tune_tmto_n () in
// inc_hash_scrypt.cl.

static u64 scrypt_candidate_v_size (const u32 scrypt_N, const u32 scrypt_r, const u32 tmto)
{
  const u64 elems = MAX ((u64) scrypt_N >> MIN (tmto, 31), 1);

  const u64 v_size = 128ULL * scrypt_r * elems;

  return v_size;
}

// Appends a variant unless the list holds it already, or the count is zero.

static u32 scrypt_tune_variant_add (tune_variant_t *variants, const u32 variants_cnt, const u32 variants_size, const u32 module_tune, const u32 kernel_accel, const double loop_launches)
{
  if (kernel_accel == 0) return variants_cnt;

  if (variants_cnt == variants_size) return variants_cnt;

  for (u32 i = 0; i < variants_cnt; i++)
  {
    if ((variants[i].module_tune == module_tune) && (variants[i].kernel_accel == kernel_accel)) return variants_cnt;
  }

  // four work items to a candidate in the four-lane loop kernels, one in the single-lane ones

  const u32 loop_lanes = ((module_tune & SCRYPT_TUNE_LANES4) != 0) ? 4 : 1;

  variants[variants_cnt].module_tune   = module_tune;
  variants[variants_cnt].kernel_accel  = kernel_accel;
  variants[variants_cnt].loop_lanes    = loop_lanes;
  variants[variants_cnt].loop_launches = loop_launches;

  const u32 variants_new = variants_cnt + 1;

  return variants_new;
}

// The self-test runs one candidate in the first way, see the seed in backend.c. TMTO 1 costs that
// candidate 2.5 N BlockMix against 2 N at TMTO 0 and runs the replay that every higher TMTO runs,
// where TMTO 6 costs it 33.5 N. So where the first pass starts at TMTO 0 and lists TMTO 1, that way
// moves to the front, and the others keep their order, which is the order autotune times them in.

static void scrypt_tune_variants_selftest_first (tune_variant_t *variants, const u32 variants_cnt)
{
  if (variants_cnt < 2) return;

  if ((variants[0].module_tune & 0xff) != 0) return;

  for (u32 i = 1; i < variants_cnt; i++)
  {
    if ((variants[i].module_tune & SCRYPT_TUNE_LANES4) != (variants[0].module_tune & SCRYPT_TUNE_LANES4)) return;

    if ((variants[i].module_tune & 0xff) != 1) continue;

    const tune_variant_t first = variants[i];

    for (u32 j = i; j > 0; j--) variants[j] = variants[j - 1];

    variants[0] = first;

    return;
  }
}

// The ways a device can run SMix: four lanes or one lane per candidate, and for each every TMTO
// from the lowest that fits up to the one where the memory holds as many candidates as a launch may
// take and at least to SCRYPT_TMTO_REACH, at the most candidates the memory holds and at fewer.
// autotune times one loop launch of each and keeps the fastest, and among those within a few
// percent of it the one with the fewest candidates, see autotune_variants (). Which of them wins
// depends on the card in a way no rule measured so far could predict.
//
// clamp_to_device holds the counts to the kernel_accel_max the device's buffers were sized for, which
// is only known once the tuning-db block below has been read.

static u32 scrypt_tune_variants (const hashconfig_t *hashconfig, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const hashes_t *hashes, const hc_device_param_t *device_param, const bool clamp_to_device, tune_variant_t *variants, const u32 variants_size)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;

  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  // A candidate also takes its tmps, twice the SMix state, and its pws entry, and the fixed reserve
  // of scrypt_available_mem () does not cover those at tens of thousands of candidates.

  const u64 size_host = (2 * 128ULL * scrypt_r * scrypt_p) + sizeof (pw_t);

  const u64 available_mem = scrypt_available_mem (scrypt_r, device_param);

  const u32 threads = scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param);

  const bool is_gpu = (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) != 0;

  u32 accel_cap = hashconfig->kernel_accel_max;

  if ((clamp_to_device == true) && (device_param->kernel_accel_max > 0)) accel_cap = MIN (accel_cap, device_param->kernel_accel_max);

  // A CPU runs one work item per core, and an APU shares its memory with the host, so neither gets
  // more candidates than a work group per processor, as before.

  if ((is_gpu == false) || (device_param->device_host_unified_memory == true)) accel_cap = MIN (accel_cap, device_param->device_processors * threads);

  // the kernel stores N >> tmto elements, so the TMTO stops short of log2 (N)

  u32 tmto_max = 0;

  while (((u64) 1 << tmto_max) < scrypt_N) tmto_max++;

  tmto_max = MIN (tmto_max, SCRYPT_TMTO_CEILING);

  const bool tmto_user = module_option_given (user_options, OPTION_SCRYPT_TMTO);

  const u32 tmto_lo = (tmto_user == true) ? module_option_u32 (user_options, OPTION_SCRYPT_TMTO) : 0;
  const u32 tmto_hi = (tmto_user == true) ? tmto_lo : tmto_max;

  const u32 accel_user = (user_options->kernel_accel_chgd == true) ? user_options->kernel_accel : 0;

  // On a CPU the kernel is one work item per candidate and TMTO only costs time, so only the lowest
  // TMTO that fits is tried, as before. The same holds where -n fixes the candidate count.

  const bool search = (is_gpu == true) && (accel_user == 0);

  // The single-lane kernel holds 64 * r words a lane, which spills past r=2. There four lanes won
  // everywhere they were measured, so the single-lane kernel is only tried up to r=2 or where the
  // four-lane one does not run. At r=1 an RTX 4090 runs it at 298.3 kH/s with TMTO 2 and 32768
  // candidates, and autotune picks it over four lanes there.

  const bool coop = scrypt_coop (hashconfig, user_options, user_options_extra, device_param);

  const bool single = (coop == false) || (scrypt_r <= 2);

  u32 variants_cnt = 0;

  for (u32 pass = 0; pass < 2; pass++)
  {
    const bool lanes4 = (pass == 0);

    if ((lanes4 == true)  && (coop   == false)) continue;
    if ((lanes4 == false) && (single == false)) continue;

    // Whole work groups, in a multiple of four candidates since the four V buffers take every fourth
    // candidate, and a wave is one of those on every processor.

    const u32 group = (lanes4 == true) ? (threads / 4) : threads;

    const u32 unit = CEILDIV (group, 4) * 4;

    const u32 wave = unit * device_param->device_processors;

    bool fits = false;

    for (u32 t = tmto_lo; t <= tmto_hi; t++)
    {
      if ((fits == true) && (search == false)) break;

      const u64 fit = available_mem / (scrypt_candidate_v_size (scrypt_N, scrypt_r, t) + size_host);

      u32 accel = (u32) MIN (fit, (u64) accel_cap);

      // A count from -n is taken as given, at the lowest TMTO it fits at, and at the highest where it
      // fits at none. The buffers are then sized for what -n asks, and the device's memory check
      // refuses it rather than a launch running past them. Together with --scrypt-tmto it is taken
      // as given as well. Either way it is held to the kernel_accel_max the device was sized for,
      // which the backend can lower below -n.

      if (accel_user > 0)
      {
        if ((fit < accel_user) && (tmto_user == false) && (t < tmto_hi)) continue;

        accel = ((clamp_to_device == true) && (device_param->kernel_accel_max > 0)) ? MIN (accel_user, device_param->kernel_accel_max) : accel_user;
      }
      else
      {
        accel -= accel % unit;

        if (accel < unit) continue;
      }

      // How many loop launches one candidate's run costs. A launch takes 2048 iterations of the
      // second loop, and the first loop is worth N BlockMix against N * (1 + replay) for the second.
      // The four-lane kernel replays the mean count, the single-lane kernel the largest in a warp.

      const u32 N_max = MIN (scrypt_N, 2048);

      const double replay = (lanes4 == true) ? ((double) ((1u << t) - 1) / 2) : (double) ((1u << t) - 1);

      const double loop_launches = ((double) scrypt_N / N_max) * (1.0 + (1.0 / (1.0 + replay)));

      const u32 tune = t | ((lanes4 == true) ? SCRYPT_TUNE_LANES4 : 0);

      variants_cnt = scrypt_tune_variant_add (variants, variants_cnt, variants_size, tune, accel, loop_launches);

      if (search == true)
      {
        // Fewer candidates than the memory holds, in whole waves: all, three quarters, a half and a
        // quarter of the count. A part wave gives some processors a work group more than the rest.
        // A smaller count also keeps the memory a launch walks within what the device translates
        // quickly, and the single-lane kernel at N=16384 r=1 ran 2.7 times faster on an RTX 4090 at
        // TMTO 2 with 32768 candidates than with 45056.

        for (u32 quarters = 4; quarters > 0; quarters--)
        {
          const u32 accel_q = (u32) (((u64) accel * quarters) / 4);

          const u32 step = (accel_q >= wave) ? wave : unit;

          variants_cnt = scrypt_tune_variant_add (variants, variants_cnt, variants_size, tune, accel_q - (accel_q % step), loop_launches);
        }
      }

      fits = true;

      // past that a higher TMTO only adds work once the memory holds every candidate the launch may
      // take

      if ((fit >= accel_cap) && (t >= SCRYPT_TMTO_REACH)) break;
    }
  }

  scrypt_tune_variants_selftest_first (variants, variants_cnt);

  // SMix opens with a loop_prepare kernel in every phase that runs it, so those are the phases
  // module_tune governs: the first for most modes, the second for 38200, all three for 44100.

  u32 loop_phases = 0;

  if ((hashconfig->kern_bits & KERN_BIT_LOOP_PREPARE)  != 0) loop_phases |= 1u << 0;
  if ((hashconfig->kern_bits & KERN_BIT_LOOP2_PREPARE) != 0) loop_phases |= 1u << 1;
  if ((hashconfig->kern_bits & KERN_BIT_LOOP3_PREPARE) != 0) loop_phases |= 1u << 2;

  for (u32 i = 0; i < variants_cnt; i++) variants[i].loop_phases = loop_phases;

  return variants_cnt;
}

u32 scrypt_module_tune_variants (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param, tune_variant_t *variants, const u32 variants_size)
{
  if (scrypt_per_candidate (hashconfig) == false) return 0;

  const u32 variants_cnt = scrypt_tune_variants (hashconfig, user_options, user_options_extra, hashes, device_param, true, variants, variants_size);

  return variants_cnt;
}

char *scrypt_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  // Under OPTS_TYPE_THREAD_MULTI_DISABLE kernel_accel only sizes the buffers here, for the variant
  // that takes the most candidates. autotune picks the variant that runs.

  if (scrypt_per_candidate (hashconfig) == true)
  {
    tune_variant_t variants[TUNE_VARIANTS_MAX];

    const u32 variants_cnt = scrypt_tune_variants (hashconfig, user_options, user_options_extra, hashes, device_param, false, variants, TUNE_VARIANTS_MAX);

    u32 kernel_accel_variants = 1;

    for (u32 i = 0; i < variants_cnt; i++) kernel_accel_variants = MAX (kernel_accel_variants, variants[i].kernel_accel);

    char *device_name = hcstrdup (device_param->device_name);

    const size_t device_name_len = strlen (device_name);

    for (size_t i = 0; i < device_name_len; i++)
    {
      if (device_name[i] == ' ') device_name[i] = '_';
    }

    char *line_buf = NULL;

    hc_asprintf (&line_buf, "%s * %u 1 %u A\n", device_name, user_options->hash_mode, kernel_accel_variants);

    hcfree (device_name);

    return line_buf;
  }

  // we enforce the same configuration for all hashes, so the next lines should be fine

  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  //const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  const u64 size_per_accel = (128ULL * scrypt_r * scrypt_N * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param));
  //const u64 state_per_accel = (128ULL * scrypt_r * scrypt_p * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param));

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_maxworkgroup_size = device_param->device_maxworkgroup_size;

  //const u32 device_local_mem_size = device_param->device_local_mem_size;

  const u64 fixed_mem = (128 * 1024 * 1024); // some storage we need for pws[], tmps[], and others. Is around 72MiB in reality.

  // SCRYPT kernels cause significant spilling, which increases global memory requirements.
  // The variables the runtime uses to allocate global memory for this spilling are undocumented.
  // As a result, launching the kernel can run into memory allocation errors, especially on devices with a large SM count and a high SCRYPT-R value.
  // Based on testing, we assume the following behavior:
  // The runtime uses device_maxworkgroup_size as the thread count, multiplies it by the SM count, and then multiplies that by the spill size.
  // Additionally, it completely ignores our specified grid sizes, which could otherwise help mitigate this.
  // We assume other runtimes behave similarly.
  // Note: we need to allocate the 128R buffer three times: main context, TMTO temporary buffer, (half-size) BlockMix.

  const u64 spill_mem = 3 * ((128ULL * scrypt_r) * device_processors * device_maxworkgroup_size);

  const u64 usable_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4));

  // a device that reports less than the reserve would underflow this on a u64, and the accel
  // computed from the wrapped value asks for far more memory than the device has

  const u64 available_mem = (usable_mem > (fixed_mem + spill_mem)) ? usable_mem - (fixed_mem + spill_mem) : 0;

  tmto = 0;

  u32 kernel_accel_new = device_processors;

  if (kernel_accel_user)
  {
    kernel_accel_new = kernel_accel_user;

    if (module_option_given (user_options, OPTION_SCRYPT_TMTO) == true)
    {
      // in this branch the user can shoot themselves into the foot

      tmto = module_option_u32 (user_options, OPTION_SCRYPT_TMTO);
    }
    else
    {
      // only option to save the user is to increase tmto

      for (tmto = 0; tmto < 6; tmto++)
      {
        const u64 size_per_accel_tmto = size_per_accel >> tmto;

        if ((size_per_accel_tmto * kernel_accel_new) > available_mem) continue; // not enough memory

        break;
      }
    }
  }
  else
  {
    if (module_option_given (user_options, OPTION_SCRYPT_TMTO) == true)
    {
      tmto = module_option_u32 (user_options, OPTION_SCRYPT_TMTO);
    }
    else
    {
      // This is the typical case and the main challenge: choosing the right TMTO value.
      // Finding a consistently good algorithm is nearly impossible due to the many factors
      // that influence performance. There is no clear rule of thumb.
      //
      // For example, consider the default scrypt configuration with N=16k and r=8.
      //
      // In one test with an NVIDIA mobile GPU with 16 GiB of memory (minus X), the device could
      // use 28/58 processors. In theory, increasing the TMTO should increase
      // performance, but in practice it had no effect at all.
      //
      // In another test with an NVIDIA discrete GPU with 11 GiB (minus X), the device initially
      // used 19/68 processors. Increasing the TMTO to utilize all 68 processors
      // did yield the expected performance improvement, matching the theory.
      //
      // However, with an AMD discrete GPU with 24 GiB (minus X), the optimal case used 46/48
      // processors. Increasing the TMTO should have reduced performance, but
      // instead it nearly doubled the speed?! This might be related to AMD GPUs performing
      // best with a thread count of 64 instead of 32, but in practice, using 64 threads
      // shows little difference compared to 32, suggesting that at a very low level,
      // only 32 threads may actually be active.
      //
      // This algorithm is far from ideal. Fortunately, we have a tuning database,
      // so users can find the best -n value for their specific setup, and a forced -n value
      // allows to easily calculate the TMTO.

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        // The kernels store N >> tmto elements, so a tmto that reaches log2 (N) stores none of them
        // and the mode stops cracking. N is a power of two by the time it gets here, so this walk is
        // that log, and it bounds both of the searches below.

        u32 tmto_max = 0;

        while (((u64) 1 << tmto_max) < scrypt_N) tmto_max++;

        tmto_max = MIN (tmto_max, SCRYPT_TMTO_CEILING);

        for (tmto = 0; tmto < 2; tmto++) // results in tmto = 2
        {
          if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
           || (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
          {
            if (device_param->device_host_unified_memory == 0) // This special rule only affects dGPUs not iGPU
            {
              if (tmto == 0) continue; // at least 1
            }
          }

          const u64 size_per_accel_tmto = size_per_accel >> tmto;

          const float blocks = (float) available_mem / size_per_accel_tmto;

          const float blocks_perc = device_processors / blocks;

          if (blocks_perc > 1.16) continue;

          // probably very low scrypt configuration = register pressure becomes a bottleneck
          if ((blocks_perc * (1 << tmto)) < 0.4)
          {
            if (scrypt_r == 1) continue;
          }

          break;
        }

        // Neither test has to be met for the loop to run out, and when neither is it ends at 2
        // whatever N is. A low N cannot carry that: at N=2 it stores nothing at all.

        tmto = MIN (tmto, tmto_max);

        // The search above stops at 2, and on a configuration big enough that even a TMTO of 2
        // leaves the device nearly empty that ceiling is what limits the launch, not the memory.
        // A 4090 attacking N=262144 gets 8 work items where 176 fit, and the same holds for every
        // mode that ships a large N: 15700 is N=262144 by default.
        //
        // Raising it everywhere is wrong. A device that is merely short of work loses more to the
        // extra recomputation than it gains from the parallelism, which is what the 1.16 test above
        // already decides. So the ceiling only lifts where the device is under half filled, and the
        // same test then chooses how far to go.

        const u64 size_per_accel_ceiling = size_per_accel >> tmto;

        const float blocks_ceiling = (float) available_mem / size_per_accel_ceiling;

        const float blocks_perc_ceiling = device_processors / blocks_ceiling;

        if (blocks_perc_ceiling > 2.0)
        {
          while (tmto < tmto_max)
          {
            const u64 size_per_accel_tmto = size_per_accel >> tmto;

            const float blocks = (float) available_mem / size_per_accel_tmto;

            const float blocks_perc = device_processors / blocks;

            if (blocks_perc <= 1.16) break;

            tmto++;
          }
        }
      }
    }

    // from here tmto is known, and we need to update kernel_accel

    if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->device_host_unified_memory == false))
    {
      const u64 size_per_accel_tmto = size_per_accel >> tmto;

      kernel_accel_new = available_mem / size_per_accel_tmto;

      kernel_accel_new = MIN (kernel_accel_new, 1024); // max supported

      // luxury option, clamp if we have twice the processors

      if (kernel_accel_new > (device_processors * 2))
      {
        const u32 extra = kernel_accel_new % device_processors;

        kernel_accel_new -= extra;
      }

      // clamp if close to device processors -- 16% seems fine on a 2080ti, and on a 4090

      if (kernel_accel_new > device_processors)
      {
        const u32 extra = kernel_accel_new % device_processors;

        if (extra < (device_processors * 0.16))
        {
          kernel_accel_new -= extra;
        }
      }
    }
  }

  char *new_device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (new_device_name); i++)
  {
    if (new_device_name[i] == ' ') new_device_name[i] = '_';
  }

  lines_pos += snprintf (lines_buf + lines_pos, lines_sz - lines_pos, "%s * %u 1 %u A\n", new_device_name, user_options->hash_mode, kernel_accel_new);

  hcfree (new_device_name);

  return lines_buf;
}

u64 scrypt_module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  // we need to set the self-test hash settings to pass the self-test
  // the decoder for the self-test is called after this function

  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  //const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  if (scrypt_per_candidate (hashconfig) == true)
  {
    // every variant autotune may pick has to fit, at the counts the device was sized for

    tune_variant_t variants[TUNE_VARIANTS_MAX];

    const u32 variants_cnt = scrypt_tune_variants (hashconfig, user_options, user_options_extra, hashes, device_param, true, variants, TUNE_VARIANTS_MAX);

    // backend.c splits this four ways and gives each part kernel_accel_max / 4 shares of
    // size / kernel_accel_max bytes, the first parts a share more where that does not divide.
    // Candidate c lives in part c & 3, so every part has to hold the most any variant puts in one,
    // and the size is worked back from that. Without a variant the kernel runs one candidate at
    // TMTO 0, see the seed in backend.c.

    u64 part_need = (variants_cnt == 0) ? scrypt_candidate_v_size (scrypt_N, scrypt_r, 0) : 0;

    for (u32 i = 0; i < variants_cnt; i++)
    {
      const u32 variant_tmto = variants[i].module_tune & 0xff;

      const u64 part_variant = CEILDIV ((u64) variants[i].kernel_accel, 4) * scrypt_candidate_v_size (scrypt_N, scrypt_r, variant_tmto);

      part_need = MAX (part_need, part_variant);
    }

    // The self-test runs one candidate at the self-test hash's N, which can be larger than the
    // target's. It fits in whichever way it runs when it fits at TMTO 0.

    if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
    {
      const u64 part_st = scrypt_candidate_v_size (hashes->st_salts_buf[0].scrypt_N, scrypt_r, 0);

      part_need = MAX (part_need, part_st);
    }

    const u64 accel_max = MAX (device_param->kernel_accel_max, 1);

    const u64 shares = MAX (accel_max / 4, 1);

    const u64 size_scrypt = accel_max * CEILDIV (part_need, shares);

    return size_scrypt;
  }

  const u64 size_per_accel = 128ULL * scrypt_r * scrypt_N * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param);

  const u64 size_per_accel_tmto = size_per_accel >> tmto;

  const u64 size_scrypt = device_param->kernel_accel_max * size_per_accel_tmto;

  return size_scrypt;
}

u64 scrypt_module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 0; // we'll add some later

  return tmp_size;
}

int scrypt_module_benchmark_cost (MAYBE_UNUSED const hashconfig_t *hashconfig, const salt_t *salt, MAYBE_UNUSED const void *esalt_buf, char *line_buf, const int line_size)
{
  // scrypt's cost is the triple N, r and p, with the memory use set by 128 * N * r bytes. salt_iter
  // carries only N, so the plain Iterations readout hides r and p. Show the three the hash spells.

  const u32 N = salt->scrypt_N;
  const u32 r = salt->scrypt_r;
  const u32 p = salt->scrypt_p;

  return snprintf (line_buf, line_size, "N=%u, r=%u, p=%u", N, r, p);
}

u64 scrypt_module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  // in general, since we compile the kernel based on N, r, p, so the JIT can optimize it, we can't have other configuration settings
  // we need to check that all hashes have the same scrypt settings
  // The per-candidate kernels read N at run time, but from the first salt, and V is sized for one N.

  for (u32 i = 1; i < hashes->salts_cnt; i++)
  {
    if ((scrypt_N != hashes->salts_buf[i].scrypt_N)
     || (scrypt_r != hashes->salts_buf[i].scrypt_r)
     || (scrypt_p != hashes->salts_buf[i].scrypt_p))
    {
      return (1ULL << 63) + i;
    }
  }

  // now that we know they all have the same settings, we also need to check the self-test hash is different to what the user hash is using

  if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
  {
    // The per-candidate kernels read N from the salt, see SCRYPT_SALT_N in inc_hash_scrypt.h, so only
    // r and p have to match there.

    const bool n_built_in = (scrypt_per_candidate (hashconfig) == false);

    if (((n_built_in == true) && (scrypt_N != hashes->st_salts_buf[0].scrypt_N))
     || (scrypt_r != hashes->st_salts_buf[0].scrypt_r)
     || (scrypt_p != hashes->st_salts_buf[0].scrypt_p))
    {
      return (1ULL << 62);
    }
  }

  // The size below is returned on the same u64 as the two error sentinels above, so a hash file
  // whose r and p carry the product up to bit 62 or 63 was read back as a configuration error that
  // nothing had actually detected. Both are far above any real scrypt parameter, so bounding them
  // here refuses no hash that works, and one above the bound still meets the existing "not enough
  // allocatable device memory" refusal rather than a silent wrong answer.

  // The value handed back is also used to build the kernel, so it has to stay a number a kernel can
  // be compiled with. 2^40 is far past anything a device can allocate, which is the refusal the user
  // should see, and far below the two sentinel bits.

  const u64 tmp_size_max = 1ULL << 40;

  if (scrypt_r > 0xffff) return tmp_size_max;
  if (scrypt_p > 0xffff) return tmp_size_max;

  // this is what we call SCRYPT_SZ in kernel

  u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  // we need twice the size of SCRYPT_SZ so we can have two elements of that size.
  // we can safely process blockmix on the second element without modifying the first element.
  // this can be useful when using hooks in combination with P > 1

  tmp_size *= 2;

  return tmp_size;
}

char *scrypt_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  // The same bound scrypt_module_extra_tmp_size applies. This value becomes SCRYPT_TMP_ELEM in the
  // kernel source, so without it an r and p out of a hash file ask for an array no compiler will
  // accept and the user is shown a JIT failure instead of an honest refusal.

  u64 tmp_size = (scrypt_r > 0xffff) || (scrypt_p > 0xffff) ? (1ULL << 40) : 128ULL * scrypt_r * scrypt_p;

  tmp_size *= 2; // see scrypt_module_extra_tmp_size for details

  char *jit_build_options = NULL;

  const u32 expected_threads = scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param);

  if (scrypt_per_candidate (hashconfig) == true)
  {
    const bool coop = scrypt_coop (hashconfig, user_options, user_options_extra, device_param);

    // HASHCAT_SCRYPT_NATIVE_CUBIN=1 has NVRTC compile the CUDA kernel for the device's sm instead of
    // handing PTX to the driver, see nvrtc_native_cubin () in backend.c. On an RTX 4090 that made
    // modes 8900, 15700 and 24000 between 1 and 16 percent faster. It is opt-in, because no other
    // card has been measured.

    const char *native_env = getenv ("HASHCAT_SCRYPT_NATIVE_CUBIN");

    const bool native_cubin = (device_param->is_cuda == true) && (native_env != NULL) && (strcmp (native_env, "1") == 0);

    hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D SCRYPT_R=%u -D SCRYPT_P=%u -D SCRYPT_TMP_ELEM=%" PRIu64 "%s%s",
      expected_threads,
      scrypt_r,
      scrypt_p,
      tmp_size / 4,
      (coop == true) ? " -D SCRYPT_COOP" : "",
      (native_cubin == true) ? " -D HC_NVRTC_NATIVE_CUBIN" : "");

    return jit_build_options;
  }

  hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D SCRYPT_N=%u -D SCRYPT_R=%u -D SCRYPT_P=%u -D SCRYPT_TMTO=%u -D SCRYPT_TMP_ELEM=%" PRIu64,
    expected_threads,
    scrypt_N,
    scrypt_r,
    scrypt_p,
    tmto,
    tmp_size / 4);

  return jit_build_options;
}

