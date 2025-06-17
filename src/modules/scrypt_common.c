
#include <inttypes.h>
#include "common.h"
#include "types.h"
#include "modules.h"
#include "bitops.h"
#include "convert.h"
#include "shared.h"
#include "memory.h"

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

u32 tmto = 0;

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

  return threads;
}

const char *scrypt_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  // we enforce the same configuration for all hashes, so the next lines should be fine

  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  const u64 size_per_accel = (128ULL * scrypt_r * scrypt_N * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param));
  const u64 state_per_accel = (128ULL * scrypt_r * scrypt_p * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param));

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_local_mem_size = device_param->device_local_mem_size;

  const u64 fixed_mem = (512 * 1024 * 1024); // some storage we need for pws[], tmps[], and others

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4)) - fixed_mem;

  tmto = 0;

  u32 kernel_accel_new = device_processors;

  if (kernel_accel_user)
  {
    kernel_accel_new = kernel_accel_user;

    if (user_options->scrypt_tmto_chgd == true)
    {
      // in this branch the user can shoot themselves into the foot

      tmto = user_options->scrypt_tmto;
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
    if (user_options->scrypt_tmto_chgd == true)
    {
      tmto = user_options->scrypt_tmto;
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
        for (tmto = 0; tmto < 2; tmto++) // results in tmto = 2
        {
          if (device_param->device_host_unified_memory == 1) break; // do not touch

          if ((device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
           || (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
          {
            if (tmto == 0) continue; // at least 1
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

        if (device_param->is_hip == true)
        {
          // we use some local memory to speed up things, so
          // we need to make sure there's enough local memory available

          u64 state_per_accel_tmto = state_per_accel >> tmto;

          while (state_per_accel_tmto > device_local_mem_size)
          {
            tmto++;

            state_per_accel_tmto = state_per_accel >> tmto;
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

u64 scrypt_module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  // in general, since we compile the kernel based on N, r, p, so the JIT can optimize it, we can't have other configuration settings
  // we need to check that all hashes have the same scrypt settings

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

  if (user_options->self_test == true)
  {
    if ((scrypt_N != hashes->st_salts_buf[0].scrypt_N)
     || (scrypt_r != hashes->st_salts_buf[0].scrypt_r)
     || (scrypt_p != hashes->st_salts_buf[0].scrypt_p))
    {
      return (1ULL << 62);
    }
  }

  const u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  return tmp_size;
}

char *scrypt_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u32 scrypt_N = (hashes->salts_buf[0].scrypt_N == 0) ? hashes->st_salts_buf[0].scrypt_N : hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = (hashes->salts_buf[0].scrypt_r == 0) ? hashes->st_salts_buf[0].scrypt_r : hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = (hashes->salts_buf[0].scrypt_p == 0) ? hashes->st_salts_buf[0].scrypt_p : hashes->salts_buf[0].scrypt_p;

  const u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D SCRYPT_N=%u -D SCRYPT_R=%u -D SCRYPT_P=%u -D SCRYPT_TMTO=%u -D SCRYPT_TMP_ELEM=%" PRIu64,
    scrypt_N,
    scrypt_r,
    scrypt_p,
    tmto,
    tmp_size / 16);

  return jit_build_options;
}

