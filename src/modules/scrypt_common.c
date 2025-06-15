
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
  const u32 kernel_loops_min = 1024;

  return kernel_loops_min;
}

u32 scrypt_module_kernel_loops_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_loops_max = 1024;

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

const char *scrypt_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  // preprocess tmto in case user has overridden
  // it's important to set to 0 otherwise so we can postprocess tmto in that case

  tmto = (user_options->scrypt_tmto_chgd == true) ? user_options->scrypt_tmto : 0;

  // we enforce the same configuration for all hashes, so the next lines should be fine

  const u32 scrypt_N = hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;

  const u64 size_per_accel = (128ULL * scrypt_r * scrypt_N * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param)) >> tmto;
  const u64 state_per_accel = (128ULL * scrypt_r * scrypt_p * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param));

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_local_mem_size = device_param->device_local_mem_size;

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4));

  u32 kernel_accel_new = device_processors;

  if (kernel_accel)
  {
    // from command line or tuning db has priority

    kernel_accel_new = user_options->kernel_accel;
  }
  else
  {
    // find a nice kernel_accel programmatically

    if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      if ((size_per_accel * device_processors) > available_mem) // not enough memory
      {
        const float multi = (float) available_mem / size_per_accel;

        int accel_multi;

        for (accel_multi = 1; accel_multi <= 2; accel_multi++)
        {
          kernel_accel_new = multi * (1 << accel_multi);

          if (kernel_accel_new >= device_processors) break;
        }

        // we need some space for tmps[], ...

        kernel_accel_new -= (1 << accel_multi);

        // clamp if close to device processors -- 16% seems fine on a 2080ti, and on a 4090

        if ((kernel_accel_new > device_processors) && ((device_processors * 1.16) > kernel_accel_new))
        {
          kernel_accel_new = device_processors;
        }
      }
      else
      {
        for (int i = 1; i <= 8; i++)
        {
          if ((size_per_accel * device_processors * i) < available_mem)
          {
            kernel_accel_new = device_processors * i;
          }
        }
      }
    }
    else
    {
      for (int i = 1; i <= 8; i++)
      {
        if ((size_per_accel * device_processors * i) < available_mem)
        {
          kernel_accel_new = device_processors * i;
        }
      }
    }
  }

  // fix tmto if user allows

  if (tmto == 0)
  {
    const u32 tmto_start = 0;
    const u32 tmto_stop  = 5;

    for (u32 tmto_new = tmto_start; tmto_new <= tmto_stop; tmto_new++)
    {
      // we have 1024 hard-coded in the kernel
      if ((scrypt_N / (1 << tmto_new)) < 1024) continue;

      // global memory check
      if (available_mem < (kernel_accel_new * (size_per_accel >> tmto_new))) continue;

      // also need local memory check because in kernel we have:
      // LOCAL_VK uint4 T_s[MAX_THREADS_PER_BLOCK][STATE_CNT4]; // 32 * 128 * r * p = 32KiB we're close if there's no TMTO
      if (device_local_mem_size < (state_per_accel >> tmto_new)) continue;

      tmto = tmto_new;

      break;
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

  const u32 scrypt_N = hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
  //const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;

  const u64 size_per_accel = 128ULL * scrypt_r * scrypt_N * scrypt_exptected_threads (hashconfig, user_options, user_options_extra, device_param);

  u64 size_scrypt = size_per_accel * device_param->kernel_accel_max;

  // We must maintain at least 1024 iteration it's hard-coded in the kernel
  if ((scrypt_N / (1 << tmto)) < 1024)
  {
    fprintf (stderr, "ERROR: SCRYPT-N parameter too low. Invalid tmto specified?\n");

    return -1;
  }

  return size_scrypt / (1 << tmto);
}

u64 scrypt_module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 0; // we'll add some later

  return tmp_size;
}

u64 scrypt_module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  const u32 scrypt_N = hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;

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

bool scrypt_module_warmup_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  return true;
}

char *scrypt_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u32 scrypt_N = hashes->salts_buf[0].scrypt_N;
  const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
  const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;

  const u64 tmp_size = 128ULL * scrypt_r * scrypt_p;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D SCRYPT_N=%u -D SCRYPT_R=%u -D SCRYPT_P=%u -D SCRYPT_TMTO=%u -D SCRYPT_TMP_ELEM=%" PRIu64,
    scrypt_N,
    scrypt_r,
    scrypt_p,
    tmto + 1,
    tmp_size / 16);

  return jit_build_options;
}
