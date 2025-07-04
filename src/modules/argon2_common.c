/**
 * Author......: Netherlands Forensic Institute
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

#define ARGON2_SYNC_POINTS  4
#define ARGON2_BLOCK_SIZE   1024

typedef struct argon2_tmp
{
  u32 state[4]; // just something for now

} argon2_tmp_t;

typedef struct argon2_options
{
  u32 type;
  u32 version;

  u32 iterations;
  u32 parallelism;
  u32 memory_usage_in_kib;

  u32 segment_length;
  u32 lane_length;
  u32 memory_block_count;

  u32 digest_len;

} argon2_options_t;

u32 argon2_module_kernel_threads_min (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_min = 32; // hard-coded in kernel

  return kernel_threads_min;
}

u32 argon2_module_kernel_threads_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 kernel_threads_max = 32; // hard-coded in kernel

  return kernel_threads_max;
}

u64 argon2_module_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u64 tmp_size = 0; // we'll add some later

  return tmp_size;
}

const char *argon2_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  argon2_options_t *options    = (argon2_options_t *) hashes->esalts_buf;
  argon2_options_t *options_st = (argon2_options_t *) hashes->st_esalts_buf;

  const u32 memory_block_count = (options->memory_block_count) ? options->memory_block_count : options_st->memory_block_count;

  const u64 size_per_accel = ARGON2_BLOCK_SIZE * memory_block_count;

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_maxworkgroup_size = device_param->device_maxworkgroup_size;

  const u64 fixed_mem = (256 * 1024 * 1024); // some storage we need for pws[], tmps[], and others. Is around 72MiB in reality.

  const u64 spill_mem = 2048 * device_processors * device_maxworkgroup_size; // 1600 according to ptxas

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4)) - (fixed_mem + spill_mem);

  u32 kernel_accel_new = device_processors;

  if (kernel_accel_user)
  {
    kernel_accel_new = kernel_accel_user;
  }
  else
  {
    if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->device_host_unified_memory == false))
    {
      kernel_accel_new = available_mem / size_per_accel;

      kernel_accel_new = MIN (kernel_accel_new, 1024); // 1024 = max supported
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

u64 argon2_module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  argon2_options_t *options    = (argon2_options_t *) hashes->esalts_buf;
  argon2_options_t *options_st = (argon2_options_t *) hashes->st_esalts_buf;

  const u32 memory_block_count = (options->memory_block_count) ? options->memory_block_count : options_st->memory_block_count;

  const u64 size_per_accel = ARGON2_BLOCK_SIZE * memory_block_count;

  const u64 size_argon2 = device_param->kernel_accel_max * size_per_accel;

  return size_argon2;
}

u64 argon2_module_extra_tmp_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes)
{
  argon2_options_t *options    = (argon2_options_t *) hashes->esalts_buf;
  argon2_options_t *options_st = (argon2_options_t *) hashes->st_esalts_buf;

  const u32 memory_block_count = (options->memory_block_count) ? options->memory_block_count : options_st->memory_block_count;
  const u32 parallelism        = (options->parallelism)        ? options->parallelism        : options_st->parallelism;

  for (u32 i = 1; i < hashes->salts_cnt; i++)
  {
    if ((memory_block_count != options[i].memory_block_count)
     || (parallelism        != options[i].parallelism))
    {
      return (1ULL << 63) + i;
    }
  }

  // now that we know they all have the same settings, we also need to check the self-test hash is different to what the user hash is using

  if ((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0)
  {
    if ((memory_block_count != options_st->memory_block_count)
     || (parallelism        != options_st->parallelism))
    {
      return (1ULL << 62);
    }
  }

  u64 tmp_size = sizeof (argon2_tmp_t);

  return tmp_size;
}

char *argon2_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  argon2_options_t *options = (argon2_options_t *) hashes->esalts_buf;

  char *jit_build_options = NULL;

  hc_asprintf (&jit_build_options, "-D ARGON2_PARALLELISM=%u -D ARGON2_TMP_ELEM=%u", options[0].parallelism, options[0].memory_block_count);

  return jit_build_options;
}

