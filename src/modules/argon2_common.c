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
#include "argon2_common.h"

// The blocks one hash of the attack needs, taken over the hashes actually loaded. The self-test hash
// is deliberately not part of this: it is charged separately, because it costs a fixed amount rather
// than an amount per accel. See get_selftest_memory_block_count ().

u64 get_largest_memory_block_count (MAYBE_UNUSED const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  merged_options_t *merged_options = (merged_options_t *) hashes->esalts_buf;

  u64 largest_memory_block_count = 0;

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    argon2_options_t *argon2_options = &merged_options[i].argon2_options;

    largest_memory_block_count = MAX (largest_memory_block_count, argon2_options->memory_block_count);
  }

  // Nothing loaded yet, which happens when the tuning block is consulted before the hashes are.
  // Falling back to the self-test hash keeps the old behaviour for that case rather than dividing
  // by zero further down.

  if (largest_memory_block_count == 0) largest_memory_block_count = get_selftest_memory_block_count (hashconfig, hashes);

  return largest_memory_block_count;
}

// The self-test runs a single work item - selftest.c calls run_kernel () with num_elements 1 - so it
// needs one hash worth of the extra buffer and no more. It used to be folded into the figure above,
// which then multiplied it by kernel_accel: attacking a 16 MiB argon2 reserved as though every lane
// were the self-test's 64 MiB, taking accel 355 where 1024 was affordable and 22.7 GB where 16.4 GB
// was needed. On a card too small to hold accel lanes of the self-test's size, that is the difference
// between running and not.

u64 get_selftest_memory_block_count (MAYBE_UNUSED const hashconfig_t *hashconfig, const hashes_t *hashes)
{
  if (hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) return 0;

  if (hashes->st_esalts_buf == NULL) return 0;

  const merged_options_t *merged_options_st = (const merged_options_t *) hashes->st_esalts_buf;

  return merged_options_st->argon2_options.memory_block_count;
}

const char *argon2_module_extra_tuningdb_block (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, const backend_ctx_t *backend_ctx, MAYBE_UNUSED const hashes_t *hashes, const u32 device_id, const u32 kernel_accel_user)
{
  hc_device_param_t *device_param = &backend_ctx->devices_param[device_id];

  const u64 memory_block_count = get_largest_memory_block_count (hashconfig, hashes);

  const u64 size_per_accel = ARGON2_BLOCK_SIZE * memory_block_count;

  int   lines_sz  = 4096;
  char *lines_buf = hcmalloc (lines_sz);
  int   lines_pos = 0;

  const u32 device_processors = device_param->device_processors;

  const u32 device_maxworkgroup_size = device_param->device_maxworkgroup_size;

  const u64 fixed_mem = (256 * 1024 * 1024); // some storage we need for pws[], tmps[], and others. Is around 72MiB in reality.

  const u64 spill_mem = 2048 * device_processors * device_maxworkgroup_size; // 1600 according to ptxas

  const u64 available_mem = MIN (device_param->device_available_mem, (device_param->device_maxmem_alloc * 4)) - (fixed_mem + spill_mem);

  const u32 kernel_accel_max = (device_param->device_host_unified_memory == true) ? (available_mem / 2) / size_per_accel : available_mem / size_per_accel;

  u32 kernel_accel_new = device_processors;

  if (kernel_accel_user)
  {
    kernel_accel_new = MIN (kernel_accel_max, kernel_accel_user);
  }
  else
  {
    if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      kernel_accel_new = MIN (device_processors, kernel_accel_max);
    }
    else
    {
      kernel_accel_new = kernel_accel_max;
    }
  }

  char *new_device_name = hcstrdup (device_param->device_name);

  for (size_t i = 0; i < strlen (new_device_name); i++)
  {
    if (new_device_name[i] == ' ') new_device_name[i] = '_';
  }

  kernel_accel_new = MIN (kernel_accel_new, KERNEL_ACCEL_MAX);

  lines_pos += snprintf (lines_buf + lines_pos, lines_sz - lines_pos, "%s * %u 1 %u A\n", new_device_name, user_options->hash_mode, kernel_accel_new);

  hcfree (new_device_name);

  return lines_buf;
}

u64 argon2_module_extra_buffer_size (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  const u64 memory_block_count = get_largest_memory_block_count (hashconfig, hashes);

  const u64 size_per_accel = ARGON2_BLOCK_SIZE * memory_block_count;

  const u64 size_argon2 = device_param->kernel_accel_max * size_per_accel;

  // and room for the self-test, which is one work item of whatever the self-test hash asks for

  const u64 size_selftest = ARGON2_BLOCK_SIZE * get_selftest_memory_block_count (hashconfig, hashes);

  return MAX (size_argon2, size_selftest);
}

char *argon2_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  int   build_options_sz  = 1024;
  char *build_options_buf = hcmalloc (build_options_sz);
  int   build_options_len = 0;

  int forced_thread_count = 32;

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    forced_thread_count = 1;
  }

  build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D FORCED_THREAD_COUNT=%d ", forced_thread_count);

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D THREADS_PER_LANE=1 ");
  }

  // We can apply some optimization logic under certain conditions

  merged_options_t *merged_options    = (merged_options_t *) hashes->esalts_buf;
  merged_options_t *merged_options_st = (merged_options_t *) hashes->st_esalts_buf;

  argon2_options_t *argon2_options    = &merged_options->argon2_options;
  argon2_options_t *argon2_options_st = &merged_options_st->argon2_options;

  u64 memory_block_count = 0;
  u64 parallelism = 0;

  if (((hashconfig->opts_type & OPTS_TYPE_SELF_TEST_DISABLE) == 0) && (argon2_options_st != NULL))
  {
    memory_block_count = argon2_options_st->memory_block_count;
    parallelism        = argon2_options_st->parallelism;
  }
  else
  {
    memory_block_count = argon2_options->memory_block_count;
    parallelism        = argon2_options->parallelism;
  }

  bool all_same_memory_block_count = true;
  bool all_same_parallelism        = true;

  for (u32 i = 0; i < hashes->salts_cnt; i++)
  {
    argon2_options = &merged_options[i].argon2_options;

    if (memory_block_count != argon2_options->memory_block_count) all_same_memory_block_count = false;

    if (parallelism != argon2_options->parallelism) all_same_parallelism = false;
  }

  if (all_same_memory_block_count == true)
  {
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D ARGON2_TMP_ELEM=%" PRIu64 " ", memory_block_count);
  }

  if (all_same_parallelism == true)
  {
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D ARGON2_PARALLELISM=%" PRIu64 " ", parallelism);
  }

  return build_options_buf;
}

