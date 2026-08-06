/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "filehandling.h"
#include "shared.h"
#include "thread.h"
#include "backend.h"
#include "user_options.h"
#include "pcfg_backend.h"
#include "pcfg.h"

// skip result struct

typedef struct
{
  u64 start_loop;
  u64 internal_skip;

} pcfg_skip_result_t;

// calculate how many passwords were generated in loops 0..N-1

static u64 cumulative_before_loop (u64 N, const pcfg_gpu_omen_data_t *lin, u64 burst_size)
{
  if (N == 0) return 0;

  const u64 B = burst_size;
  const u32 num_structs = lin->struct_cnt;
  const u64 *sorted_K = lin->sorted_keyspace;
  const u64 *prefix_K = lin->prefix_keyspace;
  const u64 threshold = N * B;

  // binary search: find split where sorted_K[split] <= threshold
  u32 lo = 0, hi = num_structs;

  while (lo < hi)
  {
    u32 mid = (lo + hi) / 2;

    if (sorted_K[mid] > threshold)
    {
      lo = mid + 1;
    }
    else
    {
      hi = mid;
    }
  }

  // structures have K > threshold → they have given N*B each
  u64 contrib_large = (u64) lo * threshold;

  // the rest gave it their all
  u64 contrib_small = prefix_K[num_structs] - prefix_K[lo];

  return contrib_large + contrib_small;
}

static pcfg_skip_result_t pcfg_gpu_omen_bycost_fast_skip (hashcat_ctx_t *hashcat_ctx, const pcfg_gpu_omen_data_t *lin, u64 skip, u64 burst_size)
{
  pcfg_skip_result_t res = {0, 0};

  if (skip == 0) return res;

  user_options_t *user_options = hashcat_ctx->user_options;
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  pcfg_model_t *model = pcfg_ctx->model;

  u32 lvl_min = user_options->pcfg_omen_cost_min;
  // find the actual max cost from the chunks (or use the lvl_max option)
  u32 lvl_max = 0;
  for (u32 c = 0; c < pcfg_ctx->omen_num_chunks; c++)
  {
    if (pcfg_ctx->omen_chunks[c].cost_end > lvl_max) lvl_max = pcfg_ctx->omen_chunks[c].cost_end;
  }

  if (lvl_max == 0) lvl_max = user_options->pcfg_omen_cost_max; // fallback

  u64 current_loop = 0;
  u32 current_cost = lvl_min;
  u64 skip_left = skip;

  while (skip_left > 0)
  {
    u64 cost_ks_in_loop = 0;

    // calculate total keyspace for this cost in the current loop
    // by iterate through all active structures at this cost
    for (u32 i = 0; i < lin->struct_cnt; i++)
    {
      int rem = (int)current_cost - (int)lin->struct_costs[i];

      if (rem < 0 || rem < (int)lin->struct_min_term_cost[i]) continue;

      // calculate the exact keyspace for this structure at this cost
      u64 s_ks = get_struct_keyspace_at_cost (&lin->structures[i], model->omen_data, rem);

      if (s_ks == 0) continue;

      // apply Interleaved (burst) logic
      u64 offset = current_loop * burst_size;

      // if the structure still has passwords available after 'offset'
      if (s_ks > offset)
      {
        u64 avail = s_ks - offset;

        // contributes to the maximum burst_size
        cost_ks_in_loop += (avail > burst_size) ? burst_size : avail;
      }
    }

    // if this cost does not produce anything in this loop (e.g., all structures are finite or empty)
    if (cost_ks_in_loop == 0)
    {
      // go to next
      current_cost++;

      // if we have completed all costs, move on to the next loop and start again from the lower costs
      if (current_cost > lvl_max)
      {
        current_cost = lvl_min;
        current_loop++;

        // safety break if loop too high
        if (current_loop > lin->max_loops + 100) break;
      }

      continue;
    }

    // found keyspace in this cost/loop
    if (skip_left >= cost_ks_in_loop)
    {
      // skip entire cost in this loop
      skip_left -= cost_ks_in_loop;

      current_cost++;

      if (current_cost > lvl_max)
      {
        current_cost = lvl_min;
        current_loop++;
      }
    }
    else
    {
      break;
    }
  }

  res.start_loop = current_loop;
  res.internal_skip = skip_left;

  // save to get back on runtime_init
  pcfg_ctx->omen_skip_target_cost = current_cost;
  return res;
}

static pcfg_skip_result_t pcfg_gpu_omen_bystruct_fast_skip (u64 skip, const pcfg_gpu_omen_data_t *lin, u64 burst_size)
{
  pcfg_skip_result_t result = {0, 0};

  if (skip == 0) return result;
  if (lin->sorted_keyspace == NULL) return result;

  // handle Classic Mode
  if (lin->max_loops == 1)
  {
    result.start_loop = 0;
    result.internal_skip = skip;
    return result;
  }

  const u64 max_loops = lin->max_loops;

  // binary search for start_loop
  u64 lo = 0, hi = max_loops;

  while (lo < hi)
  {
    u64 mid = (lo + hi + 1) / 2;

    u64 cumulative = cumulative_before_loop (mid, lin, burst_size);

    if (cumulative <= skip)
    {
      lo = mid;
    }
    else
    {
      hi = mid - 1;
    }
  }

  result.start_loop = lo;
  result.internal_skip = skip - cumulative_before_loop (lo, lin, burst_size);

  return result;
}

void generate_source_kernel_pcfg_gpu_prob_filename (char *shared_dir, char *source_file)
{
  snprintf (source_file, 255, "%s/OpenCL/pcfg_gpu_prob.cl", shared_dir);
}

void generate_cached_kernel_pcfg_gpu_prob_filename (u32 opti_type, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal)
{
  if (opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    snprintf (cached_file, 255, "%s/kernels/pcfg_gpu_prob_opti.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
  else
  {
    snprintf (cached_file, 255, "%s/kernels/pcfg_gpu_prob.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
}

void generate_source_kernel_pcfg_gpu_omen_filename (char *shared_dir, char *source_file)
{
  snprintf (source_file, 255, "%s/OpenCL/pcfg_gpu_omen.cl", shared_dir);
}

void generate_cached_kernel_pcfg_gpu_omen_filename (u32 opti_type, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal)
{
  if (opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    snprintf (cached_file, 255, "%s/kernels/pcfg_gpu_omen_opti.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
  else
  {
    snprintf (cached_file, 255, "%s/kernels/pcfg_gpu_omen.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
}

int gidd_to_pw_t_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  memset (pw, 0, sizeof (pw_t));

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

    if (hc_cuMemcpyDtoH (hashcat_ctx, pw, device_param->cuda_d_pws_buf + (gidd * sizeof (pw_t)), sizeof (pw_t)) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipSetDevice (hashcat_ctx, device_param->hip_device) == -1) return -1;

    if (hc_hipMemcpyDtoH (hashcat_ctx, pw, device_param->hip_d_pws_buf + (gidd * sizeof (pw_t)), sizeof (pw_t)) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, pw, device_param->metal_d_pws_buf, gidd * sizeof (pw_t), sizeof (pw_t)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_buf, CL_TRUE, gidd * sizeof (pw_t), sizeof (pw_t), pw, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int run_kernel_pcfg_gpu_prob (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 base_off, const u32 struct_cnt, const u64 pws_cnt)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;

  const u64 kernel_threads = device_param->kernel_wgs_pcfg_gpu_prob;

  const u32 num_devices = (pcfg_ctx && pcfg_ctx->gpu_prob_ctx) ? pcfg_ctx->gpu_prob_ctx->num_devices : 1;

  u64 num_elements = pws_cnt;

  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  // Update the variable parameters
  device_param->kernel_params_pcfg_gpu_prob_buf64[0] = base_off;
  device_param->kernel_params_pcfg_gpu_prob_buf32[1] = struct_cnt;
  device_param->kernel_params_pcfg_gpu_prob_buf64[2] = pws_cnt; // gid_max
  device_param->kernel_params_pcfg_gpu_prob_buf32[3] = num_devices;
  device_param->kernel_params_pcfg_gpu_prob_buf32[4] = hashconfig->pw_max; // pw_max

  if (device_param->is_cuda == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_cuLaunchKernel (hashcat_ctx, device_param->cuda_function_pcfg_gpu_prob, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_pcfg_gpu_prob, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_hipLaunchKernel (hashcat_ctx, device_param->hip_function_pcfg_gpu_prob, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_pcfg_gpu_prob, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    id metal_command_encoder = NULL;
    id metal_command_buffer  = NULL;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param, device_param->metal_pipeline_pcfg_gpu_prob, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    // arg 0-4: buffer pointers (already set with .buf_ptr)
    for (int i = 0; i < 5; i++)
    {
      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, i, device_param->kernel_params_pcfg_gpu_prob[i], NULL, 0) == -1) return -1;
    }

    // arg 5: base_off (u64)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, 5, NULL, device_param->kernel_params_pcfg_gpu_prob[5], sizeof (u64)) == -1) return -1;

    // arg 6: struct_cnt (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, 6, NULL, device_param->kernel_params_pcfg_gpu_prob[6], sizeof (u32)) == -1) return -1;

    // arg 7: gid_max (u64)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, 7, NULL, device_param->kernel_params_pcfg_gpu_prob[7], sizeof (u64)) == -1) return -1;

    // Arg 8: num_devices (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, 8, NULL, (void *) &num_devices, sizeof (u32)) == -1) return -1;

    // Arg 9: pw_max (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, 9, NULL, device_param->kernel_params_pcfg_gpu_prob[9], sizeof (u32)) == -1) return -1;

    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, device_param, metal_command_encoder, metal_command_buffer, 1, global_work_size, local_work_size, &ms) == -1)
    {
      event_log_error (hashcat_ctx, "%s: hc_mtlEncodeComputeCommand() failed", __func__);
      return -1;
    }
  }
  #endif

  if (device_param->is_opencl == true)
  {
    cl_kernel opencl_kernel = device_param->opencl_kernel_pcfg_gpu_prob;

    // arg 5: base_off
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 5, sizeof (cl_ulong), device_param->kernel_params_pcfg_gpu_prob[5]) == -1) return -1;

    // arg 6: struct_cnt
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_uint), device_param->kernel_params_pcfg_gpu_prob[6]) == -1) return -1;

    // arg 7: gid_max
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 7, sizeof (cl_ulong), device_param->kernel_params_pcfg_gpu_prob[7]) == -1) return -1;

    // arg 8: num_devices
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 8, sizeof (cl_uint), device_param->kernel_params_pcfg_gpu_prob[8]) == -1) return -1;

    // arg 9: pw_max
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 9, sizeof (cl_uint), device_param->kernel_params_pcfg_gpu_prob[9]) == -1) return -1;

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1)
    {
      event_log_error (hashcat_ctx, "%s: hc_clEnqueueNDRangeKernel() failed", __func__);
      return -1;
    }
  }

  return 0;
}

int run_kernel_pcfg_gpu_omen (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 base_off, const u32 batch_entry_cnt, const u64 pws_cnt, const u32 num_devices)
{
  const u64 kernel_threads = device_param->kernel_wgs_pcfg_gpu_omen;

  u64 num_elements = pws_cnt;

  // Starting index for dynamic arguments

  u32 arg_idx = device_param->pcfg_kernel_dynamic_arg_start;

  const hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  // Update local buffers for the values

  device_param->kernel_params_pcfg_gpu_omen_buf64[0] = base_off;
  device_param->kernel_params_pcfg_gpu_omen_buf32[1] = batch_entry_cnt;
  device_param->kernel_params_pcfg_gpu_omen_buf64[2] = pws_cnt;
  device_param->kernel_params_pcfg_gpu_omen_buf32[3] = num_devices;
  device_param->kernel_params_pcfg_gpu_omen_buf32[4] = hashconfig->pw_max; // pw_max

  if (device_param->is_cuda == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_cuLaunchKernel (hashcat_ctx, device_param->cuda_function_pcfg_gpu_omen, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_pcfg_gpu_omen, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_hipLaunchKernel (hashcat_ctx, device_param->hip_function_pcfg_gpu_omen, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_pcfg_gpu_omen, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    id metal_command_encoder = NULL;
    id metal_command_buffer  = NULL;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param, device_param->metal_pipeline_pcfg_gpu_omen, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    // Set static args (buffer pointers) - 0 to arg_idx-1
    for (u32 i = 0; i < arg_idx-1; i++)
    {
      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, i, device_param->kernel_params_pcfg_gpu_omen[i], NULL, 0) == -1) return -1;
    }

    // tricky data_buffer_num_parts (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx - 1, NULL, device_param->kernel_params_pcfg_gpu_omen[arg_idx - 1], sizeof (u32)) == -1) return -1;

    // Arg: pws_buf (u64)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx++, NULL, &device_param->kernel_params_pcfg_gpu_omen_buf64[0], sizeof (u64)) == -1) return -1;

    // Arg: batch_entry_cnt (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx++, NULL, &device_param->kernel_params_pcfg_gpu_omen_buf32[1], sizeof (u32)) == -1) return -1;

    // Arg: gid_max (u64)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx++, NULL, &device_param->kernel_params_pcfg_gpu_omen_buf64[2], sizeof (u64)) == -1) return -1;

    // Arg: num_devices (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx++, NULL, &device_param->kernel_params_pcfg_gpu_omen_buf32[3], sizeof (u32)) == -1) return -1;

    // Arg: pw_max (u32)
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, device_param, metal_command_encoder, 0, arg_idx++, NULL, &device_param->kernel_params_pcfg_gpu_omen_buf32[4], sizeof (u32)) == -1) return -1;

    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, device_param, metal_command_encoder, metal_command_buffer, 1, global_work_size, local_work_size, &ms) == -1)
    {
      return -1;
    }
  }
  #endif

  if (device_param->is_opencl == true)
  {
    cl_kernel opencl_kernel = device_param->opencl_kernel_pcfg_gpu_omen;

    // Arg: base_off
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, arg_idx++, sizeof (cl_ulong), &device_param->kernel_params_pcfg_gpu_omen_buf64[0]) == -1) return -1;

    // Arg: batch_entry_cnt
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, arg_idx++, sizeof (cl_uint), &device_param->kernel_params_pcfg_gpu_omen_buf32[1]) == -1) return -1;

    // Arg: gid_max
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, arg_idx++, sizeof (cl_ulong), &device_param->kernel_params_pcfg_gpu_omen_buf64[2]) == -1) return -1;

    // Arg: num_devices
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, arg_idx++, sizeof (cl_uint), &device_param->kernel_params_pcfg_gpu_omen_buf32[3]) == -1) return -1;

    // Arg: pw_max
    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, arg_idx++, sizeof (cl_uint), &device_param->kernel_params_pcfg_gpu_omen_buf32[4]) == -1) return -1;

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1)
    {
      return -1;
    }
  }

  return 0;
}

int backend_session_pcfg_gpu_prob_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t        *backend_ctx = hashcat_ctx->backend_ctx;
  const hashconfig_t   *hashconfig  = hashcat_ctx->hashconfig;
  pcfg_ctx_t           *pcfg_ctx    = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx == NULL || pcfg_ctx->gpu_prob_data == NULL) return -1;

  pcfg_gpu_prob_data_t *lin = pcfg_ctx->gpu_prob_data;

  u64 size_data_buffer = lin->data_buffer_words * sizeof (u32);
  u64 size_term_blocks = lin->term_block_cnt * sizeof (pcfg_term_block_t);
  // alloc one struct memory now
  //u64 size_structure   = sizeof (pcfg_gpu_prob_structure_t);
  // alloc all structs memory now
  u64 size_structure = lin->struct_cnt * sizeof (pcfg_gpu_prob_structure_t);
  u64 size_cumulative = lin->struct_cnt * sizeof (u64);

  const u64 size_total_pcfg = size_data_buffer + size_term_blocks + size_structure + size_cumulative;

  u64 *cumulative_buf = (u64 *) hccalloc (lin->struct_cnt, sizeof (u64));

  for (u32 i = 0; i < lin->struct_cnt; i++)
  {
    cumulative_buf[i] = lin->structures[i].cumulative;
  }

  int active_devices = backend_ctx->backend_devices_active;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    // memory checks
    u64 device_available_mem = device_param->device_available_mem;

    if (backend_ctx_device_get_memory_free (hashcat_ctx, device_param) == 0)
    {
      device_available_mem = device_param->device_available_mem;
    }

    u64 effective_maxmem_alloc     = device_param->device_maxmem_alloc;

    #if defined (__APPLE__)
    if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->is_metal == false) && (is_apple_silicon () == false))
    {
      const u64 undocumented_single_allocation_apple = 0x7fffffff;

      if (effective_maxmem_alloc == 0 || effective_maxmem_alloc > undocumented_single_allocation_apple)
      {
        effective_maxmem_alloc = undocumented_single_allocation_apple;
      }
    }
    #endif

    const u64 device_maxmem_alloc  = effective_maxmem_alloc;

    const u64 safety_margin = PCFG_OMEN_SAFETY_MARGIN_BYTES (device_param->device_global_mem);
    const u64 usable_mem    = (device_available_mem > safety_margin) ? (device_available_mem - safety_margin) : 0;
    // checks if total memory exceeds available GPU memory
    if (size_total_pcfg > usable_mem)
    {
      event_log_warning (hashcat_ctx, "PCFG PROB GPU #%u: Total PCFG buffers (%" PRIu64 " MB) exceed usable GPU memory (%" PRIu64 " MB).", backend_devices_idx + 1, size_total_pcfg / (1024 * 1024), usable_mem / (1024 * 1024));

      device_param->skipped_warning = true;

      active_devices--;

      continue;
    }

    // check if single allocation exceeds max alloc size
    if (device_maxmem_alloc > 0 && size_data_buffer > device_maxmem_alloc)
    {
      event_log_warning (hashcat_ctx, "PCFG PROB GPU #%u: data_buffer (%" PRIu64 " MB) exceeds max single allocation (%" PRIu64 " MB). This allocation is not guaranteed.", backend_devices_idx + 1, size_data_buffer / (1024 * 1024), device_maxmem_alloc / (1024 * 1024));
    }

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer, size_data_buffer) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_term_blocks, size_term_blocks) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_structure,   size_structure)   == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_cumulative,  size_cumulative) == -1) return -1;

      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer, lin->data_buffer, size_data_buffer) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_term_blocks, lin->term_blocks, size_term_blocks) == -1) return -1;

      // copy one struct at time
      //if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_structure, structures_gpu, size_structure) == -1) return -1;
      // copy all structs now
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_structure, lin->structures, size_structure) == -1) return -1;

      // copy all cumulative now
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_cumulative, cumulative_buf, size_cumulative) == -1) return -1;

      device_param->kernel_params_pcfg_gpu_prob[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                   ? &device_param->cuda_d_pws_buf
                                                   : &device_param->cuda_d_pws_amp_buf;
      device_param->kernel_params_pcfg_gpu_prob[1] = &device_param->cuda_d_pcfg_data_buffer;
      device_param->kernel_params_pcfg_gpu_prob[2] = &device_param->cuda_d_pcfg_term_blocks;
      device_param->kernel_params_pcfg_gpu_prob[3] = &device_param->cuda_d_pcfg_structure;
      device_param->kernel_params_pcfg_gpu_prob[4] = &device_param->cuda_d_pcfg_cumulative;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer, size_data_buffer) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_term_blocks, size_term_blocks) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_structure,   size_structure)   == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_cumulative,  size_cumulative)   == -1) return -1;

      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer, lin->data_buffer, size_data_buffer) == -1) return -1;
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_term_blocks, lin->term_blocks, size_term_blocks) == -1) return -1;

      // copy one struct at time
      //if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_structure, structures_gpu, size_structure) == -1) return -1;
      // copy all structs now
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_structure, lin->structures, size_structure) == -1) return -1;

      // copy all cumulative now
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_cumulative, cumulative_buf, size_cumulative) == -1) return -1;

      device_param->kernel_params_pcfg_gpu_prob[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                   ? &device_param->hip_d_pws_buf
                                                   : &device_param->hip_d_pws_amp_buf;
      device_param->kernel_params_pcfg_gpu_prob[1] = &device_param->hip_d_pcfg_data_buffer;
      device_param->kernel_params_pcfg_gpu_prob[2] = &device_param->hip_d_pcfg_term_blocks;
      device_param->kernel_params_pcfg_gpu_prob[3] = &device_param->hip_d_pcfg_structure;
      device_param->kernel_params_pcfg_gpu_prob[4] = &device_param->hip_d_pcfg_cumulative;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_data_buffer, NULL, pcfg_data_buffer);
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_term_blocks, NULL, pcfg_term_blocks);
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_structure, NULL, pcfg_structure);
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_cumulative, NULL, pcfg_cumulative);

      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer, 0, lin->data_buffer, size_data_buffer) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_term_blocks, 0, lin->term_blocks, size_term_blocks) == -1) return -1;

      // copy one struct at time
      //if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_structure, 0, structures_gpu, size_structure) == -1) return -1;
      // copy all structs now
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_structure, 0, lin->structures, size_structure) == -1) return -1;

      // copy all cumulative now
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_cumulative, 0, cumulative_buf, size_cumulative) == -1) return -1;

      device_param->kernel_params_pcfg_gpu_prob[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                   ? device_param->metal_d_pws_buf.buf_ptr
                                                   : device_param->metal_d_pws_amp_buf.buf_ptr;
      device_param->kernel_params_pcfg_gpu_prob[1] = device_param->metal_d_pcfg_data_buffer.buf_ptr;
      device_param->kernel_params_pcfg_gpu_prob[2] = device_param->metal_d_pcfg_term_blocks.buf_ptr;
      device_param->kernel_params_pcfg_gpu_prob[3] = device_param->metal_d_pcfg_structure.buf_ptr;
      device_param->kernel_params_pcfg_gpu_prob[4] = device_param->metal_d_pcfg_cumulative.buf_ptr;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_data_buffer, NULL, pcfg_data_buffer);
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_term_blocks, NULL, pcfg_term_blocks);
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_structure, NULL, pcfg_structure);
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_cumulative, NULL, pcfg_cumulative);

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer, CL_TRUE, 0, size_data_buffer, lin->data_buffer, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_term_blocks, CL_TRUE, 0, size_term_blocks, lin->term_blocks, 0, NULL, NULL) == -1) return -1;

      // copy one struct at time
      //if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_structure, CL_TRUE, 0, size_structure, structures_gpu, 0, NULL, NULL) == -1) return -1;
      // copy all structs now
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_structure, CL_TRUE, 0, size_structure, lin->structures, 0, NULL, NULL) == -1) return -1;

      // copy all cumulative now
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_cumulative, CL_TRUE, 0, size_cumulative, cumulative_buf, 0, NULL, NULL) == -1) return -1;

      device_param->kernel_params_pcfg_gpu_prob[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                   ? &device_param->opencl_d_pws_buf
                                                   : &device_param->opencl_d_pws_amp_buf;
      device_param->kernel_params_pcfg_gpu_prob[1] = &device_param->opencl_d_pcfg_data_buffer;
      device_param->kernel_params_pcfg_gpu_prob[2] = &device_param->opencl_d_pcfg_term_blocks;
      device_param->kernel_params_pcfg_gpu_prob[3] = &device_param->opencl_d_pcfg_structure;
      device_param->kernel_params_pcfg_gpu_prob[4] = &device_param->opencl_d_pcfg_cumulative;

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_prob, 0, sizeof (cl_mem), device_param->kernel_params_pcfg_gpu_prob[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_prob, 1, sizeof (cl_mem), device_param->kernel_params_pcfg_gpu_prob[1]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_prob, 2, sizeof (cl_mem), device_param->kernel_params_pcfg_gpu_prob[2]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_prob, 3, sizeof (cl_mem), device_param->kernel_params_pcfg_gpu_prob[3]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_prob, 4, sizeof (cl_mem), device_param->kernel_params_pcfg_gpu_prob[4]) == -1) return -1;
    }

    device_param->kernel_params_pcfg_gpu_prob[5] = &device_param->kernel_params_pcfg_gpu_prob_buf64[0]; // base_off
    device_param->kernel_params_pcfg_gpu_prob[6] = &device_param->kernel_params_pcfg_gpu_prob_buf32[1]; // struct_cnt
    device_param->kernel_params_pcfg_gpu_prob[7] = &device_param->kernel_params_pcfg_gpu_prob_buf64[2]; // gid_max
    device_param->kernel_params_pcfg_gpu_prob[8] = &device_param->kernel_params_pcfg_gpu_prob_buf32[3]; // num_devices
    device_param->kernel_params_pcfg_gpu_prob[9] = &device_param->kernel_params_pcfg_gpu_prob_buf32[4]; // pw_max
  }

  hcfree (cumulative_buf);

  if (active_devices == 0) return -1;

  return 0;
}
int backend_session_pcfg_gpu_omen_init (hashcat_ctx_t *hashcat_ctx)
{
  user_options_t       *user_options = hashcat_ctx->user_options;
  backend_ctx_t        *backend_ctx  = hashcat_ctx->backend_ctx;
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  pcfg_ctx_t           *pcfg_ctx     = hashcat_ctx->pcfg_ctx;

  if (pcfg_ctx == NULL || pcfg_ctx->omen_gpu_data == NULL) return -1;

  pcfg_gpu_omen_data_t *lin = pcfg_ctx->omen_gpu_data;
  pcfg_model_t *model = pcfg_ctx->model;
  pcfg_omen_extra_t *omen = model->omen_data;

  const u32 struct_cnt = lin->struct_cnt;

  // Calculation of overall limits

  u64 global_min_max_alloc = UINT64_MAX;
  u64 global_min_available = UINT64_MAX;
  u64 global_min_device_global_mem = UINT64_MAX;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    u64 device_available_mem = device_param->device_available_mem;
    u64 device_maxmem_alloc  = device_param->device_maxmem_alloc;

    if (backend_ctx_device_get_memory_free (hashcat_ctx, device_param) == 0)
    {
      device_available_mem = device_param->device_available_mem;
    }

    if (device_maxmem_alloc > device_available_mem) device_maxmem_alloc = device_available_mem;

    #if defined (__APPLE__)
    if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->is_metal == false) && (is_apple_silicon () == false))
    {
      const u64 undocumented_single_allocation_apple = 0x7fffffff;

      if (device_maxmem_alloc == 0 || device_maxmem_alloc > undocumented_single_allocation_apple)
      {
        device_maxmem_alloc = undocumented_single_allocation_apple;
      }
    }
    #endif

    if (device_maxmem_alloc < global_min_max_alloc)
      global_min_max_alloc = device_maxmem_alloc;

    if (device_available_mem < global_min_available)
      global_min_available = device_available_mem;

    if (device_param->device_global_mem < global_min_device_global_mem)
      global_min_device_global_mem = device_param->device_global_mem;
  }

  // data buffer partitioning

  u64 size_data_buffer_total = lin->data_buffer_words * sizeof (u32);

  // calculate parts based on global_min_max_alloc
  u32 num_data_parts = 0;
  u64 data_part_offsets[PCFG_DATA_BUFFER_PARTS_MAX + 1];
  u64 data_part_sizes[PCFG_DATA_BUFFER_PARTS_MAX];

  memset (data_part_sizes, 0, sizeof (data_part_sizes));
  memset (data_part_offsets, 0, sizeof (data_part_offsets));

  if (size_data_buffer_total <= global_min_max_alloc)
  {
    // single part
    num_data_parts = 1;
    data_part_sizes[0] = size_data_buffer_total;
    data_part_offsets[1] = size_data_buffer_total;
  }
  else
  {
    // multi parts: divide by OMEN cost
    // wse term_maps to find natural boundaries
    u64 current_part_size = 0;

    for (u32 cost = 0; cost < 32; cost++)
    {
      // calculate size for this cost
      u64 cost_size = 0;

      for (u32 ty = 0; ty < 256; ty++)
      {
        for (u32 ln = 0; ln < 256; ln++)
        {
          const pcfg_omen_slot_map_t *map = &omen->term_maps[ty][ln];

          if (map->counts[cost] == 0) continue;

          int block_idx = lin->type_len_to_block[ty][ln];

          if (block_idx < 0) continue;

          const pcfg_term_block_t *blk = &lin->term_blocks[block_idx];

          cost_size += (u64) map->counts[cost] * blk->stride_words * sizeof (u32);
        }
      }

      // if adding this cost exceeds max_alloc, close current part
      if (current_part_size + cost_size > global_min_max_alloc && current_part_size > 0)
      {
        if (num_data_parts >= PCFG_DATA_BUFFER_PARTS_MAX)
        {
          event_log_error (hashcat_ctx, "PCFG: Too many data buffer parts needed (max %d)", PCFG_DATA_BUFFER_PARTS_MAX);
          return -1;
        }

        data_part_sizes[num_data_parts] = current_part_size;
        num_data_parts++;
        data_part_offsets[num_data_parts] = data_part_offsets[num_data_parts - 1] + current_part_size;

        current_part_size = cost_size;
      }
      else
      {
        current_part_size += cost_size;
      }
    }

    // Ultima parte
    if (current_part_size > 0)
    {
      if (num_data_parts >= PCFG_DATA_BUFFER_PARTS_MAX)
      {
        event_log_error (hashcat_ctx, "PCFG: Too many data buffer parts needed (max %d)", PCFG_DATA_BUFFER_PARTS_MAX);
        return -1;
      }

      data_part_sizes[num_data_parts] = current_part_size;
      num_data_parts++;
      data_part_offsets[num_data_parts] = data_part_offsets[num_data_parts - 1] + current_part_size;
    }
  }

  for (u32 i = num_data_parts + 1; i <= PCFG_DATA_BUFFER_PARTS_MAX; i++)
  {
    data_part_offsets[i] = data_part_offsets[num_data_parts];
  }
  // save part info in pcfg_ctx for runtime use
  pcfg_ctx->data_buffer_num_parts = num_data_parts;
  // slot_maps setup

  u32 slot_map_cnt = 256 * 256;
  u64 size_slot_maps = slot_map_cnt * sizeof (pcfg_gpu_omen_slot_map_t);

  pcfg_gpu_omen_slot_map_t *slot_maps_gpu = (pcfg_gpu_omen_slot_map_t *) hccalloc (slot_map_cnt, sizeof (pcfg_gpu_omen_slot_map_t));

  if (slot_maps_gpu == NULL)
  {
    event_log_error (hashcat_ctx, "%s: hccalloc slot_maps_gpu (%" PRIu64 " bytes) failed ...", __func__, (u64) slot_map_cnt * sizeof (pcfg_gpu_omen_slot_map_t));
    return -1;
  }

  for (u32 ty = 0; ty < 256; ty++)
  {
    for (u32 ln = 0; ln < 256; ln++)
    {
      u32 idx = (ty << 8) | ln;
      pcfg_omen_slot_map_t *src = &omen->term_maps[ty][ln];
      pcfg_gpu_omen_slot_map_t *dst = &slot_maps_gpu[idx];

      memcpy (dst->ranks, src->ranks, sizeof (dst->ranks));
      memcpy (dst->counts, src->counts, sizeof (dst->counts));
      memcpy (dst->recip, src->recip, sizeof (dst->recip));
    }
  }

  // setup structures with pre-calculated offsets
  pcfg_gpu_omen_structure_t *structures_gpu = (pcfg_gpu_omen_structure_t *) hccalloc (struct_cnt, sizeof (pcfg_gpu_omen_structure_t));

  if (structures_gpu == NULL)
  {
    event_log_error (hashcat_ctx, "! hccalloc() structures_gpu (%" PRIu64 " bytes) failed ...", (u64) struct_cnt * sizeof (pcfg_gpu_omen_slot_map_t));
    hcfree (slot_maps_gpu);
    return -1;
  }

  for (u32 i = 0; i < struct_cnt; i++)
  {
    pcfg_gpu_omen_structure_t *src = &lin->structures[i];
    pcfg_gpu_omen_structure_t *dst = &structures_gpu[i];

    dst->token_cnt = src->token_cnt;
    dst->total_len = src->total_len;

    memcpy (dst->block_indices, src->block_indices, sizeof (dst->block_indices));
    memcpy (dst->types, src->types, sizeof (dst->types));
    memcpy (dst->lengths, src->lengths, sizeof (dst->lengths));

    // pre-calculate byte offsets
    u32 pos = 0;

    for (u32 k = 0; k < src->token_cnt; k++)
    {
      dst->offsets[k] = pos;
      pos += src->lengths[k];
    }
  }

  hc_free_aligned ((void **) &lin->structures);
  lin->structures = structures_gpu;

  // buffer size calculation

  u64 size_term_blocks = lin->term_block_cnt * sizeof (pcfg_term_block_t);
  // static
  const u64 static_overhead = size_slot_maps + size_term_blocks;

  // for max_structs calculation
  const u64 per_struct_cost = sizeof (pcfg_gpu_omen_structure_t) + sizeof (pcfg_gpu_omen_batch_entry_t) + 1024 * sizeof (pcfg_gpu_omen_partition_t);
  // allocation and upload for each GPU

  int active_devices = 0;

  // first calculate global_max_structs
  u64 global_max_structs = UINT64_MAX;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    u64 device_available_mem = device_param->device_available_mem;
    u64 device_maxmem_alloc  = device_param->device_maxmem_alloc;

    if (backend_ctx_device_get_memory_free (hashcat_ctx, device_param) == 0)
    {
      device_available_mem = device_param->device_available_mem;
    }

    if (device_maxmem_alloc > device_available_mem) device_maxmem_alloc = device_available_mem;

    #if defined (__APPLE__)
    if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->is_metal == false) && (is_apple_silicon () == false))
    {
      const u64 undocumented_single_allocation_apple = 0x7fffffff;

      if (device_maxmem_alloc == 0 || device_maxmem_alloc > undocumented_single_allocation_apple)
      {
        device_maxmem_alloc = undocumented_single_allocation_apple;
      }
    }
    #endif

    // memory available for dynamic objects
    u64 used_static = static_overhead + size_data_buffer_total + PCFG_OMEN_SAFETY_MARGIN_BYTES (device_param->device_global_mem);

    if (used_static >= device_available_mem)
    {
      event_log_warning (hashcat_ctx, "PCFG OMEN GPU #%d: Not enough memory for static buffers", backend_devices_idx + 1);
      device_param->skipped_warning = true;
      continue;
    }

    u64 available_for_dynamic = device_available_mem - used_static;

    // max_structs from memory
    u64 mem_max_structs = available_for_dynamic / per_struct_cost;

    // max_structs from max_alloc
    u64 safe_max_alloc = (device_maxmem_alloc * user_options->pcfg_omen_max_alloc_perc) / 100;
    u64 alloc_max_structs = safe_max_alloc / (1024 * sizeof (pcfg_gpu_omen_partition_t));

    u64 gpu_max_structs = (mem_max_structs < alloc_max_structs) ? mem_max_structs : alloc_max_structs;
    if (gpu_max_structs < global_max_structs)
    {
      global_max_structs = gpu_max_structs;
    }

    active_devices++;
  }

  if (active_devices == 0)
  {
    event_log_error (hashcat_ctx, "PCFG OMEN: No devices have enough memory");
    hcfree (slot_maps_gpu);
    return -1;
  }

  // save global_max_structs
  pcfg_ctx->global_max_structs = (u32) global_max_structs;
  // calculate dynamic buffer sizes (based on global_max_structs)
  u64 size_structures_dynamic = global_max_structs * sizeof (pcfg_gpu_omen_structure_t);
  u64 size_batch_entries = global_max_structs * sizeof (pcfg_gpu_omen_batch_entry_t);
  u64 size_partitions = global_max_structs * PCFG_OMEN_PARTITIONS_MAX * sizeof (pcfg_gpu_omen_partition_t);
  u64 part_offsets_size = 8 * sizeof (u64);

  // convert part offsets from bytes to u32 word indices for GPU kernel
  u64 data_part_offsets_words[PCFG_DATA_BUFFER_PARTS_MAX + 1];

  for (u32 i = 0; i <= PCFG_DATA_BUFFER_PARTS_MAX; i++)
  {
    data_part_offsets_words[i] = data_part_offsets[i] / sizeof (u32);
  }
  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    // CUDA

    if (device_param->is_cuda == true)
    {
      // static buffers
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_omen_slot_maps, size_slot_maps) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_omen_slot_maps, slot_maps_gpu, size_slot_maps) == -1) return -1;

      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_term_blocks, size_term_blocks) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_term_blocks, lin->term_blocks, size_term_blocks) == -1) return -1;

      // data_buffer parts
      u8 *src_ptr = NULL;
      u64 dst_size = 0;

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[0];
      dst_size = (u64) (data_part_sizes[0] == 0) ? 1 : data_part_sizes[0];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p1, dst_size) == -1) return -1;
      if (data_part_sizes[0] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p1, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[1];
      dst_size = (u64) (data_part_sizes[1] == 0) ? 1 : data_part_sizes[1];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p2, dst_size) == -1) return -1;
      if (data_part_sizes[1] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p2, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[2];
      dst_size = (u64) (data_part_sizes[2] == 0) ? 1 : data_part_sizes[2];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p3, dst_size) == -1) return -1;
      if (data_part_sizes[2] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p3, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[3];
      dst_size = (u64) (data_part_sizes[3] == 0) ? 1 : data_part_sizes[3];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p4, dst_size) == -1) return -1;
      if (data_part_sizes[3] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p4, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[4];
      dst_size = (u64) (data_part_sizes[4] == 0) ? 1 : data_part_sizes[4];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p5, dst_size) == -1) return -1;
      if (data_part_sizes[4] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p5, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[5];
      dst_size = (u64) (data_part_sizes[5] == 0) ? 1 : data_part_sizes[5];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p6, dst_size) == -1) return -1;
      if (data_part_sizes[5] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p6, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[6];
      dst_size = (u64) (data_part_sizes[6] == 0) ? 1 : data_part_sizes[6];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p7, dst_size) == -1) return -1;
      if (data_part_sizes[6] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p7, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[7];
      dst_size = (u64) (data_part_sizes[7] == 0) ? 1 : data_part_sizes[7];
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_data_buffer_part_p8, dst_size) == -1) return -1;
      if (data_part_sizes[7] > 0)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_data_buffer_part_p8, src_ptr, dst_size) == -1) return -1;
      }


      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_part_offsets, part_offsets_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pcfg_part_offsets, data_part_offsets_words, part_offsets_size) == -1) return -1;

      // dynamic buffers
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_omen_structures, size_structures_dynamic) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_omen_batch_entries, size_batch_entries) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pcfg_omen_partitions, size_partitions) == -1) return -1;

      // setup kernel params array
      u32 param_idx = 0;

      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                             ? &device_param->cuda_d_pws_buf
                                                             : &device_param->cuda_d_pws_amp_buf;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p1;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p2;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p3;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p4;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p5;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p6;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p7;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_data_buffer_part_p8;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_part_offsets;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_term_blocks;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_omen_structures;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_omen_slot_maps;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_omen_batch_entries;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->cuda_d_pcfg_omen_partitions;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &pcfg_ctx->data_buffer_num_parts;

      device_param->pcfg_kernel_dynamic_arg_start = param_idx;
    }

    // HIP

    if (device_param->is_hip == true)
    {
      // static buffers
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_omen_slot_maps, size_slot_maps) == -1) return -1;
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_omen_slot_maps, slot_maps_gpu, size_slot_maps) == -1) return -1;

      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_term_blocks, size_term_blocks) == -1) return -1;
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_term_blocks, lin->term_blocks, size_term_blocks) == -1) return -1;

      // data_buffer parts
      u8 *src_ptr = NULL;
      u64 dst_size = 0;

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[0];
      dst_size = (u64) (data_part_sizes[0] == 0) ? 1 : data_part_sizes[0];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p1, dst_size) == -1) return -1;
      if (data_part_sizes[0] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p1, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[1];
      dst_size = (u64) (data_part_sizes[1] == 0) ? 1 : data_part_sizes[1];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p2, dst_size) == -1) return -1;
      if (data_part_sizes[1] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p2, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[2];
      dst_size = (u64) (data_part_sizes[2] == 0) ? 1 : data_part_sizes[2];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p3, dst_size) == -1) return -1;
      if (data_part_sizes[2] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p3, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[3];
      dst_size = (u64) (data_part_sizes[3] == 0) ? 1 : data_part_sizes[3];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p4, dst_size) == -1) return -1;
      if (data_part_sizes[3] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p4, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[4];
      dst_size = (u64) (data_part_sizes[4] == 0) ? 1 : data_part_sizes[4];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p5, dst_size) == -1) return -1;
      if (data_part_sizes[4] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p5, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[5];
      dst_size = (u64) (data_part_sizes[5] == 0) ? 1 : data_part_sizes[5];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p6, dst_size) == -1) return -1;
      if (data_part_sizes[5] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p6, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[6];
      dst_size = (u64) (data_part_sizes[6] == 0) ? 1 : data_part_sizes[6];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p7, dst_size) == -1) return -1;
      if (data_part_sizes[6] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p7, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[7];
      dst_size = (u64) (data_part_sizes[7] == 0) ? 1 : data_part_sizes[7];
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_data_buffer_part_p8, dst_size) == -1) return -1;
      if (data_part_sizes[7] > 0)
      {
        if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_data_buffer_part_p8, src_ptr, dst_size) == -1) return -1;
      }


      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_part_offsets, part_offsets_size) == -1) return -1;
      if (hc_hipMemcpyHtoD (hashcat_ctx, device_param->hip_d_pcfg_part_offsets, data_part_offsets_words, part_offsets_size) == -1) return -1;

      // dynamic buffers
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_omen_structures, size_structures_dynamic) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_omen_batch_entries, size_batch_entries) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pcfg_omen_partitions, size_partitions) == -1) return -1;

      // setup kernel params array
      u32 param_idx = 0;

      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                             ? &device_param->hip_d_pws_buf
                                                             : &device_param->hip_d_pws_amp_buf;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p1;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p2;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p3;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p4;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p5;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p6;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p7;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_data_buffer_part_p8;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_part_offsets;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_term_blocks;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_omen_structures;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_omen_slot_maps;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_omen_batch_entries;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &device_param->hip_d_pcfg_omen_partitions;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &pcfg_ctx->data_buffer_num_parts;

      device_param->pcfg_kernel_dynamic_arg_start = param_idx;
    }

    // Metal

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      // static buffers
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_slot_maps, NULL, pcfg_omen_slot_maps);
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_omen_slot_maps, 0, slot_maps_gpu, size_slot_maps) == -1) return -1;

      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_term_blocks, NULL, pcfg_term_blocks);
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_term_blocks, 0, lin->term_blocks, size_term_blocks) == -1) return -1;

      // data_buffer parts
      u8 *src_ptr = NULL;
      u64 dst_size = 0;

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[0];
      dst_size = (u64) (data_part_sizes[0] == 0) ? 1 : data_part_sizes[0];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p1);
      if (data_part_sizes[0] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p1, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[1];
      dst_size = (u64) (data_part_sizes[1] == 0) ? 1 : data_part_sizes[1];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p2);
      if (data_part_sizes[1] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p2, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[2];
      dst_size = (u64) (data_part_sizes[2] == 0) ? 1 : data_part_sizes[2];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p3);
      if (data_part_sizes[2] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p3, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[3];
      dst_size = (u64) (data_part_sizes[3] == 0) ? 1 : data_part_sizes[3];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p4);
      if (data_part_sizes[3] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p4, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[4];
      dst_size = (u64) (data_part_sizes[4] == 0) ? 1 : data_part_sizes[4];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p5);
      if (data_part_sizes[4] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p5, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[5];
      dst_size = (u64) (data_part_sizes[5] == 0) ? 1 : data_part_sizes[5];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p6);
      if (data_part_sizes[5] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p6, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[6];
      dst_size = (u64) (data_part_sizes[6] == 0) ? 1 : data_part_sizes[6];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p7);
      if (data_part_sizes[6] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p7, 0, src_ptr, dst_size) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[7];
      dst_size = (u64) (data_part_sizes[7] == 0) ? 1 : data_part_sizes[7];
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p8);
      if (data_part_sizes[7] > 0)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_data_buffer_part_p8, 0, src_ptr, dst_size) == -1) return -1;
      }

      // data_buffer parts

      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, part_offsets_size, NULL, pcfg_part_offsets);
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_command_queue, device_param->metal_d_pcfg_part_offsets, 0, data_part_offsets_words, part_offsets_size) == -1) return -1;

      // dynamic buffers
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_structures_dynamic, NULL, pcfg_omen_structures);
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_batch_entries, NULL, pcfg_omen_batch_entries);
      HC_MTL_CREATEBUFFER(hashcat_ctx, device_param, size_partitions, NULL, pcfg_omen_partitions);

      // setup kernel params
      u32 param_idx = 0;

      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                             ? device_param->metal_d_pws_buf.buf_ptr
                                                             : device_param->metal_d_pws_amp_buf.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p1.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p2.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p3.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p4.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p5.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p6.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p7.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_data_buffer_part_p8.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_part_offsets.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_term_blocks.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_omen_structures.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_omen_slot_maps.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_omen_batch_entries.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = device_param->metal_d_pcfg_omen_partitions.buf_ptr;
      device_param->kernel_params_pcfg_gpu_omen[param_idx++] = &pcfg_ctx->data_buffer_num_parts;

      device_param->pcfg_kernel_dynamic_arg_start = param_idx;
    }
    #endif

    // OpenCL

    if (device_param->is_opencl == true)
    {
      // static buffers
      // slot_maps
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_slot_maps, NULL, pcfg_omen_slot_maps);
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue,
          device_param->opencl_d_pcfg_omen_slot_maps, CL_TRUE, 0, size_slot_maps,
          slot_maps_gpu, 0, NULL, NULL) == -1) return -1;
      // term_blocks
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_term_blocks, NULL, pcfg_term_blocks);

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_term_blocks, CL_TRUE, 0, size_term_blocks, lin->term_blocks, 0, NULL, NULL) == -1) return -1;

      u8 *src_ptr = NULL;
      u64 dst_size = 0;

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[0];
      dst_size = (u64) (data_part_sizes[0] == 0) ? 1 : data_part_sizes[0];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p1);
      if (data_part_sizes[0] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p1, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[1];
      dst_size = (u64) (data_part_sizes[1] == 0) ? 1 : data_part_sizes[1];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p2);
      if (data_part_sizes[1] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p2, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[2];
      dst_size = (u64) (data_part_sizes[2] == 0) ? 1 : data_part_sizes[2];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p3);
      if (data_part_sizes[2] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p3, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[3];
      dst_size = (u64) (data_part_sizes[3] == 0) ? 1 : data_part_sizes[3];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p4);
      if (data_part_sizes[3] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p4, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[4];
      dst_size = (u64) (data_part_sizes[4] == 0) ? 1 : data_part_sizes[4];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p5);
      if (data_part_sizes[4] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p5, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[5];
      dst_size = (u64) (data_part_sizes[5] == 0) ? 1 : data_part_sizes[5];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p6);
      if (data_part_sizes[5] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p6, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[6];
      dst_size = (u64) (data_part_sizes[6] == 0) ? 1 : data_part_sizes[6];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p7);
      if (data_part_sizes[6] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p7, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }

      src_ptr = ((u8 *) lin->data_buffer) + data_part_offsets[7];
      dst_size = (u64) (data_part_sizes[7] == 0) ? 1 : data_part_sizes[7];
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, dst_size, NULL, pcfg_data_buffer_part_p8);
      if (data_part_sizes[7] > 0)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pcfg_data_buffer_part_p8, CL_TRUE, 0, dst_size, src_ptr, 0, NULL, NULL) == -1) return -1;
      }
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, part_offsets_size, NULL, pcfg_part_offsets);

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue,
          device_param->opencl_d_pcfg_part_offsets, CL_TRUE, 0, part_offsets_size,
          data_part_offsets_words, 0, NULL, NULL) == -1) return -1;

      // dynamic buffers
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_structures_dynamic, NULL, pcfg_omen_structures);
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_batch_entries, NULL, pcfg_omen_batch_entries);
      HC_OCL_CREATEBUFFER(hashcat_ctx, device_param, size_partitions, NULL, pcfg_omen_partitions);

      // setup kernel args
      u32 arg_idx = 0;

      // arg 0: pws_buf (pws_amp_buf for OUTSIDE_KERNEL, same pattern as gpu_decompress)
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pws_buf) == -1) return -1;
      }
      else
      {
        if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pws_amp_buf) == -1) return -1;
      }
      // args 1-8: data_buffer_parts
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p1) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p2) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p3) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p4) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p5) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p6) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p7) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_data_buffer_part_p8) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_part_offsets) == -1) return -1;
      // other static buffers
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_term_blocks) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_omen_structures) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_omen_slot_maps) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_omen_batch_entries) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (cl_mem), &device_param->opencl_d_pcfg_omen_partitions) == -1) return -1;
      // num_data_parts
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_pcfg_gpu_omen, arg_idx++, sizeof (u32), &pcfg_ctx->data_buffer_num_parts) == -1) return -1;

      // dynamic arguments will be set at runtime (base_off, batch_cnt, gid_max, etc.)
      device_param->pcfg_kernel_dynamic_arg_start = arg_idx;
    }

    u32 arg_idx = device_param->pcfg_kernel_dynamic_arg_start;

    device_param->kernel_params_pcfg_gpu_omen[arg_idx++] = &device_param->kernel_params_pcfg_gpu_omen_buf64[0]; // base_off
    device_param->kernel_params_pcfg_gpu_omen[arg_idx++] = &device_param->kernel_params_pcfg_gpu_omen_buf32[1]; // struct_cnt
    device_param->kernel_params_pcfg_gpu_omen[arg_idx++] = &device_param->kernel_params_pcfg_gpu_omen_buf64[2]; // gid_max
    device_param->kernel_params_pcfg_gpu_omen[arg_idx++] = &device_param->kernel_params_pcfg_gpu_omen_buf32[3]; // num_devices
    device_param->kernel_params_pcfg_gpu_omen[arg_idx++] = &device_param->kernel_params_pcfg_gpu_omen_buf32[4]; // pw_max
  }

  // cleanup temps
  hcfree (slot_maps_gpu);
  return 0;
}

int backend_session_pcfg_gpu_omen_runtime_init (hashcat_ctx_t *hashcat_ctx)
{
  pcfg_ctx_t *pcfg_ctx = hashcat_ctx->pcfg_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  pcfg_gpu_omen_data_t *lin = pcfg_ctx->omen_gpu_data;
  pcfg_model_t *model = pcfg_ctx->model;

  if (!lin || !model->omen_data) return -1;

  if (user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    u8 *struct_max_term_cost = (u8 *) hccalloc (model->struct_cnt, sizeof (u8));

    if (struct_max_term_cost == NULL)
    {
      event_log_error (hashcat_ctx, "%s: failed to allocate struct_max_term_cost", __func__);
      return -1;
    }

    calculate_struct_max_term_cost (model, struct_max_term_cost);

    pcfg_ctx->analysis_struct_max_term_cost = struct_max_term_cost;
  }

  if (!pcfg_ctx->analysis_struct_max_term_cost)
  {
    event_log_error (hashcat_ctx, "PCFG OMEN RUNTIME: Missing analysis data (max_term_cost)");
    return -1;
  }
  // recalculation of chunking on linearized data
  u32 cost_min = user_options->pcfg_omen_cost_min;
  u32 cost_max = user_options->pcfg_omen_cost_max;
  if (cost_max > PCFG_OMEN_COST_PRACTICAL_MAX) cost_max = PCFG_OMEN_COST_PRACTICAL_MAX;

  u32 max_structs = pcfg_ctx->global_max_structs;

  u32 max_possible_chunks = (cost_max - cost_min + 1) * 2 + 100;

  pcfg_chunk_t *runtime_chunks = (pcfg_chunk_t *) hccalloc (max_possible_chunks, sizeof (pcfg_chunk_t));
  if (!runtime_chunks) return -1;

  u32 rt_chunk_cnt = 0;
  u32 cur_lvl = cost_min;

  // simulate chunking
  while (cur_lvl <= cost_max)
  {
    u32 best_end = cur_lvl;
    u32 best_count = 0;
    bool found = false;

    // try extending the chunk
    for (u32 try_end = cur_lvl; try_end <= cost_max; try_end++)
    {
      // count active structures in the range [cur_lvl, try_end] using linearized data
      u32 count = 0;

      for (u32 i = 0; i < lin->struct_cnt; i++)
      {
        u8 s_cost = lin->struct_costs[i];
        u8 min_term = lin->struct_min_term_cost[i];
        u32 max_term = pcfg_ctx->analysis_struct_max_term_cost[i];

        u32 min_l = s_cost + min_term;
        u32 max_l = s_cost + max_term;
        if (max_l > 300) max_l = 300; // cap

        bool is_active = (min_l <= try_end && max_l >= cur_lvl);

        if (is_active)
        {
          count++;
        }
      }

      if (count == 0 && try_end == cur_lvl)
      {
        // empty cost, skip
        best_end = try_end;
        break;
      }

      if (count > max_structs)
      {
        if (!found)
        {
          // first cost already too large -> sub-batching
          best_end = try_end;
          best_count = count;
          found = true;
        }

        break;
      }

      // valid range
      best_end = try_end;
      best_count = count;
      found = true;
    }

    if (best_count > 0)
    {
      runtime_chunks[rt_chunk_cnt].cost_start    = cur_lvl;
      runtime_chunks[rt_chunk_cnt].cost_end      = best_end;
      runtime_chunks[rt_chunk_cnt].struct_count  = best_count;
      runtime_chunks[rt_chunk_cnt].struct_start  = 0;
      runtime_chunks[rt_chunk_cnt].struct_end    = lin->struct_cnt;

      rt_chunk_cnt++;
    }

    cur_lvl = best_end + 1;
    if (rt_chunk_cnt >= max_possible_chunks) break;
  }
  // CPU BY_STRUCT Classic: split by structure range for multi-device
  if (user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_STRUCT &&
      user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC &&
      rt_chunk_cnt == 1)
  {
    u32 num_active_devices = 0;

    for (int i = 0; i < backend_ctx->backend_devices_cnt; i++)
    {
      if (!backend_ctx->devices_param[i].skipped &&
          !backend_ctx->devices_param[i].skipped_warning)
      {
        num_active_devices++;
      }
    }

    u32 total_structs = lin->struct_cnt;

    if (num_active_devices > 1 && total_structs > 1)
    {
      u32 target_chunks = num_active_devices;
      if (target_chunks > total_structs) target_chunks = total_structs;

      pcfg_chunk_t base = runtime_chunks[0];
      u32 per_chunk = total_structs / target_chunks;
      u32 remainder = total_structs % target_chunks;
      u32 s = 0;

      for (u32 c = 0; c < target_chunks; c++)
      {
        runtime_chunks[c] = base;
        runtime_chunks[c].struct_start = s;

        u32 chunk_size = per_chunk + (c < remainder ? 1 : 0);
        runtime_chunks[c].struct_end = s + chunk_size;

        u32 active = 0;
        for (u32 si = s; si < s + chunk_size; si++)
        {
          u8  sc = lin->struct_costs[si];
          u8  mt = lin->struct_min_term_cost[si];
          u32 mx = pcfg_ctx->analysis_struct_max_term_cost[si];
          u32 min_l = sc + mt;
          u32 max_l = sc + mx;
          if (max_l > 300) max_l = 300;
          if (min_l <= base.cost_end && max_l >= base.cost_start) active++;
        }
        runtime_chunks[c].struct_count = active;
        s += chunk_size;
      }

      rt_chunk_cnt = target_chunks;

      if (user_options->quiet == false)
      {
        event_log_info (hashcat_ctx, "PCFG OMEN CPU BY_STRUCT: Split by structure range for multi-device (%u chunks)", rt_chunk_cnt);
      }
    }
  }

  bool integrity_ok = true;

  // verify that the number of chunks makes sense
  if (rt_chunk_cnt == 0)
  {
    event_log_error (hashcat_ctx, "PCFG OMEN INTEGRITY ERROR: No chunks generated in runtime");
    integrity_ok = false;
  }
  else
  {
    // retrieve the last chunk of the analysis
    if (pcfg_ctx->analysis_num_chunks > 0)
    {
      pcfg_chunk_t *last_analysis_chunk = &pcfg_ctx->analysis_chunks[pcfg_ctx->analysis_num_chunks - 1];

      // verify that the last chunk of the runtime reaches at least that point
      if (rt_chunk_cnt > 0)
      {
        pcfg_chunk_t *last_runtime_chunk = &runtime_chunks[rt_chunk_cnt - 1];

        if (last_runtime_chunk->cost_end < last_analysis_chunk->cost_end)
        {
          event_log_error (hashcat_ctx, "PCFG OMEN INTEGRITY ERROR: Coverage mismatch. Runtime stops at %u, Analysis reached %u", last_runtime_chunk->cost_end, last_analysis_chunk->cost_end);
          integrity_ok = false;
        }
      }
      else
      {
        // if empty runtime but analysis is not, got an error
        integrity_ok = false;
      }
    }
  }

  // informative log if optimization changed the number of chunks (skip for CPU OMEN modes)
  if (integrity_ok && rt_chunk_cnt != pcfg_ctx->analysis_num_chunks
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_COST
      && user_options->pcfg_mode != PCFG_MODE_CPU_OMEN_BY_STRUCT)
  {
    if (user_options->quiet == false)
    {
      event_log_warning (hashcat_ctx, "PCFG OMEN RUNTIME: Chunk layout optimized (Analysis: %u chunks, Runtime: %u chunks)", pcfg_ctx->analysis_num_chunks, rt_chunk_cnt);
    }
  }

  if (!integrity_ok)
  {
    hcfree (runtime_chunks);
    return -1;
  }
  // final runtime initialization
  pcfg_ctx->omen_chunks = runtime_chunks;
  pcfg_ctx->omen_num_chunks = rt_chunk_cnt;

  hc_thread_mutex_init (pcfg_ctx->chunk_mutex);

  // set max_loops
  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_INTERLEAVED)
  {
    pcfg_ctx->omen_max_loops = model->omen_max_loops;

    if (pcfg_ctx->omen_max_loops == 0) pcfg_ctx->omen_max_loops = 1;
  }
  else
  {
    pcfg_ctx->omen_max_loops = 1;
  }

  // set the effective burst size
  u64 effective_burst = lin->burst_size;
  if (user_options->pcfg_omen_type == PCFG_OMEN_TYPE_CLASSIC)
  {
    effective_burst = UINT64_MAX; // infinite for Classic
  }
  else
  {
    // force set only if is the default
    if (user_options->pcfg_burst_size == PCFG_BURST_SIZE)
    {
      // we are in interleaved mode: set burst_size as kernel_power if there's one only active device
      u64 kernel_power_min = UINT64_MAX;

      for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
      {
        hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

        if (device_param->skipped == false && device_param->skipped_warning == false)
        {
          if (device_param->kernel_power < kernel_power_min) kernel_power_min = device_param->kernel_power;
        }
      }

      if (kernel_power_min == UINT64_MAX)
      {
        event_log_error (hashcat_ctx, "%s: BUG! no valid kernel_power/active devices here ...", __func__);
        exit (1);
      }
      else
      {
        effective_burst = kernel_power_min;

        user_options->pcfg_burst_size = kernel_power_min;

        lin->burst_size = kernel_power_min;
      }
    }

  }

  // handle fast skip
  u64 skip = pcfg_ctx->pcfg_skip;

  if (skip > 0)
  {
    pcfg_skip_result_t res;

    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST)
    {
      res = pcfg_gpu_omen_bycost_fast_skip (hashcat_ctx, lin, skip, effective_burst);
    }
    else
    {
      res = pcfg_gpu_omen_bystruct_fast_skip (skip, lin, effective_burst);
    }


    u64 current_loop = res.start_loop;
    u64 skip_left = res.internal_skip;
    u32 target_chunk = 0;
    if (user_options->pcfg_mode == PCFG_MODE_GPU_OMEN_BY_COST || user_options->pcfg_mode == PCFG_MODE_CPU_OMEN_BY_COST)
    {
      u32 target_cost = pcfg_ctx->omen_skip_target_cost;

      // find the chunk that contains target_cost
      for (u32 c = 0; c < rt_chunk_cnt; c++)
      {
        if (target_cost >= runtime_chunks[c].cost_start && target_cost <= runtime_chunks[c].cost_end)
        {
          target_chunk = c;
          break;
        }
      }

      // save target_cost for the run function
      pcfg_ctx->omen_skip_start_cost = target_cost;
    }
    else
    {
      for (u32 c = 0; c < rt_chunk_cnt; c++)
      {
        pcfg_chunk_t *chunk = &runtime_chunks[c];
        u64 chunk_k = 0;

        for (u32 i = 0; i < lin->struct_cnt; i++)
        {
          u8 s_cost = lin->struct_costs[i];
          u8 min_term = lin->struct_min_term_cost[i];
          u32 max_term = pcfg_ctx->analysis_struct_max_term_cost[i];

          u32 min_l = s_cost + min_term;
          u32 max_l = s_cost + max_term;
          if (max_l > 300) max_l = 300;

          if (min_l <= chunk->cost_end && max_l >= chunk->cost_start)
          {
            u64 s_keyspace = model->structures[i].keyspace;
            u64 offset = current_loop * effective_burst;

            if (offset < s_keyspace)
            {
              u64 avail = s_keyspace - offset;
              chunk_k += (avail > effective_burst) ? effective_burst : avail;
            }
          }
        }

        if (skip_left < chunk_k)
        {
          target_chunk = c;
          break;
        }

        skip_left -= chunk_k;
      }
    }

    if (target_chunk == rt_chunk_cnt && skip_left > 0)
    {
      pcfg_ctx->omen_next_work_unit_idx = pcfg_ctx->omen_max_loops * rt_chunk_cnt;


    }
    else
    {
      pcfg_ctx->omen_next_work_unit_idx = current_loop * rt_chunk_cnt + target_chunk;
      pcfg_ctx->omen_skip_remainder = skip_left;


    }

    pcfg_ctx->omen_skip_in_progress = (pcfg_ctx->omen_skip_remainder > 0);
  }
  else
  {
    pcfg_ctx->omen_next_work_unit_idx = 0;
    pcfg_ctx->omen_skip_remainder = 0;


  }

  return 0;
}

// PCFG kernel setup functions

int backend_session_setup_cuda_kernel_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_prob_generate_opti" : "pcfg_gpu_prob_generate";

  if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_pcfg_gpu_prob, device_param->cuda_module_pcfg_gpu_prob, pcfg_kernel_func_name) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_pcfg_gpu_prob, &device_param->kernel_wgs_pcfg_gpu_prob) == -1) return -1;
  if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_pcfg_gpu_prob, &device_param->kernel_local_mem_size_pcfg_gpu_prob) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_prob = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_prob;
  device_param->kernel_preferred_wgs_multiple_pcfg_gpu_prob = device_param->cuda_warp_size;

  return 0;
}

int backend_session_setup_hip_kernel_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_prob_generate_opti" : "pcfg_gpu_prob_generate";

  if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_pcfg_gpu_prob, device_param->hip_module_pcfg_gpu_prob, pcfg_kernel_func_name) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_pcfg_gpu_prob, &device_param->kernel_wgs_pcfg_gpu_prob) == -1) return -1;

  if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_pcfg_gpu_prob, &device_param->kernel_local_mem_size_pcfg_gpu_prob) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_prob = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_prob;

  device_param->kernel_preferred_wgs_multiple_pcfg_gpu_prob = device_param->hip_warp_size;

  return 0;
}

#if defined (__APPLE__)
int backend_session_setup_metal_kernel_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_prob_generate_opti" : "pcfg_gpu_prob_generate";

  if (hc_mtlCreateKernel (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_library_pcfg_gpu_prob, pcfg_kernel_func_name, &device_param->metal_function_pcfg_gpu_prob, &device_param->metal_pipeline_pcfg_gpu_prob) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_metal_kernel_wgs (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_prob, &device_param->kernel_wgs_pcfg_gpu_prob) == -1) return -1;

  if (get_metal_kernel_local_mem_size (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_prob, &device_param->kernel_local_mem_size_pcfg_gpu_prob) == -1) return -1;

  if (get_metal_kernel_preferred_wgs_multiple (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_prob, &device_param->kernel_preferred_wgs_multiple_pcfg_gpu_prob) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_prob = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_prob;

  return 0;
}
#endif // __APPLE__

int backend_session_setup_opencl_kernel_pcfg (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_prob_generate_opti" : "pcfg_gpu_prob_generate";

  if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_pcfg_gpu_prob, pcfg_kernel_func_name, &device_param->opencl_kernel_pcfg_gpu_prob) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_prob, &device_param->kernel_wgs_pcfg_gpu_prob) == -1) return -1;

  if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_prob, &device_param->kernel_local_mem_size_pcfg_gpu_prob) == -1) return -1;

  if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_prob, &device_param->kernel_dynamic_local_mem_size_pcfg_gpu_prob) == -1) return -1;

  if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_prob, &device_param->kernel_preferred_wgs_multiple_pcfg_gpu_prob) == -1) return -1;

  return 0;
}

int backend_session_setup_cuda_kernel_pcfg_omen (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_omen_generate_opti" : "pcfg_gpu_omen_generate";

  if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_pcfg_gpu_omen, device_param->cuda_module_pcfg_gpu_omen, pcfg_kernel_func_name) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_pcfg_gpu_omen, &device_param->kernel_wgs_pcfg_gpu_omen) == -1) return -1;

  if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_pcfg_gpu_omen, &device_param->kernel_local_mem_size_pcfg_gpu_omen) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_omen = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_omen;

  device_param->kernel_preferred_wgs_multiple_pcfg_gpu_omen = device_param->cuda_warp_size;

  return 0;
}

int backend_session_setup_hip_kernel_pcfg_omen (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_omen_generate_opti" : "pcfg_gpu_omen_generate";

  if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_pcfg_gpu_omen, device_param->hip_module_pcfg_gpu_omen, pcfg_kernel_func_name) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_pcfg_gpu_omen, &device_param->kernel_wgs_pcfg_gpu_omen) == -1) return -1;

  if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_pcfg_gpu_omen, &device_param->kernel_local_mem_size_pcfg_gpu_omen) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_omen = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_omen;

  device_param->kernel_preferred_wgs_multiple_pcfg_gpu_omen = device_param->hip_warp_size;

  return 0;
}

#if defined (__APPLE__)
int backend_session_setup_metal_kernel_pcfg_omen (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_omen_generate_opti" : "pcfg_gpu_omen_generate";

  if (hc_mtlCreateKernel (hashcat_ctx, device_param, device_param->metal_device, device_param->metal_library_pcfg_gpu_omen, pcfg_kernel_func_name, &device_param->metal_function_pcfg_gpu_omen, &device_param->metal_pipeline_pcfg_gpu_omen) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_metal_kernel_wgs (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_omen, &device_param->kernel_wgs_pcfg_gpu_omen) == -1) return -1;

  if (get_metal_kernel_local_mem_size (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_omen, &device_param->kernel_local_mem_size_pcfg_gpu_omen) == -1) return -1;

  if (get_metal_kernel_preferred_wgs_multiple (hashcat_ctx, device_param->metal_pipeline_pcfg_gpu_omen, &device_param->kernel_preferred_wgs_multiple_pcfg_gpu_omen) == -1) return -1;

  device_param->kernel_dynamic_local_mem_size_pcfg_gpu_omen = device_param->device_local_mem_size - device_param->kernel_local_mem_size_pcfg_gpu_omen;

  return 0;
}
#endif // __APPLE__

int backend_session_setup_opencl_kernel_pcfg_omen (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  hashconfig_t *hashconfig = hashcat_ctx->hashconfig;

  const char *pcfg_kernel_func_name = (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) ? "pcfg_gpu_omen_generate_opti" : "pcfg_gpu_omen_generate";

  if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_pcfg_gpu_omen, pcfg_kernel_func_name, &device_param->opencl_kernel_pcfg_gpu_omen) == -1)
  {
    event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, pcfg_kernel_func_name);
    device_param->skipped_warning = true;
    return -2;
  }

  if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_omen, &device_param->kernel_wgs_pcfg_gpu_omen) == -1) return -1;

  if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_omen, &device_param->kernel_local_mem_size_pcfg_gpu_omen) == -1) return -1;

  if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_omen, &device_param->kernel_dynamic_local_mem_size_pcfg_gpu_omen) == -1) return -1;

  if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_pcfg_gpu_omen, &device_param->kernel_preferred_wgs_multiple_pcfg_gpu_omen) == -1) return -1;

  return 0;
}
