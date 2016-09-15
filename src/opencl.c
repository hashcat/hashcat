/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "timer.h"
#include "memory.h"
#include "logging.h"
#include "locking.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "ext_OpenCL.h"
#include "cpu_md5.h"
#include "interface.h"
#include "tuningdb.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "thread.h"
#include "status.h"
#include "stdout.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "shared.h"
#include "filehandling.h"
#include "convert.h"
#include "dictstat.h"
#include "wordlist.h"
#include "hash_management.h"

extern hc_global_data_t data;

extern hc_thread_mutex_t mux_counter;

extern const int comptime;

static uint setup_opencl_platforms_filter (const char *opencl_platforms)
{
  uint opencl_platforms_filter = 0;

  if (opencl_platforms)
  {
    char *platforms = mystrdup (opencl_platforms);

    char *next = strtok (platforms, ",");

    do
    {
      int platform = atoi (next);

      if (platform < 1 || platform > 32)
      {
        log_error ("ERROR: Invalid OpenCL platform %u specified", platform);

        exit (-1);
      }

      opencl_platforms_filter |= 1u << (platform - 1);

    } while ((next = strtok (NULL, ",")) != NULL);

    myfree (platforms);
  }
  else
  {
    opencl_platforms_filter = -1u;
  }

  return opencl_platforms_filter;
}

static u32 setup_devices_filter (const char *opencl_devices)
{
  u32 devices_filter = 0;

  if (opencl_devices)
  {
    char *devices = mystrdup (opencl_devices);

    char *next = strtok (devices, ",");

    do
    {
      int device_id = atoi (next);

      if (device_id < 1 || device_id > 32)
      {
        log_error ("ERROR: Invalid device_id %u specified", device_id);

        exit (-1);
      }

      devices_filter |= 1u << (device_id - 1);

    } while ((next = strtok (NULL, ",")) != NULL);

    myfree (devices);
  }
  else
  {
    devices_filter = -1u;
  }

  return devices_filter;
}

static cl_device_type setup_device_types_filter (const char *opencl_device_types)
{
  cl_device_type device_types_filter = 0;

  if (opencl_device_types)
  {
    char *device_types = mystrdup (opencl_device_types);

    char *next = strtok (device_types, ",");

    do
    {
      int device_type = atoi (next);

      if (device_type < 1 || device_type > 3)
      {
        log_error ("ERROR: Invalid device_type %u specified", device_type);

        exit (-1);
      }

      device_types_filter |= 1u << device_type;

    } while ((next = strtok (NULL, ",")) != NULL);

    myfree (device_types);
  }
  else
  {
    // Do not use CPU by default, this often reduces GPU performance because
    // the CPU is too busy to handle GPU synchronization

    device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_CPU;
  }

  return device_types_filter;
}

void load_kernel (const char *kernel_file, int num_devices, size_t *kernel_lengths, const u8 **kernel_sources)
{
  FILE *fp = fopen (kernel_file, "rb");

  if (fp != NULL)
  {
    struct stat st;

    memset (&st, 0, sizeof (st));

    stat (kernel_file, &st);

    u8 *buf = (u8 *) mymalloc (st.st_size + 1);

    size_t num_read = fread (buf, sizeof (u8), st.st_size, fp);

    if (num_read != (size_t) st.st_size)
    {
      log_error ("ERROR: %s: %s", kernel_file, strerror (errno));

      exit (-1);
    }

    fclose (fp);

    buf[st.st_size] = 0;

    for (int i = 0; i < num_devices; i++)
    {
      kernel_lengths[i] = (size_t) st.st_size;

      kernel_sources[i] = buf;
    }
  }
  else
  {
    log_error ("ERROR: %s: %s", kernel_file, strerror (errno));

    exit (-1);
  }

  return;
}

void writeProgramBin (char *dst, u8 *binary, size_t binary_size)
{
  if (binary_size > 0)
  {
    FILE *fp = fopen (dst, "wb");

    lock_file (fp);
    fwrite (binary, sizeof (u8), binary_size, fp);

    fflush (fp);
    fclose (fp);
  }
}

int gidd_to_pw_t (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  cl_int CL_err = hc_clEnqueueReadBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, gidd * sizeof (pw_t), sizeof (pw_t), pw, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int choose_kernel (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint attack_exec, const uint attack_mode, const uint opts_type, const salt_t *salt_buf, const uint highest_pw_len, const uint pws_cnt, const uint fast_iteration)
{
  cl_int CL_err = CL_SUCCESS;

  if (hashconfig->hash_mode == 2000)
  {
    process_stdout (opencl_ctx, device_param, pws_cnt);

    return 0;
  }

  if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (attack_mode == ATTACK_MODE_BF)
    {
      if (opts_type & OPTS_TYPE_PT_BITSLICE)
      {
        const uint size_tm = 32 * sizeof (bs_word_t);

        run_kernel_bzero (opencl_ctx, device_param, device_param->d_tm_c, size_tm);

        run_kernel_tm (opencl_ctx, device_param);

        CL_err = hc_clEnqueueCopyBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_tm_c, device_param->d_bfs_c, 0, 0, size_tm, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
    }

    if (highest_pw_len < 16)
    {
      run_kernel (KERN_RUN_1, opencl_ctx, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
    else if (highest_pw_len < 32)
    {
      run_kernel (KERN_RUN_2, opencl_ctx, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
    else
    {
      run_kernel (KERN_RUN_3, opencl_ctx, device_param, pws_cnt, true, fast_iteration, hashconfig);
    }
  }
  else
  {
    run_kernel_amp (opencl_ctx, device_param, pws_cnt);

    run_kernel (KERN_RUN_1, opencl_ctx, device_param, pws_cnt, false, 0, hashconfig);

    if (opts_type & OPTS_TYPE_HOOK12)
    {
      run_kernel (KERN_RUN_12, opencl_ctx, device_param, pws_cnt, false, 0, hashconfig);

      CL_err = hc_clEnqueueReadBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // do something with data

      CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    uint iter = salt_buf->salt_iter;

    uint loop_step = device_param->kernel_loops;

    for (uint loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
    {
      uint loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      run_kernel (KERN_RUN_2, opencl_ctx, device_param, pws_cnt, true, slow_iteration, hashconfig);

      if (opencl_ctx->devices_status == STATUS_CRACKED) break;
      if (opencl_ctx->devices_status == STATUS_ABORTED) break;
      if (opencl_ctx->devices_status == STATUS_QUIT)    break;
      if (opencl_ctx->devices_status == STATUS_BYPASS)  break;

      /**
       * speed
       */

      const float iter_part = (float) (loop_pos + loop_left) / iter;

      const u64 perf_sum_all = (u64) (pws_cnt * iter_part);

      double speed_ms;

      hc_timer_get (device_param->timer_speed, speed_ms);

      const u32 speed_pos = device_param->speed_pos;

      device_param->speed_cnt[speed_pos] = perf_sum_all;

      device_param->speed_ms[speed_pos] = speed_ms;

      if (data.benchmark == 1)
      {
        if (speed_ms > 4096) opencl_ctx->devices_status = STATUS_ABORTED;
      }
    }

    if (opts_type & OPTS_TYPE_HOOK23)
    {
      run_kernel (KERN_RUN_23, opencl_ctx, device_param, pws_cnt, false, 0, hashconfig);

      CL_err = hc_clEnqueueReadBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      // do something with data

      CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }
    }

    run_kernel (KERN_RUN_3, opencl_ctx, device_param, pws_cnt, false, 0, hashconfig);
  }

  return 0;
}

int run_kernel (const uint kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num, const uint event_update, const uint iteration, hashconfig_t *hashconfig)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  device_param->kernel_params_buf32[33] = data.combs_mode;
  device_param->kernel_params_buf32[34] = num;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_1:    kernel = device_param->kernel1;     break;
    case KERN_RUN_12:   kernel = device_param->kernel12;    break;
    case KERN_RUN_2:    kernel = device_param->kernel2;     break;
    case KERN_RUN_23:   kernel = device_param->kernel23;    break;
    case KERN_RUN_3:    kernel = device_param->kernel3;     break;
  }

  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 24, sizeof (cl_uint), device_param->kernel_params[24]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 25, sizeof (cl_uint), device_param->kernel_params[25]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 26, sizeof (cl_uint), device_param->kernel_params[26]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 27, sizeof (cl_uint), device_param->kernel_params[27]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 28, sizeof (cl_uint), device_param->kernel_params[28]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 29, sizeof (cl_uint), device_param->kernel_params[29]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 30, sizeof (cl_uint), device_param->kernel_params[30]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 31, sizeof (cl_uint), device_param->kernel_params[31]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 32, sizeof (cl_uint), device_param->kernel_params[32]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 33, sizeof (cl_uint), device_param->kernel_params[33]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 34, sizeof (cl_uint), device_param->kernel_params[34]);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  cl_event event;

  if ((hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE) && (data.attack_mode == ATTACK_MODE_BF))
  {
    const size_t global_work_size[3] = { num_elements,        32, 1 };
    const size_t local_work_size[3]  = { kernel_threads / 32, 32, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 2, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else
  {
    if (kern_run == KERN_RUN_2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD)
      {
        num_elements = CEIL (num_elements / device_param->vector_width);
      }
    }

    while (num_elements % kernel_threads) num_elements++;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  CL_err = hc_clFlush (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  if (device_param->nvidia_spin_damp > 0)
  {
    if (opencl_ctx->devices_status == STATUS_RUNNING)
    {
      if (iteration < EXPECTED_ITERATIONS)
      {
        switch (kern_run)
        {
          case KERN_RUN_1: if (device_param->exec_us_prev1[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev1[iteration] * device_param->nvidia_spin_damp)); break;
          case KERN_RUN_2: if (device_param->exec_us_prev2[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev2[iteration] * device_param->nvidia_spin_damp)); break;
          case KERN_RUN_3: if (device_param->exec_us_prev3[iteration] > 0) usleep ((useconds_t)(device_param->exec_us_prev3[iteration] * device_param->nvidia_spin_damp)); break;
        }
      }
    }
  }

  CL_err = hc_clWaitForEvents (opencl_ctx->ocl, 1, &event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clWaitForEvents(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  cl_ulong time_start;
  cl_ulong time_end;

  CL_err |= hc_clGetEventProfilingInfo (opencl_ctx->ocl, event, CL_PROFILING_COMMAND_START, sizeof (time_start), &time_start, NULL);
  CL_err |= hc_clGetEventProfilingInfo (opencl_ctx->ocl, event, CL_PROFILING_COMMAND_END,   sizeof (time_end),   &time_end,   NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clGetEventProfilingInfo(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const double exec_us = (double) (time_end - time_start) / 1000;

  if (opencl_ctx->devices_status == STATUS_RUNNING)
  {
    if (iteration < EXPECTED_ITERATIONS)
    {
      switch (kern_run)
      {
        case KERN_RUN_1: device_param->exec_us_prev1[iteration] = exec_us; break;
        case KERN_RUN_2: device_param->exec_us_prev2[iteration] = exec_us; break;
        case KERN_RUN_3: device_param->exec_us_prev3[iteration] = exec_us; break;
      }
    }
  }

  if (event_update)
  {
    uint exec_pos = device_param->exec_pos;

    device_param->exec_ms[exec_pos] = exec_us / 1000;

    exec_pos++;

    if (exec_pos == EXEC_CACHE)
    {
      exec_pos = 0;
    }

    device_param->exec_pos = exec_pos;
  }

  CL_err = hc_clReleaseEvent (opencl_ctx->ocl, event);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clReleaseEvent(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int run_kernel_mp (const uint kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  switch (kern_run)
  {
    case KERN_RUN_MP:   device_param->kernel_params_mp_buf32[8]   = num; break;
    case KERN_RUN_MP_R: device_param->kernel_params_mp_r_buf32[8] = num; break;
    case KERN_RUN_MP_L: device_param->kernel_params_mp_l_buf32[9] = num; break;
  }

  // causes problems with special threads like in bcrypt
  // const uint kernel_threads = device_param->kernel_threads;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_MP:   kernel = device_param->kernel_mp;   break;
    case KERN_RUN_MP_R: kernel = device_param->kernel_mp_r; break;
    case KERN_RUN_MP_L: kernel = device_param->kernel_mp_l; break;
  }

  switch (kern_run)
  {
    case KERN_RUN_MP:   CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp[3]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp[4]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp[5]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp[6]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp[7]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp[8]);
                        break;
    case KERN_RUN_MP_R: CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_r[3]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_r[4]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_r[5]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_r[6]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_r[7]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_r[8]);
                        break;
    case KERN_RUN_MP_L: CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_l[3]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_l[4]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_l[5]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_l[6]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_l[7]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_l[8]);
                        CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 9, sizeof (cl_uint),  device_param->kernel_params_mp_l[9]);
                        break;
  }

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const size_t global_work_size[3] = { num_elements,   1, 1 };
  const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int run_kernel_tm (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param)
{
  cl_int CL_err = CL_SUCCESS;

  const uint num_elements = 1024; // fixed

  uint kernel_threads = 32;

  cl_kernel kernel = device_param->kernel_tm;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int run_kernel_amp (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  uint num_elements = num;

  device_param->kernel_params_amp_buf32[5] = data.combs_mode;
  device_param->kernel_params_amp_buf32[6] = num_elements;

  // causes problems with special threads like in bcrypt
  // const uint kernel_threads = device_param->kernel_threads;

  uint kernel_threads = device_param->kernel_threads;

  while (num_elements % kernel_threads) num_elements++;

  cl_kernel kernel = device_param->kernel_amp;

  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 5, sizeof (cl_uint), device_param->kernel_params_amp[5]);
  CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 6, sizeof (cl_uint), device_param->kernel_params_amp[6]);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFlush (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  CL_err = hc_clFinish (opencl_ctx->ocl, device_param->command_queue);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int run_kernel_memset (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const uint value, const uint num)
{
  cl_int CL_err = CL_SUCCESS;

  const u32 num16d = num / 16;
  const u32 num16m = num % 16;

  if (num16d)
  {
    device_param->kernel_params_memset_buf32[1] = value;
    device_param->kernel_params_memset_buf32[2] = num16d;

    uint kernel_threads = device_param->kernel_threads;

    uint num_elements = num16d;

    while (num_elements % kernel_threads) num_elements++;

    cl_kernel kernel = device_param->kernel_memset;

    CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 0, sizeof (cl_mem),  (void *) &buf);
    CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 1, sizeof (cl_uint), device_param->kernel_params_memset[1]);
    CL_err |= hc_clSetKernelArg (opencl_ctx->ocl, kernel, 2, sizeof (cl_uint), device_param->kernel_params_memset[2]);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clSetKernelArg(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_err = hc_clEnqueueNDRangeKernel (opencl_ctx->ocl, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueNDRangeKernel(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    CL_err = hc_clFlush (opencl_ctx->ocl, device_param->command_queue);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clFlush(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    CL_err = hc_clFinish (opencl_ctx->ocl, device_param->command_queue);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clFinish(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  if (num16m)
  {
    u32 tmp[4];

    tmp[0] = value;
    tmp[1] = value;
    tmp[2] = value;
    tmp[3] = value;

    CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, buf, CL_TRUE, num16d * 16, num16m, tmp, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }

  return 0;
}

int run_kernel_bzero (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const size_t size)
{
  return run_kernel_memset (opencl_ctx, device_param, buf, 0, size);
}

int run_copy (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint pws_cnt)
{
  cl_int CL_err = CL_SUCCESS;

  if (data.attack_kern == ATTACK_KERN_STRAIGHT)
  {
    CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, 0, pws_cnt * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else if (data.attack_kern == ATTACK_KERN_COMBI)
  {
    if (data.attack_mode == ATTACK_MODE_COMBI)
    {
      if (data.combs_mode == COMBINATOR_MODE_BASE_RIGHT)
      {
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
        {
          for (u32 i = 0; i < pws_cnt; i++)
          {
            const u32 pw_len = device_param->pws_buf[i].pw_len;

            u8 *ptr = (u8 *) device_param->pws_buf[i].i;

            ptr[pw_len] = 0x01;
          }
        }
        else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
        {
          for (u32 i = 0; i < pws_cnt; i++)
          {
            const u32 pw_len = device_param->pws_buf[i].pw_len;

            u8 *ptr = (u8 *) device_param->pws_buf[i].i;

            ptr[pw_len] = 0x80;
          }
        }
      }
    }
    else if (data.attack_mode == ATTACK_MODE_HYBRID2)
    {
      if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
      {
        for (u32 i = 0; i < pws_cnt; i++)
        {
          const u32 pw_len = device_param->pws_buf[i].pw_len;

          u8 *ptr = (u8 *) device_param->pws_buf[i].i;

          ptr[pw_len] = 0x01;
        }
      }
      else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
      {
        for (u32 i = 0; i < pws_cnt; i++)
        {
          const u32 pw_len = device_param->pws_buf[i].pw_len;

          u8 *ptr = (u8 *) device_param->pws_buf[i].i;

          ptr[pw_len] = 0x80;
        }
      }
    }

    CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, 0, pws_cnt * sizeof (pw_t), device_param->pws_buf, 0, NULL, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }
  }
  else if (data.attack_kern == ATTACK_KERN_BF)
  {
    const u64 off = device_param->words_off;

    device_param->kernel_params_mp_l_buf64[3] = off;

    run_kernel_mp (KERN_RUN_MP_L, opencl_ctx, device_param, pws_cnt);
  }

  return 0;
}

int run_cracker (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint pws_cnt)
{
  char *line_buf = (char *) mymalloc (HCBUFSIZ_LARGE);

  // init speed timer

  uint speed_pos = device_param->speed_pos;

  #if defined (_POSIX)
  if (device_param->timer_speed.tv_sec == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #endif

  #if defined (_WIN)
  if (device_param->timer_speed.QuadPart == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #endif

  // find higest password length, this is for optimization stuff

  uint highest_pw_len = 0;

  if (data.attack_kern == ATTACK_KERN_STRAIGHT)
  {
  }
  else if (data.attack_kern == ATTACK_KERN_COMBI)
  {
  }
  else if (data.attack_kern == ATTACK_KERN_BF)
  {
    highest_pw_len = device_param->kernel_params_mp_l_buf32[4]
                   + device_param->kernel_params_mp_l_buf32[5];
  }

  // iteration type

  uint innerloop_step = 0;
  uint innerloop_cnt  = 0;

  if      (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)   innerloop_step = device_param->kernel_loops;
  else                                                             innerloop_step = 1;

  if      (data.attack_kern == ATTACK_KERN_STRAIGHT) innerloop_cnt  = data.kernel_rules_cnt;
  else if (data.attack_kern == ATTACK_KERN_COMBI)    innerloop_cnt  = data.combs_cnt;
  else if (data.attack_kern == ATTACK_KERN_BF)       innerloop_cnt  = data.bfs_cnt;

  // loop start: most outer loop = salt iteration, then innerloops (if multi)

  for (uint salt_pos = 0; salt_pos < data.salts_cnt; salt_pos++)
  {
    while (opencl_ctx->devices_status == STATUS_PAUSED) hc_sleep (1);

    if (opencl_ctx->devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint (opencl_ctx);

    if (opencl_ctx->devices_status == STATUS_CRACKED) break;
    if (opencl_ctx->devices_status == STATUS_ABORTED) break;
    if (opencl_ctx->devices_status == STATUS_QUIT)    break;
    if (opencl_ctx->devices_status == STATUS_BYPASS)  break;

    salt_t *salt_buf = &data.salts_buf[salt_pos];

    device_param->kernel_params_buf32[27] = salt_pos;
    device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
    device_param->kernel_params_buf32[32] = salt_buf->digests_offset;

    FILE *combs_fp = device_param->combs_fp;

    if (data.attack_mode == ATTACK_MODE_COMBI)
    {
      rewind (combs_fp);
    }

    // innerloops

    for (uint innerloop_pos = 0; innerloop_pos < innerloop_cnt; innerloop_pos += innerloop_step)
    {
      while (opencl_ctx->devices_status == STATUS_PAUSED) hc_sleep (1);

      if (opencl_ctx->devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint (opencl_ctx);

      if (opencl_ctx->devices_status == STATUS_CRACKED) break;
      if (opencl_ctx->devices_status == STATUS_ABORTED) break;
      if (opencl_ctx->devices_status == STATUS_QUIT)    break;
      if (opencl_ctx->devices_status == STATUS_BYPASS)  break;

      uint fast_iteration = 0;

      uint innerloop_left = innerloop_cnt - innerloop_pos;

      if (innerloop_left > innerloop_step)
      {
        innerloop_left = innerloop_step;

        fast_iteration = 1;
      }

      device_param->innerloop_pos  = innerloop_pos;
      device_param->innerloop_left = innerloop_left;

      device_param->kernel_params_buf32[30] = innerloop_left;

      // i think we can get rid of this
      if (innerloop_left == 0)
      {
        puts ("bug, how should this happen????\n");

        continue;
      }

      if (data.salts_shown[salt_pos] == 1)
      {
        data.words_progress_done[salt_pos] += (u64) pws_cnt * (u64) innerloop_left;

        continue;
      }

      // initialize amplifiers

      if (data.attack_mode == ATTACK_MODE_COMBI)
      {
        uint i = 0;

        while (i < innerloop_left)
        {
          if (feof (combs_fp)) break;

          int line_len = fgetl (combs_fp, line_buf);

          if (line_len >= PW_MAX1) continue;

          line_len = convert_from_hex (line_buf, line_len);

          char *line_buf_new = line_buf;

          if (run_rule_engine (data.rule_len_r, data.rule_buf_r))
          {
            char rule_buf_out[BLOCK_SIZE] = { 0 };

            int rule_len_out = _old_apply_rule (data.rule_buf_r, data.rule_len_r, line_buf, line_len, rule_buf_out);

            if (rule_len_out < 0)
            {
              data.words_progress_rejected[salt_pos] += pws_cnt;

              continue;
            }

            line_len = rule_len_out;

            line_buf_new = rule_buf_out;
          }

          line_len = MIN (line_len, PW_DICTMAX);

          u8 *ptr = (u8 *) device_param->combs_buf[i].i;

          memcpy (ptr, line_buf_new, line_len);

          memset (ptr + line_len, 0, PW_DICTMAX1 - line_len);

          if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
          {
            uppercase (ptr, line_len);
          }

          if (data.combs_mode == COMBINATOR_MODE_BASE_LEFT)
          {
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
            {
              ptr[line_len] = 0x80;
            }

            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
            {
              ptr[line_len] = 0x01;
            }
          }

          device_param->combs_buf[i].pw_len = line_len;

          i++;
        }

        for (uint j = i; j < innerloop_left; j++)
        {
          device_param->combs_buf[j].i[0] = 0;
          device_param->combs_buf[j].i[1] = 0;
          device_param->combs_buf[j].i[2] = 0;
          device_param->combs_buf[j].i[3] = 0;
          device_param->combs_buf[j].i[4] = 0;
          device_param->combs_buf[j].i[5] = 0;
          device_param->combs_buf[j].i[6] = 0;
          device_param->combs_buf[j].i[7] = 0;

          device_param->combs_buf[j].pw_len = 0;
        }

        innerloop_left = i;
      }
      else if (data.attack_mode == ATTACK_MODE_BF)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_r_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP_R, opencl_ctx, device_param, innerloop_left);
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID1)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP, opencl_ctx, device_param, innerloop_left);
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID2)
      {
        u64 off = innerloop_pos;

        device_param->kernel_params_mp_buf64[3] = off;

        run_kernel_mp (KERN_RUN_MP, opencl_ctx, device_param, innerloop_left);
      }

      // copy amplifiers

      if (data.attack_mode == ATTACK_MODE_STRAIGHT)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_rules, device_param->d_rules_c, innerloop_pos * sizeof (kernel_rule_t), 0, innerloop_left * sizeof (kernel_rule_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_COMBI)
      {
        cl_int CL_err = hc_clEnqueueWriteBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (comb_t), device_param->combs_buf, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueWriteBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_BF)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_bfs, device_param->d_bfs_c, 0, 0, innerloop_left * sizeof (bf_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID1)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (comb_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }
      else if (data.attack_mode == ATTACK_MODE_HYBRID2)
      {
        cl_int CL_err = hc_clEnqueueCopyBuffer (opencl_ctx->ocl, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (comb_t), 0, NULL, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clEnqueueCopyBuffer(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }
      }

      if (data.benchmark == 1)
      {
        hc_timer_set (&device_param->timer_speed);
      }

      int rc = choose_kernel (opencl_ctx, device_param, hashconfig, hashconfig->attack_exec, data.attack_mode, hashconfig->opts_type, salt_buf, highest_pw_len, pws_cnt, fast_iteration);

      if (rc == -1) return -1;

      if (opencl_ctx->devices_status == STATUS_STOP_AT_CHECKPOINT) check_checkpoint (opencl_ctx);

      if (opencl_ctx->devices_status == STATUS_CRACKED) break;
      if (opencl_ctx->devices_status == STATUS_ABORTED) break;
      if (opencl_ctx->devices_status == STATUS_QUIT)    break;
      if (opencl_ctx->devices_status == STATUS_BYPASS)  break;

      /**
       * result
       */

      if (data.benchmark == 0)
      {
        check_cracked (opencl_ctx, device_param, salt_pos, hashconfig);
      }

      /**
       * progress
       */

      u64 perf_sum_all = (u64) pws_cnt * (u64) innerloop_left;

      hc_thread_mutex_lock (mux_counter);

      data.words_progress_done[salt_pos] += perf_sum_all;

      hc_thread_mutex_unlock (mux_counter);

      /**
       * speed
       */

      double speed_ms;

      hc_timer_get (device_param->timer_speed, speed_ms);

      hc_timer_set (&device_param->timer_speed);

      // current speed

      //hc_thread_mutex_lock (mux_display);

      device_param->speed_cnt[speed_pos] = perf_sum_all;

      device_param->speed_ms[speed_pos] = speed_ms;

      //hc_thread_mutex_unlock (mux_display);

      speed_pos++;

      if (speed_pos == SPEED_CACHE)
      {
        speed_pos = 0;
      }

      /**
       * benchmark
       */

      if (data.benchmark == 1) break;
    }
  }

  device_param->speed_pos = speed_pos;

  myfree (line_buf);

  return 0;
}

int opencl_ctx_init (opencl_ctx_t *opencl_ctx, const char *opencl_platforms, const char *opencl_devices, const char *opencl_device_types, const uint opencl_vector_width, const uint opencl_vector_width_chgd, const uint nvidia_spin_damp, const uint nvidia_spin_damp_chgd, const uint workload_profile, const uint kernel_accel, const uint kernel_accel_chgd, const uint kernel_loops, const uint kernel_loops_chgd, const uint keyspace, const uint stdout_flag)
{
  if (keyspace == 1)
  {
    opencl_ctx->disable = 1;

    return 0;
  }

  opencl_ctx->opencl_vector_width_chgd  = opencl_vector_width_chgd;
  opencl_ctx->opencl_vector_width       = opencl_vector_width;
  opencl_ctx->nvidia_spin_damp_chgd     = nvidia_spin_damp_chgd;
  opencl_ctx->nvidia_spin_damp          = nvidia_spin_damp;
  opencl_ctx->kernel_accel_chgd         = kernel_accel_chgd;
  opencl_ctx->kernel_accel              = kernel_accel;
  opencl_ctx->kernel_loops_chgd         = kernel_loops_chgd;
  opencl_ctx->kernel_loops              = kernel_loops;
  opencl_ctx->workload_profile          = workload_profile;

  opencl_ctx->ocl = (OCL_PTR *) mymalloc (sizeof (OCL_PTR));

  hc_device_param_t *devices_param = (hc_device_param_t *) mycalloc (DEVICES_MAX, sizeof (hc_device_param_t));

  opencl_ctx->devices_param = devices_param;

  /**
   * Load and map OpenCL library calls
   * TODO: remove exit() calls in there
   */

  ocl_init (opencl_ctx->ocl);

  /**
   * OpenCL platform selection
   */

  u32 opencl_platforms_filter = setup_opencl_platforms_filter (opencl_platforms);

  opencl_ctx->opencl_platforms_filter = opencl_platforms_filter;

  /**
   * OpenCL device selection
   */

  u32 devices_filter = setup_devices_filter (opencl_devices);

  opencl_ctx->devices_filter = devices_filter;

  /**
   * OpenCL device type selection
   */

  cl_device_type device_types_filter = setup_device_types_filter (opencl_device_types);

  opencl_ctx->device_types_filter = device_types_filter;

  /**
   * OpenCL platforms: detect
   */

  cl_uint         platforms_cnt         = 0;
  cl_platform_id *platforms             = (cl_platform_id *) mycalloc (CL_PLATFORMS_MAX, sizeof (cl_platform_id));
  cl_uint         platform_devices_cnt  = 0;
  cl_device_id   *platform_devices      = (cl_device_id *) mycalloc (DEVICES_MAX, sizeof (cl_device_id));

  cl_int CL_err = hc_clGetPlatformIDs (opencl_ctx->ocl, CL_PLATFORMS_MAX, platforms, &platforms_cnt);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clGetPlatformIDs(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  if (platforms_cnt == 0)
  {
    log_info ("");
    log_info ("ATTENTION! No OpenCL compatible platform found");
    log_info ("");
    log_info ("You're probably missing the OpenCL runtime installation");
    log_info ("  AMD users require AMD drivers 14.9 or later (recommended 15.12 or later)");
    log_info ("  Intel users require Intel OpenCL Runtime 14.2 or later (recommended 15.1 or later)");
    log_info ("  NVidia users require NVidia drivers 346.59 or later (recommended 361.x or later)");
    log_info ("");

    return -1;
  }

  if (opencl_platforms_filter != (uint) -1)
  {
    uint platform_cnt_mask = ~(((uint) -1 >> platforms_cnt) << platforms_cnt);

    if (opencl_platforms_filter > platform_cnt_mask)
    {
      log_error ("ERROR: The platform selected by the --opencl-platforms parameter is larger than the number of available platforms (%d)", platforms_cnt);

      return -1;
    }
  }

  if (opencl_device_types == NULL)
  {
    /**
     * OpenCL device types:
     *   In case the user did not specify --opencl-device-types and the user runs hashcat in a system with only a CPU only he probably want to use that CPU.
     */

    cl_device_type device_types_all = 0;

    for (uint platform_id = 0; platform_id < platforms_cnt; platform_id++)
    {
      if ((opencl_platforms_filter & (1u << platform_id)) == 0) continue;

      cl_platform_id platform = platforms[platform_id];

      cl_int CL_err = hc_clGetDeviceIDs (opencl_ctx->ocl, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

      if (CL_err != CL_SUCCESS)
      {
        //log_error ("ERROR: clGetDeviceIDs(): %s\n", val2cstr_cl (CL_err));

        //return -1;

        // Silently ignore at this point, it will be reused later and create a note for the user at that point

        continue;
      }

      for (uint platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
      {
        cl_device_id device = platform_devices[platform_devices_id];

        cl_device_type device_type;

        cl_int CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

        if (CL_err != CL_SUCCESS)
        {
          log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

          return -1;
        }

        device_types_all |= device_type;
      }
    }

    // In such a case, automatically enable CPU device type support, since it's disabled by default.

    if ((device_types_all & (CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR)) == 0)
    {
      device_types_filter |= CL_DEVICE_TYPE_CPU;
    }

    // In another case, when the user uses --stdout, using CPU devices is much faster to setup
    // If we have a CPU device, force it to be used

    if (stdout_flag == 1)
    {
      if (device_types_all & CL_DEVICE_TYPE_CPU)
      {
        device_types_filter = CL_DEVICE_TYPE_CPU;
      }
    }
  }

  opencl_ctx->platforms_cnt         = platforms_cnt;
  opencl_ctx->platforms             = platforms;
  opencl_ctx->platform_devices_cnt  = platform_devices_cnt;
  opencl_ctx->platform_devices      = platform_devices;

  return 0;
}

void opencl_ctx_destroy (opencl_ctx_t *opencl_ctx)
{
  if (opencl_ctx->disable == 1) return;

  myfree (opencl_ctx->devices_param);

  ocl_close (opencl_ctx->ocl);

  myfree (opencl_ctx->ocl);

  myfree (opencl_ctx->platforms);

  myfree (opencl_ctx->platform_devices);

  myfree (opencl_ctx);
}

int opencl_ctx_devices_init (opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig, const tuning_db_t *tuning_db, const uint attack_mode, const uint quiet, const uint force, const uint benchmark, const uint machine_readable, const uint algorithm_pos)
{
  if (opencl_ctx->disable == 1) return 0;

  /**
   * OpenCL devices: simply push all devices from all platforms into the same device array
   */

  cl_uint         platforms_cnt         = opencl_ctx->platforms_cnt;
  cl_platform_id *platforms             = opencl_ctx->platforms;
  cl_uint         platform_devices_cnt  = opencl_ctx->platform_devices_cnt;
  cl_device_id   *platform_devices      = opencl_ctx->platform_devices;

  int need_adl     = 0;
  int need_nvml    = 0;
  int need_nvapi   = 0;
  int need_xnvctrl = 0;

  u32 devices_cnt = 0;

  u32 devices_active = 0;

  for (uint platform_id = 0; platform_id < platforms_cnt; platform_id++)
  {
    cl_int CL_err = CL_SUCCESS;

    cl_platform_id platform = platforms[platform_id];

    char platform_vendor[HCBUFSIZ_TINY] = { 0 };

    CL_err = hc_clGetPlatformInfo (opencl_ctx->ocl, platform, CL_PLATFORM_VENDOR, sizeof (platform_vendor), platform_vendor, NULL);

    if (CL_err != CL_SUCCESS)
    {
      log_error ("ERROR: clGetPlatformInfo(): %s\n", val2cstr_cl (CL_err));

      return -1;
    }

    // find our own platform vendor because pocl and mesa are pushing original vendor_id through opencl
    // this causes trouble with vendor id based macros
    // we'll assign generic to those without special optimization available

    cl_uint platform_vendor_id = 0;

    if (strcmp (platform_vendor, CL_VENDOR_AMD) == 0)
    {
      platform_vendor_id = VENDOR_ID_AMD;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
    {
      platform_vendor_id = VENDOR_ID_AMD_USE_INTEL;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_APPLE) == 0)
    {
      platform_vendor_id = VENDOR_ID_APPLE;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
    {
      platform_vendor_id = VENDOR_ID_INTEL_BEIGNET;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_INTEL_SDK) == 0)
    {
      platform_vendor_id = VENDOR_ID_INTEL_SDK;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_MESA) == 0)
    {
      platform_vendor_id = VENDOR_ID_MESA;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_NV) == 0)
    {
      platform_vendor_id = VENDOR_ID_NV;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_POCL) == 0)
    {
      platform_vendor_id = VENDOR_ID_POCL;
    }
    else
    {
      platform_vendor_id = VENDOR_ID_GENERIC;
    }

    uint platform_skipped = ((opencl_ctx->opencl_platforms_filter & (1u << platform_id)) == 0);

    CL_err = hc_clGetDeviceIDs (opencl_ctx->ocl, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

    if (CL_err != CL_SUCCESS)
    {
      //log_error ("ERROR: clGetDeviceIDs(): %s\n", val2cstr_cl (CL_err));

      //return -1;

      platform_skipped = 2;
    }

    if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
    {
      if (machine_readable == 0)
      {
        if (platform_skipped == 0)
        {
          const int len = log_info ("OpenCL Platform #%u: %s", platform_id + 1, platform_vendor);

          char line[256] = { 0 };

          for (int i = 0; i < len; i++) line[i] = '=';

          log_info (line);
        }
        else if (platform_skipped == 1)
        {
          log_info ("OpenCL Platform #%u: %s, skipped", platform_id + 1, platform_vendor);
          log_info ("");
        }
        else if (platform_skipped == 2)
        {
          log_info ("OpenCL Platform #%u: %s, skipped! No OpenCL compatible devices found", platform_id + 1, platform_vendor);
          log_info ("");
        }
      }
    }

    if (platform_skipped == 1) continue;
    if (platform_skipped == 2) continue;

    hc_device_param_t *devices_param = opencl_ctx->devices_param;

    for (uint platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
    {
      size_t param_value_size = 0;

      const uint device_id = devices_cnt;

      hc_device_param_t *device_param = &devices_param[device_id];

      device_param->platform_vendor_id = platform_vendor_id;

      device_param->device = platform_devices[platform_devices_id];

      device_param->device_id = device_id;

      device_param->platform_devices_id = platform_devices_id;

      device_param->platform = platform;

      // device_type

      cl_device_type device_type;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_type &= ~CL_DEVICE_TYPE_DEFAULT;

      device_param->device_type = device_type;

      // device_name

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_NAME, 0, NULL, &param_value_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *device_name = (char *) mymalloc (param_value_size);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_NAME, param_value_size, device_name, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_name = device_name;

      // device_vendor

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_VENDOR, 0, NULL, &param_value_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *device_vendor = (char *) mymalloc (param_value_size);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_VENDOR, param_value_size, device_vendor, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_vendor = device_vendor;

      cl_uint device_vendor_id = 0;

      if (strcmp (device_vendor, CL_VENDOR_AMD) == 0)
      {
        device_vendor_id = VENDOR_ID_AMD;
      }
      else if (strcmp (device_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
      {
        device_vendor_id = VENDOR_ID_AMD_USE_INTEL;
      }
      else if (strcmp (device_vendor, CL_VENDOR_APPLE) == 0)
      {
        device_vendor_id = VENDOR_ID_APPLE;
      }
      else if (strcmp (device_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
      {
        device_vendor_id = VENDOR_ID_INTEL_BEIGNET;
      }
      else if (strcmp (device_vendor, CL_VENDOR_INTEL_SDK) == 0)
      {
        device_vendor_id = VENDOR_ID_INTEL_SDK;
      }
      else if (strcmp (device_vendor, CL_VENDOR_MESA) == 0)
      {
        device_vendor_id = VENDOR_ID_MESA;
      }
      else if (strcmp (device_vendor, CL_VENDOR_NV) == 0)
      {
        device_vendor_id = VENDOR_ID_NV;
      }
      else if (strcmp (device_vendor, CL_VENDOR_POCL) == 0)
      {
        device_vendor_id = VENDOR_ID_POCL;
      }
      else
      {
        device_vendor_id = VENDOR_ID_GENERIC;
      }

      device_param->device_vendor_id = device_vendor_id;

      // device_version

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_VERSION, 0, NULL, &param_value_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *device_version = (char *) mymalloc (param_value_size);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_VERSION, param_value_size, device_version, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_version = device_version;

      // device_opencl_version

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &param_value_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *device_opencl_version = (char *) mymalloc (param_value_size);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_OPENCL_C_VERSION, param_value_size, device_opencl_version, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->opencl_v12 = device_opencl_version[9] > '1' || device_opencl_version[11] >= '2';

      myfree (device_opencl_version);

      // vector_width

      cl_uint vector_width;

      if (opencl_ctx->opencl_vector_width_chgd == 0)
      {
        // tuning db

        tuning_db_entry_t *tuningdb_entry = tuning_db_search (tuning_db, device_param->device_name, device_param->device_type, attack_mode, hashconfig->hash_mode);

        if (tuningdb_entry == NULL || tuningdb_entry->vector_width == -1)
        {
          if (hashconfig->opti_type & OPTI_TYPE_USES_BITS_64)
          {
            CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, sizeof (vector_width), &vector_width, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
          else
          {
            CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,  sizeof (vector_width), &vector_width, NULL);

            if (CL_err != CL_SUCCESS)
            {
              log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

              return -1;
            }
          }
        }
        else
        {
          vector_width = (cl_uint) tuningdb_entry->vector_width;
        }
      }
      else
      {
        vector_width = opencl_ctx->opencl_vector_width;
      }

      if (vector_width > 16) vector_width = 16;

      device_param->vector_width = vector_width;

      // max_compute_units

      cl_uint device_processors;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof (device_processors), &device_processors, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_processors = device_processors;

      // device_maxmem_alloc
      // note we'll limit to 2gb, otherwise this causes all kinds of weird errors because of possible integer overflows in opencl runtimes

      cl_ulong device_maxmem_alloc;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof (device_maxmem_alloc), &device_maxmem_alloc, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_maxmem_alloc = MIN (device_maxmem_alloc, 0x7fffffff);

      // device_global_mem

      cl_ulong device_global_mem;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof (device_global_mem), &device_global_mem, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_global_mem = device_global_mem;

      // max_work_group_size

      size_t device_maxworkgroup_size;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof (device_maxworkgroup_size), &device_maxworkgroup_size, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      cl_uint device_maxclock_frequency;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof (device_maxclock_frequency), &device_maxclock_frequency, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->device_maxclock_frequency = device_maxclock_frequency;

      // device_endian_little

      cl_bool device_endian_little;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_ENDIAN_LITTLE, sizeof (device_endian_little), &device_endian_little, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_endian_little == CL_FALSE)
      {
        log_info ("- Device #%u: WARNING: Not a little endian device", device_id + 1);

        device_param->skipped = 1;
      }

      // device_available

      cl_bool device_available;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_AVAILABLE, sizeof (device_available), &device_available, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_available == CL_FALSE)
      {
        log_info ("- Device #%u: WARNING: Device not available", device_id + 1);

        device_param->skipped = 1;
      }

      // device_compiler_available

      cl_bool device_compiler_available;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_COMPILER_AVAILABLE, sizeof (device_compiler_available), &device_compiler_available, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_compiler_available == CL_FALSE)
      {
        log_info ("- Device #%u: WARNING: No compiler available for device", device_id + 1);

        device_param->skipped = 1;
      }

      // device_execution_capabilities

      cl_device_exec_capabilities device_execution_capabilities;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_EXECUTION_CAPABILITIES, sizeof (device_execution_capabilities), &device_execution_capabilities, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if ((device_execution_capabilities & CL_EXEC_KERNEL) == 0)
      {
        log_info ("- Device #%u: WARNING: Device does not support executing kernels", device_id + 1);

        device_param->skipped = 1;
      }

      // device_extensions

      size_t device_extensions_size;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_EXTENSIONS, 0, NULL, &device_extensions_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *device_extensions = mymalloc (device_extensions_size + 1);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_EXTENSIONS, device_extensions_size, device_extensions, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (strstr (device_extensions, "base_atomics") == 0)
      {
        log_info ("- Device #%u: WARNING: Device does not support base atomics", device_id + 1);

        device_param->skipped = 1;
      }

      if (strstr (device_extensions, "byte_addressable_store") == 0)
      {
        log_info ("- Device #%u: WARNING: Device does not support byte addressable store", device_id + 1);

        device_param->skipped = 1;
      }

      myfree (device_extensions);

      // device_local_mem_size

      cl_ulong device_local_mem_size;

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof (device_local_mem_size), &device_local_mem_size, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      if (device_local_mem_size < 32768)
      {
        log_info ("- Device #%u: WARNING: Device local mem size is too small", device_id + 1);

        device_param->skipped = 1;
      }

      // If there's both an Intel CPU and an AMD OpenCL runtime it's a tricky situation
      // Both platforms support CPU device types and therefore both will try to use 100% of the physical resources
      // This results in both utilizing it for 50%
      // However, Intel has much better SIMD control over their own hardware
      // It makes sense to give them full control over their own hardware

      if (device_type & CL_DEVICE_TYPE_CPU)
      {
        if (device_param->device_vendor_id == VENDOR_ID_AMD_USE_INTEL)
        {
          if (force == 0)
          {
            if (algorithm_pos == 0)
            {
              log_info ("- Device #%u: WARNING: Not a native Intel OpenCL runtime, expect massive speed loss", device_id + 1);
              log_info ("             You can use --force to override this but do not post error reports if you do so");
            }

            device_param->skipped = 1;
          }
        }
      }

      // skipped

      device_param->skipped |= ((opencl_ctx->devices_filter      & (1u << device_id)) == 0);
      device_param->skipped |= ((opencl_ctx->device_types_filter & (device_type))    == 0);

      // driver_version

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DRIVER_VERSION, 0, NULL, &param_value_size);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      char *driver_version = (char *) mymalloc (param_value_size);

      CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DRIVER_VERSION, param_value_size, driver_version, NULL);

      if (CL_err != CL_SUCCESS)
      {
        log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

        return -1;
      }

      device_param->driver_version = driver_version;

      // device_name_chksum

      char *device_name_chksum = (char *) mymalloc (HCBUFSIZ_TINY);

      #if defined (__x86_64__)
      snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%u-%u-%u-%s-%s-%s-%u", 64, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, comptime);
      #else
      snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%u-%u-%u-%s-%s-%s-%u", 32, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, comptime);
      #endif

      uint device_name_digest[4] = { 0 };

      md5_64 ((uint *) device_name_chksum, device_name_digest);

      snprintf (device_name_chksum, HCBUFSIZ_TINY - 1, "%08x", device_name_digest[0]);

      device_param->device_name_chksum = device_name_chksum;

      // vendor specific

      if (device_param->device_type & CL_DEVICE_TYPE_GPU)
      {
        if ((device_param->platform_vendor_id == VENDOR_ID_AMD) && (device_param->device_vendor_id == VENDOR_ID_AMD))
        {
          need_adl = 1;
        }

        if ((device_param->platform_vendor_id == VENDOR_ID_NV) && (device_param->device_vendor_id == VENDOR_ID_NV))
        {
          need_nvml = 1;

          #if defined (__linux__)
          need_xnvctrl = 1;
          #endif

          #if defined (_WIN)
          need_nvapi = 1;
          #endif
        }
      }

      if (device_type & CL_DEVICE_TYPE_GPU)
      {
        if (device_vendor_id == VENDOR_ID_NV)
        {
          cl_uint kernel_exec_timeout = 0;

          #define CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV            0x4005

          CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV, sizeof (kernel_exec_timeout), &kernel_exec_timeout, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          device_param->kernel_exec_timeout = kernel_exec_timeout;

          cl_uint sm_minor = 0;
          cl_uint sm_major = 0;

          #define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
          #define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001

          CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof (sm_minor), &sm_minor, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          CL_err = hc_clGetDeviceInfo (opencl_ctx->ocl, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof (sm_major), &sm_major, NULL);

          if (CL_err != CL_SUCCESS)
          {
            log_error ("ERROR: clGetDeviceInfo(): %s\n", val2cstr_cl (CL_err));

            return -1;
          }

          device_param->sm_minor = sm_minor;
          device_param->sm_major = sm_major;

          // CPU burning loop damper
          // Value is given as number between 0-100
          // By default 100%

          device_param->nvidia_spin_damp = (double) opencl_ctx->nvidia_spin_damp;

          if (opencl_ctx->nvidia_spin_damp_chgd == 0)
          {
            if (attack_mode == ATTACK_MODE_STRAIGHT)
            {
              /**
               * the workaround is not a friend of rule based attacks
               * the words from the wordlist combined with fast and slow rules cause
               * fluctuations which cause inaccurate wait time estimations
               * using a reduced damping percentage almost compensates this
               */

              device_param->nvidia_spin_damp = 64;
            }
          }

          device_param->nvidia_spin_damp /= 100;
        }
      }

      // display results

      if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
      {
        if (machine_readable == 0)
        {
          if (device_param->skipped == 0)
          {
            log_info ("- Device #%u: %s, %lu/%lu MB allocatable, %uMCU",
                      device_id + 1,
                      device_name,
                      (unsigned int) (device_maxmem_alloc / 1024 / 1024),
                      (unsigned int) (device_global_mem   / 1024 / 1024),
                      (unsigned int)  device_processors);
          }
          else
          {
            log_info ("- Device #%u: %s, skipped",
                      device_id + 1,
                      device_name);
          }
        }
      }

      // common driver check

      if (device_param->skipped == 0)
      {
        if (device_type & CL_DEVICE_TYPE_GPU)
        {
          if (platform_vendor_id == VENDOR_ID_AMD)
          {
            int catalyst_check = (force == 1) ? 0 : 1;

            int catalyst_warn = 0;

            int catalyst_broken = 0;

            if (catalyst_check == 1)
            {
              catalyst_warn = 1;

              // v14.9 and higher
              if (atoi (device_param->driver_version) >= 1573)
              {
                catalyst_warn = 0;
              }

              catalyst_check = 0;
            }

            if (catalyst_broken == 1)
            {
              log_info ("");
              log_info ("ATTENTION! The Catalyst driver installed on your system is known to be broken!");
              log_info ("It passes over cracked hashes and will not report them as cracked");
              log_info ("You are STRONGLY encouraged not to use it");
              log_info ("You can use --force to override this but do not post error reports if you do so");
              log_info ("");

              return -1;
            }

            if (catalyst_warn == 1)
            {
              log_info ("");
              log_info ("ATTENTION! Unsupported or incorrectly installed Catalyst driver detected!");
              log_info ("You are STRONGLY encouraged to use the official supported catalyst driver");
              log_info ("See hashcat's homepage for official supported catalyst drivers");
              #if defined (_WIN)
              log_info ("Also see: http://hashcat.net/wiki/doku.php?id=upgrading_amd_drivers_how_to");
              #endif
              log_info ("You can use --force to override this but do not post error reports if you do so");
              log_info ("");

              return -1;
            }
          }
          else if (platform_vendor_id == VENDOR_ID_NV)
          {
            if (device_param->kernel_exec_timeout != 0)
            {
              if (quiet == 0) log_info ("- Device #%u: WARNING! Kernel exec timeout is not disabled, it might cause you errors of code 702", device_id + 1);
              if (quiet == 0) log_info ("             See the wiki on how to disable it: https://hashcat.net/wiki/doku.php?id=timeout_patch");
            }
          }
        }

        /* turns out pocl still creates segfaults (because of llvm)
        if (device_type & CL_DEVICE_TYPE_CPU)
        {
          if (platform_vendor_id == VENDOR_ID_AMD)
          {
            if (force == 0)
            {
              log_info ("");
              log_info ("ATTENTION! OpenCL support for CPU of catalyst driver is not reliable.");
              log_info ("You are STRONGLY encouraged not to use it");
              log_info ("You can use --force to override this but do not post error reports if you do so");
              log_info ("A good alternative is the free pocl >= v0.13, but make sure to use a LLVM >= v3.8");
              log_info ("");

              return -1;
            }
          }
        }
        */

        /**
         * kernel accel and loops tuning db adjustment
         */

        device_param->kernel_accel_min = 1;
        device_param->kernel_accel_max = 1024;

        device_param->kernel_loops_min = 1;
        device_param->kernel_loops_max = 1024;

        tuning_db_entry_t *tuningdb_entry = tuning_db_search (tuning_db, device_param->device_name, device_param->device_type, attack_mode, hashconfig->hash_mode);

        if (tuningdb_entry != NULL)
        {
          u32 _kernel_accel = tuningdb_entry->kernel_accel;
          u32 _kernel_loops = tuningdb_entry->kernel_loops;

          if (_kernel_accel)
          {
            device_param->kernel_accel_min = _kernel_accel;
            device_param->kernel_accel_max = _kernel_accel;
          }

          if (_kernel_loops)
          {
            if (opencl_ctx->workload_profile == 1)
            {
              _kernel_loops = (_kernel_loops > 8) ? _kernel_loops / 8 : 1;
            }
            else if (opencl_ctx->workload_profile == 2)
            {
              _kernel_loops = (_kernel_loops > 4) ? _kernel_loops / 4 : 1;
            }

            device_param->kernel_loops_min = _kernel_loops;
            device_param->kernel_loops_max = _kernel_loops;
          }
        }

        // commandline parameters overwrite tuningdb entries

        if (opencl_ctx->kernel_accel_chgd == 1)
        {
          device_param->kernel_accel_min = opencl_ctx->kernel_accel;
          device_param->kernel_accel_max = opencl_ctx->kernel_accel;
        }

        if (opencl_ctx->kernel_loops_chgd == 1)
        {
          device_param->kernel_loops_min = opencl_ctx->kernel_loops;
          device_param->kernel_loops_max = opencl_ctx->kernel_loops;
        }

        /**
         * activate device
         */

        devices_active++;
      }

      // next please

      devices_cnt++;
    }

    if ((benchmark == 1 || quiet == 0) && (algorithm_pos == 0))
    {
      if (machine_readable == 0)
      {
        log_info ("");
      }
    }
  }

  if (devices_active == 0)
  {
    log_error ("ERROR: No devices found/left");

    return -1;
  }

  // additional check to see if the user has chosen a device that is not within the range of available devices (i.e. larger than devices_cnt)

  if (opencl_ctx->devices_filter != (uint) -1)
  {
    const uint devices_cnt_mask = ~(((uint) -1 >> devices_cnt) << devices_cnt);

    if (opencl_ctx->devices_filter > devices_cnt_mask)
    {
      log_error ("ERROR: The device specified by the --opencl-devices parameter is larger than the number of available devices (%d)", devices_cnt);

      return -1;
    }
  }

  opencl_ctx->devices_cnt    = devices_cnt;
  opencl_ctx->devices_active = devices_active;

  opencl_ctx->need_adl       = need_adl;
  opencl_ctx->need_nvml      = need_nvml;
  opencl_ctx->need_nvapi     = need_nvapi;
  opencl_ctx->need_xnvctrl   = need_xnvctrl;

  return 0;
}

void opencl_ctx_devices_destroy (opencl_ctx_t *opencl_ctx)
{
  opencl_ctx->devices_cnt    = 0;
  opencl_ctx->devices_active = 0;

  opencl_ctx->need_adl       = 0;
  opencl_ctx->need_nvml      = 0;
  opencl_ctx->need_nvapi     = 0;
  opencl_ctx->need_xnvctrl   = 0;
}
