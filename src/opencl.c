/**
 * Authors.....: Jens Steube <jens.steube@gmail.com>
 *               Gabriele Gristina <matrix@hashcat.net>
 *
 * License.....: MIT
 */

#include "common.h"
#include "types_int.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "locking.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "rp_cpu.h"
#include "timer.h"
#include "opencl.h"
#include "shared.h"
#include "hwmon.h"
#include "interface.h"
#include "mpsp.h"
#include "restore.h"
#include "data.h"

extern hc_global_data_t data;

uint setup_opencl_platforms_filter (char *opencl_platforms)
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

u32 setup_devices_filter (char *opencl_devices)
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

cl_device_type setup_device_types_filter (char *opencl_device_types)
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

double get_avg_exec_time (hc_device_param_t *device_param, const int last_num_entries)
{
  int exec_pos = (int) device_param->exec_pos - last_num_entries;

  if (exec_pos < 0) exec_pos += EXEC_CACHE;

  double exec_ms_sum = 0;

  int exec_ms_cnt = 0;

  for (int i = 0; i < last_num_entries; i++)
  {
    double exec_ms = device_param->exec_ms[(exec_pos + i) % EXEC_CACHE];

    if (exec_ms > 0)
    {
      exec_ms_sum += exec_ms;

      exec_ms_cnt++;
    }
  }

  if (exec_ms_cnt == 0) return 0;

  return exec_ms_sum / exec_ms_cnt;
}

int gidd_to_pw_t (hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  cl_int CL_err = hc_clEnqueueReadBuffer (data.ocl, device_param->command_queue, device_param->d_pws_buf, CL_TRUE, gidd * sizeof (pw_t), sizeof (pw_t), pw, 0, NULL, NULL);

  if (CL_err != CL_SUCCESS)
  {
    log_error ("ERROR: clEnqueueReadBuffer(): %s\n", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}
