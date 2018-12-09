/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "locking.h"
#include "thread.h"
#include "timer.h"
#include "tuningdb.h"
#include "rp.h"
#include "rp_cpu.h"
#include "mpsp.h"
#include "straight.h"
#include "combinator.h"
#include "convert.h"
#include "stdout.h"
#include "filehandling.h"
#include "interface.h"
#include "wordlist.h"
#include "shared.h"
#include "hashes.h"
#include "cpu_md5.h"
#include "event.h"
#include "dynloader.h"
#include "opencl.h"

#if defined (__linux__)
static const char *dri_card0_path = "/dev/dri/card0";

static const char *drm_card0_vendor_path = "/sys/class/drm/card0/device/vendor";
static const char *drm_card0_driver_path = "/sys/class/drm/card0/device/driver";
#endif

static const u32 full01 = 0x01010101;
static const u32 full06 = 0x06060606;
static const u32 full80 = 0x80808080;

static double TARGET_MSEC_PROFILE[4] = { 2, 12, 96, 480 };

static int ocl_check_dri (MAYBE_UNUSED hashcat_ctx_t *hashcat_ctx)
{
  #if defined (__linux__)

  // This check makes sense only if we're not root

  const uid_t uid = getuid ();

  if (uid == 0) return 0;

  // No GPU available! That's fine, so we don't need to check if we have access to it.

  if (hc_path_exist (dri_card0_path) == false) return 0;

  // Now we need to check if this an AMD vendor, because this is when the problems start

  FILE *fd_drm = fopen (drm_card0_vendor_path, "rb");

  if (fd_drm == NULL) return 0;

  u32 vendor = 0;

  if (fscanf (fd_drm, "0x%x", &vendor) != 1)
  {
    fclose (fd_drm);

    return 0;
  }

  fclose (fd_drm);

  if (vendor != 4098) return 0;

  // Now the problem is only with AMDGPU-PRO, not with oldschool AMD driver

  char buf[HCBUFSIZ_TINY];

  const ssize_t len = readlink (drm_card0_driver_path, buf, HCBUFSIZ_TINY - 1);

  if (len == -1) return 0;

  buf[len] = 0;

  if (strstr (buf, "amdgpu") == NULL) return 0;

  // Now do the real check

  FILE *fd_dri = fopen (dri_card0_path, "rb");

  if (fd_dri == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot access %s: %m.", dri_card0_path);

    event_log_warning (hashcat_ctx, "This causes some drivers to crash when OpenCL is used!");
    event_log_warning (hashcat_ctx, "Adding your user to the \"video\" group usually fixes this problem:");
    event_log_warning (hashcat_ctx, "$ sudo usermod -a -G video $LOGNAME");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  fclose (fd_dri);

  #endif // __linux__

  return 0;
}

static bool setup_opencl_platforms_filter (hashcat_ctx_t *hashcat_ctx, const char *opencl_platforms, u64 *out)
{
  u64 opencl_platforms_filter = 0;

  if (opencl_platforms)
  {
    char *platforms = hcstrdup (opencl_platforms);

    if (platforms == NULL) return false;

    char *saveptr = NULL;

    char *next = strtok_r (platforms, ",", &saveptr);

    do
    {
      const int platform = (const int) strtol (next, NULL, 10);

      if (platform <= 0 || platform >= 64)
      {
        event_log_error (hashcat_ctx, "Invalid OpenCL platform %d specified.", platform);

        hcfree (platforms);

        return false;
      }

      opencl_platforms_filter |= 1ULL << (platform - 1);

    } while ((next = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

    hcfree (platforms);
  }
  else
  {
    opencl_platforms_filter = -1ULL;
  }

  *out = opencl_platforms_filter;

  return true;
}

static bool setup_devices_filter (hashcat_ctx_t *hashcat_ctx, const char *opencl_devices, u64 *out)
{
  u64 devices_filter = 0;

  if (opencl_devices)
  {
    char *devices = hcstrdup (opencl_devices);

    if (devices == NULL) return false;

    char *saveptr = NULL;

    char *next = strtok_r (devices, ",", &saveptr);

    do
    {
      const int device_id = (const int) strtol (next, NULL, 10);

      if ((device_id <= 0) || (device_id >= 64))
      {
        event_log_error (hashcat_ctx, "Invalid device_id %d specified.", device_id);

        hcfree (devices);

        return false;
      }

      devices_filter |= 1ULL << (device_id - 1);

    } while ((next = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

    hcfree (devices);
  }
  else
  {
    devices_filter = -1ULL;
  }

  *out = devices_filter;

  return true;
}

static bool setup_device_types_filter (hashcat_ctx_t *hashcat_ctx, const char *opencl_device_types, cl_device_type *out)
{
  cl_device_type device_types_filter = 0;

  if (opencl_device_types)
  {
    char *device_types = hcstrdup (opencl_device_types);

    if (device_types == NULL) return false;

    char *saveptr = NULL;

    char *next = strtok_r (device_types, ",", &saveptr);

    do
    {
      const int device_type = (const int) strtol (next, NULL, 10);

      if (device_type < 1 || device_type > 3)
      {
        event_log_error (hashcat_ctx, "Invalid device_type %d specified.", device_type);

        hcfree (device_types);

        return false;
      }

      device_types_filter |= 1u << device_type;

    } while ((next = strtok_r (NULL, ",", &saveptr)) != NULL);

    hcfree (device_types);
  }
  else
  {
    // Do not use CPU by default, this often reduces GPU performance because
    // the CPU is too busy to handle GPU synchronization

    device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_CPU;
  }

  *out = device_types_filter;

  return true;
}

static bool read_kernel_binary (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, size_t *kernel_lengths, char **kernel_sources, const bool force_recompile)
{
  FILE *fp = fopen (kernel_file, "rb");

  if (fp != NULL)
  {
    struct stat st;

    if (stat (kernel_file, &st))
    {
      fclose (fp);

      return false;
    }

    #define EXTRASZ 100

    char *buf = (char *) hcmalloc (st.st_size + 1 + EXTRASZ);

    size_t num_read = hc_fread (buf, sizeof (char), st.st_size, fp);

    fclose (fp);

    if (num_read != (size_t) st.st_size)
    {
      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      hcfree (buf);

      return false;
    }

    buf[st.st_size] = 0;

    if (force_recompile == true)
    {
      // this adds some hopefully unique data to the opencl kernel source
      // the effect should be that opencl kernel compiler caching see this as new "uncached" source
      // we have to do this since they do not check for the changes only in the #include source

      time_t tlog = time (NULL);

      const int extra_len = snprintf (buf + st.st_size, EXTRASZ, "\n//%u\n", (u32) tlog);

      st.st_size += extra_len;
    }

    kernel_lengths[0] = (size_t) st.st_size;

    kernel_sources[0] = buf;
  }
  else
  {
    event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

    return false;
  }

  return true;
}

static bool write_kernel_binary (hashcat_ctx_t *hashcat_ctx, char *kernel_file, char *binary, size_t binary_size)
{
  if (binary_size > 0)
  {
    FILE *fp = fopen (kernel_file, "wb");

    if (fp == NULL)
    {
      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      return false;
    }

    if (lock_file (fp) == -1)
    {
      fclose (fp);

      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      return false;
    }

    hc_fwrite (binary, sizeof (char), binary_size, fp);

    fflush (fp);

    fclose (fp);
  }

  return true;
}

void generate_source_kernel_filename (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *shared_dir, char *source_file)
{
  if (opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-optimized.cl", shared_dir, (int) kern_type);
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-optimized.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a1-optimized.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a3-optimized.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-optimized.cl", shared_dir, (int) kern_type);
      }
    }
    else
    {
      snprintf (source_file, 255, "%s/OpenCL/m%05d-optimized.cl", shared_dir, (int) kern_type);
    }
  }
  else
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-pure.cl", shared_dir, (int) kern_type);
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-pure.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a1-pure.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a3-pure.cl", shared_dir, (int) kern_type);
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (source_file, 255, "%s/OpenCL/m%05d_a0-pure.cl", shared_dir, (int) kern_type);
      }
    }
    else
    {
      snprintf (source_file, 255, "%s/OpenCL/m%05d-pure.cl", shared_dir, (int) kern_type);
    }
  }
}

void generate_cached_kernel_filename (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *profile_dir, const char *device_name_chksum, char *cached_file)
{
  if (opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a1-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a3-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
      }
    }
    else
    {
      snprintf (cached_file, 255, "%s/kernels/m%05d-optimized.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
    }
  }
  else
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a1-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a3-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
      }
    }
    else
    {
      snprintf (cached_file, 255, "%s/kernels/m%05d-pure.%s.kernel", profile_dir, (int) kern_type, device_name_chksum);
    }
  }
}

void generate_source_kernel_mp_filename (const u32 opti_type, const u64 opts_type, char *shared_dir, char *source_file)
{
  if ((opti_type & OPTI_TYPE_BRUTE_FORCE) && (opts_type & OPTS_TYPE_PT_GENERATE_BE))
  {
    snprintf (source_file, 255, "%s/OpenCL/markov_be.cl", shared_dir);
  }
  else
  {
    snprintf (source_file, 255, "%s/OpenCL/markov_le.cl", shared_dir);
  }
}

void generate_cached_kernel_mp_filename (const u32 opti_type, const u64 opts_type, char *profile_dir, const char *device_name_chksum_amp_mp, char *cached_file)
{
  if ((opti_type & OPTI_TYPE_BRUTE_FORCE) && (opts_type & OPTS_TYPE_PT_GENERATE_BE))
  {
    snprintf (cached_file, 255, "%s/kernels/markov_be.%s.kernel", profile_dir, device_name_chksum_amp_mp);
  }
  else
  {
    snprintf (cached_file, 255, "%s/kernels/markov_le.%s.kernel", profile_dir, device_name_chksum_amp_mp);
  }
}

void generate_source_kernel_amp_filename (const u32 attack_kern, char *shared_dir, char *source_file)
{
  snprintf (source_file, 255, "%s/OpenCL/amp_a%u.cl", shared_dir, attack_kern);
}

void generate_cached_kernel_amp_filename (const u32 attack_kern, char *profile_dir, const char *device_name_chksum_amp_mp, char *cached_file)
{
  snprintf (cached_file, 255, "%s/kernels/amp_a%u.%s.kernel", profile_dir, attack_kern, device_name_chksum_amp_mp);
}

int ocl_init (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  memset (ocl, 0, sizeof (OCL_PTR));

  #if   defined (_WIN)
  ocl->lib = hc_dlopen ("OpenCL");
  #elif defined (__APPLE__)
  ocl->lib = hc_dlopen ("/System/Library/Frameworks/OpenCL.framework/OpenCL", RTLD_NOW);
  #elif defined (__CYGWIN__)
  ocl->lib = hc_dlopen ("opencl.dll", RTLD_NOW);

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("cygOpenCL-1.dll", RTLD_NOW);
  #else
  ocl->lib = hc_dlopen ("libOpenCL.so", RTLD_NOW);

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("libOpenCL.so.1", RTLD_NOW);
  #endif

  if (ocl->lib == NULL)
  {
    event_log_error (hashcat_ctx, "Cannot find an OpenCL ICD loader library.");

    event_log_warning (hashcat_ctx, "You are probably missing the native OpenCL runtime or driver for your platform.");
    event_log_warning (hashcat_ctx, NULL);

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"RadeonOpenCompute (ROCm)\" Software Platform (1.6.180 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"AMD Radeon Software Crimson Edition\" (15.12 or later)");
    #endif

    event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Linux require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL 2.0 GPU Driver Package for Linux\" (2.0 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Windows require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Driver for Intel Iris and Intel HD Graphics\"");
    #endif

    event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (367.x or later)");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  HC_LOAD_FUNC(ocl, clBuildProgram, OCL_CLBUILDPROGRAM, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateBuffer, OCL_CLCREATEBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateCommandQueue, OCL_CLCREATECOMMANDQUEUE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateContext, OCL_CLCREATECONTEXT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateKernel, OCL_CLCREATEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateProgramWithBinary, OCL_CLCREATEPROGRAMWITHBINARY, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clCreateProgramWithSource, OCL_CLCREATEPROGRAMWITHSOURCE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueCopyBuffer, OCL_CLENQUEUECOPYBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueMapBuffer, OCL_CLENQUEUEMAPBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueNDRangeKernel, OCL_CLENQUEUENDRANGEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueReadBuffer, OCL_CLENQUEUEREADBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueUnmapMemObject, OCL_CLENQUEUEUNMAPMEMOBJECT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clEnqueueWriteBuffer, OCL_CLENQUEUEWRITEBUFFER, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clFinish, OCL_CLFINISH, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clFlush, OCL_CLFLUSH, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetDeviceIDs, OCL_CLGETDEVICEIDS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetDeviceInfo, OCL_CLGETDEVICEINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetEventInfo, OCL_CLGETEVENTINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetKernelWorkGroupInfo, OCL_CLGETKERNELWORKGROUPINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetPlatformIDs, OCL_CLGETPLATFORMIDS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetPlatformInfo, OCL_CLGETPLATFORMINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetProgramBuildInfo, OCL_CLGETPROGRAMBUILDINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetProgramInfo, OCL_CLGETPROGRAMINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseCommandQueue, OCL_CLRELEASECOMMANDQUEUE, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseContext, OCL_CLRELEASECONTEXT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseKernel, OCL_CLRELEASEKERNEL, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseMemObject, OCL_CLRELEASEMEMOBJECT, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseProgram, OCL_CLRELEASEPROGRAM, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clSetKernelArg, OCL_CLSETKERNELARG, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clWaitForEvents, OCL_CLWAITFOREVENTS, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clGetEventProfilingInfo, OCL_CLGETEVENTPROFILINGINFO, OpenCL, 1)
  HC_LOAD_FUNC(ocl, clReleaseEvent, OCL_CLRELEASEEVENT, OpenCL, 1)

  return 0;
}

void ocl_close (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  if (ocl)
  {
    if (ocl->lib)
    {
      hc_dlclose (ocl->lib);
    }

    hcfree (opencl_ctx->ocl);
  }
}

int hc_clEnqueueNDRangeKernel (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueNDRangeKernel (command_queue, kernel, work_dim, global_work_offset, global_work_size, local_work_size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueNDRangeKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetEventInfo (hashcat_ctx_t *hashcat_ctx, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetEventInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetEventInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clFlush (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clFlush (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clFlush(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clFinish (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clFinish (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clFinish(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clSetKernelArg (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clSetKernelArg (kernel, arg_index, arg_size, arg_value);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clSetKernelArg(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueWriteBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueWriteBuffer (command_queue, buffer, blocking_write, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueWriteBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueCopyBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueCopyBuffer (command_queue, src_buffer, dst_buffer, src_offset, dst_offset, cb, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueCopyBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueReadBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueReadBuffer (command_queue, buffer, blocking_read, offset, cb, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueReadBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetPlatformIDs (hashcat_ctx_t *hashcat_ctx, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetPlatformIDs (num_entries, platforms, num_platforms);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetPlatformIDs(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetPlatformInfo (hashcat_ctx_t *hashcat_ctx, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetPlatformInfo (platform, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetPlatformInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetDeviceIDs (hashcat_ctx_t *hashcat_ctx, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetDeviceIDs (platform, device_type, num_entries, devices, num_devices);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetDeviceIDs(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetDeviceInfo (hashcat_ctx_t *hashcat_ctx, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetDeviceInfo (device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetDeviceInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateContext (hashcat_ctx_t *hashcat_ctx, cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data, cl_context *context)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *context = ocl->clCreateContext (properties, num_devices, devices, pfn_notify, user_data, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateContext(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateCommandQueue (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_command_queue *command_queue)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *command_queue = ocl->clCreateCommandQueue (context, device, properties, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateCommandQueue(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateBuffer (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_mem *mem)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *mem = ocl->clCreateBuffer (context, flags, size, host_ptr, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithSource (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint count, char **strings, const size_t *lengths, cl_program *program)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithSource (context, count, (const char **) strings, lengths, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithSource(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithBinary (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, unsigned char **binaries, cl_int *binary_status, cl_program *program)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithBinary (context, num_devices, device_list, lengths, (const unsigned char **) binaries, binary_status, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithBinary(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clBuildProgram (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clBuildProgram (program, num_devices, device_list, options, pfn_notify, user_data);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clBuildProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateKernel (hashcat_ctx_t *hashcat_ctx, cl_program program, const char *kernel_name, cl_kernel *kernel)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *kernel = ocl->clCreateKernel (program, kernel_name, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseMemObject (hashcat_ctx_t *hashcat_ctx, cl_mem mem)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseMemObject (mem);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseMemObject(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseKernel (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseKernel (kernel);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseKernel(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseProgram (hashcat_ctx_t *hashcat_ctx, cl_program program)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseProgram (program);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseProgram(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseCommandQueue (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseCommandQueue (command_queue);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseCommandQueue(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseContext (hashcat_ctx_t *hashcat_ctx, cl_context context)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseContext (context);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseContext(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueMapBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event, void **buf)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  cl_int CL_err;

  *buf = ocl->clEnqueueMapBuffer (command_queue, buffer, blocking_map, map_flags, offset, size, num_events_in_wait_list, event_wait_list, event, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueMapBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueUnmapMemObject (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueUnmapMemObject (command_queue, memobj, mapped_ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueUnmapMemObject(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetKernelWorkGroupInfo (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetKernelWorkGroupInfo (kernel, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetKernelWorkGroupInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetProgramBuildInfo (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetProgramBuildInfo (program, device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetProgramBuildInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetProgramInfo (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetProgramInfo (program, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetProgramInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clWaitForEvents (hashcat_ctx_t *hashcat_ctx, cl_uint num_events, const cl_event *event_list)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clWaitForEvents (num_events, event_list);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clWaitForEvents(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetEventProfilingInfo (hashcat_ctx_t *hashcat_ctx, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clGetEventProfilingInfo (event, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetEventProfilingInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clReleaseEvent (hashcat_ctx_t *hashcat_ctx, cl_event event)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  OCL_PTR *ocl = opencl_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseEvent (event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseEvent(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int gidd_to_pw_t (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  pw_idx_t pw_idx;

  int CL_rc;

  CL_rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, gidd * sizeof (pw_idx_t), sizeof (pw_idx_t), &pw_idx, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  const u32 off = pw_idx.off;
  const u32 cnt = pw_idx.cnt;
  const u32 len = pw_idx.len;

  if (cnt > 0)
  {
    CL_rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, off * sizeof (u32), cnt * sizeof (u32), pw->i, 0, NULL, NULL);

    if (CL_rc == -1) return -1;
  }

  for (u32 i = cnt; i < 64; i++)
  {
    pw->i[i] = 0;
  }

  pw->pw_len = len;

  return 0;
}

int choose_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u64 pws_cnt, const u32 fast_iteration, const u32 salt_pos)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (hashconfig->hash_mode == 2000)
  {
    return process_stdout (hashcat_ctx, device_param, pws_cnt);
  }

  int CL_rc;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
        {
          const u32 size_tm = 32 * sizeof (bs_word_t);

          CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_tm_c, size_tm);

          if (CL_rc == -1) return -1;

          CL_rc = run_kernel_tm (hashcat_ctx, device_param);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_tm_c, device_param->d_bfs_c, 0, 0, size_tm, 0, NULL, NULL);

          if (CL_rc == -1) return -1;
        }
      }
    }

    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      if (highest_pw_len < 16)
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_cnt, true, fast_iteration);

        if (CL_rc == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_cnt, true, fast_iteration);

        if (CL_rc == -1) return -1;
      }
      else
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_cnt, true, fast_iteration);

        if (CL_rc == -1) return -1;
      }
    }
    else
    {
      CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_4, pws_cnt, true, fast_iteration);

      if (CL_rc == -1) return -1;
    }
  }
  else
  {
    bool run_init = true;
    bool run_loop = true;
    bool run_comp = true;

    if (run_init == true)
    {
      CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_amp_buf, device_param->d_pws_buf, 0, 0, pws_cnt * sizeof (pw_t), 0, NULL, NULL);

      if (CL_rc == -1) return -1;

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        CL_rc = run_kernel_amp (hashcat_ctx, device_param, pws_cnt);

        if (CL_rc == -1) return -1;
      }

      CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_cnt, false, 0);

      if (CL_rc == -1) return -1;

      if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_12, pws_cnt, false, 0);

        if (CL_rc == -1) return -1;

        CL_rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

        if (CL_rc == -1) return -1;

        // do something with data

        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

        if (CL_rc == -1) return -1;
      }
    }

    if (run_loop == true)
    {
      u32 iter = hashes->salts_buf[salt_pos].salt_iter;

      u32 loop_step = device_param->kernel_loops;

      for (u32 loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
      {
        u32 loop_left = iter - loop_pos;

        loop_left = MIN (loop_left, loop_step);

        device_param->kernel_params_buf32[28] = loop_pos;
        device_param->kernel_params_buf32[29] = loop_left;

        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_cnt, true, slow_iteration);

        if (CL_rc == -1) return -1;

        //bug?
        //while (status_ctx->run_thread_level2 == false) break;
        if (status_ctx->run_thread_level2 == false) break;

        /**
         * speed
         */

        const float iter_part = (float) (loop_pos + loop_left) / iter;

        const u64 perf_sum_all = (u64) (pws_cnt * iter_part);

        double speed_msec = hc_timer_get (device_param->timer_speed);

        const u32 speed_pos = device_param->speed_pos;

        device_param->speed_cnt[speed_pos] = perf_sum_all;

        device_param->speed_msec[speed_pos] = speed_msec;

        if (user_options->speed_only == true)
        {
          if (speed_msec > 4000)
          {
            device_param->outerloop_multi *= (double) iter / (double) (loop_pos + loop_left);

            device_param->speed_pos = 1;

            device_param->speed_only_finish = true;

            return 0;
          }
        }
      }

      if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_23, pws_cnt, false, 0);

        if (CL_rc == -1) return -1;

        CL_rc = hc_clEnqueueReadBuffer (hashcat_ctx, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

        if (CL_rc == -1) return -1;

        /*
         * The following section depends on the hash mode
         */

        switch (hashconfig->hash_mode)
        {
          // for 7z we only need device_param->hooks_buf, but other hooks could use any info from device_param. All of them should/must update hooks_buf
          case 11600: seven_zip_hook_func (device_param, hashes->hook_salts_buf, salt_pos, pws_cnt); break;
        }

        /*
         * END of hash mode specific hook operations
         */

        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL);

        if (CL_rc == -1) return -1;
      }
    }

    // init2 and loop2 are kind of special, we use run_loop for them, too

    if (run_loop == true)
    {
      // note: they also do not influence the performance screen
      // in case you want to use this, this cane make sense only if your input data comes out of tmps[]

      if (hashconfig->opts_type & OPTS_TYPE_INIT2)
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, pws_cnt, false, 0);

        if (CL_rc == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
      {
        u32 iter = hashes->salts_buf[salt_pos].salt_iter2;

        u32 loop_step = device_param->kernel_loops;

        for (u32 loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
        {
          u32 loop_left = iter - loop_pos;

          loop_left = MIN (loop_left, loop_step);

          device_param->kernel_params_buf32[28] = loop_pos;
          device_param->kernel_params_buf32[29] = loop_left;

          CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, pws_cnt, true, slow_iteration);

          if (CL_rc == -1) return -1;

          //bug?
          //while (status_ctx->run_thread_level2 == false) break;
          if (status_ctx->run_thread_level2 == false) break;
        }
      }
    }

    if (run_comp == true)
    {
      if ((hashconfig->hash_mode == 2500) || (hashconfig->hash_mode == 2501))
      {
        const u32 loops_cnt = hashes->salts_buf[salt_pos].digests_cnt;

        for (u32 loops_pos = 0; loops_pos < loops_cnt; loops_pos++)
        {
          device_param->kernel_params_buf32[28] = loops_pos;
          device_param->kernel_params_buf32[29] = loops_cnt;

          const u32 digests_offset = hashes->salts_buf[salt_pos].digests_offset;

          wpa_eapol_t *wpa_eapols = (wpa_eapol_t *) hashes->esalts_buf;

          wpa_eapol_t *wpa_eapol = &wpa_eapols[digests_offset + loops_pos];

          if (wpa_eapol->keyver == 1)
          {
            CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, pws_cnt, false, 0);

            if (CL_rc == -1) return -1;
          }
          else if (wpa_eapol->keyver == 2)
          {
            CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX2, pws_cnt, false, 0);

            if (CL_rc == -1) return -1;
          }
          else if (wpa_eapol->keyver == 3)
          {
            CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX3, pws_cnt, false, 0);

            if (CL_rc == -1) return -1;
          }

          if (status_ctx->run_thread_level2 == false) break;
        }
      }
      else if ((hashconfig->hash_mode == 16800) || (hashconfig->hash_mode == 16801))
      {
        const u32 loops_cnt = hashes->salts_buf[salt_pos].digests_cnt;

        for (u32 loops_pos = 0; loops_pos < loops_cnt; loops_pos++)
        {
          device_param->kernel_params_buf32[28] = loops_pos;
          device_param->kernel_params_buf32[29] = loops_cnt;

          CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, pws_cnt, false, 0);

          if (CL_rc == -1) return -1;

          if (status_ctx->run_thread_level2 == false) break;
        }
      }
      else
      {
        CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_cnt, false, 0);

        if (CL_rc == -1) return -1;
      }
    }
  }

  return 0;
}

void rebuild_pws_compressed_append (hc_device_param_t *device_param, const u64 pws_cnt, const u8 chr)
{
  // this function is used if we have to modify the compressed pws buffer in order to
  // append some data to each password candidate

  u32      *tmp_pws_comp = (u32 *)      hcmalloc (device_param->size_pws_comp);
  pw_idx_t *tmp_pws_idx  = (pw_idx_t *) hcmalloc (device_param->size_pws_idx);

  for (u32 i = 0; i < pws_cnt; i++)
  {
    pw_idx_t *pw_idx_src = device_param->pws_idx + i;
    pw_idx_t *pw_idx_dst = tmp_pws_idx + i;

    const u32 src_off = pw_idx_src->off;
    const u32 src_len = pw_idx_src->len;

    u8 buf[256];

    memcpy (buf, device_param->pws_comp + src_off, src_len);

    buf[src_len] = chr;

    const u32 dst_len = src_len + 1;

    const u32 dst_pw_len4 = (dst_len + 3) & ~3; // round up to multiple of 4

    const u32 dst_pw_len4_cnt = dst_pw_len4 / 4;

    pw_idx_dst->cnt = dst_pw_len4_cnt;
    pw_idx_dst->len = src_len; // this is intenionally! src_len can not be dst_len, we dont want the kernel to think 0x80 is part of the password

    u8 *dst = (u8 *) (tmp_pws_comp + pw_idx_dst->off);

    memcpy (dst, buf, dst_len);

    memset (dst + dst_len, 0, dst_pw_len4 - dst_len);

    // prepare next element

    pw_idx_t *pw_idx_dst_next = pw_idx_dst + 1;

    pw_idx_dst_next->off = pw_idx_dst->off + pw_idx_dst->cnt;
  }

  memcpy (device_param->pws_comp, tmp_pws_comp, device_param->size_pws_comp);
  memcpy (device_param->pws_idx,  tmp_pws_idx,  device_param->size_pws_idx);

  hcfree (tmp_pws_comp);
  hcfree (tmp_pws_idx);
}

int run_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num, const u32 event_update, const u32 iteration)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  u64 num_elements = num;

  device_param->kernel_params_buf64[34] = num;

  u64       kernel_threads = 0;
  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_1:
      kernel          = device_param->kernel1;
      kernel_threads  = device_param->kernel_wgs1;
      break;
    case KERN_RUN_12:
      kernel          = device_param->kernel12;
      kernel_threads  = device_param->kernel_wgs12;
      break;
    case KERN_RUN_2:
      kernel          = device_param->kernel2;
      kernel_threads  = device_param->kernel_wgs2;
      break;
    case KERN_RUN_23:
      kernel          = device_param->kernel23;
      kernel_threads  = device_param->kernel_wgs23;
      break;
    case KERN_RUN_3:
      kernel          = device_param->kernel3;
      kernel_threads  = device_param->kernel_wgs3;
      break;
    case KERN_RUN_4:
      kernel          = device_param->kernel4;
      kernel_threads  = device_param->kernel_wgs4;
      break;
    case KERN_RUN_INIT2:
      kernel          = device_param->kernel_init2;
      kernel_threads  = device_param->kernel_wgs_init2;
      break;
    case KERN_RUN_LOOP2:
      kernel          = device_param->kernel_loop2;
      kernel_threads  = device_param->kernel_wgs_loop2;
      break;
    case KERN_RUN_AUX1:
      kernel          = device_param->kernel_aux1;
      kernel_threads  = device_param->kernel_wgs_aux1;
      break;
    case KERN_RUN_AUX2:
      kernel          = device_param->kernel_aux2;
      kernel_threads  = device_param->kernel_wgs_aux2;
      break;
    case KERN_RUN_AUX3:
      kernel          = device_param->kernel_aux3;
      kernel_threads  = device_param->kernel_wgs_aux3;
      break;
    case KERN_RUN_AUX4:
      kernel          = device_param->kernel_aux4;
      kernel_threads  = device_param->kernel_wgs_aux4;
      break;
    default:
      event_log_error (hashcat_ctx, "Invalid kernel specified.");
      return -1;
  }

  kernel_threads = MIN (kernel_threads, device_param->kernel_threads);

  // kernel_threads = power_of_two_floor_32 (kernel_threads);

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  int CL_rc;

  for (u32 i = 0; i <= 23; i++)
  {
    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, i, sizeof (cl_mem), device_param->kernel_params[i]);

    if (CL_rc == -1) return -1;
  }

  for (u32 i = 24; i <= 33; i++)
  {
    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, i, sizeof (cl_uint), device_param->kernel_params[i]);

    if (CL_rc == -1) return -1;
  }

  for (u32 i = 34; i <= 34; i++)
  {
    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, i, sizeof (cl_ulong), device_param->kernel_params[i]);

    if (CL_rc == -1) return -1;
  }

  cl_event event;

  if ((hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE) && (user_options->attack_mode == ATTACK_MODE_BF))
  {
    const size_t global_work_size[3] = { num_elements,  32, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 2, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_rc == -1) return -1;
  }
  else
  {
    if (kern_run == KERN_RUN_1)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_INIT)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }
    else if (kern_run == KERN_RUN_2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_LOOP)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }
    else if (kern_run == KERN_RUN_3)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_COMP)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &event);

    if (CL_rc == -1) return -1;
  }

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  // spin damper section

  const u32 iterationm = iteration % EXPECTED_ITERATIONS;

  cl_int event_status;

  size_t param_value_size_ret;

  CL_rc = hc_clGetEventInfo (hashcat_ctx, event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (event_status), &event_status, &param_value_size_ret);

  if (CL_rc == -1) return -1;

  if (device_param->spin_damp > 0)
  {
    double spin_total = device_param->spin_damp;

    while (event_status != CL_COMPLETE)
    {
      if (status_ctx->devices_status == STATUS_RUNNING)
      {
        switch (kern_run)
        {
          case KERN_RUN_1:      if (device_param->exec_us_prev1[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev1[iterationm]      * device_param->spin_damp)); break;
          case KERN_RUN_2:      if (device_param->exec_us_prev2[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev2[iterationm]      * device_param->spin_damp)); break;
          case KERN_RUN_3:      if (device_param->exec_us_prev3[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev3[iterationm]      * device_param->spin_damp)); break;
          case KERN_RUN_4:      if (device_param->exec_us_prev4[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev4[iterationm]      * device_param->spin_damp)); break;
          case KERN_RUN_INIT2:  if (device_param->exec_us_prev_init2[iterationm] > 0) usleep ((useconds_t) (device_param->exec_us_prev_init2[iterationm] * device_param->spin_damp)); break;
          case KERN_RUN_LOOP2:  if (device_param->exec_us_prev_loop2[iterationm] > 0) usleep ((useconds_t) (device_param->exec_us_prev_loop2[iterationm] * device_param->spin_damp)); break;
          case KERN_RUN_AUX1:   if (device_param->exec_us_prev_aux1[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux1[iterationm]  * device_param->spin_damp)); break;
          case KERN_RUN_AUX2:   if (device_param->exec_us_prev_aux2[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux2[iterationm]  * device_param->spin_damp)); break;
          case KERN_RUN_AUX3:   if (device_param->exec_us_prev_aux3[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux3[iterationm]  * device_param->spin_damp)); break;
          case KERN_RUN_AUX4:   if (device_param->exec_us_prev_aux4[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux4[iterationm]  * device_param->spin_damp)); break;
        }
      }
      else
      {
        // we were told to be nice

        sleep (0);
      }

      CL_rc = hc_clGetEventInfo (hashcat_ctx, event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (event_status), &event_status, &param_value_size_ret);

      if (CL_rc == -1) return -1;

      spin_total += device_param->spin_damp;

      if (spin_total > 1) break;
    }
  }

  CL_rc = hc_clWaitForEvents (hashcat_ctx, 1, &event);

  if (CL_rc == -1) return -1;

  cl_ulong time_start;
  cl_ulong time_end;

  CL_rc = hc_clGetEventProfilingInfo (hashcat_ctx, event, CL_PROFILING_COMMAND_START, sizeof (time_start), &time_start, NULL); if (CL_rc == -1) return -1;
  CL_rc = hc_clGetEventProfilingInfo (hashcat_ctx, event, CL_PROFILING_COMMAND_END,   sizeof (time_end),   &time_end,   NULL); if (CL_rc == -1) return -1;

  const double exec_us = (double) (time_end - time_start) / 1000;

  if (device_param->spin_damp > 0)
  {
    if (status_ctx->devices_status == STATUS_RUNNING)
    {
      switch (kern_run)
      {
        case KERN_RUN_1:      device_param->exec_us_prev1[iterationm]      = exec_us; break;
        case KERN_RUN_2:      device_param->exec_us_prev2[iterationm]      = exec_us; break;
        case KERN_RUN_3:      device_param->exec_us_prev3[iterationm]      = exec_us; break;
        case KERN_RUN_4:      device_param->exec_us_prev4[iterationm]      = exec_us; break;
        case KERN_RUN_INIT2:  device_param->exec_us_prev_init2[iterationm] = exec_us; break;
        case KERN_RUN_LOOP2:  device_param->exec_us_prev_loop2[iterationm] = exec_us; break;
        case KERN_RUN_AUX1:   device_param->exec_us_prev_aux1[iterationm]  = exec_us; break;
        case KERN_RUN_AUX2:   device_param->exec_us_prev_aux2[iterationm]  = exec_us; break;
        case KERN_RUN_AUX3:   device_param->exec_us_prev_aux3[iterationm]  = exec_us; break;
        case KERN_RUN_AUX4:   device_param->exec_us_prev_aux4[iterationm]  = exec_us; break;
      }
    }
  }

  if (event_update)
  {
    u32 exec_pos = device_param->exec_pos;

    device_param->exec_msec[exec_pos] = exec_us / 1000;

    exec_pos++;

    if (exec_pos == EXEC_CACHE)
    {
      exec_pos = 0;
    }

    device_param->exec_pos = exec_pos;
  }

  CL_rc = hc_clReleaseEvent (hashcat_ctx, event);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_mp (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num)
{
  u64 num_elements = num;

  switch (kern_run)
  {
    case KERN_RUN_MP:   device_param->kernel_params_mp_buf64[8]   = num; break;
    case KERN_RUN_MP_R: device_param->kernel_params_mp_r_buf64[8] = num; break;
    case KERN_RUN_MP_L: device_param->kernel_params_mp_l_buf64[9] = num; break;
  }

  u64       kernel_threads = 0;
  cl_kernel kernel = NULL;

  switch (kern_run)
  {
    case KERN_RUN_MP:
      kernel          = device_param->kernel_mp;
      kernel_threads  = device_param->kernel_wgs_mp;
      break;
    case KERN_RUN_MP_R:
      kernel          = device_param->kernel_mp_r;
      kernel_threads  = device_param->kernel_wgs_mp_r;
      break;
    case KERN_RUN_MP_L:
      kernel          = device_param->kernel_mp_l;
      kernel_threads  = device_param->kernel_wgs_mp_l;
      break;
    default:
      event_log_error (hashcat_ctx, "Invalid kernel specified.");
      return -1;
  }

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  int CL_rc;

  switch (kern_run)
  {
    case KERN_RUN_MP:   CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp[3]);   if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp[4]);   if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp[5]);   if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp[6]);   if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp[7]);   if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 8, sizeof (cl_ulong), device_param->kernel_params_mp[8]);   if (CL_rc == -1) return -1;
                        break;
    case KERN_RUN_MP_R: CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_r[3]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_r[4]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_r[5]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_r[6]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_r[7]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 8, sizeof (cl_ulong), device_param->kernel_params_mp_r[8]); if (CL_rc == -1) return -1;
                        break;
    case KERN_RUN_MP_L: CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_l[3]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_l[4]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_l[5]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_l[6]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_l[7]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_l[8]); if (CL_rc == -1) return -1;
                        CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 9, sizeof (cl_ulong), device_param->kernel_params_mp_l[9]); if (CL_rc == -1) return -1;
                        break;
  }

  const size_t global_work_size[3] = { num_elements,   1, 1 };
  const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

  CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_tm (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const u64 num_elements = 1024; // fixed

  const u64 kernel_threads = MIN (num_elements, device_param->kernel_wgs_tm);

  cl_kernel kernel = device_param->kernel_tm;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  int CL_rc;

  CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_amp (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_amp_buf64[6] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_amp;

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  cl_kernel kernel = device_param->kernel_amp;

  int CL_rc;

  CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 6, sizeof (cl_ulong), device_param->kernel_params_amp[6]);

  if (CL_rc == -1) return -1;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  cl_kernel kernel = device_param->kernel_atinit;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  int CL_rc;

  CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem), (void *) &buf);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  if (num16d)
  {
    device_param->kernel_params_memset_buf32[1] = value;
    device_param->kernel_params_memset_buf64[2] = num16d;

    const u64 kernel_threads = device_param->kernel_wgs_memset;

    u64 num_elements = num16d;

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_kernel kernel = device_param->kernel_memset;

    int CL_rc;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem),   (void *) &buf);                         if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]); if (CL_rc == -1) return -1;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

    if (CL_rc == -1) return -1;

    CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

    if (CL_rc == -1) return -1;

    CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

    if (CL_rc == -1) return -1;
  }

  if (num16m)
  {
    u32 tmp[4];

    tmp[0] = value;
    tmp[1] = value;
    tmp[2] = value;
    tmp[3] = value;

    int CL_rc;

    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, buf, CL_TRUE, num16d * 16, num16m, tmp, 0, NULL, NULL);

    if (CL_rc == -1) return -1;
  }

  return 0;
}

int run_kernel_decompress (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_decompress_buf64[3] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_decompress;

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  cl_kernel kernel = device_param->kernel_decompress;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  int CL_rc;

  CL_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFlush (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  CL_rc = hc_clFinish (hashcat_ctx, device_param->command_queue);

  if (CL_rc == -1) return -1;

  return 0;
}

int run_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size)
{
  return run_kernel_memset (hashcat_ctx, device_param, buf, 0, size);
}

int run_copy (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt)
{
  combinator_ctx_t     *combinator_ctx      = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  // init speed timer

  #if defined (_WIN)
  if (device_param->timer_speed.QuadPart == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #else
  if (device_param->timer_speed.tv_sec == 0)
  {
    hc_timer_set (&device_param->timer_speed);
  }
  #endif

  if (user_options->slow_candidates == true)
  {
    int CL_rc;

    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL);

    if (CL_rc == -1) return -1;

    const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

    const u32 off = pw_idx->off;

    if (off)
    {
      CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL);

      if (CL_rc == -1) return -1;
    }

    CL_rc = run_kernel_decompress (hashcat_ctx, device_param, pws_cnt);

    if (CL_rc == -1) return -1;
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      int CL_rc;

      CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL);

      if (CL_rc == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL);

        if (CL_rc == -1) return -1;
      }

      CL_rc = run_kernel_decompress (hashcat_ctx, device_param, pws_cnt);

      if (CL_rc == -1) return -1;
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        if (user_options->attack_mode == ATTACK_MODE_COMBI)
        {
          if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_RIGHT)
          {
            if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
            {
              rebuild_pws_compressed_append (device_param, pws_cnt, 0x01);
            }
            else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
            {
              rebuild_pws_compressed_append (device_param, pws_cnt, 0x06);
            }
            else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
            {
              rebuild_pws_compressed_append (device_param, pws_cnt, 0x80);
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
          {
            rebuild_pws_compressed_append (device_param, pws_cnt, 0x01);
          }
          else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
          {
            rebuild_pws_compressed_append (device_param, pws_cnt, 0x06);
          }
          else if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
          {
            rebuild_pws_compressed_append (device_param, pws_cnt, 0x80);
          }
        }

        int CL_rc;

        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL);

        if (CL_rc == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL);

          if (CL_rc == -1) return -1;
        }

        CL_rc = run_kernel_decompress (hashcat_ctx, device_param, pws_cnt);

        if (CL_rc == -1) return -1;
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_COMBI)
        {
          int CL_rc;

          CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL);

          if (CL_rc == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL);

            if (CL_rc == -1) return -1;
          }

          CL_rc = run_kernel_decompress (hashcat_ctx, device_param, pws_cnt);

          if (CL_rc == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          int CL_rc;

          CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL);

          if (CL_rc == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL);

            if (CL_rc == -1) return -1;
          }

          CL_rc = run_kernel_decompress (hashcat_ctx, device_param, pws_cnt);

          if (CL_rc == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          const u64 off = device_param->words_off;

          device_param->kernel_params_mp_buf64[3] = off;

          const int CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, pws_cnt);

          if (CL_rc == -1) return -1;
        }
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      const u64 off = device_param->words_off;

      device_param->kernel_params_mp_l_buf64[3] = off;

      const int CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP_L, pws_cnt);

      if (CL_rc == -1) return -1;
    }
  }

  return 0;
}

int run_cracker (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt)
{
  combinator_ctx_t      *combinator_ctx     = hashcat_ctx->combinator_ctx;
  hashconfig_t          *hashconfig         = hashcat_ctx->hashconfig;
  hashes_t              *hashes             = hashcat_ctx->hashes;
  mask_ctx_t            *mask_ctx           = hashcat_ctx->mask_ctx;
  status_ctx_t          *status_ctx         = hashcat_ctx->status_ctx;
  straight_ctx_t        *straight_ctx       = hashcat_ctx->straight_ctx;
  user_options_t        *user_options       = hashcat_ctx->user_options;
  user_options_extra_t  *user_options_extra = hashcat_ctx->user_options_extra;

  // do the on-the-fly combinator mode encoding

  bool iconv_enabled = false;

  iconv_t iconv_ctx = NULL;

  char *iconv_tmp = NULL;

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    iconv_enabled = true;

    iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (iconv_ctx == (iconv_t) -1) return -1;

    iconv_tmp = (char *) hcmalloc (HCBUFSIZ_TINY);
  }

  // find higest password length, this is for optimization stuff

  u32 highest_pw_len = 0;

  if (user_options->slow_candidates == true)
  {
    /*
    for (u64 pws_idx = 0; pws_idx < pws_cnt; pws_idx++)
    {
      pw_idx_t *pw_idx = device_param->pws_idx + pws_idx;

      highest_pw_len = MAX (highest_pw_len, pw_idx->len);
    }
    */
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
    {
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      highest_pw_len = device_param->kernel_params_mp_l_buf32[4]
                     + device_param->kernel_params_mp_l_buf32[5];
    }
  }

  // we make use of this in status view

  device_param->outerloop_multi = 1;
  device_param->outerloop_msec  = 0;
  device_param->outerloop_pos   = 0;
  device_param->outerloop_left  = pws_cnt;

  // loop start: most outer loop = salt iteration, then innerloops (if multi)

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    device_param->kernel_params_buf32[27] = salt_pos;
    device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
    device_param->kernel_params_buf32[32] = salt_buf->digests_offset;

    FILE *combs_fp = device_param->combs_fp;

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if ((user_options->attack_mode == ATTACK_MODE_COMBI) || (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2)))
      {
        rewind (combs_fp);
      }
    }

    // iteration type

    u32 innerloop_step = 0;
    u32 innerloop_cnt  = 0;

    if (user_options->slow_candidates == true)
    {
      innerloop_step = 1;
      innerloop_cnt  = 1;
    }
    else
    {
      if   (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) innerloop_step = device_param->kernel_loops;
      else                                                        innerloop_step = 1;

      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = (u32) straight_ctx->kernel_rules_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = (u32) combinator_ctx->combs_cnt;
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)        innerloop_cnt = (u32) mask_ctx->bfs_cnt;
    }

    // innerloops

    for (u32 innerloop_pos = 0; innerloop_pos < innerloop_cnt; innerloop_pos += innerloop_step)
    {
      while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

      u32 fast_iteration = 0;

      u32 innerloop_left = innerloop_cnt - innerloop_pos;

      if (innerloop_left > innerloop_step)
      {
        innerloop_left = innerloop_step;

        fast_iteration = 1;
      }

      hc_thread_mutex_lock (status_ctx->mux_display);

      device_param->innerloop_pos  = innerloop_pos;
      device_param->innerloop_left = innerloop_left;

      device_param->kernel_params_buf32[30] = (u32) innerloop_left;

      device_param->outerloop_multi = (double) innerloop_cnt / (double) (innerloop_pos + innerloop_left);

      hc_thread_mutex_unlock (status_ctx->mux_display);

      if (hashes->salts_shown[salt_pos] == 1)
      {
        status_ctx->words_progress_done[salt_pos] += (u64) pws_cnt * innerloop_left;

        continue;
      }

      // initialize and copy amplifiers

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          const int CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_rules, device_param->d_rules_c, innerloop_pos * sizeof (kernel_rule_t), 0, innerloop_left * sizeof (kernel_rule_t), 0, NULL, NULL);

          if (CL_rc == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            if (user_options->attack_mode == ATTACK_MODE_COMBI)
            {
              char *line_buf = device_param->scratch_buf;

              u32 i = 0;

              while (i < innerloop_left)
              {
                if (feof (combs_fp)) break;

                size_t line_len = fgetl (combs_fp, line_buf);

                line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

                if (line_len >= PW_MAX) continue;

                char *line_buf_new = line_buf;

                char rule_buf_out[RP_PASSWORD_SIZE];

                if (run_rule_engine (user_options_extra->rule_len_r, user_options->rule_buf_r))
                {
                  if (line_len >= RP_PASSWORD_SIZE) continue;

                  memset (rule_buf_out, 0, sizeof (rule_buf_out));

                  const int rule_len_out = _old_apply_rule (user_options->rule_buf_r, user_options_extra->rule_len_r, line_buf, (u32) line_len, rule_buf_out);

                  if (rule_len_out < 0)
                  {
                    status_ctx->words_progress_rejected[salt_pos] += pws_cnt;

                    continue;
                  }

                  line_len = rule_len_out;

                  line_buf_new = rule_buf_out;
                }

                // do the on-the-fly encoding

                if (iconv_enabled == true)
                {
                  char  *iconv_ptr = iconv_tmp;
                  size_t iconv_sz  = HCBUFSIZ_TINY;

                  const size_t iconv_rc = iconv (iconv_ctx, &line_buf_new, &line_len, &iconv_ptr, &iconv_sz);

                  if (iconv_rc == (size_t) -1) continue;

                  line_buf_new = iconv_tmp;
                  line_len     = HCBUFSIZ_TINY - iconv_sz;
                }

                line_len = MIN (line_len, PW_MAX - 1);

                u8 *ptr = (u8 *) device_param->combs_buf[i].i;

                memcpy (ptr, line_buf_new, line_len);

                memset (ptr + line_len, 0, PW_MAX - line_len);

                if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
                {
                  uppercase (ptr, line_len);
                }

                if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
                {
                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
                  {
                    ptr[line_len] = 0x80;
                  }

                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
                  {
                    ptr[line_len] = 0x06;
                  }

                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
                  {
                    ptr[line_len] = 0x01;
                  }
                }

                device_param->combs_buf[i].pw_len = (u32) line_len;

                i++;
              }

              for (u32 j = i; j < innerloop_left; j++)
              {
                memset (&device_param->combs_buf[j], 0, sizeof (pw_t));
              }

              innerloop_left = i;

              const int CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL);

              if (CL_rc == -1) return -1;
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              int CL_rc;

              CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left);

              if (CL_rc == -1) return -1;

              CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL);

              if (CL_rc == -1) return -1;
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              int CL_rc;

              CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left);

              if (CL_rc == -1) return -1;

              CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL);

              if (CL_rc == -1) return -1;
            }
          }
          else
          {
            if ((user_options->attack_mode == ATTACK_MODE_COMBI) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
            {
              char *line_buf = device_param->scratch_buf;

              u32 i = 0;

              while (i < innerloop_left)
              {
                if (feof (combs_fp)) break;

                size_t line_len = fgetl (combs_fp, line_buf);

                line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

                if (line_len >= PW_MAX) continue;

                char *line_buf_new = line_buf;

                char rule_buf_out[RP_PASSWORD_SIZE];

                if (run_rule_engine (user_options_extra->rule_len_r, user_options->rule_buf_r))
                {
                  if (line_len >= RP_PASSWORD_SIZE) continue;

                  memset (rule_buf_out, 0, sizeof (rule_buf_out));

                  const int rule_len_out = _old_apply_rule (user_options->rule_buf_r, user_options_extra->rule_len_r, line_buf, (u32) line_len, rule_buf_out);

                  if (rule_len_out < 0)
                  {
                    status_ctx->words_progress_rejected[salt_pos] += pws_cnt;

                    continue;
                  }

                  line_len = rule_len_out;

                  line_buf_new = rule_buf_out;
                }

                // do the on-the-fly encoding

                if (iconv_enabled == true)
                {
                  char  *iconv_ptr = iconv_tmp;
                  size_t iconv_sz  = HCBUFSIZ_TINY;

                  const size_t iconv_rc = iconv (iconv_ctx, &line_buf_new, &line_len, &iconv_ptr, &iconv_sz);

                  if (iconv_rc == (size_t) -1) continue;

                  line_buf_new = iconv_tmp;
                  line_len     = HCBUFSIZ_TINY - iconv_sz;
                }

                line_len = MIN (line_len, PW_MAX - 1);

                u8 *ptr = (u8 *) device_param->combs_buf[i].i;

                memcpy (ptr, line_buf_new, line_len);

                memset (ptr + line_len, 0, PW_MAX - line_len);

                if (hashconfig->opts_type & OPTS_TYPE_PT_UPPER)
                {
                  uppercase (ptr, line_len);
                }

                /*
                if (combinator_ctx->combs_mode == COMBINATOR_MODE_BASE_LEFT)
                {
                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)
                  {
                    ptr[line_len] = 0x80;
                  }

                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)
                  {
                    ptr[line_len] = 0x06;
                  }

                  if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)
                  {
                    ptr[line_len] = 0x01;
                  }
                }
                */

                device_param->combs_buf[i].pw_len = (u32) line_len;

                i++;
              }

              for (u32 j = i; j < innerloop_left; j++)
              {
                memset (&device_param->combs_buf[j], 0, sizeof (pw_t));
              }

              innerloop_left = i;

              const int CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL);

              if (CL_rc == -1) return -1;
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              int CL_rc;

              CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left);

              if (CL_rc == -1) return -1;

              CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_combs, device_param->d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL);

              if (CL_rc == -1) return -1;
            }
          }
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          u64 off = innerloop_pos;

          device_param->kernel_params_mp_r_buf64[3] = off;

          int CL_rc;

          CL_rc = run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP_R, innerloop_left);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bfs, device_param->d_bfs_c, 0, 0, innerloop_left * sizeof (bf_t), 0, NULL, NULL);

          if (CL_rc == -1) return -1;
        }
      }

      const int rc = choose_kernel (hashcat_ctx, device_param, highest_pw_len, pws_cnt, fast_iteration, salt_pos);

      if (rc == -1) return -1;

      /**
       * benchmark was aborted because too long kernel runtime (slow hashes only)
       */

      if ((user_options->speed_only == true) && (device_param->speed_only_finish == true))
      {
        // nothing to do in that case
      }
      else
      {
        /**
         * speed
         */

        if (status_ctx->run_thread_level2 == true)
        {
          const u64 perf_sum_all = (u64) pws_cnt * innerloop_left;

          const double speed_msec = hc_timer_get (device_param->timer_speed);

          hc_timer_set (&device_param->timer_speed);

          u32 speed_pos = device_param->speed_pos;

          device_param->speed_cnt[speed_pos] = perf_sum_all;

          device_param->speed_msec[speed_pos] = speed_msec;

          speed_pos++;

          if (speed_pos == SPEED_CACHE)
          {
            speed_pos = 0;
          }

          device_param->speed_pos = speed_pos;

          /**
           * progress
           */

          hc_thread_mutex_lock (status_ctx->mux_counter);

          status_ctx->words_progress_done[salt_pos] += perf_sum_all;

          hc_thread_mutex_unlock (status_ctx->mux_counter);
        }
      }

      /**
       * benchmark, part2
       */

      if (user_options->speed_only == true)
      {
        // let's abort this so that the user doesn't have to wait too long on the result
        // for slow hashes it's fine anyway as boost mode should be turned on

        if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
        {
          device_param->speed_only_finish = true;

          break;
        }
        else
        {
          double total_msec = device_param->speed_msec[0];

          for (u32 speed_pos = 1; speed_pos < device_param->speed_pos; speed_pos++)
          {
            total_msec += device_param->speed_msec[speed_pos];
          }

          if (user_options->slow_candidates == true)
          {
            if ((total_msec > 4000) || (device_param->speed_pos == SPEED_CACHE - 1))
            {
              const u32 speed_pos = device_param->speed_pos;

              if (speed_pos)
              {
                device_param->speed_cnt[0]  = device_param->speed_cnt[speed_pos - 1];
                device_param->speed_msec[0] = device_param->speed_msec[speed_pos - 1];
              }

              device_param->speed_pos = 0;

              device_param->speed_only_finish = true;

              break;
            }
          }
          else
          {
            // it's unclear if 4s is enough to turn on boost mode for all opencl device

            if ((total_msec > 4000) || (device_param->speed_pos == SPEED_CACHE - 1))
            {
              device_param->speed_only_finish = true;

              break;
            }
          }
        }
      }

      if (device_param->speed_only_finish == true) break;

      /**
       * result
       */

      check_cracked (hashcat_ctx, device_param, salt_pos);

      if (status_ctx->run_thread_level2 == false) break;
    }

    if (user_options->speed_only == true) break;

    //status screen makes use of this, can't reset here
    //device_param->innerloop_msec = 0;
    //device_param->innerloop_pos  = 0;
    //device_param->innerloop_left = 0;

    if (status_ctx->run_thread_level2 == false) break;
  }

  //status screen makes use of this, can't reset here
  //device_param->outerloop_msec = 0;
  //device_param->outerloop_pos  = 0;
  //device_param->outerloop_left = 0;

  if (user_options->speed_only == true)
  {
    double total_msec = device_param->speed_msec[0];

    for (u32 speed_pos = 1; speed_pos < device_param->speed_pos; speed_pos++)
    {
      total_msec += device_param->speed_msec[speed_pos];
    }

    device_param->outerloop_msec = total_msec * hashes->salts_cnt * device_param->outerloop_multi;
  }

  return 0;
}

int opencl_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  opencl_ctx->enabled = false;

  if (user_options->example_hashes == true) return 0;
  if (user_options->keyspace       == true) return 0;
  if (user_options->left           == true) return 0;
  if (user_options->show           == true) return 0;
  if (user_options->usage          == true) return 0;
  if (user_options->version        == true) return 0;

  hc_device_param_t *devices_param = (hc_device_param_t *) hccalloc (DEVICES_MAX, sizeof (hc_device_param_t));

  opencl_ctx->devices_param = devices_param;

  /**
   * Load and map OpenCL library calls
   */

  OCL_PTR *ocl = (OCL_PTR *) hcmalloc (sizeof (OCL_PTR));

  opencl_ctx->ocl = ocl;

  const int rc_ocl_init = ocl_init (hashcat_ctx);

  if (rc_ocl_init == -1) return -1;

  /**
   * Some permission pre-check, because AMDGPU-PRO Driver crashes if the user has no permission to do this
   */

  const int rc_ocl_check = ocl_check_dri (hashcat_ctx);

  if (rc_ocl_check == -1) return -1;

  /**
   * OpenCL platform selection
   */

  u64 opencl_platforms_filter;

  const bool rc_platforms_filter = setup_opencl_platforms_filter (hashcat_ctx, user_options->opencl_platforms, &opencl_platforms_filter);

  if (rc_platforms_filter == false) return -1;

  opencl_ctx->opencl_platforms_filter = opencl_platforms_filter;

  /**
   * OpenCL device selection
   */

  u64 devices_filter;

  const bool rc_devices_filter = setup_devices_filter (hashcat_ctx, user_options->opencl_devices, &devices_filter);

  if (rc_devices_filter == false) return -1;

  opencl_ctx->devices_filter = devices_filter;

  /**
   * OpenCL device type selection
   */

  cl_device_type device_types_filter;

  const bool rc_device_types_filter = setup_device_types_filter (hashcat_ctx, user_options->opencl_device_types, &device_types_filter);

  if (rc_device_types_filter == false) return -1;

  opencl_ctx->device_types_filter = device_types_filter;

  /**
   * OpenCL platforms: detect
   */

  char          **platforms_vendor      = (char **) hccalloc (CL_PLATFORMS_MAX, sizeof (char *));
  char          **platforms_name        = (char **) hccalloc (CL_PLATFORMS_MAX, sizeof (char *));
  char          **platforms_version     = (char **) hccalloc (CL_PLATFORMS_MAX, sizeof (char *));
  bool           *platforms_skipped     = (bool *)  hccalloc (CL_PLATFORMS_MAX, sizeof (bool));
  cl_uint         platforms_cnt         = 0;
  cl_platform_id *platforms             = (cl_platform_id *) hccalloc (CL_PLATFORMS_MAX, sizeof (cl_platform_id));
  cl_uint         platform_devices_cnt  = 0;
  cl_device_id   *platform_devices      = (cl_device_id *) hccalloc (DEVICES_MAX, sizeof (cl_device_id));

  int CL_rc = hc_clGetPlatformIDs (hashcat_ctx, CL_PLATFORMS_MAX, platforms, &platforms_cnt);

  #define FREE_OPENCL_CTX_ON_ERROR \
  {                                \
      hcfree (platforms_vendor);   \
      hcfree (platforms_name);     \
      hcfree (platforms_version);  \
      hcfree (platforms_skipped);  \
      hcfree (platforms);          \
      hcfree (platform_devices);   \
  }

  if (CL_rc == -1)
  {
    FREE_OPENCL_CTX_ON_ERROR;

    return -1;
  }

  if (platforms_cnt == 0)
  {
    event_log_error (hashcat_ctx, "ATTENTION! No OpenCL-compatible platform found.");

    event_log_warning (hashcat_ctx, "You are probably missing the OpenCL runtime installation.");
    event_log_warning (hashcat_ctx, NULL);

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"AMDGPU-PRO Driver\" (16.40 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"AMD Radeon Software Crimson Edition\" (15.12 or later)");
    #endif

    event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Linux require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL 2.0 GPU Driver Package for Linux\" (2.0 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Windows require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Driver for Intel Iris and Intel HD Graphics\"");
    #endif

    event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver:");
    event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (367.x or later)");
    event_log_warning (hashcat_ctx, NULL);

    FREE_OPENCL_CTX_ON_ERROR;

    return -1;
  }

  if (opencl_platforms_filter != (u64) -1)
  {
    u64 platform_cnt_mask = ~(((u64) -1 >> platforms_cnt) << platforms_cnt);

    if (opencl_platforms_filter > platform_cnt_mask)
    {
      event_log_error (hashcat_ctx, "An invalid platform was specified using the --opencl-platforms parameter.");
      event_log_error (hashcat_ctx, "The specified platform was higher than the number of available platforms (%u).", platforms_cnt);

      FREE_OPENCL_CTX_ON_ERROR;

      return -1;
    }
  }

  if (user_options->opencl_device_types == NULL)
  {
    /**
     * OpenCL device types:
     *   In case the user did not specify --opencl-device-types and the user runs hashcat in a system with only a CPU only he probably want to use that CPU.
     */

    cl_device_type device_types_all = 0;

    for (u32 platform_id = 0; platform_id < platforms_cnt; platform_id++)
    {
      if ((opencl_platforms_filter & (1ULL << platform_id)) == 0) continue;

      cl_platform_id platform = platforms[platform_id];

      CL_rc = hc_clGetDeviceIDs (hashcat_ctx, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

      if (CL_rc == -1) continue;

      for (u32 platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
      {
        cl_device_id device = platform_devices[platform_devices_id];

        cl_device_type device_type;

        CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

        if (CL_rc == -1)
        {
          FREE_OPENCL_CTX_ON_ERROR;

          return -1;
        }

        device_types_all |= device_type;
      }
    }

    // In such a case, automatically enable cpu_md5CPU device type support, since it's disabled by default.

    if ((device_types_all & (CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR)) == 0)
    {
      device_types_filter |= CL_DEVICE_TYPE_CPU;
    }

    // In another case, when the user uses --stdout, using CPU devices is much faster to setup
    // If we have a CPU device, force it to be used

    if (user_options->stdout_flag == true)
    {
      if (device_types_all & CL_DEVICE_TYPE_CPU)
      {
        device_types_filter = CL_DEVICE_TYPE_CPU;
      }
    }

    opencl_ctx->device_types_filter = device_types_filter;
  }

  opencl_ctx->enabled = true;

  opencl_ctx->platforms_vendor      = platforms_vendor;
  opencl_ctx->platforms_name        = platforms_name;
  opencl_ctx->platforms_version     = platforms_version;
  opencl_ctx->platforms_skipped     = platforms_skipped;
  opencl_ctx->platforms_cnt         = platforms_cnt;
  opencl_ctx->platforms             = platforms;
  opencl_ctx->platform_devices_cnt  = platform_devices_cnt;
  opencl_ctx->platform_devices      = platform_devices;

  return 0;
}

void opencl_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (opencl_ctx->enabled == false) return;

  ocl_close (hashcat_ctx);

  hcfree (opencl_ctx->devices_param);

  hcfree (opencl_ctx->platforms);
  hcfree (opencl_ctx->platform_devices);
  hcfree (opencl_ctx->platforms_vendor);
  hcfree (opencl_ctx->platforms_name);
  hcfree (opencl_ctx->platforms_version);
  hcfree (opencl_ctx->platforms_skipped);

  memset (opencl_ctx, 0, sizeof (opencl_ctx_t));
}

int opencl_ctx_devices_init (hashcat_ctx_t *hashcat_ctx, const int comptime)
{
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return 0;

  /**
   * OpenCL devices: simply push all devices from all platforms into the same device array
   */

  cl_uint         platforms_cnt         = opencl_ctx->platforms_cnt;
  cl_platform_id *platforms             = opencl_ctx->platforms;
  cl_uint         platform_devices_cnt  = opencl_ctx->platform_devices_cnt;
  cl_device_id   *platform_devices      = opencl_ctx->platform_devices;

  bool need_adl     = false;
  bool need_nvml    = false;
  bool need_nvapi   = false;
  bool need_sysfs   = false;

  u32 devices_cnt = 0;

  u32 devices_active = 0;

  for (u32 platform_id = 0; platform_id < platforms_cnt; platform_id++)
  {
    size_t param_value_size = 0;

    cl_platform_id platform = platforms[platform_id];

    // platform vendor

    int CL_rc;

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_VENDOR, 0, NULL, &param_value_size);

    if (CL_rc == -1) return -1;

    char *platform_vendor = (char *) hcmalloc (param_value_size);

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_VENDOR, param_value_size, platform_vendor, NULL);

    if (CL_rc == -1) return -1;

    opencl_ctx->platforms_vendor[platform_id] = platform_vendor;

    // platform name

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_NAME, 0, NULL, &param_value_size);

    if (CL_rc == -1) return -1;

    char *platform_name = (char *) hcmalloc (param_value_size);

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_NAME, param_value_size, platform_name, NULL);

    if (CL_rc == -1) return -1;

    opencl_ctx->platforms_name[platform_id] = platform_name;

    // platform version

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_VERSION, 0, NULL, &param_value_size);

    if (CL_rc == -1) return -1;

    char *platform_version = (char *) hcmalloc (param_value_size);

    CL_rc = hc_clGetPlatformInfo (hashcat_ctx, platform, CL_PLATFORM_VERSION, param_value_size, platform_version, NULL);

    if (CL_rc == -1) return -1;

    opencl_ctx->platforms_version[platform_id] = platform_version;

    // find our own platform vendor because pocl and mesa are pushing original vendor_id through opencl
    // this causes trouble with vendor id based macros
    // we'll assign generic to those without special optimization available

    cl_uint platform_vendor_id = 0;

    if (strcmp (platform_vendor, CL_VENDOR_AMD1) == 0)
    {
      platform_vendor_id = VENDOR_ID_AMD;
    }
    else if (strcmp (platform_vendor, CL_VENDOR_AMD2) == 0)
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

    bool platform_skipped = ((opencl_ctx->opencl_platforms_filter & (1ULL << platform_id)) == 0);

    CL_rc = hc_clGetDeviceIDs (hashcat_ctx, platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, platform_devices, &platform_devices_cnt);

    if (CL_rc == -1)
    {
      //event_log_error (hashcat_ctx, "clGetDeviceIDs(): %s", val2cstr_cl (CL_rc));

      //return -1;

      platform_skipped = true;
    }

    opencl_ctx->platforms_skipped[platform_id] = platform_skipped;

    if (platform_skipped == true) continue;

    if (user_options->force == false)
    {
      if (platform_vendor_id == VENDOR_ID_MESA)
      {
        event_log_error (hashcat_ctx, "Mesa (Gallium) OpenCL platform detected!");

        event_log_warning (hashcat_ctx, "The Mesa platform can cause errors that are often mistaken for bugs in hashcat.");
        event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the drivers listed in docs/readme.txt.");
        event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
        event_log_warning (hashcat_ctx, "You can also use --opencl-platforms to skip the Mesa platform(s).");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }

    hc_device_param_t *devices_param = opencl_ctx->devices_param;

    for (u32 platform_devices_id = 0; platform_devices_id < platform_devices_cnt; platform_devices_id++)
    {
      const u32 device_id = devices_cnt;

      hc_device_param_t *device_param = &devices_param[device_id];

      device_param->platform_vendor_id = platform_vendor_id;

      device_param->device = platform_devices[platform_devices_id];

      device_param->device_id = device_id;

      device_param->platform_devices_id = platform_devices_id;

      device_param->platform = platform;

      // device_type

      cl_device_type device_type;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_TYPE, sizeof (device_type), &device_type, NULL);

      if (CL_rc == -1) return -1;

      device_type &= ~CL_DEVICE_TYPE_DEFAULT;

      device_param->device_type = device_type;

      // device_name

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_NAME, 0, NULL, &param_value_size);

      if (CL_rc == -1) return -1;

      char *device_name = (char *) hcmalloc (param_value_size);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_NAME, param_value_size, device_name, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_name = device_name;

      hc_string_trim_leading (device_param->device_name);

      hc_string_trim_trailing (device_param->device_name);

      // device_vendor

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_VENDOR, 0, NULL, &param_value_size);

      if (CL_rc == -1) return -1;

      char *device_vendor = (char *) hcmalloc (param_value_size);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_VENDOR, param_value_size, device_vendor, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_vendor = device_vendor;

      cl_uint device_vendor_id = 0;

      if (strcmp (device_vendor, CL_VENDOR_AMD1) == 0)
      {
        device_vendor_id = VENDOR_ID_AMD;
      }
      else if (strcmp (device_vendor, CL_VENDOR_AMD2) == 0)
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
      else if (strcmp (device_vendor, CL_VENDOR_APPLE_USE_AMD) == 0)
      {
        device_vendor_id = VENDOR_ID_AMD;
      }
      else if (strcmp (device_vendor, CL_VENDOR_APPLE_USE_NV) == 0)
      {
        device_vendor_id = VENDOR_ID_NV;
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

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_VERSION, 0, NULL, &param_value_size);

      if (CL_rc == -1) return -1;

      char *device_version = (char *) hcmalloc (param_value_size);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_VERSION, param_value_size, device_version, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_version = device_version;

      // device_opencl_version

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &param_value_size);

      if (CL_rc == -1) return -1;

      char *device_opencl_version = (char *) hcmalloc (param_value_size);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_OPENCL_C_VERSION, param_value_size, device_opencl_version, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_opencl_version = device_opencl_version;

      // max_compute_units

      cl_uint device_processors;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof (device_processors), &device_processors, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_processors = device_processors;

      // device_global_mem

      cl_ulong device_global_mem;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof (device_global_mem), &device_global_mem, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_global_mem = device_global_mem;

      device_param->device_available_mem = 0;

      // device_maxmem_alloc

      cl_ulong device_maxmem_alloc;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof (device_maxmem_alloc), &device_maxmem_alloc, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_maxmem_alloc = device_maxmem_alloc;

      // note we'll limit to 2gb, otherwise this causes all kinds of weird errors because of possible integer overflows in opencl runtimes
      // testwise disabling that
      //device_param->device_maxmem_alloc = MIN (device_maxmem_alloc, 0x7fffffff);

      // max_work_group_size

      size_t device_maxworkgroup_size;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof (device_maxworkgroup_size), &device_maxworkgroup_size, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      cl_uint device_maxclock_frequency;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof (device_maxclock_frequency), &device_maxclock_frequency, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_maxclock_frequency = device_maxclock_frequency;

      // device_endian_little

      cl_bool device_endian_little;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_ENDIAN_LITTLE, sizeof (device_endian_little), &device_endian_little, NULL);

      if (CL_rc == -1) return -1;

      if (device_endian_little == CL_FALSE)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device is not little-endian.", device_id + 1);

        device_param->skipped = true;
      }

      // device_available

      cl_bool device_available;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_AVAILABLE, sizeof (device_available), &device_available, NULL);

      if (CL_rc == -1) return -1;

      if (device_available == CL_FALSE)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device is not available.", device_id + 1);

        device_param->skipped = true;
      }

      // device_compiler_available

      cl_bool device_compiler_available;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_COMPILER_AVAILABLE, sizeof (device_compiler_available), &device_compiler_available, NULL);

      if (CL_rc == -1) return -1;

      if (device_compiler_available == CL_FALSE)
      {
        event_log_error (hashcat_ctx, "* Device #%u: No compiler is available for this device.", device_id + 1);

        device_param->skipped = true;
      }

      // device_execution_capabilities

      cl_device_exec_capabilities device_execution_capabilities;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_EXECUTION_CAPABILITIES, sizeof (device_execution_capabilities), &device_execution_capabilities, NULL);

      if (CL_rc == -1) return -1;

      if ((device_execution_capabilities & CL_EXEC_KERNEL) == 0)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device does not support executing kernels.", device_id + 1);

        device_param->skipped = true;
      }

      // device_extensions

      size_t device_extensions_size;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_EXTENSIONS, 0, NULL, &device_extensions_size);

      if (CL_rc == -1) return -1;

      char *device_extensions = hcmalloc (device_extensions_size + 1);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_EXTENSIONS, device_extensions_size, device_extensions, NULL);

      if (CL_rc == -1) return -1;

      if (strstr (device_extensions, "base_atomics") == 0)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device does not support base atomics.", device_id + 1);

        device_param->skipped = true;
      }

      if (strstr (device_extensions, "byte_addressable_store") == 0)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device does not support byte-addressable store.", device_id + 1);

        device_param->skipped = true;
      }

      hcfree (device_extensions);

      // device_max_constant_buffer_size

      cl_ulong device_max_constant_buffer_size;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof (device_max_constant_buffer_size), &device_max_constant_buffer_size, NULL);

      if (CL_rc == -1) return -1;

      if (device_max_constant_buffer_size < 65536)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's constant buffer size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      // device_local_mem_size

      cl_ulong device_local_mem_size;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof (device_local_mem_size), &device_local_mem_size, NULL);

      if (CL_rc == -1) return -1;

      if (device_local_mem_size < 32768)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      device_param->device_local_mem_size = device_local_mem_size;

      // device_local_mem_type

      cl_device_local_mem_type device_local_mem_type;

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_LOCAL_MEM_TYPE, sizeof (device_local_mem_type), &device_local_mem_type, NULL);

      if (CL_rc == -1) return -1;

      device_param->device_local_mem_type = device_local_mem_type;

      // If there's both an Intel CPU and an AMD OpenCL runtime it's a tricky situation
      // Both platforms support CPU device types and therefore both will try to use 100% of the physical resources
      // This results in both utilizing it for 50%
      // However, Intel has much better SIMD control over their own hardware
      // It makes sense to give them full control over their own hardware

      if (device_type & CL_DEVICE_TYPE_CPU)
      {
        if (device_param->device_vendor_id == VENDOR_ID_AMD_USE_INTEL)
        {
          if (user_options->force == false)
          {
            if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Not a native Intel OpenCL runtime. Expect massive speed loss.", device_id + 1);
            if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");

            device_param->skipped = true;
          }
        }
      }

      // Since some times we get reports from users about not working hashcat, dropping error messages like:
      // CL_INVALID_COMMAND_QUEUE and CL_OUT_OF_RESOURCES
      // Turns out that this is caused by Intel OpenCL runtime handling their GPU devices
      // Disable such devices unless the user forces to use it

      #if !defined (__APPLE__)
      if (device_type & CL_DEVICE_TYPE_GPU)
      {
        if ((device_param->device_vendor_id == VENDOR_ID_INTEL_SDK) || (device_param->device_vendor_id == VENDOR_ID_INTEL_BEIGNET))
        {
          if (user_options->force == false)
          {
            if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Intel's OpenCL runtime (GPU only) is currently broken.", device_id + 1);
            if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             We are waiting for updated OpenCL drivers from Intel.");
            if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");

            device_param->skipped = true;
          }
        }
      }
      #endif // __APPLE__

      // skipped

      if ((opencl_ctx->devices_filter & (1ULL << device_id)) == 0)
      {
        device_param->skipped = true;
      }

      if ((opencl_ctx->device_types_filter & (device_type)) == 0)
      {
        device_param->skipped = true;
      }

      // driver_version

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DRIVER_VERSION, 0, NULL, &param_value_size);

      if (CL_rc == -1) return -1;

      char *driver_version = (char *) hcmalloc (param_value_size);

      CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DRIVER_VERSION, param_value_size, driver_version, NULL);

      if (CL_rc == -1) return -1;

      device_param->driver_version = driver_version;

      // vendor specific

      if (device_param->device_type & CL_DEVICE_TYPE_GPU)
      {
        if ((device_param->platform_vendor_id == VENDOR_ID_AMD) && (device_param->device_vendor_id == VENDOR_ID_AMD))
        {
          need_adl = true;

          #if defined (__linux__)
          need_sysfs = true;
          #endif
        }

        if ((device_param->platform_vendor_id == VENDOR_ID_NV) && (device_param->device_vendor_id == VENDOR_ID_NV))
        {
          need_nvml = true;

          #if defined (_WIN) || defined (__CYGWIN__)
          need_nvapi = true;
          #endif
        }
      }

      if (device_param->device_type & CL_DEVICE_TYPE_GPU)
      {
        if ((device_param->platform_vendor_id == VENDOR_ID_AMD) && (device_param->device_vendor_id == VENDOR_ID_AMD))
        {
          cl_device_topology_amd amdtopo;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_TOPOLOGY_AMD, sizeof (amdtopo), &amdtopo, NULL);

          if (CL_rc == -1) return -1;

          device_param->pcie_bus      = amdtopo.pcie.bus;
          device_param->pcie_device   = amdtopo.pcie.device;
          device_param->pcie_function = amdtopo.pcie.function;

          #if defined (__linux__)

          // check for AMD ROCm driver (only available on linux)

          const char *t1 = strstr (device_param->driver_version, "HSA");
          const char *t2 = strstr (device_param->driver_version, "LC");
          const char *t3 = strstr (device_param->driver_version, "PAL");

          if ((t1 == NULL) && (t2 == NULL) && (t3 == NULL))
          {
            device_param->is_rocm = false;
          }
          else
          {
            device_param->is_rocm = true;
          }

          #else

          device_param->is_rocm = false;

          #endif
        }

        if ((device_param->platform_vendor_id == VENDOR_ID_NV) && (device_param->device_vendor_id == VENDOR_ID_NV))
        {
          cl_uint pci_bus_id_nv;  // is cl_uint the right type for them??
          cl_uint pci_slot_id_nv;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_PCI_BUS_ID_NV, sizeof (pci_bus_id_nv), &pci_bus_id_nv, NULL);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_PCI_SLOT_ID_NV, sizeof (pci_slot_id_nv), &pci_slot_id_nv, NULL);

          if (CL_rc == -1) return -1;

          device_param->pcie_bus      = (u8) (pci_bus_id_nv);
          device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
          device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

          cl_uint sm_minor = 0;
          cl_uint sm_major = 0;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof (sm_minor), &sm_minor, NULL);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof (sm_major), &sm_major, NULL);

          if (CL_rc == -1) return -1;

          device_param->sm_minor = sm_minor;
          device_param->sm_major = sm_major;

          cl_uint kernel_exec_timeout = 0;

          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV, sizeof (kernel_exec_timeout), &kernel_exec_timeout, NULL);

          if (CL_rc == -1) return -1;

          device_param->kernel_exec_timeout = kernel_exec_timeout;

          // CPU burning loop damper
          // Value is given as number between 0-100
          // By default 8%

          device_param->spin_damp = (double) user_options->spin_damp / 100;
        }
      }

      // common driver check

      if (device_param->skipped == false)
      {
        if ((user_options->force == false) && (user_options->opencl_info == false))
        {
          if (device_type & CL_DEVICE_TYPE_CPU)
          {
            if (device_param->platform_vendor_id == VENDOR_ID_INTEL_SDK)
            {
              bool intel_warn = false;

              // Intel OpenCL runtime 18

              int opencl_driver1 = 0;
              int opencl_driver2 = 0;
              int opencl_driver3 = 0;
              int opencl_driver4 = 0;

              const int res18 = sscanf (device_param->driver_version, "%u.%u.%u.%u", &opencl_driver1, &opencl_driver2, &opencl_driver3, &opencl_driver4);

              if (res18 == 4)
              {
                // so far all versions 18 are ok
              }
              else
              {
                // Intel OpenCL runtime 16

                float opencl_version = 0;
                int   opencl_build   = 0;

                const int res16 = sscanf (device_param->device_version, "OpenCL %f (Build %d)", &opencl_version, &opencl_build);

                if (res16 == 2)
                {
                  if (opencl_build < 25) intel_warn = true;
                }
              }

              if (intel_warn == true)
              {
                event_log_error (hashcat_ctx, "* Device #%u: Outdated or broken Intel OpenCL runtime detected!", device_id + 1);

                event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported NVIDIA driver.");
                event_log_warning (hashcat_ctx, "See hashcat.net for officially supported NVIDIA drivers.");
                event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                event_log_warning (hashcat_ctx, NULL);

                return -1;
              }
            }
          }
          else if (device_type & CL_DEVICE_TYPE_GPU)
          {
            if (device_param->platform_vendor_id == VENDOR_ID_AMD)
            {
              bool amd_warn = true;

              #if defined (__linux__)
              if (device_param->is_rocm == false)
              {
                // ROCm is so much better, we should give the user some hint and remove this block

                // AMDGPU-PRO Driver 16.40 and higher
                if (strtoul (device_param->driver_version, NULL, 10) >= 2117) amd_warn = false;
                // AMDGPU-PRO Driver 16.50 is known to be broken
                if (strtoul (device_param->driver_version, NULL, 10) == 2236) amd_warn = true;
                // AMDGPU-PRO Driver 16.60 is known to be broken
                if (strtoul (device_param->driver_version, NULL, 10) == 2264) amd_warn = true;
                // AMDGPU-PRO Driver 17.10 is known to be broken
                if (strtoul (device_param->driver_version, NULL, 10) == 2348) amd_warn = true;
                // AMDGPU-PRO Driver 17.20 (2416) is fine, doesn't need check will match >= 2117
              }
              else
              {
                // Support for ROCm platform
                if (strtof (device_param->driver_version, NULL) >= 1.1f) amd_warn = false;
              }
              #elif defined (_WIN)
              // AMD Radeon Software 14.9 and higher, should be updated to 15.12
              if (strtoul (device_param->driver_version, NULL, 10) >= 1573) amd_warn = false;
              #else
              // we have no information about other os
              if (amd_warn == true) amd_warn = false;
              #endif

              if (amd_warn == true)
              {
                event_log_error (hashcat_ctx, "* Device #%u: Outdated or broken AMD driver detected!", device_id + 1);

                event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported AMD driver.");
                event_log_warning (hashcat_ctx, "See hashcat.net for officially supported AMD drivers.");
                event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                event_log_warning (hashcat_ctx, NULL);

                return -1;
              }
            }

            if (device_param->platform_vendor_id == VENDOR_ID_NV)
            {
              int nv_warn = true;

              // nvidia driver 367.x and higher
              if (strtoul (device_param->driver_version, NULL, 10) >= 367) nv_warn = false;

              if (nv_warn == true)
              {
                event_log_error (hashcat_ctx, "* Device #%u: Outdated or broken NVIDIA driver detected!", device_id + 1);

                event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported NVIDIA driver.");
                event_log_warning (hashcat_ctx, "See hashcat's homepage for officially supported NVIDIA drivers.");
                event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                event_log_warning (hashcat_ctx, NULL);

                return -1;
              }

              if (device_param->sm_major < 5)
              {
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: This hardware has outdated CUDA compute capability (%u.%u).", device_id + 1, device_param->sm_major, device_param->sm_minor);
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             For modern OpenCL performance, upgrade to hardware that supports");
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             CUDA compute capability version 5.0 (Maxwell) or higher.");
              }

              if (device_param->kernel_exec_timeout != 0)
              {
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: WARNING! Kernel exec timeout is not disabled.", device_id + 1);
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             This may cause \"CL_OUT_OF_RESOURCES\" or related errors.");
                if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             To disable the timeout, see: https://hashcat.net/q/timeoutpatch");
              }
            }

            if ((strstr (device_param->device_opencl_version, "beignet")) || (strstr (device_param->device_version, "beignet")))
            {
              event_log_error (hashcat_ctx, "* Device #%u: Intel beignet driver detected!", device_id + 1);

              event_log_warning (hashcat_ctx, "The beignet driver has been marked as likely to fail kernel compilation.");
              event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
              event_log_warning (hashcat_ctx, NULL);

              return -1;
            }
          }
        }

        /**
         * activate device
         */

        devices_active++;
      }

      // next please

      devices_cnt++;
    }
  }

  if (devices_active == 0)
  {
    event_log_error (hashcat_ctx, "No devices found/left.");

    return -1;
  }

  // additional check to see if the user has chosen a device that is not within the range of available devices (i.e. larger than devices_cnt)

  if (opencl_ctx->devices_filter != (u64) -1)
  {
    const u64 devices_cnt_mask = ~(((u64) -1 >> devices_cnt) << devices_cnt);

    if (opencl_ctx->devices_filter > devices_cnt_mask)
    {
      event_log_error (hashcat_ctx, "An invalid device was specified using the --opencl-devices parameter.");
      event_log_error (hashcat_ctx, "The specified device was higher than the number of available devices (%u).", devices_cnt);

      return -1;
    }
  }

  opencl_ctx->target_msec     = TARGET_MSEC_PROFILE[user_options->workload_profile - 1];

  opencl_ctx->devices_cnt     = devices_cnt;
  opencl_ctx->devices_active  = devices_active;

  opencl_ctx->need_adl        = need_adl;
  opencl_ctx->need_nvml       = need_nvml;
  opencl_ctx->need_nvapi      = need_nvapi;
  opencl_ctx->need_sysfs      = need_sysfs;

  opencl_ctx->comptime        = comptime;

  return 0;
}

void opencl_ctx_devices_destroy (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (opencl_ctx->enabled == false) return;

  for (u32 platform_id = 0; platform_id < opencl_ctx->platforms_cnt; platform_id++)
  {
    hcfree (opencl_ctx->platforms_vendor[platform_id]);
    hcfree (opencl_ctx->platforms_name[platform_id]);
    hcfree (opencl_ctx->platforms_version[platform_id]);
  }

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    hcfree (device_param->device_name);
    hcfree (device_param->device_version);
    hcfree (device_param->driver_version);
    hcfree (device_param->device_opencl_version);
    hcfree (device_param->device_vendor);
  }

  opencl_ctx->devices_cnt    = 0;
  opencl_ctx->devices_active = 0;

  opencl_ctx->need_adl    = false;
  opencl_ctx->need_nvml   = false;
  opencl_ctx->need_nvapi  = false;
  opencl_ctx->need_sysfs  = false;
}

static bool is_same_device_type (const hc_device_param_t *src, const hc_device_param_t *dst)
{
  if (strcmp (src->device_name,    dst->device_name)    != 0) return false;
  if (strcmp (src->device_vendor,  dst->device_vendor)  != 0) return false;
  if (strcmp (src->device_version, dst->device_version) != 0) return false;
  if (strcmp (src->driver_version, dst->driver_version) != 0) return false;

  if (src->device_processors         != dst->device_processors)         return false;
  if (src->device_maxclock_frequency != dst->device_maxclock_frequency) return false;
  if (src->device_maxworkgroup_size  != dst->device_maxworkgroup_size)  return false;

  // memory size can be different, depending on which gpu has a monitor connected
  // if (src->device_maxmem_alloc       != dst->device_maxmem_alloc)       return false;
  // if (src->device_global_mem         != dst->device_global_mem)         return false;

  if (src->sm_major != dst->sm_major) return false;
  if (src->sm_minor != dst->sm_minor) return false;

  if (src->kernel_exec_timeout != dst->kernel_exec_timeout) return false;

  return true;
}

void opencl_ctx_devices_sync_tuning (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (opencl_ctx->enabled == false) return;

  for (u32 device_id_src = 0; device_id_src < opencl_ctx->devices_cnt; device_id_src++)
  {
    hc_device_param_t *device_param_src = &opencl_ctx->devices_param[device_id_src];

    if (device_param_src->skipped == true) continue;

    for (u32 device_id_dst = device_id_src; device_id_dst < opencl_ctx->devices_cnt; device_id_dst++)
    {
      hc_device_param_t *device_param_dst = &opencl_ctx->devices_param[device_id_dst];

      if (device_param_dst->skipped == true) continue;

      if (is_same_device_type (device_param_src, device_param_dst) == false) continue;

      device_param_dst->kernel_accel = device_param_src->kernel_accel;
      device_param_dst->kernel_loops = device_param_src->kernel_loops;

      const u32 kernel_power = device_param_dst->hardware_power * device_param_dst->kernel_accel;

      device_param_dst->kernel_power = kernel_power;
    }
  }
}

void opencl_ctx_devices_update_power (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t         *opencl_ctx          = hashcat_ctx->opencl_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return;

  u32 kernel_power_all = 0;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    kernel_power_all += device_param->kernel_power;
  }

  opencl_ctx->kernel_power_all = kernel_power_all;

  /*
   * Inform user about possible slow speeds
   */

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (status_ctx->words_base < kernel_power_all)
    {
      if (user_options->quiet == false)
      {
        event_log_advice (hashcat_ctx, "The wordlist or mask that you are using is too small.");
        event_log_advice (hashcat_ctx, "This means that hashcat cannot use the full parallel power of your device(s).");
        event_log_advice (hashcat_ctx, "Unless you supply more work, your cracking speed will drop.");
        event_log_advice (hashcat_ctx, "For tips on supplying more work, see: https://hashcat.net/faq/morework");
        event_log_advice (hashcat_ctx, NULL);
      }
    }
  }
}

void opencl_ctx_devices_kernel_loops (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx      = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  hashes_t             *hashes              = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  opencl_ctx_t         *opencl_ctx          = hashcat_ctx->opencl_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  if (opencl_ctx->enabled == false) return;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    device_param->kernel_loops_min = device_param->kernel_loops_min_sav;
    device_param->kernel_loops_max = device_param->kernel_loops_max_sav;

    if (device_param->kernel_loops_min < device_param->kernel_loops_max)
    {
      u32 innerloop_cnt = 0;

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (user_options->slow_candidates == true)
        {
          innerloop_cnt = 1;
        }
        else
        {
          if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = MIN (KERNEL_RULES, (u32) straight_ctx->kernel_rules_cnt);
          else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)     innerloop_cnt = MIN (KERNEL_COMBS, (u32) combinator_ctx->combs_cnt);
          else if (user_options_extra->attack_kern == ATTACK_KERN_BF)        innerloop_cnt = MIN (KERNEL_BFS,   (u32) mask_ctx->bfs_cnt);
        }
      }
      else
      {
        innerloop_cnt = hashes->salts_buf[0].salt_iter;
      }

      if ((innerloop_cnt >= device_param->kernel_loops_min) &&
          (innerloop_cnt <= device_param->kernel_loops_max))
      {
        device_param->kernel_loops_max = innerloop_cnt;
      }
    }
  }
}

static int get_kernel_wgs (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u32 *result)
{
  int CL_rc;

  size_t work_group_size;

  CL_rc = hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (work_group_size), &work_group_size, NULL);

  if (CL_rc == -1) return -1;

  u32 kernel_threads = (u32) work_group_size;

  size_t compile_work_group_size[3];

  CL_rc = hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->device, CL_KERNEL_COMPILE_WORK_GROUP_SIZE, sizeof (compile_work_group_size), &compile_work_group_size, NULL);

  if (CL_rc == -1) return -1;

  const size_t cwgs_total = compile_work_group_size[0] * compile_work_group_size[1] * compile_work_group_size[2];

  if (cwgs_total > 0)
  {
    kernel_threads = MIN (kernel_threads, (u32) cwgs_total);
  }

  *result = kernel_threads;

  return 0;
}

static int get_kernel_preferred_wgs_multiple (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u32 *result)
{
  int CL_rc;

  size_t preferred_work_group_size_multiple;

  CL_rc = hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->device, CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof (preferred_work_group_size_multiple), &preferred_work_group_size_multiple, NULL);

  if (CL_rc == -1) return -1;

  *result = (u32) preferred_work_group_size_multiple;

  return 0;
}

static int get_kernel_local_mem_size (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u64 *result)
{
  int CL_rc;

  cl_ulong local_mem_size;

  CL_rc = hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->device, CL_KERNEL_LOCAL_MEM_SIZE, sizeof (local_mem_size), &local_mem_size, NULL);

  if (CL_rc == -1) return -1;

  *result = local_mem_size;

  return 0;
}

int opencl_session_begin (hashcat_ctx_t *hashcat_ctx)
{
  bitmap_ctx_t         *bitmap_ctx          = hashcat_ctx->bitmap_ctx;
  folder_config_t      *folder_config       = hashcat_ctx->folder_config;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  hashes_t             *hashes              = hashcat_ctx->hashes;
  opencl_ctx_t         *opencl_ctx          = hashcat_ctx->opencl_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return 0;

  /**
   * Some algorithm, like descrypt, can benefit from JIT compilation
   */

  opencl_ctx->force_jit_compilation = -1;

  if (hashconfig->hash_mode == 8900)
  {
    opencl_ctx->force_jit_compilation = 8900;
  }
  else if (hashconfig->hash_mode == 9300)
  {
    opencl_ctx->force_jit_compilation = 8900;
  }
  else if (hashconfig->hash_mode == 15700)
  {
    opencl_ctx->force_jit_compilation = 15700;
  }
  else if (hashconfig->hash_mode == 1500 && user_options->attack_mode == ATTACK_MODE_BF && hashes->salts_cnt == 1 && user_options->slow_candidates == false)
  {
    opencl_ctx->force_jit_compilation = 1500;
  }

  u32 hardware_power_all = 0;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    int CL_rc = CL_SUCCESS;

    /**
     * host buffer
     */

    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    EVENT_DATA (EVENT_OPENCL_DEVICE_INIT_PRE, &device_id, sizeof (u32));

    bool skipped_temp = false;

    #if defined (__APPLE__)

    /**
     * If '--force' is not set, we proceed to excluding unstable hash-modes,
     * too high kernel runtime, even on -u1 -n1, therefore likely to run into trap 6
     */

    if ((user_options->hash_mode ==  1500)
     || (user_options->hash_mode ==  3000)
     || (user_options->hash_mode ==  3200)
     || (user_options->hash_mode ==  8900)
     || (user_options->hash_mode ==  9300)
     || (user_options->hash_mode ==  9800)
     || (user_options->hash_mode == 12500)
     || (user_options->hash_mode == 14000)
     || (user_options->hash_mode == 14100)
     || (user_options->hash_mode == 15700))
    {
      skipped_temp = true;
    }

    #endif // __APPLE__

    if ((skipped_temp == true) && (user_options->force == false))
    {
      event_log_warning (hashcat_ctx, "* Device #%u: Skipping unstable hash-mode %u for this device.", device_id + 1, user_options->hash_mode);
      event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");

      device_param->skipped = true;

      device_param->skipped_temp = true;

      continue;
    }

    // vector_width

    cl_uint vector_width;

    if (user_options->opencl_vector_width_chgd == false)
    {
      // tuning db

      tuning_db_entry_t *tuningdb_entry;

      if (user_options->slow_candidates == true)
      {
        tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->device_type, 0, hashconfig->hash_mode);
      }
      else
      {
        tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->device_type, user_options->attack_mode, hashconfig->hash_mode);
      }

      if (tuningdb_entry == NULL || tuningdb_entry->vector_width == -1)
      {
        if (hashconfig->opti_type & OPTI_TYPE_USES_BITS_64)
        {
          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, sizeof (vector_width), &vector_width, NULL);

          if (CL_rc == -1) return -1;
        }
        else
        {
          CL_rc = hc_clGetDeviceInfo (hashcat_ctx, device_param->device, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,  sizeof (vector_width), &vector_width, NULL);

          if (CL_rc == -1) return -1;
        }
      }
      else
      {
        vector_width = (cl_uint) tuningdb_entry->vector_width;
      }
    }
    else
    {
      vector_width = user_options->opencl_vector_width;
    }

    // We can't have SIMD in kernels where we have an unknown final password length
    // It also turns out that pure kernels (that have a higher register pressure)
    // actually run faster on scalar GPU (like 1080) without SIMD

    if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
    {
      if (device_param->device_type & CL_DEVICE_TYPE_GPU)
      {
        vector_width = 1;
      }
    }

    if (vector_width > 16) vector_width = 16;

    device_param->vector_width = vector_width;

    /**
     * kernel accel and loops tuning db adjustment
     */

    device_param->kernel_accel_min = 1;
    device_param->kernel_accel_max = 1024;

    device_param->kernel_loops_min = 1;
    device_param->kernel_loops_max = 1024;

    tuning_db_entry_t *tuningdb_entry;

    if (user_options->slow_candidates == true)
    {
      tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->device_type, 0, hashconfig->hash_mode);
    }
    else
    {
      tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->device_type, user_options->attack_mode, hashconfig->hash_mode);
    }

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
        if (user_options->workload_profile == 1)
        {
          _kernel_loops = (_kernel_loops > 8) ? _kernel_loops / 8 : 1;
        }
        else if (user_options->workload_profile == 2)
        {
          _kernel_loops = (_kernel_loops > 4) ? _kernel_loops / 4 : 1;
        }

        device_param->kernel_loops_min = _kernel_loops;
        device_param->kernel_loops_max = _kernel_loops;
      }
    }

    // commandline parameters overwrite tuningdb entries

    if (user_options->kernel_accel_chgd == true)
    {
      device_param->kernel_accel_min = user_options->kernel_accel;
      device_param->kernel_accel_max = user_options->kernel_accel;
    }

    if (user_options->kernel_loops_chgd == true)
    {
      device_param->kernel_loops_min = user_options->kernel_loops;
      device_param->kernel_loops_max = user_options->kernel_loops;
    }

    // limit scrypt accel otherwise we hurt ourself when calculating the scrypt tmto

    #define SCRYPT_MAX_ACCEL 16

    if ((hashconfig->hash_mode == 8900) || (hashconfig->hash_mode == 9300) || (hashconfig->hash_mode == 15700))
    {
      // 16 is actually a bit low, we may need to change this depending on user response

      device_param->kernel_accel_max = MIN (device_param->kernel_accel_max, SCRYPT_MAX_ACCEL);
    }

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      // we have some absolute limits for fast hashes (because of limit constant memory), make sure not to overstep

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          device_param->kernel_loops_min = MIN (device_param->kernel_loops_min, KERNEL_RULES);
          device_param->kernel_loops_max = MIN (device_param->kernel_loops_max, KERNEL_RULES);
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          device_param->kernel_loops_min = MIN (device_param->kernel_loops_min, KERNEL_COMBS);
          device_param->kernel_loops_max = MIN (device_param->kernel_loops_max, KERNEL_COMBS);
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          device_param->kernel_loops_min = MIN (device_param->kernel_loops_min, KERNEL_BFS);
          device_param->kernel_loops_max = MIN (device_param->kernel_loops_max, KERNEL_BFS);
        }
      }
    }

    /**
     * device properties
     */

    const u32 device_processors = device_param->device_processors;

    /**
     * create context for each device
     */

    cl_context_properties properties[3];

    properties[0] = CL_CONTEXT_PLATFORM;
    properties[1] = (cl_context_properties) device_param->platform;
    properties[2] = 0;

    CL_rc = hc_clCreateContext (hashcat_ctx, properties, 1, &device_param->device, NULL, NULL, &device_param->context);

    if (CL_rc == -1) return -1;

    /**
     * create command-queue
     */

    // not supported with NV
    // device_param->command_queue = hc_clCreateCommandQueueWithProperties (hashcat_ctx, device_param->device, NULL);

    CL_rc = hc_clCreateCommandQueue (hashcat_ctx, device_param->context, device_param->device, CL_QUEUE_PROFILING_ENABLE, &device_param->command_queue);

    if (CL_rc == -1) return -1;

    // device_available_mem

    #define MAX_ALLOC_CHECKS_CNT  8192
    #define MAX_ALLOC_CHECKS_SIZE (64 * 1024 * 1024)

    device_param->device_available_mem = device_param->device_global_mem - MAX_ALLOC_CHECKS_SIZE;

    if ((device_param->device_type & CL_DEVICE_TYPE_GPU) && ((device_param->platform_vendor_id == VENDOR_ID_NV) || ((device_param->platform_vendor_id == VENDOR_ID_AMD) && (device_param->is_rocm == false))))
    {
      // OK, so the problem here is the following:
      // There's just CL_DEVICE_GLOBAL_MEM_SIZE to ask OpenCL about the total memory on the device,
      // but there's no way to ask for available memory on the device.
      // In combination, most OpenCL runtimes implementation of clCreateBuffer()
      // are doing so called lazy memory allocation on the device.
      // Now, if the user has X11 (or a game or anything that takes a lot of GPU memory)
      // running on the host we end up with an error type of this:
      // clEnqueueNDRangeKernel(): CL_MEM_OBJECT_ALLOCATION_FAILURE
      // The clEnqueueNDRangeKernel() is because of the lazy allocation
      // The best way to workaround this problem is if we would be able to ask for available memory,
      // The idea here is to try to evaluate available memory by allocating it till it errors

      cl_mem *tmp_device = (cl_mem *) hccalloc (MAX_ALLOC_CHECKS_CNT, sizeof (cl_mem));

      u64 c;

      for (c = 0; c < MAX_ALLOC_CHECKS_CNT; c++)
      {
        if (((c + 1 + 1) * MAX_ALLOC_CHECKS_SIZE) >= device_param->device_global_mem) break;

        cl_int CL_err;

        OCL_PTR *ocl = opencl_ctx->ocl;

        tmp_device[c] = ocl->clCreateBuffer (device_param->context, CL_MEM_READ_WRITE, MAX_ALLOC_CHECKS_SIZE, NULL, &CL_err);

        if (CL_err != CL_SUCCESS)
        {
          c--;

          break;
        }

        // transfer only a few byte should be enough to force the runtime to actually allocate the memory

        u8 tmp_host[8];

        CL_err = ocl->clEnqueueReadBuffer  (device_param->command_queue, tmp_device[c], CL_TRUE, 0, sizeof (tmp_host), tmp_host, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS) break;

        CL_err = ocl->clEnqueueWriteBuffer (device_param->command_queue, tmp_device[c], CL_TRUE, 0, sizeof (tmp_host), tmp_host, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS) break;

        CL_err = ocl->clEnqueueReadBuffer  (device_param->command_queue, tmp_device[c], CL_TRUE, MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), sizeof (tmp_host), tmp_host, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS) break;

        CL_err = ocl->clEnqueueWriteBuffer (device_param->command_queue, tmp_device[c], CL_TRUE, MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), sizeof (tmp_host), tmp_host, 0, NULL, NULL);

        if (CL_err != CL_SUCCESS) break;
      }

      device_param->device_available_mem = c * MAX_ALLOC_CHECKS_SIZE;

      // clean up

      for (c = 0; c < MAX_ALLOC_CHECKS_CNT; c++)
      {
        if (((c + 1 + 1) * MAX_ALLOC_CHECKS_SIZE) >= device_param->device_global_mem) break;

        if (tmp_device[c] != NULL)
        {
          CL_rc = hc_clReleaseMemObject (hashcat_ctx, tmp_device[c]);

          if (CL_rc == -1) return -1;
        }
      }

      hcfree (tmp_device);
    }

    /**
     * create input buffers on device : calculate size of fixed memory buffers
     */

    u64 size_root_css   = SP_PW_MAX *           sizeof (cs_t);
    u64 size_markov_css = SP_PW_MAX * CHARSIZ * sizeof (cs_t);

    device_param->size_root_css   = size_root_css;
    device_param->size_markov_css = size_markov_css;

    u64 size_results = sizeof (u32);

    device_param->size_results = size_results;

    u64 size_rules   = (u64) straight_ctx->kernel_rules_cnt * sizeof (kernel_rule_t);
    u64 size_rules_c = (u64) KERNEL_RULES                   * sizeof (kernel_rule_t);

    u64 size_plains  = (u64) hashes->digests_cnt * sizeof (plain_t);
    u64 size_salts   = (u64) hashes->salts_cnt   * sizeof (salt_t);
    u64 size_esalts  = (u64) hashes->digests_cnt * (u64) hashconfig->esalt_size;
    u64 size_shown   = (u64) hashes->digests_cnt * sizeof (u32);
    u64 size_digests = (u64) hashes->digests_cnt * (u64) hashconfig->dgst_size;

    device_param->size_plains   = size_plains;
    device_param->size_digests  = size_digests;
    device_param->size_shown    = size_shown;
    device_param->size_salts    = size_salts;

    u64 size_combs = KERNEL_COMBS * sizeof (pw_t);
    u64 size_bfs   = KERNEL_BFS   * sizeof (bf_t);
    u64 size_tm    = 32           * sizeof (bs_word_t);

    u64 size_st_digests = 1 * hashconfig->dgst_size;
    u64 size_st_salts   = 1 * sizeof (salt_t);
    u64 size_st_esalts  = 1 * hashconfig->esalt_size;

    device_param->size_st_digests = size_st_digests;
    device_param->size_st_salts   = size_st_salts;
    device_param->size_st_esalts  = size_st_esalts;

    /**
     * some algorithms need a fixed kernel-loops count
     */

    const u32 kernel_loops_fixed = hashconfig_get_kernel_loops (hashcat_ctx);

    if (kernel_loops_fixed != 0)
    {
      device_param->kernel_loops_min = kernel_loops_fixed;
      device_param->kernel_loops_max = kernel_loops_fixed;
    }

    device_param->kernel_loops_min_sav = device_param->kernel_loops_min;
    device_param->kernel_loops_max_sav = device_param->kernel_loops_max;

    device_param->size_bfs      = size_bfs;
    device_param->size_combs    = size_combs;
    device_param->size_rules    = size_rules;
    device_param->size_rules_c  = size_rules_c;

    // scryptV stuff

    u64 scrypt_tmp_size   = 0;
    u64 scrypt_tmto_final = 0;

    u64 size_scrypt = 4;

    if ((hashconfig->hash_mode == 8900) || (hashconfig->hash_mode == 9300) || (hashconfig->hash_mode == 15700))
    {
      // we need to check that all hashes have the same scrypt settings

      const u32 scrypt_N = hashes->salts_buf[0].scrypt_N;
      const u32 scrypt_r = hashes->salts_buf[0].scrypt_r;
      const u32 scrypt_p = hashes->salts_buf[0].scrypt_p;

      for (u32 i = 1; i < hashes->salts_cnt; i++)
      {
        if ((hashes->salts_buf[i].scrypt_N != scrypt_N)
         || (hashes->salts_buf[i].scrypt_r != scrypt_r)
         || (hashes->salts_buf[i].scrypt_p != scrypt_p))
        {
          event_log_error (hashcat_ctx, "Mixed scrypt settings are not supported.");

          return -1;
        }
      }

      scrypt_tmp_size = (128 * scrypt_r * scrypt_p);

      hashconfig->tmp_size = scrypt_tmp_size;

      u32 tmto_start = 1;
      u32 tmto_stop  = 6;

      if (user_options->scrypt_tmto)
      {
        tmto_start = user_options->scrypt_tmto;
        tmto_stop  = user_options->scrypt_tmto;
      }

      const u32 scrypt_threads = hashconfig_forced_kernel_threads (hashcat_ctx);

      const u64 kernel_power_max = SCRYPT_MAX_ACCEL * device_processors * scrypt_threads;

      // size_pws

      const u64 size_pws = kernel_power_max * sizeof (pw_t);

      const u64 size_pws_amp = size_pws;

      // size_pws_comp

      const u64 size_pws_comp = kernel_power_max * (sizeof (u32) * 64);

      // size_pws_idx

      const u64 size_pws_idx = (kernel_power_max + 1) * sizeof (pw_idx_t);

      // size_tmps

      const u64 size_tmps = kernel_power_max * hashconfig->tmp_size;

      // size_hooks

      const u64 size_hooks = kernel_power_max * hashconfig->hook_size;

      const u64 scrypt_extra_space
        = bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + size_bfs
        + size_combs
        + size_digests
        + size_esalts
        + size_hooks
        + size_markov_css
        + size_plains
        + size_pws
        + size_pws_amp
        + size_pws_comp
        + size_pws_idx
        + size_results
        + size_root_css
        + size_rules
        + size_rules_c
        + size_salts
        + size_shown
        + size_tm
        + size_tmps
        + size_st_digests
        + size_st_salts
        + size_st_esalts;

      bool not_enough_memory = true;

      u32 tmto;

      for (tmto = tmto_start; tmto <= tmto_stop; tmto++)
      {
        size_scrypt = (128 * scrypt_r) * scrypt_N;

        size_scrypt /= 1u << tmto;

        size_scrypt *= kernel_power_max;

        if ((size_scrypt / 4) > device_param->device_maxmem_alloc)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "Increasing single-block device memory allocatable for --scrypt-tmto %u.", tmto);

          continue;
        }

        if ((size_scrypt + scrypt_extra_space) > device_param->device_available_mem)
        {
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "Increasing total device memory allocatable for --scrypt-tmto %u.", tmto);

          continue;
        }

        for (u32 salts_pos = 0; salts_pos < hashes->salts_cnt; salts_pos++)
        {
          scrypt_tmto_final = tmto;
        }

        not_enough_memory = false;

        break;
      }

      if (not_enough_memory == true)
      {
        event_log_error (hashcat_ctx, "Cannot allocate enough device memory. Perhaps retry with -n 1.");

        return -1;
      }

      #if defined (DEBUG)
      if (user_options->quiet == false) event_log_warning (hashcat_ctx, "SCRYPT tmto optimizer value set to: %lu, mem: %lu", scrypt_tmto_final, size_scrypt);
      if (user_options->quiet == false) event_log_warning (hashcat_ctx, NULL);
      #endif
    }

    size_t size_scrypt4 = size_scrypt / 4;

    /**
     * default building options
     */

    if (chdir (folder_config->cpath_real) == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", folder_config->cpath_real, strerror (errno));

      return -1;
    }

    // include check
    // this test needs to be done manually because of macOS opencl runtime
    // if there's a problem with permission, its not reporting back and erroring out silently

    #define files_cnt 16

    const char *files_names[files_cnt] =
    {
      "inc_cipher_aes.cl",
      "inc_cipher_serpent.cl",
      "inc_cipher_twofish.cl",
      "inc_common.cl",
      "inc_comp_multi_bs.cl",
      "inc_comp_multi.cl",
      "inc_comp_single_bs.cl",
      "inc_comp_single.cl",
      "inc_hash_constants.h",
      "inc_hash_functions.cl",
      "inc_rp_optimized.cl",
      "inc_rp_optimized.h",
      "inc_simd.cl",
      "inc_scalar.cl",
      "inc_types.cl",
      "inc_vendor.cl",
    };

    for (int i = 0; i < files_cnt; i++)
    {
      if (hc_path_read (files_names[i]) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", files_names[i], strerror (errno));

        return -1;
      }
    }

    // return back to the folder we came from initially (workaround)

    #if defined (_WIN)
    if (chdir ("..") == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", "..", strerror (errno));

      return -1;
    }
    #else
    if (chdir (folder_config->cwd) == -1)
    {
      event_log_error (hashcat_ctx, "%s: %s", folder_config->cwd, strerror (errno));

      return -1;
    }
    #endif

    char build_opts_base[1024] = { 0 };

    #if defined (_WIN)
    snprintf (build_opts_base, sizeof (build_opts_base), "-cl-std=CL1.2 -I OpenCL -I \"%s\"", folder_config->cpath_real);
    #else
    snprintf (build_opts_base, sizeof (build_opts_base), "-cl-std=CL1.2 -I OpenCL -I %s", folder_config->cpath_real);
    #endif

    // we don't have sm_* on vendors not NV but it doesn't matter

    char build_opts[2048] = { 0 };

    #if defined (DEBUG)
    snprintf (build_opts, sizeof (build_opts), "%s -D LOCAL_MEM_TYPE=%u -D VENDOR_ID=%u -D CUDA_ARCH=%u -D AMD_ROCM=%u -D VECT_SIZE=%u -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D _unroll", build_opts_base, device_param->device_local_mem_type, device_param->platform_vendor_id, (device_param->sm_major * 100) + device_param->sm_minor, device_param->is_rocm, device_param->vector_width, (u32) device_param->device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, hashconfig->kern_type);
    #else
    snprintf (build_opts, sizeof (build_opts), "%s -D LOCAL_MEM_TYPE=%u -D VENDOR_ID=%u -D CUDA_ARCH=%u -D AMD_ROCM=%u -D VECT_SIZE=%u -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D _unroll -w", build_opts_base, device_param->device_local_mem_type, device_param->platform_vendor_id, (device_param->sm_major * 100) + device_param->sm_minor, device_param->is_rocm, device_param->vector_width, (u32) device_param->device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, hashconfig->kern_type);
    #endif

    /*
    if (device_param->device_type & CL_DEVICE_TYPE_CPU)
    {
      if (device_param->platform_vendor_id == VENDOR_ID_INTEL_SDK)
      {
        strncat (build_opts, " -cl-opt-disable", 16);
      }
    }
    */

    #if defined (DEBUG)
    if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: build_opts '%s'", device_id + 1, build_opts);
    #endif

    /**
     * device_name_chksum
     */

    char *device_name_chksum        = (char *) hcmalloc (HCBUFSIZ_TINY);
    char *device_name_chksum_amp_mp = (char *) hcmalloc (HCBUFSIZ_TINY);

    #if defined (__x86_64__)
    const size_t dnclen        = snprintf (device_name_chksum,        HCBUFSIZ_TINY, "%d-%u-%u-%s-%s-%s-%d-%u-%u", 64, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, opencl_ctx->comptime, user_options->opencl_vector_width, user_options->hash_mode);
    const size_t dnclen_amp_mp = snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%d-%u-%s-%s-%s-%d",          64, device_param->platform_vendor_id,                             device_param->device_name, device_param->device_version, device_param->driver_version, opencl_ctx->comptime);
    #else
    const size_t dnclen        = snprintf (device_name_chksum,        HCBUFSIZ_TINY, "%d-%u-%u-%s-%s-%s-%d-%u-%u", 32, device_param->platform_vendor_id, device_param->vector_width, device_param->device_name, device_param->device_version, device_param->driver_version, opencl_ctx->comptime, user_options->opencl_vector_width, user_options->hash_mode);
    const size_t dnclen_amp_mp = snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%d-%u-%s-%s-%s-%d",          32, device_param->platform_vendor_id,                             device_param->device_name, device_param->device_version, device_param->driver_version, opencl_ctx->comptime);
    #endif

    u32 device_name_digest[4] = { 0 };

    for (size_t i = 0; i < dnclen; i += 64)
    {
      md5_64 ((u32 *) (device_name_chksum + i), device_name_digest);
    }

    snprintf (device_name_chksum, HCBUFSIZ_TINY, "%08x", device_name_digest[0]);

    u32 device_name_digest_amp_mp[4] = { 0 };

    for (size_t i = 0; i < dnclen_amp_mp; i += 64)
    {
      md5_64 ((u32 *) (device_name_chksum_amp_mp + i), device_name_digest_amp_mp);
    }

    snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%08x", device_name_digest_amp_mp[0]);

    /**
     * main kernel
     */

    {
      /**
       * kernel source filename
       */

      char source_file[256] = { 0 };

      generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, hashconfig->opti_type, folder_config->shared_dir, source_file);

      if (hc_path_read (source_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", source_file, strerror (errno));

        return -1;
      }

      /**
       * kernel cached filename
       */

      char cached_file[256] = { 0 };

      generate_cached_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, hashconfig->kern_type, hashconfig->opti_type, folder_config->profile_dir, device_name_chksum, cached_file);

      bool cached = true;

      if (hc_path_read (cached_file) == false)
      {
        cached = false;
      }

      if (hc_path_is_empty (cached_file) == true)
      {
        cached = false;
      }

      /**
       * kernel compile or load
       */

      size_t kernel_lengths_buf = 0;

      size_t *kernel_lengths = &kernel_lengths_buf;

      char *kernel_sources_buf = NULL;

      char **kernel_sources = &kernel_sources_buf;

      if (opencl_ctx->force_jit_compilation == -1)
      {
        if (cached == false)
        {
          #if defined (DEBUG)
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          #endif

          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithSource (hashcat_ctx, device_param->context, 1, kernel_sources, NULL, &device_param->program);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program, 1, &device_param->device, build_opts, NULL, NULL);

          //if (CL_rc == -1) return -1;

          size_t build_log_size = 0;

          hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          //if (CL_rc == -1) return -1;

          #if defined (DEBUG)
          if ((build_log_size > 1) || (CL_rc == -1))
          #else
          if (CL_rc == -1)
          #endif
          {
            char *build_log = (char *) hcmalloc (build_log_size + 1);

            int CL_rc_build = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_rc_build == -1) return -1;

            puts (build_log);

            hcfree (build_log);
          }

          if (CL_rc == -1)
          {
            device_param->skipped = true;

            event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          size_t binary_size;

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

          if (CL_rc == -1) return -1;

          char *binary = (char *) hcmalloc (binary_size);

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL);

          if (CL_rc == -1) return -1;

          const bool rc_write = write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

          if (rc_write == false) return -1;

          hcfree (binary);
        }
        else
        {
          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithBinary (hashcat_ctx, device_param->context, 1, &device_param->device, kernel_lengths, (unsigned char **) kernel_sources, NULL, &device_param->program);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_rc == -1) return -1;
        }
      }
      else
      {
        const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true);

        if (rc_read_kernel == false) return -1;

        CL_rc = hc_clCreateProgramWithSource (hashcat_ctx, device_param->context, 1, kernel_sources, NULL, &device_param->program);

        if (CL_rc == -1) return -1;

        char *build_opts_update;

        if (opencl_ctx->force_jit_compilation == 1500)
        {
          hc_asprintf (&build_opts_update, "%s -DDESCRYPT_SALT=%u", build_opts, hashes->salts_buf[0].salt_buf[0]);
        }
        else if ((opencl_ctx->force_jit_compilation == 8900) || (opencl_ctx->force_jit_compilation == 15700))
        {
          hc_asprintf (&build_opts_update,"%s -DSCRYPT_N=%u -DSCRYPT_R=%u -DSCRYPT_P=%u -DSCRYPT_TMTO=%u -DSCRYPT_TMP_ELEM=%" PRIu64, build_opts, hashes->salts_buf[0].scrypt_N, hashes->salts_buf[0].scrypt_r, hashes->salts_buf[0].scrypt_p, 1u << scrypt_tmto_final, (u64) scrypt_tmp_size / 16);
        }
        else
        {
          hc_asprintf (&build_opts_update, "%s", build_opts);
        }

        CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program, 1, &device_param->device, build_opts_update, NULL, NULL);

        free (build_opts_update);

        //if (CL_rc == -1) return -1;

        size_t build_log_size = 0;

        hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

        //if (CL_rc == -1) return -1;

        #if defined (DEBUG)
        if ((build_log_size > 1) || (CL_rc == -1))
        #else
        if (CL_rc == -1)
        #endif
        {
          char *build_log = (char *) hcmalloc (build_log_size + 1);

          int CL_rc_build = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

          if (CL_rc_build == -1) return -1;

          puts (build_log);

          hcfree (build_log);
        }

        if (CL_rc == -1)
        {
          device_param->skipped = true;

          event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

          continue;
        }
      }

      hcfree (kernel_sources[0]);
    }

    /**
     * word generator kernel
     */

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (user_options->attack_mode != ATTACK_MODE_STRAIGHT)
      {
        /**
         * kernel mp source filename
         */

        char source_file[256] = { 0 };

        generate_source_kernel_mp_filename (hashconfig->opti_type, hashconfig->opts_type, folder_config->shared_dir, source_file);

        if (hc_path_read (source_file) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", source_file, strerror (errno));

          return -1;
        }

        /**
         * kernel mp cached filename
         */

        char cached_file[256] = { 0 };

        generate_cached_kernel_mp_filename (hashconfig->opti_type, hashconfig->opts_type, folder_config->profile_dir, device_name_chksum_amp_mp, cached_file);

        bool cached = true;

        if (hc_path_read (cached_file) == false)
        {
          cached = false;
        }

        if (hc_path_is_empty (cached_file) == true)
        {
          cached = false;
        }

        /**
         * kernel compile or load
         */

        size_t kernel_lengths_buf = 0;

        size_t *kernel_lengths = &kernel_lengths_buf;

        char *kernel_sources_buf = NULL;

        char **kernel_sources = &kernel_sources_buf;

        if (cached == false)
        {
          #if defined (DEBUG)
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          #endif

          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithSource (hashcat_ctx, device_param->context, 1, kernel_sources, NULL, &device_param->program_mp);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program_mp, 1, &device_param->device, build_opts, NULL, NULL);

          //if (CL_rc == -1) return -1;

          size_t build_log_size = 0;

          hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program_mp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          //if (CL_rc == -1) return -1;

          #if defined (DEBUG)
          if ((build_log_size > 1) || (CL_rc == -1))
          #else
          if (CL_rc == -1)
          #endif
          {
            char *build_log = (char *) hcmalloc (build_log_size + 1);

            int CL_rc_build = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program_mp, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_rc_build == -1) return -1;

            puts (build_log);

            hcfree (build_log);
          }

          if (CL_rc == -1)
          {
            device_param->skipped = true;

            event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          size_t binary_size;

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program_mp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

          if (CL_rc == -1) return -1;

          char *binary = (char *) hcmalloc (binary_size);

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program_mp, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL);

          if (CL_rc == -1) return -1;

          write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

          hcfree (binary);
        }
        else
        {
          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithBinary (hashcat_ctx, device_param->context, 1, &device_param->device, kernel_lengths, (unsigned char **) kernel_sources, NULL, &device_param->program_mp);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program_mp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_rc == -1) return -1;
        }

        hcfree (kernel_sources[0]);
      }
    }

    /**
     * amplifier kernel
     */

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {

      }
      else
      {
        /**
         * kernel amp source filename
         */

        char source_file[256] = { 0 };

        generate_source_kernel_amp_filename (user_options_extra->attack_kern, folder_config->shared_dir, source_file);

        if (hc_path_read (source_file) == false)
        {
          event_log_error (hashcat_ctx, "%s: %s", source_file, strerror (errno));

          return -1;
        }

        /**
         * kernel amp cached filename
         */

        char cached_file[256] = { 0 };

        generate_cached_kernel_amp_filename (user_options_extra->attack_kern, folder_config->profile_dir, device_name_chksum_amp_mp, cached_file);

        bool cached = true;

        if (hc_path_read (cached_file) == false)
        {
          cached = false;
        }

        if (hc_path_is_empty (cached_file) == true)
        {
          cached = false;
        }

        /**
         * kernel compile or load
         */

        size_t kernel_lengths_buf = 0;

        size_t *kernel_lengths = &kernel_lengths_buf;

        char *kernel_sources_buf = NULL;

        char **kernel_sources = &kernel_sources_buf;

        if (cached == false)
        {
          #if defined (DEBUG)
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          #endif

          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithSource (hashcat_ctx, device_param->context, 1, kernel_sources, NULL, &device_param->program_amp);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program_amp, 1, &device_param->device, build_opts, NULL, NULL);

          //if (CL_rc == -1) return -1;

          size_t build_log_size = 0;

          hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program_amp, device_param->device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          //if (CL_rc == -1) return -1;

          #if defined (DEBUG)
          if ((build_log_size > 1) || (CL_rc == -1))
          #else
          if (CL_rc == -1)
          #endif
          {
            char *build_log = (char *) hcmalloc (build_log_size + 1);

            int CL_rc_build_info = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->program_amp, device_param->device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (CL_rc_build_info == -1) return -1;

            puts (build_log);

            hcfree (build_log);
          }

          if (CL_rc == -1)
          {
            device_param->skipped = true;

            event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          size_t binary_size;

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program_amp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL);

          if (CL_rc == -1) return -1;

          char *binary = (char *) hcmalloc (binary_size);

          CL_rc = hc_clGetProgramInfo (hashcat_ctx, device_param->program_amp, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL);

          if (CL_rc == -1) return -1;

          write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

          hcfree (binary);
        }
        else
        {
          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false);

          if (rc_read_kernel == false) return -1;

          CL_rc = hc_clCreateProgramWithBinary (hashcat_ctx, device_param->context, 1, &device_param->device, kernel_lengths, (unsigned char **) kernel_sources, NULL, &device_param->program_amp);

          if (CL_rc == -1) return -1;

          CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->program_amp, 1, &device_param->device, build_opts, NULL, NULL);

          if (CL_rc == -1) return -1;
        }

        hcfree (kernel_sources[0]);
      }
    }

    hcfree (device_name_chksum);
    hcfree (device_name_chksum_amp_mp);

    // some algorithm collide too fast, make that impossible

    if (user_options->benchmark == true)
    {
      ((u32 *) hashes->digests_buf)[0] = -1u;
      ((u32 *) hashes->digests_buf)[1] = -1u;
      ((u32 *) hashes->digests_buf)[2] = -1u;
      ((u32 *) hashes->digests_buf)[3] = -1u;
    }

    /**
     * global buffers
     */

    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s1_a);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s1_b);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s1_c);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s1_d);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s2_a);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s2_b);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s2_c);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->d_bitmap_s2_d);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_plains,             NULL, &device_param->d_plain_bufs);     if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_digests,            NULL, &device_param->d_digests_buf);    if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_shown,              NULL, &device_param->d_digests_shown);  if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_salts,              NULL, &device_param->d_salt_bufs);      if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_results,            NULL, &device_param->d_result);         if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4,            NULL, &device_param->d_scryptV0_buf);   if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4,            NULL, &device_param->d_scryptV1_buf);   if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4,            NULL, &device_param->d_scryptV2_buf);   if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_scrypt4,            NULL, &device_param->d_scryptV3_buf);   if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_st_digests,         NULL, &device_param->d_st_digests_buf); if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_st_salts,           NULL, &device_param->d_st_salts_buf);   if (CL_rc == -1) return -1;

    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s1_a,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_a, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s1_b,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_b, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s1_c,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_c, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s1_d,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_d, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s2_a,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_a, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s2_b,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_b, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s2_c,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_c, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_bitmap_s2_d,     CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_d, 0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_digests_buf,     CL_TRUE, 0, size_digests,            hashes->digests_buf,     0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_salt_bufs,       CL_TRUE, 0, size_salts,              hashes->salts_buf,       0, NULL, NULL); if (CL_rc == -1) return -1;

    /**
     * special buffers
     */

    if (user_options->slow_candidates == true)
    {
      CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_rules_c, NULL, &device_param->d_rules_c); if (CL_rc == -1) return -1;
    }
    else
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_rules,   NULL, &device_param->d_rules);   if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_rules_c, NULL, &device_param->d_rules_c); if (CL_rc == -1) return -1;

        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_rules, CL_TRUE, 0, size_rules, straight_ctx->kernel_rules_buf, 0, NULL, NULL); if (CL_rc == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->d_combs);          if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->d_combs_c);        if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->d_root_css_buf);   if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->d_markov_css_buf); if (CL_rc == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->d_bfs);            if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->d_bfs_c);          if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_tm,         NULL, &device_param->d_tm_c);           if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->d_root_css_buf);   if (CL_rc == -1) return -1;
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->d_markov_css_buf); if (CL_rc == -1) return -1;
      }
    }

    if (size_esalts)
    {
      CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_esalts, NULL, &device_param->d_esalt_bufs);

      if (CL_rc == -1) return -1;

      CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_esalt_bufs, CL_TRUE, 0, size_esalts, hashes->esalts_buf, 0, NULL, NULL);

      if (CL_rc == -1) return -1;
    }

    if (hashconfig->st_hash != NULL)
    {
      CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_st_digests_buf,  CL_TRUE, 0, size_st_digests,         hashes->st_digests_buf,  0, NULL, NULL); if (CL_rc == -1) return -1;
      CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_st_salts_buf,    CL_TRUE, 0, size_st_salts,           hashes->st_salts_buf,    0, NULL, NULL); if (CL_rc == -1) return -1;

      if (size_esalts)
      {
        CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY, size_st_esalts, NULL, &device_param->d_st_esalts_buf);

        if (CL_rc == -1) return -1;

        CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_st_esalts_buf, CL_TRUE, 0, size_st_esalts, hashes->st_esalts_buf, 0, NULL, NULL);

        if (CL_rc == -1) return -1;
      }
    }

    /**
     * kernel args
     */

    device_param->kernel_params_buf32[24] = bitmap_ctx->bitmap_mask;
    device_param->kernel_params_buf32[25] = bitmap_ctx->bitmap_shift1;
    device_param->kernel_params_buf32[26] = bitmap_ctx->bitmap_shift2;
    device_param->kernel_params_buf32[27] = 0; // salt_pos
    device_param->kernel_params_buf32[28] = 0; // loop_pos
    device_param->kernel_params_buf32[29] = 0; // loop_cnt
    device_param->kernel_params_buf32[30] = 0; // kernel_rules_cnt
    device_param->kernel_params_buf32[31] = 0; // digests_cnt
    device_param->kernel_params_buf32[32] = 0; // digests_offset
    device_param->kernel_params_buf32[33] = 0; // combs_mode
    device_param->kernel_params_buf64[34] = 0; // gid_max

    device_param->kernel_params[ 0] = NULL; // &device_param->d_pws_buf;
    device_param->kernel_params[ 1] = &device_param->d_rules_c;
    device_param->kernel_params[ 2] = &device_param->d_combs_c;
    device_param->kernel_params[ 3] = &device_param->d_bfs_c;
    device_param->kernel_params[ 4] = NULL; // &device_param->d_tmps;
    device_param->kernel_params[ 5] = NULL; // &device_param->d_hooks;
    device_param->kernel_params[ 6] = &device_param->d_bitmap_s1_a;
    device_param->kernel_params[ 7] = &device_param->d_bitmap_s1_b;
    device_param->kernel_params[ 8] = &device_param->d_bitmap_s1_c;
    device_param->kernel_params[ 9] = &device_param->d_bitmap_s1_d;
    device_param->kernel_params[10] = &device_param->d_bitmap_s2_a;
    device_param->kernel_params[11] = &device_param->d_bitmap_s2_b;
    device_param->kernel_params[12] = &device_param->d_bitmap_s2_c;
    device_param->kernel_params[13] = &device_param->d_bitmap_s2_d;
    device_param->kernel_params[14] = &device_param->d_plain_bufs;
    device_param->kernel_params[15] = &device_param->d_digests_buf;
    device_param->kernel_params[16] = &device_param->d_digests_shown;
    device_param->kernel_params[17] = &device_param->d_salt_bufs;
    device_param->kernel_params[18] = &device_param->d_esalt_bufs;
    device_param->kernel_params[19] = &device_param->d_result;
    device_param->kernel_params[20] = &device_param->d_scryptV0_buf;
    device_param->kernel_params[21] = &device_param->d_scryptV1_buf;
    device_param->kernel_params[22] = &device_param->d_scryptV2_buf;
    device_param->kernel_params[23] = &device_param->d_scryptV3_buf;
    device_param->kernel_params[24] = &device_param->kernel_params_buf32[24];
    device_param->kernel_params[25] = &device_param->kernel_params_buf32[25];
    device_param->kernel_params[26] = &device_param->kernel_params_buf32[26];
    device_param->kernel_params[27] = &device_param->kernel_params_buf32[27];
    device_param->kernel_params[28] = &device_param->kernel_params_buf32[28];
    device_param->kernel_params[29] = &device_param->kernel_params_buf32[29];
    device_param->kernel_params[30] = &device_param->kernel_params_buf32[30];
    device_param->kernel_params[31] = &device_param->kernel_params_buf32[31];
    device_param->kernel_params[32] = &device_param->kernel_params_buf32[32];
    device_param->kernel_params[33] = &device_param->kernel_params_buf32[33];
    device_param->kernel_params[34] = &device_param->kernel_params_buf64[34];

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      device_param->kernel_params_mp_buf64[3] = 0;
      device_param->kernel_params_mp_buf32[4] = 0;
      device_param->kernel_params_mp_buf32[5] = 0;
      device_param->kernel_params_mp_buf32[6] = 0;
      device_param->kernel_params_mp_buf32[7] = 0;
      device_param->kernel_params_mp_buf64[8] = 0;

      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        device_param->kernel_params_mp[0] = &device_param->d_combs;
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          device_param->kernel_params_mp[0] = &device_param->d_combs;
        }
        else
        {
          device_param->kernel_params_mp[0] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                    // ? &device_param->d_pws_buf
                                                    // : &device_param->d_pws_amp_buf;
        }
      }

      device_param->kernel_params_mp[1] = &device_param->d_root_css_buf;
      device_param->kernel_params_mp[2] = &device_param->d_markov_css_buf;
      device_param->kernel_params_mp[3] = &device_param->kernel_params_mp_buf64[3];
      device_param->kernel_params_mp[4] = &device_param->kernel_params_mp_buf32[4];
      device_param->kernel_params_mp[5] = &device_param->kernel_params_mp_buf32[5];
      device_param->kernel_params_mp[6] = &device_param->kernel_params_mp_buf32[6];
      device_param->kernel_params_mp[7] = &device_param->kernel_params_mp_buf32[7];
      device_param->kernel_params_mp[8] = &device_param->kernel_params_mp_buf64[8];

      device_param->kernel_params_mp_l_buf64[3] = 0;
      device_param->kernel_params_mp_l_buf32[4] = 0;
      device_param->kernel_params_mp_l_buf32[5] = 0;
      device_param->kernel_params_mp_l_buf32[6] = 0;
      device_param->kernel_params_mp_l_buf32[7] = 0;
      device_param->kernel_params_mp_l_buf32[8] = 0;
      device_param->kernel_params_mp_l_buf64[9] = 0;

      device_param->kernel_params_mp_l[0] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                  // ? &device_param->d_pws_buf
                                                  // : &device_param->d_pws_amp_buf;
      device_param->kernel_params_mp_l[1] = &device_param->d_root_css_buf;
      device_param->kernel_params_mp_l[2] = &device_param->d_markov_css_buf;
      device_param->kernel_params_mp_l[3] = &device_param->kernel_params_mp_l_buf64[3];
      device_param->kernel_params_mp_l[4] = &device_param->kernel_params_mp_l_buf32[4];
      device_param->kernel_params_mp_l[5] = &device_param->kernel_params_mp_l_buf32[5];
      device_param->kernel_params_mp_l[6] = &device_param->kernel_params_mp_l_buf32[6];
      device_param->kernel_params_mp_l[7] = &device_param->kernel_params_mp_l_buf32[7];
      device_param->kernel_params_mp_l[8] = &device_param->kernel_params_mp_l_buf32[8];
      device_param->kernel_params_mp_l[9] = &device_param->kernel_params_mp_l_buf64[9];

      device_param->kernel_params_mp_r_buf64[3] = 0;
      device_param->kernel_params_mp_r_buf32[4] = 0;
      device_param->kernel_params_mp_r_buf32[5] = 0;
      device_param->kernel_params_mp_r_buf32[6] = 0;
      device_param->kernel_params_mp_r_buf32[7] = 0;
      device_param->kernel_params_mp_r_buf64[8] = 0;

      device_param->kernel_params_mp_r[0] = &device_param->d_bfs;
      device_param->kernel_params_mp_r[1] = &device_param->d_root_css_buf;
      device_param->kernel_params_mp_r[2] = &device_param->d_markov_css_buf;
      device_param->kernel_params_mp_r[3] = &device_param->kernel_params_mp_r_buf64[3];
      device_param->kernel_params_mp_r[4] = &device_param->kernel_params_mp_r_buf32[4];
      device_param->kernel_params_mp_r[5] = &device_param->kernel_params_mp_r_buf32[5];
      device_param->kernel_params_mp_r[6] = &device_param->kernel_params_mp_r_buf32[6];
      device_param->kernel_params_mp_r[7] = &device_param->kernel_params_mp_r_buf32[7];
      device_param->kernel_params_mp_r[8] = &device_param->kernel_params_mp_r_buf64[8];

      device_param->kernel_params_amp_buf32[5] = 0; // combs_mode
      device_param->kernel_params_amp_buf64[6] = 0; // gid_max

      device_param->kernel_params_amp[0] = NULL; // &device_param->d_pws_buf;
      device_param->kernel_params_amp[1] = NULL; // &device_param->d_pws_amp_buf;
      device_param->kernel_params_amp[2] = &device_param->d_rules_c;
      device_param->kernel_params_amp[3] = &device_param->d_combs_c;
      device_param->kernel_params_amp[4] = &device_param->d_bfs_c;
      device_param->kernel_params_amp[5] = &device_param->kernel_params_amp_buf32[5];
      device_param->kernel_params_amp[6] = &device_param->kernel_params_amp_buf64[6];

      device_param->kernel_params_tm[0] = &device_param->d_bfs_c;
      device_param->kernel_params_tm[1] = &device_param->d_tm_c;
    }

    device_param->kernel_params_memset_buf32[1] = 0; // value
    device_param->kernel_params_memset_buf64[2] = 0; // gid_max

    device_param->kernel_params_memset[0] = NULL;
    device_param->kernel_params_memset[1] = &device_param->kernel_params_memset_buf32[1];
    device_param->kernel_params_memset[2] = &device_param->kernel_params_memset_buf64[2];

    device_param->kernel_params_atinit_buf64[1] = 0; // gid_max

    device_param->kernel_params_atinit[0] = NULL;
    device_param->kernel_params_atinit[1] = &device_param->kernel_params_atinit_buf64[1];

    device_param->kernel_params_decompress_buf64[3] = 0; // gid_max

    device_param->kernel_params_decompress[0] = NULL; // &device_param->d_pws_idx;
    device_param->kernel_params_decompress[1] = NULL; // &device_param->d_pws_comp_buf;
    device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                      // ? &device_param->d_pws_buf
                                                      // : &device_param->d_pws_amp_buf;
    device_param->kernel_params_decompress[3] = &device_param->kernel_params_decompress_buf64[3];

    /**
     * kernel name
     */

    char kernel_name[64] = { 0 };

    if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
      {
        if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
        {
          // kernel1

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", hashconfig->kern_type, 4);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_wgs1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_local_mem_size1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_preferred_wgs_multiple1);

          if (CL_rc == -1) return -1;

          // kernel2

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", hashconfig->kern_type, 8);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_wgs2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_local_mem_size2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_preferred_wgs_multiple2);

          if (CL_rc == -1) return -1;

          // kernel3

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", hashconfig->kern_type, 16);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_wgs3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_local_mem_size3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_preferred_wgs_multiple3);

          if (CL_rc == -1) return -1;
        }
        else
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", hashconfig->kern_type);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_wgs4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_local_mem_size4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_preferred_wgs_multiple4);

          if (CL_rc == -1) return -1;
        }
      }
      else
      {
        if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
        {
          // kernel1

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", hashconfig->kern_type, 4);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_wgs1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_local_mem_size1);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_preferred_wgs_multiple1);

          if (CL_rc == -1) return -1;

          // kernel2

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", hashconfig->kern_type, 8);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_wgs2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_local_mem_size2);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_preferred_wgs_multiple2);

          if (CL_rc == -1) return -1;

          // kernel3

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", hashconfig->kern_type, 16);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_wgs3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_local_mem_size3);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_preferred_wgs_multiple3);

          if (CL_rc == -1) return -1;
        }
        else
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", hashconfig->kern_type);

          CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_wgs4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_local_mem_size4);

          if (CL_rc == -1) return -1;

          CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel4, &device_param->kernel_preferred_wgs_multiple4);

          if (CL_rc == -1) return -1;
        }
      }

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", hashconfig->kern_type);

            CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_tm);

            if (CL_rc == -1) return -1;

            CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_tm, &device_param->kernel_wgs_tm);

            if (CL_rc == -1) return -1;

            CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_tm, &device_param->kernel_local_mem_size_tm);

            if (CL_rc == -1) return -1;

            CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_tm, &device_param->kernel_preferred_wgs_multiple_tm);

            if (CL_rc == -1) return -1;
          }
        }
      }
    }
    else
    {
      // kernel1

      snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", hashconfig->kern_type);

      CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel1);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_wgs1);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_local_mem_size1);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel1, &device_param->kernel_preferred_wgs_multiple1);

      if (CL_rc == -1) return -1;

      // kernel2

      snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", hashconfig->kern_type);

      CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel2);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_wgs2);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_local_mem_size2);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel2, &device_param->kernel_preferred_wgs_multiple2);

      if (CL_rc == -1) return -1;

      // kernel3

      snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", hashconfig->kern_type);

      CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel3);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_wgs3);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_local_mem_size3);

      if (CL_rc == -1) return -1;

      CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel3, &device_param->kernel_preferred_wgs_multiple3);

      if (CL_rc == -1) return -1;

      // kernel12

      if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel12);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel12, &device_param->kernel_wgs12);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel12, &device_param->kernel_local_mem_size12);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel12, &device_param->kernel_preferred_wgs_multiple12);

        if (CL_rc == -1) return -1;
      }

      // kernel23

      if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel23);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel23, &device_param->kernel_wgs23);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel23, &device_param->kernel_local_mem_size23);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel23, &device_param->kernel_preferred_wgs_multiple23);

        if (CL_rc == -1) return -1;
      }

      // init2

      if (hashconfig->opts_type & OPTS_TYPE_INIT2)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_init2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_init2, &device_param->kernel_wgs_init2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_init2, &device_param->kernel_local_mem_size_init2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_init2, &device_param->kernel_preferred_wgs_multiple_init2);

        if (CL_rc == -1) return -1;
      }

      // loop2

      if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_loop2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_loop2, &device_param->kernel_wgs_loop2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_loop2, &device_param->kernel_local_mem_size_loop2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_loop2, &device_param->kernel_preferred_wgs_multiple_loop2);

        if (CL_rc == -1) return -1;
      }

      // aux1

      if (hashconfig->opts_type & OPTS_TYPE_AUX1)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_aux1);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_aux1, &device_param->kernel_wgs_aux1);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_aux1, &device_param->kernel_local_mem_size_aux1);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_aux1, &device_param->kernel_preferred_wgs_multiple_aux1);

        if (CL_rc == -1) return -1;
      }

      // aux2

      if (hashconfig->opts_type & OPTS_TYPE_AUX2)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_aux2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_aux2, &device_param->kernel_wgs_aux2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_aux2, &device_param->kernel_local_mem_size_aux2);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_aux2, &device_param->kernel_preferred_wgs_multiple_aux2);

        if (CL_rc == -1) return -1;
      }

      // aux3

      if (hashconfig->opts_type & OPTS_TYPE_AUX3)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_aux3);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_aux3, &device_param->kernel_wgs_aux3);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_aux3, &device_param->kernel_local_mem_size_aux3);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_aux3, &device_param->kernel_preferred_wgs_multiple_aux3);

        if (CL_rc == -1) return -1;
      }

      // aux4

      if (hashconfig->opts_type & OPTS_TYPE_AUX4)
      {
        snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", hashconfig->kern_type);

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, kernel_name, &device_param->kernel_aux4);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_aux4, &device_param->kernel_wgs_aux4);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_aux4, &device_param->kernel_local_mem_size_aux4);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_aux4, &device_param->kernel_preferred_wgs_multiple_aux4);

        if (CL_rc == -1) return -1;
      }
    }

    // GPU memset

    CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, "gpu_memset", &device_param->kernel_memset);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_memset, &device_param->kernel_wgs_memset);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_memset, &device_param->kernel_local_mem_size_memset);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_memset, &device_param->kernel_preferred_wgs_multiple_memset);

    if (CL_rc == -1) return -1;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_memset, 0, sizeof (cl_mem),   device_param->kernel_params_memset[0]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_memset, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_memset, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]); if (CL_rc == -1) return -1;

    // GPU autotune init

    CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, "gpu_atinit", &device_param->kernel_atinit);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_atinit, &device_param->kernel_wgs_atinit);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_atinit, &device_param->kernel_local_mem_size_atinit);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_atinit, &device_param->kernel_preferred_wgs_multiple_atinit);

    if (CL_rc == -1) return -1;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]); if (CL_rc == -1) return -1;

    // GPU decompress

    CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program, "gpu_decompress", &device_param->kernel_decompress);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_decompress, &device_param->kernel_wgs_decompress);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_decompress, &device_param->kernel_local_mem_size_decompress);

    if (CL_rc == -1) return -1;

    CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_decompress, &device_param->kernel_preferred_wgs_multiple_decompress);

    if (CL_rc == -1) return -1;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 0, sizeof (cl_mem),   device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 1, sizeof (cl_mem),   device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 2, sizeof (cl_mem),   device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]); if (CL_rc == -1) return -1;

    // MP start

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (user_options->attack_mode == ATTACK_MODE_BF)
      {
        // mp_l

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program_mp, "l_markov", &device_param->kernel_mp_l);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_mp_l, &device_param->kernel_wgs_mp_l);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_mp_l, &device_param->kernel_local_mem_size_mp_l);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_mp_l, &device_param->kernel_preferred_wgs_multiple_mp_l);

        if (CL_rc == -1) return -1;

        // mp_r

        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program_mp, "r_markov", &device_param->kernel_mp_r);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_mp_r, &device_param->kernel_wgs_mp_r);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_mp_r, &device_param->kernel_local_mem_size_mp_r);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_mp_r, &device_param->kernel_preferred_wgs_multiple_mp_r);

        if (CL_rc == -1) return -1;

        if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
        {
          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]); if (CL_rc == -1) return -1;
          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]); if (CL_rc == -1) return -1;
        }
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
      {
        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program_mp, "C_markov", &device_param->kernel_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_wgs_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_local_mem_size_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_preferred_wgs_multiple_mp);

        if (CL_rc == -1) return -1;
      }
      else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
      {
        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program_mp, "C_markov", &device_param->kernel_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_wgs_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_local_mem_size_mp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_mp, &device_param->kernel_preferred_wgs_multiple_mp);

        if (CL_rc == -1) return -1;
      }
    }

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        CL_rc = hc_clCreateKernel (hashcat_ctx, device_param->program_amp, "amp", &device_param->kernel_amp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_wgs (hashcat_ctx, device_param, device_param->kernel_amp, &device_param->kernel_wgs_amp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_local_mem_size (hashcat_ctx, device_param, device_param->kernel_amp, &device_param->kernel_local_mem_size_amp);

        if (CL_rc == -1) return -1;

        CL_rc = get_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->kernel_amp, &device_param->kernel_preferred_wgs_multiple_amp);

        if (CL_rc == -1) return -1;
      }

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        for (u32 i = 0; i < 5; i++)
        {
          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, i, sizeof (cl_mem), device_param->kernel_params_amp[i]);

          if (CL_rc == -1) return -1;
        }

        for (u32 i = 5; i < 6; i++)
        {
          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, i, sizeof (cl_uint), device_param->kernel_params_amp[i]);

          if (CL_rc == -1) return -1;
        }

        for (u32 i = 6; i < 7; i++)
        {
          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, i, sizeof (cl_ulong), device_param->kernel_params_amp[i]);

          if (CL_rc == -1) return -1;
        }
      }
    }

    // zero some data buffers

    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_plain_bufs,    device_param->size_plains);   if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_digests_shown, device_param->size_shown);    if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_result,        device_param->size_results);  if (CL_rc == -1) return -1;

    /**
     * special buffers
     */

    if (user_options->slow_candidates == true)
    {
      CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_rules_c, size_rules_c); if (CL_rc == -1) return -1;
    }
    else
    {
      if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
      {
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_rules_c, size_rules_c); if (CL_rc == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_combs,          size_combs);       if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_combs_c,        size_combs);       if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_root_css_buf,   size_root_css);    if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_markov_css_buf, size_markov_css);  if (CL_rc == -1) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_bfs,            size_bfs);         if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_bfs_c,          size_bfs);         if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_tm_c,           size_tm);          if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_root_css_buf,   size_root_css);    if (CL_rc == -1) return -1;
        CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_markov_css_buf, size_markov_css);  if (CL_rc == -1) return -1;
      }
    }

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if ((user_options->attack_mode == ATTACK_MODE_HYBRID1) || (user_options->attack_mode == ATTACK_MODE_HYBRID2))
      {
        /**
         * prepare mp
         */

        if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          device_param->kernel_params_mp_buf32[5] = 0;
          device_param->kernel_params_mp_buf32[6] = 0;
          device_param->kernel_params_mp_buf32[7] = 0;

          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_buf32[5] = full01;
          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)     device_param->kernel_params_mp_buf32[5] = full06;
          if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_buf32[5] = full80;
          if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_buf32[6] = 1;
          if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_buf32[7] = 1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          device_param->kernel_params_mp_buf32[5] = 0;
          device_param->kernel_params_mp_buf32[6] = 0;
          device_param->kernel_params_mp_buf32[7] = 0;
        }

        for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp, i, sizeof (cl_mem), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }
      }
      else if (user_options->attack_mode == ATTACK_MODE_BF)
      {
        /**
         * prepare mp_r and mp_l
         */

        device_param->kernel_params_mp_l_buf32[6] = 0;
        device_param->kernel_params_mp_l_buf32[7] = 0;
        device_param->kernel_params_mp_l_buf32[8] = 0;

        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD01)     device_param->kernel_params_mp_l_buf32[6] = full01;
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD06)     device_param->kernel_params_mp_l_buf32[6] = full06;
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADD80)     device_param->kernel_params_mp_l_buf32[6] = full80;
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS14) device_param->kernel_params_mp_l_buf32[7] = 1;
        if (hashconfig->opts_type & OPTS_TYPE_PT_ADDBITS15) device_param->kernel_params_mp_l_buf32[8] = 1;

        for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_l, i, sizeof (cl_mem), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
        for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_r, i, sizeof (cl_mem), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
      }
    }

    /**
     * now everything that depends on threads and accel, basically dynamic workload
     */

    u32 kernel_threads = hashconfig_get_kernel_threads (hashcat_ctx, device_param);

    // this is required because inside the kernels there is this:
    // __local pw_t s_pws[64];

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        // not required
      }
      else
      {
        kernel_threads = MIN (kernel_threads, 64);
      }
    }

    device_param->kernel_threads = kernel_threads;

    device_param->hardware_power = device_processors * kernel_threads;

    u32 kernel_accel_min = device_param->kernel_accel_min;
    u32 kernel_accel_max = device_param->kernel_accel_max;

    // find out if we would request too much memory on memory blocks which are based on kernel_accel

    u64 size_pws      = 4;
    u64 size_pws_amp  = 4;
    u64 size_pws_comp = 4;
    u64 size_pws_idx  = 4;
    u64 size_pws_pre  = 4;
    u64 size_pws_base = 4;
    u64 size_tmps     = 4;
    u64 size_hooks    = 4;
    #ifdef WITH_BRAIN
    u64 size_brain_link_in  = 4;
    u64 size_brain_link_out = 4;
    #endif

    // instead of a thread limit we can also use a memory limit.
    // this value should represent a reasonable amount of memory a host system has per GPU.
    // note we're allocating 3 blocks of that size.

    #define PWS_SPACE (1024 * 1024 * 1024)

    // sometimes device_available_mem and device_maxmem_alloc reported back from the opencl runtime are a bit inaccurate.
    // let's add some extra space just to be sure.

    #define EXTRA_SPACE (64 * 1024 * 1024)

    while (kernel_accel_max >= kernel_accel_min)
    {
      const u64 kernel_power_max = device_param->hardware_power * kernel_accel_max;

      // size_pws

      size_pws = (u64) kernel_power_max * sizeof (pw_t);

      size_pws_amp = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) ? 1 : size_pws;

      // size_pws_comp

      size_pws_comp = (u64) kernel_power_max * (sizeof (u32) * 64);

      // size_pws_idx

      size_pws_idx = (u64) (kernel_power_max + 1) * sizeof (pw_idx_t);

      // size_tmps

      size_tmps = (u64) kernel_power_max * hashconfig->tmp_size;

      // size_hooks

      size_hooks = (u64) kernel_power_max * hashconfig->hook_size;

      #ifdef WITH_BRAIN
      // size_brains

      size_brain_link_in  = (u64) kernel_power_max * 1;
      size_brain_link_out = (u64) kernel_power_max * 8;
      #endif

      if (user_options->slow_candidates == true)
      {
        // size_pws_pre

        size_pws_pre = (u64) kernel_power_max * sizeof (pw_pre_t);

        // size_pws_base

        size_pws_base = (u64) kernel_power_max * sizeof (pw_pre_t);
      }

      // now check if all device-memory sizes which depend on the kernel_accel_max amplifier are within its boundaries
      // if not, decrease amplifier and try again

      int memory_limit_hit = 0;

      if (size_pws > PWS_SPACE) memory_limit_hit = 1;

      if ((size_pws   + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;
      if ((size_tmps  + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;
      if ((size_hooks + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;

      const u64 size_total
        = bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + bitmap_ctx->bitmap_size
        + size_bfs
        + size_combs
        + size_digests
        + size_esalts
        + size_hooks
        + size_markov_css
        + size_plains
        + size_pws
        + size_pws_amp
        + size_pws_comp
        + size_pws_idx
        + size_results
        + size_root_css
        + size_rules
        + size_rules_c
        + size_salts
        + size_scrypt4
        + size_scrypt4
        + size_scrypt4
        + size_scrypt4
        + size_shown
        + size_tm
        + size_tmps
        + size_st_digests
        + size_st_salts
        + size_st_esalts;

      if ((size_total + EXTRA_SPACE) > device_param->device_available_mem) memory_limit_hit = 1;

      const u64 size_total_host
        = size_pws_comp
        + size_pws_idx
        + size_hooks
        #ifdef WITH_BRAIN
        + size_brain_link_in
        + size_brain_link_out
        #endif
        + size_pws_pre
        + size_pws_base;

      if ((size_total_host + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;

      #if defined (__x86_x64__)
      const u64 MAX_HOST_MEMORY = 16ull * 1024ull * 1024ull * 1024ull; // don't be too memory hungry
      #else
      const u64 MAX_HOST_MEMORY =  2ull * 1024ull * 1024ull * 1024ull; // windows 7 starter limits to 2gb instead of 4gb
      #endif

      // we assume all devices have the same specs here, which is wrong, it's a start
      if ((size_total_host * opencl_ctx->devices_cnt) > MAX_HOST_MEMORY) memory_limit_hit = 1;

      if (memory_limit_hit == 1)
      {
        kernel_accel_max--;

        continue;
      }

      break;
    }

    if (kernel_accel_max < kernel_accel_min)
    {
      event_log_error (hashcat_ctx, "* Device #%u: Not enough allocatable device memory for this attack.", device_id + 1);

      return -1;
    }

    device_param->kernel_accel_min = kernel_accel_min;
    device_param->kernel_accel_max = kernel_accel_max;

    device_param->size_pws      = size_pws;
    device_param->size_pws_amp  = size_pws_amp;
    device_param->size_pws_comp = size_pws_comp;
    device_param->size_pws_idx  = size_pws_idx;
    device_param->size_pws_pre  = size_pws_pre;
    device_param->size_pws_base = size_pws_base;
    device_param->size_tmps     = size_tmps;
    device_param->size_hooks    = size_hooks;
    #ifdef WITH_BRAIN
    device_param->size_brain_link_in  = size_brain_link_in;
    device_param->size_brain_link_out = size_brain_link_out;
    #endif

    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_pws,      NULL, &device_param->d_pws_buf);      if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_pws_amp,  NULL, &device_param->d_pws_amp_buf);  if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_pws_comp, NULL, &device_param->d_pws_comp_buf); if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_ONLY,   size_pws_idx,  NULL, &device_param->d_pws_idx);      if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_tmps,     NULL, &device_param->d_tmps);         if (CL_rc == -1) return -1;
    CL_rc = hc_clCreateBuffer (hashcat_ctx, device_param->context, CL_MEM_READ_WRITE,  size_hooks,    NULL, &device_param->d_hooks);        if (CL_rc == -1) return -1;

    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_pws_buf,       device_param->size_pws);      if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_pws_amp_buf,   device_param->size_pws_amp);  if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_pws_comp_buf,  device_param->size_pws_comp); if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_pws_idx,       device_param->size_pws_idx);  if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_tmps,          device_param->size_tmps);     if (CL_rc == -1) return -1;
    CL_rc = run_kernel_bzero (hashcat_ctx, device_param, device_param->d_hooks,         device_param->size_hooks);    if (CL_rc == -1) return -1;

    /**
     * main host data
     */

    u32 *pws_comp = (u32 *) hcmalloc (size_pws_comp);

    device_param->pws_comp = pws_comp;

    pw_idx_t *pws_idx = (pw_idx_t *) hcmalloc (size_pws_idx);

    device_param->pws_idx = pws_idx;

    pw_t *combs_buf = (pw_t *) hccalloc (KERNEL_COMBS, sizeof (pw_t));

    device_param->combs_buf = combs_buf;

    void *hooks_buf = hcmalloc (size_hooks);

    device_param->hooks_buf = hooks_buf;

    char *scratch_buf = (char *) hcmalloc (HCBUFSIZ_LARGE);

    device_param->scratch_buf = scratch_buf;

    #ifdef WITH_BRAIN

    u8 *brain_link_in_buf = (u8 *) hcmalloc (size_brain_link_in);

    device_param->brain_link_in_buf = brain_link_in_buf;

    u32 *brain_link_out_buf = (u32 *) hcmalloc (size_brain_link_out);

    device_param->brain_link_out_buf = brain_link_out_buf;
    #endif

    pw_pre_t *pws_pre_buf = (pw_pre_t *) hcmalloc (size_pws_pre);

    device_param->pws_pre_buf = pws_pre_buf;

    pw_pre_t *pws_base_buf = (pw_pre_t *) hcmalloc (size_pws_base);

    device_param->pws_base_buf = pws_base_buf;

    /**
     * kernel args
     */

    device_param->kernel_params[ 0] = &device_param->d_pws_buf;
    device_param->kernel_params[ 4] = &device_param->d_tmps;
    device_param->kernel_params[ 5] = &device_param->d_hooks;

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        // nothing to do
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          device_param->kernel_params_mp[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                            ? &device_param->d_pws_buf
                                            : &device_param->d_pws_amp_buf;

          CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp, 0, sizeof (cl_mem), device_param->kernel_params_mp[0]); if (CL_rc == -1) return -1;
        }
      }

      if (user_options->attack_mode == ATTACK_MODE_BF)
      {
        device_param->kernel_params_mp_l[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                            ? &device_param->d_pws_buf
                                            : &device_param->d_pws_amp_buf;

        CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_l, 0, sizeof (cl_mem), device_param->kernel_params_mp_l[0]); if (CL_rc == -1) return -1;
      }

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        device_param->kernel_params_amp[0] = &device_param->d_pws_buf;
        device_param->kernel_params_amp[1] = &device_param->d_pws_amp_buf;

        CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, 0, sizeof (cl_mem), device_param->kernel_params_amp[0]); if (CL_rc == -1) return -1;
        CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, 1, sizeof (cl_mem), device_param->kernel_params_amp[1]); if (CL_rc == -1) return -1;
      }
    }

    device_param->kernel_params_decompress[0] = &device_param->d_pws_idx;
    device_param->kernel_params_decompress[1] = &device_param->d_pws_comp_buf;
    device_param->kernel_params_decompress[2] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->d_pws_buf
                                              : &device_param->d_pws_amp_buf;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 0, sizeof (cl_mem), device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 1, sizeof (cl_mem), device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_decompress, 2, sizeof (cl_mem), device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;

    hardware_power_all += device_param->hardware_power;

    EVENT_DATA (EVENT_OPENCL_DEVICE_INIT_POST, &device_id, sizeof (u32));
  }

  // Prevent exit from benchmark mode if all devices are skipped due to unstable hash-modes (macOS)

  bool has_skipped_temp = false;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped_temp == true) has_skipped_temp = true;
  }

  if ((hardware_power_all == 0) && (has_skipped_temp == false)) return -1;

  opencl_ctx->hardware_power_all = hardware_power_all;

  return 0;
}

void opencl_session_destroy (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (opencl_ctx->enabled == false) return;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped_temp == true)
    {
      device_param->skipped_temp = false;

      device_param->skipped = false;

      continue;
    }

    if (device_param->skipped == true) continue;

    hcfree (device_param->pws_comp);
    hcfree (device_param->pws_idx);
    hcfree (device_param->pws_pre_buf);
    hcfree (device_param->pws_base_buf);
    hcfree (device_param->combs_buf);
    hcfree (device_param->hooks_buf);
    hcfree (device_param->scratch_buf);
    #ifdef WITH_BRAIN
    hcfree (device_param->brain_link_in_buf);
    hcfree (device_param->brain_link_out_buf);
    #endif

    if (device_param->d_pws_buf)        hc_clReleaseMemObject (hashcat_ctx, device_param->d_pws_buf);
    if (device_param->d_pws_amp_buf)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_pws_amp_buf);
    if (device_param->d_pws_comp_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_pws_comp_buf);
    if (device_param->d_pws_idx)        hc_clReleaseMemObject (hashcat_ctx, device_param->d_pws_idx);
    if (device_param->d_rules)          hc_clReleaseMemObject (hashcat_ctx, device_param->d_rules);
    if (device_param->d_rules_c)        hc_clReleaseMemObject (hashcat_ctx, device_param->d_rules_c);
    if (device_param->d_combs)          hc_clReleaseMemObject (hashcat_ctx, device_param->d_combs);
    if (device_param->d_combs_c)        hc_clReleaseMemObject (hashcat_ctx, device_param->d_combs_c);
    if (device_param->d_bfs)            hc_clReleaseMemObject (hashcat_ctx, device_param->d_bfs);
    if (device_param->d_bfs_c)          hc_clReleaseMemObject (hashcat_ctx, device_param->d_bfs_c);
    if (device_param->d_bitmap_s1_a)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s1_a);
    if (device_param->d_bitmap_s1_b)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s1_b);
    if (device_param->d_bitmap_s1_c)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s1_c);
    if (device_param->d_bitmap_s1_d)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s1_d);
    if (device_param->d_bitmap_s2_a)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s2_a);
    if (device_param->d_bitmap_s2_b)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s2_b);
    if (device_param->d_bitmap_s2_c)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s2_c);
    if (device_param->d_bitmap_s2_d)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_bitmap_s2_d);
    if (device_param->d_plain_bufs)     hc_clReleaseMemObject (hashcat_ctx, device_param->d_plain_bufs);
    if (device_param->d_digests_buf)    hc_clReleaseMemObject (hashcat_ctx, device_param->d_digests_buf);
    if (device_param->d_digests_shown)  hc_clReleaseMemObject (hashcat_ctx, device_param->d_digests_shown);
    if (device_param->d_salt_bufs)      hc_clReleaseMemObject (hashcat_ctx, device_param->d_salt_bufs);
    if (device_param->d_esalt_bufs)     hc_clReleaseMemObject (hashcat_ctx, device_param->d_esalt_bufs);
    if (device_param->d_tmps)           hc_clReleaseMemObject (hashcat_ctx, device_param->d_tmps);
    if (device_param->d_hooks)          hc_clReleaseMemObject (hashcat_ctx, device_param->d_hooks);
    if (device_param->d_result)         hc_clReleaseMemObject (hashcat_ctx, device_param->d_result);
    if (device_param->d_scryptV0_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_scryptV0_buf);
    if (device_param->d_scryptV1_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_scryptV1_buf);
    if (device_param->d_scryptV2_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_scryptV2_buf);
    if (device_param->d_scryptV3_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_scryptV3_buf);
    if (device_param->d_root_css_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_root_css_buf);
    if (device_param->d_markov_css_buf) hc_clReleaseMemObject (hashcat_ctx, device_param->d_markov_css_buf);
    if (device_param->d_tm_c)           hc_clReleaseMemObject (hashcat_ctx, device_param->d_tm_c);
    if (device_param->d_st_digests_buf) hc_clReleaseMemObject (hashcat_ctx, device_param->d_st_digests_buf);
    if (device_param->d_st_salts_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->d_st_salts_buf);
    if (device_param->d_st_esalts_buf)  hc_clReleaseMemObject (hashcat_ctx, device_param->d_st_esalts_buf);

    if (device_param->kernel1)          hc_clReleaseKernel (hashcat_ctx, device_param->kernel1);
    if (device_param->kernel12)         hc_clReleaseKernel (hashcat_ctx, device_param->kernel12);
    if (device_param->kernel2)          hc_clReleaseKernel (hashcat_ctx, device_param->kernel2);
    if (device_param->kernel23)         hc_clReleaseKernel (hashcat_ctx, device_param->kernel23);
    if (device_param->kernel3)          hc_clReleaseKernel (hashcat_ctx, device_param->kernel3);
    if (device_param->kernel4)          hc_clReleaseKernel (hashcat_ctx, device_param->kernel4);
    if (device_param->kernel_init2)     hc_clReleaseKernel (hashcat_ctx, device_param->kernel_init2);
    if (device_param->kernel_loop2)     hc_clReleaseKernel (hashcat_ctx, device_param->kernel_loop2);
    if (device_param->kernel_mp)        hc_clReleaseKernel (hashcat_ctx, device_param->kernel_mp);
    if (device_param->kernel_mp_l)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_mp_l);
    if (device_param->kernel_mp_r)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_mp_r);
    if (device_param->kernel_tm)        hc_clReleaseKernel (hashcat_ctx, device_param->kernel_tm);
    if (device_param->kernel_amp)       hc_clReleaseKernel (hashcat_ctx, device_param->kernel_amp);
    if (device_param->kernel_memset)    hc_clReleaseKernel (hashcat_ctx, device_param->kernel_memset);
    if (device_param->kernel_atinit)    hc_clReleaseKernel (hashcat_ctx, device_param->kernel_atinit);
    if (device_param->kernel_decompress)hc_clReleaseKernel (hashcat_ctx, device_param->kernel_decompress);
    if (device_param->kernel_aux1)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_aux1);
    if (device_param->kernel_aux2)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_aux2);
    if (device_param->kernel_aux3)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_aux3);
    if (device_param->kernel_aux4)      hc_clReleaseKernel (hashcat_ctx, device_param->kernel_aux4);

    if (device_param->program)          hc_clReleaseProgram (hashcat_ctx, device_param->program);
    if (device_param->program_mp)       hc_clReleaseProgram (hashcat_ctx, device_param->program_mp);
    if (device_param->program_amp)      hc_clReleaseProgram (hashcat_ctx, device_param->program_amp);

    if (device_param->command_queue)    hc_clReleaseCommandQueue (hashcat_ctx, device_param->command_queue);

    if (device_param->context)          hc_clReleaseContext (hashcat_ctx, device_param->context);

    device_param->pws_comp          = NULL;
    device_param->pws_idx           = NULL;
    device_param->pws_pre_buf       = NULL;
    device_param->pws_base_buf      = NULL;
    device_param->combs_buf         = NULL;
    device_param->hooks_buf         = NULL;

    device_param->d_pws_buf         = NULL;
    device_param->d_pws_amp_buf     = NULL;
    device_param->d_pws_comp_buf    = NULL;
    device_param->d_pws_idx         = NULL;
    device_param->d_rules           = NULL;
    device_param->d_rules_c         = NULL;
    device_param->d_combs           = NULL;
    device_param->d_combs_c         = NULL;
    device_param->d_bfs             = NULL;
    device_param->d_bfs_c           = NULL;
    device_param->d_bitmap_s1_a     = NULL;
    device_param->d_bitmap_s1_b     = NULL;
    device_param->d_bitmap_s1_c     = NULL;
    device_param->d_bitmap_s1_d     = NULL;
    device_param->d_bitmap_s2_a     = NULL;
    device_param->d_bitmap_s2_b     = NULL;
    device_param->d_bitmap_s2_c     = NULL;
    device_param->d_bitmap_s2_d     = NULL;
    device_param->d_plain_bufs      = NULL;
    device_param->d_digests_buf     = NULL;
    device_param->d_digests_shown   = NULL;
    device_param->d_salt_bufs       = NULL;
    device_param->d_esalt_bufs      = NULL;
    device_param->d_tmps            = NULL;
    device_param->d_hooks           = NULL;
    device_param->d_result          = NULL;
    device_param->d_scryptV0_buf    = NULL;
    device_param->d_scryptV1_buf    = NULL;
    device_param->d_scryptV2_buf    = NULL;
    device_param->d_scryptV3_buf    = NULL;
    device_param->d_root_css_buf    = NULL;
    device_param->d_markov_css_buf  = NULL;
    device_param->d_tm_c            = NULL;
    device_param->d_st_digests_buf  = NULL;
    device_param->d_st_salts_buf    = NULL;
    device_param->d_st_esalts_buf   = NULL;
    device_param->kernel1           = NULL;
    device_param->kernel12          = NULL;
    device_param->kernel2           = NULL;
    device_param->kernel23          = NULL;
    device_param->kernel3           = NULL;
    device_param->kernel4           = NULL;
    device_param->kernel_init2      = NULL;
    device_param->kernel_loop2      = NULL;
    device_param->kernel_mp         = NULL;
    device_param->kernel_mp_l       = NULL;
    device_param->kernel_mp_r       = NULL;
    device_param->kernel_tm         = NULL;
    device_param->kernel_amp        = NULL;
    device_param->kernel_memset     = NULL;
    device_param->kernel_atinit     = NULL;
    device_param->kernel_decompress = NULL;
    device_param->kernel_aux1       = NULL;
    device_param->kernel_aux2       = NULL;
    device_param->kernel_aux3       = NULL;
    device_param->kernel_aux4       = NULL;
    device_param->program           = NULL;
    device_param->program_mp        = NULL;
    device_param->program_amp       = NULL;
    device_param->command_queue     = NULL;
    device_param->context           = NULL;
  }
}

void opencl_session_reset (hashcat_ctx_t *hashcat_ctx)
{
  opencl_ctx_t *opencl_ctx = hashcat_ctx->opencl_ctx;

  if (opencl_ctx->enabled == false) return;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    device_param->speed_pos = 0;

    memset (device_param->speed_cnt,  0, SPEED_CACHE * sizeof (u64));
    memset (device_param->speed_msec, 0, SPEED_CACHE * sizeof (double));

    device_param->speed_only_finish = false;

    device_param->exec_pos = 0;

    memset (device_param->exec_msec, 0, EXEC_CACHE * sizeof (double));

    device_param->outerloop_msec = 0;
    device_param->outerloop_pos  = 0;
    device_param->outerloop_left = 0;
    device_param->innerloop_pos  = 0;
    device_param->innerloop_left = 0;

    // some more resets:

    if (device_param->pws_comp) memset (device_param->pws_comp, 0, device_param->size_pws_comp);
    if (device_param->pws_idx)  memset (device_param->pws_idx,  0, device_param->size_pws_idx);

    device_param->pws_cnt = 0;

    device_param->words_off  = 0;
    device_param->words_done = 0;

    #if defined (_WIN)
    device_param->timer_speed.QuadPart = 0;
    #else
    device_param->timer_speed.tv_sec = 0;
    #endif
  }

  opencl_ctx->kernel_power_all   = 0;
  opencl_ctx->kernel_power_final = 0;
}

int opencl_session_update_combinator (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  opencl_ctx_t     *opencl_ctx     = hashcat_ctx->opencl_ctx;
  user_options_t   *user_options   = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return 0;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    // kernel_params

    device_param->kernel_params_buf32[33] = combinator_ctx->combs_mode;

    /*
    int CL_rc;

    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel1, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel3, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
    CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel4, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;

    if (hashconfig->opts_type & OPTS_TYPE_HOOK12) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel12,     33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
    if (hashconfig->opts_type & OPTS_TYPE_HOOK23) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel23,     33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
    if (hashconfig->opts_type & OPTS_TYPE_INIT2)  { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_init2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
    if (hashconfig->opts_type & OPTS_TYPE_LOOP2)  { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_loop2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
    */

    // kernel_params_amp

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      device_param->kernel_params_amp_buf32[5] = combinator_ctx->combs_mode;

      if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
      {
        int CL_rc;

        CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_amp, 5, sizeof (cl_uint), device_param->kernel_params_amp[5]);

        if (CL_rc == -1) return -1;
      }
    }
  }

  return 0;
}

int opencl_session_update_mp (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return 0;

  if (user_options->slow_candidates == true) return 0;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    device_param->kernel_params_mp_buf64[3] = 0;
    device_param->kernel_params_mp_buf32[4] = mask_ctx->css_cnt;

    int CL_rc = CL_SUCCESS;

    for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp, i, sizeof (cl_ulong), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }
    for (u32 i = 4; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp, i, sizeof (cl_uint), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }

    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL); if (CL_rc == -1) return -1;
  }

  return 0;
}

int opencl_session_update_mp_rl (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  opencl_ctx_t   *opencl_ctx   = hashcat_ctx->opencl_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (opencl_ctx->enabled == false) return 0;

  if (user_options->slow_candidates == true) return 0;

  for (u32 device_id = 0; device_id < opencl_ctx->devices_cnt; device_id++)
  {
    hc_device_param_t *device_param = &opencl_ctx->devices_param[device_id];

    if (device_param->skipped == true) continue;

    device_param->kernel_params_mp_l_buf64[3] = 0;
    device_param->kernel_params_mp_l_buf32[4] = css_cnt_l;
    device_param->kernel_params_mp_l_buf32[5] = css_cnt_r;

    device_param->kernel_params_mp_r_buf64[3] = 0;
    device_param->kernel_params_mp_r_buf32[4] = css_cnt_r;

    int CL_rc = CL_SUCCESS;

    for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
    for (u32 i = 4; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_l, i, sizeof (cl_uint),  device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
    for (u32 i = 9; i < 9; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }

    for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
    for (u32 i = 4; i < 7; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_r, i, sizeof (cl_uint),  device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
    for (u32 i = 8; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }

    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL); if (CL_rc == -1) return -1;
    CL_rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->command_queue, device_param->d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL); if (CL_rc == -1) return -1;
  }

  return 0;
}
