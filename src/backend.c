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
#include "convert.h"
#include "stdout.h"
#include "filehandling.h"
#include "wordlist.h"
#include "shared.h"
#include "hashes.h"
#include "emu_inc_hash_md5.h"
#include "event.h"
#include "dynloader.h"
#include "backend.h"
#include "terminal.h"

#if defined (__linux__)
static const char *const  dri_card0_path = "/dev/dri/card0";

static const char *const  drm_card0_vendor_path = "/sys/class/drm/card0/device/vendor";
static const char *const  drm_card0_driver_path = "/sys/class/drm/card0/device/driver";
#endif

static const u32 full01 = 0x01010101;
static const u32 full06 = 0x06060606;
static const u32 full80 = 0x80808080;

static double TARGET_MSEC_PROFILE[4] = { 2, 12, 96, 480 };

HC_ALIGN(16)
static const u32 bzeros[4] = { 0, 0, 0, 0 };

/* forward declarations */
static void rebuild_pws_compressed_append (hc_device_param_t *device_param, const u64 pws_cnt, const u8 chr);

static bool is_same_device (const hc_device_param_t *src, const hc_device_param_t *dst)
{
  // First check by PCI address

  if (src->pcie_domain   != dst->pcie_domain)   return false; // PCI domain not available on OpenCL
  if (src->pcie_bus      != dst->pcie_bus)      return false;
  if (src->pcie_device   != dst->pcie_device)   return false;
  if (src->pcie_function != dst->pcie_function) return false;

  // macOS still can't distinguish the devices by PCIe bus:

  if (src->device_processors != dst->device_processors) return false;

  // CUDA can't have aliases

  if ((src->is_cuda == true) && (dst->is_cuda == true)) return false;

  // HIP can't have aliases

  if ((src->is_hip == true) && (dst->is_hip == true)) return false;

  #if defined (__APPLE__)
  // Metal can't have aliases

  if ((src->is_metal == true) && (dst->is_metal == true)) return false;
  #endif

  // But OpenCL can have aliases

  if ((src->is_opencl == true) && (dst->is_opencl == true))
  {
    // Intel CPU and embedded GPU would survive up to here!

    if (src->opencl_device_type != dst->opencl_device_type) return false;

    // There should be no aliases on the same opencl platform

    if (src->opencl_platform_id == dst->opencl_platform_id) return false;
  }

  return true;
}

static int backend_ctx_find_alias_devices (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  // first identify all aliases

  for (int backend_devices_cnt_src = 0; backend_devices_cnt_src < backend_ctx->backend_devices_cnt; backend_devices_cnt_src++)
  {
    hc_device_param_t *device_param_src = &backend_ctx->devices_param[backend_devices_cnt_src];

    for (int backend_devices_cnt_dst = backend_devices_cnt_src + 1; backend_devices_cnt_dst < backend_ctx->backend_devices_cnt; backend_devices_cnt_dst++)
    {
      hc_device_param_t *device_param_dst = &backend_ctx->devices_param[backend_devices_cnt_dst];

      if (is_same_device (device_param_src, device_param_dst) == false) continue;

      device_param_src->device_id_alias_buf[device_param_src->device_id_alias_cnt] = device_param_dst->device_id;
      device_param_src->device_id_alias_cnt++;

      device_param_dst->device_id_alias_buf[device_param_dst->device_id_alias_cnt] = device_param_src->device_id;
      device_param_dst->device_id_alias_cnt++;
    }
  }

  // find the alias to skip

  for (int backend_devices_pos = 0; backend_devices_pos < backend_ctx->backend_devices_cnt; backend_devices_pos++)
  {
    hc_device_param_t *backend_device = &backend_ctx->devices_param[backend_devices_pos];

    if (backend_device->skipped == true) continue;
    if (backend_device->skipped_warning == true) continue;

    for (int device_id_alias_pos = 0; device_id_alias_pos < backend_device->device_id_alias_cnt; device_id_alias_pos++)
    {
      const int alias_pos = backend_device->device_id_alias_buf[device_id_alias_pos];

      hc_device_param_t *alias_device = &backend_ctx->devices_param[alias_pos];

      if (alias_device->skipped == true) continue;
      if (alias_device->skipped_warning == true) continue;

      // this lets CUDA devices survive over OpenCL

      if (alias_device->is_cuda == true) continue;

      // this lets HIP devices survive over OpenCL

      if (alias_device->is_hip == true) continue;

      #if defined (__APPLE__)
      // this lets Metal devices survive over OpenCL

      if (alias_device->is_metal == true) continue;
      #endif

      // this lets native OpenCL runtime survive over generic OpenCL runtime

      if (alias_device->opencl_device_type & CL_DEVICE_TYPE_CPU)
      {
        if (alias_device->opencl_platform_vendor_id == alias_device->opencl_device_vendor_id) continue;
      }

      alias_device->skipped = true;

      backend_ctx->opencl_devices_active--;
      backend_ctx->backend_devices_active--;

      // show a warning for specifically listed devices if they are an alias

      if (backend_ctx->backend_devices_filter != (u64) -1)
      {
        if (backend_ctx->backend_devices_filter & (1ULL << alias_device->device_id))
        {
          event_log_warning (hashcat_ctx, "The device #%d specifically listed was skipped because it is an alias of device #%d", alias_device->device_id + 1, backend_device->device_id + 1);
          event_log_warning (hashcat_ctx, NULL);
        }
      }
    }
  }

  return -1;
}

static bool is_same_device_type (const hc_device_param_t *src, const hc_device_param_t *dst)
{
  if (src->is_cuda   != dst->is_cuda)   return false;
  if (src->is_hip    != dst->is_hip)    return false;
  #if defined (__APPLE__)
  if (src->is_metal  != dst->is_metal)  return false;
  #endif
  if (src->is_opencl != dst->is_opencl) return false;

  if (strcmp (src->device_name, dst->device_name) != 0) return false;

  if (src->is_opencl == true)
  {
    if (strcmp (src->opencl_device_vendor,  dst->opencl_device_vendor)  != 0) return false;
    if (strcmp (src->opencl_device_version, dst->opencl_device_version) != 0) return false;
    if (strcmp (src->opencl_driver_version, dst->opencl_driver_version) != 0) return false;
  }

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

  char buf[HCBUFSIZ_TINY] = { 0 };

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

static bool setup_backend_devices_filter (hashcat_ctx_t *hashcat_ctx, const char *backend_devices, u64 *out)
{
  u64 backend_devices_filter = 0;

  if (backend_devices)
  {
    char *devices = hcstrdup (backend_devices);

    if (devices == NULL) return false;

    char *saveptr = NULL;

    char *next = strtok_r (devices, ",", &saveptr);

    do
    {
      const int backend_device_id = (const int) strtol (next, NULL, 10);

      if ((backend_device_id <= 0) || (backend_device_id >= 64))
      {
        event_log_error (hashcat_ctx, "Invalid device_id %d specified.", backend_device_id);

        hcfree (devices);

        return false;
      }

      backend_devices_filter |= 1ULL << (backend_device_id - 1);

    } while ((next = strtok_r ((char *) NULL, ",", &saveptr)) != NULL);

    hcfree (devices);
  }
  else
  {
    backend_devices_filter = -1ULL;
  }

  *out = backend_devices_filter;

  return true;
}

static bool setup_opencl_device_types_filter (hashcat_ctx_t *hashcat_ctx, const char *opencl_device_types, cl_device_type *out)
{
  cl_device_type opencl_device_types_filter = 0;

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
        event_log_error (hashcat_ctx, "Invalid OpenCL device-type %d specified.", device_type);

        hcfree (device_types);

        return false;
      }

      opencl_device_types_filter |= 1U << device_type;

    } while ((next = strtok_r (NULL, ",", &saveptr)) != NULL);

    hcfree (device_types);
  }
  else
  {
    #if defined (__APPLE__)

    if (is_apple_silicon () == true)
    {
      // With Apple's M1* use GPU only, because CPU device it is not recognized by OpenCL

      opencl_device_types_filter = CL_DEVICE_TYPE_GPU;
    }
    else
    {
      // With Apple Intel use CPU only, because GPU drivers are not reliable
      // The user can explicitly enable GPU by setting -D2

      //opencl_device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_GPU;
      opencl_device_types_filter = CL_DEVICE_TYPE_CPU;
    }

    #else

    // Do not use CPU by default, this often reduces GPU performance because
    // the CPU is too busy to handle GPU synchronization
    // Do not use FPGA/other by default, this is a rare case and we expect the users to enable this manually.
    // this is needed since Intel One API started to add FPGA emulated OpenCL device by default and it's just annoying.

    //opencl_device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_CPU;
    opencl_device_types_filter = CL_DEVICE_TYPE_GPU;

    #endif
  }

  *out = opencl_device_types_filter;

  return true;
}

/*
static bool cuda_test_instruction (hashcat_ctx_t *hashcat_ctx, const int sm_major, const int sm_minor, const char *kernel_buf)
{
  nvrtcProgram program;

  if (hc_nvrtcCreateProgram (hashcat_ctx, &program, kernel_buf, "test_instruction", 0, NULL, NULL) == -1) return false;

  char *nvrtc_options[4];

  nvrtc_options[0] = "--restrict";
  nvrtc_options[1] = "--gpu-architecture";

  hc_asprintf (&nvrtc_options[2], "compute_%d%d", sm_major, sm_minor);

  nvrtc_options[3] = NULL;

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = (NVRTC_PTR *) backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcCompileProgram (program, 3, (const char * const *) nvrtc_options);

  hcfree (nvrtc_options[2]);

  size_t build_log_size = 0;

  hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    char *build_log = (char *) hcmalloc (build_log_size + 1);

    if (hc_nvrtcGetProgramLog (hashcat_ctx, program, build_log) == -1) return false;

    puts (build_log);

    hcfree (build_log);

    hc_nvrtcDestroyProgram (hashcat_ctx, &program);

    return false;
  }

  size_t binary_size;

  if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &binary_size) == -1) return false;

  char *binary = (char *) hcmalloc (binary_size);

  if (hc_nvrtcGetPTX (hashcat_ctx, program, binary) == -1)
  {
    hcfree (binary);

    return false;
  }

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  CUmodule cuda_module;

  const CUresult CU_err = cuda->cuModuleLoadDataEx (&cuda_module, binary, 0, NULL, NULL);

  if (CU_err != CUDA_SUCCESS)
  {
    hcfree (binary);

    return false;
  }

  hcfree (binary);

  if (hc_cuModuleUnload (hashcat_ctx, cuda_module) == -1) return false;

  if (hc_nvrtcDestroyProgram (hashcat_ctx, &program) == -1) return false;

  return true;
}
*/

static bool opencl_test_instruction (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_device_id device, const char *kernel_buf)
{
  cl_program program;

  if (hc_clCreateProgramWithSource (hashcat_ctx, context, 1, &kernel_buf, NULL, &program) == -1) return false;

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

  #ifndef DEBUG
  const int fd_stderr = fileno (stderr);
  const int stderr_bak = dup (fd_stderr);
  #ifdef _WIN
  const int tmp = open ("NUL", O_WRONLY);
  #else
  const int tmp = open ("/dev/null", O_WRONLY);
  #endif
  dup2 (tmp, fd_stderr);
  close (tmp);
  #endif

  const int CL_rc = ocl->clBuildProgram (program, 1, &device, NULL, NULL, NULL);

  #ifndef DEBUG
  dup2 (stderr_bak, fd_stderr);
  close (stderr_bak);
  #endif

  if (CL_rc != CL_SUCCESS)
  {
    #if defined (DEBUG)

    event_log_error (hashcat_ctx, "clBuildProgram(): %s", val2cstr_cl (CL_rc));

    size_t build_log_size = 0;

    hc_clGetProgramBuildInfo (hashcat_ctx, program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

    char *build_log = (char *) hcmalloc (build_log_size + 1);

    hc_clGetProgramBuildInfo (hashcat_ctx, program, device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

    build_log[build_log_size] = 0;

    puts (build_log);

    hcfree (build_log);

    #endif

    hc_clReleaseProgram (hashcat_ctx, program);

    return false;
  }

  if (hc_clReleaseProgram (hashcat_ctx, program) == -1) return false;

  return true;
}

static bool read_kernel_binary (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, size_t *kernel_lengths, char **kernel_sources)
{
  HCFILE fp;

  if (hc_fopen (&fp, kernel_file, "rb") == true)
  {
    struct stat st;

    if (stat (kernel_file, &st))
    {
      hc_fclose (&fp);

      return false;
    }

    const size_t klen = st.st_size;

    char *buf = (char *) hcmalloc (klen + 1);

    size_t num_read = hc_fread (buf, sizeof (char), klen, &fp);

    hc_fclose (&fp);

    if (num_read != klen)
    {
      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      hcfree (buf);

      return false;
    }

    buf[klen] = 0;

    kernel_lengths[0] = klen;

    kernel_sources[0] = buf;
  }
  else
  {
    event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

    return false;
  }

  return true;
}

static bool write_kernel_binary (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, char *binary, size_t binary_size)
{
  if (binary_size > 0)
  {
    HCFILE fp;

    if (hc_fopen (&fp, kernel_file, "wb") == false)
    {
      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      return false;
    }

    if (hc_lockfile (&fp) == -1)
    {
      hc_fclose (&fp);

      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      return false;
    }

    hc_fwrite (binary, sizeof (char), binary_size, &fp);

    hc_fflush (&fp);

    if (hc_unlockfile (&fp) == -1)
    {
      hc_fclose (&fp);

      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      return false;
    }

    hc_fclose (&fp);
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

void generate_cached_kernel_filename (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *cache_dir, const char *device_name_chksum, char *cached_file, bool is_metal)
{
  if (opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a1-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a3-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
      }
    }
    else
    {
      snprintf (cached_file, 255, "%s/kernels/m%05d-optimized.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
    }
  }
  else
  {
    if (attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
    {
      if (slow_candidates == true)
      {
        snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
      }
      else
      {
        if (attack_kern == ATTACK_KERN_STRAIGHT)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_COMBI)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a1-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_BF)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a3-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
        else if (attack_kern == ATTACK_KERN_NONE)
          snprintf (cached_file, 255, "%s/kernels/m%05d_a0-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
      }
    }
    else
    {
      snprintf (cached_file, 255, "%s/kernels/m%05d-pure.%s.%s", cache_dir, (int) kern_type, device_name_chksum, (is_metal == true) ? "metallib" : "kernel");
    }
  }
}

void generate_source_kernel_shared_filename (char *shared_dir, char *source_file)
{
  snprintf (source_file, 255, "%s/OpenCL/shared.cl", shared_dir);
}

void generate_cached_kernel_shared_filename (char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal)
{
  snprintf (cached_file, 255, "%s/kernels/shared.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
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

void generate_cached_kernel_mp_filename (const u32 opti_type, const u64 opts_type, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal)
{
  if ((opti_type & OPTI_TYPE_BRUTE_FORCE) && (opts_type & OPTS_TYPE_PT_GENERATE_BE))
  {
    snprintf (cached_file, 255, "%s/kernels/markov_be.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
  else
  {
    snprintf (cached_file, 255, "%s/kernels/markov_le.%s.%s", cache_dir, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
  }
}

void generate_source_kernel_amp_filename (const u32 attack_kern, char *shared_dir, char *source_file)
{
  snprintf (source_file, 255, "%s/OpenCL/amp_a%u.cl", shared_dir, attack_kern);
}

void generate_cached_kernel_amp_filename (const u32 attack_kern, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal)
{
  snprintf (cached_file, 255, "%s/kernels/amp_a%u.%s.%s", cache_dir, attack_kern, device_name_chksum_amp_mp, (is_metal == true) ? "metallib" : "kernel");
}

int gidd_to_pw_t (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  pw_idx_t pw_idx;

  pw_idx.off = 0;
  pw_idx.cnt = 0;
  pw_idx.len = 0;

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

    if (hc_cuMemcpyDtoHAsync (hashcat_ctx, &pw_idx, device_param->cuda_d_pws_idx + (gidd * sizeof (pw_idx_t)), sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1) return -1;

    if (hc_hipMemcpyDtoHAsync (hashcat_ctx, &pw_idx, device_param->hip_d_pws_idx + (gidd * sizeof (pw_idx_t)), sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, &pw_idx, device_param->metal_d_pws_idx, gidd * sizeof (pw_idx_t), sizeof (pw_idx_t)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, gidd * sizeof (pw_idx_t), sizeof (pw_idx_t), &pw_idx, 0, NULL, NULL) == -1) return -1;
  }

  const u32 off = pw_idx.off;
  const u32 cnt = pw_idx.cnt;
  const u32 len = pw_idx.len;

  if (cnt > 0)
  {
    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyDtoHAsync (hashcat_ctx, pw->i, device_param->cuda_d_pws_comp_buf + (off * sizeof (u32)), cnt * sizeof (u32), device_param->cuda_stream) == -1) return -1;

      if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemcpyDtoHAsync (hashcat_ctx, pw->i, device_param->hip_d_pws_comp_buf + (off * sizeof (u32)), cnt * sizeof (u32), device_param->hip_stream) == -1) return -1;

      if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, pw->i, device_param->metal_d_pws_comp_buf, off * sizeof (u32), cnt * sizeof (u32)) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      /* blocking */
      if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, off * sizeof (u32), cnt * sizeof (u32), pw->i, 0, NULL, NULL) == -1) return -1;
    }
  }

  for (u32 i = cnt; i < 64; i++)
  {
    pw->i[i] = 0;
  }

  pw->pw_len = len;

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1) return -1;
  }

  return 0;
}

int copy_pws_idx (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u64 gidd, const u64 cnt, pw_idx_t *dest)
{
  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

    if (hc_cuMemcpyDtoHAsync (hashcat_ctx, dest, device_param->cuda_d_pws_idx + (gidd * sizeof (pw_idx_t)), (cnt * sizeof (pw_idx_t)), device_param->cuda_stream) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1) return -1;

    if (hc_hipMemcpyDtoHAsync (hashcat_ctx, dest, device_param->hip_d_pws_idx + (gidd * sizeof (pw_idx_t)), (cnt * sizeof (pw_idx_t)), device_param->hip_stream) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;

    if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, dest, device_param->metal_d_pws_idx, gidd * sizeof (pw_idx_t), (cnt * sizeof (pw_idx_t))) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, gidd * sizeof (pw_idx_t), (cnt * sizeof (pw_idx_t)), dest, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int copy_pws_comp (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u32 off, u32 cnt, u32 *dest)
{
  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

    if (hc_cuMemcpyDtoHAsync (hashcat_ctx, dest, device_param->cuda_d_pws_comp_buf + (off * sizeof (u32)), cnt * sizeof (u32), device_param->cuda_stream) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1) return -1;

    if (hc_hipMemcpyDtoHAsync (hashcat_ctx, dest, device_param->hip_d_pws_comp_buf + (off * sizeof (u32)), cnt * sizeof (u32), device_param->hip_stream) == -1) return -1;

    if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;

    if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, dest, device_param->metal_d_pws_comp_buf, off * sizeof (u32), cnt * sizeof (u32)) == -1) return -1;
  }
  #endif

  if (device_param->is_opencl == true)
  {
    /* blocking */
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, off * sizeof (u32), cnt * sizeof (u32), dest, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int choose_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u64 pws_pos, const u64 pws_cnt, const u32 fast_iteration, const u32 salt_pos)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  module_ctx_t   *module_ctx   = hashcat_ctx->module_ctx;
  status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (user_options->stdout_flag == true)
  {
    return process_stdout (hashcat_ctx, device_param, pws_cnt);
  }

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    if (user_options->attack_mode == ATTACK_MODE_BF)
    {
      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
        {
          const u32 size_tm = device_param->size_tm;

          if (device_param->is_cuda == true)
          {
            if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tm_c, size_tm) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tm_c, size_tm) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_tm_c, size_tm) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tm_c, size_tm) == -1) return -1;
          }

          if (run_kernel_tm (hashcat_ctx, device_param) == -1) return -1;

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_bfs_c, device_param->cuda_d_tm_c, size_tm, device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_bfs_c, device_param->hip_d_tm_c, size_tm, device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bfs_c, 0, device_param->metal_d_tm_c, 0, size_tm) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_tm_c, device_param->opencl_d_bfs_c, 0, 0, size_tm, 0, NULL, NULL) == -1) return -1;

            if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
          }
        }
      }
    }

    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      // this is not perfectly right, only in case algorithm has to add 0x80 (most of the cases for fast optimized kernels)

      if (highest_pw_len < 16)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_pos, pws_cnt, true, fast_iteration) == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_pos, pws_cnt, true, fast_iteration) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_pos, pws_cnt, true, fast_iteration) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_4, pws_pos, pws_cnt, true, fast_iteration) == -1) return -1;
    }
  }
  else
  {
    // innerloop prediction to get a speed estimation is hard, because we don't know in advance how much
    // time the different kernels take and if their weightnings are equally distributed.
    // - for instance, a regular _loop kernel is likely to be the slowest, but _loop2 kernel can also be slow.
    //   in fact, _loop2 can be even slower (see iTunes backup >= 10.0).
    // - hooks can have a large influence depending on the OS.
    //   spawning threads and memory allocations take a lot of time on windows (compared to linux).
    // - the kernel execution can take shortcuts based on intermediate values
    //   while these intermediate valus depend on input values.
    // - if we meassure runtimes of different kernels to find out about their weightning
    //   we need to call them with real input values otherwise we miss the shortcuts inside the kernel.
    // - the problem is that these real input values could crack the hash which makes the chaos perfect.
    //
    // so the innerloop prediction is not perfectly accurate, because we:
    //
    // 1. completely ignore hooks and the time they take.
    // 2. assume that the code in _loop and _loop2 is similar,
    //    but we respect the different iteration counts in _loop and _loop2.
    // 3. ignore _comp kernel runtimes (probably irrelevant).
    //
    // as soon as the first restore checkpoint is reached the prediction is accurate.
    // also the closer it gets to that point.

    if (true)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_pws_buf, device_param->cuda_d_pws_amp_buf, pws_cnt * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_pws_buf, device_param->hip_d_pws_amp_buf, pws_cnt * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_buf, 0, device_param->metal_d_pws_amp_buf, 0, pws_cnt * sizeof (pw_t)) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_amp_buf, device_param->opencl_d_pws_buf, 0, 0, pws_cnt * sizeof (pw_t), 0, NULL, NULL) == -1) return -1;
      }

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (run_kernel_amp (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
      }

      if (hashconfig->opts_type & OPTS_TYPE_POST_AMP_UTF16LE)
      {
        if (device_param->is_cuda == true)
        {
          if (run_cuda_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->cuda_d_pws_buf, pws_cnt) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (run_hip_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->hip_d_pws_buf, pws_cnt) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (run_metal_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->metal_d_pws_buf, pws_cnt) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (run_opencl_kernel_utf8toutf16le (hashcat_ctx, device_param, device_param->opencl_d_pws_buf, pws_cnt) == -1) return -1;
        }
      }

      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_pos, pws_cnt, false, 0) == -1) return -1;

      if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_12, pws_pos, pws_cnt, false, 0) == -1) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, pws_cnt * hashconfig->hook_size, device_param->cuda_stream) == -1) return -1;

          if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->hip_d_hooks, pws_cnt * hashconfig->hook_size, device_param->hip_stream) == -1) return -1;

          if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, device_param->hooks_buf, device_param->metal_d_hooks, 0, pws_cnt * hashconfig->hook_size) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          /* blocking */
          if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, pws_cnt * hashconfig->hook_size, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }

        const int hook_threads = (int) user_options->hook_threads;

        hook_thread_param_t *hook_threads_param = (hook_thread_param_t *) hcmalloc (hook_threads * sizeof (hook_thread_param_t));
        hc_thread_t         *c_threads          = (hc_thread_t *)         hcmalloc (hook_threads * sizeof (hc_thread_t));

        for (int i = 0; i < hook_threads; i++)
        {
          hook_thread_param_t *hook_thread_param = hook_threads_param + i;

          hook_thread_param->tid = i;
          hook_thread_param->tsz = hook_threads;

          hook_thread_param->module_ctx = module_ctx;
          hook_thread_param->status_ctx = status_ctx;

          hook_thread_param->device_param = device_param;

          hook_thread_param->hook_extra_param = module_ctx->hook_extra_params[i];
          hook_thread_param->hook_salts_buf = hashes->hook_salts_buf;

          hook_thread_param->salt_pos = salt_pos;

          hook_thread_param->pws_cnt = pws_cnt;

          hc_thread_create (c_threads[i], hook12_thread, hook_thread_param);
        }

        hc_thread_wait (hook_threads, c_threads);

        hcfree (c_threads);
        hcfree (hook_threads_param);

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, pws_cnt * hashconfig->hook_size, device_param->cuda_stream) == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_hooks, device_param->hooks_buf, pws_cnt * hashconfig->hook_size, device_param->hip_stream) == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_hooks, 0, device_param->hooks_buf, pws_cnt * hashconfig->hook_size) == -1) return -1;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_FALSE, 0, pws_cnt * hashconfig->hook_size, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }
      }
    }

    if (true)
    {
      const u32 salt_repeats = hashes->salts_buf[salt_pos].salt_repeats;

      for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
      {
        device_param->kernel_param.salt_repeat = salt_repeat;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
        {
          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2P, pws_pos, pws_cnt, false, 0) == -1) return -1;
        }

        if (true)
        {
          const u32 iter = hashes->salts_buf[salt_pos].salt_iter;

          const u32 loop_step = device_param->kernel_loops;

          for (u32 loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
          {
            u32 loop_left = iter - loop_pos;

            loop_left = MIN (loop_left, loop_step);

            device_param->kernel_param.loop_pos = loop_pos;
            device_param->kernel_param.loop_cnt = loop_left;

            if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_pos, pws_cnt, true, slow_iteration) == -1) return -1;

            if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
            {
              if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2E, pws_pos, pws_cnt, true, slow_iteration) == -1) return -1;
            }

            //bug?
            //while (status_ctx->run_thread_level2 == false) break;
            if (status_ctx->run_thread_level2 == false) break;

            /**
             * speed
             */

            const u32 iter1r = hashes->salts_buf[salt_pos].salt_iter  * (salt_repeats + 1);
            const u32 iter2r = hashes->salts_buf[salt_pos].salt_iter2 * (salt_repeats + 1);

            const double iter_part = (double) ((iter * salt_repeat) + loop_pos + loop_left) / (double) (iter1r + iter2r);

            const u64 perf_sum_all = (u64) (pws_cnt * iter_part);

            double speed_msec = hc_timer_get (device_param->timer_speed);

            const u32 speed_pos = device_param->speed_pos;

            device_param->speed_cnt[speed_pos] = perf_sum_all;

            device_param->speed_msec[speed_pos] = speed_msec;

            if (user_options->speed_only == true)
            {
              if (speed_msec > 4000)
              {
                device_param->outerloop_multi *= 1 / iter_part;

                device_param->speed_pos = 1;

                device_param->speed_only_finish = true;

                return 0;
              }
            }
          }

          if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
          {
            if (run_kernel (hashcat_ctx, device_param, KERN_RUN_23, pws_pos, pws_cnt, false, 0) == -1) return -1;

            if (device_param->is_cuda == true)
            {
              if (hc_cuMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, pws_cnt * hashconfig->hook_size, device_param->cuda_stream) == -1) return -1;

              if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
            }

            if (device_param->is_hip == true)
            {
              if (hc_hipMemcpyDtoHAsync (hashcat_ctx, device_param->hooks_buf, device_param->hip_d_hooks, pws_cnt * hashconfig->hook_size, device_param->hip_stream) == -1) return -1;

              if (hc_hipStreamSynchronize (hashcat_ctx, device_param->hip_stream) == -1) return -1;
            }

            #if defined (__APPLE__)
            if (device_param->is_metal == true)
            {
              if (hc_mtlMemcpyDtoH (hashcat_ctx, device_param->metal_command_queue, device_param->hooks_buf, device_param->metal_d_hooks, 0, pws_cnt * hashconfig->hook_size) == -1) return -1;
            }
            #endif

            if (device_param->is_opencl == true)
            {
              /* blocking */
              if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, pws_cnt * hashconfig->hook_size, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
            }

            const int hook_threads = (int) user_options->hook_threads;

            hook_thread_param_t *hook_threads_param = (hook_thread_param_t *) hcmalloc (hook_threads * sizeof (hook_thread_param_t));
            hc_thread_t         *c_threads          = (hc_thread_t *)         hcmalloc (hook_threads * sizeof (hc_thread_t));

            for (int i = 0; i < hook_threads; i++)
            {
              hook_thread_param_t *hook_thread_param = hook_threads_param + i;

              hook_thread_param->tid = i;
              hook_thread_param->tsz = hook_threads;

              hook_thread_param->module_ctx = module_ctx;
              hook_thread_param->status_ctx = status_ctx;

              hook_thread_param->device_param = device_param;

              hook_thread_param->hook_extra_param = module_ctx->hook_extra_params[i];
              hook_thread_param->hook_salts_buf = hashes->hook_salts_buf;

              hook_thread_param->salt_pos = salt_pos;

              hook_thread_param->pws_cnt = pws_cnt;

              hc_thread_create (c_threads[i], hook23_thread, hook_thread_param);
            }

            hc_thread_wait (hook_threads, c_threads);

            hcfree (c_threads);
            hcfree (hook_threads_param);

            if (device_param->is_cuda == true)
            {
              if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, pws_cnt * hashconfig->hook_size, device_param->cuda_stream) == -1) return -1;
            }

            if (device_param->is_hip == true)
            {
              if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_hooks, device_param->hooks_buf, pws_cnt * hashconfig->hook_size, device_param->hip_stream) == -1) return -1;
            }

            #if defined (__APPLE__)
            if (device_param->is_metal == true)
            {
              if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_hooks, 0, device_param->hooks_buf, pws_cnt * hashconfig->hook_size) == -1) return -1;
            }
            #endif

            if (device_param->is_opencl == true)
            {
              if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_FALSE, 0, pws_cnt * hashconfig->hook_size, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
            }
          }
        }
      }
    }

    // note: they also do not influence the performance screen
    // in case you want to use this, this cane make sense only if your input data comes out of tmps[]

    if (hashconfig->opts_type & OPTS_TYPE_INIT2)
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, pws_pos, pws_cnt, false, 0) == -1) return -1;
    }

    if (true)
    {
      const u32 salt_repeats = hashes->salts_buf[salt_pos].salt_repeats;

      for (u32 salt_repeat = 0; salt_repeat <= salt_repeats; salt_repeat++)
      {
        device_param->kernel_param.salt_repeat = salt_repeat;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
        {
          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2P, pws_pos, pws_cnt, false, 0) == -1) return -1;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          u32 iter = hashes->salts_buf[salt_pos].salt_iter2;

          u32 loop_step = device_param->kernel_loops;

          for (u32 loop_pos = 0, slow_iteration = 0; loop_pos < iter; loop_pos += loop_step, slow_iteration++)
          {
            u32 loop_left = iter - loop_pos;

            loop_left = MIN (loop_left, loop_step);

            device_param->kernel_param.loop_pos = loop_pos;
            device_param->kernel_param.loop_cnt = loop_left;

            if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, pws_pos, pws_cnt, true, slow_iteration) == -1) return -1;

            //bug?
            //while (status_ctx->run_thread_level2 == false) break;
            if (status_ctx->run_thread_level2 == false) break;

            /**
             * speed
             */

            const u32 iter1r = hashes->salts_buf[salt_pos].salt_iter  * (salt_repeats + 1);
            const u32 iter2r = hashes->salts_buf[salt_pos].salt_iter2 * (salt_repeats + 1);

            const double iter_part = (double) (iter1r + (iter * salt_repeat) + loop_pos + loop_left) / (double) (iter1r + iter2r);

            const u64 perf_sum_all = (u64) (pws_cnt * iter_part);

            double speed_msec = hc_timer_get (device_param->timer_speed);

            const u32 speed_pos = device_param->speed_pos;

            device_param->speed_cnt[speed_pos] = perf_sum_all;

            device_param->speed_msec[speed_pos] = speed_msec;
          }
        }
      }
    }

    if (true)
    {
      if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
      {
        // module_ctx->module_deep_comp_kernel () would apply only on the first salt so we can't use it in -a 9 mode
        // Instead we have to call all the registered AUX kernels

        if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
        {
          const u32 loops_cnt = hashes->salts_buf[salt_pos].digests_cnt;

          for (u32 loops_pos = 0; loops_pos < loops_cnt; loops_pos++)
          {
            device_param->kernel_param.loop_pos = loops_pos;
            device_param->kernel_param.loop_cnt = loops_cnt;

            if (hashconfig->opts_type & OPTS_TYPE_AUX1)
            {
              if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX1, pws_pos, pws_cnt, false, 0) == -1) return -1;

              if (status_ctx->run_thread_level2 == false) break;
            }

            if (hashconfig->opts_type & OPTS_TYPE_AUX2)
            {
              if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX2, pws_pos, pws_cnt, false, 0) == -1) return -1;

              if (status_ctx->run_thread_level2 == false) break;
            }

            if (hashconfig->opts_type & OPTS_TYPE_AUX3)
            {
              if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX3, pws_pos, pws_cnt, false, 0) == -1) return -1;

              if (status_ctx->run_thread_level2 == false) break;
            }

            if (hashconfig->opts_type & OPTS_TYPE_AUX4)
            {
              if (run_kernel (hashcat_ctx, device_param, KERN_RUN_AUX4, pws_pos, pws_cnt, false, 0) == -1) return -1;

              if (status_ctx->run_thread_level2 == false) break;
            }
          }
        }
        else
        {
          const u32 loops_cnt = hashes->salts_buf[salt_pos].digests_cnt;

          for (u32 loops_pos = 0; loops_pos < loops_cnt; loops_pos++)
          {
            device_param->kernel_param.loop_pos = loops_pos;
            device_param->kernel_param.loop_cnt = loops_cnt;

            const u32 deep_comp_kernel = module_ctx->module_deep_comp_kernel (hashes, salt_pos, loops_pos);

            if (run_kernel (hashcat_ctx, device_param, deep_comp_kernel, pws_pos, pws_cnt, false, 0) == -1) return -1;

            if (status_ctx->run_thread_level2 == false) break;
          }
        }
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_pos, pws_cnt, false, 0) == -1) return -1;
      }
    }

    /*
     * maybe we should add this zero of temporary buffers
     * however it drops the performance from 7055338 to 7010621

    if (device_param->is_cuda == true)
    {
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tmps,   device_param->size_tmps) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tmps,    device_param->size_tmps) == -1) return -1;
    }

    if (device_param->is_opencl == true)
    {
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tmps, device_param->size_tmps) == -1) return -1;
    }
    */

    if ((hashconfig->opts_type & OPTS_TYPE_HOOK12) || (hashconfig->opts_type & OPTS_TYPE_HOOK23))
    {
      if (device_param->is_cuda == true)
      {
        if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_hooks, pws_cnt * hashconfig->hook_size) == -1) return -1;
      }

      if (device_param->is_hip == true)
      {
        if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_hooks, pws_cnt * hashconfig->hook_size) == -1) return -1;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_hooks, pws_cnt * hashconfig->hook_size) == -1) return -1;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_hooks, pws_cnt * hashconfig->hook_size) == -1) return -1;
      }
    }
  }

  return 0;
}

static void rebuild_pws_compressed_append (hc_device_param_t *device_param, const u64 pws_cnt, const u8 chr)
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

  hcfree (device_param->pws_comp);
  hcfree (device_param->pws_idx);

  device_param->pws_comp = tmp_pws_comp;
  device_param->pws_idx  = tmp_pws_idx;
}

int run_cuda_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit[0]       = (void *) &buf;
  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = CEILDIV (num_elements, kernel_threads);

  CUfunction function = device_param->cuda_function_atinit;

  if (hc_cuLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_atinit, NULL) == -1) return -1;

  return 0;
}

int run_cuda_kernel_utf8toutf16le (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_utf8toutf16le[0]       = (void *) &buf;
  device_param->kernel_params_utf8toutf16le_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_utf8toutf16le;

  num_elements = CEILDIV (num_elements, kernel_threads);

  CUfunction function = device_param->cuda_function_utf8toutf16le;

  if (hc_cuLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_utf8toutf16le, NULL) == -1) return -1;

  return 0;
}

int run_cuda_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u8 value, const u64 size)
{
  return hc_cuMemsetD8Async (hashcat_ctx, buf + offset, value, size, device_param->cuda_stream);
}

int run_cuda_kernel_memset32 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u32 value, const u64 size)
{
  /* check that the size is multiple of element size */
  if (size % 4 != 0)
  {
    return CUDA_ERROR_INVALID_VALUE;
  }

  return hc_cuMemsetD32Async (hashcat_ctx, buf + offset, value, size / 4, device_param->cuda_stream);
}

int run_cuda_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  if (num16d)
  {
    device_param->kernel_params_bzero[0]       = (void *) &buf;
    device_param->kernel_params_bzero_buf64[1] = num16d;

    const u64 kernel_threads = device_param->kernel_wgs_bzero;

    u64 num_elements = CEILDIV (num16d, kernel_threads);

    CUfunction function = device_param->cuda_function_bzero;

    if (hc_cuLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_bzero, NULL) == -1) return -1;
  }

  if (num16m)
  {
    if (hc_cuMemcpyHtoDAsync (hashcat_ctx, buf + (num16d * 16), bzeros, num16m, device_param->cuda_stream) == -1) return -1;
  }

  return 0;
}

int run_hip_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit[0]       = (void *) &buf;
  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = CEILDIV (num_elements, kernel_threads);

  hipFunction_t function = device_param->hip_function_atinit;

  if (hc_hipLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_atinit, NULL) == -1) return -1;

  return 0;
}

int run_hip_kernel_utf8toutf16le (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_utf8toutf16le[0]       = (void *) &buf;
  device_param->kernel_params_utf8toutf16le_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_utf8toutf16le;

  num_elements = CEILDIV (num_elements, kernel_threads);

  hipFunction_t function = device_param->hip_function_utf8toutf16le;

  if (hc_hipLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_utf8toutf16le, NULL) == -1) return -1;

  return 0;
}

int run_hip_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u8  value, const u64 size)
{
  return hc_hipMemsetD8Async (hashcat_ctx, buf + offset, value, size, device_param->hip_stream);
}

int run_hip_kernel_memset32 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u32 value, const u64 size)
{
  /* check that the size is multiple of element size */
  if (size % 4 != 0)
  {
    return hipErrorInvalidValue;
  }

  return hc_hipMemsetD32Async (hashcat_ctx, buf + offset, value, size / 4, device_param->hip_stream);
}

int run_hip_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  if (num16d)
  {
    device_param->kernel_params_bzero[0]       = (void *) &buf;
    device_param->kernel_params_bzero_buf64[1] = num16d;

    const u64 kernel_threads = device_param->kernel_wgs_bzero;

    u64 num_elements = CEILDIV (num16d, kernel_threads);

    hipFunction_t function = device_param->hip_function_bzero;

    if (hc_hipLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_bzero, NULL) == -1) return -1;
  }

  if (num16m)
  {
    if (hc_hipMemcpyHtoDAsync (hashcat_ctx, buf + (num16d * 16), bzeros, num16m, device_param->hip_stream) == -1) return -1;
  }

  return 0;
}

#if defined (__APPLE__)
int run_metal_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, id buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = round_up_multiple_32 (num_elements, kernel_threads);

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  id metal_command_buffer = NULL;
  id metal_command_encoder = NULL;

  if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param->metal_pipeline_atinit, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

  if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 0, buf, NULL, 0) == -1) return -1;
  if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 1, NULL, device_param->kernel_params_atinit[1], sizeof (u64)) == -1) return -1;

  double ms = 0;

  if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;

  return 0;
}

int run_metal_kernel_utf8toutf16le (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, id buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_utf8toutf16le_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_utf8toutf16le;

  num_elements = round_up_multiple_32 (num_elements, kernel_threads);

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  id metal_command_buffer = NULL;
  id metal_command_encoder = NULL;

  if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param->metal_pipeline_utf8toutf16le, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

  if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 0, buf, NULL, 0) == -1) return -1;
  if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 1, NULL, device_param->kernel_params_utf8toutf16le[1], sizeof (u64)) == -1) return -1;

  double ms = 0;

  if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;

  return 0;
}

int run_metal_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, id buf, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  // with apple GPU clEnqueueWriteBuffer() return CL_INVALID_VALUE, workaround

  if (num16d)
  {
    const u64 kernel_threads = device_param->kernel_wgs_bzero;

    u64 num_elements = round_up_multiple_32 (num16d, kernel_threads);

    id metal_command_buffer = NULL;
    id metal_command_encoder = NULL;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param->metal_pipeline_bzero, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 0, buf, NULL, 0) == -1) return -1;
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 1, NULL, (void *) &num16d, sizeof (u64)) == -1) return -1;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;
  }

  if (num16m)
  {
    if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE && \
       (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK || device_param->opencl_device_vendor_id == VENDOR_ID_APPLE) && \
       device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      u8 *bzeros_apple = (u8 *) hccalloc (num16m, sizeof (u8));

      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, buf, num16d * 16, bzeros_apple, num16m) == -1) return -1;

      hcfree (bzeros_apple);
    }
    else
    {
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, buf, num16d * 16, bzeros, num16m) == -1) return -1;
    }
  }

  return 0;
}

int run_metal_kernel_memset32 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem buf, const u64 offset, const u32 value, const u64 size)
{
  int rc;

  const u64 N = size / 4;

  /* check that the size is multiple of element size */
  if (size % 4 != 0)
  {
    return CL_INVALID_VALUE;
  }

  u32 *tmp = (u32 *) hcmalloc (size);

  for (u64 i = 0; i < N; i++)
  {
    tmp[i] = value;
  }

  rc = hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, buf, offset, tmp, size);

  hcfree (tmp);

  return rc;
}
#endif // __APPLE__

int run_opencl_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  cl_kernel kernel = device_param->opencl_kernel_atinit;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  if (hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem), (void *) &buf) == -1) return -1;

  if (hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]) == -1) return -1;

  if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

  return 0;
}

int run_opencl_kernel_utf8toutf16le (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_utf8toutf16le_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_utf8toutf16le;

  num_elements = round_up_multiple_64 (num_elements, kernel_threads);

  cl_kernel kernel = device_param->opencl_kernel_utf8toutf16le;

  const size_t global_work_size[3] = { num_elements,    1, 1 };
  const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

  if (hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem), (void *) &buf) == -1) return -1;

  if (hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_ulong), device_param->kernel_params_utf8toutf16le[1]) == -1) return -1;

  if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

  return 0;
}

int run_opencl_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u8 value, const u64 size)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  const OCL_PTR       *ocl         = backend_ctx->ocl;

  int rc;

  /* workaround if missing clEnqueueFillBuffer() */
  if (ocl->clEnqueueFillBuffer == NULL)
  {
    char *tmp = hcmalloc (size * sizeof (u8));

    memset (tmp, value, size);

    /* blocking */
    rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, CL_TRUE, offset, size, tmp, 0, NULL, NULL);

    hcfree (tmp);
  }
  else
  {
    rc = hc_clEnqueueFillBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, &value, sizeof (u8), offset, size, 0, NULL, NULL);
  }

  return rc;
}

int run_opencl_kernel_memset32 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u32 value, const u64 size)
{
  const backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  const OCL_PTR       *ocl         = backend_ctx->ocl;

  int rc;

  /* workaround if missing clEnqueueFillBuffer() */
  if (ocl->clEnqueueFillBuffer == NULL)
  {
    const u64 N = size / 4;

    /* check that the size is multiple of element size */
    if (size % 4 != 0)
    {
      return CL_INVALID_VALUE;
    }

    u32 *tmp = (u32 *) hcmalloc (size);

    for (u64 i = 0; i < N; i++)
    {
      tmp[i] = value;
    }

    /* blocking */
    rc = hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, CL_TRUE, offset, size, tmp, 0, NULL, NULL);

    hcfree (tmp);
  }
  else
  {
    rc = hc_clEnqueueFillBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, &value, sizeof (u32), offset, size, 0, NULL, NULL);
  }

  return rc;
}

int run_opencl_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  // with apple GPU clEnqueueWriteBuffer() return CL_INVALID_VALUE, workaround

  if (num16d)
  {
    const u64 kernel_threads = device_param->kernel_wgs_bzero;

    u64 num_elements = round_up_multiple_64 (num16d, kernel_threads);

    cl_kernel kernel = device_param->opencl_kernel_bzero;

    if (hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem),   (void *) &buf)    == -1) return -1;
    if (hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_ulong), (void *) &num16d) == -1) return -1;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;
  }

  if (num16m)
  {
    if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE && \
       (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK || device_param->opencl_device_vendor_id == VENDOR_ID_APPLE) && \
       device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
    {
      u8 *bzeros_apple = (u8 *) hccalloc (num16m, sizeof (u8));

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, CL_TRUE, num16d * 16, num16m, bzeros_apple, 0, NULL, NULL) == -1) return -1;

      hcfree (bzeros_apple);
    }
    else
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, CL_FALSE, num16d * 16, num16m, bzeros, 0, NULL, NULL) == -1) return -1;
    }
  }

  return 0;
}

int run_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 pws_pos, const u64 num, const u32 event_update, const u32 iteration)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;

  u64 kernel_threads = 0;
  u64 dynamic_shared_mem = 0;

  switch (kern_run)
  {
    case KERN_RUN_1:
      kernel_threads     = device_param->kernel_wgs1;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size1;
      break;
    case KERN_RUN_12:
      kernel_threads     = device_param->kernel_wgs12;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size12;
      break;
    case KERN_RUN_2P:
      kernel_threads     = device_param->kernel_wgs2p;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size2p;
      break;
    case KERN_RUN_2:
      kernel_threads     = device_param->kernel_wgs2;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size2;
      break;
    case KERN_RUN_2E:
      kernel_threads     = device_param->kernel_wgs2e;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size2e;
      break;
    case KERN_RUN_23:
      kernel_threads     = device_param->kernel_wgs23;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size23;
      break;
    case KERN_RUN_3:
      kernel_threads     = device_param->kernel_wgs3;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size3;
      break;
    case KERN_RUN_4:
      kernel_threads     = device_param->kernel_wgs4;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size4;
      break;
    case KERN_RUN_INIT2:
      kernel_threads     = device_param->kernel_wgs_init2;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_init2;
      break;
    case KERN_RUN_LOOP2P:
      kernel_threads     = device_param->kernel_wgs_loop2p;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_loop2p;
      break;
    case KERN_RUN_LOOP2:
      kernel_threads     = device_param->kernel_wgs_loop2;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_loop2;
      break;
    case KERN_RUN_AUX1:
      kernel_threads     = device_param->kernel_wgs_aux1;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_aux1;
      break;
    case KERN_RUN_AUX2:
      kernel_threads     = device_param->kernel_wgs_aux2;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_aux2;
      break;
    case KERN_RUN_AUX3:
      kernel_threads     = device_param->kernel_wgs_aux3;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_aux3;
      break;
    case KERN_RUN_AUX4:
      kernel_threads     = device_param->kernel_wgs_aux4;
      dynamic_shared_mem = device_param->kernel_dynamic_local_mem_size_aux4;
      break;
  }

  if ((hashconfig->opts_type & OPTS_TYPE_DYNAMIC_SHARED) == 0)
  {
    dynamic_shared_mem = 0;
  }

  //if (device_param->is_cuda == true)
  //{
    //if ((device_param->kernel_dynamic_local_mem_size_memset % device_param->device_local_mem_size) == 0)
    //{
      // this is the case Compute Capability 7.5
      // there is also Compute Capability 7.0 which offers a larger dynamic local size access
      // however, if it's an exact multiple the driver can optimize this for us more efficient

      //dynamic_shared_mem = 0;
    //}
  //}

  kernel_threads = MIN (kernel_threads, device_param->kernel_threads);

  device_param->kernel_param.pws_pos = pws_pos;
  device_param->kernel_param.gid_max = num;

  u64 num_elements = num;

  if (device_param->is_cuda == true)
  {
    CUfunction cuda_function = NULL;

    switch (kern_run)
    {
      case KERN_RUN_1:      cuda_function = device_param->cuda_function1;       break;
      case KERN_RUN_12:     cuda_function = device_param->cuda_function12;      break;
      case KERN_RUN_2P:     cuda_function = device_param->cuda_function2p;      break;
      case KERN_RUN_2:      cuda_function = device_param->cuda_function2;       break;
      case KERN_RUN_2E:     cuda_function = device_param->cuda_function2e;      break;
      case KERN_RUN_23:     cuda_function = device_param->cuda_function23;      break;
      case KERN_RUN_3:      cuda_function = device_param->cuda_function3;       break;
      case KERN_RUN_4:      cuda_function = device_param->cuda_function4;       break;
      case KERN_RUN_INIT2:  cuda_function = device_param->cuda_function_init2;  break;
      case KERN_RUN_LOOP2P: cuda_function = device_param->cuda_function_loop2p; break;
      case KERN_RUN_LOOP2:  cuda_function = device_param->cuda_function_loop2;  break;
      case KERN_RUN_AUX1:   cuda_function = device_param->cuda_function_aux1;   break;
      case KERN_RUN_AUX2:   cuda_function = device_param->cuda_function_aux2;   break;
      case KERN_RUN_AUX3:   cuda_function = device_param->cuda_function_aux3;   break;
      case KERN_RUN_AUX4:   cuda_function = device_param->cuda_function_aux4;   break;
    }

    if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_kernel_param, &device_param->kernel_param, device_param->size_kernel_params, device_param->cuda_stream) == -1) return -1;

    if (hc_cuFuncSetAttribute (hashcat_ctx, cuda_function, CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES, dynamic_shared_mem) == -1) return -1;

    if (kernel_threads == 0) kernel_threads = 1;

    num_elements = CEILDIV (num_elements, kernel_threads);

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
    else if (kern_run == KERN_RUN_INIT2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_INIT2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }
    else if (kern_run == KERN_RUN_LOOP2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_LOOP2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }

    if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event1, device_param->cuda_stream) == -1) return -1;

    if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 1, 1, kernel_threads, 1, 1, dynamic_shared_mem, device_param->cuda_stream, device_param->kernel_params, NULL) == -1) return -1;

    if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event2, device_param->cuda_stream) == -1) return -1;

    if (hc_cuEventSynchronize (hashcat_ctx, device_param->cuda_event2) == -1) return -1;

    float exec_ms;

    if (hc_cuEventElapsedTime (hashcat_ctx, &exec_ms, device_param->cuda_event1, device_param->cuda_event2) == -1) return -1;

    if (event_update)
    {
      u32 exec_pos = device_param->exec_pos;

      device_param->exec_msec[exec_pos] = exec_ms;

      exec_pos++;

      if (exec_pos == EXEC_CACHE)
      {
        exec_pos = 0;
      }

      device_param->exec_pos = exec_pos;
    }
  }

  if (device_param->is_hip == true)
  {
    hipFunction_t hip_function = NULL;

    switch (kern_run)
    {
      case KERN_RUN_1:      hip_function = device_param->hip_function1;       break;
      case KERN_RUN_12:     hip_function = device_param->hip_function12;      break;
      case KERN_RUN_2P:     hip_function = device_param->hip_function2p;      break;
      case KERN_RUN_2:      hip_function = device_param->hip_function2;       break;
      case KERN_RUN_2E:     hip_function = device_param->hip_function2e;      break;
      case KERN_RUN_23:     hip_function = device_param->hip_function23;      break;
      case KERN_RUN_3:      hip_function = device_param->hip_function3;       break;
      case KERN_RUN_4:      hip_function = device_param->hip_function4;       break;
      case KERN_RUN_INIT2:  hip_function = device_param->hip_function_init2;  break;
      case KERN_RUN_LOOP2P: hip_function = device_param->hip_function_loop2p; break;
      case KERN_RUN_LOOP2:  hip_function = device_param->hip_function_loop2;  break;
      case KERN_RUN_AUX1:   hip_function = device_param->hip_function_aux1;   break;
      case KERN_RUN_AUX2:   hip_function = device_param->hip_function_aux2;   break;
      case KERN_RUN_AUX3:   hip_function = device_param->hip_function_aux3;   break;
      case KERN_RUN_AUX4:   hip_function = device_param->hip_function_aux4;   break;
    }

    if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_kernel_param, &device_param->kernel_param, device_param->size_kernel_params, device_param->hip_stream) == -1) return -1;

    //if (hc_hipFuncSetAttribute (hashcat_ctx, hip_function, HIP_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES, dynamic_shared_mem) == -1) return -1;

    if (kernel_threads == 0) kernel_threads = 1;

    num_elements = CEILDIV (num_elements, kernel_threads);

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
    else if (kern_run == KERN_RUN_INIT2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_INIT2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }
    else if (kern_run == KERN_RUN_LOOP2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_LOOP2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }

    if (hc_hipEventRecord (hashcat_ctx, device_param->hip_event1, device_param->hip_stream) == -1) return -1;

    if (hc_hipLaunchKernel (hashcat_ctx, hip_function, num_elements, 1, 1, kernel_threads, 1, 1, dynamic_shared_mem, device_param->hip_stream, device_param->kernel_params, NULL) == -1) return -1;

    if (hc_hipEventRecord (hashcat_ctx, device_param->hip_event2, device_param->hip_stream) == -1) return -1;

    if (hc_hipEventSynchronize (hashcat_ctx, device_param->hip_event2) == -1) return -1;

    float exec_ms;

    if (hc_hipEventElapsedTime (hashcat_ctx, &exec_ms, device_param->hip_event1, device_param->hip_event2) == -1) return -1;

    if (event_update)
    {
      u32 exec_pos = device_param->exec_pos;

      device_param->exec_msec[exec_pos] = exec_ms;

      exec_pos++;

      if (exec_pos == EXEC_CACHE)
      {
        exec_pos = 0;
      }

      device_param->exec_pos = exec_pos;
    }
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    mtl_command_encoder metal_command_encoder = NULL;
    mtl_command_buffer  metal_command_buffer = NULL;
    mtl_pipeline        metal_pipeline = NULL;

    switch (kern_run)
    {
      case KERN_RUN_1:      metal_pipeline = device_param->metal_pipeline1;       break;
      case KERN_RUN_12:     metal_pipeline = device_param->metal_pipeline12;      break;
      case KERN_RUN_2P:     metal_pipeline = device_param->metal_pipeline2p;      break;
      case KERN_RUN_2:      metal_pipeline = device_param->metal_pipeline2;       break;
      case KERN_RUN_2E:     metal_pipeline = device_param->metal_pipeline2e;      break;
      case KERN_RUN_23:     metal_pipeline = device_param->metal_pipeline23;      break;
      case KERN_RUN_3:      metal_pipeline = device_param->metal_pipeline3;       break;
      case KERN_RUN_4:      metal_pipeline = device_param->metal_pipeline4;       break;
      case KERN_RUN_INIT2:  metal_pipeline = device_param->metal_pipeline_init2;  break;
      case KERN_RUN_LOOP2P: metal_pipeline = device_param->metal_pipeline_loop2p; break;
      case KERN_RUN_LOOP2:  metal_pipeline = device_param->metal_pipeline_loop2;  break;
      case KERN_RUN_AUX1:   metal_pipeline = device_param->metal_pipeline_aux1;   break;
      case KERN_RUN_AUX2:   metal_pipeline = device_param->metal_pipeline_aux2;   break;
      case KERN_RUN_AUX3:   metal_pipeline = device_param->metal_pipeline_aux3;   break;
      case KERN_RUN_AUX4:   metal_pipeline = device_param->metal_pipeline_aux4;   break;
    }

    if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_kernel_param, 0, &device_param->kernel_param, device_param->size_kernel_params) == -1) return -1;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, metal_pipeline, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    // all buffers must be allocated
    int tmp_buf_cnt = 0;
    mtl_mem tmp_buf[25] = { 0 };

    for (u32 i = 0; i <= 24; i++)
    {
      // allocate fake buffer if NULL
      if (device_param->kernel_params[i] == NULL)
      {
        if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, sizeof (u8), NULL, &tmp_buf[tmp_buf_cnt]) == -1) return -1;
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, tmp_buf[tmp_buf_cnt], NULL, 0) == -1) return -1;
        tmp_buf_cnt++;
      }
      else
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params[i], NULL, 0) == -1) return -1;
      }
    }

    if (kernel_threads == 0) kernel_threads = 1;

    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

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
    else if (kern_run == KERN_RUN_INIT2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_INIT2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }
    else if (kern_run == KERN_RUN_LOOP2)
    {
      if (hashconfig->opti_type & OPTI_TYPE_SLOW_HASH_SIMD_LOOP2)
      {
        num_elements = CEILDIV (num_elements, device_param->vector_width);
      }
    }

    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    double ms = 0;

    const int rc_cc = hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms);

    if (rc_cc != -1)
    {
      float exec_ms = (float) ms;

      if (event_update)
      {
        u32 exec_pos = device_param->exec_pos;

        device_param->exec_msec[exec_pos] = exec_ms;

        exec_pos++;

        if (exec_pos == EXEC_CACHE)
        {
          exec_pos = 0;
        }

        device_param->exec_pos = exec_pos;
      }
    }

    // release tmp_buf

    for (int i = 0; i < tmp_buf_cnt; i++)
    {
      hc_mtlReleaseMemObject (hashcat_ctx, tmp_buf[i]);
      tmp_buf[i] = NULL;
    }

    if (rc_cc == -1) return -1;
  }
  #endif // __APPLE__

  if (device_param->is_opencl == true)
  {
    cl_kernel opencl_kernel = NULL;

    switch (kern_run)
    {
      case KERN_RUN_1:      opencl_kernel = device_param->opencl_kernel1;       break;
      case KERN_RUN_12:     opencl_kernel = device_param->opencl_kernel12;      break;
      case KERN_RUN_2P:     opencl_kernel = device_param->opencl_kernel2p;      break;
      case KERN_RUN_2:      opencl_kernel = device_param->opencl_kernel2;       break;
      case KERN_RUN_2E:     opencl_kernel = device_param->opencl_kernel2e;      break;
      case KERN_RUN_23:     opencl_kernel = device_param->opencl_kernel23;      break;
      case KERN_RUN_3:      opencl_kernel = device_param->opencl_kernel3;       break;
      case KERN_RUN_4:      opencl_kernel = device_param->opencl_kernel4;       break;
      case KERN_RUN_INIT2:  opencl_kernel = device_param->opencl_kernel_init2;  break;
      case KERN_RUN_LOOP2P: opencl_kernel = device_param->opencl_kernel_loop2p; break;
      case KERN_RUN_LOOP2:  opencl_kernel = device_param->opencl_kernel_loop2;  break;
      case KERN_RUN_AUX1:   opencl_kernel = device_param->opencl_kernel_aux1;   break;
      case KERN_RUN_AUX2:   opencl_kernel = device_param->opencl_kernel_aux2;   break;
      case KERN_RUN_AUX3:   opencl_kernel = device_param->opencl_kernel_aux3;   break;
      case KERN_RUN_AUX4:   opencl_kernel = device_param->opencl_kernel_aux4;   break;
    }

    for (u32 i = 0; i <= 24; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_mem), device_param->kernel_params[i]) == -1) return -1;
    }

    if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_kernel_param, CL_FALSE, 0, device_param->size_kernel_params, &device_param->kernel_param, 0, NULL, NULL) == -1) return -1;

    /*
    for (u32 i = 24; i <= 34; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_uint), device_param->kernel_params[i]) == -1) return -1;
    }

    for (u32 i = 35; i <= 36; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_ulong), device_param->kernel_params[i]) == -1) return -1;
    }
    */

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_event opencl_event;

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

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &opencl_event) == -1) return -1;

    // spin damper section

    const u32 iterationm = iteration % EXPECTED_ITERATIONS;

    if (device_param->spin_damp > 0)
    {
      cl_int opencl_event_status;

      size_t param_value_size_ret;

      if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

      if (hc_clGetEventInfo (hashcat_ctx, opencl_event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (opencl_event_status), &opencl_event_status, &param_value_size_ret) == -1) return -1;

      double spin_total = device_param->spin_damp;

      while (opencl_event_status != CL_COMPLETE)
      {
        if (status_ctx->devices_status == STATUS_RUNNING)
        {
          switch (kern_run)
          {
            case KERN_RUN_1:      if (device_param->exec_us_prev1[iterationm]       > 0) usleep ((useconds_t) (device_param->exec_us_prev1[iterationm]       * device_param->spin_damp)); break;
            case KERN_RUN_2P:     if (device_param->exec_us_prev2p[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev2p[iterationm]      * device_param->spin_damp)); break;
            case KERN_RUN_2:      if (device_param->exec_us_prev2[iterationm]       > 0) usleep ((useconds_t) (device_param->exec_us_prev2[iterationm]       * device_param->spin_damp)); break;
            case KERN_RUN_2E:     if (device_param->exec_us_prev2e[iterationm]      > 0) usleep ((useconds_t) (device_param->exec_us_prev2e[iterationm]      * device_param->spin_damp)); break;
            case KERN_RUN_3:      if (device_param->exec_us_prev3[iterationm]       > 0) usleep ((useconds_t) (device_param->exec_us_prev3[iterationm]       * device_param->spin_damp)); break;
            case KERN_RUN_4:      if (device_param->exec_us_prev4[iterationm]       > 0) usleep ((useconds_t) (device_param->exec_us_prev4[iterationm]       * device_param->spin_damp)); break;
            case KERN_RUN_INIT2:  if (device_param->exec_us_prev_init2[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_init2[iterationm]  * device_param->spin_damp)); break;
            case KERN_RUN_LOOP2P: if (device_param->exec_us_prev_loop2p[iterationm] > 0) usleep ((useconds_t) (device_param->exec_us_prev_loop2p[iterationm] * device_param->spin_damp)); break;
            case KERN_RUN_LOOP2:  if (device_param->exec_us_prev_loop2[iterationm]  > 0) usleep ((useconds_t) (device_param->exec_us_prev_loop2[iterationm]  * device_param->spin_damp)); break;
            case KERN_RUN_AUX1:   if (device_param->exec_us_prev_aux1[iterationm]   > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux1[iterationm]   * device_param->spin_damp)); break;
            case KERN_RUN_AUX2:   if (device_param->exec_us_prev_aux2[iterationm]   > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux2[iterationm]   * device_param->spin_damp)); break;
            case KERN_RUN_AUX3:   if (device_param->exec_us_prev_aux3[iterationm]   > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux3[iterationm]   * device_param->spin_damp)); break;
            case KERN_RUN_AUX4:   if (device_param->exec_us_prev_aux4[iterationm]   > 0) usleep ((useconds_t) (device_param->exec_us_prev_aux4[iterationm]   * device_param->spin_damp)); break;
          }
        }
        else
        {
          // we were told to be nice

          sleep (0);
        }

        if (hc_clGetEventInfo (hashcat_ctx, opencl_event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (opencl_event_status), &opencl_event_status, &param_value_size_ret) == -1) return -1;

        spin_total += device_param->spin_damp;

        if (spin_total > 1)
        {
          if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;

          break;
        }
      }
    }
    else
    {
      if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;
    }

    cl_ulong time_start;
    cl_ulong time_end;

    if (hc_clGetEventProfilingInfo (hashcat_ctx, opencl_event, CL_PROFILING_COMMAND_START, sizeof (time_start), &time_start, NULL) == -1) return -1;
    if (hc_clGetEventProfilingInfo (hashcat_ctx, opencl_event, CL_PROFILING_COMMAND_END,   sizeof (time_end),   &time_end,   NULL) == -1) return -1;

    const double exec_us = (double) (time_end - time_start) / 1000;

    if (device_param->spin_damp > 0)
    {
      if (status_ctx->devices_status == STATUS_RUNNING)
      {
        switch (kern_run)
        {
          case KERN_RUN_1:      device_param->exec_us_prev1[iterationm]       = exec_us; break;
          case KERN_RUN_2P:     device_param->exec_us_prev2p[iterationm]      = exec_us; break;
          case KERN_RUN_2:      device_param->exec_us_prev2[iterationm]       = exec_us; break;
          case KERN_RUN_2E:     device_param->exec_us_prev2e[iterationm]      = exec_us; break;
          case KERN_RUN_3:      device_param->exec_us_prev3[iterationm]       = exec_us; break;
          case KERN_RUN_4:      device_param->exec_us_prev4[iterationm]       = exec_us; break;
          case KERN_RUN_INIT2:  device_param->exec_us_prev_init2[iterationm]  = exec_us; break;
          case KERN_RUN_LOOP2P: device_param->exec_us_prev_loop2p[iterationm] = exec_us; break;
          case KERN_RUN_LOOP2:  device_param->exec_us_prev_loop2[iterationm]  = exec_us; break;
          case KERN_RUN_AUX1:   device_param->exec_us_prev_aux1[iterationm]   = exec_us; break;
          case KERN_RUN_AUX2:   device_param->exec_us_prev_aux2[iterationm]   = exec_us; break;
          case KERN_RUN_AUX3:   device_param->exec_us_prev_aux3[iterationm]   = exec_us; break;
          case KERN_RUN_AUX4:   device_param->exec_us_prev_aux4[iterationm]   = exec_us; break;
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

    if (hc_clReleaseEvent (hashcat_ctx, opencl_event) == -1) return -1;
  }

  return 0;
}

int run_kernel_mp (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num)
{
  u64 kernel_threads = 0;

  switch (kern_run)
  {
    case KERN_RUN_MP:   kernel_threads  = device_param->kernel_wgs_mp;    break;
    case KERN_RUN_MP_R: kernel_threads  = device_param->kernel_wgs_mp_r;  break;
    case KERN_RUN_MP_L: kernel_threads  = device_param->kernel_wgs_mp_l;  break;
  }

  u64 num_elements = num;

  switch (kern_run)
  {
    case KERN_RUN_MP:   device_param->kernel_params_mp_buf64[8]   = num; break;
    case KERN_RUN_MP_R: device_param->kernel_params_mp_r_buf64[8] = num; break;
    case KERN_RUN_MP_L: device_param->kernel_params_mp_l_buf64[9] = num; break;
  }

  if (device_param->is_cuda == true)
  {
    CUfunction cuda_function = NULL;

    void **cuda_args = NULL;

    switch (kern_run)
    {
      case KERN_RUN_MP:   cuda_function = device_param->cuda_function_mp;
                          cuda_args     = device_param->kernel_params_mp;
                          break;
      case KERN_RUN_MP_R: cuda_function = device_param->cuda_function_mp_r;
                          cuda_args     = device_param->kernel_params_mp_r;
                          break;
      case KERN_RUN_MP_L: cuda_function = device_param->cuda_function_mp_l;
                          cuda_args     = device_param->kernel_params_mp_l;
                          break;
    }

    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, cuda_args, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    hipFunction_t hip_function = NULL;

    void **hip_args = NULL;

    switch (kern_run)
    {
      case KERN_RUN_MP:   hip_function = device_param->hip_function_mp;
                          hip_args     = device_param->kernel_params_mp;
                          break;
      case KERN_RUN_MP_R: hip_function = device_param->hip_function_mp_r;
                          hip_args     = device_param->kernel_params_mp_r;
                          break;
      case KERN_RUN_MP_L: hip_function = device_param->hip_function_mp_l;
                          hip_args     = device_param->kernel_params_mp_l;
                          break;
    }

    num_elements = CEILDIV (num_elements, kernel_threads);

    if (hc_hipLaunchKernel (hashcat_ctx, hip_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, hip_args, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    id metal_command_encoder = NULL;
    id metal_command_buffer  = NULL;
    id metal_pipeline        = NULL;

    switch (kern_run)
    {
      case KERN_RUN_MP:   metal_pipeline = device_param->metal_pipeline_mp;   break;
      case KERN_RUN_MP_R: metal_pipeline = device_param->metal_pipeline_mp_r; break;
      case KERN_RUN_MP_L: metal_pipeline = device_param->metal_pipeline_mp_l; break;
    }

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, metal_pipeline, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    if (kern_run == KERN_RUN_MP)
    {
      for (int i = 0; i < 3; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_mp[i], NULL, 0) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 3, NULL, device_param->kernel_params_mp[3], sizeof (u64)) == -1) return -1;

      for (int i = 4; i < 8; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, NULL, device_param->kernel_params_mp[i], sizeof (u32)) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 8, NULL, device_param->kernel_params_mp[8], sizeof (u64)) == -1) return -1;
    }
    else if (kern_run == KERN_RUN_MP_R)
    {
      for (int i = 0; i < 3; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_mp_r[i], NULL, 0) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 3, NULL, device_param->kernel_params_mp_r[3], sizeof (u64)) == -1) return -1;

      for (int i = 4; i < 8; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, NULL, device_param->kernel_params_mp_r[i], sizeof (u32)) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 8, NULL, device_param->kernel_params_mp_r[8], sizeof (u64)) == -1) return -1;
    }
    else if (kern_run == KERN_RUN_MP_L)
    {
      for (int i = 0; i < 3; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_mp_l[i], NULL, 0) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 3, NULL, device_param->kernel_params_mp_l[3], sizeof (u64)) == -1) return -1;

      for (int i = 4; i < 9; i++)
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, NULL, device_param->kernel_params_mp_l[i], sizeof (u32)) == -1) return -1;
      }

      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 9, NULL, device_param->kernel_params_mp_l[9], sizeof (u64)) == -1) return -1;
    }

    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;
  }
  #endif // __APPLE__

  if (device_param->is_opencl == true)
  {
    cl_kernel opencl_kernel = NULL;

    switch (kern_run)
    {
      case KERN_RUN_MP:   opencl_kernel = device_param->opencl_kernel_mp;   break;
      case KERN_RUN_MP_R: opencl_kernel = device_param->opencl_kernel_mp_r; break;
      case KERN_RUN_MP_L: opencl_kernel = device_param->opencl_kernel_mp_l; break;
    }

    switch (kern_run)
    {
      case KERN_RUN_MP:   if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp[3]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp[4]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp[5]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp[6]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp[7]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 8, sizeof (cl_ulong), device_param->kernel_params_mp[8]) == -1) return -1;
                          break;
      case KERN_RUN_MP_R: if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_r[3]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_r[4]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_r[5]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_r[6]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_r[7]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 8, sizeof (cl_ulong), device_param->kernel_params_mp_r[8]) == -1) return -1;
                          break;
      case KERN_RUN_MP_L: if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 3, sizeof (cl_ulong), device_param->kernel_params_mp_l[3]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 4, sizeof (cl_uint),  device_param->kernel_params_mp_l[4]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 5, sizeof (cl_uint),  device_param->kernel_params_mp_l[5]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_uint),  device_param->kernel_params_mp_l[6]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 7, sizeof (cl_uint),  device_param->kernel_params_mp_l[7]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 8, sizeof (cl_uint),  device_param->kernel_params_mp_l[8]) == -1) return -1;
                          if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 9, sizeof (cl_ulong), device_param->kernel_params_mp_l[9]) == -1) return -1;
                          break;
    }

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int run_kernel_tm (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param)
{
  const u64 num_elements = 1024; // fixed

  const u64 kernel_threads = MIN (num_elements, device_param->kernel_wgs_tm);

  if (device_param->is_cuda == true)
  {
    CUfunction cuda_function = device_param->cuda_function_tm;

    if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements / kernel_threads, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_tm, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    hipFunction_t hip_function = device_param->hip_function_tm;

    if (hc_hipLaunchKernel (hashcat_ctx, hip_function, num_elements / kernel_threads, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_tm, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    id metal_command_encoder = NULL;
    id metal_command_buffer  = NULL;
    id metal_pipeline        = device_param->metal_pipeline_tm;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, metal_pipeline, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    for (int i = 0; i < 2; i++)
    {
      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_tm[i], NULL, 0) == -1) return -1;
    }

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;
  }
  #endif // __APPLE__

  if (device_param->is_opencl == true)
  {
    cl_kernel cuda_kernel = device_param->opencl_kernel_tm;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, cuda_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int run_kernel_amp (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num)
{
  device_param->kernel_params_amp_buf64[6] = num;

  u64 num_elements = num;

  const u64 kernel_threads = device_param->kernel_wgs_amp;

  if (device_param->is_cuda == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    CUfunction cuda_function = device_param->cuda_function_amp;

    if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_amp, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    hipFunction_t hip_function = device_param->hip_function_amp;

    if (hc_hipLaunchKernel (hashcat_ctx, hip_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_amp, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    id metal_command_encoder = NULL;
    id metal_command_buffer  = NULL;
    id metal_pipeline        = device_param->metal_pipeline_amp;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, metal_pipeline, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    // all buffers must be allocated
    int tmp_buf_cnt = 0;

    mtl_mem tmp_buf[5] = { 0 };

    for (int i = 0; i < 5; i++)
    {
      // allocate fake buffer if NULL
      if (device_param->kernel_params_amp[i] == NULL)
      {
        if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, sizeof (u8), NULL, &tmp_buf[tmp_buf_cnt]) == -1) return -1;

        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, tmp_buf[tmp_buf_cnt], NULL, 0) == -1) return -1;

        tmp_buf_cnt++;
      }
      else
      {
        if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_amp[i], NULL, 0) == -1) return -1;
      }
    }

    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 5, NULL, device_param->kernel_params_amp[5], sizeof (u32)) == -1) return -1;
    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 6, NULL, device_param->kernel_params_amp[6], sizeof (u64)) == -1) return -1;

    double ms = 0;

    const int rc_cc = hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms);

    // release tmp_buf

    for (int i = 0; i < tmp_buf_cnt; i++)
    {
      hc_mtlReleaseMemObject (hashcat_ctx, tmp_buf[i]);

      tmp_buf[i] = NULL;
    }

    if (rc_cc == -1) return -1;
  }
  #endif // __APPLE__

  if (device_param->is_opencl == true)
  {
    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_kernel opencl_kernel = device_param->opencl_kernel_amp;

    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_ulong), device_param->kernel_params_amp[6]) == -1) return -1;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int run_kernel_decompress (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num)
{
  device_param->kernel_params_decompress_buf64[3] = num;

  u64 num_elements = num;

  const u64 kernel_threads = device_param->kernel_wgs_decompress;

  if (device_param->is_cuda == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    CUfunction cuda_function = device_param->cuda_function_decompress;

    if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_decompress, NULL) == -1) return -1;
  }

  if (device_param->is_hip == true)
  {
    num_elements = CEILDIV (num_elements, kernel_threads);

    hipFunction_t hip_function = device_param->hip_function_decompress;

    if (hc_hipLaunchKernel (hashcat_ctx, hip_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->hip_stream, device_param->kernel_params_decompress, NULL) == -1) return -1;
  }

  #if defined (__APPLE__)
  if (device_param->is_metal == true)
  {
    num_elements = round_up_multiple_32 (num_elements, kernel_threads);

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    id metal_command_buffer  = NULL;
    id metal_command_encoder = NULL;

    if (hc_mtlEncodeComputeCommand_pre (hashcat_ctx, device_param->metal_pipeline_decompress, device_param->metal_command_queue, &metal_command_buffer, &metal_command_encoder) == -1) return -1;

    for (int i = 0; i < 3; i++)
    {
      if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, i, device_param->kernel_params_decompress[i], NULL, 0) == -1) return -1;
    }

    if (hc_mtlSetCommandEncoderArg (hashcat_ctx, metal_command_encoder, 0, 3, NULL, device_param->kernel_params_decompress[3], sizeof (u64)) == -1) return -1;

    double ms = 0;

    if (hc_mtlEncodeComputeCommand (hashcat_ctx, metal_command_encoder, metal_command_buffer, global_work_size[0], local_work_size[0], &ms) == -1) return -1;
  }
  #endif // __APPLE__

  if (device_param->is_opencl == true)
  {
    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_kernel opencl_kernel = device_param->opencl_kernel_decompress;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]) == -1) return -1;

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
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
    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->cuda_stream) == -1) return -1;
      }
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->hip_stream) == -1) return -1;
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_idx, 0, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_comp_buf, 0, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
      }
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_FALSE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_FALSE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
      }
    }

    if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
  }
  else
  {
    if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->cuda_stream) == -1) return -1;
        }
      }

      if (device_param->is_hip == true)
      {
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->hip_stream) == -1) return -1;
        }
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_idx, 0, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_comp_buf, 0, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
        }
      }
      #endif

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_FALSE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_FALSE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
        }
      }

      if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
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

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->cuda_stream) == -1) return -1;
          }
        }

        if (device_param->is_hip == true)
        {
          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->hip_stream) == -1) return -1;
          }
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_idx, 0, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_comp_buf, 0, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
          }
        }
        #endif

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_FALSE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_FALSE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
          }
        }

        if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_COMBI)
        {
          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->cuda_stream) == -1) return -1;
            }
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->hip_stream) == -1) return -1;
            }
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_idx, 0, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_comp_buf, 0, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
            }
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_FALSE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_FALSE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
            }
          }

          if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->cuda_stream) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->cuda_stream) == -1) return -1;
            }
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t), device_param->hip_stream) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32), device_param->hip_stream) == -1) return -1;
            }
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_idx, 0, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_pws_comp_buf, 0, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
            }
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_FALSE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_FALSE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
            }
          }

          if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          const u64 off = device_param->words_off;

          device_param->kernel_params_mp_buf64[3] = off;

          if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, pws_cnt) == -1) return -1;
        }
      }
    }
    else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
    {
      const u64 off = device_param->words_off;

      device_param->kernel_params_mp_l_buf64[3] = off;

      if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP_L, pws_cnt) == -1) return -1;
    }
  }

  if (device_param->is_opencl == true)
  {
    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  return 0;
}

int run_cracker (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_pos, const u64 pws_cnt)
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

  char iconv_tmp[HCBUFSIZ_TINY] = { 0 };

  if (strcmp (user_options->encoding_from, user_options->encoding_to) != 0)
  {
    iconv_enabled = true;

    iconv_ctx = iconv_open (user_options->encoding_to, user_options->encoding_from);

    if (iconv_ctx == (iconv_t) -1) return -1;
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

  // we ignore the time to copy data over pci bus in this case

  if (user_options->speed_only == true)
  {
    hc_timer_set (&device_param->timer_speed);
  }

  // loop start: most outer loop = salt iteration, then innerloops (if multi)

  u32 salts_cnt = hashes->salts_cnt;

  if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
  {
    // We will replace in-kernel salt_pos with GID via macro

    salts_cnt = 1;
  }

  for (u32 salt_pos = 0; salt_pos < salts_cnt; salt_pos++)
  {
    while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    device_param->kernel_param.salt_pos_host       = salt_pos;
    device_param->kernel_param.digests_cnt         = salt_buf->digests_cnt;
    device_param->kernel_param.digests_offset_host = salt_buf->digests_offset;

    HCFILE *combs_fp = &device_param->combs_fp;

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if ((user_options->attack_mode == ATTACK_MODE_COMBI) || (((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0) && (user_options->attack_mode == ATTACK_MODE_HYBRID2)))
      {
        hc_rewind (combs_fp);
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
      // sanity check: do NOT cast to an u32 integer type without checking that it is safe (upper bits must NOT be set)

      if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
      {
        if ((combinator_ctx->combs_cnt >> 32) != 0) return -1;
      }
      else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
      {
        if ((mask_ctx->bfs_cnt >> 32) != 0) return -1;
      }

      if   (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) innerloop_step = device_param->kernel_loops;
      else                                                        innerloop_step = 1;

      if      (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)  innerloop_cnt = straight_ctx->kernel_rules_cnt;
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

      device_param->kernel_param.il_cnt = innerloop_left;

      device_param->outerloop_multi = (double) innerloop_cnt / (double) (innerloop_pos + innerloop_left);

      hc_thread_mutex_unlock (status_ctx->mux_display);

      if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
      {
        // does not exist here
      }
      else
      {
        if (hashes->salts_shown[salt_pos] == 1)
        {
          status_ctx->words_progress_done[salt_pos] += pws_cnt * innerloop_left;

          continue;
        }
      }

      // initialize and copy amplifiers

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_rules_c, device_param->cuda_d_rules + (innerloop_pos * sizeof (kernel_rule_t)), innerloop_left * sizeof (kernel_rule_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_rules_c, device_param->hip_d_rules + (innerloop_pos * sizeof (kernel_rule_t)), innerloop_left * sizeof (kernel_rule_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_rules_c, 0, device_param->metal_d_rules, innerloop_pos * sizeof (kernel_rule_t), innerloop_left * sizeof (kernel_rule_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_rules, device_param->opencl_d_rules_c, innerloop_pos * sizeof (kernel_rule_t), 0, innerloop_left * sizeof (kernel_rule_t), 0, NULL, NULL) == -1) return -1;
          }
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
                if (hc_feof (combs_fp)) break;

                size_t line_len = fgetl (combs_fp, line_buf, HCBUFSIZ_LARGE);

                line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

                if (line_len > PW_MAX) continue;

                char *line_buf_new = line_buf;

                char rule_buf_out[RP_PASSWORD_SIZE];

                if (run_rule_engine (user_options_extra->rule_len_r, user_options->rule_buf_r))
                {
                  if (line_len >= RP_PASSWORD_SIZE) continue;

                  memset (rule_buf_out, 0, sizeof (rule_buf_out));

                  const int rule_len_out = _old_apply_rule (user_options->rule_buf_r, user_options_extra->rule_len_r, line_buf, (u32) line_len, rule_buf_out);

                  if (rule_len_out < 0)
                  {
                    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
                    {
                      for (u32 association_salt_pos = 0; association_salt_pos < pws_cnt; association_salt_pos++)
                      {
                        status_ctx->words_progress_rejected[association_salt_pos] += 1;
                      }
                    }
                    else
                    {
                      status_ctx->words_progress_rejected[salt_pos] += pws_cnt;
                    }

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

                  if (iconv (iconv_ctx, &line_buf_new, &line_len, &iconv_ptr, &iconv_sz) == (size_t) -1) continue;

                  line_buf_new = iconv_tmp;
                  line_len     = HCBUFSIZ_TINY - iconv_sz;
                }

                line_len = MIN (line_len, PW_MAX);

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

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, device_param->combs_buf, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_FALSE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL) == -1) return -1;
              }
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left) == -1) return -1;

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, device_param->hip_d_combs, innerloop_left * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, device_param->metal_d_combs, 0, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs, device_param->opencl_d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL) == -1) return -1;
              }
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left) == -1) return -1;

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, device_param->hip_d_combs, innerloop_left * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, device_param->metal_d_combs, 0, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs, device_param->opencl_d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL) == -1) return -1;
              }
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
                if (hc_feof (combs_fp)) break;

                size_t line_len = fgetl (combs_fp, line_buf, HCBUFSIZ_LARGE);

                line_len = convert_from_hex (hashcat_ctx, line_buf, line_len);

                if (line_len > PW_MAX) continue;

                char *line_buf_new = line_buf;

                char rule_buf_out[RP_PASSWORD_SIZE];

                if (run_rule_engine (user_options_extra->rule_len_r, user_options->rule_buf_r))
                {
                  if (line_len >= RP_PASSWORD_SIZE) continue;

                  memset (rule_buf_out, 0, sizeof (rule_buf_out));

                  const int rule_len_out = _old_apply_rule (user_options->rule_buf_r, user_options_extra->rule_len_r, line_buf, (u32) line_len, rule_buf_out);

                  if (rule_len_out < 0)
                  {
                    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
                    {
                      for (u32 association_salt_pos = 0; association_salt_pos < pws_cnt; association_salt_pos++)
                      {
                        status_ctx->words_progress_rejected[association_salt_pos] += 1;
                      }
                    }
                    else
                    {
                      status_ctx->words_progress_rejected[salt_pos] += pws_cnt;
                    }

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

                  if (iconv (iconv_ctx, &line_buf_new, &line_len, &iconv_ptr, &iconv_sz) == (size_t) -1) continue;

                  line_buf_new = iconv_tmp;
                  line_len     = HCBUFSIZ_TINY - iconv_sz;
                }

                line_len = MIN (line_len, PW_MAX);

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

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, device_param->combs_buf, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_FALSE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL) == -1) return -1;
              }
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left) == -1) return -1;

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t), device_param->cuda_stream) == -1) return -1;
              }

              if (device_param->is_hip == true)
              {
                if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_combs_c, device_param->hip_d_combs, innerloop_left * sizeof (pw_t), device_param->hip_stream) == -1) return -1;
              }

              #if defined (__APPLE__)
              if (device_param->is_metal == true)
              {
                if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_combs_c, 0, device_param->metal_d_combs, 0, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }
              #endif

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs, device_param->opencl_d_combs_c, 0, 0, innerloop_left * sizeof (pw_t), 0, NULL, NULL) == -1) return -1;
              }
            }
          }
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          u64 off = innerloop_pos;

          device_param->kernel_params_mp_r_buf64[3] = off;

          if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP_R, innerloop_left) == -1) return -1;

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoDAsync (hashcat_ctx, device_param->cuda_d_bfs_c, device_param->cuda_d_bfs, innerloop_left * sizeof (bf_t), device_param->cuda_stream) == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            if (hc_hipMemcpyDtoDAsync (hashcat_ctx, device_param->hip_d_bfs_c, device_param->hip_d_bfs, innerloop_left * sizeof (bf_t), device_param->hip_stream) == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            if (hc_mtlMemcpyDtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bfs_c, 0, device_param->metal_d_bfs, 0, innerloop_left * sizeof (bf_t)) == -1) return -1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bfs, device_param->opencl_d_bfs_c, 0, 0, innerloop_left * sizeof (bf_t), 0, NULL, NULL) == -1) return -1;
          }
        }
      }

      if (choose_kernel (hashcat_ctx, device_param, highest_pw_len, pws_pos, pws_cnt, fast_iteration, salt_pos) == -1) return -1;

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
          const u64 perf_sum_all = pws_cnt * innerloop_left;

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

          if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
          {
            for (u32 association_salt_pos = 0; association_salt_pos < pws_cnt; association_salt_pos++)
            {
              status_ctx->words_progress_done[pws_pos + association_salt_pos] += innerloop_left;
            }
          }
          else
          {
            status_ctx->words_progress_done[salt_pos] += perf_sum_all;
          }

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
          // it's unclear if 4s is enough to turn on boost mode for all backend device

          if ((total_msec > 4000) || (device_param->speed_pos == SPEED_CACHE - 1))
          {
            device_param->speed_only_finish = true;

            break;
          }
        }
      }

      if (device_param->speed_only_finish == true) break;

      /**
       * result
       */

      check_cracked (hashcat_ctx, device_param);

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

    device_param->speed_only_finish = true;
  }

  if (iconv_enabled == true)
  {
    iconv_close (iconv_ctx);
  }

  return 0;
}

int backend_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  backend_ctx->enabled = false;

  if (user_options->hash_info == true) return 0;
  if (user_options->keyspace  == true) return 0;
  if (user_options->left      == true) return 0;
  if (user_options->show      == true) return 0;
  if (user_options->usage     == true) return 0;
  if (user_options->version   == true) return 0;
  if (user_options->identify  == true) return 0;

  hc_device_param_t *devices_param = (hc_device_param_t *) hccalloc (DEVICES_MAX, sizeof (hc_device_param_t));

  backend_ctx->devices_param = devices_param;

  /**
   * Load and map CUDA library calls, then init CUDA
   */

  int rc_cuda_init = -1;

  if (user_options->backend_ignore_cuda == false)
  {
    CUDA_PTR *cuda = (CUDA_PTR *) hcmalloc (sizeof (CUDA_PTR));

    backend_ctx->cuda = cuda;

    rc_cuda_init = cuda_init (hashcat_ctx);

    if (rc_cuda_init == -1)
    {
      backend_ctx->rc_cuda_init = rc_cuda_init;

      cuda_close (hashcat_ctx);
    }

    /**
     * Load and map NVRTC library calls
     */

    NVRTC_PTR *nvrtc = (NVRTC_PTR *) hcmalloc (sizeof (NVRTC_PTR));

    backend_ctx->nvrtc = nvrtc;

    int rc_nvrtc_init = nvrtc_init (hashcat_ctx);

    if (rc_nvrtc_init == -1)
    {
      backend_ctx->rc_nvrtc_init = rc_nvrtc_init;

      nvrtc_close (hashcat_ctx);
    }

    /**
     * Check if both CUDA and NVRTC were load successful
     */

    if ((rc_cuda_init == 0) && (rc_nvrtc_init == 0))
    {
      // nvrtc version

      int nvrtc_major = 0;
      int nvrtc_minor = 0;

      if (hc_nvrtcVersion (hashcat_ctx, &nvrtc_major, &nvrtc_minor) == -1) return -1;

      int nvrtc_driver_version = (nvrtc_major * 1000) + (nvrtc_minor * 10);

      backend_ctx->nvrtc_driver_version = nvrtc_driver_version;

      if (nvrtc_driver_version < 9000)
      {
        event_log_error (hashcat_ctx, "Outdated NVIDIA NVRTC driver version '%d' detected!", nvrtc_driver_version);

        event_log_warning (hashcat_ctx, "See hashcat.net for officially supported NVIDIA CUDA Toolkit versions.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }

      // cuda version

      int cuda_driver_version = 0;

      if (hc_cuDriverGetVersion (hashcat_ctx, &cuda_driver_version) == -1) return -1;

      backend_ctx->cuda_driver_version = cuda_driver_version;

      if (cuda_driver_version < 9000)
      {
        event_log_error (hashcat_ctx, "Outdated NVIDIA CUDA driver version '%d' detected!", cuda_driver_version);

        event_log_warning (hashcat_ctx, "See hashcat.net for officially supported NVIDIA CUDA Toolkit versions.");
        event_log_warning (hashcat_ctx, NULL);

        return -1;
      }
    }
    else
    {
      rc_cuda_init  = -1;
      rc_nvrtc_init = -1;

      cuda_close  (hashcat_ctx);
      nvrtc_close (hashcat_ctx);
    }
  }

  /**
   * Load and map HIP library calls, then init HIP
   */

  int rc_hip_init = -1;

  if (user_options->backend_ignore_hip == false)
  {
    HIP_PTR *hip = (HIP_PTR *) hcmalloc (sizeof (HIP_PTR));

    backend_ctx->hip = hip;

    rc_hip_init = hip_init (hashcat_ctx);

    if (rc_hip_init == -1)
    {
      backend_ctx->rc_hip_init = rc_hip_init;

      hip_close (hashcat_ctx);
    }

    /**
     * Load and map HIPRTC library calls
     */

    HIPRTC_PTR *hiprtc = (HIPRTC_PTR *) hcmalloc (sizeof (HIPRTC_PTR));

    backend_ctx->hiprtc = hiprtc;

    int rc_hiprtc_init = hiprtc_init (hashcat_ctx);

    if (rc_hiprtc_init == -1)
    {
      backend_ctx->rc_hiprtc_init = rc_hiprtc_init;

      hiprtc_close (hashcat_ctx);
    }

    /**
     * Check if both HIP and HIPRTC were load successful
     */

    if ((rc_hip_init == 0) && (rc_hiprtc_init == 0))
    {
      // hip version

      int hip_driverVersion;

      if (hc_hipDriverGetVersion (hashcat_ctx, &hip_driverVersion) == -1) return -1;

      backend_ctx->hip_driverVersion = hip_driverVersion;

      int hip_runtimeVersion;

      if (hc_hipRuntimeGetVersion (hashcat_ctx, &hip_runtimeVersion) == -1) return -1;

      backend_ctx->hip_runtimeVersion = hip_runtimeVersion;

      #if defined (_WIN)
      // 404 is ok
      if (hip_runtimeVersion < 404)
      {
        event_log_warning (hashcat_ctx, "Unsupported AMD HIP runtime version '%d.%d' detected! Falling back to OpenCL...", hip_runtimeVersion / 100, hip_runtimeVersion % 10);
        event_log_warning (hashcat_ctx, NULL);

        rc_hip_init    = -1;
        rc_hiprtc_init = -1;

        backend_ctx->rc_hip_init    = rc_hip_init;
        backend_ctx->rc_hiprtc_init = rc_hiprtc_init;

        backend_ctx->hip    = NULL;
        backend_ctx->hiprtc = NULL;

        backend_ctx->hip = NULL;

        // if we call this, opencl stops working?! so we just zero the pointer
        // this causes a memleak and an open filehandle but what can we do?
        // hip_close    (hashcat_ctx);
        // hiprtc_close (hashcat_ctx);
      }
      #else
      // 500 is ok
      if (hip_runtimeVersion < 50013601)
      {
        int hip_version_major = (hip_runtimeVersion - 0) / 10000000;
        int hip_version_minor = (hip_runtimeVersion - (hip_version_major * 10000000)) / 100000;
        int hip_version_patch = (hip_runtimeVersion - (hip_version_major * 10000000) - (hip_version_minor * 100000));

        event_log_warning (hashcat_ctx, "Unsupported AMD HIP runtime version '%d.%d.%d' detected! Falling back to OpenCL...", hip_version_major, hip_version_minor, hip_version_patch);
        event_log_warning (hashcat_ctx, NULL);

        rc_hip_init    = -1;
        rc_hiprtc_init = -1;

        backend_ctx->rc_hip_init    = rc_hip_init;
        backend_ctx->rc_hiprtc_init = rc_hiprtc_init;

        backend_ctx->hip = NULL;

        // if we call this, opencl stops working?! so we just zero the pointer
        // this causes a memleak and an open filehandle but what can we do?
        // hip_close    (hashcat_ctx);
        // hiprtc_close (hashcat_ctx);
      }
      #endif
    }
    else
    {
      rc_hip_init    = -1;
      rc_hiprtc_init = -1;

      backend_ctx->rc_hip_init    = rc_hip_init;
      backend_ctx->rc_hiprtc_init = rc_hiprtc_init;

      backend_ctx->hip = NULL;

      // if we call this, opencl stops working?! so we just zero the pointer
      // this causes a memleak and an open filehandle but what can we do?
      // hip_close    (hashcat_ctx);
      // hiprtc_close (hashcat_ctx);
    }
  }

  /**
   * Init Metal runtime
   */

  int rc_metal_init = -1;

  #if defined (__APPLE__)
  if (user_options->backend_ignore_metal == false)
  {
    MTL_PTR *mtl = (MTL_PTR *) hcmalloc (sizeof (MTL_PTR));

    backend_ctx->mtl = mtl;

    rc_metal_init = mtl_init (hashcat_ctx);

    if (rc_metal_init == 0)
    {
      size_t version_len = 0;

      if (hc_mtlRuntimeGetVersionString (hashcat_ctx, NULL, &version_len) == -1) return -1;

      if (version_len == 0) return -1;

      backend_ctx->metal_runtimeVersionStr = (char *) hcmalloc (version_len + 1);

      if (hc_mtlRuntimeGetVersionString (hashcat_ctx, backend_ctx->metal_runtimeVersionStr, &version_len) == -1) return -1;

      // TODO: needs version check
    }
    else
    {
      rc_metal_init = -1;

      backend_ctx->rc_metal_init = rc_metal_init;

      mtl_close (hashcat_ctx);
    }
  }
  #endif // __APPLE__

  /**
   * Load and map OpenCL library calls
   */

  int rc_ocl_init = -1;

  if (user_options->backend_ignore_opencl == false)
  {
    OCL_PTR *ocl = (OCL_PTR *) hcmalloc (sizeof (OCL_PTR));

    backend_ctx->ocl = ocl;

    rc_ocl_init = ocl_init (hashcat_ctx);

    if (rc_ocl_init == -1)
    {
      ocl_close (hashcat_ctx);
    }

    /**
     * return if both CUDA and OpenCL initialization failed
     */

    if ((rc_cuda_init == -1) && (rc_hip_init == -1) && (rc_ocl_init == -1) && (rc_metal_init == -1))
    {
      event_log_error (hashcat_ctx, "ATTENTION! No OpenCL, Metal, HIP or CUDA installation found.");

      event_log_warning (hashcat_ctx, "You are probably missing the CUDA, HIP or OpenCL runtime installation.");
      event_log_warning (hashcat_ctx, NULL);

      #if defined (__linux__)
      event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this driver:");
      event_log_warning (hashcat_ctx, "  \"AMDGPU\" (21.50 or later) and \"ROCm\" (5.0 or later)");
      #elif defined (_WIN)
      event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this driver:");
      event_log_warning (hashcat_ctx, "  \"AMD Adrenalin Edition\" (Adrenalin 22.5.1 exactly)");
      #endif

      event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime:");
      event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

      event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver (both):");
      event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (440.64 or later)");
      event_log_warning (hashcat_ctx, "  \"CUDA Toolkit\" (9.0 or later)");
      event_log_warning (hashcat_ctx, NULL);

      return -1;
    }

    /**
     * Some permission pre-check, because AMDGPU-PRO Driver crashes if the user has no permission to do this
     */

    if (ocl_check_dri (hashcat_ctx) == -1) return -1;
  }

  /**
   * Backend device selection
   */

  u64 backend_devices_filter;

  if (setup_backend_devices_filter (hashcat_ctx, user_options->backend_devices, &backend_devices_filter) == false) return -1;

  backend_ctx->backend_devices_filter = backend_devices_filter;

  /**
   * OpenCL device type selection
   */

  cl_device_type opencl_device_types_filter;

  if (setup_opencl_device_types_filter (hashcat_ctx, user_options->opencl_device_types, &opencl_device_types_filter) == false) return -1;

  backend_ctx->opencl_device_types_filter = opencl_device_types_filter;

  /**
   * CUDA API: init
   */

  if (backend_ctx->cuda)
  {
    if (hc_cuInit (hashcat_ctx, 0) == -1)
    {
      cuda_close (hashcat_ctx);
    }
  }

  /**
   * HIP API: init
   */

  if (backend_ctx->hip)
  {
    if (hc_hipInit (hashcat_ctx, 0) == -1)
    {
      hip_close (hashcat_ctx);
    }
  }

  /**
   * OpenCL API: init
   */

  if (backend_ctx->ocl)
  {
    #define FREE_OPENCL_CTX_ON_ERROR          \
    do {                                      \
      hcfree (opencl_platforms);              \
      hcfree (opencl_platforms_devices);      \
      hcfree (opencl_platforms_devices_cnt);  \
      hcfree (opencl_platforms_name);         \
      hcfree (opencl_platforms_vendor);       \
      hcfree (opencl_platforms_vendor_id);    \
      hcfree (opencl_platforms_version);      \
    } while (0)

    cl_platform_id *opencl_platforms             = (cl_platform_id *) hccalloc (CL_PLATFORMS_MAX, sizeof (cl_platform_id));
    cl_uint         opencl_platforms_cnt         = 0;
    cl_device_id  **opencl_platforms_devices     = (cl_device_id **)  hccalloc (CL_PLATFORMS_MAX, sizeof (cl_device_id *));
    cl_uint        *opencl_platforms_devices_cnt = (cl_uint *)        hccalloc (CL_PLATFORMS_MAX, sizeof (cl_uint));
    char          **opencl_platforms_name        = (char **)          hccalloc (CL_PLATFORMS_MAX, sizeof (char *));
    char          **opencl_platforms_vendor      = (char **)          hccalloc (CL_PLATFORMS_MAX, sizeof (char *));
    cl_uint        *opencl_platforms_vendor_id   = (cl_uint *)        hccalloc (CL_PLATFORMS_MAX, sizeof (cl_uint));
    char          **opencl_platforms_version     = (char **)          hccalloc (CL_PLATFORMS_MAX, sizeof (char *));

    if (hc_clGetPlatformIDs (hashcat_ctx, CL_PLATFORMS_MAX, opencl_platforms, &opencl_platforms_cnt) == -1)
    {
      opencl_platforms_cnt = 0;

      FREE_OPENCL_CTX_ON_ERROR;

      ocl_close (hashcat_ctx);
    }

    if (opencl_platforms_cnt > 0)
    {
      for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
      {
        opencl_platforms_name[opencl_platforms_idx]        = "N/A";
        opencl_platforms_vendor[opencl_platforms_idx]      = "N/A";
        opencl_platforms_version[opencl_platforms_idx]     = "N/A";
        opencl_platforms_devices[opencl_platforms_idx]     = NULL;
        opencl_platforms_vendor_id[opencl_platforms_idx]   = 0;
        opencl_platforms_devices_cnt[opencl_platforms_idx] = 0;

        cl_platform_id opencl_platform = opencl_platforms[opencl_platforms_idx];

        size_t param_value_size = 0;

        // platform vendor

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VENDOR, 0, NULL, &param_value_size) == -1) continue;

        char *opencl_platform_vendor = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VENDOR, param_value_size, opencl_platform_vendor, NULL) == -1)
        {
          hcfree (opencl_platform_vendor);

          continue;
        }

        opencl_platforms_vendor[opencl_platforms_idx] = opencl_platform_vendor;

        // platform name

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_NAME, 0, NULL, &param_value_size) == -1) continue;

        char *opencl_platform_name = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_NAME, param_value_size, opencl_platform_name, NULL) == -1)
        {
          hcfree (opencl_platform_name);

          continue;
        }

        opencl_platforms_name[opencl_platforms_idx] = opencl_platform_name;

        // platform version

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VERSION, 0, NULL, &param_value_size) == -1) continue;

        char *opencl_platform_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VERSION, param_value_size, opencl_platform_version, NULL) == -1)
        {
          hcfree (opencl_platform_version);

          continue;
        }

        opencl_platforms_version[opencl_platforms_idx] = opencl_platform_version;

        // find our own platform vendor because pocl and mesa are pushing original vendor_id through opencl
        // this causes trouble with vendor id based macros
        // we'll assign generic to those without special optimization available

        cl_uint opencl_platform_vendor_id = 0;

        if (strcmp (opencl_platform_vendor, CL_VENDOR_AMD1) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_AMD2) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_AMD_USE_INTEL;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_APPLE) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_APPLE;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_INTEL_BEIGNET;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_INTEL_SDK) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_INTEL_SDK;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_MESA) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_MESA;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_NV) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_NV;
        }
        else if (strcmp (opencl_platform_vendor, CL_VENDOR_POCL) == 0)
        {
          opencl_platform_vendor_id = VENDOR_ID_POCL;
        }
        else
        {
          opencl_platform_vendor_id = VENDOR_ID_GENERIC;
        }

        opencl_platforms_vendor_id[opencl_platforms_idx] = opencl_platform_vendor_id;

        cl_device_id *opencl_platform_devices = (cl_device_id *) hccalloc (DEVICES_MAX, sizeof (cl_device_id));

        cl_uint opencl_platform_devices_cnt = 0;

        const int CL_rc = hc_clGetDeviceIDs (hashcat_ctx, opencl_platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, opencl_platform_devices, &opencl_platform_devices_cnt);

        if (CL_rc == -1)
        {
          // Special handling for CL_DEVICE_NOT_FOUND, see: https://github.com/hashcat/hashcat/issues/2455

          #define IGNORE_DEVICE_NOT_FOUND 1

          if (IGNORE_DEVICE_NOT_FOUND)
          {
            //backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

            OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

            const cl_int CL_err = ocl->clGetDeviceIDs (opencl_platform, CL_DEVICE_TYPE_ALL, DEVICES_MAX, opencl_platform_devices, &opencl_platform_devices_cnt);

            if (CL_err == CL_DEVICE_NOT_FOUND && opencl_platform_devices_cnt > 0)
            {
              // we ignore this error
            }
            else
            {
              hcfree (opencl_platform_devices);

              continue;
            }
          }
          else
          {
            hcfree (opencl_platform_devices);

            continue;
          }
        }

        opencl_platforms_devices[opencl_platforms_idx]     = opencl_platform_devices;
        opencl_platforms_devices_cnt[opencl_platforms_idx] = opencl_platform_devices_cnt;
      }

      if (user_options->opencl_device_types == NULL)
      {
        /**
         * OpenCL device types:
         *   In case the user did not specify --opencl-device-types and the user runs hashcat in a system with only a CPU only he probably want to use that CPU.
         */

        cl_device_type opencl_device_types_all = 0;

        for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
        {
          cl_device_id *opencl_platform_devices     = opencl_platforms_devices[opencl_platforms_idx];
          cl_uint       opencl_platform_devices_cnt = opencl_platforms_devices_cnt[opencl_platforms_idx];

          for (u32 opencl_platform_devices_idx = 0; opencl_platform_devices_idx < opencl_platform_devices_cnt; opencl_platform_devices_idx++)
          {
            cl_device_id opencl_device = opencl_platform_devices[opencl_platform_devices_idx];

            cl_device_type opencl_device_type;

            if (hc_clGetDeviceInfo (hashcat_ctx, opencl_device, CL_DEVICE_TYPE, sizeof (opencl_device_type), &opencl_device_type, NULL) == -1)
            {
              FREE_OPENCL_CTX_ON_ERROR;

              return -1;
            }

            opencl_device_types_all |= opencl_device_type;
          }
        }

        // In such a case, automatically enable CPU device type support, since it's disabled by default.

        if ((opencl_device_types_all & (CL_DEVICE_TYPE_GPU | CL_DEVICE_TYPE_ACCELERATOR)) == 0)
        {
          opencl_device_types_filter |= CL_DEVICE_TYPE_CPU;
        }

        // In another case, when the user uses --stdout, using CPU devices is much faster to setup
        // If we have a CPU device, force it to be used

        if (user_options->stdout_flag == true)
        {
          if (opencl_device_types_all & CL_DEVICE_TYPE_CPU)
          {
            opencl_device_types_filter = CL_DEVICE_TYPE_CPU;
          }
        }

        backend_ctx->opencl_device_types_filter = opencl_device_types_filter;
      }
    }

    backend_ctx->opencl_platforms             = opencl_platforms;
    backend_ctx->opencl_platforms_cnt         = opencl_platforms_cnt;
    backend_ctx->opencl_platforms_devices     = opencl_platforms_devices;
    backend_ctx->opencl_platforms_devices_cnt = opencl_platforms_devices_cnt;
    backend_ctx->opencl_platforms_name        = opencl_platforms_name;
    backend_ctx->opencl_platforms_vendor      = opencl_platforms_vendor;
    backend_ctx->opencl_platforms_vendor_id   = opencl_platforms_vendor_id;
    backend_ctx->opencl_platforms_version     = opencl_platforms_version;

    #undef FREE_OPENCL_CTX_ON_ERROR
  }

  /**
   * Final checks
   */

  if ((backend_ctx->cuda == NULL) && (backend_ctx->hip == NULL) && (backend_ctx->ocl == NULL) && (backend_ctx->mtl == NULL))
  {
    #if defined (__APPLE__)
    event_log_error (hashcat_ctx, "ATTENTION! No OpenCL, Metal, HIP or CUDA compatible platform found.");
    #else
    event_log_error (hashcat_ctx, "ATTENTION! No OpenCL, HIP or CUDA compatible platform found.");
    #endif

    event_log_warning (hashcat_ctx, "You are probably missing the OpenCL, CUDA or HIP runtime installation.");
    event_log_warning (hashcat_ctx, NULL);

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this driver:");
    event_log_warning (hashcat_ctx, "  \"AMDGPU\" (21.50 or later) and \"ROCm\" (5.0 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this driver:");
    event_log_warning (hashcat_ctx, "  \"AMD Adrenalin Edition\" (Adrenalin 22.5.1 exactly)");
    #endif

    event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

    event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver (both):");
    event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (440.64 or later)");
    event_log_warning (hashcat_ctx, "  \"CUDA Toolkit\" (9.0 or later)");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  backend_ctx->enabled = true;

  return 0;
}

void backend_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return;

  hcfree (backend_ctx->devices_param);

  if (backend_ctx->ocl)
  {
    hcfree (backend_ctx->opencl_platforms);
    hcfree (backend_ctx->opencl_platforms_devices);
    hcfree (backend_ctx->opencl_platforms_devices_cnt);
    hcfree (backend_ctx->opencl_platforms_name);
    hcfree (backend_ctx->opencl_platforms_vendor);
    hcfree (backend_ctx->opencl_platforms_vendor_id);
    hcfree (backend_ctx->opencl_platforms_version);
  }

  nvrtc_close  (hashcat_ctx);
  hiprtc_close (hashcat_ctx);

  cuda_close   (hashcat_ctx);
  hip_close    (hashcat_ctx);
  ocl_close    (hashcat_ctx);

  memset (backend_ctx, 0, sizeof (backend_ctx_t));
}

int backend_ctx_devices_init (hashcat_ctx_t *hashcat_ctx, const int comptime)
{
  const folder_config_t *folder_config = hashcat_ctx->folder_config;
        backend_ctx_t   *backend_ctx   = hashcat_ctx->backend_ctx;
        user_options_t  *user_options  = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *devices_param = backend_ctx->devices_param;

  bool need_adl           = false;
  bool need_nvml          = false;
  bool need_nvapi         = false;
  bool need_sysfs_amdgpu  = false;
  bool need_sysfs_cpu     = false;
  bool need_iokit         = false;

  int backend_devices_idx = 0;

  // CUDA

  int cuda_devices_cnt    = 0;
  int cuda_devices_active = 0;

  if (backend_ctx->cuda)
  {
    // device count

    if (hc_cuDeviceGetCount (hashcat_ctx, &cuda_devices_cnt) == -1)
    {
      cuda_close (hashcat_ctx);
    }

    backend_ctx->cuda_devices_cnt = cuda_devices_cnt;

    // device specific

    for (int cuda_devices_idx = 0; cuda_devices_idx < cuda_devices_cnt; cuda_devices_idx++, backend_devices_idx++)
    {
      const u32 device_id = backend_devices_idx;

      hc_device_param_t *device_param = &devices_param[backend_devices_idx];

      device_param->device_id = device_id;

      backend_ctx->backend_device_from_cuda[cuda_devices_idx] = backend_devices_idx;

      CUdevice cuda_device;

      if (hc_cuDeviceGet (hashcat_ctx, &cuda_device, cuda_devices_idx) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->cuda_device = cuda_device;

      device_param->is_cuda   = true;
      device_param->is_hip    = false;
      device_param->is_metal  = false;
      device_param->is_opencl = false;

      device_param->use_opencl12 = false;
      device_param->use_opencl20 = false;
      device_param->use_opencl21 = false;

      // device_name

      char *device_name = (char *) hcmalloc (HCBUFSIZ_TINY);

      if (hc_cuDeviceGetName (hashcat_ctx, device_name, HCBUFSIZ_TINY, cuda_device) == -1)
      {
        device_param->skipped = true;
        hcfree (device_name);
        continue;
      }

      device_param->device_name = device_name;

      hc_string_trim_leading (device_name);

      hc_string_trim_trailing (device_name);

      // device_processors

      int device_processors = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_processors, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_processors = device_processors;

      // device_global_mem, device_maxmem_alloc, device_available_mem

      size_t bytes = 0;

      if (hc_cuDeviceTotalMem (hashcat_ctx, &bytes, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_global_mem = (u64) bytes;

      device_param->device_maxmem_alloc = (u64) bytes;

      device_param->device_available_mem = 0;

      // warp size

      int cuda_warp_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &cuda_warp_size, CU_DEVICE_ATTRIBUTE_WARP_SIZE, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->cuda_warp_size = cuda_warp_size;

      // sm_minor, sm_major

      int sm_major = 0;
      int sm_minor = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->sm_major = sm_major;
      device_param->sm_minor = sm_minor;

      // device_maxworkgroup_size

      int device_maxworkgroup_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_maxworkgroup_size, CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      int device_maxclock_frequency = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_maxclock_frequency, CU_DEVICE_ATTRIBUTE_CLOCK_RATE, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxclock_frequency = device_maxclock_frequency / 1000;

      // pcie_bus, pcie_device, pcie_function

      int pci_domain_id_nv  = 0;
      int pci_bus_id_nv     = 0;
      int pci_slot_id_nv    = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &pci_domain_id_nv, CU_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &pci_bus_id_nv, CU_DEVICE_ATTRIBUTE_PCI_BUS_ID, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &pci_slot_id_nv, CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->pcie_domain   = (u8) (pci_domain_id_nv);
      device_param->pcie_bus      = (u8) (pci_bus_id_nv);
      device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
      device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

      // kernel_exec_timeout

      int kernel_exec_timeout = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &kernel_exec_timeout, CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->kernel_exec_timeout = kernel_exec_timeout;

      // warp size

      int warp_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &warp_size, CU_DEVICE_ATTRIBUTE_WARP_SIZE, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->kernel_preferred_wgs_multiple = warp_size;

      // max_shared_memory_per_block

      int max_shared_memory_per_block = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &max_shared_memory_per_block, CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK_OPTIN, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (max_shared_memory_per_block < 32768)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's shared buffer size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      device_param->device_local_mem_size = max_shared_memory_per_block;

      // device_max_constant_buffer_size

      int device_max_constant_buffer_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_max_constant_buffer_size, CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY, cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (device_max_constant_buffer_size < 65536)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      // some attributes have to be hardcoded values because they are used for instance in the build options

      device_param->device_local_mem_type     = CL_LOCAL;
      device_param->opencl_device_type        = CL_DEVICE_TYPE_GPU;
      device_param->opencl_device_vendor_id   = VENDOR_ID_NV;
      device_param->opencl_platform_vendor_id = VENDOR_ID_NV;

      // or in the cached kernel checksum

      device_param->opencl_device_version     = "";
      device_param->opencl_driver_version     = "";

      // or just to make sure they are not NULL

      device_param->opencl_device_vendor     = "";
      device_param->opencl_device_c_version  = "";

      // skipped

      if ((backend_ctx->backend_devices_filter & (1ULL << device_id)) == 0)
      {
        device_param->skipped = true;
      }

      #if !defined (__APPLE__)
      if ((backend_ctx->opencl_device_types_filter & CL_DEVICE_TYPE_GPU) == 0)
      {
        device_param->skipped = true;
      }
      #endif

      if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
      {
        need_nvml = true;

        #if defined (_WIN) || defined (__CYGWIN__)
        need_nvapi = true;
        #endif
      }

      // CPU burning loop damper
      // Value is given as number between 0-100
      // By default 8%
      // in theory not needed with CUDA

      device_param->spin_damp = (double) user_options->spin_damp / 100;

      // common driver check

      if (device_param->skipped == false)
      {
        if ((user_options->force == false) && (user_options->backend_info == 0))
        {
          // CUDA does not support query nvidia driver version, therefore no driver checks here
          // IF needed, could be retrieved using nvmlSystemGetDriverVersion()

          if (device_param->sm_major < 5)
          {
            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: This hardware has outdated CUDA compute capability (%u.%u).", device_id + 1, device_param->sm_major, device_param->sm_minor);
              event_log_warning (hashcat_ctx, "             For modern OpenCL performance, upgrade to hardware that supports");
              event_log_warning (hashcat_ctx, "             CUDA compute capability version 5.0 (Maxwell) or higher.");
            }
          }

          if (device_param->kernel_exec_timeout != 0)
          {
            if (user_options->quiet == false)
            {
              event_log_advice (hashcat_ctx, "* Device #%u: WARNING! Kernel exec timeout is not disabled.", device_id + 1);
              event_log_advice (hashcat_ctx, "             This may cause \"CL_OUT_OF_RESOURCES\" or related errors.");
              event_log_advice (hashcat_ctx, "             To disable the timeout, see: https://hashcat.net/q/timeoutpatch");
            }
          }
        }

        // activate device moved below, at end
      }

      // instruction set

      // bcrypt optimization?
      //const int rc_cuCtxSetCacheConfig = hc_cuCtxSetCacheConfig (hashcat_ctx, CU_FUNC_CACHE_PREFER_SHARED);
      //
      //if (rc_cuCtxSetCacheConfig == -1) return -1;

      const int sm = (device_param->sm_major * 10) + device_param->sm_minor;

      device_param->has_add   = (sm >= 12) ? true : false;
      device_param->has_addc  = (sm >= 12) ? true : false;
      device_param->has_sub   = (sm >= 12) ? true : false;
      device_param->has_subc  = (sm >= 12) ? true : false;
      device_param->has_bfe   = (sm >= 20) ? true : false;
      device_param->has_lop3  = (sm >= 50) ? true : false;
      device_param->has_mov64 = (sm >= 10) ? true : false;
      device_param->has_prmt  = (sm >= 20) ? true : false;

      // device_available_mem

      CUcontext cuda_context;

      if (hc_cuCtxCreate (hashcat_ctx, &cuda_context, CU_CTX_SCHED_BLOCKING_SYNC, device_param->cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuCtxPushCurrent (hashcat_ctx, cuda_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      size_t free  = 0;
      size_t total = 0;

      if (hc_cuMemGetInfo (hashcat_ctx, &free, &total) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_available_mem = (u64) free;

      if (hc_cuCtxPopCurrent (hashcat_ctx, &cuda_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuCtxDestroy (hashcat_ctx, cuda_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      /**
       * activate device
       */

      if (device_param->skipped == false) cuda_devices_active++;
    }
  }

  backend_ctx->cuda_devices_cnt     = cuda_devices_cnt;
  backend_ctx->cuda_devices_active  = cuda_devices_active;

  // HIP

  int hip_devices_cnt    = 0;
  int hip_devices_active = 0;

  if (backend_ctx->hip)
  {
    // device count

    if (hc_hipDeviceGetCount (hashcat_ctx, &hip_devices_cnt) == -1)
    {
      hip_close (hashcat_ctx);
    }

    backend_ctx->hip_devices_cnt = hip_devices_cnt;

    // device specific

    for (int hip_devices_idx = 0; hip_devices_idx < hip_devices_cnt; hip_devices_idx++, backend_devices_idx++)
    {
      const u32 device_id = backend_devices_idx;

      hc_device_param_t *device_param = &devices_param[backend_devices_idx];

      device_param->device_id = device_id;

      backend_ctx->backend_device_from_hip[hip_devices_idx] = backend_devices_idx;

      hipDevice_t hip_device;

      if (hc_hipDeviceGet (hashcat_ctx, &hip_device, hip_devices_idx) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->hip_device = hip_device;

      device_param->is_cuda   = false;
      device_param->is_hip    = true;
      device_param->is_metal  = false;
      device_param->is_opencl = false;

      device_param->use_opencl12 = false;
      device_param->use_opencl20 = false;
      device_param->use_opencl21 = false;

      // device_name

      char *device_name = (char *) hcmalloc (HCBUFSIZ_TINY);

      if (hc_hipDeviceGetName (hashcat_ctx, device_name, HCBUFSIZ_TINY, hip_device) == -1)
      {
        device_param->skipped = true;
        hcfree (device_name);
        continue;
      }

      device_param->device_name = device_name;

      hc_string_trim_leading (device_name);

      hc_string_trim_trailing (device_name);

      // device_processors

      int device_processors = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &device_processors, hipDeviceAttributeMultiprocessorCount, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_processors = device_processors;

      // device_global_mem, device_maxmem_alloc, device_available_mem

      size_t bytes = 0;

      if (hc_hipDeviceTotalMem (hashcat_ctx, &bytes, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_global_mem = (u64) bytes;

      device_param->device_maxmem_alloc = (u64) bytes;

      device_param->device_available_mem = 0;

      // warp size

      int hip_warp_size = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &hip_warp_size, hipDeviceAttributeWarpSize, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->hip_warp_size = hip_warp_size;

      // sm_minor, sm_major

      int sm_major = 0;
      int sm_minor = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &sm_major, hipDeviceAttributeComputeCapabilityMajor, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &sm_minor, hipDeviceAttributeComputeCapabilityMinor, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->sm_major = sm_major;
      device_param->sm_minor = sm_minor;

      // device_maxworkgroup_size

      int device_maxworkgroup_size = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &device_maxworkgroup_size, hipDeviceAttributeMaxThreadsPerBlock, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      int device_maxclock_frequency = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &device_maxclock_frequency, hipDeviceAttributeClockRate, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxclock_frequency = device_maxclock_frequency / 1000;

      // pcie_bus, pcie_device, pcie_function

      int pci_domain_id_nv  = 0;
      int pci_bus_id_nv     = 0;
      int pci_slot_id_nv    = 0;

      // Not supported by HIP
      //if (hc_hipDeviceGetAttribute (hashcat_ctx, &pci_domain_id_nv, hipDeviceAttributePciDomainID, hip_device) == -1)
      //{
      //  device_param->skipped = true;
      //  continue;
      //}

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &pci_bus_id_nv, hipDeviceAttributePciBusId, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &pci_slot_id_nv, hipDeviceAttributePciDeviceId, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->pcie_domain   = (u8) (pci_domain_id_nv);
      device_param->pcie_bus      = (u8) (pci_bus_id_nv);

      device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
      device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

      // kernel_exec_timeout

      int kernel_exec_timeout = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &kernel_exec_timeout, hipDeviceAttributeKernelExecTimeout, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->kernel_exec_timeout = kernel_exec_timeout;

      // warp size

      int warp_size = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &warp_size, hipDeviceAttributeWarpSize, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->kernel_preferred_wgs_multiple = warp_size;

      // max_shared_memory_per_block

      int max_shared_memory_per_block = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &max_shared_memory_per_block, hipDeviceAttributeMaxSharedMemoryPerBlock, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (max_shared_memory_per_block < 32768)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's shared buffer size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      device_param->device_local_mem_size = max_shared_memory_per_block;

      // device_max_constant_buffer_size

      int device_max_constant_buffer_size = 0;

      if (hc_hipDeviceGetAttribute (hashcat_ctx, &device_max_constant_buffer_size, hipDeviceAttributeTotalConstantMemory, hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      // TODO: broken on HIP?

      device_max_constant_buffer_size = 65536;

      if (device_max_constant_buffer_size < 65536)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      // some attributes have to be hardcoded values because they are used for instance in the build options

      device_param->device_local_mem_type     = CL_LOCAL;
      device_param->opencl_device_type        = CL_DEVICE_TYPE_GPU;
      device_param->opencl_device_vendor_id   = VENDOR_ID_AMD_USE_HIP;
      device_param->opencl_platform_vendor_id = VENDOR_ID_AMD_USE_HIP;

      // or in the cached kernel checksum

      device_param->opencl_device_version     = "";
      device_param->opencl_driver_version     = "";

      // or just to make sure they are not NULL

      device_param->opencl_device_vendor     = "";
      device_param->opencl_device_c_version  = "";

      // skipped

      if ((backend_ctx->backend_devices_filter & (1ULL << device_id)) == 0)
      {
        device_param->skipped = true;
      }

      #if !defined (__APPLE__)
      if ((backend_ctx->opencl_device_types_filter & CL_DEVICE_TYPE_GPU) == 0)
      {
        device_param->skipped = true;
      }
      #endif

      if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD_USE_HIP) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_HIP))
      {
         need_adl = true;

         #if defined (__linux__)
         need_sysfs_amdgpu = true;
         #endif
      }

      // CPU burning loop damper
      // Value is given as number between 0-100
      // By default 8%
      // in theory not needed with HIP

      device_param->spin_damp = (double) user_options->spin_damp / 100;

      // common driver check

      if (device_param->skipped == false)
      {
        if ((user_options->force == false) && (user_options->backend_info == 0))
        {
          // CUDA does not support query nvidia driver version, therefore no driver checks here
          // IF needed, could be retrieved using nvmlSystemGetDriverVersion()

          if (device_param->sm_major < 5)
          {
            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: This hardware has outdated CUDA compute capability (%u.%u).", device_id + 1, device_param->sm_major, device_param->sm_minor);
              event_log_warning (hashcat_ctx, "             For modern OpenCL performance, upgrade to hardware that supports");
              event_log_warning (hashcat_ctx, "             CUDA compute capability version 5.0 (Maxwell) or higher.");
            }
          }

          if (device_param->kernel_exec_timeout != 0)
          {
            if (user_options->quiet == false)
            {
              event_log_advice (hashcat_ctx, "* Device #%u: WARNING! Kernel exec timeout is not disabled.", device_id + 1);
              event_log_advice (hashcat_ctx, "             This may cause \"CL_OUT_OF_RESOURCES\" or related errors.");
              event_log_advice (hashcat_ctx, "             To disable the timeout, see: https://hashcat.net/q/timeoutpatch");
            }
          }
        }

        // activate device moved below, at end
      }

      // instruction set

      device_param->has_add   = false;
      device_param->has_addc  = false;
      device_param->has_sub   = false;
      device_param->has_subc  = false;
      device_param->has_bfe   = false;
      device_param->has_lop3  = false;
      device_param->has_mov64 = false;
      device_param->has_prmt  = false;

      // device_available_mem

      hipCtx_t hip_context;

      if (hc_hipCtxCreate (hashcat_ctx, &hip_context, hipDeviceScheduleBlockingSync, device_param->hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipCtxPushCurrent (hashcat_ctx, hip_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      size_t free  = 0;
      size_t total = 0;

      if (hc_hipMemGetInfo (hashcat_ctx, &free, &total) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_available_mem = (u64) free;

      if (hc_hipCtxPopCurrent (hashcat_ctx, &hip_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipCtxDestroy (hashcat_ctx, hip_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      #if defined (__linux__)
      if (strchr (folder_config->cpath_real, ' ') != NULL)
      {
        if (user_options->force == false)
        {
          event_log_error (hashcat_ctx, "* Device #%u: Unusable HIP include-path! (spaces detected)", device_id + 1);

          if (user_options->quiet == false)
          {
            event_log_warning (hashcat_ctx, "Consider moving hashcat to a path with no spaces.");
            event_log_warning (hashcat_ctx, "You can use --force to override, but do not report related errors.");
            event_log_warning (hashcat_ctx, NULL);
          }

          device_param->skipped = true;
          continue;
        }
      }
      #endif

      /**
       * activate device
       */

      if (device_param->skipped == false) hip_devices_active++;
    }
  }

  backend_ctx->hip_devices_cnt     = hip_devices_cnt;
  backend_ctx->hip_devices_active  = hip_devices_active;

  // Metal

  int metal_devices_cnt    = 0;
  int metal_devices_active = 0;

  #if defined (__APPLE__)
  if (backend_ctx->mtl)
  {
    // device count

    if (hc_mtlDeviceGetCount (hashcat_ctx, &metal_devices_cnt) == -1)
    {
      mtl_close (hashcat_ctx);
    }

    backend_ctx->metal_devices_cnt = metal_devices_cnt;

    // device specific

    for (int metal_devices_idx = 0; metal_devices_idx < metal_devices_cnt; metal_devices_idx++, backend_devices_idx++)
    {
      const u32 device_id = backend_devices_idx;

      hc_device_param_t *device_param = &devices_param[backend_devices_idx];

      device_param->device_id = device_id;

      backend_ctx->backend_device_from_metal[metal_devices_idx] = backend_devices_idx;

      mtl_device_id metal_device = NULL;

      if (hc_mtlDeviceGet (hashcat_ctx, &metal_device, metal_devices_idx) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->metal_device = metal_device;

      device_param->is_cuda   = false;
      device_param->is_hip    = false;
      device_param->is_metal  = true;
      device_param->is_opencl = false;

      device_param->use_opencl12 = false;
      device_param->use_opencl20 = false;
      device_param->use_opencl21 = false;

      device_param->is_apple_silicon = is_apple_silicon ();

      // some attributes have to be hardcoded values because they are used for instance in the build options

      device_param->device_local_mem_type     = CL_LOCAL;
      device_param->opencl_device_type        = CL_DEVICE_TYPE_GPU;
      device_param->opencl_device_vendor_id   = VENDOR_ID_APPLE;
      device_param->opencl_platform_vendor_id = VENDOR_ID_APPLE;

      // or in the cached kernel checksum

      device_param->opencl_device_version     = "";
      device_param->opencl_driver_version     = "";

      // or just to make sure they are not NULL

      device_param->opencl_device_vendor     = strdup ("Apple");
      device_param->opencl_device_c_version  = "";

      // sm_minor, sm_major

      int mtl_major = 0;
      int mtl_minor = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &mtl_major, MTL_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &mtl_minor, MTL_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->mtl_major = mtl_major;
      device_param->mtl_minor = mtl_minor;

      // device_name

      char *device_name = (char *) hcmalloc (HCBUFSIZ_TINY);

      if (hc_mtlDeviceGetName (hashcat_ctx, device_name, HCBUFSIZ_TINY, metal_device) == -1)
      {
        device_param->skipped = true;
        hcfree (device_name);
        continue;
      }

      device_param->device_name = device_name;

      hc_string_trim_leading (device_name);

      hc_string_trim_trailing (device_name);

      // device_processors

      int device_processors = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_processors, MTL_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_processors = device_processors;

      // device_host_unified_memory

      int device_host_unified_memory = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_host_unified_memory, MTL_DEVICE_ATTRIBUTE_UNIFIED_MEMORY, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_host_unified_memory = device_host_unified_memory;

      // device_global_mem, device_available_mem

      size_t bytes = 0;

      if (hc_mtlDeviceTotalMem (hashcat_ctx, &bytes, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_global_mem = (u64) bytes;

      device_param->device_available_mem = 0;

      // device_maxmem_alloc

      size_t device_maxmem_alloc = 0;

      if (hc_mtlDeviceMaxMemAlloc (hashcat_ctx, &device_maxmem_alloc, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxmem_alloc = device_maxmem_alloc;

      if (device_host_unified_memory == 1) device_param->device_maxmem_alloc /= 2;

      // warp size

      int metal_warp_size = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &metal_warp_size, MTL_DEVICE_ATTRIBUTE_WARP_SIZE, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->metal_warp_size = metal_warp_size;

      // device_maxworkgroup_size

      int device_maxworkgroup_size = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_maxworkgroup_size, MTL_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      int device_maxclock_frequency = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_maxclock_frequency, MTL_DEVICE_ATTRIBUTE_CLOCK_RATE, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_maxclock_frequency = device_maxclock_frequency / 1000;

      // pcie_bus, pcie_device, pcie_function

      device_param->pcie_domain   = 0;
      device_param->pcie_bus      = 0;
      device_param->pcie_device   = 0;
      device_param->pcie_function = 0;

      int device_physical_location = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_physical_location, MTL_DEVICE_ATTRIBUTE_PHYSICAL_LOCATION, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_physical_location = device_physical_location;

      int device_location_number = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_location_number, MTL_DEVICE_ATTRIBUTE_LOCATION_NUMBER, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_location_number = device_location_number;

      int device_max_transfer_rate = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_max_transfer_rate, MTL_DEVICE_ATTRIBUTE_MAX_TRANSFER_RATE, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_max_transfer_rate = device_max_transfer_rate;

      int device_registryID = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_registryID, MTL_DEVICE_ATTRIBUTE_REGISTRY_ID, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_registryID = device_registryID;

      // kernel_exec_timeout

      device_param->kernel_exec_timeout = 0;

      // wgs_multiple

      device_param->kernel_preferred_wgs_multiple = metal_warp_size;

      // max_shared_memory_per_block

      int max_shared_memory_per_block = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &max_shared_memory_per_block, MTL_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (max_shared_memory_per_block < 32768)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's shared buffer size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      device_param->device_local_mem_size = max_shared_memory_per_block;

      // device_max_constant_buffer_size

      int device_max_constant_buffer_size = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_max_constant_buffer_size, MTL_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (device_max_constant_buffer_size < 65536)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      // gpu properties

      int device_is_headless = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_is_headless, MTL_DEVICE_ATTRIBUTE_HEADLESS, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_is_headless = device_is_headless;

      int device_is_low_power = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_is_low_power, MTL_DEVICE_ATTRIBUTE_LOW_POWER, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_is_low_power = device_is_low_power;

      int device_is_removable = 0;

      if (hc_mtlDeviceGetAttribute (hashcat_ctx, &device_is_removable, MTL_DEVICE_ATTRIBUTE_REMOVABLE, metal_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      device_param->device_is_removable = device_is_removable;

      // skipped

      if ((backend_ctx->backend_devices_filter & (1ULL << device_id)) == 0)
      {
        device_param->skipped = true;
      }

      if ((backend_ctx->opencl_device_types_filter & CL_DEVICE_TYPE_GPU) == 0)
      {
        device_param->skipped = true;
      }

      if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_vendor_id == VENDOR_ID_APPLE))
      {
        need_iokit = true;
      }

      // CPU burning loop damper
      // Value is given as number between 0-100
      // By default 8%
      // in theory not needed with Metal

      device_param->spin_damp = 0;

      // common driver check
      /*
      if (device_param->skipped == false)
      {
        if ((user_options->force == false) && (user_options->backend_info == 0))
        {
        }

        // activate device moved below, at end
      }*/

      // instruction set

      device_param->has_add   = false;
      device_param->has_addc  = false;
      device_param->has_sub   = false;
      device_param->has_subc  = false;
      device_param->has_bfe   = false;
      device_param->has_lop3  = false;
      device_param->has_mov64 = false;
      device_param->has_prmt  = false;

      // check if we need skip device

      if (device_param->device_processors == 1) device_param->skipped = true;

      /**
       * activate device
       */

      if (device_param->skipped == false) metal_devices_active++;
    }
  }
  #endif // __APPLE__

  backend_ctx->metal_devices_cnt     = metal_devices_cnt;
  backend_ctx->metal_devices_active  = metal_devices_active;

  // OCL

  int opencl_devices_cnt    = 0;
  int opencl_devices_active = 0;

  if (backend_ctx->ocl)
  {
    /**
     * OpenCL devices: simply push all devices from all platforms into the same device array
     */

    cl_uint         opencl_platforms_cnt         = backend_ctx->opencl_platforms_cnt;
    cl_device_id  **opencl_platforms_devices     = backend_ctx->opencl_platforms_devices;
    cl_uint        *opencl_platforms_devices_cnt = backend_ctx->opencl_platforms_devices_cnt;
    cl_uint        *opencl_platforms_vendor_id   = backend_ctx->opencl_platforms_vendor_id;
    char          **opencl_platforms_version     = backend_ctx->opencl_platforms_version;

    for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
    {
      cl_device_id   *opencl_platform_devices     = opencl_platforms_devices[opencl_platforms_idx];
      cl_uint         opencl_platform_devices_cnt = opencl_platforms_devices_cnt[opencl_platforms_idx];
      cl_uint         opencl_platform_vendor_id   = opencl_platforms_vendor_id[opencl_platforms_idx];
      char           *opencl_platform_version     = opencl_platforms_version[opencl_platforms_idx];

      for (u32 opencl_platform_devices_idx = 0; opencl_platform_devices_idx < opencl_platform_devices_cnt; opencl_platform_devices_idx++, backend_devices_idx++, opencl_devices_cnt++)
      {
        const u32 device_id = backend_devices_idx;

        hc_device_param_t *device_param = &devices_param[device_id];

        device_param->device_id = device_id;

        backend_ctx->backend_device_from_opencl[opencl_devices_cnt] = backend_devices_idx;

        backend_ctx->backend_device_from_opencl_platform[opencl_platforms_idx][opencl_platform_devices_idx] = backend_devices_idx;

        device_param->opencl_platform_vendor_id = opencl_platform_vendor_id;

        device_param->opencl_device = opencl_platform_devices[opencl_platform_devices_idx];

        //device_param->opencl_platform = opencl_platform;

        device_param->is_cuda   = false;
        device_param->is_hip    = false;
        device_param->is_metal  = false;
        device_param->is_opencl = true;

        // store opencl platform i

        device_param->opencl_platform_id = opencl_platforms_idx;

        // check OpenCL version

        device_param->use_opencl12 = false;
        device_param->use_opencl20 = false;
        device_param->use_opencl21 = false;

        int opencl_version_min = 0;
        int opencl_version_maj = 0;

        if (sscanf (opencl_platform_version, "OpenCL %d.%d", &opencl_version_min, &opencl_version_maj) == 2)
        {
          if ((opencl_version_min == 1) && (opencl_version_maj == 2))
          {
            device_param->use_opencl12 = true;
          }
          else if ((opencl_version_min == 2) && (opencl_version_maj == 0))
          {
            device_param->use_opencl20 = true;
          }
          else if ((opencl_version_min == 2) && (opencl_version_maj == 1))
          {
            device_param->use_opencl21 = true;
          }
        }

        size_t param_value_size = 0;

        // opencl_device_type

        cl_device_type opencl_device_type;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_TYPE, sizeof (opencl_device_type), &opencl_device_type, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        opencl_device_type &= ~CL_DEVICE_TYPE_DEFAULT;

        device_param->opencl_device_type = opencl_device_type;

        // device_name

        // try CL_DEVICE_BOARD_NAME_AMD first, if it fails fall back to CL_DEVICE_NAME
        // since AMD ROCm does not identify itself at this stage we simply check for return code from clGetDeviceInfo()

        #define CHECK_BOARD_NAME_AMD 1

        cl_int rc_board_name_amd = CL_INVALID_VALUE;

        if (CHECK_BOARD_NAME_AMD)
        {
          //backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

          OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

          rc_board_name_amd = ocl->clGetDeviceInfo (device_param->opencl_device, CL_DEVICE_BOARD_NAME_AMD, 0, NULL, NULL);
        }

        if (rc_board_name_amd == CL_SUCCESS)
        {
          if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_BOARD_NAME_AMD, 0, NULL, &param_value_size) == -1)
          {
            device_param->skipped = true;
            continue;
          }

          char *device_name = (char *) hcmalloc (param_value_size);

          if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_BOARD_NAME_AMD, param_value_size, device_name, NULL) == -1)
          {
            device_param->skipped = true;
            hcfree (device_name);
            continue;
          }

          device_param->device_name = device_name;
        }
        else
        {
          if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NAME, 0, NULL, &param_value_size) == -1)
          {
            device_param->skipped = true;
            continue;
          }

          char *device_name = (char *) hcmalloc (param_value_size);

          if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NAME, param_value_size, device_name, NULL) == -1)
          {
            device_param->skipped = true;
            hcfree (device_name);
            continue;
          }

          device_param->device_name = device_name;
        }

        hc_string_trim_leading (device_param->device_name);

        hc_string_trim_trailing (device_param->device_name);

        // device_vendor

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VENDOR, 0, NULL, &param_value_size) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        char *opencl_device_vendor = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VENDOR, param_value_size, opencl_device_vendor, NULL) == -1)
        {
          device_param->skipped = true;
          hcfree (opencl_device_vendor);
          continue;
        }

        device_param->opencl_device_vendor = opencl_device_vendor;

        cl_uint opencl_device_vendor_id = 0;

        if (strcmp (opencl_device_vendor, CL_VENDOR_AMD1) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_AMD2) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_AMD_USE_INTEL) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_AMD_USE_INTEL;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_APPLE) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_APPLE;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_APPLE_USE_AMD) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_AMD;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_APPLE_USE_NV) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_NV;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_APPLE_USE_INTEL) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_INTEL_SDK;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_APPLE_USE_INTEL2) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_INTEL_SDK;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_INTEL_BEIGNET) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_INTEL_BEIGNET;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_INTEL_SDK) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_INTEL_SDK;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_MESA) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_MESA;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_NV) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_NV;
        }
        else if (strcmp (opencl_device_vendor, CL_VENDOR_POCL) == 0)
        {
          opencl_device_vendor_id = VENDOR_ID_POCL;
        }
        else
        {
          opencl_device_vendor_id = VENDOR_ID_GENERIC;
        }

        device_param->opencl_device_vendor_id = opencl_device_vendor_id;

        // device_version

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VERSION, 0, NULL, &param_value_size) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        char *opencl_device_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VERSION, param_value_size, opencl_device_version, NULL) == -1)
        {
          device_param->skipped = true;
          hcfree (opencl_device_version);
          continue;
        }

        device_param->opencl_device_version = opencl_device_version;

        // opencl_device_c_version

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &param_value_size) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        char *opencl_device_c_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_OPENCL_C_VERSION, param_value_size, opencl_device_c_version, NULL) == -1)
        {
          device_param->skipped = true;
          hcfree (opencl_device_c_version);
          continue;
        }

        device_param->opencl_device_c_version = opencl_device_c_version;

        // max_compute_units

        cl_uint device_processors = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof (device_processors), &device_processors, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_processors = device_processors;

        // device_host_unified_memory

        cl_bool device_host_unified_memory = false;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_HOST_UNIFIED_MEMORY, sizeof (device_host_unified_memory), &device_host_unified_memory, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_host_unified_memory = (device_host_unified_memory == CL_TRUE) ? 1 : 0;

        // device_global_mem

        cl_ulong device_global_mem = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof (device_global_mem), &device_global_mem, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_global_mem = device_global_mem;

        device_param->device_available_mem = 0;

        // device_maxmem_alloc

        cl_ulong device_maxmem_alloc = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof (device_maxmem_alloc), &device_maxmem_alloc, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_maxmem_alloc = device_maxmem_alloc;

        if (device_param->device_host_unified_memory == 1)
        {
          // so, we actually have only half the memory because we need the same buffers on host side

          device_param->device_maxmem_alloc /= 2;
        }

        // note we'll limit to 2gb, otherwise this causes all kinds of weird errors because of possible integer overflows in opencl runtimes
        // testwise disabling that
        //device_param->device_maxmem_alloc = MIN (device_maxmem_alloc, 0x7fffffff);

        // max_work_group_size

        size_t device_maxworkgroup_size = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof (device_maxworkgroup_size), &device_maxworkgroup_size, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_maxworkgroup_size = device_maxworkgroup_size;

        // max_clock_frequency

        cl_uint device_maxclock_frequency = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof (device_maxclock_frequency), &device_maxclock_frequency, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_maxclock_frequency = device_maxclock_frequency;

        // device_endian_little

        cl_bool device_endian_little = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_ENDIAN_LITTLE, sizeof (device_endian_little), &device_endian_little, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if (device_endian_little == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device is not little-endian.", device_id + 1);

          device_param->skipped = true;
        }

        // device_available

        cl_bool device_available = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_AVAILABLE, sizeof (device_available), &device_available, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if (device_available == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device is not available.", device_id + 1);

          device_param->skipped = true;
        }

        // device_compiler_available

        cl_bool device_compiler_available = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPILER_AVAILABLE, sizeof (device_compiler_available), &device_compiler_available, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if (device_compiler_available == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: No compiler is available for this device.", device_id + 1);

          device_param->skipped = true;
        }

        // device_execution_capabilities

        cl_device_exec_capabilities device_execution_capabilities;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXECUTION_CAPABILITIES, sizeof (device_execution_capabilities), &device_execution_capabilities, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if ((device_execution_capabilities & CL_EXEC_KERNEL) == 0)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device does not support executing kernels.", device_id + 1);

          device_param->skipped = true;
        }

        // device_extensions

        size_t device_extensions_size;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXTENSIONS, 0, NULL, &device_extensions_size) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        char *device_extensions = (char *) hcmalloc (device_extensions_size + 1);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXTENSIONS, device_extensions_size, device_extensions, NULL) == -1)
        {
          device_param->skipped = true;
          hcfree (device_extensions);
          continue;
        }

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

        // kernel_preferred_wgs_multiple

        // There is global query for this attribute on OpenCL that is not linked to a specific kernel, so we set it to a fixed value
        // Later in the code, we add vendor specific extensions to query it

        device_param->kernel_preferred_wgs_multiple = 8;

        // device_local_mem_type

        cl_device_local_mem_type device_local_mem_type;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_LOCAL_MEM_TYPE, sizeof (device_local_mem_type), &device_local_mem_type, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        device_param->device_local_mem_type = device_local_mem_type;

        // device_max_constant_buffer_size

        cl_ulong device_max_constant_buffer_size;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof (device_max_constant_buffer_size), &device_max_constant_buffer_size, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if (device_local_mem_type == CL_LOCAL)
        {
          if (device_max_constant_buffer_size < 65536)
          {
            event_log_error (hashcat_ctx, "* Device #%u: This device's constant buffer size is too small.", device_id + 1);

            device_param->skipped = true;
          }
        }

        // device_local_mem_size

        cl_ulong device_local_mem_size = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof (device_local_mem_size), &device_local_mem_size, NULL) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        if (device_local_mem_type == CL_LOCAL)
        {
          if (device_local_mem_size < 32768)
          {
            event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

            device_param->skipped = true;
          }
        }

        // workaround inc!
        // allocating all reported local memory causes jit to fail with: SC failed. No reason given.
        // if we limit ourself to 32k it seems to work

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
          {
            if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
            {
              device_local_mem_size = MIN (device_local_mem_size, 32768);
            }
          }
        }

        device_param->device_local_mem_size = device_local_mem_size;

        // handling known bugs on POCL

        // POCL < 1.9 doesn't like quotes in the include path, see:
        // https://github.com/hashcat/hashcat/issues/2950
        // https://github.com/pocl/pocl/issues/962

        // POCL < 1.5 and older LLVM versions are known to fail compiling kernels
        // https://github.com/hashcat/hashcat/issues/2344

        // we need to inform the user to update

        if (opencl_platform_vendor_id == VENDOR_ID_POCL)
        {
          char *pocl_version_ptr = strstr (opencl_platform_version, "pocl ");
          char *llvm_version_ptr = strstr (opencl_platform_version, "LLVM ");

          if ((pocl_version_ptr != NULL) && (llvm_version_ptr != NULL))
          {
            bool pocl_skip = false;

            int pocl_maj = 0;
            int pocl_min = 0;

            int pocl_bug_whitespace_on_path = 0;
            int pocl_bug_kernel_compiling_failure = 0;

            const int res1 = sscanf (pocl_version_ptr, "pocl %d.%d", &pocl_maj, &pocl_min);

            if (res1 == 2)
            {
              const int pocl_version = (pocl_maj * 100) + pocl_min;

              if (pocl_version < 109)
              {
                if (strchr (folder_config->cpath_real, ' ') != NULL)
                {
                  pocl_skip = true;
                  pocl_bug_whitespace_on_path = 1;
                }

                if (pocl_version < 105)
                {
                  pocl_skip = true;
                  pocl_bug_kernel_compiling_failure = 1;
                }
              }
            }

            int llvm_maj = 0;
            int llvm_min = 0;

            const int res2 = sscanf (llvm_version_ptr, "LLVM %d.%d", &llvm_maj, &llvm_min);

            if (res2 == 2)
            {
              const int llvm_version = (llvm_maj * 100) + llvm_min;

              if (llvm_version < 900)
              {
                pocl_skip = true;
              }
            }

            if (pocl_skip == true)
            {
              if (user_options->force == false)
              {
                event_log_error (hashcat_ctx, "* Device #%u: Outdated POCL OpenCL driver detected!", device_id + 1);

                if (user_options->quiet == false)
                {
                  if (pocl_bug_kernel_compiling_failure == 1)
                  {
                    event_log_warning (hashcat_ctx, "This OpenCL driver may fail kernel compilation or produce false negatives.");
                  }

                  if (pocl_bug_whitespace_on_path == 1)
                  {
                    event_log_warning (hashcat_ctx, "Consider moving hashcat to a path with no spaces if you want to use this POCL version.");
                  }

                  event_log_warning (hashcat_ctx, "We recommend using a version of POCL >= 1.9");
                  event_log_warning (hashcat_ctx, "You can use --force to override, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);
                }

                device_param->skipped = true;
              }
            }
          }
        }

        #if defined (__linux__)
        if (opencl_platform_vendor_id == VENDOR_ID_AMD)
        {
          if (strchr (folder_config->cpath_real, ' ') != NULL)
          {
            if (user_options->force == false)
            {
              event_log_error (hashcat_ctx, "* Device #%u: Unusable OpenCL include-path! (spaces detected)", device_id + 1);

              if (user_options->quiet == false)
              {
                event_log_warning (hashcat_ctx, "Consider moving hashcat to a path with no spaces.");
                event_log_warning (hashcat_ctx, "You can use --force to override, but do not report related errors.");
                event_log_warning (hashcat_ctx, NULL);
              }

              device_param->skipped = true;
            }
          }
        }
        #endif

        char *opencl_device_version_lower = hcstrdup (opencl_device_version);

        lowercase ((u8 *) opencl_device_version_lower, strlen (opencl_device_version_lower));

        if ((strstr (opencl_device_version_lower, "beignet "))
         || (strstr (opencl_device_version_lower, " beignet"))
         || (strstr (opencl_device_version_lower, "mesa "))
         || (strstr (opencl_device_version_lower, " mesa")))
        {
          // BEIGNET: https://github.com/hashcat/hashcat/issues/2243
          // MESA:    https://github.com/hashcat/hashcat/issues/2269

          if (user_options->force == false)
          {
            event_log_error (hashcat_ctx, "* Device #%u: Unstable OpenCL driver detected!", device_id + 1);

            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx, "This OpenCL driver may fail kernel compilation or produce false negatives.");
              event_log_warning (hashcat_ctx, "You can use --force to override, but do not report related errors.");
              event_log_warning (hashcat_ctx, NULL);
            }

            device_param->skipped = true;
          }
        }

        hcfree (opencl_device_version_lower);

        // Since some times we get reports from users about not working hashcat, dropping error messages like:
        // CL_INVALID_COMMAND_QUEUE and CL_OUT_OF_RESOURCES
        // Turns out that this is caused by Intel OpenCL runtime handling their GPU devices
        // Disable such devices unless the user forces to use it
        // This is successfully workaround with new threading model and new memory management
        // Tested on Windows 10
        // OpenCL.Version.: OpenCL C 2.1
        // Driver.Version.: 23.20.16.4973

        /*
        #if !defined (__APPLE__)
        if (opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) || (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_BEIGNET))
          {
            if (user_options->force == false)
            {
              if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Intel's OpenCL runtime (GPU only) is currently broken.", device_id + 1);
              if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             We are waiting for updated OpenCL drivers from Intel.");
              if (user_options->quiet == false) event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");
              if (user_options->quiet == false) event_log_warning (hashcat_ctx, NULL);

              device_param->skipped = true;
            }
          }
        }
        #endif // __APPLE__
        */

        // skipped

        if ((backend_ctx->backend_devices_filter & (1ULL << device_id)) == 0)
        {
          device_param->skipped = true;
        }

        if ((backend_ctx->opencl_device_types_filter & (opencl_device_type)) == 0)
        {
          device_param->skipped = true;
        }

        #if defined (__APPLE__)
        if (opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          //if (user_options->force == false)
          if (device_param->skipped == false)
          {
            if (user_options->quiet == false)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Apple's OpenCL drivers (GPU) are known to be unreliable.", device_id + 1);
              event_log_warning (hashcat_ctx, "             You have been warned.");
              //event_log_warning (hashcat_ctx, "  There are many reports of false negatives and other issues.");
              //event_log_warning (hashcat_ctx, "  This is not a hashcat issue. Other projects report issues with these drivers.");
              //event_log_warning (hashcat_ctx, "  You can use --force to override, but do not report related errors. You have been warned.");
              event_log_warning (hashcat_ctx, NULL);
            }

            //device_param->skipped = true;
          }
        }
        #endif // __APPLE__

        // driver_version

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DRIVER_VERSION, 0, NULL, &param_value_size) == -1)
        {
          device_param->skipped = true;
          continue;
        }

        char *opencl_driver_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DRIVER_VERSION, param_value_size, opencl_driver_version, NULL) == -1)
        {
          device_param->skipped = true;
          hcfree (opencl_driver_version);
          continue;
        }

        device_param->opencl_driver_version = opencl_driver_version;

        // vendor specific

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
        {
          #if defined (__APPLE__)
          if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
          {
            need_iokit = true;
          }
          #endif

          #if defined (__linux__)
          need_sysfs_cpu = true;
          #endif
        }

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            need_adl = true;

            #if defined (__linux__)
            need_sysfs_amdgpu = true;
            #endif
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
          {
            need_nvml = true;

            #if defined (_WIN) || defined (__CYGWIN__)
            need_nvapi = true;
            #endif
          }

          #if defined (__APPLE__)
          if (strncmp (device_param->device_name, "Apple M", 7) == 0)
          {
            if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
            {
              need_iokit = true;
            }
          }
          #endif
        }

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
        {
          // they like this

          device_param->kernel_preferred_wgs_multiple = 1;
        }

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            // from https://www.khronos.org/registry/OpenCL/extensions/amd/cl_amd_device_attribute_query.txt
            #define CL_DEVICE_WAVEFRONT_WIDTH_AMD                   0x4043

            // crazy, but apple does not support this query!
            // the best alternative is "Preferred work group size multiple (kernel)", but requires to specify a kernel.
            // so we will set kernel_preferred_wgs_multiple intentionally to 0 because otherwise it it set to 8 by default.
            // we then assign the value kernel_preferred_wgs_multiple a small kernel like bzero after test if this was set to 0.

            device_param->kernel_preferred_wgs_multiple = 0;
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            cl_uint device_wavefront_width_amd;

            // from https://www.khronos.org/registry/OpenCL/extensions/amd/cl_amd_device_attribute_query.txt
            #define CL_DEVICE_WAVEFRONT_WIDTH_AMD                   0x4043

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_WAVEFRONT_WIDTH_AMD, sizeof (device_wavefront_width_amd), &device_wavefront_width_amd, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->kernel_preferred_wgs_multiple = device_wavefront_width_amd;

            cl_device_topology_amd amdtopo;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_TOPOLOGY_AMD, sizeof (amdtopo), &amdtopo, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->pcie_domain   = 0; // no attribute to query
            device_param->pcie_bus      = amdtopo.pcie.bus;
            device_param->pcie_device   = amdtopo.pcie.device;
            device_param->pcie_function = amdtopo.pcie.function;
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
          {
            cl_uint device_warp_size_nv;

            // from deps/OpenCL-Headers/CL/cl_ext.h
            #define CL_DEVICE_WARP_SIZE_NV                      0x4003

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_WARP_SIZE_NV, sizeof (device_warp_size_nv), &device_warp_size_nv, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->kernel_preferred_wgs_multiple = device_warp_size_nv;

            cl_uint pci_bus_id_nv;  // is cl_uint the right type for them??
            cl_uint pci_slot_id_nv;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_PCI_BUS_ID_NV, sizeof (pci_bus_id_nv), &pci_bus_id_nv, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_PCI_SLOT_ID_NV, sizeof (pci_slot_id_nv), &pci_slot_id_nv, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->pcie_domain   = 0; // no attribute to query
            device_param->pcie_bus      = (u8) (pci_bus_id_nv);
            device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
            device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

            int sm_minor = 0;
            int sm_major = 0;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof (sm_minor), &sm_minor, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof (sm_major), &sm_major, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->sm_minor = sm_minor;
            device_param->sm_major = sm_major;

            cl_uint kernel_exec_timeout = 0;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV, sizeof (kernel_exec_timeout), &kernel_exec_timeout, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }

            device_param->kernel_exec_timeout = kernel_exec_timeout;

            // CPU burning loop damper
            // Value is given as number between 0-100
            // By default 8%

            device_param->spin_damp = (double) user_options->spin_damp / 100;

            if (user_options->stdout_flag == false)
            {
              // recommend CUDA

              if ((backend_ctx->cuda == NULL) || (backend_ctx->nvrtc == NULL))
              {
                if (user_options->backend_ignore_cuda == false)
                {
                  if (backend_ctx->rc_cuda_init == -1)
                  {
                    event_log_warning (hashcat_ctx, "Failed to initialize the NVIDIA main driver CUDA runtime library.");
                    event_log_warning (hashcat_ctx, NULL);
                  }
                  else
                  {
                    event_log_warning (hashcat_ctx, "Successfully initialized the NVIDIA main driver CUDA runtime library.");
                    event_log_warning (hashcat_ctx, NULL);
                  }

                  if (backend_ctx->rc_nvrtc_init == -1)
                  {
                    event_log_warning (hashcat_ctx, "Failed to initialize NVIDIA RTC library.");
                    event_log_warning (hashcat_ctx, NULL);
                  }
                  else
                  {
                    event_log_warning (hashcat_ctx, "Successfully initialized NVIDIA RTC library.");
                    event_log_warning (hashcat_ctx, NULL);
                  }

                  event_log_warning (hashcat_ctx, "* Device #%u: CUDA SDK Toolkit not installed or incorrectly installed.", device_id + 1);
                  event_log_warning (hashcat_ctx, "             CUDA SDK Toolkit required for proper device support and utilization.");
                  event_log_warning (hashcat_ctx, "             Falling back to OpenCL runtime.");

                  event_log_warning (hashcat_ctx, NULL);
                }
              }
            }
          }
        }

        // instruction set

        // fixed values works only for nvidia devices
        // dynamical values for amd see time intensive section below

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_NV))
        {
          const int sm = (device_param->sm_major * 10) + device_param->sm_minor;

          device_param->has_add   = (sm >= 12) ? true : false;
          device_param->has_addc  = (sm >= 12) ? true : false;
          device_param->has_sub   = (sm >= 12) ? true : false;
          device_param->has_subc  = (sm >= 12) ? true : false;
          device_param->has_bfe   = (sm >= 20) ? true : false;
          device_param->has_lop3  = (sm >= 50) ? true : false;
          device_param->has_mov64 = (sm >= 10) ? true : false;
          device_param->has_prmt  = (sm >= 20) ? true : false;
        }

        // common driver check

        if (device_param->skipped == false)
        {
          if ((user_options->force == false) && (user_options->backend_info == 0))
          {
            if (opencl_device_type & CL_DEVICE_TYPE_CPU)
            {
              if (device_param->opencl_platform_vendor_id == VENDOR_ID_INTEL_SDK)
              {
                bool intel_warn = false;

                // Intel OpenCL runtime 18

                int opencl_driver1 = 0;
                int opencl_driver2 = 0;
                int opencl_driver3 = 0;
                int opencl_driver4 = 0;

                const int res18 = sscanf (device_param->opencl_driver_version, "%d.%d.%d.%d", &opencl_driver1, &opencl_driver2, &opencl_driver3, &opencl_driver4);

                if (res18 == 4)
                {
                  // so far all versions 18 are ok
                }
                else
                {
                  // Intel OpenCL runtime 16

                  float opencl_version = 0;
                  int   opencl_build   = 0;

                  const int res16 = sscanf (device_param->opencl_device_version, "OpenCL %f (Build %d)", &opencl_version, &opencl_build);

                  if (res16 == 2)
                  {
                    if (opencl_build < 25) intel_warn = true;
                  }
                }

                if (intel_warn == true)
                {
                  event_log_error (hashcat_ctx, "* Device #%u: Outdated or broken Intel OpenCL runtime '%s' detected!", device_id + 1, device_param->opencl_driver_version);

                  event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported runtime.");
                  event_log_warning (hashcat_ctx, "See hashcat.net for the officially supported Intel OpenCL runtime.");
                  event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                  event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);

                  device_param->skipped = true;
                  continue;
                }
              }
            }
            else if (opencl_device_type & CL_DEVICE_TYPE_GPU)
            {
              if (device_param->opencl_platform_vendor_id == VENDOR_ID_AMD)
              {
                bool amd_warn = true;

                #if defined (__linux__)
                // AMDGPU-PRO Driver 16.40 and higher
                if (strtoul (device_param->opencl_driver_version, NULL, 10) >= 2117) amd_warn = false;
                // AMDGPU-PRO Driver 16.50 is known to be broken
                if (strtoul (device_param->opencl_driver_version, NULL, 10) == 2236) amd_warn = true;
                // AMDGPU-PRO Driver 16.60 is known to be broken
                if (strtoul (device_param->opencl_driver_version, NULL, 10) == 2264) amd_warn = true;
                // AMDGPU-PRO Driver 17.10 is known to be broken
                if (strtoul (device_param->opencl_driver_version, NULL, 10) == 2348) amd_warn = true;
                // AMDGPU-PRO Driver 17.20 (2416) is fine, doesn't need check will match >= 2117
                #elif defined (_WIN)
                // AMD Radeon Software 14.9 and higher, should be updated to 15.12
                if (strtoul (device_param->opencl_driver_version, NULL, 10) >= 1573) amd_warn = false;
                #else
                // we have no information about other os
                if (amd_warn == true) amd_warn = false;
                #endif

                if (amd_warn == true)
                {
                  event_log_error (hashcat_ctx, "* Device #%u: Outdated or broken AMD driver '%s' detected!", device_id + 1, device_param->opencl_driver_version);

                  event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported driver.");
                  event_log_warning (hashcat_ctx, "See hashcat.net for officially supported AMD drivers.");
                  event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                  event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);

                  device_param->skipped = true;
                  continue;
                }
              }

              if (device_param->opencl_platform_vendor_id == VENDOR_ID_NV)
              {
                int nv_warn = true;

                int version_maj = 0;
                int version_min = 0;

                const int r = sscanf (device_param->opencl_driver_version, "%d.%d", &version_maj, &version_min);

                if (r == 2)
                {
                  // nvidia 441.x looks ok

                  if (version_maj == 440)
                  {
                    if (version_min >= 64)
                    {
                      nv_warn = false;
                    }
                  }
                  else
                  {
                    // unknown version scheme, probably new driver version

                    nv_warn = false;
                  }
                }
                else
                {
                  // unknown version scheme, probably new driver version

                  nv_warn = false;
                }

                if (nv_warn == true)
                {
                  event_log_warning (hashcat_ctx, "* Device #%u: Outdated or broken NVIDIA driver '%s' detected!", device_id + 1, device_param->opencl_driver_version);
                  event_log_warning (hashcat_ctx, NULL);

                  event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported driver.");
                  event_log_warning (hashcat_ctx, "See hashcat's homepage for officially supported NVIDIA drivers.");
                  event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                  event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);

                  device_param->skipped = true;
                  continue;
                }

                if (device_param->sm_major < 5)
                {
                  if (user_options->quiet == false)
                  {
                    event_log_warning (hashcat_ctx, "* Device #%u: This hardware has outdated CUDA compute capability (%u.%u).", device_id + 1, device_param->sm_major, device_param->sm_minor);
                    event_log_warning (hashcat_ctx, "             For modern OpenCL performance, upgrade to hardware that supports");
                    event_log_warning (hashcat_ctx, "             CUDA compute capability version 5.0 (Maxwell) or higher.");
                  }
                }

                if (device_param->kernel_exec_timeout != 0)
                {
                  if (user_options->quiet == false)
                  {
                    event_log_warning (hashcat_ctx, "* Device #%u: WARNING! Kernel exec timeout is not disabled.", device_id + 1);
                    event_log_warning (hashcat_ctx, "             This may cause \"CL_OUT_OF_RESOURCES\" or related errors.");
                    event_log_warning (hashcat_ctx, "             To disable the timeout, see: https://hashcat.net/q/timeoutpatch");
                  }
                }
              }
            }
          }

          /**
           * activate device
           */

          opencl_devices_active++;
        }
      }
    }
  }

  backend_ctx->opencl_devices_cnt     = opencl_devices_cnt;
  backend_ctx->opencl_devices_active  = opencl_devices_active;

  // all devices combined go into backend_* variables

  backend_ctx->backend_devices_cnt    = cuda_devices_cnt    + hip_devices_cnt    + metal_devices_cnt    + opencl_devices_cnt;
  backend_ctx->backend_devices_active = cuda_devices_active + hip_devices_active + metal_devices_active + opencl_devices_active;

  // find duplicate devices

  //if ((cuda_devices_cnt > 0) && (hip_devices_cnt > 0) && (opencl_devices_cnt > 0))
  //{
    // using force here enables both devices, which is the worst possible outcome
    // many users force by default, so this is not a good idea

    //if (user_options->force == false)
    //{
    backend_ctx_find_alias_devices (hashcat_ctx);
    //{
  //}

  if (backend_ctx->backend_devices_active == 0)
  {
    event_log_error (hashcat_ctx, "No devices found/left.");

    return -1;
  }

  // now we can calculate the number of parallel running hook threads based on
  // the number cpu cores and the number of active compute devices
  // unless overwritten by the user

  if (user_options->hook_threads == HOOK_THREADS)
  {
    const u32 processor_count = hc_get_processor_count ();

    const u32 processor_count_cu = CEILDIV (processor_count, backend_ctx->backend_devices_active); // should never reach 0

    user_options->hook_threads = processor_count_cu;
  }

  // additional check to see if the user has chosen a device that is not within the range of available devices (i.e. larger than devices_cnt)

  if (backend_ctx->backend_devices_filter != (u64) -1)
  {
    const u64 backend_devices_cnt_mask = ~(((u64) -1 >> backend_ctx->backend_devices_cnt) << backend_ctx->backend_devices_cnt);

    if (backend_ctx->backend_devices_filter > backend_devices_cnt_mask)
    {
      event_log_error (hashcat_ctx, "An invalid device was specified using the --backend-devices parameter.");
      event_log_error (hashcat_ctx, "The specified device was higher than the number of available devices (%u).", backend_ctx->backend_devices_cnt);

      return -1;
    }
  }

  // time or resource intensive operations which we do not run if the corresponding device was skipped by the user

  if (backend_ctx->cuda)
  {
    // instruction test for cuda devices was replaced with fixed values (see above)

    /*
    CUcontext cuda_context;

    if (hc_cuCtxCreate (hashcat_ctx, &cuda_context, CU_CTX_SCHED_BLOCKING_SYNC, device_param->cuda_device) == -1) return -1;

    if (hc_cuCtxSetCurrent (hashcat_ctx, cuda_context) == -1) return -1;

    #define RUN_INSTRUCTION_CHECKS()                                                                                                                                                                                                                      \
      device_param->has_add   = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"add.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                                              \
      device_param->has_addc  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"addc.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                                             \
      device_param->has_sub   = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"sub.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                                              \
      device_param->has_subc  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"subc.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                                             \
      device_param->has_bfe   = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"bfe.u32 %0, 0, 0, 0;\" : \"=r\"(r)); }");                                                              \
      device_param->has_lop3  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"lop3.b32 %0, 0, 0, 0, 0;\" : \"=r\"(r)); }");                                                          \
      device_param->has_mov64 = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned long long r; unsigned int a; unsigned int b; asm volatile (\"mov.b64 %0, {%1, %2};\" : \"=l\"(r) : \"r\"(a), \"r\"(b)); }");  \
      device_param->has_prmt  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"prmt.b32 %0, 0, 0, 0;\" : \"=r\"(r)); }");                                                             \

    if (backend_devices_idx > 0)
    {
      hc_device_param_t *device_param_prev = &devices_param[backend_devices_idx - 1];

      if (is_same_device_type (device_param, device_param_prev) == true)
      {
        device_param->has_add   = device_param_prev->has_add;
        device_param->has_addc  = device_param_prev->has_addc;
        device_param->has_sub   = device_param_prev->has_sub;
        device_param->has_subc  = device_param_prev->has_subc;
        device_param->has_bfe   = device_param_prev->has_bfe;
        device_param->has_lop3  = device_param_prev->has_lop3;
        device_param->has_mov64 = device_param_prev->has_mov64;
        device_param->has_prmt  = device_param_prev->has_prmt;
      }
      else
      {
        RUN_INSTRUCTION_CHECKS();
      }
    }
    else
    {
      RUN_INSTRUCTION_CHECKS();
    }

    #undef RUN_INSTRUCTION_CHECKS

    if (hc_cuCtxDestroy (hashcat_ctx, cuda_context) == -1) return -1;

    */
  }

  if (backend_ctx->hip)
  {
    // TODO HIP?
    // Maybe all devices supported by hip have these instructions guaranteed?

    for (int backend_devices_cnt = 0; backend_devices_cnt < backend_ctx->backend_devices_cnt; backend_devices_cnt++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_cnt];

      if (device_param->is_hip == false) continue;

      device_param->has_vadd     = true;
      device_param->has_vaddc    = true;
      device_param->has_vadd_co  = true;
      device_param->has_vaddc_co = true;
      device_param->has_vsub     = true;
      device_param->has_vsubb    = true;
      device_param->has_vsub_co  = true;
      device_param->has_vsubb_co = true;
      device_param->has_vadd3    = true;
      device_param->has_vbfe     = true;
      device_param->has_vperm    = true;
    }
  }

  #if defined (__APPLE__)
  if (backend_ctx->mtl)
  {
    for (int backend_devices_cnt = 0; backend_devices_cnt < backend_ctx->backend_devices_cnt; backend_devices_cnt++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_cnt];

      if (device_param->is_metal == false) continue;

      if (user_options->backend_info == 0)
      {
        // do not ignore in case -I because user expects a value also for skipped devices

        if (device_param->skipped == true) continue;
      }

      /**
       * create command-queue
       */

      mtl_command_queue command_queue;

      if (hc_mtlCreateCommandQueue (hashcat_ctx, device_param->metal_device, &command_queue) == -1)
      {
        device_param->skipped = true;

        backend_ctx->metal_devices_active--;
        backend_ctx->backend_devices_active--;
        continue;
      }

      // available device memory
      // This test causes an GPU memory usage spike.
      // In case there are multiple hashcat instances starting at the same time this will cause GPU out of memory errors which otherwise would not exist.
      // We will simply not run it if that device was skipped by the user.

      #define MAX_ALLOC_CHECKS_CNT  8192
      #define MAX_ALLOC_CHECKS_SIZE (64 * 1024 * 1024)

      device_param->device_available_mem = device_param->device_global_mem - MAX_ALLOC_CHECKS_SIZE;

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        // following the same logic as for OpenCL, explained later

        mtl_mem *tmp_device = (mtl_mem *) hccalloc (MAX_ALLOC_CHECKS_CNT, sizeof (mtl_mem));

        u64 c;

        for (c = 0; c < MAX_ALLOC_CHECKS_CNT; c++)
        {
          if (((c + 1 + 1) * MAX_ALLOC_CHECKS_SIZE) >= device_param->device_global_mem) break;

          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, MAX_ALLOC_CHECKS_SIZE, NULL, &tmp_device[c]) == -1)
          {
            c--;

            break;
          }

          // transfer only a few byte should be enough to force the runtime to actually allocate the memory

          u8 tmp_host[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };

          if (hc_mtlMemcpyHtoD (hashcat_ctx, command_queue, tmp_device[c], 0, tmp_host, sizeof (tmp_host)) == -1) break;
          if (hc_mtlMemcpyDtoH (hashcat_ctx, command_queue, tmp_host, tmp_device[c], 0, sizeof (tmp_host)) == -1) break;

          if (hc_mtlMemcpyHtoD (hashcat_ctx, command_queue, tmp_device[c], MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), tmp_host, sizeof (tmp_host)) == -1) break;
          if (hc_mtlMemcpyDtoH (hashcat_ctx, command_queue, tmp_host, tmp_device[c], MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), sizeof (tmp_host)) == -1) break;
        }

        device_param->device_available_mem = MAX_ALLOC_CHECKS_SIZE;

        if (c > 0)
        {
          device_param->device_available_mem *= c;
        }

        // clean up

        for (c = 0; c < MAX_ALLOC_CHECKS_CNT; c++)
        {
          if (((c + 1 + 1) * MAX_ALLOC_CHECKS_SIZE) >= device_param->device_global_mem) break;

          if (tmp_device[c] != NULL)
          {
            if (hc_mtlReleaseMemObject (hashcat_ctx, tmp_device[c]) == -1) return -1;
          }
        }

        hcfree (tmp_device);
      }

      hc_mtlReleaseCommandQueue (hashcat_ctx, command_queue);

      if (device_param->device_host_unified_memory == 1)
      {
        // so, we actually have only half the memory because we need the same buffers on host side

        device_param->device_available_mem /= 2;
      }
    }
  }
  #endif // __APPLE__

  if (backend_ctx->ocl)
  {
    for (int backend_devices_cnt = 0; backend_devices_cnt < backend_ctx->backend_devices_cnt; backend_devices_cnt++)
    {
      hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_cnt];

      if (device_param->is_opencl == false) continue;

      if (user_options->backend_info == 0)
      {
        // do not ignore in case -I because user expects a value also for skipped devices

        if (device_param->skipped == true) continue;
      }

      /**
       * create context for each device
       */

      cl_context context;

      /*
      cl_context_properties properties[3];

      properties[0] = CL_CONTEXT_PLATFORM;
      properties[1] = (cl_context_properties) device_param->opencl_platform;
      properties[2] = 0;

      CL_rc = hc_clCreateContext (hashcat_ctx, properties, 1, &device_param->opencl_device, NULL, NULL, &context);
      */

      if (hc_clCreateContext (hashcat_ctx, NULL, 1, &device_param->opencl_device, NULL, NULL, &context) == -1)
      {
        device_param->skipped = true;

        backend_ctx->opencl_devices_active--;
        backend_ctx->backend_devices_active--;
        continue;
      }

      /**
       * create command-queue
       */

      cl_command_queue command_queue;

      if (hc_clCreateCommandQueue (hashcat_ctx, context, device_param->opencl_device, 0, &command_queue) == -1)
      {
        device_param->skipped = true;

        backend_ctx->opencl_devices_active--;
        backend_ctx->backend_devices_active--;
        continue;
      }

      // instruction set

      if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_AMD))
      {
        #define RUN_INSTRUCTION_CHECKS() \
          device_param->has_vadd     = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_ADD_U32     %0, vcc, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vaddc    = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_ADDC_U32    %0, vcc, 0, 0, vcc;\" : \"=v\"(r1)); }"); \
          device_param->has_vadd_co  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_ADD_CO_U32  %0, vcc, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vaddc_co = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_ADDC_CO_U32 %0, vcc, 0, 0, vcc;\" : \"=v\"(r1)); }"); \
          device_param->has_vsub     = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_SUB_U32     %0, vcc, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vsubb    = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_SUBB_U32    %0, vcc, 0, 0, vcc;\" : \"=v\"(r1)); }"); \
          device_param->has_vsub_co  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_SUB_CO_U32  %0, vcc, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vsubb_co = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_SUBB_CO_U32 %0, vcc, 0, 0, vcc;\" : \"=v\"(r1)); }"); \
          device_param->has_vadd3    = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_ADD3_U32    %0,   0, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vbfe     = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_BFE_U32     %0,   0, 0, 0;\"      : \"=v\"(r1)); }"); \
          device_param->has_vperm    = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r1; __asm__ __volatile__ (\"V_PERM_B32    %0,   0, 0, 0;\"      : \"=v\"(r1)); }"); \

        if (backend_devices_idx > 0)
        {
          hc_device_param_t *device_param_prev = &devices_param[backend_devices_idx - 1];

          if (is_same_device_type (device_param, device_param_prev) == true)
          {
            device_param->has_vadd     = device_param_prev->has_vadd;
            device_param->has_vaddc    = device_param_prev->has_vaddc;
            device_param->has_vadd_co  = device_param_prev->has_vadd_co;
            device_param->has_vaddc_co = device_param_prev->has_vaddc_co;
            device_param->has_vsub     = device_param_prev->has_vsub;
            device_param->has_vsubb    = device_param_prev->has_vsubb;
            device_param->has_vsub_co  = device_param_prev->has_vsub_co;
            device_param->has_vsubb_co = device_param_prev->has_vsubb_co;
            device_param->has_vadd3    = device_param_prev->has_vadd3;
            device_param->has_vbfe     = device_param_prev->has_vbfe;
            device_param->has_vperm    = device_param_prev->has_vperm;
          }
          else
          {
            RUN_INSTRUCTION_CHECKS();
          }
        }
        else
        {
          RUN_INSTRUCTION_CHECKS();
        }

        #undef RUN_INSTRUCTION_CHECKS
      }

      if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_NV))
      {
        // replaced with fixed values see non time intensive section above

        /*
        #define RUN_INSTRUCTION_CHECKS()                                                                                                                                                                                                          \
          device_param->has_add   = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"add.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                        \
          device_param->has_addc  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"addc.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                       \
          device_param->has_sub   = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"sub.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                        \
          device_param->has_subc  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"subc.cc.u32 %0, 0, 0;\" : \"=r\"(r)); }");                                       \
          device_param->has_bfe   = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"bfe.u32 %0, 0, 0, 0;\" : \"=r\"(r)); }");                                        \
          device_param->has_lop3  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"lop3.b32 %0, 0, 0, 0, 0;\" : \"=r\"(r)); }");                                    \
          device_param->has_mov64 = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { ulong r; uint a; uint b; asm volatile (\"mov.b64 %0, {%1, %2};\" : \"=l\"(r) : \"r\"(a), \"r\"(b)); }"); \
          device_param->has_prmt  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"prmt.b32 %0, 0, 0, 0;\" : \"=r\"(r)); }");                                       \

        if (backend_devices_idx > 0)
        {
          hc_device_param_t *device_param_prev = &devices_param[backend_devices_idx - 1];

          if (is_same_device_type (device_param, device_param_prev) == true)
          {
            device_param->has_add   = device_param_prev->has_add;
            device_param->has_addc  = device_param_prev->has_addc;
            device_param->has_sub   = device_param_prev->has_sub;
            device_param->has_subc  = device_param_prev->has_subc;
            device_param->has_bfe   = device_param_prev->has_bfe;
            device_param->has_lop3  = device_param_prev->has_lop3;
            device_param->has_mov64 = device_param_prev->has_mov64;
            device_param->has_prmt  = device_param_prev->has_prmt;
          }
          else
          {
            RUN_INSTRUCTION_CHECKS();
          }
        }
        else
        {
          RUN_INSTRUCTION_CHECKS();
        }

        #undef RUN_INSTRUCTION_CHECKS
        */
      }

      // available device memory
      // This test causes an GPU memory usage spike.
      // In case there are multiple hashcat instances starting at the same time this will cause GPU out of memory errors which otherwise would not exist.
      // We will simply not run it if that device was skipped by the user.

      #define MAX_ALLOC_CHECKS_CNT  8192
      #define MAX_ALLOC_CHECKS_SIZE (64 * 1024 * 1024)

      device_param->device_available_mem = device_param->device_global_mem - MAX_ALLOC_CHECKS_SIZE;

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
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

          OCL_PTR *ocl = (OCL_PTR *) backend_ctx->ocl;

          tmp_device[c] = ocl->clCreateBuffer (context, CL_MEM_READ_WRITE, MAX_ALLOC_CHECKS_SIZE, NULL, &CL_err);

          if (CL_err != CL_SUCCESS)
          {
            c--;

            break;
          }

          // transfer only a few byte should be enough to force the runtime to actually allocate the memory

          u8 tmp_host[8];

          if (ocl->clEnqueueReadBuffer  (command_queue, tmp_device[c], CL_TRUE, 0, sizeof (tmp_host), tmp_host, 0, NULL, NULL) != CL_SUCCESS) break;
          if (ocl->clEnqueueWriteBuffer (command_queue, tmp_device[c], CL_TRUE, 0, sizeof (tmp_host), tmp_host, 0, NULL, NULL) != CL_SUCCESS) break;

          if (ocl->clEnqueueReadBuffer  (command_queue, tmp_device[c], CL_TRUE, MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), sizeof (tmp_host), tmp_host, 0, NULL, NULL) != CL_SUCCESS) break;
          if (ocl->clEnqueueWriteBuffer (command_queue, tmp_device[c], CL_TRUE, MAX_ALLOC_CHECKS_SIZE - sizeof (tmp_host), sizeof (tmp_host), tmp_host, 0, NULL, NULL) != CL_SUCCESS) break;
        }

        device_param->device_available_mem = MAX_ALLOC_CHECKS_SIZE;

        if (c > 0)
        {
          device_param->device_available_mem *= c;
        }

        // clean up

        for (c = 0; c < MAX_ALLOC_CHECKS_CNT; c++)
        {
          if (((c + 1 + 1) * MAX_ALLOC_CHECKS_SIZE) >= device_param->device_global_mem) break;

          if (tmp_device[c] != NULL)
          {
            if (hc_clReleaseMemObject (hashcat_ctx, tmp_device[c]) == -1) return -1;
          }
        }

        hcfree (tmp_device);
      }

      hc_clReleaseCommandQueue (hashcat_ctx, command_queue);

      hc_clReleaseContext (hashcat_ctx, context);

      if (device_param->device_host_unified_memory == 1)
      {
        // so, we actually have only half the memory because we need the same buffers on host side

        device_param->device_available_mem /= 2;
      }
    }
  }

  // check again to catch error on OpenCL/Metal
  if (backend_ctx->backend_devices_active == 0)
  {
    event_log_error (hashcat_ctx, "No devices found/left.");

    return -1;
  }

  backend_ctx->target_msec  = TARGET_MSEC_PROFILE[user_options->workload_profile - 1];

  backend_ctx->need_adl           = need_adl;
  backend_ctx->need_nvml          = need_nvml;
  backend_ctx->need_nvapi         = need_nvapi;
  backend_ctx->need_sysfs_amdgpu  = need_sysfs_amdgpu;
  backend_ctx->need_sysfs_cpu     = need_sysfs_cpu;
  backend_ctx->need_iokit         = need_iokit;

  backend_ctx->comptime = comptime;

  return 0;
}

void backend_ctx_devices_destroy (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return;

  for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < backend_ctx->opencl_platforms_cnt; opencl_platforms_idx++)
  {
    hcfree (backend_ctx->opencl_platforms_devices[opencl_platforms_idx]);
    hcfree (backend_ctx->opencl_platforms_name[opencl_platforms_idx]);
    hcfree (backend_ctx->opencl_platforms_vendor[opencl_platforms_idx]);
    hcfree (backend_ctx->opencl_platforms_version[opencl_platforms_idx]);
  }

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    hcfree (device_param->device_name);

    if (device_param->is_opencl == true)
    {
      hcfree (device_param->opencl_driver_version);
      hcfree (device_param->opencl_device_version);
      hcfree (device_param->opencl_device_c_version);
      hcfree (device_param->opencl_device_vendor);
    }
  }

  backend_ctx->backend_devices_cnt    = 0;
  backend_ctx->backend_devices_active = 0;
  backend_ctx->cuda_devices_cnt       = 0;
  backend_ctx->cuda_devices_active    = 0;
  backend_ctx->hip_devices_cnt        = 0;
  backend_ctx->hip_devices_active     = 0;
  backend_ctx->metal_devices_cnt      = 0;
  backend_ctx->metal_devices_active   = 0;
  backend_ctx->opencl_devices_cnt     = 0;
  backend_ctx->opencl_devices_active  = 0;

  backend_ctx->need_adl           = false;
  backend_ctx->need_nvml          = false;
  backend_ctx->need_nvapi         = false;
  backend_ctx->need_sysfs_amdgpu  = false;
  backend_ctx->need_sysfs_cpu     = false;
  backend_ctx->need_iokit         = false;
}

void backend_ctx_devices_sync_tuning (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;
  hashconfig_t  *hashconfig  = hashcat_ctx->hashconfig;

  if (backend_ctx->enabled == false) return;

  for (int backend_devices_cnt_src = 0; backend_devices_cnt_src < backend_ctx->backend_devices_cnt; backend_devices_cnt_src++)
  {
    hc_device_param_t *device_param_src = &backend_ctx->devices_param[backend_devices_cnt_src];

    if (device_param_src->skipped == true) continue;
    if (device_param_src->skipped_warning == true) continue;

    for (int backend_devices_cnt_dst = backend_devices_cnt_src + 1; backend_devices_cnt_dst < backend_ctx->backend_devices_cnt; backend_devices_cnt_dst++)
    {
      hc_device_param_t *device_param_dst = &backend_ctx->devices_param[backend_devices_cnt_dst];

      if (device_param_dst->skipped == true) continue;
      if (device_param_dst->skipped_warning == true) continue;

      if (is_same_device_type (device_param_src, device_param_dst) == false) continue;

      device_param_dst->kernel_accel   = device_param_src->kernel_accel;
      device_param_dst->kernel_loops   = device_param_src->kernel_loops;
      device_param_dst->kernel_threads = device_param_src->kernel_threads;

      const u32 hardware_power = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param_dst->device_processors) * device_param_dst->kernel_threads;

      device_param_dst->hardware_power = hardware_power;

      const u32 kernel_power = device_param_dst->hardware_power * device_param_dst->kernel_accel;

      device_param_dst->kernel_power = kernel_power;
    }
  }
}

void backend_ctx_devices_update_power (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  status_ctx_t         *status_ctx          = hashcat_ctx->status_ctx;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  user_options_t       *user_options        = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return;

  u32 kernel_power_all = 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    kernel_power_all += device_param->kernel_power;
  }

  backend_ctx->kernel_power_all = kernel_power_all;

  /*
   * Inform user about possible slow speeds
   */

  if ((user_options_extra->wordlist_mode == WL_MODE_FILE) || (user_options_extra->wordlist_mode == WL_MODE_MASK))
  {
    if (status_ctx->words_base < kernel_power_all)
    {
      if (user_options->quiet == false)
      {
        clear_prompt (hashcat_ctx);

        event_log_advice (hashcat_ctx, "The wordlist or mask that you are using is too small.");
        event_log_advice (hashcat_ctx, "This means that hashcat cannot use the full parallel power of your device(s).");
        event_log_advice (hashcat_ctx, "Unless you supply more work, your cracking speed will drop.");
        event_log_advice (hashcat_ctx, "For tips on supplying more work, see: https://hashcat.net/faq/morework");
        event_log_advice (hashcat_ctx, NULL);
      }
    }
  }
}

void backend_ctx_devices_kernel_loops (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t     *combinator_ctx      = hashcat_ctx->combinator_ctx;
  hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  hashes_t             *hashes              = hashcat_ctx->hashes;
  mask_ctx_t           *mask_ctx            = hashcat_ctx->mask_ctx;
  backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  user_options_t       *user_options        = hashcat_ctx->user_options;
  user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;

  if (backend_ctx->enabled == false) return;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

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

static int get_cuda_kernel_wgs (hashcat_ctx_t *hashcat_ctx, CUfunction function, u32 *result)
{
  int max_threads_per_block;

  if (hc_cuFuncGetAttribute (hashcat_ctx, &max_threads_per_block, CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK, function) == -1) return -1;

  *result = (u32) max_threads_per_block;

  return 0;
}

static int get_cuda_kernel_local_mem_size (hashcat_ctx_t *hashcat_ctx, CUfunction function, u64 *result)
{
  int shared_size_bytes;

  if (hc_cuFuncGetAttribute (hashcat_ctx, &shared_size_bytes, CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES, function) == -1) return -1;

  *result = (u64) shared_size_bytes;

  return 0;
}

static int get_hip_kernel_wgs (hashcat_ctx_t *hashcat_ctx, hipFunction_t function, u32 *result)
{
  int max_threads_per_block;

  if (hc_hipFuncGetAttribute (hashcat_ctx, &max_threads_per_block, HIP_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK, function) == -1) return -1;

  *result = (u32) max_threads_per_block;

  return 0;
}

static int get_hip_kernel_local_mem_size (hashcat_ctx_t *hashcat_ctx, hipFunction_t function, u64 *result)
{
  int shared_size_bytes;

  if (hc_hipFuncGetAttribute (hashcat_ctx, &shared_size_bytes, HIP_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES, function) == -1) return -1;

  *result = (u64) shared_size_bytes;

  return 0;
}

static int get_opencl_kernel_wgs (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u32 *result)
{
  size_t work_group_size = 0;

  if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->opencl_device, CL_KERNEL_WORK_GROUP_SIZE, sizeof (work_group_size), &work_group_size, NULL) == -1) return -1;

  u32 kernel_threads = (u32) work_group_size;

  size_t compile_work_group_size[3] = { 0, 0, 0 };

  if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->opencl_device, CL_KERNEL_COMPILE_WORK_GROUP_SIZE, sizeof (compile_work_group_size), &compile_work_group_size, NULL) == -1) return -1;

  const size_t cwgs_total = compile_work_group_size[0] * compile_work_group_size[1] * compile_work_group_size[2];

  if (cwgs_total > 0)
  {
    kernel_threads = MIN (kernel_threads, (u32) cwgs_total);
  }

  *result = kernel_threads;

  return 0;
}

static int get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u32 *result)
{
  size_t preferred_work_group_size_multiple = 0;

  if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->opencl_device, CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof (preferred_work_group_size_multiple), &preferred_work_group_size_multiple, NULL) == -1) return -1;

  *result = (u32) preferred_work_group_size_multiple;

  return 0;
}

static int get_opencl_kernel_local_mem_size (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u64 *result)
{
  cl_ulong local_mem_size = 0;

  if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->opencl_device, CL_KERNEL_LOCAL_MEM_SIZE, sizeof (local_mem_size), &local_mem_size, NULL) == -1) return -1;

  *result = local_mem_size;

  return 0;
}

static int get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_kernel kernel, u64 *result)
{
  cl_ulong dynamic_local_mem_size = 0;

  if (hc_clGetKernelWorkGroupInfo (hashcat_ctx, kernel, device_param->opencl_device, CL_KERNEL_LOCAL_MEM_SIZE, sizeof (dynamic_local_mem_size), &dynamic_local_mem_size, NULL) == -1) return -1;

  // unknown how to query this information in OpenCL
  // we therefore reset to zero
  // the above call to hc_clGetKernelWorkGroupInfo() is just to avoid compiler warnings

  dynamic_local_mem_size = 0;

  *result = dynamic_local_mem_size;

  return 0;
}

#if defined (__APPLE__)
static bool load_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const char *kernel_name, char *source_file, char *cached_file, const char *build_options_buf, const bool cache_disable, cl_program *opencl_program, CUmodule *cuda_module, hipModule_t *hip_module, mtl_library *metal_library)
#else
static bool load_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const char *kernel_name, char *source_file, char *cached_file, const char *build_options_buf, const bool cache_disable, cl_program *opencl_program, CUmodule *cuda_module, hipModule_t *hip_module, MAYBE_UNUSED void *metal_library)
#endif
{
  const hashconfig_t    *hashconfig    = hashcat_ctx->hashconfig;
  const user_options_t  *user_options  = hashcat_ctx->user_options;
  const folder_config_t *folder_config = hashcat_ctx->folder_config;

  bool cached = true;

  if (cache_disable == true)
  {
    cached = false;
  }

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
    if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache. Please be patient...", device_param->device_id + 1, filename_from_filepath (cached_file));
    #endif

    if (read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources) == false) return false;

    if (device_param->is_cuda == true)
    {
      nvrtcProgram program;

      if (hc_nvrtcCreateProgram (hashcat_ctx, &program, kernel_sources[0], kernel_name, 0, NULL, NULL) == -1) return false;

      char **nvrtc_options = (char **) hccalloc (7 + strlen (build_options_buf) + 1, sizeof (char *)); // ...

      nvrtc_options[0] = "--restrict";
      nvrtc_options[1] = "--device-as-default-execution-space";
      nvrtc_options[2] = "--gpu-architecture";

      hc_asprintf (&nvrtc_options[3], "compute_%d%d", device_param->sm_major, device_param->sm_minor);

      // untested on windows, but it should work
      #if defined (_WIN) || defined (__CYGWIN__) || defined (__MSYS__)
      hc_asprintf (&nvrtc_options[4], "-D INCLUDE_PATH=%s", "OpenCL");
      #else
      hc_asprintf (&nvrtc_options[4], "-D INCLUDE_PATH=%s", folder_config->cpath_real);
      #endif

      hc_asprintf (&nvrtc_options[5], "-D XM2S(x)=#x");
      hc_asprintf (&nvrtc_options[6], "-D M2S(x)=XM2S(x)");

      char *nvrtc_options_string = hcstrdup (build_options_buf);

      const int num_options = 7 + nvrtc_make_options_array_from_string (nvrtc_options_string, nvrtc_options + 7);

      const int rc_nvrtcCompileProgram = hc_nvrtcCompileProgram (hashcat_ctx, program, num_options, (const char * const *) nvrtc_options);

      hcfree (nvrtc_options_string);
      hcfree (nvrtc_options);

      size_t build_log_size = 0;

      hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

      #if defined (DEBUG)
      if ((build_log_size > 1) || (rc_nvrtcCompileProgram == -1))
      #else
      if (rc_nvrtcCompileProgram == -1)
      #endif
      {
        char *build_log = (char *) hcmalloc (build_log_size + 1);

        if (hc_nvrtcGetProgramLog (hashcat_ctx, program, build_log) == -1)
        {
          hcfree (build_log);

          return false;
        }

        build_log[build_log_size] = 0;

        puts (build_log);

        hcfree (build_log);
      }

      if (rc_nvrtcCompileProgram == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

        return false;
      }

      size_t binary_size = 0;

      if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &binary_size) == -1) return false;

      char *binary = (char *) hcmalloc (binary_size);

      if (hc_nvrtcGetPTX (hashcat_ctx, program, binary) == -1) return false;

      if (hc_nvrtcDestroyProgram (hashcat_ctx, &program) == -1) return false;

      #define LOG_SIZE 8192

      char *mod_info_log  = (char *) hcmalloc (LOG_SIZE + 1);
      char *mod_error_log = (char *) hcmalloc (LOG_SIZE + 1);

      int mod_cnt = 6;

      CUjit_option mod_opts[7];
      void *mod_vals[7];

      mod_opts[0] = CU_JIT_TARGET_FROM_CUCONTEXT;
      mod_vals[0] = (void *) 0;

      mod_opts[1] = CU_JIT_LOG_VERBOSE;
      mod_vals[1] = (void *) 1;

      mod_opts[2] = CU_JIT_INFO_LOG_BUFFER;
      mod_vals[2] = (void *) mod_info_log;

      mod_opts[3] = CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES;
      mod_vals[3] = (void *) LOG_SIZE;

      mod_opts[4] = CU_JIT_ERROR_LOG_BUFFER;
      mod_vals[4] = (void *) mod_error_log;

      mod_opts[5] = CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES;
      mod_vals[5] = (void *) LOG_SIZE;

      if (hashconfig->opti_type & OPTI_TYPE_REGISTER_LIMIT)
      {
        mod_opts[6] = CU_JIT_MAX_REGISTERS;
        mod_vals[6] = (void *) 128;

        mod_cnt++;
      }

      #if defined (WITH_CUBIN)

      char *jit_info_log  = (char *) hcmalloc (LOG_SIZE + 1);
      char *jit_error_log = (char *) hcmalloc (LOG_SIZE + 1);

      int jit_cnt = 6;

      CUjit_option jit_opts[7];
      void *jit_vals[7];

      jit_opts[0] = CU_JIT_TARGET_FROM_CUCONTEXT;
      jit_vals[0] = (void *) 0;

      jit_opts[1] = CU_JIT_LOG_VERBOSE;
      jit_vals[1] = (void *) 1;

      jit_opts[2] = CU_JIT_INFO_LOG_BUFFER;
      jit_vals[2] = (void *) jit_info_log;

      jit_opts[3] = CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES;
      jit_vals[3] = (void *) LOG_SIZE;

      jit_opts[4] = CU_JIT_ERROR_LOG_BUFFER;
      jit_vals[4] = (void *) jit_error_log;

      jit_opts[5] = CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES;
      jit_vals[5] = (void *) LOG_SIZE;

      if (hashconfig->opti_type & OPTI_TYPE_REGISTER_LIMIT)
      {
        jit_opts[6] = CU_JIT_MAX_REGISTERS;
        jit_vals[6] = (void *) 128;

        jit_cnt++;
      }

      CUlinkState state;

      if (hc_cuLinkCreate (hashcat_ctx, jit_cnt, jit_opts, jit_vals, &state) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s link failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", jit_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      if (hc_cuLinkAddData (hashcat_ctx, state, CU_JIT_INPUT_PTX, binary, binary_size, kernel_name, 0, NULL, NULL) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s link failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", jit_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      void *cubin = NULL;

      size_t cubin_size = 0;

      if (hc_cuLinkComplete (hashcat_ctx, state, &cubin, &cubin_size) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s link failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", jit_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s link successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", jit_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      if (hc_cuModuleLoadDataEx (hashcat_ctx, cuda_module, cubin, mod_cnt, mod_opts, mod_vals) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s load failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", mod_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", mod_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      if (cache_disable == false)
      {
        if (write_kernel_binary (hashcat_ctx, cached_file, cubin, cubin_size) == false) return false;
      }

      if (hc_cuLinkDestroy (hashcat_ctx, state) == -1) return false;

      hcfree (jit_info_log);
      hcfree (jit_error_log);

      #else

      if (hc_cuModuleLoadDataEx (hashcat_ctx, cuda_module, binary, mod_cnt, mod_opts, mod_vals) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s load failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", mod_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", mod_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      if (cache_disable == false)
      {
        if (write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size) == false) return false;
      }

      #endif

      hcfree (mod_info_log);
      hcfree (mod_error_log);

      hcfree (binary);
    }

    if (device_param->is_hip == true)
    {
      hiprtcProgram program;

      if (hc_hiprtcCreateProgram (hashcat_ctx, &program, kernel_sources[0], kernel_name, 0, NULL, NULL) == -1) return false;

      char **hiprtc_options = (char **) hccalloc (8 + strlen (build_options_buf) + 1, sizeof (char *)); // ...

      //hiprtc_options[0] = "--restrict";
      //hiprtc_options[1] = "--device-as-default-execution-space";
      //hiprtc_options[2] = "--gpu-architecture";

      hc_asprintf (&hiprtc_options[0], "--gpu-max-threads-per-block=%d", (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : device_param->kernel_threads_max);

      /* 4.3 linux
      hiprtc_options[1] = "-I";
      hiprtc_options[2] = "/opt/rocm/hip/bin/include";
      hiprtc_options[3] = "-I";
      hiprtc_options[4] = "/opt/rocm/include";
      hiprtc_options[5] = "-I";
      */

      hiprtc_options[1] = "-nocudainc";
      hiprtc_options[2] = "-nocudalib";
      hiprtc_options[3] = "-flegacy-pass-manager";
      hiprtc_options[4] = "";

      // untested but it should work
      #if defined (_WIN) || defined (__CYGWIN__) || defined (__MSYS__)
      hc_asprintf (&hiprtc_options[5], "-D INCLUDE_PATH=%s/OpenCL/", folder_config->cwd);
      // ugly, but required since HIPRTC is changing the current working folder to the temporary compile folder
      #else
      hc_asprintf (&hiprtc_options[5], "-D INCLUDE_PATH=%s", folder_config->cpath_real);
      #endif

      hc_asprintf (&hiprtc_options[6], "-D XM2S(x)=#x");
      hc_asprintf (&hiprtc_options[7], "-D M2S(x)=XM2S(x)");

      char *hiprtc_options_string = hcstrdup (build_options_buf);

      const int num_options = 8 + hiprtc_make_options_array_from_string (hiprtc_options_string, hiprtc_options + 8);

      const int rc_hiprtcCompileProgram = hc_hiprtcCompileProgram (hashcat_ctx, program, num_options, (const char * const *) hiprtc_options);

      hcfree (hiprtc_options_string);
      hcfree (hiprtc_options);

      size_t build_log_size = 0;

      hc_hiprtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

      #if defined (DEBUG)
      if ((build_log_size > 1) || (rc_hiprtcCompileProgram == -1))
      #else
      if (rc_hiprtcCompileProgram == -1)
      #endif
      {
        char *build_log = (char *) hcmalloc (build_log_size + 1);

        if (hc_hiprtcGetProgramLog (hashcat_ctx, program, build_log) == -1)
        {
          hcfree (build_log);

          return false;
        }

        build_log[build_log_size] = 0;

        puts (build_log);

        hcfree (build_log);
      }

      if (rc_hiprtcCompileProgram == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

        return false;
      }

      size_t binary_size = 0;

      if (hc_hiprtcGetCodeSize (hashcat_ctx, program, &binary_size) == -1) return false;

      char *binary = (char *) hcmalloc (binary_size);

      if (hc_hiprtcGetCode (hashcat_ctx, program, binary) == -1) return false;

      if (hc_hiprtcDestroyProgram (hashcat_ctx, &program) == -1) return false;

      #define LOG_SIZE 8192

      char *mod_info_log  = (char *) hcmalloc (LOG_SIZE + 1);
      char *mod_error_log = (char *) hcmalloc (LOG_SIZE + 1);

      int mod_cnt = 6;

      hipJitOption mod_opts[6];
      void *mod_vals[6];

      mod_opts[0] = hipJitOptionTargetFromContext;
      mod_vals[0] = (void *) 0;

      mod_opts[1] = hipJitOptionLogVerbose;
      mod_vals[1] = (void *) 1;

      mod_opts[2] = hipJitOptionInfoLogBuffer;
      mod_vals[2] = (void *) mod_info_log;

      mod_opts[3] = hipJitOptionInfoLogBufferSizeBytes;
      mod_vals[3] = (void *) LOG_SIZE;

      mod_opts[4] = hipJitOptionErrorLogBuffer;
      mod_vals[4] = (void *) mod_error_log;

      mod_opts[5] = hipJitOptionErrorLogBufferSizeBytes;
      mod_vals[5] = (void *) LOG_SIZE;

      if (hc_hipModuleLoadDataEx (hashcat_ctx, hip_module, binary, mod_cnt, mod_opts, mod_vals) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s load failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", mod_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", mod_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      if (cache_disable == false)
      {
        if (write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size) == false) return false;
      }

      hcfree (mod_info_log);
      hcfree (mod_error_log);

      hcfree (binary);
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      mtl_library metal_lib = NULL;

      if (hc_mtlCreateLibraryWithSource (hashcat_ctx, device_param->metal_device, kernel_sources[0], build_options_buf, folder_config->cpath_real, &metal_lib) == -1) return false;

      *metal_library = metal_lib;

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful.", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, NULL);
      #endif
    }
    #endif // __APPLE__

    if (device_param->is_opencl == true)
    {
      size_t build_log_size = 0;

      int CL_rc;

      cl_program p1 = NULL;

      // workaround opencl issue with Apple Silicon

      if (strncmp (device_param->device_name, "Apple M", 7) == 0)
      {
        if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) kernel_sources, NULL, opencl_program) == -1) return false;

        CL_rc = hc_clBuildProgram (hashcat_ctx, *opencl_program, 1, &device_param->opencl_device, build_options_buf, NULL, NULL);

        hc_clGetProgramBuildInfo (hashcat_ctx, *opencl_program, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);
      }
      else
      {
        if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) kernel_sources, NULL, &p1) == -1) return false;

        CL_rc = hc_clCompileProgram (hashcat_ctx, p1, 1, &device_param->opencl_device, build_options_buf, 0, NULL, NULL, NULL, NULL);

        hc_clGetProgramBuildInfo (hashcat_ctx, p1, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);
      }

      #if defined (DEBUG)
      if ((build_log_size > 1) || (CL_rc == -1))
      #else
      if (CL_rc == -1)
      #endif
      {
        char *build_log = (char *) hcmalloc (build_log_size + 1);

        int rc_clGetProgramBuildInfo;

        if (strncmp (device_param->device_name, "Apple M", 7) == 0)
        {
          rc_clGetProgramBuildInfo = hc_clGetProgramBuildInfo (hashcat_ctx, *opencl_program, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);
        }
        else
        {
          rc_clGetProgramBuildInfo = hc_clGetProgramBuildInfo (hashcat_ctx, p1, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);
        }

        if (rc_clGetProgramBuildInfo == -1)
        {
          hcfree (build_log);

          return false;
        }

        build_log[build_log_size] = 0;

        puts (build_log);

        hcfree (build_log);
      }

      if (CL_rc == -1) return false;

      // workaround opencl issue with Apple Silicon

      if (strncmp (device_param->device_name, "Apple M", 7) != 0)
      {
        cl_program t2[1];

        t2[0] = p1;

        cl_program fin;

        if (hc_clLinkProgram (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, NULL, 1, t2, NULL, NULL, &fin) == -1) return false;

        // it seems errors caused by clLinkProgram() do not go into CL_PROGRAM_BUILD
        // I couldn't find any information on the web explaining how else to retrieve the error messages from the linker

        *opencl_program = fin;

        hc_clReleaseProgram (hashcat_ctx, p1);
      }

      if (cache_disable == false)
      {
        size_t binary_size;

        if (hc_clGetProgramInfo (hashcat_ctx, *opencl_program, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL) == -1) return false;

        char *binary = (char *) hcmalloc (binary_size);

        if (hc_clGetProgramInfo (hashcat_ctx, *opencl_program, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL) == -1) return false;

        if (write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size) == false) return false;

        hcfree (binary);
      }
    }
  }
  else
  {
    if (read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources) == false) return false;

    if (device_param->is_cuda == true)
    {
      #define LOG_SIZE 8192

      char *mod_info_log  = (char *) hcmalloc (LOG_SIZE + 1);
      char *mod_error_log = (char *) hcmalloc (LOG_SIZE + 1);

      int mod_cnt = 6;

      CUjit_option mod_opts[7];
      void *mod_vals[7];

      mod_opts[0] = CU_JIT_TARGET_FROM_CUCONTEXT;
      mod_vals[0] = (void *) 0;

      mod_opts[1] = CU_JIT_LOG_VERBOSE;
      mod_vals[1] = (void *) 1;

      mod_opts[2] = CU_JIT_INFO_LOG_BUFFER;
      mod_vals[2] = (void *) mod_info_log;

      mod_opts[3] = CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES;
      mod_vals[3] = (void *) LOG_SIZE;

      mod_opts[4] = CU_JIT_ERROR_LOG_BUFFER;
      mod_vals[4] = (void *) mod_error_log;

      mod_opts[5] = CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES;
      mod_vals[5] = (void *) LOG_SIZE;

      if (hashconfig->opti_type & OPTI_TYPE_REGISTER_LIMIT)
      {
        mod_opts[6] = CU_JIT_MAX_REGISTERS;
        mod_vals[6] = (void *) 128;

        mod_cnt++;
      }

      if (hc_cuModuleLoadDataEx (hashcat_ctx, cuda_module, kernel_sources[0], mod_cnt, mod_opts, mod_vals) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s load failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", mod_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", mod_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      hcfree (mod_info_log);
      hcfree (mod_error_log);
    }

    if (device_param->is_hip == true)
    {
      #define LOG_SIZE 8192

      char *mod_info_log  = (char *) hcmalloc (LOG_SIZE + 1);
      char *mod_error_log = (char *) hcmalloc (LOG_SIZE + 1);

      int mod_cnt = 6;

      hipJitOption mod_opts[6];
      void *mod_vals[6];

      mod_opts[0] = hipJitOptionTargetFromContext;
      mod_vals[0] = (void *) 0;

      mod_opts[1] = hipJitOptionLogVerbose;
      mod_vals[1] = (void *) 1;

      mod_opts[2] = hipJitOptionInfoLogBuffer;
      mod_vals[2] = (void *) mod_info_log;

      mod_opts[3] = hipJitOptionInfoLogBufferSizeBytes;
      mod_vals[3] = (void *) LOG_SIZE;

      mod_opts[4] = hipJitOptionErrorLogBuffer;
      mod_vals[4] = (void *) mod_error_log;

      mod_opts[5] = hipJitOptionErrorLogBufferSizeBytes;
      mod_vals[5] = (void *) LOG_SIZE;

      if (hc_hipModuleLoadDataEx (hashcat_ctx, hip_module, kernel_sources[0], mod_cnt, mod_opts, mod_vals) == -1)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s load failed. Error Log:", device_param->device_id + 1, source_file);
        event_log_error (hashcat_ctx, "%s", mod_error_log);
        event_log_error (hashcat_ctx, NULL);

        return false;
      }

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful. Info Log:", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, "%s", mod_info_log);
      event_log_info (hashcat_ctx, NULL);
      #endif

      hcfree (mod_info_log);
      hcfree (mod_error_log);
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      mtl_library metal_lib = NULL;

      if (hc_mtlCreateLibraryWithFile (hashcat_ctx, device_param->metal_device, cached_file, &metal_lib) == -1) return false;

      *metal_library = metal_lib;

      #if defined (DEBUG)
      event_log_info (hashcat_ctx, "* Device #%u: Kernel %s load successful.", device_param->device_id + 1, source_file);
      event_log_info (hashcat_ctx, NULL);
      #endif
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clCreateProgramWithBinary (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, kernel_lengths, (const unsigned char **) kernel_sources, NULL, opencl_program) == -1) return false;

      if (hc_clBuildProgram (hashcat_ctx, *opencl_program, 1, &device_param->opencl_device, build_options_buf, NULL, NULL) == -1) return false;
    }
  }

  hcfree (kernel_sources[0]);

  return true;
}

int backend_session_begin (hashcat_ctx_t *hashcat_ctx)
{
  const bitmap_ctx_t         *bitmap_ctx          = hashcat_ctx->bitmap_ctx;
  const folder_config_t      *folder_config       = hashcat_ctx->folder_config;
  const hashconfig_t         *hashconfig          = hashcat_ctx->hashconfig;
  const hashes_t             *hashes              = hashcat_ctx->hashes;
  const module_ctx_t         *module_ctx          = hashcat_ctx->module_ctx;
        backend_ctx_t        *backend_ctx         = hashcat_ctx->backend_ctx;
  const straight_ctx_t       *straight_ctx        = hashcat_ctx->straight_ctx;
  const user_options_extra_t *user_options_extra  = hashcat_ctx->user_options_extra;
  const user_options_t       *user_options        = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  u64 size_total_host_all = 0;

  u32 hardware_power_all = 0;

  int backend_memory_hit_warnings    = 0;
  int backend_runtime_skip_warnings  = 0;
  int backend_kernel_build_warnings  = 0;
  int backend_kernel_create_warnings = 0;
  int backend_kernel_accel_warnings  = 0;
  int backend_extra_size_warning     = 0;

  backend_ctx->memory_hit_warning    = false;
  backend_ctx->runtime_skip_warning  = false;
  backend_ctx->kernel_build_warning  = false;
  backend_ctx->kernel_create_warning = false;
  backend_ctx->kernel_accel_warnings = false;
  backend_ctx->extra_size_warning    = false;
  backend_ctx->mixed_warnings        = false;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    /**
     * host buffer
     */

    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;

    EVENT_DATA (EVENT_BACKEND_DEVICE_INIT_PRE, &backend_devices_idx, sizeof (int));

    const int device_id = device_param->device_id;

    /**
     * module depending checks
     */

    device_param->skipped_warning = false;

    if (module_ctx->module_unstable_warning != MODULE_DEFAULT)
    {
      const bool unstable_warning = module_ctx->module_unstable_warning (hashconfig, user_options, user_options_extra, device_param);

      if ((unstable_warning == true) && (user_options->force == false))
      {
        char runtime_name[7];

        memset (runtime_name, 0, sizeof (runtime_name));

        if (device_param->is_cuda   == true) memcpy (runtime_name, "CUDA", 4);
        if (device_param->is_hip    == true) memcpy (runtime_name, "HIP", 3);
        #if defined (__APPLE__)
        if (device_param->is_metal  == true) memcpy (runtime_name, "Metal", 5);
        #endif
        if (device_param->is_opencl == true) memcpy (runtime_name, "OpenCL", 6);

        event_log_warning (hashcat_ctx, "* Device #%u: Skipping (hash-mode %u)", device_id + 1, hashconfig->hash_mode);
        event_log_warning (hashcat_ctx, "             This is due to a known %s runtime and/or device driver issue (not a hashcat issue)", runtime_name);
        event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");
        event_log_warning (hashcat_ctx, NULL);

        backend_runtime_skip_warnings++;

        device_param->skipped_warning = true;
        continue;
      }
    }

    /**
     * tuning db
     */

    if (module_ctx->module_extra_tuningdb_block != MODULE_DEFAULT)
    {
      const char *extra_tuningdb_block = module_ctx->module_extra_tuningdb_block (hashconfig, user_options, user_options_extra);

      char *lines_buf = hcstrdup (extra_tuningdb_block);

      char *saveptr = NULL;

      char *next = strtok_r (lines_buf, "\n", &saveptr);

      int line_num = 0;

      do
      {
        line_num++;

        const size_t line_len = strlen (next);

        if (line_len == 0) continue;

        if (next[0] == '#') continue;

        tuning_db_process_line (hashcat_ctx, next, line_num);

      } while ((next = strtok_r ((char *) NULL, "\n", &saveptr)) != NULL);

      hcfree (lines_buf);

      // todo: print loaded 'cnt' message

      // sort the database

      tuning_db_t *tuning_db = hashcat_ctx->tuning_db;

      qsort (tuning_db->alias_buf, tuning_db->alias_cnt, sizeof (tuning_db_alias_t), sort_by_tuning_db_alias);
      qsort (tuning_db->entry_buf, tuning_db->entry_cnt, sizeof (tuning_db_entry_t), sort_by_tuning_db_entry);
    }

    // vector_width

    int vector_width = 0;

    if (user_options->backend_vector_width_chgd == false)
    {
      // tuning db

      tuning_db_entry_t *tuningdb_entry;

      if (user_options->slow_candidates == true)
      {
        tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->opencl_device_type, 0, hashconfig->hash_mode);
      }
      else
      {
        tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->opencl_device_type, user_options->attack_mode, hashconfig->hash_mode);
      }

      if (tuningdb_entry == NULL || tuningdb_entry->vector_width == -1)
      {
        if (hashconfig->opti_type & OPTI_TYPE_USES_BITS_64)
        {
          if (device_param->is_cuda == true)
          {
            // cuda does not support this query

            vector_width = 1;
          }

          if (device_param->is_hip == true)
          {
            // hip does not support this query

            vector_width = 1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            // Metal does not support this query

            vector_width = 1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, sizeof (vector_width), &vector_width, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }
          }
        }
        else
        {
          if (device_param->is_cuda == true)
          {
            // cuda does not support this query

            vector_width = 1;
          }

          if (device_param->is_hip == true)
          {
            // hip does not support this query

            vector_width = 1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            // Metal does not support this query

            vector_width = 1;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,  sizeof (vector_width), &vector_width, NULL) == -1)
            {
              device_param->skipped = true;
              continue;
            }
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
      vector_width = user_options->backend_vector_width;
    }

    // Metal supports vectors up to 4

    if (device_param->is_metal == true && vector_width > 4)
    {
      vector_width = 4;
    }

    // We can't have SIMD in kernels where we have an unknown final password length
    // It also turns out that pure kernels (that have a higher register pressure)
    // actually run faster on scalar GPU (like 1080) without SIMD

    if ((hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL) == 0)
    {
      if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        vector_width = 1;
      }
    }

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // not working in this mode because the GID does not align with password candidate count
      // and if it cracks, it will crack the same hash twice, running into segfaults

      vector_width = 1;
    }

    if (vector_width > 16) vector_width = 16;

    device_param->vector_width = vector_width;

    /**
     * kernel accel and loops tuning db adjustment
     */

    device_param->kernel_accel_min   = hashconfig->kernel_accel_min;
    device_param->kernel_accel_max   = hashconfig->kernel_accel_max;
    device_param->kernel_loops_min   = hashconfig->kernel_loops_min;
    device_param->kernel_loops_max   = hashconfig->kernel_loops_max;
    device_param->kernel_threads_min = hashconfig->kernel_threads_min;
    device_param->kernel_threads_max = hashconfig->kernel_threads_max;

    tuning_db_entry_t *tuningdb_entry = NULL;

    if (user_options->slow_candidates == true)
    {
      tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->opencl_device_type, 0, hashconfig->hash_mode);
    }
    else
    {
      tuningdb_entry = tuning_db_search (hashcat_ctx, device_param->device_name, device_param->opencl_device_type, user_options->attack_mode, hashconfig->hash_mode);
    }

    // user commandline option override tuning db
    // but both have to stay inside the boundaries of the module

    if (user_options->kernel_accel_chgd == true)
    {
      const u32 _kernel_accel = user_options->kernel_accel;

      if ((_kernel_accel >= device_param->kernel_accel_min) && (_kernel_accel <= device_param->kernel_accel_max))
      {
        device_param->kernel_accel_min = _kernel_accel;
        device_param->kernel_accel_max = _kernel_accel;
      }
    }
    else
    {
      if (tuningdb_entry != NULL)
      {
        const u32 _kernel_accel = tuningdb_entry->kernel_accel;

        if (_kernel_accel == (u32) -1) // native, makes sense if OPTS_TYPE_MP_MULTI_DISABLE is used
        {
          if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
          {
            if (module_ctx->module_extra_tuningdb_block != MODULE_DEFAULT)
            {
              event_log_warning (hashcat_ctx, "ATTENTION! This hash-mode requires manual tuning to achieve full performance.");
              event_log_warning (hashcat_ctx, "The loss of performance can be greater than 100%% without manual tuning.");
              event_log_warning (hashcat_ctx, NULL);
              event_log_warning (hashcat_ctx, "This warning message disappears after a definition for the installed");
              event_log_warning (hashcat_ctx, "compute-device in this computer has been added to either list:");
              event_log_warning (hashcat_ctx, "- src/modules/module_%05d.c", hashconfig->hash_mode);
              event_log_warning (hashcat_ctx, "- hashcat.hctune");
              event_log_warning (hashcat_ctx, NULL);
              event_log_warning (hashcat_ctx, "For instructions on tuning, see src/modules/module_%05d.c", hashconfig->hash_mode);
              event_log_warning (hashcat_ctx, "Also, consider sending a PR to Hashcat Master so that other users can benefit from your work.");
              event_log_warning (hashcat_ctx, NULL);
            }
          }

          device_param->kernel_accel_min = device_param->device_processors;
          device_param->kernel_accel_max = device_param->device_processors;
        }
        else
        {
          if (_kernel_accel)
          {
            if ((_kernel_accel >= device_param->kernel_accel_min) && (_kernel_accel <= device_param->kernel_accel_max))
            {
              device_param->kernel_accel_min = _kernel_accel;
              device_param->kernel_accel_max = _kernel_accel;
            }
          }
        }
      }
    }

    if (user_options->kernel_loops_chgd == true)
    {
      const u32 _kernel_loops = user_options->kernel_loops;

      if ((_kernel_loops >= device_param->kernel_loops_min) && (_kernel_loops <= device_param->kernel_loops_max))
      {
        device_param->kernel_loops_min = _kernel_loops;
        device_param->kernel_loops_max = _kernel_loops;
      }
    }
    else
    {
      if (tuningdb_entry != NULL)
      {
        u32 _kernel_loops = tuningdb_entry->kernel_loops;

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

          if ((_kernel_loops >= device_param->kernel_loops_min) && (_kernel_loops <= device_param->kernel_loops_max))
          {
            device_param->kernel_loops_min = _kernel_loops;
            device_param->kernel_loops_max = _kernel_loops;
          }
        }
      }
    }

    // there's no thread column in tuning db, stick to commandline if defined

    if (user_options->kernel_threads_chgd == true)
    {
      const u32 _kernel_threads = user_options->kernel_threads;

      if ((_kernel_threads >= device_param->kernel_threads_min) && (_kernel_threads <= device_param->kernel_threads_max))
      {
        device_param->kernel_threads_min = _kernel_threads;
        device_param->kernel_threads_max = _kernel_threads;
      }
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

    device_param->kernel_loops_min_sav = device_param->kernel_loops_min;
    device_param->kernel_loops_max_sav = device_param->kernel_loops_max;

    /**
     * device properties
     */

    const u32 device_processors = device_param->device_processors;

    /**
     * device threads
     */

    if (hashconfig->opts_type & OPTS_TYPE_MAXIMUM_THREADS)
    {
      // default for all, because the else branch is doing the same (nothing), but is actually used as a way to
      // disable the default native thread configuration for HIP
      // this can have negative performance if not tested on multiple different gpu architectures
    }
    else if (hashconfig->opts_type & OPTS_TYPE_NATIVE_THREADS)
    {
      u32 native_threads = 0;

      if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
      {
        native_threads = 1;
      }
      else if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
      {
        native_threads = device_param->kernel_preferred_wgs_multiple;
      }
      else
      {
        // abort?
      }

      if ((native_threads >= device_param->kernel_threads_min) && (native_threads <= device_param->kernel_threads_max))
      {
        device_param->kernel_threads_min = native_threads;
        device_param->kernel_threads_max = native_threads;
      }
      else
      {
        // abort?
      }
    }
    else
    {
      if (device_param->is_hip == true)
      {
        const u32 native_threads = device_param->kernel_preferred_wgs_multiple;

        if ((native_threads >= device_param->kernel_threads_min) && (native_threads <= device_param->kernel_threads_max))
        {
          device_param->kernel_threads_min = native_threads;
          device_param->kernel_threads_max = native_threads;
        }
        else
        {
          // abort?
        }
      }
    }

    // this seems to work always

    if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      u32 native_threads = 1;

      if ((native_threads >= device_param->kernel_threads_min) && (native_threads <= device_param->kernel_threads_max))
      {
        device_param->kernel_threads_min = native_threads;
        device_param->kernel_threads_max = native_threads;
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      // set some limits with Metal

      device_param->kernel_threads_max = 128;
      device_param->kernel_loops_max = 1024;  // autotune go over ...
    }
    #endif

    /**
     * create context for each device
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuCtxCreate (hashcat_ctx, &device_param->cuda_context, CU_CTX_SCHED_BLOCKING_SYNC, device_param->cuda_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipCtxCreate (hashcat_ctx, &device_param->hip_context, hipDeviceScheduleBlockingSync, device_param->hip_device) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipCtxPushCurrent (hashcat_ctx, device_param->hip_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      /**
       * create command-queue
       */

      if (hc_mtlCreateCommandQueue (hashcat_ctx, device_param->metal_device, &device_param->metal_command_queue) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }
    #endif

    if (device_param->is_opencl == true)
    {
      /*
      cl_context_properties properties[3];

      properties[0] = CL_CONTEXT_PLATFORM;
      properties[1] = (cl_context_properties) device_param->opencl_platform;
      properties[2] = 0;

      CL_rc = hc_clCreateContext (hashcat_ctx, properties, 1, &device_param->opencl_device, NULL, NULL, &device_param->opencl_context);
      */

      if (hc_clCreateContext (hashcat_ctx, NULL, 1, &device_param->opencl_device, NULL, NULL, &device_param->opencl_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      /**
       * create command-queue
       */

      // not supported with NV
      // device_param->opencl_command_queue = hc_clCreateCommandQueueWithProperties (hashcat_ctx, device_param->opencl_device, NULL);

      if (hc_clCreateCommandQueue (hashcat_ctx, device_param->opencl_context, device_param->opencl_device, CL_QUEUE_PROFILING_ENABLE, &device_param->opencl_command_queue) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    /**
     * create stream for CUDA devices
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuStreamCreate (hashcat_ctx, &device_param->cuda_stream, CU_STREAM_DEFAULT) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    /**
     * create stream for HIP devices
     */

    if (device_param->is_hip == true)
    {
      if (hc_hipStreamCreate (hashcat_ctx, &device_param->hip_stream, hipStreamDefault) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    /**
     * create events for CUDA devices
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuEventCreate (hashcat_ctx, &device_param->cuda_event1, CU_EVENT_BLOCKING_SYNC) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuEventCreate (hashcat_ctx, &device_param->cuda_event2, CU_EVENT_BLOCKING_SYNC) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_cuEventCreate (hashcat_ctx, &device_param->cuda_event3, CU_EVENT_DISABLE_TIMING) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    /**
     * create events for HIP devices
     */

    if (device_param->is_hip == true)
    {
      if (hc_hipEventCreate (hashcat_ctx, &device_param->hip_event1, hipEventBlockingSync) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipEventCreate (hashcat_ctx, &device_param->hip_event2, hipEventBlockingSync) == -1)
      {
        device_param->skipped = true;
        continue;
      }

      if (hc_hipEventCreate (hashcat_ctx, &device_param->hip_event3, hipEventDisableTiming) == -1)
      {
        device_param->skipped = true;
        continue;
      }
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

    device_param->size_rules    = size_rules;
    device_param->size_rules_c  = size_rules_c;

    u64 size_plains  = (u64) hashes->digests_cnt * sizeof (plain_t);
    u64 size_salts   = (u64) hashes->salts_cnt   * sizeof (salt_t);
    u64 size_esalts  = (u64) hashes->digests_cnt * hashconfig->esalt_size;
    u64 size_shown   = (u64) hashes->digests_cnt * sizeof (u32);
    u64 size_digests = (u64) hashes->digests_cnt * (u64) hashconfig->dgst_size;

    device_param->size_plains   = size_plains;
    device_param->size_digests  = size_digests;
    device_param->size_shown    = size_shown;
    device_param->size_salts    = size_salts;
    device_param->size_esalts   = size_esalts;

    u64 size_combs          = KERNEL_COMBS * sizeof (pw_t);
    u64 size_bfs            = KERNEL_BFS   * sizeof (bf_t);
    u64 size_tm             = 32           * sizeof (bs_word_t);
    u64 size_kernel_params  = 1            * sizeof (kernel_param_t);

    device_param->size_bfs           = size_bfs;
    device_param->size_combs         = size_combs;
    device_param->size_tm            = size_tm;
    device_param->size_kernel_params = size_kernel_params;

    u64 size_st_digests = 1 * hashconfig->dgst_size;
    u64 size_st_salts   = 1 * sizeof (salt_t);
    u64 size_st_esalts  = 1 * hashconfig->esalt_size;

    device_param->size_st_digests = size_st_digests;
    device_param->size_st_salts   = size_st_salts;
    device_param->size_st_esalts  = size_st_esalts;

    // extra buffer

    u64 size_extra_buffer = 4;

    if (module_ctx->module_extra_buffer_size != MODULE_DEFAULT)
    {
      const u64 extra_buffer_size = module_ctx->module_extra_buffer_size (hashconfig, user_options, user_options_extra, hashes, device_param);

      if (extra_buffer_size == (u64) -1)
      {
        event_log_error (hashcat_ctx, "Invalid extra buffer size.");

        backend_extra_size_warning++;

        device_param->skipped_warning = true;
        continue;
      }

      device_param->extra_buffer_size = extra_buffer_size;

      // for the size we actually allocate we need to cheat a bit in order to make it more easy for plugin developer.
      //
      // we will divide this size by 4 to workaround opencl limitation.
      // this collides with a theoretical scenario (like -n1 -T1) where there's only one workitem,
      // because inside the kernel the target buffer is selected by workitem_id / 4.
      // but the maximum size of the buffer would be only 1/4 of what is needed -> overflow.
      //
      // to workaround this we make sure that there's always a full buffer in each of the 4 allocated buffers available.

      const u64 kernel_power_max = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_param->device_processors) * device_param->kernel_threads_max * device_param->kernel_accel_max;

      const u64 extra_buffer_size_one = extra_buffer_size / kernel_power_max;

      size_extra_buffer = extra_buffer_size + (extra_buffer_size_one * 4);
    }

    // kern type

    u32 kern_type = hashconfig->kern_type;

    if (module_ctx->module_kern_type_dynamic != MODULE_DEFAULT)
    {
      if (user_options->benchmark == true)
      {
      }
      else
      {
        void        *digests_buf    = hashes->digests_buf;
        salt_t      *salts_buf      = hashes->salts_buf;
        void        *esalts_buf     = hashes->esalts_buf;
        void        *hook_salts_buf = hashes->hook_salts_buf;
        hashinfo_t **hash_info      = hashes->hash_info;

        hashinfo_t *hash_info_ptr = NULL;

        if (hash_info) hash_info_ptr = hash_info[0];

        kern_type = (u32) module_ctx->module_kern_type_dynamic (hashconfig, digests_buf, salts_buf, esalts_buf, hook_salts_buf, hash_info_ptr);
      }
    }

    // built options

    const size_t build_options_sz = 4096;

    char *build_options_buf = (char *) hcmalloc (build_options_sz);

    int build_options_len = snprintf (build_options_buf, build_options_sz, "-D KERNEL_STATIC ");

    if ((device_param->is_cuda == true) || (device_param->is_hip == true))
    {
      // using a path with a space will break nvrtc_make_options_array_from_string()
      // we add it to options array in a clean way later
    }
    else
    {
      #if defined (_WIN) || defined (__CYGWIN__) || defined (__MSYS__)
      // workaround for AMD
      if (device_param->opencl_platform_vendor_id == VENDOR_ID_AMD && device_param->opencl_device_vendor_id == VENDOR_ID_AMD)
      {
        build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-I . ");
      }

      // when built with cygwin or msys, cpath_real doesn't work
      build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D INCLUDE_PATH=%s ", "OpenCL");
      #else
      const char *build_options_include_fmt = (strchr (folder_config->cpath_real, ' ') != NULL) ? "-D INCLUDE_PATH=\"%s\" " : "-D INCLUDE_PATH=%s ";

      build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, build_options_include_fmt, folder_config->cpath_real);
      #endif

      build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D XM2S(x)=#x ");
      build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D M2S(x)=XM2S(x) ");

      #if defined (__APPLE__)
      if (is_apple_silicon () == true)
      {
        build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D IS_APPLE_SILICON ");
      }
      #endif
    }

    /* currently disabled, hangs NEO drivers since 20.09.
       was required for NEO driver 20.08 to workaround the same issue!
       we go with the latest version

    if (device_param->is_opencl == true)
    {
      if (device_param->use_opencl12 == true)
      {
        build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-cl-std=CL1.2 ");
      }
      else if (device_param->use_opencl20 == true)
      {
        build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-cl-std=CL2.0 ");
      }
      else if (device_param->use_opencl21 == true)
      {
        build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-cl-std=CL2.1 ");
      }
    }
    */

    // we don't have sm_* on vendors not NV but it doesn't matter

    #if defined (DEBUG)
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D LOCAL_MEM_TYPE=%d -D VENDOR_ID=%u -D CUDA_ARCH=%u -D HAS_ADD=%u -D HAS_ADDC=%u -D HAS_SUB=%u -D HAS_SUBC=%u -D HAS_VADD=%u -D HAS_VADDC=%u -D HAS_VADD_CO=%u -D HAS_VADDC_CO=%u -D HAS_VSUB=%u -D HAS_VSUBB=%u -D HAS_VSUB_CO=%u -D HAS_VSUBB_CO=%u -D HAS_VPERM=%u -D HAS_VADD3=%u -D HAS_VBFE=%u -D HAS_BFE=%u -D HAS_LOP3=%u -D HAS_MOV64=%u -D HAS_PRMT=%u -D VECT_SIZE=%d -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D ATTACK_EXEC=%u -D ATTACK_KERN=%u -D ATTACK_MODE=%u ", device_param->device_local_mem_type, device_param->opencl_platform_vendor_id, (device_param->sm_major * 100) + (device_param->sm_minor * 10), device_param->has_add, device_param->has_addc, device_param->has_sub, device_param->has_subc, device_param->has_vadd, device_param->has_vaddc, device_param->has_vadd_co, device_param->has_vaddc_co, device_param->has_vsub, device_param->has_vsubb, device_param->has_vsub_co, device_param->has_vsubb_co, device_param->has_vperm, device_param->has_vadd3, device_param->has_vbfe, device_param->has_bfe, device_param->has_lop3, device_param->has_mov64, device_param->has_prmt, device_param->vector_width, (u32) device_param->opencl_device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, kern_type, hashconfig->attack_exec, user_options_extra->attack_kern, user_options->attack_mode);
    #else
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D LOCAL_MEM_TYPE=%d -D VENDOR_ID=%u -D CUDA_ARCH=%u -D HAS_ADD=%u -D HAS_ADDC=%u -D HAS_SUB=%u -D HAS_SUBC=%u -D HAS_VADD=%u -D HAS_VADDC=%u -D HAS_VADD_CO=%u -D HAS_VADDC_CO=%u -D HAS_VSUB=%u -D HAS_VSUBB=%u -D HAS_VSUB_CO=%u -D HAS_VSUBB_CO=%u -D HAS_VPERM=%u -D HAS_VADD3=%u -D HAS_VBFE=%u -D HAS_BFE=%u -D HAS_LOP3=%u -D HAS_MOV64=%u -D HAS_PRMT=%u -D VECT_SIZE=%d -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D ATTACK_EXEC=%u -D ATTACK_KERN=%u -D ATTACK_MODE=%u -w ", device_param->device_local_mem_type, device_param->opencl_platform_vendor_id, (device_param->sm_major * 100) + (device_param->sm_minor * 10), device_param->has_add, device_param->has_addc, device_param->has_sub, device_param->has_subc, device_param->has_vadd, device_param->has_vaddc, device_param->has_vadd_co, device_param->has_vaddc_co, device_param->has_vsub, device_param->has_vsubb, device_param->has_vsub_co, device_param->has_vsubb_co, device_param->has_vperm, device_param->has_vadd3, device_param->has_vbfe, device_param->has_bfe, device_param->has_lop3, device_param->has_mov64, device_param->has_prmt, device_param->vector_width, (u32) device_param->opencl_device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, kern_type, hashconfig->attack_exec, user_options_extra->attack_kern, user_options->attack_mode);
    #endif

    build_options_buf[build_options_len] = 0;

    /*
    if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
    {
      if (device_param->opencl_platform_vendor_id == VENDOR_ID_INTEL_SDK)
      {
        strncat (build_options_buf, " -cl-opt-disable", 16);
      }
    }
    */

    #if defined (DEBUG)
    if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: build_options '%s'", device_id + 1, build_options_buf);
    #endif

    /**
     * device_name_chksum_amp_mp
     */

    char device_name_chksum_amp_mp[HCBUFSIZ_TINY] = { 0 };

    const size_t dnclen_amp_mp = snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%d-%d-%d-%u-%d-%u-%s-%s-%s-%u",
      backend_ctx->comptime,
      backend_ctx->cuda_driver_version,
      backend_ctx->hip_runtimeVersion,
      backend_ctx->metal_runtimeVersion,
      device_param->is_opencl,
      device_param->opencl_platform_vendor_id,
      device_param->device_name,
      device_param->opencl_device_version,
      device_param->opencl_driver_version,
      (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : device_param->kernel_threads_max);

    md5_ctx_t md5_ctx;

    md5_init   (&md5_ctx);
    md5_update (&md5_ctx, (u32 *) device_name_chksum_amp_mp, dnclen_amp_mp);
    md5_final  (&md5_ctx);

    snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%08x", md5_ctx.h[0]);

    /**
     * kernel cache
     */

    bool cache_disable = false;

    // Seems to be completely broken on Apple + (Intel?) CPU
    // To reproduce set cache_disable to false and run benchmark -b

    if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
    {
      if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
      {
        cache_disable = true;
      }
    }

    if (module_ctx->module_jit_cache_disable != MODULE_DEFAULT)
    {
      cache_disable = module_ctx->module_jit_cache_disable (hashconfig, user_options, user_options_extra, hashes, device_param);
    }

    #if defined (DEBUG)
    // https://github.com/hashcat/hashcat/issues/2750
    cache_disable = true;
    #endif

    /**
     * shared kernel with no hashconfig dependencies
     */

    {
      /**
       * kernel shared source filename
       */

      char source_file[256] = { 0 };

      generate_source_kernel_shared_filename (folder_config->shared_dir, source_file);

      if (hc_path_read (source_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", source_file, strerror (errno));

        return -1;
      }

      /**
       * kernel shared cached filename
       */

      char cached_file[256] = { 0 };

      generate_cached_kernel_shared_filename (folder_config->cache_dir, device_name_chksum_amp_mp, cached_file, device_param->is_metal);

      #if defined (__APPLE__)
      const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "shared_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_shared, &device_param->cuda_module_shared, &device_param->hip_module_shared, &device_param->metal_library_shared);
      #else
      const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "shared_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_shared, &device_param->cuda_module_shared, &device_param->hip_module_shared, NULL);
      #endif

      if (rc_load_kernel == false)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

        return -1;
      }

      if (device_param->is_cuda == true)
      {
        // GPU memset

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_memset, device_param->cuda_module_shared, "gpu_memset") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_memset");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_memset, &device_param->kernel_wgs_memset) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_memset, &device_param->kernel_local_mem_size_memset) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_memset = device_param->device_local_mem_size - device_param->kernel_local_mem_size_memset;

        device_param->kernel_preferred_wgs_multiple_memset = device_param->cuda_warp_size;

        // GPU bzero

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_bzero, device_param->cuda_module_shared, "gpu_bzero") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_bzero");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_bzero, &device_param->kernel_wgs_bzero) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_bzero, &device_param->kernel_local_mem_size_bzero) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_bzero = device_param->device_local_mem_size - device_param->kernel_local_mem_size_bzero;

        device_param->kernel_preferred_wgs_multiple_bzero = device_param->cuda_warp_size;

        // GPU autotune init

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_atinit, device_param->cuda_module_shared, "gpu_atinit") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_atinit");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_atinit, &device_param->kernel_local_mem_size_atinit) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_atinit = device_param->device_local_mem_size - device_param->kernel_local_mem_size_atinit;

        device_param->kernel_preferred_wgs_multiple_atinit = device_param->cuda_warp_size;

        // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]); if (CL_rc == -1) return -1;
        // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]); if (CL_rc == -1) return -1;

        // GPU decompress

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_decompress, device_param->cuda_module_shared, "gpu_decompress") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_decompress");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_decompress, &device_param->kernel_local_mem_size_decompress) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_decompress = device_param->device_local_mem_size - device_param->kernel_local_mem_size_decompress;

        device_param->kernel_preferred_wgs_multiple_decompress = device_param->cuda_warp_size;

        // GPU utf8 to utf16le conversion

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_utf8toutf16le, device_param->cuda_module_shared, "gpu_utf8_to_utf16") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_utf8_to_utf16");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_utf8toutf16le, &device_param->kernel_wgs_utf8toutf16le) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_utf8toutf16le, &device_param->kernel_local_mem_size_utf8toutf16le) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_utf8toutf16le = device_param->device_local_mem_size - device_param->kernel_local_mem_size_utf8toutf16le;

        device_param->kernel_preferred_wgs_multiple_utf8toutf16le = device_param->cuda_warp_size;
      }

      if (device_param->is_hip == true)
      {
        // GPU memset

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_memset, device_param->hip_module_shared, "gpu_memset") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_memset");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_memset, &device_param->kernel_wgs_memset) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_memset, &device_param->kernel_local_mem_size_memset) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_memset = device_param->device_local_mem_size - device_param->kernel_local_mem_size_memset;

        device_param->kernel_preferred_wgs_multiple_memset = device_param->hip_warp_size;

        // GPU bzero

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_bzero, device_param->hip_module_shared, "gpu_bzero") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_bzero");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_bzero, &device_param->kernel_wgs_bzero) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_bzero, &device_param->kernel_local_mem_size_bzero) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_bzero = device_param->device_local_mem_size - device_param->kernel_local_mem_size_bzero;

        device_param->kernel_preferred_wgs_multiple_bzero = device_param->hip_warp_size;

        // GPU autotune init

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_atinit, device_param->hip_module_shared, "gpu_atinit") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_atinit");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_atinit, &device_param->kernel_local_mem_size_atinit) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_atinit = device_param->device_local_mem_size - device_param->kernel_local_mem_size_atinit;

        device_param->kernel_preferred_wgs_multiple_atinit = device_param->hip_warp_size;

        // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]); if (CL_rc == -1) return -1;
        // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]); if (CL_rc == -1) return -1;

        // GPU decompress

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_decompress, device_param->hip_module_shared, "gpu_decompress") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_decompress");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_decompress, &device_param->kernel_local_mem_size_decompress) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_decompress = device_param->device_local_mem_size - device_param->kernel_local_mem_size_decompress;

        device_param->kernel_preferred_wgs_multiple_decompress = device_param->hip_warp_size;

        // GPU utf8 to utf16le conversion

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_utf8toutf16le, device_param->hip_module_shared, "gpu_utf8_to_utf16") == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_utf8_to_utf16");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_utf8toutf16le, &device_param->kernel_wgs_utf8toutf16le) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_utf8toutf16le, &device_param->kernel_local_mem_size_utf8toutf16le) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size_utf8toutf16le = device_param->device_local_mem_size - device_param->kernel_local_mem_size_utf8toutf16le;

        device_param->kernel_preferred_wgs_multiple_utf8toutf16le = device_param->hip_warp_size;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        // GPU memset

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_shared, "gpu_memset", &device_param->metal_function_memset, &device_param->metal_pipeline_memset) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_memset");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_memset, &device_param->kernel_wgs_memset) == -1) return -1;

        device_param->kernel_local_mem_size_memset = 0;
        device_param->kernel_dynamic_local_mem_size_memset = 0;
        device_param->kernel_preferred_wgs_multiple_memset = device_param->metal_warp_size;

        // GPU bzero

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_shared, "gpu_bzero", &device_param->metal_function_bzero, &device_param->metal_pipeline_bzero) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_bzero");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_bzero, &device_param->kernel_wgs_bzero) == -1) return -1;

        device_param->kernel_local_mem_size_bzero = 0;
        device_param->kernel_dynamic_local_mem_size_bzero = 0;
        device_param->kernel_preferred_wgs_multiple_bzero = device_param->metal_warp_size;

        // GPU autotune init

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_shared, "gpu_atinit", &device_param->metal_function_atinit, &device_param->metal_pipeline_atinit) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_atinit");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

        device_param->kernel_local_mem_size_atinit = 0;
        device_param->kernel_dynamic_local_mem_size_atinit = 0;
        device_param->kernel_preferred_wgs_multiple_atinit = device_param->metal_warp_size;

        // GPU decompress

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_shared, "gpu_decompress", &device_param->metal_function_decompress, &device_param->metal_pipeline_decompress) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_decompress");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

        device_param->kernel_local_mem_size_decompress = 0;
        device_param->kernel_dynamic_local_mem_size_decompress = 0;
        device_param->kernel_preferred_wgs_multiple_decompress = device_param->metal_warp_size;

        // GPU utf8 to utf16le conversion

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_shared, "gpu_utf8_to_utf16", &device_param->metal_function_utf8toutf16le, &device_param->metal_pipeline_utf8toutf16le) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_utf8_to_utf16");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_utf8toutf16le, &device_param->kernel_wgs_utf8toutf16le) == -1) return -1;

        device_param->kernel_local_mem_size_utf8toutf16le = 0;
        device_param->kernel_dynamic_local_mem_size_utf8toutf16le = 0;
        device_param->kernel_preferred_wgs_multiple_utf8toutf16le = device_param->metal_warp_size;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        // GPU memset

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_shared, "gpu_memset", &device_param->opencl_kernel_memset) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_memset");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_wgs_memset) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_local_mem_size_memset) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_dynamic_local_mem_size_memset) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_preferred_wgs_multiple_memset) == -1) return -1;

        // GPU bzero

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_shared, "gpu_bzero", &device_param->opencl_kernel_bzero) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_bzero");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_bzero, &device_param->kernel_wgs_bzero) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_bzero, &device_param->kernel_local_mem_size_bzero) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_bzero, &device_param->kernel_dynamic_local_mem_size_bzero) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_bzero, &device_param->kernel_preferred_wgs_multiple_bzero) == -1) return -1;

        // apple hack, but perhaps also an alternative for other vendors

        if (device_param->kernel_preferred_wgs_multiple == 0) device_param->kernel_preferred_wgs_multiple = device_param->kernel_preferred_wgs_multiple_bzero;

        // GPU autotune init

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_shared, "gpu_atinit", &device_param->opencl_kernel_atinit) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_atinit");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_local_mem_size_atinit) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_dynamic_local_mem_size_atinit) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_preferred_wgs_multiple_atinit) == -1) return -1;

        // GPU decompress

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_shared, "gpu_decompress", &device_param->opencl_kernel_decompress) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_decompress");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_local_mem_size_decompress) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_dynamic_local_mem_size_decompress) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_preferred_wgs_multiple_decompress) == -1) return -1;

        // GPU utf8 to utf16le conversion

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_shared, "gpu_utf8_to_utf16", &device_param->opencl_kernel_utf8toutf16le) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "gpu_utf8_to_utf16");

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_utf8toutf16le, &device_param->kernel_wgs_utf8toutf16le) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_utf8toutf16le, &device_param->kernel_local_mem_size_utf8toutf16le) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_utf8toutf16le, &device_param->kernel_dynamic_local_mem_size_utf8toutf16le) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_utf8toutf16le, &device_param->kernel_preferred_wgs_multiple_utf8toutf16le) == -1) return -1;
      }
    }

    /**
     * main kernel
     */

    {
      char *build_options_module_buf = (char *) hcmalloc (build_options_sz);

      int build_options_module_len = 0;

      build_options_module_len += snprintf (build_options_module_buf + build_options_module_len, build_options_sz - build_options_module_len, "%s ", build_options_buf);

      if (module_ctx->module_jit_build_options != MODULE_DEFAULT)
      {
        char *jit_build_options = module_ctx->module_jit_build_options (hashconfig, user_options, user_options_extra, hashes, device_param);

        if (jit_build_options != NULL)
        {
          build_options_module_len += snprintf (build_options_module_buf + build_options_module_len, build_options_sz - build_options_module_len, "%s", jit_build_options);

          // this is a bit ugly
          // would be better to have the module return the value as value

          u32 fixed_local_size = 0;

          if (sscanf (jit_build_options, "-D FIXED_LOCAL_SIZE=%u", &fixed_local_size) == 1)
          {
            device_param->kernel_threads_min = fixed_local_size;
            device_param->kernel_threads_max = fixed_local_size;
          }
          else
          {
            // kernels specific minimum needs to be set so that self-test wont fail

            if (sscanf (jit_build_options, "-D FIXED_LOCAL_SIZE_COMP=%u", &fixed_local_size) == 1)
            {
              device_param->kernel_threads_min = fixed_local_size;
              // device_param->kernel_threads_max = fixed_local_size;
            }
          }
        }
      }

      build_options_module_buf[build_options_module_len] = 0;

      #if defined (DEBUG)
      if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: build_options_module '%s'", device_id + 1, build_options_module_buf);
      #endif

      /**
       * device_name_chksum
       */

      char device_name_chksum[HCBUFSIZ_TINY] = { 0 };

      // The kernel source can depend on some JiT compiler macros which themself depend on the attack_modes.
      // ATM this is relevant only for ATTACK_MODE_ASSOCIATION which slightly modifies ATTACK_MODE_STRAIGHT kernels.

      const u32 extra_value = (user_options->attack_mode == ATTACK_MODE_ASSOCIATION) ? ATTACK_MODE_ASSOCIATION : ATTACK_MODE_NONE;

      const size_t dnclen = snprintf (device_name_chksum, HCBUFSIZ_TINY, "%d-%d-%d-%u-%d-%u-%s-%s-%s-%d-%u-%u-%u-%s",
        backend_ctx->comptime,
        backend_ctx->cuda_driver_version,
        backend_ctx->hip_runtimeVersion,
        backend_ctx->metal_runtimeVersion,
        device_param->is_opencl,
        device_param->opencl_platform_vendor_id,
        device_param->device_name,
        device_param->opencl_device_version,
        device_param->opencl_driver_version,
        device_param->vector_width,
        hashconfig->kern_type,
        extra_value,
        (user_options->kernel_threads_chgd == true) ? user_options->kernel_threads : device_param->kernel_threads_max,
        build_options_module_buf);

      memset     (&md5_ctx, 0, sizeof (md5_ctx_t));
      md5_init   (&md5_ctx);
      md5_update (&md5_ctx, (u32 *) device_name_chksum, dnclen);
      md5_final  (&md5_ctx);

      snprintf (device_name_chksum, HCBUFSIZ_TINY, "%08x", md5_ctx.h[0]);

      /**
       * kernel source filename
       */

      char source_file[256] = { 0 };

      generate_source_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, kern_type, hashconfig->opti_type, folder_config->shared_dir, source_file);

      if (hc_path_read (source_file) == false)
      {
        event_log_error (hashcat_ctx, "%s: %s", source_file, strerror (errno));

        return -1;
      }

      /**
       * kernel cached filename
       */

      char cached_file[256] = { 0 };

      generate_cached_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, kern_type, hashconfig->opti_type, folder_config->cache_dir, device_name_chksum, cached_file, device_param->is_metal);

      /**
       * load kernel
       */

      #if defined (__APPLE__)
      const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "main_kernel", source_file, cached_file, build_options_module_buf, cache_disable, &device_param->opencl_program, &device_param->cuda_module, &device_param->hip_module, &device_param->metal_library);
      #else
      const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "main_kernel", source_file, cached_file, build_options_module_buf, cache_disable, &device_param->opencl_program, &device_param->cuda_module, &device_param->hip_module, NULL);
      #endif

      if (rc_load_kernel == false)
      {
        event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

        backend_kernel_build_warnings++;

        device_param->skipped_warning = true;
        continue;
      }

      hcfree (build_options_module_buf);
    }

    /**
     * word generator kernel
     */

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      if ((user_options->attack_mode != ATTACK_MODE_STRAIGHT) && (user_options->attack_mode != ATTACK_MODE_ASSOCIATION))
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

        generate_cached_kernel_mp_filename (hashconfig->opti_type, hashconfig->opts_type, folder_config->cache_dir, device_name_chksum_amp_mp, cached_file, device_param->is_metal);

        #if defined (__APPLE__)
        const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "mp_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_mp, &device_param->cuda_module_mp, &device_param->hip_module_mp, &device_param->metal_library_mp);
        #else
        const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "mp_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_mp, &device_param->cuda_module_mp, &device_param->hip_module_mp, NULL);
        #endif

        if (rc_load_kernel == false)
        {
          event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

          return -1;
        }
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

        generate_cached_kernel_amp_filename (user_options_extra->attack_kern, folder_config->cache_dir, device_name_chksum_amp_mp, cached_file, device_param->is_metal);

        #if defined (__APPLE__)
        const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "amp_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_amp, &device_param->cuda_module_amp, &device_param->hip_module_amp, &device_param->metal_library_amp);
        #else
        const bool rc_load_kernel = load_kernel (hashcat_ctx, device_param, "amp_kernel", source_file, cached_file, build_options_buf, cache_disable, &device_param->opencl_program_amp, &device_param->cuda_module_amp, &device_param->hip_module_amp, NULL);
        #endif

        if (rc_load_kernel == false)
        {
          event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed.", device_param->device_id + 1, source_file);

          return -1;
        }

        hcfree (build_options_buf);
      }
    }

    /**
     * no more need for the compiler. cuda doesn't offer this function.
     * from opencl specs:
     * Calls to clBuildProgram, clCompileProgram or clLinkProgram after clUnloadPlatformCompiler will reload the compiler, if necessary, to build the appropriate program executable.
     */
    // Disabled after user reporting weird errors like CL_OUT_OF_HOST_MEMORY after calling
    /*
    if (device_param->is_opencl == true)
    {
      cl_platform_id platform_id = backend_ctx->opencl_platforms[device_param->opencl_platform_id];

      if (hc_clUnloadPlatformCompiler (hashcat_ctx, platform_id) == -1) return -1;
    }
    */

    // some algorithm collide too fast, make that impossible

    if (user_options->benchmark == true)
    {
      ((u32 *) hashes->digests_buf)[0] = -1U;
      ((u32 *) hashes->digests_buf)[1] = -1U;
      ((u32 *) hashes->digests_buf)[2] = -1U;
      ((u32 *) hashes->digests_buf)[3] = -1U;
    }

    /**
     * global buffers
     */

    const u64 size_total_fixed
      = bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + bitmap_ctx->bitmap_size
      + size_plains
      + size_digests
      + size_shown
      + size_salts
      + size_results
      + size_extra_buffer
      + size_st_digests
      + size_st_salts
      + size_st_esalts
      + size_esalts
      + size_markov_css
      + size_root_css
      + size_rules
      + size_rules_c
      + size_tm
      + size_kernel_params;

    if (size_total_fixed > device_param->device_available_mem)
    {
      event_log_error (hashcat_ctx, "* Device #%u: Not enough allocatable device memory for this hashlist/ruleset.", device_id + 1);

      backend_memory_hit_warnings++;

      device_param->skipped_warning = true;
      continue;
    }

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s1_a,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s1_b,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s1_c,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s1_d,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s2_a,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s2_b,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s2_c,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bitmap_s2_d,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_plain_bufs,     size_plains)             == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_digests_buf,    size_digests)            == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_digests_shown,  size_shown)              == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_salt_bufs,      size_salts)              == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_result,         size_results)            == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_extra0_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_extra1_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_extra2_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_extra3_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_st_digests_buf, size_st_digests)         == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_st_salts_buf,   size_st_salts)           == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_kernel_param,   size_kernel_params)      == -1) return -1;

      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s1_a, bitmap_ctx->bitmap_s1_a, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s1_b, bitmap_ctx->bitmap_s1_b, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s1_c, bitmap_ctx->bitmap_s1_c, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s1_d, bitmap_ctx->bitmap_s1_d, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s2_a, bitmap_ctx->bitmap_s2_a, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s2_b, bitmap_ctx->bitmap_s2_b, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s2_c, bitmap_ctx->bitmap_s2_c, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_bitmap_s2_d, bitmap_ctx->bitmap_s2_d, bitmap_ctx->bitmap_size, device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_digests_buf, hashes->digests_buf,     size_digests,            device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_salt_bufs,   hashes->salts_buf,       size_salts,              device_param->cuda_stream) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_rules,   size_rules) == -1) return -1;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            size_t dummy = 0;

            if (hc_cuModuleGetGlobal (hashcat_ctx, &device_param->cuda_d_rules_c, &dummy, device_param->cuda_module, "generic_constant") == -1) return -1;
          }
          else
          {
            if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_rules_c, size_rules_c) == -1) return -1;
          }

          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_rules, straight_ctx->kernel_rules_buf, size_rules, device_param->cuda_stream) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_combs,          size_combs)      == -1) return -1;
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_combs_c,        size_combs)      == -1) return -1;
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_markov_css_buf, size_markov_css) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bfs,            size_bfs)        == -1) return -1;
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_markov_css_buf, size_markov_css) == -1) return -1;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            size_t dummy = 0;

            if (hc_cuModuleGetGlobal (hashcat_ctx, &device_param->cuda_d_bfs_c, &dummy, device_param->cuda_module, "generic_constant") == -1) return -1;

            if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_tm_c,           size_tm)       == -1) return -1;
          }
          else
          {
            if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_bfs_c,          size_bfs)      == -1) return -1;
            if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_tm_c,           size_tm)       == -1) return -1;
          }
        }
      }

      if (size_esalts)
      {
        if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_esalt_bufs, size_esalts) == -1) return -1;

        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_esalt_bufs, hashes->esalts_buf, size_esalts, device_param->cuda_stream) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_st_digests_buf, hashes->st_digests_buf, size_st_digests, device_param->cuda_stream) == -1) return -1;
        if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_st_salts_buf,   hashes->st_salts_buf,   size_st_salts,   device_param->cuda_stream)   == -1) return -1;

        if (size_esalts)
        {
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_st_esalts_buf, size_st_esalts) == -1) return -1;

          if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_st_esalts_buf, hashes->st_esalts_buf, size_st_esalts, device_param->cuda_stream) == -1) return -1;
        }
      }
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s1_a,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s1_b,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s1_c,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s1_d,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s2_a,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s2_b,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s2_c,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bitmap_s2_d,    bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_plain_bufs,     size_plains)             == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_digests_buf,    size_digests)            == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_digests_shown,  size_shown)              == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_salt_bufs,      size_salts)              == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_result,         size_results)            == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_extra0_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_extra1_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_extra2_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_extra3_buf,     size_extra_buffer / 4)   == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_st_digests_buf, size_st_digests)         == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_st_salts_buf,   size_st_salts)           == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_kernel_param,   size_kernel_params)      == -1) return -1;

      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s1_a, bitmap_ctx->bitmap_s1_a, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s1_b, bitmap_ctx->bitmap_s1_b, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s1_c, bitmap_ctx->bitmap_s1_c, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s1_d, bitmap_ctx->bitmap_s1_d, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s2_a, bitmap_ctx->bitmap_s2_a, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s2_b, bitmap_ctx->bitmap_s2_b, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s2_c, bitmap_ctx->bitmap_s2_c, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_bitmap_s2_d, bitmap_ctx->bitmap_s2_d, bitmap_ctx->bitmap_size, device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_digests_buf, hashes->digests_buf,     size_digests,            device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_salt_bufs,   hashes->salts_buf,       size_salts,              device_param->hip_stream) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_rules,   size_rules) == -1) return -1;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            size_t dummy = 0;

            if (hc_hipModuleGetGlobal (hashcat_ctx, &device_param->hip_d_rules_c, &dummy, device_param->hip_module, "generic_constant") == -1) return -1;
          }
          else
          {
            if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_rules_c, size_rules_c) == -1) return -1;
          }

          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_rules, straight_ctx->kernel_rules_buf, size_rules, device_param->hip_stream) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_combs,          size_combs)      == -1) return -1;
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_combs_c,        size_combs)      == -1) return -1;
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_markov_css_buf, size_markov_css) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bfs,            size_bfs)        == -1) return -1;
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_markov_css_buf, size_markov_css) == -1) return -1;

          if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
          {
            size_t dummy = 0;

            if (hc_hipModuleGetGlobal (hashcat_ctx, &device_param->hip_d_bfs_c, &dummy, device_param->hip_module, "generic_constant") == -1) return -1;

            if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_tm_c,           size_tm)       == -1) return -1;
          }
          else
          {
            if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_bfs_c,          size_bfs)      == -1) return -1;
            if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_tm_c,           size_tm)       == -1) return -1;
          }
        }
      }

      if (size_esalts)
      {
        if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_esalt_bufs, size_esalts) == -1) return -1;

        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_esalt_bufs, hashes->esalts_buf, size_esalts, device_param->hip_stream) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_st_digests_buf, hashes->st_digests_buf, size_st_digests, device_param->hip_stream) == -1) return -1;
        if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_st_salts_buf,   hashes->st_salts_buf,   size_st_salts,   device_param->hip_stream) == -1) return -1;

        if (size_esalts)
        {
          if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_st_esalts_buf, size_st_esalts) == -1) return -1;

          if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_st_esalts_buf, hashes->st_esalts_buf, size_st_esalts, device_param->hip_stream) == -1) return -1;
        }
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      // gpu only
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s1_a)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s1_b)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s1_c)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s1_d)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s2_a)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s2_b)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s2_c)    == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, bitmap_ctx->bitmap_size, NULL, &device_param->metal_d_bitmap_s2_d)    == -1) return -1;

      // shared
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_plains,             NULL, &device_param->metal_d_plain_bufs)     == -1) return -1;

      // gpu only
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_digests,            NULL, &device_param->metal_d_digests_buf)    == -1) return -1;

      // shared
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_shown,              NULL, &device_param->metal_d_digests_shown)  == -1) return -1;

      // gpu only
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_salts,              NULL, &device_param->metal_d_salt_bufs)      == -1) return -1;

      // shared
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_results,            NULL, &device_param->metal_d_result)         == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_extra_buffer / 4,   NULL, &device_param->metal_d_extra0_buf)     == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_extra_buffer / 4,   NULL, &device_param->metal_d_extra1_buf)     == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_extra_buffer / 4,   NULL, &device_param->metal_d_extra2_buf)     == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_extra_buffer / 4,   NULL, &device_param->metal_d_extra3_buf)     == -1) return -1;

      // gpu only
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_st_digests,         NULL, &device_param->metal_d_st_digests_buf) == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_st_salts,           NULL, &device_param->metal_d_st_salts_buf)   == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_kernel_params,      NULL, &device_param->metal_d_kernel_param)   == -1) return -1;

      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s1_a, 0, bitmap_ctx->bitmap_s1_a, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s1_b, 0, bitmap_ctx->bitmap_s1_b, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s1_c, 0, bitmap_ctx->bitmap_s1_c, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s1_d, 0, bitmap_ctx->bitmap_s1_d, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s2_a, 0, bitmap_ctx->bitmap_s2_a, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s2_b, 0, bitmap_ctx->bitmap_s2_b, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s2_c, 0, bitmap_ctx->bitmap_s2_c, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_bitmap_s2_d, 0, bitmap_ctx->bitmap_s2_d, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_digests_buf, 0, hashes->digests_buf,     size_digests)            == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_salt_bufs,   0, hashes->salts_buf,       size_salts)              == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        // gpu only
        if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_rules_c, NULL, &device_param->metal_d_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          // gpu only
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_rules, NULL, &device_param->metal_d_rules) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_rules_c, NULL, &device_param->metal_d_rules_c) == -1) return -1;

          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_rules, 0, straight_ctx->kernel_rules_buf, size_rules) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          // gpu only
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_combs, NULL, &device_param->metal_d_combs) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_combs, NULL, &device_param->metal_d_combs_c) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_root_css, NULL, &device_param->metal_d_root_css_buf) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_markov_css, NULL, &device_param->metal_d_markov_css_buf) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          // gpu only
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_bfs, NULL, &device_param->metal_d_bfs) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_bfs, NULL, &device_param->metal_d_bfs_c) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_tm, NULL, &device_param->metal_d_tm_c) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_root_css, NULL, &device_param->metal_d_root_css_buf) == -1) return -1;
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_markov_css, NULL, &device_param->metal_d_markov_css_buf) == -1) return -1;
        }
      }

      if (size_esalts)
      {
        // gpu only
        if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_esalts, NULL, &device_param->metal_d_esalt_bufs) == -1) return -1;

        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_esalt_bufs, 0, hashes->esalts_buf, size_esalts) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_st_digests_buf, 0, hashes->st_digests_buf, size_st_digests) == -1) return -1;
        if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_st_salts_buf, 0, hashes->st_salts_buf, size_st_salts) == -1) return -1;

        if (size_esalts)
        {
          // gpu only
          if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_st_esalts, NULL, &device_param->metal_d_st_esalts_buf) == -1) return -1;

          if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_st_esalts_buf, 0, hashes->st_esalts_buf, size_st_esalts) == -1) return -1;
        }
      }
    }
    #endif // __APPLE__

    if (device_param->is_opencl == true)
    {
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s1_a)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s1_b)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s1_c)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s1_d)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s2_a)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s2_b)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s2_c)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   bitmap_ctx->bitmap_size, NULL, &device_param->opencl_d_bitmap_s2_d)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_plains,             NULL, &device_param->opencl_d_plain_bufs)     == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_digests,            NULL, &device_param->opencl_d_digests_buf)    == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_shown,              NULL, &device_param->opencl_d_digests_shown)  == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_salts,              NULL, &device_param->opencl_d_salt_bufs)      == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_results,            NULL, &device_param->opencl_d_result)         == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_extra_buffer / 4,   NULL, &device_param->opencl_d_extra0_buf)     == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_extra_buffer / 4,   NULL, &device_param->opencl_d_extra1_buf)     == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_extra_buffer / 4,   NULL, &device_param->opencl_d_extra2_buf)     == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_extra_buffer / 4,   NULL, &device_param->opencl_d_extra3_buf)     == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_st_digests,         NULL, &device_param->opencl_d_st_digests_buf) == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_st_salts,           NULL, &device_param->opencl_d_st_salts_buf)   == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_kernel_params,      NULL, &device_param->opencl_d_kernel_param)   == -1) return -1;

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_a, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_a, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_b, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_b, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_c, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_c, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_d, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_d, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_a, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_a, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_b, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_b, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_c, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_c, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_d, CL_FALSE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_d, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_digests_buf, CL_FALSE, 0, size_digests,            hashes->digests_buf,     0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_salt_bufs,   CL_FALSE, 0, size_salts,              hashes->salts_buf,       0, NULL, NULL) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_rules_c, NULL, &device_param->opencl_d_rules_c)   == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_rules,   NULL, &device_param->opencl_d_rules)   == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_rules_c, NULL, &device_param->opencl_d_rules_c) == -1) return -1;

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_rules, CL_FALSE, 0, size_rules, straight_ctx->kernel_rules_buf, 0, NULL, NULL) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->opencl_d_combs)          == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_combs,      NULL, &device_param->opencl_d_combs_c)        == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->opencl_d_root_css_buf)   == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->opencl_d_markov_css_buf) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->opencl_d_bfs)            == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_bfs,        NULL, &device_param->opencl_d_bfs_c)          == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_tm,         NULL, &device_param->opencl_d_tm_c)           == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_root_css,   NULL, &device_param->opencl_d_root_css_buf)   == -1) return -1;
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_markov_css, NULL, &device_param->opencl_d_markov_css_buf) == -1) return -1;
        }
      }

      if (size_esalts)
      {
        if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_esalts, NULL, &device_param->opencl_d_esalt_bufs) == -1) return -1;

        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_esalt_bufs, CL_FALSE, 0, size_esalts, hashes->esalts_buf, 0, NULL, NULL) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_digests_buf,  CL_FALSE, 0, size_st_digests,         hashes->st_digests_buf,  0, NULL, NULL) == -1) return -1;
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_salts_buf,    CL_FALSE, 0, size_st_salts,           hashes->st_salts_buf,    0, NULL, NULL) == -1) return -1;

        if (size_esalts)
        {
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_st_esalts, NULL, &device_param->opencl_d_st_esalts_buf) == -1) return -1;

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_esalts_buf, CL_FALSE, 0, size_st_esalts, hashes->st_esalts_buf, 0, NULL, NULL) == -1) return -1;
        }
      }

      if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
    }

    /**
     * kernel args
     */

    device_param->kernel_param.bitmap_mask         = bitmap_ctx->bitmap_mask;
    device_param->kernel_param.bitmap_shift1       = bitmap_ctx->bitmap_shift1;
    device_param->kernel_param.bitmap_shift2       = bitmap_ctx->bitmap_shift2;
    device_param->kernel_param.salt_pos_host       = 0;
    device_param->kernel_param.loop_pos            = 0;
    device_param->kernel_param.loop_cnt            = 0;
    device_param->kernel_param.il_cnt              = 0;
    device_param->kernel_param.digests_cnt         = 0;
    device_param->kernel_param.digests_offset_host = 0;
    device_param->kernel_param.combs_mode          = 0;
    device_param->kernel_param.salt_repeat         = 0;
    device_param->kernel_param.combs_mode          = 0;
    device_param->kernel_param.salt_repeat         = 0;
    device_param->kernel_param.pws_pos             = 0;
    device_param->kernel_param.gid_max             = 0;

    if (device_param->is_cuda == true)
    {
      device_param->kernel_params[ 0] = NULL; // &device_param->cuda_d_pws_buf;
      device_param->kernel_params[ 1] = &device_param->cuda_d_rules_c;
      device_param->kernel_params[ 2] = &device_param->cuda_d_combs_c;
      device_param->kernel_params[ 3] = &device_param->cuda_d_bfs_c;
      device_param->kernel_params[ 4] = NULL; // &device_param->cuda_d_tmps;
      device_param->kernel_params[ 5] = NULL; // &device_param->cuda_d_hooks;
      device_param->kernel_params[ 6] = &device_param->cuda_d_bitmap_s1_a;
      device_param->kernel_params[ 7] = &device_param->cuda_d_bitmap_s1_b;
      device_param->kernel_params[ 8] = &device_param->cuda_d_bitmap_s1_c;
      device_param->kernel_params[ 9] = &device_param->cuda_d_bitmap_s1_d;
      device_param->kernel_params[10] = &device_param->cuda_d_bitmap_s2_a;
      device_param->kernel_params[11] = &device_param->cuda_d_bitmap_s2_b;
      device_param->kernel_params[12] = &device_param->cuda_d_bitmap_s2_c;
      device_param->kernel_params[13] = &device_param->cuda_d_bitmap_s2_d;
      device_param->kernel_params[14] = &device_param->cuda_d_plain_bufs;
      device_param->kernel_params[15] = &device_param->cuda_d_digests_buf;
      device_param->kernel_params[16] = &device_param->cuda_d_digests_shown;
      device_param->kernel_params[17] = &device_param->cuda_d_salt_bufs;
      device_param->kernel_params[18] = &device_param->cuda_d_esalt_bufs;
      device_param->kernel_params[19] = &device_param->cuda_d_result;
      device_param->kernel_params[20] = &device_param->cuda_d_extra0_buf;
      device_param->kernel_params[21] = &device_param->cuda_d_extra1_buf;
      device_param->kernel_params[22] = &device_param->cuda_d_extra2_buf;
      device_param->kernel_params[23] = &device_param->cuda_d_extra3_buf;
      device_param->kernel_params[24] = &device_param->cuda_d_kernel_param;
    }

    if (device_param->is_hip == true)
    {
      device_param->kernel_params[ 0] = NULL; // &device_param->hip_d_pws_buf;
      device_param->kernel_params[ 1] = &device_param->hip_d_rules_c;
      device_param->kernel_params[ 2] = &device_param->hip_d_combs_c;
      device_param->kernel_params[ 3] = &device_param->hip_d_bfs_c;
      device_param->kernel_params[ 4] = NULL; // &device_param->hip_d_tmps;
      device_param->kernel_params[ 5] = NULL; // &device_param->hip_d_hooks;
      device_param->kernel_params[ 6] = &device_param->hip_d_bitmap_s1_a;
      device_param->kernel_params[ 7] = &device_param->hip_d_bitmap_s1_b;
      device_param->kernel_params[ 8] = &device_param->hip_d_bitmap_s1_c;
      device_param->kernel_params[ 9] = &device_param->hip_d_bitmap_s1_d;
      device_param->kernel_params[10] = &device_param->hip_d_bitmap_s2_a;
      device_param->kernel_params[11] = &device_param->hip_d_bitmap_s2_b;
      device_param->kernel_params[12] = &device_param->hip_d_bitmap_s2_c;
      device_param->kernel_params[13] = &device_param->hip_d_bitmap_s2_d;
      device_param->kernel_params[14] = &device_param->hip_d_plain_bufs;
      device_param->kernel_params[15] = &device_param->hip_d_digests_buf;
      device_param->kernel_params[16] = &device_param->hip_d_digests_shown;
      device_param->kernel_params[17] = &device_param->hip_d_salt_bufs;
      device_param->kernel_params[18] = &device_param->hip_d_esalt_bufs;
      device_param->kernel_params[19] = &device_param->hip_d_result;
      device_param->kernel_params[20] = &device_param->hip_d_extra0_buf;
      device_param->kernel_params[21] = &device_param->hip_d_extra1_buf;
      device_param->kernel_params[22] = &device_param->hip_d_extra2_buf;
      device_param->kernel_params[23] = &device_param->hip_d_extra3_buf;
      device_param->kernel_params[24] = &device_param->hip_d_kernel_param;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      device_param->kernel_params[ 0] = NULL; // device_param->metal_d_pws_buf;
      device_param->kernel_params[ 1] = device_param->metal_d_rules_c;
      device_param->kernel_params[ 2] = device_param->metal_d_combs_c;
      device_param->kernel_params[ 3] = device_param->metal_d_bfs_c;
      device_param->kernel_params[ 4] = NULL; // device_param->metal_d_tmps;
      device_param->kernel_params[ 5] = NULL; // device_param->metal_d_hooks;
      device_param->kernel_params[ 6] = device_param->metal_d_bitmap_s1_a;
      device_param->kernel_params[ 7] = device_param->metal_d_bitmap_s1_b;
      device_param->kernel_params[ 8] = device_param->metal_d_bitmap_s1_c;
      device_param->kernel_params[ 9] = device_param->metal_d_bitmap_s1_d;
      device_param->kernel_params[10] = device_param->metal_d_bitmap_s2_a;
      device_param->kernel_params[11] = device_param->metal_d_bitmap_s2_b;
      device_param->kernel_params[12] = device_param->metal_d_bitmap_s2_c;
      device_param->kernel_params[13] = device_param->metal_d_bitmap_s2_d;
      device_param->kernel_params[14] = device_param->metal_d_plain_bufs;
      device_param->kernel_params[15] = device_param->metal_d_digests_buf;
      device_param->kernel_params[16] = device_param->metal_d_digests_shown;
      device_param->kernel_params[17] = device_param->metal_d_salt_bufs;
      device_param->kernel_params[18] = device_param->metal_d_esalt_bufs;
      device_param->kernel_params[19] = device_param->metal_d_result;
      device_param->kernel_params[20] = device_param->metal_d_extra0_buf;
      device_param->kernel_params[21] = device_param->metal_d_extra1_buf;
      device_param->kernel_params[22] = device_param->metal_d_extra2_buf;
      device_param->kernel_params[23] = device_param->metal_d_extra3_buf;
      device_param->kernel_params[24] = device_param->metal_d_kernel_param;
    }
    #endif // __APPLE__

    if (device_param->is_opencl == true)
    {
      device_param->kernel_params[ 0] = NULL; // &device_param->opencl_d_pws_buf;
      device_param->kernel_params[ 1] = &device_param->opencl_d_rules_c;
      device_param->kernel_params[ 2] = &device_param->opencl_d_combs_c;
      device_param->kernel_params[ 3] = &device_param->opencl_d_bfs_c;
      device_param->kernel_params[ 4] = NULL; // &device_param->opencl_d_tmps;
      device_param->kernel_params[ 5] = NULL; // &device_param->opencl_d_hooks;
      device_param->kernel_params[ 6] = &device_param->opencl_d_bitmap_s1_a;
      device_param->kernel_params[ 7] = &device_param->opencl_d_bitmap_s1_b;
      device_param->kernel_params[ 8] = &device_param->opencl_d_bitmap_s1_c;
      device_param->kernel_params[ 9] = &device_param->opencl_d_bitmap_s1_d;
      device_param->kernel_params[10] = &device_param->opencl_d_bitmap_s2_a;
      device_param->kernel_params[11] = &device_param->opencl_d_bitmap_s2_b;
      device_param->kernel_params[12] = &device_param->opencl_d_bitmap_s2_c;
      device_param->kernel_params[13] = &device_param->opencl_d_bitmap_s2_d;
      device_param->kernel_params[14] = &device_param->opencl_d_plain_bufs;
      device_param->kernel_params[15] = &device_param->opencl_d_digests_buf;
      device_param->kernel_params[16] = &device_param->opencl_d_digests_shown;
      device_param->kernel_params[17] = &device_param->opencl_d_salt_bufs;
      device_param->kernel_params[18] = &device_param->opencl_d_esalt_bufs;
      device_param->kernel_params[19] = &device_param->opencl_d_result;
      device_param->kernel_params[20] = &device_param->opencl_d_extra0_buf;
      device_param->kernel_params[21] = &device_param->opencl_d_extra1_buf;
      device_param->kernel_params[22] = &device_param->opencl_d_extra2_buf;
      device_param->kernel_params[23] = &device_param->opencl_d_extra3_buf;
      device_param->kernel_params[24] = &device_param->opencl_d_kernel_param;
    }

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
        if (device_param->is_cuda == true)
        {
          device_param->kernel_params_mp[0] = &device_param->cuda_d_combs;
        }

        if (device_param->is_hip == true)
        {
          device_param->kernel_params_mp[0] = &device_param->hip_d_combs;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          device_param->kernel_params_mp[0] = device_param->metal_d_combs;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          device_param->kernel_params_mp[0] = &device_param->opencl_d_combs;
        }
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (device_param->is_cuda == true)
          {
            device_param->kernel_params_mp[0] = &device_param->cuda_d_combs;
          }

          if (device_param->is_hip == true)
          {
            device_param->kernel_params_mp[0] = &device_param->hip_d_combs;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            device_param->kernel_params_mp[0] = device_param->metal_d_combs;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            device_param->kernel_params_mp[0] = &device_param->opencl_d_combs;
          }
        }
        else
        {
          device_param->kernel_params_mp[0] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                    // ? &device_param->opencl_d_pws_buf
                                                    // : &device_param->opencl_d_pws_amp_buf;
        }
      }

      if (device_param->is_cuda == true)
      {
        device_param->kernel_params_mp[1] = &device_param->cuda_d_root_css_buf;
        device_param->kernel_params_mp[2] = &device_param->cuda_d_markov_css_buf;
      }

      if (device_param->is_hip == true)
      {
        device_param->kernel_params_mp[1] = &device_param->hip_d_root_css_buf;
        device_param->kernel_params_mp[2] = &device_param->hip_d_markov_css_buf;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        device_param->kernel_params_mp[1] = device_param->metal_d_root_css_buf;
        device_param->kernel_params_mp[2] = device_param->metal_d_markov_css_buf;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        device_param->kernel_params_mp[1] = &device_param->opencl_d_root_css_buf;
        device_param->kernel_params_mp[2] = &device_param->opencl_d_markov_css_buf;
      }

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
                                                  // ? &device_param->opencl_d_pws_buf
                                                  // : &device_param->opencl_d_pws_amp_buf;

      if (device_param->is_cuda == true)
      {
        device_param->kernel_params_mp_l[1] = &device_param->cuda_d_root_css_buf;
        device_param->kernel_params_mp_l[2] = &device_param->cuda_d_markov_css_buf;
      }

      if (device_param->is_hip == true)
      {
        device_param->kernel_params_mp_l[1] = &device_param->hip_d_root_css_buf;
        device_param->kernel_params_mp_l[2] = &device_param->hip_d_markov_css_buf;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        device_param->kernel_params_mp_l[1] = device_param->metal_d_root_css_buf;
        device_param->kernel_params_mp_l[2] = device_param->metal_d_markov_css_buf;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        device_param->kernel_params_mp_l[1] = &device_param->opencl_d_root_css_buf;
        device_param->kernel_params_mp_l[2] = &device_param->opencl_d_markov_css_buf;
      }

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

      if (device_param->is_cuda == true)
      {
        device_param->kernel_params_mp_r[0] = &device_param->cuda_d_bfs;
        device_param->kernel_params_mp_r[1] = &device_param->cuda_d_root_css_buf;
        device_param->kernel_params_mp_r[2] = &device_param->cuda_d_markov_css_buf;
      }

      if (device_param->is_hip == true)
      {
        device_param->kernel_params_mp_r[0] = &device_param->hip_d_bfs;
        device_param->kernel_params_mp_r[1] = &device_param->hip_d_root_css_buf;
        device_param->kernel_params_mp_r[2] = &device_param->hip_d_markov_css_buf;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        device_param->kernel_params_mp_r[0] = device_param->metal_d_bfs;
        device_param->kernel_params_mp_r[1] = device_param->metal_d_root_css_buf;
        device_param->kernel_params_mp_r[2] = device_param->metal_d_markov_css_buf;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        device_param->kernel_params_mp_r[0] = &device_param->opencl_d_bfs;
        device_param->kernel_params_mp_r[1] = &device_param->opencl_d_root_css_buf;
        device_param->kernel_params_mp_r[2] = &device_param->opencl_d_markov_css_buf;
      }

      device_param->kernel_params_mp_r[3] = &device_param->kernel_params_mp_r_buf64[3];
      device_param->kernel_params_mp_r[4] = &device_param->kernel_params_mp_r_buf32[4];
      device_param->kernel_params_mp_r[5] = &device_param->kernel_params_mp_r_buf32[5];
      device_param->kernel_params_mp_r[6] = &device_param->kernel_params_mp_r_buf32[6];
      device_param->kernel_params_mp_r[7] = &device_param->kernel_params_mp_r_buf32[7];
      device_param->kernel_params_mp_r[8] = &device_param->kernel_params_mp_r_buf64[8];

      device_param->kernel_params_amp_buf32[5] = 0; // combs_mode
      device_param->kernel_params_amp_buf64[6] = 0; // gid_max

      if (device_param->is_cuda == true)
      {
        device_param->kernel_params_amp[0] = NULL; // &device_param->cuda_d_pws_buf;
        device_param->kernel_params_amp[1] = NULL; // &device_param->cuda_d_pws_amp_buf;
        device_param->kernel_params_amp[2] = &device_param->cuda_d_rules_c;
        device_param->kernel_params_amp[3] = &device_param->cuda_d_combs_c;
        device_param->kernel_params_amp[4] = &device_param->cuda_d_bfs_c;
      }

      if (device_param->is_hip == true)
      {
        device_param->kernel_params_amp[0] = NULL; // &device_param->hip_d_pws_buf;
        device_param->kernel_params_amp[1] = NULL; // &device_param->hip_d_pws_amp_buf;
        device_param->kernel_params_amp[2] = &device_param->hip_d_rules_c;
        device_param->kernel_params_amp[3] = &device_param->hip_d_combs_c;
        device_param->kernel_params_amp[4] = &device_param->hip_d_bfs_c;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        device_param->kernel_params_amp[0] = NULL; // device_param->metal_d_pws_buf;
        device_param->kernel_params_amp[1] = NULL; // device_param->metal_d_pws_amp_buf;
        device_param->kernel_params_amp[2] = device_param->metal_d_rules_c;
        device_param->kernel_params_amp[3] = device_param->metal_d_combs_c;
        device_param->kernel_params_amp[4] = device_param->metal_d_bfs_c;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        device_param->kernel_params_amp[0] = NULL; // &device_param->opencl_d_pws_buf;
        device_param->kernel_params_amp[1] = NULL; // &device_param->opencl_d_pws_amp_buf;
        device_param->kernel_params_amp[2] = &device_param->opencl_d_rules_c;
        device_param->kernel_params_amp[3] = &device_param->opencl_d_combs_c;
        device_param->kernel_params_amp[4] = &device_param->opencl_d_bfs_c;
      }

      device_param->kernel_params_amp[5] = &device_param->kernel_params_amp_buf32[5];
      device_param->kernel_params_amp[6] = &device_param->kernel_params_amp_buf64[6];

      if (device_param->is_cuda == true)
      {
        device_param->kernel_params_tm[0] = &device_param->cuda_d_bfs_c;
        device_param->kernel_params_tm[1] = &device_param->cuda_d_tm_c;
      }

      if (device_param->is_hip == true)
      {
        device_param->kernel_params_tm[0] = &device_param->hip_d_bfs_c;
        device_param->kernel_params_tm[1] = &device_param->hip_d_tm_c;
      }

      #if defined (__APPLE__)
      if (device_param->is_metal == true)
      {
        device_param->kernel_params_tm[0] = device_param->metal_d_bfs_c;
        device_param->kernel_params_tm[1] = device_param->metal_d_tm_c;
      }
      #endif

      if (device_param->is_opencl == true)
      {
        device_param->kernel_params_tm[0] = &device_param->opencl_d_bfs_c;
        device_param->kernel_params_tm[1] = &device_param->opencl_d_tm_c;
      }
    }

    device_param->kernel_params_memset_buf32[1] = 0; // value
    device_param->kernel_params_memset_buf64[2] = 0; // gid_max

    device_param->kernel_params_memset[0] = NULL;
    device_param->kernel_params_memset[1] = &device_param->kernel_params_memset_buf32[1];
    device_param->kernel_params_memset[2] = &device_param->kernel_params_memset_buf64[2];

    device_param->kernel_params_bzero_buf64[1] = 0; // gid_max

    device_param->kernel_params_bzero[0] = NULL;
    device_param->kernel_params_bzero[1] = &device_param->kernel_params_bzero_buf64[1];

    device_param->kernel_params_atinit_buf64[1] = 0; // gid_max

    device_param->kernel_params_atinit[0] = NULL;
    device_param->kernel_params_atinit[1] = &device_param->kernel_params_atinit_buf64[1];

    device_param->kernel_params_utf8toutf16le_buf64[1] = 0; // gid_max

    device_param->kernel_params_utf8toutf16le[0] = NULL;
    device_param->kernel_params_utf8toutf16le[1] = &device_param->kernel_params_utf8toutf16le_buf64[1];

    device_param->kernel_params_decompress_buf64[3] = 0; // gid_max

    if (device_param->is_cuda == true)
    {
      device_param->kernel_params_decompress[0] = NULL; // &device_param->cuda_d_pws_idx;
      device_param->kernel_params_decompress[1] = NULL; // &device_param->cuda_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                        // ? &device_param->cuda_d_pws_buf
                                                        // : &device_param->cuda_d_pws_amp_buf;
    }

    if (device_param->is_hip == true)
    {
      device_param->kernel_params_decompress[0] = NULL; // &device_param->hip_d_pws_idx;
      device_param->kernel_params_decompress[1] = NULL; // &device_param->hip_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                        // ? &device_param->hip_d_pws_buf
                                                        // : &device_param->hip_d_pws_amp_buf;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      device_param->kernel_params_decompress[0] = NULL; // device_param->metal_d_pws_idx;
      device_param->kernel_params_decompress[1] = NULL; // device_param->metal_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                        // ? device_param->metal_d_pws_buf
                                                        // : device_param->metal_d_pws_amp_buf;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      device_param->kernel_params_decompress[0] = NULL; // &device_param->opencl_d_pws_idx;
      device_param->kernel_params_decompress[1] = NULL; // &device_param->opencl_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                        // ? &device_param->opencl_d_pws_buf
                                                        // : &device_param->opencl_d_pws_amp_buf;
    }

    device_param->kernel_params_decompress[3] = &device_param->kernel_params_decompress_buf64[3];

    /**
     * kernel name
     */

    if (device_param->is_cuda == true)
    {
      char kernel_name[64] = { 0 };

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 4);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

            device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

            device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function4, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size4;

            device_param->kernel_preferred_wgs_multiple4 = device_param->cuda_warp_size;
          }
        }
        else
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

            device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

            device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function4, device_param->cuda_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size4;

            device_param->kernel_preferred_wgs_multiple4 = device_param->cuda_warp_size;
          }
        }

        if (user_options->slow_candidates == true)
        {
        }
        else
        {
          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_tm, device_param->cuda_module, kernel_name) == -1)
              {
                event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

                backend_kernel_create_warnings++;

                device_param->skipped_warning = true;
                continue;
              }

              if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_tm, &device_param->kernel_local_mem_size_tm) == -1) return -1;

              device_param->kernel_dynamic_local_mem_size_tm = device_param->device_local_mem_size - device_param->kernel_local_mem_size_tm;

              device_param->kernel_preferred_wgs_multiple_tm = device_param->cuda_warp_size;
            }
          }
        }
      }
      else
      {
        // kernel1

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

        device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

        // kernel2

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

        device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

        // kernel3

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

        device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
        {
          // kernel2p

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_prepare", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2p, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2p, &device_param->kernel_wgs2p) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2p, &device_param->kernel_local_mem_size2p) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size2p = device_param->device_local_mem_size - device_param->kernel_local_mem_size2p;

          device_param->kernel_preferred_wgs_multiple2p = device_param->cuda_warp_size;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          // kernel2e

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_extended", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2e, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2e, &device_param->kernel_wgs2e) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2e, &device_param->kernel_local_mem_size2e) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size2e = device_param->device_local_mem_size - device_param->kernel_local_mem_size2e;

          device_param->kernel_preferred_wgs_multiple2e = device_param->cuda_warp_size;
        }

        // kernel12

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function12, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function12, &device_param->kernel_wgs12) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function12, &device_param->kernel_local_mem_size12) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size12 = device_param->device_local_mem_size - device_param->kernel_local_mem_size12;

          device_param->kernel_preferred_wgs_multiple12 = device_param->cuda_warp_size;
        }

        // kernel23

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function23, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function23, &device_param->kernel_wgs23) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function23, &device_param->kernel_local_mem_size23) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size23 = device_param->device_local_mem_size - device_param->kernel_local_mem_size23;

          device_param->kernel_preferred_wgs_multiple23 = device_param->cuda_warp_size;
        }

        // init2

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_init2, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_init2, &device_param->kernel_local_mem_size_init2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_init2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_init2;

          device_param->kernel_preferred_wgs_multiple_init2 = device_param->cuda_warp_size;
        }

        // loop2 prepare

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2_prepare", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_loop2p, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_loop2p, &device_param->kernel_wgs_loop2p) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_loop2p, &device_param->kernel_local_mem_size_loop2p) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_loop2p = device_param->device_local_mem_size - device_param->kernel_local_mem_size_loop2p;

          device_param->kernel_preferred_wgs_multiple_loop2p = device_param->cuda_warp_size;
        }

        // loop2

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_loop2, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_loop2, &device_param->kernel_local_mem_size_loop2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_loop2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_loop2;

          device_param->kernel_preferred_wgs_multiple_loop2 = device_param->cuda_warp_size;
        }

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux1, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux1, &device_param->kernel_local_mem_size_aux1) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux1;

          device_param->kernel_preferred_wgs_multiple_aux1 = device_param->cuda_warp_size;
        }

        // aux2

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux2, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux2, &device_param->kernel_local_mem_size_aux2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux2;

          device_param->kernel_preferred_wgs_multiple_aux2 = device_param->cuda_warp_size;
        }

        // aux3

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux3, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux3, &device_param->kernel_local_mem_size_aux3) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux3;

          device_param->kernel_preferred_wgs_multiple_aux3 = device_param->cuda_warp_size;
        }

        // aux4

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux4, device_param->cuda_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux4, &device_param->kernel_local_mem_size_aux4) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux4;

          device_param->kernel_preferred_wgs_multiple_aux4 = device_param->cuda_warp_size;
        }
      }

      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem),   device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem),   device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem),   device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]); if (CL_rc == -1) return -1;

      // MP start

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          // mp_l

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp_l, device_param->cuda_module_mp, "l_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "l_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp_l, &device_param->kernel_local_mem_size_mp_l) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp_l = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp_l;

          device_param->kernel_preferred_wgs_multiple_mp_l = device_param->cuda_warp_size;

          // mp_r

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp_r, device_param->cuda_module_mp, "r_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "r_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp_r, &device_param->kernel_local_mem_size_mp_r) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp_r = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp_r;

          device_param->kernel_preferred_wgs_multiple_mp_r = device_param->cuda_warp_size;

          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]); if (CL_rc == -1) return -1;
              //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]); if (CL_rc == -1) return -1;
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp, device_param->cuda_module_mp, "C_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp;

          device_param->kernel_preferred_wgs_multiple_mp = device_param->cuda_warp_size;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp, device_param->cuda_module_mp, "C_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp;

          device_param->kernel_preferred_wgs_multiple_mp = device_param->cuda_warp_size;
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
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_amp, device_param->cuda_module_amp, "amp") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "amp");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_amp, &device_param->kernel_local_mem_size_amp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_amp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_amp;

          device_param->kernel_preferred_wgs_multiple_amp = device_param->cuda_warp_size;
        }

        /*
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          // nothing to do
        }
        else
        {
          for (u32 i = 0; i < 5; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_mem), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }

          for (u32 i = 5; i < 6; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_uint), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }

          for (u32 i = 6; i < 7; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_ulong), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }
        }
        */
      }

      // zero some data buffers

      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_digests_shown, device_param->size_shown)   == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_result,        device_param->size_results) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_rules_c, size_rules_c) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_combs,          size_combs)       == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_combs_c,        size_combs)       == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_markov_css_buf, size_markov_css)  == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_bfs,            size_bfs)         == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_bfs_c,          size_bfs)         == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tm_c,           size_tm)          == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_markov_css_buf, size_markov_css)  == -1) return -1;
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

          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_mem), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }
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

          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_mem), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_mem), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
        }
      }
    }

    if (device_param->is_hip == true)
    {
      char kernel_name[64] = { 0 };

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 4);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function1, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->hip_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function2, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

            device_param->kernel_preferred_wgs_multiple2 = device_param->hip_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function3, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

            device_param->kernel_preferred_wgs_multiple3 = device_param->hip_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function4, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size4;

            device_param->kernel_preferred_wgs_multiple4 = device_param->hip_warp_size;
          }
        }
        else
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function1, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->hip_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function2, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

            device_param->kernel_preferred_wgs_multiple2 = device_param->hip_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function3, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

            device_param->kernel_preferred_wgs_multiple3 = device_param->hip_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function4, device_param->hip_module, kernel_name) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

            device_param->kernel_dynamic_local_mem_size4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size4;

            device_param->kernel_preferred_wgs_multiple4 = device_param->hip_warp_size;
          }
        }

        if (user_options->slow_candidates == true)
        {
        }
        else
        {
          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_tm, device_param->hip_module, kernel_name) == -1)
              {
                event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

                backend_kernel_create_warnings++;

                device_param->skipped_warning = true;
                continue;
              }

              if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_tm, &device_param->kernel_local_mem_size_tm) == -1) return -1;

              device_param->kernel_dynamic_local_mem_size_tm = device_param->device_local_mem_size - device_param->kernel_local_mem_size_tm;

              device_param->kernel_preferred_wgs_multiple_tm = device_param->hip_warp_size;
            }
          }
        }
      }
      else
      {
        // kernel1

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function1, device_param->hip_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function1, &device_param->kernel_wgs1) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size1;

        device_param->kernel_preferred_wgs_multiple1 = device_param->hip_warp_size;

        // kernel2

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function2, device_param->hip_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function2, &device_param->kernel_wgs2) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size2;

        device_param->kernel_preferred_wgs_multiple2 = device_param->hip_warp_size;

        // kernel3

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function3, device_param->hip_module, kernel_name) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function3, &device_param->kernel_wgs3) == -1) return -1;

        if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

        device_param->kernel_dynamic_local_mem_size3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size3;

        device_param->kernel_preferred_wgs_multiple3 = device_param->hip_warp_size;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
        {
          // kernel2p

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_prepare", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function2p, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function2p, &device_param->kernel_wgs2p) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function2p, &device_param->kernel_local_mem_size2p) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size2p = device_param->device_local_mem_size - device_param->kernel_local_mem_size2p;

          device_param->kernel_preferred_wgs_multiple2p = device_param->hip_warp_size;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          // kernel2e

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_extended", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function2e, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function2e, &device_param->kernel_wgs2e) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function2e, &device_param->kernel_local_mem_size2e) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size2e = device_param->device_local_mem_size - device_param->kernel_local_mem_size2e;

          device_param->kernel_preferred_wgs_multiple2e = device_param->hip_warp_size;
        }

        // kernel12

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function12, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function12, &device_param->kernel_wgs12) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function12, &device_param->kernel_local_mem_size12) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size12 = device_param->device_local_mem_size - device_param->kernel_local_mem_size12;

          device_param->kernel_preferred_wgs_multiple12 = device_param->hip_warp_size;
        }

        // kernel23

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function23, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function23, &device_param->kernel_wgs23) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function23, &device_param->kernel_local_mem_size23) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size23 = device_param->device_local_mem_size - device_param->kernel_local_mem_size23;

          device_param->kernel_preferred_wgs_multiple23 = device_param->hip_warp_size;
        }

        // init2

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_init2, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_init2, &device_param->kernel_local_mem_size_init2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_init2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_init2;

          device_param->kernel_preferred_wgs_multiple_init2 = device_param->hip_warp_size;
        }

        // loop2 prepare

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2_prepare", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_loop2p, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_loop2p, &device_param->kernel_wgs_loop2p) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_loop2p, &device_param->kernel_local_mem_size_loop2p) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_loop2p = device_param->device_local_mem_size - device_param->kernel_local_mem_size_loop2p;

          device_param->kernel_preferred_wgs_multiple_loop2p = device_param->hip_warp_size;
        }

        // loop2

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_loop2, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_loop2, &device_param->kernel_local_mem_size_loop2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_loop2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_loop2;

          device_param->kernel_preferred_wgs_multiple_loop2 = device_param->hip_warp_size;
        }

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_aux1, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_aux1, &device_param->kernel_local_mem_size_aux1) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux1 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux1;

          device_param->kernel_preferred_wgs_multiple_aux1 = device_param->hip_warp_size;
        }

        // aux2

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_aux2, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_aux2, &device_param->kernel_local_mem_size_aux2) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux2 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux2;

          device_param->kernel_preferred_wgs_multiple_aux2 = device_param->hip_warp_size;
        }

        // aux3

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_aux3, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_aux3, &device_param->kernel_local_mem_size_aux3) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux3 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux3;

          device_param->kernel_preferred_wgs_multiple_aux3 = device_param->hip_warp_size;
        }

        // aux4

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_aux4, device_param->hip_module, kernel_name) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_aux4, &device_param->kernel_local_mem_size_aux4) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_aux4 = device_param->device_local_mem_size - device_param->kernel_local_mem_size_aux4;

          device_param->kernel_preferred_wgs_multiple_aux4 = device_param->hip_warp_size;
        }
      }

      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem),   device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem),   device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem),   device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]); if (CL_rc == -1) return -1;

      // MP start

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          // mp_l

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_mp_l, device_param->hip_module_mp, "l_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "l_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_mp_l, &device_param->kernel_local_mem_size_mp_l) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp_l = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp_l;

          device_param->kernel_preferred_wgs_multiple_mp_l = device_param->hip_warp_size;

          // mp_r

          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_mp_r, device_param->hip_module_mp, "r_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "r_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_mp_r, &device_param->kernel_local_mem_size_mp_r) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp_r = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp_r;

          device_param->kernel_preferred_wgs_multiple_mp_r = device_param->hip_warp_size;

          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]); if (CL_rc == -1) return -1;
              //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]); if (CL_rc == -1) return -1;
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_mp, device_param->hip_module_mp, "C_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp;

          device_param->kernel_preferred_wgs_multiple_mp = device_param->hip_warp_size;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_mp, device_param->hip_module_mp, "C_markov") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_mp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_mp;

          device_param->kernel_preferred_wgs_multiple_mp = device_param->hip_warp_size;
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
          if (hc_hipModuleGetFunction (hashcat_ctx, &device_param->hip_function_amp, device_param->hip_module_amp, "amp") == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "amp");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_hip_kernel_wgs (hashcat_ctx, device_param->hip_function_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (get_hip_kernel_local_mem_size (hashcat_ctx, device_param->hip_function_amp, &device_param->kernel_local_mem_size_amp) == -1) return -1;

          device_param->kernel_dynamic_local_mem_size_amp = device_param->device_local_mem_size - device_param->kernel_local_mem_size_amp;

          device_param->kernel_preferred_wgs_multiple_amp = device_param->hip_warp_size;
        }

        /*
        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          // nothing to do
        }
        else
        {
          for (u32 i = 0; i < 5; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_mem), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }

          for (u32 i = 5; i < 6; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_uint), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }

          for (u32 i = 6; i < 7; i++)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_ulong), device_param->kernel_params_amp[i]);

            //if (CL_rc == -1) return -1;
          }
        }
        */
      }

      // zero some data buffers

      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_digests_shown, device_param->size_shown)   == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_result,        device_param->size_results) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_rules_c, size_rules_c) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_combs,          size_combs)       == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_combs_c,        size_combs)       == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_markov_css_buf, size_markov_css)  == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_bfs,            size_bfs)         == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_bfs_c,          size_bfs)         == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tm_c,           size_tm)          == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_markov_css_buf, size_markov_css)  == -1) return -1;
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

          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_mem), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }
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

          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_mem), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
          //for (u32 i = 0; i < 3; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_mem), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
        }
      }
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      char kernel_name[64] = { 0 };

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1: m%05u_s%02d

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 4);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function1, &device_param->metal_pipeline1) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_wgs1) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            device_param->kernel_local_mem_size1 = 0;

            device_param->kernel_dynamic_local_mem_size1 = 0;

            // kernel2: m%05u_s%02d

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function2, &device_param->metal_pipeline2) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_wgs2) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            device_param->kernel_local_mem_size2 = 0;

            device_param->kernel_dynamic_local_mem_size2 = 0;

            // kernel3: m%05u_s%02d

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function3, &device_param->metal_pipeline3) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_wgs3) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;

            device_param->kernel_local_mem_size3 = 0;

            device_param->kernel_dynamic_local_mem_size3 = 0;
          }
          else
          {
            // kernel4: m%05u_sxx

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function4, &device_param->metal_pipeline4) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline4, &device_param->kernel_wgs4) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline4, &device_param->kernel_preferred_wgs_multiple4) == -1) return -1;

            device_param->kernel_local_mem_size4 = 0;

            device_param->kernel_dynamic_local_mem_size4 = 0;
          }
        }
        else // multi
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function1, &device_param->metal_pipeline1) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_wgs1) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            device_param->kernel_local_mem_size1 = 0;

            device_param->kernel_dynamic_local_mem_size1 = 0;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function2, &device_param->metal_pipeline2) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_wgs2) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            device_param->kernel_local_mem_size2 = 0;

            device_param->kernel_dynamic_local_mem_size2 = 0;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function3, &device_param->metal_pipeline3) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_wgs3) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;

            device_param->kernel_local_mem_size3 = 0;

            device_param->kernel_dynamic_local_mem_size3 = 0;
          }
          else
          {
            // kernel4

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function4, &device_param->metal_pipeline4) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline4, &device_param->kernel_wgs4) == -1) return -1;

            if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline4, &device_param->kernel_preferred_wgs_multiple4) == -1) return -1;

            device_param->kernel_local_mem_size4 = 0;

            device_param->kernel_dynamic_local_mem_size4 = 0;
          }
        }

        if (user_options->slow_candidates == true)
        {
        }
        else
        {
          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_tm, &device_param->metal_pipeline_tm) == -1)
              {
                event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

                backend_kernel_create_warnings++;

                device_param->skipped_warning = true;
                continue;
              }

              if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_tm, &device_param->kernel_preferred_wgs_multiple_tm) == -1) return -1;

              device_param->kernel_local_mem_size_tm = 0;

              device_param->kernel_dynamic_local_mem_size_tm = 0;
            }
          }
        }
      }
      else
      {
        // kernel1: m%05u_init

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function1, &device_param->metal_pipeline1) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_wgs1) == -1) return -1;

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

        device_param->kernel_local_mem_size1 = 0;

        device_param->kernel_dynamic_local_mem_size1 = 0;

        // kernel2: m%05u_loop

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function2, &device_param->metal_pipeline2) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_wgs2) == -1) return -1;

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

        device_param->kernel_local_mem_size2 = 0;

        device_param->kernel_dynamic_local_mem_size2 = 0;

        // kernel3: m%05u_comp

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function3, &device_param->metal_pipeline3) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_wgs3) == -1) return -1;

        if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;

        device_param->kernel_local_mem_size3 = 0;

        device_param->kernel_dynamic_local_mem_size3 = 0;

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
        {
          // kernel2p: m%05u_loop_prepare

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_prepare", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function2p, &device_param->metal_pipeline2p) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline2p, &device_param->kernel_wgs2p) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline2p, &device_param->kernel_preferred_wgs_multiple2p) == -1) return -1;

          device_param->kernel_local_mem_size2p = 0;

          device_param->kernel_dynamic_local_mem_size2p = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          // kernel2e: m%05u_loop_extended

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_extended", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function2e, &device_param->metal_pipeline2e) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline2e, &device_param->kernel_wgs2e) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline2e, &device_param->kernel_preferred_wgs_multiple2e) == -1) return -1;

          device_param->kernel_local_mem_size2e = 0;

          device_param->kernel_dynamic_local_mem_size2e = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          // kernel12: m%05u_hook12

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function12, &device_param->metal_pipeline12) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline12, &device_param->kernel_wgs12) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline12, &device_param->kernel_preferred_wgs_multiple12) == -1) return -1;

          device_param->kernel_local_mem_size12 = 0;

          device_param->kernel_dynamic_local_mem_size12 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          // kernel23: m%05u_hook23

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function23, &device_param->metal_pipeline23) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline23, &device_param->kernel_wgs23) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline23, &device_param->kernel_preferred_wgs_multiple23) == -1) return -1;

          device_param->kernel_local_mem_size23 = 0;

          device_param->kernel_dynamic_local_mem_size23 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          // init2: m%05u_init2

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_init2, &device_param->metal_pipeline_init2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_init2, &device_param->kernel_preferred_wgs_multiple_init2) == -1) return -1;

          device_param->kernel_local_mem_size_init2 = 0;

          device_param->kernel_dynamic_local_mem_size_init2 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
        {
          // loop2 prepare: m%05u_loop2_prepare

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2_prepare", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_loop2p, &device_param->metal_pipeline_loop2p) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_loop2p, &device_param->kernel_wgs_loop2p) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_loop2p, &device_param->kernel_preferred_wgs_multiple_loop2p) == -1) return -1;

          device_param->kernel_local_mem_size_loop2p = 0;

          device_param->kernel_dynamic_local_mem_size_loop2p = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          // loop2: m%05u_loop2

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_loop2, &device_param->metal_pipeline_loop2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_loop2, &device_param->kernel_preferred_wgs_multiple_loop2) == -1) return -1;

          device_param->kernel_local_mem_size_loop2 = 0;

          device_param->kernel_dynamic_local_mem_size_loop2 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          // aux1: m%05u_aux1

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_aux1, &device_param->metal_pipeline_aux1) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_aux1, &device_param->kernel_preferred_wgs_multiple_aux1) == -1) return -1;

          device_param->kernel_local_mem_size_aux1 = 0;

          device_param->kernel_dynamic_local_mem_size_aux1 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          // aux2: m%05u_aux2

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_aux2, &device_param->metal_pipeline_aux2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_aux2, &device_param->kernel_preferred_wgs_multiple_aux2) == -1) return -1;

          device_param->kernel_local_mem_size_aux2 = 0;

          device_param->kernel_dynamic_local_mem_size_aux2 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          // aux3: m%05u_aux3

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_aux3, &device_param->metal_pipeline_aux3) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_aux3, &device_param->kernel_preferred_wgs_multiple_aux3) == -1) return -1;

          device_param->kernel_local_mem_size_aux3 = 0;

          device_param->kernel_dynamic_local_mem_size_aux3 = 0;
        }

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          // aux4: m%05u_aux4

          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library, kernel_name, &device_param->metal_function_aux4, &device_param->metal_pipeline_aux4) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_aux4, &device_param->kernel_preferred_wgs_multiple_aux4) == -1) return -1;

          device_param->kernel_local_mem_size_aux4 = 0;

          device_param->kernel_dynamic_local_mem_size_aux4 = 0;
        }
      }

      // MP start

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          // mp_l: l_markov

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_mp, "l_markov", &device_param->metal_function_mp_l, &device_param->metal_pipeline_mp_l) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "l_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_mp_l, &device_param->kernel_preferred_wgs_multiple_mp_l) == -1) return -1;

          device_param->kernel_local_mem_size_mp_l = 0;

          device_param->kernel_dynamic_local_mem_size_mp_l = 0;

          // mp_r: r_markov

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_mp, "r_markov", &device_param->metal_function_mp_r, &device_param->metal_pipeline_mp_r) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "r_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_mp_r, &device_param->kernel_preferred_wgs_multiple_mp_r) == -1) return -1;

          device_param->kernel_local_mem_size_mp_r = 0;

          device_param->kernel_dynamic_local_mem_size_mp_r = 0;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          // mp_c: C_markov

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_mp, "C_markov", &device_param->metal_function_mp, &device_param->metal_pipeline_mp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_mp, &device_param->kernel_preferred_wgs_multiple_mp) == -1) return -1;

          device_param->kernel_local_mem_size_mp = 0;

          device_param->kernel_dynamic_local_mem_size_mp = 0;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          // mp_c: C_markov

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_mp, "C_markov", &device_param->metal_function_mp, &device_param->metal_pipeline_mp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_mp, &device_param->kernel_preferred_wgs_multiple_mp) == -1) return -1;

          device_param->kernel_local_mem_size_mp = 0;

          device_param->kernel_dynamic_local_mem_size_mp = 0;
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
          // amp

          if (hc_mtlCreateKernel (hashcat_ctx, device_param->metal_device, device_param->metal_library_amp, "amp", &device_param->metal_function_amp, &device_param->metal_pipeline_amp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "amp");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (hc_mtlGetMaxTotalThreadsPerThreadgroup (hashcat_ctx, device_param->metal_pipeline_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (hc_mtlGetThreadExecutionWidth (hashcat_ctx, device_param->metal_pipeline_amp, &device_param->kernel_preferred_wgs_multiple_amp) == -1) return -1;

          device_param->kernel_local_mem_size_amp = 0;

          device_param->kernel_dynamic_local_mem_size_amp = 0;
        }
      }

      // zero some data buffers

      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_plain_bufs,    device_param->size_plains)  == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_digests_shown, device_param->size_shown)   == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_result,        device_param->size_results) == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_rules_c, size_rules_c) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_combs,          size_combs)       == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_combs_c,        size_combs)       == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_markov_css_buf, size_markov_css)  == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_bfs,            size_bfs)         == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_bfs_c,          size_bfs)         == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_tm_c,           size_tm)          == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_root_css_buf,   size_root_css)    == -1) return -1;
          if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_markov_css_buf, size_markov_css)  == -1) return -1;
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
        }
      }
    }
    #endif // __APPLE__

    if (device_param->is_opencl == true)
    {
      // GPU autotune init

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]) == -1) return -1;

      // GPU utf8 to utf16le init

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_utf8toutf16le, 0, sizeof (cl_mem),   device_param->kernel_params_utf8toutf16le[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_utf8toutf16le, 1, sizeof (cl_ulong), device_param->kernel_params_utf8toutf16le[1]) == -1) return -1;

      // GPU decompress

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem),   device_param->kernel_params_decompress[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem),   device_param->kernel_params_decompress[1]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem),   device_param->kernel_params_decompress[2]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]) == -1) return -1;

      char kernel_name[64] = { 0 };

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_SINGLE_HASH)
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 4);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_dynamic_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_dynamic_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_dynamic_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel4) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_local_mem_size4) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_dynamic_local_mem_size4) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_preferred_wgs_multiple4) == -1) return -1;
          }
        }
        else
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_dynamic_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_dynamic_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_dynamic_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel4) == -1)
            {
              event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

              backend_kernel_create_warnings++;

              device_param->skipped_warning = true;
              continue;
            }

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_local_mem_size4) == -1) return -1;

            if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_dynamic_local_mem_size4) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_preferred_wgs_multiple4) == -1) return -1;
          }
        }

        if (user_options->slow_candidates == true)
        {
        }
        else
        {
          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_tm) == -1)
              {
                event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

                backend_kernel_create_warnings++;

                device_param->skipped_warning = true;
                continue;
              }

              if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_local_mem_size_tm) == -1) return -1;

              if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_dynamic_local_mem_size_tm) == -1) return -1;

              if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_preferred_wgs_multiple_tm) == -1) return -1;
            }
          }
        }
      }
      else
      {
        // kernel1

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_dynamic_local_mem_size1) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

        // kernel2

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_dynamic_local_mem_size2) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

        // kernel3

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1)
        {
          event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

          backend_kernel_create_warnings++;

          device_param->skipped_warning = true;
          continue;
        }

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

        if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_dynamic_local_mem_size3) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_PREPARE)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_prepare", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2p) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2p, &device_param->kernel_wgs2p) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2p, &device_param->kernel_local_mem_size2p) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2p, &device_param->kernel_dynamic_local_mem_size2p) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2p, &device_param->kernel_preferred_wgs_multiple2p) == -1) return -1;
        }

        if (hashconfig->opts_type & OPTS_TYPE_LOOP_EXTENDED)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop_extended", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2e) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2e, &device_param->kernel_wgs2e) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2e, &device_param->kernel_local_mem_size2e) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2e, &device_param->kernel_dynamic_local_mem_size2e) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2e, &device_param->kernel_preferred_wgs_multiple2e) == -1) return -1;
        }

        // kernel12

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel12) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_wgs12) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_local_mem_size12) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_dynamic_local_mem_size12) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_preferred_wgs_multiple12) == -1) return -1;
        }

        // kernel23

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel23) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_wgs23) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_local_mem_size23) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_dynamic_local_mem_size23) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_preferred_wgs_multiple23) == -1) return -1;
        }

        // init2

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_init2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_local_mem_size_init2) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_dynamic_local_mem_size_init2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_preferred_wgs_multiple_init2) == -1) return -1;
        }

        // loop2 prepare

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2_PREPARE)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2_prepare", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_loop2p) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_loop2p, &device_param->kernel_wgs_loop2p) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_loop2p, &device_param->kernel_local_mem_size_loop2p) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_loop2p, &device_param->kernel_dynamic_local_mem_size_loop2p) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_loop2p, &device_param->kernel_preferred_wgs_multiple_loop2p) == -1) return -1;
        }

        // loop2

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_loop2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_local_mem_size_loop2) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_dynamic_local_mem_size_loop2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_preferred_wgs_multiple_loop2) == -1) return -1;
        }

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux1) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_local_mem_size_aux1) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_dynamic_local_mem_size_aux1) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_preferred_wgs_multiple_aux1) == -1) return -1;
        }

        // aux2

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux2) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_local_mem_size_aux2) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_dynamic_local_mem_size_aux2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_preferred_wgs_multiple_aux2) == -1) return -1;
        }

        // aux3

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux3) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_local_mem_size_aux3) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_dynamic_local_mem_size_aux3) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_preferred_wgs_multiple_aux3) == -1) return -1;
        }

        // aux4

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux4) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, kernel_name);

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_local_mem_size_aux4) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_dynamic_local_mem_size_aux4) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_preferred_wgs_multiple_aux4) == -1) return -1;
        }
      }

      // MP start

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          // mp_l

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "l_markov", &device_param->opencl_kernel_mp_l) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "l_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_local_mem_size_mp_l) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_dynamic_local_mem_size_mp_l) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_preferred_wgs_multiple_mp_l) == -1) return -1;

          // mp_r

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "r_markov", &device_param->opencl_kernel_mp_r) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "r_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_local_mem_size_mp_r) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_dynamic_local_mem_size_mp_r) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_preferred_wgs_multiple_mp_r) == -1) return -1;

          if (user_options->attack_mode == ATTACK_MODE_BF)
          {
            if (hashconfig->opts_type & OPTS_TYPE_TM_KERNEL)
            {
              if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]) == -1) return -1;
              if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]) == -1) return -1;
            }
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "C_markov", &device_param->opencl_kernel_mp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_dynamic_local_mem_size_mp) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_preferred_wgs_multiple_mp) == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "C_markov", &device_param->opencl_kernel_mp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "C_markov");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_dynamic_local_mem_size_mp) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_preferred_wgs_multiple_mp) == -1) return -1;
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
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_amp, "amp", &device_param->opencl_kernel_amp) == -1)
          {
            event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s create failed.", device_param->device_id + 1, "amp");

            backend_kernel_create_warnings++;

            device_param->skipped_warning = true;
            continue;
          }

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_local_mem_size_amp) == -1) return -1;

          if (get_opencl_kernel_dynamic_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_dynamic_local_mem_size_amp) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_preferred_wgs_multiple_amp) == -1) return -1;
        }

        if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
        {
          // nothing to do
        }
        else
        {
          for (u32 i = 0; i < 5; i++)
          {
            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_mem), device_param->kernel_params_amp[i]) == -1) return -1;
          }

          for (u32 i = 5; i < 6; i++)
          {
            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_uint), device_param->kernel_params_amp[i]) == -1) return -1;
          }

          for (u32 i = 6; i < 7; i++)
          {
            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, i, sizeof (cl_ulong), device_param->kernel_params_amp[i]) == -1) return -1;
          }
        }
      }

      // zero some data buffers

      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_plain_bufs,    device_param->size_plains)   == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_digests_shown, device_param->size_shown)    == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_result,        device_param->size_results)  == -1) return -1;

      /**
       * special buffers
       */

      if (user_options->slow_candidates == true)
      {
        if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_rules_c, size_rules_c) == -1) return -1;
      }
      else
      {
        if (user_options_extra->attack_kern == ATTACK_KERN_STRAIGHT)
        {
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_rules_c, size_rules_c) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_COMBI)
        {
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_combs,          size_combs)      == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_combs_c,        size_combs)      == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_markov_css_buf, size_markov_css) == -1) return -1;
        }
        else if (user_options_extra->attack_kern == ATTACK_KERN_BF)
        {
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_bfs,            size_bfs)        == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_bfs_c,          size_bfs)        == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tm_c,           size_tm)         == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_root_css_buf,   size_root_css)   == -1) return -1;
          if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_markov_css_buf, size_markov_css) == -1) return -1;
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

          for (u32 i = 0; i < 3; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_mem), device_param->kernel_params_mp[i]) == -1) return -1; }
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

          for (u32 i = 0; i < 3; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_mem), device_param->kernel_params_mp_l[i]) == -1) return -1; }
          for (u32 i = 0; i < 3; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_mem), device_param->kernel_params_mp_r[i]) == -1) return -1; }
        }
      }
    }

    // this is required because inside the kernels there is this:
    // __local pw_t s_pws[64];

    if ((user_options->attack_mode == ATTACK_MODE_STRAIGHT)
     || (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
     || (user_options->slow_candidates == true))
    {
      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
        {
          // not required
        }
        else
        {
          device_param->kernel_threads_min = MIN (device_param->kernel_threads_min, 64);
          device_param->kernel_threads_max = MIN (device_param->kernel_threads_max, 64);
        }
      }
    }

    /**
     * now everything that depends on threads and accel, basically dynamic workload
     */

    //    u32 kernel_threads = get_kernel_threads (device_param);

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      // the smaller the kernel_threads the more accurate we can set kernel_accel
      // in autotune. in this attack mode kernel_power is limited by salts_cnt so we
      // do not have a lot of options left.

      device_param->kernel_threads_min = MIN (device_param->kernel_threads_min, 64);
      device_param->kernel_threads_max = MIN (device_param->kernel_threads_max, 64);
    }

    //    device_param->kernel_threads = kernel_threads;
    device_param->kernel_threads = 0;

    u32 hardware_power_max = ((hashconfig->opts_type & OPTS_TYPE_MP_MULTI_DISABLE) ? 1 : device_processors) * device_param->kernel_threads_max;

    u32 kernel_accel_min = device_param->kernel_accel_min;
    u32 kernel_accel_max = device_param->kernel_accel_max;

    // We need to deal with the situation that the total video RAM > total host RAM.
    // For the opposite direction, we do that in the loop section below.
    // Especially in multi-GPU setups that is very likely.
    // The buffers which actually take a lot of memory (except for SCRYPT) are the ones for the password candidates.
    // They are stored in an aligned order for better performance, but this increases the memory pressure.
    // The best way to keep these buffers to a reasonable size is by controlling the kernel_accel parameter.
    //
    // In theory this check could be disabled if we check if total video RAM < total host RAM,
    // but at this point of initialization phase we don't have this information available.

    // We need to hard-code some value, let's assume that (in 2021) the host has at least 4GB ram per active GPU

    const u64 SIZE_4GB = 4ULL * 1024 * 1024 * 1024;

    u64 accel_limit = SIZE_4GB;

    // in slow candidate mode we need to keep the buffers on the host alive
    // a high accel value doesn't help much here anyway

    if (user_options->slow_candidates == true)
    {
      // Tested with NTLM, almost no difference in performance

      accel_limit /= 8;
    }

    // this is device_processors * kernel_threads

    accel_limit /= hardware_power_max;

    // single password candidate size

    accel_limit /= sizeof (pw_t);

    // pws[], pws_comp[] and pw_pre[] are some large blocks with password candidates

    accel_limit /= 3;

    // Is possible that the GPU simply has too much hardware resources and 8GB per GPU is not enough, but OTOH we can't get lower than 1

    accel_limit = MAX (accel_limit, 1);

    // I think vector size is not required because vector_size is dividing the pws_cnt in run_kernel()

    kernel_accel_max = MIN (kernel_accel_max, accel_limit);

    if (kernel_accel_min > kernel_accel_max)
    {
      event_log_error (hashcat_ctx, "* Device #%u: Too many compute units to keep minimum kernel accel limit.", device_id + 1);
      event_log_error (hashcat_ctx, "             Retry with lower --backend-kernel-threads value.");

      backend_kernel_accel_warnings++;

      device_param->skipped_warning = true;
      continue;
    }

    // Opposite direction check: find out if we would request too much memory on memory blocks which are based on kernel_accel

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

    while (kernel_accel_max >= kernel_accel_min)
    {
      const u64 kernel_power_max = hardware_power_max * kernel_accel_max;

      // size_pws

      size_pws = kernel_power_max * sizeof (pw_t);

      size_pws_amp = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) ? 1 : size_pws;

      // size_pws_comp

      size_pws_comp = kernel_power_max * (sizeof (u32) * 64);

      // size_pws_idx

      size_pws_idx = (u64) (kernel_power_max + 1) * sizeof (pw_idx_t);

      // size_tmps

      size_tmps = kernel_power_max * hashconfig->tmp_size;

      // size_hooks

      size_hooks = kernel_power_max * hashconfig->hook_size;

      #ifdef WITH_BRAIN
      // size_brains

      size_brain_link_in  = kernel_power_max * 1;
      size_brain_link_out = kernel_power_max * 8;
      #endif

      if (user_options->slow_candidates == true)
      {
        // size_pws_pre

        size_pws_pre = kernel_power_max * sizeof (pw_pre_t);

        // size_pws_base

        size_pws_base = kernel_power_max * sizeof (pw_pre_t);
      }

      // now check if all device-memory sizes which depend on the kernel_accel_max amplifier are within its boundaries
      // if not, decrease amplifier and try again

      int memory_limit_hit = 0;

      // sometimes device_available_mem and device_maxmem_alloc reported back from the opencl runtime are a bit inaccurate.
      // let's add some extra space just to be sure.
      // now depends on the kernel-accel value (where scrypt and similar benefits), but also hard minimum 64mb and maximum 1024mb limit

      u64 EXTRA_SPACE = (1024ULL * 1024ULL) * kernel_accel_max;

      EXTRA_SPACE = MAX (EXTRA_SPACE, ( 256ULL * 1024ULL * 1024ULL));
      EXTRA_SPACE = MIN (EXTRA_SPACE, (1024ULL * 1024ULL * 1024ULL));

      if ((size_pws   + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;
      if ((size_tmps  + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;
      if ((size_hooks + EXTRA_SPACE) > device_param->device_maxmem_alloc) memory_limit_hit = 1;

      // work around, for some reason apple opencl can't have buffers larger 2^31
      // typically runs into trap 6
      // maybe 32/64 bit problem affecting size_t?

      if (device_param->opencl_platform_vendor_id == VENDOR_ID_APPLE)
      {
        const size_t undocumented_single_allocation_apple = 0x7fffffff;

        if (bitmap_ctx->bitmap_size > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_bfs                > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_combs              > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_digests            > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_esalts             > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_hooks              > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_markov_css         > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_plains             > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_pws                > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_pws_amp            > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_pws_comp           > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_pws_idx            > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_results            > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_root_css           > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_rules              > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_rules_c            > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_salts              > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_extra_buffer       > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_shown              > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_tm                 > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_tmps               > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_st_digests         > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_st_salts           > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_st_esalts          > undocumented_single_allocation_apple) memory_limit_hit = 1;
        if (size_kernel_params      > undocumented_single_allocation_apple) memory_limit_hit = 1;
      }

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
        + size_extra_buffer
        + size_shown
        + size_tm
        + size_tmps
        + size_st_digests
        + size_st_salts
        + size_st_esalts
        + size_kernel_params;

      if ((size_total + EXTRA_SPACE) > device_param->device_available_mem) memory_limit_hit = 1;

      if (memory_limit_hit == 1)
      {
        kernel_accel_max--;

        continue;
      }

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

      size_total_host_all += size_total_host;

      break;
    }

    if (kernel_accel_max < kernel_accel_min)
    {
      event_log_error (hashcat_ctx, "* Device #%u: Not enough allocatable device memory for this attack.", device_id + 1);

      backend_memory_hit_warnings++;

      device_param->skipped_warning = true;
      continue;
    }

    // similar process for association attack
    // there's no need to have a device_power > salts_cnt since salt_pos is set to GID in kernel

    if (user_options->attack_mode == ATTACK_MODE_ASSOCIATION)
    {
      while (kernel_accel_max > kernel_accel_min)
      {
        const u64 kernel_power_max = hardware_power_max * kernel_accel_max;

        if (kernel_power_max > hashes->salts_cnt)
        {
          kernel_accel_max--;

          continue;
        }

        break;
      }
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

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pws_buf,      size_pws)      == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pws_amp_buf,  size_pws_amp)  == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pws_comp_buf, size_pws_comp) == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_pws_idx,      size_pws_idx)  == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_tmps,         size_tmps)     == -1) return -1;
      if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_hooks,        size_hooks)    == -1) return -1;

      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_buf,       device_param->size_pws)      == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_amp_buf,   device_param->size_pws_amp)  == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_comp_buf,  device_param->size_pws_comp) == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_pws_idx,       device_param->size_pws_idx)  == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tmps,          device_param->size_tmps)     == -1) return -1;
      if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_hooks,         device_param->size_hooks)    == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pws_buf,      size_pws)      == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pws_amp_buf,  size_pws_amp)  == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pws_comp_buf, size_pws_comp) == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_pws_idx,      size_pws_idx)  == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_tmps,         size_tmps)     == -1) return -1;
      if (hc_hipMemAlloc (hashcat_ctx, &device_param->hip_d_hooks,        size_hooks)    == -1) return -1;

      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_buf,       device_param->size_pws)      == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_amp_buf,   device_param->size_pws_amp)  == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_comp_buf,  device_param->size_pws_comp) == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_pws_idx,       device_param->size_pws_idx)  == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_tmps,          device_param->size_tmps)     == -1) return -1;
      if (run_hip_kernel_bzero (hashcat_ctx, device_param, device_param->hip_d_hooks,         device_param->size_hooks)    == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_pws,      NULL, &device_param->metal_d_pws_buf)      == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_pws_amp,  NULL, &device_param->metal_d_pws_amp_buf)  == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_pws_comp, NULL, &device_param->metal_d_pws_comp_buf) == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_pws_idx,  NULL, &device_param->metal_d_pws_idx)      == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_tmps,     NULL, &device_param->metal_d_tmps)         == -1) return -1;
      if (hc_mtlCreateBuffer (hashcat_ctx, device_param->metal_device, size_hooks,    NULL, &device_param->metal_d_hooks)        == -1) return -1;

      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_buf,       device_param->size_pws)      == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_amp_buf,   device_param->size_pws_amp)  == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_comp_buf,  device_param->size_pws_comp) == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_pws_idx,       device_param->size_pws_idx)  == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_tmps,          device_param->size_tmps)     == -1) return -1;
      if (run_metal_kernel_bzero (hashcat_ctx, device_param, device_param->metal_d_hooks,         device_param->size_hooks)    == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_pws,      NULL, &device_param->opencl_d_pws_buf)      == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_pws_amp,  NULL, &device_param->opencl_d_pws_amp_buf)  == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_pws_comp, NULL, &device_param->opencl_d_pws_comp_buf) == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY,   size_pws_idx,  NULL, &device_param->opencl_d_pws_idx)      == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_tmps,     NULL, &device_param->opencl_d_tmps)         == -1) return -1;
      if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_WRITE,  size_hooks,    NULL, &device_param->opencl_d_hooks)        == -1) return -1;

      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_buf,       device_param->size_pws)      == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_amp_buf,   device_param->size_pws_amp)  == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_comp_buf,  device_param->size_pws_comp) == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_pws_idx,       device_param->size_pws_idx)  == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tmps,          device_param->size_tmps)     == -1) return -1;
      if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_hooks,         device_param->size_hooks)    == -1) return -1;
    }

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

    if (device_param->is_cuda == true)
    {
      device_param->kernel_params[ 0] = &device_param->cuda_d_pws_buf;
      device_param->kernel_params[ 4] = &device_param->cuda_d_tmps;
      device_param->kernel_params[ 5] = &device_param->cuda_d_hooks;
    }

    if (device_param->is_hip == true)
    {
      device_param->kernel_params[ 0] = &device_param->hip_d_pws_buf;
      device_param->kernel_params[ 4] = &device_param->hip_d_tmps;
      device_param->kernel_params[ 5] = &device_param->hip_d_hooks;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      device_param->kernel_params[ 0] = device_param->metal_d_pws_buf;
      device_param->kernel_params[ 4] = device_param->metal_d_tmps;
      device_param->kernel_params[ 5] = device_param->metal_d_hooks;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      device_param->kernel_params[ 0] = &device_param->opencl_d_pws_buf;
      device_param->kernel_params[ 4] = &device_param->opencl_d_tmps;
      device_param->kernel_params[ 5] = &device_param->opencl_d_hooks;
    }

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
          if (device_param->is_cuda == true)
          {
            device_param->kernel_params_mp[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->cuda_d_pws_buf
                                              : &device_param->cuda_d_pws_amp_buf;

            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, 0, sizeof (cl_mem), device_param->kernel_params_mp[0]); if (CL_rc == -1) return -1;
          }

          if (device_param->is_hip == true)
          {
            device_param->kernel_params_mp[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->hip_d_pws_buf
                                              : &device_param->hip_d_pws_amp_buf;

            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, 0, sizeof (cl_mem), device_param->kernel_params_mp[0]); if (CL_rc == -1) return -1;
          }

          #if defined (__APPLE__)
          if (device_param->is_metal == true)
          {
            device_param->kernel_params_mp[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? device_param->metal_d_pws_buf
                                              : device_param->metal_d_pws_amp_buf;
          }
          #endif

          if (device_param->is_opencl == true)
          {
            device_param->kernel_params_mp[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->opencl_d_pws_buf
                                              : &device_param->opencl_d_pws_amp_buf;

            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, 0, sizeof (cl_mem), device_param->kernel_params_mp[0]) == -1) return -1;
          }
        }
      }

      if (user_options->attack_mode == ATTACK_MODE_BF)
      {
        if (device_param->is_cuda == true)
        {
          device_param->kernel_params_mp_l[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->cuda_d_pws_buf
                                              : &device_param->cuda_d_pws_amp_buf;

          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, 0, sizeof (cl_mem), device_param->kernel_params_mp_l[0]); if (CL_rc == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          device_param->kernel_params_mp_l[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->hip_d_pws_buf
                                              : &device_param->hip_d_pws_amp_buf;

          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, 0, sizeof (cl_mem), device_param->kernel_params_mp_l[0]); if (CL_rc == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          device_param->kernel_params_mp_l[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? device_param->metal_d_pws_buf
                                              : device_param->metal_d_pws_amp_buf;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          device_param->kernel_params_mp_l[0] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                              ? &device_param->opencl_d_pws_buf
                                              : &device_param->opencl_d_pws_amp_buf;

          if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, 0, sizeof (cl_mem), device_param->kernel_params_mp_l[0]) == -1) return -1;
        }
      }

      if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
      {
        // nothing to do
      }
      else
      {
        if (device_param->is_cuda == true)
        {
          device_param->kernel_params_amp[0] = &device_param->cuda_d_pws_buf;
          device_param->kernel_params_amp[1] = &device_param->cuda_d_pws_amp_buf;

          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 0, sizeof (cl_mem), device_param->kernel_params_amp[0]); if (CL_rc == -1) return -1;
          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 1, sizeof (cl_mem), device_param->kernel_params_amp[1]); if (CL_rc == -1) return -1;
        }

        if (device_param->is_hip == true)
        {
          device_param->kernel_params_amp[0] = &device_param->hip_d_pws_buf;
          device_param->kernel_params_amp[1] = &device_param->hip_d_pws_amp_buf;

          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 0, sizeof (cl_mem), device_param->kernel_params_amp[0]); if (CL_rc == -1) return -1;
          //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 1, sizeof (cl_mem), device_param->kernel_params_amp[1]); if (CL_rc == -1) return -1;
        }

        #if defined (__APPLE__)
        if (device_param->is_metal == true)
        {
          device_param->kernel_params_amp[0] = device_param->metal_d_pws_buf;
          device_param->kernel_params_amp[1] = device_param->metal_d_pws_amp_buf;
        }
        #endif

        if (device_param->is_opencl == true)
        {
          device_param->kernel_params_amp[0] = &device_param->opencl_d_pws_buf;
          device_param->kernel_params_amp[1] = &device_param->opencl_d_pws_amp_buf;

          if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 0, sizeof (cl_mem), device_param->kernel_params_amp[0]) == -1) return -1;
          if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 1, sizeof (cl_mem), device_param->kernel_params_amp[1]) == -1) return -1;
        }
      }
    }

    if (device_param->is_cuda == true)
    {
      device_param->kernel_params_decompress[0] = &device_param->cuda_d_pws_idx;
      device_param->kernel_params_decompress[1] = &device_param->cuda_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                ? &device_param->cuda_d_pws_buf
                                                : &device_param->cuda_d_pws_amp_buf;

      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem), device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem), device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem), device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      device_param->kernel_params_decompress[0] = &device_param->hip_d_pws_idx;
      device_param->kernel_params_decompress[1] = &device_param->hip_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                ? &device_param->hip_d_pws_buf
                                                : &device_param->hip_d_pws_amp_buf;

      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem), device_param->kernel_params_decompress[0]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem), device_param->kernel_params_decompress[1]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem), device_param->kernel_params_decompress[2]); if (CL_rc == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      device_param->kernel_params_decompress[0] = device_param->metal_d_pws_idx;
      device_param->kernel_params_decompress[1] = device_param->metal_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                ? device_param->metal_d_pws_buf
                                                : device_param->metal_d_pws_amp_buf;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      device_param->kernel_params_decompress[0] = &device_param->opencl_d_pws_idx;
      device_param->kernel_params_decompress[1] = &device_param->opencl_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                ? &device_param->opencl_d_pws_buf
                                                : &device_param->opencl_d_pws_amp_buf;

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem), device_param->kernel_params_decompress[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem), device_param->kernel_params_decompress[1]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem), device_param->kernel_params_decompress[2]) == -1) return -1;
    }

    // context

    if (device_param->is_cuda == true)
    {
      if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipCtxPopCurrent (hashcat_ctx, &device_param->hip_context) == -1)
      {
        device_param->skipped = true;
        continue;
      }
    }

    hardware_power_all += hardware_power_max;

    EVENT_DATA (EVENT_BACKEND_DEVICE_INIT_POST, &backend_devices_idx, sizeof (int));
  }

  int rc = 0;

  backend_ctx->memory_hit_warning    = (backend_memory_hit_warnings    == backend_ctx->backend_devices_active);
  backend_ctx->runtime_skip_warning  = (backend_runtime_skip_warnings  == backend_ctx->backend_devices_active);
  backend_ctx->kernel_build_warning  = (backend_kernel_build_warnings  == backend_ctx->backend_devices_active);
  backend_ctx->kernel_create_warning = (backend_kernel_create_warnings == backend_ctx->backend_devices_active);
  backend_ctx->kernel_accel_warnings = (backend_kernel_accel_warnings  == backend_ctx->backend_devices_active);
  backend_ctx->extra_size_warning    = (backend_extra_size_warning     == backend_ctx->backend_devices_active);

  // if all active devices failed, set rc to -1
  // later we prevent hashcat exit if is started in benchmark mode
  if ((backend_ctx->memory_hit_warning    == true) ||
      (backend_ctx->runtime_skip_warning  == true) ||
      (backend_ctx->kernel_build_warning  == true) ||
      (backend_ctx->kernel_create_warning == true) ||
      (backend_ctx->kernel_accel_warnings == true) ||
      (backend_ctx->extra_size_warning    == true))
  {
    rc = -1;
  }
  else
  {
    // handle mix of, in case of multiple devices with different warnings
    backend_ctx->mixed_warnings = ((backend_memory_hit_warnings + backend_runtime_skip_warnings + backend_kernel_build_warnings + backend_kernel_create_warnings + backend_kernel_accel_warnings + backend_extra_size_warning) == backend_ctx->backend_devices_active);

    if (backend_ctx->mixed_warnings) rc = -1;
  }

  if (user_options->benchmark == false)
  {
    if (hardware_power_all == 0) return -1;
  }

  backend_ctx->hardware_power_all = hardware_power_all;

  EVENT_DATA (EVENT_BACKEND_SESSION_HOSTMEM, &size_total_host_all, sizeof (u64));

  return rc;
}

void backend_session_destroy (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

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

    if (device_param->is_cuda == true)
    {
      if (device_param->cuda_d_pws_buf)        hc_cuMemFree (hashcat_ctx, device_param->cuda_d_pws_buf);
      if (device_param->cuda_d_pws_amp_buf)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_pws_amp_buf);
      if (device_param->cuda_d_pws_comp_buf)   hc_cuMemFree (hashcat_ctx, device_param->cuda_d_pws_comp_buf);
      if (device_param->cuda_d_pws_idx)        hc_cuMemFree (hashcat_ctx, device_param->cuda_d_pws_idx);
      if (device_param->cuda_d_rules)          hc_cuMemFree (hashcat_ctx, device_param->cuda_d_rules);
      //if (device_param->cuda_d_rules_c)        hc_cuMemFree (hashcat_ctx, device_param->cuda_d_rules_c);
      if (device_param->cuda_d_combs)          hc_cuMemFree (hashcat_ctx, device_param->cuda_d_combs);
      if (device_param->cuda_d_combs_c)        hc_cuMemFree (hashcat_ctx, device_param->cuda_d_combs_c);
      if (device_param->cuda_d_bfs)            hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bfs);
      //if (device_param->cuda_d_bfs_c)          hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bfs_c);
      if (device_param->cuda_d_bitmap_s1_a)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s1_a);
      if (device_param->cuda_d_bitmap_s1_b)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s1_b);
      if (device_param->cuda_d_bitmap_s1_c)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s1_c);
      if (device_param->cuda_d_bitmap_s1_d)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s1_d);
      if (device_param->cuda_d_bitmap_s2_a)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s2_a);
      if (device_param->cuda_d_bitmap_s2_b)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s2_b);
      if (device_param->cuda_d_bitmap_s2_c)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s2_c);
      if (device_param->cuda_d_bitmap_s2_d)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_bitmap_s2_d);
      if (device_param->cuda_d_plain_bufs)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_plain_bufs);
      if (device_param->cuda_d_digests_buf)    hc_cuMemFree (hashcat_ctx, device_param->cuda_d_digests_buf);
      if (device_param->cuda_d_digests_shown)  hc_cuMemFree (hashcat_ctx, device_param->cuda_d_digests_shown);
      if (device_param->cuda_d_salt_bufs)      hc_cuMemFree (hashcat_ctx, device_param->cuda_d_salt_bufs);
      if (device_param->cuda_d_esalt_bufs)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_esalt_bufs);
      if (device_param->cuda_d_tmps)           hc_cuMemFree (hashcat_ctx, device_param->cuda_d_tmps);
      if (device_param->cuda_d_hooks)          hc_cuMemFree (hashcat_ctx, device_param->cuda_d_hooks);
      if (device_param->cuda_d_result)         hc_cuMemFree (hashcat_ctx, device_param->cuda_d_result);
      if (device_param->cuda_d_extra0_buf)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_extra0_buf);
      if (device_param->cuda_d_extra1_buf)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_extra1_buf);
      if (device_param->cuda_d_extra2_buf)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_extra2_buf);
      if (device_param->cuda_d_extra3_buf)     hc_cuMemFree (hashcat_ctx, device_param->cuda_d_extra3_buf);
      if (device_param->cuda_d_root_css_buf)   hc_cuMemFree (hashcat_ctx, device_param->cuda_d_root_css_buf);
      if (device_param->cuda_d_markov_css_buf) hc_cuMemFree (hashcat_ctx, device_param->cuda_d_markov_css_buf);
      if (device_param->cuda_d_tm_c)           hc_cuMemFree (hashcat_ctx, device_param->cuda_d_tm_c);
      if (device_param->cuda_d_st_digests_buf) hc_cuMemFree (hashcat_ctx, device_param->cuda_d_st_digests_buf);
      if (device_param->cuda_d_st_salts_buf)   hc_cuMemFree (hashcat_ctx, device_param->cuda_d_st_salts_buf);
      if (device_param->cuda_d_st_esalts_buf)  hc_cuMemFree (hashcat_ctx, device_param->cuda_d_st_esalts_buf);
      if (device_param->cuda_d_kernel_param)   hc_cuMemFree (hashcat_ctx, device_param->cuda_d_kernel_param);

      if (device_param->cuda_event1)           hc_cuEventDestroy (hashcat_ctx, device_param->cuda_event1);
      if (device_param->cuda_event2)           hc_cuEventDestroy (hashcat_ctx, device_param->cuda_event2);
      if (device_param->cuda_event3)           hc_cuEventDestroy (hashcat_ctx, device_param->cuda_event3);

      if (device_param->cuda_stream)           hc_cuStreamDestroy (hashcat_ctx, device_param->cuda_stream);

      if (device_param->cuda_module)           hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module);
      if (device_param->cuda_module_mp)        hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module_mp);
      if (device_param->cuda_module_amp)       hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module_amp);
      if (device_param->cuda_module_shared)    hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module_shared);

      if (device_param->cuda_context)          hc_cuCtxDestroy (hashcat_ctx, device_param->cuda_context);

      device_param->cuda_d_pws_buf            = 0;
      device_param->cuda_d_pws_amp_buf        = 0;
      device_param->cuda_d_pws_comp_buf       = 0;
      device_param->cuda_d_pws_idx            = 0;
      device_param->cuda_d_rules              = 0;
      device_param->cuda_d_rules_c            = 0;
      device_param->cuda_d_combs              = 0;
      device_param->cuda_d_combs_c            = 0;
      device_param->cuda_d_bfs                = 0;
      device_param->cuda_d_bfs_c              = 0;
      device_param->cuda_d_bitmap_s1_a        = 0;
      device_param->cuda_d_bitmap_s1_b        = 0;
      device_param->cuda_d_bitmap_s1_c        = 0;
      device_param->cuda_d_bitmap_s1_d        = 0;
      device_param->cuda_d_bitmap_s2_a        = 0;
      device_param->cuda_d_bitmap_s2_b        = 0;
      device_param->cuda_d_bitmap_s2_c        = 0;
      device_param->cuda_d_bitmap_s2_d        = 0;
      device_param->cuda_d_plain_bufs         = 0;
      device_param->cuda_d_digests_buf        = 0;
      device_param->cuda_d_digests_shown      = 0;
      device_param->cuda_d_salt_bufs          = 0;
      device_param->cuda_d_esalt_bufs         = 0;
      device_param->cuda_d_tmps               = 0;
      device_param->cuda_d_hooks              = 0;
      device_param->cuda_d_result             = 0;
      device_param->cuda_d_extra0_buf         = 0;
      device_param->cuda_d_extra1_buf         = 0;
      device_param->cuda_d_extra2_buf         = 0;
      device_param->cuda_d_extra3_buf         = 0;
      device_param->cuda_d_root_css_buf       = 0;
      device_param->cuda_d_markov_css_buf     = 0;
      device_param->cuda_d_tm_c               = 0;
      device_param->cuda_d_st_digests_buf     = 0;
      device_param->cuda_d_st_salts_buf       = 0;
      device_param->cuda_d_st_esalts_buf      = 0;
      device_param->cuda_d_kernel_param       = 0;

      device_param->cuda_function1            = NULL;
      device_param->cuda_function12           = NULL;
      device_param->cuda_function2p           = NULL;
      device_param->cuda_function2            = NULL;
      device_param->cuda_function2e           = NULL;
      device_param->cuda_function23           = NULL;
      device_param->cuda_function3            = NULL;
      device_param->cuda_function4            = NULL;
      device_param->cuda_function_init2       = NULL;
      device_param->cuda_function_loop2p      = NULL;
      device_param->cuda_function_loop2       = NULL;
      device_param->cuda_function_mp          = NULL;
      device_param->cuda_function_mp_l        = NULL;
      device_param->cuda_function_mp_r        = NULL;
      device_param->cuda_function_tm          = NULL;
      device_param->cuda_function_amp         = NULL;
      device_param->cuda_function_memset      = NULL;
      device_param->cuda_function_bzero       = NULL;
      device_param->cuda_function_atinit      = NULL;
      device_param->cuda_function_utf8toutf16le = NULL;
      device_param->cuda_function_decompress  = NULL;
      device_param->cuda_function_aux1        = NULL;
      device_param->cuda_function_aux2        = NULL;
      device_param->cuda_function_aux3        = NULL;
      device_param->cuda_function_aux4        = NULL;

      device_param->cuda_event1               = NULL;
      device_param->cuda_event2               = NULL;
      device_param->cuda_event3               = NULL;

      device_param->cuda_stream               = NULL;

      device_param->cuda_module               = NULL;
      device_param->cuda_module_mp            = NULL;
      device_param->cuda_module_amp           = NULL;
      device_param->cuda_module_shared        = NULL;

      device_param->cuda_context              = NULL;
    }

    if (device_param->is_hip == true)
    {
      if (device_param->hip_d_pws_buf)        hc_hipMemFree (hashcat_ctx, device_param->hip_d_pws_buf);
      if (device_param->hip_d_pws_amp_buf)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_pws_amp_buf);
      if (device_param->hip_d_pws_comp_buf)   hc_hipMemFree (hashcat_ctx, device_param->hip_d_pws_comp_buf);
      if (device_param->hip_d_pws_idx)        hc_hipMemFree (hashcat_ctx, device_param->hip_d_pws_idx);
      if (device_param->hip_d_rules)          hc_hipMemFree (hashcat_ctx, device_param->hip_d_rules);
      //if (device_param->hip_d_rules_c)        hc_hipMemFree (hashcat_ctx, device_param->hip_d_rules_c);
      if (device_param->hip_d_combs)          hc_hipMemFree (hashcat_ctx, device_param->hip_d_combs);
      if (device_param->hip_d_combs_c)        hc_hipMemFree (hashcat_ctx, device_param->hip_d_combs_c);
      if (device_param->hip_d_bfs)            hc_hipMemFree (hashcat_ctx, device_param->hip_d_bfs);
      //if (device_param->hip_d_bfs_c)          hc_hipMemFree (hashcat_ctx, device_param->hip_d_bfs_c);
      if (device_param->hip_d_bitmap_s1_a)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s1_a);
      if (device_param->hip_d_bitmap_s1_b)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s1_b);
      if (device_param->hip_d_bitmap_s1_c)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s1_c);
      if (device_param->hip_d_bitmap_s1_d)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s1_d);
      if (device_param->hip_d_bitmap_s2_a)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s2_a);
      if (device_param->hip_d_bitmap_s2_b)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s2_b);
      if (device_param->hip_d_bitmap_s2_c)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s2_c);
      if (device_param->hip_d_bitmap_s2_d)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_bitmap_s2_d);
      if (device_param->hip_d_plain_bufs)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_plain_bufs);
      if (device_param->hip_d_digests_buf)    hc_hipMemFree (hashcat_ctx, device_param->hip_d_digests_buf);
      if (device_param->hip_d_digests_shown)  hc_hipMemFree (hashcat_ctx, device_param->hip_d_digests_shown);
      if (device_param->hip_d_salt_bufs)      hc_hipMemFree (hashcat_ctx, device_param->hip_d_salt_bufs);
      if (device_param->hip_d_esalt_bufs)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_esalt_bufs);
      if (device_param->hip_d_tmps)           hc_hipMemFree (hashcat_ctx, device_param->hip_d_tmps);
      if (device_param->hip_d_hooks)          hc_hipMemFree (hashcat_ctx, device_param->hip_d_hooks);
      if (device_param->hip_d_result)         hc_hipMemFree (hashcat_ctx, device_param->hip_d_result);
      if (device_param->hip_d_extra0_buf)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_extra0_buf);
      if (device_param->hip_d_extra1_buf)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_extra1_buf);
      if (device_param->hip_d_extra2_buf)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_extra2_buf);
      if (device_param->hip_d_extra3_buf)     hc_hipMemFree (hashcat_ctx, device_param->hip_d_extra3_buf);
      if (device_param->hip_d_root_css_buf)   hc_hipMemFree (hashcat_ctx, device_param->hip_d_root_css_buf);
      if (device_param->hip_d_markov_css_buf) hc_hipMemFree (hashcat_ctx, device_param->hip_d_markov_css_buf);
      if (device_param->hip_d_tm_c)           hc_hipMemFree (hashcat_ctx, device_param->hip_d_tm_c);
      if (device_param->hip_d_st_digests_buf) hc_hipMemFree (hashcat_ctx, device_param->hip_d_st_digests_buf);
      if (device_param->hip_d_st_salts_buf)   hc_hipMemFree (hashcat_ctx, device_param->hip_d_st_salts_buf);
      if (device_param->hip_d_st_esalts_buf)  hc_hipMemFree (hashcat_ctx, device_param->hip_d_st_esalts_buf);
      if (device_param->hip_d_kernel_param)   hc_hipMemFree (hashcat_ctx, device_param->hip_d_kernel_param);

      if (device_param->hip_event1)           hc_hipEventDestroy (hashcat_ctx, device_param->hip_event1);
      if (device_param->hip_event2)           hc_hipEventDestroy (hashcat_ctx, device_param->hip_event2);
      if (device_param->hip_event3)           hc_hipEventDestroy (hashcat_ctx, device_param->hip_event3);

      if (device_param->hip_stream)           hc_hipStreamDestroy (hashcat_ctx, device_param->hip_stream);

      if (device_param->hip_module)           hc_hipModuleUnload (hashcat_ctx, device_param->hip_module);
      if (device_param->hip_module_mp)        hc_hipModuleUnload (hashcat_ctx, device_param->hip_module_mp);
      if (device_param->hip_module_amp)       hc_hipModuleUnload (hashcat_ctx, device_param->hip_module_amp);
      if (device_param->hip_module_shared)    hc_hipModuleUnload (hashcat_ctx, device_param->hip_module_shared);

      if (device_param->hip_context)          hc_hipCtxDestroy (hashcat_ctx, device_param->hip_context);

      device_param->hip_d_pws_buf            = 0;
      device_param->hip_d_pws_amp_buf        = 0;
      device_param->hip_d_pws_comp_buf       = 0;
      device_param->hip_d_pws_idx            = 0;
      device_param->hip_d_rules              = 0;
      device_param->hip_d_rules_c            = 0;
      device_param->hip_d_combs              = 0;
      device_param->hip_d_combs_c            = 0;
      device_param->hip_d_bfs                = 0;
      device_param->hip_d_bfs_c              = 0;
      device_param->hip_d_bitmap_s1_a        = 0;
      device_param->hip_d_bitmap_s1_b        = 0;
      device_param->hip_d_bitmap_s1_c        = 0;
      device_param->hip_d_bitmap_s1_d        = 0;
      device_param->hip_d_bitmap_s2_a        = 0;
      device_param->hip_d_bitmap_s2_b        = 0;
      device_param->hip_d_bitmap_s2_c        = 0;
      device_param->hip_d_bitmap_s2_d        = 0;
      device_param->hip_d_plain_bufs         = 0;
      device_param->hip_d_digests_buf        = 0;
      device_param->hip_d_digests_shown      = 0;
      device_param->hip_d_salt_bufs          = 0;
      device_param->hip_d_esalt_bufs         = 0;
      device_param->hip_d_tmps               = 0;
      device_param->hip_d_hooks              = 0;
      device_param->hip_d_result             = 0;
      device_param->hip_d_extra0_buf         = 0;
      device_param->hip_d_extra1_buf         = 0;
      device_param->hip_d_extra2_buf         = 0;
      device_param->hip_d_extra3_buf         = 0;
      device_param->hip_d_root_css_buf       = 0;
      device_param->hip_d_markov_css_buf     = 0;
      device_param->hip_d_tm_c               = 0;
      device_param->hip_d_st_digests_buf     = 0;
      device_param->hip_d_st_salts_buf       = 0;
      device_param->hip_d_st_esalts_buf      = 0;
      device_param->hip_d_kernel_param       = 0;

      device_param->hip_function1            = NULL;
      device_param->hip_function12           = NULL;
      device_param->hip_function2p           = NULL;
      device_param->hip_function2            = NULL;
      device_param->hip_function2e           = NULL;
      device_param->hip_function23           = NULL;
      device_param->hip_function3            = NULL;
      device_param->hip_function4            = NULL;
      device_param->hip_function_init2       = NULL;
      device_param->hip_function_loop2p      = NULL;
      device_param->hip_function_loop2       = NULL;
      device_param->hip_function_mp          = NULL;
      device_param->hip_function_mp_l        = NULL;
      device_param->hip_function_mp_r        = NULL;
      device_param->hip_function_tm          = NULL;
      device_param->hip_function_amp         = NULL;
      device_param->hip_function_memset      = NULL;
      device_param->hip_function_bzero       = NULL;
      device_param->hip_function_atinit      = NULL;
      device_param->hip_function_utf8toutf16le = NULL;
      device_param->hip_function_decompress  = NULL;
      device_param->hip_function_aux1        = NULL;
      device_param->hip_function_aux2        = NULL;
      device_param->hip_function_aux3        = NULL;
      device_param->hip_function_aux4        = NULL;

      device_param->hip_event1               = NULL;
      device_param->hip_event2               = NULL;
      device_param->hip_event3               = NULL;

      device_param->hip_stream               = NULL;

      device_param->hip_module               = NULL;
      device_param->hip_module_mp            = NULL;
      device_param->hip_module_amp           = NULL;
      device_param->hip_module_shared        = NULL;

      device_param->hip_context              = NULL;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (device_param->metal_d_pws_buf)              hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_pws_buf);
      if (device_param->metal_d_pws_amp_buf)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_pws_amp_buf);
      if (device_param->metal_d_pws_comp_buf)         hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_pws_comp_buf);
      if (device_param->metal_d_pws_idx)              hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_pws_idx);
      if (device_param->metal_d_rules)                hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_rules);
      if (device_param->metal_d_rules_c)              hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_rules_c);
      if (device_param->metal_d_combs)                hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_combs);
      if (device_param->metal_d_combs_c)              hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_combs_c);
      if (device_param->metal_d_bfs)                  hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bfs);
      if (device_param->metal_d_bfs_c)                hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bfs_c);
      if (device_param->metal_d_bitmap_s1_a)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s1_a);
      if (device_param->metal_d_bitmap_s1_b)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s1_b);
      if (device_param->metal_d_bitmap_s1_c)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s1_c);
      if (device_param->metal_d_bitmap_s1_d)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s1_d);
      if (device_param->metal_d_bitmap_s2_a)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s2_a);
      if (device_param->metal_d_bitmap_s2_b)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s2_b);
      if (device_param->metal_d_bitmap_s2_c)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s2_c);
      if (device_param->metal_d_bitmap_s2_d)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_bitmap_s2_d);
      if (device_param->metal_d_plain_bufs)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_plain_bufs);
      if (device_param->metal_d_digests_buf)          hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_digests_buf);
      if (device_param->metal_d_digests_shown)        hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_digests_shown);
      if (device_param->metal_d_salt_bufs)            hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_salt_bufs);
      if (device_param->metal_d_esalt_bufs)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_esalt_bufs);
      if (device_param->metal_d_tmps)                 hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_tmps);
      if (device_param->metal_d_hooks)                hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_hooks);
      if (device_param->metal_d_result)               hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_result);
      if (device_param->metal_d_extra0_buf)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_extra0_buf);
      if (device_param->metal_d_extra1_buf)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_extra1_buf);
      if (device_param->metal_d_extra2_buf)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_extra2_buf);
      if (device_param->metal_d_extra3_buf)           hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_extra3_buf);
      if (device_param->metal_d_root_css_buf)         hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_root_css_buf);
      if (device_param->metal_d_markov_css_buf)       hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_markov_css_buf);
      if (device_param->metal_d_tm_c)                 hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_tm_c);
      if (device_param->metal_d_st_digests_buf)       hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_st_digests_buf);
      if (device_param->metal_d_st_salts_buf)         hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_st_salts_buf);
      if (device_param->metal_d_st_esalts_buf)        hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_st_esalts_buf);
      if (device_param->metal_d_kernel_param)         hc_mtlReleaseMemObject (hashcat_ctx, device_param->metal_d_kernel_param);

      if (device_param->metal_function1)              hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function1);
      if (device_param->metal_function12)             hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function12);
      if (device_param->metal_function2p)             hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function2p);
      if (device_param->metal_function2)              hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function2);
      if (device_param->metal_function2e)             hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function2e);
      if (device_param->metal_function23)             hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function23);
      if (device_param->metal_function3)              hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function3);
      if (device_param->metal_function4)              hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function4);
      if (device_param->metal_function_init2)         hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_init2);
      if (device_param->metal_function_loop2p)        hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_loop2p);
      if (device_param->metal_function_loop2)         hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_loop2);
      if (device_param->metal_function_mp)            hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_mp);
      if (device_param->metal_function_mp_l)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_mp_l);
      if (device_param->metal_function_mp_r)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_mp_r);
      if (device_param->metal_function_tm)            hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_tm);
      if (device_param->metal_function_amp)           hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_amp);
      if (device_param->metal_function_memset)        hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_memset);
      if (device_param->metal_function_bzero)         hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_bzero);
      if (device_param->metal_function_atinit)        hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_atinit);
      if (device_param->metal_function_utf8toutf16le) hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_utf8toutf16le);
      if (device_param->metal_function_decompress)    hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_decompress);
      if (device_param->metal_function_aux1)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_aux1);
      if (device_param->metal_function_aux2)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_aux2);
      if (device_param->metal_function_aux3)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_aux3);
      if (device_param->metal_function_aux4)          hc_mtlReleaseFunction (hashcat_ctx, device_param->metal_function_aux4);

      if (device_param->metal_library)                hc_mtlReleaseLibrary (hashcat_ctx, device_param->metal_library);
      if (device_param->metal_library_mp)             hc_mtlReleaseLibrary (hashcat_ctx, device_param->metal_library_mp);
      if (device_param->metal_library_amp)            hc_mtlReleaseLibrary (hashcat_ctx, device_param->metal_library_amp);
      if (device_param->metal_library_shared)         hc_mtlReleaseLibrary (hashcat_ctx, device_param->metal_library_shared);

      if (device_param->metal_command_queue)          hc_mtlReleaseCommandQueue (hashcat_ctx, device_param->metal_command_queue);

      //if (device_param->metal_device)                 hc_mtlReleaseDevice (hashcat_ctx, device_param->metal_device);

      device_param->metal_d_pws_buf              = NULL;
      device_param->metal_d_pws_amp_buf          = NULL;
      device_param->metal_d_pws_comp_buf         = NULL;
      device_param->metal_d_pws_idx              = NULL;
      device_param->metal_d_rules                = NULL;
      device_param->metal_d_rules_c              = NULL;
      device_param->metal_d_combs                = NULL;
      device_param->metal_d_combs_c              = NULL;
      device_param->metal_d_bfs                  = NULL;
      device_param->metal_d_bfs_c                = NULL;
      device_param->metal_d_bitmap_s1_a          = NULL;
      device_param->metal_d_bitmap_s1_b          = NULL;
      device_param->metal_d_bitmap_s1_c          = NULL;
      device_param->metal_d_bitmap_s1_d          = NULL;
      device_param->metal_d_bitmap_s2_a          = NULL;
      device_param->metal_d_bitmap_s2_b          = NULL;
      device_param->metal_d_bitmap_s2_c          = NULL;
      device_param->metal_d_bitmap_s2_d          = NULL;
      device_param->metal_d_plain_bufs           = NULL;
      device_param->metal_d_digests_buf          = NULL;
      device_param->metal_d_digests_shown        = NULL;
      device_param->metal_d_salt_bufs            = NULL;
      device_param->metal_d_esalt_bufs           = NULL;
      device_param->metal_d_tmps                 = NULL;
      device_param->metal_d_hooks                = NULL;
      device_param->metal_d_result               = NULL;
      device_param->metal_d_extra0_buf           = NULL;
      device_param->metal_d_extra1_buf           = NULL;
      device_param->metal_d_extra2_buf           = NULL;
      device_param->metal_d_extra3_buf           = NULL;
      device_param->metal_d_root_css_buf         = NULL;
      device_param->metal_d_markov_css_buf       = NULL;
      device_param->metal_d_tm_c                 = NULL;
      device_param->metal_d_st_digests_buf       = NULL;
      device_param->metal_d_st_salts_buf         = NULL;
      device_param->metal_d_st_esalts_buf        = NULL;
      device_param->metal_d_kernel_param         = NULL;
      device_param->metal_function1              = NULL;
      device_param->metal_function12             = NULL;
      device_param->metal_function2p             = NULL;
      device_param->metal_function2              = NULL;
      device_param->metal_function2e             = NULL;
      device_param->metal_function23             = NULL;
      device_param->metal_function3              = NULL;
      device_param->metal_function4              = NULL;
      device_param->metal_function_init2         = NULL;
      device_param->metal_function_loop2p        = NULL;
      device_param->metal_function_loop2         = NULL;
      device_param->metal_function_mp            = NULL;
      device_param->metal_function_mp_l          = NULL;
      device_param->metal_function_mp_r          = NULL;
      device_param->metal_function_tm            = NULL;
      device_param->metal_function_amp           = NULL;
      device_param->metal_function_memset        = NULL;
      device_param->metal_function_bzero         = NULL;
      device_param->metal_function_atinit        = NULL;
      device_param->metal_function_utf8toutf16le = NULL;
      device_param->metal_function_decompress    = NULL;
      device_param->metal_function_aux1          = NULL;
      device_param->metal_function_aux2          = NULL;
      device_param->metal_function_aux3          = NULL;
      device_param->metal_function_aux4          = NULL;
      device_param->metal_library                = NULL;
      device_param->metal_library_mp             = NULL;
      device_param->metal_library_amp            = NULL;
      device_param->metal_library_shared         = NULL;
      device_param->metal_command_queue          = NULL;
      //device_param->metal_device                 = NULL;
    }
    #endif // __APPLE__

    if (device_param->is_opencl == true)
    {
      if (device_param->opencl_d_pws_buf)        hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_pws_buf);
      if (device_param->opencl_d_pws_amp_buf)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_pws_amp_buf);
      if (device_param->opencl_d_pws_comp_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_pws_comp_buf);
      if (device_param->opencl_d_pws_idx)        hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_pws_idx);
      if (device_param->opencl_d_rules)          hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_rules);
      if (device_param->opencl_d_rules_c)        hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_rules_c);
      if (device_param->opencl_d_combs)          hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_combs);
      if (device_param->opencl_d_combs_c)        hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_combs_c);
      if (device_param->opencl_d_bfs)            hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bfs);
      if (device_param->opencl_d_bfs_c)          hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bfs_c);
      if (device_param->opencl_d_bitmap_s1_a)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s1_a);
      if (device_param->opencl_d_bitmap_s1_b)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s1_b);
      if (device_param->opencl_d_bitmap_s1_c)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s1_c);
      if (device_param->opencl_d_bitmap_s1_d)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s1_d);
      if (device_param->opencl_d_bitmap_s2_a)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s2_a);
      if (device_param->opencl_d_bitmap_s2_b)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s2_b);
      if (device_param->opencl_d_bitmap_s2_c)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s2_c);
      if (device_param->opencl_d_bitmap_s2_d)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_bitmap_s2_d);
      if (device_param->opencl_d_plain_bufs)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_plain_bufs);
      if (device_param->opencl_d_digests_buf)    hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_digests_buf);
      if (device_param->opencl_d_digests_shown)  hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_digests_shown);
      if (device_param->opencl_d_salt_bufs)      hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_salt_bufs);
      if (device_param->opencl_d_esalt_bufs)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_esalt_bufs);
      if (device_param->opencl_d_tmps)           hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_tmps);
      if (device_param->opencl_d_hooks)          hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_hooks);
      if (device_param->opencl_d_result)         hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_result);
      if (device_param->opencl_d_extra0_buf)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_extra0_buf);
      if (device_param->opencl_d_extra1_buf)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_extra1_buf);
      if (device_param->opencl_d_extra2_buf)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_extra2_buf);
      if (device_param->opencl_d_extra3_buf)     hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_extra3_buf);
      if (device_param->opencl_d_root_css_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_root_css_buf);
      if (device_param->opencl_d_markov_css_buf) hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_markov_css_buf);
      if (device_param->opencl_d_tm_c)           hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_tm_c);
      if (device_param->opencl_d_st_digests_buf) hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_st_digests_buf);
      if (device_param->opencl_d_st_salts_buf)   hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_st_salts_buf);
      if (device_param->opencl_d_st_esalts_buf)  hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_st_esalts_buf);
      if (device_param->opencl_d_kernel_param)   hc_clReleaseMemObject (hashcat_ctx, device_param->opencl_d_kernel_param);

      if (device_param->opencl_kernel1)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel1);
      if (device_param->opencl_kernel12)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel12);
      if (device_param->opencl_kernel2p)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel2p);
      if (device_param->opencl_kernel2)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel2);
      if (device_param->opencl_kernel2e)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel2e);
      if (device_param->opencl_kernel23)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel23);
      if (device_param->opencl_kernel3)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel3);
      if (device_param->opencl_kernel4)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel4);
      if (device_param->opencl_kernel_init2)     hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_init2);
      if (device_param->opencl_kernel_loop2p)    hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_loop2p);
      if (device_param->opencl_kernel_loop2)     hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_loop2);
      if (device_param->opencl_kernel_mp)        hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp);
      if (device_param->opencl_kernel_mp_l)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp_l);
      if (device_param->opencl_kernel_mp_r)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp_r);
      if (device_param->opencl_kernel_tm)        hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_tm);
      if (device_param->opencl_kernel_amp)       hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_amp);
      if (device_param->opencl_kernel_memset)    hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_memset);
      if (device_param->opencl_kernel_bzero)     hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_bzero);
      if (device_param->opencl_kernel_atinit)    hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_atinit);
      if (device_param->opencl_kernel_utf8toutf16le) hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_utf8toutf16le);
      if (device_param->opencl_kernel_decompress)hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_decompress);
      if (device_param->opencl_kernel_aux1)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux1);
      if (device_param->opencl_kernel_aux2)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux2);
      if (device_param->opencl_kernel_aux3)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux3);
      if (device_param->opencl_kernel_aux4)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux4);

      if (device_param->opencl_program)          hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program);
      if (device_param->opencl_program_mp)       hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program_mp);
      if (device_param->opencl_program_amp)      hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program_amp);
      if (device_param->opencl_program_shared)   hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program_shared);

      if (device_param->opencl_command_queue)    hc_clReleaseCommandQueue (hashcat_ctx, device_param->opencl_command_queue);

      if (device_param->opencl_context)          hc_clReleaseContext (hashcat_ctx, device_param->opencl_context);

      device_param->opencl_d_pws_buf           = NULL;
      device_param->opencl_d_pws_amp_buf       = NULL;
      device_param->opencl_d_pws_comp_buf      = NULL;
      device_param->opencl_d_pws_idx           = NULL;
      device_param->opencl_d_rules             = NULL;
      device_param->opencl_d_rules_c           = NULL;
      device_param->opencl_d_combs             = NULL;
      device_param->opencl_d_combs_c           = NULL;
      device_param->opencl_d_bfs               = NULL;
      device_param->opencl_d_bfs_c             = NULL;
      device_param->opencl_d_bitmap_s1_a       = NULL;
      device_param->opencl_d_bitmap_s1_b       = NULL;
      device_param->opencl_d_bitmap_s1_c       = NULL;
      device_param->opencl_d_bitmap_s1_d       = NULL;
      device_param->opencl_d_bitmap_s2_a       = NULL;
      device_param->opencl_d_bitmap_s2_b       = NULL;
      device_param->opencl_d_bitmap_s2_c       = NULL;
      device_param->opencl_d_bitmap_s2_d       = NULL;
      device_param->opencl_d_plain_bufs        = NULL;
      device_param->opencl_d_digests_buf       = NULL;
      device_param->opencl_d_digests_shown     = NULL;
      device_param->opencl_d_salt_bufs         = NULL;
      device_param->opencl_d_esalt_bufs        = NULL;
      device_param->opencl_d_tmps              = NULL;
      device_param->opencl_d_hooks             = NULL;
      device_param->opencl_d_result            = NULL;
      device_param->opencl_d_extra0_buf        = NULL;
      device_param->opencl_d_extra1_buf        = NULL;
      device_param->opencl_d_extra2_buf        = NULL;
      device_param->opencl_d_extra3_buf        = NULL;
      device_param->opencl_d_root_css_buf      = NULL;
      device_param->opencl_d_markov_css_buf    = NULL;
      device_param->opencl_d_tm_c              = NULL;
      device_param->opencl_d_st_digests_buf    = NULL;
      device_param->opencl_d_st_salts_buf      = NULL;
      device_param->opencl_d_st_esalts_buf     = NULL;
      device_param->opencl_d_kernel_param      = NULL;
      device_param->opencl_kernel1             = NULL;
      device_param->opencl_kernel12            = NULL;
      device_param->opencl_kernel2p            = NULL;
      device_param->opencl_kernel2             = NULL;
      device_param->opencl_kernel2e            = NULL;
      device_param->opencl_kernel23            = NULL;
      device_param->opencl_kernel3             = NULL;
      device_param->opencl_kernel4             = NULL;
      device_param->opencl_kernel_init2        = NULL;
      device_param->opencl_kernel_loop2p       = NULL;
      device_param->opencl_kernel_loop2        = NULL;
      device_param->opencl_kernel_mp           = NULL;
      device_param->opencl_kernel_mp_l         = NULL;
      device_param->opencl_kernel_mp_r         = NULL;
      device_param->opencl_kernel_tm           = NULL;
      device_param->opencl_kernel_amp          = NULL;
      device_param->opencl_kernel_memset       = NULL;
      device_param->opencl_kernel_bzero        = NULL;
      device_param->opencl_kernel_atinit       = NULL;
      device_param->opencl_kernel_utf8toutf16le = NULL;
      device_param->opencl_kernel_decompress   = NULL;
      device_param->opencl_kernel_aux1         = NULL;
      device_param->opencl_kernel_aux2         = NULL;
      device_param->opencl_kernel_aux3         = NULL;
      device_param->opencl_kernel_aux4         = NULL;
      device_param->opencl_program             = NULL;
      device_param->opencl_program_mp          = NULL;
      device_param->opencl_program_amp         = NULL;
      device_param->opencl_program_shared      = NULL;
      device_param->opencl_command_queue       = NULL;
      device_param->opencl_context             = NULL;
    }

    device_param->pws_comp            = NULL;
    device_param->pws_idx             = NULL;
    device_param->pws_pre_buf         = NULL;
    device_param->pws_base_buf        = NULL;
    device_param->combs_buf           = NULL;
    device_param->hooks_buf           = NULL;
    device_param->scratch_buf         = NULL;
    #ifdef WITH_BRAIN
    device_param->brain_link_in_buf   = NULL;
    device_param->brain_link_out_buf  = NULL;
    #endif
  }
}

void backend_session_reset (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  if (backend_ctx->enabled == false) return;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

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

    device_param->kernel_power   = 0;
    device_param->hardware_power = 0;
  }

  backend_ctx->kernel_power_all   = 0;
  backend_ctx->kernel_power_final = 0;
}

int backend_session_update_combinator (hashcat_ctx_t *hashcat_ctx)
{
  combinator_ctx_t *combinator_ctx = hashcat_ctx->combinator_ctx;
  hashconfig_t     *hashconfig     = hashcat_ctx->hashconfig;
  backend_ctx_t    *backend_ctx    = hashcat_ctx->backend_ctx;
  user_options_t   *user_options   = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    // kernel_params

    device_param->kernel_param.combs_mode = combinator_ctx->combs_mode;

    // kernel_params_amp

    if (user_options->slow_candidates == true)
    {
    }
    else
    {
      device_param->kernel_params_amp_buf32[5] = combinator_ctx->combs_mode;

      if (hashconfig->attack_exec == ATTACK_EXEC_OUTSIDE_KERNEL)
      {
        if (device_param->is_opencl == true)
        {
          const int rc_clSetKernelArg = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_amp, 5, sizeof (cl_uint), device_param->kernel_params_amp[5]);

          if (rc_clSetKernelArg == -1) return -1;
        }
      }
    }
  }

  return 0;
}

int backend_session_update_mp (hashcat_ctx_t *hashcat_ctx)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  if (user_options->slow_candidates == true) return 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    device_param->kernel_params_mp_buf64[3] = 0;
    device_param->kernel_params_mp_buf32[4] = mask_ctx->css_cnt;

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css,   device_param->cuda_stream)   == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css, device_param->cuda_stream) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css,   device_param->hip_stream)   == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css, device_param->hip_stream) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_root_css_buf,   0, mask_ctx->root_css_buf,   device_param->size_root_css)   == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_markov_css_buf, 0, mask_ctx->markov_css_buf, device_param->size_markov_css) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_root_css_buf,   CL_FALSE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_markov_css_buf, CL_FALSE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL) == -1) return -1;

      if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
    }
  }

  return 0;
}

int backend_session_update_mp_rl (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  if (user_options->slow_candidates == true) return 0;

  for (int backend_devices_idx = 0; backend_devices_idx < backend_ctx->backend_devices_cnt; backend_devices_idx++)
  {
    hc_device_param_t *device_param = &backend_ctx->devices_param[backend_devices_idx];

    if (device_param->skipped == true) continue;
    if (device_param->skipped_warning == true) continue;

    device_param->kernel_params_mp_l_buf64[3] = 0;
    device_param->kernel_params_mp_l_buf32[4] = css_cnt_l;
    device_param->kernel_params_mp_l_buf32[5] = css_cnt_r;

    device_param->kernel_params_mp_r_buf64[3] = 0;
    device_param->kernel_params_mp_r_buf32[4] = css_cnt_r;

    if (device_param->is_cuda == true)
    {
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css,   device_param->cuda_stream) == -1) return -1;
      if (hc_cuMemcpyHtoDAsync (hashcat_ctx, device_param->cuda_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css, device_param->cuda_stream) == -1) return -1;
    }

    if (device_param->is_hip == true)
    {
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css,   device_param->hip_stream) == -1) return -1;
      if (hc_hipMemcpyHtoDAsync (hashcat_ctx, device_param->hip_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css, device_param->hip_stream) == -1) return -1;
    }

    #if defined (__APPLE__)
    if (device_param->is_metal == true)
    {
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_root_css_buf,   0, mask_ctx->root_css_buf,   device_param->size_root_css)   == -1) return -1;
      if (hc_mtlMemcpyHtoD (hashcat_ctx, device_param->metal_command_queue, device_param->metal_d_markov_css_buf, 0, mask_ctx->markov_css_buf, device_param->size_markov_css) == -1) return -1;
    }
    #endif

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_root_css_buf,   CL_FALSE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_markov_css_buf, CL_FALSE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL) == -1) return -1;

      if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
    }
  }

  return 0;
}

void *hook12_thread (void *p)
{
  hook_thread_param_t *hook_thread_param = (hook_thread_param_t *) p;

  module_ctx_t *module_ctx = hook_thread_param->module_ctx;
  status_ctx_t *status_ctx = hook_thread_param->status_ctx;

  const u64 tid     = hook_thread_param->tid;
  const u64 tsz     = hook_thread_param->tsz;
  const u64 pws_cnt = hook_thread_param->pws_cnt;

  for (u64 pw_pos = tid; pw_pos < pws_cnt; pw_pos += tsz)
  {
    while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

    if (status_ctx->devices_status == STATUS_RUNNING)
    {
      module_ctx->module_hook12 (hook_thread_param->device_param, hook_thread_param->hook_extra_param, hook_thread_param->hook_salts_buf, hook_thread_param->salt_pos, pw_pos);
    }
  }

  return NULL;
}

void *hook23_thread (void *p)
{
  hook_thread_param_t *hook_thread_param = (hook_thread_param_t *) p;

  module_ctx_t *module_ctx = hook_thread_param->module_ctx;
  status_ctx_t *status_ctx = hook_thread_param->status_ctx;

  const u64 tid     = hook_thread_param->tid;
  const u64 tsz     = hook_thread_param->tsz;
  const u64 pws_cnt = hook_thread_param->pws_cnt;

  for (u64 pw_pos = tid; pw_pos < pws_cnt; pw_pos += tsz)
  {
    while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

    if (status_ctx->devices_status == STATUS_RUNNING)
    {
      module_ctx->module_hook23 (hook_thread_param->device_param, hook_thread_param->hook_extra_param, hook_thread_param->hook_salts_buf, hook_thread_param->salt_pos, pw_pos);
    }
  }

  return NULL;
}
