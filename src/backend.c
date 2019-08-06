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

#if defined (__linux__)
static const char *dri_card0_path = "/dev/dri/card0";

static const char *drm_card0_vendor_path = "/sys/class/drm/card0/device/vendor";
static const char *drm_card0_driver_path = "/sys/class/drm/card0/device/driver";
#endif

static const u32 full01 = 0x01010101;
static const u32 full06 = 0x06060606;
static const u32 full80 = 0x80808080;

static double TARGET_MSEC_PROFILE[4] = { 2, 12, 96, 480 };

static bool is_same_device (const hc_device_param_t *src, const hc_device_param_t *dst)
{
  if (src->pcie_bus      != dst->pcie_bus)      return false;
  if (src->pcie_device   != dst->pcie_device)   return false;
  if (src->pcie_function != dst->pcie_function) return false;

  return true;
}

static int backend_ctx_find_alias_devices (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

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

      if (is_same_device (device_param_src, device_param_dst) == false) continue;

      device_param_src->device_id_alias_buf[device_param_src->device_id_alias_cnt] = device_param_dst->device_id;
      device_param_src->device_id_alias_cnt++;

      device_param_dst->device_id_alias_buf[device_param_dst->device_id_alias_cnt] = device_param_src->device_id;
      device_param_dst->device_id_alias_cnt++;

      if (device_param_dst->is_opencl == true)
      {
        if (device_param_dst->skipped == false)
        {
          device_param_dst->skipped = true;

          backend_ctx->opencl_devices_active--;

          backend_ctx->backend_devices_active--;
        }
      }
    }
  }

  return -1;
}

static bool is_same_device_type (const hc_device_param_t *src, const hc_device_param_t *dst)
{
  if (strcmp (src->device_name, dst->device_name) != 0) return false;

  if (src->is_cuda   != dst->is_cuda)   return false;
  if (src->is_opencl != dst->is_opencl) return false;

  if (src->is_cuda == true)
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
    // Do not use CPU by default, this often reduces GPU performance because
    // the CPU is too busy to handle GPU synchronization

    opencl_device_types_filter = CL_DEVICE_TYPE_ALL & ~CL_DEVICE_TYPE_CPU;
  }

  *out = opencl_device_types_filter;

  return true;
}

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

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

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

  CUDA_PTR *cuda = backend_ctx->cuda;

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

static bool opencl_test_instruction (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_device_id device, const char *kernel_buf)
{
  cl_program program;

  if (hc_clCreateProgramWithSource (hashcat_ctx, context, 1, &kernel_buf, NULL, &program) == -1) return false;

  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  // LLVM seems to write an error message (if there's an error) directly to stderr
  // and not (as supposted to) into buffer for later request using clGetProgramBuildInfo()

  #ifndef DEBUG
  #ifndef _WIN
  fflush (stderr);
  int bak = fcntl(2, F_DUPFD_CLOEXEC);
  int tmp = open ("/dev/null", O_WRONLY | O_CLOEXEC);
  dup2 (tmp, 2);
  close (tmp);
  #endif
  #endif

  int CL_rc = ocl->clBuildProgram (program, 1, &device, "-Werror", NULL, NULL); // do not use the wrapper to avoid the error message

  #ifndef DEBUG
  #ifndef _WIN
  fflush (stderr);
  #ifndef __APPLE__
  dup3 (bak, 2, O_CLOEXEC);
  #else
  dup2 (bak, 2);
  #endif
  close (bak);
  #endif
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

static bool read_kernel_binary (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, size_t *kernel_lengths, char **kernel_sources, const bool force_recompile)
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

    #define EXTRASZ 100

    size_t klen = st.st_size;

    char *buf = (char *) hcmalloc (klen + 1 + EXTRASZ);

    size_t num_read = hc_fread (buf, sizeof (char), klen, &fp);

    hc_fclose (&fp);

    if (num_read != klen)
    {
      event_log_error (hashcat_ctx, "%s: %s", kernel_file, strerror (errno));

      hcfree (buf);

      return false;
    }

    buf[klen] = 0;

    if (force_recompile == true)
    {
      // this adds some hopefully unique data to the backend kernel source
      // the effect should be that backend kernel compiler caching see this as new "uncached" source
      // we have to do this since they do not check for the changes only in the #include source

      time_t tlog = time (NULL);

      const int extra_len = snprintf (buf + klen, EXTRASZ, "\n//%u\n", (u32) tlog);

      klen += extra_len;
    }

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

static bool write_kernel_binary (hashcat_ctx_t *hashcat_ctx, char *kernel_file, char *binary, size_t binary_size)
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

// NVRTC

int nvrtc_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  memset (nvrtc, 0, sizeof (NVRTC_PTR));

  #if   defined (_WIN)
  nvrtc->lib = hc_dlopen ("nvrtc.dll");

  if (nvrtc->lib == NULL)
  {
    // super annoying: nvidia is using the CUDA version in nvrtc???.dll filename!
    // however, the cuda version string comes from nvcuda.dll which is from nvidia driver, but
    // the driver version and the installed CUDA toolkit version can be different, so it cannot be used as a reference.
    // brute force to the rescue

    char dllname[100];

    for (int major = 20; major >= 10; major--) // older than 3.x do not ship _v2 functions anyway
                                               // older than 7.x does not support sm 5.x
                                               // older than 8.x does not have documentation archive online, no way to check if nvrtc support whatever we need
                                               // older than 10.x is just a theoretical limit since we define 10.1 as the minimum required version
    {
      for (int minor = 20; minor >= 0; minor--)
      {
        snprintf (dllname, sizeof (dllname), "nvrtc64_%d%d.dll", major, minor);

        nvrtc->lib = hc_dlopen (dllname);

        if (nvrtc->lib) break;

        snprintf (dllname, sizeof (dllname), "nvrtc64_%d%d_0.dll", major, minor);

        nvrtc->lib = hc_dlopen (dllname);

        if (nvrtc->lib) break;
      }

      if (nvrtc->lib) break;
    }
  }
  #elif defined (__APPLE__)
  nvrtc->lib = hc_dlopen ("nvrtc.dylib");
  #elif defined (__CYGWIN__)
  nvrtc->lib = hc_dlopen ("nvrtc.dll");
  #else
  nvrtc->lib = hc_dlopen ("libnvrtc.so");

  if (nvrtc->lib == NULL) nvrtc->lib = hc_dlopen ("libnvrtc.so.1");
  #endif

  if (nvrtc->lib == NULL) return -1;

  HC_LOAD_FUNC (nvrtc, nvrtcAddNameExpression,  NVRTC_NVRTCADDNAMEEXPRESSION, NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcCompileProgram,     NVRTC_NVRTCCOMPILEPROGRAM,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcCreateProgram,      NVRTC_NVRTCCREATEPROGRAM,     NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcDestroyProgram,     NVRTC_NVRTCDESTROYPROGRAM,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetLoweredName,     NVRTC_NVRTCGETLOWEREDNAME,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetPTX,             NVRTC_NVRTCGETPTX,            NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetPTXSize,         NVRTC_NVRTCGETPTXSIZE,        NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetProgramLog,      NVRTC_NVRTCGETPROGRAMLOG,     NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetProgramLogSize,  NVRTC_NVRTCGETPROGRAMLOGSIZE, NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcGetErrorString,     NVRTC_NVRTCGETERRORSTRING,    NVRTC, 1);
  HC_LOAD_FUNC (nvrtc, nvrtcVersion,            NVRTC_NVRTCVERSION,           NVRTC, 1);

  return 0;
}

void nvrtc_close (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  if (nvrtc)
  {
    if (nvrtc->lib)
    {
      hc_dlclose (nvrtc->lib);
    }

    hcfree (backend_ctx->nvrtc);

    backend_ctx->nvrtc = NULL;
  }
}

int hc_nvrtcCreateProgram (hashcat_ctx_t *hashcat_ctx, nvrtcProgram *prog, const char *src, const char *name, int numHeaders, const char * const *headers, const char * const *includeNames)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcCreateProgram (prog, src, name, numHeaders, headers, includeNames);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcCreateProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcDestroyProgram (hashcat_ctx_t *hashcat_ctx, nvrtcProgram *prog)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcDestroyProgram (prog);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcDestroyProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcCompileProgram (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, int numOptions, const char * const *options)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcCompileProgram (prog, numOptions, options);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcCompileProgram(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetProgramLogSize (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, size_t *logSizeRet)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetProgramLogSize (prog, logSizeRet);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetProgramLogSize(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetProgramLog (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, char *log)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetProgramLog (prog, log);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetProgramLog(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetPTXSize (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, size_t *ptxSizeRet)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetPTXSize (prog, ptxSizeRet);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetPTXSize(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcGetPTX (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, char *ptx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcGetPTX (prog, ptx);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcGetPTX(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

int hc_nvrtcVersion (hashcat_ctx_t *hashcat_ctx, int *major, int *minor)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  NVRTC_PTR *nvrtc = backend_ctx->nvrtc;

  const nvrtcResult NVRTC_err = nvrtc->nvrtcVersion (major, minor);

  if (NVRTC_err != NVRTC_SUCCESS)
  {
    event_log_error (hashcat_ctx, "nvrtcVersion(): %s", nvrtc->nvrtcGetErrorString (NVRTC_err));

    return -1;
  }

  return 0;
}

// CUDA

int cuda_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  memset (cuda, 0, sizeof (CUDA_PTR));

  #if   defined (_WIN)
  cuda->lib = hc_dlopen ("nvcuda.dll");
  #elif defined (__APPLE__)
  cuda->lib = hc_dlopen ("nvcuda.dylib");
  #elif defined (__CYGWIN__)
  cuda->lib = hc_dlopen ("nvcuda.dll");
  #else
  cuda->lib = hc_dlopen ("libcuda.so");

  if (cuda->lib == NULL) cuda->lib = hc_dlopen ("libcuda.so.1");
  #endif

  if (cuda->lib == NULL) return -1;

  #define HC_LOAD_FUNC_CUDA(ptr,name,cudaname,type,libname,noerr) \
    ptr->name = (type) hc_dlsym ((ptr)->lib, #cudaname); \
    if ((noerr) != -1) { \
      if (!(ptr)->name) { \
        if ((noerr) == 1) { \
          event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
          return -1; \
        } \
        if ((noerr) != 1) { \
          event_log_warning (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
          return 0; \
        } \
      } \
    }

  // finding the right symbol is a PITA, because of the _v2 suffix
  // a good reference is cuda.h itself
  // this needs to be verified for each new cuda release

  HC_LOAD_FUNC_CUDA (cuda, cuCtxCreate,              cuCtxCreate_v2,            CUDA_CUCTXCREATE,               CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxDestroy,             cuCtxDestroy_v2,           CUDA_CUCTXDESTROY,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetCacheConfig,      cuCtxGetCacheConfig,       CUDA_CUCTXGETCACHECONFIG,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetCurrent,          cuCtxGetCurrent,           CUDA_CUCTXGETCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetSharedMemConfig,  cuCtxGetSharedMemConfig,   CUDA_CUCTXGETSHAREDMEMCONFIG,   CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxPopCurrent,          cuCtxPopCurrent_v2,        CUDA_CUCTXPOPCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxPushCurrent,         cuCtxPushCurrent_v2,       CUDA_CUCTXPUSHCURRENT,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetCacheConfig,      cuCtxSetCacheConfig,       CUDA_CUCTXSETCACHECONFIG,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetCurrent,          cuCtxSetCurrent,           CUDA_CUCTXSETCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetSharedMemConfig,  cuCtxSetSharedMemConfig,   CUDA_CUCTXSETSHAREDMEMCONFIG,   CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSynchronize,         cuCtxSynchronize,          CUDA_CUCTXSYNCHRONIZE,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetAttribute,     cuDeviceGetAttribute,      CUDA_CUDEVICEGETATTRIBUTE,      CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetCount,         cuDeviceGetCount,          CUDA_CUDEVICEGETCOUNT,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGet,              cuDeviceGet,               CUDA_CUDEVICEGET,               CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetName,          cuDeviceGetName,           CUDA_CUDEVICEGETNAME,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceTotalMem,         cuDeviceTotalMem_v2,       CUDA_CUDEVICETOTALMEM,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDriverGetVersion,       cuDriverGetVersion,        CUDA_CUDRIVERGETVERSION,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventCreate,            cuEventCreate,             CUDA_CUEVENTCREATE,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventDestroy,           cuEventDestroy_v2,         CUDA_CUEVENTDESTROY,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventElapsedTime,       cuEventElapsedTime,        CUDA_CUEVENTELAPSEDTIME,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventQuery,             cuEventQuery,              CUDA_CUEVENTQUERY,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventRecord,            cuEventRecord,             CUDA_CUEVENTRECORD,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventSynchronize,       cuEventSynchronize,        CUDA_CUEVENTSYNCHRONIZE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncGetAttribute,       cuFuncGetAttribute,        CUDA_CUFUNCGETATTRIBUTE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetAttribute,       cuFuncSetAttribute,        CUDA_CUFUNCSETATTRIBUTE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetCacheConfig,     cuFuncSetCacheConfig,      CUDA_CUFUNCSETCACHECONFIG,      CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetSharedMemConfig, cuFuncSetSharedMemConfig,  CUDA_CUFUNCSETSHAREDMEMCONFIG,  CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuGetErrorName,           cuGetErrorName,            CUDA_CUGETERRORNAME,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuGetErrorString,         cuGetErrorString,          CUDA_CUGETERRORSTRING,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuInit,                   cuInit,                    CUDA_CUINIT,                    CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuLaunchKernel,           cuLaunchKernel,            CUDA_CULAUNCHKERNEL,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemAlloc,               cuMemAlloc_v2,             CUDA_CUMEMALLOC,                CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemAllocHost,           cuMemAllocHost_v2,         CUDA_CUMEMALLOCHOST,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyDtoD,             cuMemcpyDtoD_v2,           CUDA_CUMEMCPYDTOD,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyDtoH,             cuMemcpyDtoH_v2,           CUDA_CUMEMCPYDTOH,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyHtoD,             cuMemcpyHtoD_v2,           CUDA_CUMEMCPYHTOD,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemFree,                cuMemFree_v2,              CUDA_CUMEMFREE,                 CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemFreeHost,            cuMemFreeHost,             CUDA_CUMEMFREEHOST,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemGetInfo,             cuMemGetInfo_v2,           CUDA_CUMEMGETINFO,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemsetD32,              cuMemsetD32_v2,            CUDA_CUMEMSETD32,               CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemsetD8,               cuMemsetD8_v2,             CUDA_CUMEMSETD8,                CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleGetFunction,      cuModuleGetFunction,       CUDA_CUMODULEGETFUNCTION,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleGetGlobal,        cuModuleGetGlobal_v2,      CUDA_CUMODULEGETGLOBAL,         CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoad,             cuModuleLoad,              CUDA_CUMODULELOAD,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoadData,         cuModuleLoadData,          CUDA_CUMODULELOADDATA,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoadDataEx,       cuModuleLoadDataEx,        CUDA_CUMODULELOADDATAEX,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleUnload,           cuModuleUnload,            CUDA_CUMODULEUNLOAD,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuProfilerStart,          cuProfilerStart,           CUDA_CUPROFILERSTART,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuProfilerStop,           cuProfilerStop,            CUDA_CUPROFILERSTOP,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamCreate,           cuStreamCreate,            CUDA_CUSTREAMCREATE,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamDestroy,          cuStreamDestroy_v2,        CUDA_CUSTREAMDESTROY,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamSynchronize,      cuStreamSynchronize,       CUDA_CUSTREAMSYNCHRONIZE,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamWaitEvent,        cuStreamWaitEvent,         CUDA_CUSTREAMWAITEVENT,         CUDA, 1);

  return 0;
}

void cuda_close (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  if (cuda)
  {
    if (cuda->lib)
    {
      hc_dlclose (cuda->lib);
    }

    hcfree (backend_ctx->cuda);

    backend_ctx->cuda = NULL;
  }
}

int hc_cuInit (hashcat_ctx_t *hashcat_ctx, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuInit (Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuInit(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuInit(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetAttribute (hashcat_ctx_t *hashcat_ctx, int *pi, CUdevice_attribute attrib, CUdevice dev)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetAttribute (pi, attrib, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetCount (hashcat_ctx_t *hashcat_ctx, int *count)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetCount (count);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetCount(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetCount(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGet (hashcat_ctx_t *hashcat_ctx, CUdevice* device, int ordinal)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGet (device, ordinal);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGet(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGet(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetName (hashcat_ctx_t *hashcat_ctx, char *name, int len, CUdevice dev)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetName (name, len, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetName(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetName(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceTotalMem (hashcat_ctx_t *hashcat_ctx, size_t *bytes, CUdevice dev)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceTotalMem (bytes, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceTotalMem(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceTotalMem(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDriverGetVersion (hashcat_ctx_t *hashcat_ctx, int *driverVersion)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDriverGetVersion (driverVersion);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDriverGetVersion(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDriverGetVersion(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxCreate (hashcat_ctx_t *hashcat_ctx, CUcontext *pctx, unsigned int flags, CUdevice dev)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxCreate (pctx, flags, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxDestroy (hashcat_ctx_t *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxDestroy (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleLoadDataEx (hashcat_ctx_t *hashcat_ctx, CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleLoadDataEx (module, image, numOptions, options, optionValues);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleLoadDataEx(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleLoadDataEx(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleLoadDataExLog (hashcat_ctx_t *hashcat_ctx, CUmodule *module, const void *image)
{
  #define LOG_SIZE 8192

  char *info_log  = hcmalloc (LOG_SIZE);
  char *error_log = hcmalloc (LOG_SIZE);

  CUjit_option opts[6];
  void *vals[6];

  opts[0] = CU_JIT_TARGET_FROM_CUCONTEXT;
  vals[0] = (void *) 0;

  opts[1] = CU_JIT_LOG_VERBOSE;
  vals[1] = (void *) 1;

  opts[2] = CU_JIT_INFO_LOG_BUFFER;
  vals[2] = (void *) info_log;

  opts[3] = CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES;
  vals[3] = (void *) LOG_SIZE;

  opts[4] = CU_JIT_ERROR_LOG_BUFFER;
  vals[4] = (void *) error_log;

  opts[5] = CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES;
  vals[5] = (void *) LOG_SIZE;

  const int rc_cuModuleLoadDataEx = hc_cuModuleLoadDataEx (hashcat_ctx, module, image, 6, opts, vals);

  #if defined (DEBUG)
  printf ("cuModuleLoadDataEx() Info Log (%d):\n%s\n\n",  (int) strlen (info_log),  info_log);
  printf ("cuModuleLoadDataEx() Error Log (%d):\n%s\n\n", (int) strlen (error_log), error_log);
  #else
  if (rc_cuModuleLoadDataEx == -1)
  {
    printf ("cuModuleLoadDataEx() Info Log (%d):\n%s\n\n",  (int) strlen (info_log),  info_log);
    printf ("cuModuleLoadDataEx() Error Log (%d):\n%s\n\n", (int) strlen (error_log), error_log);
  }
  #endif

  hcfree (info_log);
  hcfree (error_log);

  return rc_cuModuleLoadDataEx;
}

int hc_cuModuleUnload (hashcat_ctx_t *hashcat_ctx, CUmodule hmod)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleUnload (hmod);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleUnload(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleUnload(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSetCurrent (hashcat_ctx_t *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSetCurrent (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSetCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSetCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemAlloc (hashcat_ctx_t *hashcat_ctx, CUdeviceptr *dptr, size_t bytesize)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemAlloc (dptr, bytesize);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemAlloc(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemAlloc(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemFree (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dptr)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemFree (dptr);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemFree(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemFree(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyDtoH (hashcat_ctx_t *hashcat_ctx, void *dstHost, CUdeviceptr srcDevice, size_t ByteCount)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyDtoH (dstHost, srcDevice, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoH(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoH(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyDtoD (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyDtoD (dstDevice, srcDevice, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoD(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoD(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyHtoD (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyHtoD (dstDevice, srcHost, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyHtoD(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyHtoD(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleGetFunction (hashcat_ctx_t *hashcat_ctx, CUfunction *hfunc, CUmodule hmod, const char *name)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleGetFunction (hfunc, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleGetFunction(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleGetFunction(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleGetGlobal (hashcat_ctx_t *hashcat_ctx, CUdeviceptr *dptr, size_t *bytes, CUmodule hmod, const char *name)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleGetGlobal (dptr, bytes, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleGetGlobal(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleGetGlobal(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemGetInfo (hashcat_ctx_t *hashcat_ctx, size_t *free, size_t *total)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemGetInfo (free, total);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemGetInfo(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemGetInfo(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuFuncGetAttribute (hashcat_ctx_t *hashcat_ctx, int *pi, CUfunction_attribute attrib, CUfunction hfunc)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuFuncGetAttribute (pi, attrib, hfunc);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuFuncGetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuFuncGetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuFuncSetAttribute (hashcat_ctx_t *hashcat_ctx, CUfunction hfunc, CUfunction_attribute attrib, int value)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuFuncSetAttribute (hfunc, attrib, value);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuFuncSetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuFuncSetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamCreate (hashcat_ctx_t *hashcat_ctx, CUstream *phStream, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamCreate (phStream, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamDestroy (hashcat_ctx_t *hashcat_ctx, CUstream hStream)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamDestroy (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamSynchronize (hashcat_ctx_t *hashcat_ctx, CUstream hStream)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamSynchronize (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLaunchKernel (hashcat_ctx_t *hashcat_ctx, CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLaunchKernel (f, gridDimX, gridDimY, gridDimZ, blockDimX, blockDimY, blockDimZ, sharedMemBytes, hStream, kernelParams, extra);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLaunchKernel(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLaunchKernel(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSynchronize (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSynchronize ();

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventCreate (hashcat_ctx_t *hashcat_ctx, CUevent *phEvent, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventCreate (phEvent, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventDestroy (hashcat_ctx_t *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventDestroy (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventElapsedTime (hashcat_ctx_t *hashcat_ctx, float *pMilliseconds, CUevent hStart, CUevent hEnd)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventElapsedTime (pMilliseconds, hStart, hEnd);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventElapsedTime(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventElapsedTime(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventQuery (hashcat_ctx_t *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventQuery (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventQuery(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventQuery(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventRecord (hashcat_ctx_t *hashcat_ctx, CUevent hEvent, CUstream hStream)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventRecord (hEvent, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventRecord(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventRecord(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventSynchronize (hashcat_ctx_t *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventSynchronize (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSetCacheConfig (hashcat_ctx_t *hashcat_ctx, CUfunc_cache config)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSetCacheConfig (config);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSetCacheConfig(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSetCacheConfig(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxPushCurrent (hashcat_ctx_t *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxPushCurrent (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxPushCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxPushCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxPopCurrent (hashcat_ctx_t *hashcat_ctx, CUcontext *pctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  CUDA_PTR *cuda = backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxPopCurrent (pctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxPopCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxPopCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}


// OpenCL

int ocl_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  memset (ocl, 0, sizeof (OCL_PTR));

  #if   defined (_WIN)
  ocl->lib = hc_dlopen ("OpenCL");
  #elif defined (__APPLE__)
  ocl->lib = hc_dlopen ("/System/Library/Frameworks/OpenCL.framework/OpenCL");
  #elif defined (__CYGWIN__)
  ocl->lib = hc_dlopen ("opencl.dll");

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("cygOpenCL-1.dll");
  #else
  ocl->lib = hc_dlopen ("libOpenCL.so");

  if (ocl->lib == NULL) ocl->lib = hc_dlopen ("libOpenCL.so.1");
  #endif

  if (ocl->lib == NULL) return -1;

  HC_LOAD_FUNC (ocl, clBuildProgram,            OCL_CLBUILDPROGRAM,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateBuffer,            OCL_CLCREATEBUFFER,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateCommandQueue,      OCL_CLCREATECOMMANDQUEUE,       OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateContext,           OCL_CLCREATECONTEXT,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateKernel,            OCL_CLCREATEKERNEL,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateProgramWithBinary, OCL_CLCREATEPROGRAMWITHBINARY,  OpenCL, 1);
  HC_LOAD_FUNC (ocl, clCreateProgramWithSource, OCL_CLCREATEPROGRAMWITHSOURCE,  OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueCopyBuffer,       OCL_CLENQUEUECOPYBUFFER,        OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueMapBuffer,        OCL_CLENQUEUEMAPBUFFER,         OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueNDRangeKernel,    OCL_CLENQUEUENDRANGEKERNEL,     OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueReadBuffer,       OCL_CLENQUEUEREADBUFFER,        OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueUnmapMemObject,   OCL_CLENQUEUEUNMAPMEMOBJECT,    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clEnqueueWriteBuffer,      OCL_CLENQUEUEWRITEBUFFER,       OpenCL, 1);
  HC_LOAD_FUNC (ocl, clFinish,                  OCL_CLFINISH,                   OpenCL, 1);
  HC_LOAD_FUNC (ocl, clFlush,                   OCL_CLFLUSH,                    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetDeviceIDs,            OCL_CLGETDEVICEIDS,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetDeviceInfo,           OCL_CLGETDEVICEINFO,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetEventInfo,            OCL_CLGETEVENTINFO,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetKernelWorkGroupInfo,  OCL_CLGETKERNELWORKGROUPINFO,   OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetPlatformIDs,          OCL_CLGETPLATFORMIDS,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetPlatformInfo,         OCL_CLGETPLATFORMINFO,          OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetProgramBuildInfo,     OCL_CLGETPROGRAMBUILDINFO,      OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetProgramInfo,          OCL_CLGETPROGRAMINFO,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseCommandQueue,     OCL_CLRELEASECOMMANDQUEUE,      OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseContext,          OCL_CLRELEASECONTEXT,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseKernel,           OCL_CLRELEASEKERNEL,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseMemObject,        OCL_CLRELEASEMEMOBJECT,         OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseProgram,          OCL_CLRELEASEPROGRAM,           OpenCL, 1);
  HC_LOAD_FUNC (ocl, clSetKernelArg,            OCL_CLSETKERNELARG,             OpenCL, 1);
  HC_LOAD_FUNC (ocl, clWaitForEvents,           OCL_CLWAITFOREVENTS,            OpenCL, 1);
  HC_LOAD_FUNC (ocl, clGetEventProfilingInfo,   OCL_CLGETEVENTPROFILINGINFO,    OpenCL, 1);
  HC_LOAD_FUNC (ocl, clReleaseEvent,            OCL_CLRELEASEEVENT,             OpenCL, 1);

  return 0;
}

void ocl_close (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  if (ocl)
  {
    if (ocl->lib)
    {
      hc_dlclose (ocl->lib);
    }

    hcfree (backend_ctx->ocl);

    backend_ctx->ocl = NULL;
  }
}

int hc_clEnqueueNDRangeKernel (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clSetKernelArg (kernel, arg_index, arg_size, arg_value);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clSetKernelArg(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueWriteBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueWriteBuffer (command_queue, buffer, blocking_write, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueWriteBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueCopyBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueCopyBuffer (command_queue, src_buffer, dst_buffer, src_offset, dst_offset, size, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueCopyBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clEnqueueReadBuffer (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clEnqueueReadBuffer (command_queue, buffer, blocking_read, offset, size, ptr, num_events_in_wait_list, event_wait_list, event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clEnqueueReadBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clGetPlatformIDs (hashcat_ctx_t *hashcat_ctx, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clGetDeviceInfo (device, param_name, param_value_size, param_value, param_value_size_ret);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clGetDeviceInfo(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateContext (hashcat_ctx_t *hashcat_ctx, const cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *errinfo, const void *private_info, size_t cb, void *user_data), void *user_data, cl_context *context)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  cl_int CL_err;

  *mem = ocl->clCreateBuffer (context, flags, size, host_ptr, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateBuffer(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithSource (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint count, const char **strings, const size_t *lengths, cl_program *program)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithSource (context, count, strings, lengths, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithSource(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clCreateProgramWithBinary (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status, cl_program *program)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  cl_int CL_err;

  *program = ocl->clCreateProgramWithBinary (context, num_devices, device_list, lengths, binaries, binary_status, &CL_err);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clCreateProgramWithBinary(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

int hc_clBuildProgram (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

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
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

  OCL_PTR *ocl = backend_ctx->ocl;

  const cl_int CL_err = ocl->clReleaseEvent (event);

  if (CL_err != CL_SUCCESS)
  {
    event_log_error (hashcat_ctx, "clReleaseEvent(): %s", val2cstr_cl (CL_err));

    return -1;
  }

  return 0;
}

// Backend

int gidd_to_pw_t (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw)
{
  pw_idx_t pw_idx;

  pw_idx.off = 0;
  pw_idx.cnt = 0;
  pw_idx.len = 0;

  if (device_param->is_cuda == true)
  {
    if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

    if (hc_cuMemcpyDtoH (hashcat_ctx, &pw_idx, device_param->cuda_d_pws_idx + (gidd * sizeof (pw_idx_t)), sizeof (pw_idx_t)) == -1) return -1;

    if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, gidd * sizeof (pw_idx_t), sizeof (pw_idx_t), &pw_idx, 0, NULL, NULL) == -1) return -1;
  }

  const u32 off = pw_idx.off;
  const u32 cnt = pw_idx.cnt;
  const u32 len = pw_idx.len;

  if (device_param->is_cuda == true)
  {
    if (cnt > 0)
    {
      if (hc_cuCtxPushCurrent (hashcat_ctx, device_param->cuda_context) == -1) return -1;

      if (hc_cuMemcpyDtoH (hashcat_ctx,pw->i, device_param->cuda_d_pws_comp_buf + (off * sizeof (u32)), cnt * sizeof (u32)) == -1) return -1;

      if (hc_cuCtxPopCurrent (hashcat_ctx, &device_param->cuda_context) == -1) return -1;
    }
  }

  if (device_param->is_opencl == true)
  {
    if (cnt > 0)
    {
      if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, off * sizeof (u32), cnt * sizeof (u32), pw->i, 0, NULL, NULL) == -1) return -1;
    }
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
        if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
        {
          const u32 size_tm = device_param->size_tm;

          if (device_param->is_cuda == true)
          {
            if (run_cuda_kernel_bzero (hashcat_ctx, device_param, device_param->cuda_d_tm_c, size_tm) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (run_opencl_kernel_bzero (hashcat_ctx, device_param, device_param->opencl_d_tm_c, size_tm) == -1) return -1;
          }

          if (run_kernel_tm (hashcat_ctx, device_param) == -1) return -1;

          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_bfs_c, device_param->cuda_d_tm_c, size_tm) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_tm_c, device_param->opencl_d_bfs_c, 0, 0, size_tm, 0, NULL, NULL) == -1) return -1;
          }
        }
      }
    }

    if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
    {
      if (highest_pw_len < 16)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_cnt, true, fast_iteration) == -1) return -1;
      }
      else if (highest_pw_len < 32)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_cnt, true, fast_iteration) == -1) return -1;
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_cnt, true, fast_iteration) == -1) return -1;
      }
    }
    else
    {
      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_4, pws_cnt, true, fast_iteration) == -1) return -1;
    }
  }
  else
  {
    bool run_init = true;
    bool run_loop = true;
    bool run_comp = true;

    if (run_init == true)
    {
      if (device_param->is_cuda == true)
      {
        if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_pws_buf, device_param->cuda_d_pws_amp_buf, pws_cnt * sizeof (pw_t)) == -1) return -1;
      }

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

      if (run_kernel (hashcat_ctx, device_param, KERN_RUN_1, pws_cnt, false, 0) == -1) return -1;

      if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_12, pws_cnt, false, 0) == -1) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyDtoH (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }

        module_ctx->module_hook12 (device_param, hashes->hook_salts_buf, salt_pos, pws_cnt);

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }
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

        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_2, pws_cnt, true, slow_iteration) == -1) return -1;

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
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_23, pws_cnt, false, 0) == -1) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyDtoH (hashcat_ctx, device_param->hooks_buf, device_param->cuda_d_hooks, device_param->size_hooks) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueReadBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }

        module_ctx->module_hook23 (device_param, hashes->hook_salts_buf, salt_pos, pws_cnt);

        if (device_param->is_cuda == true)
        {
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_hooks, device_param->hooks_buf, device_param->size_hooks) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_hooks, CL_TRUE, 0, device_param->size_hooks, device_param->hooks_buf, 0, NULL, NULL) == -1) return -1;
        }
      }
    }

    // init2 and loop2 are kind of special, we use run_loop for them, too

    if (run_loop == true)
    {
      // note: they also do not influence the performance screen
      // in case you want to use this, this cane make sense only if your input data comes out of tmps[]

      if (hashconfig->opts_type & OPTS_TYPE_INIT2)
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_INIT2, pws_cnt, false, 0) == -1) return -1;
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

          if (run_kernel (hashcat_ctx, device_param, KERN_RUN_LOOP2, pws_cnt, true, slow_iteration) == -1) return -1;

          //bug?
          //while (status_ctx->run_thread_level2 == false) break;
          if (status_ctx->run_thread_level2 == false) break;
        }
      }
    }

    if (run_comp == true)
    {
      if (hashconfig->opts_type & OPTS_TYPE_DEEP_COMP_KERNEL)
      {
        const u32 loops_cnt = hashes->salts_buf[salt_pos].digests_cnt;

        for (u32 loops_pos = 0; loops_pos < loops_cnt; loops_pos++)
        {
          device_param->kernel_params_buf32[28] = loops_pos;
          device_param->kernel_params_buf32[29] = loops_cnt;

          const u32 deep_comp_kernel = module_ctx->module_deep_comp_kernel (hashes, salt_pos, loops_pos);

          if (run_kernel (hashcat_ctx, device_param, deep_comp_kernel, pws_cnt, false, 0) == -1) return -1;

          if (status_ctx->run_thread_level2 == false) break;
        }
      }
      else
      {
        if (run_kernel (hashcat_ctx, device_param, KERN_RUN_3, pws_cnt, false, 0) == -1) return -1;
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

int run_cuda_kernel_atinit (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num)
{
  u64 num_elements = num;

  device_param->kernel_params_atinit[0]       = (void *) &buf;
  device_param->kernel_params_atinit_buf64[1] = num_elements;

  const u64 kernel_threads = device_param->kernel_wgs_atinit;

  num_elements = CEILDIV (num_elements, kernel_threads);

  CUfunction function = device_param->cuda_function_atinit;

  if (hc_cuLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_atinit, NULL) == -1) return -1;

  if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;

  return 0;
}

int run_cuda_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u32 value, const u64 size)
{
  const u64 num16d = size / 16;
  const u64 num16m = size % 16;

  if (num16d)
  {
    device_param->kernel_params_memset[0]       = (void *) &buf;
    device_param->kernel_params_memset_buf32[1] = value;
    device_param->kernel_params_memset_buf64[2] = num16d;

    const u64 kernel_threads = device_param->kernel_wgs_memset;

    u64 num_elements = num16d;

    num_elements = CEILDIV (num_elements, kernel_threads);

    CUfunction function = device_param->cuda_function_memset;

    //CU_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem),   (void *) &buf);                         if (CU_rc == -1) return -1;
    //CU_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]); if (CU_rc == -1) return -1;
    //CU_rc = hc_clSetKernelArg (hashcat_ctx, kernel, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]); if (CU_rc == -1) return -1;

    //const size_t global_work_size[3] = { num_elements,   1, 1 };
    //const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_cuLaunchKernel (hashcat_ctx, function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params_memset, NULL) == -1) return -1;

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (num16m)
  {
    u32 tmp[4];

    tmp[0] = value;
    tmp[1] = value;
    tmp[2] = value;
    tmp[3] = value;

    // Apparently are allowed to do this: https://devtalk.nvidia.com/default/topic/761515/how-to-copy-to-device-memory-with-offset-/

    if (hc_cuMemcpyHtoD (hashcat_ctx, buf + (num16d * 16), tmp, num16m) == -1) return -1;
  }

  return 0;
}

int run_cuda_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 size)
{
  return run_cuda_kernel_memset (hashcat_ctx, device_param, buf, 0, size);
}

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

  if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

  if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

  return 0;
}

int run_opencl_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u64 size)
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

    cl_kernel kernel = device_param->opencl_kernel_memset;

    if (hc_clSetKernelArg (hashcat_ctx, kernel, 0, sizeof (cl_mem),   (void *) &buf) == -1)                         return -1;
    if (hc_clSetKernelArg (hashcat_ctx, kernel, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]) == -1) return -1;
    if (hc_clSetKernelArg (hashcat_ctx, kernel, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]) == -1) return -1;

    const size_t global_work_size[3] = { num_elements,   1, 1 };
    const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
  }

  if (num16m)
  {
    u32 tmp[4];

    tmp[0] = value;
    tmp[1] = value;
    tmp[2] = value;
    tmp[3] = value;

    if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, buf, CL_TRUE, num16d * 16, num16m, tmp, 0, NULL, NULL) == -1) return -1;
  }

  return 0;
}

int run_opencl_kernel_bzero (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size)
{
  return run_opencl_kernel_memset (hashcat_ctx, device_param, buf, 0, size);
}

int run_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num, const u32 event_update, const u32 iteration)
{
  const hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  const status_ctx_t   *status_ctx   = hashcat_ctx->status_ctx;
  const user_options_t *user_options = hashcat_ctx->user_options;

  u64 kernel_threads = 0;

  switch (kern_run)
  {
    case KERN_RUN_1:      kernel_threads  = device_param->kernel_wgs1;      break;
    case KERN_RUN_12:     kernel_threads  = device_param->kernel_wgs12;     break;
    case KERN_RUN_2:      kernel_threads  = device_param->kernel_wgs2;      break;
    case KERN_RUN_23:     kernel_threads  = device_param->kernel_wgs23;     break;
    case KERN_RUN_3:      kernel_threads  = device_param->kernel_wgs3;      break;
    case KERN_RUN_4:      kernel_threads  = device_param->kernel_wgs4;      break;
    case KERN_RUN_INIT2:  kernel_threads  = device_param->kernel_wgs_init2; break;
    case KERN_RUN_LOOP2:  kernel_threads  = device_param->kernel_wgs_loop2; break;
    case KERN_RUN_AUX1:   kernel_threads  = device_param->kernel_wgs_aux1;  break;
    case KERN_RUN_AUX2:   kernel_threads  = device_param->kernel_wgs_aux2;  break;
    case KERN_RUN_AUX3:   kernel_threads  = device_param->kernel_wgs_aux3;  break;
    case KERN_RUN_AUX4:   kernel_threads  = device_param->kernel_wgs_aux4;  break;
  }

  kernel_threads = MIN (kernel_threads, device_param->kernel_threads);

  device_param->kernel_params_buf64[34] = num;

  u64 num_elements = num;

  if (device_param->is_cuda == true)
  {
    CUfunction cuda_function = NULL;

    if (device_param->is_cuda == true)
    {
      switch (kern_run)
      {
        case KERN_RUN_1:      cuda_function = device_param->cuda_function1;      break;
        case KERN_RUN_12:     cuda_function = device_param->cuda_function12;     break;
        case KERN_RUN_2:      cuda_function = device_param->cuda_function2;      break;
        case KERN_RUN_23:     cuda_function = device_param->cuda_function23;     break;
        case KERN_RUN_3:      cuda_function = device_param->cuda_function3;      break;
        case KERN_RUN_4:      cuda_function = device_param->cuda_function4;      break;
        case KERN_RUN_INIT2:  cuda_function = device_param->cuda_function_init2; break;
        case KERN_RUN_LOOP2:  cuda_function = device_param->cuda_function_loop2; break;
        case KERN_RUN_AUX1:   cuda_function = device_param->cuda_function_aux1;  break;
        case KERN_RUN_AUX2:   cuda_function = device_param->cuda_function_aux2;  break;
        case KERN_RUN_AUX3:   cuda_function = device_param->cuda_function_aux3;  break;
        case KERN_RUN_AUX4:   cuda_function = device_param->cuda_function_aux4;  break;
      }
    }

    num_elements = CEILDIV (num_elements, kernel_threads);

    if ((hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE) && (user_options->attack_mode == ATTACK_MODE_BF))
    {
      if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event1, device_param->cuda_stream) == -1) return -1;

      if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 32, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params, NULL) == -1) return -1;

      if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event2, device_param->cuda_stream) == -1) return -1;
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

      if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event1, device_param->cuda_stream) == -1) return -1;

      if (hc_cuLaunchKernel (hashcat_ctx, cuda_function, num_elements, 1, 1, kernel_threads, 1, 1, 0, device_param->cuda_stream, device_param->kernel_params, NULL) == -1) return -1;

      if (hc_cuEventRecord (hashcat_ctx, device_param->cuda_event2, device_param->cuda_stream) == -1) return -1;
    }

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;

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

  if (device_param->is_opencl == true)
  {
    cl_kernel opencl_kernel = NULL;

    if (device_param->is_opencl == true)
    {
      switch (kern_run)
      {
        case KERN_RUN_1:      opencl_kernel = device_param->opencl_kernel1;      break;
        case KERN_RUN_12:     opencl_kernel = device_param->opencl_kernel12;     break;
        case KERN_RUN_2:      opencl_kernel = device_param->opencl_kernel2;      break;
        case KERN_RUN_23:     opencl_kernel = device_param->opencl_kernel23;     break;
        case KERN_RUN_3:      opencl_kernel = device_param->opencl_kernel3;      break;
        case KERN_RUN_4:      opencl_kernel = device_param->opencl_kernel4;      break;
        case KERN_RUN_INIT2:  opencl_kernel = device_param->opencl_kernel_init2; break;
        case KERN_RUN_LOOP2:  opencl_kernel = device_param->opencl_kernel_loop2; break;
        case KERN_RUN_AUX1:   opencl_kernel = device_param->opencl_kernel_aux1;  break;
        case KERN_RUN_AUX2:   opencl_kernel = device_param->opencl_kernel_aux2;  break;
        case KERN_RUN_AUX3:   opencl_kernel = device_param->opencl_kernel_aux3;  break;
        case KERN_RUN_AUX4:   opencl_kernel = device_param->opencl_kernel_aux4;  break;
      }
    }

    for (u32 i = 0; i <= 23; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_mem), device_param->kernel_params[i]) == -1) return -1;
    }

    for (u32 i = 24; i <= 33; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_uint), device_param->kernel_params[i]) == -1) return -1;
    }

    for (u32 i = 34; i <= 34; i++)
    {
      if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, i, sizeof (cl_ulong), device_param->kernel_params[i]) == -1) return -1;
    }

    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_event opencl_event;

    if ((hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE) && (user_options->attack_mode == ATTACK_MODE_BF))
    {
      const size_t global_work_size[3] = { num_elements,  32, 1 };
      const size_t local_work_size[3]  = { kernel_threads, 1, 1 };

      if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 2, NULL, global_work_size, local_work_size, 0, NULL, &opencl_event) == -1) return -1;
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

      if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, &opencl_event) == -1) return -1;
    }

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

    // spin damper section

    const u32 iterationm = iteration % EXPECTED_ITERATIONS;

    cl_int opencl_event_status;

    size_t param_value_size_ret;

    if (hc_clGetEventInfo (hashcat_ctx, opencl_event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (opencl_event_status), &opencl_event_status, &param_value_size_ret) == -1) return -1;

    if (device_param->spin_damp > 0)
    {
      double spin_total = device_param->spin_damp;

      while (opencl_event_status != CL_COMPLETE)
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

        if (hc_clGetEventInfo (hashcat_ctx, opencl_event, CL_EVENT_COMMAND_EXECUTION_STATUS, sizeof (opencl_event_status), &opencl_event_status, &param_value_size_ret) == -1) return -1;

        spin_total += device_param->spin_damp;

        if (spin_total > 1) break;
      }
    }

    if (hc_clWaitForEvents (hashcat_ctx, 1, &opencl_event) == -1) return -1;

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

    if (hc_clReleaseEvent (hashcat_ctx, opencl_event) == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
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

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

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

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue)  == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
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

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    cl_kernel cuda_kernel = device_param->opencl_kernel_tm;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, cuda_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
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

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_kernel opencl_kernel = device_param->opencl_kernel_amp;

    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 6, sizeof (cl_ulong), device_param->kernel_params_amp[6]) == -1) return -1;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue)  == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
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

    if (hc_cuStreamSynchronize (hashcat_ctx, device_param->cuda_stream) == -1) return -1;
  }

  if (device_param->is_opencl == true)
  {
    num_elements = round_up_multiple_64 (num_elements, kernel_threads);

    cl_kernel opencl_kernel = device_param->opencl_kernel_decompress;

    const size_t global_work_size[3] = { num_elements,    1, 1 };
    const size_t local_work_size[3]  = { kernel_threads,  1, 1 };

    if (hc_clSetKernelArg (hashcat_ctx, opencl_kernel, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]) == -1) return -1;

    if (hc_clEnqueueNDRangeKernel (hashcat_ctx, device_param->opencl_command_queue, opencl_kernel, 1, NULL, global_work_size, local_work_size, 0, NULL, NULL) == -1) return -1;

    if (hc_clFlush (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;

    if (hc_clFinish (hashcat_ctx, device_param->opencl_command_queue) == -1) return -1;
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
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
      }
    }

    if (device_param->is_opencl == true)
    {
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

      const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

      const u32 off = pw_idx->off;

      if (off)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
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
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
        }
      }

      if (device_param->is_opencl == true)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

        const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

        const u32 off = pw_idx->off;

        if (off)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
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
          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
          }
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

          const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

          const u32 off = pw_idx->off;

          if (off)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
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
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
            }
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
            }
          }

          if (run_kernel_decompress (hashcat_ctx, device_param, pws_cnt) == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_idx, device_param->pws_idx, pws_cnt * sizeof (pw_idx_t)) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_pws_comp_buf, device_param->pws_comp, off * sizeof (u32)) == -1) return -1;
            }
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_idx, CL_TRUE, 0, pws_cnt * sizeof (pw_idx_t), device_param->pws_idx, 0, NULL, NULL) == -1) return -1;

            const pw_idx_t *pw_idx = device_param->pws_idx + pws_cnt;

            const u32 off = pw_idx->off;

            if (off)
            {
              if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_pws_comp_buf, CL_TRUE, 0, off * sizeof (u32), device_param->pws_comp, 0, NULL, NULL) == -1) return -1;
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

  // we ignore the time to copy data over pci bus in this case

  if (user_options->speed_only == true)
  {
    hc_timer_set (&device_param->timer_speed);
  }

  // loop start: most outer loop = salt iteration, then innerloops (if multi)

  for (u32 salt_pos = 0; salt_pos < hashes->salts_cnt; salt_pos++)
  {
    while (status_ctx->devices_status == STATUS_PAUSED) sleep (1);

    salt_t *salt_buf = &hashes->salts_buf[salt_pos];

    device_param->kernel_params_buf32[27] = salt_pos;
    device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
    device_param->kernel_params_buf32[32] = salt_buf->digests_offset;

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

      device_param->kernel_params_buf32[30] = innerloop_left;

      device_param->outerloop_multi = (double) innerloop_cnt / (double) (innerloop_pos + innerloop_left);

      hc_thread_mutex_unlock (status_ctx->mux_display);

      if (hashes->salts_shown[salt_pos] == 1)
      {
        status_ctx->words_progress_done[salt_pos] += pws_cnt * innerloop_left;

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
          if (device_param->is_cuda == true)
          {
            if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_rules_c, device_param->cuda_d_rules + (innerloop_pos * sizeof (kernel_rule_t)), innerloop_left * sizeof (kernel_rule_t)) == -1) return -1;
          }

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
                if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL) == -1) return -1;
              }
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left) == -1) return -1;

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }

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
                if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }

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
                if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_combs_c, device_param->combs_buf, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }

              if (device_param->is_opencl == true)
              {
                if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_combs_c, CL_TRUE, 0, innerloop_left * sizeof (pw_t), device_param->combs_buf, 0, NULL, NULL) == -1) return -1;
              }
            }
            else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
            {
              u64 off = innerloop_pos;

              device_param->kernel_params_mp_buf64[3] = off;

              if (run_kernel_mp (hashcat_ctx, device_param, KERN_RUN_MP, innerloop_left) == -1) return -1;

              if (device_param->is_cuda == true)
              {
                if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_combs_c, device_param->cuda_d_combs, innerloop_left * sizeof (pw_t)) == -1) return -1;
              }

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
            if (hc_cuMemcpyDtoD (hashcat_ctx, device_param->cuda_d_bfs_c, device_param->cuda_d_bfs, innerloop_left * sizeof (bf_t)) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clEnqueueCopyBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bfs, device_param->opencl_d_bfs_c, 0, 0, innerloop_left * sizeof (bf_t), 0, NULL, NULL) == -1) return -1;
          }
        }
      }

      if (choose_kernel (hashcat_ctx, device_param, highest_pw_len, pws_cnt, fast_iteration, salt_pos) == -1) return -1;

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

    device_param->speed_only_finish = true;
  }

  return 0;
}

int backend_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  backend_ctx->enabled = false;

  if (user_options->example_hashes == true) return 0;
  if (user_options->keyspace       == true) return 0;
  if (user_options->left           == true) return 0;
  if (user_options->show           == true) return 0;
  if (user_options->usage          == true) return 0;
  if (user_options->version        == true) return 0;

  hc_device_param_t *devices_param = (hc_device_param_t *) hccalloc (DEVICES_MAX, sizeof (hc_device_param_t));

  backend_ctx->devices_param = devices_param;

  /**
   * Load and map CUDA library calls, then init CUDA
   */

  CUDA_PTR *cuda = (CUDA_PTR *) hcmalloc (sizeof (CUDA_PTR));

  backend_ctx->cuda = cuda;

  int rc_cuda_init = cuda_init (hashcat_ctx);

  if (rc_cuda_init == -1)
  {
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

    // cuda version

    int cuda_driver_version = 0;

    if (hc_cuDriverGetVersion (hashcat_ctx, &cuda_driver_version) == -1) return -1;

    backend_ctx->cuda_driver_version = cuda_driver_version;

    // some pre-check

    if ((nvrtc_driver_version < 10010) || (cuda_driver_version < 10010))
    {
      event_log_error (hashcat_ctx, "Outdated NVIDIA CUDA Toolkit version '%d' detected!", cuda_driver_version);

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

  /**
   * Load and map OpenCL library calls
   */

  OCL_PTR *ocl = (OCL_PTR *) hcmalloc (sizeof (OCL_PTR));

  backend_ctx->ocl = ocl;

  const int rc_ocl_init = ocl_init (hashcat_ctx);

  if (rc_ocl_init == -1)
  {
    ocl_close (hashcat_ctx);
  }

  /**
   * return if both CUDA and OpenCL initialization failed
   */

  if ((rc_cuda_init == -1) && (rc_ocl_init == -1))
  {
    event_log_error (hashcat_ctx, "ATTENTION! No OpenCL or CUDA installation found.");

    event_log_warning (hashcat_ctx, "You are probably missing the CUDA or OpenCL runtime installation.");
    event_log_warning (hashcat_ctx, NULL);

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this driver:");
    event_log_warning (hashcat_ctx, "  \"RadeonOpenCompute (ROCm)\" Software Platform (1.6.180 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this driver:");
    event_log_warning (hashcat_ctx, "  \"AMD Radeon Software Crimson Edition\" (15.12 or later)");
    #endif

    event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Linux require this driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL 2.0 GPU Driver Package for Linux\" (2.0 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Windows require this driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Driver for Intel Iris and Intel HD Graphics\"");
    #endif

    event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver (both):");
    event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (418.56 or later)");
    event_log_warning (hashcat_ctx, "  \"CUDA Toolkit\" (10.1 or later)");
    event_log_warning (hashcat_ctx, NULL);

    return -1;
  }

  /**
   * Some permission pre-check, because AMDGPU-PRO Driver crashes if the user has no permission to do this
   */

  if (ocl_check_dri (hashcat_ctx) == -1) return -1;

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
   * OpenCL API: init
   */

  if (backend_ctx->ocl)
  {
    #define FREE_OPENCL_CTX_ON_ERROR          \
    {                                         \
      hcfree (opencl_platforms);              \
      hcfree (opencl_platforms_devices);      \
      hcfree (opencl_platforms_devices_cnt);  \
      hcfree (opencl_platforms_name);         \
      hcfree (opencl_platforms_vendor);       \
      hcfree (opencl_platforms_vendor_id);    \
      hcfree (opencl_platforms_version);      \
    }

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

    if (opencl_platforms_cnt)
    {
      for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
      {
        cl_platform_id opencl_platform = opencl_platforms[opencl_platforms_idx];

        size_t param_value_size = 0;

        // platform vendor

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VENDOR, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_platform_vendor = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VENDOR, param_value_size, opencl_platform_vendor, NULL) == -1) return -1;

        opencl_platforms_vendor[opencl_platforms_idx] = opencl_platform_vendor;

        // platform name

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_NAME, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_platform_name = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_NAME, param_value_size, opencl_platform_name, NULL) == -1) return -1;

        opencl_platforms_name[opencl_platforms_idx] = opencl_platform_name;

        // platform version

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VERSION, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_platform_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetPlatformInfo (hashcat_ctx, opencl_platform, CL_PLATFORM_VERSION, param_value_size, opencl_platform_version, NULL) == -1) return -1;

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
          event_log_error (hashcat_ctx, "clGetDeviceIDs(): %s", val2cstr_cl (CL_rc));

          return -1;
        }

        opencl_platforms_devices[opencl_platforms_idx] = opencl_platform_devices;

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

  if ((backend_ctx->cuda == NULL) && (backend_ctx->ocl == NULL))
  {
    event_log_error (hashcat_ctx, "ATTENTION! No OpenCL-compatible or CUDA-compatible platform found.");

    event_log_warning (hashcat_ctx, "You are probably missing the OpenCL or CUDA runtime installation.");
    event_log_warning (hashcat_ctx, NULL);

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Linux require this driver:");
    event_log_warning (hashcat_ctx, "  \"RadeonOpenCompute (ROCm)\" Software Platform (1.6.180 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* AMD GPUs on Windows require this driver:");
    event_log_warning (hashcat_ctx, "  \"AMD Radeon Software Crimson Edition\" (15.12 or later)");
    #endif

    event_log_warning (hashcat_ctx, "* Intel CPUs require this runtime:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Runtime for Intel Core and Intel Xeon Processors\" (16.1.1 or later)");

    #if defined (__linux__)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Linux require this driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL 2.0 GPU Driver Package for Linux\" (2.0 or later)");
    #elif defined (_WIN)
    event_log_warning (hashcat_ctx, "* Intel GPUs on Windows require this driver:");
    event_log_warning (hashcat_ctx, "  \"OpenCL Driver for Intel Iris and Intel HD Graphics\"");
    #endif

    event_log_warning (hashcat_ctx, "* NVIDIA GPUs require this runtime and/or driver (both):");
    event_log_warning (hashcat_ctx, "  \"NVIDIA Driver\" (418.56 or later)");
    event_log_warning (hashcat_ctx, "  \"CUDA Toolkit\" (10.1 or later)");
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

  nvrtc_close (hashcat_ctx);
  cuda_close  (hashcat_ctx);
  ocl_close   (hashcat_ctx);

  memset (backend_ctx, 0, sizeof (backend_ctx_t));
}

int backend_ctx_devices_init (hashcat_ctx_t *hashcat_ctx, const int comptime)
{
  backend_ctx_t  *backend_ctx  = hashcat_ctx->backend_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  if (backend_ctx->enabled == false) return 0;

  hc_device_param_t *devices_param = backend_ctx->devices_param;

  bool need_adl     = false;
  bool need_nvml    = false;
  bool need_nvapi   = false;
  bool need_sysfs   = false;

  int backend_devices_idx = 0;

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

      if (hc_cuDeviceGet (hashcat_ctx, &cuda_device, cuda_devices_idx) == -1) return -1;

      device_param->cuda_device = cuda_device;

      device_param->is_cuda = true;

      // device_name

      char *device_name = (char *) hcmalloc (HCBUFSIZ_TINY);

      if (hc_cuDeviceGetName (hashcat_ctx, device_name, HCBUFSIZ_TINY, cuda_device) == -1) return -1;

      device_param->device_name = device_name;

      hc_string_trim_leading (device_name);

      hc_string_trim_trailing (device_name);

      // device_processors

      int device_processors = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_processors, CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT, cuda_device) == -1) return -1;

      device_param->device_processors = device_processors;

      // device_global_mem, device_maxmem_alloc, device_available_mem

      size_t bytes = 0;

      if (hc_cuDeviceTotalMem (hashcat_ctx, &bytes, cuda_device) == -1) return -1;

      device_param->device_global_mem = (u64) bytes;

      device_param->device_maxmem_alloc = (u64) bytes;

      device_param->device_available_mem = 0;

      // warp size

      int cuda_warp_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &cuda_warp_size, CU_DEVICE_ATTRIBUTE_WARP_SIZE, cuda_device) == -1) return -1;

      device_param->cuda_warp_size = cuda_warp_size;

      // sm_minor, sm_major

      int sm_major = 0;
      int sm_minor = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &sm_major, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR, cuda_device) == -1) return -1;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &sm_minor, CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR, cuda_device) == -1) return -1;

      device_param->sm_major = sm_major;
      device_param->sm_minor = sm_minor;

      // device_maxworkgroup_size

      int device_maxworkgroup_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_maxworkgroup_size, CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK, cuda_device) == -1) return -1;

      device_param->device_maxworkgroup_size = device_maxworkgroup_size;

      // max_clock_frequency

      int device_maxclock_frequency = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_maxclock_frequency, CU_DEVICE_ATTRIBUTE_CLOCK_RATE, cuda_device) == -1) return -1;

      device_param->device_maxclock_frequency = device_maxclock_frequency / 1000;

      // pcie_bus, pcie_device, pcie_function

      int pci_bus_id_nv  = 0;
      int pci_slot_id_nv = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &pci_bus_id_nv, CU_DEVICE_ATTRIBUTE_PCI_BUS_ID, cuda_device) == -1) return -1;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &pci_slot_id_nv, CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID, cuda_device) == -1) return -1;

      device_param->pcie_bus      = (u8) (pci_bus_id_nv);
      device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
      device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

      // kernel_exec_timeout

      int kernel_exec_timeout = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &kernel_exec_timeout, CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT, cuda_device) == -1) return -1;

      device_param->kernel_exec_timeout = kernel_exec_timeout;

      // max_shared_memory_per_block

      int max_shared_memory_per_block = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &max_shared_memory_per_block, CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK, cuda_device) == -1) return -1;

      if (max_shared_memory_per_block < 32768)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's shared buffer size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      device_param->device_local_mem_size = max_shared_memory_per_block;

      // device_max_constant_buffer_size

      int device_max_constant_buffer_size = 0;

      if (hc_cuDeviceGetAttribute (hashcat_ctx, &device_max_constant_buffer_size, CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY, cuda_device) == -1) return -1;

      if (device_max_constant_buffer_size < 65536)
      {
        event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

        device_param->skipped = true;
      }

      // some attributes have to be hardcoded because they are used for instance in the build options

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

      if ((backend_ctx->opencl_device_types_filter & CL_DEVICE_TYPE_GPU) == 0)
      {
        device_param->skipped = true;
      }

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
        if ((user_options->force == false) && (user_options->backend_info == false))
        {
          // CUDA does not support query nvidia driver version, therefore no driver checks here
          // IF needed, could be retrieved using nvmlSystemGetDriverVersion()

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

        /**
         * activate device
         */

        cuda_devices_active++;
      }

      CUcontext cuda_context;

      if (hc_cuCtxCreate (hashcat_ctx, &cuda_context, CU_CTX_SCHED_BLOCKING_SYNC, device_param->cuda_device) == -1) return -1;

      if (hc_cuCtxSetCurrent (hashcat_ctx, cuda_context) == -1) return -1;

      // bcrypt optimization?
      //const int rc_cuCtxSetCacheConfig = hc_cuCtxSetCacheConfig (hashcat_ctx, CU_FUNC_CACHE_PREFER_SHARED);
      //
      //if (rc_cuCtxSetCacheConfig == -1) return -1;

      device_param->has_bfe   = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"bfe.u32 %0, 0, 0, 0;\" : \"=r\"(r)); }");
      device_param->has_lop3  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"lop3.b32 %0, 0, 0, 0, 0;\" : \"=r\"(r)); }");
      device_param->has_mov64 = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned long long r; unsigned int a; unsigned int b; asm volatile (\"mov.b64 %0, {%1, %2};\" : \"=l\"(r) : \"r\"(a), \"r\"(b)); }");
      device_param->has_prmt  = cuda_test_instruction (hashcat_ctx, sm_major, sm_minor, "__global__ void test () { unsigned int r; asm volatile (\"prmt.b32 %0, 0, 0, 0;\" : \"=r\"(r)); }");

      // device_available_mem

      size_t free  = 0;
      size_t total = 0;

      if (hc_cuMemGetInfo (hashcat_ctx, &free, &total) == -1) return -1;

      device_param->device_available_mem = (u64) free;

      if (hc_cuCtxDestroy (hashcat_ctx, cuda_context) == -1) return -1;
    }
  }

  backend_ctx->cuda_devices_cnt     = cuda_devices_cnt;
  backend_ctx->cuda_devices_active  = cuda_devices_active;

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

    for (u32 opencl_platforms_idx = 0; opencl_platforms_idx < opencl_platforms_cnt; opencl_platforms_idx++)
    {
      cl_device_id   *opencl_platform_devices     = opencl_platforms_devices[opencl_platforms_idx];
      cl_uint         opencl_platform_devices_cnt = opencl_platforms_devices_cnt[opencl_platforms_idx];
      cl_uint         opencl_platform_vendor_id   = opencl_platforms_vendor_id[opencl_platforms_idx];

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

        device_param->is_opencl = true;

        size_t param_value_size = 0;

        // opencl_device_type

        cl_device_type opencl_device_type;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_TYPE, sizeof (opencl_device_type), &opencl_device_type, NULL) == -1) return -1;

        opencl_device_type &= ~CL_DEVICE_TYPE_DEFAULT;

        device_param->opencl_device_type = opencl_device_type;

        // device_name

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NAME, 0, NULL, &param_value_size) == -1) return -1;

        char *device_name = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NAME, param_value_size, device_name, NULL) == -1) return -1;

        device_param->device_name = device_name;

        hc_string_trim_leading (device_param->device_name);

        hc_string_trim_trailing (device_param->device_name);

        // device_vendor

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VENDOR, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_device_vendor = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VENDOR, param_value_size, opencl_device_vendor, NULL) == -1) return -1;

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

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VERSION, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_device_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_VERSION, param_value_size, opencl_device_version, NULL) == -1) return -1;

        device_param->opencl_device_version = opencl_device_version;

        // opencl_device_c_version

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_device_c_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_OPENCL_C_VERSION, param_value_size, opencl_device_c_version, NULL) == -1) return -1;

        device_param->opencl_device_c_version = opencl_device_c_version;

        // max_compute_units

        cl_uint device_processors = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_COMPUTE_UNITS, sizeof (device_processors), &device_processors, NULL) == -1) return -1;

        device_param->device_processors = device_processors;

        // device_global_mem

        cl_ulong device_global_mem = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_GLOBAL_MEM_SIZE, sizeof (device_global_mem), &device_global_mem, NULL) == -1) return -1;

        device_param->device_global_mem = device_global_mem;

        device_param->device_available_mem = 0;

        // device_maxmem_alloc

        cl_ulong device_maxmem_alloc = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof (device_maxmem_alloc), &device_maxmem_alloc, NULL) == -1) return -1;

        device_param->device_maxmem_alloc = device_maxmem_alloc;

        // note we'll limit to 2gb, otherwise this causes all kinds of weird errors because of possible integer overflows in opencl runtimes
        // testwise disabling that
        //device_param->device_maxmem_alloc = MIN (device_maxmem_alloc, 0x7fffffff);

        // max_work_group_size

        size_t device_maxworkgroup_size = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof (device_maxworkgroup_size), &device_maxworkgroup_size, NULL) == -1) return -1;

        device_param->device_maxworkgroup_size = device_maxworkgroup_size;

        // max_clock_frequency

        cl_uint device_maxclock_frequency = 0;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_CLOCK_FREQUENCY, sizeof (device_maxclock_frequency), &device_maxclock_frequency, NULL) == -1) return -1;

        device_param->device_maxclock_frequency = device_maxclock_frequency;

        // device_endian_little

        cl_bool device_endian_little = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_ENDIAN_LITTLE, sizeof (device_endian_little), &device_endian_little, NULL) == -1) return -1;

        if (device_endian_little == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device is not little-endian.", device_id + 1);

          device_param->skipped = true;
        }

        // device_available

        cl_bool device_available = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_AVAILABLE, sizeof (device_available), &device_available, NULL) == -1) return -1;

        if (device_available == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device is not available.", device_id + 1);

          device_param->skipped = true;
        }

        // device_compiler_available

        cl_bool device_compiler_available = CL_FALSE;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPILER_AVAILABLE, sizeof (device_compiler_available), &device_compiler_available, NULL) == -1) return -1;

        if (device_compiler_available == CL_FALSE)
        {
          event_log_error (hashcat_ctx, "* Device #%u: No compiler is available for this device.", device_id + 1);

          device_param->skipped = true;
        }

        // device_execution_capabilities

        cl_device_exec_capabilities device_execution_capabilities;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXECUTION_CAPABILITIES, sizeof (device_execution_capabilities), &device_execution_capabilities, NULL) == -1) return -1;

        if ((device_execution_capabilities & CL_EXEC_KERNEL) == 0)
        {
          event_log_error (hashcat_ctx, "* Device #%u: This device does not support executing kernels.", device_id + 1);

          device_param->skipped = true;
        }

        // device_extensions

        size_t device_extensions_size;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXTENSIONS, 0, NULL, &device_extensions_size) == -1) return -1;

        char *device_extensions = hcmalloc (device_extensions_size + 1);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_EXTENSIONS, device_extensions_size, device_extensions, NULL) == -1) return -1;

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

        // device_local_mem_type

        cl_device_local_mem_type device_local_mem_type;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_LOCAL_MEM_TYPE, sizeof (device_local_mem_type), &device_local_mem_type, NULL) == -1) return -1;

        device_param->device_local_mem_type = device_local_mem_type;

        // device_max_constant_buffer_size

        cl_ulong device_max_constant_buffer_size;

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof (device_max_constant_buffer_size), &device_max_constant_buffer_size, NULL) == -1) return -1;

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

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_LOCAL_MEM_SIZE, sizeof (device_local_mem_size), &device_local_mem_size, NULL) == -1) return -1;

        if (device_local_mem_type == CL_LOCAL)
        {
          if (device_local_mem_size < 32768)
          {
            event_log_error (hashcat_ctx, "* Device #%u: This device's local mem size is too small.", device_id + 1);

            device_param->skipped = true;
          }
        }

        device_param->device_local_mem_size = device_local_mem_size;

        // If there's both an Intel CPU and an AMD OpenCL runtime it's a tricky situation
        // Both platforms support CPU device types and therefore both will try to use 100% of the physical resources
        // This results in both utilizing it for 50%
        // However, Intel has much better SIMD control over their own hardware
        // It makes sense to give them full control over their own hardware

        if (opencl_device_type & CL_DEVICE_TYPE_CPU)
        {
          if (device_param->opencl_device_vendor_id == VENDOR_ID_AMD_USE_INTEL)
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
        if (opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_SDK) || (device_param->opencl_device_vendor_id == VENDOR_ID_INTEL_BEIGNET))
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

        if ((backend_ctx->backend_devices_filter & (1ULL << device_id)) == 0)
        {
          device_param->skipped = true;
        }

        if ((backend_ctx->opencl_device_types_filter & (opencl_device_type)) == 0)
        {
          device_param->skipped = true;
        }

        // driver_version

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DRIVER_VERSION, 0, NULL, &param_value_size) == -1) return -1;

        char *opencl_driver_version = (char *) hcmalloc (param_value_size);

        if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DRIVER_VERSION, param_value_size, opencl_driver_version, NULL) == -1) return -1;

        device_param->opencl_driver_version = opencl_driver_version;

        // vendor specific

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            need_adl = true;

            #if defined (__linux__)
            need_sysfs = true;
            #endif
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
          {
            need_nvml = true;

            #if defined (_WIN) || defined (__CYGWIN__)
            need_nvapi = true;
            #endif
          }
        }

        if (device_param->opencl_device_type & CL_DEVICE_TYPE_GPU)
        {
          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_AMD) && (device_param->opencl_device_vendor_id == VENDOR_ID_AMD))
          {
            cl_device_topology_amd amdtopo;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_TOPOLOGY_AMD, sizeof (amdtopo), &amdtopo, NULL) == -1) return -1;

            device_param->pcie_bus      = amdtopo.pcie.bus;
            device_param->pcie_device   = amdtopo.pcie.device;
            device_param->pcie_function = amdtopo.pcie.function;
          }

          if ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) && (device_param->opencl_device_vendor_id == VENDOR_ID_NV))
          {
            cl_uint pci_bus_id_nv;  // is cl_uint the right type for them??
            cl_uint pci_slot_id_nv;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_PCI_BUS_ID_NV, sizeof (pci_bus_id_nv), &pci_bus_id_nv, NULL) == -1) return -1;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_PCI_SLOT_ID_NV, sizeof (pci_slot_id_nv), &pci_slot_id_nv, NULL) == -1) return -1;

            device_param->pcie_bus      = (u8) (pci_bus_id_nv);
            device_param->pcie_device   = (u8) (pci_slot_id_nv >> 3);
            device_param->pcie_function = (u8) (pci_slot_id_nv & 7);

            int sm_minor = 0;
            int sm_major = 0;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof (sm_minor), &sm_minor, NULL) == -1) return -1;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof (sm_major), &sm_major, NULL) == -1) return -1;

            device_param->sm_minor = sm_minor;
            device_param->sm_major = sm_major;

            cl_uint kernel_exec_timeout = 0;

            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV, sizeof (kernel_exec_timeout), &kernel_exec_timeout, NULL) == -1) return -1;

            device_param->kernel_exec_timeout = kernel_exec_timeout;

            // CPU burning loop damper
            // Value is given as number between 0-100
            // By default 8%

            device_param->spin_damp = (double) user_options->spin_damp / 100;

            // recommend CUDA

            if ((backend_ctx->cuda == NULL) || (backend_ctx->nvrtc == NULL))
            {
              event_log_warning (hashcat_ctx, "* Device #%u: CUDA SDK Toolkit installation NOT detected.", device_id + 1);
              event_log_warning (hashcat_ctx, "             CUDA SDK Toolkit installation required for proper device support and utilization");
              event_log_warning (hashcat_ctx, "             Falling back to OpenCL Runtime");

              event_log_warning (hashcat_ctx, NULL);
            }
          }
        }

        // common driver check

        if (device_param->skipped == false)
        {
          if ((user_options->force == false) && (user_options->backend_info == false))
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

                  event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported Intel OpenCL runtime.");
                  event_log_warning (hashcat_ctx, "See hashcat.net for officially supported Intel OpenCL runtime.");
                  event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                  event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);

                  return -1;
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

                  event_log_warning (hashcat_ctx, "You are STRONGLY encouraged to use the officially supported AMD driver.");
                  event_log_warning (hashcat_ctx, "See hashcat.net for officially supported AMD drivers.");
                  event_log_warning (hashcat_ctx, "See also: https://hashcat.net/faq/wrongdriver");
                  event_log_warning (hashcat_ctx, "You can use --force to override this, but do not report related errors.");
                  event_log_warning (hashcat_ctx, NULL);

                  return -1;
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
                  if (version_maj >= 367)
                  {
                    if (version_maj == 418)
                    {
                      // older 418.x versions are known to be broken.
                      // for instance, NVIDIA-Linux-x86_64-418.43.run
                      // run ./hashcat -b -m 2501 results in self-test fail

                      if (version_min >= 56)
                      {
                        nv_warn = false;
                      }
                    }
                    else
                    {
                      nv_warn = false;
                    }
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

              if ((strstr (device_param->opencl_device_c_version, "beignet")) || (strstr (device_param->opencl_device_version, "beignet")))
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

          opencl_devices_active++;
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

        if (hc_clCreateContext (hashcat_ctx, NULL, 1, &device_param->opencl_device, NULL, NULL, &context) == -1) return -1;

        /**
         * create command-queue
         */

        cl_command_queue command_queue;

        if (hc_clCreateCommandQueue (hashcat_ctx, context, device_param->opencl_device, 0, &command_queue) == -1) return -1;

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_AMD))
        {
          device_param->has_vadd3 = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; __asm__ __volatile__ (\"V_ADD3_U32 %0, 0, 0, 0;\" : \"=v\"(r)); }");
          device_param->has_vbfe  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; __asm__ __volatile__ (\"V_BFE_U32 %0, 0, 0, 0;\" : \"=v\"(r)); }");
          device_param->has_vperm = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; __asm__ __volatile__ (\"V_PERM_B32 %0, 0, 0, 0;\" : \"=v\"(r)); }");
        }

        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_NV))
        {
          device_param->has_bfe   = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"bfe.u32 %0, 0, 0, 0;\" : \"=r\"(r)); }");
          device_param->has_lop3  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"lop3.b32 %0, 0, 0, 0, 0;\" : \"=r\"(r)); }");
          device_param->has_mov64 = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { ulong r; uint a; uint b; asm volatile (\"mov.b64 %0, {%1, %2};\" : \"=l\"(r) : \"r\"(a), \"r\"(b)); }");
          device_param->has_prmt  = opencl_test_instruction (hashcat_ctx, context, device_param->opencl_device, "__kernel void test () { uint r; asm volatile (\"prmt.b32 %0, 0, 0, 0;\" : \"=r\"(r)); }");
        }

        // device_available_mem

        #define MAX_ALLOC_CHECKS_CNT  8192
        #define MAX_ALLOC_CHECKS_SIZE (64 * 1024 * 1024)

        device_param->device_available_mem = device_param->device_global_mem - MAX_ALLOC_CHECKS_SIZE;

        #if defined (_WIN)
        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && (device_param->opencl_platform_vendor_id == VENDOR_ID_NV))
        #else
        if ((device_param->opencl_device_type & CL_DEVICE_TYPE_GPU) && ((device_param->opencl_platform_vendor_id == VENDOR_ID_NV) || (device_param->opencl_platform_vendor_id == VENDOR_ID_AMD)))
        #endif
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

            OCL_PTR *ocl = backend_ctx->ocl;

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
      }
    }
  }

  backend_ctx->opencl_devices_cnt     = opencl_devices_cnt;
  backend_ctx->opencl_devices_active  = opencl_devices_active;

  // all devices combined go into backend_* variables

  backend_ctx->backend_devices_cnt    = cuda_devices_cnt    + opencl_devices_cnt;
  backend_ctx->backend_devices_active = cuda_devices_active + opencl_devices_active;

  // find duplicate devices (typically CUDA and OpenCL)

  if ((cuda_devices_cnt > 0) && (opencl_devices_cnt > 0))
  {
    // using force here enables both devices, which is the worst possible outcome
    // many users force by default, so this is not a good idea

    //if (user_options->force == false)
    //{
    backend_ctx_find_alias_devices (hashcat_ctx);
    //{
  }

  if (backend_ctx->backend_devices_active == 0)
  {
    event_log_error (hashcat_ctx, "No devices found/left.");

    return -1;
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

  backend_ctx->target_msec  = TARGET_MSEC_PROFILE[user_options->workload_profile - 1];

  backend_ctx->need_adl     = need_adl;
  backend_ctx->need_nvml    = need_nvml;
  backend_ctx->need_nvapi   = need_nvapi;
  backend_ctx->need_sysfs   = need_sysfs;

  backend_ctx->comptime     = comptime;

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

    if (device_param->skipped == true) continue;

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
  backend_ctx->opencl_devices_cnt     = 0;
  backend_ctx->opencl_devices_active  = 0;

  backend_ctx->need_adl    = false;
  backend_ctx->need_nvml   = false;
  backend_ctx->need_nvapi  = false;
  backend_ctx->need_sysfs  = false;
}

void backend_ctx_devices_sync_tuning (hashcat_ctx_t *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = hashcat_ctx->backend_ctx;

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

      const u32 hardware_power = device_param_dst->device_processors * device_param_dst->kernel_threads;

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

static u32 get_kernel_threads (const hc_device_param_t *device_param)
{
  // this is an upper limit, a good start, since our strategy is to reduce thread counts only.

  u32 kernel_threads_min = device_param->kernel_threads_min;
  u32 kernel_threads_max = device_param->kernel_threads_max;

  // the changes we do here are just optimizations, since the module always has priority.

  const u32 device_maxworkgroup_size = (const u32) device_param->device_maxworkgroup_size;

  kernel_threads_max = MIN (kernel_threads_max, device_maxworkgroup_size);

  // for CPU we just do 1 ...

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    const u32 cpu_prefered_thread_count = 1;

    kernel_threads_max = MIN (kernel_threads_max, cpu_prefered_thread_count);
  }

  // this is intenionally! at this point, kernel_threads_min can be higher than kernel_threads_max.
  // in this case we actually want kernel_threads_min selected.

  const u32 kernel_threads = MAX (kernel_threads_min, kernel_threads_max);

  return kernel_threads;
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
        event_log_warning (hashcat_ctx, "* Device #%u: Skipping hash-mode %u - known CUDA/OpenCL Runtime/Driver issue (not a hashcat issue)", device_id + 1, hashconfig->hash_mode);
        event_log_warning (hashcat_ctx, "             You can use --force to override, but do not report related errors.");

        device_param->skipped_warning = true;

        continue;
      }
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

          if (device_param->is_opencl == true)
          {
            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NATIVE_VECTOR_WIDTH_LONG, sizeof (vector_width), &vector_width, NULL) == -1) return -1;
          }
        }
        else
        {
          if (device_param->is_cuda == true)
          {
            // cuda does not support this query

            vector_width = 1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clGetDeviceInfo (hashcat_ctx, device_param->opencl_device, CL_DEVICE_NATIVE_VECTOR_WIDTH_INT,  sizeof (vector_width), &vector_width, NULL) == -1) return -1;
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
     * create context for each device
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuCtxCreate (hashcat_ctx, &device_param->cuda_context, CU_CTX_SCHED_BLOCKING_SYNC, device_param->cuda_device) == -1) return -1;
    }

    if (device_param->is_opencl == true)
    {
      /*
      cl_context_properties properties[3];

      properties[0] = CL_CONTEXT_PLATFORM;
      properties[1] = (cl_context_properties) device_param->opencl_platform;
      properties[2] = 0;

      CL_rc = hc_clCreateContext (hashcat_ctx, properties, 1, &device_param->opencl_device, NULL, NULL, &device_param->opencl_context);
      */

      if (hc_clCreateContext (hashcat_ctx, NULL, 1, &device_param->opencl_device, NULL, NULL, &device_param->opencl_context) == -1) return -1;

      /**
       * create command-queue
       */

      // not supported with NV
      // device_param->opencl_command_queue = hc_clCreateCommandQueueWithProperties (hashcat_ctx, device_param->opencl_device, NULL);

      if (hc_clCreateCommandQueue (hashcat_ctx, device_param->opencl_context, device_param->opencl_device, CL_QUEUE_PROFILING_ENABLE, &device_param->opencl_command_queue) == -1) return -1;
    }

    /**
     * create stream for CUDA devices
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuStreamCreate (hashcat_ctx, &device_param->cuda_stream, CU_STREAM_DEFAULT) == -1) return -1;
    }

    /**
     * create events for CUDA devices
     */

    if (device_param->is_cuda == true)
    {
      if (hc_cuEventCreate (hashcat_ctx, &device_param->cuda_event1, CU_EVENT_DEFAULT) == -1) return -1;

      if (hc_cuEventCreate (hashcat_ctx, &device_param->cuda_event2, CU_EVENT_DEFAULT) == -1) return -1;
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

    u64 size_combs = KERNEL_COMBS * sizeof (pw_t);
    u64 size_bfs   = KERNEL_BFS   * sizeof (bf_t);
    u64 size_tm    = 32           * sizeof (bs_word_t);

    device_param->size_bfs      = size_bfs;
    device_param->size_combs    = size_combs;
    device_param->size_tm       = size_tm;

    u64 size_st_digests = 1 * hashconfig->dgst_size;
    u64 size_st_salts   = 1 * sizeof (salt_t);
    u64 size_st_esalts  = 1 * hashconfig->esalt_size;

    device_param->size_st_digests = size_st_digests;
    device_param->size_st_salts   = size_st_salts;
    device_param->size_st_esalts  = size_st_esalts;

    u64 size_extra_buffer = 4;

    if (module_ctx->module_extra_buffer_size != MODULE_DEFAULT)
    {
      const u64 extra_buffer_size = module_ctx->module_extra_buffer_size (hashconfig, user_options, user_options_extra, hashes, device_param);

      if (extra_buffer_size == (u64) -1)
      {
        event_log_error (hashcat_ctx, "Invalid extra buffer size.");

        return -1;
      }

      device_param->extra_buffer_size = extra_buffer_size;

      size_extra_buffer = extra_buffer_size;
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

    int build_options_len = 0;

    #if defined (_WIN)
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D KERNEL_STATIC -I OpenCL -I \"%s\" ", folder_config->cpath_real);
    #else
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D KERNEL_STATIC -I OpenCL -I %s ", folder_config->cpath_real);
    #endif

    // we don't have sm_* on vendors not NV but it doesn't matter

    #if defined (DEBUG)
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D LOCAL_MEM_TYPE=%d -D VENDOR_ID=%u -D CUDA_ARCH=%u -D HAS_VPERM=%u -D HAS_VADD3=%u -D HAS_VBFE=%u -D HAS_BFE=%u -D HAS_LOP3=%u -D HAS_MOV64=%u -D HAS_PRMT=%u -D VECT_SIZE=%d -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D ATTACK_EXEC=%u -D ATTACK_KERN=%u -D _unroll ", device_param->device_local_mem_type, device_param->opencl_platform_vendor_id, (device_param->sm_major * 100) + (device_param->sm_minor * 10), device_param->has_vperm, device_param->has_vadd3, device_param->has_vbfe, device_param->has_bfe, device_param->has_lop3, device_param->has_mov64, device_param->has_prmt, device_param->vector_width, (u32) device_param->opencl_device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, kern_type, hashconfig->attack_exec, user_options_extra->attack_kern);
    #else
    build_options_len += snprintf (build_options_buf + build_options_len, build_options_sz - build_options_len, "-D LOCAL_MEM_TYPE=%d -D VENDOR_ID=%u -D CUDA_ARCH=%u -D HAS_VPERM=%u -D HAS_VADD3=%u -D HAS_VBFE=%u -D HAS_BFE=%u -D HAS_LOP3=%u -D HAS_MOV64=%u -D HAS_PRMT=%u -D VECT_SIZE=%d -D DEVICE_TYPE=%u -D DGST_R0=%u -D DGST_R1=%u -D DGST_R2=%u -D DGST_R3=%u -D DGST_ELEM=%u -D KERN_TYPE=%u -D ATTACK_EXEC=%u -D ATTACK_KERN=%u -D _unroll -w ", device_param->device_local_mem_type, device_param->opencl_platform_vendor_id, (device_param->sm_major * 100) + (device_param->sm_minor * 10), device_param->has_vperm, device_param->has_vadd3, device_param->has_vbfe, device_param->has_bfe, device_param->has_lop3, device_param->has_mov64, device_param->has_prmt, device_param->vector_width, (u32) device_param->opencl_device_type, hashconfig->dgst_pos0, hashconfig->dgst_pos1, hashconfig->dgst_pos2, hashconfig->dgst_pos3, hashconfig->dgst_size / 4, kern_type, hashconfig->attack_exec, user_options_extra->attack_kern);
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
      }
    }

    build_options_module_buf[build_options_module_len] = 0;

    #if defined (DEBUG)
    if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: build_options '%s'", device_id + 1, build_options_buf);
    if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: build_options_module '%s'", device_id + 1, build_options_module_buf);
    #endif

    /**
     * device_name_chksum
     */

    char *device_name_chksum        = (char *) hcmalloc (HCBUFSIZ_TINY);
    char *device_name_chksum_amp_mp = (char *) hcmalloc (HCBUFSIZ_TINY);

    const size_t dnclen = snprintf (device_name_chksum, HCBUFSIZ_TINY, "%d-%d-%d-%u-%s-%s-%s-%d-%u",
      backend_ctx->comptime,
      backend_ctx->cuda_driver_version,
      device_param->is_opencl,
      device_param->opencl_platform_vendor_id,
      device_param->device_name,
      device_param->opencl_device_version,
      device_param->opencl_driver_version,
      device_param->vector_width,
      hashconfig->kern_type);

    const size_t dnclen_amp_mp = snprintf (device_name_chksum_amp_mp, HCBUFSIZ_TINY, "%d-%d-%d-%u-%s-%s-%s",
      backend_ctx->comptime,
      backend_ctx->cuda_driver_version,
      device_param->is_opencl,
      device_param->opencl_platform_vendor_id,
      device_param->device_name,
      device_param->opencl_device_version,
      device_param->opencl_driver_version);

    md5_ctx_t md5_ctx;

    md5_init   (&md5_ctx);
    md5_update (&md5_ctx, (u32 *) device_name_chksum, dnclen);
    md5_final  (&md5_ctx);

    snprintf (device_name_chksum, HCBUFSIZ_TINY, "%08x", md5_ctx.h[0]);

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

    /**
     * main kernel
     */

    {
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

      generate_cached_kernel_filename (user_options->slow_candidates, hashconfig->attack_exec, user_options_extra->attack_kern, kern_type, hashconfig->opti_type, folder_config->profile_dir, device_name_chksum, cached_file);

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
        if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
        #endif

        if (read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true) == false) return -1;

        if (device_param->is_cuda == true)
        {
          nvrtcProgram program;

          if (hc_nvrtcCreateProgram (hashcat_ctx, &program, kernel_sources[0], "main_kernel", 0, NULL, NULL) == -1) return -1;

          char **nvrtc_options = (char **) hccalloc (4 + strlen (build_options_module_buf) + 1, sizeof (char *)); // ...

          nvrtc_options[0] = "--restrict";
          nvrtc_options[1] = "--device-as-default-execution-space";
          nvrtc_options[2] = "--gpu-architecture";

          hc_asprintf (&nvrtc_options[3], "compute_%d%d", device_param->sm_major, device_param->sm_minor);

          char *nvrtc_options_string = hcstrdup (build_options_module_buf);

          const int num_options = 4 + nvrtc_make_options_array_from_string (nvrtc_options_string, nvrtc_options + 4);

          const int rc_nvrtcCompileProgram = hc_nvrtcCompileProgram (hashcat_ctx, program, num_options, (const char * const *) nvrtc_options);

          size_t build_log_size = 0;

          hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

          #if defined (DEBUG)
          if ((build_log_size > 1) || (rc_nvrtcCompileProgram == -1))
          #else
          if (rc_nvrtcCompileProgram == -1)
          #endif
          {
            char *build_log = (char *) hcmalloc (build_log_size + 1);

            if (hc_nvrtcGetProgramLog (hashcat_ctx, program, build_log) == -1) return -1;

            puts (build_log);

            hcfree (build_log);
          }

          if (rc_nvrtcCompileProgram == -1)
          {
            device_param->skipped_warning = true;

            event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          hcfree (nvrtc_options);
          hcfree (nvrtc_options_string);

          size_t binary_size;

          if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &binary_size) == -1) return -1;

          char *binary = (char *) hcmalloc (binary_size);

          if (hc_nvrtcGetPTX (hashcat_ctx, program, binary) == -1) return -1;

          if (hc_nvrtcDestroyProgram (hashcat_ctx, &program) == -1) return -1;

          const int rc_cuModuleLoadDataEx = hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module, binary);

          if (rc_cuModuleLoadDataEx == -1) return -1;

          if (cache_disable == false)
          {
            const bool rc_write = write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

            if (rc_write == false) return -1;
          }

          hcfree (binary);
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) kernel_sources, NULL, &device_param->opencl_program) == -1) return -1;

          const int CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->opencl_program, 1, &device_param->opencl_device, build_options_module_buf, NULL, NULL);

          //if (CL_rc == -1) return -1;

          size_t build_log_size = 0;

          hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

          //if (CL_rc == -1) return -1;

          #if defined (DEBUG)
          if ((build_log_size > 1) || (CL_rc == -1))
          #else
          if (CL_rc == -1)
          #endif
          {
            char *build_log = (char *) hcmalloc (build_log_size + 1);

            const int rc_clGetProgramBuildInfo = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

            if (rc_clGetProgramBuildInfo == -1) return -1;

            puts (build_log);

            hcfree (build_log);
          }

          if (CL_rc == -1)
          {
            device_param->skipped_warning = true;

            event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

            continue;
          }

          if (cache_disable == false)
          {
            size_t binary_size;

            if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL) == -1) return -1;

            char *binary = (char *) hcmalloc (binary_size);

            if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL) == -1) return -1;

            if (write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size) == false) return -1;

            hcfree (binary);
          }
        }
      }
      else
      {
        if (read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false) == false) return -1;

        if (device_param->is_cuda == true)
        {
          if (hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module, kernel_sources[0]) == -1) return -1;
        }

        if (device_param->is_opencl == true)
        {
          if (hc_clCreateProgramWithBinary (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, kernel_lengths, (const unsigned char **) kernel_sources, NULL, &device_param->opencl_program) == -1) return -1;

          if (hc_clBuildProgram (hashcat_ctx, device_param->opencl_program, 1, &device_param->opencl_device, build_options_module_buf, NULL, NULL) == -1) return -1;
        }
      }

      hcfree (kernel_sources[0]);
    }

    hcfree (build_options_module_buf);

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
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          #endif

          if (read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true) == false) return -1;

          if (device_param->is_cuda == true)
          {
            nvrtcProgram program;

            if (hc_nvrtcCreateProgram (hashcat_ctx, &program, kernel_sources[0], "mp_kernel", 0, NULL, NULL) == -1) return -1;

            char **nvrtc_options = (char **) hccalloc (4 + strlen (build_options_buf) + 1, sizeof (char *)); // ...

            nvrtc_options[0] = "--restrict";
            nvrtc_options[1] = "--device-as-default-execution-space";
            nvrtc_options[2] = "--gpu-architecture";

            hc_asprintf (&nvrtc_options[3], "compute_%d%d", device_param->sm_major, device_param->sm_minor);

            char *nvrtc_options_string = hcstrdup (build_options_buf);

            const int num_options = 4 + nvrtc_make_options_array_from_string (nvrtc_options_string, nvrtc_options + 4);

            const int rc_nvrtcCompileProgram = hc_nvrtcCompileProgram (hashcat_ctx, program, num_options, (const char * const *) nvrtc_options);

            size_t build_log_size = 0;

            hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

            #if defined (DEBUG)
            if ((build_log_size > 1) || (rc_nvrtcCompileProgram == -1))
            #else
            if (rc_nvrtcCompileProgram == -1)
            #endif
            {
              char *build_log = (char *) hcmalloc (build_log_size + 1);

              if (hc_nvrtcGetProgramLog (hashcat_ctx, program, build_log) == -1) return -1;

              puts (build_log);

              hcfree (build_log);
            }

            if (rc_nvrtcCompileProgram == -1)
            {
              device_param->skipped_warning = true;

              event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

              continue;
            }

            hcfree (nvrtc_options);
            hcfree (nvrtc_options_string);

            size_t binary_size = 0;

            if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &binary_size) == -1) return -1;

            char *binary = (char *) hcmalloc (binary_size);

            if (hc_nvrtcGetPTX (hashcat_ctx, program, binary) == -1) return -1;

            if (hc_nvrtcDestroyProgram (hashcat_ctx, &program) == -1) return -1;

            // tbd: check for some useful options

            const int rc_cuModuleLoadDataEx = hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module_mp, binary);

            if (rc_cuModuleLoadDataEx == -1) return -1;

            if (cache_disable == false)
            {
              const bool rc_write = write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

              if (rc_write == false) return -1;
            }

            hcfree (binary);
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) kernel_sources, NULL, &device_param->opencl_program_mp) == -1) return -1;

            const int CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->opencl_program_mp, 1, &device_param->opencl_device, build_options_buf, NULL, NULL);

            //if (CL_rc == -1) return -1;

            size_t build_log_size = 0;

            hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program_mp, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

            //if (CL_rc == -1) return -1;

            #if defined (DEBUG)
            if ((build_log_size > 1) || (CL_rc == -1))
            #else
            if (CL_rc == -1)
            #endif
            {
              char *build_log = (char *) hcmalloc (build_log_size + 1);

              const int rc_clGetProgramBuildInfo = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program_mp, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

              if (rc_clGetProgramBuildInfo == -1) return -1;

              puts (build_log);

              hcfree (build_log);
            }

            if (CL_rc == -1)
            {
              device_param->skipped_warning = true;

              event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

              continue;
            }

            if (cache_disable == false)
            {
              size_t binary_size = 0;

              if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program_mp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL) == -1) return -1;

              char *binary = (char *) hcmalloc (binary_size);

              if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program_mp, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL) == -1) return -1;

              write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

              hcfree (binary);
            }
          }
        }
        else
        {
          if (read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false) == false) return -1;

          if (device_param->is_cuda == true)
          {
            if (hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module_mp, kernel_sources[0]) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clCreateProgramWithBinary (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, kernel_lengths, (const unsigned char **) kernel_sources, NULL, &device_param->opencl_program_mp) == -1) return -1;

            if (hc_clBuildProgram (hashcat_ctx, device_param->opencl_program_mp, 1, &device_param->opencl_device, build_options_buf, NULL, NULL) == -1) return -1;
          }
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
          if (user_options->quiet == false) event_log_warning (hashcat_ctx, "* Device #%u: Kernel %s not found in cache! Building may take a while...", device_id + 1, filename_from_filepath (cached_file));
          #endif

          const bool rc_read_kernel = read_kernel_binary (hashcat_ctx, source_file, kernel_lengths, kernel_sources, true);

          if (rc_read_kernel == false) return -1;

          if (device_param->is_cuda == true)
          {
            nvrtcProgram program;

            if (hc_nvrtcCreateProgram (hashcat_ctx, &program, kernel_sources[0], "mp_kernel", 0, NULL, NULL) == -1) return -1;

            char **nvrtc_options = (char **) hccalloc (4 + strlen (build_options_buf) + 1, sizeof (char *)); // ...

            nvrtc_options[0] = "--restrict";
            nvrtc_options[1] = "--device-as-default-execution-space";
            nvrtc_options[2] = "--gpu-architecture";

            hc_asprintf (&nvrtc_options[3], "compute_%d%d", device_param->sm_major, device_param->sm_minor);

            char *nvrtc_options_string = hcstrdup (build_options_buf);

            const int num_options = 4 + nvrtc_make_options_array_from_string (nvrtc_options_string, nvrtc_options + 4);

            const int rc_nvrtcCompileProgram = hc_nvrtcCompileProgram (hashcat_ctx, program, num_options, (const char * const *) nvrtc_options);

            size_t build_log_size = 0;

            hc_nvrtcGetProgramLogSize (hashcat_ctx, program, &build_log_size);

            #if defined (DEBUG)
            if ((build_log_size > 1) || (rc_nvrtcCompileProgram == -1))
            #else
            if (rc_nvrtcCompileProgram == -1)
            #endif
            {
              char *build_log = (char *) hcmalloc (build_log_size + 1);

              if (hc_nvrtcGetProgramLog (hashcat_ctx, program, build_log) == -1) return -1;

              puts (build_log);

              hcfree (build_log);
            }

            if (rc_nvrtcCompileProgram == -1)
            {
              device_param->skipped_warning = true;

              event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

              continue;
            }

            hcfree (nvrtc_options);
            hcfree (nvrtc_options_string);

            size_t binary_size = 0;

            if (hc_nvrtcGetPTXSize (hashcat_ctx, program, &binary_size) == -1) return -1;

            char *binary = (char *) hcmalloc (binary_size);

            if (hc_nvrtcGetPTX (hashcat_ctx, program, binary) == -1) return -1;

            if (hc_nvrtcDestroyProgram (hashcat_ctx, &program) == -1) return -1;

            // tbd: check for some useful options

            if (hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module_amp, binary) == -1) return -1;

            if (cache_disable == false)
            {
              if (write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size) == false) return -1;
            }

            hcfree (binary);
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clCreateProgramWithSource (hashcat_ctx, device_param->opencl_context, 1, (const char **) kernel_sources, NULL, &device_param->opencl_program_amp) == -1) return -1;

            const int CL_rc = hc_clBuildProgram (hashcat_ctx, device_param->opencl_program_amp, 1, &device_param->opencl_device, build_options_buf, NULL, NULL);

            //if (CL_rc == -1) return -1;

            size_t build_log_size = 0;

            hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program_amp, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, 0, NULL, &build_log_size);

            //if (CL_rc == -1) return -1;

            #if defined (DEBUG)
            if ((build_log_size > 1) || (CL_rc == -1))
            #else
            if (CL_rc == -1)
            #endif
            {
              char *build_log = (char *) hcmalloc (build_log_size + 1);

              const int rc_clGetProgramBuildInfo = hc_clGetProgramBuildInfo (hashcat_ctx, device_param->opencl_program_amp, device_param->opencl_device, CL_PROGRAM_BUILD_LOG, build_log_size, build_log, NULL);

              if (rc_clGetProgramBuildInfo == -1) return -1;

              puts (build_log);

              hcfree (build_log);
            }

            if (CL_rc == -1)
            {
              device_param->skipped_warning = true;

              event_log_error (hashcat_ctx, "* Device #%u: Kernel %s build failed - proceeding without this device.", device_id + 1, source_file);

              continue;
            }

            if (cache_disable == false)
            {
              size_t binary_size;

              if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program_amp, CL_PROGRAM_BINARY_SIZES, sizeof (size_t), &binary_size, NULL) == -1) return -1;

              char *binary = (char *) hcmalloc (binary_size);

              if (hc_clGetProgramInfo (hashcat_ctx, device_param->opencl_program_amp, CL_PROGRAM_BINARIES, sizeof (char *), &binary, NULL) == -1) return -1;

              write_kernel_binary (hashcat_ctx, cached_file, binary, binary_size);

              hcfree (binary);
            }
          }
        }
        else
        {
          if (read_kernel_binary (hashcat_ctx, cached_file, kernel_lengths, kernel_sources, false) == false) return -1;

          if (device_param->is_cuda == true)
          {
            if (hc_cuModuleLoadDataExLog (hashcat_ctx, &device_param->cuda_module_amp, kernel_sources[0]) == -1) return -1;
          }

          if (device_param->is_opencl == true)
          {
            if (hc_clCreateProgramWithBinary (hashcat_ctx, device_param->opencl_context, 1, &device_param->opencl_device, kernel_lengths, (const unsigned char **) kernel_sources, NULL, &device_param->opencl_program_amp) == -1) return -1;

            if (hc_clBuildProgram (hashcat_ctx, device_param->opencl_program_amp, 1, &device_param->opencl_device, build_options_buf, NULL, NULL) == -1) return -1;
          }
        }

        hcfree (kernel_sources[0]);

        hcfree (build_options_buf);
      }
    }

    hcfree (device_name_chksum);
    hcfree (device_name_chksum_amp_mp);

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

      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s1_a, bitmap_ctx->bitmap_s1_a, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s1_b, bitmap_ctx->bitmap_s1_b, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s1_c, bitmap_ctx->bitmap_s1_c, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s1_d, bitmap_ctx->bitmap_s1_d, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s2_a, bitmap_ctx->bitmap_s2_a, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s2_b, bitmap_ctx->bitmap_s2_b, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s2_c, bitmap_ctx->bitmap_s2_c, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_bitmap_s2_d, bitmap_ctx->bitmap_s2_d, bitmap_ctx->bitmap_size) == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_digests_buf, hashes->digests_buf,     size_digests)            == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_salt_bufs,   hashes->salts_buf,       size_salts)              == -1) return -1;

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

          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_rules, straight_ctx->kernel_rules_buf, size_rules) == -1) return -1;
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

        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_esalt_bufs, hashes->esalts_buf, size_esalts) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_st_digests_buf, hashes->st_digests_buf, size_st_digests) == -1) return -1;
        if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_st_salts_buf,   hashes->st_salts_buf,   size_st_salts)   == -1) return -1;

        if (size_esalts)
        {
          if (hc_cuMemAlloc (hashcat_ctx, &device_param->cuda_d_st_esalts_buf, size_st_esalts) == -1) return -1;

          if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_st_esalts_buf, hashes->st_esalts_buf, size_st_esalts) == -1) return -1;
        }
      }
    }

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

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_a, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_a, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_b, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_b, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_c, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_c, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s1_d, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s1_d, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_a, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_a, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_b, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_b, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_c, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_c, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_bitmap_s2_d, CL_TRUE, 0, bitmap_ctx->bitmap_size, bitmap_ctx->bitmap_s2_d, 0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_digests_buf, CL_TRUE, 0, size_digests,            hashes->digests_buf,     0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_salt_bufs,   CL_TRUE, 0, size_salts,              hashes->salts_buf,       0, NULL, NULL) == -1) return -1;

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

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_rules, CL_TRUE, 0, size_rules, straight_ctx->kernel_rules_buf, 0, NULL, NULL) == -1) return -1;
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

        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_esalt_bufs, CL_TRUE, 0, size_esalts, hashes->esalts_buf, 0, NULL, NULL) == -1) return -1;
      }

      if (hashconfig->st_hash != NULL)
      {
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_digests_buf,  CL_TRUE, 0, size_st_digests,         hashes->st_digests_buf,  0, NULL, NULL) == -1) return -1;
        if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_salts_buf,    CL_TRUE, 0, size_st_salts,           hashes->st_salts_buf,    0, NULL, NULL) == -1) return -1;

        if (size_esalts)
        {
          if (hc_clCreateBuffer (hashcat_ctx, device_param->opencl_context, CL_MEM_READ_ONLY, size_st_esalts, NULL, &device_param->opencl_d_st_esalts_buf) == -1) return -1;

          if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_st_esalts_buf, CL_TRUE, 0, size_st_esalts, hashes->st_esalts_buf, 0, NULL, NULL) == -1) return -1;
        }
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
    }

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
    }

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
        if (device_param->is_cuda == true)
        {
          device_param->kernel_params_mp[0] = &device_param->cuda_d_combs;
        }

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

    device_param->kernel_params_atinit_buf64[1] = 0; // gid_max

    device_param->kernel_params_atinit[0] = NULL;
    device_param->kernel_params_atinit[1] = &device_param->kernel_params_atinit_buf64[1];

    device_param->kernel_params_decompress_buf64[3] = 0; // gid_max

    if (device_param->is_cuda == true)
    {
      device_param->kernel_params_decompress[0] = NULL; // &device_param->cuda_d_pws_idx;
      device_param->kernel_params_decompress[1] = NULL; // &device_param->cuda_d_pws_comp_buf;
      device_param->kernel_params_decompress[2] = NULL; // (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
                                                        // ? &device_param->cuda_d_pws_buf
                                                        // : &device_param->cuda_d_pws_amp_buf;
    }

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

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function4, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple4 = device_param->cuda_warp_size;
          }
        }
        else
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

            device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function4, device_param->cuda_module, kernel_name) == -1) return -1;

            if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function4, &device_param->kernel_local_mem_size4) == -1) return -1;

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
            if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_tm, device_param->cuda_module, kernel_name) == -1) return -1;

              if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_tm, &device_param->kernel_local_mem_size_tm) == -1) return -1;

              device_param->kernel_preferred_wgs_multiple_tm = device_param->cuda_warp_size;
            }
          }
        }
      }
      else
      {
        // kernel1

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function1, device_param->cuda_module, kernel_name) == -1) return -1;

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_wgs1) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function1, &device_param->kernel_local_mem_size1) == -1) return -1;

        device_param->kernel_preferred_wgs_multiple1 = device_param->cuda_warp_size;

        // kernel2

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function2, device_param->cuda_module, kernel_name) == -1) return -1;

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_wgs2) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function2, &device_param->kernel_local_mem_size2) == -1) return -1;

        device_param->kernel_preferred_wgs_multiple2 = device_param->cuda_warp_size;

        // kernel3

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function3, device_param->cuda_module, kernel_name) == -1) return -1;

        if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_wgs3) == -1) return -1;

        if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function3, &device_param->kernel_local_mem_size3) == -1) return -1;

        device_param->kernel_preferred_wgs_multiple3 = device_param->cuda_warp_size;

        // kernel12

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function12, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function12, &device_param->kernel_wgs12) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function12, &device_param->kernel_local_mem_size12) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple12 = device_param->cuda_warp_size;
        }

        // kernel23

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function23, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function23, &device_param->kernel_wgs23) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function23, &device_param->kernel_local_mem_size23) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple23 = device_param->cuda_warp_size;
        }

        // init2

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_init2, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_init2, &device_param->kernel_local_mem_size_init2) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_init2 = device_param->cuda_warp_size;
        }

        // loop2

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_loop2, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_loop2, &device_param->kernel_local_mem_size_loop2) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_loop2 = device_param->cuda_warp_size;
        }

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux1, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux1, &device_param->kernel_local_mem_size_aux1) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_aux1 = device_param->cuda_warp_size;
        }

        // aux2

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux2, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux2, &device_param->kernel_local_mem_size_aux2) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_aux2 = device_param->cuda_warp_size;
        }

        // aux3

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux3, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux3, &device_param->kernel_local_mem_size_aux3) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_aux3 = device_param->cuda_warp_size;
        }

        // aux4

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_aux4, device_param->cuda_module, kernel_name) == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_aux4, &device_param->kernel_local_mem_size_aux4) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_aux4 = device_param->cuda_warp_size;
        }
      }

      // GPU memset

      if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_memset, device_param->cuda_module, "gpu_memset") == -1) return -1;

      if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_memset, &device_param->kernel_wgs_memset) == -1) return -1;

      if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_memset, &device_param->kernel_local_mem_size_memset) == -1) return -1;

      device_param->kernel_preferred_wgs_multiple_memset = device_param->cuda_warp_size;

      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 0, sizeof (cl_mem),   device_param->kernel_params_memset[0]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]); if (CL_rc == -1) return -1;
      //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]); if (CL_rc == -1) return -1;

      // GPU autotune init

      if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_atinit, device_param->cuda_module, "gpu_atinit") == -1) return -1;

      if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

      if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_atinit, &device_param->kernel_local_mem_size_atinit) == -1) return -1;

      device_param->kernel_preferred_wgs_multiple_atinit = device_param->cuda_warp_size;

      // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]); if (CL_rc == -1) return -1;
      // CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]); if (CL_rc == -1) return -1;

      // GPU decompress

      if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_decompress, device_param->cuda_module, "gpu_decompress") == -1) return -1;

      if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

      if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_decompress, &device_param->kernel_local_mem_size_decompress) == -1) return -1;

      device_param->kernel_preferred_wgs_multiple_decompress = device_param->cuda_warp_size;

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

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp_l, device_param->cuda_module_mp, "l_markov") == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp_l, &device_param->kernel_local_mem_size_mp_l) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_mp_l = device_param->cuda_warp_size;

          // mp_r

          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp_r, device_param->cuda_module_mp, "r_markov") == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp_r, &device_param->kernel_local_mem_size_mp_r) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_mp_r = device_param->cuda_warp_size;

          if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
          {
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]); if (CL_rc == -1) return -1;
            //CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]); if (CL_rc == -1) return -1;
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp, device_param->cuda_module_mp, "C_markov") == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          device_param->kernel_preferred_wgs_multiple_mp = device_param->cuda_warp_size;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_mp, device_param->cuda_module_mp, "C_markov") == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

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
          if (hc_cuModuleGetFunction (hashcat_ctx, &device_param->cuda_function_amp, device_param->cuda_module_amp, "amp") == -1) return -1;

          if (get_cuda_kernel_wgs (hashcat_ctx, device_param->cuda_function_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (get_cuda_kernel_local_mem_size (hashcat_ctx, device_param->cuda_function_amp, &device_param->kernel_local_mem_size_amp) == -1) return -1;

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

    if (device_param->is_opencl == true)
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

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 8);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_s%02d", kern_type, 16);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_sxx", kern_type);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel4) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_local_mem_size4) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_preferred_wgs_multiple4) == -1) return -1;
          }
        }
        else
        {
          if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
          {
            // kernel1

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 4);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

            // kernel2

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 8);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

            // kernel3

            snprintf (kernel_name, sizeof (kernel_name), "m%05u_m%02d", kern_type, 16);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

            if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;
          }
          else
          {
            snprintf (kernel_name, sizeof (kernel_name), "m%05u_mxx", kern_type);

            if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel4) == -1) return -1;

            if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_wgs4) == -1) return -1;

            if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel4, &device_param->kernel_local_mem_size4) == -1) return -1;

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
            if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
            {
              snprintf (kernel_name, sizeof (kernel_name), "m%05u_tm", kern_type);

              if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_tm) == -1) return -1;

              if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_wgs_tm) == -1) return -1;

              if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_local_mem_size_tm) == -1) return -1;

              if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_tm, &device_param->kernel_preferred_wgs_multiple_tm) == -1) return -1;
            }
          }
        }
      }
      else
      {
        // kernel1

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_init", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel1) == -1) return -1;

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_wgs1) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_local_mem_size1) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel1, &device_param->kernel_preferred_wgs_multiple1) == -1) return -1;

        // kernel2

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel2) == -1) return -1;

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_wgs2) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_local_mem_size2) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel2, &device_param->kernel_preferred_wgs_multiple2) == -1) return -1;

        // kernel3

        snprintf (kernel_name, sizeof (kernel_name), "m%05u_comp", kern_type);

        if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel3) == -1) return -1;

        if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_wgs3) == -1) return -1;

        if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_local_mem_size3) == -1) return -1;

        if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel3, &device_param->kernel_preferred_wgs_multiple3) == -1) return -1;

        // kernel12

        if (hashconfig->opts_type & OPTS_TYPE_HOOK12)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook12", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel12) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_wgs12) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_local_mem_size12) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel12, &device_param->kernel_preferred_wgs_multiple12) == -1) return -1;
        }

        // kernel23

        if (hashconfig->opts_type & OPTS_TYPE_HOOK23)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_hook23", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel23) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_wgs23) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_local_mem_size23) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel23, &device_param->kernel_preferred_wgs_multiple23) == -1) return -1;
        }

        // init2

        if (hashconfig->opts_type & OPTS_TYPE_INIT2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_init2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_init2) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_wgs_init2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_local_mem_size_init2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_init2, &device_param->kernel_preferred_wgs_multiple_init2) == -1) return -1;
        }

        // loop2

        if (hashconfig->opts_type & OPTS_TYPE_LOOP2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_loop2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_loop2) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_wgs_loop2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_local_mem_size_loop2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_loop2, &device_param->kernel_preferred_wgs_multiple_loop2) == -1) return -1;
        }

        // aux1

        if (hashconfig->opts_type & OPTS_TYPE_AUX1)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux1", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux1) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_wgs_aux1) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_local_mem_size_aux1) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux1, &device_param->kernel_preferred_wgs_multiple_aux1) == -1) return -1;
        }

        // aux2

        if (hashconfig->opts_type & OPTS_TYPE_AUX2)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux2", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux2) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_wgs_aux2) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_local_mem_size_aux2) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux2, &device_param->kernel_preferred_wgs_multiple_aux2) == -1) return -1;
        }

        // aux3

        if (hashconfig->opts_type & OPTS_TYPE_AUX3)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux3", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux3) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_wgs_aux3) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_local_mem_size_aux3) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux3, &device_param->kernel_preferred_wgs_multiple_aux3) == -1) return -1;
        }

        // aux4

        if (hashconfig->opts_type & OPTS_TYPE_AUX4)
        {
          snprintf (kernel_name, sizeof (kernel_name), "m%05u_aux4", kern_type);

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, kernel_name, &device_param->opencl_kernel_aux4) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_wgs_aux4) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_local_mem_size_aux4) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_aux4, &device_param->kernel_preferred_wgs_multiple_aux4) == -1) return -1;
        }
      }

      // GPU memset

      if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, "gpu_memset", &device_param->opencl_kernel_memset) == -1) return -1;

      if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_wgs_memset) == -1) return -1;

      if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_local_mem_size_memset) == -1) return -1;

      if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_memset, &device_param->kernel_preferred_wgs_multiple_memset) == -1) return -1;

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 0, sizeof (cl_mem),   device_param->kernel_params_memset[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 1, sizeof (cl_uint),  device_param->kernel_params_memset[1]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_memset, 2, sizeof (cl_ulong), device_param->kernel_params_memset[2]) == -1) return -1;

      // GPU autotune init

      if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, "gpu_atinit", &device_param->opencl_kernel_atinit) == -1) return -1;

      if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_wgs_atinit) == -1) return -1;

      if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_local_mem_size_atinit) == -1) return -1;

      if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_atinit, &device_param->kernel_preferred_wgs_multiple_atinit) == -1) return -1;

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 0, sizeof (cl_mem),   device_param->kernel_params_atinit[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_atinit, 1, sizeof (cl_ulong), device_param->kernel_params_atinit[1]) == -1) return -1;

      // GPU decompress

      if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program, "gpu_decompress", &device_param->opencl_kernel_decompress) == -1) return -1;

      if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_wgs_decompress) == -1) return -1;

      if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_local_mem_size_decompress) == -1) return -1;

      if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_decompress, &device_param->kernel_preferred_wgs_multiple_decompress) == -1) return -1;

      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 0, sizeof (cl_mem),   device_param->kernel_params_decompress[0]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 1, sizeof (cl_mem),   device_param->kernel_params_decompress[1]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 2, sizeof (cl_mem),   device_param->kernel_params_decompress[2]) == -1) return -1;
      if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_decompress, 3, sizeof (cl_ulong), device_param->kernel_params_decompress[3]) == -1) return -1;

      // MP start

      if (user_options->slow_candidates == true)
      {
      }
      else
      {
        if (user_options->attack_mode == ATTACK_MODE_BF)
        {
          // mp_l

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "l_markov", &device_param->opencl_kernel_mp_l) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_wgs_mp_l) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_local_mem_size_mp_l) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp_l, &device_param->kernel_preferred_wgs_multiple_mp_l) == -1) return -1;

          // mp_r

          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "r_markov", &device_param->opencl_kernel_mp_r) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_wgs_mp_r) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_local_mem_size_mp_r) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp_r, &device_param->kernel_preferred_wgs_multiple_mp_r) == -1) return -1;

          if (hashconfig->opts_type & OPTS_TYPE_PT_BITSLICE)
          {
            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 0, sizeof (cl_mem), device_param->kernel_params_tm[0]) == -1) return -1;
            if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_tm, 1, sizeof (cl_mem), device_param->kernel_params_tm[1]) == -1) return -1;
          }
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID1)
        {
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "C_markov", &device_param->opencl_kernel_mp) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

          if (get_opencl_kernel_preferred_wgs_multiple (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_preferred_wgs_multiple_mp) == -1) return -1;
        }
        else if (user_options->attack_mode == ATTACK_MODE_HYBRID2)
        {
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_mp, "C_markov", &device_param->opencl_kernel_mp) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_wgs_mp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_mp, &device_param->kernel_local_mem_size_mp) == -1) return -1;

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
          if (hc_clCreateKernel (hashcat_ctx, device_param->opencl_program_amp, "amp", &device_param->opencl_kernel_amp) == -1) return -1;

          if (get_opencl_kernel_wgs (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_wgs_amp) == -1) return -1;

          if (get_opencl_kernel_local_mem_size (hashcat_ctx, device_param, device_param->opencl_kernel_amp, &device_param->kernel_local_mem_size_amp) == -1) return -1;

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

    if (user_options->attack_mode == ATTACK_MODE_STRAIGHT)
    {
      if (hashconfig->opti_type & OPTI_TYPE_OPTIMIZED_KERNEL)
      {
        // not required
      }
      else
      {
        device_param->kernel_threads_max = MIN (device_param->kernel_threads_max, 64);
      }
    }

    /**
     * now everything that depends on threads and accel, basically dynamic workload
     */

    const u32 kernel_threads = get_kernel_threads (device_param);

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

    const u64 PWS_SPACE = 1024ULL * 1024ULL * 1024ULL;

    // sometimes device_available_mem and device_maxmem_alloc reported back from the opencl runtime are a bit inaccurate.
    // let's add some extra space just to be sure.

    const u64 EXTRA_SPACE = 64ULL * 1024ULL * 1024ULL;

    while (kernel_accel_max >= kernel_accel_min)
    {
      const u64 kernel_power_max = device_param->hardware_power * kernel_accel_max;

      // size_pws

      size_pws = kernel_power_max * sizeof (pw_t);

      size_pws_amp = (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL) ? 1 : size_pws;

      // size_pws_comp

      size_pws_comp = kernel_power_max * (sizeof (u32) * 64);

      // size_pws_idx

      size_pws_idx = (u64) (kernel_power_max + 1) * sizeof (pw_idx_t);

      // size_tmps

      size_tmps = kernel_power_max * (hashconfig->tmp_size + hashconfig->extra_tmp_size);

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
        + size_extra_buffer
        + size_shown
        + size_tm
        + size_tmps
        + size_st_digests
        + size_st_salts
        + size_st_esalts;

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

      size_total_host_all += size_total_host + EXTRA_SPACE;

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

    hardware_power_all += device_param->hardware_power;

    EVENT_DATA (EVENT_BACKEND_DEVICE_INIT_POST, &backend_devices_idx, sizeof (int));
  }

  if (user_options->benchmark == false)
  {
    if (hardware_power_all == 0) return -1;
  }

  backend_ctx->hardware_power_all = hardware_power_all;

  EVENT_DATA (EVENT_BACKEND_SESSION_HOSTMEM, &size_total_host_all, sizeof (u64));

  return 0;
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

      if (device_param->cuda_event1)           hc_cuEventDestroy (hashcat_ctx, device_param->cuda_event1);
      if (device_param->cuda_event2)           hc_cuEventDestroy (hashcat_ctx, device_param->cuda_event2);

      if (device_param->cuda_stream)           hc_cuStreamDestroy (hashcat_ctx, device_param->cuda_stream);

      if (device_param->cuda_module)           hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module);
      if (device_param->cuda_module_mp)        hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module_mp);
      if (device_param->cuda_module_amp)       hc_cuModuleUnload (hashcat_ctx, device_param->cuda_module_amp);

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

      device_param->cuda_function1            = NULL;
      device_param->cuda_function12           = NULL;
      device_param->cuda_function2            = NULL;
      device_param->cuda_function23           = NULL;
      device_param->cuda_function3            = NULL;
      device_param->cuda_function4            = NULL;
      device_param->cuda_function_init2       = NULL;
      device_param->cuda_function_loop2       = NULL;
      device_param->cuda_function_mp          = NULL;
      device_param->cuda_function_mp_l        = NULL;
      device_param->cuda_function_mp_r        = NULL;
      device_param->cuda_function_tm          = NULL;
      device_param->cuda_function_amp         = NULL;
      device_param->cuda_function_memset      = NULL;
      device_param->cuda_function_atinit      = NULL;
      device_param->cuda_function_decompress  = NULL;
      device_param->cuda_function_aux1        = NULL;
      device_param->cuda_function_aux2        = NULL;
      device_param->cuda_function_aux3        = NULL;
      device_param->cuda_function_aux4        = NULL;

      device_param->cuda_module               = NULL;
      device_param->cuda_module_mp            = NULL;
      device_param->cuda_module_amp           = NULL;

      device_param->cuda_context              = NULL;
    }

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

      if (device_param->opencl_kernel1)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel1);
      if (device_param->opencl_kernel12)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel12);
      if (device_param->opencl_kernel2)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel2);
      if (device_param->opencl_kernel23)         hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel23);
      if (device_param->opencl_kernel3)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel3);
      if (device_param->opencl_kernel4)          hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel4);
      if (device_param->opencl_kernel_init2)     hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_init2);
      if (device_param->opencl_kernel_loop2)     hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_loop2);
      if (device_param->opencl_kernel_mp)        hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp);
      if (device_param->opencl_kernel_mp_l)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp_l);
      if (device_param->opencl_kernel_mp_r)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_mp_r);
      if (device_param->opencl_kernel_tm)        hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_tm);
      if (device_param->opencl_kernel_amp)       hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_amp);
      if (device_param->opencl_kernel_memset)    hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_memset);
      if (device_param->opencl_kernel_atinit)    hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_atinit);
      if (device_param->opencl_kernel_decompress)hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_decompress);
      if (device_param->opencl_kernel_aux1)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux1);
      if (device_param->opencl_kernel_aux2)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux2);
      if (device_param->opencl_kernel_aux3)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux3);
      if (device_param->opencl_kernel_aux4)      hc_clReleaseKernel (hashcat_ctx, device_param->opencl_kernel_aux4);

      if (device_param->opencl_program)          hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program);
      if (device_param->opencl_program_mp)       hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program_mp);
      if (device_param->opencl_program_amp)      hc_clReleaseProgram (hashcat_ctx, device_param->opencl_program_amp);

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
      device_param->opencl_kernel1             = NULL;
      device_param->opencl_kernel12            = NULL;
      device_param->opencl_kernel2             = NULL;
      device_param->opencl_kernel23            = NULL;
      device_param->opencl_kernel3             = NULL;
      device_param->opencl_kernel4             = NULL;
      device_param->opencl_kernel_init2        = NULL;
      device_param->opencl_kernel_loop2        = NULL;
      device_param->opencl_kernel_mp           = NULL;
      device_param->opencl_kernel_mp_l         = NULL;
      device_param->opencl_kernel_mp_r         = NULL;
      device_param->opencl_kernel_tm           = NULL;
      device_param->opencl_kernel_amp          = NULL;
      device_param->opencl_kernel_memset       = NULL;
      device_param->opencl_kernel_atinit       = NULL;
      device_param->opencl_kernel_decompress   = NULL;
      device_param->opencl_kernel_aux1         = NULL;
      device_param->opencl_kernel_aux2         = NULL;
      device_param->opencl_kernel_aux3         = NULL;
      device_param->opencl_kernel_aux4         = NULL;
      device_param->opencl_program             = NULL;
      device_param->opencl_program_mp          = NULL;
      device_param->opencl_program_amp         = NULL;
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

    device_param->kernel_params_buf32[33] = combinator_ctx->combs_mode;

    /*
    if (device_param->is_opencl == true)
    {
      CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel1, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
      CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
      CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel3, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;
      CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel4, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1;

      if (hashconfig->opts_type & OPTS_TYPE_HOOK12) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel12,     33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
      if (hashconfig->opts_type & OPTS_TYPE_HOOK23) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel23,     33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
      if (hashconfig->opts_type & OPTS_TYPE_INIT2)  { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_init2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
      if (hashconfig->opts_type & OPTS_TYPE_LOOP2)  { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_loop2, 33, sizeof (cl_uint), device_param->kernel_params[33]); if (CL_rc == -1) return -1; }
    }
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
      //for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_ulong), device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }
      //for (u32 i = 4; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_uint),  device_param->kernel_params_mp[i]); if (CL_rc == -1) return -1; }

      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css)   == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css) == -1) return -1;
    }

    if (device_param->is_opencl == true)
    {
      for (u32 i = 3; i < 4; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_ulong), device_param->kernel_params_mp[i]) == -1) return -1; }
      for (u32 i = 4; i < 8; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp, i, sizeof (cl_uint),  device_param->kernel_params_mp[i]) == -1) return -1; }

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL) == -1) return -1;
    }
  }

  return 0;
}

int backend_session_update_mp_rl (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r)
{
  mask_ctx_t     *mask_ctx     = hashcat_ctx->mask_ctx;
  backend_ctx_t   *backend_ctx   = hashcat_ctx->backend_ctx;
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
      //for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
      //for (u32 i = 4; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_uint),  device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }
      //for (u32 i = 9; i < 9; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]); if (CL_rc == -1) return -1; }

      //for (u32 i = 3; i < 4; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
      //for (u32 i = 4; i < 7; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_uint),  device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }
      //for (u32 i = 8; i < 8; i++) { CL_rc = hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]); if (CL_rc == -1) return -1; }

      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_root_css_buf,   mask_ctx->root_css_buf,   device_param->size_root_css)   == -1) return -1;
      if (hc_cuMemcpyHtoD (hashcat_ctx, device_param->cuda_d_markov_css_buf, mask_ctx->markov_css_buf, device_param->size_markov_css) == -1) return -1;
    }

    if (device_param->is_opencl == true)
    {
      for (u32 i = 3; i < 4; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]) == -1) return -1; }
      for (u32 i = 4; i < 8; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_uint),  device_param->kernel_params_mp_l[i]) == -1) return -1; }
      for (u32 i = 9; i < 9; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_l, i, sizeof (cl_ulong), device_param->kernel_params_mp_l[i]) == -1) return -1; }

      for (u32 i = 3; i < 4; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]) == -1) return -1; }
      for (u32 i = 4; i < 7; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_uint),  device_param->kernel_params_mp_r[i]) == -1) return -1; }
      for (u32 i = 8; i < 8; i++) { if (hc_clSetKernelArg (hashcat_ctx, device_param->opencl_kernel_mp_r, i, sizeof (cl_ulong), device_param->kernel_params_mp_r[i]) == -1) return -1; }

      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_root_css_buf,   CL_TRUE, 0, device_param->size_root_css,   mask_ctx->root_css_buf,   0, NULL, NULL) == -1) return -1;
      if (hc_clEnqueueWriteBuffer (hashcat_ctx, device_param->opencl_command_queue, device_param->opencl_d_markov_css_buf, CL_TRUE, 0, device_param->size_markov_css, mask_ctx->markov_css_buf, 0, NULL, NULL) == -1) return -1;
    }
  }

  return 0;
}
