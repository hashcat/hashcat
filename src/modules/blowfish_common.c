/**
 * Author......: See docs/credits.txt
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

u32 blowfish_module_pw_max (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra)
{
  const u32 pw_max = 72; // Underlaying Blowfish max

  return pw_max;
}

bool blowfish_module_jit_cache_disable (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  return true;
}

char *blowfish_module_jit_build_options (MAYBE_UNUSED const hashconfig_t *hashconfig, MAYBE_UNUSED const user_options_t *user_options, MAYBE_UNUSED const user_options_extra_t *user_options_extra, MAYBE_UNUSED const hashes_t *hashes, MAYBE_UNUSED const hc_device_param_t *device_param)
{
  char *jit_build_options = NULL;

  // this mode heavily depends on the available shared memory size
  // note the kernel need to have some special code changes in order to make use to use post-48k memory region
  // we need to set some macros

  bool use_dynamic = false;

  if (device_param->is_cuda == true)
  {
    use_dynamic = true;
  }

  // this uses some nice feedback effect.
  // based on the device_local_mem_size the reqd_work_group_size in the kernel is set to some value
  // which is then is read from the opencl host in the device_preferred_wgs_multiple result.
  // therefore we do not need to set module_kernel_threads_min/max except for CPU, where the threads are set to fixed 1.

  if (device_param->opencl_device_type & CL_DEVICE_TYPE_CPU)
  {
    hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", 1);
  }
  else
  {
    u32 overhead = 0;

    if (device_param->opencl_device_vendor_id == VENDOR_ID_NV)
    {
      // note we need to use device_param->device_local_mem_size - 4 because opencl jit returns with:
      // Entry function '...' uses too much shared data (0xc004 bytes, 0xc000 max)
      // on my development system. no clue where the 4 bytes are spent.
      // I did some research on this and it seems to be related with the datatype.
      // For example, if i used u8 instead, there's only 1 byte wasted.

      if (device_param->is_opencl == true)
      {
        overhead = 1;
      }
    }

    if (user_options->kernel_threads_chgd == true)
    {
      u32 fixed_local_size = user_options->kernel_threads;

      if (use_dynamic == true)
      {
        if ((fixed_local_size * 4096) > device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET])
        {
          // otherwise out-of-bound reads

          fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        if ((fixed_local_size * 4096) > (device_param->device_local_mem_size - overhead))
        {
          // otherwise out-of-bound reads

          fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;
        }

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", fixed_local_size);
      }
    }
    else
    {
      if (use_dynamic == true)
      {
        // using kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] is a bit hackish.
        // we had to brute-force this value out of an already loaded CUDA function.
        // there's no official way to query for this value.

        const u32 fixed_local_size = device_param->kernel_dynamic_local_mem_size[HC_DEV_KERN_MEMSET] / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u -D DYNAMIC_LOCAL", fixed_local_size);
      }
      else
      {
        const u32 fixed_local_size = (device_param->device_local_mem_size - overhead) / 4096;

        hc_asprintf (&jit_build_options, "-D FIXED_LOCAL_SIZE=%u", fixed_local_size);
      }
    }
  }

  return jit_build_options;
}
