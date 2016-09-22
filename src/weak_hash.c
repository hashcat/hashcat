/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "interface.h"
#include "timer.h"
#include "logging.h"
#include "ext_OpenCL.h"
#include "ext_ADL.h"
#include "ext_nvapi.h"
#include "ext_nvml.h"
#include "ext_xnvctrl.h"
#include "mpsp.h"
#include "rp_cpu.h"
#include "tuningdb.h"
#include "thread.h"
#include "opencl.h"
#include "hwmon.h"
#include "restore.h"
#include "hash_management.h"
#include "outfile.h"
#include "potfile.h"
#include "debugfile.h"
#include "loopback.h"
#include "data.h"
#include "weak_hash.h"

extern hc_global_data_t data;

void weak_hash_check (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, hashconfig_t *hashconfig, hashes_t *hashes, const uint salt_pos)
{
  if (device_param == NULL)
  {
    log_error ("ERROR: %s : Invalid argument", __func__);

    exit (-1);
  }

  salt_t *salt_buf = &hashes->salts_buf[salt_pos];

  device_param->kernel_params_buf32[27] = salt_pos;
  device_param->kernel_params_buf32[30] = 1;
  device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
  device_param->kernel_params_buf32[32] = salt_buf->digests_offset;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf32[34] = 1;

  char *dictfile_old = data.dictfile;

  const char *weak_hash_check = "weak-hash-check";

  data.dictfile = (char *) weak_hash_check;

  uint cmd0_rule_old = data.kernel_rules_buf[0].cmds[0];

  data.kernel_rules_buf[0].cmds[0] = 0;

  /**
   * run the kernel
   */

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    run_kernel (KERN_RUN_1, opencl_ctx, device_param, 1, false, 0, hashconfig);
  }
  else
  {
    run_kernel (KERN_RUN_1, opencl_ctx, device_param, 1, false, 0, hashconfig);

    uint loop_step = 16;

    const uint iter = salt_buf->salt_iter;

    for (uint loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
    {
      uint loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      run_kernel (KERN_RUN_2, opencl_ctx, device_param, 1, false, 0, hashconfig);
    }

    run_kernel (KERN_RUN_3, opencl_ctx, device_param, 1, false, 0, hashconfig);
  }

  /**
   * result
   */

  check_cracked (opencl_ctx, device_param, user_options, hashconfig, hashes, salt_pos);

  /**
   * cleanup
   */

  device_param->kernel_params_buf32[27] = 0;
  device_param->kernel_params_buf32[28] = 0;
  device_param->kernel_params_buf32[29] = 0;
  device_param->kernel_params_buf32[30] = 0;
  device_param->kernel_params_buf32[31] = 0;
  device_param->kernel_params_buf32[32] = 0;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf32[34] = 0;

  data.dictfile = dictfile_old;

  data.kernel_rules_buf[0].cmds[0] = cmd0_rule_old;
}
