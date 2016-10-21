/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "event.h"
#include "opencl.h"
#include "hashes.h"
#include "weak_hash.h"

int weak_hash_check (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos)
{
  hashconfig_t   *hashconfig   = hashcat_ctx->hashconfig;
  hashes_t       *hashes       = hashcat_ctx->hashes;
  straight_ctx_t *straight_ctx = hashcat_ctx->straight_ctx;

  salt_t *salt_buf = &hashes->salts_buf[salt_pos];

  device_param->kernel_params_buf32[27] = salt_pos;
  device_param->kernel_params_buf32[30] = 1;
  device_param->kernel_params_buf32[31] = salt_buf->digests_cnt;
  device_param->kernel_params_buf32[32] = salt_buf->digests_offset;
  device_param->kernel_params_buf32[33] = 0;
  device_param->kernel_params_buf32[34] = 1;

  u32 cmd0_rule_old = straight_ctx->kernel_rules_buf[0].cmds[0];

  straight_ctx->kernel_rules_buf[0].cmds[0] = 0;

  /**
   * run the kernel
   */

  int CL_rc;

  if (hashconfig->attack_exec == ATTACK_EXEC_INSIDE_KERNEL)
  {
    CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 1, false, 0);

    if (CL_rc == -1) return -1;
  }
  else
  {
    CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_1, 1, false, 0);

    if (CL_rc == -1) return -1;

    u32 loop_step = 16;

    const u32 iter = salt_buf->salt_iter;

    for (u32 loop_pos = 0; loop_pos < iter; loop_pos += loop_step)
    {
      u32 loop_left = iter - loop_pos;

      loop_left = MIN (loop_left, loop_step);

      device_param->kernel_params_buf32[28] = loop_pos;
      device_param->kernel_params_buf32[29] = loop_left;

      CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_2, 1, false, 0);

      if (CL_rc == -1) return -1;
    }

    CL_rc = run_kernel (hashcat_ctx, device_param, KERN_RUN_3, 1, false, 0);

    if (CL_rc == -1) return -1;
  }

  /**
   * result
   */

  check_cracked (hashcat_ctx, device_param, salt_pos);

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

  straight_ctx->kernel_rules_buf[0].cmds[0] = cmd0_rule_old;

  return 0;
}
