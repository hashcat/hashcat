/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#if defined (__APPLE__)
#include <stdio.h>
#endif

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "shared.h"
#include "filehandling.h"
#include "rp.h"
#include "rp_cpu.h"
#include "straight.h"

int straight_ctx_init (straight_ctx_t *straight_ctx, const user_options_t *user_options)
{
  memset (straight_ctx, 0, sizeof (straight_ctx_t));

  straight_ctx->enabled = false;

  if (user_options->attack_mode != ATTACK_MODE_STRAIGHT) return 0;

  straight_ctx->enabled = true;

  if ((user_options->rp_files_cnt == 0) && (user_options->rp_gen == 0))
  {
    straight_ctx->kernel_rules_buf = (kernel_rule_t *) mymalloc (sizeof (kernel_rule_t));

    straight_ctx->kernel_rules_buf[0].cmds[0] = RULE_OP_MANGLE_NOOP;

    straight_ctx->kernel_rules_cnt = 1;
  }
  else
  {
    if (user_options->rp_files_cnt)
    {
      const int rc_kernel_load = kernel_rules_load (&straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt, user_options);

      if (rc_kernel_load == -1) return -1;
    }
    else if (user_options->rp_gen)
    {
      const int rc_kernel_generate = kernel_rules_generate (&straight_ctx->kernel_rules_buf, &straight_ctx->kernel_rules_cnt, user_options);

      if (rc_kernel_generate == -1) return -1;
    }
  }

  /**
   * generate NOP rules
   */


  return 0;
}

void straight_ctx_destroy (straight_ctx_t *straight_ctx)
{
  if (straight_ctx->enabled == false) return;

  myfree (straight_ctx->kernel_rules_buf);

  straight_ctx->kernel_rules_buf = NULL;
  straight_ctx->kernel_rules_cnt = 0;

  myfree (straight_ctx);
}
