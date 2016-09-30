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
  straight_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if (user_options->attack_mode == ATTACK_MODE_BF) return 0;

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

  for (u32 dict_pos = 0; dict_pos < straight_ctx->dicts_cnt; dict_pos++)
  {
    myfree (straight_ctx->dicts[dict_pos]);
  }

  myfree (straight_ctx->dicts);

  myfree (straight_ctx->kernel_rules_buf);

  straight_ctx->kernel_rules_buf = NULL;
  straight_ctx->kernel_rules_cnt = 0;

  myfree (straight_ctx);
}

void straight_append_dict (straight_ctx_t *straight_ctx, const char *dict)
{
  if (straight_ctx->dicts_avail == straight_ctx->dicts_cnt)
  {
    straight_ctx->dicts = (char **) myrealloc (straight_ctx->dicts, straight_ctx->dicts_avail * sizeof (char *), INCR_DICTS * sizeof (char *));

    straight_ctx->dicts_avail += INCR_DICTS;
  }

  straight_ctx->dicts[straight_ctx->dicts_cnt] = mystrdup (dict);

  straight_ctx->dicts_cnt++;
}
