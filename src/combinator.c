/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "combinator.h"
#include "wordlist.h"

int combinator_ctx_init (combinator_ctx_t *combinator_ctx, const user_options_t *user_options)
{
  combinator_ctx->enabled = false;

  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  if ((user_options->attack_mode != ATTACK_MODE_COMBI)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID1)
   && (user_options->attack_mode != ATTACK_MODE_HYBRID2)) return 0;

  combinator_ctx->enabled = true;

  return 0;
}

void combinator_ctx_destroy (combinator_ctx_t *combinator_ctx)
{
  if (combinator_ctx->enabled == false) return;

  myfree (combinator_ctx);
}

