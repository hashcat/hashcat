/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "cpt.h"

int cpt_ctx_init (cpt_ctx_t *cpt_ctx, const user_options_t *user_options)
{
  cpt_ctx->enabled = false;

  if (user_options->keyspace    == true) return 0;
  if (user_options->left        == true) return 0;
  if (user_options->opencl_info == true) return 0;
  if (user_options->show        == true) return 0;
  if (user_options->stdout_flag == true) return 0;
  if (user_options->usage       == true) return 0;
  if (user_options->version     == true) return 0;

  cpt_ctx->enabled = true;

  cpt_ctx->cpt_buf = (cpt_t *) mycalloc (CPT_BUF, sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);

  return 0;
}

void cpt_ctx_destroy (cpt_ctx_t *cpt_ctx)
{
  if (cpt_ctx->enabled == false) return;

  myfree (cpt_ctx->cpt_buf);

  memset (cpt_ctx, 0, sizeof (cpt_ctx_t));
}

void cpt_ctx_reset (cpt_ctx_t *cpt_ctx)
{
  if (cpt_ctx->enabled == false) return;

  memset (cpt_ctx->cpt_buf, 0, CPT_BUF * sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);
}
