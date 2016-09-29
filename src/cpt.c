/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "logging.h"
#include "cpt.h"

int cpt_ctx_init (cpt_ctx_t *cpt_ctx)
{
  cpt_ctx->cpt_buf = (cpt_t *) mycalloc (CPT_BUF, sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);

  return 0;
}

void cpt_ctx_destroy (cpt_ctx_t *cpt_ctx)
{
  myfree (cpt_ctx->cpt_buf);

  myfree (cpt_ctx);
}

void cpt_ctx_reset (cpt_ctx_t *cpt_ctx)
{
  memset (cpt_ctx->cpt_buf, 0, CPT_BUF * sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);
}
