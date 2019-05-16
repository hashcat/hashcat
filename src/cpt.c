/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "cpt.h"

int cpt_ctx_init (hashcat_ctx_t *hashcat_ctx)
{
  cpt_ctx_t      *cpt_ctx      = hashcat_ctx->cpt_ctx;
  user_options_t *user_options = hashcat_ctx->user_options;

  cpt_ctx->enabled = false;

  if (user_options->example_hashes == true) return 0;
  if (user_options->keyspace       == true) return 0;
  if (user_options->left           == true) return 0;
  if (user_options->backend_info   == true) return 0;
  if (user_options->show           == true) return 0;
  if (user_options->usage          == true) return 0;
  if (user_options->version        == true) return 0;

  cpt_ctx->enabled = true;

  cpt_ctx->cpt_buf = (cpt_t *) hccalloc (CPT_CACHE, sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);

  return 0;
}

void cpt_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  if (cpt_ctx->enabled == false) return;

  hcfree (cpt_ctx->cpt_buf);

  memset (cpt_ctx, 0, sizeof (cpt_ctx_t));
}

void cpt_ctx_reset (hashcat_ctx_t *hashcat_ctx)
{
  cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  if (cpt_ctx->enabled == false) return;

  memset (cpt_ctx->cpt_buf, 0, CPT_CACHE * sizeof (cpt_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_pos   = 0;
  cpt_ctx->cpt_start = time (NULL);
}
