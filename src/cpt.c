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

  if (user_options->usage         > 0)    return 0;
  if (user_options->backend_info  > 0)    return 0;
  if (user_options->hash_info     > 0)    return 0;

  if (user_options->keyspace     == true) return 0;
  if (user_options->left         == true) return 0;
  if (user_options->show         == true) return 0;
  if (user_options->version      == true) return 0;
  if (user_options->identify     == true) return 0;

  cpt_ctx->enabled = true;

  cpt_ctx->cpt_buf = (cpt_t *) hccalloc (CPT_SECONDS, sizeof (cpt_t));

  cpt_ctx->curve_buf = (curve_point_t *) hccalloc (CURVE_SAMPLES, sizeof (curve_point_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_start = time (NULL);

  cpt_ctx->curve_cnt           = 0;
  cpt_ctx->curve_never         = 0;
  cpt_ctx->curve_total         = 0;
  cpt_ctx->curve_inter         = 0;
  cpt_ctx->curve_slope         = 0;
  cpt_ctx->curve_have          = false;
  cpt_ctx->curve_s             = 0;
  cpt_ctx->curve_xbar          = 0;
  cpt_ctx->curve_sxx           = 0;
  cpt_ctx->curve_n             = 0;
  cpt_ctx->curve_never_lo      = 0;
  cpt_ctx->curve_never_hi      = 0;

  return 0;
}

void cpt_ctx_destroy (hashcat_ctx_t *hashcat_ctx)
{
  cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  if (cpt_ctx->enabled == false) return;

  hcfree (cpt_ctx->cpt_buf);

  hcfree (cpt_ctx->curve_buf);

  memset (cpt_ctx, 0, sizeof (cpt_ctx_t));
}

void cpt_ctx_reset (hashcat_ctx_t *hashcat_ctx)
{
  cpt_ctx_t *cpt_ctx = hashcat_ctx->cpt_ctx;

  if (cpt_ctx->enabled == false) return;

  memset (cpt_ctx->cpt_buf, 0, CPT_SECONDS * sizeof (cpt_t));

  memset (cpt_ctx->curve_buf, 0, CURVE_SAMPLES * sizeof (curve_point_t));

  cpt_ctx->cpt_total = 0;
  cpt_ctx->cpt_start = time (NULL);

  cpt_ctx->curve_cnt           = 0;
  cpt_ctx->curve_never         = 0;
  cpt_ctx->curve_total         = 0;
  cpt_ctx->curve_inter         = 0;
  cpt_ctx->curve_slope         = 0;
  cpt_ctx->curve_have          = false;
  cpt_ctx->curve_s             = 0;
  cpt_ctx->curve_xbar          = 0;
  cpt_ctx->curve_sxx           = 0;
  cpt_ctx->curve_n             = 0;
  cpt_ctx->curve_never_lo      = 0;
  cpt_ctx->curve_never_hi      = 0;
}
