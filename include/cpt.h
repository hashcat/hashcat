/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPT_H
#define _CPT_H

#include <stdio.h>
#include <errno.h>
#include <time.h>

int  cpt_ctx_init    (cpt_ctx_t *cpt_ctx, const user_options_t *user_options);
void cpt_ctx_destroy (cpt_ctx_t *cpt_ctx);
void cpt_ctx_reset   (cpt_ctx_t *cpt_ctx);

#endif // _CPT_H
