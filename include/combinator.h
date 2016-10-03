/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _COMBINATOR_H
#define _COMBINATOR_H

#include <stdio.h>
#include <errno.h>

int combinator_ctx_init (combinator_ctx_t *combinator_ctx, user_options_t *user_options, user_options_extra_t *user_options_extra, const straight_ctx_t *straight_ctx, dictstat_ctx_t *dictstat_ctx, wl_data_t *wl_data);
void combinator_ctx_destroy (combinator_ctx_t *combinator_ctx);

#endif // _COMBINATOR_H
