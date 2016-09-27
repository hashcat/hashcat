/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _COMBINATOR_H
#define _COMBINATOR_H

#include <stdio.h>
#include <errno.h>

int combinator_ctx_init (combinator_ctx_t *combinator_ctx, const user_options_t *user_options);
void combinator_ctx_destroy (combinator_ctx_t *combinator_ctx);

#endif // _COMBINATOR_H
