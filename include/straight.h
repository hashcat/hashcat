/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STRAIGHT_H
#define _STRAIGHT_H

#include <string.h>

int  straight_ctx_init     (straight_ctx_t *straight_ctx, const user_options_t *user_options);
void straight_ctx_destroy  (straight_ctx_t *straight_ctx);

#endif // _STRAIGHT_H
