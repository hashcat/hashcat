/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _STRAIGHT_H
#define _STRAIGHT_H

#include <string.h>

#define INCR_DICTS 1000

int  straight_ctx_init     (straight_ctx_t *straight_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, hashconfig_t *hashconfig);
void straight_ctx_destroy  (straight_ctx_t *straight_ctx);

void straight_append_dict  (straight_ctx_t *straight_ctx, const char *dict);

#endif // _STRAIGHT_H
