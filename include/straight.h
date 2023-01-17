/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef STRAIGHT_H
#define STRAIGHT_H

#include <string.h>

#define INCR_DICTS 1000

int  straight_ctx_update_loop (hashcat_ctx_t *hashcat_ctx);
int  straight_ctx_init        (hashcat_ctx_t *hashcat_ctx);
void straight_ctx_destroy     (hashcat_ctx_t *hashcat_ctx);

#endif // STRAIGHT_H
