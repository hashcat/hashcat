/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_COMBINATOR_H
#define HC_COMBINATOR_H

#include <stdio.h>
#include <errno.h>

int  combinator_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void combinator_ctx_destroy (hashcat_ctx_t *hashcat_ctx);

#endif // HC_COMBINATOR_H
