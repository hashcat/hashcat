/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_CPT_H
#define HC_CPT_H

#include <stdio.h>
#include <errno.h>
#include <time.h>

int  cpt_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void cpt_ctx_destroy (hashcat_ctx_t *hashcat_ctx);
void cpt_ctx_reset   (hashcat_ctx_t *hashcat_ctx);

#endif // HC_CPT_H
