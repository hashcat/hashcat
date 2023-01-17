/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef CPT_H
#define CPT_H

#include <stdio.h>
#include <errno.h>
#include <time.h>

int  cpt_ctx_init    (hashcat_ctx_t *hashcat_ctx);
void cpt_ctx_destroy (hashcat_ctx_t *hashcat_ctx);
void cpt_ctx_reset   (hashcat_ctx_t *hashcat_ctx);

#endif // CPT_H
