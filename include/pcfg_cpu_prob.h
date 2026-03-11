/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_CPU_PROB_H
#define HC_PCFG_CPU_PROB_H

#include "pcfg_common.h"

// gen_next handler for PCFG_MODE_CPU_PROB (returns 0=ok, -1=done)
int pcfg_cpu_prob_gen_next        (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len);

#endif // HC_PCFG_CPU_PROB_H
