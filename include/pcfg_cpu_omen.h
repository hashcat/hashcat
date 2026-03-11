/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_CPU_OMEN_H
#define HC_PCFG_CPU_OMEN_H

#include "pcfg_common.h"

int  pcfg_cpu_omen_by_cost_gen_next          (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len);
int  pcfg_cpu_omen_by_struct_gen_next        (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len);

#endif // HC_PCFG_CPU_OMEN_H
