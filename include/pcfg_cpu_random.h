/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_CPU_RANDOM_H
#define HC_PCFG_CPU_RANDOM_H

#include "pcfg_common.h"

// heap
pcfg_heap_t *pcfg_cpu_random_heap_alloc      (u64 cap);
void         pcfg_cpu_random_heap_free       (pcfg_heap_t *h);
int          pcfg_cpu_random_heap_push       (pcfg_heap_t *h, const pcfg_candidate_t *c);

// candidate building
int          pcfg_cpu_random_build_candidate (pcfg_model_t *m, pcfg_structure_t *s, u32 struct_idx, pcfg_candidate_t *out, char *out_buf, u64 *rng_state, u8 ahf_type);

// structure shuffle
void         pcfg_cpu_random_structure_shuffle (pcfg_gen_t *gen, pcfg_structure_t *s);

// AHF reset
int          pcfg_cpu_random_ahf_reset       (pcfg_gen_t *gen);

// gen_next handler (returns 0=ok, -1/-2=done, 2=restart)
int          pcfg_cpu_random_gen_next        (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, char *out, u32 *len);

// skip/restore
void         pcfg_cpu_random_gen_skip        (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *gen, u64 local_skip, u64 restore_skip, int thread_count, int thread_id);

// AHF structure refresh (generates random structures for next batch)
void         pcfg_cpu_random_ahf_refresh     (hashcat_ctx_t *hashcat_ctx, pcfg_gen_t *g);

#endif // HC_PCFG_CPU_RANDOM_H
