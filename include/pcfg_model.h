/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_MODEL_H
#define HC_PCFG_MODEL_H

#include "pcfg_common.h"

// model I/O
pcfg_model_t *pcfg_model_load_filtered       (hashcat_ctx_t *hashcat_ctx, const char *path);
pcfg_model_t *pcfg_model_load_fast           (hashcat_ctx_t *hashcat_ctx, const char *path);

// model lifecycle
void          pcfg_model_destroy             (pcfg_model_t *m);
void          pcfg_model_free_terminal_data  (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m);
u64           pcfg_model_count_elements      (pcfg_model_t *m);

// model info
void          pcfg_model_info                (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m);
void          pcfg_model_diff                (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *a, pcfg_model_t *b);
int           pcfg_model_merge               (hashcat_ctx_t *hashcat_ctx);

// model calculations
void          pcfg_model_keyspace_update_all (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m);
void          pcfg_model_build_omen_metadata (hashcat_ctx_t *hashcat_ctx, pcfg_model_t *m);

#endif // HC_PCFG_MODEL_H
