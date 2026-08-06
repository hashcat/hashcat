/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_DISPATCH_H
#define HC_PCFG_DISPATCH_H

#include "pcfg_common.h"

int pcfg_gpu_omen_upload_batch        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const pcfg_gpu_omen_batch_entry_t *batch_entries, u64 size_batch_entries, const pcfg_gpu_omen_partition_t *partitions, u64 size_partitions, const pcfg_gpu_omen_structure_t *structures, u64 size_structures);
int backend_session_pcfg_gpu_prob_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int backend_session_pcfg_gpu_omen_run (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int calc_pcfg                         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);

#endif // HC_PCFG_DISPATCH_H
