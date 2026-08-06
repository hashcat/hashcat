/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_PCFG_BACKEND_H
#define HC_PCFG_BACKEND_H

#include "pcfg_common.h"

// filename generators
void generate_source_kernel_pcfg_gpu_prob_filename (char *shared_dir, char *source_file);
void generate_cached_kernel_pcfg_gpu_prob_filename (u32 opti_type, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal);
void generate_source_kernel_pcfg_gpu_omen_filename (char *shared_dir, char *source_file);
void generate_cached_kernel_pcfg_gpu_omen_filename (u32 opti_type, char *cache_dir, const char *device_name_chksum_amp_mp, char *cached_file, bool is_metal);

// GPU data transfer
int gidd_to_pw_t_pcfg                              (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

// kernel runners
int run_kernel_pcfg_gpu_prob                       (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 base_off, const u32 struct_cnt, const u64 pws_cnt);
int run_kernel_pcfg_gpu_omen                       (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 base_off, const u32 batch_entry_cnt, const u64 pws_cnt, const u32 num_devices);

// session init
int backend_session_pcfg_gpu_prob_init             (hashcat_ctx_t *hashcat_ctx);
int backend_session_pcfg_gpu_omen_init             (hashcat_ctx_t *hashcat_ctx);
int backend_session_pcfg_gpu_omen_runtime_init     (hashcat_ctx_t *hashcat_ctx);

// kernel setup
int backend_session_setup_cuda_kernel_pcfg         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int backend_session_setup_hip_kernel_pcfg          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
#if defined (__APPLE__)
int backend_session_setup_metal_kernel_pcfg        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
#endif
int backend_session_setup_opencl_kernel_pcfg       (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int backend_session_setup_cuda_kernel_pcfg_omen    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int backend_session_setup_hip_kernel_pcfg_omen     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
#if defined (__APPLE__)
int backend_session_setup_metal_kernel_pcfg_omen   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
#endif
int backend_session_setup_opencl_kernel_pcfg_omen  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);

#endif // HC_PCFG_BACKEND_H
