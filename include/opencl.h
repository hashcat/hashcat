/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OPENCL_H
#define _OPENCL_H

#include <stdio.h>
#include <errno.h>

#define KERNEL_ACCEL            0
#define KERNEL_LOOPS            0
#define KERNEL_RULES            1024
#define KERNEL_COMBS            1024
#define KERNEL_BFS              1024
#define KERNEL_THREADS_MAX      256
#define KERNEL_THREADS_MAX_CPU  1
#define WORKLOAD_PROFILE        2
#define SCRYPT_TMTO             0
#define NVIDIA_SPIN_DAMP        100

static const char CL_VENDOR_AMD[]           = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[]         = "Apple";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[]     = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]          = "Mesa";
static const char CL_VENDOR_NV[]            = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]          = "The pocl project";

typedef enum vendor_id
{
  VENDOR_ID_AMD           = (1 << 0),
  VENDOR_ID_APPLE         = (1 << 1),
  VENDOR_ID_INTEL_BEIGNET = (1 << 2),
  VENDOR_ID_INTEL_SDK     = (1 << 3),
  VENDOR_ID_MESA          = (1 << 4),
  VENDOR_ID_NV            = (1 << 5),
  VENDOR_ID_POCL          = (1 << 6),
  VENDOR_ID_AMD_USE_INTEL = (1 << 7),
  VENDOR_ID_GENERIC       = (1 << 31)

} vendor_id_t;

void load_kernel (const char *kernel_file, int num_devices, size_t *kernel_lengths, const u8 **kernel_sources);
void writeProgramBin (char *dst, u8 *binary, size_t binary_size);

int gidd_to_pw_t (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

int choose_kernel (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint attack_exec, const uint attack_mode, const uint opts_type, const salt_t *salt_buf, const uint highest_pw_len, const uint pws_cnt, const uint fast_iteration);
int run_kernel (const uint kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num, const uint event_update, const uint iteration, hashconfig_t *hashconfig);
int run_kernel_mp (const uint kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num);
int run_kernel_tm (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param);
int run_kernel_amp (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const uint num);
int run_kernel_memset (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const uint value, const uint num);
int run_kernel_bzero (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const size_t size);

int run_copy (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const uint pws_cnt);

int run_cracker (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, hashes_t *hashes, const uint pws_cnt);

int opencl_ctx_init (opencl_ctx_t *opencl_ctx, const char *opencl_platforms, const char *opencl_devices, const char *opencl_device_types, const uint opencl_vector_width, const uint opencl_vector_width_chgd, const uint nvidia_spin_damp, const uint nvidia_spin_damp_chgd, const uint workload_profile, const uint kernel_accel, const uint kernel_accel_chgd, const uint kernel_loops, const uint kernel_loops_chgd, const uint keyspace, const uint stdout_flag);
void opencl_ctx_destroy (opencl_ctx_t *opencl_ctx);

int opencl_ctx_devices_init (opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig, const tuning_db_t *tuning_db, const uint attack_mode, const bool quiet, const bool force, const bool benchmark, const bool machine_readable, const uint algorithm_pos);
void opencl_ctx_devices_destroy (opencl_ctx_t *opencl_ctx);

int opencl_session_begin (opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig, const hashes_t *hashes, const session_ctx_t *session_ctx);
int opencl_session_destroy (opencl_ctx_t *opencl_ctx);

#endif // _OPENCL_H
