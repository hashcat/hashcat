/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OPENCL_H
#define _OPENCL_H

#include <stdio.h>
#include <errno.h>

static const char CL_VENDOR_AMD[]           = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[]         = "Apple";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[]     = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]          = "Mesa";
static const char CL_VENDOR_NV[]            = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]          = "The pocl project";

int gidd_to_pw_t (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

int choose_kernel (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const user_options_t *user_options, const straight_ctx_t *straight_ctx, const combinator_ctx_t *combinator_ctx, const mask_ctx_t *mask_ctx, hashconfig_t *hashconfig, const hashes_t *hashes, const outfile_ctx_t *outfile_ctx, status_ctx_t *status_ctx, const u32 highest_pw_len, const u32 pws_cnt, const u32 fast_iteration, const u32 salt_pos);

int run_kernel (const u32 kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u32 num, const u32 event_update, const u32 iteration, hashconfig_t *hashconfig, const user_options_t *user_options, status_ctx_t *status_ctx);
int run_kernel_mp (const u32 kern_run, opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u32 num);
int run_kernel_tm (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param);
int run_kernel_amp (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, const u32 num);
int run_kernel_memset (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u32 num);
int run_kernel_bzero (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, cl_mem buf, const size_t size);

int run_copy (opencl_ctx_t *opencl_ctx, hc_device_param_t *device_param, hashconfig_t *hashconfig, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const combinator_ctx_t *combinator_ctx, const u32 pws_cnt);

int run_cracker (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 pws_cnt);

int  opencl_ctx_init                  (opencl_ctx_t *opencl_ctx, const user_options_t *user_options);
void opencl_ctx_destroy               (opencl_ctx_t *opencl_ctx);

int  opencl_ctx_devices_init          (opencl_ctx_t *opencl_ctx, const user_options_t *user_options, const int comptime);
void opencl_ctx_devices_destroy       (opencl_ctx_t *opencl_ctx);
void opencl_ctx_devices_update_power  (opencl_ctx_t *opencl_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, status_ctx_t *status_ctx);
void opencl_ctx_devices_kernel_loops  (opencl_ctx_t *opencl_ctx, const user_options_extra_t *user_options_extra, const hashconfig_t *hashconfig, const hashes_t *hashes, straight_ctx_t *straight_ctx, combinator_ctx_t *combinator_ctx, mask_ctx_t *mask_ctx);

int  opencl_session_begin             (opencl_ctx_t *opencl_ctx, hashconfig_t *hashconfig, const hashes_t *hashes, const straight_ctx_t *straight_ctx, const user_options_t *user_options, const user_options_extra_t *user_options_extra, const folder_config_t *folder_config, const bitmap_ctx_t *bitmap_ctx, const tuning_db_t *tuning_db);
void opencl_session_destroy           (opencl_ctx_t *opencl_ctx);
void opencl_session_reset             (opencl_ctx_t *opencl_ctx);
int  opencl_session_update_combinator (opencl_ctx_t *opencl_ctx, const hashconfig_t *hashconfig, const combinator_ctx_t *combinator_ctx);
int  opencl_session_update_mp         (opencl_ctx_t *opencl_ctx, const mask_ctx_t *mask_ctx);
int  opencl_session_update_mp_rl      (opencl_ctx_t *opencl_ctx, const mask_ctx_t *mask_ctx, const u32 css_cnt_l, const u32 css_cnt_r);

#endif // _OPENCL_H
