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

int gidd_to_pw_t      (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);
int choose_kernel     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u32 pws_cnt, const u32 fast_iteration, const u32 salt_pos);
int run_kernel        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u32 num, const u32 event_update, const u32 iteration);
int run_kernel_mp     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u32 num);
int run_kernel_tm     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_kernel_amp    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 num);
int run_kernel_memset (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u32 num);
int run_kernel_bzero  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const size_t size);
int run_copy          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 pws_cnt);
int run_cracker       (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 pws_cnt);

int  opencl_ctx_init                  (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_destroy               (hashcat_ctx_t *hashcat_ctx);

int  opencl_ctx_devices_init          (hashcat_ctx_t *hashcat_ctx, const int comptime);
void opencl_ctx_devices_destroy       (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_devices_update_power  (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_devices_kernel_loops  (hashcat_ctx_t *hashcat_ctx);

int  opencl_session_begin             (hashcat_ctx_t *hashcat_ctx);
void opencl_session_destroy           (hashcat_ctx_t *hashcat_ctx);
void opencl_session_reset             (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_combinator (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_mp         (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_mp_rl      (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r);

#endif // _OPENCL_H
