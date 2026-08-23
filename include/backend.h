/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_BACKEND_H
#define HC_BACKEND_H

#include <stdio.h>
#include <errno.h>

static const char CL_VENDOR_AMD1[]              = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD2[]              = "AuthenticAMD";
static const char CL_VENDOR_AMD_USE_INTEL[]     = "GenuineIntel";
static const char CL_VENDOR_APPLE[]             = "Apple";
static const char CL_VENDOR_APPLE_USE_AMD[]     = "AMD";
static const char CL_VENDOR_APPLE_USE_NV[]      = "NVIDIA";
static const char CL_VENDOR_APPLE_USE_INTEL[]   = "Intel";
static const char CL_VENDOR_APPLE_USE_INTEL2[]  = "Intel Inc.";
static const char CL_VENDOR_INTEL_BEIGNET[]     = "Intel";
static const char CL_VENDOR_INTEL_SDK[]         = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]              = "Mesa";
static const char CL_VENDOR_NV[]                = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]              = "The pocl project";
static const char CL_VENDOR_MICROSOFT[]         = "Microsoft";

int  backend_ctx_init                       (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_destroy                    (hashcat_ctx_t *hashcat_ctx);

int  backend_ctx_devices_init               (hashcat_ctx_t *hashcat_ctx, const int comptime);
void backend_ctx_devices_destroy            (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_devices_sync_tuning        (hashcat_ctx_t *hashcat_ctx);
bool backend_ctx_devices_tuning_restore     (hashcat_ctx_t *hashcat_ctx);

// Presentation groups. A group is devices that are the same kind of thing, reported as one line. It
// exists for the status view only: work is fed, tuned and failed per DEVICE. See the comment on
// backend_ctx_devices_group.

void backend_ctx_devices_group              (hashcat_ctx_t *hashcat_ctx);
bool backend_ctx_device_is_group_leader     (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx);
int  backend_ctx_device_group_size          (const hashcat_ctx_t *hashcat_ctx, const int backend_devices_idx, int *last_idx);
void backend_ctx_devices_update_power       (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_devices_kernel_loops       (hashcat_ctx_t *hashcat_ctx);

void backend_session_context_reset          (hashcat_ctx_t *hashcat_ctx);
int  backend_session_begin                  (hashcat_ctx_t *hashcat_ctx);
void backend_session_destroy                (hashcat_ctx_t *hashcat_ctx);
void backend_session_reset                  (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_combinator      (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_mp              (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_mp_rl           (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r);

void generate_source_kernel_filename        (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *shared_dir, char *source_file);
void generate_cached_kernel_filename        (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *cache_dir, const char *device_name_chksum, char *cached_file, bool is_metal);
void generate_source_kernel_shared_filename (char *shared_dir, char *source_file);
void generate_cached_kernel_shared_filename (char *cache_dir, const char *device_name_chksum, char *cached_file, bool is_metal);
void generate_source_kernel_mp_filename     (const u32 opti_type, const u64 opts_type, char *shared_dir, char *source_file);
void generate_cached_kernel_mp_filename     (const u32 opti_type, const u64 opts_type, char *cache_dir, const char *device_name_chksum, char *cached_file, bool is_metal);
void generate_source_kernel_amp_filename    (const u32 attack_kern, char *shared_dir, char *source_file);
void generate_cached_kernel_amp_filename    (const u32 attack_kern, char *cache_dir, const char *device_name_chksum, char *cached_file, bool is_metal);

bool read_kernel_binary (hashcat_ctx_t *hashcat_ctx, const char *kernel_file, size_t *kernel_lengths, char **kernel_sources);

// Where a launch's wall clock goes, split by the stage that spent it. A launch is a chain of host
// steps around one device step, and the steps live in different files, so the buckets are global and
// printed together. HASHCAT_PIPE=1 turns it on, and nothing is measured or timed otherwise.

typedef enum pipe_slot
{
  PIPE_FEED   = 0,  // building the candidate batch on the host, off the critical path
  PIPE_COPY   = 1,  // uploading it and running the decompress kernel
  PIPE_INIT   = 2,  // amplifier, utf16 conversion and the init kernel
  PIPE_XFER   = 3,  // tmps out to the host and back
  PIPE_LAUNCH = 4,  // the loop itself, kernel or bridge
  PIPE_COMP   = 5,  // the comp kernel

  PIPE_SLOTS  = 6,

} pipe_slot_t;

void pipe_mark                              (hc_timer_t *timer);
void pipe_acc                               (const pipe_slot_t slot, hc_timer_t *timer);
void pipe_launch_done                       (const u64 cands);

int gidd_to_pw_t                            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

int copy_pws_idx                            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u64 gidd, const u64 cnt, pw_idx_t *dest);
int copy_pws_comp                           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, u32 off, u32 cnt, u32 *dest);

int choose_kernel                           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u64 pws_pos, const u64 pws_cnt, const u32 fast_iteration, const u32 salt_pos, const bool is_autotune);

int run_cuda_kernel_atinit                  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num);
int run_cuda_kernel_utf8toutf16le           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num);
int run_cuda_kernel_memset                  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u8  value, const u64 size);
int run_cuda_kernel_memset32                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u32 value, const u64 size);
int run_cuda_kernel_bzero                   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 size);

int run_hip_kernel_atinit                   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num);
int run_hip_kernel_utf8toutf16le            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num);
int run_hip_kernel_memset                   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u8  value, const u64 size);
int run_hip_kernel_memset32                 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u32 value, const u64 size);
int run_hip_kernel_bzero                    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 size);

#if defined (__APPLE__)
int run_metal_kernel_atinit                 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem_t buf, const u64 num);
int run_metal_kernel_utf8toutf16le          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem_t buf, const u64 num);
int run_metal_kernel_memset                 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem_t buf, const u64 offset, const u8  value, const u64 size);
int run_metal_kernel_memset32               (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem_t buf, const u64 offset, const u32 value, const u64 size);
int run_metal_kernel_bzero                  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, mtl_mem_t buf, const u64 size);
#endif

int run_opencl_kernel_atinit                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_opencl_kernel_utf8toutf16le         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_opencl_kernel_memset                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u8  value, const u64 size);
int run_opencl_kernel_memset32              (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u32 value, const u64 size);
int run_opencl_kernel_bzero                 (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size);

int run_kernel                              (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 pws_pos, const u64 num, const u32 event_update, const u32 iteration, const bool is_autotune);
int run_bridge_loop                         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 salt_pos, const u64 pws_cnt, const u32 loop_pos, const u32 loop_cnt, const u32 event_update);
int run_kernel_mp                           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num);
int run_kernel_tm                           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_kernel_amp                          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_kernel_decompress                   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_copy                                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);
int pcfg_seed_cells                         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_cracker                             (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_pos, const u64 pws_cnt);

#if defined (_WIN32) || defined (__WIN32__)
HC_API_CALL DWORD hook12_thread (void *p);
HC_API_CALL DWORD hook23_thread (void *p);
#else
HC_API_CALL void *hook12_thread (void *p);
HC_API_CALL void *hook23_thread (void *p);
#endif

#endif // HC_BACKEND_H
