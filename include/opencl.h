/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _OPENCL_H
#define _OPENCL_H

#include <stdio.h>
#include <errno.h>

static const char CL_VENDOR_AMD1[]          = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD2[]          = "AuthenticAMD";
static const char CL_VENDOR_AMD_USE_INTEL[] = "GenuineIntel";
static const char CL_VENDOR_APPLE[]         = "Apple";
static const char CL_VENDOR_APPLE_USE_AMD[] = "AMD";
static const char CL_VENDOR_APPLE_USE_NV[]  = "NVIDIA";
static const char CL_VENDOR_INTEL_BEIGNET[] = "Intel";
static const char CL_VENDOR_INTEL_SDK[]     = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]          = "Mesa";
static const char CL_VENDOR_NV[]            = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]          = "The pocl project";

int  ocl_init  (hashcat_ctx_t *hashcat_ctx);
void ocl_close (hashcat_ctx_t *hashcat_ctx);

int hc_clBuildProgram            (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data);
int hc_clCreateBuffer            (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_mem *mem);
int hc_clCreateCommandQueue      (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_command_queue *command_queue);
int hc_clCreateContext           (hashcat_ctx_t *hashcat_ctx, cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *, const void *, size_t, void *), void *user_data, cl_context *context);
int hc_clCreateKernel            (hashcat_ctx_t *hashcat_ctx, cl_program program, const char *kernel_name, cl_kernel *kernel);
int hc_clCreateProgramWithBinary (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, unsigned char **binaries, cl_int *binary_status, cl_program *program);
int hc_clCreateProgramWithSource (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint count, char **strings, const size_t *lengths, cl_program *program);
int hc_clEnqueueCopyBuffer       (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueMapBuffer        (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t cb, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event, void **buf);
int hc_clEnqueueNDRangeKernel    (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueReadBuffer       (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t cb, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueUnmapMemObject   (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueWriteBuffer      (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t cb, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clFinish                  (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue);
int hc_clFlush                   (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue);
int hc_clGetDeviceIDs            (hashcat_ctx_t *hashcat_ctx, cl_platform_id platform, cl_device_type device_type, cl_uint num_entries, cl_device_id *devices, cl_uint *num_devices);
int hc_clGetDeviceInfo           (hashcat_ctx_t *hashcat_ctx, cl_device_id device, cl_device_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetEventInfo            (hashcat_ctx_t *hashcat_ctx, cl_event event, cl_event_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetEventProfilingInfo   (hashcat_ctx_t *hashcat_ctx, cl_event event, cl_profiling_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetKernelWorkGroupInfo  (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel, cl_device_id device, cl_kernel_work_group_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetPlatformIDs          (hashcat_ctx_t *hashcat_ctx, cl_uint num_entries, cl_platform_id *platforms, cl_uint *num_platforms);
int hc_clGetPlatformInfo         (hashcat_ctx_t *hashcat_ctx, cl_platform_id platform, cl_platform_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetProgramBuildInfo     (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_device_id device, cl_program_build_info param_name, size_t param_value_size, void *param_value, size_t *param_value_size_ret);
int hc_clGetProgramInfo          (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_program_info param_name, size_t param_value_size, void *param_value, size_t * param_value_size_ret);
int hc_clReleaseCommandQueue     (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue);
int hc_clReleaseContext          (hashcat_ctx_t *hashcat_ctx, cl_context context);
int hc_clReleaseEvent            (hashcat_ctx_t *hashcat_ctx, cl_event event);
int hc_clReleaseKernel           (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel);
int hc_clReleaseMemObject        (hashcat_ctx_t *hashcat_ctx, cl_mem mem);
int hc_clReleaseProgram          (hashcat_ctx_t *hashcat_ctx, cl_program program);
int hc_clSetKernelArg            (hashcat_ctx_t *hashcat_ctx, cl_kernel kernel, cl_uint arg_index, size_t arg_size, const void *arg_value);
int hc_clWaitForEvents           (hashcat_ctx_t *hashcat_ctx, cl_uint num_events, const cl_event *event_list);

int gidd_to_pw_t (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

int choose_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u64 pws_cnt, const u32 fast_iteration, const u32 salt_pos);

void rebuild_pws_compressed_append (hc_device_param_t *device_param, const u64 pws_cnt, const u8 chr);

int run_kernel            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num, const u32 event_update, const u32 iteration);
int run_kernel_mp         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num);
int run_kernel_tm         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_kernel_amp        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_kernel_atinit     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_kernel_memset     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u64 size);
int run_kernel_bzero      (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size);
int run_kernel_decompress (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_copy              (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);
int run_cracker           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);

void generate_source_kernel_filename     (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *shared_dir, char *source_file);
void generate_cached_kernel_filename     (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_mp_filename  (const u32 opti_type, const u64 opts_type, char *shared_dir, char *source_file);
void generate_cached_kernel_mp_filename  (const u32 opti_type, const u64 opts_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_amp_filename (const u32 attack_kern, char *shared_dir, char *source_file);
void generate_cached_kernel_amp_filename (const u32 attack_kern, char *profile_dir, const char *device_name_chksum, char *cached_file);

int  opencl_ctx_init                  (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_destroy               (hashcat_ctx_t *hashcat_ctx);

int  opencl_ctx_devices_init          (hashcat_ctx_t *hashcat_ctx, const int comptime);
void opencl_ctx_devices_destroy       (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_devices_sync_tuning   (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_devices_update_power  (hashcat_ctx_t *hashcat_ctx);
void opencl_ctx_devices_kernel_loops  (hashcat_ctx_t *hashcat_ctx);

int  opencl_session_begin             (hashcat_ctx_t *hashcat_ctx);
void opencl_session_destroy           (hashcat_ctx_t *hashcat_ctx);
void opencl_session_reset             (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_combinator (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_mp         (hashcat_ctx_t *hashcat_ctx);
int  opencl_session_update_mp_rl      (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r);

#endif // _OPENCL_H
