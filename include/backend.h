/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BACKEND_H
#define _BACKEND_H

#include <stdio.h>
#include <errno.h>

static const char CL_VENDOR_AMD1[]            = "Advanced Micro Devices, Inc.";
static const char CL_VENDOR_AMD2[]            = "AuthenticAMD";
static const char CL_VENDOR_AMD_USE_INTEL[]   = "GenuineIntel";
static const char CL_VENDOR_APPLE[]           = "Apple";
static const char CL_VENDOR_APPLE_USE_AMD[]   = "AMD";
static const char CL_VENDOR_APPLE_USE_NV[]    = "NVIDIA";
static const char CL_VENDOR_APPLE_USE_INTEL[] = "Intel Inc.";
static const char CL_VENDOR_INTEL_BEIGNET[]   = "Intel";
static const char CL_VENDOR_INTEL_SDK[]       = "Intel(R) Corporation";
static const char CL_VENDOR_MESA[]            = "Mesa";
static const char CL_VENDOR_NV[]              = "NVIDIA Corporation";
static const char CL_VENDOR_POCL[]            = "The pocl project";

int  cuda_init   (hashcat_ctx_t *hashcat_ctx);
void cuda_close  (hashcat_ctx_t *hashcat_ctx);

int  nvrtc_init  (hashcat_ctx_t *hashcat_ctx);
void nvrtc_close (hashcat_ctx_t *hashcat_ctx);

int  ocl_init    (hashcat_ctx_t *hashcat_ctx);
void ocl_close   (hashcat_ctx_t *hashcat_ctx);

int hc_nvrtcCreateProgram        (hashcat_ctx_t *hashcat_ctx, nvrtcProgram *prog, const char *src, const char *name, int numHeaders, const char * const *headers, const char * const *includeNames);
int hc_nvrtcDestroyProgram       (hashcat_ctx_t *hashcat_ctx, nvrtcProgram *prog);
int hc_nvrtcCompileProgram       (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, int numOptions, const char * const *options);
int hc_nvrtcGetProgramLogSize    (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, size_t *logSizeRet);
int hc_nvrtcGetProgramLog        (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, char *log);
int hc_nvrtcGetPTXSize           (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, size_t *ptxSizeRet);
int hc_nvrtcGetPTX               (hashcat_ctx_t *hashcat_ctx, nvrtcProgram prog, char *ptx);
int hc_nvrtcVersion              (hashcat_ctx_t *hashcat_ctx, int *major, int *minor);

int hc_cuCtxCreate               (hashcat_ctx_t *hashcat_ctx, CUcontext *pctx, unsigned int flags, CUdevice dev);
int hc_cuCtxDestroy              (hashcat_ctx_t *hashcat_ctx, CUcontext ctx);
int hc_cuCtxSetCurrent           (hashcat_ctx_t *hashcat_ctx, CUcontext ctx);
int hc_cuCtxSetCacheConfig       (hashcat_ctx_t *hashcat_ctx, CUfunc_cache config);
int hc_cuCtxSynchronize          (hashcat_ctx_t *hashcat_ctx);
int hc_cuDeviceGetAttribute      (hashcat_ctx_t *hashcat_ctx, int *pi, CUdevice_attribute attrib, CUdevice dev);
int hc_cuDeviceGetCount          (hashcat_ctx_t *hashcat_ctx, int *count);
int hc_cuDeviceGet               (hashcat_ctx_t *hashcat_ctx, CUdevice *device, int ordinal);
int hc_cuDeviceGetName           (hashcat_ctx_t *hashcat_ctx, char *name, int len, CUdevice dev);
int hc_cuDeviceTotalMem          (hashcat_ctx_t *hashcat_ctx, size_t *bytes, CUdevice dev);
int hc_cuDriverGetVersion        (hashcat_ctx_t *hashcat_ctx, int *driverVersion);
int hc_cuEventCreate             (hashcat_ctx_t *hashcat_ctx, CUevent *phEvent, unsigned int Flags);
int hc_cuEventDestroy            (hashcat_ctx_t *hashcat_ctx, CUevent hEvent);
int hc_cuEventElapsedTime        (hashcat_ctx_t *hashcat_ctx, float *pMilliseconds, CUevent hStart, CUevent hEnd);
int hc_cuEventQuery              (hashcat_ctx_t *hashcat_ctx, CUevent hEvent);
int hc_cuEventRecord             (hashcat_ctx_t *hashcat_ctx, CUevent hEvent, CUstream hStream);
int hc_cuEventSynchronize        (hashcat_ctx_t *hashcat_ctx, CUevent hEvent);
int hc_cuFuncGetAttribute        (hashcat_ctx_t *hashcat_ctx, int *pi, CUfunction_attribute attrib, CUfunction hfunc);
int hc_cuFuncSetAttribute        (hashcat_ctx_t *hashcat_ctx, CUfunction hfunc, CUfunction_attribute attrib, int value);
int hc_cuInit                    (hashcat_ctx_t *hashcat_ctx, unsigned int Flags);
int hc_cuLaunchKernel            (hashcat_ctx_t *hashcat_ctx, CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra);
int hc_cuMemAlloc                (hashcat_ctx_t *hashcat_ctx, CUdeviceptr *dptr, size_t bytesize);
int hc_cuMemcpyDtoD              (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount);
int hc_cuMemcpyDtoH              (hashcat_ctx_t *hashcat_ctx, void *dstHost, CUdeviceptr srcDevice, size_t ByteCount);
int hc_cuMemcpyHtoD              (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount);
int hc_cuMemFree                 (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dptr);
int hc_cuModuleGetFunction       (hashcat_ctx_t *hashcat_ctx, CUfunction *hfunc, CUmodule hmod, const char *name);
int hc_cuModuleLoadDataEx        (hashcat_ctx_t *hashcat_ctx, CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues);
int hc_cuModuleLoadDataExLog     (hashcat_ctx_t *hashcat_ctx, CUmodule *module, const void *image);
int hc_cuModuleUnload            (hashcat_ctx_t *hashcat_ctx, CUmodule hmod);
int hc_cuStreamCreate            (hashcat_ctx_t *hashcat_ctx, CUstream *phStream, unsigned int Flags);
int hc_cuStreamDestroy           (hashcat_ctx_t *hashcat_ctx, CUstream hStream);
int hc_cuStreamSynchronize       (hashcat_ctx_t *hashcat_ctx, CUstream hStream);
int hc_cuCtxPushCurrent          (hashcat_ctx_t *hashcat_ctx, CUcontext ctx);
int hc_cuCtxPopCurrent           (hashcat_ctx_t *hashcat_ctx, CUcontext *pctx);

int hc_clBuildProgram            (hashcat_ctx_t *hashcat_ctx, cl_program program, cl_uint num_devices, const cl_device_id *device_list, const char *options, void (CL_CALLBACK *pfn_notify) (cl_program program, void *user_data), void *user_data);
int hc_clCreateBuffer            (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_mem_flags flags, size_t size, void *host_ptr, cl_mem *mem);
int hc_clCreateCommandQueue      (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_device_id device, cl_command_queue_properties properties, cl_command_queue *command_queue);
int hc_clCreateContext           (hashcat_ctx_t *hashcat_ctx, const cl_context_properties *properties, cl_uint num_devices, const cl_device_id *devices, void (CL_CALLBACK *pfn_notify) (const char *errinfo, const void *private_info, size_t cb, void *user_data), void *user_data, cl_context *context);
int hc_clCreateKernel            (hashcat_ctx_t *hashcat_ctx, cl_program program, const char *kernel_name, cl_kernel *kernel);
int hc_clCreateProgramWithBinary (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint num_devices, const cl_device_id *device_list, const size_t *lengths, const unsigned char **binaries, cl_int *binary_status, cl_program *program);
int hc_clCreateProgramWithSource (hashcat_ctx_t *hashcat_ctx, cl_context context, cl_uint count, const char **strings, const size_t *lengths, cl_program *program);
int hc_clEnqueueCopyBuffer       (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem src_buffer, cl_mem dst_buffer, size_t src_offset, size_t dst_offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueMapBuffer        (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_map, cl_map_flags map_flags, size_t offset, size_t size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event, void **buf);
int hc_clEnqueueNDRangeKernel    (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_kernel kernel, cl_uint work_dim, const size_t *global_work_offset, const size_t *global_work_size, const size_t *local_work_size, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueReadBuffer       (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_read, size_t offset, size_t size, void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueUnmapMemObject   (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem memobj, void *mapped_ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
int hc_clEnqueueWriteBuffer      (hashcat_ctx_t *hashcat_ctx, cl_command_queue command_queue, cl_mem buffer, cl_bool blocking_write, size_t offset, size_t size, const void *ptr, cl_uint num_events_in_wait_list, const cl_event *event_wait_list, cl_event *event);
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

int run_cuda_kernel_atinit    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num);
int run_cuda_kernel_memset    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u32 value, const u64 size);
int run_cuda_kernel_bzero     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 size);

int run_opencl_kernel_atinit  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_opencl_kernel_memset  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u32 value, const u64 size);
int run_opencl_kernel_bzero   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size);

int run_kernel                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num, const u32 event_update, const u32 iteration);
int run_kernel_mp             (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num);
int run_kernel_tm             (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_kernel_amp            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_kernel_decompress     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_copy                  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);
int run_cracker               (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);

void generate_source_kernel_filename     (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *shared_dir, char *source_file);
void generate_cached_kernel_filename     (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_mp_filename  (const u32 opti_type, const u64 opts_type, char *shared_dir, char *source_file);
void generate_cached_kernel_mp_filename  (const u32 opti_type, const u64 opts_type, char *profile_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_amp_filename (const u32 attack_kern, char *shared_dir, char *source_file);
void generate_cached_kernel_amp_filename (const u32 attack_kern, char *profile_dir, const char *device_name_chksum, char *cached_file);

int  backend_ctx_init                  (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_destroy               (hashcat_ctx_t *hashcat_ctx);

int  backend_ctx_devices_init          (hashcat_ctx_t *hashcat_ctx, const int comptime);
void backend_ctx_devices_destroy       (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_devices_sync_tuning   (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_devices_update_power  (hashcat_ctx_t *hashcat_ctx);
void backend_ctx_devices_kernel_loops  (hashcat_ctx_t *hashcat_ctx);

int  backend_session_begin             (hashcat_ctx_t *hashcat_ctx);
void backend_session_destroy           (hashcat_ctx_t *hashcat_ctx);
void backend_session_reset             (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_combinator (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_mp         (hashcat_ctx_t *hashcat_ctx);
int  backend_session_update_mp_rl      (hashcat_ctx_t *hashcat_ctx, const u32 css_cnt_l, const u32 css_cnt_r);

#endif // _BACKEND_H
