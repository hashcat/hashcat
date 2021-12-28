/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _BACKEND_H
#define _BACKEND_H

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

int  cuda_init    (hashcat_ctx_t *hashcat_ctx);
void cuda_close   (hashcat_ctx_t *hashcat_ctx);

int  hip_init     (hashcat_ctx_t *hashcat_ctx);
void hip_close    (hashcat_ctx_t *hashcat_ctx);

int  nvrtc_init   (hashcat_ctx_t *hashcat_ctx);
void nvrtc_close  (hashcat_ctx_t *hashcat_ctx);

int  hiprtc_init  (hashcat_ctx_t *hashcat_ctx);
void hiprtc_close (hashcat_ctx_t *hashcat_ctx);

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
int hc_cuMemcpyDtoDAsync         (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
int hc_cuMemcpyDtoHAsync         (hashcat_ctx_t *hashcat_ctx, void *dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
int hc_cuMemcpyHtoDAsync         (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount, CUstream hStream);
int hc_cuMemFree                 (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dptr);
int hc_cuMemsetD32Async          (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, unsigned int ui, size_t N, CUstream hStream);
int hc_cuMemsetD8Async           (hashcat_ctx_t *hashcat_ctx, CUdeviceptr dstDevice, unsigned char uc, size_t N, CUstream hStream);
int hc_cuModuleGetFunction       (hashcat_ctx_t *hashcat_ctx, CUfunction *hfunc, CUmodule hmod, const char *name);
int hc_cuModuleLoadDataEx        (hashcat_ctx_t *hashcat_ctx, CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues);
int hc_cuModuleUnload            (hashcat_ctx_t *hashcat_ctx, CUmodule hmod);
int hc_cuStreamCreate            (hashcat_ctx_t *hashcat_ctx, CUstream *phStream, unsigned int Flags);
int hc_cuStreamDestroy           (hashcat_ctx_t *hashcat_ctx, CUstream hStream);
int hc_cuStreamSynchronize       (hashcat_ctx_t *hashcat_ctx, CUstream hStream);
int hc_cuCtxPushCurrent          (hashcat_ctx_t *hashcat_ctx, CUcontext ctx);
int hc_cuCtxPopCurrent           (hashcat_ctx_t *hashcat_ctx, CUcontext *pctx);
int hc_cuLinkCreate              (hashcat_ctx_t *hashcat_ctx, unsigned int numOptions, CUjit_option *options, void **optionValues, CUlinkState *stateOut);
int hc_cuLinkAddData             (hashcat_ctx_t *hashcat_ctx, CUlinkState state, CUjitInputType type, void *data, size_t size, const char *name, unsigned int numOptions, CUjit_option *options, void **optionValues);
int hc_cuLinkDestroy             (hashcat_ctx_t *hashcat_ctx, CUlinkState state);
int hc_cuLinkComplete            (hashcat_ctx_t *hashcat_ctx, CUlinkState state, void **cubinOut, size_t *sizeOut);

int hc_hipCreateProgram          (hashcat_ctx_t *hashcat_ctx, hiprtcProgram *prog, const char *src, const char *name, int numHeaders, const char * const *headers, const char * const *includeNames);
int hc_hipDestroyProgram         (hashcat_ctx_t *hashcat_ctx, hiprtcProgram *prog);
int hc_hipCompileProgram         (hashcat_ctx_t *hashcat_ctx, hiprtcProgram prog, int numOptions, const char * const *options);
int hc_hipGetProgramLogSize      (hashcat_ctx_t *hashcat_ctx, hiprtcProgram prog, size_t *logSizeRet);
int hc_hipGetProgramLog          (hashcat_ctx_t *hashcat_ctx, hiprtcProgram prog, char *log);
int hc_hipGetCodeSize            (hashcat_ctx_t *hashcat_ctx, hiprtcProgram prog, size_t *codeSizeRet);
int hc_hipGetCode                (hashcat_ctx_t *hashcat_ctx, hiprtcProgram prog, char *code);

int hc_hipCtxCreate              (hashcat_ctx_t *hashcat_ctx, hipCtx_t *pctx, unsigned int flags, hipDevice_t dev);
int hc_hipCtxDestroy             (hashcat_ctx_t *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxPopCurrent          (hashcat_ctx_t *hashcat_ctx, hipCtx_t *pctx);
int hc_hipCtxPushCurrent         (hashcat_ctx_t *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxSetCurrent          (hashcat_ctx_t *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxSynchronize         (hashcat_ctx_t *hashcat_ctx);
int hc_hipDeviceGet              (hashcat_ctx_t *hashcat_ctx, hipDevice_t *device, int ordinal);
int hc_hipDeviceGetAttribute     (hashcat_ctx_t *hashcat_ctx, int *pi, hipDeviceAttribute_t attrib, hipDevice_t dev);
int hc_hipDeviceGetCount         (hashcat_ctx_t *hashcat_ctx, int *count);
int hc_hipDeviceGetName          (hashcat_ctx_t *hashcat_ctx, char *name, int len, hipDevice_t dev);
int hc_hipDeviceTotalMem         (hashcat_ctx_t *hashcat_ctx, size_t *bytes, hipDevice_t dev);
int hc_hipDriverGetVersion       (hashcat_ctx_t *hashcat_ctx, int *driverVersion);
int hc_hipEventCreate            (hashcat_ctx_t *hashcat_ctx, hipEvent_t *phEvent, unsigned int Flags);
int hc_hipEventDestroy           (hashcat_ctx_t *hashcat_ctx, hipEvent_t hEvent);
int hc_hipEventElapsedTime       (hashcat_ctx_t *hashcat_ctx, float *pMilliseconds, hipEvent_t hStart, hipEvent_t hEnd);
int hc_hipEventQuery             (hashcat_ctx_t *hashcat_ctx, hipEvent_t hEvent);
int hc_hipEventRecord            (hashcat_ctx_t *hashcat_ctx, hipEvent_t hEvent, hipStream_t hStream);
int hc_hipEventSynchronize       (hashcat_ctx_t *hashcat_ctx, hipEvent_t hEvent);
int hc_hipFuncGetAttribute       (hashcat_ctx_t *hashcat_ctx, int *pi, hipFunction_attribute attrib, hipFunction_t hfunc);
int hc_hipInit                   (hashcat_ctx_t *hashcat_ctx, unsigned int Flags);
int hc_hipLaunchKernel           (hashcat_ctx_t *hashcat_ctx, hipFunction_t f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, hipStream_t hStream, void **kernelParams, void **extra);
int hc_hipMemAlloc               (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t *dptr, size_t bytesize);
int hc_hipMemFree                (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t dptr);
int hc_hipMemcpyDtoDAsync        (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t dstDevice, hipDeviceptr_t srcDevice, size_t ByteCount, hipStream_t hStream);
int hc_hipMemcpyDtoHAsync        (hashcat_ctx_t *hashcat_ctx, void *dstHost, hipDeviceptr_t srcDevice, size_t ByteCount, hipStream_t hStream);
int hc_hipMemcpyHtoDAsync        (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t dstDevice, const void *srcHost, size_t ByteCount, hipStream_t hStream);
int hc_hipMemsetD32Async         (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t dstDevice, unsigned int ui, size_t N, hipStream_t hStream);
int hc_hipMemsetD8Async          (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t dstDevice, unsigned char uc, size_t N, hipStream_t hStream);
int hc_hipModuleGetFunction      (hashcat_ctx_t *hashcat_ctx, hipFunction_t *hfunc, hipModule_t hmod, const char *name);
int hc_hipModuleGetGlobal        (hashcat_ctx_t *hashcat_ctx, hipDeviceptr_t *dptr, size_t *bytes, hipModule_t hmod, const char *name);
int hc_hipModuleLoadDataEx       (hashcat_ctx_t *hashcat_ctx, hipModule_t *module, const void *image, unsigned int numOptions, hipJitOption *options, void **optionValues);
int hc_hipModuleUnload           (hashcat_ctx_t *hashcat_ctx, hipModule_t hmod);
int hc_hipRuntimeGetVersion      (hashcat_ctx_t *hashcat_ctx, int *runtimeVersion);
int hc_hipStreamCreate           (hashcat_ctx_t *hashcat_ctx, hipStream_t *phStream, unsigned int Flags);
int hc_hipStreamDestroy          (hashcat_ctx_t *hashcat_ctx, hipStream_t hStream);
int hc_hipStreamSynchronize      (hashcat_ctx_t *hashcat_ctx, hipStream_t hStream);

int gidd_to_pw_t (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 gidd, pw_t *pw);

int choose_kernel (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 highest_pw_len, const u64 pws_pos, const u64 pws_cnt, const u32 fast_iteration, const u32 salt_pos);

int run_cuda_kernel_atinit          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num);
int run_cuda_kernel_utf8toutf16le   (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 num);
int run_cuda_kernel_memset          (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u8  value, const u64 size);
int run_cuda_kernel_memset32        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 offset, const u32 value, const u64 size);
int run_cuda_kernel_bzero           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, CUdeviceptr buf, const u64 size);

int run_hip_kernel_atinit           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num);
int run_hip_kernel_utf8toutf16le    (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 num);
int run_hip_kernel_memset           (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u8  value, const u64 size);
int run_hip_kernel_memset32         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 offset, const u32 value, const u64 size);
int run_hip_kernel_bzero            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, hipDeviceptr_t buf, const u64 size);

int run_opencl_kernel_atinit        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_opencl_kernel_utf8toutf16le (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 num);
int run_opencl_kernel_memset        (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u8  value, const u64 size);
int run_opencl_kernel_memset32      (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 offset, const u32 value, const u64 size);
int run_opencl_kernel_bzero         (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, cl_mem buf, const u64 size);

int run_kernel                (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 pws_pos, const u64 num, const u32 event_update, const u32 iteration);
int run_kernel_mp             (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u32 kern_run, const u64 num);
int run_kernel_tm             (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param);
int run_kernel_amp            (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_kernel_decompress     (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 num);
int run_copy                  (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_cnt);
int run_cracker               (hashcat_ctx_t *hashcat_ctx, hc_device_param_t *device_param, const u64 pws_pos, const u64 pws_cnt);

void generate_source_kernel_filename        (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *shared_dir, char *source_file);
void generate_cached_kernel_filename        (const bool slow_candidates, const u32 attack_exec, const u32 attack_kern, const u32 kern_type, const u32 opti_type, char *cache_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_shared_filename (char *shared_dir, char *source_file);
void generate_cached_kernel_shared_filename (char *cache_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_mp_filename     (const u32 opti_type, const u64 opts_type, char *shared_dir, char *source_file);
void generate_cached_kernel_mp_filename     (const u32 opti_type, const u64 opts_type, char *cache_dir, const char *device_name_chksum, char *cached_file);
void generate_source_kernel_amp_filename    (const u32 attack_kern, char *shared_dir, char *source_file);
void generate_cached_kernel_amp_filename    (const u32 attack_kern, char *cache_dir, const char *device_name_chksum, char *cached_file);

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

void *hook12_thread (void *p);
void *hook23_thread (void *p);

#endif // _BACKEND_H
