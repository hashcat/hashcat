/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifndef EXT_CUDA_H
#define EXT_CUDA_H

#include <common.h>

#include <cuda.h>

void hc_cuDeviceGetCount (int *count);
void hc_cuDeviceGet (CUdevice *device, int ordinal);
void hc_cuDeviceGetName (char *name, int len, CUdevice dev);
void hc_cuDeviceTotalMem (size_t *bytes, CUdevice dev);
void hc_cuDeviceGetAttribute (int *pi, CUdevice_attribute attrib, CUdevice dev);
void hc_cuCtxCreate (CUcontext *pctx, unsigned int flags, CUdevice dev);
void hc_cuMemAllocHost (void **pp, size_t bytesize);
void hc_cuMemAlloc (CUdeviceptr *dptr, size_t bytesize);
void hc_cuMemsetD8 (CUdeviceptr dstDevice, unsigned char uc, unsigned int N);
void hc_cuMemsetD32 (CUdeviceptr dstDevice, unsigned int ui, unsigned int N);
void hc_cuMemcpyDtoD (CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount);
void hc_cuMemcpyDtoDAsync (CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
void hc_cuMemcpyHtoD (CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount);
void hc_cuMemcpyHtoDAsync (CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount, CUstream hStream);
void hc_cuMemcpyDtoH (void *dstHost, CUdeviceptr srcDevice, size_t ByteCount);
void hc_cuMemcpyDtoHAsync (void *dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
void hc_cuEventCreate (CUevent *phEvent, unsigned int Flags);
void hc_cuStreamCreate (CUstream *phStream, unsigned int Flags);
void hc_cuDeviceComputeCapability (int *major, int *minor, CUdevice dev);
void hc_cuModuleLoad (CUmodule *module, const char *fname);
void hc_cuModuleLoadData (CUmodule *module, const void *image);
void hc_cuModuleGetFunction (CUfunction *hfunc, CUmodule hmod, const char *name);
void hc_cuFuncSetBlockShape (CUfunction hfunc, int x, int y, int z);
void hc_cuParamSetSize (CUfunction hfunc, unsigned int numbytes);
void hc_cuParamSetv (CUfunction hfunc, int offset, void *ptr, unsigned int numbytes);
void hc_cuParamSeti (CUfunction hfunc, int offset, unsigned int value);
void hc_cuModuleGetGlobal (CUdeviceptr *dptr, size_t *bytes, CUmodule hmod, const char *name);
void hc_cuCtxPopCurrent (CUcontext *pctx);
void hc_cuCtxPushCurrent (CUcontext ctx);
void hc_cuLaunchKernel (CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra);
void hc_cuLaunchGrid (CUfunction f, int grid_width, int grid_height);
void hc_cuLaunchGridAsync (CUfunction f, int grid_width, int grid_height, CUstream hStream);
void hc_cuEventSynchronize (CUevent hEvent);
void hc_cuStreamSynchronize (CUstream hStream);
void hc_cuMemFreeHost (void *p);
void hc_cuMemFree (CUdeviceptr dptr);
void hc_cuEventDestroy (CUevent hEvent);
void hc_cuStreamDestroy (CUstream hStream);
void hc_cuModuleUnload (CUmodule hmod);
void hc_cuCtxDestroy (CUcontext ctx);
void hc_cuCtxAttach (CUcontext *pctx, unsigned int flags);
void hc_cuCtxDetach (CUcontext ctx);
void hc_cuCtxSynchronize (void);
void hc_cuCtxSetCacheConfig (CUfunc_cache config);
void hc_cuDriverGetVersion (int *driverVersion);
void hc_cuModuleLoadDataEx (CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues);
void hc_cuLinkAddFile (CUlinkState state, CUjitInputType type, const char *path, unsigned int numOptions, CUjit_option *options, void **optionValues);
void hc_cuLinkComplete (CUlinkState state, void **cubinOut, size_t *sizeOut);
void hc_cuLinkCreate (unsigned int numOptions, CUjit_option *options, void **optionValues, CUlinkState *stateOut);
void hc_cuLinkDestroy (CUlinkState state);

#endif
