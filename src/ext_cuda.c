/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#include <ext_cuda.h>

void hc_cuDeviceGetCount (int *count)
{
  CUresult CU_err = cuDeviceGetCount (count);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceGetCount()", CU_err);

    exit (-1);
  }
}

void hc_cuDeviceGet (CUdevice *device, int ordinal)
{
  CUresult CU_err = cuDeviceGet (device, ordinal);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceGet()", CU_err);

    exit (-1);
  }
}

void hc_cuDeviceGetName (char *name, int len, CUdevice dev)
{
  CUresult CU_err = cuDeviceGetName (name, len, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceGetName()", CU_err);

    exit (-1);
  }
}

void hc_cuDeviceTotalMem (size_t *bytes, CUdevice dev)
{
  CUresult CU_err = cuDeviceTotalMem (bytes, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceTotalMem()", CU_err);

    exit (-1);
  }
}

void hc_cuDeviceGetAttribute (int *pi, CUdevice_attribute attrib, CUdevice dev)
{
  CUresult CU_err = cuDeviceGetAttribute (pi, attrib, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceGetAttribute()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxCreate (CUcontext *pctx, unsigned int flags, CUdevice dev)
{
  CUresult CU_err = cuCtxCreate (pctx, flags, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxCreate()", CU_err);

    exit (-1);
  }
}

void hc_cuMemAllocHost (void **pp, size_t bytesize)
{
  CUresult CU_err = cuMemAllocHost (pp, bytesize);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemAllocHost()", CU_err);

    exit (-1);
  }
}

void hc_cuMemAlloc (CUdeviceptr *dptr, size_t bytesize)
{
  CUresult CU_err = cuMemAlloc (dptr, bytesize);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemAlloc()", CU_err);

    exit (-1);
  }
}

void hc_cuMemsetD8 (CUdeviceptr dstDevice, unsigned char uc, unsigned int N)
{
  CUresult CU_err = cuMemsetD8 (dstDevice, uc, N);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemsetD8()", CU_err);

    exit (-1);
  }
}

void hc_cuMemsetD32 (CUdeviceptr dstDevice, unsigned int ui, unsigned int N)
{
  CUresult CU_err = cuMemsetD32 (dstDevice, ui, N);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemsetD32()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyDtoD (CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount)
{
  CUresult CU_err = cuMemcpyDtoD (dstDevice, srcDevice, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyDtoD()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyDtoDAsync (CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream)
{
  CUresult CU_err = cuMemcpyDtoDAsync (dstDevice, srcDevice, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyDtoDAsync()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyHtoD (CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount)
{
  CUresult CU_err = cuMemcpyHtoD (dstDevice, srcHost, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyHtoD()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyHtoDAsync (CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount, CUstream hStream)
{
  CUresult CU_err = cuMemcpyHtoDAsync (dstDevice, srcHost, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyHtoDAsync()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyDtoH (void *dstHost, CUdeviceptr srcDevice, size_t ByteCount)
{
  CUresult CU_err = cuMemcpyDtoH (dstHost, srcDevice, ByteCount);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyDtoH()", CU_err);

    exit (-1);
  }
}

void hc_cuMemcpyDtoHAsync (void *dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream)
{
  CUresult CU_err = cuMemcpyDtoHAsync (dstHost, srcDevice, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemcpyDtoHAsync()", CU_err);

    exit (-1);
  }
}

void hc_cuEventCreate (CUevent *phEvent, unsigned int Flags)
{
  CUresult CU_err = cuEventCreate (phEvent, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuEventCreate()", CU_err);

    exit (-1);
  }
}

void hc_cuStreamCreate (CUstream *phStream, unsigned int Flags)
{
  CUresult CU_err = cuStreamCreate (phStream, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuStreamCreate()", CU_err);

    exit (-1);
  }
}

void hc_cuDeviceComputeCapability (int *major, int *minor, CUdevice dev)
{
  CUresult CU_err = cuDeviceComputeCapability (major, minor, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDeviceComputeCapability()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleLoad (CUmodule *module, const char *fname)
{
  CUresult CU_err = cuModuleLoad (module, fname);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleLoad()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleLoadData (CUmodule *module, const void *image)
{
  CUresult CU_err = cuModuleLoadData (module, image);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleLoadData()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleGetFunction (CUfunction *hfunc, CUmodule hmod, const char *name)
{
  CUresult CU_err = cuModuleGetFunction (hfunc, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleGetFunction()", CU_err);

    exit (-1);
  }
}

void hc_cuFuncSetBlockShape (CUfunction hfunc, int x, int y, int z)
{
  CUresult CU_err = cuFuncSetBlockShape (hfunc, x, y, z);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuFuncSetBlockShape()", CU_err);

    exit (-1);
  }
}

void hc_cuParamSetSize (CUfunction hfunc, unsigned int numbytes)
{
  CUresult CU_err = cuParamSetSize (hfunc, numbytes);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuParamSetSize()", CU_err);

    exit (-1);
  }
}

void hc_cuParamSetv (CUfunction hfunc, int offset, void *ptr, unsigned int numbytes)
{
  CUresult CU_err = cuParamSetv (hfunc, offset, ptr, numbytes);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuParamSetv()", CU_err);

    exit (-1);
  }
}

void hc_cuParamSeti (CUfunction hfunc, int offset, unsigned int value)
{
  CUresult CU_err = cuParamSeti (hfunc, offset, value);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuParamSeti()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleGetGlobal (CUdeviceptr *dptr, size_t *bytes, CUmodule hmod, const char *name)
{
  CUresult CU_err = cuModuleGetGlobal (dptr, bytes, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleGetGlobal()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxPopCurrent (CUcontext *pctx)
{
  CUresult CU_err = cuCtxPopCurrent (pctx);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxPopCurrent()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxPushCurrent (CUcontext ctx)
{
  CUresult CU_err = cuCtxPushCurrent (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxPushCurrent()", CU_err);

    exit (-1);
  }
}

void hc_cuLaunchKernel (CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra)
{
  CUresult CU_err = cuLaunchKernel (f, gridDimX, gridDimY, gridDimZ, blockDimX, blockDimY, blockDimZ, sharedMemBytes, hStream, kernelParams, extra);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuLaunchKernel()", CU_err);

    exit (-1);
  }
}

void hc_cuLaunchGrid (CUfunction f, int grid_width, int grid_height)
{
  CUresult CU_err = cuLaunchGrid (f, grid_width, grid_height);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuLaunchGrid()", CU_err);

    exit (-1);
  }
}

void hc_cuLaunchGridAsync (CUfunction f, int grid_width, int grid_height, CUstream hStream)
{
  CUresult CU_err = cuLaunchGridAsync (f, grid_width, grid_height, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuLaunchGridAsync()", CU_err);

    exit (-1);
  }
}

void hc_cuEventSynchronize (CUevent hEvent)
{
  CUresult CU_err = cuEventSynchronize (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuEventSynchronize()", CU_err);

    exit (-1);
  }
}

void hc_cuStreamSynchronize (CUstream hStream)
{
  CUresult CU_err = cuStreamSynchronize (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuStreamSynchronize()", CU_err);

    exit (-1);
  }
}

void hc_cuMemFreeHost (void *p)
{
  CUresult CU_err = cuMemFreeHost (p);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemFreeHost()", CU_err);

    exit (-1);
  }
}

void hc_cuMemFree (CUdeviceptr dptr)
{
  CUresult CU_err = cuMemFree (dptr);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuMemFree()", CU_err);

    exit (-1);
  }
}

void hc_cuEventDestroy (CUevent hEvent)
{
  CUresult CU_err = cuEventDestroy (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuEventDestroy()", CU_err);

    exit (-1);
  }
}

void hc_cuStreamDestroy (CUstream hStream)
{
  CUresult CU_err = cuStreamDestroy (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuStreamDestroy()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleUnload (CUmodule hmod)
{
  CUresult CU_err = cuModuleUnload (hmod);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleUnload()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxDestroy (CUcontext ctx)
{
  CUresult CU_err = cuCtxDestroy (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxDestroy()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxAttach (CUcontext *pctx, unsigned int flags)
{
  CUresult CU_err = cuCtxAttach (pctx, flags);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxAttach()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxDetach (CUcontext ctx)
{
  CUresult CU_err = cuCtxDetach (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxDetach()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxSynchronize (void)
{
  CUresult CU_err = cuCtxSynchronize ();

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxSynchronize()", CU_err);

    exit (-1);
  }
}

void hc_cuCtxSetCacheConfig (CUfunc_cache config)
{
  CUresult CU_err = cuCtxSetCacheConfig (config);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuCtxSetCacheConfig()", CU_err);

    exit (-1);
  }
}

void hc_cuDriverGetVersion (int *driverVersion)
{
  CUresult CU_err = cuDriverGetVersion (driverVersion);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuDriverGetVersion()", CU_err);

    exit (-1);
  }
}

void hc_cuModuleLoadDataEx (CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues)
{
  CUresult CU_err = cuModuleLoadDataEx (module, image, numOptions, options, optionValues);

  if (CU_err != CUDA_SUCCESS)
  {
    log_error ("ERROR: %s %d\n", "cuModuleLoadDataEx()", CU_err);

    exit (-1);
  }
}
