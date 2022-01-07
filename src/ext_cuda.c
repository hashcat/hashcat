/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "common.h"
#include "types.h"
#include "memory.h"
#include "event.h"
#include "ext_cuda.h"

#include "dynloader.h"

int cuda_init (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  memset (cuda, 0, sizeof (CUDA_PTR));

  #if   defined (_WIN)
  cuda->lib = hc_dlopen ("nvcuda.dll");
  #elif defined (__APPLE__)
  cuda->lib = hc_dlopen ("nvcuda.dylib");
  #elif defined (__CYGWIN__)
  cuda->lib = hc_dlopen ("nvcuda.dll");
  #else
  cuda->lib = hc_dlopen ("libcuda.so");

  if (cuda->lib == NULL) cuda->lib = hc_dlopen ("libcuda.so.1");
  #endif

  if (cuda->lib == NULL) return -1;

  #define HC_LOAD_FUNC_CUDA(ptr,name,cudaname,type,libname,noerr) \
    do { \
      ptr->name = (type) hc_dlsym ((ptr)->lib, #cudaname); \
      if ((noerr) != -1) { \
        if (!(ptr)->name) { \
          if ((noerr) == 1) { \
            event_log_error (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
            return -1; \
          } \
          if ((noerr) != 1) { \
            event_log_warning (hashcat_ctx, "%s is missing from %s shared library.", #name, #libname); \
            return 0; \
          } \
        } \
      } \
    } while (0)

  // finding the right symbol is a PITA, because of the _v2 suffix
  // a good reference is cuda.h itself
  // this needs to be verified for each new cuda release

  HC_LOAD_FUNC_CUDA (cuda, cuCtxCreate,              cuCtxCreate_v2,            CUDA_CUCTXCREATE,               CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxDestroy,             cuCtxDestroy_v2,           CUDA_CUCTXDESTROY,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetCacheConfig,      cuCtxGetCacheConfig,       CUDA_CUCTXGETCACHECONFIG,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetCurrent,          cuCtxGetCurrent,           CUDA_CUCTXGETCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxGetSharedMemConfig,  cuCtxGetSharedMemConfig,   CUDA_CUCTXGETSHAREDMEMCONFIG,   CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxPopCurrent,          cuCtxPopCurrent_v2,        CUDA_CUCTXPOPCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxPushCurrent,         cuCtxPushCurrent_v2,       CUDA_CUCTXPUSHCURRENT,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetCacheConfig,      cuCtxSetCacheConfig,       CUDA_CUCTXSETCACHECONFIG,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetCurrent,          cuCtxSetCurrent,           CUDA_CUCTXSETCURRENT,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSetSharedMemConfig,  cuCtxSetSharedMemConfig,   CUDA_CUCTXSETSHAREDMEMCONFIG,   CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuCtxSynchronize,         cuCtxSynchronize,          CUDA_CUCTXSYNCHRONIZE,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetAttribute,     cuDeviceGetAttribute,      CUDA_CUDEVICEGETATTRIBUTE,      CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetCount,         cuDeviceGetCount,          CUDA_CUDEVICEGETCOUNT,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGet,              cuDeviceGet,               CUDA_CUDEVICEGET,               CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceGetName,          cuDeviceGetName,           CUDA_CUDEVICEGETNAME,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDeviceTotalMem,         cuDeviceTotalMem_v2,       CUDA_CUDEVICETOTALMEM,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuDriverGetVersion,       cuDriverGetVersion,        CUDA_CUDRIVERGETVERSION,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventCreate,            cuEventCreate,             CUDA_CUEVENTCREATE,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventDestroy,           cuEventDestroy_v2,         CUDA_CUEVENTDESTROY,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventElapsedTime,       cuEventElapsedTime,        CUDA_CUEVENTELAPSEDTIME,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventQuery,             cuEventQuery,              CUDA_CUEVENTQUERY,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventRecord,            cuEventRecord,             CUDA_CUEVENTRECORD,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuEventSynchronize,       cuEventSynchronize,        CUDA_CUEVENTSYNCHRONIZE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncGetAttribute,       cuFuncGetAttribute,        CUDA_CUFUNCGETATTRIBUTE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetAttribute,       cuFuncSetAttribute,        CUDA_CUFUNCSETATTRIBUTE,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetCacheConfig,     cuFuncSetCacheConfig,      CUDA_CUFUNCSETCACHECONFIG,      CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuFuncSetSharedMemConfig, cuFuncSetSharedMemConfig,  CUDA_CUFUNCSETSHAREDMEMCONFIG,  CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuGetErrorName,           cuGetErrorName,            CUDA_CUGETERRORNAME,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuGetErrorString,         cuGetErrorString,          CUDA_CUGETERRORSTRING,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuInit,                   cuInit,                    CUDA_CUINIT,                    CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuLaunchKernel,           cuLaunchKernel,            CUDA_CULAUNCHKERNEL,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemAlloc,               cuMemAlloc_v2,             CUDA_CUMEMALLOC,                CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemAllocHost,           cuMemAllocHost_v2,         CUDA_CUMEMALLOCHOST,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyDtoDAsync,        cuMemcpyDtoDAsync_v2,      CUDA_CUMEMCPYDTODASYNC,         CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyDtoHAsync,        cuMemcpyDtoHAsync_v2,      CUDA_CUMEMCPYDTOHASYNC,         CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemcpyHtoDAsync,        cuMemcpyHtoDAsync_v2,      CUDA_CUMEMCPYHTODASYNC,         CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemFree,                cuMemFree_v2,              CUDA_CUMEMFREE,                 CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemFreeHost,            cuMemFreeHost,             CUDA_CUMEMFREEHOST,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemGetInfo,             cuMemGetInfo_v2,           CUDA_CUMEMGETINFO,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemsetD32Async,         cuMemsetD32Async,          CUDA_CUMEMSETD32ASYNC,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuMemsetD8Async,          cuMemsetD8Async,           CUDA_CUMEMSETD8ASYNC,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleGetFunction,      cuModuleGetFunction,       CUDA_CUMODULEGETFUNCTION,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleGetGlobal,        cuModuleGetGlobal_v2,      CUDA_CUMODULEGETGLOBAL,         CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoad,             cuModuleLoad,              CUDA_CUMODULELOAD,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoadData,         cuModuleLoadData,          CUDA_CUMODULELOADDATA,          CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleLoadDataEx,       cuModuleLoadDataEx,        CUDA_CUMODULELOADDATAEX,        CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuModuleUnload,           cuModuleUnload,            CUDA_CUMODULEUNLOAD,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuProfilerStart,          cuProfilerStart,           CUDA_CUPROFILERSTART,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuProfilerStop,           cuProfilerStop,            CUDA_CUPROFILERSTOP,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamCreate,           cuStreamCreate,            CUDA_CUSTREAMCREATE,            CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamDestroy,          cuStreamDestroy_v2,        CUDA_CUSTREAMDESTROY,           CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamSynchronize,      cuStreamSynchronize,       CUDA_CUSTREAMSYNCHRONIZE,       CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuStreamWaitEvent,        cuStreamWaitEvent,         CUDA_CUSTREAMWAITEVENT,         CUDA, 1);
  #if defined (WITH_CUBIN)
  HC_LOAD_FUNC_CUDA (cuda, cuLinkCreate,             cuLinkCreate_v2,           CUDA_CULINKCREATE,              CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuLinkAddData,            cuLinkAddData_v2,          CUDA_CULINKADDDATA,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuLinkDestroy,            cuLinkDestroy,             CUDA_CULINKDESTROY,             CUDA, 1);
  HC_LOAD_FUNC_CUDA (cuda, cuLinkComplete,           cuLinkComplete,            CUDA_CULINKCOMPLETE,            CUDA, 1);
  #endif

  return 0;
}

void cuda_close (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  if (cuda)
  {
    if (cuda->lib)
    {
      hc_dlclose (cuda->lib);
    }

    hcfree (backend_ctx->cuda);

    backend_ctx->cuda = NULL;
  }
}

int hc_cuInit (void *hashcat_ctx, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuInit (Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuInit(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuInit(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetAttribute (void *hashcat_ctx, int *pi, CUdevice_attribute attrib, CUdevice dev)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetAttribute (pi, attrib, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetCount (void *hashcat_ctx, int *count)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetCount (count);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetCount(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetCount(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGet (void *hashcat_ctx, CUdevice* device, int ordinal)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGet (device, ordinal);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGet(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGet(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceGetName (void *hashcat_ctx, char *name, int len, CUdevice dev)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceGetName (name, len, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceGetName(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceGetName(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDeviceTotalMem (void *hashcat_ctx, size_t *bytes, CUdevice dev)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDeviceTotalMem (bytes, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDeviceTotalMem(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDeviceTotalMem(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuDriverGetVersion (void *hashcat_ctx, int *driverVersion)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuDriverGetVersion (driverVersion);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuDriverGetVersion(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuDriverGetVersion(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxCreate (void *hashcat_ctx, CUcontext *pctx, unsigned int flags, CUdevice dev)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxCreate (pctx, flags, dev);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxDestroy (void *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxDestroy (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleLoadDataEx (void *hashcat_ctx, CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleLoadDataEx (module, image, numOptions, options, optionValues);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleLoadDataEx(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleLoadDataEx(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleUnload (void *hashcat_ctx, CUmodule hmod)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleUnload (hmod);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleUnload(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleUnload(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSetCurrent (void *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSetCurrent (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSetCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSetCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemAlloc (void *hashcat_ctx, CUdeviceptr *dptr, size_t bytesize)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemAlloc (dptr, bytesize);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemAlloc(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemAlloc(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemFree (void *hashcat_ctx, CUdeviceptr dptr)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemFree (dptr);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemFree(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemFree(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyDtoHAsync (void *hashcat_ctx, void *dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyDtoHAsync (dstHost, srcDevice, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoHAsync(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoHAsync(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyDtoDAsync (void *hashcat_ctx, CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyDtoDAsync (dstDevice, srcDevice, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoDAsync(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyDtoDAsync(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemcpyHtoDAsync (void *hashcat_ctx, CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemcpyHtoDAsync (dstDevice, srcHost, ByteCount, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemcpyHtoDAsync(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemcpyHtoDAsync(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemsetD32Async (void *hashcat_ctx, CUdeviceptr dstDevice, unsigned int ui, size_t N, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemsetD32Async (dstDevice, ui, N, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemsetD32Async(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemsetD32Async(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemsetD8Async (void *hashcat_ctx, CUdeviceptr dstDevice, unsigned char uc, size_t N, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemsetD8Async (dstDevice, uc, N, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemsetD8Async(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemsetD8Async(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleGetFunction (void *hashcat_ctx, CUfunction *hfunc, CUmodule hmod, const char *name)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleGetFunction (hfunc, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleGetFunction(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleGetFunction(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuModuleGetGlobal (void *hashcat_ctx, CUdeviceptr *dptr, size_t *bytes, CUmodule hmod, const char *name)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuModuleGetGlobal (dptr, bytes, hmod, name);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuModuleGetGlobal(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuModuleGetGlobal(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuMemGetInfo (void *hashcat_ctx, size_t *free, size_t *total)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuMemGetInfo (free, total);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuMemGetInfo(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuMemGetInfo(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuFuncGetAttribute (void *hashcat_ctx, int *pi, CUfunction_attribute attrib, CUfunction hfunc)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuFuncGetAttribute (pi, attrib, hfunc);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuFuncGetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuFuncGetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuFuncSetAttribute (void *hashcat_ctx, CUfunction hfunc, CUfunction_attribute attrib, int value)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuFuncSetAttribute (hfunc, attrib, value);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuFuncSetAttribute(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuFuncSetAttribute(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamCreate (void *hashcat_ctx, CUstream *phStream, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamCreate (phStream, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamDestroy (void *hashcat_ctx, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamDestroy (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuStreamSynchronize (void *hashcat_ctx, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuStreamSynchronize (hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuStreamSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuStreamSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLaunchKernel (void *hashcat_ctx, CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLaunchKernel (f, gridDimX, gridDimY, gridDimZ, blockDimX, blockDimY, blockDimZ, sharedMemBytes, hStream, kernelParams, extra);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLaunchKernel(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLaunchKernel(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSynchronize (void *hashcat_ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSynchronize ();

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventCreate (void *hashcat_ctx, CUevent *phEvent, unsigned int Flags)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventCreate (phEvent, Flags);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventDestroy (void *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventDestroy (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventElapsedTime (void *hashcat_ctx, float *pMilliseconds, CUevent hStart, CUevent hEnd)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventElapsedTime (pMilliseconds, hStart, hEnd);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventElapsedTime(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventElapsedTime(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventQuery (void *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventQuery (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventQuery(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventQuery(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventRecord (void *hashcat_ctx, CUevent hEvent, CUstream hStream)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventRecord (hEvent, hStream);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventRecord(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventRecord(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuEventSynchronize (void *hashcat_ctx, CUevent hEvent)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuEventSynchronize (hEvent);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuEventSynchronize(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuEventSynchronize(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxSetCacheConfig (void *hashcat_ctx, CUfunc_cache config)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxSetCacheConfig (config);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxSetCacheConfig(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxSetCacheConfig(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxPushCurrent (void *hashcat_ctx, CUcontext ctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxPushCurrent (ctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxPushCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxPushCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuCtxPopCurrent (void *hashcat_ctx, CUcontext *pctx)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuCtxPopCurrent (pctx);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuCtxPopCurrent(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuCtxPopCurrent(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLinkCreate (void *hashcat_ctx, unsigned int numOptions, CUjit_option *options, void **optionValues, CUlinkState *stateOut)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLinkCreate (numOptions, options, optionValues, stateOut);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLinkCreate(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLinkCreate(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLinkAddData (void *hashcat_ctx, CUlinkState state, CUjitInputType type, void *data, size_t size, const char *name, unsigned int numOptions, CUjit_option *options, void **optionValues)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLinkAddData (state, type, data, size, name, numOptions, options, optionValues);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLinkAddData(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLinkAddData(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLinkDestroy (void *hashcat_ctx, CUlinkState state)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLinkDestroy (state);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLinkDestroy(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLinkDestroy(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}

int hc_cuLinkComplete (void *hashcat_ctx, CUlinkState state, void **cubinOut, size_t *sizeOut)
{
  backend_ctx_t *backend_ctx = ((hashcat_ctx_t *) hashcat_ctx)->backend_ctx;

  CUDA_PTR *cuda = (CUDA_PTR *) backend_ctx->cuda;

  const CUresult CU_err = cuda->cuLinkComplete (state, cubinOut, sizeOut);

  if (CU_err != CUDA_SUCCESS)
  {
    const char *pStr = NULL;

    if (cuda->cuGetErrorString (CU_err, &pStr) == CUDA_SUCCESS)
    {
      event_log_error (hashcat_ctx, "cuLinkComplete(): %s", pStr);
    }
    else
    {
      event_log_error (hashcat_ctx, "cuLinkComplete(): %d", CU_err);
    }

    return -1;
  }

  return 0;
}
