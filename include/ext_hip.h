/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_HIP_H
#define _EXT_HIP_H

// The general Idea with HIP is to use it for AMD GPU since we use CUDA for NV
// Therefore, we need to take certain items, such as hipDeviceptr_t from driver specific paths like amd_driver_types.h
// We just need to keep this in mind in case we need to update these constants from future SDK versions

// start: amd_driver_types.h

typedef void* hipDeviceptr_t;

typedef enum hipFunction_attribute {
    HIP_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK,
    HIP_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES,
    HIP_FUNC_ATTRIBUTE_CONST_SIZE_BYTES,
    HIP_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES,
    HIP_FUNC_ATTRIBUTE_NUM_REGS,
    HIP_FUNC_ATTRIBUTE_PTX_VERSION,
    HIP_FUNC_ATTRIBUTE_BINARY_VERSION,
    HIP_FUNC_ATTRIBUTE_CACHE_MODE_CA,
    HIP_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES,
    HIP_FUNC_ATTRIBUTE_PREFERRED_SHARED_MEMORY_CARVEOUT,
    HIP_FUNC_ATTRIBUTE_MAX
}hipFunction_attribute;

// stop: amd_driver_types.h

// start: hip_runtime_api.h

typedef int hipDevice_t;
typedef struct ihipCtx_t* hipCtx_t;
typedef struct ihipEvent_t* hipEvent_t;
typedef struct ihipStream_t* hipStream_t;
typedef struct ihipModule_t* hipModule_t;
typedef struct ihipModuleSymbol_t* hipFunction_t;

// Ignoring error-code return values from hip APIs is discouraged. On C++17,
// we can make that yield a warning
#if __cplusplus >= 201703L
#define __HIP_NODISCARD [[nodiscard]]
#else
#define __HIP_NODISCARD
#endif

typedef enum __HIP_NODISCARD hipError_t {
    hipSuccess = 0,  ///< Successful completion.
    hipErrorInvalidValue = 1,  ///< One or more of the parameters passed to the API call is NULL
                               ///< or not in an acceptable range.
    hipErrorOutOfMemory = 2,
    // Deprecated
    hipErrorMemoryAllocation = 2,  ///< Memory allocation error.
    hipErrorNotInitialized = 3,
    // Deprecated
    hipErrorInitializationError = 3,
    hipErrorDeinitialized = 4,
    hipErrorProfilerDisabled = 5,
    hipErrorProfilerNotInitialized = 6,
    hipErrorProfilerAlreadyStarted = 7,
    hipErrorProfilerAlreadyStopped = 8,
    hipErrorInvalidConfiguration = 9,
    hipErrorInvalidPitchValue = 12,
    hipErrorInvalidSymbol = 13,
    hipErrorInvalidDevicePointer = 17,  ///< Invalid Device Pointer
    hipErrorInvalidMemcpyDirection = 21,  ///< Invalid memory copy direction
    hipErrorInsufficientDriver = 35,
    hipErrorMissingConfiguration = 52,
    hipErrorPriorLaunchFailure = 53,
    hipErrorInvalidDeviceFunction = 98,
    hipErrorNoDevice = 100,  ///< Call to hipGetDeviceCount returned 0 devices
    hipErrorInvalidDevice = 101,  ///< DeviceID must be in range 0...#compute-devices.
    hipErrorInvalidImage = 200,
    hipErrorInvalidContext = 201,  ///< Produced when input context is invalid.
    hipErrorContextAlreadyCurrent = 202,
    hipErrorMapFailed = 205,
    // Deprecated
    hipErrorMapBufferObjectFailed = 205,  ///< Produced when the IPC memory attach failed from ROCr.
    hipErrorUnmapFailed = 206,
    hipErrorArrayIsMapped = 207,
    hipErrorAlreadyMapped = 208,
    hipErrorNoBinaryForGpu = 209,
    hipErrorAlreadyAcquired = 210,
    hipErrorNotMapped = 211,
    hipErrorNotMappedAsArray = 212,
    hipErrorNotMappedAsPointer = 213,
    hipErrorECCNotCorrectable = 214,
    hipErrorUnsupportedLimit = 215,
    hipErrorContextAlreadyInUse = 216,
    hipErrorPeerAccessUnsupported = 217,
    hipErrorInvalidKernelFile = 218,  ///< In CUDA DRV, it is CUDA_ERROR_INVALID_PTX
    hipErrorInvalidGraphicsContext = 219,
    hipErrorInvalidSource = 300,
    hipErrorFileNotFound = 301,
    hipErrorSharedObjectSymbolNotFound = 302,
    hipErrorSharedObjectInitFailed = 303,
    hipErrorOperatingSystem = 304,
    hipErrorInvalidHandle = 400,
    // Deprecated
    hipErrorInvalidResourceHandle = 400,  ///< Resource handle (hipEvent_t or hipStream_t) invalid.
    hipErrorNotFound = 500,
    hipErrorNotReady = 600,  ///< Indicates that asynchronous operations enqueued earlier are not
                             ///< ready.  This is not actually an error, but is used to distinguish
                             ///< from hipSuccess (which indicates completion).  APIs that return
                             ///< this error include hipEventQuery and hipStreamQuery.
    hipErrorIllegalAddress = 700,
    hipErrorLaunchOutOfResources = 701,  ///< Out of resources error.
    hipErrorLaunchTimeOut = 702,
    hipErrorPeerAccessAlreadyEnabled =
        704,  ///< Peer access was already enabled from the current device.
    hipErrorPeerAccessNotEnabled =
        705,  ///< Peer access was never enabled from the current device.
    hipErrorSetOnActiveProcess = 708,
    hipErrorContextIsDestroyed = 709,
    hipErrorAssert = 710,  ///< Produced when the kernel calls assert.
    hipErrorHostMemoryAlreadyRegistered =
        712,  ///< Produced when trying to lock a page-locked memory.
    hipErrorHostMemoryNotRegistered =
        713,  ///< Produced when trying to unlock a non-page-locked memory.
    hipErrorLaunchFailure =
        719,  ///< An exception occurred on the device while executing a kernel.
    hipErrorCooperativeLaunchTooLarge =
        720,  ///< This error indicates that the number of blocks launched per grid for a kernel
              ///< that was launched via cooperative launch APIs exceeds the maximum number of
              ///< allowed blocks for the current device
    hipErrorNotSupported = 801,  ///< Produced when the hip API is not supported/implemented
    hipErrorStreamCaptureUnsupported = 900,  ///< The operation is not permitted when the stream
                                             ///< is capturing.
    hipErrorStreamCaptureInvalidated = 901,  ///< The current capture sequence on the stream
                                             ///< has been invalidated due to a previous error.
    hipErrorStreamCaptureMerge = 902,  ///< The operation would have resulted in a merge of
                                       ///< two independent capture sequences.
    hipErrorStreamCaptureUnmatched = 903,  ///< The capture was not initiated in this stream.
    hipErrorStreamCaptureUnjoined = 904,  ///< The capture sequence contains a fork that was not
                                          ///< joined to the primary stream.
    hipErrorStreamCaptureIsolation = 905,  ///< A dependency would have been created which crosses
                                           ///< the capture sequence boundary. Only implicit
                                           ///< in-stream ordering dependencies  are allowed
                                           ///< to cross the boundary
    hipErrorStreamCaptureImplicit = 906,  ///< The operation would have resulted in a disallowed
                                          ///< implicit dependency on a current capture sequence
                                          ///< from hipStreamLegacy.
    hipErrorCapturedEvent = 907,  ///< The operation is not permitted on an event which was last
                                  ///< recorded in a capturing stream.
    hipErrorStreamCaptureWrongThread = 908,  ///< A stream capture sequence not initiated with
                                             ///< the hipStreamCaptureModeRelaxed argument to
                                             ///< hipStreamBeginCapture was passed to
                                             ///< hipStreamEndCapture in a different thread.
    hipErrorUnknown = 999,  //< Unknown error.
    // HSA Runtime Error Codes start here.
    hipErrorRuntimeMemory = 1052,  ///< HSA runtime memory call returned error.  Typically not seen
                                   ///< in production systems.
    hipErrorRuntimeOther = 1053,  ///< HSA runtime call other than memory returned error.  Typically
                                  ///< not seen in production systems.
    hipErrorTbd  ///< Marker that more error codes are needed.
} hipError_t;

#undef __HIP_NODISCARD

typedef enum hipDeviceAttribute_t {
    hipDeviceAttributeMaxThreadsPerBlock,       ///< Maximum number of threads per block.
    hipDeviceAttributeMaxBlockDimX,             ///< Maximum x-dimension of a block.
    hipDeviceAttributeMaxBlockDimY,             ///< Maximum y-dimension of a block.
    hipDeviceAttributeMaxBlockDimZ,             ///< Maximum z-dimension of a block.
    hipDeviceAttributeMaxGridDimX,              ///< Maximum x-dimension of a grid.
    hipDeviceAttributeMaxGridDimY,              ///< Maximum y-dimension of a grid.
    hipDeviceAttributeMaxGridDimZ,              ///< Maximum z-dimension of a grid.
    hipDeviceAttributeMaxSharedMemoryPerBlock,  ///< Maximum shared memory available per block in
                                                ///< bytes.
    hipDeviceAttributeTotalConstantMemory,      ///< Constant memory size in bytes.
    hipDeviceAttributeWarpSize,                 ///< Warp size in threads.
    hipDeviceAttributeMaxRegistersPerBlock,  ///< Maximum number of 32-bit registers available to a
                                             ///< thread block. This number is shared by all thread
                                             ///< blocks simultaneously resident on a
                                             ///< multiprocessor.
    hipDeviceAttributeClockRate,             ///< Peak clock frequency in kilohertz.
    hipDeviceAttributeMemoryClockRate,       ///< Peak memory clock frequency in kilohertz.
    hipDeviceAttributeMemoryBusWidth,        ///< Global memory bus width in bits.
    hipDeviceAttributeMultiprocessorCount,   ///< Number of multiprocessors on the device.
    hipDeviceAttributeComputeMode,           ///< Compute mode that device is currently in.
    hipDeviceAttributeL2CacheSize,  ///< Size of L2 cache in bytes. 0 if the device doesn't have L2
                                    ///< cache.
    hipDeviceAttributeMaxThreadsPerMultiProcessor,  ///< Maximum resident threads per
                                                    ///< multiprocessor.
    hipDeviceAttributeComputeCapabilityMajor,       ///< Major compute capability version number.
    hipDeviceAttributeComputeCapabilityMinor,       ///< Minor compute capability version number.
    hipDeviceAttributeConcurrentKernels,  ///< Device can possibly execute multiple kernels
                                          ///< concurrently.
    hipDeviceAttributePciBusId,           ///< PCI Bus ID.
    hipDeviceAttributePciDeviceId,        ///< PCI Device ID.
    hipDeviceAttributeMaxSharedMemoryPerMultiprocessor,  ///< Maximum Shared Memory Per
                                                         ///< Multiprocessor.
    hipDeviceAttributeIsMultiGpuBoard,                   ///< Multiple GPU devices.
    hipDeviceAttributeIntegrated,                        ///< iGPU
    hipDeviceAttributeCooperativeLaunch,                 ///< Support cooperative launch
    hipDeviceAttributeCooperativeMultiDeviceLaunch,      ///< Support cooperative launch on multiple devices
    hipDeviceAttributeMaxTexture1DWidth,    ///< Maximum number of elements in 1D images
    hipDeviceAttributeMaxTexture2DWidth,    ///< Maximum dimension width of 2D images in image elements
    hipDeviceAttributeMaxTexture2DHeight,   ///< Maximum dimension height of 2D images in image elements
    hipDeviceAttributeMaxTexture3DWidth,    ///< Maximum dimension width of 3D images in image elements
    hipDeviceAttributeMaxTexture3DHeight,   ///< Maximum dimensions height of 3D images in image elements
    hipDeviceAttributeMaxTexture3DDepth,    ///< Maximum dimensions depth of 3D images in image elements

    hipDeviceAttributeHdpMemFlushCntl,      ///< Address of the HDP_MEM_COHERENCY_FLUSH_CNTL register
    hipDeviceAttributeHdpRegFlushCntl,      ///< Address of the HDP_REG_COHERENCY_FLUSH_CNTL register

    hipDeviceAttributeMaxPitch,             ///< Maximum pitch in bytes allowed by memory copies
    hipDeviceAttributeTextureAlignment,     ///<Alignment requirement for textures
    hipDeviceAttributeTexturePitchAlignment, ///<Pitch alignment requirement for 2D texture references bound to pitched memory;
    hipDeviceAttributeKernelExecTimeout,    ///<Run time limit for kernels executed on the device
    hipDeviceAttributeCanMapHostMemory,     ///<Device can map host memory into device address space
    hipDeviceAttributeEccEnabled,           ///<Device has ECC support enabled

    hipDeviceAttributeCooperativeMultiDeviceUnmatchedFunc,        ///< Supports cooperative launch on multiple
                                                                  ///devices with unmatched functions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedGridDim,     ///< Supports cooperative launch on multiple
                                                                  ///devices with unmatched grid dimensions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedBlockDim,    ///< Supports cooperative launch on multiple
                                                                  ///devices with unmatched block dimensions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedSharedMem,   ///< Supports cooperative launch on multiple
                                                                  ///devices with unmatched shared memories
    hipDeviceAttributeAsicRevision,         ///< Revision of the GPU in this device
    hipDeviceAttributeManagedMemory,        ///< Device supports allocating managed memory on this system
    hipDeviceAttributeDirectManagedMemAccessFromHost, ///< Host can directly access managed memory on
                                                      /// the device without migration
    hipDeviceAttributeConcurrentManagedAccess,  ///< Device can coherently access managed memory
                                                /// concurrently with the CPU
    hipDeviceAttributePageableMemoryAccess,     ///< Device supports coherently accessing pageable memory
                                                /// without calling hipHostRegister on it
    hipDeviceAttributePageableMemoryAccessUsesHostPageTables, ///< Device accesses pageable memory via
                                                              /// the host's page tables
    hipDeviceAttributeCanUseStreamWaitValue ///< '1' if Device supports hipStreamWaitValue32() and
                                            ///< hipStreamWaitValue64() , '0' otherwise.

} hipDeviceAttribute_t;

//! Flags that can be used with hipStreamCreateWithFlags
#define hipStreamDefault                                                                           \
    0x00  ///< Default stream creation flags. These are used with hipStreamCreate().
#define hipStreamNonBlocking 0x01  ///< Stream does not implicitly synchronize with null stream


//! Flags that can be used with hipEventCreateWithFlags:
#define hipEventDefault 0x0  ///< Default flags
#define hipEventBlockingSync                                                                       \
    0x1  ///< Waiting will yield CPU.  Power-friendly and usage-friendly but may increase latency.
#define hipEventDisableTiming                                                                      \
    0x2  ///< Disable event's capability to record timing information.  May improve performance.
#define hipEventInterprocess 0x4  ///< Event can support IPC.  @warning - not supported in HIP.
#define hipEventReleaseToDevice                                                                    \
    0x40000000  /// < Use a device-scope release when recording this event.  This flag is useful to
                /// obtain more precise timings of commands between events.  The flag is a no-op on
                /// CUDA platforms.
#define hipEventReleaseToSystem                                                                    \
    0x80000000  /// < Use a system-scope release when recording this event.  This flag is
                /// useful to make non-coherent host memory visible to the host.  The flag is a
                /// no-op on CUDA platforms.


#define hipDeviceScheduleAuto 0x0  ///< Automatically select between Spin and Yield
#define hipDeviceScheduleSpin                                                                      \
    0x1  ///< Dedicate a CPU core to spin-wait.  Provides lowest latency, but burns a CPU core and
         ///< may consume more power.
#define hipDeviceScheduleYield                                                                     \
    0x2  ///< Yield the CPU to the operating system when waiting.  May increase latency, but lowers
         ///< power and is friendlier to other threads in the system.
#define hipDeviceScheduleBlockingSync 0x4
#define hipDeviceScheduleMask 0x7
#define hipDeviceMapHost 0x8
#define hipDeviceLmemResizeToMax 0x16

typedef enum hipJitOption {
    hipJitOptionMaxRegisters = 0,
    hipJitOptionThreadsPerBlock,
    hipJitOptionWallTime,
    hipJitOptionInfoLogBuffer,
    hipJitOptionInfoLogBufferSizeBytes,
    hipJitOptionErrorLogBuffer,
    hipJitOptionErrorLogBufferSizeBytes,
    hipJitOptionOptimizationLevel,
    hipJitOptionTargetFromContext,
    hipJitOptionTarget,
    hipJitOptionFallbackStrategy,
    hipJitOptionGenerateDebugInfo,
    hipJitOptionLogVerbose,
    hipJitOptionGenerateLineInfo,
    hipJitOptionCacheMode,
    hipJitOptionSm3xOpt,
    hipJitOptionFastCompile,
    hipJitOptionNumOptions
} hipJitOption;

// stop: hip_runtime_api.h

#ifdef _WIN32
#define HIPAPI __stdcall
#else
#define HIPAPI
#endif

#define HIP_API_CALL HIPAPI

typedef hipError_t (HIP_API_CALL *HIP_HIPCTXCREATE)              (hipCtx_t *, unsigned int, hipDevice_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPCTXDESTROY)             (hipCtx_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPCTXPOPCURRENT)          (hipCtx_t *);
typedef hipError_t (HIP_API_CALL *HIP_HIPCTXPUSHCURRENT)         (hipCtx_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPCTXSETCURRENT)          (hipCtx_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPCTXSYNCHRONIZE)         ();
typedef hipError_t (HIP_API_CALL *HIP_HIPDEVICEGETATTRIBUTE)     (int *, hipDeviceAttribute_t, hipDevice_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPDEVICEGETCOUNT)         (int *);
typedef hipError_t (HIP_API_CALL *HIP_HIPDEVICEGET)              (hipDevice_t *, int);
typedef hipError_t (HIP_API_CALL *HIP_HIPDEVICEGETNAME)          (char *, int, hipDevice_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPDEVICETOTALMEM)         (size_t *, hipDevice_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPDRIVERGETVERSION)       (int *);
typedef hipError_t (HIP_API_CALL *HIP_HIPEVENTCREATE)            (hipEvent_t *, unsigned int);
typedef hipError_t (HIP_API_CALL *HIP_HIPEVENTDESTROY)           (hipEvent_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPEVENTELAPSEDTIME)       (float *, hipEvent_t, hipEvent_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPEVENTRECORD)            (hipEvent_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPEVENTSYNCHRONIZE)       (hipEvent_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPFUNCGETATTRIBUTE)       (int *, hipFunction_attribute, hipFunction_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPGETERRORNAME)           (hipError_t, const char **);
typedef hipError_t (HIP_API_CALL *HIP_HIPGETERRORSTRING)         (hipError_t, const char **);
typedef hipError_t (HIP_API_CALL *HIP_HIPINIT)                   (unsigned int);
typedef hipError_t (HIP_API_CALL *HIP_HIPLAUNCHKERNEL)           (hipFunction_t, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, hipStream_t, void **, void **);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMALLOC)               (hipDeviceptr_t *, size_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMFREE)                (hipDeviceptr_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMGETINFO)             (size_t *, size_t *);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMCPYDTODASYNC)        (hipDeviceptr_t, hipDeviceptr_t, size_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMCPYDTOHASYNC)        (void *, hipDeviceptr_t, size_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMCPYHTODASYNC)        (hipDeviceptr_t, const void *, size_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMSETD32ASYNC)         (hipDeviceptr_t, unsigned int, size_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMEMSETD8ASYNC)          (hipDeviceptr_t, unsigned char, size_t, hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPMODULEGETFUNCTION)      (hipFunction_t *, hipModule_t, const char *);
typedef hipError_t (HIP_API_CALL *HIP_HIPMODULEGETGLOBAL)        (hipDeviceptr_t *, size_t *, hipModule_t, const char *);
typedef hipError_t (HIP_API_CALL *HIP_HIPMODULELOADDATAEX)       (hipModule_t *, const void *, unsigned int, hipJitOption *, void **);
typedef hipError_t (HIP_API_CALL *HIP_HIPMODULEUNLOAD)           (hipModule_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPRUNTIMEGETVERSION)      (int *);
typedef hipError_t (HIP_API_CALL *HIP_HIPSTREAMCREATE)           (hipStream_t *, unsigned int);
typedef hipError_t (HIP_API_CALL *HIP_HIPSTREAMDESTROY)          (hipStream_t);
typedef hipError_t (HIP_API_CALL *HIP_HIPSTREAMSYNCHRONIZE)      (hipStream_t);

typedef struct hc_hip_lib
{
  hc_dynlib_t lib;

  HIP_HIPCTXCREATE              hipCtxCreate;
  HIP_HIPCTXDESTROY             hipCtxDestroy;
  HIP_HIPCTXPOPCURRENT          hipCtxPopCurrent;
  HIP_HIPCTXPUSHCURRENT         hipCtxPushCurrent;
  HIP_HIPCTXSETCURRENT          hipCtxSetCurrent;
  HIP_HIPCTXSYNCHRONIZE         hipCtxSynchronize;
  HIP_HIPDEVICEGETATTRIBUTE     hipDeviceGetAttribute;
  HIP_HIPDEVICEGETCOUNT         hipDeviceGetCount;
  HIP_HIPDEVICEGET              hipDeviceGet;
  HIP_HIPDEVICEGETNAME          hipDeviceGetName;
  HIP_HIPDEVICETOTALMEM         hipDeviceTotalMem;
  HIP_HIPDRIVERGETVERSION       hipDriverGetVersion;
  HIP_HIPEVENTCREATE            hipEventCreate;
  HIP_HIPEVENTDESTROY           hipEventDestroy;
  HIP_HIPEVENTELAPSEDTIME       hipEventElapsedTime;
  HIP_HIPEVENTRECORD            hipEventRecord;
  HIP_HIPEVENTSYNCHRONIZE       hipEventSynchronize;
  HIP_HIPFUNCGETATTRIBUTE       hipFuncGetAttribute;
  HIP_HIPGETERRORNAME           hipGetErrorName;
  HIP_HIPGETERRORSTRING         hipGetErrorString;
  HIP_HIPINIT                   hipInit;
  HIP_HIPLAUNCHKERNEL           hipLaunchKernel;
  HIP_HIPMEMALLOC               hipMemAlloc;
  HIP_HIPMEMFREE                hipMemFree;
  HIP_HIPMEMGETINFO             hipMemGetInfo;
  HIP_HIPMEMCPYDTODASYNC        hipMemcpyDtoDAsync;
  HIP_HIPMEMCPYDTOHASYNC        hipMemcpyDtoHAsync;
  HIP_HIPMEMCPYHTODASYNC        hipMemcpyHtoDAsync;
  HIP_HIPMEMSETD32ASYNC         hipMemsetD32Async;
  HIP_HIPMEMSETD8ASYNC          hipMemsetD8Async;
  HIP_HIPMODULEGETFUNCTION      hipModuleGetFunction;
  HIP_HIPMODULEGETGLOBAL        hipModuleGetGlobal;
  HIP_HIPMODULELOADDATAEX       hipModuleLoadDataEx;
  HIP_HIPMODULEUNLOAD           hipModuleUnload;
  HIP_HIPRUNTIMEGETVERSION      hipRuntimeGetVersion;
  HIP_HIPSTREAMCREATE           hipStreamCreate;
  HIP_HIPSTREAMDESTROY          hipStreamDestroy;
  HIP_HIPSTREAMSYNCHRONIZE      hipStreamSynchronize;

} hc_hip_lib_t;

typedef hc_hip_lib_t HIP_PTR;

#endif // _EXT_HIP_H
