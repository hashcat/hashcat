/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_HIP_H
#define _EXT_HIP_H

// The general Idea with HIP is to use it for AMD GPU since we use CUDA for NV
// Therefore, we need to take certain items, such as hipDeviceptr_t from driver specific paths like amd_driver_types.h
// We just need to keep this in mind in case we need to update these constants from future SDK versions

// start: driver_types.h

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
} hipFunction_attribute;

// stop: driver_types.h

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
    hipErrorIllegalState = 401, ///< Resource required is not in a valid state to perform operation.
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
    hipErrorGraphExecUpdateFailure = 910,  ///< This error indicates that the graph update
                                           ///< not performed because it included changes which
                                           ///< violated constraintsspecific to instantiated graph
                                           ///< update.
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
    hipDeviceAttributeCudaCompatibleBegin = 0,

    hipDeviceAttributeEccEnabled = hipDeviceAttributeCudaCompatibleBegin, ///< Whether ECC support is enabled.
    hipDeviceAttributeAccessPolicyMaxWindowSize,        ///< Cuda only. The maximum size of the window policy in bytes.
    hipDeviceAttributeAsyncEngineCount,                 ///< Cuda only. Asynchronous engines number.
    hipDeviceAttributeCanMapHostMemory,                 ///< Whether host memory can be mapped into device address space
    hipDeviceAttributeCanUseHostPointerForRegisteredMem,///< Cuda only. Device can access host registered memory
                                                        ///< at the same virtual address as the CPU
    hipDeviceAttributeClockRate,                        ///< Peak clock frequency in kilohertz.
    hipDeviceAttributeComputeMode,                      ///< Compute mode that device is currently in.
    hipDeviceAttributeComputePreemptionSupported,       ///< Cuda only. Device supports Compute Preemption.
    hipDeviceAttributeConcurrentKernels,                ///< Device can possibly execute multiple kernels concurrently.
    hipDeviceAttributeConcurrentManagedAccess,          ///< Device can coherently access managed memory concurrently with the CPU
    hipDeviceAttributeCooperativeLaunch,                ///< Support cooperative launch
    hipDeviceAttributeCooperativeMultiDeviceLaunch,     ///< Support cooperative launch on multiple devices
    hipDeviceAttributeDeviceOverlap,                    ///< Cuda only. Device can concurrently copy memory and execute a kernel.
                                                        ///< Deprecated. Use instead asyncEngineCount.
    hipDeviceAttributeDirectManagedMemAccessFromHost,   ///< Host can directly access managed memory on
                                                        ///< the device without migration
    hipDeviceAttributeGlobalL1CacheSupported,           ///< Cuda only. Device supports caching globals in L1
    hipDeviceAttributeHostNativeAtomicSupported,        ///< Cuda only. Link between the device and the host supports native atomic operations
    hipDeviceAttributeIntegrated,                       ///< Device is integrated GPU
    hipDeviceAttributeIsMultiGpuBoard,                  ///< Multiple GPU devices.
    hipDeviceAttributeKernelExecTimeout,                ///< Run time limit for kernels executed on the device
    hipDeviceAttributeL2CacheSize,                      ///< Size of L2 cache in bytes. 0 if the device doesn't have L2 cache.
    hipDeviceAttributeLocalL1CacheSupported,            ///< caching locals in L1 is supported
    hipDeviceAttributeLuid,                             ///< Cuda only. 8-byte locally unique identifier in 8 bytes. Undefined on TCC and non-Windows platforms
    hipDeviceAttributeLuidDeviceNodeMask,               ///< Cuda only. Luid device node mask. Undefined on TCC and non-Windows platforms
    hipDeviceAttributeComputeCapabilityMajor,           ///< Major compute capability version number.
    hipDeviceAttributeManagedMemory,                    ///< Device supports allocating managed memory on this system
    hipDeviceAttributeMaxBlocksPerMultiProcessor,       ///< Cuda only. Max block size per multiprocessor
    hipDeviceAttributeMaxBlockDimX,                     ///< Max block size in width.
    hipDeviceAttributeMaxBlockDimY,                     ///< Max block size in height.
    hipDeviceAttributeMaxBlockDimZ,                     ///< Max block size in depth.
    hipDeviceAttributeMaxGridDimX,                      ///< Max grid size  in width.
    hipDeviceAttributeMaxGridDimY,                      ///< Max grid size  in height.
    hipDeviceAttributeMaxGridDimZ,                      ///< Max grid size  in depth.
    hipDeviceAttributeMaxSurface1D,                     ///< Maximum size of 1D surface.
    hipDeviceAttributeMaxSurface1DLayered,              ///< Cuda only. Maximum dimensions of 1D layered surface.
    hipDeviceAttributeMaxSurface2D,                     ///< Maximum dimension (width, height) of 2D surface.
    hipDeviceAttributeMaxSurface2DLayered,              ///< Cuda only. Maximum dimensions of 2D layered surface.
    hipDeviceAttributeMaxSurface3D,                     ///< Maximum dimension (width, height, depth) of 3D surface.
    hipDeviceAttributeMaxSurfaceCubemap,                ///< Cuda only. Maximum dimensions of Cubemap surface.
    hipDeviceAttributeMaxSurfaceCubemapLayered,         ///< Cuda only. Maximum dimension of Cubemap layered surface.
    hipDeviceAttributeMaxTexture1DWidth,                ///< Maximum size of 1D texture.
    hipDeviceAttributeMaxTexture1DLayered,              ///< Cuda only. Maximum dimensions of 1D layered texture.
    hipDeviceAttributeMaxTexture1DLinear,               ///< Maximum number of elements allocatable in a 1D linear texture.
                                                        ///< Use cudaDeviceGetTexture1DLinearMaxWidth() instead on Cuda.
    hipDeviceAttributeMaxTexture1DMipmap,               ///< Cuda only. Maximum size of 1D mipmapped texture.
    hipDeviceAttributeMaxTexture2DWidth,                ///< Maximum dimension width of 2D texture.
    hipDeviceAttributeMaxTexture2DHeight,               ///< Maximum dimension hight of 2D texture.
    hipDeviceAttributeMaxTexture2DGather,               ///< Cuda only. Maximum dimensions of 2D texture if gather operations  performed.
    hipDeviceAttributeMaxTexture2DLayered,              ///< Cuda only. Maximum dimensions of 2D layered texture.
    hipDeviceAttributeMaxTexture2DLinear,               ///< Cuda only. Maximum dimensions (width, height, pitch) of 2D textures bound to pitched memory.
    hipDeviceAttributeMaxTexture2DMipmap,               ///< Cuda only. Maximum dimensions of 2D mipmapped texture.
    hipDeviceAttributeMaxTexture3DWidth,                ///< Maximum dimension width of 3D texture.
    hipDeviceAttributeMaxTexture3DHeight,               ///< Maximum dimension height of 3D texture.
    hipDeviceAttributeMaxTexture3DDepth,                ///< Maximum dimension depth of 3D texture.
    hipDeviceAttributeMaxTexture3DAlt,                  ///< Cuda only. Maximum dimensions of alternate 3D texture.
    hipDeviceAttributeMaxTextureCubemap,                ///< Cuda only. Maximum dimensions of Cubemap texture
    hipDeviceAttributeMaxTextureCubemapLayered,         ///< Cuda only. Maximum dimensions of Cubemap layered texture.
    hipDeviceAttributeMaxThreadsDim,                    ///< Maximum dimension of a block
    hipDeviceAttributeMaxThreadsPerBlock,               ///< Maximum number of threads per block.
    hipDeviceAttributeMaxThreadsPerMultiProcessor,      ///< Maximum resident threads per multiprocessor.
    hipDeviceAttributeMaxPitch,                         ///< Maximum pitch in bytes allowed by memory copies
    hipDeviceAttributeMemoryBusWidth,                   ///< Global memory bus width in bits.
    hipDeviceAttributeMemoryClockRate,                  ///< Peak memory clock frequency in kilohertz.
    hipDeviceAttributeComputeCapabilityMinor,           ///< Minor compute capability version number.
    hipDeviceAttributeMultiGpuBoardGroupID,             ///< Cuda only. Unique ID of device group on the same multi-GPU board
    hipDeviceAttributeMultiprocessorCount,              ///< Number of multiprocessors on the device.
    hipDeviceAttributeName,                             ///< Device name.
    hipDeviceAttributePageableMemoryAccess,             ///< Device supports coherently accessing pageable memory
                                                        ///< without calling hipHostRegister on it
    hipDeviceAttributePageableMemoryAccessUsesHostPageTables, ///< Device accesses pageable memory via the host's page tables
    hipDeviceAttributePciBusId,                         ///< PCI Bus ID.
    hipDeviceAttributePciDeviceId,                      ///< PCI Device ID.
    hipDeviceAttributePciDomainID,                      ///< PCI Domain ID.
    hipDeviceAttributePersistingL2CacheMaxSize,         ///< Cuda11 only. Maximum l2 persisting lines capacity in bytes
    hipDeviceAttributeMaxRegistersPerBlock,             ///< 32-bit registers available to a thread block. This number is shared
                                                        ///< by all thread blocks simultaneously resident on a multiprocessor.
    hipDeviceAttributeMaxRegistersPerMultiprocessor,    ///< 32-bit registers available per block.
    hipDeviceAttributeReservedSharedMemPerBlock,        ///< Cuda11 only. Shared memory reserved by CUDA driver per block.
    hipDeviceAttributeMaxSharedMemoryPerBlock,          ///< Maximum shared memory available per block in bytes.
    hipDeviceAttributeSharedMemPerBlockOptin,           ///< Cuda only. Maximum shared memory per block usable by special opt in.
    hipDeviceAttributeSharedMemPerMultiprocessor,       ///< Cuda only. Shared memory available per multiprocessor.
    hipDeviceAttributeSingleToDoublePrecisionPerfRatio, ///< Cuda only. Performance ratio of single precision to double precision.
    hipDeviceAttributeStreamPrioritiesSupported,        ///< Cuda only. Whether to support stream priorities.
    hipDeviceAttributeSurfaceAlignment,                 ///< Cuda only. Alignment requirement for surfaces
    hipDeviceAttributeTccDriver,                        ///< Cuda only. Whether device is a Tesla device using TCC driver
    hipDeviceAttributeTextureAlignment,                 ///< Alignment requirement for textures
    hipDeviceAttributeTexturePitchAlignment,            ///< Pitch alignment requirement for 2D texture references bound to pitched memory;
    hipDeviceAttributeTotalConstantMemory,              ///< Constant memory size in bytes.
    hipDeviceAttributeTotalGlobalMem,                   ///< Global memory available on devicice.
    hipDeviceAttributeUnifiedAddressing,                ///< Cuda only. An unified address space shared with the host.
    hipDeviceAttributeUuid,                             ///< Cuda only. Unique ID in 16 byte.
    hipDeviceAttributeWarpSize,                         ///< Warp size in threads.

    hipDeviceAttributeCudaCompatibleEnd = 9999,
    hipDeviceAttributeAmdSpecificBegin = 10000,

    hipDeviceAttributeClockInstructionRate = hipDeviceAttributeAmdSpecificBegin,  ///< Frequency in khz of the timer used by the device-side "clock*"
    hipDeviceAttributeArch,                                     ///< Device architecture
    hipDeviceAttributeMaxSharedMemoryPerMultiprocessor,         ///< Maximum Shared Memory PerMultiprocessor.
    hipDeviceAttributeGcnArch,                                  ///< Device gcn architecture
    hipDeviceAttributeGcnArchName,                              ///< Device gcnArch name in 256 bytes
    hipDeviceAttributeHdpMemFlushCntl,                          ///< Address of the HDP_MEM_COHERENCY_FLUSH_CNTL register
    hipDeviceAttributeHdpRegFlushCntl,                          ///< Address of the HDP_REG_COHERENCY_FLUSH_CNTL register
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedFunc,      ///< Supports cooperative launch on multiple
                                                                ///< devices with unmatched functions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedGridDim,   ///< Supports cooperative launch on multiple
                                                                ///< devices with unmatched grid dimensions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedBlockDim,  ///< Supports cooperative launch on multiple
                                                                ///< devices with unmatched block dimensions
    hipDeviceAttributeCooperativeMultiDeviceUnmatchedSharedMem, ///< Supports cooperative launch on multiple
                                                                ///< devices with unmatched shared memories
    hipDeviceAttributeIsLargeBar,                               ///< Whether it is LargeBar
    hipDeviceAttributeAsicRevision,                             ///< Revision of the GPU in this device
    hipDeviceAttributeCanUseStreamWaitValue,                    ///< '1' if Device supports hipStreamWaitValue32() and
                                                                ///< hipStreamWaitValue64(), '0' otherwise.
    hipDeviceAttributeImageSupport,                             ///< '1' if Device supports image, '0' otherwise.
    hipDeviceAttributePhysicalMultiProcessorCount,              ///< All available physical compute
                                                                ///< units for the device
    hipDeviceAttributeAmdSpecificEnd = 19999,
    hipDeviceAttributeVendorSpecificBegin = 20000,
    // Extended attributes for vendors
} hipDeviceAttribute_t;

//Flags that can be used with hipStreamCreateWithFlags.
/** Default stream creation flags. These are used with hipStreamCreate().*/
#define hipStreamDefault  0x00

/** Stream does not implicitly synchronize with null stream.*/
#define hipStreamNonBlocking 0x01

//Flags that can be used with hipEventCreateWithFlags.
/** Default flags.*/
#define hipEventDefault 0x0

/** Waiting will yield CPU. Power-friendly and usage-friendly but may increase latency.*/
#define hipEventBlockingSync 0x1

/** Disable event's capability to record timing information. May improve performance.*/
#define hipEventDisableTiming  0x2

/** Event can support IPC. Warnig: It is not supported in HIP.*/
#define hipEventInterprocess 0x4

/** Use a device-scope release when recording this event. This flag is useful to obtain more
 * precise timings of commands between events.  The flag is a no-op on CUDA platforms.*/
#define hipEventReleaseToDevice  0x40000000

/** Use a system-scope release when recording this event. This flag is useful to make
 * non-coherent host memory visible to the host. The flag is a no-op on CUDA platforms.*/
#define hipEventReleaseToSystem  0x80000000

#define hipDeviceScheduleAuto 0x0

/** Dedicate a CPU core to spin-wait. Provides lowest latency, but burns a CPU core and may
 * consume more power.*/
#define hipDeviceScheduleSpin  0x1

/** Yield the CPU to the operating system when waiting. May increase latency, but lowers power
 * and is friendlier to other threads in the system.*/
#define hipDeviceScheduleYield  0x2
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

int  hip_init                  (void *hashcat_ctx);
void hip_close                 (void *hashcat_ctx);

int hc_hipCtxCreate            (void *hashcat_ctx, hipCtx_t *pctx, unsigned int flags, hipDevice_t dev);
int hc_hipCtxDestroy           (void *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxPopCurrent        (void *hashcat_ctx, hipCtx_t *pctx);
int hc_hipCtxPushCurrent       (void *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxSetCurrent        (void *hashcat_ctx, hipCtx_t ctx);
int hc_hipCtxSynchronize       (void *hashcat_ctx);
int hc_hipDeviceGet            (void *hashcat_ctx, hipDevice_t *device, int ordinal);
int hc_hipDeviceGetAttribute   (void *hashcat_ctx, int *pi, hipDeviceAttribute_t attrib, hipDevice_t dev);
int hc_hipDeviceGetCount       (void *hashcat_ctx, int *count);
int hc_hipDeviceGetName        (void *hashcat_ctx, char *name, int len, hipDevice_t dev);
int hc_hipDeviceTotalMem       (void *hashcat_ctx, size_t *bytes, hipDevice_t dev);
int hc_hipDriverGetVersion     (void *hashcat_ctx, int *driverVersion);
int hc_hipEventCreate          (void *hashcat_ctx, hipEvent_t *phEvent, unsigned int Flags);
int hc_hipEventDestroy         (void *hashcat_ctx, hipEvent_t hEvent);
int hc_hipEventElapsedTime     (void *hashcat_ctx, float *pMilliseconds, hipEvent_t hStart, hipEvent_t hEnd);
int hc_hipEventQuery           (void *hashcat_ctx, hipEvent_t hEvent);
int hc_hipEventRecord          (void *hashcat_ctx, hipEvent_t hEvent, hipStream_t hStream);
int hc_hipEventSynchronize     (void *hashcat_ctx, hipEvent_t hEvent);
int hc_hipFuncGetAttribute     (void *hashcat_ctx, int *pi, hipFunction_attribute attrib, hipFunction_t hfunc);
int hc_hipInit                 (void *hashcat_ctx, unsigned int Flags);
int hc_hipLaunchKernel         (void *hashcat_ctx, hipFunction_t f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, hipStream_t hStream, void **kernelParams, void **extra);
int hc_hipMemAlloc             (void *hashcat_ctx, hipDeviceptr_t *dptr, size_t bytesize);
int hc_hipMemFree              (void *hashcat_ctx, hipDeviceptr_t dptr);
int hc_hipMemGetInfo           (void *hashcat_ctx, size_t *free, size_t *total);
int hc_hipMemcpyDtoDAsync      (void *hashcat_ctx, hipDeviceptr_t dstDevice, hipDeviceptr_t srcDevice, size_t ByteCount, hipStream_t hStream);
int hc_hipMemcpyDtoHAsync      (void *hashcat_ctx, void *dstHost, hipDeviceptr_t srcDevice, size_t ByteCount, hipStream_t hStream);
int hc_hipMemcpyHtoDAsync      (void *hashcat_ctx, hipDeviceptr_t dstDevice, const void *srcHost, size_t ByteCount, hipStream_t hStream);
int hc_hipMemsetD32Async       (void *hashcat_ctx, hipDeviceptr_t dstDevice, unsigned int ui, size_t N, hipStream_t hStream);
int hc_hipMemsetD8Async        (void *hashcat_ctx, hipDeviceptr_t dstDevice, unsigned char uc, size_t N, hipStream_t hStream);
int hc_hipModuleGetFunction    (void *hashcat_ctx, hipFunction_t *hfunc, hipModule_t hmod, const char *name);
int hc_hipModuleGetGlobal      (void *hashcat_ctx, hipDeviceptr_t *dptr, size_t *bytes, hipModule_t hmod, const char *name);
int hc_hipModuleLoadDataEx     (void *hashcat_ctx, hipModule_t *module, const void *image, unsigned int numOptions, hipJitOption *options, void **optionValues);
int hc_hipModuleUnload         (void *hashcat_ctx, hipModule_t hmod);
int hc_hipRuntimeGetVersion    (void *hashcat_ctx, int *runtimeVersion);
int hc_hipStreamCreate         (void *hashcat_ctx, hipStream_t *phStream, unsigned int Flags);
int hc_hipStreamDestroy        (void *hashcat_ctx, hipStream_t hStream);
int hc_hipStreamSynchronize    (void *hashcat_ctx, hipStream_t hStream);

#endif // _EXT_HIP_H
