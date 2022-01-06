/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_CUDA_H
#define _EXT_CUDA_H

/**
 * from cuda.h (/usr/local/cuda-10.1/targets/x86_64-linux/include/cuda.h)
 */

#define __CUDA_API_VERSION 10010

/**
 * CUDA device pointer
 * CUdeviceptr is defined as an unsigned integer type whose size matches the size of a pointer on the target platform.
 */
#if __CUDA_API_VERSION >= 3020

#if defined(_WIN64) || defined(__LP64__)
typedef unsigned long long CUdeviceptr;
#else
typedef unsigned int CUdeviceptr;
#endif

#endif /* __CUDA_API_VERSION >= 3020 */

typedef int CUdevice;                                     /**< CUDA device */
typedef struct CUctx_st *CUcontext;                       /**< CUDA context */
typedef struct CUevent_st *CUevent;                       /**< CUDA event */
typedef struct CUfunc_st *CUfunction;                     /**< CUDA function */
typedef struct CUmod_st *CUmodule;                        /**< CUDA module */
typedef struct CUstream_st *CUstream;                     /**< CUDA stream */
typedef struct CUlinkState_st *CUlinkState;

typedef enum cudaError_enum
{
  /**
   * The API call returned with no errors. In the case of query calls, this
   * also means that the operation being queried is complete (see
   * ::cuEventQuery() and ::cuStreamQuery()).
   */
  CUDA_SUCCESS                              = 0,

  /**
   * This indicates that one or more of the parameters passed to the API call
   * is not within an acceptable range of values.
   */
  CUDA_ERROR_INVALID_VALUE                  = 1,

  /**
   * The API call failed because it was unable to allocate enough memory to
   * perform the requested operation.
   */
  CUDA_ERROR_OUT_OF_MEMORY                  = 2,

  /**
   * This indicates that the CUDA driver has not been initialized with
   * ::cuInit() or that initialization has failed.
   */
  CUDA_ERROR_NOT_INITIALIZED                = 3,

  /**
   * This indicates that the CUDA driver is in the process of shutting down.
   */
  CUDA_ERROR_DEINITIALIZED                  = 4,

  /**
   * This indicates profiler is not initialized for this run. This can
   * happen when the application is running with external profiling tools
   * like visual profiler.
   */
  CUDA_ERROR_PROFILER_DISABLED              = 5,

  /**
   * \deprecated
   * This error return is deprecated as of CUDA 5.0. It is no longer an error
   * to attempt to enable/disable the profiling via ::cuProfilerStart or
   * ::cuProfilerStop without initialization.
   */
  CUDA_ERROR_PROFILER_NOT_INITIALIZED       = 6,

  /**
   * \deprecated
   * This error return is deprecated as of CUDA 5.0. It is no longer an error
   * to call cuProfilerStart() when profiling is already enabled.
   */
  CUDA_ERROR_PROFILER_ALREADY_STARTED       = 7,

  /**
   * \deprecated
   * This error return is deprecated as of CUDA 5.0. It is no longer an error
   * to call cuProfilerStop() when profiling is already disabled.
   */
  CUDA_ERROR_PROFILER_ALREADY_STOPPED       = 8,

  /**
   * This indicates that no CUDA-capable devices were detected by the installed
   * CUDA driver.
   */
  CUDA_ERROR_NO_DEVICE                      = 100,

  /**
   * This indicates that the device ordinal supplied by the user does not
   * correspond to a valid CUDA device.
   */
  CUDA_ERROR_INVALID_DEVICE                 = 101,


  /**
   * This indicates that the device kernel image is invalid. This can also
   * indicate an invalid CUDA module.
   */
  CUDA_ERROR_INVALID_IMAGE                  = 200,

  /**
   * This most frequently indicates that there is no context bound to the
   * current thread. This can also be returned if the context passed to an
   * API call is not a valid handle (such as a context that has had
   * ::cuCtxDestroy() invoked on it). This can also be returned if a user
   * mixes different API versions (i.e. 3010 context with 3020 API calls).
   * See ::cuCtxGetApiVersion() for more details.
   */
  CUDA_ERROR_INVALID_CONTEXT                = 201,

  /**
   * This indicated that the context being supplied as a parameter to the
   * API call was already the active context.
   * \deprecated
   * This error return is deprecated as of CUDA 3.2. It is no longer an
   * error to attempt to push the active context via ::cuCtxPushCurrent().
   */
  CUDA_ERROR_CONTEXT_ALREADY_CURRENT        = 202,

  /**
   * This indicates that a map or register operation has failed.
   */
  CUDA_ERROR_MAP_FAILED                     = 205,

  /**
   * This indicates that an unmap or unregister operation has failed.
   */
  CUDA_ERROR_UNMAP_FAILED                   = 206,

  /**
   * This indicates that the specified array is currently mapped and thus
   * cannot be destroyed.
   */
  CUDA_ERROR_ARRAY_IS_MAPPED                = 207,

  /**
   * This indicates that the resource is already mapped.
   */
  CUDA_ERROR_ALREADY_MAPPED                 = 208,

  /**
   * This indicates that there is no kernel image available that is suitable
   * for the device. This can occur when a user specifies code generation
   * options for a particular CUDA source file that do not include the
   * corresponding device configuration.
   */
  CUDA_ERROR_NO_BINARY_FOR_GPU              = 209,

  /**
   * This indicates that a resource has already been acquired.
   */
  CUDA_ERROR_ALREADY_ACQUIRED               = 210,

  /**
   * This indicates that a resource is not mapped.
   */
  CUDA_ERROR_NOT_MAPPED                     = 211,

  /**
   * This indicates that a mapped resource is not available for access as an
   * array.
   */
  CUDA_ERROR_NOT_MAPPED_AS_ARRAY            = 212,

  /**
   * This indicates that a mapped resource is not available for access as a
   * pointer.
   */
  CUDA_ERROR_NOT_MAPPED_AS_POINTER          = 213,

  /**
   * This indicates that an uncorrectable ECC error was detected during
   * execution.
   */
  CUDA_ERROR_ECC_UNCORRECTABLE              = 214,

  /**
   * This indicates that the ::CUlimit passed to the API call is not
   * supported by the active device.
   */
  CUDA_ERROR_UNSUPPORTED_LIMIT              = 215,

  /**
   * This indicates that the ::CUcontext passed to the API call can
   * only be bound to a single CPU thread at a time but is already
   * bound to a CPU thread.
   */
  CUDA_ERROR_CONTEXT_ALREADY_IN_USE         = 216,

  /**
   * This indicates that peer access is not supported across the given
   * devices.
   */
  CUDA_ERROR_PEER_ACCESS_UNSUPPORTED        = 217,

  /**
   * This indicates that a PTX JIT compilation failed.
   */
  CUDA_ERROR_INVALID_PTX                    = 218,

  /**
   * This indicates an error with OpenGL or DirectX context.
   */
  CUDA_ERROR_INVALID_GRAPHICS_CONTEXT       = 219,

  /**
  * This indicates that an uncorrectable NVLink error was detected during the
  * execution.
  */
  CUDA_ERROR_NVLINK_UNCORRECTABLE           = 220,

  /**
  * This indicates that the PTX JIT compiler library was not found.
  */
  CUDA_ERROR_JIT_COMPILER_NOT_FOUND         = 221,

  /**
   * This indicates that the device kernel source is invalid.
   */
  CUDA_ERROR_INVALID_SOURCE                 = 300,

  /**
   * This indicates that the file specified was not found.
   */
  CUDA_ERROR_FILE_NOT_FOUND                 = 301,

  /**
   * This indicates that a link to a shared object failed to resolve.
   */
  CUDA_ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND = 302,

  /**
   * This indicates that initialization of a shared object failed.
   */
  CUDA_ERROR_SHARED_OBJECT_INIT_FAILED      = 303,

  /**
   * This indicates that an OS call failed.
   */
  CUDA_ERROR_OPERATING_SYSTEM               = 304,

  /**
   * This indicates that a resource handle passed to the API call was not
   * valid. Resource handles are opaque types like ::CUstream and ::CUevent.
   */
  CUDA_ERROR_INVALID_HANDLE                 = 400,

  /**
   * This indicates that a resource required by the API call is not in a
   * valid state to perform the requested operation.
   */
  CUDA_ERROR_ILLEGAL_STATE                  = 401,

  /**
   * This indicates that a named symbol was not found. Examples of symbols
   * are global/constant variable names, texture names, and surface names.
   */
  CUDA_ERROR_NOT_FOUND                      = 500,

  /**
   * This indicates that asynchronous operations issued previously have not
   * completed yet. This result is not actually an error, but must be indicated
   * differently than ::CUDA_SUCCESS (which indicates completion). Calls that
   * may return this value include ::cuEventQuery() and ::cuStreamQuery().
   */
  CUDA_ERROR_NOT_READY                      = 600,

  /**
   * While executing a kernel, the device encountered a
   * load or store instruction on an invalid memory address.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_ILLEGAL_ADDRESS                = 700,

  /**
   * This indicates that a launch did not occur because it did not have
   * appropriate resources. This error usually indicates that the user has
   * attempted to pass too many arguments to the device kernel, or the
   * kernel launch specifies too many threads for the kernel's register
   * count. Passing arguments of the wrong size (i.e. a 64-bit pointer
   * when a 32-bit int is expected) is equivalent to passing too many
   * arguments and can also result in this error.
   */
  CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES        = 701,

  /**
   * This indicates that the device kernel took too long to execute. This can
   * only occur if timeouts are enabled - see the device attribute
   * ::CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT for more information.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_LAUNCH_TIMEOUT                 = 702,

  /**
   * This error indicates a kernel launch that uses an incompatible texturing
   * mode.
   */
  CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING  = 703,

  /**
   * This error indicates that a call to ::cuCtxEnablePeerAccess() is
   * trying to re-enable peer access to a context which has already
   * had peer access to it enabled.
   */
  CUDA_ERROR_PEER_ACCESS_ALREADY_ENABLED    = 704,

  /**
   * This error indicates that ::cuCtxDisablePeerAccess() is
   * trying to disable peer access which has not been enabled yet
   * via ::cuCtxEnablePeerAccess().
   */
  CUDA_ERROR_PEER_ACCESS_NOT_ENABLED        = 705,

  /**
   * This error indicates that the primary context for the specified device
   * has already been initialized.
   */
  CUDA_ERROR_PRIMARY_CONTEXT_ACTIVE         = 708,

  /**
   * This error indicates that the context current to the calling thread
   * has been destroyed using ::cuCtxDestroy, or is a primary context which
   * has not yet been initialized.
   */
  CUDA_ERROR_CONTEXT_IS_DESTROYED           = 709,

  /**
   * A device-side assert triggered during kernel execution. The context
   * cannot be used anymore, and must be destroyed. All existing device
   * memory allocations from this context are invalid and must be
   * reconstructed if the program is to continue using CUDA.
   */
  CUDA_ERROR_ASSERT                         = 710,

  /**
   * This error indicates that the hardware resources required to enable
   * peer access have been exhausted for one or more of the devices
   * passed to ::cuCtxEnablePeerAccess().
   */
  CUDA_ERROR_TOO_MANY_PEERS                 = 711,

  /**
   * This error indicates that the memory range passed to ::cuMemHostRegister()
   * has already been registered.
   */
  CUDA_ERROR_HOST_MEMORY_ALREADY_REGISTERED = 712,

  /**
   * This error indicates that the pointer passed to ::cuMemHostUnregister()
   * does not correspond to any currently registered memory region.
   */
  CUDA_ERROR_HOST_MEMORY_NOT_REGISTERED     = 713,

  /**
   * While executing a kernel, the device encountered a stack error.
   * This can be due to stack corruption or exceeding the stack size limit.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_HARDWARE_STACK_ERROR           = 714,

  /**
   * While executing a kernel, the device encountered an illegal instruction.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_ILLEGAL_INSTRUCTION            = 715,

  /**
   * While executing a kernel, the device encountered a load or store instruction
   * on a memory address which is not aligned.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_MISALIGNED_ADDRESS             = 716,

  /**
   * While executing a kernel, the device encountered an instruction
   * which can only operate on memory locations in certain address spaces
   * (global, shared, or local), but was supplied a memory address not
   * belonging to an allowed address space.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_INVALID_ADDRESS_SPACE          = 717,

  /**
   * While executing a kernel, the device program counter wrapped its address space.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_INVALID_PC                     = 718,

  /**
   * An exception occurred on the device while executing a kernel. Common
   * causes include dereferencing an invalid device pointer and accessing
   * out of bounds shared memory. Less common cases can be system specific - more
   * information about these cases can be found in the system specific user guide.
   * This leaves the process in an inconsistent state and any further CUDA work
   * will return the same error. To continue using CUDA, the process must be terminated
   * and relaunched.
   */
  CUDA_ERROR_LAUNCH_FAILED                  = 719,

  /**
   * This error indicates that the number of blocks launched per grid for a kernel that was
   * launched via either ::cuLaunchCooperativeKernel or ::cuLaunchCooperativeKernelMultiDevice
   * exceeds the maximum number of blocks as allowed by ::cuOccupancyMaxActiveBlocksPerMultiprocessor
   * or ::cuOccupancyMaxActiveBlocksPerMultiprocessorWithFlags times the number of multiprocessors
   * as specified by the device attribute ::CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT.
   */
  CUDA_ERROR_COOPERATIVE_LAUNCH_TOO_LARGE   = 720,

  /**
   * This error indicates that the attempted operation is not permitted.
   */
  CUDA_ERROR_NOT_PERMITTED                  = 800,

  /**
   * This error indicates that the attempted operation is not supported
   * on the current system or device.
   */
  CUDA_ERROR_NOT_SUPPORTED                  = 801,

  /**
   * This error indicates that the system is not yet ready to start any CUDA
   * work.  To continue using CUDA, verify the system configuration is in a
   * valid state and all required driver daemons are actively running.
   * More information about this error can be found in the system specific
   * user guide.
   */
  CUDA_ERROR_SYSTEM_NOT_READY               = 802,

  /**
   * This error indicates that there is a mismatch between the versions of
   * the display driver and the CUDA driver. Refer to the compatibility documentation
   * for supported versions.
   */
  CUDA_ERROR_SYSTEM_DRIVER_MISMATCH         = 803,

  /**
   * This error indicates that the system was upgraded to run with forward compatibility
   * but the visible hardware detected by CUDA does not support this configuration.
   * Refer to the compatibility documentation for the supported hardware matrix or ensure
   * that only supported hardware is visible during initialization via the CUDA_VISIBLE_DEVICES
   * environment variable.
   */
  CUDA_ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE = 804,

  /**
   * This error indicates that the operation is not permitted when
   * the stream is capturing.
   */
  CUDA_ERROR_STREAM_CAPTURE_UNSUPPORTED     = 900,

  /**
   * This error indicates that the current capture sequence on the stream
   * has been invalidated due to a previous error.
   */
  CUDA_ERROR_STREAM_CAPTURE_INVALIDATED     = 901,

  /**
   * This error indicates that the operation would have resulted in a merge
   * of two independent capture sequences.
   */
  CUDA_ERROR_STREAM_CAPTURE_MERGE           = 902,

  /**
   * This error indicates that the capture was not initiated in this stream.
   */
  CUDA_ERROR_STREAM_CAPTURE_UNMATCHED       = 903,

  /**
   * This error indicates that the capture sequence contains a fork that was
   * not joined to the primary stream.
   */
  CUDA_ERROR_STREAM_CAPTURE_UNJOINED        = 904,

  /**
   * This error indicates that a dependency would have been created which
   * crosses the capture sequence boundary. Only implicit in-stream ordering
   * dependencies are allowed to cross the boundary.
   */
  CUDA_ERROR_STREAM_CAPTURE_ISOLATION       = 905,

  /**
   * This error indicates a disallowed implicit dependency on a current capture
   * sequence from cudaStreamLegacy.
   */
  CUDA_ERROR_STREAM_CAPTURE_IMPLICIT        = 906,

  /**
   * This error indicates that the operation is not permitted on an event which
   * was last recorded in a capturing stream.
   */
  CUDA_ERROR_CAPTURED_EVENT                 = 907,

  /**
   * A stream capture sequence not initiated with the ::CU_STREAM_CAPTURE_MODE_RELAXED
   * argument to ::cuStreamBeginCapture was passed to ::cuStreamEndCapture in a
   * different thread.
   */
  CUDA_ERROR_STREAM_CAPTURE_WRONG_THREAD    = 908,

  /**
   * This indicates that an unknown internal error has occurred.
   */
  CUDA_ERROR_UNKNOWN                        = 999

} CUresult;

/**
 * Online compiler and linker options
 */
typedef enum CUjit_option_enum
{
  /**
   * Max number of registers that a thread may use.\n
   * Option type: unsigned int\n
   * Applies to: compiler only
   */
  CU_JIT_MAX_REGISTERS = 0,

  /**
   * IN: Specifies minimum number of threads per block to target compilation
   * for\n
   * OUT: Returns the number of threads the compiler actually targeted.
   * This restricts the resource utilization fo the compiler (e.g. max
   * registers) such that a block with the given number of threads should be
   * able to launch based on register limitations. Note, this option does not
   * currently take into account any other resource limitations, such as
   * shared memory utilization.\n
   * Cannot be combined with ::CU_JIT_TARGET.\n
   * Option type: unsigned int\n
   * Applies to: compiler only
   */
  CU_JIT_THREADS_PER_BLOCK,

  /**
   * Overwrites the option value with the total wall clock time, in
   * milliseconds, spent in the compiler and linker\n
   * Option type: float\n
   * Applies to: compiler and linker
   */
  CU_JIT_WALL_TIME,

  /**
   * Pointer to a buffer in which to print any log messages
   * that are informational in nature (the buffer size is specified via
   * option ::CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES)\n
   * Option type: char *\n
   * Applies to: compiler and linker
   */
  CU_JIT_INFO_LOG_BUFFER,

  /**
   * IN: Log buffer size in bytes.  Log messages will be capped at this size
   * (including null terminator)\n
   * OUT: Amount of log buffer filled with messages\n
   * Option type: unsigned int\n
   * Applies to: compiler and linker
   */
  CU_JIT_INFO_LOG_BUFFER_SIZE_BYTES,

  /**
   * Pointer to a buffer in which to print any log messages that
   * reflect errors (the buffer size is specified via option
   * ::CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES)\n
   * Option type: char *\n
   * Applies to: compiler and linker
   */
  CU_JIT_ERROR_LOG_BUFFER,

  /**
   * IN: Log buffer size in bytes.  Log messages will be capped at this size
   * (including null terminator)\n
   * OUT: Amount of log buffer filled with messages\n
   * Option type: unsigned int\n
   * Applies to: compiler and linker
   */
  CU_JIT_ERROR_LOG_BUFFER_SIZE_BYTES,

  /**
   * Level of optimizations to apply to generated code (0 - 4), with 4
   * being the default and highest level of optimizations.\n
   * Option type: unsigned int\n
   * Applies to: compiler only
   */
  CU_JIT_OPTIMIZATION_LEVEL,

  /**
   * No option value required. Determines the target based on the current
   * attached context (default)\n
   * Option type: No option value needed\n
   * Applies to: compiler and linker
   */
  CU_JIT_TARGET_FROM_CUCONTEXT,

  /**
   * Target is chosen based on supplied ::CUjit_target.  Cannot be
   * combined with ::CU_JIT_THREADS_PER_BLOCK.\n
   * Option type: unsigned int for enumerated type ::CUjit_target\n
   * Applies to: compiler and linker
   */
  CU_JIT_TARGET,

  /**
   * Specifies choice of fallback strategy if matching cubin is not found.
   * Choice is based on supplied ::CUjit_fallback.  This option cannot be
   * used with cuLink* APIs as the linker requires exact matches.\n
   * Option type: unsigned int for enumerated type ::CUjit_fallback\n
   * Applies to: compiler only
   */
  CU_JIT_FALLBACK_STRATEGY,

  /**
   * Specifies whether to create debug information in output (-g)
   * (0: false, default)\n
   * Option type: int\n
   * Applies to: compiler and linker
   */
  CU_JIT_GENERATE_DEBUG_INFO,

  /**
   * Generate verbose log messages (0: false, default)\n
   * Option type: int\n
   * Applies to: compiler and linker
   */
  CU_JIT_LOG_VERBOSE,

  /**
   * Generate line number information (-lineinfo) (0: false, default)\n
   * Option type: int\n
   * Applies to: compiler only
   */
  CU_JIT_GENERATE_LINE_INFO,

  /**
   * Specifies whether to enable caching explicitly (-dlcm) \n
   * Choice is based on supplied ::CUjit_cacheMode_enum.\n
   * Option type: unsigned int for enumerated type ::CUjit_cacheMode_enum\n
   * Applies to: compiler only
   */
  CU_JIT_CACHE_MODE,

  /**
   * The below jit options are used for internal purposes only, in this version of CUDA
   */
  CU_JIT_NEW_SM3X_OPT,
  CU_JIT_FAST_COMPILE,

  /**
   * Array of device symbol names that will be relocated to the corresponing
   * host addresses stored in ::CU_JIT_GLOBAL_SYMBOL_ADDRESSES.\n
   * Must contain ::CU_JIT_GLOBAL_SYMBOL_COUNT entries.\n
   * When loding a device module, driver will relocate all encountered
   * unresolved symbols to the host addresses.\n
   * It is only allowed to register symbols that correspond to unresolved
   * global variables.\n
   * It is illegal to register the same device symbol at multiple addresses.\n
   * Option type: const char **\n
   * Applies to: dynamic linker only
   */
  CU_JIT_GLOBAL_SYMBOL_NAMES,

  /**
   * Array of host addresses that will be used to relocate corresponding
   * device symbols stored in ::CU_JIT_GLOBAL_SYMBOL_NAMES.\n
   * Must contain ::CU_JIT_GLOBAL_SYMBOL_COUNT entries.\n
   * Option type: void **\n
   * Applies to: dynamic linker only
   */
  CU_JIT_GLOBAL_SYMBOL_ADDRESSES,

  /**
   * Number of entries in ::CU_JIT_GLOBAL_SYMBOL_NAMES and
   * ::CU_JIT_GLOBAL_SYMBOL_ADDRESSES arrays.\n
   * Option type: unsigned int\n
   * Applies to: dynamic linker only
   */
  CU_JIT_GLOBAL_SYMBOL_COUNT,

  CU_JIT_NUM_OPTIONS

} CUjit_option;

/**
 * Device properties
 */
typedef enum CUdevice_attribute_enum
{
  CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 1,              /**< Maximum number of threads per block */
  CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X = 2,                    /**< Maximum block dimension X */
  CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y = 3,                    /**< Maximum block dimension Y */
  CU_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z = 4,                    /**< Maximum block dimension Z */
  CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X = 5,                     /**< Maximum grid dimension X */
  CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y = 6,                     /**< Maximum grid dimension Y */
  CU_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z = 7,                     /**< Maximum grid dimension Z */
  CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK = 8,        /**< Maximum shared memory available per block in bytes */
  CU_DEVICE_ATTRIBUTE_SHARED_MEMORY_PER_BLOCK = 8,            /**< Deprecated, use CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK */
  CU_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY = 9,              /**< Memory available on device for __constant__ variables in a CUDA C kernel in bytes */
  CU_DEVICE_ATTRIBUTE_WARP_SIZE = 10,                         /**< Warp size in threads */
  CU_DEVICE_ATTRIBUTE_MAX_PITCH = 11,                         /**< Maximum pitch in bytes allowed by memory copies */
  CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK = 12,           /**< Maximum number of 32-bit registers available per block */
  CU_DEVICE_ATTRIBUTE_REGISTERS_PER_BLOCK = 12,               /**< Deprecated, use CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK */
  CU_DEVICE_ATTRIBUTE_CLOCK_RATE = 13,                        /**< Typical clock frequency in kilohertz */
  CU_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT = 14,                 /**< Alignment requirement for textures */
  CU_DEVICE_ATTRIBUTE_GPU_OVERLAP = 15,                       /**< Device can possibly copy memory and execute a kernel concurrently. Deprecated. Use instead CU_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT. */
  CU_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT = 16,              /**< Number of multiprocessors on device */
  CU_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT = 17,               /**< Specifies whether there is a run time limit on kernels */
  CU_DEVICE_ATTRIBUTE_INTEGRATED = 18,                        /**< Device is integrated with host memory */
  CU_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY = 19,               /**< Device can map host memory into CUDA address space */
  CU_DEVICE_ATTRIBUTE_COMPUTE_MODE = 20,                      /**< Compute mode (See ::CUcomputemode for details) */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_WIDTH = 21,           /**< Maximum 1D texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_WIDTH = 22,           /**< Maximum 2D texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_HEIGHT = 23,          /**< Maximum 2D texture height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH = 24,           /**< Maximum 3D texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT = 25,          /**< Maximum 3D texture height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH = 26,           /**< Maximum 3D texture depth */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_WIDTH = 27,   /**< Maximum 2D layered texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_HEIGHT = 28,  /**< Maximum 2D layered texture height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_LAYERS = 29,  /**< Maximum layers in a 2D layered texture */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_WIDTH = 27,     /**< Deprecated, use CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_WIDTH */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_HEIGHT = 28,    /**< Deprecated, use CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_HEIGHT */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_NUMSLICES = 29, /**< Deprecated, use CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_LAYERS */
  CU_DEVICE_ATTRIBUTE_SURFACE_ALIGNMENT = 30,                 /**< Alignment requirement for surfaces */
  CU_DEVICE_ATTRIBUTE_CONCURRENT_KERNELS = 31,                /**< Device can possibly execute multiple kernels concurrently */
  CU_DEVICE_ATTRIBUTE_ECC_ENABLED = 32,                       /**< Device has ECC support enabled */
  CU_DEVICE_ATTRIBUTE_PCI_BUS_ID = 33,                        /**< PCI bus ID of the device */
  CU_DEVICE_ATTRIBUTE_PCI_DEVICE_ID = 34,                     /**< PCI device ID of the device */
  CU_DEVICE_ATTRIBUTE_TCC_DRIVER = 35,                        /**< Device is using TCC driver model */
  CU_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE = 36,                 /**< Peak memory clock frequency in kilohertz */
  CU_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH = 37,           /**< Global memory bus width in bits */
  CU_DEVICE_ATTRIBUTE_L2_CACHE_SIZE = 38,                     /**< Size of L2 cache in bytes */
  CU_DEVICE_ATTRIBUTE_MAX_THREADS_PER_MULTIPROCESSOR = 39,    /**< Maximum resident threads per multiprocessor */
  CU_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT = 40,                /**< Number of asynchronous engines */
  CU_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING = 41,                /**< Device shares a unified address space with the host */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_WIDTH = 42,   /**< Maximum 1D layered texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_LAYERS = 43,  /**< Maximum layers in a 1D layered texture */
  CU_DEVICE_ATTRIBUTE_CAN_TEX2D_GATHER = 44,                  /**< Deprecated, do not use. */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_WIDTH = 45,    /**< Maximum 2D texture width if CUDA_ARRAY3D_TEXTURE_GATHER is set */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_HEIGHT = 46,   /**< Maximum 2D texture height if CUDA_ARRAY3D_TEXTURE_GATHER is set */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH_ALTERNATE = 47, /**< Alternate maximum 3D texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT_ALTERNATE = 48,/**< Alternate maximum 3D texture height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH_ALTERNATE = 49, /**< Alternate maximum 3D texture depth */
  CU_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID = 50,                     /**< PCI domain ID of the device */
  CU_DEVICE_ATTRIBUTE_TEXTURE_PITCH_ALIGNMENT = 51,           /**< Pitch alignment requirement for textures */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_WIDTH = 52,      /**< Maximum cubemap texture width/height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_WIDTH = 53,  /**< Maximum cubemap layered texture width/height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_LAYERS = 54, /**< Maximum layers in a cubemap layered texture */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_WIDTH = 55,           /**< Maximum 1D surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_WIDTH = 56,           /**< Maximum 2D surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_HEIGHT = 57,          /**< Maximum 2D surface height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_WIDTH = 58,           /**< Maximum 3D surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_HEIGHT = 59,          /**< Maximum 3D surface height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_DEPTH = 60,           /**< Maximum 3D surface depth */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_WIDTH = 61,   /**< Maximum 1D layered surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_LAYERS = 62,  /**< Maximum layers in a 1D layered surface */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_WIDTH = 63,   /**< Maximum 2D layered surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_HEIGHT = 64,  /**< Maximum 2D layered surface height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_LAYERS = 65,  /**< Maximum layers in a 2D layered surface */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_WIDTH = 66,      /**< Maximum cubemap surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_WIDTH = 67,  /**< Maximum cubemap layered surface width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_LAYERS = 68, /**< Maximum layers in a cubemap layered surface */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LINEAR_WIDTH = 69,    /**< Maximum 1D linear texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_WIDTH = 70,    /**< Maximum 2D linear texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_HEIGHT = 71,   /**< Maximum 2D linear texture height */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_PITCH = 72,    /**< Maximum 2D linear texture pitch in bytes */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_WIDTH = 73, /**< Maximum mipmapped 2D texture width */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_HEIGHT = 74,/**< Maximum mipmapped 2D texture height */
  CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 75,          /**< Major compute capability version number */
  CU_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 76,          /**< Minor compute capability version number */
  CU_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_MIPMAPPED_WIDTH = 77, /**< Maximum mipmapped 1D texture width */
  CU_DEVICE_ATTRIBUTE_STREAM_PRIORITIES_SUPPORTED = 78,       /**< Device supports stream priorities */
  CU_DEVICE_ATTRIBUTE_GLOBAL_L1_CACHE_SUPPORTED = 79,         /**< Device supports caching globals in L1 */
  CU_DEVICE_ATTRIBUTE_LOCAL_L1_CACHE_SUPPORTED = 80,          /**< Device supports caching locals in L1 */
  CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_MULTIPROCESSOR = 81,  /**< Maximum shared memory available per multiprocessor in bytes */
  CU_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_MULTIPROCESSOR = 82,  /**< Maximum number of 32-bit registers available per multiprocessor */
  CU_DEVICE_ATTRIBUTE_MANAGED_MEMORY = 83,                    /**< Device can allocate managed memory on this system */
  CU_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD = 84,                    /**< Device is on a multi-GPU board */
  CU_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD_GROUP_ID = 85,           /**< Unique id for a group of devices on the same multi-GPU board */
  CU_DEVICE_ATTRIBUTE_HOST_NATIVE_ATOMIC_SUPPORTED = 86,       /**< Link between the device and the host supports native atomic operations (this is a placeholder attribute, and is not supported on any current hardware)*/
  CU_DEVICE_ATTRIBUTE_SINGLE_TO_DOUBLE_PRECISION_PERF_RATIO = 87,  /**< Ratio of single precision performance (in floating-point operations per second) to double precision performance */
  CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS = 88,            /**< Device supports coherently accessing pageable memory without calling cudaHostRegister on it */
  CU_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS = 89,         /**< Device can coherently access managed memory concurrently with the CPU */
  CU_DEVICE_ATTRIBUTE_COMPUTE_PREEMPTION_SUPPORTED = 90,      /**< Device supports compute preemption. */
  CU_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM = 91, /**< Device can access host registered memory at the same virtual address as the CPU */
  CU_DEVICE_ATTRIBUTE_CAN_USE_STREAM_MEM_OPS = 92,            /**< ::cuStreamBatchMemOp and related APIs are supported. */
  CU_DEVICE_ATTRIBUTE_CAN_USE_64_BIT_STREAM_MEM_OPS = 93,     /**< 64-bit operations are supported in ::cuStreamBatchMemOp and related APIs. */
  CU_DEVICE_ATTRIBUTE_CAN_USE_STREAM_WAIT_VALUE_NOR = 94,     /**< ::CU_STREAM_WAIT_VALUE_NOR is supported. */
  CU_DEVICE_ATTRIBUTE_COOPERATIVE_LAUNCH = 95,                /**< Device supports launching cooperative kernels via ::cuLaunchCooperativeKernel */
  CU_DEVICE_ATTRIBUTE_COOPERATIVE_MULTI_DEVICE_LAUNCH = 96,   /**< Device can participate in cooperative kernels launched via ::cuLaunchCooperativeKernelMultiDevice */
  CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK_OPTIN = 97, /**< Maximum optin shared memory per block */
  CU_DEVICE_ATTRIBUTE_CAN_FLUSH_REMOTE_WRITES = 98,           /**< Both the ::CU_STREAM_WAIT_VALUE_FLUSH flag and the ::CU_STREAM_MEM_OP_FLUSH_REMOTE_WRITES MemOp are supported on the device. See \ref CUDA_MEMOP for additional details. */
  CU_DEVICE_ATTRIBUTE_HOST_REGISTER_SUPPORTED = 99,           /**< Device supports host memory registration via ::cudaHostRegister. */
  CU_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES = 100, /**< Device accesses pageable memory via the host's page tables. */
  CU_DEVICE_ATTRIBUTE_DIRECT_MANAGED_MEM_ACCESS_FROM_HOST = 101, /**< The host can directly access managed memory on the device without migration. */
  CU_DEVICE_ATTRIBUTE_MAX

} CUdevice_attribute;

/**
 * Function cache configurations
 */
typedef enum CUfunc_cache_enum
{
  CU_FUNC_CACHE_PREFER_NONE    = 0x00, /**< no preference for shared memory or L1 (default) */
  CU_FUNC_CACHE_PREFER_SHARED  = 0x01, /**< prefer larger shared memory and smaller L1 cache */
  CU_FUNC_CACHE_PREFER_L1      = 0x02, /**< prefer larger L1 cache and smaller shared memory */
  CU_FUNC_CACHE_PREFER_EQUAL   = 0x03  /**< prefer equal sized L1 cache and shared memory */

} CUfunc_cache;

/**
 * Shared memory configurations
 */
typedef enum CUsharedconfig_enum
{
  CU_SHARED_MEM_CONFIG_DEFAULT_BANK_SIZE    = 0x00, /**< set default shared memory bank size */
  CU_SHARED_MEM_CONFIG_FOUR_BYTE_BANK_SIZE  = 0x01, /**< set shared memory bank width to four bytes */
  CU_SHARED_MEM_CONFIG_EIGHT_BYTE_BANK_SIZE = 0x02  /**< set shared memory bank width to eight bytes */

} CUsharedconfig;

/**
 * Function properties
 */
typedef enum CUfunction_attribute_enum
{
  /**
   * The maximum number of threads per block, beyond which a launch of the
   * function would fail. This number depends on both the function and the
   * device on which the function is currently loaded.
   */
  CU_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 0,

  /**
   * The size in bytes of statically-allocated shared memory required by
   * this function. This does not include dynamically-allocated shared
   * memory requested by the user at runtime.
   */
  CU_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES = 1,

  /**
   * The size in bytes of user-allocated constant memory required by this
   * function.
   */
  CU_FUNC_ATTRIBUTE_CONST_SIZE_BYTES = 2,

  /**
   * The size in bytes of local memory used by each thread of this function.
   */
  CU_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES = 3,

  /**
   * The number of registers used by each thread of this function.
   */
  CU_FUNC_ATTRIBUTE_NUM_REGS = 4,

  /**
   * The PTX virtual architecture version for which the function was
   * compiled. This value is the major PTX version * 10 + the minor PTX
   * version, so a PTX version 1.3 function would return the value 13.
   * Note that this may return the undefined value of 0 for cubins
   * compiled prior to CUDA 3.0.
   */
  CU_FUNC_ATTRIBUTE_PTX_VERSION = 5,

  /**
   * The binary architecture version for which the function was compiled.
   * This value is the major binary version * 10 + the minor binary version,
   * so a binary version 1.3 function would return the value 13. Note that
   * this will return a value of 10 for legacy cubins that do not have a
   * properly-encoded binary architecture version.
   */
  CU_FUNC_ATTRIBUTE_BINARY_VERSION = 6,

  /**
   * The attribute to indicate whether the function has been compiled with
   * user specified option "-Xptxas --dlcm=ca" set .
   */
  CU_FUNC_ATTRIBUTE_CACHE_MODE_CA = 7,

  /**
   * The maximum size in bytes of dynamically-allocated shared memory that can be used by
   * this function. If the user-specified dynamic shared memory size is larger than this
   * value, the launch will fail.
   * See ::cuFuncSetAttribute
   */
  CU_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES = 8,

  /**
   * On devices where the L1 cache and shared memory use the same hardware resources,
   * this sets the shared memory carveout preference, in percent of the total shared memory.
   * Refer to ::CU_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_MULTIPROCESSOR.
   * This is only a hint, and the driver can choose a different ratio if required to execute the function.
   * See ::cuFuncSetAttribute
   */
  CU_FUNC_ATTRIBUTE_PREFERRED_SHARED_MEMORY_CARVEOUT = 9,

  CU_FUNC_ATTRIBUTE_MAX

} CUfunction_attribute;

/**
 * Context creation flags
 */
typedef enum CUctx_flags_enum
{
  CU_CTX_SCHED_AUTO          = 0x00, /**< Automatic scheduling */
  CU_CTX_SCHED_SPIN          = 0x01, /**< Set spin as default scheduling */
  CU_CTX_SCHED_YIELD         = 0x02, /**< Set yield as default scheduling */
  CU_CTX_SCHED_BLOCKING_SYNC = 0x04, /**< Set blocking synchronization as default scheduling */
  CU_CTX_BLOCKING_SYNC       = 0x04, /**< Set blocking synchronization as default scheduling
                                       *  \deprecated This flag was deprecated as of CUDA 4.0
                                       *  and was replaced with ::CU_CTX_SCHED_BLOCKING_SYNC. */
  CU_CTX_SCHED_MASK          = 0x07,
  CU_CTX_MAP_HOST            = 0x08, /**< Support mapped pinned allocations */
  CU_CTX_LMEM_RESIZE_TO_MAX  = 0x10, /**< Keep local memory allocation after launch */
  CU_CTX_FLAGS_MASK          = 0x1f

} CUctx_flags;

/**
 * Stream creation flags
 */
typedef enum CUstream_flags_enum
{
  CU_STREAM_DEFAULT      = 0x0, /**< Default stream flag */
  CU_STREAM_NON_BLOCKING = 0x1  /**< Stream does not synchronize with stream 0 (the NULL stream) */

} CUstream_flags;

/**
 * Event creation flags
 */
typedef enum CUevent_flags_enum
{
  CU_EVENT_DEFAULT        = 0x0, /**< Default event flag */
  CU_EVENT_BLOCKING_SYNC  = 0x1, /**< Event uses blocking synchronization */
  CU_EVENT_DISABLE_TIMING = 0x2, /**< Event will not record timing data */
  CU_EVENT_INTERPROCESS   = 0x4  /**< Event is suitable for interprocess use. CU_EVENT_DISABLE_TIMING must be set */

} CUevent_flags;

typedef enum CUjitInputType_enum
{
  /**
   * Compiled device-class-specific device code\n
   * Applicable options: none
   */
  CU_JIT_INPUT_CUBIN = 0,

  /**
   * PTX source code\n
   * Applicable options: PTX compiler options
   */
  CU_JIT_INPUT_PTX,

  /**
   * Bundle of multiple cubins and/or PTX of some device code\n
   * Applicable options: PTX compiler options, ::CU_JIT_FALLBACK_STRATEGY
   */
  CU_JIT_INPUT_FATBINARY,

  /**
   * Host object with embedded device code\n
   * Applicable options: PTX compiler options, ::CU_JIT_FALLBACK_STRATEGY
   */
  CU_JIT_INPUT_OBJECT,

  /**
   * Archive of host objects with embedded device code\n
   * Applicable options: PTX compiler options, ::CU_JIT_FALLBACK_STRATEGY
   */
  CU_JIT_INPUT_LIBRARY,

  CU_JIT_NUM_INPUT_TYPES

} CUjitInputType;

#ifdef _WIN32
#define CUDAAPI __stdcall
#else
#define CUDAAPI
#endif

#define CUDA_API_CALL CUDAAPI

typedef CUresult (CUDA_API_CALL *CUDA_CUCTXCREATE)              (CUcontext *, unsigned int, CUdevice);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXDESTROY)             (CUcontext);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXGETCACHECONFIG)      (CUfunc_cache *);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXGETCURRENT)          (CUcontext *);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXGETSHAREDMEMCONFIG)  (CUsharedconfig *);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXPOPCURRENT)          (CUcontext *);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXPUSHCURRENT)         (CUcontext);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXSETCACHECONFIG)      (CUfunc_cache);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXSETCURRENT)          (CUcontext);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXSETSHAREDMEMCONFIG)  (CUsharedconfig);
typedef CUresult (CUDA_API_CALL *CUDA_CUCTXSYNCHRONIZE)         ();
typedef CUresult (CUDA_API_CALL *CUDA_CUDEVICEGETATTRIBUTE)     (int *, CUdevice_attribute, CUdevice);
typedef CUresult (CUDA_API_CALL *CUDA_CUDEVICEGETCOUNT)         (int *);
typedef CUresult (CUDA_API_CALL *CUDA_CUDEVICEGET)              (CUdevice *, int);
typedef CUresult (CUDA_API_CALL *CUDA_CUDEVICEGETNAME)          (char *, int, CUdevice);
typedef CUresult (CUDA_API_CALL *CUDA_CUDEVICETOTALMEM)         (size_t *, CUdevice);
typedef CUresult (CUDA_API_CALL *CUDA_CUDRIVERGETVERSION)       (int *);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTCREATE)            (CUevent *, unsigned int);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTDESTROY)           (CUevent);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTELAPSEDTIME)       (float *, CUevent, CUevent);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTQUERY)             (CUevent);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTRECORD)            (CUevent, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUEVENTSYNCHRONIZE)       (CUevent);
typedef CUresult (CUDA_API_CALL *CUDA_CUFUNCGETATTRIBUTE)       (int *, CUfunction_attribute, CUfunction);
typedef CUresult (CUDA_API_CALL *CUDA_CUFUNCSETATTRIBUTE)       (CUfunction, CUfunction_attribute, int);
typedef CUresult (CUDA_API_CALL *CUDA_CUFUNCSETCACHECONFIG)     (CUfunction, CUfunc_cache);
typedef CUresult (CUDA_API_CALL *CUDA_CUFUNCSETSHAREDMEMCONFIG) (CUfunction, CUsharedconfig);
typedef CUresult (CUDA_API_CALL *CUDA_CUGETERRORNAME)           (CUresult, const char **);
typedef CUresult (CUDA_API_CALL *CUDA_CUGETERRORSTRING)         (CUresult, const char **);
typedef CUresult (CUDA_API_CALL *CUDA_CUINIT)                   (unsigned int);
typedef CUresult (CUDA_API_CALL *CUDA_CULAUNCHKERNEL)           (CUfunction, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, CUstream, void **, void **);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMALLOC)               (CUdeviceptr *, size_t);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMALLOCHOST)           (void **, size_t);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMCPYDTODASYNC)        (CUdeviceptr, CUdeviceptr, size_t, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMCPYDTOHASYNC)        (void *, CUdeviceptr, size_t, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMCPYHTODASYNC)        (CUdeviceptr, const void *, size_t, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMFREE)                (CUdeviceptr);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMFREEHOST)            (void *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMGETINFO)             (size_t *, size_t *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMSETD32ASYNC)         (CUdeviceptr, unsigned int, size_t, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUMEMSETD8ASYNC)          (CUdeviceptr, unsigned char, size_t, CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULEGETFUNCTION)      (CUfunction *, CUmodule, const char *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULEGETGLOBAL)        (CUdeviceptr *, size_t *, CUmodule, const char *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULELOAD)             (CUmodule *, const char *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULELOADDATA)         (CUmodule *, const void *);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULELOADDATAEX)       (CUmodule *, const void *, unsigned int, CUjit_option *, void **);
typedef CUresult (CUDA_API_CALL *CUDA_CUMODULEUNLOAD)           (CUmodule);
typedef CUresult (CUDA_API_CALL *CUDA_CUPROFILERSTART)          ();
typedef CUresult (CUDA_API_CALL *CUDA_CUPROFILERSTOP)           ();
typedef CUresult (CUDA_API_CALL *CUDA_CUSTREAMCREATE)           (CUstream *, unsigned int);
typedef CUresult (CUDA_API_CALL *CUDA_CUSTREAMDESTROY)          (CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUSTREAMSYNCHRONIZE)      (CUstream);
typedef CUresult (CUDA_API_CALL *CUDA_CUSTREAMWAITEVENT)        (CUstream, CUevent, unsigned int);
typedef CUresult (CUDA_API_CALL *CUDA_CULINKCREATE)             (unsigned int, CUjit_option *, void **, CUlinkState *);
typedef CUresult (CUDA_API_CALL *CUDA_CULINKADDDATA)            (CUlinkState, CUjitInputType, void *, size_t, const char *, unsigned int, CUjit_option *, void **);
typedef CUresult (CUDA_API_CALL *CUDA_CULINKDESTROY)            (CUlinkState);
typedef CUresult (CUDA_API_CALL *CUDA_CULINKCOMPLETE)           (CUlinkState, void **, size_t *);

typedef struct hc_cuda_lib
{
  hc_dynlib_t lib;

  CUDA_CUCTXCREATE              cuCtxCreate;
  CUDA_CUCTXDESTROY             cuCtxDestroy;
  CUDA_CUCTXGETCACHECONFIG      cuCtxGetCacheConfig;
  CUDA_CUCTXGETCURRENT          cuCtxGetCurrent;
  CUDA_CUCTXGETSHAREDMEMCONFIG  cuCtxGetSharedMemConfig;
  CUDA_CUCTXPOPCURRENT          cuCtxPopCurrent;
  CUDA_CUCTXPUSHCURRENT         cuCtxPushCurrent;
  CUDA_CUCTXSETCACHECONFIG      cuCtxSetCacheConfig;
  CUDA_CUCTXSETCURRENT          cuCtxSetCurrent;
  CUDA_CUCTXSETSHAREDMEMCONFIG  cuCtxSetSharedMemConfig;
  CUDA_CUCTXSYNCHRONIZE         cuCtxSynchronize;
  CUDA_CUDEVICEGETATTRIBUTE     cuDeviceGetAttribute;
  CUDA_CUDEVICEGETCOUNT         cuDeviceGetCount;
  CUDA_CUDEVICEGET              cuDeviceGet;
  CUDA_CUDEVICEGETNAME          cuDeviceGetName;
  CUDA_CUDEVICETOTALMEM         cuDeviceTotalMem;
  CUDA_CUDRIVERGETVERSION       cuDriverGetVersion;
  CUDA_CUEVENTCREATE            cuEventCreate;
  CUDA_CUEVENTDESTROY           cuEventDestroy;
  CUDA_CUEVENTELAPSEDTIME       cuEventElapsedTime;
  CUDA_CUEVENTQUERY             cuEventQuery;
  CUDA_CUEVENTRECORD            cuEventRecord;
  CUDA_CUEVENTSYNCHRONIZE       cuEventSynchronize;
  CUDA_CUFUNCGETATTRIBUTE       cuFuncGetAttribute;
  CUDA_CUFUNCSETATTRIBUTE       cuFuncSetAttribute;
  CUDA_CUFUNCSETCACHECONFIG     cuFuncSetCacheConfig;
  CUDA_CUFUNCSETSHAREDMEMCONFIG cuFuncSetSharedMemConfig;
  CUDA_CUGETERRORNAME           cuGetErrorName;
  CUDA_CUGETERRORSTRING         cuGetErrorString;
  CUDA_CUINIT                   cuInit;
  CUDA_CULAUNCHKERNEL           cuLaunchKernel;
  CUDA_CUMEMALLOC               cuMemAlloc;
  CUDA_CUMEMALLOCHOST           cuMemAllocHost;
  CUDA_CUMEMCPYDTODASYNC        cuMemcpyDtoDAsync;
  CUDA_CUMEMCPYDTOHASYNC        cuMemcpyDtoHAsync;
  CUDA_CUMEMCPYHTODASYNC        cuMemcpyHtoDAsync;
  CUDA_CUMEMFREE                cuMemFree;
  CUDA_CUMEMFREEHOST            cuMemFreeHost;
  CUDA_CUMEMGETINFO             cuMemGetInfo;
  CUDA_CUMEMSETD32ASYNC         cuMemsetD32Async;
  CUDA_CUMEMSETD8ASYNC          cuMemsetD8Async;
  CUDA_CUMODULEGETFUNCTION      cuModuleGetFunction;
  CUDA_CUMODULEGETGLOBAL        cuModuleGetGlobal;
  CUDA_CUMODULELOAD             cuModuleLoad;
  CUDA_CUMODULELOADDATA         cuModuleLoadData;
  CUDA_CUMODULELOADDATAEX       cuModuleLoadDataEx;
  CUDA_CUMODULEUNLOAD           cuModuleUnload;
  CUDA_CUPROFILERSTART          cuProfilerStart;
  CUDA_CUPROFILERSTOP           cuProfilerStop;
  CUDA_CUSTREAMCREATE           cuStreamCreate;
  CUDA_CUSTREAMDESTROY          cuStreamDestroy;
  CUDA_CUSTREAMSYNCHRONIZE      cuStreamSynchronize;
  CUDA_CUSTREAMWAITEVENT        cuStreamWaitEvent;
  CUDA_CULINKCREATE             cuLinkCreate;
  CUDA_CULINKADDDATA            cuLinkAddData;
  CUDA_CULINKDESTROY            cuLinkDestroy;
  CUDA_CULINKCOMPLETE           cuLinkComplete;

} hc_cuda_lib_t;

typedef hc_cuda_lib_t CUDA_PTR;

int  cuda_init                 (void *hashcat_ctx);
void cuda_close                (void *hashcat_ctx);

int hc_cuCtxCreate             (void *hashcat_ctx, CUcontext *pctx, unsigned int flags, CUdevice dev);
int hc_cuCtxDestroy            (void *hashcat_ctx, CUcontext ctx);
int hc_cuCtxSetCurrent         (void *hashcat_ctx, CUcontext ctx);
int hc_cuCtxSetCacheConfig     (void *hashcat_ctx, CUfunc_cache config);
int hc_cuCtxSynchronize        (void *hashcat_ctx);
int hc_cuDeviceGetAttribute    (void *hashcat_ctx, int *pi, CUdevice_attribute attrib, CUdevice dev);
int hc_cuDeviceGetCount        (void *hashcat_ctx, int *count);
int hc_cuDeviceGet             (void *hashcat_ctx, CUdevice *device, int ordinal);
int hc_cuDeviceGetName         (void *hashcat_ctx, char *name, int len, CUdevice dev);
int hc_cuDeviceTotalMem        (void *hashcat_ctx, size_t *bytes, CUdevice dev);
int hc_cuDriverGetVersion      (void *hashcat_ctx, int *driverVersion);
int hc_cuEventCreate           (void *hashcat_ctx, CUevent *phEvent, unsigned int Flags);
int hc_cuEventDestroy          (void *hashcat_ctx, CUevent hEvent);
int hc_cuEventElapsedTime      (void *hashcat_ctx, float *pMilliseconds, CUevent hStart, CUevent hEnd);
int hc_cuEventQuery            (void *hashcat_ctx, CUevent hEvent);
int hc_cuEventRecord           (void *hashcat_ctx, CUevent hEvent, CUstream hStream);
int hc_cuEventSynchronize      (void *hashcat_ctx, CUevent hEvent);
int hc_cuFuncGetAttribute      (void *hashcat_ctx, int *pi, CUfunction_attribute attrib, CUfunction hfunc);
int hc_cuFuncSetAttribute      (void *hashcat_ctx, CUfunction hfunc, CUfunction_attribute attrib, int value);
int hc_cuInit                  (void *hashcat_ctx, unsigned int Flags);
int hc_cuLaunchKernel          (void *hashcat_ctx, CUfunction f, unsigned int gridDimX, unsigned int gridDimY, unsigned int gridDimZ, unsigned int blockDimX, unsigned int blockDimY, unsigned int blockDimZ, unsigned int sharedMemBytes, CUstream hStream, void **kernelParams, void **extra);
int hc_cuMemAlloc              (void *hashcat_ctx, CUdeviceptr *dptr, size_t bytesize);
int hc_cuMemcpyDtoDAsync       (void *hashcat_ctx, CUdeviceptr dstDevice, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
int hc_cuMemcpyDtoHAsync       (void *hashcat_ctx, void *dstHost, CUdeviceptr srcDevice, size_t ByteCount, CUstream hStream);
int hc_cuMemcpyHtoDAsync       (void *hashcat_ctx, CUdeviceptr dstDevice, const void *srcHost, size_t ByteCount, CUstream hStream);
int hc_cuMemFree               (void *hashcat_ctx, CUdeviceptr dptr);
int hc_cuMemGetInfo            (void *hashcat_ctx, size_t *free, size_t *total);
int hc_cuMemsetD32Async        (void *hashcat_ctx, CUdeviceptr dstDevice, unsigned int ui, size_t N, CUstream hStream);
int hc_cuMemsetD8Async         (void *hashcat_ctx, CUdeviceptr dstDevice, unsigned char uc, size_t N, CUstream hStream);
int hc_cuModuleGetFunction     (void *hashcat_ctx, CUfunction *hfunc, CUmodule hmod, const char *name);
int hc_cuModuleGetGlobal       (void *hashcat_ctx, CUdeviceptr *dptr, size_t *bytes, CUmodule hmod, const char *name);
int hc_cuModuleLoadDataEx      (void *hashcat_ctx, CUmodule *module, const void *image, unsigned int numOptions, CUjit_option *options, void **optionValues);
int hc_cuModuleUnload          (void *hashcat_ctx, CUmodule hmod);
int hc_cuStreamCreate          (void *hashcat_ctx, CUstream *phStream, unsigned int Flags);
int hc_cuStreamDestroy         (void *hashcat_ctx, CUstream hStream);
int hc_cuStreamSynchronize     (void *hashcat_ctx, CUstream hStream);
int hc_cuCtxPushCurrent        (void *hashcat_ctx, CUcontext ctx);
int hc_cuCtxPopCurrent         (void *hashcat_ctx, CUcontext *pctx);
int hc_cuLinkCreate            (void *hashcat_ctx, unsigned int numOptions, CUjit_option *options, void **optionValues, CUlinkState *stateOut);
int hc_cuLinkAddData           (void *hashcat_ctx, CUlinkState state, CUjitInputType type, void *data, size_t size, const char *name, unsigned int numOptions, CUjit_option *options, void **optionValues);
int hc_cuLinkDestroy           (void *hashcat_ctx, CUlinkState state);
int hc_cuLinkComplete          (void *hashcat_ctx, CUlinkState state, void **cubinOut, size_t *sizeOut);

#endif // _EXT_CUDA_H
