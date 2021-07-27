/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _EXT_HIP_H
#define _EXT_HIP_H

/**
 * TODO: FIX ME
 */

#define __HIP_API_VERSION 4221131

/**
 * HIP device pointer
 * HIPdeviceptr is defined as an unsigned integer type whose size matches the size of a pointer on the target platform.
 */
#if __HIP_API_VERSION >= 3020

#if defined(_WIN64) || defined(__LP64__)
typedef unsigned long long HIPdeviceptr;
#else
typedef unsigned int HIPdeviceptr;
#endif

#endif /* __HIP_API_VERSION >= 3020 */

typedef int HIPdevice;                                     /**< HIP device */
typedef struct HIPctx_st *HIPcontext;                       /**< HIP context */
typedef struct HIPevent_st *HIPevent;                       /**< HIP event */
typedef struct HIPfunc_st *HIPfunction;                     /**< HIP function */
typedef struct HIPmod_st *HIPmodule;                        /**< HIP module */
typedef struct HIPstream_st *HIPstream;                     /**< HIP stream */
typedef struct HIPlinkState_st *HIPlinkState;


typedef enum hipError_enum {
    /**
     * The API call returned with no errors. In the case of query calls, this
     * also means that the operation being queried is complete (see
     * ::hipEventQuery() and ::hipStreamQuery()).
     */
    HIP_SUCCESS                              = 0,

    /**
     * This indicates that one or more of the parameters passed to the API call
     * is not within an acceptable range of values.
     */
    HIP_ERROR_INVALID_VALUE                  = 1,

    /**
     * The API call failed because it was unable to allocate enough memory to
     * perform the requested operation.
     */
    HIP_ERROR_OUT_OF_MEMORY                  = 2,

    /**
     * This indicates that the HIP driver has not been initialized with
     * ::hipInit() or that initialization has failed.
     */
    HIP_ERROR_NOT_INITIALIZED                = 3,

    /**
     * This indicates that the HIP driver is in the process of shutting down.
     */
    HIP_ERROR_DEINITIALIZED                  = 4,

    /**
     * This indicates profiler is not initialized for this run. This can
     * happen when the application is running with external profiling tools
     * like visual profiler.
     */
    HIP_ERROR_PROFILER_DISABLED              = 5,

    /**
     * \deprecated
     * This error return is deprecated as of HIP 5.0. It is no longer an error
     * to attempt to enable/disable the profiling via ::hipProfilerStart or
     * ::hipProfilerStop without initialization.
     */
    HIP_ERROR_PROFILER_NOT_INITIALIZED       = 6,

    /**
     * \deprecated
     * This error return is deprecated as of HIP 5.0. It is no longer an error
     * to call hipProfilerStart() when profiling is already enabled.
     */
    HIP_ERROR_PROFILER_ALREADY_STARTED       = 7,

    /**
     * \deprecated
     * This error return is deprecated as of HIP 5.0. It is no longer an error
     * to call hipProfilerStop() when profiling is already disabled.
     */
    HIP_ERROR_PROFILER_ALREADY_STOPPED       = 8,

    /**
     * This indicates that no HIP-capable devices were detected by the installed
     * HIP driver.
     */
    HIP_ERROR_NO_DEVICE                      = 100,

    /**
     * This indicates that the device ordinal supplied by the user does not
     * correspond to a valid HIP device.
     */
    HIP_ERROR_INVALID_DEVICE                 = 101,


    /**
     * This indicates that the device kernel image is invalid. This can also
     * indicate an invalid HIP module.
     */
    HIP_ERROR_INVALID_IMAGE                  = 200,

    /**
     * This most frequently indicates that there is no context bound to the
     * hiprrent thread. This can also be returned if the context passed to an
     * API call is not a valid handle (such as a context that has had
     * ::hipCtxDestroy() invoked on it). This can also be returned if a user
     * mixes different API versions (i.e. 3010 context with 3020 API calls).
     * See ::hipCtxGetApiVersion() for more details.
     */
    HIP_ERROR_INVALID_CONTEXT                = 201,

    /**
     * This indicated that the context being supplied as a parameter to the
     * API call was already the active context.
     * \deprecated
     * This error return is deprecated as of HIP 3.2. It is no longer an
     * error to attempt to push the active context via ::hipCtxPushCurrent().
     */
    HIP_ERROR_CONTEXT_ALREADY_CURRENT        = 202,

    /**
     * This indicates that a map or register operation has failed.
     */
    HIP_ERROR_MAP_FAILED                     = 205,

    /**
     * This indicates that an unmap or unregister operation has failed.
     */
    HIP_ERROR_UNMAP_FAILED                   = 206,

    /**
     * This indicates that the specified array is currently mapped and thus
     * cannot be destroyed.
     */
    HIP_ERROR_ARRAY_IS_MAPPED                = 207,

    /**
     * This indicates that the resource is already mapped.
     */
    HIP_ERROR_ALREADY_MAPPED                 = 208,

    /**
     * This indicates that there is no kernel image available that is suitable
     * for the device. This can occur when a user specifies code generation
     * options for a particular HIP source file that do not include the
     * corresponding device configuration.
     */
    HIP_ERROR_NO_BINARY_FOR_GPU              = 209,

    /**
     * This indicates that a resource has already been acquired.
     */
    HIP_ERROR_ALREADY_ACQUIRED               = 210,

    /**
     * This indicates that a resource is not mapped.
     */
    HIP_ERROR_NOT_MAPPED                     = 211,

    /**
     * This indicates that a mapped resource is not available for access as an
     * array.
     */
    HIP_ERROR_NOT_MAPPED_AS_ARRAY            = 212,

    /**
     * This indicates that a mapped resource is not available for access as a
     * pointer.
     */
    HIP_ERROR_NOT_MAPPED_AS_POINTER          = 213,

    /**
     * This indicates that an uncorrectable ECC error was detected during
     * execution.
     */
    HIP_ERROR_ECC_UNCORRECTABLE              = 214,

    /**
     * This indicates that the ::HIPlimit passed to the API call is not
     * supported by the active device.
     */
    HIP_ERROR_UNSUPPORTED_LIMIT              = 215,

    /**
     * This indicates that the ::HIPcontext passed to the API call can
     * only be bound to a single CPU thread at a time but is already
     * bound to a CPU thread.
     */
    HIP_ERROR_CONTEXT_ALREADY_IN_USE         = 216,

    /**
     * This indicates that peer access is not supported across the given
     * devices.
     */
    HIP_ERROR_PEER_ACCESS_UNSUPPORTED        = 217,

    /**
     * This indicates that a PTX JIT compilation failed.
     */
    HIP_ERROR_INVALID_PTX                    = 218,

    /**
     * This indicates an error with OpenGL or DirectX context.
     */
    HIP_ERROR_INVALID_GRAPHICS_CONTEXT       = 219,

    /**
    * This indicates that an uncorrectable NVLink error was detected during the
    * execution.
    */
    HIP_ERROR_NVLINK_UNCORRECTABLE           = 220,

    /**
    * This indicates that the PTX JIT compiler library was not found.
    */
    HIP_ERROR_JIT_COMPILER_NOT_FOUND         = 221,

    /**
     * This indicates that the device kernel source is invalid.
     */
    HIP_ERROR_INVALID_SOURCE                 = 300,

    /**
     * This indicates that the file specified was not found.
     */
    HIP_ERROR_FILE_NOT_FOUND                 = 301,

    /**
     * This indicates that a link to a shared object failed to resolve.
     */
    HIP_ERROR_SHARED_OBJECT_SYMBOL_NOT_FOUND = 302,

    /**
     * This indicates that initialization of a shared object failed.
     */
    HIP_ERROR_SHARED_OBJECT_INIT_FAILED      = 303,

    /**
     * This indicates that an OS call failed.
     */
    HIP_ERROR_OPERATING_SYSTEM               = 304,

    /**
     * This indicates that a resource handle passed to the API call was not
     * valid. Resource handles are opaque types like ::HIPstream and ::HIPevent.
     */
    HIP_ERROR_INVALID_HANDLE                 = 400,

    /**
     * This indicates that a resource required by the API call is not in a
     * valid state to perform the requested operation.
     */
    HIP_ERROR_ILLEGAL_STATE                  = 401,

    /**
     * This indicates that a named symbol was not found. Examples of symbols
     * are global/constant variable names, texture names, and surface names.
     */
    HIP_ERROR_NOT_FOUND                      = 500,

    /**
     * This indicates that asynchronous operations issued previously have not
     * completed yet. This result is not actually an error, but must be indicated
     * differently than ::HIP_SUCCESS (which indicates completion). Calls that
     * may return this value include ::hipEventQuery() and ::hipStreamQuery().
     */
    HIP_ERROR_NOT_READY                      = 600,

    /**
     * While executing a kernel, the device encountered a
     * load or store instruction on an invalid memory address.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_ILLEGAL_ADDRESS                = 700,

    /**
     * This indicates that a launch did not occur because it did not have
     * appropriate resources. This error usually indicates that the user has
     * attempted to pass too many arguments to the device kernel, or the
     * kernel launch specifies too many threads for the kernel's register
     * count. Passing arguments of the wrong size (i.e. a 64-bit pointer
     * when a 32-bit int is expected) is equivalent to passing too many
     * arguments and can also result in this error.
     */
    HIP_ERROR_LAUNCH_OUT_OF_RESOURCES        = 701,

    /**
     * This indicates that the device kernel took too long to execute. This can
     * only occur if timeouts are enabled - see the device attribute
     * ::HIP_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT for more information.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_LAUNCH_TIMEOUT                 = 702,

    /**
     * This error indicates a kernel launch that uses an incompatible texturing
     * mode.
     */
    HIP_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING  = 703,

    /**
     * This error indicates that a call to ::hipCtxEnablePeerAccess() is
     * trying to re-enable peer access to a context which has already
     * had peer access to it enabled.
     */
    HIP_ERROR_PEER_ACCESS_ALREADY_ENABLED    = 704,

    /**
     * This error indicates that ::hipCtxDisablePeerAccess() is
     * trying to disable peer access which has not been enabled yet
     * via ::hipCtxEnablePeerAccess().
     */
    HIP_ERROR_PEER_ACCESS_NOT_ENABLED        = 705,

    /**
     * This error indicates that the primary context for the specified device
     * has already been initialized.
     */
    HIP_ERROR_PRIMARY_CONTEXT_ACTIVE         = 708,

    /**
     * This error indicates that the context hiprrent to the calling thread
     * has been destroyed using ::hipCtxDestroy, or is a primary context which
     * has not yet been initialized.
     */
    HIP_ERROR_CONTEXT_IS_DESTROYED           = 709,

    /**
     * A device-side assert triggered during kernel execution. The context
     * cannot be used anymore, and must be destroyed. All existing device
     * memory allocations from this context are invalid and must be
     * reconstructed if the program is to continue using HIP.
     */
    HIP_ERROR_ASSERT                         = 710,

    /**
     * This error indicates that the hardware resources required to enable
     * peer access have been exhausted for one or more of the devices
     * passed to ::hipCtxEnablePeerAccess().
     */
    HIP_ERROR_TOO_MANY_PEERS                 = 711,

    /**
     * This error indicates that the memory range passed to ::hipMemHostRegister()
     * has already been registered.
     */
    HIP_ERROR_HOST_MEMORY_ALREADY_REGISTERED = 712,

    /**
     * This error indicates that the pointer passed to ::hipMemHostUnregister()
     * does not correspond to any currently registered memory region.
     */
    HIP_ERROR_HOST_MEMORY_NOT_REGISTERED     = 713,

    /**
     * While executing a kernel, the device encountered a stack error.
     * This can be due to stack corruption or exceeding the stack size limit.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_HARDWARE_STACK_ERROR           = 714,

    /**
     * While executing a kernel, the device encountered an illegal instruction.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_ILLEGAL_INSTRUCTION            = 715,

    /**
     * While executing a kernel, the device encountered a load or store instruction
     * on a memory address which is not aligned.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_MISALIGNED_ADDRESS             = 716,

    /**
     * While executing a kernel, the device encountered an instruction
     * which can only operate on memory locations in certain address spaces
     * (global, shared, or local), but was supplied a memory address not
     * belonging to an allowed address space.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_INVALID_ADDRESS_SPACE          = 717,

    /**
     * While executing a kernel, the device program counter wrapped its address space.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_INVALID_PC                     = 718,

    /**
     * An exception occurred on the device while executing a kernel. Common
     * causes include dereferencing an invalid device pointer and accessing
     * out of bounds shared memory. Less common cases can be system specific - more
     * information about these cases can be found in the system specific user guide.
     * This leaves the process in an inconsistent state and any further HIP work
     * will return the same error. To continue using HIP, the process must be terminated
     * and relaunched.
     */
    HIP_ERROR_LAUNCH_FAILED                  = 719,

    /**
     * This error indicates that the number of blocks launched per grid for a kernel that was
     * launched via either ::hipLaunchCooperativeKernel or ::hipLaunchCooperativeKernelMultiDevice
     * exceeds the maximum number of blocks as allowed by ::hipOccupancyMaxActiveBlocksPerMultiprocessor
     * or ::hipOccupancyMaxActiveBlocksPerMultiprocessorWithFlags times the number of multiprocessors
     * as specified by the device attribute ::HIP_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT.
     */
    HIP_ERROR_COOPERATIVE_LAUNCH_TOO_LARGE   = 720,

    /**
     * This error indicates that the attempted operation is not permitted.
     */
    HIP_ERROR_NOT_PERMITTED                  = 800,

    /**
     * This error indicates that the attempted operation is not supported
     * on the current system or device.
     */
    HIP_ERROR_NOT_SUPPORTED                  = 801,

    /**
     * This error indicates that the system is not yet ready to start any HIP
     * work.  To continue using HIP, verify the system configuration is in a
     * valid state and all required driver daemons are actively running.
     * More information about this error can be found in the system specific
     * user guide.
     */
    HIP_ERROR_SYSTEM_NOT_READY               = 802,

    /**
     * This error indicates that there is a mismatch between the versions of
     * the display driver and the HIP driver. Refer to the compatibility documentation
     * for supported versions.
     */
    HIP_ERROR_SYSTEM_DRIVER_MISMATCH         = 803,

    /**
     * This error indicates that the system was upgraded to run with forward compatibility
     * but the visible hardware detected by HIP does not support this configuration.
     * Refer to the compatibility documentation for the supported hardware matrix or ensure
     * that only supported hardware is visible during initialization via the HIP_VISIBLE_DEVICES
     * environment variable.
     */
    HIP_ERROR_COMPAT_NOT_SUPPORTED_ON_DEVICE = 804,

    /**
     * This error indicates that the operation is not permitted when
     * the stream is capturing.
     */
    HIP_ERROR_STREAM_CAPTURE_UNSUPPORTED     = 900,

    /**
     * This error indicates that the current capture sequence on the stream
     * has been invalidated due to a previous error.
     */
    HIP_ERROR_STREAM_CAPTURE_INVALIDATED     = 901,

    /**
     * This error indicates that the operation would have resulted in a merge
     * of two independent capture sequences.
     */
    HIP_ERROR_STREAM_CAPTURE_MERGE           = 902,

    /**
     * This error indicates that the capture was not initiated in this stream.
     */
    HIP_ERROR_STREAM_CAPTURE_UNMATCHED       = 903,

    /**
     * This error indicates that the capture sequence contains a fork that was
     * not joined to the primary stream.
     */
    HIP_ERROR_STREAM_CAPTURE_UNJOINED        = 904,

    /**
     * This error indicates that a dependency would have been created which
     * crosses the capture sequence boundary. Only implicit in-stream ordering
     * dependencies are allowed to cross the boundary.
     */
    HIP_ERROR_STREAM_CAPTURE_ISOLATION       = 905,

    /**
     * This error indicates a disallowed implicit dependency on a current capture
     * sequence from HIPStreamLegacy.
     */
    HIP_ERROR_STREAM_CAPTURE_IMPLICIT        = 906,

    /**
     * This error indicates that the operation is not permitted on an event which
     * was last recorded in a capturing stream.
     */
    HIP_ERROR_CAPTURED_EVENT                 = 907,

    /**
     * A stream capture sequence not initiated with the ::HIP_STREAM_CAPTURE_MODE_RELAXED
     * argument to ::HIPStreamBeginCapture was passed to ::hipStreamEndCapture in a
     * different thread.
     */
    HIP_ERROR_STREAM_CAPTURE_WRONG_THREAD    = 908,

    /**
     * This indicates that an unknown internal error has occurred.
     */
    HIP_ERROR_UNKNOWN                        = 999
} HIPresult;

/**
 * Online compiler and linker options
 */
typedef enum HIPjit_option_enum
{
    /**
     * Max number of registers that a thread may use.\n
     * Option type: unsigned int\n
     * Applies to: compiler only
     */
    HIP_JIT_MAX_REGISTERS = 0,

    /**
     * IN: Specifies minimum number of threads per block to target compilation
     * for\n
     * OUT: Returns the number of threads the compiler actually targeted.
     * This restricts the resource utilization fo the compiler (e.g. max
     * registers) such that a block with the given number of threads should be
     * able to launch based on register limitations. Note, this option does not
     * currently take into account any other resource limitations, such as
     * shared memory utilization.\n
     * Cannot be combined with ::HIP_JIT_TARGET.\n
     * Option type: unsigned int\n
     * Applies to: compiler only
     */
    HIP_JIT_THREADS_PER_BLOCK,

    /**
     * Overwrites the option value with the total wall clock time, in
     * milliseconds, spent in the compiler and linker\n
     * Option type: float\n
     * Applies to: compiler and linker
     */
    HIP_JIT_WALL_TIME,

    /**
     * Pointer to a buffer in which to print any log messages
     * that are informational in nature (the buffer size is specified via
     * option ::HIP_JIT_INFO_LOG_BUFFER_SIZE_BYTES)\n
     * Option type: char *\n
     * Applies to: compiler and linker
     */
    HIP_JIT_INFO_LOG_BUFFER,

    /**
     * IN: Log buffer size in bytes.  Log messages will be capped at this size
     * (including null terminator)\n
     * OUT: Amount of log buffer filled with messages\n
     * Option type: unsigned int\n
     * Applies to: compiler and linker
     */
    HIP_JIT_INFO_LOG_BUFFER_SIZE_BYTES,

    /**
     * Pointer to a buffer in which to print any log messages that
     * reflect errors (the buffer size is specified via option
     * ::HIP_JIT_ERROR_LOG_BUFFER_SIZE_BYTES)\n
     * Option type: char *\n
     * Applies to: compiler and linker
     */
    HIP_JIT_ERROR_LOG_BUFFER,

    /**
     * IN: Log buffer size in bytes.  Log messages will be capped at this size
     * (including null terminator)\n
     * OUT: Amount of log buffer filled with messages\n
     * Option type: unsigned int\n
     * Applies to: compiler and linker
     */
    HIP_JIT_ERROR_LOG_BUFFER_SIZE_BYTES,

    /**
     * Level of optimizations to apply to generated code (0 - 4), with 4
     * being the default and highest level of optimizations.\n
     * Option type: unsigned int\n
     * Applies to: compiler only
     */
    HIP_JIT_OPTIMIZATION_LEVEL,

    /**
     * No option value required. Determines the target based on the current
     * attached context (default)\n
     * Option type: No option value needed\n
     * Applies to: compiler and linker
     */
    HIP_JIT_TARGET_FROM_HIPCONTEXT,

    /**
     * Target is chosen based on supplied ::HIPjit_target.  Cannot be
     * combined with ::HIP_JIT_THREADS_PER_BLOCK.\n
     * Option type: unsigned int for enumerated type ::HIPjit_target\n
     * Applies to: compiler and linker
     */
    HIP_JIT_TARGET,

    /**
     * Specifies choice of fallback strategy if matching HIPbin is not found.
     * Choice is based on supplied ::HIPjit_fallback.  This option cannot be
     * used with HIPLink* APIs as the linker requires exact matches.\n
     * Option type: unsigned int for enumerated type ::HIPjit_fallback\n
     * Applies to: compiler only
     */
    HIP_JIT_FALLBACK_STRATEGY,

    /**
     * Specifies whether to create debug information in output (-g)
     * (0: false, default)\n
     * Option type: int\n
     * Applies to: compiler and linker
     */
    HIP_JIT_GENERATE_DEBUG_INFO,

    /**
     * Generate verbose log messages (0: false, default)\n
     * Option type: int\n
     * Applies to: compiler and linker
     */
    HIP_JIT_LOG_VERBOSE,

    /**
     * Generate line number information (-lineinfo) (0: false, default)\n
     * Option type: int\n
     * Applies to: compiler only
     */
    HIP_JIT_GENERATE_LINE_INFO,

    /**
     * Specifies whether to enable caching explicitly (-dlcm) \n
     * Choice is based on supplied ::HIPjit_cacheMode_enum.\n
     * Option type: unsigned int for enumerated type ::HIPjit_cacheMode_enum\n
     * Applies to: compiler only
     */
    HIP_JIT_CACHE_MODE,

    /**
     * The below jit options are used for internal purposes only, in this version of HIP
     */
    HIP_JIT_NEW_SM3X_OPT,
    HIP_JIT_FAST_COMPILE,

    /**
     * Array of device symbol names that will be relocated to the corresponing
     * host addresses stored in ::HIP_JIT_GLOBAL_SYMBOL_ADDRESSES.\n
     * Must contain ::HIP_JIT_GLOBAL_SYMBOL_COUNT entries.\n
     * When loding a device module, driver will relocate all encountered
     * unresolved symbols to the host addresses.\n
     * It is only allowed to register symbols that correspond to unresolved
     * global variables.\n
     * It is illegal to register the same device symbol at multiple addresses.\n
     * Option type: const char **\n
     * Applies to: dynamic linker only
     */
    HIP_JIT_GLOBAL_SYMBOL_NAMES,

    /**
     * Array of host addresses that will be used to relocate corresponding
     * device symbols stored in ::HIP_JIT_GLOBAL_SYMBOL_NAMES.\n
     * Must contain ::HIP_JIT_GLOBAL_SYMBOL_COUNT entries.\n
     * Option type: void **\n
     * Applies to: dynamic linker only
     */
    HIP_JIT_GLOBAL_SYMBOL_ADDRESSES,

    /**
     * Number of entries in ::HIP_JIT_GLOBAL_SYMBOL_NAMES and
     * ::HIP_JIT_GLOBAL_SYMBOL_ADDRESSES arrays.\n
     * Option type: unsigned int\n
     * Applies to: dynamic linker only
     */
    HIP_JIT_GLOBAL_SYMBOL_COUNT,

    HIP_JIT_NUM_OPTIONS

} HIPjit_option;


/**
 * Device properties
 */
typedef enum HIPdevice_attribute_enum {
    
    HIP_DEVICE_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 0,              /**< Maximum number of threads per block */
    HIP_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_X = 1,                    /**< Maximum block dimension X */
    HIP_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Y = 2,                    /**< Maximum block dimension Y */
    HIP_DEVICE_ATTRIBUTE_MAX_BLOCK_DIM_Z = 3,                    /**< Maximum block dimension Z */
    HIP_DEVICE_ATTRIBUTE_MAX_GRID_DIM_X = 4,                     /**< Maximum grid dimension X */
    HIP_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Y = 5,                     /**< Maximum grid dimension Y */
    HIP_DEVICE_ATTRIBUTE_MAX_GRID_DIM_Z = 6,                     /**< Maximum grid dimension Z */
    HIP_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK = 7,        /**< Maximum shared memory available per block in bytes */
    HIP_DEVICE_ATTRIBUTE_SHARED_MEMORY_PER_BLOCK = 7,            /**< Deprecated, use HIP_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK */
    HIP_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_BLOCK_OPTIN = 7, /**< Maximum optin shared memory per block */
    HIP_DEVICE_ATTRIBUTE_TOTAL_CONSTANT_MEMORY = 8,              /**< Memory available on device for __constant__ variables in a HIP C kernel in bytes */
    HIP_DEVICE_ATTRIBUTE_WARP_SIZE = 9,                         /**< Warp size in threads */
    HIP_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK = 10,           /**< Maximum number of 32-bit registers available per block */
    HIP_DEVICE_ATTRIBUTE_REGISTERS_PER_BLOCK = 10,               /**< Deprecated, use HIP_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_BLOCK */
    HIP_DEVICE_ATTRIBUTE_CLOCK_RATE = 11,                        /**< Typical clock frequency in kilohertz */
    HIP_DEVICE_ATTRIBUTE_MEMORY_CLOCK_RATE = 12,                 /**< Peak memory clock frequency in kilohertz */
    HIP_DEVICE_ATTRIBUTE_GLOBAL_MEMORY_BUS_WIDTH = 13,           /**< Global memory bus width in bits */
    HIP_DEVICE_ATTRIBUTE_MULTIPROCESSOR_COUNT = 14,              /**< Number of multiprocessors on device */
    HIP_DEVICE_ATTRIBUTE_COMPUTE_MODE = 15,                      /**< Compute mode (See ::HIPcomputemode for details) */
    HIP_DEVICE_ATTRIBUTE_L2_CACHE_SIZE = 16,                     /**< Size of L2 cache in bytes */
    HIP_DEVICE_ATTRIBUTE_MAX_THREADS_PER_MULTIPROCESSOR = 17,    /**< Maximum resident threads per multiprocessor */
    HIP_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MAJOR = 18,          /**< Major compute capability version number */
    HIP_DEVICE_ATTRIBUTE_COMPUTE_CAPABILITY_MINOR = 19,          /**< Minor compute capability version number */
    HIP_DEVICE_ATTRIBUTE_CONCURRENT_KERNELS = 20,                /**< Device can possibly execute multiple kernels concurrently */
    HIP_DEVICE_ATTRIBUTE_PCI_BUS_ID = 21,                        /**< PCI bus ID of the device */
    HIP_DEVICE_ATTRIBUTE_PCI_DEVICE_ID = 22,                     /**< PCI device ID of the device */
    HIP_DEVICE_ATTRIBUTE_PCI_DOMAIN_ID = 22,                     /**< PCI domain ID of the device */
    HIP_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_MULTIPROCESSOR = 23,  /**< Maximum shared memory available per multiprocessor in bytes */
    HIP_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD = 24,                    /**< Device is on a multi-GPU board */
    HIP_DEVICE_ATTRIBUTE_INTEGRATED = 25,                        /**< Device is integrated with host memory */
    HIP_DEVICE_ATTRIBUTE_COOPERATIVE_LAUNCH = 26,                /**< Device supports launching cooperative kernels via ::hipLaunchCooperativeKernel */
    HIP_DEVICE_ATTRIBUTE_COOPERATIVE_MULTI_DEVICE_LAUNCH = 27,   /**< Device can participate in cooperative kernels launched via ::hipLaunchCooperativeKernelMultiDevice */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_WIDTH = 28,           /**< Maximum 1D texture width */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_WIDTH = 29,           /**< Maximum 2D texture width */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_HEIGHT = 30,          /**< Maximum 2D texture height */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH = 31,           /**< Maximum 3D texture width */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT = 32,          /**< Maximum 3D texture height */
    HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH = 33,           /**< Maximum 3D texture depth */
    
    HIP_DEVICE_ATTRIBUTE_TEXTURE_ALIGNMENT = 37,                 /**< Alignment requirement for textures */
    HIP_DEVICE_ATTRIBUTE_TEXTURE_PITCH_ALIGNMENT = 38,           /**< Pitch alignment requirement for textures */
    HIP_DEVICE_ATTRIBUTE_KERNEL_EXEC_TIMEOUT = 39,               /**< Specifies whether there is a run time limit on kernels */
    HIP_DEVICE_ATTRIBUTE_CAN_MAP_HOST_MEMORY = 40,               /**< Device can map host memory into HIP address space */
    HIP_DEVICE_ATTRIBUTE_ECC_ENABLED = 41,                       /**< Device has ECC support enabled */
    
    HIP_DEVICE_ATTRIBUTE_MANAGED_MEMORY = 47,                    /**< Device can allocate managed memory on this system */
    HIP_DEVICE_ATTRIBUTE_DIRECT_MANAGED_MEM_ACCESS_FROM_HOST = 48, /**< The host can directly access managed memory on the device without migration. */
    HIP_DEVICE_ATTRIBUTE_CONCURRENT_MANAGED_ACCESS = 49,         /**< Device can coherently access managed memory concurrently with the CPU */
    HIP_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS = 50,            /**< Device supports coherently accessing pageable memory without calling HIPHostRegister on it */
    HIP_DEVICE_ATTRIBUTE_PAGEABLE_MEMORY_ACCESS_USES_HOST_PAGE_TABLES = 51, /**< Device accesses pageable memory via the host's page tables. */
    HIP_DEVICE_ATTRIBUTE_CAN_USE_STREAM_WAIT_VALUE_NOR = 52,     /**< ::HIP_STREAM_WAIT_VALUE_NOR is supported. */
    
    
    // HIP_DEVICE_ATTRIBUTE_MAX_PITCH = ,                         /**< Maximum pitch in bytes allowed by memory copies */
    // HIP_DEVICE_ATTRIBUTE_GPU_OVERLAP = ,                       /**< Device can possibly copy memory and execute a kernel concurrently. Deprecated. Use instead HIP_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT. */
    // 
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_WIDTH = ,   /**< Maximum 2D layered texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_HEIGHT = ,  /**< Maximum 2D layered texture height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_LAYERS = ,  /**< Maximum layers in a 2D layered texture */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_WIDTH = ,     /**< Deprecated, use HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_WIDTH */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_HEIGHT = ,    /**< Deprecated, use HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_HEIGHT */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_ARRAY_NUMSLICES = , /**< Deprecated, use HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LAYERED_LAYERS */
    // HIP_DEVICE_ATTRIBUTE_SURFACE_ALIGNMENT =,                 /**< Alignment requirement for surfaces */
    // HIP_DEVICE_ATTRIBUTE_TCC_DRIVER = ,                        /**< Device is using TCC driver model */
    // HIP_DEVICE_ATTRIBUTE_ASYNC_ENGINE_COUNT = ,                /**< Number of asynchronous engines */
    // HIP_DEVICE_ATTRIBUTE_UNIFIED_ADDRESSING = ,                /**< Device shares a unified address space with the host */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_WIDTH = ,   /**< Maximum 1D layered texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LAYERED_LAYERS = ,  /**< Maximum layers in a 1D layered texture */
    // HIP_DEVICE_ATTRIBUTE_CAN_TEX2D_GATHER = ,                  /**< Deprecated, do not use. */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_WIDTH = ,    /**< Maximum 2D texture width if HIP_ARRAY3D_TEXTURE_GATHER is set */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_GATHER_HEIGHT = ,   /**< Maximum 2D texture height if HIP_ARRAY3D_TEXTURE_GATHER is set */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_WIDTH_ALTERNATE = , /**< Alternate maximum 3D texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_HEIGHT_ALTERNATE = ,/**< Alternate maximum 3D texture height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE3D_DEPTH_ALTERNATE = , /**< Alternate maximum 3D texture depth */
    // 
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_WIDTH = ,      /**< Maximum cubemap texture width/height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_WIDTH = ,  /**< Maximum cubemap layered texture width/height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURECUBEMAP_LAYERED_LAYERS = , /**< Maximum layers in a cubemap layered texture */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_WIDTH = ,           /**< Maximum 1D surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_WIDTH = ,           /**< Maximum 2D surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_HEIGHT = ,          /**< Maximum 2D surface height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_WIDTH = ,           /**< Maximum 3D surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_HEIGHT = ,          /**< Maximum 3D surface height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE3D_DEPTH = ,           /**< Maximum 3D surface depth */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_WIDTH = ,   /**< Maximum 1D layered surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE1D_LAYERED_LAYERS = ,  /**< Maximum layers in a 1D layered surface */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_WIDTH = ,   /**< Maximum 2D layered surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_HEIGHT = ,  /**< Maximum 2D layered surface height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACE2D_LAYERED_LAYERS = ,  /**< Maximum layers in a 2D layered surface */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_WIDTH = ,      /**< Maximum cubemap surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_WIDTH = ,  /**< Maximum cubemap layered surface width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_SURFACECUBEMAP_LAYERED_LAYERS = , /**< Maximum layers in a cubemap layered surface */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_LINEAR_WIDTH = ,    /**< Maximum 1D linear texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_WIDTH = ,    /**< Maximum 2D linear texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_HEIGHT = ,   /**< Maximum 2D linear texture height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_LINEAR_PITCH = ,    /**< Maximum 2D linear texture pitch in bytes */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_WIDTH = , /**< Maximum mipmapped 2D texture width */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE2D_MIPMAPPED_HEIGHT = ,/**< Maximum mipmapped 2D texture height */
    // HIP_DEVICE_ATTRIBUTE_MAXIMUM_TEXTURE1D_MIPMAPPED_WIDTH = , /**< Maximum mipmapped 1D texture width */
    // HIP_DEVICE_ATTRIBUTE_STREAM_PRIORITIES_SUPPORTED = ,       /**< Device supports stream priorities */
    // HIP_DEVICE_ATTRIBUTE_GLOBAL_L1_CACHE_SUPPORTED = ,         /**< Device supports caching globals in L1 */
    // HIP_DEVICE_ATTRIBUTE_LOCAL_L1_CACHE_SUPPORTED = ,          /**< Device supports caching locals in L1 */
    // HIP_DEVICE_ATTRIBUTE_MAX_REGISTERS_PER_MULTIPROCESSOR = ,  /**< Maximum number of 32-bit registers available per multiprocessor */
    // HIP_DEVICE_ATTRIBUTE_MULTI_GPU_BOARD_GROUP_ID = ,           /**< Unique id for a group of devices on the same multi-GPU board */
    // HIP_DEVICE_ATTRIBUTE_HOST_NATIVE_ATOMIC_SUPPORTED = ,       /**< Link between the device and the host supports native atomic operations (this is a placeholder attribute, and is not supported on any current hardware)*/
    // HIP_DEVICE_ATTRIBUTE_SINGLE_TO_DOUBLE_PRECISION_PERF_RATIO = ,  /**< Ratio of single precision performance (in floating-point operations per second) to double precision performance */
    // HIP_DEVICE_ATTRIBUTE_COMPUTE_PREEMPTION_SUPPORTED = ,      /**< Device supports compute preemption. */
    // HIP_DEVICE_ATTRIBUTE_CAN_USE_HOST_POINTER_FOR_REGISTERED_MEM = , /**< Device can access host registered memory at the same virtual address as the CPU */
    // HIP_DEVICE_ATTRIBUTE_CAN_USE_STREAM_MEM_OPS = ,            /**< ::hipStreamBatchMemOp and related APIs are supported. */
    // HIP_DEVICE_ATTRIBUTE_CAN_USE_64_BIT_STREAM_MEM_OPS = ,     /**< 64-bit operations are supported in ::hipStreamBatchMemOp and related APIs. */
    // HIP_DEVICE_ATTRIBUTE_CAN_FLUSH_REMOTE_WRITES = ,           /**< Both the ::HIP_STREAM_WAIT_VALUE_FLUSH flag and the ::HIP_STREAM_MEM_OP_FLUSH_REMOTE_WRITES MemOp are supported on the device. See \ref HIP_MEMOP for additional details. */
    // HIP_DEVICE_ATTRIBUTE_HOST_REGISTER_SUPPORTED = ,           /**< Device supports host memory registration via ::HIPHostRegister. */
    // HIP_DEVICE_ATTRIBUTE_MAX
} HIPdevice_attribute;

/**
 * Function cache configurations
 */
typedef enum HIPfunc_cache_enum {
    HIP_FUNC_CACHE_PREFER_NONE    = 0x00, /**< no preference for shared memory or L1 (default) */
    HIP_FUNC_CACHE_PREFER_SHARED  = 0x01, /**< prefer larger shared memory and smaller L1 cache */
    HIP_FUNC_CACHE_PREFER_L1      = 0x02, /**< prefer larger L1 cache and smaller shared memory */
    HIP_FUNC_CACHE_PREFER_EQUAL   = 0x03  /**< prefer equal sized L1 cache and shared memory */
} HIPfunc_cache;

/**
 * Shared memory configurations
 */
typedef enum HIPsharedconfig_enum {
    HIP_SHARED_MEM_CONFIG_DEFAULT_BANK_SIZE    = 0x00, /**< set default shared memory bank size */
    HIP_SHARED_MEM_CONFIG_FOUR_BYTE_BANK_SIZE  = 0x01, /**< set shared memory bank width to four bytes */
    HIP_SHARED_MEM_CONFIG_EIGHT_BYTE_BANK_SIZE = 0x02  /**< set shared memory bank width to eight bytes */
} HIPsharedconfig;

/**
 * Function properties
 */
typedef enum HIPfunction_attribute_enum {
    /**
     * The maximum number of threads per block, beyond which a launch of the
     * function would fail. This number depends on both the function and the
     * device on which the function is currently loaded.
     */
    HIP_FUNC_ATTRIBUTE_MAX_THREADS_PER_BLOCK = 0,

    /**
     * The size in bytes of statically-allocated shared memory required by
     * this function. This does not include dynamically-allocated shared
     * memory requested by the user at runtime.
     */
    HIP_FUNC_ATTRIBUTE_SHARED_SIZE_BYTES = 1,

    /**
     * The size in bytes of user-allocated constant memory required by this
     * function.
     */
    HIP_FUNC_ATTRIBUTE_CONST_SIZE_BYTES = 2,

    /**
     * The size in bytes of local memory used by each thread of this function.
     */
    HIP_FUNC_ATTRIBUTE_LOCAL_SIZE_BYTES = 3,

    /**
     * The number of registers used by each thread of this function.
     */
    HIP_FUNC_ATTRIBUTE_NUM_REGS = 4,

    /**
     * The PTX virtual architecture version for which the function was
     * compiled. This value is the major PTX version * 10 + the minor PTX
     * version, so a PTX version 1.3 function would return the value 13.
     * Note that this may return the undefined value of 0 for cubins
     * compiled prior to HIP 3.0.
     */
    HIP_FUNC_ATTRIBUTE_PTX_VERSION = 5,

    /**
     * The binary architecture version for which the function was compiled.
     * This value is the major binary version * 10 + the minor binary version,
     * so a binary version 1.3 function would return the value 13. Note that
     * this will return a value of 10 for legacy cubins that do not have a
     * properly-encoded binary architecture version.
     */
    HIP_FUNC_ATTRIBUTE_BINARY_VERSION = 6,

    /**
     * The attribute to indicate whether the function has been compiled with
     * user specified option "-Xptxas --dlcm=ca" set .
     */
    HIP_FUNC_ATTRIBUTE_CACHE_MODE_CA = 7,

    /**
     * The maximum size in bytes of dynamically-allocated shared memory that can be used by
     * this function. If the user-specified dynamic shared memory size is larger than this
     * value, the launch will fail.
     * See ::hipFuncSetAttribute
     */
    HIP_FUNC_ATTRIBUTE_MAX_DYNAMIC_SHARED_SIZE_BYTES = 8,

    /**
     * On devices where the L1 cache and shared memory use the same hardware resources,
     * this sets the shared memory carveout preference, in percent of the total shared memory.
     * Refer to ::HIP_DEVICE_ATTRIBUTE_MAX_SHARED_MEMORY_PER_MULTIPROCESSOR.
     * This is only a hint, and the driver can choose a different ratio if required to execute the function.
     * See ::hipFuncSetAttribute
     */
    HIP_FUNC_ATTRIBUTE_PREFERRED_SHARED_MEMORY_CARVEOUT = 9,

    HIP_FUNC_ATTRIBUTE_MAX
} HIPfunction_attribute;

/**
 * Context creation flags
 */
typedef enum HIPctx_flags_enum {
    HIP_CTX_SCHED_AUTO          = 0x00, /**< Automatic scheduling */
    HIP_CTX_SCHED_SPIN          = 0x01, /**< Set spin as default scheduling */
    HIP_CTX_SCHED_YIELD         = 0x02, /**< Set yield as default scheduling */
    HIP_CTX_SCHED_BLOCKING_SYNC = 0x04, /**< Set blocking synchronization as default scheduling */
    HIP_CTX_BLOCKING_SYNC       = 0x04, /**< Set blocking synchronization as default scheduling
                                         *  \deprecated This flag was deprecated as of HIP 4.0
                                         *  and was replaced with ::HIP_CTX_SCHED_BLOCKING_SYNC. */
    HIP_CTX_SCHED_MASK          = 0x07,
    HIP_CTX_MAP_HOST            = 0x08, /**< Support mapped pinned allocations */
    HIP_CTX_LMEM_RESIZE_TO_MAX  = 0x10, /**< Keep local memory allocation after launch */
    HIP_CTX_FLAGS_MASK          = 0x1f
} HIPctx_flags;

/**
 * Stream creation flags
 */
typedef enum HIPstream_flags_enum {
    HIP_STREAM_DEFAULT      = 0x0, /**< Default stream flag */
    HIP_STREAM_NON_BLOCKING = 0x1  /**< Stream does not synchronize with stream 0 (the NULL stream) */
} HIPstream_flags;

/**
 * Event creation flags
 */
typedef enum HIPevent_flags_enum {
    HIP_EVENT_DEFAULT        = 0x0, /**< Default event flag */
    HIP_EVENT_BLOCKING_SYNC  = 0x1, /**< Event uses blocking synchronization */
    HIP_EVENT_DISABLE_TIMING = 0x2, /**< Event will not record timing data */
    HIP_EVENT_INTERPROCESS   = 0x4  /**< Event is suitable for interprocess use. HIP_EVENT_DISABLE_TIMING must be set */
} HIPevent_flags;

typedef enum HIPjitInputType_enum
{
    /**
     * Compiled device-class-specific device code\n
     * Applicable options: none
     */
    HIP_JIT_INPUT_HIPBIN = 0,

    /**
     * PTX source code\n
     * Applicable options: PTX compiler options
     */
    HIP_JIT_INPUT_PTX,

    /**
     * Bundle of multiple cubins and/or PTX of some device code\n
     * Applicable options: PTX compiler options, ::HIP_JIT_FALLBACK_STRATEGY
     */
    HIP_JIT_INPUT_FATBINARY,

    /**
     * Host object with embedded device code\n
     * Applicable options: PTX compiler options, ::HIP_JIT_FALLBACK_STRATEGY
     */
    HIP_JIT_INPUT_OBJECT,

    /**
     * Archive of host objects with embedded device code\n
     * Applicable options: PTX compiler options, ::HIP_JIT_FALLBACK_STRATEGY
     */
    HIP_JIT_INPUT_LIBRARY,

    HIP_JIT_NUM_INPUT_TYPES
} HIPjitInputType;

#ifdef _WIN32
#define HIPAPI __stdcall
#else
#define HIPAPI
#endif

#define HIP_API_CALL HIPAPI

typedef HIPresult (HIP_API_CALL *HIP_HIPCTXCREATE)              (HIPcontext *, unsigned int, HIPdevice);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXDESTROY)             (HIPcontext);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXGETCACHECONFIG)      (HIPfunc_cache *);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXGETCURRENT)          (HIPcontext *);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXGETSHAREDMEMCONFIG)  (HIPsharedconfig *);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXPOPCURRENT)          (HIPcontext *);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXPUSHCURRENT)         (HIPcontext);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXSETCACHECONFIG)      (HIPfunc_cache);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXSETCURRENT)          (HIPcontext);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXSETSHAREDMEMCONFIG)  (HIPsharedconfig);
typedef HIPresult (HIP_API_CALL *HIP_HIPCTXSYNCHRONIZE)         ();
typedef HIPresult (HIP_API_CALL *HIP_HIPDEVICEGETATTRIBUTE)     (int *, HIPdevice_attribute, HIPdevice);
typedef HIPresult (HIP_API_CALL *HIP_HIPDEVICEGETCOUNT)         (int *);
typedef HIPresult (HIP_API_CALL *HIP_HIPDEVICEGET)              (HIPdevice *, int);
typedef HIPresult (HIP_API_CALL *HIP_HIPDEVICEGETNAME)          (char *, int, HIPdevice);
typedef HIPresult (HIP_API_CALL *HIP_HIPDEVICETOTALMEM)         (size_t *, HIPdevice);
typedef HIPresult (HIP_API_CALL *HIP_HIPDRIVERGETVERSION)       (int *);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTCREATE)            (HIPevent *, unsigned int);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTDESTROY)           (HIPevent);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTELAPSEDTIME)       (float *, HIPevent, HIPevent);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTQUERY)             (HIPevent);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTRECORD)            (HIPevent, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPEVENTSYNCHRONIZE)       (HIPevent);
typedef HIPresult (HIP_API_CALL *HIP_HIPFUNCGETATTRIBUTE)       (int *, HIPfunction_attribute, HIPfunction);
typedef HIPresult (HIP_API_CALL *HIP_HIPFUNCSETATTRIBUTE)       (HIPfunction, HIPfunction_attribute, int);
typedef HIPresult (HIP_API_CALL *HIP_HIPFUNCSETCACHECONFIG)     (HIPfunction, HIPfunc_cache);
typedef HIPresult (HIP_API_CALL *HIP_HIPFUNCSETSHAREDMEMCONFIG) (HIPfunction, HIPsharedconfig);
typedef HIPresult (HIP_API_CALL *HIP_HIPGETERRORNAME)           (HIPresult, const char **);
typedef HIPresult (HIP_API_CALL *HIP_HIPGETERRORSTRING)         (HIPresult, const char **);
typedef HIPresult (HIP_API_CALL *HIP_HIPINIT)                   (unsigned int);
typedef HIPresult (HIP_API_CALL *HIP_HIPLAUNCHKERNEL)           (HIPfunction, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, unsigned int, HIPstream, void **, void **);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMALLOC)               (HIPdeviceptr *, size_t);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMALLOCHOST)           (void **, size_t);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMCPYDTODASYNC)        (HIPdeviceptr, HIPdeviceptr, size_t, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMCPYDTOHASYNC)        (void *, HIPdeviceptr, size_t, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMCPYHTODASYNC)        (HIPdeviceptr, const void *, size_t, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMFREE)                (HIPdeviceptr);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMFREEHOST)            (void *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMGETINFO)             (size_t *, size_t *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMSETD32ASYNC)         (HIPdeviceptr, unsigned int, size_t, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPMEMSETD8ASYNC)          (HIPdeviceptr, unsigned char, size_t, HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULEGETFUNCTION)      (HIPfunction *, HIPmodule, const char *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULEGETGLOBAL)        (HIPdeviceptr *, size_t *, HIPmodule, const char *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULELOAD)             (HIPmodule *, const char *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULELOADDATA)         (HIPmodule *, const void *);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULELOADDATAEX)       (HIPmodule *, const void *, unsigned int, HIPjit_option *, void **);
typedef HIPresult (HIP_API_CALL *HIP_HIPMODULEUNLOAD)           (HIPmodule);
typedef HIPresult (HIP_API_CALL *HIP_HIPPROFILERSTART)          ();
typedef HIPresult (HIP_API_CALL *HIP_HIPPROFILERSTOP)           ();
typedef HIPresult (HIP_API_CALL *HIP_HIPSTREAMCREATE)           (HIPstream *, unsigned int);
typedef HIPresult (HIP_API_CALL *HIP_HIPSTREAMDESTROY)          (HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPSTREAMSYNCHRONIZE)      (HIPstream);
typedef HIPresult (HIP_API_CALL *HIP_HIPSTREAMWAITEVENT)        (HIPstream, HIPevent, unsigned int);
typedef HIPresult (HIP_API_CALL *HIP_HIPLINKCREATE)             (unsigned int, HIPjit_option *, void **, HIPlinkState *);
typedef HIPresult (HIP_API_CALL *HIP_HIPLINKADDDATA)            (HIPlinkState, HIPjitInputType, void *, size_t, const char *, unsigned int, HIPjit_option *, void **);
typedef HIPresult (HIP_API_CALL *HIP_HIPLINKDESTROY)            (HIPlinkState);
typedef HIPresult (HIP_API_CALL *HIP_HIPLINKCOMPLETE)           (HIPlinkState, void **, size_t *);

typedef struct hc_hip_lib
{
  hc_dynlib_t lib;

  HIP_HIPCTXCREATE              hipCtxCreate;
  HIP_HIPCTXDESTROY             hipCtxDestroy;
  HIP_HIPCTXGETCACHECONFIG      hipCtxGetCacheConfig;
  HIP_HIPCTXGETCURRENT          hipCtxGetCurrent;
  HIP_HIPCTXGETSHAREDMEMCONFIG  hipCtxGetSharedMemConfig;
  HIP_HIPCTXPOPCURRENT          hipCtxPopCurrent;
  HIP_HIPCTXPUSHCURRENT         hipCtxPushCurrent;
  HIP_HIPCTXSETCACHECONFIG      hipCtxSetCacheConfig;
  HIP_HIPCTXSETCURRENT          hipCtxSetCurrent;
  HIP_HIPCTXSETSHAREDMEMCONFIG  hipCtxSetSharedMemConfig;
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
  HIP_HIPEVENTQUERY             hipEventQuery;
  HIP_HIPEVENTRECORD            hipEventRecord;
  HIP_HIPEVENTSYNCHRONIZE       hipEventSynchronize;
  HIP_HIPFUNCGETATTRIBUTE       hipFuncGetAttribute;
  HIP_HIPFUNCSETATTRIBUTE       hipFuncSetAttribute;
  HIP_HIPFUNCSETCACHECONFIG     hipFuncSetCacheConfig;
  HIP_HIPFUNCSETSHAREDMEMCONFIG hipFuncSetSharedMemConfig;
  HIP_HIPGETERRORNAME           hipGetErrorName;
  HIP_HIPGETERRORSTRING         hipGetErrorString;
  HIP_HIPINIT                   hipInit;
  HIP_HIPLAUNCHKERNEL           hipLaunchKernel;
  HIP_HIPMEMALLOC               hipMemAlloc;
  HIP_HIPMEMALLOCHOST           hipMemAllocHost;
  HIP_HIPMEMCPYDTODASYNC        hipMemcpyDtoDAsync;
  HIP_HIPMEMCPYDTOHASYNC        hipMemcpyDtoHAsync;
  HIP_HIPMEMCPYHTODASYNC        hipMemcpyHtoDAsync;
  HIP_HIPMEMFREE                hipMemFree;
  HIP_HIPMEMFREEHOST            hipMemFreeHost;
  HIP_HIPMEMGETINFO             hipMemGetInfo;
  HIP_HIPMEMSETD32ASYNC         hipMemsetD32Async;
  HIP_HIPMEMSETD8ASYNC          hipMemsetD8Async;
  HIP_HIPMODULEGETFUNCTION      hipModuleGetFunction;
  HIP_HIPMODULEGETGLOBAL        hipModuleGetGlobal;
  HIP_HIPMODULELOAD             hipModuleLoad;
  HIP_HIPMODULELOADDATA         hipModuleLoadData;
  HIP_HIPMODULELOADDATAEX       hipModuleLoadDataEx;
  HIP_HIPMODULEUNLOAD           hipModuleUnload;
  HIP_HIPPROFILERSTART          hipProfilerStart;
  HIP_HIPPROFILERSTOP           hipProfilerStop;
  HIP_HIPSTREAMCREATE           hipStreamCreate;
  HIP_HIPSTREAMDESTROY          hipStreamDestroy;
  HIP_HIPSTREAMSYNCHRONIZE      hipStreamSynchronize;
  HIP_HIPSTREAMWAITEVENT        hipStreamWaitEvent;
  HIP_HIPLINKCREATE             hipLinkCreate;
  HIP_HIPLINKADDDATA            hipLinkAddData;
  HIP_HIPLINKDESTROY            hipLinkDestroy;
  HIP_HIPLINKCOMPLETE           hipLinkComplete;

} hc_hip_lib_t;

typedef hc_hip_lib_t HIP_PTR;

#endif // _EXT_HIP_H
