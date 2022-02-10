/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_VENDOR_H
#define _INC_VENDOR_H

#if defined _CPU_OPENCL_EMU_H
#define IS_NATIVE
#elif defined __CUDACC__
#define IS_CUDA
#elif defined __HIPCC__
#define IS_HIP
#elif defined __METAL_MACOS__
#define IS_METAL
#else
#define IS_OPENCL
#endif

#if defined IS_METAL
#include <metal_stdlib>

using namespace metal;
#endif

#if defined IS_NATIVE
#define CONSTANT_VK
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ
#elif defined IS_CUDA
#define CONSTANT_VK __constant__
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK    __shared__
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ   extern "C" __global__
#elif defined IS_HIP
#define CONSTANT_VK __constant__
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK    __shared__
#define LOCAL_AS
#define PRIVATE_AS
#define KERNEL_FQ   extern "C" __global__
#elif defined IS_METAL
#define CONSTANT_VK constant
#define CONSTANT_AS constant
#define GLOBAL_AS   device
#define LOCAL_VK    threadgroup
#define LOCAL_AS    threadgroup
#define PRIVATE_AS  thread
#define KERNEL_FQ   kernel
#elif defined IS_OPENCL
#define CONSTANT_VK __constant
#define CONSTANT_AS __constant
#define GLOBAL_AS   __global
#define LOCAL_VK    __local
#define LOCAL_AS    __local
#define PRIVATE_AS
#define KERNEL_FQ   __kernel
#endif

#ifndef MAYBE_UNUSED
#define MAYBE_UNUSED
#endif

/**
 * device type
 */

#define DEVICE_TYPE_CPU   2
#define DEVICE_TYPE_GPU   4
#define DEVICE_TYPE_ACCEL 8

#if   DEVICE_TYPE == DEVICE_TYPE_CPU
#define IS_CPU
#elif DEVICE_TYPE == DEVICE_TYPE_GPU
#define IS_GPU
#elif DEVICE_TYPE == DEVICE_TYPE_ACCEL
#define IS_ACCEL
#endif

/**
 * vendor specific
 */

#if   VENDOR_ID == (1 << 0)
#define IS_AMD
#elif VENDOR_ID == (1 << 1)
#define IS_APPLE
#define IS_GENERIC
#elif VENDOR_ID == (1 << 2)
#define IS_INTEL_BEIGNET
#define IS_GENERIC
#elif VENDOR_ID == (1 << 3)
#define IS_INTEL_SDK
#define IS_GENERIC
#elif VENDOR_ID == (1 << 4)
#define IS_MESA
#define IS_GENERIC
#elif VENDOR_ID == (1 << 5)
#define IS_NV
#elif VENDOR_ID == (1 << 6)
#define IS_POCL
#define IS_GENERIC
#elif VENDOR_ID == (1 << 8)
#define IS_AMD_USE_HIP
#else
#define IS_GENERIC
#endif

#if defined IS_AMD && HAS_VPERM == 1
#define IS_ROCM
#endif

#define LOCAL_MEM_TYPE_LOCAL  1
#define LOCAL_MEM_TYPE_GLOBAL 2

#if LOCAL_MEM_TYPE == LOCAL_MEM_TYPE_LOCAL
#define REAL_SHM
#endif

// So far, only used by -m 22100 and only affects NVIDIA on OpenCL. CUDA seems to work fine.
#ifdef FORCE_DISABLE_SHM
#undef REAL_SHM
#endif

#ifdef REAL_SHM
#define SHM_TYPE LOCAL_AS
#else
#define SHM_TYPE CONSTANT_AS
#endif

/**
 * function declarations can have a large influence depending on the opencl runtime
 * fast but pure kernels on rocm is a good example
 */

#if defined IS_AMD && defined IS_GPU
#define DECLSPEC inline static
#elif defined IS_HIP
#define DECLSPEC __device__
#else
#define DECLSPEC
#endif

#define HC_INLINE0 __attribute__ ((noinline))
#define HC_INLINE1 __attribute__ ((inline))

/**
 * AMD specific
 */

#ifdef IS_AMD
#if defined(cl_amd_media_ops)
#pragma OPENCL EXTENSION cl_amd_media_ops  : enable
#endif
#if defined(cl_amd_media_ops2)
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable
#endif
#endif

// Whitelist some OpenCL specific functions
// This could create more stable kernels on systems with bad OpenCL drivers

#ifdef IS_CUDA
#define USE_BITSELECT
#define USE_ROTATE
#endif

#ifdef IS_HIP
#define USE_BITSELECT
#define USE_ROTATE
#endif

#ifdef IS_ROCM
#define USE_BITSELECT
#define USE_ROTATE
#endif

#ifdef IS_INTEL_SDK
#ifdef IS_CPU
//#define USE_BITSELECT
//#define USE_ROTATE
#endif
#endif

#ifdef IS_OPENCL
//#define USE_BITSELECT
//#define USE_ROTATE
//#define USE_SWIZZLE
#endif

#ifdef IS_METAL
#define USE_ROTATE

// Metal support max VECT_SIZE = 4
#define s0 x
#define s1 y
#define s2 z
#define s3 w
#endif

#endif // _INC_VENDOR_H
