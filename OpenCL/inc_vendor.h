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
#else
#define IS_OPENCL
#endif

#if defined IS_NATIVE
#define CONSTANT_VK
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK
#define LOCAL_AS
#define KERNEL_FQ
#elif defined IS_CUDA
#define CONSTANT_VK __constant__
#define CONSTANT_AS
#define GLOBAL_AS
#define LOCAL_VK    __shared__
#define LOCAL_AS
#define KERNEL_FQ   extern "C" __global__
#elif defined IS_OPENCL
#define CONSTANT_VK __constant
#define CONSTANT_AS __constant
#define GLOBAL_AS   __global
#define LOCAL_VK    __local
#define LOCAL_AS    __local
#define KERNEL_FQ   __kernel
#endif

#ifndef MAYBE_VOLATILE
#define MAYBE_VOLATILE
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
#else
#define IS_GENERIC
#endif

#define LOCAL_MEM_TYPE_LOCAL  1
#define LOCAL_MEM_TYPE_GLOBAL 2

#if LOCAL_MEM_TYPE == LOCAL_MEM_TYPE_LOCAL
#define REAL_SHM
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

#if defined IS_CPU
#define DECLSPEC inline
#elif defined IS_GPU
#if defined IS_AMD
#define DECLSPEC inline static
#else
#define DECLSPEC
#endif
#else
#define DECLSPEC
#endif

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

/**
 * Unrolling is generally enabled, for all device types and hash modes
 * There's a few exception when it's better not to unroll
 * Some algorithms run into too much register pressure due to loop unrolling
 */

// generic vendors: those algos have shown that they produce better results on both amd and nv when not unrolled
// so we can assume they will produce better results on other vendors as well

#ifdef NO_UNROLL
#undef _unroll
#endif

#endif
