/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

//fails on intel opencl sdk
//#pragma OPENCL EXTENSION cl_khr_int64_base_atomics     : enable
//#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

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
//#define IS_GENERIC
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
//#define IS_GENERIC
#elif VENDOR_ID == (1 << 6)
#define IS_POCL
#define IS_GENERIC
#else
#define IS_GENERIC
#endif

/**
 * AMD specific
 */

#ifdef IS_AMD
#pragma OPENCL EXTENSION cl_amd_media_ops  : enable
#pragma OPENCL EXTENSION cl_amd_media_ops2 : enable
#endif

/**
 * Unrolling is generally enabled, for all device types and hash modes
 * There's a few exception when it's better not to unroll
 */

// Some algorithms run into too much register pressure due to loop unrolling

#ifdef IS_NV
#ifdef IS_GPU

#if KERN_TYPE == 1500
#undef _unroll
#endif
#if KERN_TYPE == 1800
#undef _unroll
#endif
#if KERN_TYPE == 3000
#undef _unroll
#endif
#if KERN_TYPE == 6221
#undef _unroll
#endif
#if KERN_TYPE == 6222
#undef _unroll
#endif
#if KERN_TYPE == 6223
#undef _unroll
#endif
#if KERN_TYPE == 6500
#undef _unroll
#endif
#if KERN_TYPE == 7100
#undef _unroll
#endif
#if KERN_TYPE == 7400
#undef _unroll
#endif
#if KERN_TYPE == 7900
#undef _unroll
#endif
#if KERN_TYPE == 8200
#undef _unroll
#endif
#if KERN_TYPE == 10400
#undef _unroll
#endif
#if KERN_TYPE == 10500
#undef _unroll
#endif
#if KERN_TYPE == 10700
#undef _unroll
#endif
#if KERN_TYPE == 12300
#undef _unroll
#endif
#if KERN_TYPE == 12400
#undef _unroll
#endif
#if KERN_TYPE == 13721
#undef _unroll
#endif
#if KERN_TYPE == 13722
#undef _unroll
#endif
#if KERN_TYPE == 13723
#undef _unroll
#endif

#endif
#endif

#ifdef IS_AMD
#ifdef IS_GPU

#if KERN_TYPE == 3200
#undef _unroll
#endif
#if KERN_TYPE == 5200
#undef _unroll
#endif
#if KERN_TYPE == 6100
#undef _unroll
#endif
#if KERN_TYPE == 6221
#undef _unroll
#endif
#if KERN_TYPE == 6222
#undef _unroll
#endif
#if KERN_TYPE == 6223
#undef _unroll
#endif
#if KERN_TYPE == 6400
#undef _unroll
#endif
#if KERN_TYPE == 6500
#undef _unroll
#endif
#if KERN_TYPE == 6800
#undef _unroll
#endif
#if KERN_TYPE == 7100
#undef _unroll
#endif
#if KERN_TYPE == 7400
#undef _unroll
#endif
#if KERN_TYPE == 8000
#undef _unroll
#endif
#if KERN_TYPE == 8200
#undef _unroll
#endif
#if KERN_TYPE == 10900
#undef _unroll
#endif
#if KERN_TYPE == 11600
#undef _unroll
#endif
#if KERN_TYPE == 12300
#undef _unroll
#endif
#if KERN_TYPE == 12800
#undef _unroll
#endif
#if KERN_TYPE == 12900
#undef _unroll
#endif
#if KERN_TYPE == 13000
#undef _unroll
#endif
#if KERN_TYPE == 13721
#undef _unroll
#endif
#if KERN_TYPE == 13722
#undef _unroll
#endif
#if KERN_TYPE == 13723
#undef _unroll
#endif

#endif
#endif

// Some algorithms break due to loop unrolling, it's unknown why, probably compiler bugs
// Can overlap with above cases

#ifdef IS_AMD
#ifdef IS_GPU

#if KERN_TYPE == 1750
#undef _unroll
#endif
#if KERN_TYPE == 1760
#undef _unroll
#endif
#if KERN_TYPE == 6500
#undef _unroll
#endif
#if KERN_TYPE == 7100
#undef _unroll
#endif
#if KERN_TYPE == 9600
#undef _unroll
#endif
#if KERN_TYPE == 12200
#undef _unroll
#endif
#if KERN_TYPE == 12300
#undef _unroll
#endif

#endif
#endif
