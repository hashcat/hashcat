/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

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
 * Some algorithms run into too much register pressure due to loop unrolling
 */

// generic vendors: those algos have shown that they produce better results on both amd and nv when not unrolled
// so we can assume they will produce better results on other vendors as well

#if KERN_TYPE == 1420
#undef _unroll
#endif
#if KERN_TYPE == 1450
#undef _unroll
#endif
#if KERN_TYPE == 1460
#undef _unroll
#endif
#if KERN_TYPE == 1720
#undef _unroll
#endif
#if KERN_TYPE == 1750
#undef _unroll
#endif
#if KERN_TYPE == 1760
#undef _unroll
#endif
#if KERN_TYPE == 1800
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
#if KERN_TYPE == 8200
#undef _unroll
#endif
#if KERN_TYPE == 8900
#undef _unroll
#endif
#if KERN_TYPE == 10700
#undef _unroll
#endif
#if KERN_TYPE == 12300
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
#if KERN_TYPE == 13751
#undef _unroll
#endif
#if KERN_TYPE == 13752
#undef _unroll
#endif
#if KERN_TYPE == 13753
#undef _unroll
#endif
#if KERN_TYPE == 13800
#undef _unroll
#endif

// nvidia specific

#ifdef IS_NV
#ifdef IS_GPU

#if KERN_TYPE == 1500
#undef _unroll
#endif
#if KERN_TYPE == 3000
#undef _unroll
#endif
#if KERN_TYPE == 3200
#undef _unroll
#endif
#if KERN_TYPE == 7900
#undef _unroll
#endif
#if KERN_TYPE == 10500
#undef _unroll
#endif
#if KERN_TYPE == 14000
#undef _unroll
#endif
#if KERN_TYPE == 14100
#undef _unroll
#endif

#endif
#endif

// amd specific

#ifdef IS_AMD
#ifdef IS_GPU

#if KERN_TYPE == 1700
#undef _unroll
#endif
#if KERN_TYPE == 1710
#undef _unroll
#endif
#if KERN_TYPE == 5200
#undef _unroll
#endif
#if KERN_TYPE == 8000
#undef _unroll
#endif
#if KERN_TYPE == 10400
#undef _unroll
#endif
#if KERN_TYPE == 10410
#undef _unroll
#endif
#if KERN_TYPE == 10800
#undef _unroll
#endif
#if KERN_TYPE == 10900
#undef _unroll
#endif
#if KERN_TYPE == 12800
#undef _unroll
#endif
#if KERN_TYPE == 12900
#undef _unroll
#endif

#endif
#endif

// apple specific

#ifdef IS_APPLE

#if KERN_TYPE == 5000
#undef _unroll
#endif

#endif
