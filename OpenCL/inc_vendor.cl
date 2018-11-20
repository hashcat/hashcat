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
#define AMD_GCN 0
#if AMD_ROCM == 1
#if defined __gfx600__ || defined __gfx601__
#undef  AMD_GCN
#define AMD_GCN 1
#endif
#if defined __gfx700__ || defined __gfx701__ || defined __gfx702__ || defined __gfx703__
#undef  AMD_GCN
#define AMD_GCN 2
#endif
#if defined __gfx800__ || defined __gfx801__ || defined __gfx802__ || defined __gfx803__ || defined __gfx804__ || defined __gfx810__
#undef  AMD_GCN
#define AMD_GCN 3
// According to AMD docs, GCN 3 and 4 are the same
#endif
#if defined __gfx900__ || defined __gfx901__ || defined __gfx902__ || defined __gfx903__
#undef  AMD_GCN
#define AMD_GCN 5
#endif
#endif
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
#define SHM_TYPE __local
#else
#define SHM_TYPE __constant
#endif

/**
 * function declarations can have a large influence depending on the opencl runtime
 */

#if defined IS_CPU
#define DECLSPEC inline
#elif defined IS_GPU
#if defined IS_AMD
#define DECLSPEC inline
#else
#define DECLSPEC
#endif
#else
#define DECLSPEC
#endif

#if (defined IS_AMD && AMD_GCN < 3)
#define MAYBE_VOLATILE volatile
#else
#define MAYBE_VOLATILE
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
#if KERN_TYPE == 7100
#undef _unroll
#endif
#if KERN_TYPE == 7400
#undef _unroll
#endif
#if KERN_TYPE == 7900
#undef _unroll
#endif
#if KERN_TYPE == 8900
#undef _unroll
#endif
#if KERN_TYPE == 10700
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
#if KERN_TYPE == 15700
#undef _unroll
#endif

// nvidia specific

#ifdef IS_NV
#ifdef IS_GPU

#endif
#endif

// amd specific

#ifdef IS_AMD
#ifdef IS_GPU

#if KERN_TYPE == 8000
#undef _unroll
#endif
#if KERN_TYPE == 8200
#undef _unroll
#endif
#if KERN_TYPE == 12300
#undef _unroll
#endif
#if KERN_TYPE == 14100
#undef _unroll
#endif
#if KERN_TYPE == 15300
#undef _unroll
#endif
#if KERN_TYPE == 15900
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
