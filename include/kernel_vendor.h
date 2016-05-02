/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
#endif

/**
 * vendor specific
 */

#if VENDOR_ID == (1 << 0)
#define IS_AMD
#elif VENDOR_ID == (1 << 6)
#define IS_NV
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
 * NV specific
 */

#ifdef IS_NV
#endif

/**
 * Generic
 */

#ifdef IS_GENERIC
#endif
