/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable

/**
 * vendor specific
 */

#if VENDOR_ID == 4098
#define IS_AMD
#endif

#if VENDOR_ID == 4318
#define IS_NV
#endif

#if VENDOR_ID == 9998 // temporary for dev
#define IS_UNKNOWN
#endif

#if VENDOR_ID == 9999
#define IS_UNKNOWN
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
