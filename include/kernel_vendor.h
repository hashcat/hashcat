/**
 * Author......: Jens Steube <jens.steube@gmail.com>
 * License.....: MIT
 */

#ifdef cl_khr_byte_addressable_store
#pragma OPENCL EXTENSION cl_khr_byte_addressable_store : enable
#endif

#ifdef cl_clang_storage_class_specifiers
#pragma OPENCL EXTENSION cl_clang_storage_class_specifiers : enable
#endif

/**
 * vendor specific
 */

#if VENDOR_ID == 4098
#define IS_AMD
#elif VENDOR_ID == 4318
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
