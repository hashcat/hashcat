/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef HC_CPU_OPENCL_EMU_H
#define HC_CPU_OPENCL_EMU_H

// This guard is what inc_vendor.h reads to decide that it is compiling for the host, so this is the
// header that has to have the export macros in hand before it.

#include "export.h"

#define DEVICE_TYPE    -1
#define VENDOR_ID      -1
#define LOCAL_MEM_TYPE 2
#define CUDA_ARCH      0
#define HAS_VPERM      0
#define HAS_VADD3      0
#define HAS_VBFE       0
#define VECT_SIZE      1

#ifdef DGST_ELEM
typedef struct digest
{
  u32 digest_buf[DGST_ELEM];

} digest_t;
#endif

HC_PLUGIN_API size_t get_global_id  (u32 dimindx __attribute__((unused)));
HC_PLUGIN_API size_t get_local_id   (u32 dimindx __attribute__((unused)));
HC_PLUGIN_API size_t get_local_size (u32 dimindx __attribute__((unused)));

#endif // HC_CPU_OPENCL_EMU_H
