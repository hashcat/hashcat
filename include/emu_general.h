/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_OPENCL_EMU_H
#define _CPU_OPENCL_EMU_H

#define DEVICE_TYPE    -1
#define VENDOR_ID      -1
#define LOCAL_MEM_TYPE 2
#define CUDA_ARCH      0
#define HAS_VPERM      0
#define HAS_VADD3      0
#define HAS_VBFE       0
#define VECT_SIZE      1

uint atomic_dec (uint *p);
uint atomic_inc (uint *p);

size_t get_global_id  (uint dimindx __attribute__((unused)));
size_t get_local_id   (uint dimindx __attribute__((unused)));
size_t get_local_size (uint dimindx __attribute__((unused)));

#endif // _CPU_OPENCL_EMU_H
