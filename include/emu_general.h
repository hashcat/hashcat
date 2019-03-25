/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _CPU_OPENCL_EMU_H
#define _CPU_OPENCL_EMU_H

#include <math.h>
#include <stdint.h>
#include <stddef.h>

#define DEVICE_TYPE    -1
#define VENDOR_ID      -1
#define LOCAL_MEM_TYPE 2
#define CUDA_ARCH      0
#define HAS_VPERM      0
#define HAS_VADD3      0
#define HAS_VBFE       0
#define VECT_SIZE      1

typedef uint8_t  uchar;
typedef uint16_t ushort;
typedef uint32_t uint;
typedef uint64_t ulong;

typedef uchar  u8;
typedef ushort u16;
typedef uint   u32;
typedef ulong  u64;

// there's no such thing in plain C, therefore all vector operation cannot work in this emu
// which is why VECT_SIZE is set to 1

typedef u8  u8x;
typedef u16 u16x;
typedef u32 u32x;
typedef u64 u64x;

typedef uint uint4;

uint atomic_dec (uint *p);
uint atomic_inc (uint *p);

size_t get_global_id  (uint dimindx __attribute__((unused)));
size_t get_local_id   (uint dimindx __attribute__((unused)));
size_t get_local_size (uint dimindx __attribute__((unused)));

#endif // _CPU_OPENCL_EMU_H
