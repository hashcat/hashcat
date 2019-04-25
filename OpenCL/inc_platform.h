/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PLATFORM_H

#ifdef IS_CUDA
DECLSPEC u32    atomic_dec      (u32 *p);
DECLSPEC u32    atomic_inc      (u32 *p);
DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_id    (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_size  (const u32 dimindx __attribute__((unused)));
DECLSPEC uint4  uint4_init      (const u32 a);
DECLSPEC uint4  uint4_init      (const u32 a, const u32 b, const u32 c, const u32 d);
DECLSPEC __inline__ u8    rotate (const u8  v, const int i);
DECLSPEC __inline__ u32   rotate (const u32 v, const int i);
DECLSPEC __inline__ u64   rotate (const u64 v, const int i);

#define rotate(a,n) (((a) << (n)) | ((a) >> (32 - (n))))
#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif

#endif // _INC_PLATFORM_H
