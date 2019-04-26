/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PLATFORM_H
#define _INC_PLATFORM_H

#ifdef IS_CUDA
DECLSPEC u32    atomic_dec      (u32 *p);
DECLSPEC u32    atomic_inc      (u32 *p);
DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_id    (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_size  (const u32 dimindx __attribute__((unused)));

#define rotate(a,n) (((a) << (n)) | ((a) >> (32 - (n))))
#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif

#endif // _INC_PLATFORM_H
