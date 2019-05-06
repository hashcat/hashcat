/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PLATFORM_H
#define _INC_PLATFORM_H

#ifdef IS_CUDA
DECLSPEC u32    atomic_dec      (u32 *p);
DECLSPEC u32    atomic_inc      (u32 *p);
DECLSPEC u32    atomic_or       (u32 *p, u32 val);
DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_id    (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_size  (const u32 dimindx __attribute__((unused)));

DECLSPEC u32x hc_rotl32   (const u32x a, const int n);
DECLSPEC u32x hc_rotr32   (const u32x a, const int n);
DECLSPEC u32  hc_rotl32_S (const u32  a, const int n);
DECLSPEC u32  hc_rotr32_S (const u32  a, const int n);
DECLSPEC u64x hc_rotl64   (const u64x a, const int n);
DECLSPEC u64x hc_rotr64   (const u64x a, const int n);
DECLSPEC u64  hc_rotl64_S (const u64  a, const int n);
DECLSPEC u64  hc_rotr64_S (const u64  a, const int n);

//#define rotate(a,n) (((a) << (n)) | ((a) >> (32 - (n))))
#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif

#endif // _INC_PLATFORM_H
