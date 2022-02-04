/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef _INC_PLATFORM_H
#define _INC_PLATFORM_H

DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

#ifdef IS_AMD
DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

DECLSPEC u64x rotl64   (const u64x a, const int n);
DECLSPEC u64x rotr64   (const u64x a, const int n);
DECLSPEC u64  rotl64_S (const u64  a, const int n);
DECLSPEC u64  rotr64_S (const u64  a, const int n);
#endif // IS_AMD

#ifdef IS_CUDA
DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_id    (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_local_size  (const u32 dimindx __attribute__((unused)));

DECLSPEC u32x rotl32   (const u32x a, const int n);
DECLSPEC u32x rotr32   (const u32x a, const int n);
DECLSPEC u32  rotl32_S (const u32  a, const int n);
DECLSPEC u32  rotr32_S (const u32  a, const int n);
DECLSPEC u64x rotl64   (const u64x a, const int n);
DECLSPEC u64x rotr64   (const u64x a, const int n);
DECLSPEC u64  rotl64_S (const u64  a, const int n);
DECLSPEC u64  rotr64_S (const u64  a, const int n);

//#define rotate(a,n) (((a) << (n)) | ((a) >> (32 - (n))))
#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif // IS_CUDA

#ifdef IS_HIP
DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

DECLSPEC size_t get_global_id   (const u32 dimindx);
DECLSPEC size_t get_local_id    (const u32 dimindx);
DECLSPEC size_t get_local_size  (const u32 dimindx);

DECLSPEC u32x rotl32   (const u32x a, const int n);
DECLSPEC u32x rotr32   (const u32x a, const int n);
DECLSPEC u32  rotl32_S (const u32  a, const int n);
DECLSPEC u32  rotr32_S (const u32  a, const int n);
DECLSPEC u64x rotl64   (const u64x a, const int n);
DECLSPEC u64x rotr64   (const u64x a, const int n);
DECLSPEC u64  rotl64_S (const u64  a, const int n);
DECLSPEC u64  rotr64_S (const u64  a, const int n);

//#define rotate(a,n) (((a) << (n)) | ((a) >> (32 - (n))))
#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif // IS_HIP

#ifdef IS_METAL

DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

#define get_global_id(param) hc_gid
#define get_local_id(param) hc_lid
#define get_local_size(param) hc_lsz

DECLSPEC u32x rotl32   (const u32x a, const int n);
DECLSPEC u32x rotr32   (const u32x a, const int n);
DECLSPEC u32  rotl32_S (const u32  a, const int n);
DECLSPEC u32  rotr32_S (const u32  a, const int n);
DECLSPEC u64x rotl64   (const u64x a, const int n);
DECLSPEC u64x rotr64   (const u64x a, const int n);
DECLSPEC u64  rotl64_S (const u64  a, const int n);
DECLSPEC u64  rotr64_S (const u64  a, const int n);

#define bitselect(a,b,c) ((a) ^ ((c) & ((b) ^ (a))))
#endif // IS_METAL

#endif // _INC_PLATFORM_H
