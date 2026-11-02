/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifndef INC_PLATFORM_H
#define INC_PLATFORM_H

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

#ifdef IS_NV
DECLSPEC u32 hc_funnelshift_l (const u32 lo, const u32 hi, const int shift);
DECLSPEC u32 hc_funnelshift_r (const u32 lo, const u32 hi, const int shift);
#endif // IS_NV

#ifdef IS_CUDA
DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_group_id    (const u32 dimindx);
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
#endif // IS_CUDA

#ifdef IS_HIP
DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p);
DECLSPEC u32 hc_atomic_or  (volatile GLOBAL_AS u32 *p, volatile const u32 val);

DECLSPEC size_t get_global_id   (const u32 dimindx __attribute__((unused)));
DECLSPEC size_t get_group_id    (const u32 dimindx);
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

#define get_global_id(dimindx)   \
  ((dimindx) == 0 ? hc_gid.x :   \
   (dimindx) == 1 ? hc_gid.y :   \
   (dimindx) == 2 ? hc_gid.z : -1)

#define get_group_id(dimindx)    \
  ((dimindx) == 0 ? hc_bid.x :   \
   (dimindx) == 1 ? hc_bid.y :   \
   (dimindx) == 2 ? hc_bid.z : -1)

#define get_local_id(dimindx)    \
  ((dimindx) == 0 ? hc_lid.x :   \
   (dimindx) == 1 ? hc_lid.y :   \
   (dimindx) == 2 ? hc_lid.z : -1)

#define get_local_size(dimindx)  \
  ((dimindx) == 0 ? hc_lsz.x :   \
   (dimindx) == 1 ? hc_lsz.y :   \
   (dimindx) == 2 ? hc_lsz.z : -1)

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

/**
 * cross lane exchange
 */

// hc_shfl_u64 hands every thread the value src_lane holds in var within the thread's own group of
// lsz threads, which has to lie within one wave (CUDA, HIP and NVIDIA OpenCL take 32 for lsz), and
// every thread of the group has to reach the call. Where there is no lane crossbar, the exchange
// goes through shfl_buf, which needs room for one u64 per thread, and every call is a barrier
// across the workgroup. HC_SHFL_BARRIER marks that case: there every thread of the workgroup has
// to make the calls.

// An AMD GPU reaches the crossbar through the lane builtins of the amdgcn target, but not every AMD
// OpenCL compiler declares them. The one in AMD's Windows driver rejects __builtin_amdgcn_mbcnt_hi,
// and since every program includes this file, no kernel builds at all. Where they are missing, the
// exchange goes through local memory as it does on other platforms.

#if defined IS_AMD_USE_OPENCL && defined IS_GPU && defined __has_builtin
#if __has_builtin (__builtin_amdgcn_mbcnt_lo) && __has_builtin (__builtin_amdgcn_mbcnt_hi) && __has_builtin (__builtin_amdgcn_ds_bpermute)
#define HC_SHFL_AMDGCN
#endif
#endif

#if defined IS_CUDA
#define hc_shfl_u64(shfl_buf,var,src_lane,lid,lsz) __shfl_sync (0xffffffff, (var), (src_lane))
#elif defined IS_HIP
// width is the wave, and the callers pin the workgroup to 32
#define hc_shfl_u64(shfl_buf,var,src_lane,lid,lsz) __shfl ((var), (src_lane), 32)
#else
#define hc_shfl_u64(shfl_buf,var,src_lane,lid,lsz) hc_shfl_u64_impl ((shfl_buf), (var), (src_lane), (lid), (lsz))
DECLSPEC u64 hc_shfl_u64_impl (MAYBE_UNUSED LOCAL_AS u64 *shfl_buf, const u64 var, const int src_lane, MAYBE_UNUSED const u32 lid, MAYBE_UNUSED const u32 lsz);
#if !defined IS_METAL && !defined HC_SHFL_AMDGCN && !(defined IS_NV && defined IS_GPU)
#define HC_SHFL_BARRIER
#endif
#endif

#endif // INC_PLATFORM_H
