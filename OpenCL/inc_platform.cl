/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"

#ifdef IS_NATIVE
#define FIXED_THREAD_COUNT(n)
#define SYNC_THREADS()
#endif

#ifdef IS_AMD

DECLSPEC u64x rotl64 (const u64x a, const int n)
{
  return rotr64 (a, 64 - n);
}

DECLSPEC u64x rotr64 (const u64x a, const int n)
{
  #if VECT_SIZE == 1
  return rotr64_S (a, n);
  #else
  return ((a >> n) | ((a << (64 - n))));
  #endif
}

DECLSPEC u64 rotl64_S (const u64 a, const int n)
{
  return rotr64_S (a, 64 - n);
}

DECLSPEC u64 rotr64_S (const u64 a, const int n)
{
  vconv64_t in;

  in.v64 = a;

  const u32 a0 = in.v32.a;
  const u32 a1 = in.v32.b;

  vconv64_t out;

  if (n < 32)
  {
    out.v32.a = amd_bitalign (a1, a0, n);
    out.v32.b = amd_bitalign (a0, a1, n);
  }
  else
  {
    out.v32.a = amd_bitalign (a0, a1, n - 32);
    out.v32.b = amd_bitalign (a1, a0, n - 32);
  }

  return out.v64;
}

#endif // IS_AMD

#if defined IS_CUDA

#if ATTACK_EXEC == 11

CONSTANT_VK u32 generic_constant[8192]; // 32k

#if   ATTACK_KERN == 0
#define bfs_buf     g_bfs_buf
#define rules_buf   ((const kernel_rule_t *) generic_constant)
#define words_buf_s g_words_buf_s
#define words_buf_r g_words_buf_r
#elif ATTACK_KERN == 1
#define bfs_buf     g_bfs_buf
#define rules_buf   g_rules_buf
#define words_buf_s g_words_buf_s
#define words_buf_r g_words_buf_r
#elif ATTACK_KERN == 3
#define rules_buf   g_rules_buf
#define bfs_buf     ((const bf_t *)      generic_constant)
#define words_buf_s ((const bs_word_t *) generic_constant)
#define words_buf_r ((const u32x *)      generic_constant)
#endif // ATTACK_KERN

#endif // ATTACK_EXEC

DECLSPEC u32 hc_atomic_dec (GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomicSub (p, val);
}

DECLSPEC u32 hc_atomic_inc (GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomicAdd (p, val);
}

DECLSPEC u32 hc_atomic_or (GLOBAL_AS u32 *p, volatile const u32 val)
{
  return atomicOr (p, val);
}

DECLSPEC size_t get_global_id  (const u32 dimindx __attribute__((unused)))
{
  return (blockIdx.x * blockDim.x) + threadIdx.x;
}

DECLSPEC size_t get_local_id (const u32 dimindx __attribute__((unused)))
{
  return threadIdx.x;
}

DECLSPEC size_t get_local_size (const u32 dimindx __attribute__((unused)))
{
  // verify
  return blockDim.x;
}

DECLSPEC u32x rotl32 (const u32x a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}

DECLSPEC u32x rotr32 (const u32x a, const int n)
{
  return ((a >> n) | ((a << (32 - n))));
}

DECLSPEC u32 rotl32_S (const u32 a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}

DECLSPEC u32 rotr32_S (const u32 a, const int n)
{
  return ((a >> n) | ((a << (32 - n))));
}

DECLSPEC u64x rotl64 (const u64x a, const int n)
{
  return ((a << n) | ((a >> (64 - n))));
}

DECLSPEC u64x rotr64 (const u64x a, const int n)
{
  return ((a >> n) | ((a << (64 - n))));
}

DECLSPEC u64 rotl64_S (const u64 a, const int n)
{
  return ((a << n) | ((a >> (64 - n))));
}

DECLSPEC u64 rotr64_S (const u64 a, const int n)
{
  return ((a >> n) | ((a << (64 - n))));
}

#define FIXED_THREAD_COUNT(n) __launch_bounds__((n), 0)
#define SYNC_THREADS() __syncthreads ()
#endif // IS_CUDA

#if defined IS_HIP

#if ATTACK_EXEC == 11

CONSTANT_VK u32 generic_constant[8192] __attribute__((used)); // 32k

#if   ATTACK_KERN == 0
#define bfs_buf     g_bfs_buf
#define rules_buf   ((const kernel_rule_t *) generic_constant)
#define words_buf_s g_words_buf_s
#define words_buf_r g_words_buf_r
#elif ATTACK_KERN == 1
#define bfs_buf     g_bfs_buf
#define rules_buf   g_rules_buf
#define words_buf_s g_words_buf_s
#define words_buf_r g_words_buf_r
#elif ATTACK_KERN == 3
#define rules_buf   g_rules_buf
#define bfs_buf     ((const bf_t *)      generic_constant)
#define words_buf_s ((const bs_word_t *) generic_constant)
#define words_buf_r ((const u32x *)      generic_constant)
#endif // ATTACK_KERN

#endif // ATTACK_EXEC

DECLSPEC u32 hc_atomic_dec (GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomicSub (p, val);
}

DECLSPEC u32 hc_atomic_inc (GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomicAdd (p, val);
}

DECLSPEC u32 hc_atomic_or (GLOBAL_AS u32 *p, volatile const u32 val)
{
  return atomicOr (p, val);
}

DECLSPEC size_t get_global_id  (const u32 dimindx __attribute__((unused)))
{
  return (blockIdx.x * blockDim.x) + threadIdx.x;
}

DECLSPEC size_t get_local_id (const u32 dimindx __attribute__((unused)))
{
  return threadIdx.x;
}

DECLSPEC size_t get_local_size (const u32 dimindx __attribute__((unused)))
{
  // verify
  return blockDim.x;
}

DECLSPEC u32x rotl32 (const u32x a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}

DECLSPEC u32x rotr32 (const u32x a, const int n)
{
  return ((a >> n) | ((a << (32 - n))));
}

DECLSPEC u32 rotl32_S (const u32 a, const int n)
{
  return ((a << n) | ((a >> (32 - n))));
}

DECLSPEC u32 rotr32_S (const u32 a, const int n)
{
  return ((a >> n) | ((a << (32 - n))));
}

DECLSPEC u64x rotl64 (const u64x a, const int n)
{
  return rotr64 (a, 64 - n);
}

DECLSPEC u32 amd_bitalign_S (const u32 a, const u32 b, const int n)
{
  u32 r = 0;

  __asm__ ("V_ALIGNBIT_B32 %0, %1, %2, %3;" : "=v"(r): "v"(a), "v"(b), "I"(n));

  return r;
}

DECLSPEC u64x rotr64 (const u64x a, const int n)
{
  #if VECT_SIZE == 1
  return rotr64_S (a, n);
  #else
  return ((a >> n) | ((a << (64 - n))));
  #endif
}

DECLSPEC u64 rotl64_S (const u64 a, const int n)
{
  return rotr64_S (a, 64 - n);
}

DECLSPEC u64 rotr64_S (const u64 a, const int n)
{
  vconv64_t in;

  in.v64 = a;

  const u32 a0 = in.v32.a;
  const u32 a1 = in.v32.b;

  vconv64_t out;

  if (n < 32)
  {
    out.v32.a = amd_bitalign_S (a1, a0, n);
    out.v32.b = amd_bitalign_S (a0, a1, n);
  }
  else
  {
    out.v32.a = amd_bitalign_S (a0, a1, n - 32);
    out.v32.b = amd_bitalign_S (a1, a0, n - 32);
  }

  return out.v64;
}

#define FIXED_THREAD_COUNT(n) __launch_bounds__((n), 0)
#define SYNC_THREADS() __syncthreads ()
#endif // IS_HIP

#ifdef IS_METAL

DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;
  volatile GLOBAL_AS atomic_int *pd = (volatile GLOBAL_AS atomic_int *) p;

  return atomic_fetch_sub_explicit (pd, val, memory_order_relaxed);
}

DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;
  volatile GLOBAL_AS atomic_int *pd = (volatile GLOBAL_AS atomic_int *) p;

  return atomic_fetch_add_explicit (pd, val, memory_order_relaxed);
}

DECLSPEC u32 hc_atomic_or (volatile GLOBAL_AS u32 *p, volatile const u32 val)
{
  volatile GLOBAL_AS atomic_int *pd = (volatile GLOBAL_AS atomic_int *) p;

  return atomic_fetch_or_explicit (pd, val, memory_order_relaxed);
}

#define FIXED_THREAD_COUNT(n)
#define SYNC_THREADS() threadgroup_barrier (mem_flags::mem_threadgroup)
#endif // IS_METAL

#ifdef IS_OPENCL

DECLSPEC u32 hc_atomic_dec (volatile GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomic_sub (p, val);
}

DECLSPEC u32 hc_atomic_inc (volatile GLOBAL_AS u32 *p)
{
  volatile const u32 val = 1;

  return atomic_add  (p, val);
}

DECLSPEC u32 hc_atomic_or (volatile GLOBAL_AS u32 *p, volatile const u32 val)
{
  return atomic_or (p, val);
}

#define FIXED_THREAD_COUNT(n) __attribute__((reqd_work_group_size((n), 1, 1)))
#define SYNC_THREADS() barrier (CLK_LOCAL_MEM_FENCE)
#endif // IS_OPENCL
