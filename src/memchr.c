/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

// Finding one byte in a buffer, in the widest form the processor running the binary supports.
//
// This is the only host side SIMD in the tree, so it is also the only place that has to ask what the
// processor can do. The answer is settled once at load time and read back through a function
// pointer, which keeps the question out of the loop and, more importantly, out of everything that
// merely wants to scan a buffer. A plugin that decodes a hash line has no business linking a
// dispatch over AVX-512.

#include "common.h"
#include "types.h"
#include "cpu_features.h"
#include "memchr.h"

#if defined (__x86_64__) || defined (_M_X64) || defined (__i386__) || defined (_M_IX86)
#include <immintrin.h>
#elif defined (__aarch64__)
#include <sse2neon.h>
#endif

size_t hc_memchr_generic (const u8 *ptr, int ch, size_t max_len)
{
  const u8 *found = memchr (ptr, ch, max_len);

  return found ? (size_t)(found - ptr) : max_len;
}

#if defined (__x86_64__) || defined (_M_X64) || defined (__i386__) || defined (_M_IX86) || defined (__aarch64__)
#if !defined (__aarch64__)
__attribute__((target("avx2")))
#endif
size_t hc_memchr_avx2 (const u8 *ptr, int ch, size_t max_len)
{
  size_t offset = 0;

  while (max_len >= 32)
  {
    #if defined (__aarch64__)

    __m128i block1 = _mm_loadu_si128      ((const __m128i *)(ptr));
    __m128i block2 = _mm_loadu_si128      ((const __m128i *)(ptr + 16));

    __m128i nl     = _mm_set1_epi8        (ch);

    __m128i cmp1   = _mm_cmpeq_epi8       (block1, nl);
    __m128i cmp2   = _mm_cmpeq_epi8       (block2, nl);

    int mask1      = _mm_movemask_epi8    (cmp1);
    int mask2      = _mm_movemask_epi8    (cmp2);

    if (mask1) return offset + __builtin_ctz (mask1);
    if (mask2) return offset + 16 + __builtin_ctz  (mask2);

    #else

    __m256i block  = _mm256_loadu_si256   ((const __m256i *)ptr);
    __m256i nl     = _mm256_set1_epi8     (ch);
    __m256i cmp    = _mm256_cmpeq_epi8    (block, nl);

    int mask       = _mm256_movemask_epi8 (cmp);

    if (mask != 0) return offset + __builtin_ctz (mask);

    #endif

    ptr     += 32;
    max_len -= 32;
    offset  += 32;
  }

  size_t tail = hc_memchr_generic (ptr, ch, max_len);

  return offset + tail;
}

#if !defined (__aarch64__)
__attribute__((target("avx512f,avx512bw")))
#endif
size_t hc_memchr_avx512 (const u8 *ptr, int ch, size_t max_len)
{
  size_t offset = 0;

  while (max_len >= 64)
  {
    #if defined (__aarch64__)

    // Map 64-byte scan using two 32-byte NEON blocks

    __m128i block1 = _mm_loadu_si128        ((const __m128i *)(ptr));
    __m128i block2 = _mm_loadu_si128        ((const __m128i *)(ptr + 16));
    __m128i block3 = _mm_loadu_si128        ((const __m128i *)(ptr + 32));
    __m128i block4 = _mm_loadu_si128        ((const __m128i *)(ptr + 48));

    __m128i nl     = _mm_set1_epi8          (ch);

    int mask1      = _mm_movemask_epi8      (_mm_cmpeq_epi8 (block1, nl));
    int mask2      = _mm_movemask_epi8      (_mm_cmpeq_epi8 (block2, nl));
    int mask3      = _mm_movemask_epi8      (_mm_cmpeq_epi8 (block3, nl));
    int mask4      = _mm_movemask_epi8      (_mm_cmpeq_epi8 (block4, nl));

    if (mask1) return offset + __builtin_ctz      (mask1);
    if (mask2) return offset + 16 + __builtin_ctz (mask2);
    if (mask3) return offset + 32 + __builtin_ctz (mask3);
    if (mask4) return offset + 48 + __builtin_ctz (mask4);

    #else

    __m512i block  = _mm512_loadu_si512     ((const __m512i *)ptr);
    __m512i nl     = _mm512_set1_epi8       (ch);
    __mmask64 mask = _mm512_cmpeq_epi8_mask (block, nl);

    if (mask != 0) return offset + __builtin_ctzll (mask);

    #endif

    ptr     += 64;
    max_len -= 64;
    offset  += 64;
  }

  size_t tail = hc_memchr_generic (ptr, ch, max_len);

  return offset + tail;
}
#endif // __x86_64__ || _M_X64 || __i386__ || _M_IX86 || __aarch64__

static hc_memchr_t hc_memchr_cached = hc_memchr_generic;

__attribute__((constructor))
static void hc_memchr_init (void)
{
  #if defined (__x86_64__) || defined (_M_X64) || defined (__i386__) || defined (_M_IX86)

  // AVX-512 is not used even where it is available, because it loses. What this scans for is the end of
  // a password, so it stops after about ten bytes, and a 64 byte load to travel ten bytes costs more
  // than it saves. Measured on a Zen 5, over a real wordlist of twelve million lines:
  //
  //   libc 279 M lines/s, AVX2 276 M/s, AVX-512 238 M/s
  //
  // and over fixed length lines it holds at every length from 6 bytes to 200. AVX-512 was never once
  // the fastest, and it was the one being chosen on every CPU new enough to have it.
  //
  // The library's own memchr is as fast as AVX2 here, and on glibc it would do. It is not used because
  // it is not the same routine everywhere: hashcat ships for Windows and macOS as well, and this is the
  // one place where a weak libc would cost the whole feed. AVX2 is the same speed on the C library that
  // is good and faster than the ones that are not.

  if (cpu_supports_avx2 ())
  {
    hc_memchr_cached = hc_memchr_avx2;
  }
  else
  {
    hc_memchr_cached = hc_memchr_generic;
  }

  #elif defined (__aarch64__)

  // Use 64-byte NEON-mapped function for Apple Silicon
  // hc_memchr_cached = hc_memchr_avx512;

  // Use 32-byte NEON-mapped function for Apple Silicon by default
  hc_memchr_cached   = hc_memchr_avx2;

  #else

  hc_memchr_cached   = hc_memchr_generic;

  #endif
}

hc_memchr_t hc_memchr_get (void)
{
  return hc_memchr_cached;
}