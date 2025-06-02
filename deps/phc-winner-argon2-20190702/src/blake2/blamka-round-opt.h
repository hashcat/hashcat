/*
 * Argon2 reference source code package - reference C implementations
 *
 * Copyright 2015
 * Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, and Samuel Neves
 *
 * You may use this work under the terms of a Creative Commons CC0 1.0
 * License/Waiver or the Apache Public License 2.0, at your option. The terms of
 * these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * You should have received a copy of both of these licenses along with this
 * software. If not, they may be obtained at the above URLs.
 */

#ifndef BLAKE_ROUND_MKA_OPT_H
#define BLAKE_ROUND_MKA_OPT_H

#include "blake2-impl.h"

#include <emmintrin.h>
#if defined(__SSSE3__)
#include <tmmintrin.h> /* for _mm_shuffle_epi8 and _mm_alignr_epi8 */
#endif

#if defined(__XOP__) && (defined(__GNUC__) || defined(__clang__))
#include <x86intrin.h>
#endif

#if !defined(__AVX512F__)
#if !defined(__AVX2__)
#if !defined(__XOP__)
#if defined(__SSSE3__)
#define r16                                                                    \
    (_mm_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))
#define r24                                                                    \
    (_mm_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))
#define _mm_roti_epi64(x, c)                                                   \
    (-(c) == 32)                                                               \
        ? _mm_shuffle_epi32((x), _MM_SHUFFLE(2, 3, 0, 1))                      \
        : (-(c) == 24)                                                         \
              ? _mm_shuffle_epi8((x), r24)                                     \
              : (-(c) == 16)                                                   \
                    ? _mm_shuffle_epi8((x), r16)                               \
                    : (-(c) == 63)                                             \
                          ? _mm_xor_si128(_mm_srli_epi64((x), -(c)),           \
                                          _mm_add_epi64((x), (x)))             \
                          : _mm_xor_si128(_mm_srli_epi64((x), -(c)),           \
                                          _mm_slli_epi64((x), 64 - (-(c))))
#else /* defined(__SSE2__) */
#define _mm_roti_epi64(r, c)                                                   \
    _mm_xor_si128(_mm_srli_epi64((r), -(c)), _mm_slli_epi64((r), 64 - (-(c))))
#endif
#else
#endif

static BLAKE2_INLINE __m128i fBlaMka(__m128i x, __m128i y) {
    const __m128i z = _mm_mul_epu32(x, y);
    return _mm_add_epi64(_mm_add_epi64(x, y), _mm_add_epi64(z, z));
}

#define G1(A0, B0, C0, D0, A1, B1, C1, D1)                                     \
    do {                                                                       \
        A0 = fBlaMka(A0, B0);                                                  \
        A1 = fBlaMka(A1, B1);                                                  \
                                                                               \
        D0 = _mm_xor_si128(D0, A0);                                            \
        D1 = _mm_xor_si128(D1, A1);                                            \
                                                                               \
        D0 = _mm_roti_epi64(D0, -32);                                          \
        D1 = _mm_roti_epi64(D1, -32);                                          \
                                                                               \
        C0 = fBlaMka(C0, D0);                                                  \
        C1 = fBlaMka(C1, D1);                                                  \
                                                                               \
        B0 = _mm_xor_si128(B0, C0);                                            \
        B1 = _mm_xor_si128(B1, C1);                                            \
                                                                               \
        B0 = _mm_roti_epi64(B0, -24);                                          \
        B1 = _mm_roti_epi64(B1, -24);                                          \
    } while ((void)0, 0)

#define G2(A0, B0, C0, D0, A1, B1, C1, D1)                                     \
    do {                                                                       \
        A0 = fBlaMka(A0, B0);                                                  \
        A1 = fBlaMka(A1, B1);                                                  \
                                                                               \
        D0 = _mm_xor_si128(D0, A0);                                            \
        D1 = _mm_xor_si128(D1, A1);                                            \
                                                                               \
        D0 = _mm_roti_epi64(D0, -16);                                          \
        D1 = _mm_roti_epi64(D1, -16);                                          \
                                                                               \
        C0 = fBlaMka(C0, D0);                                                  \
        C1 = fBlaMka(C1, D1);                                                  \
                                                                               \
        B0 = _mm_xor_si128(B0, C0);                                            \
        B1 = _mm_xor_si128(B1, C1);                                            \
                                                                               \
        B0 = _mm_roti_epi64(B0, -63);                                          \
        B1 = _mm_roti_epi64(B1, -63);                                          \
    } while ((void)0, 0)

#if defined(__SSSE3__)
#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                            \
    do {                                                                       \
        __m128i t0 = _mm_alignr_epi8(B1, B0, 8);                               \
        __m128i t1 = _mm_alignr_epi8(B0, B1, 8);                               \
        B0 = t0;                                                               \
        B1 = t1;                                                               \
                                                                               \
        t0 = C0;                                                               \
        C0 = C1;                                                               \
        C1 = t0;                                                               \
                                                                               \
        t0 = _mm_alignr_epi8(D1, D0, 8);                                       \
        t1 = _mm_alignr_epi8(D0, D1, 8);                                       \
        D0 = t1;                                                               \
        D1 = t0;                                                               \
    } while ((void)0, 0)

#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                          \
    do {                                                                       \
        __m128i t0 = _mm_alignr_epi8(B0, B1, 8);                               \
        __m128i t1 = _mm_alignr_epi8(B1, B0, 8);                               \
        B0 = t0;                                                               \
        B1 = t1;                                                               \
                                                                               \
        t0 = C0;                                                               \
        C0 = C1;                                                               \
        C1 = t0;                                                               \
                                                                               \
        t0 = _mm_alignr_epi8(D0, D1, 8);                                       \
        t1 = _mm_alignr_epi8(D1, D0, 8);                                       \
        D0 = t1;                                                               \
        D1 = t0;                                                               \
    } while ((void)0, 0)
#else /* SSE2 */
#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                            \
    do {                                                                       \
        __m128i t0 = D0;                                                       \
        __m128i t1 = B0;                                                       \
        D0 = C0;                                                               \
        C0 = C1;                                                               \
        C1 = D0;                                                               \
        D0 = _mm_unpackhi_epi64(D1, _mm_unpacklo_epi64(t0, t0));               \
        D1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(D1, D1));               \
        B0 = _mm_unpackhi_epi64(B0, _mm_unpacklo_epi64(B1, B1));               \
        B1 = _mm_unpackhi_epi64(B1, _mm_unpacklo_epi64(t1, t1));               \
    } while ((void)0, 0)

#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1)                          \
    do {                                                                       \
        __m128i t0, t1;                                                        \
        t0 = C0;                                                               \
        C0 = C1;                                                               \
        C1 = t0;                                                               \
        t0 = B0;                                                               \
        t1 = D0;                                                               \
        B0 = _mm_unpackhi_epi64(B1, _mm_unpacklo_epi64(B0, B0));               \
        B1 = _mm_unpackhi_epi64(t0, _mm_unpacklo_epi64(B1, B1));               \
        D0 = _mm_unpackhi_epi64(D0, _mm_unpacklo_epi64(D1, D1));               \
        D1 = _mm_unpackhi_epi64(D1, _mm_unpacklo_epi64(t1, t1));               \
    } while ((void)0, 0)
#endif

#define BLAKE2_ROUND(A0, A1, B0, B1, C0, C1, D0, D1)                           \
    do {                                                                       \
        G1(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
        G2(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
                                                                               \
        DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);                           \
                                                                               \
        G1(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
        G2(A0, B0, C0, D0, A1, B1, C1, D1);                                    \
                                                                               \
        UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1);                         \
    } while ((void)0, 0)
#else /* __AVX2__ */

#include <immintrin.h>

#define rotr32(x)   _mm256_shuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1))
#define rotr24(x)   _mm256_shuffle_epi8(x, _mm256_setr_epi8(3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10, 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10))
#define rotr16(x)   _mm256_shuffle_epi8(x, _mm256_setr_epi8(2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9, 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9))
#define rotr63(x)   _mm256_xor_si256(_mm256_srli_epi64((x), 63), _mm256_add_epi64((x), (x)))

#define G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml = _mm256_mul_epu32(A0, B0); \
        ml = _mm256_add_epi64(ml, ml); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D0 = rotr32(D0); \
        \
        ml = _mm256_mul_epu32(C0, D0); \
        ml = _mm256_add_epi64(ml, ml); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml)); \
        \
        B0 = _mm256_xor_si256(B0, C0); \
        B0 = rotr24(B0); \
        \
        ml = _mm256_mul_epu32(A1, B1); \
        ml = _mm256_add_epi64(ml, ml); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml)); \
        D1 = _mm256_xor_si256(D1, A1); \
        D1 = rotr32(D1); \
        \
        ml = _mm256_mul_epu32(C1, D1); \
        ml = _mm256_add_epi64(ml, ml); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml)); \
        \
        B1 = _mm256_xor_si256(B1, C1); \
        B1 = rotr24(B1); \
    } while((void)0, 0);

#define G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i ml = _mm256_mul_epu32(A0, B0); \
        ml = _mm256_add_epi64(ml, ml); \
        A0 = _mm256_add_epi64(A0, _mm256_add_epi64(B0, ml)); \
        D0 = _mm256_xor_si256(D0, A0); \
        D0 = rotr16(D0); \
        \
        ml = _mm256_mul_epu32(C0, D0); \
        ml = _mm256_add_epi64(ml, ml); \
        C0 = _mm256_add_epi64(C0, _mm256_add_epi64(D0, ml)); \
        B0 = _mm256_xor_si256(B0, C0); \
        B0 = rotr63(B0); \
        \
        ml = _mm256_mul_epu32(A1, B1); \
        ml = _mm256_add_epi64(ml, ml); \
        A1 = _mm256_add_epi64(A1, _mm256_add_epi64(B1, ml)); \
        D1 = _mm256_xor_si256(D1, A1); \
        D1 = rotr16(D1); \
        \
        ml = _mm256_mul_epu32(C1, D1); \
        ml = _mm256_add_epi64(ml, ml); \
        C1 = _mm256_add_epi64(C1, _mm256_add_epi64(D1, ml)); \
        B1 = _mm256_xor_si256(B1, C1); \
        B1 = rotr63(B1); \
    } while((void)0, 0);

#define DIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1)); \
        C0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3)); \
        \
        B1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1)); \
        C1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3)); \
    } while((void)0, 0);

#define DIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i tmp1 = _mm256_blend_epi32(B0, B1, 0xCC); \
        __m256i tmp2 = _mm256_blend_epi32(B0, B1, 0x33); \
        B1 = _mm256_permute4x64_epi64(tmp1, _MM_SHUFFLE(2,3,0,1)); \
        B0 = _mm256_permute4x64_epi64(tmp2, _MM_SHUFFLE(2,3,0,1)); \
        \
        tmp1 = C0; \
        C0 = C1; \
        C1 = tmp1; \
        \
        tmp1 = _mm256_blend_epi32(D0, D1, 0xCC); \
        tmp2 = _mm256_blend_epi32(D0, D1, 0x33); \
        D0 = _mm256_permute4x64_epi64(tmp1, _MM_SHUFFLE(2,3,0,1)); \
        D1 = _mm256_permute4x64_epi64(tmp2, _MM_SHUFFLE(2,3,0,1)); \
    } while(0);

#define UNDIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm256_permute4x64_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3)); \
        C0 = _mm256_permute4x64_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        D0 = _mm256_permute4x64_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1)); \
        \
        B1 = _mm256_permute4x64_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3)); \
        C1 = _mm256_permute4x64_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
        D1 = _mm256_permute4x64_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1)); \
    } while((void)0, 0);

#define UNDIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        __m256i tmp1 = _mm256_blend_epi32(B0, B1, 0xCC); \
        __m256i tmp2 = _mm256_blend_epi32(B0, B1, 0x33); \
        B0 = _mm256_permute4x64_epi64(tmp1, _MM_SHUFFLE(2,3,0,1)); \
        B1 = _mm256_permute4x64_epi64(tmp2, _MM_SHUFFLE(2,3,0,1)); \
        \
        tmp1 = C0; \
        C0 = C1; \
        C1 = tmp1; \
        \
        tmp1 = _mm256_blend_epi32(D0, D1, 0x33); \
        tmp2 = _mm256_blend_epi32(D0, D1, 0xCC); \
        D0 = _mm256_permute4x64_epi64(tmp1, _MM_SHUFFLE(2,3,0,1)); \
        D1 = _mm256_permute4x64_epi64(tmp2, _MM_SHUFFLE(2,3,0,1)); \
    } while((void)0, 0);

#define BLAKE2_ROUND_1(A0, A1, B0, B1, C0, C1, D0, D1) \
    do{ \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        \
        DIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
        \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        \
        UNDIAGONALIZE_1(A0, B0, C0, D0, A1, B1, C1, D1) \
    } while((void)0, 0);

#define BLAKE2_ROUND_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do{ \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        \
        DIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
        \
        G1_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        G2_AVX2(A0, A1, B0, B1, C0, C1, D0, D1) \
        \
        UNDIAGONALIZE_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    } while((void)0, 0);

#endif /* __AVX2__ */

#else /* __AVX512F__ */

#include <immintrin.h>

#define ror64(x, n) _mm512_ror_epi64((x), (n))

static __m512i muladd(__m512i x, __m512i y)
{
    __m512i z = _mm512_mul_epu32(x, y);
    return _mm512_add_epi64(_mm512_add_epi64(x, y), _mm512_add_epi64(z, z));
}

#define G1(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = muladd(A0, B0); \
        A1 = muladd(A1, B1); \
\
        D0 = _mm512_xor_si512(D0, A0); \
        D1 = _mm512_xor_si512(D1, A1); \
\
        D0 = ror64(D0, 32); \
        D1 = ror64(D1, 32); \
\
        C0 = muladd(C0, D0); \
        C1 = muladd(C1, D1); \
\
        B0 = _mm512_xor_si512(B0, C0); \
        B1 = _mm512_xor_si512(B1, C1); \
\
        B0 = ror64(B0, 24); \
        B1 = ror64(B1, 24); \
    } while ((void)0, 0)

#define G2(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        A0 = muladd(A0, B0); \
        A1 = muladd(A1, B1); \
\
        D0 = _mm512_xor_si512(D0, A0); \
        D1 = _mm512_xor_si512(D1, A1); \
\
        D0 = ror64(D0, 16); \
        D1 = ror64(D1, 16); \
\
        C0 = muladd(C0, D0); \
        C1 = muladd(C1, D1); \
\
        B0 = _mm512_xor_si512(B0, C0); \
        B1 = _mm512_xor_si512(B1, C1); \
\
        B0 = ror64(B0, 63); \
        B1 = ror64(B1, 63); \
    } while ((void)0, 0)

#define DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(0, 3, 2, 1)); \
        B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(0, 3, 2, 1)); \
\
        C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
\
        D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(2, 1, 0, 3)); \
        D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(2, 1, 0, 3)); \
    } while ((void)0, 0)

#define UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        B0 = _mm512_permutex_epi64(B0, _MM_SHUFFLE(2, 1, 0, 3)); \
        B1 = _mm512_permutex_epi64(B1, _MM_SHUFFLE(2, 1, 0, 3)); \
\
        C0 = _mm512_permutex_epi64(C0, _MM_SHUFFLE(1, 0, 3, 2)); \
        C1 = _mm512_permutex_epi64(C1, _MM_SHUFFLE(1, 0, 3, 2)); \
\
        D0 = _mm512_permutex_epi64(D0, _MM_SHUFFLE(0, 3, 2, 1)); \
        D1 = _mm512_permutex_epi64(D1, _MM_SHUFFLE(0, 3, 2, 1)); \
    } while ((void)0, 0)

#define BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1) \
    do { \
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
\
        DIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
\
        G1(A0, B0, C0, D0, A1, B1, C1, D1); \
        G2(A0, B0, C0, D0, A1, B1, C1, D1); \
\
        UNDIAGONALIZE(A0, B0, C0, D0, A1, B1, C1, D1); \
    } while ((void)0, 0)

#define SWAP_HALVES(A0, A1) \
    do { \
        __m512i t0, t1; \
        t0 = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(1, 0, 1, 0)); \
        t1 = _mm512_shuffle_i64x2(A0, A1, _MM_SHUFFLE(3, 2, 3, 2)); \
        A0 = t0; \
        A1 = t1; \
    } while((void)0, 0)

#define SWAP_QUARTERS(A0, A1) \
    do { \
        SWAP_HALVES(A0, A1); \
        A0 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A0); \
        A1 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A1); \
    } while((void)0, 0)

#define UNSWAP_QUARTERS(A0, A1) \
    do { \
        A0 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A0); \
        A1 = _mm512_permutexvar_epi64(_mm512_setr_epi64(0, 1, 4, 5, 2, 3, 6, 7), A1); \
        SWAP_HALVES(A0, A1); \
    } while((void)0, 0)

#define BLAKE2_ROUND_1(A0, C0, B0, D0, A1, C1, B1, D1) \
    do { \
        SWAP_HALVES(A0, B0); \
        SWAP_HALVES(C0, D0); \
        SWAP_HALVES(A1, B1); \
        SWAP_HALVES(C1, D1); \
        BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1); \
        SWAP_HALVES(A0, B0); \
        SWAP_HALVES(C0, D0); \
        SWAP_HALVES(A1, B1); \
        SWAP_HALVES(C1, D1); \
    } while ((void)0, 0)

#define BLAKE2_ROUND_2(A0, A1, B0, B1, C0, C1, D0, D1) \
    do { \
        SWAP_QUARTERS(A0, A1); \
        SWAP_QUARTERS(B0, B1); \
        SWAP_QUARTERS(C0, C1); \
        SWAP_QUARTERS(D0, D1); \
        BLAKE2_ROUND(A0, B0, C0, D0, A1, B1, C1, D1); \
        UNSWAP_QUARTERS(A0, A1); \
        UNSWAP_QUARTERS(B0, B1); \
        UNSWAP_QUARTERS(C0, C1); \
        UNSWAP_QUARTERS(D0, D1); \
    } while ((void)0, 0)

#endif /* __AVX512F__ */
#endif /* BLAKE_ROUND_MKA_OPT_H */
