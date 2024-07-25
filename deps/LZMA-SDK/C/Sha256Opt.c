/* Sha256Opt.c -- SHA-256 optimized code for SHA-256 hardware instructions
2021-04-01 : Igor Pavlov : Public domain */

#include "Precomp.h"

#if defined(_MSC_VER)
#if (_MSC_VER < 1900) && (_MSC_VER >= 1200)
// #define USE_MY_MM
#endif
#endif

#include "CpuArch.h"

#ifdef MY_CPU_X86_OR_AMD64
  #if defined(__clang__)
    #if (__clang_major__ >= 8) // fix that check
      #define USE_HW_SHA
      #ifndef __SHA__
        #define ATTRIB_SHA __attribute__((__target__("sha,ssse3")))
        #if defined(_MSC_VER)
          // SSSE3: for clang-cl:
          #include <tmmintrin.h>
          #define __SHA__
        #endif
      #endif

    #endif
  #elif defined(__GNUC__)
    #if (__GNUC__ >= 8) // fix that check
      #define USE_HW_SHA
      #ifndef __SHA__
        #define ATTRIB_SHA __attribute__((__target__("sha,ssse3")))
        // #pragma GCC target("sha,ssse3")
      #endif
    #endif
  #elif defined(__INTEL_COMPILER)
    #if (__INTEL_COMPILER >= 1800) // fix that check
      #define USE_HW_SHA
    #endif
  #elif defined(_MSC_VER)
    #ifdef USE_MY_MM
      #define USE_VER_MIN 1300
    #else
      #define USE_VER_MIN 1910
    #endif
    #if _MSC_VER >= USE_VER_MIN
      #define USE_HW_SHA
    #endif
  #endif
// #endif // MY_CPU_X86_OR_AMD64

#ifdef USE_HW_SHA

// #pragma message("Sha256 HW")
// #include <wmmintrin.h>

#if !defined(_MSC_VER) || (_MSC_VER >= 1900)
#include <immintrin.h>
#else
#include <emmintrin.h>

#if defined(_MSC_VER) && (_MSC_VER >= 1600)
// #include <intrin.h>
#endif

#ifdef USE_MY_MM
#include "My_mm.h"
#endif

#endif

/*
SHA256 uses:
SSE2:
  _mm_loadu_si128
  _mm_storeu_si128
  _mm_set_epi32
  _mm_add_epi32
  _mm_shuffle_epi32 / pshufd


  
SSSE3:
  _mm_shuffle_epi8 / pshufb
  _mm_alignr_epi8
SHA:
  _mm_sha256*
*/

// K array must be aligned for 16-bytes at least.
// The compiler can look align attribute and selects
//   movdqu - for code without align attribute
//   movdqa - for code with    align attribute
extern
MY_ALIGN(64)
const UInt32 SHA256_K_ARRAY[64];

#define K SHA256_K_ARRAY


#define ADD_EPI32(dest, src) dest = _mm_add_epi32(dest, src);
#define SHA256_MSG1(dest, src) dest = _mm_sha256msg1_epu32(dest, src);
#define SHA25G_MSG2(dest, src) dest = _mm_sha256msg2_epu32(dest, src);


#define LOAD_SHUFFLE(m, k) \
    m = _mm_loadu_si128((const __m128i *)(const void *)(data + (k) * 16)); \
    m = _mm_shuffle_epi8(m, mask); \

#define SM1(g0, g1, g2, g3) \
    SHA256_MSG1(g3, g0); \

#define SM2(g0, g1, g2, g3) \
    tmp = _mm_alignr_epi8(g1, g0, 4); \
    ADD_EPI32(g2, tmp); \
    SHA25G_MSG2(g2, g1); \

// #define LS0(k, g0, g1, g2, g3) LOAD_SHUFFLE(g0, k)
// #define LS1(k, g0, g1, g2, g3) LOAD_SHUFFLE(g1, k+1)


#define NNN(g0, g1, g2, g3)


#define RND2(t0, t1) \
    t0 = _mm_sha256rnds2_epu32(t0, t1, msg);

#define RND2_0(m, k) \
    msg = _mm_add_epi32(m, *(const __m128i *) (const void *) &K[(k) * 4]); \
    RND2(state0, state1); \
    msg = _mm_shuffle_epi32(msg, 0x0E); \


#define RND2_1 \
    RND2(state1, state0); \


// We use scheme with 3 rounds ahead for SHA256_MSG1 / 2 rounds ahead for SHA256_MSG2

#define R4(k, g0, g1, g2, g3, OP0, OP1) \
    RND2_0(g0, k); \
    OP0(g0, g1, g2, g3); \
    RND2_1; \
    OP1(g0, g1, g2, g3); \

#define R16(k, OP0, OP1, OP2, OP3, OP4, OP5, OP6, OP7) \
    R4 ( (k)*4+0, m0, m1, m2, m3, OP0, OP1 ) \
    R4 ( (k)*4+1, m1, m2, m3, m0, OP2, OP3 ) \
    R4 ( (k)*4+2, m2, m3, m0, m1, OP4, OP5 ) \
    R4 ( (k)*4+3, m3, m0, m1, m2, OP6, OP7 ) \

#define PREPARE_STATE \
    tmp    = _mm_shuffle_epi32(state0, 0x1B); /* abcd */ \
    state0 = _mm_shuffle_epi32(state1, 0x1B); /* efgh */ \
    state1 = state0; \
    state0 = _mm_unpacklo_epi64(state0, tmp); /* cdgh */ \
    state1 = _mm_unpackhi_epi64(state1, tmp); /* abef */ \


void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks);
#ifdef ATTRIB_SHA
ATTRIB_SHA
#endif
void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks)
{
  const __m128i mask = _mm_set_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203);
  __m128i tmp;
  __m128i state0, state1;

  if (numBlocks == 0)
    return;

  state0 = _mm_loadu_si128((const __m128i *) (const void *) &state[0]);
  state1 = _mm_loadu_si128((const __m128i *) (const void *) &state[4]);
  
  PREPARE_STATE

  do
  {
    __m128i state0_save, state1_save;
    __m128i m0, m1, m2, m3;
    __m128i msg;
    // #define msg tmp

    state0_save = state0;
    state1_save = state1;
    
    LOAD_SHUFFLE (m0, 0)
    LOAD_SHUFFLE (m1, 1)
    LOAD_SHUFFLE (m2, 2)
    LOAD_SHUFFLE (m3, 3)



    R16 ( 0, NNN, NNN, SM1, NNN, SM1, SM2, SM1, SM2 );
    R16 ( 1, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 );
    R16 ( 2, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 );
    R16 ( 3, SM1, SM2, NNN, SM2, NNN, NNN, NNN, NNN );
    
    ADD_EPI32(state0, state0_save);
    ADD_EPI32(state1, state1_save);
    
    data += 64;
  }
  while (--numBlocks);

  PREPARE_STATE

  _mm_storeu_si128((__m128i *) (void *) &state[0], state0);
  _mm_storeu_si128((__m128i *) (void *) &state[4], state1);
}

#endif // USE_HW_SHA

#elif defined(MY_CPU_ARM_OR_ARM64)

  #if defined(__clang__)
    #if (__clang_major__ >= 8) // fix that check
      #define USE_HW_SHA
    #endif
  #elif defined(__GNUC__)
    #if (__GNUC__ >= 6) // fix that check
      #define USE_HW_SHA
    #endif
  #elif defined(_MSC_VER)
    #if _MSC_VER >= 1910
      #define USE_HW_SHA
    #endif
  #endif

#ifdef USE_HW_SHA

// #pragma message("=== Sha256 HW === ")

#if defined(__clang__) || defined(__GNUC__)
  #ifdef MY_CPU_ARM64
    #define ATTRIB_SHA __attribute__((__target__("+crypto")))
  #else
    #define ATTRIB_SHA __attribute__((__target__("fpu=crypto-neon-fp-armv8")))
  #endif
#else
  // _MSC_VER
  // for arm32
  #define _ARM_USE_NEW_NEON_INTRINSICS
#endif

#if defined(_MSC_VER) && defined(MY_CPU_ARM64)
#include <arm64_neon.h>
#else
#include <arm_neon.h>
#endif

typedef uint32x4_t v128;
// typedef __n128 v128; // MSVC

#ifdef MY_CPU_BE
  #define MY_rev32_for_LE(x)
#else
  #define MY_rev32_for_LE(x) x = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(x)))
#endif

#define LOAD_128(_p)      (*(const v128 *)(const void *)(_p))
#define STORE_128(_p, _v) *(v128 *)(void *)(_p) = (_v)

#define LOAD_SHUFFLE(m, k) \
    m = LOAD_128((data + (k) * 16)); \
    MY_rev32_for_LE(m); \

// K array must be aligned for 16-bytes at least.
extern
MY_ALIGN(64)
const UInt32 SHA256_K_ARRAY[64];

#define K SHA256_K_ARRAY


#define SHA256_SU0(dest, src)        dest = vsha256su0q_u32(dest, src);
#define SHA25G_SU1(dest, src2, src3) dest = vsha256su1q_u32(dest, src2, src3);

#define SM1(g0, g1, g2, g3)  SHA256_SU0(g3, g0)
#define SM2(g0, g1, g2, g3)  SHA25G_SU1(g2, g0, g1)
#define NNN(g0, g1, g2, g3)


#define R4(k, g0, g1, g2, g3, OP0, OP1) \
    msg = vaddq_u32(g0, *(const v128 *) (const void *) &K[(k) * 4]); \
    tmp = state0; \
    state0 = vsha256hq_u32( state0, state1, msg ); \
    state1 = vsha256h2q_u32( state1, tmp, msg ); \
    OP0(g0, g1, g2, g3); \
    OP1(g0, g1, g2, g3); \


#define R16(k, OP0, OP1, OP2, OP3, OP4, OP5, OP6, OP7) \
    R4 ( (k)*4+0, m0, m1, m2, m3, OP0, OP1 ) \
    R4 ( (k)*4+1, m1, m2, m3, m0, OP2, OP3 ) \
    R4 ( (k)*4+2, m2, m3, m0, m1, OP4, OP5 ) \
    R4 ( (k)*4+3, m3, m0, m1, m2, OP6, OP7 ) \


void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks);
#ifdef ATTRIB_SHA
ATTRIB_SHA
#endif
void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks)
{
  v128 state0, state1;

  if (numBlocks == 0)
    return;

  state0 = LOAD_128(&state[0]);
  state1 = LOAD_128(&state[4]);
  
  do
  {
    v128 state0_save, state1_save;
    v128 m0, m1, m2, m3;
    v128 msg, tmp;

    state0_save = state0;
    state1_save = state1;
    
    LOAD_SHUFFLE (m0, 0)
    LOAD_SHUFFLE (m1, 1)
    LOAD_SHUFFLE (m2, 2)
    LOAD_SHUFFLE (m3, 3)

    R16 ( 0, NNN, NNN, SM1, NNN, SM1, SM2, SM1, SM2 );
    R16 ( 1, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 );
    R16 ( 2, SM1, SM2, SM1, SM2, SM1, SM2, SM1, SM2 );
    R16 ( 3, SM1, SM2, NNN, SM2, NNN, NNN, NNN, NNN );
    
    state0 = vaddq_u32(state0, state0_save);
    state1 = vaddq_u32(state1, state1_save);
    
    data += 64;
  }
  while (--numBlocks);

  STORE_128(&state[0], state0);
  STORE_128(&state[4], state1);
}

#endif // USE_HW_SHA

#endif // MY_CPU_ARM_OR_ARM64


#ifndef USE_HW_SHA

// #error Stop_Compiling_UNSUPPORTED_SHA
// #include <stdlib.h>

// #include "Sha256.h"
void MY_FAST_CALL Sha256_UpdateBlocks(UInt32 state[8], const Byte *data, size_t numBlocks);

#pragma message("Sha256 HW-SW stub was used")

void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks);
void MY_FAST_CALL Sha256_UpdateBlocks_HW(UInt32 state[8], const Byte *data, size_t numBlocks)
{
  Sha256_UpdateBlocks(state, data, numBlocks);
  /*
  UNUSED_VAR(state);
  UNUSED_VAR(data);
  UNUSED_VAR(numBlocks);
  exit(1);
  return;
  */
}

#endif
