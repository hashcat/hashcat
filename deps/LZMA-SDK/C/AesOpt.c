/* AesOpt.c -- AES optimized code for x86 AES hardware instructions
2021-04-01 : Igor Pavlov : Public domain */

#include "Precomp.h"

#include "CpuArch.h"

#ifdef MY_CPU_X86_OR_AMD64

  #if defined(__clang__)
    #if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 8)
      #define USE_INTEL_AES
        #define ATTRIB_AES __attribute__((__target__("aes")))
      #if (__clang_major__ >= 8)
        #define USE_INTEL_VAES
        #define ATTRIB_VAES __attribute__((__target__("aes,vaes,avx2")))
      #endif
    #endif
  #elif defined(__GNUC__)
    #if (__GNUC__ > 4) || (__GNUC__ == 4 && __GNUC_MINOR__ >= 4)
      #define USE_INTEL_AES
      #ifndef __AES__
        #define ATTRIB_AES __attribute__((__target__("aes")))
      #endif
      #if (__GNUC__ >= 8)
        #define USE_INTEL_VAES
        #define ATTRIB_VAES __attribute__((__target__("aes,vaes,avx2")))
      #endif
    #endif
  #elif defined(__INTEL_COMPILER)
    #if (__INTEL_COMPILER >= 1110)
      #define USE_INTEL_AES
      #if (__INTEL_COMPILER >= 1900)
        #define USE_INTEL_VAES
      #endif
    #endif
  #elif defined(_MSC_VER)
    #if (_MSC_VER > 1500) || (_MSC_FULL_VER >= 150030729)
      #define USE_INTEL_AES
      #if (_MSC_VER >= 1910)
        #define USE_INTEL_VAES
      #endif
    #endif
  #endif

#ifndef ATTRIB_AES
  #define ATTRIB_AES
#endif
#ifndef ATTRIB_VAES
  #define ATTRIB_VAES
#endif


#ifdef USE_INTEL_AES

#include <wmmintrin.h>

#ifndef USE_INTEL_VAES
#define AES_TYPE_keys __m128i
#define AES_TYPE_data __m128i
#endif

#define AES_FUNC_START(name) \
    void MY_FAST_CALL name(__m128i *p, __m128i *data, size_t numBlocks)

#define AES_FUNC_START2(name) \
AES_FUNC_START (name); \
ATTRIB_AES \
AES_FUNC_START (name)

#define MM_OP(op, dest, src)  dest = op(dest, src);
#define MM_OP_m(op, src)      MM_OP(op, m, src);

#define MM_XOR( dest, src)    MM_OP(_mm_xor_si128,    dest, src);
#define AVX_XOR(dest, src)    MM_OP(_mm256_xor_si256, dest, src);


AES_FUNC_START2 (AesCbc_Encode_HW)
{
  __m128i m = *p;
  const __m128i k0 = p[2];
  const __m128i k1 = p[3];
  const UInt32 numRounds2 = *(const UInt32 *)(p + 1) - 1;
  for (; numBlocks != 0; numBlocks--, data++)
  {
    UInt32 r = numRounds2;
    const __m128i *w = p + 4;
    __m128i temp = *data;
    MM_XOR (temp, k0);
    MM_XOR (m, temp);
    MM_OP_m (_mm_aesenc_si128, k1);
    do
    {
      MM_OP_m (_mm_aesenc_si128, w[0]);
      MM_OP_m (_mm_aesenc_si128, w[1]);
      w += 2;
    }
    while (--r);
    MM_OP_m (_mm_aesenclast_si128, w[0]);
    *data = m;
  }
  *p = m;
}


#define WOP_1(op)
#define WOP_2(op)   WOP_1 (op)  op (m1, 1);
#define WOP_3(op)   WOP_2 (op)  op (m2, 2);
#define WOP_4(op)   WOP_3 (op)  op (m3, 3);
#ifdef MY_CPU_AMD64
#define WOP_5(op)   WOP_4 (op)  op (m4, 4);
#define WOP_6(op)   WOP_5 (op)  op (m5, 5);
#define WOP_7(op)   WOP_6 (op)  op (m6, 6);
#define WOP_8(op)   WOP_7 (op)  op (m7, 7);
#endif
/*
#define WOP_9(op)   WOP_8 (op)  op (m8, 8);
#define WOP_10(op)  WOP_9 (op)  op (m9, 9);
#define WOP_11(op)  WOP_10(op)  op (m10, 10);
#define WOP_12(op)  WOP_11(op)  op (m11, 11);
#define WOP_13(op)  WOP_12(op)  op (m12, 12);
#define WOP_14(op)  WOP_13(op)  op (m13, 13);
*/

#ifdef MY_CPU_AMD64
  #define NUM_WAYS      8
  #define WOP_M1    WOP_8
#else
  #define NUM_WAYS      4
  #define WOP_M1    WOP_4
#endif

#define WOP(op)  op (m0, 0);  WOP_M1(op)


#define DECLARE_VAR(reg, ii)  __m128i reg
#define LOAD_data(  reg, ii)  reg = data[ii];
#define STORE_data( reg, ii)  data[ii] = reg;
#if (NUM_WAYS > 1)
#define XOR_data_M1(reg, ii)  MM_XOR (reg, data[ii- 1]);
#endif

#define AVX__DECLARE_VAR(reg, ii)  __m256i reg
#define AVX__LOAD_data(  reg, ii)  reg = ((const __m256i *)(const void *)data)[ii];
#define AVX__STORE_data( reg, ii)  ((__m256i *)(void *)data)[ii] = reg;
#define AVX__XOR_data_M1(reg, ii)  AVX_XOR (reg, (((const __m256i *)(const void *)(data - 1))[ii]));

#define MM_OP_key(op, reg)  MM_OP(op, reg, key);

#define AES_DEC(      reg, ii)   MM_OP_key (_mm_aesdec_si128,     reg)
#define AES_DEC_LAST( reg, ii)   MM_OP_key (_mm_aesdeclast_si128, reg)
#define AES_ENC(      reg, ii)   MM_OP_key (_mm_aesenc_si128,     reg)
#define AES_ENC_LAST( reg, ii)   MM_OP_key (_mm_aesenclast_si128, reg)
#define AES_XOR(      reg, ii)   MM_OP_key (_mm_xor_si128,        reg)


#define AVX__AES_DEC(      reg, ii)   MM_OP_key (_mm256_aesdec_epi128,     reg)
#define AVX__AES_DEC_LAST( reg, ii)   MM_OP_key (_mm256_aesdeclast_epi128, reg)
#define AVX__AES_ENC(      reg, ii)   MM_OP_key (_mm256_aesenc_epi128,     reg)
#define AVX__AES_ENC_LAST( reg, ii)   MM_OP_key (_mm256_aesenclast_epi128, reg)
#define AVX__AES_XOR(      reg, ii)   MM_OP_key (_mm256_xor_si256,         reg)

#define CTR_START(reg, ii)  MM_OP (_mm_add_epi64, ctr, one); reg = ctr;
#define CTR_END(  reg, ii)  MM_XOR (data[ii], reg);

#define AVX__CTR_START(reg, ii)  MM_OP (_mm256_add_epi64, ctr2, two); reg = _mm256_xor_si256(ctr2, key);
#define AVX__CTR_END(  reg, ii)  AVX_XOR (((__m256i *)(void *)data)[ii], reg);

#define WOP_KEY(op, n) { \
    const __m128i key = w[n]; \
    WOP(op); }

#define AVX__WOP_KEY(op, n) { \
    const __m256i key = w[n]; \
    WOP(op); }


#define WIDE_LOOP_START  \
    dataEnd = data + numBlocks;  \
    if (numBlocks >= NUM_WAYS)  \
    { dataEnd -= NUM_WAYS; do {  \


#define WIDE_LOOP_END  \
    data += NUM_WAYS;  \
    } while (data <= dataEnd);  \
    dataEnd += NUM_WAYS; }  \


#define SINGLE_LOOP  \
    for (; data < dataEnd; data++)


#define NUM_AES_KEYS_MAX 15

#define WIDE_LOOP_START_AVX(OP)  \
    dataEnd = data + numBlocks;  \
    if (numBlocks >= NUM_WAYS * 2)  \
    { __m256i keys[NUM_AES_KEYS_MAX]; \
    UInt32 ii; \
    OP \
    for (ii = 0; ii < numRounds; ii++) \
      keys[ii] = _mm256_broadcastsi128_si256(p[ii]); \
    dataEnd -= NUM_WAYS * 2; do {  \


#define WIDE_LOOP_END_AVX(OP)  \
    data += NUM_WAYS * 2;  \
    } while (data <= dataEnd);  \
    dataEnd += NUM_WAYS * 2;  \
    OP  \
    _mm256_zeroupper();  \
    }  \

/* MSVC for x86: If we don't call _mm256_zeroupper(), and -arch:IA32 is not specified,
   MSVC still can insert vzeroupper instruction. */


AES_FUNC_START2 (AesCbc_Decode_HW)
{
  __m128i iv = *p;
  const __m128i *wStart = p + *(const UInt32 *)(p + 1) * 2 + 2 - 1;
  const __m128i *dataEnd;
  p += 2;
  
  WIDE_LOOP_START
  {
    const __m128i *w = wStart;
    
    WOP (DECLARE_VAR)
    WOP (LOAD_data);
    WOP_KEY (AES_XOR, 1)

    do
    {
      WOP_KEY (AES_DEC, 0)
      w--;
    }
    while (w != p);
    WOP_KEY (AES_DEC_LAST, 0)

    MM_XOR (m0, iv);
    WOP_M1 (XOR_data_M1)
    iv = data[NUM_WAYS - 1];
    WOP (STORE_data);
  }
  WIDE_LOOP_END

  SINGLE_LOOP
  {
    const __m128i *w = wStart - 1;
    __m128i m = _mm_xor_si128 (w[2], *data);
    do
    {
      MM_OP_m (_mm_aesdec_si128, w[1]);
      MM_OP_m (_mm_aesdec_si128, w[0]);
      w -= 2;
    }
    while (w != p);
    MM_OP_m (_mm_aesdec_si128,     w[1]);
    MM_OP_m (_mm_aesdeclast_si128, w[0]);

    MM_XOR (m, iv);
    iv = *data;
    *data = m;
  }
  
  p[-2] = iv;
}


AES_FUNC_START2 (AesCtr_Code_HW)
{
  __m128i ctr = *p;
  UInt32 numRoundsMinus2 = *(const UInt32 *)(p + 1) * 2 - 1;
  const __m128i *dataEnd;
  __m128i one = _mm_cvtsi32_si128(1);

  p += 2;
  
  WIDE_LOOP_START
  {
    const __m128i *w = p;
    UInt32 r = numRoundsMinus2;
    WOP (DECLARE_VAR)
    WOP (CTR_START);
    WOP_KEY (AES_XOR, 0)
    w += 1;
    do
    {
      WOP_KEY (AES_ENC, 0)
      w += 1;
    }
    while (--r);
    WOP_KEY (AES_ENC_LAST, 0)
   
    WOP (CTR_END);
  }
  WIDE_LOOP_END

  SINGLE_LOOP
  {
    UInt32 numRounds2 = *(const UInt32 *)(p - 2 + 1) - 1;
    const __m128i *w = p;
    __m128i m;
    MM_OP (_mm_add_epi64, ctr, one);
    m = _mm_xor_si128 (ctr, p[0]);
    w += 1;
    do
    {
      MM_OP_m (_mm_aesenc_si128, w[0]);
      MM_OP_m (_mm_aesenc_si128, w[1]);
      w += 2;
    }
    while (--numRounds2);
    MM_OP_m (_mm_aesenc_si128,     w[0]);
    MM_OP_m (_mm_aesenclast_si128, w[1]);
    MM_XOR (*data, m);
  }
  
  p[-2] = ctr;
}



#ifdef USE_INTEL_VAES

#if defined(__clang__) && defined(_MSC_VER)
#define __SSE4_2__
#define __AES__
#define __AVX__
#define __AVX2__
#define __VAES__
#define __AVX512F__
#define __AVX512VL__
#endif

#include <immintrin.h>

#define VAES_FUNC_START2(name) \
AES_FUNC_START (name); \
ATTRIB_VAES \
AES_FUNC_START (name)

VAES_FUNC_START2 (AesCbc_Decode_HW_256)
{
  __m128i iv = *p;
  const __m128i *dataEnd;
  UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
  p += 2;
  
  WIDE_LOOP_START_AVX(;)
  {
    const __m256i *w = keys + numRounds - 2;
    
    WOP (AVX__DECLARE_VAR)
    WOP (AVX__LOAD_data);
    AVX__WOP_KEY (AVX__AES_XOR, 1)

    do
    {
      AVX__WOP_KEY (AVX__AES_DEC, 0)
      w--;
    }
    while (w != keys);
    AVX__WOP_KEY (AVX__AES_DEC_LAST, 0)

    AVX_XOR (m0, _mm256_setr_m128i(iv, data[0]));
    WOP_M1 (AVX__XOR_data_M1)
    iv = data[NUM_WAYS * 2 - 1];
    WOP (AVX__STORE_data);
  }
  WIDE_LOOP_END_AVX(;)

  SINGLE_LOOP
  {
    const __m128i *w = p + *(const UInt32 *)(p + 1 - 2) * 2 + 1 - 3;
    __m128i m = _mm_xor_si128 (w[2], *data);
    do
    {
      MM_OP_m (_mm_aesdec_si128, w[1]);
      MM_OP_m (_mm_aesdec_si128, w[0]);
      w -= 2;
    }
    while (w != p);
    MM_OP_m (_mm_aesdec_si128,     w[1]);
    MM_OP_m (_mm_aesdeclast_si128, w[0]);

    MM_XOR (m, iv);
    iv = *data;
    *data = m;
  }
  
  p[-2] = iv;
}


/*
SSE2: _mm_cvtsi32_si128 : movd
AVX:  _mm256_setr_m128i            : vinsertf128
AVX2: _mm256_add_epi64             : vpaddq ymm, ymm, ymm
      _mm256_extracti128_si256     : vextracti128
      _mm256_broadcastsi128_si256  : vbroadcasti128
*/

#define AVX__CTR_LOOP_START  \
    ctr2 = _mm256_setr_m128i(_mm_sub_epi64(ctr, one), ctr); \
    two = _mm256_setr_m128i(one, one); \
    two = _mm256_add_epi64(two, two); \

// two = _mm256_setr_epi64x(2, 0, 2, 0);
  
#define AVX__CTR_LOOP_ENC  \
    ctr = _mm256_extracti128_si256 (ctr2, 1); \
 
VAES_FUNC_START2 (AesCtr_Code_HW_256)
{
  __m128i ctr = *p;
  UInt32 numRounds = *(const UInt32 *)(p + 1) * 2 + 1;
  const __m128i *dataEnd;
  __m128i one = _mm_cvtsi32_si128(1);
  __m256i ctr2, two;
  p += 2;
  
  WIDE_LOOP_START_AVX (AVX__CTR_LOOP_START)
  {
    const __m256i *w = keys;
    UInt32 r = numRounds - 2;
    WOP (AVX__DECLARE_VAR)
    AVX__WOP_KEY (AVX__CTR_START, 0);

    w += 1;
    do
    {
      AVX__WOP_KEY (AVX__AES_ENC, 0)
      w += 1;
    }
    while (--r);
    AVX__WOP_KEY (AVX__AES_ENC_LAST, 0)
   
    WOP (AVX__CTR_END);
  }
  WIDE_LOOP_END_AVX (AVX__CTR_LOOP_ENC)
  
  SINGLE_LOOP
  {
    UInt32 numRounds2 = *(const UInt32 *)(p - 2 + 1) - 1;
    const __m128i *w = p;
    __m128i m;
    MM_OP (_mm_add_epi64, ctr, one);
    m = _mm_xor_si128 (ctr, p[0]);
    w += 1;
    do
    {
      MM_OP_m (_mm_aesenc_si128, w[0]);
      MM_OP_m (_mm_aesenc_si128, w[1]);
      w += 2;
    }
    while (--numRounds2);
    MM_OP_m (_mm_aesenc_si128,     w[0]);
    MM_OP_m (_mm_aesenclast_si128, w[1]);
    MM_XOR (*data, m);
  }

  p[-2] = ctr;
}

#endif // USE_INTEL_VAES

#else // USE_INTEL_AES

/* no USE_INTEL_AES */

#pragma message("AES  HW_SW stub was used")

#define AES_TYPE_keys UInt32
#define AES_TYPE_data Byte

#define AES_FUNC_START(name) \
    void MY_FAST_CALL name(UInt32 *p, Byte *data, size_t numBlocks) \

#define AES_COMPAT_STUB(name) \
    AES_FUNC_START(name); \
    AES_FUNC_START(name ## _HW) \
    { name(p, data, numBlocks); }

AES_COMPAT_STUB (AesCbc_Encode)
AES_COMPAT_STUB (AesCbc_Decode)
AES_COMPAT_STUB (AesCtr_Code)

#endif // USE_INTEL_AES


#ifndef USE_INTEL_VAES

#pragma message("VAES HW_SW stub was used")

#define VAES_COMPAT_STUB(name) \
    void MY_FAST_CALL name ## _256(UInt32 *p, Byte *data, size_t numBlocks); \
    void MY_FAST_CALL name ## _256(UInt32 *p, Byte *data, size_t numBlocks) \
    { name((AES_TYPE_keys *)(void *)p, (AES_TYPE_data *)(void *)data, numBlocks); }

VAES_COMPAT_STUB (AesCbc_Decode_HW)
VAES_COMPAT_STUB (AesCtr_Code_HW)

#endif // ! USE_INTEL_VAES


#elif defined(MY_CPU_ARM_OR_ARM64) && defined(MY_CPU_LE)

  #if defined(__clang__)
    #if (__clang_major__ >= 8) // fix that check
      #define USE_HW_AES
    #endif
  #elif defined(__GNUC__)
    #if (__GNUC__ >= 6) // fix that check
      #define USE_HW_AES
    #endif
  #elif defined(_MSC_VER)
    #if _MSC_VER >= 1910
      #define USE_HW_AES
    #endif
  #endif

#ifdef USE_HW_AES

// #pragma message("=== AES HW === ")

#if defined(__clang__) || defined(__GNUC__)
  #ifdef MY_CPU_ARM64
    #define ATTRIB_AES __attribute__((__target__("+crypto")))
  #else
    #define ATTRIB_AES __attribute__((__target__("fpu=crypto-neon-fp-armv8")))
  #endif
#else
  // _MSC_VER
  // for arm32
  #define _ARM_USE_NEW_NEON_INTRINSICS
#endif

#ifndef ATTRIB_AES
  #define ATTRIB_AES
#endif

#if defined(_MSC_VER) && defined(MY_CPU_ARM64)
#include <arm64_neon.h>
#else
#include <arm_neon.h>
#endif

typedef uint8x16_t v128;

#define AES_FUNC_START(name) \
    void MY_FAST_CALL name(v128 *p, v128 *data, size_t numBlocks)

#define AES_FUNC_START2(name) \
AES_FUNC_START (name); \
ATTRIB_AES \
AES_FUNC_START (name)

#define MM_OP(op, dest, src)  dest = op(dest, src);
#define MM_OP_m(op, src)      MM_OP(op, m, src);
#define MM_OP1_m(op)          m = op(m);

#define MM_XOR( dest, src)    MM_OP(veorq_u8, dest, src);
#define MM_XOR_m( src)        MM_XOR(m, src);

#define AES_E_m(k)     MM_OP_m (vaeseq_u8, k);
#define AES_E_MC_m(k)  AES_E_m (k);  MM_OP1_m(vaesmcq_u8);


AES_FUNC_START2 (AesCbc_Encode_HW)
{
  v128 m = *p;
  const v128 k0 = p[2];
  const v128 k1 = p[3];
  const v128 k2 = p[4];
  const v128 k3 = p[5];
  const v128 k4 = p[6];
  const v128 k5 = p[7];
  const v128 k6 = p[8];
  const v128 k7 = p[9];
  const v128 k8 = p[10];
  const v128 k9 = p[11];
  const UInt32 numRounds2 = *(const UInt32 *)(p + 1);
  const v128 *w = p + ((size_t)numRounds2 * 2);
  const v128 k_z1 = w[1];
  const v128 k_z0 = w[2];
  for (; numBlocks != 0; numBlocks--, data++)
  {
    MM_XOR_m (*data);
    AES_E_MC_m (k0)
    AES_E_MC_m (k1)
    AES_E_MC_m (k2)
    AES_E_MC_m (k3)
    AES_E_MC_m (k4)
    AES_E_MC_m (k5)
    AES_E_MC_m (k6)
    AES_E_MC_m (k7)
    AES_E_MC_m (k8)
    if (numRounds2 >= 6)
    {
      AES_E_MC_m (k9)
      AES_E_MC_m (p[12])
      if (numRounds2 != 6)
      {
        AES_E_MC_m (p[13])
        AES_E_MC_m (p[14])
      }
    }
    AES_E_m  (k_z1);
    MM_XOR_m (k_z0);
    *data = m;
  }
  *p = m;
}


#define WOP_1(op)
#define WOP_2(op)   WOP_1 (op)  op (m1, 1);
#define WOP_3(op)   WOP_2 (op)  op (m2, 2);
#define WOP_4(op)   WOP_3 (op)  op (m3, 3);
#define WOP_5(op)   WOP_4 (op)  op (m4, 4);
#define WOP_6(op)   WOP_5 (op)  op (m5, 5);
#define WOP_7(op)   WOP_6 (op)  op (m6, 6);
#define WOP_8(op)   WOP_7 (op)  op (m7, 7);

  #define NUM_WAYS      8
  #define WOP_M1    WOP_8

#define WOP(op)  op (m0, 0);  WOP_M1(op)

#define DECLARE_VAR(reg, ii)  v128 reg
#define LOAD_data(  reg, ii)  reg = data[ii];
#define STORE_data( reg, ii)  data[ii] = reg;
#if (NUM_WAYS > 1)
#define XOR_data_M1(reg, ii)  MM_XOR (reg, data[ii- 1]);
#endif

#define MM_OP_key(op, reg)  MM_OP (op, reg, key);

#define AES_D_m(k)      MM_OP_m (vaesdq_u8, k);
#define AES_D_IMC_m(k)  AES_D_m (k);  MM_OP1_m (vaesimcq_u8);

#define AES_XOR(   reg, ii)  MM_OP_key (veorq_u8,  reg)
#define AES_D(     reg, ii)  MM_OP_key (vaesdq_u8, reg)
#define AES_E(     reg, ii)  MM_OP_key (vaeseq_u8, reg)

#define AES_D_IMC( reg, ii)  AES_D (reg, ii);  reg = vaesimcq_u8(reg)
#define AES_E_MC(  reg, ii)  AES_E (reg, ii);  reg = vaesmcq_u8(reg)

#define CTR_START(reg, ii)  MM_OP (vaddq_u64, ctr, one);  reg = vreinterpretq_u8_u64(ctr);
#define CTR_END(  reg, ii)  MM_XOR (data[ii], reg);

#define WOP_KEY(op, n) { \
    const v128 key = w[n]; \
    WOP(op); }

#define WIDE_LOOP_START  \
    dataEnd = data + numBlocks;  \
    if (numBlocks >= NUM_WAYS)  \
    { dataEnd -= NUM_WAYS; do {  \

#define WIDE_LOOP_END  \
    data += NUM_WAYS;  \
    } while (data <= dataEnd);  \
    dataEnd += NUM_WAYS; }  \

#define SINGLE_LOOP  \
    for (; data < dataEnd; data++)


AES_FUNC_START2 (AesCbc_Decode_HW)
{
  v128 iv = *p;
  const v128 *wStart = p + ((size_t)*(const UInt32 *)(p + 1)) * 2;
  const v128 *dataEnd;
  p += 2;
  
  WIDE_LOOP_START
  {
    const v128 *w = wStart;
    WOP (DECLARE_VAR)
    WOP (LOAD_data);
    WOP_KEY (AES_D_IMC, 2)
    do
    {
      WOP_KEY (AES_D_IMC, 1)
      WOP_KEY (AES_D_IMC, 0)
      w -= 2;
    }
    while (w != p);
    WOP_KEY (AES_D,   1)
    WOP_KEY (AES_XOR, 0)
    MM_XOR (m0, iv);
    WOP_M1 (XOR_data_M1)
    iv = data[NUM_WAYS - 1];
    WOP (STORE_data);
  }
  WIDE_LOOP_END

  SINGLE_LOOP
  {
    const v128 *w = wStart;
    v128 m = *data;
    AES_D_IMC_m (w[2])
    do
    {
      AES_D_IMC_m (w[1]);
      AES_D_IMC_m (w[0]);
      w -= 2;
    }
    while (w != p);
    AES_D_m  (w[1]);
    MM_XOR_m (w[0]);
    MM_XOR_m (iv);
    iv = *data;
    *data = m;
  }
  
  p[-2] = iv;
}


AES_FUNC_START2 (AesCtr_Code_HW)
{
  uint64x2_t ctr = vreinterpretq_u64_u8(*p);
  const v128 *wEnd = p + ((size_t)*(const UInt32 *)(p + 1)) * 2;
  const v128 *dataEnd;
  uint64x2_t one = vdupq_n_u64(0);
  one = vsetq_lane_u64(1, one, 0);
  p += 2;
  
  WIDE_LOOP_START
  {
    const v128 *w = p;
    WOP (DECLARE_VAR)
    WOP (CTR_START);
    do
    {
      WOP_KEY (AES_E_MC, 0)
      WOP_KEY (AES_E_MC, 1)
      w += 2;
    }
    while (w != wEnd);
    WOP_KEY (AES_E_MC, 0)
    WOP_KEY (AES_E,    1)
    WOP_KEY (AES_XOR,  2)
    WOP (CTR_END);
  }
  WIDE_LOOP_END

  SINGLE_LOOP
  {
    const v128 *w = p;
    v128 m;
    CTR_START (m, 0);
    do
    {
      AES_E_MC_m (w[0]);
      AES_E_MC_m (w[1]);
      w += 2;
    }
    while (w != wEnd);
    AES_E_MC_m (w[0]);
    AES_E_m    (w[1]);
    MM_XOR_m   (w[2]);
    CTR_END (m, 0);
  }
  
  p[-2] = vreinterpretq_u8_u64(ctr);
}

#endif // USE_HW_AES

#endif // MY_CPU_ARM_OR_ARM64
