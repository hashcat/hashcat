#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"

#ifndef RC4_LID_TYPE
#define RC4_LID_TYPE u32
#define RC4_LID_TYPE_DEFAULT
#endif

#include "inc_cipher_rc4.h"

#ifdef IS_HIP
#define RC4_NOINLINE __attribute__ ((noinline))
#else
#define RC4_NOINLINE
#endif

#ifdef IS_CPU

// Pattern linear

DECLSPEC u8 GET_KEY8 (LOCAL_AS u32 *S, const u8 k, MAYBE_UNUSED const RC4_LID_TYPE lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  return S8[k];
}

DECLSPEC void SET_KEY8 (LOCAL_AS u32 *S, const u8 k, const u8 v, MAYBE_UNUSED const RC4_LID_TYPE lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  S8[k] = v;
}

DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, MAYBE_UNUSED const RC4_LID_TYPE lid)
{
  S[k] = v;
}

#else

// The goal of this pattern is to have the minimum shared memory bank conflicts as possible.
// Bank conflicts force the device to serialize the bank access and this results in performance drops.
//
// Good to know:
// NV and AMD GPU both have exactly 32 shared memory banks (at least on all modern GPU).
// These banks can't be addressed directly, but indirectly.
// Each of the 32 banks add some space to the total LOCAL buffer.
// But this space is not simply appended, but in chunks of 4 bytes:
//   Bank 0 provides bytes 0..3, Bank 1 provides bytes 4..7, Bank 2 provides 8..11, and so on..
//
// We design the memory structure that each thread ID aligns with the corresponding bank ID.
// If a thread always access the same bank, then there are no bank conflicts and we reach our goal.
//
// Since we have 32 banks, we ideally operate on 32 threads.
// For NV GPU this aligns perfectly, because native threads = 32.
// For AMD GPU it does not, because native threads = 64. But we can reduce it to only 1 bank conflict per thread.
//
// The size for the S[] buffer for each thread is 256 byte, basically just the RC4 sbox.
// We want to assign 1 thread to 1 bank, so for 32 banks the total size is 8192 bytes (256 * 32 = 8192):
//   LOCAL_VK u32 S[64 * FIXED_LOCAL_SIZE];
// Note that sizeof (u32) * 64 = 256 and then multiplied with the thread count.
//
// Addressing:
//
// This is the first major offset and is relevant for thread ID >= 32 (AMD or non-native thread count on NV):
//   (t / 32) * 8192
// The first 8192 bytes of S[] are accessed from threads 0..31 and the next 8192 bytes from threads 32..63
// We could also use more than 64 threads but we need to make sure it's a multiple of 32.
//
// Inside this window of 8192 bytes we select the bank id from the thread id:
//   (t & 31) * 4
// We need to do the * 4 because of the 4 byte chunks (see top)
//
// Because of the indirect bank ID addressing we can't write from left to right, we write from top to bottom.
// To ensure each thread stays to its assigned bank id from the previous calculation we could simply do k * 128,
// because 128 = 4 (bank chunk size) * 32 (banks).
//
// However, it's not that easy. We need to find a way to enforce a chunk size of 4.
//   (k / 4) * 128
//
// Finally we can select the actual target byte from (1 out of 4) from this chunk:
//   (k & 3)

#ifdef RC4_USE_BITWISE_ADDRESSING
#define KEY8(t,k) (((k) & 3) | (((k) / 4) * 128) | (((t) & 31) * 4) | (((t) / 32) * 8192))
#else
#define KEY8(t,k) (((k) & 3) + (((k) / 4) * 128) + (((t) & 31) * 4) + (((t) / 32) * 8192))
#endif

DECLSPEC u8 GET_KEY8 (LOCAL_AS u32 *S, const u8 k, const RC4_LID_TYPE lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  return S8[KEY8 (lid, k)];
}

DECLSPEC void SET_KEY8 (LOCAL_AS u32 *S, const u8 k, const u8 v, const RC4_LID_TYPE lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  S8[KEY8 (lid, k)] = v;
}

#ifdef RC4_USE_BITWISE_ADDRESSING
#define KEY32(t,k) (((k) * 32) | ((t) & 31) | (((t) / 32) * 2048))
#else
#define KEY32(t,k) (((k) * 32) + ((t) & 31) + (((t) / 32) * 2048))
#endif

DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, const RC4_LID_TYPE lid)
{
  S[KEY32 (lid, k)] = v;
}

#undef KEY8
#undef KEY32

#endif

DECLSPEC void rc4_init_40 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  const u8 d0 = v8a_from_v32_S (key[0]);
  const u8 d1 = v8b_from_v32_S (key[0]);
  const u8 d2 = v8c_from_v32_S (key[0]);
  const u8 d3 = v8d_from_v32_S (key[0]);
  const u8 d4 = v8a_from_v32_S (key[1]);

  u8 j = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 255; i += 5)
  {
    j += GET_KEY8 (S, i + 0, lid) + d0; rc4_swap (S, i + 0, j, lid);
    j += GET_KEY8 (S, i + 1, lid) + d1; rc4_swap (S, i + 1, j, lid);
    j += GET_KEY8 (S, i + 2, lid) + d2; rc4_swap (S, i + 2, j, lid);
    j += GET_KEY8 (S, i + 3, lid) + d3; rc4_swap (S, i + 3, j, lid);
    j += GET_KEY8 (S, i + 4, lid) + d4; rc4_swap (S, i + 4, j, lid);
  }

  j += GET_KEY8 (S, 255, lid) + d0; rc4_swap (S, 255, j, lid);
}

DECLSPEC void rc4_init_72 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  const u8 d0 = v8a_from_v32_S (key[0]);
  const u8 d1 = v8b_from_v32_S (key[0]);
  const u8 d2 = v8c_from_v32_S (key[0]);
  const u8 d3 = v8d_from_v32_S (key[0]);
  const u8 d4 = v8a_from_v32_S (key[1]);
  const u8 d5 = v8b_from_v32_S (key[1]);
  const u8 d6 = v8c_from_v32_S (key[1]);
  const u8 d7 = v8d_from_v32_S (key[1]);
  const u8 d8 = v8a_from_v32_S (key[2]);

  u8 j = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 252; i += 9)
  {
    j += GET_KEY8 (S, i + 0, lid) + d0; rc4_swap (S, i + 0, j, lid);
    j += GET_KEY8 (S, i + 1, lid) + d1; rc4_swap (S, i + 1, j, lid);
    j += GET_KEY8 (S, i + 2, lid) + d2; rc4_swap (S, i + 2, j, lid);
    j += GET_KEY8 (S, i + 3, lid) + d3; rc4_swap (S, i + 3, j, lid);
    j += GET_KEY8 (S, i + 4, lid) + d4; rc4_swap (S, i + 4, j, lid);
    j += GET_KEY8 (S, i + 5, lid) + d5; rc4_swap (S, i + 5, j, lid);
    j += GET_KEY8 (S, i + 6, lid) + d6; rc4_swap (S, i + 6, j, lid);
    j += GET_KEY8 (S, i + 7, lid) + d7; rc4_swap (S, i + 7, j, lid);
    j += GET_KEY8 (S, i + 8, lid) + d8; rc4_swap (S, i + 8, j, lid);
  }

  j += GET_KEY8 (S, 252, lid) + d0; rc4_swap (S, 252, j, lid);
  j += GET_KEY8 (S, 253, lid) + d1; rc4_swap (S, 253, j, lid);
  j += GET_KEY8 (S, 254, lid) + d2; rc4_swap (S, 254, j, lid);
  j += GET_KEY8 (S, 255, lid) + d3; rc4_swap (S, 255, j, lid);
}

DECLSPEC void rc4_init_104 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  const u8 d0  = v8a_from_v32_S(key[0]);
  const u8 d1  = v8b_from_v32_S(key[0]);
  const u8 d2  = v8c_from_v32_S(key[0]);
  const u8 d3  = v8d_from_v32_S(key[0]);
  const u8 d4  = v8a_from_v32_S(key[1]);
  const u8 d5  = v8b_from_v32_S(key[1]);
  const u8 d6  = v8c_from_v32_S(key[1]);
  const u8 d7  = v8d_from_v32_S(key[1]);
  const u8 d8  = v8a_from_v32_S(key[2]);
  const u8 d9  = v8b_from_v32_S(key[2]);
  const u8 d10 = v8c_from_v32_S(key[2]);
  const u8 d11 = v8d_from_v32_S(key[2]);
  const u8 d12 = v8a_from_v32_S(key[3]);

  u8 j = 0;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u32 i = 0; i < 247; i += 13)
  {
    j += GET_KEY8(S, i +  0, lid) + d0;  rc4_swap(S, i +  0, j, lid);
    j += GET_KEY8(S, i +  1, lid) + d1;  rc4_swap(S, i +  1, j, lid);
    j += GET_KEY8(S, i +  2, lid) + d2;  rc4_swap(S, i +  2, j, lid);
    j += GET_KEY8(S, i +  3, lid) + d3;  rc4_swap(S, i +  3, j, lid);
    j += GET_KEY8(S, i +  4, lid) + d4;  rc4_swap(S, i +  4, j, lid);
    j += GET_KEY8(S, i +  5, lid) + d5;  rc4_swap(S, i +  5, j, lid);
    j += GET_KEY8(S, i +  6, lid) + d6;  rc4_swap(S, i +  6, j, lid);
    j += GET_KEY8(S, i +  7, lid) + d7;  rc4_swap(S, i +  7, j, lid);
    j += GET_KEY8(S, i +  8, lid) + d8;  rc4_swap(S, i +  8, j, lid);
    j += GET_KEY8(S, i +  9, lid) + d9;  rc4_swap(S, i +  9, j, lid);
    j += GET_KEY8(S, i + 10, lid) + d10; rc4_swap(S, i + 10, j, lid);
    j += GET_KEY8(S, i + 11, lid) + d11; rc4_swap(S, i + 11, j, lid);
    j += GET_KEY8(S, i + 12, lid) + d12; rc4_swap(S, i + 12, j, lid);
  }

  j += GET_KEY8(S, 247, lid) + d0;  rc4_swap(S, 247, j, lid);
  j += GET_KEY8(S, 248, lid) + d1;  rc4_swap(S, 248, j, lid);
  j += GET_KEY8(S, 249, lid) + d2;  rc4_swap(S, 249, j, lid);
  j += GET_KEY8(S, 250, lid) + d3;  rc4_swap(S, 250, j, lid);
  j += GET_KEY8(S, 251, lid) + d4;  rc4_swap(S, 251, j, lid);
  j += GET_KEY8(S, 252, lid) + d5;  rc4_swap(S, 252, j, lid);
  j += GET_KEY8(S, 253, lid) + d6;  rc4_swap(S, 253, j, lid);
  j += GET_KEY8(S, 254, lid) + d7;  rc4_swap(S, 254, j, lid);
  j += GET_KEY8(S, 255, lid) + d8;  rc4_swap(S, 255, j, lid);
}

#ifndef RC4_INIT_128_PREFETCH

DECLSPEC void rc4_init_128 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid)
{
  u32 v = 0x03020100;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 0; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  u8 j = 0;

  #ifdef RC4_INIT_128_UNROLL8
  #pragma unroll 8
  #endif
  for (u32 i = 0; i < 16; i++)
  {
    u8 idx = i * 16;

    u32 v;

    v = key[0];

    j += GET_KEY8 (S, idx, lid) + v8a_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8b_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8c_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8d_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;

    v = key[1];

    j += GET_KEY8 (S, idx, lid) + v8a_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8b_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8c_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8d_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;

    v = key[2];

    j += GET_KEY8 (S, idx, lid) + v8a_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8b_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8c_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8d_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;

    v = key[3];

    j += GET_KEY8 (S, idx, lid) + v8a_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8b_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8c_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
    j += GET_KEY8 (S, idx, lid) + v8d_from_v32_S (v); rc4_swap (S, idx, j, lid); idx++;
  }
}

#else

#define RC4_KSA_PREFETCH_STEP(d)            \
{                                           \
  const u8 s_next = GET_KEY8 (S, idx + 1, lid); \
  j += s_i + (d);                           \
  const u8 s_j = GET_KEY8 (S, j, lid);      \
  SET_KEY8 (S, idx, s_j, lid);              \
  SET_KEY8 (S, j, s_i, lid);                \
  idx++;                                    \
  s_i = (j == idx) ? s_i : s_next;          \
}

DECLSPEC void rc4_init_128 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const RC4_LID_TYPE lid)
{
  u32 v = 0x07060504;
  u32 a = 0x04040404;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (u8 i = 1; i < 64; i++)
  {
    SET_KEY32 (S, i, v, lid); v += a;
  }

  v = key[0];

  const u8 d0 = v8a_from_v32_S (v);
  const u8 d1 = v8b_from_v32_S (v);
  const u8 d2 = v8c_from_v32_S (v);
  const u8 d3 = v8d_from_v32_S (v);

  const u8 j0 = d0;

  const u8 s1  = (j0 == 1) ? 0 : 1;
  const u8 j1  = j0 + s1 + d1;
  const u8 sj1 = (j1 == j0) ? 0 : ((j1 == 0) ? j0 : j1);

  const u8 s2  = (j1 == 2) ? s1 : ((j0 == 2) ? 0 : 2);
  const u8 j2  = j1 + s2 + d2;
  const u8 sj2 = (j2 == j1) ? s1
               : (j2 == 1)  ? sj1
               : (j2 == j0) ? 0
               : (j2 == 0)  ? j0
               : j2;

  const u8 s3  = (j2 == 3) ? s2
               : (j1 == 3) ? s1
               : (j0 == 3) ? 0
               : 3;
  const u8 j3  = j2 + s3 + d3;
  const u8 sj3 = (j3 == j2) ? s2
               : (j3 == 2)  ? sj2
               : (j3 == j1) ? s1
               : (j3 == 1)  ? sj1
               : (j3 == j0) ? 0
               : (j3 == 0)  ? j0
               : j3;

  SET_KEY8 (S, j0,  0, lid);
  SET_KEY8 (S, j1, s1, lid);
  SET_KEY8 (S, j2, s2, lid);
  SET_KEY8 (S, j3, s3, lid);

  const u8 s0 = (j3 == 0) ? s3
              : (j2 == 0) ? s2
              : (j1 == 0) ? s1
              : (j0 == 0) ? 0
              : j0;
  const u8 s1_final = (j3 == 1) ? s3
                    : (j2 == 1) ? s2
                    : sj1;
  const u8 s2_final = (j3 == 2) ? s3 : sj2;

  const u8 s4 = (j3 == 4) ? s3
              : (j2 == 4) ? s2
              : (j1 == 4) ? s1
              : (j0 == 4) ? 0
              : 4;

  const u32 sbox03 = ((u32) s0       <<  0)
                   | ((u32) s1_final <<  8)
                   | ((u32) s2_final << 16)
                   | ((u32) sj3      << 24);

  SET_KEY32 (S, 0, sbox03, lid);

  u8 j   = j3;
  u8 idx = 4;
  u8 s_i = s4;

  v = key[1];

  RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  v = key[2];

  RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  v = key[3];

  RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
  RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

  #ifdef RC4_INIT_128_PREFETCH_UNROLL8
  #pragma unroll 8
  #endif
  for (u32 i = 1; i < 16; i++)
  {
    idx = i * 16;

    v = key[0];

    RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[1];

    RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[2];

    RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));

    v = key[3];

    RC4_KSA_PREFETCH_STEP (v8a_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8b_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8c_from_v32_S (v));
    RC4_KSA_PREFETCH_STEP (v8d_from_v32_S (v));
  }
}

#undef RC4_KSA_PREFETCH_STEP

#endif

DECLSPEC void rc4_swap (LOCAL_AS u32 *S, const u8 i, const u8 j, const RC4_LID_TYPE lid)
{
  u8 tmp;

  tmp           = GET_KEY8 (S, i, lid);
  SET_KEY8 (S, i, GET_KEY8 (S, j, lid), lid);
  SET_KEY8 (S, j, tmp, lid);
}

DECLSPEC void rc4_dropN (LOCAL_AS u32 *S, PRIVATE_AS u8 *i, PRIVATE_AS u8 *j, const u32 n, const RC4_LID_TYPE lid)
{
  u8 a = *i;
  u8 b = *j;

  for (u32 z = 0; z < n; z++)
  {
    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    u8 idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    GET_KEY8 (S, idx, lid);
  }

  *i = a;
  *j = b;
}

#ifdef RC4_ENABLE_NEXT_4

DECLSPEC u8 rc4_next_4 (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;

  u32 xor4 = 0;

  u32 tmp;

  u8 idx;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp <<  0;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp <<  8;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 16;

  a += 1;
  b += GET_KEY8 (S, a, lid);

  rc4_swap (S, a, b, lid);

  idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 24;

  out[0] = in[0] ^ xor4;

  return b;
}

#endif

#ifdef RC4_NEXT_16_PREFETCH

DECLSPEC u8 rc4_next_16 (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;

  u8 s_prefetch = GET_KEY8 (S, a + 1, lid);

  #ifdef RC4_NEXT_16_UNROLL2
  #pragma unroll 2
  #else
  #ifdef _unroll
  #pragma unroll
  #endif
  #endif
  for (int k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u32 tmp;

    u8 idx;
    u8 next;
    u8 sa;
    u8 sb;
    u8 s_next;

    a += 1;
    next = a + 1;
    s_next = GET_KEY8 (S, next, lid);
    sa = s_prefetch;
    b += sa;
    sb = GET_KEY8 (S, b, lid);
    SET_KEY8 (S, a, sb, lid);
    SET_KEY8 (S, b, sa, lid);
    idx = sa + sb;

    tmp = GET_KEY8 (S, idx, lid);

    s_prefetch = (b == next) ? sa : s_next;

    xor4 |= tmp <<  0;

    a += 1;
    next = a + 1;
    s_next = GET_KEY8 (S, next, lid);
    sa = s_prefetch;
    b += sa;
    sb = GET_KEY8 (S, b, lid);
    SET_KEY8 (S, a, sb, lid);
    SET_KEY8 (S, b, sa, lid);
    idx = sa + sb;

    tmp = GET_KEY8 (S, idx, lid);

    s_prefetch = (b == next) ? sa : s_next;

    xor4 |= tmp <<  8;

    a += 1;
    next = a + 1;
    s_next = GET_KEY8 (S, next, lid);
    sa = s_prefetch;
    b += sa;
    sb = GET_KEY8 (S, b, lid);
    SET_KEY8 (S, a, sb, lid);
    SET_KEY8 (S, b, sa, lid);
    idx = sa + sb;

    tmp = GET_KEY8 (S, idx, lid);

    s_prefetch = (b == next) ? sa : s_next;

    xor4 |= tmp << 16;

    a += 1;
    next = a + 1;
    s_next = GET_KEY8 (S, next, lid);
    sa = s_prefetch;
    b += sa;
    sb = GET_KEY8 (S, b, lid);
    SET_KEY8 (S, a, sb, lid);
    SET_KEY8 (S, b, sa, lid);
    idx = sa + sb;

    tmp = GET_KEY8 (S, idx, lid);

    s_prefetch = (b == next) ? sa : s_next;

    xor4 |= tmp << 24;

    out[k] = in[k] ^ xor4;
  }

  return b;
}

#else

DECLSPEC u8 rc4_next_16 (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u32 tmp;

    u8 idx;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  0;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  8;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 16;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 24;

    out[k] = in[k] ^ xor4;
  }

  return b;
}

#endif

#ifdef RC4_ENABLE_KRB5_HELPERS

DECLSPEC RC4_NOINLINE int rc4_next_12_global_krb5_staged (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;
  u8 sa = GET_KEY8 (S, i + 1, lid);
  u8 sb;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int k = 0; k < 8; k++)
  {
    a += 1;
    const u8 next = a + 1;
    const u8 s_next = GET_KEY8 (S, next, lid);
    b += sa;
    sb = GET_KEY8 (S, b, lid);

    SET_KEY8 (S, a, sb, lid);
    SET_KEY8 (S, b, sa, lid);

    sa = (b == next) ? sa : s_next;
  }

  u32 xor4 = 0;

  u32 tmp;

  u8 idx;

  a += 1;
  b += sa;
  sb = GET_KEY8 (S, b, lid);

  SET_KEY8 (S, a, sb, lid);
  SET_KEY8 (S, b, sa, lid);

  idx = sa + sb;

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 0;

  if (((in[2] ^ xor4) & 0xff) != 0x63) return -1;

  a += 1;
  sa = GET_KEY8 (S, a, lid);
  b += sa;
  sb = GET_KEY8 (S, b, lid);

  SET_KEY8 (S, a, sb, lid);
  SET_KEY8 (S, b, sa, lid);

  idx = sa + sb;

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 8;

  const u32 prefix = (in[2] ^ xor4) & 0xffff;

  if ((prefix != 0x8163) && (prefix != 0x8263)) return -1;

  a += 1;
  sa = GET_KEY8 (S, a, lid);
  b += sa;
  sb = GET_KEY8 (S, b, lid);

  SET_KEY8 (S, a, sb, lid);
  SET_KEY8 (S, b, sa, lid);

  idx = sa + sb;

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 16;

  a += 1;
  sa = GET_KEY8 (S, a, lid);
  b += sa;
  sb = GET_KEY8 (S, b, lid);

  SET_KEY8 (S, a, sb, lid);
  SET_KEY8 (S, b, sa, lid);

  idx = sa + sb;

  tmp = GET_KEY8 (S, idx, lid);

  xor4 |= tmp << 24;

  const u32 out = in[2] ^ xor4;

  if (((out & 0xff00ffff) != 0x30008163) && ((out & 0x0000ffff) != 0x00008263)) return -1;

  return b;
}

DECLSPEC RC4_NOINLINE u8 rc4_next_12_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int k = 0; k < 3; k++)
  {
    u32 xor4 = 0;

    u32 tmp;

    u8 idx;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  0;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  8;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 16;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 24;

    out[k] = in[k] ^ xor4;
  }

  return b;
}

#endif

DECLSPEC RC4_NOINLINE u8 rc4_next_16_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, const RC4_LID_TYPE lid)
{
  u8 a = i;
  u8 b = j;

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int k = 0; k < 4; k++)
  {
    u32 xor4 = 0;

    u32 tmp;

    u8 idx;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  0;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp <<  8;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 16;

    a += 1;
    b += GET_KEY8 (S, a, lid);

    rc4_swap (S, a, b, lid);

    idx = GET_KEY8 (S, a, lid) + GET_KEY8 (S, b, lid);

    tmp = GET_KEY8 (S, idx, lid);

    xor4 |= tmp << 24;

    out[k] = in[k] ^ xor4;
  }

  return b;
}

#ifdef RC4_LID_TYPE_DEFAULT
#undef RC4_LID_TYPE_DEFAULT
#undef RC4_LID_TYPE
#endif
