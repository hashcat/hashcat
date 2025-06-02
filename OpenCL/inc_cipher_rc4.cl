#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.h"
#include "inc_common.h"
#include "inc_cipher_rc4.h"

#ifdef IS_HIP
#define RC4_NOINLINE __attribute__ ((noinline))
#else
#define RC4_NOINLINE
#endif

#ifdef IS_CPU

// Pattern linear

DECLSPEC u8 GET_KEY8 (LOCAL_AS u32 *S, const u8 k, MAYBE_UNUSED const u64 lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  return S8[k];
}

DECLSPEC void SET_KEY8 (LOCAL_AS u32 *S, const u8 k, const u8 v, MAYBE_UNUSED const u64 lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  S8[k] = v;
}

DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, MAYBE_UNUSED const u64 lid)
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

#define KEY8(t,k) (((k) & 3) + (((k) / 4) * 128) + (((t) & 31) * 4) + (((t) / 32) * 8192))

DECLSPEC u8 GET_KEY8 (LOCAL_AS u32 *S, const u8 k, const u64 lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  return S8[KEY8 (lid, k)];
}

DECLSPEC void SET_KEY8 (LOCAL_AS u32 *S, const u8 k, const u8 v, const u64 lid)
{
  LOCAL_AS u8 *S8 = (LOCAL_AS u8 *) S;

  S8[KEY8 (lid, k)] = v;
}

#define KEY32(t,k) (((k) * 32) + ((t) & 31) + (((t) / 32) * 2048))

DECLSPEC void SET_KEY32 (LOCAL_AS u32 *S, const u8 k, const u32 v, const u64 lid)
{
  S[KEY32 (lid, k)] = v;
}

#undef KEY8
#undef KEY32

#endif

DECLSPEC void rc4_init_40 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
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

DECLSPEC void rc4_init_72 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
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

DECLSPEC void rc4_init_104 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
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

DECLSPEC void rc4_init_128 (LOCAL_AS u32 *S, PRIVATE_AS const u32 *key, const u64 lid)
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

DECLSPEC void rc4_swap (LOCAL_AS u32 *S, const u8 i, const u8 j, const u64 lid)
{
  u8 tmp;

  tmp           = GET_KEY8 (S, i, lid);
  SET_KEY8 (S, i, GET_KEY8 (S, j, lid), lid);
  SET_KEY8 (S, j, tmp, lid);
}

DECLSPEC void rc4_dropN (LOCAL_AS u32 *S, PRIVATE_AS u8 *i, PRIVATE_AS u8 *j, const u32 n, const u64 lid)
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

DECLSPEC u8 rc4_next_16 (LOCAL_AS u32 *S, const u8 i, const u8 j, PRIVATE_AS const u32 *in, PRIVATE_AS u32 *out, const u64 lid)
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

DECLSPEC RC4_NOINLINE u8 rc4_next_16_global (LOCAL_AS u32 *S, const u8 i, const u8 j, GLOBAL_AS const u32 *in, PRIVATE_AS u32 *out, const u64 lid)
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
