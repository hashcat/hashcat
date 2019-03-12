/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#include "inc_vendor.cl"
#include "inc_hash_constants.h"
#include "inc_hash_functions.cl"
#include "inc_types.cl"
#include "inc_common.cl"
#include "inc_simd.cl"

__constant u64a keccakf_rndc[24] =
{
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

__kernel void m17900_m04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * Keccak
     */

    u64x a00 = hl32_to_64 (w0[1], w0[0]);
    u64x a01 = hl32_to_64 (w0[3], w0[2]);
    u64x a02 = hl32_to_64 (w1[1], w1[0]);
    u64x a03 = hl32_to_64 (w1[3], w1[2]);
    u64x a04 = hl32_to_64 (w2[1], w2[0]);
    u64x a10 = hl32_to_64 (w2[3], w2[2]);
    u64x a11 = hl32_to_64 (w3[1], w3[0]);
    u64x a12 = hl32_to_64 (w3[3], w3[2]);
    u64x a13 = 0;
    u64x a14 = 0;
    u64x a20 = 0;
    u64x a21 = 0;
    u64x a22 = 0x8000000000000000;
    u64x a23 = 0;
    u64x a24 = 0;
    u64x a30 = 0;
    u64x a31 = 0;
    u64x a32 = 0;
    u64x a33 = 0;
    u64x a34 = 0;
    u64x a40 = 0;
    u64x a41 = 0;
    u64x a42 = 0;
    u64x a43 = 0;
    u64x a44 = 0;

    #define Rho_Pi(ad,r)     \
      bc0 = ad;              \
      ad = rotl64 (t, r);    \
      t = bc0;               \

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int round = 0; round < KECCAK_ROUNDS - 1; round++)
    {
      // Theta

      u64x bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
      u64x bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
      u64x bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
      u64x bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
      u64x bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

      u64x t;

      t = bc4 ^ rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t; a40 ^= t;
      t = bc0 ^ rotl64 (bc2, 1); a01 ^= t; a11 ^= t; a21 ^= t; a31 ^= t; a41 ^= t;
      t = bc1 ^ rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t; a42 ^= t;
      t = bc2 ^ rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
      t = bc3 ^ rotl64 (bc0, 1); a04 ^= t; a14 ^= t; a24 ^= t; a34 ^= t; a44 ^= t;

      // Rho Pi

      t = a01;

      Rho_Pi (a20,  1);
      Rho_Pi (a12,  3);
      Rho_Pi (a21,  6);
      Rho_Pi (a32, 10);
      Rho_Pi (a33, 15);
      Rho_Pi (a03, 21);
      Rho_Pi (a10, 28);
      Rho_Pi (a31, 36);
      Rho_Pi (a13, 45);
      Rho_Pi (a41, 55);
      Rho_Pi (a44,  2);
      Rho_Pi (a04, 14);
      Rho_Pi (a30, 27);
      Rho_Pi (a43, 41);
      Rho_Pi (a34, 56);
      Rho_Pi (a23,  8);
      Rho_Pi (a22, 25);
      Rho_Pi (a02, 43);
      Rho_Pi (a40, 62);
      Rho_Pi (a24, 18);
      Rho_Pi (a42, 39);
      Rho_Pi (a14, 61);
      Rho_Pi (a11, 20);
      Rho_Pi (a01, 44);

      //  Chi

      bc0 = a00; bc1 = a01; bc2 = a02; bc3 = a03; bc4 = a04;
      a00 ^= ~bc1 & bc2; a01 ^= ~bc2 & bc3; a02 ^= ~bc3 & bc4; a03 ^= ~bc4 & bc0; a04 ^= ~bc0 & bc1;

      bc0 = a10; bc1 = a11; bc2 = a12; bc3 = a13; bc4 = a14;
      a10 ^= ~bc1 & bc2; a11 ^= ~bc2 & bc3; a12 ^= ~bc3 & bc4; a13 ^= ~bc4 & bc0; a14 ^= ~bc0 & bc1;

      bc0 = a20; bc1 = a21; bc2 = a22; bc3 = a23; bc4 = a24;
      a20 ^= ~bc1 & bc2; a21 ^= ~bc2 & bc3; a22 ^= ~bc3 & bc4; a23 ^= ~bc4 & bc0; a24 ^= ~bc0 & bc1;

      bc0 = a30; bc1 = a31; bc2 = a32; bc3 = a33; bc4 = a34;
      a30 ^= ~bc1 & bc2; a31 ^= ~bc2 & bc3; a32 ^= ~bc3 & bc4; a33 ^= ~bc4 & bc0; a34 ^= ~bc0 & bc1;

      bc0 = a40; bc1 = a41; bc2 = a42; bc3 = a43; bc4 = a44;
      a40 ^= ~bc1 & bc2; a41 ^= ~bc2 & bc3; a42 ^= ~bc3 & bc4; a43 ^= ~bc4 & bc0; a44 ^= ~bc0 & bc1;

      //  Iota

      a00 ^= keccakf_rndc[round];
    }

    // Theta

    u64x bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
    u64x bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
    u64x bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
    u64x bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
    u64x bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

    u64x t;

    t = bc4 ^ rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t;
    t = bc0 ^ rotl64 (bc2, 1);                     a21 ^= t; a31 ^= t; a41 ^= t;
    t = bc1 ^ rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t;
    t = bc2 ^ rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
    t = bc3 ^ rotl64 (bc0, 1); a04 ^= t;                     a34 ^= t; a44 ^= t;

    // Rho Pi

    t = a01;

    Rho_Pi (a20,  1);
    Rho_Pi (a12,  3);
    Rho_Pi (a21,  6);
    Rho_Pi (a32, 10);
    Rho_Pi (a33, 15);
    Rho_Pi (a03, 21);
    Rho_Pi (a10, 28);
    Rho_Pi (a31, 36);
    Rho_Pi (a13, 45);
    Rho_Pi (a41, 55);
    Rho_Pi (a44,  2);
    Rho_Pi (a04, 14);
    Rho_Pi (a30, 27);
    Rho_Pi (a43, 41);
    Rho_Pi (a34, 56);
    Rho_Pi (a23,  8);
    Rho_Pi (a22, 25);
    Rho_Pi (a02, 43);

    #undef Rho_Pi

    bc0 = a00;
    bc2 = a02;
    bc3 = a03;
    bc4 = a04;

    a02 ^= ~bc3 & bc4;
    a03 ^= ~bc4 & bc0;

    const u32x r0 = l32_from_64 (a03);
    const u32x r1 = h32_from_64 (a03);
    const u32x r2 = l32_from_64 (a02);
    const u32x r3 = h32_from_64 (a02);

    COMPARE_M_SIMD (r0, r1, r2, r3);
  }
}


__kernel void m17900_m08 (KERN_ATTR_BASIC ())
{
}

__kernel void m17900_m16 (KERN_ATTR_BASIC ())
{
}

__kernel void m17900_s04 (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  u32 pw_buf0[4];
  u32 pw_buf1[4];

  pw_buf0[0] = pws[gid].i[0];
  pw_buf0[1] = pws[gid].i[1];
  pw_buf0[2] = pws[gid].i[2];
  pw_buf0[3] = pws[gid].i[3];
  pw_buf1[0] = pws[gid].i[4];
  pw_buf1[1] = pws[gid].i[5];
  pw_buf1[2] = pws[gid].i[6];
  pw_buf1[3] = pws[gid].i[7];

  const u32 pw_l_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x pw_r_len = pwlenx_create_combt (combs_buf, il_pos) & 63;

    const u32x pw_len = (pw_l_len + pw_r_len) & 63;

    /**
     * concat password candidate
     */

    u32x wordl0[4] = { 0 };
    u32x wordl1[4] = { 0 };
    u32x wordl2[4] = { 0 };
    u32x wordl3[4] = { 0 };

    wordl0[0] = pw_buf0[0];
    wordl0[1] = pw_buf0[1];
    wordl0[2] = pw_buf0[2];
    wordl0[3] = pw_buf0[3];
    wordl1[0] = pw_buf1[0];
    wordl1[1] = pw_buf1[1];
    wordl1[2] = pw_buf1[2];
    wordl1[3] = pw_buf1[3];

    u32x wordr0[4] = { 0 };
    u32x wordr1[4] = { 0 };
    u32x wordr2[4] = { 0 };
    u32x wordr3[4] = { 0 };

    wordr0[0] = ix_create_combt (combs_buf, il_pos, 0);
    wordr0[1] = ix_create_combt (combs_buf, il_pos, 1);
    wordr0[2] = ix_create_combt (combs_buf, il_pos, 2);
    wordr0[3] = ix_create_combt (combs_buf, il_pos, 3);
    wordr1[0] = ix_create_combt (combs_buf, il_pos, 4);
    wordr1[1] = ix_create_combt (combs_buf, il_pos, 5);
    wordr1[2] = ix_create_combt (combs_buf, il_pos, 6);
    wordr1[3] = ix_create_combt (combs_buf, il_pos, 7);

    if (combs_mode == COMBINATOR_MODE_BASE_LEFT)
    {
      switch_buffer_by_offset_le_VV (wordr0, wordr1, wordr2, wordr3, pw_l_len);
    }
    else
    {
      switch_buffer_by_offset_le_VV (wordl0, wordl1, wordl2, wordl3, pw_r_len);
    }

    u32x w0[4];
    u32x w1[4];
    u32x w2[4];
    u32x w3[4];

    w0[0] = wordl0[0] | wordr0[0];
    w0[1] = wordl0[1] | wordr0[1];
    w0[2] = wordl0[2] | wordr0[2];
    w0[3] = wordl0[3] | wordr0[3];
    w1[0] = wordl1[0] | wordr1[0];
    w1[1] = wordl1[1] | wordr1[1];
    w1[2] = wordl1[2] | wordr1[2];
    w1[3] = wordl1[3] | wordr1[3];
    w2[0] = wordl2[0] | wordr2[0];
    w2[1] = wordl2[1] | wordr2[1];
    w2[2] = wordl2[2] | wordr2[2];
    w2[3] = wordl2[3] | wordr2[3];
    w3[0] = wordl3[0] | wordr3[0];
    w3[1] = wordl3[1] | wordr3[1];
    w3[2] = wordl3[2] | wordr3[2];
    w3[3] = wordl3[3] | wordr3[3];

    /**
     * Keccak
     */

    u64x a00 = hl32_to_64 (w0[1], w0[0]);
    u64x a01 = hl32_to_64 (w0[3], w0[2]);
    u64x a02 = hl32_to_64 (w1[1], w1[0]);
    u64x a03 = hl32_to_64 (w1[3], w1[2]);
    u64x a04 = hl32_to_64 (w2[1], w2[0]);
    u64x a10 = hl32_to_64 (w2[3], w2[2]);
    u64x a11 = hl32_to_64 (w3[1], w3[0]);
    u64x a12 = hl32_to_64 (w3[3], w3[2]);
    u64x a13 = 0;
    u64x a14 = 0;
    u64x a20 = 0;
    u64x a21 = 0;
    u64x a22 = 0x8000000000000000;
    u64x a23 = 0;
    u64x a24 = 0;
    u64x a30 = 0;
    u64x a31 = 0;
    u64x a32 = 0;
    u64x a33 = 0;
    u64x a34 = 0;
    u64x a40 = 0;
    u64x a41 = 0;
    u64x a42 = 0;
    u64x a43 = 0;
    u64x a44 = 0;

    #define Rho_Pi(ad,r)     \
      bc0 = ad;              \
      ad = rotl64 (t, r);    \
      t = bc0;               \

    #ifdef _unroll
    #pragma unroll
    #endif
    for (int round = 0; round < KECCAK_ROUNDS - 1; round++)
    {
      // Theta

      u64x bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
      u64x bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
      u64x bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
      u64x bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
      u64x bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

      u64x t;

      t = bc4 ^ rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t; a40 ^= t;
      t = bc0 ^ rotl64 (bc2, 1); a01 ^= t; a11 ^= t; a21 ^= t; a31 ^= t; a41 ^= t;
      t = bc1 ^ rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t; a42 ^= t;
      t = bc2 ^ rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
      t = bc3 ^ rotl64 (bc0, 1); a04 ^= t; a14 ^= t; a24 ^= t; a34 ^= t; a44 ^= t;

      // Rho Pi

      t = a01;

      Rho_Pi (a20,  1);
      Rho_Pi (a12,  3);
      Rho_Pi (a21,  6);
      Rho_Pi (a32, 10);
      Rho_Pi (a33, 15);
      Rho_Pi (a03, 21);
      Rho_Pi (a10, 28);
      Rho_Pi (a31, 36);
      Rho_Pi (a13, 45);
      Rho_Pi (a41, 55);
      Rho_Pi (a44,  2);
      Rho_Pi (a04, 14);
      Rho_Pi (a30, 27);
      Rho_Pi (a43, 41);
      Rho_Pi (a34, 56);
      Rho_Pi (a23,  8);
      Rho_Pi (a22, 25);
      Rho_Pi (a02, 43);
      Rho_Pi (a40, 62);
      Rho_Pi (a24, 18);
      Rho_Pi (a42, 39);
      Rho_Pi (a14, 61);
      Rho_Pi (a11, 20);
      Rho_Pi (a01, 44);

      //  Chi

      bc0 = a00; bc1 = a01; bc2 = a02; bc3 = a03; bc4 = a04;
      a00 ^= ~bc1 & bc2; a01 ^= ~bc2 & bc3; a02 ^= ~bc3 & bc4; a03 ^= ~bc4 & bc0; a04 ^= ~bc0 & bc1;

      bc0 = a10; bc1 = a11; bc2 = a12; bc3 = a13; bc4 = a14;
      a10 ^= ~bc1 & bc2; a11 ^= ~bc2 & bc3; a12 ^= ~bc3 & bc4; a13 ^= ~bc4 & bc0; a14 ^= ~bc0 & bc1;

      bc0 = a20; bc1 = a21; bc2 = a22; bc3 = a23; bc4 = a24;
      a20 ^= ~bc1 & bc2; a21 ^= ~bc2 & bc3; a22 ^= ~bc3 & bc4; a23 ^= ~bc4 & bc0; a24 ^= ~bc0 & bc1;

      bc0 = a30; bc1 = a31; bc2 = a32; bc3 = a33; bc4 = a34;
      a30 ^= ~bc1 & bc2; a31 ^= ~bc2 & bc3; a32 ^= ~bc3 & bc4; a33 ^= ~bc4 & bc0; a34 ^= ~bc0 & bc1;

      bc0 = a40; bc1 = a41; bc2 = a42; bc3 = a43; bc4 = a44;
      a40 ^= ~bc1 & bc2; a41 ^= ~bc2 & bc3; a42 ^= ~bc3 & bc4; a43 ^= ~bc4 & bc0; a44 ^= ~bc0 & bc1;

      //  Iota

      a00 ^= keccakf_rndc[round];
    }

    // Theta

    u64x bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
    u64x bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
    u64x bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
    u64x bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
    u64x bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

    u64x t;

    t = bc4 ^ rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t;
    t = bc0 ^ rotl64 (bc2, 1);                     a21 ^= t; a31 ^= t; a41 ^= t;
    t = bc1 ^ rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t;
    t = bc2 ^ rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
    t = bc3 ^ rotl64 (bc0, 1); a04 ^= t;                     a34 ^= t; a44 ^= t;

    // Rho Pi

    t = a01;

    Rho_Pi (a20,  1);
    Rho_Pi (a12,  3);
    Rho_Pi (a21,  6);
    Rho_Pi (a32, 10);
    Rho_Pi (a33, 15);
    Rho_Pi (a03, 21);
    Rho_Pi (a10, 28);
    Rho_Pi (a31, 36);
    Rho_Pi (a13, 45);
    Rho_Pi (a41, 55);
    Rho_Pi (a44,  2);
    Rho_Pi (a04, 14);
    Rho_Pi (a30, 27);
    Rho_Pi (a43, 41);
    Rho_Pi (a34, 56);
    Rho_Pi (a23,  8);
    Rho_Pi (a22, 25);
    Rho_Pi (a02, 43);

    #undef Rho_Pi

    bc0 = a00;
    bc2 = a02;
    bc3 = a03;
    bc4 = a04;

    a02 ^= ~bc3 & bc4;
    a03 ^= ~bc4 & bc0;

    const u32x r0 = l32_from_64 (a03);
    const u32x r1 = h32_from_64 (a03);
    const u32x r2 = l32_from_64 (a02);
    const u32x r3 = h32_from_64 (a02);

    COMPARE_S_SIMD (r0, r1, r2, r3);
  }
}

__kernel void m17900_s08 (KERN_ATTR_BASIC ())
{
}

__kernel void m17900_s16 (KERN_ATTR_BASIC ())
{
}
