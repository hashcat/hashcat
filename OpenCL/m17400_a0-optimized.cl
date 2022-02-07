/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_rp_optimized.h)
#include M2S(INCLUDE_PATH/inc_rp_optimized.cl)
#include M2S(INCLUDE_PATH/inc_simd.cl)
#endif

CONSTANT_VK u64a keccakf_rndc[24] =
{
  KECCAK_RNDC_00, KECCAK_RNDC_01, KECCAK_RNDC_02, KECCAK_RNDC_03,
  KECCAK_RNDC_04, KECCAK_RNDC_05, KECCAK_RNDC_06, KECCAK_RNDC_07,
  KECCAK_RNDC_08, KECCAK_RNDC_09, KECCAK_RNDC_10, KECCAK_RNDC_11,
  KECCAK_RNDC_12, KECCAK_RNDC_13, KECCAK_RNDC_14, KECCAK_RNDC_15,
  KECCAK_RNDC_16, KECCAK_RNDC_17, KECCAK_RNDC_18, KECCAK_RNDC_19,
  KECCAK_RNDC_20, KECCAK_RNDC_21, KECCAK_RNDC_22, KECCAK_RNDC_23
};

#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

KERNEL_FQ void m17400_m04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x06_2x4_VV (w0, w1, out_len);

    /**
     * Keccak
     */

    u64x a00 = hl32_to_64 (w0[1], w0[0]);
    u64x a01 = hl32_to_64 (w0[3], w0[2]);
    u64x a02 = hl32_to_64 (w1[1], w1[0]);
    u64x a03 = hl32_to_64 (w1[3], w1[2]);
    u64x a04 = 0;
    u64x a10 = 0;
    u64x a11 = 0;
    u64x a12 = 0;
    u64x a13 = 0;
    u64x a14 = 0;
    u64x a20 = 0;
    u64x a21 = 0;
    u64x a22 = 0;
    u64x a23 = 0;
    u64x a24 = 0;
    u64x a30 = 0;
    u64x a31 = 0x8000000000000000UL;
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
      ad = hc_rotl64 (t, r); \
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

      t = bc4 ^ hc_rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t; a40 ^= t;
      t = bc0 ^ hc_rotl64 (bc2, 1); a01 ^= t; a11 ^= t; a21 ^= t; a31 ^= t; a41 ^= t;
      t = bc1 ^ hc_rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t; a42 ^= t;
      t = bc2 ^ hc_rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
      t = bc3 ^ hc_rotl64 (bc0, 1); a04 ^= t; a14 ^= t; a24 ^= t; a34 ^= t; a44 ^= t;

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

    t = bc4 ^ hc_rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t;
    t = bc0 ^ hc_rotl64 (bc2, 1);                     a21 ^= t; a31 ^= t; a41 ^= t;
    t = bc1 ^ hc_rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t;
    t = bc2 ^ hc_rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
    t = bc3 ^ hc_rotl64 (bc0, 1); a04 ^= t;                     a34 ^= t; a44 ^= t;

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

KERNEL_FQ void m17400_m08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m17400_m16 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m17400_s04 (KERN_ATTR_RULES ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);

  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

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

  const u32 pw_len = pws[gid].pw_len & 63;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET_HOST].digest_buf[DGST_R3]
  };

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    u32x w0[4] = { 0 };
    u32x w1[4] = { 0 };
    u32x w2[4] = { 0 };
    u32x w3[4] = { 0 };

    const u32x out_len = apply_rules_vect_optimized (pw_buf0, pw_buf1, pw_len, rules_buf, il_pos, w0, w1);

    append_0x06_2x4_VV (w0, w1, out_len);

    /**
     * Keccak
     */

    u64x a00 = hl32_to_64 (w0[1], w0[0]);
    u64x a01 = hl32_to_64 (w0[3], w0[2]);
    u64x a02 = hl32_to_64 (w1[1], w1[0]);
    u64x a03 = hl32_to_64 (w1[3], w1[2]);
    u64x a04 = 0;
    u64x a10 = 0;
    u64x a11 = 0;
    u64x a12 = 0;
    u64x a13 = 0;
    u64x a14 = 0;
    u64x a20 = 0;
    u64x a21 = 0;
    u64x a22 = 0;
    u64x a23 = 0;
    u64x a24 = 0;
    u64x a30 = 0;
    u64x a31 = 0x8000000000000000UL;
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
      ad = hc_rotl64 (t, r); \
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

      t = bc4 ^ hc_rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t; a40 ^= t;
      t = bc0 ^ hc_rotl64 (bc2, 1); a01 ^= t; a11 ^= t; a21 ^= t; a31 ^= t; a41 ^= t;
      t = bc1 ^ hc_rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t; a42 ^= t;
      t = bc2 ^ hc_rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
      t = bc3 ^ hc_rotl64 (bc0, 1); a04 ^= t; a14 ^= t; a24 ^= t; a34 ^= t; a44 ^= t;

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

    t = bc4 ^ hc_rotl64 (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t;
    t = bc0 ^ hc_rotl64 (bc2, 1);                     a21 ^= t; a31 ^= t; a41 ^= t;
    t = bc1 ^ hc_rotl64 (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t;
    t = bc2 ^ hc_rotl64 (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
    t = bc3 ^ hc_rotl64 (bc0, 1); a04 ^= t;                     a34 ^= t; a44 ^= t;

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

KERNEL_FQ void m17400_s08 (KERN_ATTR_RULES ())
{
}

KERNEL_FQ void m17400_s16 (KERN_ATTR_RULES ())
{
}
