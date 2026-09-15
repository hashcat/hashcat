/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_pcfg.h)
#include M2S(INCLUDE_PATH/inc_pcfg.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
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

#define PCFG_KECCAK_512_MAXLEN 31

typedef struct pcfg_hash_ctx
{
  u32 unused;

} pcfg_hash_ctx_t;

DECLSPEC void pcfg_hash_init (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED GLOBAL_AS const salt_t *salt_bufs, MAYBE_UNUSED const u32 salt_pos, MAYBE_UNUSED GLOBAL_AS const void *esalt_bufs, MAYBE_UNUSED GLOBAL_AS const digest_t *digests_buf, MAYBE_UNUSED const u32 digest_pos)
{
}

DECLSPEC void pcfg_hash_setup (MAYBE_UNUSED PRIVATE_AS pcfg_hash_ctx_t *hc, MAYBE_UNUSED PRIVATE_AS u32 *w, MAYBE_UNUSED const u32 pw_len)
{
}

DECLSPEC bool pcfg_keccak_512 (PRIVATE_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  u32 w0[4];
  u32 w1[4];

  w0[0] = w[0];
  w0[1] = w[1];
  w0[2] = w[2];
  w0[3] = w[3];
  w1[0] = w[4];
  w1[1] = w[5];
  w1[2] = w[6];
  w1[3] = w[7];

  append_0x01_2x4_S (w0, w1, len);

  /**
   * Keccak
   */

  u64 a00 = hl32_to_64_S (w0[1], w0[0]);
  u64 a01 = hl32_to_64_S (w0[3], w0[2]);
  u64 a02 = hl32_to_64_S (w1[1], w1[0]);
  u64 a03 = hl32_to_64_S (w1[3], w1[2]);
  u64 a04 = 0;
  u64 a10 = 0;
  u64 a11 = 0;
  u64 a12 = 0;
  u64 a13 = 0x8000000000000000UL;
  u64 a14 = 0;
  u64 a20 = 0;
  u64 a21 = 0;
  u64 a22 = 0;
  u64 a23 = 0;
  u64 a24 = 0;
  u64 a30 = 0;
  u64 a31 = 0;
  u64 a32 = 0;
  u64 a33 = 0;
  u64 a34 = 0;
  u64 a40 = 0;
  u64 a41 = 0;
  u64 a42 = 0;
  u64 a43 = 0;
  u64 a44 = 0;

  #define Rho_Pi(ad,r)       \
    bc0 = ad;                \
    ad = hc_rotl64_S (t, r); \
    t = bc0;                 \

  #ifdef _unroll
  #pragma unroll
  #endif
  for (int round = 0; round < KECCAK_ROUNDS - 1; round++)
  {
    // Theta

    u64 bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
    u64 bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
    u64 bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
    u64 bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
    u64 bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

    u64 t;

    t = bc4 ^ hc_rotl64_S (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t; a40 ^= t;
    t = bc0 ^ hc_rotl64_S (bc2, 1); a01 ^= t; a11 ^= t; a21 ^= t; a31 ^= t; a41 ^= t;
    t = bc1 ^ hc_rotl64_S (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t; a42 ^= t;
    t = bc2 ^ hc_rotl64_S (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
    t = bc3 ^ hc_rotl64_S (bc0, 1); a04 ^= t; a14 ^= t; a24 ^= t; a34 ^= t; a44 ^= t;

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

  u64 bc0 = a00 ^ a10 ^ a20 ^ a30 ^ a40;
  u64 bc1 = a01 ^ a11 ^ a21 ^ a31 ^ a41;
  u64 bc2 = a02 ^ a12 ^ a22 ^ a32 ^ a42;
  u64 bc3 = a03 ^ a13 ^ a23 ^ a33 ^ a43;
  u64 bc4 = a04 ^ a14 ^ a24 ^ a34 ^ a44;

  u64 t;

  t = bc4 ^ hc_rotl64_S (bc1, 1); a00 ^= t; a10 ^= t; a20 ^= t; a30 ^= t;
  t = bc0 ^ hc_rotl64_S (bc2, 1);                     a21 ^= t; a31 ^= t; a41 ^= t;
  t = bc1 ^ hc_rotl64_S (bc3, 1); a02 ^= t; a12 ^= t; a22 ^= t; a32 ^= t;
  t = bc2 ^ hc_rotl64_S (bc4, 1); a03 ^= t; a13 ^= t; a23 ^= t; a33 ^= t; a43 ^= t;
  t = bc3 ^ hc_rotl64_S (bc0, 1); a04 ^= t;                     a34 ^= t; a44 ^= t;

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

  dgst[0] = l32_from_64_S (a03);
  dgst[1] = h32_from_64_S (a03);
  dgst[2] = l32_from_64_S (a02);
  dgst[3] = h32_from_64_S (a02);

  return true;
}

DECLSPEC bool pcfg_hash (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, PRIVATE_AS u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_KECCAK_512_MAXLEN) return false;

  return pcfg_keccak_512 (w, len, dgst);
}

DECLSPEC bool pcfg_hash_global (MAYBE_UNUSED PRIVATE_AS const pcfg_hash_ctx_t *hc, GLOBAL_AS const u32 *w, const u32 len, PRIVATE_AS u32 *dgst)
{
  if (len > PCFG_KECCAK_512_MAXLEN) return false;

  u32 t[8];

  for (u32 i = 0; i < 8; i++) t[i] = ((i * 4) < len) ? w[i] : 0;

  return pcfg_keccak_512 (t, len, dgst);
}

#define PCFG_KERNEL_MXX m18000_mxx
#define PCFG_KERNEL_SXX m18000_sxx

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_pcfg_kernel.cl)
#endif
