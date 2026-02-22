/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 *
 * Ethereum Wallet SCRYPT - Minimal kernel for scrypt-jane bridge
 * This kernel is designed to work with the scrypt-jane bridge which handles
 * the expensive ROMix computation using AVX2 intrinsics.
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#endif

#define COMPARE_S M2S(INCLUDE_PATH/inc_comp_single.cl)
#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

#define SCRYPT_R_MAX 16
#define SCRYPT_P_MAX 16

#define SCRYPT_TMP_SIZE (128ULL * SCRYPT_R_MAX * SCRYPT_P_MAX)
#define SCRYPT_TMP_SIZE4 (SCRYPT_TMP_SIZE / 4)

typedef struct
{
  u32 P[SCRYPT_TMP_SIZE4];

} scrypt_tmp_t;

typedef struct ethereum_scrypt
{
  u32 salt_buf[16];
  u32 ciphertext[8];

} ethereum_scrypt_t;

// Keccak-256 implementation for Ethereum key derivation
#ifndef KECCAK_ROUNDS
#define KECCAK_ROUNDS 24
#endif

#define Theta1(s) (st[0 + s] ^ st[5 + s] ^ st[10 + s] ^ st[15 + s] ^ st[20 + s])

#define Theta2(s)               \
{                               \
  st[ 0 + s] ^= t;              \
  st[ 5 + s] ^= t;              \
  st[10 + s] ^= t;              \
  st[15 + s] ^= t;              \
  st[20 + s] ^= t;              \
}

#define Rho_Pi(s)               \
{                               \
  u32 j = keccakf_piln[s];      \
  u32 k = keccakf_rotc[s];      \
  bc0 = st[j];                  \
  st[j] = hc_rotl64_S (t, k);   \
  t = bc0;                      \
}

#define Chi(s)                  \
{                               \
  bc0 = st[0 + s];              \
  bc1 = st[1 + s];              \
  bc2 = st[2 + s];              \
  bc3 = st[3 + s];              \
  bc4 = st[4 + s];              \
  st[0 + s] ^= ~bc1 & bc2;      \
  st[1 + s] ^= ~bc2 & bc3;      \
  st[2 + s] ^= ~bc3 & bc4;      \
  st[3 + s] ^= ~bc4 & bc0;      \
  st[4 + s] ^= ~bc0 & bc1;      \
}

CONSTANT_VK u64a keccakf_rndc[24] =
{
  KECCAK_RNDC_00, KECCAK_RNDC_01, KECCAK_RNDC_02, KECCAK_RNDC_03,
  KECCAK_RNDC_04, KECCAK_RNDC_05, KECCAK_RNDC_06, KECCAK_RNDC_07,
  KECCAK_RNDC_08, KECCAK_RNDC_09, KECCAK_RNDC_10, KECCAK_RNDC_11,
  KECCAK_RNDC_12, KECCAK_RNDC_13, KECCAK_RNDC_14, KECCAK_RNDC_15,
  KECCAK_RNDC_16, KECCAK_RNDC_17, KECCAK_RNDC_18, KECCAK_RNDC_19,
  KECCAK_RNDC_20, KECCAK_RNDC_21, KECCAK_RNDC_22, KECCAK_RNDC_23
};

DECLSPEC void keccak_transform_S (PRIVATE_AS u64 *st)
{
  const u8 keccakf_rotc[24] =
  {
     1,  3,  6, 10, 15, 21, 28, 36, 45, 55,  2, 14,
    27, 41, 56,  8, 25, 43, 62, 18, 39, 61, 20, 44
  };

  const u8 keccakf_piln[24] =
  {
    10,  7, 11, 17, 18,  3,  5, 16,  8, 21, 24,  4,
    15, 23, 19, 13, 12,  2, 20, 14, 22,  9,  6,  1
  };

  for (int round = 0; round < KECCAK_ROUNDS; round++)
  {
    u64 bc0 = Theta1 (0);
    u64 bc1 = Theta1 (1);
    u64 bc2 = Theta1 (2);
    u64 bc3 = Theta1 (3);
    u64 bc4 = Theta1 (4);

    u64 t;

    t = bc4 ^ hc_rotl64_S (bc1, 1); Theta2 (0);
    t = bc0 ^ hc_rotl64_S (bc2, 1); Theta2 (1);
    t = bc1 ^ hc_rotl64_S (bc3, 1); Theta2 (2);
    t = bc2 ^ hc_rotl64_S (bc4, 1); Theta2 (3);
    t = bc3 ^ hc_rotl64_S (bc0, 1); Theta2 (4);

    t = st[1];

    Rho_Pi (0);
    Rho_Pi (1);
    Rho_Pi (2);
    Rho_Pi (3);
    Rho_Pi (4);
    Rho_Pi (5);
    Rho_Pi (6);
    Rho_Pi (7);
    Rho_Pi (8);
    Rho_Pi (9);
    Rho_Pi (10);
    Rho_Pi (11);
    Rho_Pi (12);
    Rho_Pi (13);
    Rho_Pi (14);
    Rho_Pi (15);
    Rho_Pi (16);
    Rho_Pi (17);
    Rho_Pi (18);
    Rho_Pi (19);
    Rho_Pi (20);
    Rho_Pi (21);
    Rho_Pi (22);
    Rho_Pi (23);

    Chi (0);
    Chi (5);
    Chi (10);
    Chi (15);
    Chi (20);

    st[0] ^= keccakf_rndc[round];
  }
}

// Initial PBKDF2 to create the scrypt input state
KERNEL_FQ KERNEL_FA void m70400_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, ethereum_scrypt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len);

  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0, k = 1; i < x_bytes; i += 32, j += 8, k += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = k;
    w0[1] = 0;
    w0[2] = 0;
    w0[3] = 0;
    w1[0] = 0;
    w1[1] = 0;
    w1[2] = 0;
    w1[3] = 0;
    w2[0] = 0;
    w2[1] = 0;
    w2[2] = 0;
    w2[3] = 0;
    w3[0] = 0;
    w3[1] = 0;
    w3[2] = 0;
    w3[3] = 0;

    sha256_hmac_update_64 (&sha256_hmac_ctx2, w0, w1, w2, w3, 4);

    sha256_hmac_final (&sha256_hmac_ctx2);

    u32 digest[8];

    digest[0] = sha256_hmac_ctx2.opad.h[0];
    digest[1] = sha256_hmac_ctx2.opad.h[1];
    digest[2] = sha256_hmac_ctx2.opad.h[2];
    digest[3] = sha256_hmac_ctx2.opad.h[3];
    digest[4] = sha256_hmac_ctx2.opad.h[4];
    digest[5] = sha256_hmac_ctx2.opad.h[5];
    digest[6] = sha256_hmac_ctx2.opad.h[6];
    digest[7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].P[j + 0] = hc_swap32_S (digest[0]);
    tmps[gid].P[j + 1] = hc_swap32_S (digest[1]);
    tmps[gid].P[j + 2] = hc_swap32_S (digest[2]);
    tmps[gid].P[j + 3] = hc_swap32_S (digest[3]);
    tmps[gid].P[j + 4] = hc_swap32_S (digest[4]);
    tmps[gid].P[j + 5] = hc_swap32_S (digest[5]);
    tmps[gid].P[j + 6] = hc_swap32_S (digest[6]);
    tmps[gid].P[j + 7] = hc_swap32_S (digest[7]);
  }
}

// The bridge handles this kernel - it will call scrypt_ROMix from scrypt-jane
KERNEL_FQ KERNEL_FA void m70400_loop (KERN_ATTR_TMPS (scrypt_tmp_t))
{
  // EMPTY - The scrypt-jane bridge replaces this with AVX2 implementation
}

// Final comparison - applies Keccak and compares
KERNEL_FQ KERNEL_FA void m70400_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, ethereum_scrypt_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  /**
   * 2nd pbkdf2, creates B
   */

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  sha256_hmac_ctx_t ctx;

  sha256_hmac_init_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);

  u32 r = salt_bufs[SALT_POS_HOST].scrypt_r;
  u32 p = salt_bufs[SALT_POS_HOST].scrypt_p;

  u32 chunk_bytes = 64 * r * 2;

  u32 x_bytes = chunk_bytes * p;

  for (u32 i = 0, j = 0; i < x_bytes; i += 64, j += 16)
  {
    w0[0] = hc_swap32_S (tmps[gid].P[j +  0]);
    w0[1] = hc_swap32_S (tmps[gid].P[j +  1]);
    w0[2] = hc_swap32_S (tmps[gid].P[j +  2]);
    w0[3] = hc_swap32_S (tmps[gid].P[j +  3]);
    w1[0] = hc_swap32_S (tmps[gid].P[j +  4]);
    w1[1] = hc_swap32_S (tmps[gid].P[j +  5]);
    w1[2] = hc_swap32_S (tmps[gid].P[j +  6]);
    w1[3] = hc_swap32_S (tmps[gid].P[j +  7]);
    w2[0] = hc_swap32_S (tmps[gid].P[j +  8]);
    w2[1] = hc_swap32_S (tmps[gid].P[j +  9]);
    w2[2] = hc_swap32_S (tmps[gid].P[j + 10]);
    w2[3] = hc_swap32_S (tmps[gid].P[j + 11]);
    w3[0] = hc_swap32_S (tmps[gid].P[j + 12]);
    w3[1] = hc_swap32_S (tmps[gid].P[j + 13]);
    w3[2] = hc_swap32_S (tmps[gid].P[j + 14]);
    w3[3] = hc_swap32_S (tmps[gid].P[j + 15]);

    sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 64);
  }

  w0[0] = 1;
  w0[1] = 0;
  w0[2] = 0;
  w0[3] = 0;
  w1[0] = 0;
  w1[1] = 0;
  w1[2] = 0;
  w1[3] = 0;
  w2[0] = 0;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = 0;

  sha256_hmac_update_64 (&ctx, w0, w1, w2, w3, 4);

  sha256_hmac_final (&ctx);

  u32 out[8];

  out[0] = hc_swap32_S (ctx.opad.h[0]);
  out[1] = hc_swap32_S (ctx.opad.h[1]);
  out[2] = hc_swap32_S (ctx.opad.h[2]);
  out[3] = hc_swap32_S (ctx.opad.h[3]);
  out[4] = hc_swap32_S (ctx.opad.h[4]);
  out[5] = hc_swap32_S (ctx.opad.h[5]);
  out[6] = hc_swap32_S (ctx.opad.h[6]);
  out[7] = hc_swap32_S (ctx.opad.h[7]);

  /**
   * keccak
   */

  u32 ciphertext[8];

  ciphertext[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[0];
  ciphertext[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[1];
  ciphertext[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[2];
  ciphertext[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[3];
  ciphertext[4] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[4];
  ciphertext[5] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[5];
  ciphertext[6] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[6];
  ciphertext[7] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[7];

  u32 key[4];

  key[0] = out[4];
  key[1] = out[5];
  key[2] = out[6];
  key[3] = out[7];

  u64 st[25];

  st[ 0] = hl32_to_64_S (key[1], key[0]);
  st[ 1] = hl32_to_64_S (key[3], key[2]);
  st[ 2] = hl32_to_64_S (ciphertext[1], ciphertext[0]);
  st[ 3] = hl32_to_64_S (ciphertext[3], ciphertext[2]);
  st[ 4] = hl32_to_64_S (ciphertext[5], ciphertext[4]);
  st[ 5] = hl32_to_64_S (ciphertext[7], ciphertext[6]);
  st[ 6] = 0x01;
  st[ 7] = 0;
  st[ 8] = 0;
  st[ 9] = 0;
  st[10] = 0;
  st[11] = 0;
  st[12] = 0;
  st[13] = 0;
  st[14] = 0;
  st[15] = 0;
  st[16] = 0;
  st[17] = 0;
  st[18] = 0;
  st[19] = 0;
  st[20] = 0;
  st[21] = 0;
  st[22] = 0;
  st[23] = 0;
  st[24] = 0;

  const u32 mdlen = 32;

  const u32 rsiz = 200 - (2 * mdlen);

  const u32 add80w = (rsiz - 1) / 8;

  st[add80w] |= 0x8000000000000000UL;

  keccak_transform_S (st);

  const u32 r0 = l32_from_64_S (st[0]);
  const u32 r1 = h32_from_64_S (st[0]);
  const u32 r2 = l32_from_64_S (st[1]);
  const u32 r3 = h32_from_64_S (st[1]);

  #define il_pos 0

  #ifdef KERNEL_STATIC
  #include COMPARE_M
  #endif
}
