/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha256.cl"
#include "inc_cipher_aes.cl"
#endif

#define COMPARE_S "inc_comp_single.cl"
#define COMPARE_M "inc_comp_multi.cl"

typedef struct ethereum_presale
{
  u32 iv[4];
  u32 enc_seed[152];
  u32 enc_seed_len;

} ethereum_presale_t;

typedef struct pbkdf2_sha256_tmp
{
  u32  ipad[8];
  u32  opad[8];

  u32  dgst[32];
  u32  out[32];

} pbkdf2_sha256_tmp_t;

CONSTANT_VK u64a keccakf_rndc[24] =
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
  st[j] = hc_rotl64_S (t, k);      \
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

DECLSPEC void keccak_transform_S (u64 *st)
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

  /**
   * Keccak
   */

  int round;

  for (round = 0; round < KECCAK_ROUNDS; round++)
  {
    // Theta

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

    // Rho Pi

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

    //  Chi

    Chi (0);
    Chi (5);
    Chi (10);
    Chi (15);
    Chi (20);

    //  Iota

    st[0] ^= keccakf_rndc[round];
  }
}

DECLSPEC void hmac_sha256_run_V (u32x *w0, u32x *w1, u32x *w2, u32x *w3, u32x *ipad, u32x *opad, u32x *digest)
{
  digest[0] = ipad[0];
  digest[1] = ipad[1];
  digest[2] = ipad[2];
  digest[3] = ipad[3];
  digest[4] = ipad[4];
  digest[5] = ipad[5];
  digest[6] = ipad[6];
  digest[7] = ipad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);

  w0[0] = digest[0];
  w0[1] = digest[1];
  w0[2] = digest[2];
  w0[3] = digest[3];
  w1[0] = digest[4];
  w1[1] = digest[5];
  w1[2] = digest[6];
  w1[3] = digest[7];
  w2[0] = 0x80000000;
  w2[1] = 0;
  w2[2] = 0;
  w2[3] = 0;
  w3[0] = 0;
  w3[1] = 0;
  w3[2] = 0;
  w3[3] = (64 + 32) * 8;

  digest[0] = opad[0];
  digest[1] = opad[1];
  digest[2] = opad[2];
  digest[3] = opad[3];
  digest[4] = opad[4];
  digest[5] = opad[5];
  digest[6] = opad[6];
  digest[7] = opad[7];

  sha256_transform_vector (w0, w1, w2, w3, digest);
}

KERNEL_FQ void m16300_init (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, ethereum_presale_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  sha256_hmac_ctx_t sha256_hmac_ctx;

  sha256_hmac_init_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  tmps[gid].ipad[0] = sha256_hmac_ctx.ipad.h[0];
  tmps[gid].ipad[1] = sha256_hmac_ctx.ipad.h[1];
  tmps[gid].ipad[2] = sha256_hmac_ctx.ipad.h[2];
  tmps[gid].ipad[3] = sha256_hmac_ctx.ipad.h[3];
  tmps[gid].ipad[4] = sha256_hmac_ctx.ipad.h[4];
  tmps[gid].ipad[5] = sha256_hmac_ctx.ipad.h[5];
  tmps[gid].ipad[6] = sha256_hmac_ctx.ipad.h[6];
  tmps[gid].ipad[7] = sha256_hmac_ctx.ipad.h[7];

  tmps[gid].opad[0] = sha256_hmac_ctx.opad.h[0];
  tmps[gid].opad[1] = sha256_hmac_ctx.opad.h[1];
  tmps[gid].opad[2] = sha256_hmac_ctx.opad.h[2];
  tmps[gid].opad[3] = sha256_hmac_ctx.opad.h[3];
  tmps[gid].opad[4] = sha256_hmac_ctx.opad.h[4];
  tmps[gid].opad[5] = sha256_hmac_ctx.opad.h[5];
  tmps[gid].opad[6] = sha256_hmac_ctx.opad.h[6];
  tmps[gid].opad[7] = sha256_hmac_ctx.opad.h[7];

  sha256_hmac_update_global_swap (&sha256_hmac_ctx, pws[gid].i, pws[gid].pw_len);

  for (u32 i = 0, j = 1; i < 8; i += 8, j += 1)
  {
    sha256_hmac_ctx_t sha256_hmac_ctx2 = sha256_hmac_ctx;

    u32 w0[4];
    u32 w1[4];
    u32 w2[4];
    u32 w3[4];

    w0[0] = j;
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

    tmps[gid].dgst[i + 0] = sha256_hmac_ctx2.opad.h[0];
    tmps[gid].dgst[i + 1] = sha256_hmac_ctx2.opad.h[1];
    tmps[gid].dgst[i + 2] = sha256_hmac_ctx2.opad.h[2];
    tmps[gid].dgst[i + 3] = sha256_hmac_ctx2.opad.h[3];
    tmps[gid].dgst[i + 4] = sha256_hmac_ctx2.opad.h[4];
    tmps[gid].dgst[i + 5] = sha256_hmac_ctx2.opad.h[5];
    tmps[gid].dgst[i + 6] = sha256_hmac_ctx2.opad.h[6];
    tmps[gid].dgst[i + 7] = sha256_hmac_ctx2.opad.h[7];

    tmps[gid].out[i + 0] = tmps[gid].dgst[i + 0];
    tmps[gid].out[i + 1] = tmps[gid].dgst[i + 1];
    tmps[gid].out[i + 2] = tmps[gid].dgst[i + 2];
    tmps[gid].out[i + 3] = tmps[gid].dgst[i + 3];
    tmps[gid].out[i + 4] = tmps[gid].dgst[i + 4];
    tmps[gid].out[i + 5] = tmps[gid].dgst[i + 5];
    tmps[gid].out[i + 6] = tmps[gid].dgst[i + 6];
    tmps[gid].out[i + 7] = tmps[gid].dgst[i + 7];
  }
}

KERNEL_FQ void m16300_loop (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, ethereum_presale_t))
{
  const u64 gid = get_global_id (0);

  if ((gid * VECT_SIZE) >= gid_max) return;

  u32x ipad[8];
  u32x opad[8];

  ipad[0] = packv (tmps, ipad, gid, 0);
  ipad[1] = packv (tmps, ipad, gid, 1);
  ipad[2] = packv (tmps, ipad, gid, 2);
  ipad[3] = packv (tmps, ipad, gid, 3);
  ipad[4] = packv (tmps, ipad, gid, 4);
  ipad[5] = packv (tmps, ipad, gid, 5);
  ipad[6] = packv (tmps, ipad, gid, 6);
  ipad[7] = packv (tmps, ipad, gid, 7);

  opad[0] = packv (tmps, opad, gid, 0);
  opad[1] = packv (tmps, opad, gid, 1);
  opad[2] = packv (tmps, opad, gid, 2);
  opad[3] = packv (tmps, opad, gid, 3);
  opad[4] = packv (tmps, opad, gid, 4);
  opad[5] = packv (tmps, opad, gid, 5);
  opad[6] = packv (tmps, opad, gid, 6);
  opad[7] = packv (tmps, opad, gid, 7);

  for (u32 i = 0; i < 8; i += 8)
  {
    u32x dgst[8];
    u32x out[8];

    dgst[0] = packv (tmps, dgst, gid, i + 0);
    dgst[1] = packv (tmps, dgst, gid, i + 1);
    dgst[2] = packv (tmps, dgst, gid, i + 2);
    dgst[3] = packv (tmps, dgst, gid, i + 3);
    dgst[4] = packv (tmps, dgst, gid, i + 4);
    dgst[5] = packv (tmps, dgst, gid, i + 5);
    dgst[6] = packv (tmps, dgst, gid, i + 6);
    dgst[7] = packv (tmps, dgst, gid, i + 7);

    out[0] = packv (tmps, out, gid, i + 0);
    out[1] = packv (tmps, out, gid, i + 1);
    out[2] = packv (tmps, out, gid, i + 2);
    out[3] = packv (tmps, out, gid, i + 3);
    out[4] = packv (tmps, out, gid, i + 4);
    out[5] = packv (tmps, out, gid, i + 5);
    out[6] = packv (tmps, out, gid, i + 6);
    out[7] = packv (tmps, out, gid, i + 7);

    for (u32 j = 0; j < loop_cnt; j++)
    {
      u32x w0[4];
      u32x w1[4];
      u32x w2[4];
      u32x w3[4];

      w0[0] = dgst[0];
      w0[1] = dgst[1];
      w0[2] = dgst[2];
      w0[3] = dgst[3];
      w1[0] = dgst[4];
      w1[1] = dgst[5];
      w1[2] = dgst[6];
      w1[3] = dgst[7];
      w2[0] = 0x80000000;
      w2[1] = 0;
      w2[2] = 0;
      w2[3] = 0;
      w3[0] = 0;
      w3[1] = 0;
      w3[2] = 0;
      w3[3] = (64 + 32) * 8;

      hmac_sha256_run_V (w0, w1, w2, w3, ipad, opad, dgst);

      out[0] ^= dgst[0];
      out[1] ^= dgst[1];
      out[2] ^= dgst[2];
      out[3] ^= dgst[3];
      out[4] ^= dgst[4];
      out[5] ^= dgst[5];
      out[6] ^= dgst[6];
      out[7] ^= dgst[7];
    }

    unpackv (tmps, dgst, gid, i + 0, dgst[0]);
    unpackv (tmps, dgst, gid, i + 1, dgst[1]);
    unpackv (tmps, dgst, gid, i + 2, dgst[2]);
    unpackv (tmps, dgst, gid, i + 3, dgst[3]);
    unpackv (tmps, dgst, gid, i + 4, dgst[4]);
    unpackv (tmps, dgst, gid, i + 5, dgst[5]);
    unpackv (tmps, dgst, gid, i + 6, dgst[6]);
    unpackv (tmps, dgst, gid, i + 7, dgst[7]);

    unpackv (tmps, out, gid, i + 0, out[0]);
    unpackv (tmps, out, gid, i + 1, out[1]);
    unpackv (tmps, out, gid, i + 2, out[2]);
    unpackv (tmps, out, gid, i + 3, out[3]);
    unpackv (tmps, out, gid, i + 4, out[4]);
    unpackv (tmps, out, gid, i + 5, out[5]);
    unpackv (tmps, out, gid, i + 6, out[6]);
    unpackv (tmps, out, gid, i + 7, out[7]);
  }
}

KERNEL_FQ void m16300_comp (KERN_ATTR_TMPS_ESALT (pbkdf2_sha256_tmp_t, ethereum_presale_t))
{
  /**
   * base
   */

  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];

    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= gid_max) return;

  /*
   * AES-CBC-128 decrypt
   */

  /**
   * aes decrypt key
   */

  u32 ukey[4];

  ukey[0] = tmps[gid].out[0];
  ukey[1] = tmps[gid].out[1];
  ukey[2] = tmps[gid].out[2];
  ukey[3] = tmps[gid].out[3];

  /**
   * aes init
   */

  #define KEYLEN 60

  u32 ks[KEYLEN];

  AES128_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

  u32 iv[4];

  iv[0] = esalt_bufs[digests_offset].iv[0];
  iv[1] = esalt_bufs[digests_offset].iv[1];
  iv[2] = esalt_bufs[digests_offset].iv[2];
  iv[3] = esalt_bufs[digests_offset].iv[3];

  u32 a = iv[0];
  u32 b = iv[1];
  u32 c = iv[2];
  u32 d = iv[3];

  u32 enc_seed_len = esalt_bufs[digests_offset].enc_seed_len;

  u64 seed[76 + 1]; // we need the + 1 to add the final \x02

  u32 loop_idx = 0;
  u32 seed_idx = 0;

  for (loop_idx = 0, seed_idx = 0; loop_idx < enc_seed_len / 4; loop_idx += 4, seed_idx += 2)
  {
    u32 data[4];

    data[0] = esalt_bufs[digests_offset].enc_seed[loop_idx + 0];
    data[1] = esalt_bufs[digests_offset].enc_seed[loop_idx + 1];
    data[2] = esalt_bufs[digests_offset].enc_seed[loop_idx + 2];
    data[3] = esalt_bufs[digests_offset].enc_seed[loop_idx + 3];

    u32 out[4];

    AES128_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

    a ^= out[0];
    b ^= out[1];
    c ^= out[2];
    d ^= out[3];

    a = hc_swap32_S (a);
    b = hc_swap32_S (b);
    c = hc_swap32_S (c);
    d = hc_swap32_S (d);

    seed[seed_idx + 0] = hl32_to_64_S (b, a);
    seed[seed_idx + 1] = hl32_to_64_S (d, c);

    a = data[0];
    b = data[1];
    c = data[2];
    d = data[3];
  }

  /*
   * check padding
   */

  u32 padding_len = h32_from_64_S (seed[seed_idx - 1]) >> 24;

  // the ethereum algorithm adds a \x02 after the seed i.e. keccak ($seed . "\x02")
  // and the keccak adds an additional \x01 after the whole input

  u32 final_len  = enc_seed_len - padding_len + 2;

  switch (padding_len)
  {
    case 16:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x1010101010101010) ||
            ((seed[seed_idx - 2] & 0xffffffffffffffff) != 0x1010101010101010))
        {
          return;
        }

        seed[seed_idx - 2] = 0x0102;
        seed[seed_idx - 1] = 0;
      break;

    case 15:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0f0f0f0f0f0f0f0f) ||
            ((seed[seed_idx - 2] & 0xffffffffffffff00) != 0x0f0f0f0f0f0f0f00))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x00000000000000ff;
        seed[seed_idx - 2] |= 0x0000000000010200;
        seed[seed_idx - 1] = 0;
      break;

    case 14:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0e0e0e0e0e0e0e0e) ||
            ((seed[seed_idx - 2] & 0xffffffffffff0000) != 0x0e0e0e0e0e0e0000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x000000000000ffff;
        seed[seed_idx - 2] |= 0x0000000001020000;
        seed[seed_idx - 1] = 0;
      break;

    case 13:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0d0d0d0d0d0d0d0d) ||
            ((seed[seed_idx - 2] & 0xffffffffff000000) != 0x0d0d0d0d0d000000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x0000000000ffffff;
        seed[seed_idx - 2] |= 0x0000000102000000;
        seed[seed_idx - 1] = 0;
      break;

    case 12:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0c0c0c0c0c0c0c0c) ||
            ((seed[seed_idx - 2] & 0xffffffff00000000) != 0x0c0c0c0c00000000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x00000000ffffffff;
        seed[seed_idx - 2] |= 0x0000010200000000;
        seed[seed_idx - 1] = 0;
      break;

    case 11:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0b0b0b0b0b0b0b0b) ||
            ((seed[seed_idx - 2] & 0xffffff0000000000) != 0x0b0b0b0000000000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x000000ffffffffff;
        seed[seed_idx - 2] |= 0x0001020000000000;
        seed[seed_idx - 1] = 0;
      break;

    case 10:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0a0a0a0a0a0a0a0a) ||
            ((seed[seed_idx - 2] & 0xffff000000000000) != 0x0a0a000000000000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x0000ffffffffffff;
        seed[seed_idx - 2] |= 0x0102000000000000;
        seed[seed_idx - 1] = 0;
      break;

    case  9:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0909090909090909) ||
            ((seed[seed_idx - 2] & 0xff00000000000000) != 0x0900000000000000))
        {
          return;
        }

        seed[seed_idx - 2] &= 0x00ffffffffffffff;
        seed[seed_idx - 2] |= 0x0200000000000000;
        seed[seed_idx - 1] = 0x01;
      break;

    case  8:
        if (((seed[seed_idx - 1] & 0xffffffffffffffff) != 0x0808080808080808) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] = 0x0102;
      break;

    case  7:
        if (((seed[seed_idx - 1] & 0xffffffffffffff00) != 0x0707070707070700) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x00000000000000ff;
        seed[seed_idx - 1] |= 0x0000000000010200;
      break;

    case  6:
        if (((seed[seed_idx - 1] & 0xffffffffffff0000) != 0x0606060606060000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x000000000000ffff;
        seed[seed_idx - 1] |= 0x0000000001020000;
      break;

    case  5:
        if (((seed[seed_idx - 1] & 0xffffffffff000000) != 0x0505050505000000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x0000000000ffffff;
        seed[seed_idx - 1] |= 0x0000000102000000;
      break;

    case  4:
        if (((seed[seed_idx - 1] & 0xffffffff00000000) != 0x0404040400000000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x00000000ffffffff;
        seed[seed_idx - 1] |= 0x0000010200000000;
      break;

    case  3:
        if (((seed[seed_idx - 1] & 0xffffff0000000000) != 0x0303030000000000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x000000ffffffffff;
        seed[seed_idx - 1] |= 0x0001020000000000;
      break;

    case  2:
        if (((seed[seed_idx - 1] & 0xffff000000000000) != 0x0202000000000000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x0000ffffffffffff;
        seed[seed_idx - 1] |= 0x0102000000000000;
      break;

    case  1:
        if (((seed[seed_idx - 1] & 0xff00000000000000) != 0x0100000000000000) ||
            ((seed[seed_idx - 2] & 0x0000000000000000) != 0x0000000000000000))
        {
          return;
        }

        seed[seed_idx - 1] &= 0x00ffffffffffffff;
        seed[seed_idx - 1] |= 0x0200000000000000;
        seed[seed_idx - 0] = 0x01;
      break;

    default:
        return;
      break;
  }

  /**
   * keccak
   */

  u64 st[25] = { 0 };

  u32 keccak_idx = 0;

  for (loop_idx = 0, seed_idx = 0, keccak_idx = 0; loop_idx < final_len; loop_idx += 8, seed_idx++, keccak_idx++)
  {
    if (keccak_idx == 17) // or just: keccak_idx > 16
    {
      keccak_transform_S (st);

      keccak_idx = 0;
    }

    st[keccak_idx] ^= seed[seed_idx];
  }

  // final:

  st[16] ^= 0x8000000000000000;

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
