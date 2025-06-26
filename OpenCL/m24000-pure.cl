/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)
#include M2S(INCLUDE_PATH/inc_hash_scrypt.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#include M2S(INCLUDE_PATH/inc_cipher_twofish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_serpent.cl)
#include M2S(INCLUDE_PATH/inc_cipher_camellia.cl)
#endif

typedef struct bestcrypt_scrypt
{
  u32 salt_buf[24];
  u32 ciphertext[96];
  u32 version;

} bestcrypt_scrypt_t;

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
  0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
  0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
  0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
  0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
  0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
  0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
  0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
  0x8000000000008080, 0x0000000080000001, 0x8000000080008008
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

KERNEL_FQ KERNEL_FA void m24000_init (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  scrypt_pbkdf2_ggg (pws[gid].i, pws[gid].pw_len, salt_bufs[SALT_POS_HOST].salt_buf, salt_bufs[SALT_POS_HOST].salt_len, tmps[gid].in, SCRYPT_SZ);

  scrypt_blockmix_in (tmps[gid].in, tmps[gid].out, SCRYPT_SZ);
}

KERNEL_FQ KERNEL_FA void m24000_loop_prepare (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_init (P, X, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m24000_loop (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);
  const u64 bid = get_group_id (0);

  if (gid >= GID_CNT) return;

  u32 X[STATE_CNT4];
  u32 T[STATE_CNT4];

  GLOBAL_AS u32 *P = tmps[gid].out + (SALT_REPEAT * STATE_CNT4);

  scrypt_smix_loop (P, X, T, d_extra0_buf, d_extra1_buf, d_extra2_buf, d_extra3_buf, gid, lid, lsz, bid);
}

KERNEL_FQ KERNEL_FA void m24000_comp (KERN_ATTR_TMPS_ESALT (scrypt_tmp_t, bestcrypt_scrypt_t))
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

  if (gid >= GID_CNT) return;

  scrypt_blockmix_out (tmps[gid].out, tmps[gid].in, SCRYPT_SZ);

  u32 out[8];

  scrypt_pbkdf2_ggp (pws[gid].i, pws[gid].pw_len, tmps[gid].in, SCRYPT_SZ, out, 32);

  u32 version = esalt_bufs[DIGESTS_OFFSET_HOST].version;

  u32 iv[4] = { 0 };

  u32 res[20]; // full would be 24 x u32 (96 bytes)

  u32 key[8];

  key[0] = out[0];
  key[1] = out[1];
  key[2] = out[2];
  key[3] = out[3];
  key[4] = out[4];
  key[5] = out[5];
  key[6] = out[6];
  key[7] = out[7];

  if (version == 0x38) //0x38 is char for '8' which is the crypto type passed in position 3 of hash ( $08$ )
  {
    #define KEYLEN 60

    u32 ks[KEYLEN];

    aes256_set_decrypt_key (ks, key, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];

      u32 out[4];

      aes256_decrypt (ks, data, out, s_td0, s_td1, s_td2, s_td3, s_td4);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  if (version == 0x39) //0x39 is char for '9' which is the crypto type passed in position 3 of hash ( $09$ )
  {
    u32 sk[4];
    u32 lk[40];

    twofish256_set_key (sk, lk, key);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];

      u32 out[4];

      twofish256_decrypt (sk, lk, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  if (version == 0x61) //0x61 is char for 'a' which is the crypto type passed in position 3 of hash ( $0a$ )
  {
    u32 ks_serpent[140];

    serpent256_set_key (ks_serpent, key);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];


      u32 out[4];

      serpent256_decrypt (ks_serpent, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  if (version == 0x66) //0x66 is char for 'f' which is the crypto type passed in position 3 of hash ( $0f$ )
  {
    u32 ks_camellia[68];

    camellia256_set_key (ks_camellia, key);

    for (u32 i = 0; i < 20; i += 4) // 96 bytes output would contain the full 32 byte checksum
    {
      u32 data[4];

      data[0] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 0];
      data[1] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 1];
      data[2] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 2];
      data[3] = esalt_bufs[DIGESTS_OFFSET_HOST].ciphertext[i + 3];


      u32 out[4];

      camellia256_decrypt (ks_camellia, data, out);

      res[i + 0] = hc_swap32_S (out[0] ^ iv[0]);
      res[i + 1] = hc_swap32_S (out[1] ^ iv[1]);
      res[i + 2] = hc_swap32_S (out[2] ^ iv[2]);
      res[i + 3] = hc_swap32_S (out[3] ^ iv[3]);

      iv[0] = data[0];
      iv[1] = data[1];
      iv[2] = data[2];
      iv[3] = data[3];
    }
  }

  u32 digest[8];

  digest[0] = SHA256M_A;
  digest[1] = SHA256M_B;
  digest[2] = SHA256M_C;
  digest[3] = SHA256M_D;
  digest[4] = SHA256M_E;
  digest[5] = SHA256M_F;
  digest[6] = SHA256M_G;
  digest[7] = SHA256M_H;

  u32 w0[4];
  u32 w1[4];
  u32 w2[4];
  u32 w3[4];

  w0[0] = res[ 0];
  w0[1] = res[ 1];
  w0[2] = res[ 2];
  w0[3] = res[ 3];
  w1[0] = res[ 4];
  w1[1] = res[ 5];
  w1[2] = res[ 6];
  w1[3] = res[ 7];
  w2[0] = res[ 8];
  w2[1] = res[ 9];
  w2[2] = res[10];
  w2[3] = res[11];
  w3[0] = res[12];
  w3[1] = res[13];
  w3[2] = res[14];
  w3[3] = res[15];

  sha256_transform (w0, w1, w2, w3, digest);

  w0[0] = 0x80000000;
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
  w3[3] = 64 * 8;

  sha256_transform (w0, w1, w2, w3, digest);

  if ((digest[0] == res[16]) &&
      (digest[1] == res[17]) &&
      (digest[2] == res[18]) &&
      (digest[3] == res[19]))
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }

    return;
  }
}

