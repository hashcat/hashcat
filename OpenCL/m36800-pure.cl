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
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_blowfish.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

#if   VECT_SIZE == 1
#define uint_to_hex_lower8(i) make_u32x (l_bin2asc[(i)])
#endif

// must stay identical to the copy in src/modules/module_36800.c
typedef struct sshng_bcrypt
{
  u32 cipher;
  u32 ct_offset;
  u32 rounds;
  u32 salt_buf[4];
  u32 ct_buf[4];
  u32 data_buf[8192];
  int data_len;

} sshng_bcrypt_t;

typedef struct sshng_bcrypt_tmp
{
  u32 pass_hash[16];
  u32 sha2salt[2][16];
  u32 out[2][8];

} sshng_bcrypt_tmp_t;

// "OxychromaticBlowfishSwatDynamite"
CONSTANT_VK u32 c_bcrypt_magic[8] =
{
  0x4f787963, 0x68726f6d, 0x61746963, 0x426c6f77,
  0x66697368, 0x53776174, 0x44796e61, 0x6d697465
};

#define SSHNG_CIPHER_AES256_CBC 2
#define SSHNG_CIPHER_AES256_CTR 6

DECLSPEC void sha512_digest_to_words (PRIVATE_AS const u64 *h, PRIVATE_AS u32 *w)
{
  for (int i = 0; i < 8; i++)
  {
    w[(i * 2) + 0] = (u32) (h[i] >> 32);
    w[(i * 2) + 1] = (u32) (h[i] & 0xffffffff);
  }
}

// written inline because blowfish_set_key() re-initialises P and the S-boxes
// on entry, where this has to mutate the state the previous call left
DECLSPEC void bf_expand0state (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *key)
{
  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= key[i % 16];
  }

  blowfish_encrypt (P, S0, S1, S2, S3);
}

// blowfish_set_key_salt() from inc_cipher_blowfish cannot be reused: it
// hardcodes a 4-word salt, where bcrypt-pbkdf feeds a 64-byte sha2salt that the
// data stream cycles over 16 words at a time
DECLSPEC void bf_expandstate (PRIVATE_AS u32 *P, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3, PRIVATE_AS const u32 *data, PRIVATE_AS const u32 *key)
{
  for (u32 i = 0; i < 18; i++)
  {
    P[i] ^= key[i % 16];
  }

  u32 L0 = 0;
  u32 R0 = 0;
  u32 j  = 0;

  for (u32 i = 0; i < 18; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    P[i + 0] = L0;
    P[i + 1] = R0;
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S0, i + 0, L0);
    SET_KEY32 (S0, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S1, i + 0, L0);
    SET_KEY32 (S1, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S2, i + 0, L0);
    SET_KEY32 (S2, i + 1, R0);
  }

  for (u32 i = 0; i < 256; i += 2)
  {
    L0 ^= data[j & 15]; j++;
    R0 ^= data[j & 15]; j++;

    BF_ENCRYPT (L0, R0);

    SET_KEY32 (S3, i + 0, L0);
    SET_KEY32 (S3, i + 1, R0);
  }
}

DECLSPEC void bcrypt_hash (PRIVATE_AS const u32 *sha2pass, PRIVATE_AS const u32 *sha2salt, PRIVATE_AS u32 *out, LOCAL_AS u32 *S0, LOCAL_AS u32 *S1, LOCAL_AS u32 *S2, LOCAL_AS u32 *S3)
{
  u32 P[18];

  // Blowfish_initstate

  for (u32 i = 0; i < 18; i++)
  {
    P[i] = c_pbox[i];
  }

  for (u32 i = 0; i < 256; i++)
  {
    SET_KEY32 (S0, i, c_sbox0[i]);
    SET_KEY32 (S1, i, c_sbox1[i]);
    SET_KEY32 (S2, i, c_sbox2[i]);
    SET_KEY32 (S3, i, c_sbox3[i]);
  }

  bf_expandstate (P, S0, S1, S2, S3, sha2salt, sha2pass);

  for (u32 i = 0; i < 64; i++)
  {
    bf_expand0state (P, S0, S1, S2, S3, sha2salt);
    bf_expand0state (P, S0, S1, S2, S3, sha2pass);
  }

  u32 cdata[8];

  for (u32 i = 0; i < 8; i++)
  {
    cdata[i] = c_bcrypt_magic[i];
  }

  for (u32 i = 0; i < 64; i++)
  {
    for (u32 k = 0; k < 8; k += 2)
    {
      u32 L0 = cdata[k + 0];
      u32 R0 = cdata[k + 1];

      BF_ENCRYPT (L0, R0);

      cdata[k + 0] = L0;
      cdata[k + 1] = R0;
    }
  }

  // output is little-endian

  for (u32 i = 0; i < 8; i++)
  {
    out[i] = hc_swap32_S (cdata[i]);
  }
}

KERNEL_FQ KERNEL_FA void m36800_init (KERN_ATTR_TMPS_ESALT (sshng_bcrypt_tmp_t, sshng_bcrypt_t))
{
  const u64 gid = get_global_id (0);

  if (gid >= GID_CNT) return;

  sha512_ctx_t ctx;

  sha512_init (&ctx);
  sha512_update_global_swap (&ctx, pws[gid].i, pws[gid].pw_len);
  sha512_final (&ctx);

  u32 pass_hash[16];

  sha512_digest_to_words (ctx.h, pass_hash);

  for (u32 i = 0; i < 16; i++)
  {
    tmps[gid].pass_hash[i] = pass_hash[i];
  }

  // 48 bytes of output needs stride 2, so two blocks each run the full round
  // loop. Every salt after the first comes from the round before, which is
  // what lets _loop stop at any round

  for (u32 count = 1; count <= 2; count++)
  {
    // sha512_update() reads 32 words regardless of len

    u32 w[32] = { 0 };

    w[0] = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[0];
    w[1] = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[1];
    w[2] = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[2];
    w[3] = esalt_bufs[DIGESTS_OFFSET_HOST].salt_buf[3];
    w[4] = count;

    sha512_ctx_t ctx_salt;

    sha512_init   (&ctx_salt);
    sha512_update (&ctx_salt, w, 20);
    sha512_final  (&ctx_salt);

    u32 sha2salt[16];

    sha512_digest_to_words (ctx_salt.h, sha2salt);

    for (u32 i = 0; i < 16; i++)
    {
      tmps[gid].sha2salt[count - 1][i] = sha2salt[i];
    }

    for (u32 i = 0; i < 8; i++)
    {
      tmps[gid].out[count - 1][i] = 0;
    }
  }
}

KERNEL_FQ KERNEL_FA void m36800_loop (KERN_ATTR_TMPS_ESALT (sshng_bcrypt_tmp_t, sshng_bcrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);

  // on CUDA the S-boxes exceed the 48 KB static limit, same as m03200
  #ifdef DYNAMIC_LOCAL
  // from host
  #else
  LOCAL_VK u32 S0_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S1_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S2_all[FIXED_LOCAL_SIZE][256];
  LOCAL_VK u32 S3_all[FIXED_LOCAL_SIZE][256];
  #endif

  #ifdef BCRYPT_AVOID_BANK_CONFLICTS
  LOCAL_AS u32 *S0 = S + (FIXED_LOCAL_SIZE * 256 * 0);
  LOCAL_AS u32 *S1 = S + (FIXED_LOCAL_SIZE * 256 * 1);
  LOCAL_AS u32 *S2 = S + (FIXED_LOCAL_SIZE * 256 * 2);
  LOCAL_AS u32 *S3 = S + (FIXED_LOCAL_SIZE * 256 * 3);
  #else
  LOCAL_AS u32 *S0 = S0_all[lid];
  LOCAL_AS u32 *S1 = S1_all[lid];
  LOCAL_AS u32 *S2 = S2_all[lid];
  LOCAL_AS u32 *S3 = S3_all[lid];
  #endif

  if (gid >= GID_CNT) return;

  u32 sha2pass[16];

  for (u32 i = 0; i < 16; i++)
  {
    sha2pass[i] = tmps[gid].pass_hash[i];
  }

  // a bcrypt_hash() cannot be split, so this runs LOOP_CNT whole rounds

  for (u32 b = 0; b < 2; b++)
  {
    u32 sha2salt[16];

    for (u32 i = 0; i < 16; i++)
    {
      sha2salt[i] = tmps[gid].sha2salt[b][i];
    }

    u32 out[8];

    for (u32 i = 0; i < 8; i++)
    {
      out[i] = tmps[gid].out[b][i];
    }

    for (u32 i = 0; i < LOOP_CNT; i++)
    {
      u32 tmp[8];

      bcrypt_hash (sha2pass, sha2salt, tmp, S0, S1, S2, S3);

      for (u32 j = 0; j < 8; j++)
      {
        out[j] ^= tmp[j];
      }

      // the next round's salt, one of which is computed and never read

      u32 wt[32] = { 0 };

      for (u32 j = 0; j < 8; j++)
      {
        wt[j] = tmp[j];
      }

      sha512_ctx_t ctx;

      sha512_init   (&ctx);
      sha512_update (&ctx, wt, 32);
      sha512_final  (&ctx);

      sha512_digest_to_words (ctx.h, sha2salt);
    }

    for (u32 i = 0; i < 16; i++)
    {
      tmps[gid].sha2salt[b][i] = sha2salt[i];
    }

    for (u32 i = 0; i < 8; i++)
    {
      tmps[gid].out[b][i] = out[i];
    }
  }
}

KERNEL_FQ KERNEL_FA void m36800_comp (KERN_ATTR_TMPS_ESALT (sshng_bcrypt_tmp_t, sshng_bcrypt_t))
{
  const u64 gid = get_global_id (0);
  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM
  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  LOCAL_VK u32 s_td0[256];
  LOCAL_VK u32 s_td1[256];
  LOCAL_VK u32 s_td2[256];
  LOCAL_VK u32 s_td3[256];
  LOCAL_VK u32 s_td4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];

    s_td0[i] = td0[i];
    s_td1[i] = td1[i];
    s_td2[i] = td2[i];
    s_td3[i] = td3[i];
    s_td4[i] = td4[i];
  }

  SYNC_THREADS ();
  #else
  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  CONSTANT_AS u32a *s_td0 = td0;
  CONSTANT_AS u32a *s_td1 = td1;
  CONSTANT_AS u32a *s_td2 = td2;
  CONSTANT_AS u32a *s_td3 = td3;
  CONSTANT_AS u32a *s_td4 = td4;
  #endif

  if (gid >= GID_CNT) return;

  // key[i * stride + block] = out[i], byte-wise, for i < 24. Explicit shifts
  // rather than a u8* view, which would walk each word backwards

  u32 dk[12] = { 0 };

  for (u32 b = 0; b < 2; b++)
  {
    u32 out[8];

    for (u32 i = 0; i < 8; i++)
    {
      out[i] = tmps[gid].out[b][i];
    }

    for (u32 i = 0; i < 24; i++)
    {
      const u32 dest = (i * 2) + b;

      const u32 byte = (out[i / 4] >> (24 - (8 * (i % 4)))) & 0xff;

      const u32 widx  = dest / 4;
      const u32 shift = 24 - (8 * (dest % 4));

      dk[widx] |= byte << shift;
    }
  }

  u32 ukey[8];
  u32 iv[4];

  for (u32 i = 0; i < 8; i++)
  {
    ukey[i] = dk[i];
  }

  for (u32 i = 0; i < 4; i++)
  {
    iv[i] = dk[8 + i];
  }

  u32 ct[4];

  for (u32 i = 0; i < 4; i++)
  {
    ct[i] = esalt_bufs[DIGESTS_OFFSET_HOST].ct_buf[i];
  }

  // the first plaintext block holds the two check integers OpenSSH writes
  // equal before encrypting. The uppercase AES256_* calls are the big-endian
  // API: wrapper and callee swap, so the key/IV pass through unchanged

  u32 pt[2];

  u32 ks[60];

  if (esalt_bufs[DIGESTS_OFFSET_HOST].cipher == SSHNG_CIPHER_AES256_CTR)
  {
    // CTR: the IV is counter block zero, and the first block needs no increment

    AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

    u32 keystream[4];

    AES256_encrypt (ks, iv, keystream, s_te0, s_te1, s_te2, s_te3, s_te4);

    pt[0] = ct[0] ^ keystream[0];
    pt[1] = ct[1] ^ keystream[1];
  }
  else
  {
    // CBC: P1 = D(K, C1) ^ IV

    AES256_set_decrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3, s_td0, s_td1, s_td2, s_td3);

    u32 dec[4];

    AES256_decrypt (ks, ct, dec, s_td0, s_td1, s_td2, s_td3, s_td4);

    pt[0] = dec[0] ^ iv[0];
    pt[1] = dec[1] ^ iv[1];
  }

  if (pt[0] == pt[1])
  {
    if (hc_atomic_inc (&hashes_shown[DIGESTS_OFFSET_HOST]) == 0)
    {
      mark_hash (plains_buf, d_return_buf, SALT_POS_HOST, DIGESTS_CNT, 0, DIGESTS_OFFSET_HOST + 0, gid, 0, 0, 0);
    }
  }
}
