/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_scalar.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha512.cl)
#include M2S(INCLUDE_PATH/inc_cipher_aes.cl)
#endif

typedef struct cryptoapi
{
  u32 kern_type;
  u32 key_size;

} cryptoapi_t;

KERNEL_FQ void m14531_mxx (KERN_ATTR_VECTOR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

  /**
   * base
   */

  u32 aes_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap (&ctx0, w, pw_len);

    sha512_final (&ctx0);

    const u32 k0 = h32_from_64_S (ctx0.h[0]);
    const u32 k1 = l32_from_64_S (ctx0.h[0]);
    const u32 k2 = h32_from_64_S (ctx0.h[1]);
    const u32 k3 = l32_from_64_S (ctx0.h[1]);

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (aes_key_len > 128)
    {
      k4 = h32_from_64_S (ctx0.h[2]);
      k5 = l32_from_64_S (ctx0.h[2]);

      if (aes_key_len > 192)
      {
        k6 = h32_from_64_S (ctx0.h[3]);
        k7 = l32_from_64_S (ctx0.h[3]);
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (aes_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (aes_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
      }
    }

    // IV

    const u32 iv[4] = {
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[0]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[1]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[2]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[3])
    };

    // CT

    u32 CT[4] = { 0 };

    // aes

    u32 ks[60] = { 0 };

    if (aes_key_len == 128)
    {
      AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else if (aes_key_len == 192)
    {
      AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else
    {
      AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    const u32 r0 = CT[0];
    const u32 r1 = CT[1];
    const u32 r2 = CT[2];
    const u32 r3 = CT[3];

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m14531_sxx (KERN_ATTR_VECTOR_ESALT (cryptoapi_t))
{
  /**
   * modifier
   */

  const u64 gid = get_global_id (0);

  /**
   * aes shared
   */

  #ifdef REAL_SHM

  const u64 lid = get_local_id (0);
  const u64 lsz = get_local_size (0);

  LOCAL_VK u32 s_te0[256];
  LOCAL_VK u32 s_te1[256];
  LOCAL_VK u32 s_te2[256];
  LOCAL_VK u32 s_te3[256];
  LOCAL_VK u32 s_te4[256];

  for (u32 i = lid; i < 256; i += lsz)
  {
    s_te0[i] = te0[i];
    s_te1[i] = te1[i];
    s_te2[i] = te2[i];
    s_te3[i] = te3[i];
    s_te4[i] = te4[i];
  }

  SYNC_THREADS ();

  #else

  CONSTANT_AS u32a *s_te0 = te0;
  CONSTANT_AS u32a *s_te1 = te1;
  CONSTANT_AS u32a *s_te2 = te2;
  CONSTANT_AS u32a *s_te3 = te3;
  CONSTANT_AS u32a *s_te4 = te4;

  #endif

  if (gid >= GID_CNT) return;

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
   * base
   */

  u32 aes_key_len = esalt_bufs[DIGESTS_OFFSET_HOST].key_size;

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < IL_CNT; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha512_ctx_t ctx0;

    sha512_init (&ctx0);

    sha512_update_swap(&ctx0, w, pw_len);

    sha512_final (&ctx0);

    const u32 k0 = h32_from_64_S (ctx0.h[0]);
    const u32 k1 = l32_from_64_S (ctx0.h[0]);
    const u32 k2 = h32_from_64_S (ctx0.h[1]);
    const u32 k3 = l32_from_64_S (ctx0.h[1]);

    u32 k4 = 0, k5 = 0, k6 = 0, k7 = 0;

    if (aes_key_len > 128)
    {
      k4 = h32_from_64_S (ctx0.h[2]);
      k5 = l32_from_64_S (ctx0.h[2]);

      if (aes_key_len > 192)
      {
        k6 = h32_from_64_S (ctx0.h[3]);
        k7 = l32_from_64_S (ctx0.h[3]);
      }
    }

    // key

    u32 ukey[8] = { 0 };

    ukey[0] = k0;
    ukey[1] = k1;
    ukey[2] = k2;
    ukey[3] = k3;

    if (aes_key_len > 128)
    {
      ukey[4] = k4;
      ukey[5] = k5;

      if (aes_key_len > 192)
      {
        ukey[6] = k6;
        ukey[7] = k7;
      }
    }

    // IV

    const u32 iv[4] = {
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[0]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[1]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[2]),
      hc_swap32_S(salt_bufs[SALT_POS_HOST].salt_buf[3])
    };

    // CT

    u32 CT[4] = { 0 };

    // aes

    u32 ks[60] = { 0 };

    if (aes_key_len == 128)
    {
      AES128_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES128_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else if (aes_key_len == 192)
    {
      AES192_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES192_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }
    else
    {
      AES256_set_encrypt_key (ks, ukey, s_te0, s_te1, s_te2, s_te3);

      AES256_encrypt (ks, iv, CT, s_te0, s_te1, s_te2, s_te3, s_te4);
    }

    const u32 r0 = CT[0];
    const u32 r1 = CT[1];
    const u32 r2 = CT[2];
    const u32 r3 = CT[3];

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
